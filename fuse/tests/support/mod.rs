//! Shared setup for integration tests: a real single-node raft5 cluster
//! (a real `raft5_server` node with authentication and mTLS on, listening
//! on real localhost sockets), two filesystem servers over it (over TLS),
//! and a `Raft5Fs` mounted on top of those through the actual FUSE kernel
//! interface -- deployed the way a real installation is meant to be. Tests then just use `std::fs` against
//! `Harness::path` -- the same path a real caller would take, all the
//! way through the kernel, `fuser`, and our `Filesystem` impl, into a
//! real (if single-node) cluster.
//!
//! Everything -- the cluster's server task, the `raft5_client::Client`,
//! and every `block_on` our `Filesystem` methods do from fuser's request
//! threads -- shares one multi-threaded `Runtime`, exactly like
//! `main.rs`: `Handle::block_on` from an arbitrary OS thread is only
//! guaranteed to work against a multi-threaded runtime, and resources
//! created on one runtime (the client's connections) can't safely be
//! driven by another.

#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fuser::{BackgroundSession, Config, MountOption};
use raft5_client::{Certificate, Client, ClientTls, Identity, Principal, Right};
use raft5_server::auth::{AuthConfig, InitialAdmin, hash_password};
use raft5_server::{ClientApiTls, ServerConfig, serve_config};
use raft5fs_core::users::{self, Account};
use raft5fs_core::{DEFAULT_READ_CACHE_BYTES, FsCore, accounts};
use raft5fs_crypto::password::KdfParams;
use raft5fs_fuse::filesystem::Raft5Fs;
use raft5fs_fuse::remote::{Credentials, Remote};
use raft5fs_server::auth::{DEFAULT_SESSION_TTL, Signer};
use raft5fs_server::{FsService, Store};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::{ClientTlsConfig, ServerTlsConfig};

// Generous: every test spins up its own single-node cluster and FUSE
// mount, and they all run concurrently by default, so under load a
// node's first `Bootstrap` attempt can be waiting well behind others for
// CPU time rather than for anything actually wrong.
const DEADLINE: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_millis(20);

/// Small enough that a "several chunks" test moves kilobytes rather than
/// megabytes, while still exercising every boundary the real default
/// would.
pub const TEST_CHUNK_SIZE: u64 = 64 * 1024;

/// The cluster's token secret and startup administrator.
const STORE_SECRET: &[u8] = b"test store secret";
const ADMIN: &str = "admin";
/// The store account the filesystem servers work as: the only one the
/// empty-prefix ACL lets at the filesystem's keys.
pub const SERVICE_USER: &str = "raft5fs";
/// What the filesystem servers sign sessions and handles with, unless a
/// test asks for another.
pub const TOKEN_KEY: &str = "test token key, at least 32 bytes long";
/// The user every mount logs in as unless told otherwise. Acts as
/// whoever runs the tests, and owns the root directory.
pub const TESTER: &str = "tester";

const CERT_ENV: &str = "RAFT5FS_TEST_CERT_PEM";
const KEY_ENV: &str = "RAFT5FS_TEST_KEY_PEM";

/// One self-signed certificate for everything in a test run: the store
/// serves its client API with it and requires it of clients (mTLS), the
/// filesystem servers present it to the store and serve with it, and
/// every client trusts it. Made by the first test that needs it and
/// handed to server processes through the environment, so all agree.
struct TestCert {
    cert: String,
    key: String,
}

fn cert() -> &'static TestCert {
    static CERT: std::sync::LazyLock<TestCert> = std::sync::LazyLock::new(|| {
        if let (Ok(cert), Ok(key)) = (std::env::var(CERT_ENV), std::env::var(KEY_ENV)) {
            return TestCert { cert, key };
        }
        let made = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("generate a test certificate");
        TestCert {
            cert: made.cert.pem(),
            key: made.signing_key.serialize_pem(),
        }
    });
    &CERT
}

fn identity() -> Identity {
    Identity::from_pem(&cert().cert, &cert().key)
}

/// How a client reaches the test store: trusting its certificate, and
/// presenting it, since the store requires one.
pub fn store_tls() -> ClientTls {
    ClientTls::new(Certificate::from_pem(&cert().cert)).identity(identity())
}

/// Like `store_tls`, but presenting no certificate -- as a user who was
/// never given one.
pub fn store_tls_without_identity() -> ClientTls {
    ClientTls::new(Certificate::from_pem(&cert().cert))
}

/// How a client reaches a test filesystem server.
pub fn fs_tls() -> ClientTlsConfig {
    ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&cert().cert))
}

/// Every test account's password: its name, backwards, so a test that
/// wants a wrong one can just use the name.
pub fn password(user: &str) -> String {
    user.chars().rev().collect()
}

pub fn credentials(user: &str) -> Credentials {
    Credentials {
        username: user.to_string(),
        password: password(user),
    }
}

/// Whoever runs the tests: the tester's identity, and the root's owner.
fn own_ids() -> (u32, u32, Vec<u32>) {
    // SAFETY: plain libc calls; `getgroups` writes at most `n` entries
    // into a buffer of that many.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut());
        let mut groups = vec![0; n.max(0) as usize];
        let n = libc::getgroups(groups.len() as i32, groups.as_mut_ptr());
        groups.truncate(n.max(0) as usize);
        (libc::getuid(), libc::getgid(), groups)
    }
}

/// A single-node raft5 cluster running for one test, on its own
/// temporary database directory and ephemeral ports. Dropping it stops
/// the server and deletes the database.
pub struct TestCluster {
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
    db_dir: PathBuf,
    /// The node's client API, for anything else that needs to reach it.
    pub client_address: String,
    /// Logged in as the cluster's administrator, for managing accounts.
    pub admin: Client,
}

impl TestCluster {
    /// Starts a fresh node on `runtime` and bootstraps it into a
    /// single-node cluster with authentication on, locked down the way a
    /// real deployment is (only `SERVICE_USER` may touch any key), and
    /// with `TESTER` set up as a filesystem user. Returns it alongside a
    /// client logged in as `SERVICE_USER`.
    pub fn start(runtime: &Runtime) -> (Self, Client) {
        let client_addr = free_local_addr();
        let peer_addr = free_local_addr();
        let db_dir = temp_dir("db");
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let db_dir_clone = db_dir.clone();
        let id = "test-node".to_string();
        let id_clone = id.clone();

        let password_hash = runtime
            .block_on(hash_password(password(ADMIN)))
            .expect("hash the administrator's password");
        let auth = AuthConfig::new(
            STORE_SECRET,
            Duration::from_secs(3600),
            Some(InitialAdmin {
                username: ADMIN.to_string(),
                password_hash,
            }),
        );
        // Minted here rather than asked for: a login sent before the node
        // is bootstrapped waits out the client's search for a cluster
        // that doesn't exist yet, which costs every test ten seconds.
        let (admin_token, _) = auth.issue(ADMIN).expect("issue the administrator a token");
        let task = runtime.spawn(async move {
            let config = ServerConfig {
                id: id_clone,
                db: db_dir_clone,
                client_addr,
                peer_addr,
                advertise: None,
                advertise_client: None,
                auth: Some(auth),
                peer_tls: None,
                client_tls: Some(ClientApiTls {
                    identity: identity(),
                    client_ca: Some(Certificate::from_pem(&cert().cert)),
                }),
            };
            let result = serve_config(config, cancel_clone).await;
            // Swallowing this turns "the port was taken, so nothing ever
            // listened" into a bare 30 s bootstrap timeout, which says
            // nothing about why. Reported unconditionally: `serve` cancels
            // the token itself on its way out (a bind failure on either
            // port brings the node down), so gating this on the token
            // would hide precisely the failure worth seeing.
            if let Err(e) = result {
                eprintln!("test cluster on {client_addr} never served: {e}");
            }
        });

        let address = format!("https://{client_addr}");
        let (admin, service) = runtime.block_on(async {
            let admin = Client::with_tls([&address], store_tls())
                .expect("failed to construct raft5 client");
            admin.login_with_token(admin_token);

            // The node's gRPC service exists as soon as `serve` binds its
            // listeners, but its state machine may not have reached
            // `Uninitialized` internally yet, so an immediate `Bootstrap`
            // can transiently race that -- retry rather than assume the
            // first attempt lands.
            let until = Instant::now() + DEADLINE;
            loop {
                match admin.bootstrap(&id).await {
                    Ok(()) => break,
                    Err(_) if Instant::now() < until => tokio::time::sleep(RETRY_DELAY).await,
                    Err(e) => panic!("bootstrap never succeeded: {e}"),
                }
            }

            admin
                .create_user(SERVICE_USER, &password(SERVICE_USER), false)
                .await
                .expect("create the service account");
            admin
                .set_acl(b"", &[(Principal::user(SERVICE_USER), Right::Write)])
                .await
                .expect("lock the store down to the service account");
            let service = Client::with_tls([&address], store_tls())
                .expect("failed to construct raft5 client");
            service
                .login(SERVICE_USER, &password(SERVICE_USER))
                .await
                .expect("log in as the service account");
            (admin, service)
        });

        let cluster = Self {
            cancel,
            task: Some(task),
            db_dir,
            client_address: address,
            admin,
        };
        let (uid, gid, groups) = own_ids();
        cluster.add_user(runtime, &service, TESTER, uid, gid, &groups);
        (cluster, service)
    }

    /// Creates store account `name` (password `password(name)`) and gives
    /// it a filesystem identity, writing the user table through
    /// `service`.
    pub fn add_user(
        &self,
        runtime: &Runtime,
        service: &Client,
        name: &str,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) {
        runtime.block_on(async {
            self.admin
                .create_user(name, &password(name), false)
                .await
                .unwrap_or_else(|e| panic!("create store account {name}: {e}"));
            let account = Account {
                uid,
                gid,
                groups: groups.to_vec(),
            };
            users::set(service, name, &account)
                .await
                .unwrap_or_else(|e| panic!("add {name} to the user table: {e}"));
        });
    }
}

impl Drop for TestCluster {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = std::fs::remove_dir_all(&self.db_dir);
    }
}

/// How many filesystem servers each test runs. More than one, so every
/// test also exercises servers sharing a store: mounts start on different
/// instances, and nothing a test does relies on hitting the same one.
const SERVERS: usize = 2;

/// A filesystem server over the test cluster, run as a separate process
/// -- this test binary again, in server mode (see `serve_if_requested`).
/// Dropping it kills the process, which is exactly what a crashed server
/// looks like: its sockets close at once, connections and all.
///
/// In-process servers can't promise that. This process also hosts FUSE
/// mounts, and every mount and unmount forks `fusermount3`; a fork hands
/// the child a copy of every descriptor here -- a server's listening
/// socket included -- so a "stopped" in-process server's port could go on
/// accepting connections that nothing would ever answer. A server process
/// never forks, so nothing can outlive it.
pub struct TestServer {
    child: Option<std::process::Child>,
    pub address: String,
}

const SERVER_CLUSTER_ENV: &str = "RAFT5FS_TEST_SERVER_CLUSTER";
const SERVER_CHUNK_ENV: &str = "RAFT5FS_TEST_SERVER_CHUNK_SIZE";
const SERVER_LISTEN_ENV: &str = "RAFT5FS_TEST_SERVER_LISTEN";
const SERVER_TOKEN_KEY_ENV: &str = "RAFT5FS_TEST_SERVER_TOKEN_KEY";
const SERVER_ENCRYPTED_ENV: &str = "RAFT5FS_TEST_SERVER_ENCRYPTED";
/// The test that is really the server-mode entry point; see
/// `serve_if_requested`.
const SERVER_MODE_TEST: &str = "server_process_mode";

impl TestServer {
    /// Starts a server process over the cluster at `cluster_address` and
    /// waits until it is accepting connections. It opens the filesystem on
    /// the way (settling the chunk size, finishing interrupted deletions).
    pub fn start(cluster_address: &str, chunk_size: u64, encrypted: bool) -> Self {
        for _ in 0..20 {
            if let Some(server) = Self::try_start(
                cluster_address,
                chunk_size,
                free_local_addr(),
                TOKEN_KEY,
                encrypted,
            ) {
                return server;
            }
        }
        panic!("could not start a filesystem server on any port");
    }

    /// Starts a server on `listen`, signing with `token_key`; `None` if
    /// the port turned out to be taken.
    fn try_start(
        cluster_address: &str,
        chunk_size: u64,
        listen: SocketAddr,
        token_key: &str,
        encrypted: bool,
    ) -> Option<Self> {
        let exe = std::env::current_exe().expect("the test binary's own path");
        {
            let mut child = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    SERVER_MODE_TEST,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(SERVER_CLUSTER_ENV, cluster_address)
                .env(SERVER_CHUNK_ENV, chunk_size.to_string())
                .env(SERVER_LISTEN_ENV, listen.to_string())
                .env(SERVER_TOKEN_KEY_ENV, token_key)
                .env(SERVER_ENCRYPTED_ENV, if encrypted { "1" } else { "0" })
                .env(CERT_ENV, &cert().cert)
                .env(KEY_ENV, &cert().key)
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("start a server process");
            let deadline = Instant::now() + DEADLINE;
            loop {
                // Exiting before it ever accepted means its port was taken
                // between choosing and binding it; try another.
                if let Ok(Some(_)) = child.try_wait() {
                    return None;
                }
                if std::net::TcpStream::connect(listen).is_ok() {
                    return Some(Self {
                        child: Some(child),
                        address: format!("https://{listen}"),
                    });
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("a filesystem server never started listening on {listen}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    /// The listening address, without the scheme.
    fn socket_addr(&self) -> SocketAddr {
        self.address
            .trim_start_matches("https://")
            .parse()
            .expect("a server address is host:port")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Server mode: if this process was started by `TestServer::start`, serve
/// the filesystem until killed and never return. Otherwise return at once,
/// so the test that calls this passes trivially in a normal run.
pub fn serve_if_requested() {
    let Ok(cluster) = std::env::var(SERVER_CLUSTER_ENV) else {
        return;
    };
    let chunk_size: u64 = std::env::var(SERVER_CHUNK_ENV).unwrap().parse().unwrap();
    let listen: SocketAddr = std::env::var(SERVER_LISTEN_ENV).unwrap().parse().unwrap();
    let token_key = std::env::var(SERVER_TOKEN_KEY_ENV).unwrap();
    let encrypted = std::env::var(SERVER_ENCRYPTED_ENV).as_deref() == Ok("1");

    // Die with the test that started us, even if it never gets to kill us:
    // a panicking test unwinds past `Drop`s only so far.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    if std::os::unix::process::parent_id() == 1 {
        std::process::exit(1);
    }

    let runtime = Runtime::new().expect("failed to start the server's runtime");
    runtime.block_on(async move {
        let store = Store {
            seeds: vec![cluster],
            tls: Some(store_tls()),
        };
        let client = store.client().expect("failed to construct raft5 client");
        client
            .login(SERVICE_USER, &password(SERVICE_USER))
            .await
            .unwrap_or_else(|e| {
                eprintln!("test server could not log in to the store: {e}");
                std::process::exit(1);
            });
        // The root belongs to whoever runs the tests, so their own mounts
        // can work in it the way a user works in their home directory.
        let (uid, gid, _) = own_ids();
        let root_owner = (uid, gid);
        let core = FsCore::connect(
            client,
            chunk_size,
            DEFAULT_READ_CACHE_BYTES,
            root_owner,
            encrypted,
        )
        .await
        .unwrap_or_else(|why| {
            eprintln!("test server could not open the filesystem: {why}");
            std::process::exit(1);
        });
        let Ok(listener) = tokio::net::TcpListener::bind(listen).await else {
            // Taken since the parent chose it; the parent will pick another.
            std::process::exit(2);
        };
        let signer = Signer::new(token_key.as_bytes(), DEFAULT_SESSION_TTL);
        // Read the user table on every request, so a test that changes
        // it sees the change at once.
        let fs = FsService::new(Arc::new(core), signer, store, Duration::ZERO);
        if let Err(e) = raft5fs_server::serve(
            fs,
            listener,
            Some(ServerTlsConfig::new().identity(identity())),
            std::future::pending(),
        )
        .await
        {
            eprintln!("test server stopped: {e}");
        }
        std::process::exit(1);
    });
}

fn start_servers(cluster: &TestCluster, chunk_size: u64, encrypted: bool) -> Vec<TestServer> {
    (0..SERVERS)
        .map(|_| TestServer::start(&cluster.client_address, chunk_size, encrypted))
        .collect()
}

/// A `Raft5Fs` mounted at a real, temporary directory. Dropping it
/// unmounts the filesystem and removes the (now-empty) mountpoint.
pub struct MountedFs {
    session: Option<BackgroundSession>,
    pub path: PathBuf,
}

impl MountedFs {
    /// Mounts against `servers`, trying them in that order, logged in as
    /// `TESTER`.
    pub fn mount(runtime: &Runtime, servers: Vec<String>) -> Self {
        Self::mount_as(runtime, servers, TESTER)
    }

    /// Like `mount`, but logged in as `user` -- whatever local user
    /// actually uses the mountpoint.
    pub fn mount_as(runtime: &Runtime, servers: Vec<String>, user: &str) -> Self {
        let fs =
            Raft5Fs::new(servers, credentials(user), runtime.handle().clone()).with_tls(fs_tls());
        let path = temp_dir("mnt");

        let mut options = Config::default();
        options.mount_options = vec![MountOption::FSName("raft5fs-test".to_string())];
        // Matches main.rs: writes commit synchronously now, so this is
        // what keeps one file's commit from stalling every other fuse
        // request in tests too.
        options.n_threads = Some(8);

        let session = fuser::spawn_mount(fs, &path, &options)
            .unwrap_or_else(|e| panic!("failed to mount at {path:?}: {e}"));

        Self {
            session: Some(session),
            path,
        }
    }
}

impl Drop for MountedFs {
    fn drop(&mut self) {
        // Dropping the session unmounts before the directory is removed.
        self.session.take();
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A cluster and a filesystem mounted on it, for one test.
///
/// Field order is the drop order, and it matters: the mount has to come
/// down (storing what it buffered) before the servers it stores through,
/// those before the cluster they talk to, and everything before the
/// runtime it all runs on.
pub struct Harness {
    pub mount: MountedFs,
    pub servers: Vec<TestServer>,
    pub client: Client,
    pub cluster: TestCluster,
    pub runtime: Runtime,
    pub chunk_size: u64,
    /// Whether the servers were asked to make the filesystem encrypted;
    /// if so, `add_user` also enrols the user.
    pub encrypted: bool,
}

impl Harness {
    /// The mountpoint. Shorthand for the `mount.path` every test needs.
    pub fn path(&self) -> &std::path::Path {
        &self.mount.path
    }

    /// Restarts the servers (asking for `chunk_size`) and remounts, as a
    /// restart of everything but the store would. The store, and
    /// everything recorded in it, survives.
    ///
    /// The old mount comes down while its servers are still up, so what it
    /// buffered is stored on the way out.
    pub fn remount(&mut self, chunk_size: u64) {
        let servers = start_servers(&self.cluster, chunk_size, self.encrypted);
        let addresses = servers.iter().map(|s| s.address.clone()).collect();
        self.mount = MountedFs::mount(&self.runtime, addresses);
        self.servers = servers;
    }

    /// The servers' addresses, starting with the `first`th and wrapping.
    fn addresses_from(&self, first: usize) -> Vec<String> {
        let n = self.servers.len();
        (0..n)
            .map(|i| self.servers[(first + i) % n].address.clone())
            .collect()
    }

    /// Every key in the store that starts with `prefix`. `key_iterator`
    /// walks to the end of the keyspace, so the caller's prefix is what
    /// bounds it.
    pub fn keys_with_prefix(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.runtime.block_on(async {
            let mut iter = self.client.key_iterator(prefix);
            let mut keys = Vec::new();
            while let Some(key) = iter.next().await.expect("key scan failed") {
                if !key.starts_with(prefix) {
                    break;
                }
                keys.push(key);
            }
            keys
        })
    }

    pub fn read_key(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.runtime
            .block_on(self.client.read(key))
            .expect("read failed")
            .value
    }

    /// The sequence number `key`'s current value was written at. Every
    /// key a transaction writes lands at the same seq, so this is how a
    /// test can tell which writes shared a commit.
    pub fn key_version(&self, key: &[u8]) -> u64 {
        self.runtime
            .block_on(self.client.get_version(key))
            .expect("get_version failed")
    }

    pub fn write_key(&self, key: &[u8], value: Option<&[u8]>) {
        self.runtime
            .block_on(self.client.write(key, value))
            .expect("write failed");
    }

    /// A second filesystem mounted over the same cluster, standing in for
    /// another host's mount: its own write buffers, the same store
    /// underneath -- and it starts on a different server than the first
    /// mount, so the two don't even share a read cache.
    ///
    /// Bind it to a local declared *after* the `Harness`, so that it is
    /// dropped -- and unmounted -- before the cluster and runtime it
    /// talks to go away.
    pub fn second_mount(&self) -> MountedFs {
        MountedFs::mount(&self.runtime, self.addresses_from(1))
    }

    /// Like `second_mount`, but logged in as `user`: another user's
    /// mount of the same filesystem.
    pub fn mount_as(&self, user: &str) -> MountedFs {
        MountedFs::mount_as(&self.runtime, self.addresses_from(1), user)
    }

    /// Adds a filesystem user `name` (password `password(name)`) acting
    /// as `uid`, `gid` and `groups`.
    pub fn add_user(&self, name: &str, uid: u32, gid: u32, groups: &[u32]) {
        self.cluster
            .add_user(&self.runtime, &self.client, name, uid, gid, groups);
        if self.encrypted {
            self.enrol(name);
        }
    }

    /// The servers' addresses, in order.
    pub fn addresses(&self) -> Vec<String> {
        self.addresses_from(0)
    }

    /// Enrols `name` on this encrypted filesystem with password
    /// `password(name)`, through the real enrolment RPC, and returns their
    /// public key.
    pub fn enrol(&self, name: &str) -> [u8; 32] {
        enrol(&self.runtime, &self.client, &self.addresses(), name)
    }

    /// Restarts every server in place -- same addresses, so the mounts
    /// carry on with them -- signing with `token_key` from then on. To a
    /// mount that is every session and handle it holds turning invalid at
    /// once, as an expiry or a key rotation would make them.
    pub fn restart_servers_with_key(&mut self, token_key: &str) {
        for server in &mut self.servers {
            let listen = server.socket_addr();
            *server = TestServer {
                child: None,
                address: String::new(),
            };
            let deadline = Instant::now() + DEADLINE;
            *server = loop {
                if let Some(s) = TestServer::try_start(
                    &self.cluster.client_address,
                    self.chunk_size,
                    listen,
                    token_key,
                    self.encrypted,
                ) {
                    break s;
                }
                assert!(
                    Instant::now() < deadline,
                    "could not restart a server on {listen}"
                );
                std::thread::sleep(RETRY_DELAY);
            };
        }
    }
}

pub fn setup() -> Harness {
    setup_with_chunk_size(TEST_CHUNK_SIZE)
}

pub fn setup_with_chunk_size(chunk_size: u64) -> Harness {
    setup_with(chunk_size, false)
}

/// Like `setup`, but the filesystem is encrypted, and `TESTER` enrolled
/// before mounting.
pub fn setup_encrypted() -> Harness {
    setup_with(TEST_CHUNK_SIZE, true)
}

fn setup_with(chunk_size: u64, encrypted: bool) -> Harness {
    let runtime = Runtime::new().expect("failed to start tokio runtime");
    let (cluster, client) = TestCluster::start(&runtime);
    let servers = start_servers(&cluster, chunk_size, encrypted);
    let addresses: Vec<String> = servers.iter().map(|s| s.address.clone()).collect();
    if encrypted {
        enrol(&runtime, &client, &addresses, TESTER);
    }
    let mount = MountedFs::mount(&runtime, addresses);
    Harness {
        mount,
        servers,
        client,
        cluster,
        runtime,
        chunk_size,
        encrypted,
    }
}

/// Issues `name` an enrolment code and enrols them with it, with
/// password `password(name)` and cheap key-stretching settings.
fn enrol(runtime: &Runtime, client: &Client, addresses: &[String], name: &str) -> [u8; 32] {
    runtime.block_on(async {
        let code = accounts::issue_code(client, name)
            .await
            .unwrap_or_else(|e| panic!("issue {name} an enrolment code: {e}"));
        Remote::enrol(
            addresses,
            Some(fs_tls()),
            name,
            &code,
            &password(name),
            KdfParams::TESTING,
        )
        .await
        .unwrap_or_else(|e| panic!("enrol {name}: {e}"))
    })
}

/// An address for a test cluster to listen on, such that no two tests in
/// this process are ever handed the same one.
///
/// Binding `127.0.0.1:0` and reading the port back cannot do this. The
/// listener is dropped to free the port for the server, and two tests
/// starting at once are then readily handed the *same* port by the
/// kernel. The loser's `serve` fails to bind while its client, pointed at
/// that port, connects to the winner's cluster -- so two tests silently
/// share one store. That surfaces as a test seeing keys it never wrote,
/// or as a node that never manages to bootstrap.
///
/// So the port comes from a counter instead, which cannot repeat, and is
/// only probed to confirm nothing outside this process already holds it.
fn free_local_addr() -> SocketAddr {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // Offset per process as well, so two concurrent `cargo test` runs of
    // this suite do not line up with each other.
    let base = u64::from(std::process::id()) * 8;
    for _ in 0..1_000 {
        let n = base + NEXT.fetch_add(1, Ordering::Relaxed);
        // Below `ip_local_port_range` (32768 on Linux by default). Inside
        // it, a port confirmed free here can be taken by one of the many
        // outgoing gRPC connections these tests open before the server
        // gets to bind it -- which shows up only as a node that never
        // becomes reachable.
        let port = 10_000 + (n % 22_000);
        let addr = SocketAddr::from(([127, 0, 0, 1], port as u16));
        if TcpListener::bind(addr).is_ok() {
            return addr;
        }
    }
    panic!("no free local port after 1000 tries");
}

fn temp_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "jmeisel_raft5_fuse_test_{label}_{}_{counter}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create temp dir");
    path
}
