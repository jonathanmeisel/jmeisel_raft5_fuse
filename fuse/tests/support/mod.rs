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
use raft5fs_core::{FsCore, accounts};
use raft5fs_crypto::password::KdfParams;
use raft5fs_fuse::filesystem::Raft5Fs;
use raft5fs_fuse::prune_queue::PruneQueue;
use raft5fs_fuse::pruner::PrunerConfig;
use raft5fs_fuse::remote::{Credentials, Remote};
use raft5fs_fuse::vault::KnownKeys;
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

/// `user`'s credentials, accepting the cheap key stretching test
/// accounts are enrolled with.
pub fn credentials(user: &str) -> Credentials {
    credentials_with(user, &password(user))
}

pub fn credentials_with(user: &str, password: &str) -> Credentials {
    Credentials {
        min_kdf: KdfParams::TESTING,
        ..Credentials::new(user, password)
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
    /// real deployment is (only `SERVICE_USER` may touch any key).
    /// Returns it alongside a client logged in as `SERVICE_USER`.
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
        (cluster, service)
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
/// The test that is really the server-mode entry point; see
/// `serve_if_requested`.
const SERVER_MODE_TEST: &str = "server_process_mode";

impl TestServer {
    /// Starts a server process over the cluster at `cluster_address` and
    /// waits until it is accepting connections. It opens the filesystem on
    /// the way (settling the chunk size, finishing interrupted deletions).
    pub fn start(cluster_address: &str, chunk_size: u64) -> Self {
        for _ in 0..20 {
            if let Some(server) =
                Self::try_start(cluster_address, chunk_size, free_local_addr(), TOKEN_KEY)
            {
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
        let core = FsCore::connect(client, chunk_size)
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
        // Look accounts up on every request, so a test that removes one
        // sees it at once.
        let fs = FsService::new(Arc::new(core), signer, Duration::ZERO);
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

fn start_servers(cluster: &TestCluster, chunk_size: u64) -> Vec<TestServer> {
    (0..SERVERS)
        .map(|_| TestServer::start(&cluster.client_address, chunk_size))
        .collect()
}

/// The volume `setup` makes, which most tests work in as if it were the
/// root of an ordinary filesystem.
pub const VOLUME: &str = "v";

/// A `Raft5Fs` mounted at a real, temporary directory. Dropping it
/// unmounts the filesystem and removes the (now-empty) mountpoint.
pub struct MountedFs {
    session: Option<BackgroundSession>,
    /// The mountpoint: the mounting user's root.
    pub root: PathBuf,
    /// Where tests work: the root, or a volume in it (see `in_volume`).
    pub path: PathBuf,
}

impl MountedFs {
    /// Mounts against `servers`, trying them in that order, logged in as
    /// `TESTER`.
    pub fn mount(runtime: &Runtime, servers: Vec<String>) -> Self {
        Self::mount_as(runtime, servers, TESTER, KnownKeys::in_memory())
    }

    /// Like `mount`, but logged in as `user` -- whatever local user
    /// actually uses the mountpoint -- with the public keys in `known`
    /// pinned.
    pub fn mount_as(runtime: &Runtime, servers: Vec<String>, user: &str, known: KnownKeys) -> Self {
        Self::mount_with(runtime, servers, user, known, None)
    }

    /// Like `mount_as`, working through `prune` in the background too.
    pub fn mount_with(
        runtime: &Runtime,
        servers: Vec<String>,
        user: &str,
        known: KnownKeys,
        prune: Option<PruneQueue>,
    ) -> Self {
        let mut fs = Raft5Fs::new(servers, credentials(user), runtime.handle().clone())
            .with_tls(fs_tls())
            .with_known_keys(known);
        if let Some(queue) = prune {
            // Quick about it, for tests.
            let config = PrunerConfig {
                poll: Duration::from_millis(50),
                pace: Duration::from_millis(1),
                backoff: Duration::from_millis(200),
                max_backoff: Duration::from_secs(1),
            };
            fs = fs.with_prune_queue(queue, config);
        }
        let path = temp_dir("mnt");

        let mut options = Config::default();
        options.mount_options = vec![MountOption::FSName("raft5fs-test".to_string())];
        // Matches `raft5fs mount`: writes commit synchronously now, so this is
        // what keeps one file's commit from stalling every other fuse
        // request in tests too.
        options.n_threads = Some(8);

        let session = fuser::spawn_mount(fs, &path, &options)
            .unwrap_or_else(|e| panic!("failed to mount at {path:?}: {e}"));

        Self {
            session: Some(session),
            root: path.clone(),
            path,
        }
    }

    /// The same mount, with `path` the volume `VOLUME` rather than the
    /// root.
    pub fn in_volume(mut self) -> Self {
        self.path = self.root.join(VOLUME);
        self
    }
}

impl Drop for MountedFs {
    fn drop(&mut self) {
        // Dropping the session unmounts before the directory is removed.
        self.session.take();
        let _ = std::fs::remove_dir_all(&self.root);
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
    /// Whether `TESTER`'s mounts work in `VOLUME`, made at setup.
    pub volume: bool,
    /// `TESTER`'s public key, from their enrolment at setup.
    pub tester_key: [u8; 32],
}

impl Harness {
    /// Where tests work: `VOLUME` (or with `setup_root`, the root).
    /// Shorthand for the `mount.path` every test needs.
    pub fn path(&self) -> &std::path::Path {
        &self.mount.path
    }

    /// `TESTER`'s root, which lists what is shared with them.
    pub fn root(&self) -> &std::path::Path {
        &self.mount.root
    }

    /// A mount as `TESTER`, working where this harness's tests do.
    fn tester_mount(&self, servers: Vec<String>) -> MountedFs {
        let mount = MountedFs::mount(&self.runtime, servers);
        if self.volume {
            mount.in_volume()
        } else {
            mount
        }
    }

    /// Restarts the servers (asking for `chunk_size`) and remounts, as a
    /// restart of everything but the store would. The store, and
    /// everything recorded in it, survives.
    ///
    /// The old mount comes down while its servers are still up, so what it
    /// buffered is stored on the way out.
    pub fn remount(&mut self, chunk_size: u64) {
        let servers = start_servers(&self.cluster, chunk_size);
        let addresses = servers.iter().map(|s| s.address.clone()).collect();
        self.mount = self.tester_mount(addresses);
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
    /// underneath, and a cache of its own -- and it starts on a different
    /// server than the first mount.
    ///
    /// Bind it to a local declared *after* the `Harness`, so that it is
    /// dropped -- and unmounted -- before the cluster and runtime it
    /// talks to go away.
    pub fn second_mount(&self) -> MountedFs {
        self.tester_mount(self.addresses_from(1))
    }

    /// Like `second_mount`, but logged in as `user`: another user's
    /// mount of the same filesystem, working at its root. It trusts
    /// `TESTER`'s key, as if `user` had checked its fingerprint (see
    /// `known_keys`).
    pub fn mount_as(&self, user: &str) -> MountedFs {
        MountedFs::mount_as(
            &self.runtime,
            self.addresses_from(1),
            user,
            self.known_keys(),
        )
    }

    /// Another mount as `TESTER`, at the root, working through `queue` in
    /// the background.
    pub fn pruning_mount(&self, queue: PruneQueue) -> MountedFs {
        MountedFs::mount_with(
            &self.runtime,
            self.addresses_from(1),
            TESTER,
            self.known_keys(),
            Some(queue),
        )
    }

    /// Pins, in memory, of `TESTER`'s key: what every other test user has
    /// checked out of band, so grants from `TESTER` are trusted.
    pub fn known_keys(&self) -> KnownKeys {
        let known = KnownKeys::in_memory();
        known
            .check(TESTER, &self.tester_key)
            .expect("pin the tester's key");
        known
    }

    /// Takes snapshot `name` of the filesystem, as the store's
    /// administrator does (`raft5fs-server snapshot create`).
    pub fn snapshot(&self, name: &str) {
        self.runtime
            .block_on(raft5fs_core::snapshots::create(
                &self.cluster.admin,
                Some(name),
            ))
            .expect("take a snapshot");
    }

    /// Removes snapshot `name`, as `raft5fs-server snapshot del` does.
    pub fn drop_snapshot(&self, name: &str) {
        self.runtime
            .block_on(raft5fs_core::snapshots::remove(&self.cluster.admin, name))
            .expect("remove a snapshot");
    }

    /// Adds user `name`, enrolled with password `password(name)`.
    pub fn add_user(&self, name: &str) {
        self.enrol(name);
    }

    /// The servers' addresses, in order.
    pub fn addresses(&self) -> Vec<String> {
        self.addresses_from(0)
    }

    /// Enrols `name` with password
    /// `password(name)`, through the real enrolment RPC, and returns their
    /// public key.
    pub fn enrol(&self, name: &str) -> [u8; 32] {
        enrol(&self.runtime, &self.client, &self.addresses(), name)
    }

    /// Restarts every server in place -- same addresses, so the mounts
    /// carry on with them -- signing with `token_key` from then on. To a
    /// mount that is every session it holds turning invalid at once, as an
    /// expiry or a key rotation would make them.
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

/// A filesystem with `TESTER` enrolled and mounted, working in a volume
/// made for the test (`VOLUME`): to most tests, an ordinary empty
/// filesystem.
pub fn setup() -> Harness {
    setup_with_chunk_size(TEST_CHUNK_SIZE)
}

pub fn setup_with_chunk_size(chunk_size: u64) -> Harness {
    setup_with(chunk_size, true)
}

/// Like `setup`, but with nothing made: the mount works at `TESTER`'s
/// root, which is empty.
pub fn setup_root() -> Harness {
    setup_with(TEST_CHUNK_SIZE, false)
}

fn setup_with(chunk_size: u64, volume: bool) -> Harness {
    let runtime = Runtime::new().expect("failed to start tokio runtime");
    let (cluster, client) = TestCluster::start(&runtime);
    let servers = start_servers(&cluster, chunk_size);
    let addresses: Vec<String> = servers.iter().map(|s| s.address.clone()).collect();
    let tester_key = enrol(&runtime, &client, &addresses, TESTER);
    let mut mount = MountedFs::mount(&runtime, addresses);
    if volume {
        std::fs::create_dir(mount.root.join(VOLUME)).expect("make the test's volume");
        mount = mount.in_volume();
    }
    Harness {
        mount,
        servers,
        client,
        cluster,
        runtime,
        chunk_size,
        volume,
        tester_key,
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
            credentials(name),
            &code,
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
