//! Shared setup for integration tests: a real single-node raft5 cluster,
//! and filesystem servers on it, set up as a real installation is. The
//! cluster is a real `raft5_server` node with authentication and mTLS on,
//! on real localhost sockets, and the filesystem servers use TLS. Each
//! front end's tests put a mount, a WebDAV server, or a bare session on top
//! (see `Backend`).
//!
//! Everything shares one multi-threaded `Runtime`: the cluster's server
//! task, the `raft5_client::Client`, and every `block_on` a front end does.
//! `Handle::block_on` from any OS thread is only guaranteed to work on a
//! multi-threaded runtime, and resources made on one runtime (the client's
//! connections) cannot safely be driven by another.
//!
//! Filesystem servers run as their own processes: the test binary again, in
//! server mode. So every test binary that uses this must have:
//!
//! ```ignore
//! #[test]
//! fn server_process_mode() {
//!     raft5fs_testkit::serve_if_requested();
//! }
//! ```

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use raft5_client::{
    BACKUP_OPERATORS_GROUP, Certificate, Client, ClientTls, Consistency, Identity, Principal, Right,
};
use raft5_server::auth::{AuthConfig, InitialAdmin, hash_password};
use raft5_server::{ClientApiTls, ServerConfig, serve_config};
use raft5fs_client::remote::{Credentials, Remote};
use raft5fs_client::vault::KnownKeys;
use raft5fs_core::backup::BackupStore;
use raft5fs_core::objects::{DEFAULT_GET_TTL, DEFAULT_PUT_TTL, ObjectSettings};
use raft5fs_core::{FsCore, accounts};
use raft5fs_crypto::password::KdfParams;
use raft5fs_objstore::fake::{self, FakeStore};
use raft5fs_objstore::http::HttpConfig;
use raft5fs_objstore::{S3Config, S3Store};
use raft5fs_server::auth::{DEFAULT_SESSION_TTL, Signer};
use raft5fs_server::{FsService, InviteSettings, Store};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::{ClientTlsConfig, ServerTlsConfig};

// Long on purpose: every test starts its own single-node cluster and front
// end, and they all run at the same time by default. Under load, a node's
// first `Bootstrap` attempt can wait a long time for CPU, with nothing
// actually wrong.
const DEADLINE: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_millis(20);

/// Small enough that a "several chunks" test moves kilobytes, not
/// megabytes, but still tests every boundary that the real default would.
pub const TEST_CHUNK_SIZE: u64 = 64 * 1024;

/// With object storage (`setup_with_objects`): hybrid files' blocks start
/// this many chunks in, and hold this many chunks each. Small, so a test
/// reaches the blocks, and crosses between them, with a few hundred
/// kilobytes.
pub const TEST_OBJECT_FROM_CHUNKS: u64 = 2;
pub const TEST_BLOCK_CHUNKS: u64 = 4;
/// The fake object store's bucket, and the prefix that the servers keep
/// objects under in it.
pub const TEST_BUCKET: &str = "bucket";
pub const TEST_OBJECT_PREFIX: &str = "fs/";

/// The cluster's token secret and startup administrator.
const STORE_SECRET: &[u8] = b"test store secret";
const ADMIN: &str = "admin";
/// The store account that the filesystem servers use. The empty-prefix ACL
/// lets only this account reach the filesystem's keys.
pub const SERVICE_USER: &str = "raft5fs";
/// The key that the filesystem servers sign sessions and handles with,
/// unless a test asks for another.
pub const TOKEN_KEY: &str = "test token key, at least 32 bytes long";
/// The user that every mount logs in as by default. Acts as the user who
/// runs the tests, and owns the root directory.
pub const TESTER: &str = "tester";

const CERT_ENV: &str = "RAFT5FS_TEST_CERT_PEM";
const KEY_ENV: &str = "RAFT5FS_TEST_KEY_PEM";

/// One self-signed certificate for everything in a test run. The store
/// serves its client API with it and requires it from clients (mTLS). The
/// filesystem servers present it to the store and serve with it. Every
/// client trusts it. The first test that needs it makes it, and server
/// processes get it through the environment, so all of them agree.
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

/// How a client connects to the test store: it trusts the store's
/// certificate, and presents it, because the store requires one.
pub fn store_tls() -> ClientTls {
    ClientTls::new(Certificate::from_pem(&cert().cert)).identity(identity())
}

/// Like `store_tls`, but presents no certificate, as a user who never got
/// one.
pub fn store_tls_without_identity() -> ClientTls {
    ClientTls::new(Certificate::from_pem(&cert().cert))
}

/// How a client connects to a test filesystem server.
pub fn fs_tls() -> ClientTlsConfig {
    ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&cert().cert))
}

/// The certificate that `fs_tls` trusts, in DER: the test filesystem's
/// CA, as an invitation carries it.
pub fn fs_ca_der() -> Vec<u8> {
    raft5fs_proto::invite::pem_to_der(&cert().cert).expect("the test certificate is PEM")
}

/// TLS for a filesystem server that `fs_tls` trusts.
pub fn server_tls() -> ServerTlsConfig {
    ServerTlsConfig::new().identity(identity())
}

/// Every test account's password: its name, backwards. A test that wants a
/// wrong password can use the name.
pub fn password(user: &str) -> String {
    user.chars().rev().collect()
}

/// `user`'s credentials. They accept the low-cost key stretching that test
/// accounts are enrolled with.
pub fn credentials(user: &str) -> Credentials {
    credentials_with(user, &password(user))
}

pub fn credentials_with(user: &str, password: &str) -> Credentials {
    Credentials {
        min_kdf: KdfParams::TESTING,
        // The fake object store is plain HTTP on localhost.
        objects: HttpConfig {
            allow_plaintext: true,
            ..HttpConfig::default()
        },
        ..Credentials::new(user, password)
    }
}

/// A single-node raft5 cluster for one test, on its own temporary database
/// directory and ephemeral ports. Dropping it stops the server and deletes
/// the database.
pub struct TestCluster {
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
    db_dir: PathBuf,
    /// The node's client API address, for anything else that needs to reach
    /// it.
    pub client_address: String,
    /// Logged in as the cluster's administrator, to manage accounts.
    pub admin: Client,
}

impl TestCluster {
    /// Starts a new node on `runtime` and bootstraps it into a single-node
    /// cluster with authentication on, locked down as a real deployment is
    /// (only `SERVICE_USER` can touch any key, and it may take snapshots
    /// and backups). Returns it with a client logged in as `SERVICE_USER`.
    pub fn start(runtime: &Runtime) -> (Self, Client) {
        Self::start_with(runtime, None)
    }

    /// Like `start`, but the cluster holds the store backup at `backup`,
    /// accounts and ACLs included, as a restore does.
    pub fn start_from_backup(runtime: &Runtime, backup: &Path) -> (Self, Client) {
        Self::start_with(runtime, Some(backup))
    }

    fn start_with(runtime: &Runtime, backup: Option<&Path>) -> (Self, Client) {
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
        // Made here and not requested: a login sent before the node is
        // bootstrapped waits while the client searches for a cluster that
        // does not exist yet, which costs every test ten seconds.
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
            // If this error were ignored, "the port was taken, so nothing
            // listened" would show only as a 30 s bootstrap timeout, with
            // no reason. Always report it: `serve` cancels the token itself
            // when it exits (a bind failure on either port stops the node),
            // so checking the token first would hide exactly this failure.
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
            // listeners, but its state machine might not be `Uninitialized`
            // yet. So an immediate `Bootstrap` can race it for a short
            // time. Retry, and do not assume that the first attempt works.
            let until = Instant::now() + DEADLINE;
            loop {
                let done = match backup {
                    None => admin.bootstrap(&id, None).await,
                    Some(path) => {
                        let file = tokio::fs::File::open(path)
                            .await
                            .expect("open the store backup");
                        admin.bootstrap_from_backup(&id, None, file).await
                    }
                };
                match done {
                    Ok(()) => break,
                    Err(_) if Instant::now() < until => tokio::time::sleep(RETRY_DELAY).await,
                    Err(e) => panic!("bootstrap never succeeded: {e}"),
                }
            }

            // A restored cluster has these from the backup.
            if backup.is_none() {
                admin
                    .create_user(SERVICE_USER, &password(SERVICE_USER), false)
                    .await
                    .expect("create the service account");
                admin
                    .set_acl(b"", &[(Principal::user(SERVICE_USER), Right::Write)])
                    .await
                    .expect("lock the store down to the service account");
                admin
                    .update_group(
                        BACKUP_OPERATORS_GROUP,
                        &[Principal::user(SERVICE_USER)],
                        &[],
                        &[],
                        &[],
                    )
                    .await
                    .expect("let the service account take snapshots and backups");
            }
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

/// How many filesystem servers each test runs. More than one, so every test
/// also tests servers that share a store: mounts start on different
/// instances, and no test depends on reaching the same one.
const SERVERS: usize = 2;

/// A filesystem server on the test cluster, run as a separate process: this
/// test binary again, in server mode (see `serve_if_requested`). Dropping
/// it kills the process, which is exactly how a crashed server looks: its
/// sockets and connections close at once.
///
/// An in-process server cannot promise that. This process also hosts FUSE
/// mounts, and every mount and unmount forks `fusermount3`. A fork gives
/// the child a copy of every descriptor here, including a server's
/// listening socket. So a "stopped" in-process server's port could continue
/// to accept connections that nothing would answer. A server process never
/// forks, so nothing can outlive it.
pub struct TestServer {
    child: Option<std::process::Child>,
    pub address: String,
}

const SERVER_CLUSTER_ENV: &str = "RAFT5FS_TEST_SERVER_CLUSTER";
const SERVER_CHUNK_ENV: &str = "RAFT5FS_TEST_SERVER_CHUNK_SIZE";
const SERVER_LISTEN_ENV: &str = "RAFT5FS_TEST_SERVER_LISTEN";
const SERVER_TOKEN_KEY_ENV: &str = "RAFT5FS_TEST_SERVER_TOKEN_KEY";
/// The fake object store's endpoint, for a server that keeps objects.
const SERVER_OBJECTS_ENV: &str = "RAFT5FS_TEST_SERVER_OBJECTS";
/// Set for a server that leaves every object with no pointer to the sweeps.
const SERVER_NO_PROMPT_DELETE_ENV: &str = "RAFT5FS_TEST_SERVER_NO_PROMPT_DELETE";

/// Where a server keeps objects, and whether it deletes an object as soon
/// as nothing points to it (see `ObjectSettings::prompt_delete`).
#[derive(Debug, Clone)]
pub struct ServerObjects {
    pub endpoint: String,
    pub prompt_delete: bool,
}
/// The test that is the server-mode entry point; see `serve_if_requested`.
const SERVER_MODE_TEST: &str = "server_process_mode";

impl TestServer {
    /// Starts a server process on the cluster at `cluster_address`, and
    /// waits until it accepts connections. On the way, it opens the
    /// filesystem (sets the chunk size, finishes interrupted deletions).
    /// With `objects`, a fake object store, it keeps hybrid files' blocks
    /// there.
    pub fn start(cluster_address: &str, chunk_size: u64, objects: Option<&ServerObjects>) -> Self {
        for _ in 0..20 {
            if let Some(server) = Self::try_start(
                cluster_address,
                chunk_size,
                objects,
                free_local_addr(),
                TOKEN_KEY,
            ) {
                return server;
            }
        }
        panic!("could not start a filesystem server on any port");
    }

    /// Starts a server on `listen` that signs with `token_key`. Returns
    /// `None` if the port was taken.
    fn try_start(
        cluster_address: &str,
        chunk_size: u64,
        objects: Option<&ServerObjects>,
        listen: SocketAddr,
        token_key: &str,
    ) -> Option<Self> {
        let exe = std::env::current_exe().expect("the test binary's own path");
        {
            let mut command = std::process::Command::new(&exe);
            if let Some(objects) = objects {
                command.env(SERVER_OBJECTS_ENV, &objects.endpoint);
                if !objects.prompt_delete {
                    command.env(SERVER_NO_PROMPT_DELETE_ENV, "1");
                }
            }
            let mut child = command
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
                // If it exited before it accepted anything, its port was
                // taken between choosing and binding it. Try another port.
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

/// Server mode: if `TestServer::start` started this process, serve the
/// filesystem until killed, and never return. Otherwise return at once, so
/// the test that calls this passes in a normal run.
pub fn serve_if_requested() {
    let Ok(cluster) = std::env::var(SERVER_CLUSTER_ENV) else {
        return;
    };
    let chunk_size: u64 = std::env::var(SERVER_CHUNK_ENV).unwrap().parse().unwrap();
    let listen: SocketAddr = std::env::var(SERVER_LISTEN_ENV).unwrap().parse().unwrap();
    let token_key = std::env::var(SERVER_TOKEN_KEY_ENV).unwrap();
    let objects = std::env::var(SERVER_OBJECTS_ENV).ok();
    let prompt_delete = std::env::var(SERVER_NO_PROMPT_DELETE_ENV).is_err();

    // Exit with the test that started this process, even if the test never
    // kills it: a panicking test runs only some `Drop`s as it unwinds.
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
        let objects =
            objects.map(|endpoint| object_settings(endpoint, chunk_size, prompt_delete, |_| {}));
        let core = FsCore::connect(client, chunk_size, objects)
            .await
            .unwrap_or_else(|why| {
                eprintln!("test server could not open the filesystem: {why}");
                std::process::exit(1);
            });
        let Ok(listener) = tokio::net::TcpListener::bind(listen).await else {
            // The port was taken after the parent chose it. The parent will
            // choose another.
            std::process::exit(2);
        };
        let signer = Signer::new(token_key.as_bytes(), DEFAULT_SESSION_TTL);
        // Check accounts on every request, so a test that removes one sees
        // the result at once.
        let core = Arc::new(core);
        // Usage counts as on a real server; tests measure when they want
        // (`MeasureUsage`).
        tokio::spawn(Arc::clone(&core).run_tallies());
        let fs = FsService::new(core, signer, Duration::ZERO)
            .with_timing_header(true)
            .with_invites(Some(InviteSettings {
                servers: vec![format!("https://{listen}")],
                tls_server_name: None,
                ca: fs_ca_der(),
            }));
        if let Err(e) =
            raft5fs_server::serve(fs, listener, Some(server_tls()), std::future::pending()).await
        {
            eprintln!("test server stopped: {e}");
        }
        std::process::exit(1);
    });
}

/// The object settings for a test server: the fake store at `endpoint`, on
/// the test grid, with changes from `edit`.
pub fn object_settings(
    endpoint: String,
    chunk_size: u64,
    prompt_delete: bool,
    edit: impl FnOnce(&mut S3Config),
) -> ObjectSettings {
    let http = raft5fs_objstore::http::client(&HttpConfig {
        allow_plaintext: true,
        ..HttpConfig::default()
    })
    .expect("an HTTP client for the object store");
    let mut config = S3Config {
        endpoint,
        bucket: TEST_BUCKET.into(),
        region: fake::REGION.into(),
        path_style: true,
        access_key: fake::ACCESS_KEY.into(),
        secret_key: fake::SECRET_KEY.into(),
        prefix: TEST_OBJECT_PREFIX.into(),
    };
    edit(&mut config);
    ObjectSettings {
        store: S3Store::new(&config, http).expect("the fake object store's settings"),
        object_from: TEST_OBJECT_FROM_CHUNKS * chunk_size,
        object_block: TEST_BLOCK_CHUNKS * chunk_size,
        put_ttl: DEFAULT_PUT_TTL,
        get_ttl: DEFAULT_GET_TTL,
        prompt_delete,
    }
}

/// An `S3Store` for `config`, on a fake store over plain HTTP.
pub fn store_on(config: &S3Config) -> S3Store {
    let http = raft5fs_objstore::http::client(&HttpConfig {
        allow_plaintext: true,
        ..HttpConfig::default()
    })
    .expect("an HTTP client for the object store");
    S3Store::new(config, http).expect("the fake object store's settings")
}

/// The bucket and prefix that tests keep backups under.
pub const TEST_BACKUP_BUCKET: &str = "backups";
pub const TEST_BACKUP_PREFIX: &str = "bk/";

/// A backup space in `space`, a fake store made with `TEST_BACKUP_BUCKET`,
/// as `raft5fs-server backup` sets one up.
pub fn backup_store(space: &FakeStore) -> BackupStore {
    let pool = space.config(&format!("{TEST_BACKUP_PREFIX}objects/"));
    BackupStore::new(store_on(&pool), store_on(&space.config(TEST_BACKUP_PREFIX)))
}

pub fn start_servers(
    cluster: &TestCluster,
    chunk_size: u64,
    objects: Option<&ServerObjects>,
) -> Vec<TestServer> {
    (0..SERVERS)
        .map(|_| TestServer::start(&cluster.client_address, chunk_size, objects))
        .collect()
}

/// The volume that tests make. Most tests use it as if it were the root of
/// a normal filesystem.
pub const VOLUME: &str = "v";

/// A cluster and filesystem servers on it, with `TESTER` enrolled, for one
/// test: everything except the front end. Fields drop in order, and the
/// order matters: the servers stop before the cluster they use, and
/// everything stops before its runtime. A front end on these must be
/// dropped first.
pub struct Backend {
    pub servers: Vec<TestServer>,
    pub client: Client,
    pub cluster: TestCluster,
    /// The object store where the servers keep blocks, if they do.
    pub objects: Option<FakeStore>,
    /// Whether the servers delete an object as soon as nothing points to
    /// it, or leave it for garbage collection.
    pub prompt_delete: bool,
    pub runtime: Runtime,
    pub chunk_size: u64,
    /// `TESTER`'s public key, from their enrolment at setup.
    pub tester_key: [u8; 32],
}

impl Backend {
    /// A new cluster, servers on it that ask for `chunk_size`, and `TESTER`
    /// enrolled. With `with_objects`, the servers keep hybrid files' blocks
    /// in a fake object store.
    pub fn start(chunk_size: u64, with_objects: bool, prompt_delete: bool) -> Self {
        let runtime = Runtime::new().expect("failed to start tokio runtime");
        let (cluster, client) = TestCluster::start(&runtime);
        let objects = with_objects.then(|| {
            runtime
                .block_on(FakeStore::start(TEST_BUCKET))
                .expect("start a fake object store")
        });
        let server_objects = objects.as_ref().map(|store| ServerObjects {
            endpoint: store.endpoint(),
            prompt_delete,
        });
        let servers = start_servers(&cluster, chunk_size, server_objects.as_ref());
        let addresses: Vec<String> = servers.iter().map(|s| s.address.clone()).collect();
        let tester_key = enrol(&runtime, &client, &addresses, TESTER);
        Self {
            servers,
            client,
            cluster,
            objects,
            prompt_delete,
            runtime,
            chunk_size,
            tester_key,
        }
    }

    /// Replaces the servers with new ones that ask for `chunk_size`, as a
    /// restart of everything except the store would. Returns the old
    /// servers, for the caller to drop after its front end is done with
    /// them.
    pub fn replace_servers(&mut self, chunk_size: u64) -> Vec<TestServer> {
        let servers = start_servers(&self.cluster, chunk_size, self.server_objects().as_ref());
        std::mem::replace(&mut self.servers, servers)
    }

    /// The servers' object store, if they have one.
    fn server_objects(&self) -> Option<ServerObjects> {
        self.objects.as_ref().map(|store| ServerObjects {
            endpoint: store.endpoint(),
            prompt_delete: self.prompt_delete,
        })
    }

    /// The fake object store where the servers keep blocks. Only with
    /// `setup_with_objects`.
    pub fn store(&self) -> &FakeStore {
        self.objects
            .as_ref()
            .expect("this harness has no object store; use setup_with_objects")
    }

    /// A filesystem core in this process, on the same store and object
    /// store as the servers, so tests can run garbage collection when and
    /// at the time they choose. It deletes only by sweeping.
    pub fn gc_core(&self) -> FsCore {
        self.gc_core_with(|_| {})
    }

    /// `gc_core`, with its object store settings changed by `edit`.
    pub fn gc_core_with(&self, edit: impl FnOnce(&mut S3Config)) -> FsCore {
        let settings = object_settings(self.store().endpoint(), self.chunk_size, false, edit);
        self.runtime
            .block_on(FsCore::connect(
                self.client.clone(),
                self.chunk_size,
                Some(settings),
            ))
            .expect("open the filesystem for garbage collection")
    }

    /// The servers' addresses, starting with the `first`th and wrapping.
    pub fn addresses_from(&self, first: usize) -> Vec<String> {
        let n = self.servers.len();
        (0..n)
            .map(|i| self.servers[(first + i) % n].address.clone())
            .collect()
    }

    /// The servers' addresses, in order.
    pub fn addresses(&self) -> Vec<String> {
        self.addresses_from(0)
    }

    /// Every key in the store that starts with `prefix`. `key_iterator`
    /// walks to the end of the keyspace, so the caller's prefix is what
    /// limits it.
    pub fn keys_with_prefix(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.runtime.block_on(async {
            let mut iter = self.client.key_iterator(prefix, Consistency::Stale);
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
            .block_on(self.client.read(&[key], Consistency::Stale))
            .expect("read failed")
            .entries
            .remove(0)
            .value
    }

    /// The sequence number that `key`'s current value was written at. Every
    /// key that a transaction writes gets the same seq, so a test can use
    /// this to tell which writes shared a commit.
    pub fn key_version(&self, key: &[u8]) -> u64 {
        self.runtime
            .block_on(self.client.read_versions(&[key], Consistency::Stale))
            .expect("read_versions failed")
            .entries
            .remove(0)
            .seq
    }

    pub fn write_key(&self, key: &[u8], value: Option<&[u8]>) {
        self.runtime
            .block_on(self.client.write(key, value))
            .expect("write failed");
    }

    /// In-memory pins of `TESTER`'s key, as if every other test user
    /// checked it on another channel. So grants from `TESTER` are trusted.
    pub fn known_keys(&self) -> KnownKeys {
        let known = KnownKeys::in_memory();
        known
            .check(TESTER, &self.tester_key)
            .expect("pin the tester's key");
        known
    }

    /// Takes snapshot `name` of the filesystem as the servers' account, as
    /// `raft5fs-server snapshot create` does.
    pub fn snapshot(&self, name: &str) {
        self.runtime
            .block_on(raft5fs_core::snapshots::create(&self.client, Some(name)))
            .expect("take a snapshot");
    }

    /// Removes snapshot `name`, as `raft5fs-server snapshot del` does.
    pub fn drop_snapshot(&self, name: &str) {
        self.runtime
            .block_on(raft5fs_core::snapshots::remove(&self.client, name))
            .expect("remove a snapshot");
    }

    /// The servers' object store, as a backup reads it. Only with
    /// `setup_with_objects`.
    pub fn serving_store(&self) -> Arc<S3Store> {
        Arc::new(store_on(&self.store().config(TEST_OBJECT_PREFIX)))
    }

    /// Adds user `name`, enrolled with password `password(name)`.
    pub fn add_user(&self, name: &str) {
        self.enrol(name);
    }

    /// Enrols `name` with password `password(name)` through the real
    /// enrolment RPC, and returns their public key.
    pub fn enrol(&self, name: &str) -> [u8; 32] {
        enrol(&self.runtime, &self.client, &self.addresses(), name)
    }

    /// Restarts every server in place (same addresses, so the front ends
    /// continue to use them), signing with `token_key` from then on. For a
    /// front end, every session it holds becomes invalid at once, as after
    /// an expiry or a key rotation.
    pub fn restart_servers_with_key(&mut self, token_key: &str) {
        let objects = self.server_objects();
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
                    objects.as_ref(),
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

/// Issues `name` an enrolment code and enrols them with it, with password
/// `password(name)` and low-cost key stretching settings.
pub fn enrol(runtime: &Runtime, client: &Client, addresses: &[String], name: &str) -> [u8; 32] {
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

/// An address for a test cluster to listen on, never the same for two tests
/// in this process.
///
/// Binding `127.0.0.1:0` and reading the port back cannot do this. The
/// listener is dropped to free the port for the server, and the kernel then
/// often gives two tests that start at the same time the *same* port. The
/// loser's `serve` fails to bind, while its client, pointed at that port,
/// connects to the winner's cluster. So two tests share one store without
/// notice. That shows as a test that sees keys it never wrote, or as a node
/// that never bootstraps.
///
/// So the port comes from a counter, which cannot repeat. It is only probed
/// to check that nothing outside this process already has it.
fn free_local_addr() -> SocketAddr {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // Also offset for each process, so two `cargo test` runs of this suite
    // at the same time do not use the same ports.
    let base = u64::from(std::process::id()) * 8;
    for _ in 0..1_000 {
        let n = base + NEXT.fetch_add(1, Ordering::Relaxed);
        // Below `ip_local_port_range` (32768 on Linux by default). Inside
        // that range, a port confirmed free here can be taken by one of the
        // many outgoing gRPC connections that these tests open before the
        // server binds it. That shows only as a node that never becomes
        // reachable.
        let port = 10_000 + (n % 22_000);
        let addr = SocketAddr::from(([127, 0, 0, 1], port as u16));
        if TcpListener::bind(addr).is_ok() {
            return addr;
        }
    }
    panic!("no free local port after 1000 tries");
}

pub fn temp_dir(label: &str) -> PathBuf {
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
