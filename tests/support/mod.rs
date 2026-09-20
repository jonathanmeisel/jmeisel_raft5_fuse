//! Shared setup for integration tests: a real single-node raft5 cluster
//! (a real `raft5_server::serve` node, listening on real localhost
//! sockets) with a `Raft5Fs` mounted on top of it through the actual
//! FUSE kernel interface. Tests then just use `std::fs` against
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fuser::{BackgroundSession, Config, MountOption};
use jmeisel_raft5_fuse::filesystem::Raft5Fs;
use raft5_client::Client;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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

/// A single-node raft5 cluster running for one test, on its own
/// temporary database directory and ephemeral ports. Dropping it stops
/// the server and deletes the database.
pub struct TestCluster {
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
    db_dir: PathBuf,
}

impl TestCluster {
    /// Starts a fresh node on `runtime` and bootstraps it into a
    /// single-node cluster, returning it alongside a client already
    /// connected to it.
    pub fn start(runtime: &Runtime) -> (Self, Client) {
        let client_addr = free_local_addr();
        let peer_addr = free_local_addr();
        let db_dir = temp_dir("db");
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let db_dir_clone = db_dir.clone();
        let id = "test-node".to_string();
        let id_clone = id.clone();

        let task = runtime.spawn(async move {
            let _ = raft5_server::serve(
                id_clone,
                &db_dir_clone,
                client_addr,
                peer_addr,
                None,
                None,
                cancel_clone,
            )
            .await;
        });

        let client = runtime.block_on(async {
            let client = Client::new([format!("http://{client_addr}")])
                .expect("failed to construct raft5 client");

            // The node's gRPC service exists as soon as `serve` binds its
            // listeners, but its state machine may not have reached
            // `Uninitialized` internally yet, so an immediate `Bootstrap`
            // can transiently race that -- retry rather than assume the
            // first attempt lands.
            let until = Instant::now() + DEADLINE;
            loop {
                match client.bootstrap(&id).await {
                    Ok(()) => break,
                    Err(e) if Instant::now() < until => {
                        let _ = e;
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                    Err(e) => panic!("bootstrap never succeeded: {e}"),
                }
            }
            client
        });

        (
            Self {
                cancel,
                task: Some(task),
                db_dir,
            },
            client,
        )
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

/// A `Raft5Fs` mounted at a real, temporary directory. Dropping it
/// unmounts the filesystem and removes the (now-empty) mountpoint.
pub struct MountedFs {
    session: Option<BackgroundSession>,
    pub path: PathBuf,
}

impl MountedFs {
    pub fn mount(runtime: &Runtime, client: Client, chunk_size: u64) -> Self {
        let fs = Raft5Fs::new(client, runtime.handle().clone(), chunk_size);
        let path = temp_dir("mnt");

        let mut options = Config::default();
        options.mount_options = vec![MountOption::FSName("raft5fs-test".to_string())];

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
/// down before the cluster it talks to and before the runtime its
/// request threads borrow.
pub struct Harness {
    pub mount: MountedFs,
    pub client: Client,
    pub cluster: TestCluster,
    pub runtime: Runtime,
    pub chunk_size: u64,
}

impl Harness {
    /// The mountpoint. Shorthand for the `mount.path` every test needs.
    pub fn path(&self) -> &std::path::Path {
        &self.mount.path
    }

    /// Unmounts and mounts again over the same cluster, as a restart
    /// would -- the store, and everything recorded in it, survives.
    pub fn remount(&mut self, chunk_size: u64) {
        self.mount = MountedFs::mount(&self.runtime, self.client.clone(), chunk_size);
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

    pub fn write_key(&self, key: &[u8], value: Option<&[u8]>) {
        self.runtime
            .block_on(self.client.write(key, value))
            .expect("write failed");
    }

    /// A `Raft5Fs` over the same cluster that is deliberately *not*
    /// mounted, for exercising the parts that run before a mount exists.
    pub fn unmounted_fs(&self, chunk_size: u64) -> Raft5Fs {
        Raft5Fs::new(
            self.client.clone(),
            self.runtime.handle().clone(),
            chunk_size,
        )
    }
}

pub fn setup() -> Harness {
    setup_with_chunk_size(TEST_CHUNK_SIZE)
}

pub fn setup_with_chunk_size(chunk_size: u64) -> Harness {
    let runtime = Runtime::new().expect("failed to start tokio runtime");
    let (cluster, client) = TestCluster::start(&runtime);
    let mount = MountedFs::mount(&runtime, client.clone(), chunk_size);
    Harness {
        mount,
        client,
        cluster,
        runtime,
        chunk_size,
    }
}

fn free_local_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr")
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
