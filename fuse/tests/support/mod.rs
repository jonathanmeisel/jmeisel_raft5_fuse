//! Setup for the FUSE tests: the store and servers `raft5fs_testkit`
//! starts, and a `Raft5Fs` mounted on top of those through the actual
//! FUSE kernel interface. Tests then just use `std::fs` against
//! `Harness::path` -- the same path a real caller would take, all the
//! way through the kernel, `fuser`, and our `Filesystem` impl, into a
//! real (if single-node) cluster.

#![allow(dead_code)]

use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::time::Duration;

use fuser::{BackgroundSession, Config, MountOption};
use raft5fs_client::prune_queue::PruneQueue;
use raft5fs_client::pruner::PrunerConfig;
use raft5fs_client::vault::KnownKeys;
use raft5fs_fuse::filesystem::Raft5Fs;
use tokio::runtime::Runtime;

pub use raft5fs_testkit::*;

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

/// A cluster and a filesystem mounted on it, for one test. Everything
/// but the mount is the `Backend`'s, which it derefs to.
///
/// Field order is the drop order, and it matters: the mount has to come
/// down (storing what it buffered) before the servers it stores through.
pub struct Harness {
    pub mount: MountedFs,
    /// Whether `TESTER`'s mounts work in `VOLUME`, made at setup.
    pub volume: bool,
    pub backend: Backend,
}

impl Deref for Harness {
    type Target = Backend;

    fn deref(&self) -> &Backend {
        &self.backend
    }
}

impl DerefMut for Harness {
    fn deref_mut(&mut self) -> &mut Backend {
        &mut self.backend
    }
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
        let old = self.backend.replace_servers(chunk_size);
        self.mount = self.tester_mount(self.addresses());
        drop(old);
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
}

/// A filesystem with `TESTER` enrolled and mounted, working in a volume
/// made for the test (`VOLUME`): to most tests, an ordinary empty
/// filesystem.
pub fn setup() -> Harness {
    setup_with_chunk_size(TEST_CHUNK_SIZE)
}

pub fn setup_with_chunk_size(chunk_size: u64) -> Harness {
    setup_with(chunk_size, true, false, true)
}

/// Like `setup`, but with nothing made: the mount works at `TESTER`'s
/// root, which is empty.
pub fn setup_root() -> Harness {
    setup_with(TEST_CHUNK_SIZE, false, false, true)
}

/// Like `setup`, with the servers keeping hybrid files' blocks in a fake
/// object store (`Harness::store`), on the grid `TEST_OBJECT_FROM_CHUNKS`
/// and `TEST_BLOCK_CHUNKS` make.
pub fn setup_with_objects() -> Harness {
    setup_with(TEST_CHUNK_SIZE, true, true, true)
}

/// Like `setup_with_objects`, with the servers leaving every object
/// nothing points at to garbage collection: for tests of the sweep.
pub fn setup_with_objects_no_prompt_delete() -> Harness {
    setup_with(TEST_CHUNK_SIZE, true, true, false)
}

fn setup_with(chunk_size: u64, volume: bool, with_objects: bool, prompt_delete: bool) -> Harness {
    let backend = Backend::start(chunk_size, with_objects, prompt_delete);
    let mut mount = MountedFs::mount(&backend.runtime, backend.addresses());
    if volume {
        std::fs::create_dir(mount.root.join(VOLUME)).expect("make the test's volume");
        mount = mount.in_volume();
    }
    Harness {
        mount,
        volume,
        backend,
    }
}
