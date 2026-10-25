//! Small named blobs that a client keeps on its device: the pins of other
//! users' keys (`KnownKeys`) and the prune queue (`PruneQueue`).
//!
//! - `FileStore`: a file for each blob in one directory, readable only by
//!   its owner. Native clients use it.
//! - `MemoryStore`: blobs in memory, forgotten when it drops.
//! - A browser build gives its own store (IndexedDB).

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

pub trait Store: Send + Sync {
    /// Blob `name`, or `None` if there is none.
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>>;

    /// Replaces blob `name` in one step: a reader sees the old blob or the
    /// new one, never part of one.
    fn save(&self, name: &str, data: &[u8]) -> io::Result<()>;

    /// Runs `f` while no other holder of lock `lock` runs, in this process
    /// or another. Callers hold it across a load and a save, so that two
    /// changes at the same time both land.
    fn exclusive(&self, lock: &str, f: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()>;

    /// Where blob `name` is, for messages.
    fn location(&self, name: &str) -> String;
}

/// Runs `f` under `store`'s lock `lock` and returns what `f` returns.
pub(crate) fn locked<T>(
    store: &dyn Store,
    lock: &str,
    f: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let mut f = Some(f);
    let mut out = None;
    store.exclusive(lock, &mut || {
        if let Some(f) = f.take() {
            out = Some(f()?);
        }
        Ok(())
    })?;
    out.ok_or_else(|| io::Error::other("the store did not run the locked change"))
}

#[derive(Default)]
pub struct MemoryStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    lock: Mutex<()>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(self.blobs.lock().unwrap().get(name).cloned())
    }

    fn save(&self, name: &str, data: &[u8]) -> io::Result<()> {
        self.blobs
            .lock()
            .unwrap()
            .insert(name.to_string(), data.to_vec());
        Ok(())
    }

    fn exclusive(&self, _lock: &str, f: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        let _held = self.lock.lock().unwrap();
        f()
    }

    fn location(&self, name: &str) -> String {
        format!("{name} (in memory)")
    }
}

#[cfg(unix)]
pub use file::FileStore;

#[cfg(unix)]
mod file {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    use super::Store;

    /// A file for each blob in directory `dir`, which does not have to
    /// exist yet. The store makes it readable only by its owner. A lock is
    /// an `flock` on its own file in `dir`.
    pub struct FileStore {
        dir: PathBuf,
    }

    /// An exclusive lock on a lock file, released when dropped.
    struct Locked(File);

    impl Drop for Locked {
        fn drop(&mut self) {
            // SAFETY: the descriptor is the open file's own.
            unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }

    impl FileStore {
        pub fn new(dir: PathBuf) -> Self {
            Self { dir }
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        fn make_dir(&self) -> io::Result<()> {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.dir)
        }
    }

    impl Store for FileStore {
        fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
            match std::fs::read(self.dir.join(name)) {
                Ok(data) => Ok(Some(data)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Writes a file next to the blob's, then renames it over it.
        fn save(&self, name: &str, data: &[u8]) -> io::Result<()> {
            self.make_dir()?;
            let file = self.dir.join(name);
            let tmp = self.dir.join(format!("{name}.{}.tmp", std::process::id()));
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, file)
        }

        fn exclusive(&self, lock: &str, f: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
            self.make_dir()?;
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(self.dir.join(lock))?;
            // SAFETY: as above.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let _held = Locked(file);
            f()
        }

        fn location(&self, name: &str) -> String {
            self.dir.join(name).display().to_string()
        }
    }
}
