//! Where a device keeps the index files it has read: in memory for one
//! run, or on disk (native), sealed so that a copy of the disk is
//! ciphertext without the account.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use super::SegmentCache;
use crate::rt::BoxFuture;

/// A cache for one run: what a pass reads twice, it fetches once.
#[derive(Default)]
pub struct MemoryCache(Mutex<HashMap<String, Vec<u8>>>);

impl SegmentCache for MemoryCache {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Option<Vec<u8>>> {
        let got = self.0.lock().unwrap().get(key).cloned();
        Box::pin(async move { got })
    }

    fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> BoxFuture<'a, ()> {
        self.0
            .lock()
            .unwrap()
            .insert(key.to_string(), bytes.to_vec());
        Box::pin(async {})
    }

    fn keep_only<'a>(&'a self, volume: u64, keys: &'a [String]) -> BoxFuture<'a, ()> {
        let keep: HashSet<&str> = keys.iter().map(String::as_str).collect();
        let prefix = format!("{volume}/");
        self.0
            .lock()
            .unwrap()
            .retain(|k, _| !k.starts_with(&prefix) || keep.contains(k.as_str()));
        Box::pin(async {})
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use disk::DiskCache;

#[cfg(not(target_arch = "wasm32"))]
mod disk {
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;

    use raft5fs_crypto::identity::Identity;
    use raft5fs_crypto::local::{open_local, seal_local};
    use sha2::{Digest, Sha256};

    use super::SegmentCache;
    use crate::rt::BoxFuture;

    /// Index files on disk, one file each, under a folder per volume,
    /// named by the hash of their key and sealed with the account's local
    /// key (raft5fs-crypto's `local`).
    pub struct DiskCache {
        dir: PathBuf,
        identity: Arc<Identity>,
    }

    impl DiskCache {
        pub fn new(dir: PathBuf, identity: Arc<Identity>) -> Self {
            Self { dir, identity }
        }

        fn path(&self, key: &str) -> PathBuf {
            let volume = key.split('/').next().unwrap_or("0");
            let name = raft5fs_wire::hex(&Sha256::digest(key.as_bytes()));
            self.dir.join(volume).join(name)
        }

        /// What it keeps under `key`, at once.
        pub fn get_now(&self, key: &str) -> Option<Vec<u8>> {
            let sealed = std::fs::read(self.path(key)).ok()?;
            open_local(&self.identity, key, &sealed).ok()
        }

        /// Keeps `bytes` under `key`, at once. A cache that can't keep it
        /// only costs a read next time.
        pub fn put_now(&self, key: &str, bytes: &[u8]) {
            let path = self.path(key);
            if let Some(parent) = path.parent()
                && std::fs::create_dir_all(parent).is_ok()
            {
                let part = path.with_extension("part");
                if std::fs::write(&part, seal_local(&self.identity, key, bytes)).is_ok() {
                    let _ = std::fs::rename(&part, &path);
                }
            }
        }
    }

    impl SegmentCache for DiskCache {
        fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Option<Vec<u8>>> {
            Box::pin(async move { self.get_now(key) })
        }

        fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> BoxFuture<'a, ()> {
            Box::pin(async move { self.put_now(key, bytes) })
        }

        fn keep_only<'a>(&'a self, volume: u64, keys: &'a [String]) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                let keep: HashSet<PathBuf> = keys.iter().map(|k| self.path(k)).collect();
                let Ok(list) = std::fs::read_dir(self.dir.join(volume.to_string())) else {
                    return;
                };
                for e in list.flatten() {
                    if !keep.contains(&e.path()) {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            })
        }
    }
}
