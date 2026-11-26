//! Where compaction keeps its work on local disk: the old generation's
//! pieces, its buckets of postings and vectors (raft5fs-search's
//! `compact::Buckets`), and the new server files until they are written.
//!
//! - Everything is sealed with the account's local key, so what a crash
//!   leaves on disk is ciphertext.
//! - Each compaction has its own folder, named for it; `clean_old` removes
//!   the folders of earlier runs that ended without cleaning up.
//! - A bucket is appended to in sealed blocks of about `BLOCK` bytes, so
//!   memory holds one small buffer a bucket.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use raft5fs_crypto::identity::Identity;
use raft5fs_crypto::local::{open_local, seal_local};
use raft5fs_search::compact::Buckets;

/// A bucket's buffer is sealed and written at this size.
const BLOCK: usize = 16 << 10;
/// Spill folders' names start so.
const PREFIX: &str = "compact-";

fn io(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// One compaction's folder.
pub struct Spill {
    dir: PathBuf,
    identity: Arc<Identity>,
}

impl Spill {
    /// A new folder in `base`.
    pub fn new(base: &Path, identity: Arc<Identity>) -> std::io::Result<Self> {
        let id = raft5fs_wire::hex(&crate::pruner::new_holder());
        let dir = base.join(format!("{PREFIX}{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, identity })
    }

    /// Removes folders that earlier compactions left in `base`.
    pub fn clean_old(base: &Path) {
        let Ok(list) = std::fs::read_dir(base) else {
            return;
        };
        for e in list.flatten() {
            if e.file_name().to_string_lossy().starts_with(PREFIX) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }

    fn seal(&self, name: &str, bytes: &[u8]) -> Vec<u8> {
        seal_local(&self.identity, name, bytes)
    }

    fn open(&self, name: &str, sealed: &[u8]) -> std::io::Result<Vec<u8>> {
        open_local(&self.identity, name, sealed).map_err(io)
    }

    /// Keeps `bytes` as `name`.
    pub fn put(&self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.dir.join(name), self.seal(name, bytes))
    }

    /// What `put` kept as `name`.
    pub fn get(&self, name: &str) -> std::io::Result<Vec<u8>> {
        let sealed = std::fs::read(self.dir.join(name))?;
        self.open(name, &sealed)
    }

    /// Buckets in this folder.
    pub fn buckets(self: &Arc<Self>) -> DiskBuckets {
        DiskBuckets {
            spill: Arc::clone(self),
            buffers: HashMap::new(),
        }
    }
}

impl Drop for Spill {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `Buckets` on disk: each a file of sealed blocks, each block its length
/// then its bytes.
pub struct DiskBuckets {
    spill: Arc<Spill>,
    buffers: HashMap<u32, Vec<u8>>,
}

impl DiskBuckets {
    fn name(bucket: u32) -> String {
        format!("bucket-{bucket}")
    }

    fn write_block(&self, bucket: u32, plain: &[u8]) -> std::io::Result<()> {
        let name = Self::name(bucket);
        let sealed = self.spill.seal(&name, plain);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.spill.dir.join(&name))?;
        f.write_all(&(sealed.len() as u32).to_le_bytes())?;
        f.write_all(&sealed)
    }
}

impl Buckets for DiskBuckets {
    fn append(&mut self, bucket: u32, bytes: &[u8]) -> std::io::Result<()> {
        let buffer = self.buffers.entry(bucket).or_default();
        buffer.extend_from_slice(bytes);
        if buffer.len() >= BLOCK {
            let full = std::mem::take(buffer);
            self.write_block(bucket, &full)?;
        }
        Ok(())
    }

    fn take(&mut self, bucket: u32) -> std::io::Result<Vec<u8>> {
        let name = Self::name(bucket);
        let path = self.spill.dir.join(&name);
        let mut out = Vec::new();
        if let Ok(mut f) = File::open(&path) {
            let mut all = Vec::new();
            f.read_to_end(&mut all)?;
            let mut at = 0;
            while at + 4 <= all.len() {
                let len = u32::from_le_bytes(all[at..at + 4].try_into().expect("4 bytes")) as usize;
                let block = all
                    .get(at + 4..at + 4 + len)
                    .ok_or_else(|| io("a spill bucket is short"))?;
                out.extend(self.spill.open(&name, block)?);
                at += 4 + len;
            }
            let _ = std::fs::remove_file(&path);
        }
        if let Some(rest) = self.buffers.remove(&bucket) {
            out.extend(rest);
        }
        Ok(out)
    }
}
