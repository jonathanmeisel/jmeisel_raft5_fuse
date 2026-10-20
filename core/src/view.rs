//! Reading the store as it is now, or as it was at a snapshot.
//!
//! A snapshot (see `snapshots`) pins a moment of the whole store, and the
//! read-only operations can be asked of it instead of the present: every
//! read they make -- the Entry, the dirents, the chunks, and the grants and
//! key records access is decided by -- goes through a `View`, so one asked
//! at a snapshot sees the filesystem exactly as it stood then, consistent
//! with itself whatever has changed since.

use std::future::Future;

use raft5_client::{
    Client, Consistency, Entry, Error as KvError, KeyIterator, Transaction, Version,
};
use raft5_shared::MAX_KEYS_PER_READ;

/// Reading the store, any number of keys at a time. `read_some` and
/// `read_versions_some` are one call each, as the store answers it;
/// everything else is built on them.
pub(crate) trait ReadKeys: Sync {
    /// Up to `MAX_KEYS_PER_READ` keys' entries, in order, all as of one
    /// moment -- possibly only a prefix of them, never an empty one, when
    /// the values would pass the store's budget for one answer.
    fn read_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> impl Future<Output = Result<Vec<Entry>, KvError>> + Send;

    /// Up to `MAX_KEYS_PER_READ` keys' seqs (0 for one with no value), in
    /// order. Never cut short: no value is read.
    fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> impl Future<Output = Result<Vec<u64>, KvError>> + Send;

    /// Every one of `keys`' entries, in order, in as few calls as the
    /// store's limits allow. Each call is one moment, but a read needing
    /// several is several moments unless it is in a transaction or at a
    /// snapshot -- no weaker than reading the keys one at a time.
    fn read_many<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> impl Future<Output = Result<Vec<Entry>, KvError>> + Send {
        async move {
            let mut entries = Vec::with_capacity(keys.len());
            while entries.len() < keys.len() {
                let rest = &keys[entries.len()..];
                let some = self.read_some(&rest[..rest.len().min(MAX_KEYS_PER_READ)]);
                entries.extend(some.await?);
            }
            Ok(entries)
        }
    }

    /// Every one of `keys`' seqs, in order, as `read_many` reads values.
    fn read_versions_many<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> impl Future<Output = Result<Vec<u64>, KvError>> + Send {
        async move {
            let mut seqs = Vec::with_capacity(keys.len());
            for batch in keys.chunks(MAX_KEYS_PER_READ) {
                seqs.extend(self.read_versions_some(batch).await?);
            }
            Ok(seqs)
        }
    }

    /// The snapshot these reads are at, or `None` for the live store.
    fn snapshot(&self) -> Option<&[u8]> {
        None
    }

    /// One key's entry: its value, and the seq it was written at (0 and
    /// no value if it has none).
    fn read_one(&self, key: &[u8]) -> impl Future<Output = Result<Entry, KvError>> + Send {
        async move { Ok(only(self.read_some(&[key]).await?)) }
    }
}

/// The one entry a read of one key answers with. The client refuses an
/// empty answer to a non-empty read, so there always is one.
fn only<T>(mut entries: Vec<T>) -> T {
    entries.pop().expect("a read of one key answers it")
}

fn seqs(versions: Vec<Version>) -> Vec<u64> {
    versions.into_iter().map(|v| v.seq).collect()
}

/// Possibly-stale reads of the live store.
impl ReadKeys for Client {
    async fn read_some<K: AsRef<[u8]> + Sync>(&self, keys: &[K]) -> Result<Vec<Entry>, KvError> {
        Ok(self.read(keys, Consistency::Stale).await?.entries)
    }

    async fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> Result<Vec<u64>, KvError> {
        Ok(seqs(
            self.read_versions(keys, Consistency::Stale).await?.entries,
        ))
    }
}

/// Reads that hold every key for the rest of the transaction.
impl ReadKeys for Transaction {
    async fn read_some<K: AsRef<[u8]> + Sync>(&self, keys: &[K]) -> Result<Vec<Entry>, KvError> {
        Ok(self.read(keys).await?.entries)
    }

    async fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> Result<Vec<u64>, KvError> {
        Ok(seqs(self.read_versions(keys).await?.entries))
    }
}

/// Where reads go: the live store, or snapshot `at`.
#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    client: &'a Client,
    at: Option<&'a [u8]>,
}

impl<'a> View<'a> {
    pub(crate) fn live(client: &'a Client) -> Self {
        Self { client, at: None }
    }

    /// Snapshot `id`, which the caller has checked exists: the store
    /// retries a read at an unknown one until its deadline, rather than
    /// saying so.
    pub(crate) fn at(client: &'a Client, id: &'a [u8]) -> Self {
        Self {
            client,
            at: Some(id),
        }
    }

    pub(crate) fn is_snapshot(&self) -> bool {
        self.at.is_some()
    }

    fn consistency(&self) -> Consistency<'a> {
        match self.at {
            None => Consistency::Stale,
            Some(id) => Consistency::Snapshot(id),
        }
    }

    pub(crate) fn key_iterator(&self, start: &[u8]) -> KeyIterator {
        match self.at {
            None => self.client.key_iterator(start),
            Some(id) => self.client.key_iterator_at(id, start),
        }
    }
}

impl ReadKeys for View<'_> {
    fn snapshot(&self) -> Option<&[u8]> {
        self.at
    }

    async fn read_some<K: AsRef<[u8]> + Sync>(&self, keys: &[K]) -> Result<Vec<Entry>, KvError> {
        Ok(self.client.read(keys, self.consistency()).await?.entries)
    }

    async fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> Result<Vec<u64>, KvError> {
        let read = self.client.read_versions(keys, self.consistency()).await?;
        Ok(seqs(read.entries))
    }
}
