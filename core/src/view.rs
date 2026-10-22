//! Reads the store as it is now, or as it was at a snapshot. A snapshot
//! (see `snapshots`) keeps one moment of the whole store. The read-only
//! operations can read a snapshot in place of the present. Every read they
//! make goes through a `View`: the Entry, the dirents, the chunks, and the
//! grants and key records that control access. So a read at a snapshot sees
//! the filesystem exactly as it was then, consistent with itself, whatever
//! changed after.

use std::future::Future;

use raft5_client::{
    Client, Consistency, Entry, Error as KvError, KeyIterator, Transaction, Version,
};
use raft5_shared::MAX_KEYS_PER_READ;

use crate::timing;

/// Reads the store, any number of keys at a time. `read_some` and
/// `read_versions_some` are each one store call. Everything else is built
/// on them.
pub(crate) trait ReadKeys: Sync {
    /// Reads up to `MAX_KEYS_PER_READ` keys' entries, in order, all from
    /// one moment. If the values would go over the store's limit for one
    /// answer, it can return only the first part of them, but never
    /// nothing.
    fn read_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> impl Future<Output = Result<Vec<Entry>, KvError>> + Send;

    /// Reads up to `MAX_KEYS_PER_READ` keys' seqs (0 for a key with no
    /// value), in order. It reads no values, so it is never cut short.
    fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> impl Future<Output = Result<Vec<u64>, KvError>> + Send;

    /// Reads every one of `keys`' entries, in order, in as few calls as the
    /// store's limits allow. Each call reads one moment. A read that needs
    /// several calls reads several moments, unless it is in a transaction
    /// or at a snapshot. That is no weaker than reading the keys one at a
    /// time.
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

    /// Reads every one of `keys`' seqs, in order, as `read_many` reads
    /// values.
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

    /// Reads one key's entry: its value, and the seq it was written at (0
    /// and no value if it has none).
    fn read_one(&self, key: &[u8]) -> impl Future<Output = Result<Entry, KvError>> + Send {
        async move { Ok(only(self.read_some(&[key]).await?)) }
    }
}

/// The one entry that a read of one key returns. The client refuses an
/// empty answer to a read that is not empty, so there is always one.
fn only<T>(mut entries: Vec<T>) -> T {
    entries.pop().expect("a read of one key answers it")
}

fn seqs(versions: Vec<Version>) -> Vec<u64> {
    versions.into_iter().map(|v| v.seq).collect()
}

/// Reads of the live store, which can be stale.
impl ReadKeys for Client {
    async fn read_some<K: AsRef<[u8]> + Sync>(&self, keys: &[K]) -> Result<Vec<Entry>, KvError> {
        let read = self.read(keys, Consistency::Stale);
        Ok(timing::read(keys.len(), false, read).await?.entries)
    }

    async fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> Result<Vec<u64>, KvError> {
        let read = self.read_versions(keys, Consistency::Stale);
        Ok(seqs(timing::read(keys.len(), true, read).await?.entries))
    }
}

/// Reads that hold every key until the transaction ends.
impl ReadKeys for Transaction {
    async fn read_some<K: AsRef<[u8]> + Sync>(&self, keys: &[K]) -> Result<Vec<Entry>, KvError> {
        let read = self.read(keys);
        Ok(timing::read(keys.len(), false, read).await?.entries)
    }

    async fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> Result<Vec<u64>, KvError> {
        let read = self.read_versions(keys);
        Ok(seqs(timing::read(keys.len(), true, read).await?.entries))
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

    /// Reads at snapshot `id`. The caller must first check that it exists,
    /// because the store retries a read at an unknown snapshot until its
    /// deadline and does not report it.
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
        let read = self.client.read(keys, self.consistency());
        Ok(timing::read(keys.len(), false, read).await?.entries)
    }

    async fn read_versions_some<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> Result<Vec<u64>, KvError> {
        let read = self.client.read_versions(keys, self.consistency());
        Ok(seqs(timing::read(keys.len(), true, read).await?.entries))
    }
}
