//! Reading the store as it is now, or as it was at a snapshot.
//!
//! A snapshot (see `snapshots`) pins a moment of the whole store, and the
//! read-only operations can be asked of it instead of the present: every
//! read they make -- the Entry, the dirents, the chunks, and the grants and
//! key records access is decided by -- goes through a `View`, so one asked
//! at a snapshot sees the filesystem exactly as it stood then, consistent
//! with itself whatever has changed since.

use raft5_client::{Client, Error as KvError, KeyIterator};

use crate::grants::Reads;

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

    pub(crate) async fn read(&self, key: &[u8]) -> Result<raft5_client::ReadResult, KvError> {
        match self.at {
            None => self.client.read(key).await,
            Some(id) => self.client.read_at(id, key).await,
        }
    }

    pub(crate) async fn get_version(&self, key: &[u8]) -> Result<u64, KvError> {
        match self.at {
            None => self.client.get_version(key).await,
            Some(id) => self.client.get_version_at(id, key).await,
        }
    }

    pub(crate) fn key_iterator(&self, start: &[u8]) -> KeyIterator {
        match self.at {
            None => self.client.key_iterator(start),
            Some(id) => self.client.key_iterator_at(id, start),
        }
    }
}

impl Reads for View<'_> {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self.read(key).await?.value)
    }
}
