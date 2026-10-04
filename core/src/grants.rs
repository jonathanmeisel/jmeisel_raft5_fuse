//! Encrypted filesystems' access control: grants, key records, and the
//! walk that decides whether a user may reach an inode.
//!
//! A user reaches an inode only through a grant of a directory at or above
//! it. `authorize` walks up from the inode through each Entry's `parent`
//! until it finds the nearest directory granted to the user -- whose grant
//! then decides, read-only or read-write -- or reaches the real root, where
//! nothing is granted and access is refused. Operations run it on their
//! own transaction, so the walk's reads and the change they guard commit
//! together: a rename moving the inode out from under the grant, or the
//! grant's removal, conflicts with the operation instead of slipping
//! between the check and the change. (A transaction's reads take shared
//! locks, so walks don't conflict with each other.)
//!
//! Every inode also has a key record (raft5fs-crypto's `NodeKeys`), which
//! the server stores and hands out but can't open; it reads only the two
//! version numbers at its front. A grant holds the granted directory's key
//! sealed to the grantee, so with the records along the way (`key_path`)
//! the grantee can unwrap the key of anything under it.

use std::future::Future;

use raft5_client::{Client, Error as KvError, Transaction};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_proto::types::{FsError, Grant, KeyPath};

use crate::entry::decode_entry;
use crate::layout::{
    GRANT_INDEX_PREFIX, GRANTS_PREFIX, NODE_KEYS_PREFIX, RESERVATION_PREFIX, ROOT_INO, attr_key,
};

/// Deeper than any tree should get; a walk longer than this is a loop in
/// the parent links, which only corruption could make.
const MAX_DEPTH: usize = 4096;

/// Reading a key, whether inside a transaction (taking its lock) or not.
pub(crate) trait Reads: Sync {
    fn get(&self, key: &[u8]) -> impl Future<Output = Result<Option<Vec<u8>>, KvError>> + Send;
}

impl Reads for Client {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self.read(key).await?.value)
    }
}

impl Reads for Transaction {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self.read(key).await?.value)
    }
}

pub(crate) fn grant_key(ino: u64, user: &str) -> Vec<u8> {
    let mut key = grant_prefix(ino);
    key.extend_from_slice(user.as_bytes());
    key
}

/// Every grant of `ino`, whoever to.
pub(crate) fn grant_prefix(ino: u64) -> Vec<u8> {
    let mut key = GRANTS_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

fn index_prefix(user: &str) -> Vec<u8> {
    let mut key = GRANT_INDEX_PREFIX.to_vec();
    key.extend_from_slice(user.as_bytes());
    key.push(0);
    key
}

pub(crate) fn index_key(user: &str, ino: u64) -> Vec<u8> {
    let mut key = index_prefix(user);
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

pub(crate) fn node_keys_key(ino: u64) -> Vec<u8> {
    let mut key = NODE_KEYS_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

pub(crate) fn reservation_key(ino: u64) -> Vec<u8> {
    let mut key = RESERVATION_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// A username that can't be part of the index's keys -- they end at a
/// zero byte -- is refused wherever one would be written.
pub(crate) fn check_username(user: &str) -> Result<(), FsError> {
    if user.is_empty() || user.as_bytes().contains(&0) {
        return Err(FsError::new(libc::EINVAL, format!("bad username {user:?}")));
    }
    Ok(())
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

pub(crate) fn encode_grant(grant: &Grant) -> Vec<u8> {
    let mut out = vec![u8::from(grant.writable)];
    out.extend_from_slice(&grant.key_version.to_be_bytes());
    put(&mut out, &grant.sealed_key);
    put(&mut out, &grant.sealed_label);
    out
}

pub(crate) fn decode_grant(ino: u64, bytes: &[u8]) -> Result<Grant, FsError> {
    let garbled = || {
        FsError::new(
            libc::EIO,
            format!("the grant row of inode {ino} is garbled"),
        )
    };
    let (&writable, rest) = bytes.split_first().ok_or_else(garbled)?;
    let (version, mut rest) = rest.split_at_checked(4).ok_or_else(garbled)?;
    let mut field = || -> Result<Vec<u8>, FsError> {
        let (len, after) = rest.split_at_checked(4).ok_or_else(garbled)?;
        let n = u32::from_be_bytes(len.try_into().unwrap()) as usize;
        let (value, after) = after.split_at_checked(n).ok_or_else(garbled)?;
        rest = after;
        Ok(value.to_vec())
    };
    let sealed_key = field()?;
    let sealed_label = field()?;
    if !rest.is_empty() {
        return Err(garbled());
    }
    Ok(Grant {
        ino,
        writable: writable == 1,
        key_version: u32::from_be_bytes(version.try_into().unwrap()),
        sealed_key,
        sealed_label,
    })
}

/// `(version, parent_version)` of `ino`'s key record, which every inode of
/// an encrypted filesystem has.
pub(crate) async fn key_versions(
    r: &impl Reads,
    ino: u64,
) -> Result<Result<(u32, u32), FsError>, KvError> {
    Ok(match r.get(&node_keys_key(ino)).await? {
        Some(bytes) => NodeKeys::versions(&bytes)
            .map_err(|e| FsError::new(libc::EIO, format!("inode {ino}: {e}"))),
        None => Err(FsError::new(
            libc::EIO,
            format!("inode {ino} has no key record"),
        )),
    })
}

/// The walk from `ino` up to the nearest directory granted to `user`:
/// that grant, and the inodes passed on the way, starting with `ino` and
/// ending with the granted directory. `ENOENT` if `ino` itself doesn't
/// exist; `EACCES` if nothing above it is granted to `user`.
async fn walk(
    r: &impl Reads,
    user: &str,
    ino: u64,
) -> Result<Result<(Grant, Vec<u64>), FsError>, KvError> {
    let refused = || {
        FsError::new(
            libc::EACCES,
            format!("nothing granted to {user} covers inode {ino}"),
        )
    };
    let gone = |cur: u64| {
        if cur == ino {
            FsError::errno(libc::ENOENT)
        } else {
            refused()
        }
    };
    let mut path = Vec::new();
    let mut cur = ino;
    for _ in 0..MAX_DEPTH {
        // The real root is granted to no one: what lies directly under it
        // is the volumes, each reached only by its own grants.
        if cur == ROOT_INO {
            return Ok(Err(refused()));
        }
        let Some(bytes) = r.get(&attr_key(cur)).await? else {
            return Ok(Err(gone(cur)));
        };
        let entry = decode_entry(cur, &bytes);
        if entry.is_deleted() {
            return Ok(Err(gone(cur)));
        }
        path.push(cur);
        if let Some(bytes) = r.get(&grant_key(cur, user)).await? {
            return Ok(decode_grant(cur, &bytes).map(|grant| (grant, path)));
        }
        // A file from before files recorded their parent: no way up.
        if entry.parent == 0 {
            return Ok(Err(refused()));
        }
        cur = entry.parent;
    }
    Ok(Err(FsError::new(
        libc::EIO,
        format!("inode {ino}'s parent links loop"),
    )))
}

/// The grant through which `user` reaches `ino` -- `EACCES` if none does,
/// `EROFS` if `write` is asked of a read-only one.
pub(crate) async fn authorize(
    r: &impl Reads,
    user: &str,
    ino: u64,
    write: bool,
) -> Result<Result<Grant, FsError>, KvError> {
    Ok(match walk(r, user, ino).await? {
        Ok((grant, _)) if write && !grant.writable => Err(FsError::new(
            libc::EROFS,
            format!("inode {ino} is shared with {user} read-only"),
        )),
        Ok((grant, _)) => Ok(grant),
        Err(e) => Err(e),
    })
}

/// What `user` needs to unwrap `ino`'s key: their grant over it and the
/// key records from the granted directory down to `ino`.
pub async fn key_path(client: &Client, user: &str, ino: u64) -> Result<KeyPath, FsError> {
    let (grant, path) = walk(client, user, ino).await??;
    let mut nodes = Vec::with_capacity(path.len());
    for &node in path.iter().rev() {
        let keys = client
            .read(&node_keys_key(node))
            .await?
            .value
            .ok_or_else(|| FsError::new(libc::EIO, format!("inode {node} has no key record")))?;
        nodes.push((node, keys));
    }
    Ok(KeyPath { grant, nodes })
}

/// Every grant made to `user`.
pub async fn list(client: &Client, user: &str) -> Result<Vec<Grant>, FsError> {
    let prefix = index_prefix(user);
    let mut inos = Vec::new();
    let mut iter = client.key_iterator(&prefix);
    while let Some(key) = iter.next().await? {
        if !key.starts_with(&prefix) {
            break;
        }
        if let Ok(ino) = <[u8; 8]>::try_from(&key[prefix.len()..]) {
            inos.push(u64::from_be_bytes(ino));
        }
    }
    let mut grants = Vec::with_capacity(inos.len());
    for ino in inos {
        // Gone between the scan and here: revoked meanwhile.
        if let Some(bytes) = client.read(&grant_key(ino, user)).await?.value {
            grants.push(decode_grant(ino, &bytes)?);
        }
    }
    Ok(grants)
}

/// Writes `grant` of its inode to `user`, with its index entry.
pub(crate) async fn put_grant(txn: &Transaction, user: &str, grant: &Grant) -> Result<(), KvError> {
    txn.write(&grant_key(grant.ino, user), Some(&encode_grant(grant)))
        .await?;
    txn.write(&index_key(user, grant.ino), Some(&[])).await
}

/// Removes every grant of `ino`, and its key record: what goes with an
/// inode when it does.
pub(crate) async fn forget_inode(txn: &Transaction, ino: u64) -> Result<(), KvError> {
    let prefix = grant_prefix(ino);
    let mut users = Vec::new();
    let mut iter = txn.key_iterator(&prefix);
    while let Some(key) = iter.next().await? {
        if !key.starts_with(&prefix) {
            break;
        }
        users.push(String::from_utf8_lossy(&key[prefix.len()..]).into_owned());
    }
    for user in users {
        txn.write(&grant_key(ino, &user), None).await?;
        txn.write(&index_key(&user, ino), None).await?;
    }
    txn.write(&node_keys_key(ino), None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_round_trip_and_garbage_is_eio() {
        let grant = Grant {
            ino: 9,
            writable: true,
            key_version: 3,
            sealed_key: vec![1, 2, 3],
            sealed_label: b"photos".to_vec(),
        };
        let bytes = encode_grant(&grant);
        assert_eq!(decode_grant(9, &bytes).unwrap(), grant);
        for cut in 0..bytes.len() {
            assert_eq!(decode_grant(9, &bytes[..cut]).unwrap_err().errno, libc::EIO);
        }
    }

    #[test]
    fn one_users_index_never_takes_in_anothers() {
        // "al" is a prefix of "alice", but its index prefix isn't of hers.
        assert!(!index_key("alice", 1).starts_with(&index_prefix("al")));
        assert!(index_key("al", 1).starts_with(&index_prefix("al")));
    }

    #[test]
    fn usernames_that_would_break_the_index_are_refused() {
        check_username("alice").unwrap();
        assert!(check_username("").is_err());
        assert!(check_username("a\0b").is_err());
    }
}
