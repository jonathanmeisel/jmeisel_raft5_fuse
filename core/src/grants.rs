//! Access control: grants, key records, and the
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
//! A server remembers where each walk went (`Paths`), and the next from
//! the same inode reads that whole path at once, checking it is still the
//! way a walk would go, instead of a level at a time. What is remembered
//! never decides anything: a grant taken back, or a node moved, fails the
//! check, and the walk goes on as if nothing had been remembered.
//!
//! Every inode also has a key record (raft5fs-crypto's `NodeKeys`), which
//! the server stores and hands out but can't open; it reads only the two
//! version numbers at its front. A grant holds the granted directory's key
//! sealed to the grantee, so with the records along the way (`key_path`)
//! the grantee can unwrap the key of anything under it.
//!
//! Beside a granted node's grants the server keeps who its key holders say
//! it is granted to (raft5fs-crypto's `grantees`), sealed under its key,
//! which it can't read either. Every change to the grants brings a new one
//! sealed under the node's current key version, and `grants_under` hands
//! it out with the grants, for a rotating client to check them against.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Mutex;

use raft5_client::{Client, Error as KvError, Transaction};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_proto::types::{FsError, Grant, GrantedNode, Grantee, KeyPath};

use crate::entry::decode_entry;
use crate::layout::{
    GRANT_INDEX_PREFIX, GRANTEES_PREFIX, GRANTS_PREFIX, NODE_KEYS_PREFIX, RESERVATION_PREFIX,
    ROOT_INO, attr_key,
};
use crate::timing::next_key;
use crate::view::{ReadKeys, View};

/// Deeper than any tree should get; a walk longer than this is a loop in
/// the parent links, which only corruption could make.
const MAX_DEPTH: usize = 4096;

/// How many paths `Paths` holds before it forgets them all and starts
/// again.
const MAX_PATHS: usize = 1 << 16;

/// Where walks have gone: for a user and an inode, live or at a snapshot,
/// the path the last walk from it took up to the user's grant.
///
/// Only ever a guess at which keys to read. A walk that finds one checks
/// every condition it would have checked on its way up against the store,
/// in one read (see `follows`), and walks on as usual if any fails -- so
/// a path out of date, after a grant is revoked or made or a node moves
/// or goes, costs a read and decides nothing. Nothing here needs telling
/// about a change, and each server keeps its own.
#[derive(Default)]
pub(crate) struct Paths {
    known: Mutex<HashMap<PathKey, Vec<u64>>>,
}

/// A snapshot (`None` for the live store), a user and an inode.
type PathKey = (Option<Vec<u8>>, String, u64);

impl Paths {
    fn get(&self, at: Option<&[u8]>, user: &str, ino: u64) -> Option<Vec<u64>> {
        let key = (at.map(<[u8]>::to_vec), user.to_string(), ino);
        self.known.lock().unwrap().get(&key).cloned()
    }

    /// Records `path`, a walk's from its first node to the grant, for each
    /// node on it: what is left of it is that node's own way up.
    fn remember(&self, at: Option<&[u8]>, user: &str, path: &[u64]) {
        let mut known = self.known.lock().unwrap();
        if known.len() + path.len() > MAX_PATHS {
            known.clear();
        }
        for i in 0..path.len() {
            let key = (at.map(<[u8]>::to_vec), user.to_string(), path[i]);
            known.insert(key, path[i..].to_vec());
        }
    }

    fn forget(&self, at: Option<&[u8]>, user: &str, ino: u64) {
        let key = (at.map(<[u8]>::to_vec), user.to_string(), ino);
        self.known.lock().unwrap().remove(&key);
    }
}

/// Reading keys' values, whether inside a transaction (taking their
/// locks) or not.
pub(crate) trait Reads: ReadKeys {
    fn get(&self, key: &[u8]) -> impl Future<Output = Result<Option<Vec<u8>>, KvError>> + Send {
        async move { Ok(self.read_one(key).await?.value) }
    }

    /// Every one of `keys`' values, in order, in one call where the
    /// store's limits allow.
    fn get_many<K: AsRef<[u8]> + Sync>(
        &self,
        keys: &[K],
    ) -> impl Future<Output = Result<Vec<Option<Vec<u8>>>, KvError>> + Send {
        async move {
            let entries = self.read_many(keys).await?;
            Ok(entries.into_iter().map(|e| e.value).collect())
        }
    }
}

impl<T: ReadKeys> Reads for T {}

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

pub(crate) fn index_prefix(user: &str) -> Vec<u8> {
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

/// Where `ino`'s sealed grantee list is kept.
pub(crate) fn grantees_key(ino: u64) -> Vec<u8> {
    let mut key = GRANTEES_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// Whether `sealed` is a grantee list of `ino` sealed under its key at
/// `version` -- the current one, or the one a rotation is moving it to:
/// one sealed under an older version is one someone revoked could have
/// made. (What it says, the server can't check.)
pub(crate) fn check_grantees_version(ino: u64, sealed: &[u8], version: u32) -> Result<(), FsError> {
    if raft5fs_crypto::data::sealed_version(sealed).ok() == Some(version) {
        Ok(())
    } else {
        Err(FsError::new(
            raft5fs_proto::errno::EKEYEXPIRED,
            format!("inode {ino}'s grantee list must be sealed under key version {version}"),
        ))
    }
}

pub(crate) fn reservation_key(ino: u64) -> Vec<u8> {
    let mut key = RESERVATION_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// A username outside `raft5fs_proto::types::check_username` -- which
/// also keeps out the zero byte the index's keys end at -- is refused
/// wherever one would be written or looked up.
pub(crate) fn check_username(user: &str) -> Result<(), FsError> {
    raft5fs_proto::types::check_username(user)
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
/// the filesystem has.
pub(crate) async fn key_versions(
    r: &impl Reads,
    ino: u64,
) -> Result<Result<(u32, u32), FsError>, KvError> {
    Ok(versions_of(ino, r.get(&node_keys_key(ino)).await?))
}

/// The versions `ino`'s key record, as read, holds.
pub(crate) fn versions_of(ino: u64, record: Option<Vec<u8>>) -> Result<(u32, u32), FsError> {
    match record {
        Some(bytes) => NodeKeys::versions(&bytes)
            .map_err(|e| FsError::new(libc::EIO, format!("inode {ino}: {e}"))),
        None => Err(FsError::new(
            libc::EIO,
            format!("inode {ino} has no key record"),
        )),
    }
}

/// The walk from `ino` up to the nearest directory granted to `user`:
/// that grant, and the inodes passed on the way, starting with `ino` and
/// ending with the granted directory. `ENOENT` if `ino` itself doesn't
/// exist; `EACCES` if nothing above it is granted to `user`.
///
/// One read a level, except where `paths` knows the way on from a node:
/// then the rest is checked in one read, and walked only if it fails.
async fn walk(
    r: &impl Reads,
    paths: &Paths,
    user: &str,
    ino: u64,
) -> Result<Result<(Grant, Vec<u64>), FsError>, KvError> {
    let at = r.snapshot();
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
        if let Some(known) = paths.get(at, user, cur) {
            if let Some(grant) = follows(r, user, &known).await? {
                path.extend_from_slice(&known);
                paths.remember(at, user, &path);
                return Ok(Ok((grant, path)));
            }
            paths.forget(at, user, cur);
        }
        // The grant is only looked at if the Entry is there, but read
        // with it: one round trip a level.
        let [entry, grant] = two(r.get_many(&[attr_key(cur), grant_key(cur, user)]).await?);
        let Some(bytes) = entry else {
            return Ok(Err(gone(cur)));
        };
        let entry = decode_entry(cur, &bytes);
        if entry.is_deleted() {
            return Ok(Err(gone(cur)));
        }
        path.push(cur);
        if let Some(bytes) = grant {
            let grant = decode_grant(cur, &bytes);
            if grant.is_ok() {
                paths.remember(at, user, &path);
            }
            return Ok(grant.map(|grant| (grant, path)));
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

/// The grant at the top of `path` if a walk from its first node would
/// take `path` to it now -- every node there and not being deleted, each
/// the child of the next, none granted to `user` but the last, and that
/// one granted -- read in one go, the very keys the walk would read.
/// `None` if anything is otherwise, for the walk to find out what.
async fn follows(r: &impl Reads, user: &str, path: &[u64]) -> Result<Option<Grant>, KvError> {
    let keys: Vec<Vec<u8>> = path
        .iter()
        .flat_map(|&node| [attr_key(node), grant_key(node, user)])
        .collect();
    let values = r.get_many(&keys).await?;
    for (i, (&node, level)) in path.iter().zip(values.chunks_exact(2)).enumerate() {
        let Some(bytes) = &level[0] else {
            return Ok(None);
        };
        let entry = decode_entry(node, bytes);
        if node == ROOT_INO || entry.is_deleted() {
            return Ok(None);
        }
        match (&level[1], path.get(i + 1)) {
            (Some(grant), None) => return Ok(decode_grant(node, grant).ok()),
            (None, Some(&next)) if entry.parent == next && next != 0 => {}
            _ => return Ok(None),
        }
    }
    Ok(None)
}

/// The grant through which `user` reaches `ino` -- `EACCES` if none does,
/// `EROFS` if `write` is asked of a read-only one.
pub(crate) async fn authorize(
    r: &impl Reads,
    paths: &Paths,
    user: &str,
    ino: u64,
    write: bool,
) -> Result<Result<Grant, FsError>, KvError> {
    Ok(match walk(r, paths, user, ino).await? {
        Ok((grant, _)) if write && !grant.writable => Err(FsError::new(
            libc::EROFS,
            format!("inode {ino} is shared with {user} read-only"),
        )),
        Ok((grant, _)) => Ok(grant),
        Err(e) => Err(e),
    })
}

/// Whether every node from `ino` up to its volume is wrapped under its
/// parent's current key -- `EKEYEXPIRED`, naming the first that isn't, if
/// not. A stale node's key is one someone revoked may still hold (see
/// raft5fs-crypto's `node`), so nothing new may be sealed under it, nor
/// under anything below it, until it has a new one.
pub(crate) async fn check_fresh(r: &impl Reads, ino: u64) -> Result<Result<(), FsError>, KvError> {
    // Each level reads a node's Entry and key record together. Its key
    // version is what the node below it was to be wrapped under, so that
    // is checked a level late, by `below`: the node, and the version of
    // this one's key it is wrapped under.
    let mut below: Option<(u64, u32)> = None;
    let mut cur = ino;
    for _ in 0..MAX_DEPTH {
        if cur == ROOT_INO {
            // The real root has a key record but is no one's to check
            // against an Entry: only the node below it needs comparing.
            let Some(child) = below else {
                return Ok(Ok(()));
            };
            return Ok(versions_of(cur, r.get(&node_keys_key(cur)).await?)
                .and_then(|(version, _)| check_wrapped(child, version)));
        }
        let [entry, keys] = two(r.get_many(&[attr_key(cur), node_keys_key(cur)]).await?);
        // The node itself must exist before its key record matters; a
        // parent's key record is checked against its child first, as when
        // each was read in turn.
        if below.is_none() && entry.is_none() {
            return Ok(Err(FsError::errno(libc::ENOENT)));
        }
        let (version, wrapped_under) = match versions_of(cur, keys) {
            Ok(versions) => versions,
            Err(e) => return Ok(Err(e)),
        };
        if let Some(child) = below
            && let Err(e) = check_wrapped(child, version)
        {
            return Ok(Err(e));
        }
        let Some(bytes) = entry else {
            return Ok(Err(FsError::errno(libc::ENOENT)));
        };
        // A volume's root: no parent key wraps it.
        if wrapped_under == 0 {
            return Ok(Ok(()));
        }
        below = Some((cur, wrapped_under));
        cur = decode_entry(cur, &bytes).parent;
    }
    Ok(Err(FsError::new(
        libc::EIO,
        format!("inode {ino}'s parent links loop"),
    )))
}

/// Whether `child`, wrapped under the given version of its parent's key,
/// is wrapped under `parent_version`, the current one.
fn check_wrapped((child, wrapped_under): (u64, u32), parent_version: u32) -> Result<(), FsError> {
    if wrapped_under == parent_version {
        Ok(())
    } else {
        Err(FsError::new(
            raft5fs_proto::errno::EKEYEXPIRED,
            format!(
                "inode {child} needs a new key: it is wrapped under an old one of its parent's"
            ),
        ))
    }
}

/// The two values a read of two keys gave, in order.
fn two(values: Vec<Option<Vec<u8>>>) -> [Option<Vec<u8>>; 2] {
    values.try_into().expect("a read of two keys answers both")
}

/// Every node at or under `top` that is granted to anyone, with the path
/// from `top` down to it and its grantees -- each with their public key as
/// the server has it, empty for one who no longer has keys.
pub async fn grants_under(client: &Client, top: u64) -> Result<Vec<GrantedNode>, FsError> {
    let mut keys = Vec::new();
    let mut iter = client.key_iterator(GRANTS_PREFIX);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(GRANTS_PREFIX) {
            break;
        }
        if key.len() >= 9 {
            keys.push(key);
        }
    }
    let mut by_ino: BTreeMap<u64, Vec<(String, bool)>> = BTreeMap::new();
    for (key, bytes) in keys.iter().zip(client.get_many(&keys).await?) {
        // Gone since the scan saw it: revoked meanwhile.
        let Some(bytes) = bytes else {
            continue;
        };
        let ino = u64::from_be_bytes(key[1..9].try_into().unwrap());
        let user = String::from_utf8_lossy(&key[9..]).into_owned();
        let writable = decode_grant(ino, &bytes)?.writable;
        by_ino.entry(ino).or_default().push((user, writable));
    }
    let mut under = Vec::new();
    for (ino, grants) in by_ino {
        if let Some(path) = path_from(client, top, ino).await? {
            under.push((ino, path, grants));
        }
    }

    let users: Vec<&str> = under
        .iter()
        .flat_map(|(_, _, grants)| grants.iter().map(|(user, _)| user.as_str()))
        .collect();
    let mut accounts = crate::accounts::get_many(client, &users).await?.into_iter();
    let listed_keys: Vec<Vec<u8>> = under.iter().map(|&(ino, ..)| grantees_key(ino)).collect();
    let listed = client.read_many(&listed_keys).await?;
    let mut nodes = Vec::with_capacity(under.len());
    for ((ino, path, grants), listed) in under.into_iter().zip(listed) {
        let grantees = grants
            .into_iter()
            .zip(accounts.by_ref())
            .map(|((user, writable), keys)| Grantee {
                user,
                public_key: keys.map(|keys| keys.public_key).unwrap_or_default(),
                writable,
            })
            .collect();
        nodes.push(GrantedNode {
            ino,
            path,
            grantees,
            sealed_grantees: listed.value.unwrap_or_default(),
            grantees_seq: listed.seq,
        });
    }
    Ok(nodes)
}

/// The inodes from `top` down to `ino`, both included, if `ino` is at or
/// under `top`.
async fn path_from(client: &Client, top: u64, ino: u64) -> Result<Option<Vec<u64>>, FsError> {
    let mut path = vec![ino];
    let mut cur = ino;
    for _ in 0..MAX_DEPTH {
        if cur == top {
            path.reverse();
            return Ok(Some(path));
        }
        if cur == ROOT_INO {
            return Ok(None);
        }
        let Some(bytes) = client.read_one(&attr_key(cur)).await?.value else {
            return Ok(None);
        };
        cur = decode_entry(cur, &bytes).parent;
        if cur == 0 {
            return Ok(None);
        }
        path.push(cur);
    }
    Ok(None)
}

/// Every grant of `ino`, by grantee, as `txn` sees it -- holding each
/// against change until it ends.
pub(crate) async fn grants_of(
    txn: &Transaction,
    ino: u64,
) -> Result<BTreeMap<String, Grant>, KvError> {
    let prefix = grant_prefix(ino);
    let mut keys = Vec::new();
    let mut iter = txn.key_iterator(&prefix);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(&prefix) {
            break;
        }
        keys.push(key);
    }
    let mut grants = BTreeMap::new();
    for (key, bytes) in keys.iter().zip(txn.get_many(&keys).await?) {
        if let Some(bytes) = bytes
            && let Ok(grant) = decode_grant(ino, &bytes)
        {
            grants.insert(
                String::from_utf8_lossy(&key[prefix.len()..]).into_owned(),
                grant,
            );
        }
    }
    Ok(grants)
}

/// Removes `user`'s grant of `ino`, with its index entry.
pub(crate) async fn remove_grant(txn: &Transaction, user: &str, ino: u64) -> Result<(), KvError> {
    txn.write(&grant_key(ino, user), None).await?;
    txn.write(&index_key(user, ino), None).await
}

/// What `user` needs to unwrap `ino`'s key: their grant over it and the
/// key records from the granted directory down to `ino`, as `view` has
/// them.
pub(crate) async fn key_path(
    view: &View<'_>,
    paths: &Paths,
    user: &str,
    ino: u64,
) -> Result<KeyPath, FsError> {
    let (grant, mut path) = walk(view, paths, user, ino).await??;
    path.reverse();
    let records: Vec<Vec<u8>> = path.iter().map(|&node| node_keys_key(node)).collect();
    let mut nodes = Vec::with_capacity(path.len());
    for (node, keys) in path.into_iter().zip(view.get_many(&records).await?) {
        let keys =
            keys.ok_or_else(|| FsError::new(libc::EIO, format!("inode {node} has no key record")))?;
        nodes.push((node, keys));
    }
    Ok(KeyPath { grant, nodes })
}

/// Every grant made to `user`, as `view` has them.
pub(crate) async fn list(view: &View<'_>, user: &str) -> Result<Vec<Grant>, FsError> {
    let prefix = index_prefix(user);
    let mut inos = Vec::new();
    let mut iter = view.key_iterator(&prefix);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(&prefix) {
            break;
        }
        if let Ok(ino) = <[u8; 8]>::try_from(&key[prefix.len()..]) {
            inos.push(u64::from_be_bytes(ino));
        }
    }
    let keys: Vec<Vec<u8>> = inos.iter().map(|&ino| grant_key(ino, user)).collect();
    let mut grants = Vec::with_capacity(inos.len());
    for (ino, bytes) in inos.into_iter().zip(view.get_many(&keys).await?) {
        // Gone between the scan and here: revoked meanwhile.
        if let Some(bytes) = bytes {
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
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(&prefix) {
            break;
        }
        users.push(String::from_utf8_lossy(&key[prefix.len()..]).into_owned());
    }
    for user in users {
        txn.write(&grant_key(ino, &user), None).await?;
        txn.write(&index_key(&user, ino), None).await?;
    }
    txn.write(&grantees_key(ino), None).await?;
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
        assert!(check_username("a\nb").is_err());
    }
}
