//! Access control: grants, key records, and the walk that decides whether a
//! user can reach an inode.
//!
//! **The walk.** A user reaches an inode only through a grant of a
//! directory at or above it. `authorize` walks up from the inode through
//! each Entry's `parent` until it finds the nearest directory granted to
//! the user. That grant then decides: read-only or read-write. If the walk
//! reaches the real root, where nothing is granted, access is refused.
//!
//! - Operations run the walk in their own transaction, so the walk's reads
//!   and the change they protect commit together. A rename that moves the
//!   inode out from under the grant, or a removal of the grant, conflicts
//!   with the operation and cannot happen between the check and the change.
//!   (A transaction's reads take shared locks, so walks do not conflict
//!   with each other.)
//! - A server remembers where each walk went (`Paths`). The next walk from
//!   the same inode reads that whole path at once and checks that a walk
//!   would still go that way, in place of one level at a time. What is
//!   remembered never decides anything: if a grant was removed or a node
//!   moved, the check fails, and the walk continues as if nothing was
//!   remembered.
//!
//! **Keys.** Every inode also has a key record (raft5fs-crypto's
//! `NodeKeys`). The server stores it and gives it out, but cannot open it:
//! it reads only the two version numbers at the start. A grant holds the
//! granted directory's key, sealed to the grantee. With the records along
//! the path (`key_path`), the grantee can unwrap the key of anything below
//! it.
//!
//! **Grantee lists.** Next to a granted node's grants, the server keeps the
//! list of users that its key holders say it is granted to
//! (raft5fs-crypto's `grantees`), sealed under its key. The server cannot
//! read this either. Every change to the grants sends a new list, sealed
//! under the node's current key version. `grants_under` gives it out with
//! the grants, so a client that rotates the key can check the grants
//! against it.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Mutex;

use raft5_client::{Client, Consistency, Error as KvError, Transaction};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_proto::types::{FsError, Grant, GrantedNode, Grantee, KeyPath};

use crate::entry::decode_entry;
use crate::layout::{
    GRANT_INDEX_PREFIX, GRANTEES_PREFIX, GRANTS_PREFIX, NODE_KEYS_PREFIX, RESERVATION_PREFIX,
    ROOT_INO, attr_key,
};
use crate::timing::next_key;
use crate::view::{ReadKeys, View};

/// Deeper than any real tree. A longer walk means a loop in the parent
/// links, which only corruption could make.
const MAX_DEPTH: usize = 4096;

/// How many paths `Paths` holds before it forgets all of them and starts
/// again.
const MAX_PATHS: usize = 1 << 16;

/// Where walks went: for a user and an inode, live or at a snapshot, the
/// path that the last walk from it took up to the user's grant.
///
/// It is only a guess at which keys to read. A walk that finds a path
/// checks every condition that it would check on its way up, against the
/// store, in one read (see `follows`). If any condition fails, it walks on
/// as usual. So an old path (after a grant is made or removed, or a node
/// moves or is removed) costs one read and decides nothing. Nothing here
/// needs to hear about changes, and each server keeps its own.
#[derive(Default)]
pub(crate) struct Paths {
    known: Mutex<HashMap<PathKey, Vec<u64>>>,
}

/// A snapshot (`None` for the live store), a user, and an inode.
type PathKey = (Option<Vec<u8>>, String, u64);

impl Paths {
    fn get(&self, at: Option<&[u8]>, user: &str, ino: u64) -> Option<Vec<u64>> {
        let key = (at.map(<[u8]>::to_vec), user.to_string(), ino);
        self.known.lock().unwrap().get(&key).cloned()
    }

    /// Records `path`, a walk from its first node to the grant, for each
    /// node on it. The rest of the path after a node is that node's own way
    /// up.
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

/// Reads keys' values, in a transaction (taking their locks) or not.
pub(crate) trait Reads: ReadKeys {
    fn get(&self, key: &[u8]) -> impl Future<Output = Result<Option<Vec<u8>>, KvError>> + Send {
        async move { Ok(self.read_one(key).await?.value) }
    }

    /// Reads every one of `keys`' values, in order, in one call where the
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

/// The prefix of every grant of `ino`, to any user.
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

/// The key that holds `ino`'s sealed grantee list.
pub(crate) fn grantees_key(ino: u64) -> Vec<u8> {
    let mut key = GRANTEES_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// Whether `sealed` is a grantee list of `ino` sealed under its key at
/// `version`: the current version, or the version that a rotation is moving
/// it to. A revoked user could have made a list sealed under an older
/// version. The server cannot check what the list says.
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

/// A reservation's value: who it is for, a 0 byte (which no name has), and
/// when it was made, in seconds since the Unix epoch.
pub(crate) fn reservation_value(user: &str, at: u64) -> Vec<u8> {
    let mut value = user.as_bytes().to_vec();
    value.push(0);
    value.extend_from_slice(&at.to_be_bytes());
    value
}

/// Who a reservation is for, and when it was made. Reservations made before
/// they had a time are only the name, and have no time.
pub(crate) fn reservation_parts(value: &[u8]) -> (&[u8], Option<u64>) {
    match value.iter().position(|&b| b == 0) {
        Some(end) => (
            &value[..end],
            value[end + 1..].try_into().ok().map(u64::from_be_bytes),
        ),
        None => (value, None),
    }
}

/// Refuses a username that `raft5fs_proto::types::check_username` does not
/// allow, wherever one would be written or looked up. That check also
/// blocks the zero byte that the index's keys end at.
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

/// Reads `(version, parent_version)` from `ino`'s key record. Every inode
/// of the filesystem has one.
pub(crate) async fn key_versions(
    r: &impl Reads,
    ino: u64,
) -> Result<Result<(u32, u32), FsError>, KvError> {
    Ok(versions_of(ino, r.get(&node_keys_key(ino)).await?))
}

/// The versions in `ino`'s key record, as read.
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

/// Walks from `ino` up to the nearest directory granted to `user`.
///
/// Returns that grant, and the inodes on the way, from `ino` to the granted
/// directory. Returns `ENOENT` if `ino` does not exist, and `EACCES` if
/// nothing above it is granted to `user`.
///
/// It reads one level at a time, except where `paths` knows the way up from
/// a node. Then it checks the rest in one read, and walks only if the check
/// fails.
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
        // The real root is granted to no one. The nodes directly below it
        // are the volumes, and each one is reached only by its own grants.
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
        // Read the grant with the Entry, so each level is one round trip.
        // The grant counts only if the Entry exists.
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
        // No parent is recorded, so there is no way up.
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

/// Returns the grant at the top of `path` if a walk from its first node
/// would follow `path` to it now. It reads, in one go, the same keys that
/// the walk would read, and checks:
///
/// - every node exists and is not being deleted;
/// - each node is a child of the next;
/// - only the last node is granted to `user`, and it is granted.
///
/// Returns `None` if anything is different, so the walk finds out what
/// changed.
async fn follows(r: &impl Reads, user: &str, path: &[u64]) -> Result<Option<Grant>, KvError> {
    let keys: Vec<Vec<u8>> = path
        .iter()
        .flat_map(|&node| [attr_key(node), grant_key(node, user)])
        .collect();
    let values = r.get_many(&keys).await?;
    for (i, (&node, level)) in path.iter().zip(values.as_chunks::<2>().0).enumerate() {
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

/// The grant through which `user` reaches `ino`. Returns `EACCES` if there
/// is none, and `EROFS` if `write` is asked of a read-only grant.
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

/// Checks that every node from `ino` up to its volume is wrapped under its
/// parent's current key. If not, returns `EKEYEXPIRED` and names the first
/// node that is not. A revoked user can still have a stale node's key (see
/// raft5fs-crypto's `node`). So nothing new can be sealed under the node,
/// or under anything below it, until it gets a new key.
pub(crate) async fn check_fresh(r: &impl Reads, ino: u64) -> Result<Result<(), FsError>, KvError> {
    // Each level reads a node's Entry and key record together. A node's key
    // version is what the node below it should be wrapped under, so that
    // check happens one level later, with `below`: the node below, and the
    // version of this node's key that wraps it.
    let mut below: Option<(u64, u32)> = None;
    let mut cur = ino;
    for _ in 0..MAX_DEPTH {
        if cur == ROOT_INO {
            // The real root has a key record, but no Entry to check it
            // against. Only the node below it needs the comparison.
            let Some(child) = below else {
                return Ok(Ok(()));
            };
            return Ok(versions_of(cur, r.get(&node_keys_key(cur)).await?)
                .and_then(|(version, _)| check_wrapped(child, version)));
        }
        let [entry, keys] = two(r.get_many(&[attr_key(cur), node_keys_key(cur)]).await?);
        // The node itself must exist before its key record matters. A
        // parent's key record is checked against its child first, as if
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

/// Checks that `child`, wrapped under the given version of its parent's
/// key, is wrapped under `parent_version`, the current version.
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

/// The two values that a read of two keys returned, in order.
fn two(values: Vec<Option<Vec<u8>>>) -> [Option<Vec<u8>>; 2] {
    values.try_into().expect("a read of two keys answers both")
}

/// Every node at or below `top` that is granted to anyone, with the path
/// from `top` down to it and its grantees. Each grantee has their public
/// key as the server has it, or an empty key if they no longer have keys.
pub async fn grants_under(client: &Client, top: u64) -> Result<Vec<GrantedNode>, FsError> {
    let mut keys = Vec::new();
    let mut iter = client.key_iterator(GRANTS_PREFIX, Consistency::Stale);
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
        // Removed after the scan saw it: revoked in the meantime.
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
/// below `top`.
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

/// Every grant of `ino`, by grantee, as `txn` sees it. Each one is locked
/// against changes until the transaction ends.
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

/// Removes `user`'s grant of `ino` and its index entry.
pub(crate) async fn remove_grant(txn: &Transaction, user: &str, ino: u64) -> Result<(), KvError> {
    txn.write(&grant_key(ino, user), None).await?;
    txn.write(&index_key(user, ino), None).await?;
    crate::accounts::drop_unused_link(txn, user).await
}

/// What `user` needs to unwrap `ino`'s key: their grant above it, and the
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
        // Removed between the scan and here: revoked in the meantime.
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

/// Removes every grant of `ino` and its key record, when the inode is
/// removed.
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
        remove_grant(txn, &user, ino).await?;
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
        // "al" is a prefix of "alice", but its index prefix is not a prefix
        // of alice's.
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
