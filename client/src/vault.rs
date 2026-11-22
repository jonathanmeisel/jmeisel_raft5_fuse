//! Client-side encryption for the filesystem. The server stores all data,
//! but it must not learn names or file contents, even if it lies.
//!
//! - **Keys.** Each inode has a key, wrapped under its parent's key. The
//!   vault unwraps keys from this account's grant down to the inode, and
//!   keeps them, so it walks each subtree only once.
//! - **Data.** The client seals each chunk under the file's key, so the
//!   server cannot change byte ranges. A partial chunk write is a
//!   read-modify-write, guarded by the chunk's sequence number.
//! - **Names.** Each entry is filed under a tag, an HMAC of its name. The
//!   real name is sealed under the directory's key, and opens only if it
//!   matches its tag.
//! - **Revocation.** Revoking a grant gives the directory a new key at
//!   once. Nodes below it get new keys lazily: they are stale, the server
//!   refuses writes under them (`EKEYEXPIRED`), and `freshen` rotates them.
//!   A revocation also rotates the path down to every grant below, because
//!   those grantees cannot rotate keys above their grant.
//! - **Public keys.** The vault pins a user's key once a person has checked
//!   its fingerprint with them (`KnownKeys`), and refuses a different key
//!   later.
//! - **The root.** A mount shows a virtual root, with one entry for each
//!   grant to this account. Making a directory there makes a new volume. A
//!   label with `/` in it puts its grant in virtual folders (groups), so that
//!   grants from all over the filesystem can sit together (`Roots`).
//!
//! The vault does not trust the server:
//!
//! - It seals keys only to users on the sealed grantee list, never to users
//!   that only the server names.
//! - It reads grants from senders that are not pinned, but seals nothing
//!   under them.
//! - It checks that a looked-up name names the inode that the server
//!   returned.
//! - It refuses key records older than ones it already saw.
//! - It leaves out a name that a writer sealed but no folder could hold.

use futures_util::stream::{FuturesUnordered, StreamExt};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use raft5fs_crypto::Key;
use raft5fs_crypto::data::{
    CHUNK_OVERHEAD, name_tag, open_chunk, open_name, seal_chunk, seal_name, sealed_version,
};
use raft5fs_crypto::grantees::{GranteeEntry, open_grantees, seal_grantees};
use raft5fs_crypto::identity::{
    Identity, PUBLIC_KEY_LEN, fingerprint, fingerprint_matches, grant_sender, label_signer,
    seal_grant, seal_label, seal_signed_label,
};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_crypto::password::new_link_credentials;
use raft5fs_crypto::pins::{PendingInvite, PinEntry, PinList, open_pins, seal_pins};
use raft5fs_proto::errno;
use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{
    Attr, ChunkBody, ChunkWrite, Chunks, DirItem, FsError, Grant, GrantedNode, Grantee, KeyPath,
    LINK_PREFIX, Layout, LinkAccount, NewNode, Rotation, SealedChunk, SealedMove, SetAttr,
    WriteBody, WriteError, check_username,
};

use crate::chunk_cache::{ChunkCache, Lookup};
pub use blocks::Staged;
use blocks::{BlockEdit, Rewritten};
pub use known_keys::KnownKeys;
use roots::Roots;

mod activity;
mod blocks;
mod data;
mod keys;
mod known_keys;
mod merge;
mod namespace;
mod pins;
mod prune;
mod rollback;
mod roots;
mod sharing;
mod trust;
pub use activity::{ActivityLine, ActivityLines, Change};
pub use prune::{GrantRoot, PruneStats};

use crate::remote::Remote;
use crate::store::{MemoryStore, Store};
use raft5fs_proto::since;

/// The inode number that the kernel uses for a mount's root. This is the
/// virtual root, not the server's real root.
pub const VIRTUAL_ROOT: u64 = 1;

/// The first inode number of a group: a virtual folder in the root. Real
/// inodes count up from 1 and never get here, and snapshots' numbers start at
/// `1 << 63`.
const GROUP_BASE: u64 = 1 << 62;

/// Whether `ino` is a group.
pub fn is_group(ino: u64) -> bool {
    (GROUP_BASE..1 << 63).contains(&ino)
}

/// Whether `ino` is only in this client's view of the root: not on the servers.
pub fn is_virtual(ino: u64) -> bool {
    ino == VIRTUAL_ROOT || is_group(ino)
}

/// How many names a label can hold, with its groups. A label comes from whoever
/// shares, so this keeps a careless or forged one from making an absurd tree.
const MAX_LABEL_DEPTH: usize = 8;

/// The root resolves this name, but does not list it.
pub const SNAPSHOT_DIR: &str = ".snapshot";

/// An inode's key record and current key. A directory also has a name key,
/// which makes its entries' tags.
pub struct Node {
    pub record: NodeKeys,
    pub key: Key,
    name_key: Key,
    /// True if this node, or a node above it, is wrapped under an old
    /// version of its parent's key. A revoked user can have that key, so
    /// the vault gives this node a new key (`freshen`) before it seals
    /// anything new under it.
    stale: bool,
    /// The sender of the grant that this node was reached through, if this
    /// account does not trust them (it is not this account, and no key is
    /// pinned for them). See `sealable`.
    untrusted: Option<Arc<Untrusted>>,
}

/// A grant made to this account, as `Vault::shares` lists it.
#[derive(Debug)]
pub struct Share {
    /// The name it shows in the root.
    pub label: OsString,
    pub ino: u64,
    pub writable: bool,
    /// The sender that the grant claims.
    pub sender: String,
    pub trust: ShareTrust,
}

/// Who vouches for a share's label.
enum LabelSource {
    /// This account sealed it.
    Me,
    /// Someone whose key this account checked.
    Checked,
    /// It's signed, by a key that only the servers vouch for.
    Unchecked,
    /// Nobody: anyone could have sealed it.
    Unsigned,
}

/// Whether this account trusts a share's sender.
#[derive(Debug)]
pub enum ShareTrust {
    /// This account, or a user whose key is pinned here.
    Trusted,
    /// Another user whose key is not pinned. `key` is the key that the
    /// server gives for them. The share is read-only until the user pins it
    /// (`Vault::trust`).
    Untrusted { key: [u8; PUBLIC_KEY_LEN] },
    /// The grant does not open.
    Unreadable(FsError),
}

/// A grant's sender, with the public key that the server gives for them.
#[derive(Debug)]
struct Untrusted {
    sender: String,
    key: [u8; PUBLIC_KEY_LEN],
}

impl Node {
    /// Makes the node for `ino` with current key `key`. It fails if `key`
    /// does not open the record's name key, because then `key` is not this
    /// node's key. The node starts fresh and trusted; the caller changes
    /// this if necessary.
    fn new(ino: u64, record: NodeKeys, key: Key) -> Result<Self, FsError> {
        let name_key = record.name_key(ino, &key).map_err(|e| corrupt(ino, e))?;
        Ok(Self {
            record,
            key,
            name_key,
            stale: false,
            untrusted: None,
        })
    }

    /// Fails if the grant above this node comes from an untrusted sender.
    /// The server could have made that grant, and the tree below it, with a
    /// key it knows. Then the server could read anything written there, or
    /// shared from there.
    fn sealable(&self, ino: u64) -> Result<(), FsError> {
        match &self.untrusted {
            None => Ok(()),
            Some(u) => Err(FsError::new(
                errno::EACCES,
                format!(
                    "inode {ino} is shared with this account by {}, whose key isn't pinned \
                     here: the server could have made the share up, so nothing is written \
                     under it. If {} really shared it, ask them for their key's fingerprint, \
                     then: raft5fs trust {} <fingerprint>",
                    u.sender, u.sender, u.sender
                ),
            )),
        }
    }

    /// The tag that `name` is filed under in this directory.
    pub fn tag(&self, name: &OsStr) -> OsString {
        os_bytes::into_name(name_tag(&self.name_key, os_bytes::bytes(name)).to_vec())
    }

    /// Seals `name`, filed under `tag` in directory `ino` and pointing to
    /// inode `child`, under the directory's current key.
    pub fn seal(&self, ino: u64, child: u64, tag: &OsStr, name: &OsStr) -> Vec<u8> {
        seal_name(
            &self.key,
            self.record.version,
            ino,
            child,
            os_bytes::bytes(tag),
            os_bytes::bytes(name),
        )
    }

    /// Opens the name of `child` in this directory, `ino`, sealed as it is
    /// filed under `tag`. It must name `child`.
    fn open_entry(
        &self,
        ino: u64,
        child: u64,
        tag: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, FsError> {
        let version = sealed_version(sealed).map_err(|e| corrupt(ino, e))?;
        let key = self.key_at(ino, version)?;
        open_name(&key, &self.name_key, ino, child, tag, sealed).map_err(|e| corrupt(ino, e))
    }

    /// This node's key at `version`: the current key, or an older key from
    /// the key history.
    fn key_at(&self, ino: u64, version: u32) -> Result<Key, FsError> {
        if version == self.record.version {
            Ok(self.key.clone())
        } else {
            self.record
                .older(ino, &self.key, version)
                .map_err(|e| corrupt(ino, e))
        }
    }
}

/// How many times to try a key rotation again when another client changes
/// the keys at the same time.
const ROTATION_ROUNDS: usize = 16;

fn expired(e: &FsError) -> bool {
    e.errno == raft5fs_proto::errno::EKEYEXPIRED
}

/// Whether another client gave `granted`'s node a new key since this one
/// cached `node`: its sealed grantee list is under a later version.
fn newer_key(node: &Node, granted: &GrantedNode) -> bool {
    !granted.sealed_grantees.is_empty()
        && sealed_version(&granted.sealed_grantees).is_ok_and(|v| v > node.record.version)
}

fn changed(e: &FsError) -> bool {
    e.errno == errno::EAGAIN
}

/// How many times to do a read-modify-write of a chunk again when another
/// writer changes the chunk first. After that, the write fails with
/// `EAGAIN`.
const CHANGE_RETRIES: usize = 32;

/// The part of a write that falls in one chunk: the chunk's index, where in
/// the chunk the part starts, and its length.
type Span = (u64, usize, usize);

/// Splits `[offset, offset + len)` into one span for each chunk (see
/// `Span`).
fn spans(chunk_size: u64, offset: u64, len: usize) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut pos = offset;
    let end = offset + len as u64;
    while pos < end {
        let within = pos % chunk_size;
        let n = (chunk_size - within).min(end - pos);
        spans.push((pos / chunk_size, within as usize, n as usize));
        pos += n;
    }
    spans
}

/// How many object ranges one read fetches at the same time.
const MAX_FETCHES: usize = 8;

/// How many pieces `Vault::prefetch` splits its chunks into, each fetched
/// at the same time as the others.
const PREFETCH_PIECES: u64 = 8;

/// A chunk's sealed bytes from a read, or `None` for a hole. Every read
/// here fetches object-storage segments first (`fetch_segments`), so a
/// segment here is an error. This is also true for a prune, which reads
/// chunks itself.
fn sealed_blob(ino: u64, body: &ChunkBody) -> Result<Option<&[u8]>, FsError> {
    match body {
        ChunkBody::Hole => Ok(None),
        ChunkBody::Inline(blob) => Ok(Some(blob)),
        ChunkBody::Segment { .. } => Err(FsError::new(
            errno::EIO,
            format!("inode {ino}: a chunk in object storage, not fetched"),
        )),
    }
}

/// Whether a name can be one thing in one folder. A writer seals what names
/// they like, and a `/` or a `..` would make a listing say something a path
/// can't, or point somewhere else.
fn good_name(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

/// The names in a label, from the outermost group to the share itself, or
/// `None` if any can't be a name, or there are too many.
fn label_parts(label: &[u8]) -> Option<Vec<OsString>> {
    let parts: Vec<&[u8]> = label.split(|&b| b == b'/').collect();
    (parts.len() <= MAX_LABEL_DEPTH && parts.iter().all(|part| good_name(part))).then(|| {
        parts
            .into_iter()
            .map(|part| os_bytes::into_name(part.to_vec()))
            .collect()
    })
}

fn check_new_label(label: &OsStr) -> Result<Vec<OsString>, FsError> {
    label_parts(os_bytes::bytes(label)).ok_or_else(|| {
        FsError::new(
            errno::EINVAL,
            format!(
                "{label:?} can't be a label: it is up to {MAX_LABEL_DEPTH} names with a / between \
                 them, and a name can't be empty, . or .., or hold a NUL"
            ),
        )
    })
}

fn check_new_name(name: &OsStr) -> Result<(), FsError> {
    if good_name(os_bytes::bytes(name)) {
        return Ok(());
    }
    Err(FsError::new(
        errno::EINVAL,
        format!("{name:?} can't be a name: it can't be empty, . or .., or hold a / or a NUL"),
    ))
}

fn corrupt(ino: u64, e: impl std::fmt::Display) -> FsError {
    FsError::new(errno::EIO, format!("inode {ino}: {e}"))
}

pub struct Vault {
    remote: Arc<Remote>,
    identity: Arc<Identity>,
    known: KnownKeys,
    nodes: Mutex<HashMap<u64, Arc<Node>>>,
    /// The newest key version seen for each inode, kept beside the pins.
    /// Clearing `nodes` does not clear it. See `rollback`.
    versions: Mutex<rollback::Versions>,
    /// Public keys that the server gave for grant senders, by user name.
    senders: Mutex<HashMap<String, [u8; PUBLIC_KEY_LEN]>>,
    /// If true (`with_untrusted_warnings`), print a message once for each
    /// grant from an untrusted sender. `warned` holds the grants already
    /// reported.
    warn_untrusted: bool,
    warned: Mutex<HashSet<u64>>,
    roots: Mutex<Roots>,
    /// Each group's inode, by its names, kept for this vault's life so that
    /// the kernel's stays right when grants come and go.
    group_numbers: Mutex<HashMap<Vec<OsString>, u64>>,
    /// Decrypted chunks, each with the seq it was read or written at. The
    /// snapshot vaults of the same mount share this cache, and each one
    /// uses its own `space` in it.
    cache: Arc<Mutex<ChunkCache>>,
    space: u64,
    /// Each file's layout, kept after the first request (see `layout`).
    layouts: Mutex<HashMap<u64, Layout>>,
    /// What the last merge of the trusted keys said beyond the keys (see
    /// `trust`).
    trust: Mutex<trust::TrustState>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.save_versions(true);
    }
}

/// How much decrypted file data a vault caches by default.
pub const DEFAULT_CACHE_BYTES: usize = 64 << 20;

/// How long a cached chunk can stay unconfirmed before the cache drops it.
/// The vault confirms every cache hit with the server anyway, so this only
/// frees space. The value is large because a dropped chunk costs a full
/// fetch and decrypt, but a confirmation costs only eight bytes.
const CACHE_TTL: Duration = Duration::from_secs(60);

impl Vault {
    /// The vault for `remote`'s account. The account must be logged in.
    pub fn new(remote: Arc<Remote>) -> Result<Self, FsError> {
        let identity = remote
            .identity()
            .ok_or_else(|| FsError::new(errno::EACCES, "not logged in"))?;
        Ok(Self {
            remote,
            identity,
            known: KnownKeys::in_memory(),
            nodes: Mutex::new(HashMap::new()),
            versions: Mutex::default(),
            senders: Mutex::new(HashMap::new()),
            warn_untrusted: false,
            warned: Mutex::new(HashSet::new()),
            roots: Mutex::new(Roots::default()),
            group_numbers: Mutex::default(),
            cache: Arc::new(Mutex::new(ChunkCache::new(DEFAULT_CACHE_BYTES, CACHE_TTL))),
            space: 0,
            layouts: Mutex::new(HashMap::new()),
            trust: Mutex::default(),
        })
    }

    /// Caches up to `bytes` of decrypted file data. 0 disables the cache.
    pub fn with_cache_size(mut self, bytes: usize) -> Self {
        self.cache = Arc::new(Mutex::new(ChunkCache::new(bytes, CACHE_TTL)));
        self
    }

    /// A read-only vault for snapshot `name`: this account's view of the
    /// filesystem at that time. It keeps its own keys, because a snapshot's
    /// key records are as they were then, not as they are now. It uses this
    /// vault's cache under `space`, which must be unique to this snapshot
    /// and not 0.
    pub fn at_snapshot(&self, name: &str, space: u64) -> Self {
        debug_assert_ne!(space, 0, "space 0 is the live filesystem's");
        Self {
            remote: Arc::new(self.remote.at(name)),
            identity: Arc::clone(&self.identity),
            // Who this account checked, for showing shares as it does live.
            // Nothing can be sealed in a snapshot, so this risks nothing.
            known: self.known.memory_copy(),
            nodes: Mutex::new(HashMap::new()),
            versions: Mutex::default(),
            senders: Mutex::new(HashMap::new()),
            warn_untrusted: false,
            warned: Mutex::new(HashSet::new()),
            roots: Mutex::new(Roots::default()),
            group_numbers: Mutex::default(),
            cache: Arc::clone(&self.cache),
            space,
            layouts: Mutex::new(HashMap::new()),
            trust: Mutex::default(),
        }
    }

    /// Prints a message on stderr, once for each grant, when the vault
    /// opens a grant from an untrusted sender. A mount uses this, because
    /// stderr is the only place where it can say why writes there fail.
    pub fn with_untrusted_warnings(mut self) -> Self {
        self.warn_untrusted = true;
        self
    }

    /// Pins public keys in `known`, not only in memory.
    pub fn with_known_keys(mut self, known: KnownKeys) -> Self {
        self.known = known;
        self.load_versions();
        self
    }

    pub fn known_keys(&self) -> &KnownKeys {
        &self.known
    }

    pub fn remote(&self) -> &Arc<Remote> {
        &self.remote
    }

    /// Drops every key unwrapped so far, so the next use fetches it again.
    /// A rotation, here or by another client, can make the kept keys out of
    /// date.
    fn forget_all(&self) {
        self.nodes.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_cover_a_range_chunk_by_chunk() {
        assert_eq!(spans(10, 0, 0), []);
        assert_eq!(spans(10, 3, 4), [(0, 3, 4)]);
        assert_eq!(spans(10, 0, 10), [(0, 0, 10)]);
        assert_eq!(spans(10, 8, 15), [(0, 8, 2), (1, 0, 10), (2, 0, 3)]);
    }
}
