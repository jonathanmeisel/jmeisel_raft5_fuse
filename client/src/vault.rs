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
//! - **Public keys.** The vault pins each user's key the first time it sees
//!   it (`KnownKeys`), and refuses a different key later.
//! - **The root.** A mount shows a virtual root, with one entry for each
//!   grant to this account. Making a directory there makes a new volume.
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
    Identity, PUBLIC_KEY_LEN, fingerprint, fingerprint_matches, fingerprint_words, grant_sender,
    seal_grant, seal_label,
};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_crypto::password::new_link_credentials;
use raft5fs_proto::errno;
use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{
    Attr, ChunkBody, ChunkWrite, Chunks, DirItem, FsError, Grant, GrantedNode, Grantee, KeyPath,
    Layout, LinkAccount, NewNode, Rotation, SealedChunk, SealedMove, SetAttr, WriteBody,
    WriteError, check_username,
};

use crate::chunk_cache::{ChunkCache, Lookup};
use blocks::{BlockEdit, Rewritten};

mod blocks;
mod prune;
pub use prune::{GrantRoot, PruneStats};

use crate::remote::Remote;
use crate::store::{MemoryStore, Store};

/// The inode number that the kernel uses for a mount's root. This is the
/// virtual root, not the server's real root.
pub const VIRTUAL_ROOT: u64 = 1;

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
                     under it. If {} really shared it, check their key's fingerprint ({}) \
                     with them, then: raft5fs-share trust {} <fingerprint>",
                    u.sender,
                    u.sender,
                    fingerprint_words(&u.key),
                    u.sender
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

/// Public keys that this account sealed to, by user. The server could give
/// its own key in place of a user's key, so the vault trusts the first key
/// it sees for a user and refuses a different key later. It keeps the keys
/// in memory and in a blob of a `Store` (one `user hex-key` line for each
/// user; natively, a file readable only by its owner).
///
/// The names come from the server, so the vault checks each one
/// (`check_username`) before it writes it to the blob. A name with a line
/// break could otherwise add a line that pins a key for a different user.
pub struct KnownKeys {
    keys: Mutex<HashMap<String, [u8; PUBLIC_KEY_LEN]>>,
    store: Arc<dyn Store>,
    name: String,
}

impl KnownKeys {
    /// Pins kept only in memory, forgotten when the last handle drops.
    pub fn in_memory() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            store: Arc::new(MemoryStore::new()),
            name: "known_keys".into(),
        }
    }

    /// Loads the keys pinned in blob `name` of `store`, which does not have
    /// to exist yet. New pins go into the same blob. A bad line, or a
    /// second key for the same user, makes the whole blob fail: this code
    /// did not write that blob, and it cannot know which key is correct.
    pub fn open(store: Arc<dyn Store>, name: &str) -> std::io::Result<Self> {
        let keys = read_pins(store.as_ref(), name)?;
        Ok(Self {
            keys: Mutex::new(keys),
            store,
            name: name.to_string(),
        })
    }

    /// Loads the keys pinned in `file`, which does not have to exist yet,
    /// as `open` does.
    #[cfg(unix)]
    pub fn load(file: std::path::PathBuf) -> std::io::Result<Self> {
        let bad = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} isn't a file name this can use", file.display()),
            )
        };
        let name = file.file_name().and_then(|n| n.to_str()).ok_or_else(bad)?;
        let dir = file.parent().ok_or_else(bad)?.to_path_buf();
        Self::open(Arc::new(crate::store::FileStore::new(dir)), name)
    }

    /// Another handle on the same pins and the same store. A pin that one
    /// handle adds later reaches the other handle through the store.
    pub fn duplicate(&self) -> Self {
        Self {
            keys: Mutex::new(self.keys.lock().unwrap().clone()),
            store: Arc::clone(&self.store),
            name: self.name.clone(),
        }
    }

    fn lock_name(&self) -> String {
        format!("{}.lock", self.name)
    }

    /// The key pinned for `user`, if there is one. If no key is known in
    /// memory, this reads the store again, because `raft5fs trust` can add
    /// a pin while a mount runs. If the blob is now bad, this adds nothing.
    pub fn pinned(&self, user: &str) -> Option<[u8; PUBLIC_KEY_LEN]> {
        let mut keys = self.keys.lock().unwrap();
        if let Some(key) = keys.get(user) {
            return Some(*key);
        }
        let key = *read_pins(self.store.as_ref(), &self.name).ok()?.get(user)?;
        keys.insert(user.to_string(), key);
        Some(key)
    }

    /// Checks `key` against the key pinned for `user`.
    ///
    /// - Returns `key` if it matches the pin.
    /// - If no key is pinned, pins `key` (also in the store) and returns
    ///   it.
    /// - Returns `EPERM` if a different key is pinned, and `EIO` if `key`
    ///   has the wrong length.
    pub fn check(&self, user: &str, key: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        let key: [u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| FsError::new(errno::EIO, format!("{user}'s public key is malformed")))?;
        // Another process could have pinned this user in the store.
        self.pinned(user);
        let mut keys = self.keys.lock().unwrap();
        match keys.get(user) {
            Some(pinned) if *pinned == key => Ok(key),
            Some(pinned) => Err(FsError::new(
                errno::EPERM,
                format!(
                    "the server gave a different key for {user} than before ({} now, {} pinned); \
                     if they enrolled again, check the new fingerprint with them and forget the old",
                    fingerprint(&key),
                    fingerprint(pinned)
                ),
            )),
            None => {
                self.append_pin(user, &key).map_err(|e| {
                    FsError::new(
                        errno::EIO,
                        format!(
                            "cannot pin {user}'s key in {}: {e}",
                            self.store.location(&self.name)
                        ),
                    )
                })?;
                keys.insert(user.to_string(), key);
                Ok(key)
            }
        }
    }

    /// Adds a `user key` line to the blob, under the store's lock so that
    /// another process's pin made at the same time is kept.
    fn append_pin(&self, user: &str, key: &[u8]) -> std::io::Result<()> {
        crate::store::locked(self.store.as_ref(), &self.lock_name(), || {
            let mut data = self.store.load(&self.name)?.unwrap_or_default();
            if !data.is_empty() && !data.ends_with(b"\n") {
                data.push(b'\n');
            }
            data.extend_from_slice(format!("{user} {}\n", to_hex(key)).as_bytes());
            self.store.save(&self.name, &data)
        })
    }

    /// Every pinned key, by user name, sorted by name.
    pub fn entries(&self) -> Vec<(String, [u8; PUBLIC_KEY_LEN])> {
        let mut entries: Vec<_> = self
            .keys
            .lock()
            .unwrap()
            .iter()
            .map(|(user, key)| (user.clone(), *key))
            .collect();
        entries.sort();
        entries
    }

    /// Removes `user`'s pinned key, so the vault trusts the next key it
    /// sees for them.
    pub fn forget(&self, user: &str) -> std::io::Result<()> {
        check_username(user).map_err(|e| std::io::Error::other(e.message))?;
        let mut keys = self.keys.lock().unwrap();
        crate::store::locked(self.store.as_ref(), &self.lock_name(), || {
            // Keep pins that another process added since this one loaded.
            if let Ok(stored) = read_pins(self.store.as_ref(), &self.name) {
                for (other, key) in stored {
                    keys.entry(other).or_insert(key);
                }
            }
            keys.remove(user);
            let mut users: Vec<_> = keys.iter().collect();
            users.sort();
            let text: String = users
                .into_iter()
                .map(|(user, key)| format!("{user} {}\n", to_hex(key)))
                .collect();
            self.store.save(&self.name, text.as_bytes())
        })
    }
}

/// Reads the pins in blob `name`. A missing blob has no pins. A bad line,
/// or a second key for the same user, makes the whole blob fail.
fn read_pins(
    store: &dyn Store,
    name: &str,
) -> std::io::Result<HashMap<String, [u8; PUBLIC_KEY_LEN]>> {
    let bad = |n: usize, why: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} line {}: {why}", store.location(name), n + 1),
        )
    };
    let mut keys = HashMap::new();
    let Some(data) = store.load(name)? else {
        return Ok(keys);
    };
    let text = String::from_utf8(data).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: not text", store.location(name)),
        )
    })?;
    for (n, line) in text.lines().enumerate() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (user, hex) = match fields.as_slice() {
            [] => continue,
            [user, hex] => (*user, *hex),
            _ => return Err(bad(n, "not a user name and a key")),
        };
        check_username(user).map_err(|e| bad(n, &e.message))?;
        let key = from_hex(hex).ok_or_else(|| bad(n, "not a public key"))?;
        if keys.insert(user.to_string(), key).is_some_and(|k| k != key) {
            return Err(bad(n, &format!("a second, different key for {user}")));
        }
    }
    Ok(keys)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(hex: &str) -> Option<[u8; PUBLIC_KEY_LEN]> {
    if hex.len() != PUBLIC_KEY_LEN * 2 {
        return None;
    }
    let mut out = [0; PUBLIC_KEY_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
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

fn corrupt(ino: u64, e: impl std::fmt::Display) -> FsError {
    FsError::new(errno::EIO, format!("inode {ino}: {e}"))
}

/// The grants this account has, by the names they show in the root.
#[derive(Default)]
struct Roots {
    by_name: BTreeMap<OsString, u64>,
    inos: HashSet<u64>,
}

pub struct Vault {
    remote: Arc<Remote>,
    identity: Arc<Identity>,
    known: KnownKeys,
    nodes: Mutex<HashMap<u64, Arc<Node>>>,
    /// The newest key version seen for each inode in this session. Clearing
    /// `nodes` does not clear it. It stops the server from returning an
    /// older key record, under a key that a revoked user still has.
    seen: Mutex<HashMap<u64, u32>>,
    /// Public keys that the server gave for grant senders, by user name.
    senders: Mutex<HashMap<String, [u8; PUBLIC_KEY_LEN]>>,
    /// If true (`with_untrusted_warnings`), print a message once for each
    /// grant from an untrusted sender. `warned` holds the grants already
    /// reported.
    warn_untrusted: bool,
    warned: Mutex<HashSet<u64>>,
    roots: Mutex<Roots>,
    /// Decrypted chunks, each with the seq it was read or written at. The
    /// snapshot vaults of the same mount share this cache, and each one
    /// uses its own `space` in it.
    cache: Arc<Mutex<ChunkCache>>,
    space: u64,
    /// Each file's layout, kept after the first request (see `layout`).
    layouts: Mutex<HashMap<u64, Layout>>,
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
            seen: Mutex::new(HashMap::new()),
            senders: Mutex::new(HashMap::new()),
            warn_untrusted: false,
            warned: Mutex::new(HashSet::new()),
            roots: Mutex::new(Roots::default()),
            cache: Arc::new(Mutex::new(ChunkCache::new(DEFAULT_CACHE_BYTES, CACHE_TTL))),
            space: 0,
            layouts: Mutex::new(HashMap::new()),
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
            known: KnownKeys::in_memory(),
            nodes: Mutex::new(HashMap::new()),
            seen: Mutex::new(HashMap::new()),
            senders: Mutex::new(HashMap::new()),
            warn_untrusted: false,
            warned: Mutex::new(HashSet::new()),
            roots: Mutex::new(Roots::default()),
            cache: Arc::clone(&self.cache),
            space,
            layouts: Mutex::new(HashMap::new()),
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

    /// Fetches `ino`'s key again, with every key above it. Use this when
    /// data is sealed under a newer key version than the one known here.
    async fn refresh(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        self.forget_all();
        self.node(ino).await
    }

    /// Returns `ino`'s key for sealing new data.
    ///
    /// - Opens the grant again if the user trusted its sender after it was
    ///   opened.
    /// - Returns `EACCES` if the key comes through an untrusted grant
    ///   (`Node::sealable`).
    /// - If the node is stale, first gives it, and every stale node above
    ///   it, a new key.
    async fn fresh_node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        let mut node = self.node(ino).await?;
        // The user trusted the grant's sender after the grant was opened,
        // so open the grant again.
        if let Some(untrusted) = &node.untrusted
            && self.known.pinned(&untrusted.sender).is_some()
        {
            self.forget_all();
            node = self.node(ino).await?;
        }
        node.sealable(ino)?;
        if node.stale {
            return self.freshen(ino).await;
        }
        Ok(node)
    }

    fn known_node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        self.nodes
            .lock()
            .unwrap()
            .get(&ino)
            .cloned()
            .ok_or_else(|| FsError::new(errno::EIO, format!("inode {ino}'s key went missing")))
    }

    /// Gives every stale node on the path from this account's grant to
    /// `ino` a new key, and returns `ino`'s key. Call it after the server
    /// refuses a write with `EKEYEXPIRED`.
    ///
    /// Steps, repeated up to `ROTATION_ROUNDS` times:
    ///
    /// - Fetch and unwrap the key path again.
    /// - Find the highest stale node. If there is none, return.
    /// - Rotate it, and everything below it down to each grant
    ///   (`rotate_from`). If another client rotated first, start again.
    ///
    /// Returns `EAGAIN` if the keys keep changing.
    pub async fn freshen(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        for _ in 0..ROTATION_ROUNDS {
            self.forget_all();
            let path = self.remote.key_path(ino).await?;
            let inos: Vec<u64> = path.nodes.iter().map(|&(i, _)| i).collect();
            let last = self.unwrap_path(path).await?;
            let mut stale = None;
            for pair in inos.windows(2) {
                let parent = self.known_node(pair[0])?;
                if self
                    .known_node(pair[1])?
                    .record
                    .is_stale(parent.record.version)
                {
                    stale = Some((pair[1], parent));
                    break;
                }
            }
            let Some((stale, parent)) = stale else {
                return Ok(last);
            };
            match self.rotate_from(stale, Some(&parent), None).await {
                Ok(()) => {}
                // Another client rotated the key first. Check again.
                Err(e) if changed(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("the keys above inode {ino} kept changing"),
        ))
    }

    /// Checks the server's grantee list for `granted` against the list
    /// sealed under its key. A server that lies could add a user, to get a
    /// key sealed to them.
    ///
    /// Returns each grantee's sealed entry (public key and write access),
    /// by user name.
    ///
    /// Edge cases:
    ///
    /// - Returns `EPERM` if the sealed list is missing or under an old key
    ///   version, or if the server lists a user that the sealed list does
    ///   not have, or lists them differently.
    /// - Returns `EPERM` if a different key is pinned here for a user.
    /// - Leaves out users with no keys (their account was deleted).
    /// - Leaves out users on the sealed list that the server no longer
    ///   lists, because removing a grant needs no approval.
    fn checked_grantees(
        &self,
        node: &Node,
        ino: u64,
        granted: &GrantedNode,
    ) -> Result<HashMap<String, GranteeEntry>, FsError> {
        let mismatch = |why: String| {
            FsError::new(
                errno::EPERM,
                format!(
                    "inode {ino}: the server's list of who it is granted to doesn't match the \
                     one sealed under its key ({why}); refusing to seal its key to anyone on it"
                ),
            )
        };
        let named: Vec<&Grantee> = granted
            .grantees
            .iter()
            .filter(|g| !g.public_key.is_empty())
            .collect();
        if named.is_empty() {
            return Ok(HashMap::new());
        }
        if granted.sealed_grantees.is_empty() {
            return Err(mismatch("there is no sealed list".to_string()));
        }
        let version = sealed_version(&granted.sealed_grantees).map_err(|e| corrupt(ino, e))?;
        if version != node.record.version {
            return Err(mismatch(format!(
                "the sealed list is under key version {version}, not the current {}",
                node.record.version
            )));
        }
        let sealed = open_grantees(&node.key, ino, &granted.sealed_grantees)
            .map_err(|e| mismatch(e.to_string()))?;
        let mut out = HashMap::new();
        for grantee in named {
            check_username(&grantee.user).map_err(|e| mismatch(e.message))?;
            let Some(entry) = sealed.iter().find(|e| e.user == grantee.user) else {
                return Err(mismatch(format!(
                    "{} isn't on the sealed list",
                    grantee.user
                )));
            };
            if entry.public_key.as_slice() != grantee.public_key.as_slice() {
                return Err(mismatch(format!(
                    "{}'s key isn't the one their grant was sealed to",
                    grantee.user
                )));
            }
            if entry.writable != grantee.writable {
                return Err(mismatch(format!(
                    "{}'s grant is read-{} on the sealed list",
                    grantee.user,
                    if entry.writable { "write" } else { "only" }
                )));
            }
            // A different key is pinned here for this user. Whoever added
            // them to the list used a key that this account would not
            // accept.
            if let Some(pinned) = self.known.pinned(&grantee.user)
                && pinned != entry.public_key
            {
                self.known.check(&grantee.user, &entry.public_key)?;
            }
            out.insert(grantee.user.clone(), entry.clone());
        }
        Ok(out)
    }

    /// Gives `top`, and every node from `top` down to each grant below it,
    /// a new key. Grantees lower down cannot rotate keys above their grant,
    /// so this must happen now.
    ///
    /// Inputs:
    ///
    /// - `parent`: the node of `top`'s parent, which wraps `top`'s new key.
    ///   `None` for a volume.
    /// - `drop`: a user whose grant of `top` to remove, for a revocation.
    ///
    /// Steps:
    ///
    /// - List the grants below `top`, and order the nodes from the top
    ///   down.
    /// - Make a new key for each node, wrapped under its parent's new key.
    /// - Seal each grant again, only to the users and keys on the node's
    ///   sealed grantee list (`checked_grantees`). Seal that list again
    ///   under the new key.
    /// - Send all rotations in one request. The server refuses them with
    ///   `EAGAIN` if another client changed a key first.
    ///
    /// Returns `ENOENT` if `drop` has no grant of `top`.
    async fn rotate_from(
        &self,
        top: u64,
        parent: Option<&Node>,
        drop: Option<&str>,
    ) -> Result<(), FsError> {
        let under: Vec<GrantedNode> = self.remote.grants_under(top).await?;
        let mut parent_of = HashMap::new();
        let mut depth = HashMap::from([(top, 0)]);
        let mut granted: HashMap<u64, GrantedNode> = HashMap::new();
        for node in under {
            for (d, pair) in node.path.windows(2).enumerate() {
                parent_of.insert(pair[1], pair[0]);
                depth.insert(pair[1], d + 1);
            }
            granted.insert(node.ino, node);
        }
        if let Some(user) = drop
            && !granted
                .get(&top)
                .is_some_and(|n| n.grantees.iter().any(|g| g.user == user))
        {
            return Err(FsError::new(
                errno::ENOENT,
                format!("{user} has no grant of inode {top}"),
            ));
        }
        let mut order: Vec<u64> = depth.keys().copied().collect();
        order.sort_by_key(|ino| (depth[ino], *ino));

        let me = self.remote.username();
        let mut new_keys: HashMap<u64, (Key, u32)> = HashMap::new();
        let mut rotations = Vec::with_capacity(order.len());
        for ino in order {
            let current = self.node(ino).await?;
            current.sealable(ino)?;
            let wrap = if current.record.parent_version == 0 {
                None
            } else if ino == top {
                let parent = parent.ok_or_else(|| {
                    FsError::new(
                        errno::EACCES,
                        format!(
                            "a new key for inode {top} must be wrapped under its parent's, \
                             which this account can't reach"
                        ),
                    )
                })?;
                parent.sealable(ino)?;
                Some((parent.key.clone(), parent.record.version))
            } else {
                Some(new_keys[&parent_of[&ino]].clone())
            };
            let (record, key) = current
                .record
                .rotate(ino, &current.key, wrap.as_ref().map(|(k, v)| (k, *v)))
                .map_err(|e| corrupt(ino, e))?;
            let mut grants = Vec::new();
            let mut kept = Vec::new();
            if let Some(node) = granted.remove(&ino) {
                // Removing a user needs no approval, so do not check the
                // user being removed. This is also how to remove a grantee
                // that the server made up.
                let dropping = |g: &Grantee| ino == top && drop == Some(g.user.as_str());
                let checked = GrantedNode {
                    grantees: node
                        .grantees
                        .iter()
                        .filter(|g| !dropping(g))
                        .cloned()
                        .collect(),
                    ..node.clone()
                };
                let listed = self.checked_grantees(&current, ino, &checked)?;
                for grantee in node.grantees {
                    let sealed = match listed.get(&grantee.user) {
                        _ if ino == top && drop == Some(grantee.user.as_str()) => Vec::new(),
                        Some(entry) => {
                            kept.push(entry.clone());
                            seal_grant(
                                &self.identity,
                                me,
                                &entry.public_key,
                                ino,
                                record.version,
                                &key,
                            )
                        }
                        // The user's account has no keys, so there is
                        // nothing to seal to. Remove the grant.
                        None => {
                            eprintln!(
                                "dropping {}'s grant of inode {ino}: they have no keys",
                                grantee.user
                            );
                            Vec::new()
                        }
                    };
                    grants.push((grantee.user, sealed));
                }
            }
            let sealed_grantees = if kept.is_empty() {
                Vec::new()
            } else {
                seal_grantees(&key, record.version, ino, &kept)
            };
            rotations.push(Rotation {
                ino,
                expected_version: current.record.version,
                node_keys: record.encode(),
                grants,
                sealed_grantees,
            });
            new_keys.insert(ino, (key, record.version));
        }
        let rotated = self.remote.rotate(rotations).await;
        self.forget_all();
        rotated
    }

    /// Removes `user`'s grant of directory `ino` and gives the directory a
    /// new key. This needs the key of the directory above, which wraps the
    /// new key, unless `ino` is a volume. Tries again if another client
    /// changes the keys at the same time.
    pub async fn revoke(&self, ino: u64, user: &str) -> Result<(), FsError> {
        for _ in 0..ROTATION_ROUNDS {
            self.freshen(ino).await?;
            let path = self.remote.key_path(ino).await?;
            let parent = match path.nodes.len() {
                0 | 1 => None,
                n => Some(self.node(path.nodes[n - 2].0).await?),
            };
            match self.rotate_from(ino, parent.as_deref(), Some(user)).await {
                Err(e) if changed(&e) => continue,
                other => return other,
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s keys kept changing under this revocation"),
        ))
    }

    /// The users that directory `ino` is granted to. Returns `EPERM` if the
    /// list does not agree with the grantee list sealed under its key, or
    /// with the keys pinned here.
    pub async fn grantees(&self, ino: u64) -> Result<Vec<Grantee>, FsError> {
        Ok(self.grantees_with_links(ino).await?.0)
    }

    /// `grantees`, and the secret of each public link among them, by link
    /// name, from the sealed grantee list. Needs write access to `ino`, as
    /// the list does.
    pub async fn grantees_with_links(
        &self,
        ino: u64,
    ) -> Result<(Vec<Grantee>, HashMap<String, String>), FsError> {
        let mut node = self.node(ino).await?;
        let Some(granted) = self
            .remote
            .grants_under(ino)
            .await?
            .into_iter()
            .find(|n| n.ino == ino)
        else {
            return Ok((Vec::new(), HashMap::new()));
        };
        if newer_key(&node, &granted) {
            self.forget_all();
            node = self.node(ino).await?;
        }
        let secrets = self
            .checked_grantees(&node, ino, &granted)?
            .into_values()
            .filter_map(|e| Some((e.user, e.link_secret?)))
            .collect();
        Ok((granted.grantees, secrets))
    }

    /// Returns `ino`'s key. If it is not known yet, unwraps it from this
    /// account's grant.
    pub async fn node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        if let Some(node) = self.nodes.lock().unwrap().get(&ino) {
            return Ok(Arc::clone(node));
        }
        let path = self.remote.key_path(ino).await?;
        self.unwrap_path(path).await
    }

    /// Opens `grant` of `ino` with its sender's public key. Returns the key
    /// version, the key, and the sender if this account does not trust
    /// them. A trusted sender is this account, or a user whose key is
    /// pinned here. For other senders, the vault uses the key that the
    /// server gives, so the server could have made the grant.
    async fn open_grant(
        &self,
        ino: u64,
        grant: &Grant,
    ) -> Result<(u32, Key, Option<Arc<Untrusted>>), FsError> {
        let refused = |e: String| FsError::new(errno::EACCES, format!("inode {ino}: {e}"));
        let sealed = &grant.sealed_key;
        let sender = grant_sender(sealed).map_err(|e| refused(e.to_string()))?;
        check_username(sender).map_err(|e| refused(e.message))?;
        if sender == self.remote.username() {
            let (version, key) = self
                .identity
                .open_grant(&self.identity.public_key(), ino, sealed)
                .map_err(|e| refused(e.to_string()))?;
            return Ok((version, key, None));
        }
        if let Some(pinned) = self.known.pinned(sender)
            && let Ok((version, key)) = self.identity.open_grant(&pinned, ino, sealed)
        {
            return Ok((version, key, None));
        }
        let served = self.sender_key(sender).await?;
        let (version, key) = self
            .identity
            .open_grant(&served, ino, sealed)
            .map_err(|e| refused(e.to_string()))?;
        let untrusted = Untrusted {
            sender: sender.to_string(),
            key: served,
        };
        Ok((version, key, Some(Arc::new(untrusted))))
    }

    /// `user`'s public key, as the server gives it.
    async fn sender_key(&self, user: &str) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        if let Some(key) = self.senders.lock().unwrap().get(user) {
            return Ok(*key);
        }
        let key: [u8; PUBLIC_KEY_LEN] = self
            .remote
            .public_key(user)
            .await?
            .try_into()
            .map_err(|_| FsError::new(errno::EIO, format!("{user}'s public key is malformed")))?;
        self.senders.lock().unwrap().insert(user.to_string(), key);
        Ok(key)
    }

    /// Unwraps every key along `path`, from the grant down, keeps each one,
    /// and returns the last.
    ///
    /// - Refuses a key record older than one already seen
    ///   (`check_not_older`).
    /// - Marks a node stale if it, or a node above it, is wrapped under an
    ///   old version of its parent's key.
    /// - Marks every node below an untrusted grant as untrusted.
    async fn unwrap_path(&self, path: KeyPath) -> Result<Arc<Node>, FsError> {
        let mut nodes = path.nodes.into_iter();
        let (root_ino, root_bytes) = nodes
            .next()
            .ok_or_else(|| FsError::new(errno::EIO, "an empty key path"))?;
        let record = NodeKeys::decode(&root_bytes).map_err(|e| corrupt(root_ino, e))?;
        self.check_not_older(root_ino, &record)?;
        let (version, key, untrusted) = self.open_grant(root_ino, &path.grant).await?;
        // A grant always holds the current key version, because a rotation
        // seals every grant of the node again.
        if version != record.version {
            return Err(FsError::new(
                errno::EACCES,
                format!("the grant of inode {root_ino} holds an out-of-date key"),
            ));
        }
        // `Node::new` checks the key. If the key does not open the record,
        // it is not this node's key, whatever the grant says.
        let mut root = Node::new(root_ino, record, key)?;
        if let Some(u) = &untrusted
            && self.warn_untrusted
            && self.warned.lock().unwrap().insert(root_ino)
        {
            eprintln!(
                "a share from {} is read-only here until their key is trusted: \
                 see `raft5fs pending`",
                u.sender
            );
        }
        root.untrusted = untrusted;
        let mut parent = (root_ino, self.keep(root_ino, root));
        for (ino, bytes) in nodes {
            let record = NodeKeys::decode(&bytes).map_err(|e| corrupt(ino, e))?;
            self.check_not_older(ino, &record)?;
            let wrapping = parent.1.key_at(parent.0, record.parent_version)?;
            let key = record.open(ino, &wrapping).map_err(|e| corrupt(ino, e))?;
            let stale = parent.1.stale || record.is_stale(parent.1.record.version);
            let mut node = Node::new(ino, record, key)?;
            node.stale = stale;
            node.untrusted = parent.1.untrusted.clone();
            parent = (ino, self.keep(ino, node));
        }
        Ok(parent.1)
    }

    /// Returns `EIO` if `record` is older than a record seen before for
    /// `ino`. A server could send an old record so that the client seals
    /// new data under a key that a revoked user still has.
    fn check_not_older(&self, ino: u64, record: &NodeKeys) -> Result<(), FsError> {
        match self.seen.lock().unwrap().get(&ino) {
            Some(&seen) if record.version < seen => Err(FsError::new(
                errno::EIO,
                format!(
                    "inode {ino}: the server handed back key version {}, older than \
                     version {seen} seen before",
                    record.version
                ),
            )),
            _ => Ok(()),
        }
    }

    fn keep(&self, ino: u64, node: Node) -> Arc<Node> {
        let mut seen = self.seen.lock().unwrap();
        let newest = seen.entry(ino).or_insert(node.record.version);
        *newest = (*newest).max(node.record.version);
        drop(seen);
        let node = Arc::new(node);
        self.nodes.lock().unwrap().insert(ino, Arc::clone(&node));
        node
    }

    /// Reads this account's grants again and returns the root's entries:
    /// each grant's label, made unique, and its inode.
    pub async fn root_entries(&self) -> Result<Vec<(OsString, u64)>, FsError> {
        let mut grants = self.remote.list_grants().await?;
        grants.sort_by_key(|g| g.ino);
        let mut roots = Roots::default();
        for grant in grants {
            let label = self
                .identity
                .open_label(grant.ino, &grant.sealed_label)
                .map(os_bytes::into_name)
                .unwrap_or_else(|_| OsString::from(format!("unreadable-{}", grant.ino)));
            let mut name = label.clone();
            let mut n = 2;
            while roots.by_name.contains_key(&name) || name.is_empty() || self.reserved(&name) {
                let mut numbered = label.clone();
                numbered.push(format!(" ({n})"));
                name = numbered;
                n += 1;
            }
            roots.by_name.insert(name, grant.ino);
            roots.inos.insert(grant.ino);
        }
        let entries = roots
            .by_name
            .iter()
            .map(|(name, &ino)| (name.clone(), ino))
            .collect();
        *self.roots.lock().unwrap() = roots;
        Ok(entries)
    }

    /// Whether `name` is reserved in the root. Only the live root's
    /// `.snapshot` is. A grant with that label gets a different name.
    fn reserved(&self, name: &OsStr) -> bool {
        self.remote.snapshot().is_none() && name == SNAPSHOT_DIR
    }

    /// Returns the grant that `name` refers to in the root. If the name is
    /// not known, reads the grants again.
    pub async fn root_lookup(&self, name: &OsStr) -> Result<u64, FsError> {
        if let Some(&ino) = self.roots.lock().unwrap().by_name.get(name) {
            return Ok(ino);
        }
        self.root_entries()
            .await?
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, ino)| ino)
            .ok_or_else(|| FsError::errno(errno::ENOENT))
    }

    /// Whether `ino` is granted to this account. These inodes are the
    /// root's entries, and their `..` is the root.
    pub fn is_grant_root(&self, ino: u64) -> bool {
        self.roots.lock().unwrap().inos.contains(&ino)
    }

    /// Reserves an inode and makes a key for a new child `name` of
    /// `parent`. Also returns the tag that the entry is filed under.
    async fn new_child(
        &self,
        parent: u64,
        name: &OsStr,
    ) -> Result<(NewNode, Node, OsString), FsError> {
        let parent_node = self.fresh_node(parent).await?;
        let ino = self.remote.allocate_inode().await?;
        let (record, key) =
            NodeKeys::create(ino, Some((&parent_node.key, parent_node.record.version)));
        let tag = parent_node.tag(name);
        let new = NewNode {
            ino,
            keys: record.encode(),
            sealed_name: parent_node.seal(parent, ino, &tag, name),
        };
        Ok((new, Node::new(ino, record, key)?, tag))
    }

    /// The tag that `name` is filed under in directory `parent`.
    async fn tag(&self, parent: u64, name: &OsStr) -> Result<OsString, FsError> {
        Ok(self.node(parent).await?.tag(name))
    }

    /// Looks up `name` in directory `parent` and returns its attributes.
    ///
    /// The entry's sealed name must open under the directory's key as
    /// `name`, and must name the inode that the server returned. If not,
    /// the server could return any inode this account can reach, and writes
    /// to `name` could go to a place that other users read. Returns `EIO`
    /// if this check fails.
    pub async fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        let mut dir = self.node(parent).await?;
        let tag = dir.tag(name);
        let (attr, sealed) = self.remote.lookup(parent, &tag).await?;
        let version = sealed_version(&sealed).map_err(|e| corrupt(parent, e))?;
        if version > dir.record.version {
            // The name is sealed under a newer key than the one known here.
            dir = self.refresh(parent).await?;
        }
        let key = dir.key_at(parent, version)?;
        open_name(
            &key,
            &dir.name_key,
            parent,
            attr.ino,
            os_bytes::bytes(&tag),
            &sealed,
        )
        .map_err(|e| {
            corrupt(
                parent,
                format!(
                    "{e}: the entry the server gave doesn't name inode {}",
                    attr.ino
                ),
            )
        })?;
        Ok(attr)
    }

    /// Drops the kept key and cached data of an inode that is gone.
    fn forget_inode(&self, ino: u64) {
        self.nodes.lock().unwrap().remove(&ino);
        self.cache.lock().unwrap().invalidate_ino(self.space, ino);
    }

    /// Removes a file, as `Remote::unlink` does.
    pub async fn unlink(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.unlink(parent, &tag).await?;
        self.forget_inode(ino);
        Ok(ino)
    }

    /// Removes an empty directory, as `Remote::rmdir` does.
    pub async fn rmdir(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.rmdir(parent, &tag).await?;
        self.forget_inode(ino);
        Ok(ino)
    }

    /// Returns directory `ino`'s entries with their real names.
    ///
    /// - Fetches newer keys if a name is sealed under a newer key version.
    /// - Keeps `.` and `..`, which have no sealed name.
    /// - Leaves out, and reports on stderr, any entry whose name does not
    ///   open or does not match its tag. The directory's key holders did
    ///   not make that entry.
    pub async fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let items = self.remote.readdir(ino).await?;
        let mut dir = self.node(ino).await?;
        // A name sealed under a newer key than the one known here means
        // that another client rotated the key.
        let newest = items
            .iter()
            .filter_map(|i| sealed_version(&i.sealed_name).ok())
            .max()
            .unwrap_or(0);
        if newest > dir.record.version {
            dir = self.refresh(ino).await?;
        }
        let mut named = Vec::with_capacity(items.len());
        for mut item in items {
            if item.sealed_name.is_empty() {
                // `.` and `..` have no tag.
                if item.name == "." || item.name == ".." {
                    named.push(item);
                } else {
                    eprintln!("inode {ino}: an entry with no sealed name; left out");
                }
                continue;
            }
            let opened = sealed_version(&item.sealed_name)
                .map_err(|e| corrupt(ino, e))
                .and_then(|version| dir.key_at(ino, version))
                .and_then(|key| {
                    open_name(
                        &key,
                        &dir.name_key,
                        ino,
                        item.ino,
                        os_bytes::bytes(&item.name),
                        &item.sealed_name,
                    )
                    .map_err(|e| corrupt(ino, e))
                });
            match opened {
                Ok(name) => {
                    item.name = os_bytes::into_name(name);
                    item.sealed_name = Vec::new();
                    named.push(item);
                }
                Err(e) => eprintln!("{e}; the entry for inode {} left out", item.ino),
            }
        }
        Ok(named)
    }

    pub async fn mkdir(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        match self.mkdir_once(parent, name, perm).await {
            Err(e) if expired(&e) => {
                self.freshen(parent).await?;
                self.mkdir_once(parent, name, perm).await
            }
            other => other,
        }
    }

    async fn mkdir_once(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        let (new, node, tag) = self.new_child(parent, name).await?;
        let attr = self.remote.mkdir(parent, &tag, perm, &new).await?;
        self.keep(attr.ino, node);
        Ok(attr)
    }

    /// Creates a file, as `Remote::create` does.
    pub async fn create(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        match self.create_once(parent, name, perm).await {
            Err(e) if expired(&e) => {
                self.freshen(parent).await?;
                self.create_once(parent, name, perm).await
            }
            other => other,
        }
    }

    async fn create_once(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        let (new, node, tag) = self.new_child(parent, name).await?;
        let attr = self.remote.create(parent, &tag, perm, &new).await?;
        self.keep(attr.ino, node);
        Ok(attr)
    }

    /// Moves `name` in `parent` to `new_name` in `new_parent`. Returns the
    /// inode it replaced, if any.
    ///
    /// Steps:
    ///
    /// - If the parent changes, give the moved node a new key first
    ///   (`rotate_moving`). Otherwise, users with the old parent's key
    ///   could read what is written to the node after the move.
    /// - Seal the new name under the new parent's key, and wrap the moved
    ///   node's key under the new parent's key.
    /// - If a key is stale (`EKEYEXPIRED`), get new keys and try once more.
    ///
    /// Nodes below the moved node become stale, so they get new keys the
    /// next time they are written.
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
        if parent != new_parent {
            self.rotate_moving(parent, name).await?;
        }
        match self
            .rename_once(parent, name, new_parent, new_name, noreplace)
            .await
        {
            Err(e) if expired(&e) => {
                self.freshen(new_parent).await?;
                let moved = self.lookup(parent, name).await?.ino;
                self.freshen(moved).await?;
                self.rename_once(parent, name, new_parent, new_name, noreplace)
                    .await
            }
            other => other,
        }
    }

    async fn rename_once(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
        let from = self.node(parent).await?;
        let to = self.fresh_node(new_parent).await?;
        let tag = from.tag(name);
        let new_tag = to.tag(new_name);
        let ino = self.lookup(parent, name).await?.ino;
        let mut sealed = SealedMove {
            ino,
            node_keys: Vec::new(),
            sealed_name: to.seal(new_parent, ino, &new_tag, new_name),
        };
        let mut rewrapped = None;
        if parent != new_parent {
            from.sealable(parent)?;
            let moved = self.node(ino).await?;
            let record = moved
                .record
                .rewrap(ino, &moved.key, (&to.key, to.record.version))
                .map_err(|e| corrupt(ino, e))?;
            sealed.node_keys = record.encode();
            rewrapped = Some(Node {
                record,
                key: moved.key.clone(),
                name_key: moved.name_key.clone(),
                stale: moved.stale,
                untrusted: to.untrusted.clone(),
            });
        }
        let replaced = self
            .remote
            .rename(parent, &tag, new_parent, &new_tag, noreplace, &sealed)
            .await?;
        if let Some(node) = rewrapped {
            self.keep(ino, node);
        }
        if let Some(victim) = replaced {
            self.forget_inode(victim);
        }
        Ok(replaced)
    }

    /// Gives the node that `name` refers to in `parent` a new key, wrapped
    /// under `parent`'s key, before it moves to another directory (see
    /// `rename`).
    async fn rotate_moving(&self, parent: u64, name: &OsStr) -> Result<(), FsError> {
        for _ in 0..ROTATION_ROUNDS {
            let from = self.fresh_node(parent).await?;
            let moved = self.lookup(parent, name).await?.ino;
            match self.rotate_from(moved, Some(&from), None).await {
                Err(e) if changed(&e) || expired(&e) => {
                    self.forget_all();
                    continue;
                }
                other => return other,
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("the keys of the node moving out of inode {parent} kept changing"),
        ))
    }

    /// Makes a new volume, shown in this account's root as `label`.
    pub async fn create_volume(&self, label: &OsStr, perm: u16) -> Result<Attr, FsError> {
        if label == SNAPSHOT_DIR || self.root_lookup(label).await.is_ok() {
            return Err(FsError::errno(errno::EEXIST));
        }
        let ino = self.remote.allocate_inode().await?;
        let (record, key) = NodeKeys::create(ino, None);
        let me = self.identity.public_key();
        let username = self.remote.username();
        let sealed_key = seal_grant(&self.identity, username, &me, ino, record.version, &key);
        let sealed_label = seal_label(&me, ino, os_bytes::bytes(label));
        let sealed_grantees = seal_grantees(
            &key,
            record.version,
            ino,
            &[GranteeEntry {
                user: username.to_string(),
                public_key: me,
                writable: true,
                link_secret: None,
            }],
        );
        let new = NewNode {
            ino,
            keys: record.encode(),
            sealed_name: Vec::new(),
        };
        let node = Node::new(ino, record, key)?;
        let attr = self
            .remote
            .create_volume(&new, perm, sealed_key, sealed_label, sealed_grantees)
            .await?;
        self.keep(ino, node);
        let mut roots = self.roots.lock().unwrap();
        roots.by_name.insert(label.to_os_string(), ino);
        roots.inos.insert(ino);
        Ok(attr)
    }

    /// Removes the empty volume shown in the root as `label`.
    pub async fn delete_volume(&self, label: &OsStr) -> Result<(), FsError> {
        let ino = self.root_lookup(label).await?;
        self.remote.delete_volume(ino).await?;
        self.forget_inode(ino);
        let mut roots = self.roots.lock().unwrap();
        roots.by_name.remove(label);
        roots.inos.remove(&ino);
        Ok(())
    }

    /// Grants directory `ino`, and everything below it, to `user`. The
    /// grant shows in their root as `label`.
    ///
    /// Steps:
    ///
    /// - Check that this account can seal under `ino`.
    /// - Get `user`'s public key from the server, and pin it if no key is
    ///   pinned.
    /// - Seal the key to `user`, add them to the sealed grantee list, and
    ///   send both. Try again if another client changes the grants at the
    ///   same time.
    ///
    /// Returns the public key that the grant was sealed to. If it was not
    /// pinned before, compare it with the fingerprint that the user saw
    /// when they enrolled (`raft5fs-share` calls `trust` first to require
    /// this). A pin is trust in both directions: shares from `user` are
    /// trusted after this.
    pub async fn grant(
        &self,
        ino: u64,
        user: &str,
        writable: bool,
        label: &OsStr,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        self.grant_with(ino, user, writable, label, None).await
    }

    /// `grant`, with `link_secret` kept in `user`'s sealed grantee entry
    /// when `user` is a public link.
    async fn grant_with(
        &self,
        ino: u64,
        user: &str,
        writable: bool,
        label: &OsStr,
        link_secret: Option<&str>,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        // Check this before pinning `user`'s key. A pin also makes shares
        // from `user` trusted, and sharing from an untrusted share must not
        // cause that.
        self.fresh_node(ino).await?;
        let public_key = self.remote.public_key(user).await?;
        let public_key = self.known.check(user, &public_key)?;
        let mut expired_once = false;
        for _ in 0..CHANGE_RETRIES {
            let node = self.fresh_node(ino).await?;
            let granted = self
                .remote
                .grants_under(ino)
                .await?
                .into_iter()
                .find(|n| n.ino == ino);
            if granted.as_ref().is_some_and(|g| newer_key(&node, g)) {
                self.forget_all();
                continue;
            }
            let seq = granted.as_ref().map_or(0, |g| g.grantees_seq);
            let mut entries: Vec<GranteeEntry> = match &granted {
                Some(granted) => self
                    .checked_grantees(&node, ino, granted)?
                    .into_values()
                    .filter(|e| e.user != user)
                    .collect(),
                None => Vec::new(),
            };
            entries.push(GranteeEntry {
                user: user.to_string(),
                public_key,
                writable,
                link_secret: link_secret.map(str::to_string),
            });
            let version = node.record.version;
            let grant = Grant {
                ino,
                writable,
                key_version: version,
                sealed_key: seal_grant(
                    &self.identity,
                    self.remote.username(),
                    &public_key,
                    ino,
                    version,
                    &node.key,
                ),
                sealed_label: seal_label(&public_key, ino, os_bytes::bytes(label)),
            };
            let sealed_grantees = seal_grantees(&node.key, version, ino, &entries);
            match self.remote.grant(user, grant, sealed_grantees, seq).await {
                Err(e) if expired(&e) && !expired_once => {
                    expired_once = true;
                    self.freshen(ino).await?;
                }
                // Another client changed the grants at the same time. Start
                // again from their list.
                Err(e) if changed(&e) => {}
                other => return other.map(|()| public_key),
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s grantees kept changing under this grant"),
        ))
    }

    /// Makes a public link to directory `ino`: a new account that can only
    /// read it, until it expires (`expires`, in seconds since the Unix
    /// epoch) or anyone who can write the directory revokes it. Needs the
    /// `links` capability and write access.
    ///
    /// - `path` is how this account knows the directory. It is sealed to
    ///   this account's key, so only `links` here reads it back.
    /// - `label` is the name the directory shows under for the link's
    ///   visitors.
    ///
    /// Returns the link's account name and secret. The secret goes in the
    /// link (`public_link`), and in the directory's sealed grantee list, so
    /// whoever can change the directory can copy the link again
    /// (`grantees_with_links`).
    pub async fn create_link(
        &self,
        ino: u64,
        path: &str,
        label: &OsStr,
        expires: Option<u64>,
    ) -> Result<(String, String), FsError> {
        // Checked first, so a refused grant leaves no account behind.
        self.remote.access(ino, 2).await?;
        let (user, secret) = new_link_credentials();
        let note = seal_label(&self.identity.public_key(), ino, path.as_bytes());
        let key = self
            .remote
            .create_link_account(&user, &secret, expires, ino, note)
            .await?;
        // This account made the key, so it needs no fingerprint check.
        self.known.check(&user, &key)?;
        self.grant_with(ino, &user, false, label, Some(&secret))
            .await?;
        Ok((user, secret))
    }

    /// The public links that this account made, with the path each was made
    /// for (`None` if it can't be read).
    pub async fn links(&self) -> Result<Vec<(LinkAccount, Option<String>)>, FsError> {
        let links = self.remote.list_links().await?;
        Ok(links
            .into_iter()
            .map(|link| {
                let path = self
                    .identity
                    .open_label(link.info.folder, &link.info.note)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                (link, path)
            })
            .collect())
    }

    /// Pins `user`'s public key if its fingerprint matches `expected`.
    /// Spaces and case in `expected` do not matter. This makes grants from
    /// `user` trusted, and lets a first grant to them go ahead without
    /// trusting the server for their key.
    ///
    /// Returns `EPERM` if the fingerprint is different, or if a different
    /// key is already pinned.
    pub async fn trust(&self, user: &str, expected: &str) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        let served = self.served_key(user).await?;
        let matches = fingerprint_matches(&served, expected)
            .map_err(|e| FsError::new(errno::EINVAL, format!("{expected:?}: {e}")))?;
        if !matches {
            return Err(FsError::new(
                errno::EPERM,
                format!(
                    "the server's key for {user} has fingerprint\n  {}\nnot the one given: \
                     not pinning it",
                    fingerprint_words(&served)
                ),
            ));
        }
        let key = self.known.check(user, &served)?;
        // Grants from this user were opened as untrusted before, so open
        // them again.
        self.forget_all();
        Ok(key)
    }

    /// The public key that the server gives for `user`. Only the server
    /// says it is theirs.
    pub async fn served_key(&self, user: &str) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        self.remote
            .public_key(user)
            .await?
            .try_into()
            .map_err(|_| FsError::new(errno::EIO, format!("{user}'s public key is malformed")))
    }

    /// Every grant made to this account, with its sender and whether this
    /// account trusts them (see `Node::sealable`).
    pub async fn shares(&self) -> Result<Vec<Share>, FsError> {
        let mut grants = self.remote.list_grants().await?;
        grants.sort_by_key(|g| g.ino);
        let mut shares = Vec::with_capacity(grants.len());
        for grant in grants {
            let label = self
                .identity
                .open_label(grant.ino, &grant.sealed_label)
                .map(os_bytes::into_name)
                .unwrap_or_else(|_| OsString::from(format!("unreadable-{}", grant.ino)));
            let sender = grant_sender(&grant.sealed_key).unwrap_or("?").to_string();
            let trust = match self.open_grant(grant.ino, &grant).await {
                Ok((_, _, None)) => ShareTrust::Trusted,
                Ok((_, _, Some(untrusted))) => ShareTrust::Untrusted { key: untrusted.key },
                Err(e) => ShareTrust::Unreadable(e),
            };
            shares.push(Share {
                label,
                ino: grant.ino,
                writable: grant.writable,
                sender,
                trust,
            });
        }
        Ok(shares)
    }

    /// The inode at `path`: a root entry's name, then names below it,
    /// separated by `/`.
    pub async fn resolve(&self, path: &str) -> Result<u64, FsError> {
        let mut parts = path.split('/').filter(|p| !p.is_empty() && *p != ".");
        let first = parts
            .next()
            .ok_or_else(|| FsError::new(errno::EINVAL, "an empty path"))?;
        let mut ino = self.root_lookup(OsStr::new(first)).await?;
        for part in parts {
            ino = self.lookup(ino, OsStr::new(part)).await?.ino;
        }
        Ok(ino)
    }

    /// Returns bytes `[offset, offset + len)` of file `ino`.
    ///
    /// - Stops at the end of the file. Returns nothing if `offset` is at or
    ///   past the end.
    /// - Holes read as zeros.
    /// - Uses a cached chunk only after the server confirms that it has not
    ///   changed.
    pub async fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let chunk_size = self.remote.chunk_size();
        let first = offset / chunk_size;
        let last = (offset + len as u64 - 1) / chunk_size;
        let lookups: Vec<Lookup> = {
            let mut cache = self.cache.lock().unwrap();
            (first..=last)
                .map(|index| cache.get(self.space, ino, index))
                .collect()
        };
        let known: Vec<u64> = lookups
            .iter()
            .map(|l| match l {
                Lookup::Unconfirmed { version, .. } => *version,
                Lookup::Miss { .. } => 0,
            })
            .collect();
        let (size, chunks) = self.fetch(ino, first, last, &known).await?;
        if offset >= size {
            return Ok(Vec::new());
        }
        let end = (offset + len as u64).min(size);
        let mut out = vec![0; (end - offset) as usize];
        let mut node = None;
        for (chunk, lookup) in chunks.into_iter().zip(lookups) {
            let index = chunk.index;
            let plain = self.chunk_from(ino, chunk, lookup, &mut node).await?;
            let start = index * chunk_size;
            let lo = start.max(offset);
            let hi = (start + plain.len() as u64).min(end);
            if lo < hi {
                out[(lo - offset) as usize..(hi - offset) as usize]
                    .copy_from_slice(&plain[(lo - start) as usize..(hi - start) as usize]);
            }
        }
        Ok(out)
    }

    /// Returns the plaintext for one chunk of a read: the cached bytes that
    /// the server confirmed, or the bytes that the server sent, opened and
    /// cached. `node` holds the file's key, fetched the first time it is
    /// needed.
    async fn chunk_from(
        &self,
        ino: u64,
        chunk: SealedChunk,
        lookup: Lookup,
        node: &mut Option<Arc<Node>>,
    ) -> Result<Arc<[u8]>, FsError> {
        let index = chunk.index;
        if chunk.unchanged {
            if let Lookup::Unconfirmed {
                data, generation, ..
            } = lookup
                && self
                    .cache
                    .lock()
                    .unwrap()
                    .confirm(self.space, ino, index, generation)
            {
                return Ok(data);
            }
            // The server confirmed that the chunk did not change, but the
            // cache dropped it in the meantime, possibly because of a write
            // from this client. Read it again.
            let fresh = self.fetch_one(ino, index, 0).await?;
            let generation = self
                .cache
                .lock()
                .unwrap()
                .get(self.space, ino, index)
                .generation();
            return self.open_and_keep(ino, fresh, generation, node).await;
        }
        let generation = match lookup {
            Lookup::Unconfirmed { generation, .. } | Lookup::Miss { generation } => generation,
        };
        self.open_and_keep(ino, chunk, generation, node).await
    }

    /// Opens a chunk as the server sent it (a hole is empty) and caches it
    /// at its seq.
    async fn open_and_keep(
        &self,
        ino: u64,
        chunk: SealedChunk,
        generation: u64,
        node: &mut Option<Arc<Node>>,
    ) -> Result<Arc<[u8]>, FsError> {
        let plain: Arc<[u8]> = match sealed_blob(ino, &chunk.body)? {
            Some(blob) => {
                let version = sealed_version(blob).map_err(|e| corrupt(ino, e))?;
                let known = match node.take() {
                    Some(known) => known,
                    None => self.node(ino).await?,
                };
                // The chunk is sealed under a newer key than the one known
                // here, so another client rotated the key.
                let current = if version > known.record.version {
                    self.refresh(ino).await?
                } else {
                    known
                };
                let opened = self.open(&current, ino, chunk.index, blob)?;
                *node = Some(current);
                opened.into()
            }
            None => Arc::from(Vec::new()),
        };
        self.cache.lock().unwrap().insert(
            self.space,
            ino,
            chunk.index,
            Arc::clone(&plain),
            chunk.seq,
            generation,
        );
        Ok(plain)
    }

    /// Fetches chunks `first..=last` of `ino`, in as many requests as the
    /// server's limit needs, and returns the file's size from the last
    /// reply. `known[i]` is the seq that chunk `first + i` is cached at, or
    /// 0. Chunks in object storage come back fetched, as if they were
    /// inline (see `fetch_segments`).
    async fn fetch(
        &self,
        ino: u64,
        first: u64,
        last: u64,
        known: &[u64],
    ) -> Result<(u64, Vec<SealedChunk>), FsError> {
        let mut reads = Vec::new();
        let mut size = 0;
        let mut next = first;
        while next <= last {
            let count = (last - next + 1).min(u64::from(u32::MAX)) as u32;
            let known = &known[(next - first) as usize..];
            let read = self.remote.read_chunks(ino, next, count, known).await?;
            size = read.attr.size;
            let Some(after) = read.chunks.last().map(|c| c.index + 1) else {
                return Err(FsError::new(errno::EIO, "the server returned no chunks"));
            };
            next = after;
            reads.push(read);
        }
        Ok((size, self.fetch_segments(ino, reads).await?))
    }

    /// Fetches one chunk of `ino` and its seq. If the chunk is still at
    /// `known` (0 for none), it comes back `unchanged`, with no bytes.
    async fn fetch_one(&self, ino: u64, index: u64, known: u64) -> Result<SealedChunk, FsError> {
        let read = self.remote.read_chunks(ino, index, 1, &[known]).await?;
        let mut got = self.fetch_segments(ino, vec![read]).await?;
        got.pop().filter(|c| c.index == index).ok_or_else(|| {
            FsError::new(errno::EIO, format!("chunk {index} of inode {ino} missing"))
        })
    }

    /// Fetches each chunk in `reads` that is in object storage, and puts
    /// its sealed bytes in its place. Later code can then read it like an
    /// inline chunk.
    ///
    /// - Groups consecutive segments of one block into one ranged GET.
    /// - Runs up to `MAX_FETCHES` GETs at the same time.
    ///
    /// A range can be cut from a block without reading the rest, because
    /// each segment is padded with zeros to a full chunk before sealing. So
    /// all segments have the same length.
    async fn fetch_segments(
        &self,
        ino: u64,
        reads: Vec<Chunks>,
    ) -> Result<Vec<SealedChunk>, FsError> {
        let segment_len = self.remote.chunk_size() + CHUNK_OVERHEAD as u64;
        let mut chunks = Vec::new();
        // The runs to fetch: the URL, the first segment, and the place in
        // `chunks` for each segment of the run.
        let mut runs: Vec<(String, u32, Vec<usize>)> = Vec::new();
        for read in reads {
            let mut wanted: Vec<(u32, u32, usize)> = Vec::new();
            for chunk in read.chunks {
                if let ChunkBody::Segment { block, segment } = chunk.body {
                    wanted.push((block, segment, chunks.len()));
                }
                chunks.push(chunk);
            }
            wanted.sort_unstable();
            for (block, segment, at) in wanted {
                match runs.last_mut() {
                    Some((url, start, ats))
                        if *url == read.blocks[block as usize].url
                            && *start + ats.len() as u32 == segment =>
                    {
                        ats.push(at)
                    }
                    _ => runs.push((read.blocks[block as usize].url.clone(), segment, vec![at])),
                }
            }
        }

        // Several downloads in flight at once. They only fetch: opening the
        // chunks happens below, so one task polling them all loses nothing.
        let mut fetching = FuturesUnordered::new();
        let mut runs = runs.into_iter();
        loop {
            while fetching.len() < MAX_FETCHES {
                let Some((url, start, ats)) = runs.next() else {
                    break;
                };
                let client = self.remote.objects().clone();
                let range = u64::from(start) * segment_len
                    ..(u64::from(start) + ats.len() as u64) * segment_len;
                fetching.push(async move {
                    let bytes = raft5fs_objstore::http::get_range(&client, &url, range).await;
                    (bytes, ats)
                });
            }
            let Some((bytes, ats)) = fetching.next().await else {
                break;
            };
            let bytes = bytes.map_err(|e| {
                FsError::new(errno::EIO, format!("inode {ino}: fetching a block: {e}"))
            })?;
            for (sealed, at) in bytes.chunks(segment_len as usize).zip(ats) {
                chunks[at].body = ChunkBody::Inline(sealed.to_vec());
            }
        }
        Ok(chunks)
    }

    /// Opens a sealed chunk of `ino` with the key version that it was
    /// sealed under.
    fn open(&self, node: &Node, ino: u64, index: u64, blob: &[u8]) -> Result<Vec<u8>, FsError> {
        let version = sealed_version(blob).map_err(|e| corrupt(ino, e))?;
        let key = node.key_at(ino, version)?;
        open_chunk(&key, ino, index, blob).map_err(|e| corrupt(ino, e))
    }

    /// Returns the current plaintext of chunk `index` and its seq, to
    /// change and write back. It uses the cached copy without asking the
    /// server, because the write sends the seq it expects, and the server
    /// refuses the write if the copy is out of date. If there is no cached
    /// copy, it fetches the chunk.
    async fn base(&self, node: &Node, ino: u64, index: u64) -> Result<(Vec<u8>, u64), FsError> {
        if let Lookup::Unconfirmed { data, version, .. } =
            self.cache.lock().unwrap().get(self.space, ino, index)
        {
            return Ok((data.to_vec(), version));
        }
        let chunk = self.fetch_one(ino, index, 0).await?;
        let plain = match sealed_blob(ino, &chunk.body)? {
            Some(blob) => self.open(node, ino, index, blob)?,
            None => Vec::new(),
        };
        Ok((plain, chunk.seq))
    }

    /// Writes `data` at `offset` in file `ino`, and makes the file larger
    /// if necessary.
    ///
    /// Steps:
    ///
    /// - Split the range into one span for each chunk.
    /// - Group the spans: one group for each block in a hybrid file's block
    ///   region, and at most one batch for each group of inline chunks.
    /// - Store each group in order: `rewrite_block` for a block,
    ///   `write_batch` for inline chunks. If the key is stale, get new keys
    ///   and try that group once more.
    ///
    /// Returns the file's attributes after the last group.
    ///
    /// Edge cases:
    ///
    /// - An empty write stores nothing, but still changes mtime.
    /// - On failure, `WriteError::written` counts the bytes stored, in
    ///   whole groups. The groups before the failed one stay stored.
    pub async fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<Attr, WriteError> {
        let failed = |written, error| WriteError { written, error };
        let mut node = self.fresh_node(ino).await.map_err(|e| failed(0, e))?;
        if data.is_empty() {
            // An empty write still changes mtime.
            let touched = match self.remote.write_chunks(ino, &[], offset).await {
                Err(e) if expired(&e) => {
                    self.freshen(ino).await.map_err(|e| failed(0, e))?;
                    self.remote.write_chunks(ino, &[], offset).await
                }
                other => other,
            };
            return touched.map(|(attr, _)| attr).map_err(|e| failed(0, e));
        }
        let chunk_size = self.remote.chunk_size();
        let per_batch = (self.remote.batch_bytes() / chunk_size).max(1) as usize;
        let spans = spans(chunk_size, offset, data.len());
        // Spans are in order, so if the last span is not in a block, no
        // span is.
        let grid = match self.remote.grid() {
            Some(grid)
                if spans
                    .last()
                    .is_some_and(|&(index, ..)| grid.in_blocks(index)) =>
            {
                match self.layout(ino).await.map_err(|e| failed(0, e))? {
                    Layout::Hybrid => Some(grid),
                    Layout::Inline => None,
                }
            }
            _ => None,
        };
        let block_of = |index: u64| {
            grid.filter(|g| g.in_blocks(index))
                .map(|g| g.block_start(index))
        };
        // Each group is stored in one commit. An inline group holds at most
        // one batch, to stay below the server's transaction size limit.
        let mut groups: Vec<(Option<u64>, &[Span])> = Vec::new();
        let mut rest = &spans[..];
        while let Some(&(index, ..)) = rest.first() {
            let block = block_of(index);
            let len = rest
                .iter()
                .take_while(|&&(i, ..)| block_of(i) == block)
                .count()
                .min(if block.is_some() {
                    usize::MAX
                } else {
                    per_batch
                });
            groups.push((block, &rest[..len]));
            rest = &rest[len..];
        }

        let mut attr = None;
        let mut cursor = 0;
        for (block, group) in groups {
            let bytes: usize = group.iter().map(|&(_, _, n)| n).sum();
            let end = offset + (cursor + bytes) as u64;
            let piece = &data[cursor..cursor + bytes];
            let once = |node: Arc<Node>| async move {
                match (block, grid) {
                    (Some(start), Some(grid)) => {
                        let edit = BlockEdit::Write {
                            spans: group,
                            data: piece,
                            end,
                        };
                        match self.rewrite_block(&node, ino, grid, start, edit).await? {
                            Rewritten::Stored {
                                attr: Some(attr), ..
                            } => Ok(attr),
                            _ => Err(FsError::new(errno::EIO, "a write stored nothing")),
                        }
                    }
                    _ => self.write_batch(&node, ino, group, piece, end).await,
                }
            };
            let stored = match once(Arc::clone(&node)).await {
                // The key is stale, here or above. Get new keys and try
                // again.
                Err(e) if expired(&e) => {
                    node = self.freshen(ino).await.map_err(|e| failed(cursor, e))?;
                    once(Arc::clone(&node)).await
                }
                other => other,
            }
            .map_err(|e| failed(cursor, e))?;
            attr = Some(stored);
            cursor += bytes;
        }
        Ok(attr.expect("a non-empty write has at least one batch"))
    }

    /// Stores one inline group of spans in one transaction, and caches what
    /// it stores.
    ///
    /// Steps:
    ///
    /// - Seal each span's chunk. A whole-chunk span seals the new bytes
    ///   directly. A partial span changes the chunk's current bytes
    ///   (`base`), and the write expects the chunk's seq.
    /// - Send all chunks in one `write_chunks` call.
    /// - If another writer changed a chunk first (`EAGAIN`), drop the
    ///   cached copies and do it again, up to `CHANGE_RETRIES` times.
    ///
    /// On any other error, the result is not known, so it drops the file's
    /// whole cache.
    async fn write_batch(
        &self,
        node: &Node,
        ino: u64,
        spans: &[(u64, usize, usize)],
        data: &[u8],
        end: u64,
    ) -> Result<Attr, FsError> {
        let chunk_size = self.remote.chunk_size();
        for _ in 0..CHANGE_RETRIES {
            let generation = self
                .cache
                .lock()
                .unwrap()
                .get(self.space, ino, spans[0].0)
                .generation();
            let mut writes = Vec::with_capacity(spans.len());
            let mut plains = Vec::with_capacity(spans.len());
            let mut cursor = 0;
            for &(index, within, n) in spans {
                let piece = &data[cursor..cursor + n];
                cursor += n;
                let (plain, expected_seq) = if within == 0 && n as u64 == chunk_size {
                    (piece.to_vec(), None)
                } else {
                    let (mut plain, seq) = self.base(node, ino, index).await?;
                    if plain.len() < within + n {
                        plain.resize(within + n, 0);
                    }
                    plain[within..within + n].copy_from_slice(piece);
                    (plain, Some(seq))
                };
                writes.push(ChunkWrite {
                    index,
                    expected_seq,
                    body: WriteBody::Inline(seal_chunk(
                        &node.key,
                        node.record.version,
                        ino,
                        index,
                        &plain,
                    )),
                });
                plains.push((index, plain));
            }
            match self.remote.write_chunks(ino, &writes, end).await {
                Err(e) if changed(&e) => {
                    // A cached base was out of date. Drop it and fetch it
                    // again.
                    let mut cache = self.cache.lock().unwrap();
                    for &(index, ..) in spans {
                        cache.invalidate(self.space, ino, index..=index);
                    }
                }
                Err(e) => {
                    // It is not known whether the write was stored, so do
                    // not trust the cache.
                    self.cache.lock().unwrap().invalidate_ino(self.space, ino);
                    return Err(e);
                }
                Ok((attr, seq)) => {
                    let mut cache = self.cache.lock().unwrap();
                    for (index, plain) in plains {
                        cache.insert(self.space, ino, index, plain.into(), seq, generation);
                    }
                    return Ok(attr);
                }
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s chunks kept changing under this write"),
        ))
    }

    /// Applies `changes` to `ino` (see `Remote::setattr`). When the file
    /// gets shorter, the client first seals the chunk at the new end again,
    /// cut short, because the server cannot open the chunk to do this.
    pub async fn setattr(&self, ino: u64, changes: SetAttr) -> Result<Attr, FsError> {
        if let Some(size) = changes.size {
            self.truncate(ino, size).await?;
        }
        let changed = self.remote.setattr(ino, changes).await;
        if let Some(size) = changes.size {
            // The chunks after the new end are gone, whatever the result
            // was.
            let chunk_size = self.remote.chunk_size();
            self.cache
                .lock()
                .unwrap()
                .invalidate(self.space, ino, size / chunk_size..=u64::MAX);
        }
        changed
    }

    /// Seals the chunk that `new_size` falls in again, without the bytes
    /// after `new_size`.
    async fn truncate(&self, ino: u64, new_size: u64) -> Result<(), FsError> {
        match self.truncate_once(ino, new_size).await {
            Err(e) if expired(&e) => {
                self.freshen(ino).await?;
                self.truncate_once(ino, new_size).await
            }
            other => other,
        }
    }

    async fn truncate_once(&self, ino: u64, new_size: u64) -> Result<(), FsError> {
        let chunk_size = self.remote.chunk_size();
        let keep = (new_size % chunk_size) as usize;
        if keep == 0 {
            return Ok(());
        }
        let index = new_size / chunk_size;
        let node = self.fresh_node(ino).await?;
        if let Some(grid) = self.remote.grid().filter(|g| g.in_blocks(index))
            && self.layout(ino).await? == Layout::Hybrid
        {
            let start = grid.block_start(index);
            let edit = BlockEdit::Truncate { index, keep };
            return self
                .rewrite_block(&node, ino, grid, start, edit)
                .await
                .map(drop);
        }
        for _ in 0..CHANGE_RETRIES {
            let (mut plain, seq) = self.base(&node, ino, index).await?;
            if plain.len() <= keep {
                return Ok(());
            }
            plain.truncate(keep);
            let write = ChunkWrite {
                index,
                expected_seq: Some(seq),
                body: WriteBody::Inline(seal_chunk(
                    &node.key,
                    node.record.version,
                    ino,
                    index,
                    &plain,
                )),
            };
            let written = self.remote.write_chunks(ino, &[write], 0).await;
            // Whatever happened, the cached copy is now out of date.
            self.cache
                .lock()
                .unwrap()
                .invalidate(self.space, ino, index..=index);
            match written {
                Err(e) if changed(&e) => continue,
                other => return other.map(drop),
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s last chunk kept changing under this truncate"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_pins_survive_a_reload(open: impl Fn() -> KnownKeys) {
        let known = open();
        known.check("alice", &[1; 32]).unwrap();
        known.check("bob", &[2; 32]).unwrap();

        let again = open();
        again.check("alice", &[1; 32]).unwrap();
        assert_eq!(
            again.check("alice", &[9; 32]).unwrap_err().errno,
            errno::EPERM
        );
        assert_eq!(
            again.check("alice", &[1; 31]).unwrap_err().errno,
            errno::EIO
        );

        // A pin made through another handle reaches this one.
        let other = open();
        known.check("carol", &[4; 32]).unwrap();
        assert_eq!(other.pinned("carol"), Some([4; 32]));

        // Forgetting keeps pins that another handle added since.
        again.forget("alice").unwrap();
        let after = open();
        assert_eq!(after.pinned("carol"), Some([4; 32]));
        after.check("alice", &[9; 32]).unwrap();
        assert_eq!(
            after.check("bob", &[3; 32]).unwrap_err().errno,
            errno::EPERM
        );
    }

    #[test]
    fn pinned_keys_survive_a_reload_and_a_different_key_is_refused() {
        let file = std::env::temp_dir().join(format!("raft5fs-known-keys-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        check_pins_survive_a_reload(|| KnownKeys::load(file.clone()).unwrap());
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(file.with_file_name(format!(
            "{}.lock",
            file.file_name().unwrap().to_str().unwrap()
        )));

        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        check_pins_survive_a_reload(|| KnownKeys::open(Arc::clone(&store), "pins").unwrap());
    }

    #[test]
    fn pins_from_two_places_at_once_all_land() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let threads: Vec<_> = (0..8u8)
            .map(|t| {
                let known = KnownKeys::open(Arc::clone(&store), "pins").unwrap();
                std::thread::spawn(move || {
                    for i in 0..10u8 {
                        known
                            .check(&format!("u{t}x{i}"), &[t * 10 + i; 32])
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let known = KnownKeys::open(store, "pins").unwrap();
        assert_eq!(known.entries().len(), 80);
    }

    #[test]
    fn a_name_that_could_forge_a_pin_line_is_refused() {
        let file =
            std::env::temp_dir().join(format!("raft5fs-known-inject-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let known = KnownKeys::load(file.clone()).unwrap();
        let forged = format!("x\nbob {}\ny", to_hex(&[7; 32]));
        assert_eq!(
            known.check(&forged, &[1; 32]).unwrap_err().errno,
            errno::EINVAL
        );
        assert!(known.forget(&forged).is_err());
        known.check("bob", &[2; 32]).unwrap();
        assert_eq!(
            KnownKeys::load(file.clone()).unwrap().pinned("bob"),
            Some([2; 32])
        );
        // Only the owner can read the file.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        known.forget("bob").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_pin_file_that_isnt_one_this_wrote_is_refused() {
        let file = std::env::temp_dir().join(format!("raft5fs-known-bad-{}", std::process::id()));
        let line = |user: &str, byte: u8| format!("{user} {}\n", to_hex(&[byte; 32]));
        for text in [
            // Two keys for one user: the code cannot know which key is
            // correct.
            format!("{}{}", line("bob", 1), line("bob", 2)),
            format!("{}junk\n", line("bob", 1)),
            line("Bob", 1),
            format!("bob {} extra\n", to_hex(&[1; 32])),
            "bob 1234\n".to_string(),
        ] {
            std::fs::write(&file, &text).unwrap();
            assert!(KnownKeys::load(file.clone()).is_err(), "{text:?}");
        }
        // The same key twice, and blank lines, are accepted.
        std::fs::write(&file, format!("{}\n{}", line("bob", 1), line("bob", 1))).unwrap();
        assert_eq!(
            KnownKeys::load(file.clone()).unwrap().pinned("bob"),
            Some([1; 32])
        );
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn spans_cover_a_range_chunk_by_chunk() {
        assert_eq!(spans(10, 0, 0), []);
        assert_eq!(spans(10, 3, 4), [(0, 3, 4)]);
        assert_eq!(spans(10, 0, 10), [(0, 0, 10)]);
        assert_eq!(spans(10, 8, 15), [(0, 8, 2), (1, 0, 10), (2, 0, 3)]);
    }
}
