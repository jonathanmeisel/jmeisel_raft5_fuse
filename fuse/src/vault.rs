//! The client's side of the filesystem's encryption: inode keys, and the root
//! a user sees.
//!
//! **Keys.** Every inode has a key, wrapped under its parent's (see
//! raft5fs-crypto's `node`). The vault unwraps them top down: from a grant
//! sealed to this account, through the key records the server hands back
//! with it (`Remote::key_path`), to the inode wanted -- and keeps what it
//! unwrapped, so the walk is paid once per subtree. A create makes the new
//! node's key here, wrapped under its parent's, and a move to another
//! directory re-wraps the moved node's key under its new parent's.
//!
//! **Data.** Nor any file's contents: each chunk is sealed under the
//! file's key here (raft5fs-crypto's `data`), so the server can't patch a
//! byte range. A write that
//! covers a chunk whole just seals it; one that covers part of a chunk
//! reads the chunk, opens it, changes it and seals it again -- stored only
//! if no one changed the chunk in between (the store's sequence number
//! says), and otherwise done over. Truncating re-seals the chunk the new
//! end falls in, cut short, before the server drops the chunks past it.
//!
//! **Names.** The server never sees one. An entry is filed under a tag --
//! an HMAC of its name under the directory's name key -- so the vault
//! turns every name it is handed into a tag before asking for it, and
//! seals the real name under the directory's key for listings to return.
//! A listed name opens only if it matches its tag, so the server can't
//! pass one entry off under another's name.
//!
//! **Revocation.** Taking a grant back gives the directory a new key --
//! the old one stays in its history, under the new, so nothing written
//! before is lost -- and re-seals it for everyone else who holds it. The
//! revoked user still has the old key, and every key under it, so the rest
//! is lazy: a node wrapped under an old version of its parent's key is
//! stale, the server refuses writes that would seal anything new under a
//! stale node (`EKEYEXPIRED`), and the vault then gives the stale nodes on
//! the way new keys, top down (`freshen`), and writes again. One thing
//! can't wait: whoever holds a grant further down can't rotate what is
//! above it, so a revocation also rotates the path down to every other
//! grant beneath it -- which keeps every grant, and everything above it,
//! always fresh.
//!
//! **Public keys** come from the server, which could hand out its own.
//! The vault pins each user's key the first time it seals to it
//! (`KnownKeys`), and refuses to seal to a different one later.
//!
//! **The root.** The server's real root is no one's to see. What a mount
//! shows at its root instead is virtual: one entry per grant made to this
//! account, named as the granter named it (a label sealed to this account,
//! so the server can't read it either). Making a directory there makes a
//! volume -- a new top-level directory, granted to its maker -- and
//! removing one removes the volume.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use raft5fs_crypto::Key;
use raft5fs_crypto::data::{
    name_tag, open_chunk, open_name, seal_chunk, seal_name, sealed_version,
};
use raft5fs_crypto::identity::{Identity, PUBLIC_KEY_LEN, fingerprint, seal_grant, seal_label};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_proto::types::{
    Attr, ChunkWrite, DirItem, FsError, Grant, GrantedNode, Grantee, KeyPath, NewNode, Rotation,
    SealedChunk, SealedMove, SetAttr, WriteError,
};

use crate::chunk_cache::{ChunkCache, Lookup};

mod prune;
pub use prune::{GrantRoot, PruneStats};

use crate::remote::Remote;

/// The inode the kernel knows a mount's root by: the virtual root, never
/// the server's real one.
pub const VIRTUAL_ROOT: u64 = 1;

/// Where the root shows the snapshots, though it doesn't list it.
pub const SNAPSHOT_DIR: &str = ".snapshot";

/// An inode's key record, its current key, and (for a directory) the key
/// its entries' tags are made with.
pub struct Node {
    pub record: NodeKeys,
    pub key: Key,
    name_key: Key,
}

impl Node {
    /// `ino`'s node with current key `key`, which this checks: a key that
    /// doesn't open the record's name key isn't this node's.
    fn new(ino: u64, record: NodeKeys, key: Key) -> Result<Self, FsError> {
        let name_key = record.name_key(ino, &key).map_err(|e| corrupt(ino, e))?;
        Ok(Self {
            record,
            key,
            name_key,
        })
    }

    /// The tag `name` is filed under in this directory.
    pub fn tag(&self, name: &OsStr) -> OsString {
        OsString::from_vec(name_tag(&self.name_key, name.as_bytes()).to_vec())
    }

    /// `name`, filed under `tag` in this directory `ino`, sealed under its
    /// current key.
    pub fn seal(&self, ino: u64, tag: &OsStr, name: &OsStr) -> Vec<u8> {
        seal_name(
            &self.key,
            self.record.version,
            ino,
            tag.as_bytes(),
            name.as_bytes(),
        )
    }

    /// This node's key at `version`: the current one, or an older one
    /// walked down to through the history.
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

/// How many times giving keys new versions is tried again when someone
/// else changed them meanwhile.
const ROTATION_ROUNDS: usize = 16;

fn expired(e: &FsError) -> bool {
    e.errno == libc::EKEYEXPIRED
}

fn changed(e: &FsError) -> bool {
    e.errno == libc::EAGAIN
}

/// Public keys sealed to before, by user: the first one seen for a user is
/// trusted, and a different one later refused -- the server could have
/// substituted its own. Kept in memory, and in a file if given one (lines
/// of `user hex-key`).
pub struct KnownKeys {
    keys: Mutex<HashMap<String, [u8; PUBLIC_KEY_LEN]>>,
    file: Option<PathBuf>,
}

impl KnownKeys {
    pub fn in_memory() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            file: None,
        }
    }

    /// The keys pinned in `file`, which needn't exist yet; new pins are
    /// added to it.
    pub fn load(file: PathBuf) -> std::io::Result<Self> {
        let mut keys = HashMap::new();
        match std::fs::read_to_string(&file) {
            Ok(text) => {
                for line in text.lines() {
                    let mut fields = line.split_whitespace();
                    if let (Some(user), Some(hex)) = (fields.next(), fields.next())
                        && let Some(key) = from_hex(hex)
                    {
                        keys.insert(user.to_string(), key);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self {
            keys: Mutex::new(keys),
            file: Some(file),
        })
    }

    /// `key` as `user`'s, if it is the one pinned for them -- or, if none
    /// is, after pinning it. `EPERM` if another one is pinned.
    pub fn check(&self, user: &str, key: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        let key: [u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| FsError::new(libc::EIO, format!("{user}'s public key is malformed")))?;
        let mut keys = self.keys.lock().unwrap();
        match keys.get(user) {
            Some(pinned) if *pinned == key => Ok(key),
            Some(pinned) => Err(FsError::new(
                libc::EPERM,
                format!(
                    "the server gave a different key for {user} than before ({} now, {} pinned); \
                     if they enrolled again, check the new fingerprint with them and forget the old",
                    fingerprint(&key),
                    fingerprint(pinned)
                ),
            )),
            None => {
                if let Some(file) = &self.file {
                    let saved = (|| {
                        if let Some(dir) = file.parent() {
                            std::fs::create_dir_all(dir)?;
                        }
                        let mut f = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(file)?;
                        writeln!(f, "{user} {}", to_hex(&key))
                    })();
                    saved.map_err(|e| {
                        FsError::new(
                            libc::EIO,
                            format!("cannot pin {user}'s key in {}: {e}", file.display()),
                        )
                    })?;
                }
                keys.insert(user.to_string(), key);
                Ok(key)
            }
        }
    }

    /// Forgets `user`'s pinned key, so the next one seen is trusted.
    pub fn forget(&self, user: &str) -> std::io::Result<()> {
        let mut keys = self.keys.lock().unwrap();
        keys.remove(user);
        if let Some(file) = &self.file {
            let text: String = keys
                .iter()
                .map(|(user, key)| format!("{user} {}\n", to_hex(key)))
                .collect();
            std::fs::write(file, text)?;
        }
        Ok(())
    }
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

/// How many times a read-modify-write of a chunk is redone when someone
/// else changed the chunk under it, before giving up with `EAGAIN`.
const CHANGE_RETRIES: usize = 32;

/// The pieces of `[offset, offset + len)` by chunk: each chunk's index,
/// where in the chunk the piece starts, and how long it is.
fn spans(chunk_size: u64, offset: u64, len: usize) -> Vec<(u64, usize, usize)> {
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

fn corrupt(ino: u64, e: impl std::fmt::Display) -> FsError {
    FsError::new(libc::EIO, format!("inode {ino}: {e}"))
}

/// The grants this account holds, by the names they show up as.
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
    roots: Mutex<Roots>,
    /// Decrypted chunks, each with the seq it was read or written at:
    /// shared with the vaults of the same mount's snapshots, each keeping
    /// its own `space` in it.
    cache: Arc<Mutex<ChunkCache>>,
    space: u64,
}

/// How much decrypted file data a vault caches unless told otherwise.
pub const DEFAULT_CACHE_BYTES: usize = 64 << 20;

/// How long a cached chunk may go unconfirmed before it is dropped rather
/// than revalidated. Not a staleness bound: every hit is confirmed with
/// the server first (see `ChunkCache`), so what this buys is only that a
/// chunk nothing has read for this long stops holding its share of the
/// budget. Generous on purpose -- dropping an entry costs a whole chunk
/// fetched and decrypted, where confirming one costs eight bytes.
const CACHE_TTL: Duration = Duration::from_secs(60);

impl Vault {
    /// The vault of `remote`'s account, which must have logged in.
    pub fn new(remote: Arc<Remote>) -> Result<Self, FsError> {
        let identity = remote
            .identity()
            .ok_or_else(|| FsError::new(libc::EACCES, "not logged in"))?;
        Ok(Self {
            remote,
            identity,
            known: KnownKeys::in_memory(),
            nodes: Mutex::new(HashMap::new()),
            roots: Mutex::new(Roots::default()),
            cache: Arc::new(Mutex::new(ChunkCache::new(DEFAULT_CACHE_BYTES, CACHE_TTL))),
            space: 0,
        })
    }

    /// Caches up to `bytes` of decrypted file data (0 caches none).
    pub fn with_cache_size(mut self, bytes: usize) -> Self {
        self.cache = Arc::new(Mutex::new(ChunkCache::new(bytes, CACHE_TTL)));
        self
    }

    /// The vault of snapshot `name`: this account's view of the
    /// filesystem as it was then, read-only. Its keys are its own -- a
    /// snapshot's key records are as they were, not as they are -- but it
    /// caches into this vault's cache, under `space`, which must be unique
    /// to it and not 0.
    pub fn at_snapshot(&self, name: &str, space: u64) -> Self {
        debug_assert_ne!(space, 0, "space 0 is the live filesystem's");
        Self {
            remote: Arc::new(self.remote.at(name)),
            identity: Arc::clone(&self.identity),
            known: KnownKeys::in_memory(),
            nodes: Mutex::new(HashMap::new()),
            roots: Mutex::new(Roots::default()),
            cache: Arc::clone(&self.cache),
            space,
        }
    }

    /// Pins public keys in `known` rather than in memory only.
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

    /// Drops every key unwrapped so far, for the next use to fetch afresh:
    /// what a rotation, here or anywhere, can leave out of date.
    fn forget_all(&self) {
        self.nodes.lock().unwrap().clear();
    }

    /// `ino`'s key fetched afresh, with everything above it: for data
    /// sealed under a version newer than the one known here.
    async fn refresh(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        self.forget_all();
        self.node(ino).await
    }

    fn known_node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        self.nodes
            .lock()
            .unwrap()
            .get(&ino)
            .cloned()
            .ok_or_else(|| FsError::new(libc::EIO, format!("inode {ino}'s key went missing")))
    }

    /// `ino`'s key, after giving every stale node from this account's grant
    /// down to it a new key, top down: what a write the server refused
    /// with `EKEYEXPIRED` needs before it is tried again.
    pub async fn freshen(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        for _ in 0..ROTATION_ROUNDS {
            self.forget_all();
            let path = self.remote.key_path(ino).await?;
            let inos: Vec<u64> = path.nodes.iter().map(|&(i, _)| i).collect();
            let last = self.unwrap_path(path)?;
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
                // Someone else got there first: look again.
                Err(e) if changed(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Err(FsError::new(
            libc::EAGAIN,
            format!("the keys above inode {ino} kept changing"),
        ))
    }

    /// Gives `top` a new key, and every node from it down to each grant
    /// beneath it, re-sealing every grant of them -- except `drop`'s of
    /// `top`, which is removed. `parent`: `top`'s parent's node, which its
    /// new key is wrapped under (unless `top` is a volume, which has none).
    async fn rotate_from(
        &self,
        top: u64,
        parent: Option<&Node>,
        drop: Option<&str>,
    ) -> Result<(), FsError> {
        let under: Vec<GrantedNode> = self.remote.grants_under(top).await?;
        let mut parent_of = HashMap::new();
        let mut depth = HashMap::from([(top, 0)]);
        let mut grantees: HashMap<u64, Vec<Grantee>> = HashMap::new();
        for node in under {
            for (d, pair) in node.path.windows(2).enumerate() {
                parent_of.insert(pair[1], pair[0]);
                depth.insert(pair[1], d + 1);
            }
            grantees.insert(node.ino, node.grantees);
        }
        if let Some(user) = drop
            && !grantees
                .get(&top)
                .is_some_and(|gs| gs.iter().any(|g| g.user == user))
        {
            return Err(FsError::new(
                libc::ENOENT,
                format!("{user} has no grant of inode {top}"),
            ));
        }
        let mut order: Vec<u64> = depth.keys().copied().collect();
        order.sort_by_key(|ino| (depth[ino], *ino));

        let mut new_keys: HashMap<u64, (Key, u32)> = HashMap::new();
        let mut rotations = Vec::with_capacity(order.len());
        for ino in order {
            let current = self.node(ino).await?;
            let wrap = if current.record.parent_version == 0 {
                None
            } else if ino == top {
                let parent = parent.ok_or_else(|| {
                    FsError::new(
                        libc::EACCES,
                        format!(
                            "a new key for inode {top} must be wrapped under its parent's, \
                             which this account can't reach"
                        ),
                    )
                })?;
                Some((parent.key.clone(), parent.record.version))
            } else {
                Some(new_keys[&parent_of[&ino]].clone())
            };
            let (record, key) = current
                .record
                .rotate(ino, &current.key, wrap.as_ref().map(|(k, v)| (k, *v)))
                .map_err(|e| corrupt(ino, e))?;
            let mut grants = Vec::new();
            for grantee in grantees.remove(&ino).unwrap_or_default() {
                let sealed = if ino == top && drop == Some(grantee.user.as_str()) {
                    Vec::new()
                } else if grantee.public_key.is_empty() {
                    // Their account has no keys any more: nothing to seal
                    // to, so the grant goes.
                    eprintln!(
                        "dropping {}'s grant of inode {ino}: they have no keys",
                        grantee.user
                    );
                    Vec::new()
                } else {
                    let public_key = self.known.check(&grantee.user, &grantee.public_key)?;
                    seal_grant(&public_key, ino, record.version, &key)
                };
                grants.push((grantee.user, sealed));
            }
            rotations.push(Rotation {
                ino,
                expected_version: current.record.version,
                node_keys: record.encode(),
                grants,
            });
            new_keys.insert(ino, (key, record.version));
        }
        let rotated = self.remote.rotate(rotations).await;
        self.forget_all();
        rotated
    }

    /// Takes `user`'s grant of directory `ino` back, giving it a new key
    /// (see the module doc). Needs the key of the directory above it --
    /// its new key is wrapped under that -- unless it is a volume.
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
            libc::EAGAIN,
            format!("inode {ino}'s keys kept changing under this revocation"),
        ))
    }

    /// Who directory `ino` is granted to, with their keys checked against
    /// the pinned ones (`EPERM` on a mismatch).
    pub async fn grantees(&self, ino: u64) -> Result<Vec<Grantee>, FsError> {
        let mut grantees = Vec::new();
        for node in self.remote.grants_under(ino).await? {
            if node.ino == ino {
                grantees = node.grantees;
            }
        }
        for grantee in &grantees {
            if !grantee.public_key.is_empty() {
                self.known.check(&grantee.user, &grantee.public_key)?;
            }
        }
        Ok(grantees)
    }

    /// `ino`'s key, unwrapping it from this account's grant if it isn't
    /// known yet.
    pub async fn node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        if let Some(node) = self.nodes.lock().unwrap().get(&ino) {
            return Ok(Arc::clone(node));
        }
        let path = self.remote.key_path(ino).await?;
        self.unwrap_path(path)
    }

    /// Unwraps every key along `path`, keeping each, and returns the last.
    fn unwrap_path(&self, path: KeyPath) -> Result<Arc<Node>, FsError> {
        let mut nodes = path.nodes.into_iter();
        let (root_ino, root_bytes) = nodes
            .next()
            .ok_or_else(|| FsError::new(libc::EIO, "an empty key path"))?;
        let record = NodeKeys::decode(&root_bytes).map_err(|e| corrupt(root_ino, e))?;
        let (version, key) = self
            .identity
            .open_grant(root_ino, &path.grant.sealed_key)
            .map_err(|e| FsError::new(libc::EACCES, format!("inode {root_ino}: {e}")))?;
        // A grant always holds the current version: a rotation re-seals
        // every grant of the node it rotates.
        if version != record.version {
            return Err(FsError::new(
                libc::EACCES,
                format!("the grant of inode {root_ino} holds an out-of-date key"),
            ));
        }
        // `Node::new` proves the key: whatever the grant claims, one that
        // doesn't open the record isn't this node's.
        let root = Node::new(root_ino, record, key)?;
        let mut parent = (root_ino, self.keep(root_ino, root));
        for (ino, bytes) in nodes {
            let record = NodeKeys::decode(&bytes).map_err(|e| corrupt(ino, e))?;
            let wrapping = parent.1.key_at(parent.0, record.parent_version)?;
            let key = record.open(ino, &wrapping).map_err(|e| corrupt(ino, e))?;
            parent = (ino, self.keep(ino, Node::new(ino, record, key)?));
        }
        Ok(parent.1)
    }

    fn keep(&self, ino: u64, node: Node) -> Arc<Node> {
        let node = Arc::new(node);
        self.nodes.lock().unwrap().insert(ino, Arc::clone(&node));
        node
    }

    /// Reads this account's grants afresh, returning the root's entries:
    /// each grant's label, made unique, and its inode.
    pub async fn root_entries(&self) -> Result<Vec<(OsString, u64)>, FsError> {
        let mut grants = self.remote.list_grants().await?;
        grants.sort_by_key(|g| g.ino);
        let mut roots = Roots::default();
        for grant in grants {
            let label = self
                .identity
                .open_label(grant.ino, &grant.sealed_label)
                .map(OsString::from_vec)
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

    /// Whether `name` is taken in the root already, whatever is granted:
    /// the live root's `.snapshot`, which a grant labelled so gives way to.
    fn reserved(&self, name: &OsStr) -> bool {
        self.remote.snapshot().is_none() && name == SNAPSHOT_DIR
    }

    /// The grant `name` stands for in the root, reading the grants afresh
    /// if it isn't one already known.
    pub async fn root_lookup(&self, name: &OsStr) -> Result<u64, FsError> {
        if let Some(&ino) = self.roots.lock().unwrap().by_name.get(name) {
            return Ok(ino);
        }
        self.root_entries()
            .await?
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, ino)| ino)
            .ok_or_else(|| FsError::errno(libc::ENOENT))
    }

    /// Whether `ino` is granted to this account: one of the root's entries,
    /// whose `..` is the root.
    pub fn is_grant_root(&self, ino: u64) -> bool {
        self.roots.lock().unwrap().inos.contains(&ino)
    }

    /// A reserved inode and key for a new child `name` of `parent`, and
    /// the tag it is filed under.
    async fn new_child(
        &self,
        parent: u64,
        name: &OsStr,
    ) -> Result<(NewNode, Node, OsString), FsError> {
        let parent_node = self.node(parent).await?;
        let ino = self.remote.allocate_inode().await?;
        let (record, key) =
            NodeKeys::create(ino, Some((&parent_node.key, parent_node.record.version)));
        let tag = parent_node.tag(name);
        let new = NewNode {
            ino,
            keys: record.encode(),
            sealed_name: parent_node.seal(parent, &tag, name),
        };
        Ok((new, Node::new(ino, record, key)?, tag))
    }

    /// The tag `name` is filed under in directory `parent`.
    async fn tag(&self, parent: u64, name: &OsStr) -> Result<OsString, FsError> {
        Ok(self.node(parent).await?.tag(name))
    }

    pub async fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        let tag = self.tag(parent, name).await?;
        self.remote.lookup(parent, &tag).await
    }

    /// Drops what is held for an inode that is gone.
    fn forget_inode(&self, ino: u64) {
        self.nodes.lock().unwrap().remove(&ino);
        self.cache.lock().unwrap().invalidate_ino(self.space, ino);
    }

    /// Removes a file, as `Remote::unlink`.
    pub async fn unlink(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.unlink(parent, &tag).await?;
        self.forget_inode(ino);
        Ok(ino)
    }

    /// Removes an empty directory, as `Remote::rmdir`.
    pub async fn rmdir(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.rmdir(parent, &tag).await?;
        self.forget_inode(ino);
        Ok(ino)
    }

    /// Directory `ino`'s entries, with their real names. An entry whose
    /// name doesn't open, or doesn't match its tag, isn't one this
    /// directory's key holders made: it is left out, and said so.
    pub async fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let items = self.remote.readdir(ino).await?;
        let mut dir = self.node(ino).await?;
        // Names sealed under a key newer than the one known here: someone
        // rotated it since.
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
                // `.` and `..`, which have no tag to hide behind.
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
                        item.name.as_bytes(),
                        &item.sealed_name,
                    )
                    .map_err(|e| corrupt(ino, e))
                });
            match opened {
                Ok(name) => {
                    item.name = OsString::from_vec(name);
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

    /// Creates a file, as `Remote::create`.
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

    /// Moves a name, as `Remote::rename`: the new name sealed under the
    /// new parent's key, and the moved node's key re-wrapped under it if
    /// the parent changes.
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
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
        let to = self.node(new_parent).await?;
        let tag = from.tag(name);
        let new_tag = to.tag(new_name);
        let ino = self.remote.lookup(parent, &tag).await?.ino;
        let mut sealed = SealedMove {
            ino,
            node_keys: Vec::new(),
            sealed_name: to.seal(new_parent, &new_tag, new_name),
        };
        let mut rewrapped = None;
        if parent != new_parent {
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

    /// A new volume, shown in this account's root as `label`.
    pub async fn create_volume(&self, label: &OsStr, perm: u16) -> Result<Attr, FsError> {
        if label == SNAPSHOT_DIR || self.root_lookup(label).await.is_ok() {
            return Err(FsError::errno(libc::EEXIST));
        }
        let ino = self.remote.allocate_inode().await?;
        let (record, key) = NodeKeys::create(ino, None);
        let me = self.identity.public_key();
        let sealed_key = seal_grant(&me, ino, record.version, &key);
        let sealed_label = seal_label(&me, ino, label.as_bytes());
        let new = NewNode {
            ino,
            keys: record.encode(),
            sealed_name: Vec::new(),
        };
        let node = Node::new(ino, record, key)?;
        let attr = self
            .remote
            .create_volume(&new, perm, sealed_key, sealed_label)
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

    /// Grants directory `ino`, and everything under it, to `user`, to show
    /// up in their root as `label`. Returns the public key it was sealed
    /// to -- the server's word for whose it is, which is worth checking
    /// against the fingerprint the grantee saw when they enrolled.
    pub async fn grant(
        &self,
        ino: u64,
        user: &str,
        writable: bool,
        label: &OsStr,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        let public_key = self.remote.public_key(user).await?;
        let public_key = self.known.check(user, &public_key)?;
        let node = self.node(ino).await?;
        let grant = |node: &Node| Grant {
            ino,
            writable,
            key_version: node.record.version,
            sealed_key: seal_grant(&public_key, ino, node.record.version, &node.key),
            sealed_label: seal_label(&public_key, ino, label.as_bytes()),
        };
        match self.remote.grant(user, grant(&node)).await {
            Err(e) if expired(&e) => {
                let node = self.freshen(ino).await?;
                self.remote.grant(user, grant(&node)).await?;
            }
            other => other?,
        }
        Ok(public_key)
    }

    /// The inode at `path`: a root entry's name, then names under it,
    /// separated by `/`.
    pub async fn resolve(&self, path: &str) -> Result<u64, FsError> {
        let mut parts = path.split('/').filter(|p| !p.is_empty() && *p != ".");
        let first = parts
            .next()
            .ok_or_else(|| FsError::new(libc::EINVAL, "an empty path"))?;
        let mut ino = self.root_lookup(OsStr::new(first)).await?;
        for part in parts {
            ino = self.lookup(ino, OsStr::new(part)).await?.ino;
        }
        Ok(ino)
    }

    /// File `ino`'s bytes `[offset, offset + len)`, as far as its size,
    /// with holes reading as zeros. Chunks cached here are served from the
    /// cache once the server confirms they haven't changed.
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

    /// The plaintext a read's answer for one chunk stands for: the cached
    /// bytes it confirmed, or the bytes it sent, opened and cached. `node`
    /// is the file's key, fetched the first time one is needed.
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
            // Confirmed unchanged on the server, but invalidated here
            // meanwhile -- a write of ours may have replaced it: read it
            // afresh.
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

    /// Opens a chunk as sent (empty for a hole) and caches it at its seq.
    async fn open_and_keep(
        &self,
        ino: u64,
        chunk: SealedChunk,
        generation: u64,
        node: &mut Option<Arc<Node>>,
    ) -> Result<Arc<[u8]>, FsError> {
        let plain: Arc<[u8]> = match &chunk.blob {
            Some(blob) => {
                let version = sealed_version(blob).map_err(|e| corrupt(ino, e))?;
                let known = match node.take() {
                    Some(known) => known,
                    None => self.node(ino).await?,
                };
                // Sealed under a key newer than the one known here:
                // someone rotated it since.
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

    /// Chunks `first..=last` of `ino`, in as many asks as the server's cap
    /// takes, and the file's size as of the last. `known[i]` is the seq
    /// chunk `first + i` is cached at, or 0.
    async fn fetch(
        &self,
        ino: u64,
        first: u64,
        last: u64,
        known: &[u64],
    ) -> Result<(u64, Vec<SealedChunk>), FsError> {
        let mut chunks = Vec::new();
        let mut size = 0;
        let mut next = first;
        while next <= last {
            let count = (last - next + 1).min(u64::from(u32::MAX)) as u32;
            let known = &known[(next - first) as usize..];
            let (attr, got) = self.remote.read_chunks(ino, next, count, known).await?;
            size = attr.size;
            let Some(after) = got.last().map(|c| c.index + 1) else {
                return Err(FsError::new(libc::EIO, "the server returned no chunks"));
            };
            next = after;
            chunks.extend(got);
        }
        Ok((size, chunks))
    }

    /// One chunk of `ino`, and the store's seq for it; `unchanged`, with
    /// no bytes, if it is still at `known` (0 for none).
    async fn fetch_one(&self, ino: u64, index: u64, known: u64) -> Result<SealedChunk, FsError> {
        let (_, mut got) = self.remote.read_chunks(ino, index, 1, &[known]).await?;
        got.pop()
            .filter(|c| c.index == index)
            .ok_or_else(|| FsError::new(libc::EIO, format!("chunk {index} of inode {ino} missing")))
    }

    /// Opens a sealed chunk of `ino`, with whichever of its key versions
    /// it was sealed under.
    fn open(&self, node: &Node, ino: u64, index: u64, blob: &[u8]) -> Result<Vec<u8>, FsError> {
        let version = sealed_version(blob).map_err(|e| corrupt(ino, e))?;
        let key = node.key_at(ino, version)?;
        open_chunk(&key, ino, index, blob).map_err(|e| corrupt(ino, e))
    }

    /// The current plaintext of chunk `index` of `ino`, and the seq it is
    /// at, to change and write back: the cached copy if there is one --
    /// unconfirmed, since the write names the seq it expects and the
    /// server refuses it if the copy was out of date -- or else fetched.
    async fn base(&self, node: &Node, ino: u64, index: u64) -> Result<(Vec<u8>, u64), FsError> {
        if let Lookup::Unconfirmed { data, version, .. } =
            self.cache.lock().unwrap().get(self.space, ino, index)
        {
            return Ok((data.to_vec(), version));
        }
        let chunk = self.fetch_one(ino, index, 0).await?;
        let plain = match &chunk.blob {
            Some(blob) => self.open(node, ino, index, blob)?,
            None => Vec::new(),
        };
        Ok((plain, chunk.seq))
    }

    /// Writes `data` at `offset` in file `ino`, a batch at a time, growing
    /// it as needed. A failure says how many leading bytes were stored, by
    /// whole batches.
    pub async fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<Attr, WriteError> {
        let failed = |written, error| WriteError { written, error };
        let mut node = self.node(ino).await.map_err(|e| failed(0, e))?;
        if data.is_empty() {
            // Still a write, as far as mtime is concerned.
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
        let mut attr = None;
        let mut cursor = 0;
        for group in spans.chunks(per_batch) {
            let bytes: usize = group.iter().map(|&(_, _, n)| n).sum();
            let end = offset + (cursor + bytes) as u64;
            let piece = &data[cursor..cursor + bytes];
            let stored = match self.write_batch(&node, ino, group, piece, end).await {
                // A stale key, here or above: new keys, then again.
                Err(e) if expired(&e) => {
                    node = self.freshen(ino).await.map_err(|e| failed(cursor, e))?;
                    self.write_batch(&node, ino, group, piece, end).await
                }
                other => other,
            }
            .map_err(|e| failed(cursor, e))?;
            attr = Some(stored);
            cursor += bytes;
        }
        Ok(attr.expect("a non-empty write has at least one batch"))
    }

    /// One batch of `write`: seals each span's chunk -- whole, or changed
    /// from its current bytes and re-sealed -- and stores them all, or
    /// does it over if a chunk changed before they could be. What it
    /// stores, it caches.
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
                    blob: seal_chunk(&node.key, node.record.version, ino, index, &plain),
                });
                plains.push((index, plain));
            }
            match self.remote.write_chunks(ino, &writes, end).await {
                Err(e) if changed(&e) => {
                    // A base was out of date: drop it, and fetch afresh.
                    let mut cache = self.cache.lock().unwrap();
                    for &(index, ..) in spans {
                        cache.invalidate(self.space, ino, index..=index);
                    }
                }
                Err(e) => {
                    // Whether it landed is unknown: trust nothing cached.
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
            libc::EAGAIN,
            format!("inode {ino}'s chunks kept changing under this write"),
        ))
    }

    /// Applies `changes` to `ino` (see `Remote::setattr`). Cutting a file
    /// short first re-seals the chunk its new end falls in, cut short too,
    /// which the server can't do itself.
    pub async fn setattr(&self, ino: u64, changes: SetAttr) -> Result<Attr, FsError> {
        if let Some(size) = changes.size {
            self.truncate(ino, size).await?;
        }
        let changed = self.remote.setattr(ino, changes).await;
        if let Some(size) = changes.size {
            // The chunks past the new end are gone, whatever came back.
            let chunk_size = self.remote.chunk_size();
            self.cache
                .lock()
                .unwrap()
                .invalidate(self.space, ino, size / chunk_size..=u64::MAX);
        }
        changed
    }

    /// Re-seals the chunk `new_size` falls in without what lies past it.
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
        let node = self.node(ino).await?;
        for _ in 0..CHANGE_RETRIES {
            let (mut plain, seq) = self.base(&node, ino, index).await?;
            if plain.len() <= keep {
                return Ok(());
            }
            plain.truncate(keep);
            let write = ChunkWrite {
                index,
                expected_seq: Some(seq),
                blob: seal_chunk(&node.key, node.record.version, ino, index, &plain),
            };
            let written = self.remote.write_chunks(ino, &[write], 0).await;
            // Whatever happened, the cached copy is superseded.
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
            libc::EAGAIN,
            format!("inode {ino}'s last chunk kept changing under this truncate"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_keys_survive_a_reload_and_a_different_key_is_refused() {
        let file = std::env::temp_dir().join(format!("raft5fs-known-keys-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let known = KnownKeys::load(file.clone()).unwrap();
        known.check("alice", &[1; 32]).unwrap();
        known.check("bob", &[2; 32]).unwrap();

        let again = KnownKeys::load(file.clone()).unwrap();
        again.check("alice", &[1; 32]).unwrap();
        assert_eq!(
            again.check("alice", &[9; 32]).unwrap_err().errno,
            libc::EPERM
        );
        assert_eq!(again.check("alice", &[1; 31]).unwrap_err().errno, libc::EIO);

        again.forget("alice").unwrap();
        let after = KnownKeys::load(file.clone()).unwrap();
        after.check("alice", &[9; 32]).unwrap();
        assert_eq!(after.check("bob", &[3; 32]).unwrap_err().errno, libc::EPERM);
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
