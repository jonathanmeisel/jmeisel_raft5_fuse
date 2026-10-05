//! The client's side of an encrypted filesystem: inode keys, and the root
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
//! byte range the way it does for an unencrypted filesystem. A write that
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
//! **The root.** The server's real root is no one's to see. What a mount
//! shows at its root instead is virtual: one entry per grant made to this
//! account, named as the granter named it (a label sealed to this account,
//! so the server can't read it either). Making a directory there makes a
//! volume -- a new top-level directory, granted to its maker -- and
//! removing one removes the volume.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::{Arc, Mutex};

use raft5fs_crypto::Key;
use raft5fs_crypto::data::{
    name_tag, open_chunk, open_name, seal_chunk, seal_name, sealed_version,
};
use raft5fs_crypto::identity::{Identity, PUBLIC_KEY_LEN, seal_grant, seal_label};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_proto::types::{
    Attr, ChunkWrite, DirItem, FsError, Grant, KeyPath, NewNode, SealedChunk, SealedMove,
    WriteError,
};

use crate::remote::Remote;

/// The inode the kernel knows a mount's root by. On an encrypted
/// filesystem it is the virtual root, never the server's real one.
pub const VIRTUAL_ROOT: u64 = 1;

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
    nodes: Mutex<HashMap<u64, Arc<Node>>>,
    roots: Mutex<Roots>,
}

impl Vault {
    /// The vault of `remote`'s account, which must have logged in to an
    /// encrypted filesystem.
    pub fn new(remote: Arc<Remote>) -> Result<Self, FsError> {
        let identity = remote
            .identity()
            .ok_or_else(|| FsError::new(libc::EOPNOTSUPP, "not an encrypted filesystem's login"))?;
        Ok(Self {
            remote,
            identity,
            nodes: Mutex::new(HashMap::new()),
            roots: Mutex::new(Roots::default()),
        })
    }

    pub fn remote(&self) -> &Arc<Remote> {
        &self.remote
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
            while roots.by_name.contains_key(&name) || name.is_empty() {
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

    /// Removes a file, as `Remote::unlink`.
    pub async fn unlink(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.unlink(parent, &tag).await?;
        self.nodes.lock().unwrap().remove(&ino);
        Ok(ino)
    }

    /// Removes an empty directory, as `Remote::rmdir`.
    pub async fn rmdir(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.rmdir(parent, &tag).await?;
        self.nodes.lock().unwrap().remove(&ino);
        Ok(ino)
    }

    /// Directory `ino`'s entries, with their real names. An entry whose
    /// name doesn't open, or doesn't match its tag, isn't one this
    /// directory's key holders made: it is left out, and said so.
    pub async fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let items = self.remote.readdir(ino).await?;
        let dir = self.node(ino).await?;
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
        let (new, node, tag) = self.new_child(parent, name).await?;
        let attr = self.remote.mkdir(parent, &tag, perm, Some(&new)).await?;
        self.keep(attr.ino, node);
        Ok(attr)
    }

    /// Creates and opens a file, as `Remote::create`.
    pub async fn create(
        &self,
        parent: u64,
        name: &OsStr,
        perm: u16,
    ) -> Result<(Attr, String), FsError> {
        let (new, node, tag) = self.new_child(parent, name).await?;
        let created = self.remote.create(parent, &tag, perm, Some(&new)).await?;
        self.keep(created.0.ino, node);
        Ok(created)
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
            .rename(parent, &tag, new_parent, &new_tag, noreplace, Some(&sealed))
            .await?;
        if let Some(node) = rewrapped {
            self.keep(ino, node);
        }
        if let Some(victim) = replaced {
            self.nodes.lock().unwrap().remove(&victim);
        }
        Ok(replaced)
    }

    /// A new volume, shown in this account's root as `label`.
    pub async fn create_volume(&self, label: &OsStr, perm: u16) -> Result<Attr, FsError> {
        if self.root_lookup(label).await.is_ok() {
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
        self.nodes.lock().unwrap().remove(&ino);
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
        let public_key: [u8; PUBLIC_KEY_LEN] = self
            .remote
            .public_key(user)
            .await?
            .try_into()
            .map_err(|_| FsError::new(libc::EIO, format!("{user}'s public key is malformed")))?;
        let node = self.node(ino).await?;
        let grant = Grant {
            ino,
            writable,
            key_version: node.record.version,
            sealed_key: seal_grant(&public_key, ino, node.record.version, &node.key),
            sealed_label: seal_label(&public_key, ino, label.as_bytes()),
        };
        self.remote.grant(user, grant).await?;
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
    /// with holes reading as zeros.
    pub async fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let chunk_size = self.remote.chunk_size();
        let first = offset / chunk_size;
        let last = (offset + len as u64 - 1) / chunk_size;
        let (size, chunks) = self.fetch(ino, first, last).await?;
        if offset >= size {
            return Ok(Vec::new());
        }
        let end = (offset + len as u64).min(size);
        let mut out = vec![0; (end - offset) as usize];
        let node = self.node(ino).await?;
        for chunk in chunks {
            let Some(blob) = &chunk.blob else {
                continue;
            };
            let plain = self.open(&node, ino, chunk.index, blob)?;
            let start = chunk.index * chunk_size;
            let lo = start.max(offset);
            let hi = (start + plain.len() as u64).min(end);
            if lo < hi {
                out[(lo - offset) as usize..(hi - offset) as usize]
                    .copy_from_slice(&plain[(lo - start) as usize..(hi - start) as usize]);
            }
        }
        Ok(out)
    }

    /// Chunks `first..=last` of `ino`, in as many asks as the server's cap
    /// takes, and the file's size as of the last.
    async fn fetch(
        &self,
        ino: u64,
        first: u64,
        last: u64,
    ) -> Result<(u64, Vec<SealedChunk>), FsError> {
        let mut chunks = Vec::new();
        let mut size = 0;
        let mut next = first;
        while next <= last {
            let count = (last - next + 1).min(u64::from(u32::MAX)) as u32;
            let (attr, got) = self.remote.read_chunks(ino, next, count).await?;
            size = attr.size;
            let Some(after) = got.last().map(|c| c.index + 1) else {
                return Err(FsError::new(libc::EIO, "the server returned no chunks"));
            };
            next = after;
            chunks.extend(got);
        }
        Ok((size, chunks))
    }

    /// One chunk of `ino`, and the store's sequence number for it.
    async fn fetch_one(&self, ino: u64, index: u64) -> Result<SealedChunk, FsError> {
        let (_, mut got) = self.remote.read_chunks(ino, index, 1).await?;
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

    /// Writes `data` at `offset` in file `ino`, a batch at a time, growing
    /// it as needed. As `Remote::write`, a failure says how many leading
    /// bytes were stored, by whole batches.
    pub async fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<Attr, WriteError> {
        let failed = |written, error| WriteError { written, error };
        let node = self.node(ino).await.map_err(|e| failed(0, e))?;
        if data.is_empty() {
            // Still a write, as far as mtime is concerned.
            return self
                .remote
                .write_chunks(ino, &[], offset)
                .await
                .map_err(|e| failed(0, e));
        }
        let chunk_size = self.remote.chunk_size();
        let per_batch = (self.remote.batch_bytes() / chunk_size).max(1) as usize;
        let spans = spans(chunk_size, offset, data.len());
        let mut attr = None;
        let mut cursor = 0;
        for group in spans.chunks(per_batch) {
            let bytes: usize = group.iter().map(|&(_, _, n)| n).sum();
            let end = offset + (cursor + bytes) as u64;
            let stored = self
                .write_batch(&node, ino, group, &data[cursor..cursor + bytes], end)
                .await
                .map_err(|e| failed(cursor, e))?;
            attr = Some(stored);
            cursor += bytes;
        }
        Ok(attr.expect("a non-empty write has at least one batch"))
    }

    /// One batch of `write`: seals each span's chunk -- whole, or read,
    /// changed and re-sealed -- and stores them all, or does it over if a
    /// chunk read changed before they could be.
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
            let mut writes = Vec::with_capacity(spans.len());
            let mut cursor = 0;
            for &(index, within, n) in spans {
                let piece = &data[cursor..cursor + n];
                cursor += n;
                let (plain, expected_seq) = if within == 0 && n as u64 == chunk_size {
                    (piece.to_vec(), None)
                } else {
                    let chunk = self.fetch_one(ino, index).await?;
                    let mut plain = match &chunk.blob {
                        Some(blob) => self.open(node, ino, index, blob)?,
                        None => Vec::new(),
                    };
                    if plain.len() < within + n {
                        plain.resize(within + n, 0);
                    }
                    plain[within..within + n].copy_from_slice(piece);
                    (plain, Some(chunk.seq))
                };
                writes.push(ChunkWrite {
                    index,
                    expected_seq,
                    blob: seal_chunk(&node.key, node.record.version, ino, index, &plain),
                });
            }
            match self.remote.write_chunks(ino, &writes, end).await {
                Err(e) if e.errno == libc::EAGAIN => continue,
                other => return other,
            }
        }
        Err(FsError::new(
            libc::EAGAIN,
            format!("inode {ino}'s chunks kept changing under this write"),
        ))
    }

    /// Readies file `ino` to be cut to `new_size`: re-seals the chunk the
    /// new end falls in without what lies past it, which the server can't
    /// cut itself. The truncation proper -- the size, and dropping the
    /// chunks past it -- is the setattr that follows.
    pub async fn truncate(&self, ino: u64, new_size: u64) -> Result<(), FsError> {
        let chunk_size = self.remote.chunk_size();
        let keep = (new_size % chunk_size) as usize;
        if keep == 0 {
            return Ok(());
        }
        let index = new_size / chunk_size;
        let node = self.node(ino).await?;
        for _ in 0..CHANGE_RETRIES {
            let chunk = self.fetch_one(ino, index).await?;
            let Some(blob) = &chunk.blob else {
                return Ok(());
            };
            let mut plain = self.open(&node, ino, index, blob)?;
            if plain.len() <= keep {
                return Ok(());
            }
            plain.truncate(keep);
            let write = ChunkWrite {
                index,
                expected_seq: Some(chunk.seq),
                blob: seal_chunk(&node.key, node.record.version, ino, index, &plain),
            };
            match self.remote.write_chunks(ino, &[write], 0).await {
                Err(e) if e.errno == libc::EAGAIN => continue,
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
    fn spans_cover_a_range_chunk_by_chunk() {
        assert_eq!(spans(10, 0, 0), []);
        assert_eq!(spans(10, 3, 4), [(0, 3, 4)]);
        assert_eq!(spans(10, 0, 10), [(0, 0, 10)]);
        assert_eq!(spans(10, 8, 15), [(0, 8, 2), (1, 0, 10), (2, 0, 3)]);
    }
}
