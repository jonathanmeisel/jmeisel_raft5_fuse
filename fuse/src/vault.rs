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
use raft5fs_crypto::identity::{Identity, PUBLIC_KEY_LEN, seal_grant, seal_label};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_proto::types::{Attr, FsError, Grant, KeyPath, NewNode};

use crate::remote::Remote;

/// The inode the kernel knows a mount's root by. On an encrypted
/// filesystem it is the virtual root, never the server's real one.
pub const VIRTUAL_ROOT: u64 = 1;

/// An inode's key record, and its current key.
pub struct Node {
    pub record: NodeKeys,
    pub key: Key,
}

impl Node {
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
        // Proves the key: one that doesn't open the record isn't this
        // node's, whatever the grant claims.
        record
            .name_key(root_ino, &key)
            .map_err(|e| corrupt(root_ino, e))?;
        let mut parent = (root_ino, self.keep(root_ino, Node { record, key }));
        for (ino, bytes) in nodes {
            let record = NodeKeys::decode(&bytes).map_err(|e| corrupt(ino, e))?;
            let wrapping = parent.1.key_at(parent.0, record.parent_version)?;
            let key = record.open(ino, &wrapping).map_err(|e| corrupt(ino, e))?;
            parent = (ino, self.keep(ino, Node { record, key }));
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

    /// A reserved inode and key for a new child of `parent`.
    async fn new_child(&self, parent: u64) -> Result<(NewNode, Node), FsError> {
        let parent_node = self.node(parent).await?;
        let ino = self.remote.allocate_inode().await?;
        let (record, key) =
            NodeKeys::create(ino, Some((&parent_node.key, parent_node.record.version)));
        let new = NewNode {
            ino,
            keys: record.encode(),
        };
        Ok((new, Node { record, key }))
    }

    pub async fn mkdir(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        let (new, node) = self.new_child(parent).await?;
        let attr = self.remote.mkdir(parent, name, perm, Some(&new)).await?;
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
        let (new, node) = self.new_child(parent).await?;
        let created = self.remote.create(parent, name, perm, Some(&new)).await?;
        self.keep(created.0.ino, node);
        Ok(created)
    }

    /// Moves a name, as `Remote::rename`, re-wrapping the moved node's key
    /// under its new parent's if the parent changes.
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
        if parent == new_parent {
            return self
                .remote
                .rename(parent, name, new_parent, new_name, noreplace, None)
                .await;
        }
        let ino = self.remote.lookup(parent, name).await?.ino;
        let moved = self.node(ino).await?;
        let to = self.node(new_parent).await?;
        let record = moved
            .record
            .rewrap(ino, &moved.key, (&to.key, to.record.version))
            .map_err(|e| corrupt(ino, e))?;
        let replaced = self
            .remote
            .rename(
                parent,
                name,
                new_parent,
                new_name,
                noreplace,
                Some((ino, &record.encode())),
            )
            .await?;
        let key = moved.key.clone();
        self.keep(ino, Node { record, key });
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
        };
        let attr = self
            .remote
            .create_volume(&new, perm, sealed_key, sealed_label)
            .await?;
        self.keep(ino, Node { record, key });
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
            ino = self.remote.lookup(ino, OsStr::new(part)).await?.ino;
        }
        Ok(ino)
    }
}
