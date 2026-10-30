//! Folders and files that no account can reach any more, and removing them.
//!
//! A node is reachable while some account has a grant of it, or of a folder
//! above it. When the last such account is removed, or enrolls again (which
//! drops its grants), the node stays: in the store, and its blocks in object
//! storage, sealed under keys that nobody has. Nothing can open it again.
//!
//! - `unreachable` finds the largest parts of the tree that nobody can reach
//!   and that hold no grant anywhere inside. A folder above a granted one
//!   stays, as the way down to it.
//! - `removal_impact` says what removing one account's grants would leave
//!   unreachable.
//! - `remove_unreachable` deletes one such part, a node at a time from the
//!   leaves up, as a removal by a user does. Each step checks again, in its
//!   own transaction, that no grant reaches the node. Nobody can grant a
//!   node they can't reach, so this only guards against a stale scan.

use std::collections::{HashMap, HashSet};

use super::*;
use crate::layout::{GRANTS_PREFIX, ROOT_INO, dirent_ino, dirent_prefix};
use raft5fs_proto::types::Unreachable;

/// A node of the tree, as `load_tree` reads it.
pub(super) struct Node {
    pub(super) parent: u64,
    /// Its directory entry's name (the tag) in `parent`.
    name: Vec<u8>,
    pub(super) kind: Kind,
    pub(super) size: u64,
    mtime: SystemTime,
    pub(super) children: Vec<u64>,
}

/// Every live node, by inode, the root included, as of a scan.
pub(super) type Tree = HashMap<u64, Node>;

impl FsCore {
    /// The largest parts of the tree that no account can reach (see the top
    /// of this file), with their sizes.
    pub async fn unreachable(&self) -> Result<Vec<Unreachable>, FsError> {
        let tree = self.load_tree().await?;
        let granted: HashSet<u64> = self.granted().await?.into_keys().collect();
        Ok(roots(&tree, &granted)
            .into_iter()
            .map(|ino| stats(&tree, ino))
            .collect())
    }

    /// What would become unreachable if `user` had no grants: the parts
    /// that only `user` can reach now.
    pub async fn removal_impact(&self, user: &str) -> Result<Vec<Unreachable>, FsError> {
        let tree = self.load_tree().await?;
        let granted = self.granted().await?;
        let now: HashSet<u64> = granted.keys().copied().collect();
        let after: HashSet<u64> = granted
            .iter()
            .filter(|(_, users)| users.iter().any(|u| u != user))
            .map(|(&ino, _)| ino)
            .collect();
        let already: HashSet<u64> = roots(&tree, &now).into_iter().collect();
        Ok(roots(&tree, &after)
            .into_iter()
            .filter(|ino| !already.contains(ino))
            .map(|ino| stats(&tree, ino))
            .collect())
    }

    /// Deletes unreachable part `ino`, with everything in it, from the store
    /// and object storage. `EINVAL` unless `unreachable` lists it.
    pub async fn remove_unreachable(&self, ino: u64) -> Result<(), FsError> {
        let tree = self.load_tree().await?;
        let granted: HashSet<u64> = self.granted().await?.into_keys().collect();
        if !roots(&tree, &granted).contains(&ino) {
            return Err(FsError::new(
                libc::EINVAL,
                format!("inode {ino} isn't one that nobody can reach"),
            ));
        }
        for node in post_order(&tree, ino) {
            let n = &tree[&node];
            self.remove_unreached(node, n.parent, &n.name, n.kind)
                .await?;
            self.finish_removal(node).await?;
        }
        Ok(())
    }

    /// Unlinks `ino` from `parent`, as `remove_child` does, if still no
    /// grant reaches it. A directory must be empty by now. Does nothing if
    /// it is gone already.
    async fn remove_unreached(
        &self,
        ino: u64,
        parent: u64,
        name: &[u8],
        kind: Kind,
    ) -> Result<(), FsError> {
        let dirent = &dirent_key(parent, OsStr::from_bytes(name));
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let Some(mut entry) = live(ino, txn.read_one(&attr_key(ino)).await?.value) else {
                return Ok(Ok(()));
            };
            // No grant of it, or of any folder above it.
            let mut at = ino;
            while at != ROOT_INO {
                if !grants::grants_of(&txn, at).await?.is_empty() {
                    return Ok(Err(FsError::new(
                        libc::EBUSY,
                        format!("inode {at} has a grant now: not removing inode {ino}"),
                    )));
                }
                at = match txn.read_one(&attr_key(at)).await?.value {
                    Some(bytes) => decode_entry(at, &bytes).parent,
                    None => ROOT_INO,
                };
            }
            if named(&txn, dirent).await? != Some(ino) {
                return Ok(Ok(()));
            }
            entry.mark_deleted();
            entry.attr.ctime = SystemTime::now();
            write_entry(&txn, &entry).await?;
            if kind == Kind::Directory && !is_empty_dir(&txn, ino).await? {
                return Ok(Err(FsError::new(
                    libc::EBUSY,
                    format!("folder {ino} has new entries: not removing it"),
                )));
            }
            txn.write(dirent, None).await?;
            txn.write(&tombstone_key(ino), Some(&[1])).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Every live node from the root down, read outside a transaction.
    pub(super) async fn load_tree(&self) -> Result<Tree, FsError> {
        let mut tree = Tree::new();
        tree.insert(
            ROOT_INO,
            Node {
                parent: ROOT_INO,
                name: Vec::new(),
                kind: Kind::Directory,
                size: 0,
                mtime: SystemTime::UNIX_EPOCH,
                children: Vec::new(),
            },
        );
        let mut dirs = vec![ROOT_INO];
        while let Some(dir) = dirs.pop() {
            let prefix = dirent_prefix(dir);
            let mut keys = Vec::new();
            let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
            while let Some(key) = next_key(&mut iter).await? {
                if !key.starts_with(&prefix) {
                    break;
                }
                keys.push(key);
            }
            if keys.is_empty() {
                continue;
            }
            let mut children = Vec::new();
            for (key, value) in keys.iter().zip(self.client.get_many(&keys).await?) {
                if let Some(value) = value {
                    children.push((dirent_ino(&value), key[prefix.len()..].to_vec()));
                }
            }
            let attrs: Vec<Vec<u8>> = children.iter().map(|&(ino, _)| attr_key(ino)).collect();
            for ((ino, name), attr) in children
                .into_iter()
                .zip(self.client.get_many(&attrs).await?)
            {
                let Some(entry) = live(ino, attr) else {
                    continue;
                };
                if entry.attr.kind == Kind::Directory {
                    dirs.push(ino);
                }
                if let Some(parent) = tree.get_mut(&dir) {
                    parent.children.push(ino);
                }
                tree.insert(
                    ino,
                    Node {
                        parent: dir,
                        name,
                        kind: entry.attr.kind,
                        size: entry.attr.size,
                        mtime: entry.attr.mtime,
                        children: Vec::new(),
                    },
                );
            }
        }
        Ok(tree)
    }

    /// Every granted inode, with the users that hold its grants.
    async fn granted(&self) -> Result<HashMap<u64, Vec<String>>, FsError> {
        let mut granted: HashMap<u64, Vec<String>> = HashMap::new();
        let mut iter = self.client.key_iterator(GRANTS_PREFIX, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(GRANTS_PREFIX) {
                break;
            }
            if let Some(ino) = key.get(1..9) {
                let ino = u64::from_be_bytes(ino.try_into().unwrap());
                let user = String::from_utf8_lossy(&key[9..]).into_owned();
                granted.entry(ino).or_default().push(user);
            }
        }
        Ok(granted)
    }
}

/// The largest parts of `tree` that no grant in `granted` reaches and that
/// hold none: each node with no grant at or above it, none below it, whose
/// parent is the root or holds a grant below it.
fn roots(tree: &Tree, granted: &HashSet<u64>) -> Vec<u64> {
    // From the root down: reached if granted, or its parent is reached.
    let mut order = vec![ROOT_INO];
    let mut reached = HashMap::from([(ROOT_INO, false)]);
    let mut i = 0;
    while i < order.len() {
        let ino = order[i];
        for &child in &tree[&ino].children {
            reached.insert(child, reached[&ino] || granted.contains(&child));
            order.push(child);
        }
        i += 1;
    }
    // From the leaves up: whether a grant is at or below it.
    let mut holds: HashMap<u64, bool> = HashMap::new();
    for &ino in order.iter().rev() {
        let below = tree[&ino].children.iter().any(|c| holds[c]);
        holds.insert(ino, granted.contains(&ino) || below);
    }
    order
        .into_iter()
        .filter(|&ino| ino != ROOT_INO && !reached[&ino] && !holds[&ino])
        .filter(|&ino| {
            let parent = tree[&ino].parent;
            parent == ROOT_INO || holds[&parent]
        })
        .collect()
}

/// `ino` and everything below it, children before their parents.
pub(super) fn post_order(tree: &Tree, ino: u64) -> Vec<u64> {
    let mut order = vec![ino];
    let mut i = 0;
    while i < order.len() {
        order.extend(tree[&order[i]].children.iter().copied());
        i += 1;
    }
    order.reverse();
    order
}

/// What part `ino` of `tree` holds.
fn stats(tree: &Tree, ino: u64) -> Unreachable {
    let mut out = Unreachable {
        ino,
        volume: tree[&ino].parent == ROOT_INO,
        files: 0,
        folders: 0,
        bytes: 0,
        modified: SystemTime::UNIX_EPOCH,
    };
    for node in post_order(tree, ino) {
        let n = &tree[&node];
        match n.kind {
            Kind::Directory => out.folders += 1,
            Kind::File => {
                out.files += 1;
                out.bytes += n.size;
            }
        }
        out.modified = out.modified.max(n.mtime);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree from `(ino, parent, kind)`, in parent-first order.
    fn tree(nodes: &[(u64, u64, Kind)]) -> Tree {
        let mut tree = Tree::new();
        let node = |parent, kind| Node {
            parent,
            name: Vec::new(),
            kind,
            size: 10,
            mtime: SystemTime::UNIX_EPOCH,
            children: Vec::new(),
        };
        tree.insert(ROOT_INO, node(ROOT_INO, Kind::Directory));
        for &(ino, parent, kind) in nodes {
            tree.insert(ino, node(parent, kind));
            tree.get_mut(&parent).unwrap().children.push(ino);
        }
        tree
    }

    #[test]
    fn the_largest_unreached_parts_without_grants_inside() {
        use Kind::{Directory as D, File as F};
        // Volume 2 (granted), volume 3 (not), volume 4 (not, but 6 inside is).
        let t = tree(&[
            (2, 1, D),
            (10, 2, F),
            (3, 1, D),
            (11, 3, F),
            (4, 1, D),
            (5, 4, D),
            (12, 5, F),
            (6, 4, D),
            (13, 6, F),
            (14, 4, F),
        ]);
        let granted = HashSet::from([2, 6]);
        let mut found = roots(&t, &granted);
        found.sort();
        // 3 whole; in 4, all but 6 (and 4 itself, the way down to 6).
        assert_eq!(found, [3, 5, 14]);
        assert_eq!(stats(&t, 5).files, 1);
        assert_eq!(stats(&t, 5).folders, 1);
        assert_eq!(post_order(&t, 5), [12, 5]);
        assert!(roots(&t, &HashSet::from([2, 3, 4])).is_empty());
    }
}
