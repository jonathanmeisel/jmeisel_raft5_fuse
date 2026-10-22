//! The mount's `/.snapshot`: every snapshot of the filesystem, each
//! browsable, read-only, as `/.snapshot/<name>/...`.
//!
//! Under `<name>` is what this account's root was when the snapshot was
//! taken -- its grants then, under their labels then -- and below that the
//! filesystem as it stood. It is read through a vault of its own
//! (`Vault::at_snapshot`), since a snapshot's keys are as they were then.
//!
//! The kernel knows one inode number per file, but a snapshot's inodes
//! have the same numbers as the live ones. So everything here gets a
//! number of its own, from `SNAPSHOT_BASE` up, kept for the life of the
//! mount; the live filesystem keeps the server's numbers, which stay below
//! it.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use raft5fs_proto::types::{Attr, DirItem, FsError, Kind, Layout, SnapshotInfo};

use crate::vault::{SNAPSHOT_DIR, Vault};

/// The first inode number of the snapshots' side: `/.snapshot` itself.
/// Every number below it is the live filesystem's.
pub const SNAPSHOT_BASE: u64 = 1 << 63;

/// Whether the kernel's inode `ino` is one of the snapshots'.
pub fn is_snapshot_ino(ino: u64) -> bool {
    ino >= SNAPSHOT_BASE
}

/// Whether `name` in the mount's root is the snapshots' directory.
pub fn is_snapshot_dir(name: &OsStr) -> bool {
    name == SNAPSHOT_DIR
}

/// What every change asked of a snapshot gets.
pub fn read_only() -> FsError {
    FsError::new(libc::EROFS, "a snapshot is read-only")
}

fn stale() -> FsError {
    FsError::new(libc::ENOENT, "that snapshot is gone")
}

/// One snapshot this mount has looked into.
struct Snap {
    name: String,
    created: SystemTime,
    vault: Arc<Vault>,
    /// The kernel's inode for `/.snapshot/<name>`.
    root: u64,
}

/// What one of the kernel's snapshot-side inodes stands for.
enum Target {
    /// `/.snapshot`.
    List,
    /// `/.snapshot/<name>`: the account's root as it was.
    Root(Arc<Snap>),
    /// An inode of the filesystem at a snapshot, by its own number.
    Node(Arc<Snap>, u64),
}

#[derive(Default)]
struct Inodes {
    /// The next inode number to hand out.
    next: u64,
    /// The next cache space (see `ChunkCache`) to hand out; 0 is the live
    /// filesystem's.
    next_space: u64,
    by_name: HashMap<String, Arc<Snap>>,
    targets: HashMap<u64, (Arc<Snap>, Option<u64>)>,
    /// The kernel's number for each snapshot's inode, by root inode and
    /// the inode's own number.
    numbers: HashMap<(u64, u64), u64>,
}

pub struct SnapshotTree {
    /// The times `/.snapshot` shows: the mount's.
    mounted_at: SystemTime,
    inodes: Mutex<Inodes>,
}

impl SnapshotTree {
    pub fn new(mounted_at: SystemTime) -> Self {
        Self {
            mounted_at,
            inodes: Mutex::new(Inodes {
                next: SNAPSHOT_BASE + 1,
                next_space: 1,
                ..Inodes::default()
            }),
        }
    }

    fn target(&self, ino: u64) -> Result<Target, FsError> {
        if ino == SNAPSHOT_BASE {
            return Ok(Target::List);
        }
        let inodes = self.inodes.lock().unwrap();
        match inodes.targets.get(&ino) {
            Some((snap, None)) => Ok(Target::Root(Arc::clone(snap))),
            Some((snap, Some(node))) => Ok(Target::Node(Arc::clone(snap), *node)),
            None => Err(stale()),
        }
    }

    /// The kernel's number for inode `node` of `snap`, handed out the first
    /// time it is asked for.
    fn number(&self, snap: &Arc<Snap>, node: u64) -> u64 {
        let mut inodes = self.inodes.lock().unwrap();
        if let Some(&ino) = inodes.numbers.get(&(snap.root, node)) {
            return ino;
        }
        let ino = inodes.next;
        inodes.next += 1;
        inodes.numbers.insert((snap.root, node), ino);
        inodes.targets.insert(ino, (Arc::clone(snap), Some(node)));
        ino
    }

    /// Snapshot `name`, as the servers list it now.
    async fn open(&self, live: &Vault, name: &OsStr) -> Result<Arc<Snap>, FsError> {
        let name = name.to_str().ok_or_else(|| FsError::errno(libc::ENOENT))?;
        let listed = live.remote().list_snapshots().await?;
        let Some(info) = listed.into_iter().find(|s| s.name == name) else {
            self.inodes.lock().unwrap().by_name.remove(name);
            return Err(FsError::errno(libc::ENOENT));
        };
        Ok(self.snap(live, info))
    }

    /// The snapshot `info` lists, opened the first time it is seen -- and
    /// again if it has since been removed and another taken under its
    /// name, which is a different snapshot.
    fn snap(&self, live: &Vault, info: SnapshotInfo) -> Arc<Snap> {
        let mut inodes = self.inodes.lock().unwrap();
        if let Some(snap) = inodes.by_name.get(&info.name)
            && snap.created == info.created
        {
            return Arc::clone(snap);
        }
        let name = info.name.clone();
        let space = inodes.next_space;
        inodes.next_space += 1;
        let root = inodes.next;
        inodes.next += 1;
        let snap = Arc::new(Snap {
            name: info.name,
            created: info.created,
            vault: Arc::new(live.at_snapshot(&name, space)),
            root,
        });
        inodes.by_name.insert(name, Arc::clone(&snap));
        inodes.targets.insert(root, (Arc::clone(&snap), None));
        snap
    }

    fn dir_attr(ino: u64, at: SystemTime) -> Attr {
        Attr {
            ino,
            kind: Kind::Directory,
            size: 0,
            perm: 0o555,
            nlink: 2,
            atime: at,
            mtime: at,
            ctime: at,
            layout: Layout::Inline,
        }
    }

    /// `node`'s attributes as of `snap`, under the kernel's number for it,
    /// and with no write bits: nothing here can be written.
    fn node_attr(&self, snap: &Arc<Snap>, mut attr: Attr) -> Attr {
        attr.ino = self.number(snap, attr.ino);
        attr.perm &= !0o222;
        attr
    }

    /// `/.snapshot`'s attributes, for a lookup of it in the root.
    pub fn list_attr(&self) -> Attr {
        Self::dir_attr(SNAPSHOT_BASE, self.mounted_at)
    }

    pub async fn getattr(&self, ino: u64) -> Result<Attr, FsError> {
        match self.target(ino)? {
            Target::List => Ok(self.list_attr()),
            Target::Root(snap) => Ok(Self::dir_attr(snap.root, snap.created)),
            Target::Node(snap, node) => {
                let attr = snap.vault.remote().getattr(node).await?;
                Ok(self.node_attr(&snap, attr))
            }
        }
    }

    pub async fn lookup(&self, live: &Vault, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        match self.target(parent)? {
            Target::List => {
                let snap = self.open(live, name).await?;
                Ok(Self::dir_attr(snap.root, snap.created))
            }
            Target::Root(snap) => {
                let node = snap.vault.root_lookup(name).await?;
                let attr = snap.vault.remote().getattr(node).await?;
                Ok(self.node_attr(&snap, attr))
            }
            Target::Node(snap, node) => {
                let attr = snap.vault.lookup(node, name).await?;
                Ok(self.node_attr(&snap, attr))
            }
        }
    }

    /// access(2): anything but writing, which nothing here allows.
    pub async fn access(&self, ino: u64, mask: u32) -> Result<(), FsError> {
        if mask & libc::W_OK as u32 != 0 {
            return Err(read_only());
        }
        match self.target(ino)? {
            Target::List | Target::Root(_) => Ok(()),
            Target::Node(snap, node) => snap.vault.remote().access(node, mask).await,
        }
    }

    pub async fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        match self.target(ino)? {
            Target::List | Target::Root(_) => Err(FsError::errno(libc::EISDIR)),
            Target::Node(snap, node) => snap.vault.read(node, offset, len).await,
        }
    }

    /// A directory's entries, `.` and `..` included, under the kernel's
    /// numbers. `root` is the kernel's number for the mount's root.
    pub async fn readdir(
        &self,
        live: &Vault,
        root: u64,
        ino: u64,
    ) -> Result<Vec<DirItem>, FsError> {
        let item = |ino, kind, name: &str| DirItem {
            ino,
            kind,
            name: name.into(),
            sealed_name: Vec::new(),
        };
        match self.target(ino)? {
            Target::List => {
                let mut items = vec![
                    item(SNAPSHOT_BASE, Kind::Directory, "."),
                    item(root, Kind::Directory, ".."),
                ];
                for info in live.remote().list_snapshots().await? {
                    let snap = self.snap(live, info);
                    items.push(item(snap.root, Kind::Directory, &snap.name));
                }
                Ok(items)
            }
            Target::Root(snap) => {
                let mut items = vec![
                    item(snap.root, Kind::Directory, "."),
                    item(SNAPSHOT_BASE, Kind::Directory, ".."),
                ];
                for (name, node) in snap.vault.root_entries().await? {
                    items.push(DirItem {
                        ino: self.number(&snap, node),
                        kind: Kind::Directory,
                        name,
                        sealed_name: Vec::new(),
                    });
                }
                Ok(items)
            }
            Target::Node(snap, node) => {
                let mut items = snap.vault.readdir(node).await?;
                // A grant's `..` is the snapshot's root, as in the live one.
                let above_grant = snap.vault.is_grant_root(node);
                for item in &mut items {
                    item.ino = if above_grant && item.name == ".." {
                        snap.root
                    } else {
                        self.number(&snap, item.ino)
                    };
                }
                Ok(items)
            }
        }
    }
}
