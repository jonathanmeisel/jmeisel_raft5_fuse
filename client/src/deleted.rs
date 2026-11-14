//! What was deleted from a folder, for the web app's "Show deleted": what
//! the snapshots hold that the folder doesn't now.
//!
//! - The folder is found by inode in each snapshot, so one renamed since
//!   still counts, and listed there with its live key (`Vault::adopt`).
//! - An entry counts if its inode isn't in the folder now, and no entry
//!   now has its name. A file saved over by an editor (a new file renamed
//!   over the old) keeps its name, so it shows in its Versions instead.
//! - For each name, the newest snapshot that holds it gives the entry.
//! - An entry whose inode is still there, somewhere else, was moved, not
//!   deleted. `locate` finds where it is now.
//! - A file made and deleted between two snapshots is in none of them, so
//!   it isn't found. It can't be restored either.
//!
//! It costs three round trips, each with everything in it sent at once:
//! the snapshots and the folder now; the folder in every snapshot; then
//! each entry found, in its snapshot and live.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::time::SystemTime;

use futures_util::future::join_all;
use raft5fs_proto::errno;
use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{Attr, DirItem, FsError, Kind};

use crate::session::Session;
use crate::snapshot_tree::is_snapshot_ino;
use crate::vault::is_virtual;

/// One entry that is gone from a folder.
#[derive(Debug, Clone)]
pub struct Gone {
    pub name: OsString,
    pub kind: Kind,
    /// The newest snapshot that holds it, and when that was taken.
    pub snapshot: String,
    pub taken: SystemTime,
    /// Its attributes in that snapshot. `ino` is the session's number for
    /// it, under `/.snapshot`.
    pub attr: Attr,
    /// Its live inode, if it still exists elsewhere: it was moved.
    pub moved: Option<u64>,
}

/// What `Session::deleted` found.
#[derive(Debug)]
pub struct Deleted {
    /// By name.
    pub gone: Vec<Gone>,
    /// How many snapshots couldn't be read.
    pub unreadable: usize,
}

fn gone(e: &FsError) -> bool {
    e.errno == errno::ENOENT
}

impl Session {
    /// What is gone from folder `path` (from the virtual root), as the
    /// module says. `EINVAL` for the root, a group, or a snapshot.
    pub async fn deleted(&self, path: &[u8]) -> Result<Deleted, FsError> {
        let mut dir = self.resolve_ino(path).await?;
        let mut first = true;
        // The folder now, its key, and the snapshots, at once. The inode
        // came from remembered names, so if it is gone, look again.
        let (now, key, snapshots) = loop {
            if is_virtual(dir) || is_snapshot_ino(dir) {
                return Err(FsError::new(
                    errno::EINVAL,
                    "only a folder in a share has deleted files",
                ));
            }
            let (now, key, snapshots) = futures_util::join!(
                self.readdir(dir),
                self.vault().node(dir),
                self.vault().remote().list_snapshots(),
            );
            match now {
                Err(e) if gone(&e) && first => {
                    first = false;
                    dir = self.resolve_ino_fresh(path).await?;
                }
                now => break (now?, key?, snapshots?),
            }
        };
        let names: HashSet<OsString> = now.iter().map(|i| i.name.clone()).collect();
        let inos: HashSet<u64> = now.iter().map(|i| i.ino).collect();

        let listings = join_all(snapshots.into_iter().map(|info| {
            let key = std::sync::Arc::clone(&key);
            async move {
                let listing = self
                    .snapshots
                    .listing_in(self.vault(), info.clone(), dir, key)
                    .await;
                (info, listing)
            }
        }))
        .await;
        let mut unreadable = 0;
        // For each name gone, the newest snapshot that holds it.
        let mut newest: HashMap<OsString, (raft5fs_proto::types::SnapshotInfo, DirItem, u64)> =
            HashMap::new();
        for (info, listing) in listings {
            let items = match listing {
                Ok(items) => items,
                // The folder wasn't made yet.
                Err(e) if gone(&e) => continue,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            for (item, number) in items {
                if names.contains(&item.name) || inos.contains(&item.ino) {
                    continue;
                }
                let newer = newest
                    .get(&item.name)
                    .is_none_or(|(known, _, _)| info.created > known.created);
                if newer {
                    newest.insert(item.name.clone(), (info.clone(), item, number));
                }
            }
        }

        let found = join_all(newest.into_values().map(|(info, item, number)| async move {
            let (then, live) = futures_util::join!(
                self.getattr(number),
                self.vault().remote().getattr(item.ino),
            );
            let moved = match live {
                Err(e) if gone(&e) => None,
                // Still there, if only where this account can't look.
                _ => Some(item.ino),
            };
            then.ok().map(|attr| Gone {
                name: item.name,
                kind: item.kind,
                snapshot: info.name,
                taken: info.created,
                attr,
                moved,
            })
        }))
        .await;
        let mut gone: Vec<Gone> = found.into_iter().flatten().collect();
        gone.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Deleted { gone, unreadable })
    }

    /// Where live inode `ino` is now, as a path from the virtual root, or
    /// `None` if this account can't reach it by a path it shows.
    ///
    /// - Asks for the keys' path to it (from the grant above it, down) and
    ///   where each grant shows, at once.
    /// - Then finds each folder's name on the way: from remembered names,
    ///   or else by listing its parent, all at once.
    pub async fn locate(&self, ino: u64) -> Result<Option<String>, FsError> {
        let (chain, shown) = futures_util::join!(
            self.vault().remote().key_path(ino),
            self.vault().grant_paths(),
        );
        let chain = match chain {
            Ok(chain) => chain,
            Err(e) if gone(&e) || e.errno == errno::EACCES => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut shown = shown?;
        let inos: Vec<u64> = chain.nodes.iter().map(|&(i, _)| i).collect();
        // A grant inside another one doesn't show in the root.
        let Some(top) = inos.first().and_then(|top| shown.remove(top)) else {
            return Ok(None);
        };
        let names = join_all(inos.windows(2).map(|w| self.name_in(w[0], w[1]))).await;
        let mut path = format!("/{top}");
        for name in names {
            let Some(name) = name? else {
                return Ok(None);
            };
            path.push('/');
            path.push_str(&String::from_utf8_lossy(os_bytes::bytes(&name)));
        }
        Ok(Some(path))
    }

    /// The name of `child` in directory `parent`, from remembered names or
    /// else from a listing of `parent`.
    async fn name_in(&self, parent: u64, child: u64) -> Result<Option<OsString>, FsError> {
        if let Some(name) = self.dentries.name_of(parent, child) {
            return Ok(Some(name));
        }
        let items = self.readdir(parent).await?;
        Ok(items
            .into_iter()
            .find(|i| i.ino == child && i.name != "." && i.name != "..")
            .map(|i| i.name))
    }
}
