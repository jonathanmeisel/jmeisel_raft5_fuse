//! What a file or folder was in each snapshot, for "Versions".
//!
//! - Each snapshot is searched for the same name in the same folder: the
//!   folder that holds the path now, by inode. So a file that an editor
//!   saves by writing a new one and renaming it over the old is found, and
//!   so is a file whose folder was renamed or moved since. A file renamed
//!   since isn't, and neither is one from before its folder was deleted and
//!   made again.
//! - Every snapshot is searched at once, each in one round trip. A path
//!   whose folder is gone now, or is the root or a group, is searched by
//!   path in each snapshot instead, which costs a round trip per name.
//! - Snapshots in a row that hold the same version of a file (the same
//!   modification time and size) give one version: the newest snapshot that
//!   has it. A version the same as the file now is left out.
//! - A folder has one version for each snapshot it is in.

use std::future::Future;
use std::sync::Arc;
use std::time::SystemTime;

use futures_util::stream::{self, StreamExt};
use raft5fs_proto::errno;
use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{Attr, FsError, Kind, SnapshotInfo};

use crate::session::Session;
use crate::snapshot_tree::is_snapshot_ino;
use crate::vault::is_virtual;

/// How many snapshots are searched at once: all of them, on a cluster that
/// keeps hourly snapshots for a day and daily ones for a week.
const AT_ONCE: usize = 32;

/// What a path was in one snapshot.
#[derive(Debug, Clone)]
pub struct Version {
    pub snapshot: String,
    pub taken: SystemTime,
    pub attr: Attr,
}

/// What a path is now, and what it was in each snapshot (see
/// `Session::versions`).
#[derive(Debug)]
pub struct Versions {
    /// The path now, or `None` if nothing is there.
    pub now: Option<Attr>,
    /// What `collapse` keeps, newest first. Each `attr.ino` is the
    /// session's number for the version, under `/.snapshot`.
    pub versions: Vec<Version>,
    /// How many snapshots couldn't be read.
    pub unreadable: usize,
}

impl Session {
    /// What `path` (from the virtual root) is now, and what it was in each
    /// snapshot, as the module says. `EINVAL` for the root.
    ///
    /// - Looks up the path now and the snapshots, at once. The path's
    ///   folder is then known.
    /// - Then looks the name up in that folder in every snapshot, at once,
    ///   with the folder's live key.
    pub async fn versions(&self, path: &[u8]) -> Result<Versions, FsError> {
        let path = path.strip_suffix(b"/").unwrap_or(path);
        let (above, name) = match path.iter().rposition(|&b| b == b'/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => (&[][..], path),
        };
        if name.is_empty() {
            return Err(FsError::new(errno::EINVAL, "the root has no versions"));
        }
        let name = os_bytes::as_name(name);
        let (now, snapshots) =
            futures_util::join!(self.resolve(path), self.vault().remote().list_snapshots(),);
        let now = match now {
            Ok(attr) => Some(attr),
            Err(e) if e.errno == errno::ENOENT => None,
            Err(e) => return Err(e),
        };
        let snapshots = snapshots?;
        // Resolving the path kept its folder's name, so this costs nothing
        // unless the path is gone now.
        let dir = match self.resolve_ino(above).await {
            Ok(ino) if !is_virtual(ino) && !is_snapshot_ino(ino) => {
                self.vault().node(ino).await.ok().map(|dir| (ino, dir))
            }
            _ => None,
        };
        let (found, unreadable) = match dir {
            Some((parent, dir)) => {
                find(snapshots, |info| {
                    let dir = Arc::clone(&dir);
                    async move {
                        self.snapshots
                            .lookup_in(self.vault(), info, parent, dir, name)
                            .await
                    }
                })
                .await
            }
            None => {
                let path = String::from_utf8_lossy(path).into_owned();
                find(snapshots, |info| {
                    let at = format!("/.snapshot/{}{path}", info.name);
                    async move { self.resolve(at.as_bytes()).await }
                })
                .await
            }
        };
        Ok(Versions {
            versions: collapse(now.as_ref(), found),
            now,
            unreadable,
        })
    }
}

/// Looks the path up in each of `snapshots` with `stat`. Gives what was
/// found, and how many snapshots couldn't be read. A snapshot without the
/// path isn't one of those.
pub async fn find<F, Fut>(snapshots: Vec<SnapshotInfo>, stat: F) -> (Vec<Version>, usize)
where
    F: Fn(SnapshotInfo) -> Fut,
    Fut: Future<Output = Result<Attr, FsError>>,
{
    let looked: Vec<_> = stream::iter(snapshots)
        .map(|s| {
            let found = stat(s.clone());
            async move { (s, found.await) }
        })
        .buffer_unordered(AT_ONCE)
        .collect()
        .await;
    let mut found = Vec::new();
    let mut unreadable = 0;
    for (s, attr) in looked {
        match attr {
            Ok(attr) => found.push(Version {
                snapshot: s.name,
                taken: s.created,
                attr,
            }),
            Err(e) if e.errno == errno::ENOENT => {}
            Err(_) => unreadable += 1,
        }
    }
    (found, unreadable)
}

/// The versions in `found` worth showing, newest first, given what the path is
/// now (`None` if nothing is there now).
pub fn collapse(now: Option<&Attr>, mut found: Vec<Version>) -> Vec<Version> {
    found.sort_by_key(|v| std::cmp::Reverse(v.taken));
    let same = |attr: &Attr| (attr.kind, attr.mtime, attr.size);
    let mut last = now.filter(|a| a.kind == Kind::File).map(same);
    let mut kept = Vec::new();
    for version in found {
        if version.attr.kind == Kind::File {
            let this = same(&version.attr);
            if last == Some(this) {
                continue;
            }
            last = Some(this);
        } else {
            last = None;
        }
        kept.push(version);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use raft5fs_proto::types::Layout;
    use std::time::{Duration, UNIX_EPOCH};

    fn attr(kind: Kind, mtime: u64, size: u64) -> Attr {
        let at = UNIX_EPOCH + Duration::from_secs(mtime);
        Attr {
            ino: 7,
            kind,
            size,
            perm: 0o644,
            nlink: 1,
            atime: at,
            mtime: at,
            ctime: at,
            layout: Layout::Inline,
        }
    }

    fn version(snapshot: &str, taken: u64, attr: Attr) -> Version {
        Version {
            snapshot: snapshot.into(),
            taken: UNIX_EPOCH + Duration::from_secs(taken),
            attr,
        }
    }

    fn names(versions: &[Version]) -> Vec<&str> {
        versions.iter().map(|v| v.snapshot.as_str()).collect()
    }

    #[test]
    fn a_file_shows_each_version_once_newest_first() {
        let one = attr(Kind::File, 100, 3);
        let two = attr(Kind::File, 200, 5);
        let now = attr(Kind::File, 300, 8);
        let found = vec![
            version("s1", 110, one),
            version("s4", 410, now),
            version("s2", 120, one),
            version("s3", 210, two),
        ];
        // s4 holds what is there now, and s1 the same as s2.
        assert_eq!(names(&collapse(Some(&now), found.clone())), ["s3", "s2"]);
        // Once the file is gone, its last version is one too.
        assert_eq!(names(&collapse(None, found)), ["s4", "s3", "s2"]);
        // The same contents again later is another version.
        let back = vec![
            version("s1", 110, one),
            version("s2", 210, two),
            version("s3", 310, one),
        ];
        assert_eq!(names(&collapse(Some(&now), back)), ["s3", "s2", "s1"]);
    }

    #[test]
    fn a_folder_has_one_version_for_each_snapshot() {
        let folder = attr(Kind::Directory, 100, 0);
        let found = vec![version("s1", 110, folder), version("s2", 120, folder)];
        assert_eq!(names(&collapse(Some(&folder), found)), ["s2", "s1"]);
    }
}
