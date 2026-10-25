//! Paths, for front ends that use paths and not inodes (WebDAV). A path is
//! resolved one name at a time from the virtual root, through
//! `Session::lookup`, so volume labels and `/.snapshot` resolve as they do
//! in a mount.
//!
//! - Each name on a path would be a round trip, so each resolved name is
//!   kept for `DENTRY_TTL`. The kernel's dentry cache does the same for a
//!   mount, for FUSE's own TTL.
//! - Changes made through the session forget what they change at once.
//!   Another client's changes show after the TTL.
//! - The last name of a path is always looked up again, so its attributes
//!   are never stale.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::sync::Mutex;
use std::time::Duration;

// `std::time::Instant` panics in a browser; this is the same type natively.
use web_time::Instant;

use raft5fs_proto::errno;
use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{Attr, FsError};

use crate::session::Session;
use crate::vault::VIRTUAL_ROOT;

/// How long a resolved name is trusted for.
const DENTRY_TTL: Duration = Duration::from_secs(1);

/// How many resolved names to keep before expired ones are removed.
const MAX_DENTRIES: usize = 16 * 1024;

/// Resolved names: the inode for each `(directory, name)`, and when it was
/// resolved.
#[derive(Default)]
pub(crate) struct Dentries(Mutex<HashMap<(u64, OsString), (u64, Instant)>>);

impl Dentries {
    fn get(&self, parent: u64, name: &OsStr) -> Option<u64> {
        let map = self.0.lock().unwrap();
        map.get(&(parent, name.to_os_string()))
            .filter(|(_, at)| at.elapsed() < DENTRY_TTL)
            .map(|&(ino, _)| ino)
    }

    fn put(&self, parent: u64, name: &OsStr, ino: u64) {
        let mut map = self.0.lock().unwrap();
        if map.len() >= MAX_DENTRIES {
            map.retain(|_, (_, at)| at.elapsed() < DENTRY_TTL);
            if map.len() >= MAX_DENTRIES {
                map.clear();
            }
        }
        map.insert((parent, name.to_os_string()), (ino, Instant::now()));
    }

    /// Forgets `name` in `parent`, which the session just changed.
    pub(crate) fn forget(&self, parent: u64, name: &OsStr) {
        self.0
            .lock()
            .unwrap()
            .remove(&(parent, name.to_os_string()));
    }

    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

/// `path`'s names, separated by `/`, without empty names and `.`. `..` is
/// refused, because a front end has already resolved it against the path
/// itself, as an HTTP server does.
fn components(path: &[u8]) -> Result<Vec<&OsStr>, FsError> {
    let mut names = Vec::new();
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => return Err(FsError::new(errno::EINVAL, "a path with `..` in it")),
            name => names.push(os_bytes::as_name(name)),
        }
    }
    Ok(names)
}

impl Session {
    /// The attributes of what `path` names, from the virtual root: `/` is
    /// the root itself, `/<label>` is a volume, and so on down.
    pub async fn resolve(&self, path: &[u8]) -> Result<Attr, FsError> {
        let names = components(path)?;
        match self.walk(&names, true).await {
            // A remembered name could be the one that is now gone. Look up
            // the whole path again.
            Err(e) if e.errno == errno::ENOENT => {
                self.dentries.clear();
                self.walk(&names, false).await
            }
            other => other,
        }
    }

    /// The directory that `path` would be made in, and its name there, for
    /// create, remove, and rename by path. The root has no parent
    /// (`EPERM`).
    pub async fn resolve_parent(&self, path: &[u8]) -> Result<(u64, OsString), FsError> {
        let names = components(path)?;
        let Some((name, above)) = names.split_last() else {
            return Err(FsError::new(errno::EPERM, "the root has no parent"));
        };
        let parent = match self.walk(above, true).await {
            Err(e) if e.errno == errno::ENOENT => {
                self.dentries.clear();
                self.walk(above, false).await
            }
            other => other,
        }?;
        if parent.kind != raft5fs_proto::types::Kind::Directory {
            return Err(FsError::errno(errno::ENOTDIR));
        }
        Ok((parent.ino, name.to_os_string()))
    }

    /// Resolves `names` from the root and returns the last name's
    /// attributes, fresh. If `cached`, it uses remembered names along the
    /// way.
    async fn walk(&self, names: &[&OsStr], cached: bool) -> Result<Attr, FsError> {
        let Some((last, above)) = names.split_last() else {
            return self.getattr(VIRTUAL_ROOT).await;
        };
        let mut ino = VIRTUAL_ROOT;
        for name in above {
            ino = match self.dentries.get(ino, name).filter(|_| cached) {
                Some(child) => child,
                None => {
                    let child = self.lookup(ino, name).await?.ino;
                    self.dentries.put(ino, name, child);
                    child
                }
            };
        }
        match self.dentries.get(ino, last).filter(|_| cached) {
            Some(child) => self.getattr(child).await,
            None => {
                let attr = self.lookup(ino, last).await?;
                self.dentries.put(ino, last, attr.ino);
                Ok(attr)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_skip_empty_names_and_dots() {
        let names = components(b"//a/./b/").unwrap();
        assert_eq!(names, [OsStr::new("a"), OsStr::new("b")]);
        assert!(components(b"/").unwrap().is_empty());
    }

    #[test]
    fn components_refuse_dot_dot() {
        assert_eq!(components(b"/a/../b").unwrap_err().errno, errno::EINVAL);
    }

    #[test]
    fn dentries_forget_and_expire() {
        let d = Dentries::default();
        d.put(1, OsStr::new("a"), 7);
        assert_eq!(d.get(1, OsStr::new("a")), Some(7));
        d.forget(1, OsStr::new("a"));
        assert_eq!(d.get(1, OsStr::new("a")), None);
    }
}
