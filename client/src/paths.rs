//! Paths, for front ends that use paths and not inodes (WebDAV, the web
//! app). A path is resolved one name at a time from the virtual root,
//! through `Session::lookup`, so volume labels and `/.snapshot` resolve as
//! they do in a mount.
//!
//! - Each name on a path would be a round trip, so each resolved name is
//!   kept for the session's `path_ttl`. The kernel's dentry cache does the
//!   same for a mount, for FUSE's own TTL.
//! - A listing keeps the names it lists, so a path into a folder just shown
//!   costs nothing to resolve.
//! - Changes made through the session forget what they change at once.
//!   Another client's changes show after the TTL, or at once when a
//!   remembered name leads to something gone (`ENOENT`).
//! - `resolve` always looks the last name up again, so its attributes are
//!   never stale. `resolve_ino` trusts every remembered name, for callers
//!   that only need the inode.

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

/// How long a resolved name is trusted for, unless the session says.
pub const DEFAULT_PATH_TTL: Duration = Duration::from_secs(1);

/// How many resolved names to keep before expired ones are removed.
const MAX_DENTRIES: usize = 16 * 1024;

/// Resolved names: the inode for each `(directory, name)`, and when it was
/// resolved.
pub(crate) struct Dentries {
    map: Mutex<HashMap<(u64, OsString), (u64, Instant)>>,
    ttl: Duration,
}

impl Default for Dentries {
    fn default() -> Self {
        Self::new(DEFAULT_PATH_TTL)
    }
}

impl Dentries {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            map: Mutex::default(),
            ttl,
        }
    }

    fn get(&self, parent: u64, name: &OsStr) -> Option<u64> {
        let map = self.map.lock().unwrap();
        map.get(&(parent, name.to_os_string()))
            .filter(|(_, at)| at.elapsed() < self.ttl)
            .map(|&(ino, _)| ino)
    }

    pub(crate) fn put(&self, parent: u64, name: &OsStr, ino: u64) {
        let mut map = self.map.lock().unwrap();
        if map.len() >= MAX_DENTRIES {
            map.retain(|_, (_, at)| at.elapsed() < self.ttl);
            if map.len() >= MAX_DENTRIES {
                map.clear();
            }
        }
        map.insert((parent, name.to_os_string()), (ino, Instant::now()));
    }

    /// Forgets `name` in `parent`, which the session just changed.
    pub(crate) fn forget(&self, parent: u64, name: &OsStr) {
        self.map
            .lock()
            .unwrap()
            .remove(&(parent, name.to_os_string()));
    }

    /// Forgets each remembered name along `names`, from the root down, so
    /// that the path is looked up again. Names on other paths stay.
    fn forget_path(&self, names: &[&OsStr]) {
        let mut map = self.map.lock().unwrap();
        let mut at = VIRTUAL_ROOT;
        for name in names {
            match map.remove(&(at, name.to_os_string())) {
                Some((child, _)) => at = child,
                None => break,
            }
        }
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

fn gone(e: &FsError) -> bool {
    e.errno == errno::ENOENT
}

impl Session {
    /// The attributes of what `path` names, from the virtual root: `/` is
    /// the root itself, `/<label>` is a volume, and so on down.
    pub async fn resolve(&self, path: &[u8]) -> Result<Attr, FsError> {
        let names = components(path)?;
        match self.walk(&names, true).await {
            // A remembered name could be the one that is now gone. Look up
            // the path again.
            Err(e) if gone(&e) => {
                self.dentries.forget_path(&names);
                self.walk(&names, false).await
            }
            other => other,
        }
    }

    /// The inode that `path` names, from remembered names wherever they
    /// are known: a path whose names are all remembered costs no round
    /// trip. The inode can be stale, so a caller whose next request finds
    /// it gone (`ENOENT`) asks `resolve_ino_fresh`.
    pub async fn resolve_ino(&self, path: &[u8]) -> Result<u64, FsError> {
        let names = components(path)?;
        match self.walk_ino(&names, true).await {
            Err(e) if gone(&e) => {
                self.dentries.forget_path(&names);
                self.walk_ino(&names, false).await
            }
            other => other,
        }
    }

    /// `resolve_ino` with nothing remembered along `path`, for when the
    /// inode that it gave turned out to be gone.
    pub async fn resolve_ino_fresh(&self, path: &[u8]) -> Result<u64, FsError> {
        let names = components(path)?;
        self.dentries.forget_path(&names);
        self.walk_ino(&names, false).await
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
            Err(e) if gone(&e) => {
                self.dentries.forget_path(above);
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
        let parent = self.walk_ino(above, cached).await?;
        match self.dentries.get(parent, last).filter(|_| cached) {
            Some(child) => self.getattr(child).await,
            None => {
                let attr = self.lookup(parent, last).await?;
                self.dentries.put(parent, last, attr.ino);
                Ok(attr)
            }
        }
    }

    /// Resolves `names` from the root to an inode. If `cached`, it uses
    /// remembered names for each of them, the last one too.
    async fn walk_ino(&self, names: &[&OsStr], cached: bool) -> Result<u64, FsError> {
        let mut ino = VIRTUAL_ROOT;
        for name in names {
            ino = match self.dentries.get(ino, name).filter(|_| cached) {
                Some(child) => child,
                None => {
                    let child = self.lookup(ino, name).await?.ino;
                    self.dentries.put(ino, name, child);
                    child
                }
            };
        }
        Ok(ino)
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
        let short = Dentries::new(Duration::ZERO);
        short.put(1, OsStr::new("a"), 7);
        assert_eq!(short.get(1, OsStr::new("a")), None);
    }

    #[test]
    fn forgetting_a_path_keeps_other_paths() {
        let d = Dentries::new(Duration::from_secs(60));
        let [a, b, c] = [OsStr::new("a"), OsStr::new("b"), OsStr::new("c")];
        d.put(VIRTUAL_ROOT, a, 10);
        d.put(10, b, 11);
        d.put(10, c, 12);
        d.forget_path(&[a, b]);
        assert_eq!(d.get(VIRTUAL_ROOT, a), None);
        assert_eq!(d.get(10, b), None);
        assert_eq!(d.get(10, c), Some(12));
    }
}
