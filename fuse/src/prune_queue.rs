//! The directories waiting to be pruned, kept on this machine for one
//! account: what a revocation leaves (see `Vault::prune_tree`), for a
//! mount to work through in the background, or `raft5fs prune` in the
//! foreground, whichever gets there first.
//!
//! Until a directory is pruned, what was written under it before the
//! revocation is still sealed under keys whoever was revoked holds -- so
//! the queue survives restarts, and an entry goes only once its prune has
//! left nothing behind.
//!
//! Three files in one directory, readable by their owner alone:
//! `queue` (`ino seconds-since-epoch note`, one a line: the note says what
//! the directory was, for people), `status` (`ino what`,
//! the last word on each entry), and `lock`, which every change to the
//! other two holds -- a mount and a CLI may be at them at once. They
//! reveal inode numbers, which the server knows anyway.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vault::replace_private;

/// One directory waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub ino: u64,
    /// When it was queued, in seconds since the Unix epoch.
    pub since: u64,
    /// What it was, for people: a path and why, say.
    pub note: String,
}

pub struct PruneQueue {
    dir: PathBuf,
}

/// An exclusive hold on the queue's lock file, released when dropped.
struct Locked(File);

impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: the descriptor is the open file's own.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl PruneQueue {
    /// The queue kept in `dir`, which needn't exist yet.
    pub fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn lock(&self) -> io::Result<Locked> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dir.join("lock"))?;
        // SAFETY: as above.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Locked(file))
    }

    fn read_lines(&self, name: &str) -> io::Result<BTreeMap<u64, String>> {
        let text = match std::fs::read_to_string(self.dir.join(name)) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e),
        };
        let mut lines = BTreeMap::new();
        for line in text.lines() {
            let (ino, rest) = line.split_once(' ').unwrap_or((line, ""));
            let ino = ino.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {line:?} isn't an entry", self.dir.join(name).display()),
                )
            })?;
            lines.insert(ino, rest.to_string());
        }
        Ok(lines)
    }

    fn write_lines(&self, name: &str, lines: &BTreeMap<u64, String>) -> io::Result<()> {
        let text: String = lines
            .iter()
            .map(|(ino, rest)| format!("{ino} {rest}\n"))
            .collect();
        replace_private(&self.dir.join(name), text.as_bytes())
    }

    /// Queues `ino`, noting what it is, unless it is queued already.
    pub fn add(&self, ino: u64, note: &str) -> io::Result<()> {
        let _held = self.lock()?;
        let mut queue = self.read_lines("queue")?;
        if queue.contains_key(&ino) {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        queue.insert(ino, format!("{now} {}", note.replace('\n', " ")));
        self.write_lines("queue", &queue)
    }

    /// What is waiting, oldest inode number first.
    pub fn entries(&self) -> io::Result<Vec<Queued>> {
        let _held = self.lock()?;
        Ok(self
            .read_lines("queue")?
            .into_iter()
            .map(|(ino, rest)| {
                let (since, note) = rest.split_once(' ').unwrap_or((&rest, ""));
                Queued {
                    ino,
                    since: since.parse().unwrap_or(0),
                    note: note.to_string(),
                }
            })
            .collect())
    }

    /// Takes `ino` off the queue, done, with its status.
    pub fn remove(&self, ino: u64) -> io::Result<()> {
        let _held = self.lock()?;
        let mut queue = self.read_lines("queue")?;
        let mut status = self.read_lines("status")?;
        queue.remove(&ino);
        status.remove(&ino);
        self.write_lines("queue", &queue)?;
        self.write_lines("status", &status)
    }

    /// Records the last word on `ino`'s prune (one line).
    pub fn set_status(&self, ino: u64, what: &str) -> io::Result<()> {
        let _held = self.lock()?;
        let mut status = self.read_lines("status")?;
        status.insert(ino, what.replace('\n', " "));
        self.write_lines("status", &status)
    }

    /// The last word on each entry that has one.
    pub fn statuses(&self) -> io::Result<BTreeMap<u64, String>> {
        let _held = self.lock()?;
        self.read_lines("status")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn queue(name: &str) -> PruneQueue {
        let dir = std::env::temp_dir().join(format!("raft5fs-queue-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        PruneQueue::at(dir)
    }

    #[test]
    fn entries_collapse_and_go_once_done() {
        let q = queue("collapse");
        assert!(q.entries().unwrap().is_empty());
        q.add(9, "photos/2024").unwrap();
        q.add(3, "x").unwrap();
        q.add(9, "again").unwrap();
        let inos: Vec<u64> = q.entries().unwrap().iter().map(|e| e.ino).collect();
        assert_eq!(inos, [3, 9]);
        assert!(q.entries().unwrap().iter().all(|e| e.since > 0));
        assert_eq!(
            q.entries().unwrap()[1].note,
            "photos/2024",
            "the first add's"
        );
        q.set_status(9, "halfway\nthere").unwrap();
        assert_eq!(q.statuses().unwrap()[&9], "halfway there");
        q.remove(9).unwrap();
        let inos: Vec<u64> = q.entries().unwrap().iter().map(|e| e.ino).collect();
        assert_eq!(inos, [3]);
        assert!(q.statuses().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(q.dir());
    }

    #[test]
    fn only_the_owner_can_read_it() {
        let q = queue("private");
        q.add(1, "").unwrap();
        q.set_status(1, "x").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(q.dir()), 0o700);
        for name in ["queue", "status", "lock"] {
            assert_eq!(mode(&q.dir().join(name)), 0o600, "{name}");
        }
        let _ = std::fs::remove_dir_all(q.dir());
    }

    #[test]
    fn adds_from_two_places_at_once_all_land() {
        let q = std::sync::Arc::new(queue("racing"));
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let q = std::sync::Arc::clone(&q);
                std::thread::spawn(move || {
                    for i in 0..25 {
                        q.add(t * 100 + i, "n").unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(q.entries().unwrap().len(), 200);
        let _ = std::fs::remove_dir_all(q.dir());
    }

    #[test]
    fn a_garbled_queue_is_an_error_not_an_empty_one() {
        let q = queue("garbled");
        q.add(1, "").unwrap();
        std::fs::write(q.dir().join("queue"), "not a number\n").unwrap();
        assert!(q.entries().is_err());
        let _ = std::fs::remove_dir_all(q.dir());
    }
}
