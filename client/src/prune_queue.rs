//! The directories waiting to be pruned, kept on this machine for one
//! account. A revocation adds them (see `Vault::prune_tree`). A mount works
//! through them in the background, or `raft5fs prune` does in the
//! foreground, whichever comes first.
//!
//! Until a directory is pruned, data written below it before the revocation
//! is still sealed under keys that the revoked user has. So the queue
//! survives restarts, and an entry leaves only after its prune left nothing
//! behind.
//!
//! It is two blobs in a `Store` (natively, files in one directory, readable
//! only by their owner):
//!
//! - `queue`: one line for each entry, `ino seconds-since-epoch note`. The
//!   note says what the directory was, for people.
//! - `status`: `ino what`, the latest status of each entry.
//!
//! Every change holds the store's lock `lock`, because a mount and the CLI
//! can change the queue at the same time.
//!
//! The blobs show inode numbers, which the server knows anyway.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use crate::store::{Store, locked};

/// One directory waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub ino: u64,
    /// When it was queued, in seconds since the Unix epoch.
    pub since: u64,
    /// What it was, for people: for example, a path and a reason.
    pub note: String,
}

/// A handle on the queue. Clones share the same store.
#[derive(Clone)]
pub struct PruneQueue {
    store: Arc<dyn Store>,
}

impl PruneQueue {
    /// The queue in `store`, which can be empty.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }

    /// The queue in directory `dir`, which does not have to exist yet.
    #[cfg(unix)]
    pub fn at(dir: std::path::PathBuf) -> Self {
        Self::new(Arc::new(crate::store::FileStore::new(dir)))
    }

    /// Where the queue is, for messages.
    pub fn location(&self) -> String {
        self.store.location("queue")
    }

    fn locked<T>(&self, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        locked(self.store.as_ref(), "lock", f)
    }

    fn read_lines(&self, name: &str) -> io::Result<BTreeMap<u64, String>> {
        let Some(data) = self.store.load(name)? else {
            return Ok(BTreeMap::new());
        };
        let bad = |what: String| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {what}", self.store.location(name)),
            )
        };
        let text = String::from_utf8(data).map_err(|_| bad("not text".into()))?;
        let mut lines = BTreeMap::new();
        for line in text.lines() {
            let (ino, rest) = line.split_once(' ').unwrap_or((line, ""));
            let ino = ino
                .parse()
                .map_err(|_| bad(format!("{line:?} isn't an entry")))?;
            lines.insert(ino, rest.to_string());
        }
        Ok(lines)
    }

    fn write_lines(&self, name: &str, lines: &BTreeMap<u64, String>) -> io::Result<()> {
        let text: String = lines
            .iter()
            .map(|(ino, rest)| format!("{ino} {rest}\n"))
            .collect();
        self.store.save(name, text.as_bytes())
    }

    /// Adds `ino` to the queue with a note about what it is, unless it is
    /// already queued.
    pub fn add(&self, ino: u64, note: &str) -> io::Result<()> {
        self.locked(|| {
            let mut queue = self.read_lines("queue")?;
            if queue.contains_key(&ino) {
                return Ok(());
            }
            let now = raft5fs_proto::clock::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            queue.insert(ino, format!("{now} {}", note.replace('\n', " ")));
            self.write_lines("queue", &queue)
        })
    }

    /// The waiting entries, lowest inode number first.
    pub fn entries(&self) -> io::Result<Vec<Queued>> {
        let queue = self.locked(|| self.read_lines("queue"))?;
        Ok(queue
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

    /// Removes `ino` from the queue as done, with its status.
    pub fn remove(&self, ino: u64) -> io::Result<()> {
        self.locked(|| {
            let mut queue = self.read_lines("queue")?;
            let mut status = self.read_lines("status")?;
            queue.remove(&ino);
            status.remove(&ino);
            self.write_lines("queue", &queue)?;
            self.write_lines("status", &status)
        })
    }

    /// Records the latest status of `ino`'s prune (one line).
    pub fn set_status(&self, ino: u64, what: &str) -> io::Result<()> {
        self.locked(|| {
            let mut status = self.read_lines("status")?;
            status.insert(ino, what.replace('\n', " "));
            self.write_lines("status", &status)
        })
    }

    /// The latest status of each entry that has one.
    pub fn statuses(&self) -> io::Result<BTreeMap<u64, String>> {
        self.locked(|| self.read_lines("status"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{FileStore, MemoryStore};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("raft5fs-queue-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn check_entries_collapse_and_go_once_done(q: PruneQueue) {
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
    }

    #[test]
    fn entries_collapse_and_go_once_done() {
        let dir = temp_dir("collapse");
        check_entries_collapse_and_go_once_done(PruneQueue::at(dir.clone()));
        let _ = std::fs::remove_dir_all(dir);
        check_entries_collapse_and_go_once_done(PruneQueue::new(Arc::new(MemoryStore::new())));
    }

    #[test]
    fn only_the_owner_can_read_it() {
        let dir = temp_dir("private");
        let q = PruneQueue::at(dir.clone());
        q.add(1, "").unwrap();
        q.set_status(1, "x").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        for name in ["queue", "status", "lock"] {
            assert_eq!(mode(&dir.join(name)), 0o600, "{name}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    fn check_adds_from_two_places_at_once_all_land(open: impl Fn() -> PruneQueue) {
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let q = open();
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
        assert_eq!(open().entries().unwrap().len(), 200);
    }

    #[test]
    fn adds_from_two_places_at_once_all_land() {
        // Each thread has its own handle on the files, as two processes do.
        let dir = temp_dir("racing");
        check_adds_from_two_places_at_once_all_land(|| PruneQueue::at(dir.clone()));
        let _ = std::fs::remove_dir_all(dir);
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        check_adds_from_two_places_at_once_all_land(|| PruneQueue::new(Arc::clone(&store)));
    }

    #[test]
    fn a_garbled_queue_is_an_error_not_an_empty_one() {
        let dir = temp_dir("garbled");
        let q = PruneQueue::at(dir.clone());
        q.add(1, "").unwrap();
        std::fs::write(dir.join("queue"), "not a number\n").unwrap();
        assert!(q.entries().is_err());
        let _ = std::fs::remove_dir_all(dir);
        let store = Arc::new(MemoryStore::new());
        store.save("queue", b"1 2 x\n\xff\n").unwrap();
        assert!(PruneQueue::new(store).entries().is_err());
    }

    #[test]
    fn the_location_names_the_directory() {
        let dir = temp_dir("location");
        let q = PruneQueue::new(Arc::new(FileStore::new(dir.clone())));
        assert_eq!(q.location(), dir.join("queue").display().to_string());
    }
}
