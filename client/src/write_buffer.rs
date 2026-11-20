use std::collections::VecDeque;
use std::time::Duration;

use raft5fs_proto::types::FsError;
use tokio::sync::oneshot;

use crate::vault::Staged;
// `std::time::Instant` panics in a browser; this is the same type natively.
use web_time::Instant;

/// Bytes that `write` accepted but did not yet commit: one contiguous run,
/// which can span several chunks. The caller limits it to what one
/// transaction holds (see `chunks_per_batch`). A commit is synchronous and
/// holds this buffer's lock for the whole round trip, so an inode has at
/// most one commit in progress, and nothing needs a queue.
#[derive(Default)]
pub struct WriteBuf {
    start: u64,
    data: Vec<u8>,
    /// A failed commit's error. It is kept because the lost bytes were
    /// already reported as written. Every `write`, `flush`, and `fsync`
    /// reports it. Only `fsync`, or the release of the file's last
    /// descriptor, clears it.
    pub err: Option<FsError>,
    /// The inode the run belongs to.
    pub ino: u64,
    /// When the run got its first byte, and its latest.
    since: Option<Instant>,
    last: Option<Instant>,
    /// When any byte last came, whatever has happened to it since.
    last_write: Option<Instant>,
    /// How many runs `take` has handed out to be stored, and staged blocks
    /// committed.
    pub taken: u64,
    /// Whole blocks taken from the run and uploading, oldest first, not yet
    /// committed (see `Session::end_batch`). They count as buffered: they
    /// are committed, in order, before the run.
    pub staged: VecDeque<Pending>,
}

/// A whole block uploading in the background.
pub struct Pending {
    /// Where its bytes end in the file.
    pub end: u64,
    /// The upload's result, to commit.
    pub staged: oneshot::Receiver<Staged>,
}

impl WriteBuf {
    /// Whether nothing waits to be stored: no run, and no staged block.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.staged.is_empty()
    }

    /// Whether a write at `offset` continues the buffered run, or there is
    /// no run.
    pub fn accepts(&self, offset: u64) -> bool {
        self.data.is_empty() || offset == self.start + self.data.len() as u64
    }

    /// Appends `bytes` at `offset`. The caller must check `accepts`, and
    /// that the bytes stay in one chunk.
    pub fn append(&mut self, offset: u64, bytes: &[u8]) {
        let now = Instant::now();
        if self.data.is_empty() {
            self.start = offset;
            self.since = Some(now);
        }
        self.last = Some(now);
        self.last_write = Some(now);
        self.data.extend_from_slice(bytes);
    }

    /// The run's offset and length, if there is one.
    pub fn run(&self) -> Option<(u64, usize)> {
        (!self.data.is_empty()).then_some((self.start, self.data.len()))
    }

    /// Where the run and the staged blocks end, if there are any: the file
    /// is at least this long once they are stored.
    pub fn end(&self) -> Option<u64> {
        let run = (!self.data.is_empty()).then(|| self.start + self.data.len() as u64);
        run.into_iter()
            .chain(self.staged.iter().map(|p| p.end))
            .max()
    }

    /// How long until the run should be stored by time: once no byte came
    /// for `quiet`, or once its first byte is `max_age` old. Zero if that
    /// is now, and `None` if there is no run.
    /// With no run but staged blocks, they are due once no byte came for
    /// `quiet`.
    pub fn due_in(&self, quiet: Duration, max_age: Duration) -> Option<Duration> {
        if self.data.is_empty() {
            if self.staged.is_empty() {
                return None;
            }
            return Some(quiet.saturating_sub(self.last_write?.elapsed()));
        }
        let (since, last) = (self.since?, self.last?);
        Some(
            quiet
                .saturating_sub(last.elapsed())
                .min(max_age.saturating_sub(since.elapsed())),
        )
    }

    /// Empties the buffer and returns what it held as `(offset, bytes)`.
    pub fn take(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.data.is_empty() {
            return None;
        }
        self.since = None;
        self.last = None;
        self.taken += 1;
        Some((self.start, std::mem::take(&mut self.data)))
    }

    /// Drops the buffered bytes and any pending error, because the file is
    /// gone. The caller already holds this buffer's lock, which waits for
    /// any commit in progress (see `Session::discard_ino`).
    pub fn discard(&mut self) {
        self.data.clear();
        // Their uploads end by themselves. The objects have no pointer, so
        // the servers' garbage collection removes them.
        self.staged.clear();
        self.since = None;
        self.last = None;
        self.err = None;
    }
}

#[cfg(test)]
mod tests {
    use raft5fs_proto::errno;

    use super::*;

    #[test]
    fn accepts_only_the_next_offset() {
        let mut b = WriteBuf::default();
        assert!(b.accepts(100));
        b.append(100, b"abc");
        assert!(b.accepts(103));
        assert!(!b.accepts(104));
        assert!(!b.accepts(100));
    }

    #[test]
    fn take_returns_run_and_empties() {
        let mut b = WriteBuf::default();
        b.append(8, b"ab");
        b.append(10, b"cd");
        assert_eq!(b.take(), Some((8, b"abcd".to_vec())));
        assert!(b.is_empty());
        assert_eq!(b.take(), None);
        b.append(0, b"x");
        assert_eq!(b.take(), Some((0, b"x".to_vec())));
    }

    #[test]
    fn the_end_counts_buffered_bytes() {
        let mut b = WriteBuf::default();
        assert_eq!(b.end(), None);
        b.append(8, b"ab");
        b.append(10, b"cd");
        assert_eq!(b.end(), Some(12));
        b.take();
        assert_eq!(b.end(), None);
    }

    #[test]
    fn a_run_is_due_once_quiet_or_old() {
        let quiet = Duration::from_millis(50);
        let mut b = WriteBuf::default();
        assert_eq!(b.due_in(quiet, Duration::from_secs(5)), None);
        b.append(0, b"a");
        assert!(b.due_in(quiet, Duration::from_secs(5)).unwrap() > Duration::ZERO);
        std::thread::sleep(quiet);
        assert_eq!(
            b.due_in(quiet, Duration::from_secs(5)),
            Some(Duration::ZERO)
        );
        // Steady writes keep it from being quiet, but not past its age.
        b.append(1, b"b");
        assert!(b.due_in(quiet, Duration::from_secs(5)).unwrap() > Duration::ZERO);
        assert_eq!(b.due_in(quiet, quiet), Some(Duration::ZERO));
    }

    #[test]
    fn discard_clears_data_and_error() {
        let mut b = WriteBuf::default();
        b.append(0, b"abc");
        b.err = Some(FsError::errno(errno::EIO));
        b.discard();
        assert!(b.is_empty());
        assert_eq!(b.err, None);
    }
}
