use std::sync::Arc;

use fuser::Errno;

/// Bytes accepted by `write` but not yet committed: one contiguous run,
/// which may span several chunks (the caller bounds it to what one
/// transaction will carry -- see `chunks_per_batch`).
///
/// Committing a run is synchronous and holds this buffer's lock for the
/// whole round trip, so at most one commit for a given inode is ever
/// outstanding -- there is nothing here to queue.
#[derive(Default)]
pub struct WriteBuf {
    start: u64,
    data: Vec<u8>,
    /// A failed commit's error, kept because the bytes it lost had already
    /// been reported written. Every `write`, `flush` and `fsync` reports
    /// it; only `fsync`, or the release of the file's last descriptor,
    /// clears it.
    pub err: Option<Errno>,
    /// The handle the run is committed with: the one the latest write
    /// came through. Any writable handle this mount holds for the inode
    /// would do -- the server only checks it permits writing that inode --
    /// and a handle stays valid after its descriptor is closed, so a run
    /// outliving the descriptor that wrote it can still be committed.
    pub handle: Option<Arc<str>>,
}

impl WriteBuf {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether a write at `offset` continues the buffered run (or there is
    /// no run to continue).
    pub fn accepts(&self, offset: u64) -> bool {
        self.data.is_empty() || offset == self.start + self.data.len() as u64
    }

    /// Appends `bytes` at `offset`. The caller has checked `accepts` and
    /// that the bytes stay within one chunk.
    pub fn append(&mut self, offset: u64, bytes: &[u8]) {
        if self.data.is_empty() {
            self.start = offset;
        }
        self.data.extend_from_slice(bytes);
    }

    /// Empties the buffer, returning what it held as `(offset, bytes)`.
    pub fn take(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.data.is_empty() {
            return None;
        }
        Some((self.start, std::mem::take(&mut self.data)))
    }

    /// Drops the buffered bytes and forgets any pending error (the file is
    /// gone). The caller already holds this buffer's lock, which by itself
    /// waits out any commit in progress -- see `Raft5Fs::discard_ino`.
    pub fn discard(&mut self) {
        self.data.clear();
        self.err = None;
    }
}

#[cfg(test)]
mod tests {
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
    fn discard_clears_data_and_error() {
        let mut b = WriteBuf::default();
        b.append(0, b"abc");
        b.err = Some(Errno::EIO);
        b.discard();
        assert!(b.is_empty());
        assert_eq!(b.err, None);
    }
}
