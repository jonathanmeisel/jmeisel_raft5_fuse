use raft5fs_proto::types::FsError;

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
}

impl WriteBuf {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether a write at `offset` continues the buffered run, or there is
    /// no run.
    pub fn accepts(&self, offset: u64) -> bool {
        self.data.is_empty() || offset == self.start + self.data.len() as u64
    }

    /// Appends `bytes` at `offset`. The caller must check `accepts`, and
    /// that the bytes stay in one chunk.
    pub fn append(&mut self, offset: u64, bytes: &[u8]) {
        if self.data.is_empty() {
            self.start = offset;
        }
        self.data.extend_from_slice(bytes);
    }

    /// Empties the buffer and returns what it held as `(offset, bytes)`.
    pub fn take(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.data.is_empty() {
            return None;
        }
        Some((self.start, std::mem::take(&mut self.data)))
    }

    /// Drops the buffered bytes and any pending error, because the file is
    /// gone. The caller already holds this buffer's lock, which waits for
    /// any commit in progress (see `Session::discard_ino`).
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
        b.err = Some(FsError::errno(libc::EIO));
        b.discard();
        assert!(b.is_empty());
        assert_eq!(b.err, None);
    }
}
