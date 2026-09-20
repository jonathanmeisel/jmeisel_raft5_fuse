use fuser::Errno;

/// Bytes accepted by `write` but not yet stored: one contiguous run that
/// never crosses a chunk boundary, so flushing it touches a single chunk.
///
/// `err` is a failed flush's errno, held until the next `flush`, `fsync`
/// or `write` so the application hears about lost data the way it would
/// from a write-back cache.
#[derive(Default)]
pub struct WriteBuf {
    start: u64,
    data: Vec<u8>,
    pub err: Option<Errno>,
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

    /// Drops the buffered bytes and any pending error (the file is gone).
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
}
