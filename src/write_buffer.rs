use std::sync::{Arc, Condvar, Mutex};

use fuser::Errno;
use tokio::task::JoinHandle;

/// How many batch transactions one file may have queued or running at
/// once. `write` only blocks once this many are outstanding, so this is
/// also the most unstored data a file holds beyond its buffer.
///
/// Two, not more: a batch already coalesces several chunks into one
/// commit, so the runway is measured in batches rather than chunks, and
/// one committing plus one accumulating is as far ahead of the store as a
/// writer needs to get. The pipeline commits in order anyway, so extra
/// depth buys no parallelism -- only memory, and a larger share of the
/// cluster's node-wide buffered-transaction budget.
pub const MAX_IN_FLIGHT: usize = 2;

/// Bytes accepted by `write` but not yet handed off: one contiguous run,
/// which may span several chunks (the caller bounds it to what one
/// transaction will carry -- see `chunks_per_batch`).
///
/// A full run is not stored by the caller; it is queued on `pipe`, whose
/// tasks commit a file's batches one at a time, in order. `tail` is the
/// most recently queued one, which the next waits on.
#[derive(Default)]
pub struct WriteBuf {
    start: u64,
    data: Vec<u8>,
    pub pipe: Arc<Pipeline>,
    pub tail: Option<JoinHandle<()>>,
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

    /// Drops the buffered bytes, cancels every queued batch, waits out the
    /// one that may already be running, and forgets any pending error
    /// (the file is gone).
    pub fn discard(&mut self) {
        self.data.clear();
        self.pipe.discard();
        self.tail = None;
    }
}

/// The batch transactions a file has queued or running, and how they
/// went. Deliberately separate from `WriteBuf` and behind its own lock:
/// a writer holds the buffer's lock while it waits here for room, so the
/// tasks that report back must never need that lock themselves.
#[derive(Default)]
pub struct Pipeline {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    pending: usize,
    /// The first failure since it was last taken. While set, queued
    /// batches are skipped: storing them would extend the file over a hole
    /// the failed batch left, and the caller is already going to hear
    /// about it.
    err: Option<Errno>,
    /// Set by `discard` so queued batches of a deleted file are not
    /// stored.
    discarding: bool,
}

impl Pipeline {
    /// Claims a slot for one more batch, waiting while `MAX_IN_FLIGHT` are
    /// outstanding.
    ///
    /// Blocks the calling thread. Every caller is a fuse callback thread,
    /// where that is the point -- it is what makes `write` back off. A
    /// caller on an async worker must use `try_reserve` instead.
    pub fn reserve(&self) {
        let mut st = self.state.lock().unwrap();
        while st.pending >= MAX_IN_FLIGHT {
            st = self.changed.wait(st).unwrap();
        }
        st.pending += 1;
    }

    /// `reserve`, for a caller that must not block: claims a slot if one
    /// is free and says whether it got it.
    pub fn try_reserve(&self) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.pending >= MAX_IN_FLIGHT {
            return false;
        }
        st.pending += 1;
        true
    }

    /// Whether a queued batch should be dropped instead of stored.
    pub fn should_skip(&self) -> bool {
        let st = self.state.lock().unwrap();
        st.discarding || st.err.is_some()
    }

    /// Releases a slot, recording `err` if it is the first failure.
    pub fn complete(&self, err: Option<Errno>) {
        let mut st = self.state.lock().unwrap();
        st.pending -= 1;
        if st.err.is_none() {
            st.err = err;
        }
        self.changed.notify_all();
    }

    /// Blocks until every reserved batch has completed.
    pub fn wait_drained(&self) {
        let mut st = self.state.lock().unwrap();
        while st.pending > 0 {
            st = self.changed.wait(st).unwrap();
        }
    }

    /// The pending error, left in place for whoever reports it next.
    pub fn peek_err(&self) -> Option<Errno> {
        self.state.lock().unwrap().err
    }

    pub fn take_err(&self) -> Option<Errno> {
        self.state.lock().unwrap().err.take()
    }

    /// Nothing queued, running or unreported.
    pub fn is_idle(&self) -> bool {
        let st = self.state.lock().unwrap();
        st.pending == 0 && st.err.is_none()
    }

    fn discard(&self) {
        let mut st = self.state.lock().unwrap();
        st.discarding = true;
        while st.pending > 0 {
            st = self.changed.wait(st).unwrap();
        }
        st.discarding = false;
        st.err = None;
    }
}

/// Completes a reserved slot when dropped, reporting `EIO` unless told
/// otherwise, so a task that panics still frees its slot instead of
/// leaving every later `flush` waiting forever.
pub struct Slot {
    pipe: Arc<Pipeline>,
    err: Option<Errno>,
}

impl Slot {
    pub fn new(pipe: Arc<Pipeline>) -> Self {
        Self {
            pipe,
            err: Some(Errno::EIO),
        }
    }

    pub fn finish(mut self, err: Option<Errno>) {
        self.err = err;
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.pipe.complete(self.err);
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
    fn reserve_blocks_at_the_limit_until_a_chunk_completes() {
        let pipe = Arc::new(Pipeline::default());
        for _ in 0..MAX_IN_FLIGHT {
            pipe.reserve();
        }

        let waiter = {
            let pipe = Arc::clone(&pipe);
            std::thread::spawn(move || pipe.reserve())
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waiter.is_finished(), "reserved past the limit");

        pipe.complete(None);
        waiter.join().unwrap();
    }

    #[test]
    fn try_reserve_gives_up_at_the_limit_instead_of_waiting() {
        let pipe = Pipeline::default();
        for _ in 0..MAX_IN_FLIGHT {
            assert!(pipe.try_reserve(), "a free slot should be claimable");
        }

        // The distinction that matters: `reserve` would park here, which on
        // an async worker would stall it. This returns.
        assert!(!pipe.try_reserve());

        pipe.complete(None);
        assert!(pipe.try_reserve(), "a completed batch frees its slot");
    }

    #[test]
    fn the_first_error_is_kept_and_queued_chunks_are_skipped() {
        let pipe = Pipeline::default();
        pipe.reserve();
        pipe.reserve();
        assert!(!pipe.should_skip());

        pipe.complete(Some(Errno::EIO));
        pipe.complete(Some(Errno::ENOENT));
        assert!(pipe.should_skip());
        assert_eq!(pipe.peek_err(), Some(Errno::EIO));
        assert_eq!(pipe.take_err(), Some(Errno::EIO));
        assert!(!pipe.should_skip());
        assert!(pipe.is_idle());
    }

    #[test]
    fn a_dropped_slot_reports_eio_unless_finished() {
        let pipe = Arc::new(Pipeline::default());
        pipe.reserve();
        drop(Slot::new(Arc::clone(&pipe)));
        assert_eq!(pipe.take_err(), Some(Errno::EIO));

        pipe.reserve();
        Slot::new(Arc::clone(&pipe)).finish(None);
        assert!(pipe.is_idle());
    }
}
