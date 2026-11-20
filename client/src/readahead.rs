//! Read-ahead: when a file is read in order, fetch the chunks after the
//! read before anyone asks for them.
//!
//! Each read costs a round trip to the servers, and for chunks in object
//! storage a second one to the store. A reader that asks for one piece at a
//! time (the web app's streams, a WebDAV client, a program reading a file)
//! otherwise waits for both on every piece. This keeps a window of chunks
//! in flight ahead of such a reader, so it finds them in the cache.
//!
//! - A read continues a file's run if it starts where the last read of the
//!   file ended, or at the start of a file with no run.
//! - The window starts at `INITIAL_WINDOW` chunks and doubles with each
//!   read of the run, up to the most the session allows.
//! - It fetches more once less than half a window is fetched ahead of the
//!   reader, so it fetches in batches, not one chunk per read.
//! - A read that wants a chunk being fetched waits for that fetch, and does
//!   not fetch the chunk again.
//! - A read anywhere else ends the run. A short read (the end of the file)
//!   ends it too.
//!
//! This only plans. The session runs the fetches (`Vault::prefetch`), and
//! the cache keeps what they get. A read still confirms each cached chunk
//! with the servers, so a fetch never makes a read see stale data.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::Mutex;

use tokio::sync::watch;

/// The window of a new run, in chunks.
const INITIAL_WINDOW: u64 = 2;
/// The most bytes fetched ahead of one reader.
pub const MAX_AHEAD_BYTES: u64 = 8 << 20;
/// How many files' runs are kept. When there are more, runs with nothing
/// in flight are forgotten.
const MAX_RUNS: usize = 256;

/// A fetch in flight: its chunks, and a signal that turns true when it
/// ends.
struct Fetch {
    chunks: RangeInclusive<u64>,
    done: watch::Receiver<bool>,
}

/// One file's run of reads in order.
#[derive(Default)]
struct Run {
    /// Where the next read of the run starts.
    next: u64,
    /// The window, in chunks. 0 when the file is not being read in order.
    window: u64,
    /// The first chunk that no fetch has started on.
    ahead: u64,
    fetches: Vec<Fetch>,
}

/// What a read must do: wait for `wait`, which fetch chunks it wants, and
/// start `fetch`, if any, by running `Vault::prefetch` on those chunks and
/// then sending `true` on `done`.
pub struct Plan {
    pub wait: Vec<watch::Receiver<bool>>,
    pub fetch: Option<(RangeInclusive<u64>, watch::Sender<bool>)>,
}

/// The runs of one session's files.
pub struct ReadAhead {
    chunk_size: u64,
    /// The largest window, in chunks. 0 turns read-ahead off.
    max_window: u64,
    runs: Mutex<HashMap<u64, Run>>,
}

impl ReadAhead {
    /// Read-ahead for chunks of `chunk_size` bytes, with a cache of
    /// `cache_bytes`. It keeps to a quarter of the cache, so what it
    /// fetches is not pushed out before the reader gets to it.
    pub fn new(chunk_size: u64, cache_bytes: usize) -> Self {
        let bytes = MAX_AHEAD_BYTES.min(cache_bytes as u64 / 4);
        Self {
            chunk_size,
            max_window: bytes / chunk_size,
            runs: Mutex::new(HashMap::new()),
        }
    }

    /// Plans a read of `len` bytes of `ino` at `offset`. Call it before the
    /// read, so a fetch runs at the same time as the read.
    pub fn before(&self, ino: u64, offset: u64, len: usize) -> Plan {
        let mut plan = Plan {
            wait: Vec::new(),
            fetch: None,
        };
        if self.max_window == 0 || len == 0 {
            return plan;
        }
        let end = offset + len as u64;
        let wanted = offset / self.chunk_size..=(end - 1) / self.chunk_size;
        let mut runs = self.runs.lock().unwrap();
        if runs.len() >= MAX_RUNS && !runs.contains_key(&ino) {
            runs.retain(|_, run| !run.fetches.is_empty());
        }
        let run = runs.entry(ino).or_default();
        run.fetches.retain(|f| !*f.done.borrow());
        plan.wait = run
            .fetches
            .iter()
            .filter(|f| f.chunks.start() <= wanted.end() && wanted.start() <= f.chunks.end())
            .map(|f| f.done.clone())
            .collect();

        let in_order = offset == run.next;
        run.next = end;
        if !in_order {
            run.window = 0;
            return plan;
        }
        // Not `clamp`: with large chunks the most can be below the start.
        run.window = (run.window * 2).max(INITIAL_WINDOW).min(self.max_window);
        // The first chunk after this read: a chunk that the read ends part
        // way into is the read's own.
        let from = end.div_ceil(self.chunk_size);
        let to = from + run.window - 1;
        if run.ahead > from + run.window / 2 {
            return plan;
        }
        let start = run.ahead.max(from);
        if start > to {
            return plan;
        }
        let (done_tx, done) = watch::channel(false);
        run.fetches.push(Fetch {
            chunks: start..=to,
            done,
        });
        run.ahead = to + 1;
        plan.fetch = Some((start..=to, done_tx));
        plan
    }

    /// Records that a read of `len` bytes got `got`. Fewer means the end of
    /// the file, so the run ends.
    pub fn after(&self, ino: u64, len: usize, got: usize) {
        if got < len
            && let Some(run) = self.runs.lock().unwrap().get_mut(&ino)
        {
            // No read starts here, so the next read starts a new run, once
            // a read follows it.
            run.next = u64::MAX;
            run.window = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: u64 = 1 << 20;

    fn ahead() -> ReadAhead {
        ReadAhead::new(C, 64 << 20)
    }

    fn fetched(plan: &Plan) -> Option<RangeInclusive<u64>> {
        plan.fetch.as_ref().map(|(chunks, _)| chunks.clone())
    }

    #[test]
    fn a_read_in_order_fetches_a_window_that_grows() {
        let r = ahead();
        let got: Vec<_> = (0..7)
            .map(|i| fetched(&r.before(7, i * C, C as usize)))
            .collect();
        // The window doubles from 2 to 8 chunks (8 MiB, the most). Once it
        // is full, it fetches again only when half a window is left ahead.
        assert_eq!(
            got,
            [
                Some(1..=2),
                Some(3..=5),
                Some(6..=10),
                None,
                None,
                None,
                Some(11..=14),
            ]
        );
    }

    #[test]
    fn a_read_waits_for_the_fetch_of_its_chunks() {
        let r = ahead();
        let first = r.before(7, 0, C as usize);
        assert!(first.wait.is_empty());
        let second = r.before(7, C, C as usize);
        assert_eq!(second.wait.len(), 1);
        // Once that fetch ends, nothing waits on it.
        first.fetch.unwrap().1.send(true).unwrap();
        assert!(r.before(7, 2 * C, C as usize).wait.is_empty());
    }

    #[test]
    fn a_jump_ends_the_run_and_the_end_of_the_file_stops_it() {
        let r = ahead();
        assert!(r.before(7, 0, C as usize).fetch.is_some());
        assert!(r.before(7, 40 * C, C as usize).fetch.is_none());
        // A new run from there, once the next read follows on.
        assert!(r.before(7, 41 * C, C as usize).fetch.is_some());

        r.after(7, C as usize, 10);
        assert!(r.before(7, 42 * C, C as usize).fetch.is_none());
    }

    #[test]
    fn small_reads_fetch_whole_chunks_after_the_one_they_are_in() {
        let r = ahead();
        let got: Vec<_> = (0..4)
            .map(|i| fetched(&r.before(7, i * 4096, 4096)))
            .collect();
        // Never chunk 0, which the reads are in, and no further than a full
        // window past it.
        assert_eq!(got, [Some(1..=2), Some(3..=4), Some(5..=8), None]);
    }

    #[test]
    fn a_small_cache_or_none_turns_it_down_or_off() {
        let r = ReadAhead::new(C, 8 << 20);
        let mut most = 0;
        for i in 0..10 {
            if let Some(chunks) = fetched(&r.before(7, i * C, C as usize)) {
                most = most.max(chunks.end() - chunks.start() + 1);
            }
        }
        assert_eq!(most, 2);
        let off = ReadAhead::new(C, 0);
        assert!(off.before(7, 0, C as usize).fetch.is_none());
    }

    #[test]
    fn chunks_as_large_as_the_most_fetch_one_at_a_time() {
        let big = 8 << 20;
        let r = ReadAhead::new(big, 64 << 20);
        let got: Vec<_> = (0..3)
            .map(|i| fetched(&r.before(7, i * big, big as usize)))
            .collect();
        assert_eq!(got, [Some(1..=1), Some(2..=2), Some(3..=3)]);
    }
}
