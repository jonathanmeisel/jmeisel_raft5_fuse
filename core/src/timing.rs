//! How long a request waited on the store, for finding out where an
//! operation's time goes.
//!
//! The server runs each request inside `measure`, which gives it a
//! `StoreTime` of its own. Every store call made while it runs adds to
//! that: point reads (through `view`'s `ReadKeys`, which every read goes
//! through), batches of keys fetched by walks (`next_key`), transaction
//! attempts (`attempt`, which `retrying` runs each one in), and the few
//! calls that are none of those (`other`).
//! Each call is logged at `debug` too, in whatever span the request is
//! in. Calls made outside any request -- the GC, startup -- are only
//! logged.

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::time::Instant;

use raft5_client::{Error as KvError, KeyIterator};
use raft5fs_proto::timing::{StoreTime, ms};

tokio::task_local! {
    static CURRENT: Cell<StoreTime>;
}

/// Runs `f`, and says what it spent on the store.
pub async fn measure<F: Future>(f: F) -> (F::Output, StoreTime) {
    CURRENT
        .scope(Cell::new(StoreTime::default()), async move {
            let out = f.await;
            (out, CURRENT.with(Cell::get))
        })
        .await
}

/// What the current request has spent so far, if there is one.
fn so_far() -> Option<StoreTime> {
    CURRENT.try_with(Cell::get).ok()
}

fn update(f: impl FnOnce(&mut StoreTime)) {
    let _ = CURRENT.try_with(|cell| {
        let mut time = cell.get();
        f(&mut time);
        cell.set(time);
    });
}

/// `f`, a point read of `keys` keys, timed.
pub(crate) async fn read<T>(keys: usize, versions_only: bool, f: impl Future<Output = T>) -> T {
    let start = Instant::now();
    let out = f.await;
    let waited = start.elapsed();
    update(|t| t.reads.add(waited));
    tracing::debug!(keys, versions_only, took = ms(waited), "store read");
    out
}

/// `iter`'s next key. Counted only when it had to go to the store for
/// it: one already fetched is handed out without waiting on anything,
/// and a fetch can't be answered without waiting at least once.
pub(crate) async fn next_key(iter: &mut KeyIterator) -> Result<Option<Vec<u8>>, KvError> {
    let start = Instant::now();
    let mut next = pin!(iter.next());
    let mut waited_on_something = false;
    let out = poll_fn(|cx| {
        let poll = next.as_mut().poll(cx);
        waited_on_something |= poll.is_pending();
        poll
    })
    .await;
    if waited_on_something {
        let waited = start.elapsed();
        update(|t| t.scans.add(waited));
        tracing::debug!(took = ms(waited), "store key batch");
    }
    out
}

/// `f`, a store call none of the others cover, timed.
pub(crate) async fn other<T>(what: &'static str, f: impl Future<Output = T>) -> T {
    let start = Instant::now();
    let out = f.await;
    let waited = start.elapsed();
    update(|t| t.other.add(waited));
    tracing::debug!(took = ms(waited), "store {what}");
    out
}

/// `f`, one attempt at a transaction, timed. What counts is what its
/// other calls don't already account for.
pub(crate) async fn attempt<T>(f: impl Future<Output = Result<T, KvError>>) -> Result<T, KvError> {
    let before = so_far();
    let start = Instant::now();
    let out = f.await;
    let took = start.elapsed();
    let inner = match (before, so_far()) {
        (Some(before), Some(after)) => {
            (after.reads.waited - before.reads.waited)
                + (after.scans.waited - before.scans.waited)
                + (after.other.waited - before.other.waited)
        }
        _ => Default::default(),
    };
    update(|t| t.txns.add(took.saturating_sub(inner)));
    tracing::debug!(
        took = ms(took),
        aborted = matches!(out, Err(KvError::Aborted { .. })),
        "store transaction attempt"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn adds_up_within_a_request_only() {
        let ((), time) = measure(async {
            read(2, false, tokio::time::sleep(Duration::from_millis(2))).await;
            read(1, true, async {}).await;
        })
        .await;
        assert_eq!(time.reads.count, 2);
        assert!(time.reads.waited >= Duration::from_millis(2));
        assert_eq!(time.scans.count, 0);

        // Outside any request: nothing to add to, and nothing breaks.
        read(1, false, async {}).await;
        assert_eq!(so_far(), None);
    }

    #[tokio::test]
    async fn an_attempt_counts_only_its_own_time() {
        let (_, time) = measure(attempt(async {
            read(1, false, tokio::time::sleep(Duration::from_millis(20))).await;
            Ok::<_, KvError>(())
        }))
        .await;
        assert_eq!(time.reads.count, 1);
        assert_eq!(time.txns.count, 1);
        assert!(time.txns.waited < time.reads.waited);
    }
}
