//! Working through the prune queue (`prune_queue`): in a mount's
//! background, unhurried, or all at once in the foreground
//! (`raft5fs prune`).
//!
//! Each entry is a directory to prune whole (`Vault::prune_tree`). It
//! leaves the queue only once a prune of it skips nothing; one that does
//! is tried again later -- in the background, after a wait that grows each
//! time. Pruning was made to run beside writes (the server refuses a cut
//! that would lose anything, and the walk comes back to it), so a mount
//! pruning in the background needs nothing more than its own vault.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::prune_queue::PruneQueue;
use crate::vault::{PruneStats, Vault};

/// How a background pruner paces itself.
#[derive(Debug, Clone, Copy)]
pub struct PrunerConfig {
    /// How often an empty queue is looked at again.
    pub poll: Duration,
    /// The wait after each node pruned, leaving the store to the mount's
    /// own reads and writes.
    pub pace: Duration,
    /// The first wait before trying again an entry whose prune skipped
    /// something; it doubles each time, up to `max_backoff`.
    pub backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for PrunerConfig {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(5),
            pace: Duration::from_millis(20),
            backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
        }
    }
}

/// One line on how a prune went, or is going.
pub fn describe(stats: &PruneStats) -> String {
    let mut line = format!(
        "{} nodes; re-sealed {} chunks and {} names; rotated {} stale children; \
         dropped {} old key versions",
        stats.nodes, stats.chunks, stats.names, stats.rotated, stats.dropped
    );
    if let Some((ino, e)) = stats.skipped.first() {
        line.push_str(&format!(
            "; skipped {} (inode {ino}: {e})",
            stats.skipped.len()
        ));
    }
    line
}

/// Prunes queued entry `ino` -- recording how it goes as its status, at
/// most once a second -- and takes it off the queue if nothing was
/// skipped. Returns what the prune did.
pub async fn prune_entry(
    vault: &Vault,
    queue: &PruneQueue,
    ino: u64,
    pace: Duration,
) -> PruneStats {
    let _ = queue.set_status(ino, "pruning: started");
    let mut last = Instant::now();
    let stats = vault
        .prune_tree_paced(ino, false, pace, &mut |so_far| {
            if last.elapsed() >= Duration::from_secs(1) {
                last = Instant::now();
                let _ = queue.set_status(ino, &format!("pruning: {}", describe(so_far)));
            }
        })
        .await;
    if stats.skipped.is_empty() {
        let _ = queue.remove(ino);
    } else {
        let _ = queue.set_status(
            ino,
            &format!("incomplete, to try again: {}", describe(&stats)),
        );
    }
    stats
}

/// Starts working through `queue` in the background, on `rt`, with
/// `vault` (best its own, not the one the mount serves requests with:
/// a prune drops the keys it holds often). Runs until aborted; whatever is
/// left stays queued.
pub fn spawn(rt: &Handle, vault: Vault, queue: PruneQueue, config: PrunerConfig) -> JoinHandle<()> {
    rt.spawn(async move {
        let mut retry: HashMap<u64, (Instant, Duration)> = HashMap::new();
        loop {
            let entries = match queue.entries() {
                Ok(entries) => entries,
                Err(e) => {
                    eprintln!(
                        "cannot read the prune queue in {}: {e}",
                        queue.dir().display()
                    );
                    tokio::time::sleep(config.max_backoff.min(config.poll * 12)).await;
                    continue;
                }
            };
            retry.retain(|ino, _| entries.iter().any(|e| e.ino == *ino));
            let now = Instant::now();
            let due = entries
                .iter()
                .find(|e| retry.get(&e.ino).is_none_or(|(at, _)| *at <= now));
            let Some(entry) = due else {
                tokio::time::sleep(config.poll).await;
                continue;
            };
            let stats = prune_entry(&vault, &queue, entry.ino, config.pace).await;
            if !stats.skipped.is_empty() {
                let wait = retry
                    .get(&entry.ino)
                    .map_or(config.backoff, |(_, w)| (*w * 2).min(config.max_backoff));
                retry.insert(entry.ino, (Instant::now() + wait, wait));
            }
        }
    })
}
