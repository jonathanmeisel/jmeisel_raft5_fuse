//! Works through the prune queue (`prune_queue`): slowly in a mount's
//! background, or all at once in the foreground (`raft5fs prune`).
//!
//! - Each entry is a directory to prune completely (`Vault::prune_tree`).
//! - An entry leaves the queue only after a prune of it skips nothing. If a
//!   prune skips something, the entry is tried again later. In the
//!   background, the wait gets longer each time.
//!
//! Pruning can run at the same time as writes: the server refuses a cut
//! that would lose data, and the walk comes back to it. So a mount that
//! prunes in the background needs only its own vault.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::prune_queue::PruneQueue;
use crate::vault::{PruneStats, Vault};

/// How fast a background pruner works.
#[derive(Debug, Clone, Copy)]
pub struct PrunerConfig {
    /// How often to check an empty queue again.
    pub poll: Duration,
    /// The wait after each pruned node, so the mount's own reads and writes
    /// can use the store.
    pub pace: Duration,
    /// The first wait before an entry whose prune skipped something is
    /// tried again. It doubles each time, up to `max_backoff`.
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

/// One line about how a prune went, or is going.
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

/// Prunes queued entry `ino`, and records its progress as its status, at
/// most once a second. Removes it from the queue if nothing was skipped.
/// Returns what the prune did.
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

/// Starts to work through `queue` in the background, on `rt`, with `vault`.
/// Best give it its own vault, not the one that serves the mount's
/// requests, because a prune often drops the keys it holds. Runs until
/// aborted. Anything left stays in the queue.
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
