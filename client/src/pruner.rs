//! Prunes what the servers say waits for a prune (the server's
//! `fs::pruning`): slowly in a mount's or a browser tab's background, or all
//! at once in the foreground (`raft5fs prune`).
//!
//! - A node waits while its key record keeps older versions. The servers
//!   list those that this account can write, so any client that can write a
//!   tree can finish its prune, not only the one that revoked.
//! - Before it prunes a node, a pruner claims it for a while, and renews the
//!   claim as it goes, so that two pruners don't do the same work. A claim
//!   someone else holds is left alone.
//! - Each node is pruned completely (`Vault::prune_tree`). If a prune skips
//!   something, the node stays listed, and this pruner tries it again later,
//!   after a wait that doubles each time.
//!
//! Pruning can run at the same time as writes: the server refuses a cut
//! that would lose data, and the walk comes back to it. So a mount that
//! prunes in the background needs only its own vault.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// `std::time::Instant` panics in a browser; this is the same type natively.
use web_time::Instant;

use raft5fs_proto::errno;
use raft5fs_proto::types::{FsError, Unpruned};
use tokio::sync::Notify;

use crate::rt::{self, AbortHandle};
use crate::vault::{PruneStats, Vault};

/// How fast a background pruner works.
#[derive(Debug, Clone, Copy)]
pub struct PrunerConfig {
    /// How often to ask the servers again when nothing is left to do here.
    pub poll: Duration,
    /// The wait after each pruned node, so the mount's own reads and writes
    /// can use the store.
    pub pace: Duration,
    /// The first wait before a node whose prune skipped something is tried
    /// again. It doubles each time, up to `max_backoff`.
    pub backoff: Duration,
    pub max_backoff: Duration,
    /// How often a claim is renewed while its prune runs. Well inside the
    /// servers' claim time (ten minutes).
    pub renew: Duration,
}

impl Default for PrunerConfig {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(300),
            pace: Duration::from_millis(20),
            backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
            renew: Duration::from_secs(180),
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

/// A name for one pruner in its claims: random, so each device's pruner
/// tells its own claims from others', the same account's included.
pub fn new_holder() -> [u8; 16] {
    let key = raft5fs_crypto::Key::random();
    key.as_bytes()[..16].try_into().expect("a key has 32 bytes")
}

/// Claims node `ino` for `holder`, prunes it completely, renewing the claim
/// as it goes, and gives the claim up. `progress` hears how far it got, at
/// most once a second. `EBUSY` if someone else holds the claim.
pub async fn prune_claimed(
    vault: &Vault,
    ino: u64,
    holder: [u8; 16],
    config: &PrunerConfig,
    progress: &mut (dyn FnMut(&PruneStats) + Send),
) -> Result<PruneStats, FsError> {
    let remote = vault.remote();
    let claim = remote.claim_prune(ino, holder, false).await?;
    if !claim.granted {
        let by = claim
            .claim
            .map_or_else(String::new, |c| format!(" by {}", c.user));
        return Err(FsError::new(
            errno::EBUSY,
            format!("inode {ino} is being pruned elsewhere{by}"),
        ));
    }
    let mut told = Instant::now();
    let mut tell = |so_far: &PruneStats| {
        if told.elapsed() >= Duration::from_secs(1) {
            told = Instant::now();
            progress(so_far);
        }
    };
    let walk = std::pin::pin!(vault.prune_tree_paced(ino, false, config.pace, &mut tell));
    // Renews the claim while the walk runs; it ends with the walk. A
    // failed renewal is tried again at the next: at worst, the claim runs
    // out and someone else prunes too, which is safe.
    let renew = std::pin::pin!(async {
        loop {
            rt::sleep(config.renew).await;
            let _ = remote.claim_prune(ino, holder, false).await;
        }
    });
    let stats = match futures_util::future::select(walk, renew).await {
        futures_util::future::Either::Left((stats, _)) => stats,
        futures_util::future::Either::Right((never, _)) => never,
    };
    let _ = remote.claim_prune(ino, holder, true).await;
    Ok(stats)
}

/// What a background pruner knows, for showing.
#[derive(Debug, Clone, Default)]
pub struct PruneStatus {
    /// What waits for a prune that this account can write, as the servers
    /// last listed it.
    pub waiting: Vec<Unpruned>,
    /// The node this pruner prunes now, and how far it got.
    pub current: Option<(u64, String)>,
    /// Nodes this pruner couldn't finish, and why: it tries them again.
    pub incomplete: HashMap<u64, String>,
    /// Why the servers couldn't be asked, the last time they weren't.
    pub error: Option<String>,
}

/// A pruner running in the background: dropping it stops it.
pub struct Pruner {
    handle: AbortHandle,
    kick: Arc<Notify>,
    status: Arc<Mutex<PruneStatus>>,
}

impl Pruner {
    /// Asks the servers again now, as after a revoke.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    pub fn status(&self) -> PruneStatus {
        self.status.lock().unwrap().clone()
    }
}

impl Drop for Pruner {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Starts to prune, with `vault`, what the servers list for this account.
/// Best give it its own vault, not the one that serves the mount's
/// requests, because a prune often drops the keys it holds. Runs until the
/// `Pruner` drops.
pub fn spawn(vault: Vault, config: PrunerConfig) -> Pruner {
    let kick = Arc::new(Notify::new());
    let status = Arc::new(Mutex::new(PruneStatus::default()));
    let handle = rt::spawn(run(vault, config, Arc::clone(&kick), Arc::clone(&status)));
    Pruner {
        handle,
        kick,
        status,
    }
}

/// Waits `duration`, or less if kicked.
async fn rest(duration: Duration, kick: &Notify) {
    let sleep = std::pin::pin!(rt::sleep(duration));
    let kicked = std::pin::pin!(kick.notified());
    futures_util::future::select(sleep, kicked).await;
}

/// The background loop:
///
/// - Lists what waits. If that fails, waits longer each time.
/// - Takes the first node not claimed by someone else and not waiting out
///   an earlier failure here, and prunes it with a claim.
/// - With nothing to do, waits `config.poll`, or until kicked.
async fn run(
    vault: Vault,
    config: PrunerConfig,
    kick: Arc<Notify>,
    status: Arc<Mutex<PruneStatus>>,
) {
    let holder = new_holder();
    let mut retry: HashMap<u64, (Instant, Duration)> = HashMap::new();
    let mut list_wait = config.backoff;
    loop {
        let waiting = match vault.remote().list_unpruned().await {
            Ok(waiting) => {
                list_wait = config.backoff;
                status.lock().unwrap().error = None;
                waiting
            }
            Err(e) => {
                status.lock().unwrap().error = Some(e.to_string());
                // A server too old to list has nothing to do here.
                let wait = if e.errno == errno::ENOTSUP {
                    config.max_backoff
                } else {
                    list_wait
                };
                list_wait = (list_wait * 2).min(config.max_backoff);
                rest(wait, &kick).await;
                continue;
            }
        };
        retry.retain(|ino, _| waiting.iter().any(|w| w.ino == *ino));
        {
            let mut s = status.lock().unwrap();
            s.incomplete
                .retain(|ino, _| waiting.iter().any(|w| w.ino == *ino));
            s.waiting = waiting.clone();
        }
        let Some(ino) = next_due(&waiting, &retry, Instant::now()) else {
            rest(config.poll, &kick).await;
            continue;
        };
        status.lock().unwrap().current = Some((ino, "started".into()));
        let pruned = prune_claimed(&vault, ino, holder, &config, &mut |so_far| {
            status.lock().unwrap().current = Some((ino, describe(so_far)));
        })
        .await;
        let mut s = status.lock().unwrap();
        s.current = None;
        let failed = match pruned {
            Ok(stats) if stats.skipped.is_empty() => None,
            Ok(stats) => Some(describe(&stats)),
            // Someone else claimed it first: the next listing says so.
            Err(e) if e.errno == errno::EBUSY => None,
            Err(e) => Some(e.to_string()),
        };
        if let Some(why) = failed {
            s.incomplete.insert(ino, why);
            let wait = next_backoff(retry.get(&ino).map(|(_, w)| *w), &config);
            retry.insert(ino, (Instant::now() + wait, wait));
        }
    }
}

/// The first node in `waiting` that nobody else has claimed, and that is
/// not waiting out an earlier failure here (`retry`: when to try a node
/// again, and the wait that led there).
fn next_due(
    waiting: &[Unpruned],
    retry: &HashMap<u64, (Instant, Duration)>,
    now: Instant,
) -> Option<u64> {
    waiting
        .iter()
        .find(|w| w.claim.is_none() && retry.get(&w.ino).is_none_or(|(at, _)| *at <= now))
        .map(|w| w.ino)
}

/// How long to wait before trying a node again after it failed, given the
/// wait after its last failure: `backoff` the first time, then double, up
/// to `max_backoff`.
fn next_backoff(last: Option<Duration>, config: &PrunerConfig) -> Duration {
    last.map_or(config.backoff, |w| (w * 2).min(config.max_backoff))
}

#[cfg(test)]
mod tests {
    use raft5fs_proto::types::PruneClaim;

    use super::*;

    fn waiting(ino: u64, claimed: bool) -> Unpruned {
        Unpruned {
            ino,
            claim: claimed.then(|| PruneClaim {
                user: "bob".into(),
                expires_ms: 1,
            }),
        }
    }

    #[test]
    fn the_next_node_is_unclaimed_and_not_waiting_out_a_failure() {
        let now = Instant::now();
        let list = [waiting(1, true), waiting(2, false), waiting(3, false)];
        let mut retry = HashMap::new();
        assert_eq!(next_due(&list, &retry, now), Some(2));
        retry.insert(2, (now + Duration::from_secs(5), Duration::from_secs(5)));
        assert_eq!(next_due(&list, &retry, now), Some(3));
        // Once its wait is over, it is due again.
        assert_eq!(
            next_due(&list, &retry, now + Duration::from_secs(5)),
            Some(2)
        );
        assert_eq!(next_due(&list[..1], &retry, now), None);
    }

    #[test]
    fn the_wait_after_a_failure_doubles_up_to_the_most() {
        let config = PrunerConfig::default();
        assert_eq!(next_backoff(None, &config), config.backoff);
        assert_eq!(
            next_backoff(Some(config.backoff), &config),
            config.backoff * 2
        );
        assert_eq!(
            next_backoff(Some(config.max_backoff), &config),
            config.max_backoff
        );
    }
}
