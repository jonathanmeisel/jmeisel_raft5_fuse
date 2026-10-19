//! Garbage collection of object storage: deleting the objects nothing
//! points at any more.
//!
//! Every change to a block makes a new object (objects are written once),
//! and nothing deletes the one it replaced -- nor one uploaded for a
//! commit that then failed or never came, nor any of a file's when the
//! file goes. The KV store side of every one of those is just a key
//! removed or rewritten, as it always was. This finds what that left
//! behind, by mark and sweep:
//!
//! 1. Mark: every block pointer in the live store, then in every
//!    snapshot. Live first: a snapshot taken while the live scan runs is
//!    then always listed after it, so a pointer the scan passed before it
//!    was overwritten is still found, in that snapshot.
//! 2. List the bucket under the filesystem's prefix.
//! 3. Delete each object that is unreferenced now and was unreferenced at
//!    a sweep at least a read URL's life ago, so that nobody can still be
//!    reading it through a URL handed out when it was referenced. An
//!    object minted too recently to be past the commit window is left
//!    alone whatever: a commit naming it may still come.
//!
//! Anything going wrong before the deleting -- a read failing, a
//! snapshot gone mid-scan, the listing failing, the lease lost -- ends
//! the sweep with nothing deleted. A key under the prefix that isn't one
//! of our object names is never deleted.
//!
//! Reads outside a transaction may be stale, but a stale replica can only
//! miss a *recent* pointer, and the mint-age rule and the two sweeps
//! cover that.
//!
//! One server sweeps at a time: whichever holds the lease, a value with an
//! expiry (no lock is held across transactions). Which objects were
//! unreferenced last time is the holder's to remember, in memory; another
//! server taking over only starts that count again.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use raft5_client::Error as KvError;
use raft5fs_objstore::ObjectName;
use raft5fs_objstore::name::millis;
use raft5fs_proto::types::{Layout, ObjectGrid};

use crate::entry::decode_entry;
use crate::fs::{FsCore, TXN_TTL, retrying};
use crate::layout::{ChunkValue, GC_LEASE_KEY, attr_key};
use crate::objects::CLOCK_SKEW;
use crate::view::{ReadKeys, View};

/// How long one sweep may hold the lease before renewing it.
pub const LEASE_TTL: Duration = Duration::from_secs(600);
/// Beyond a read URL's life, how long an object must have gone
/// unreferenced before it is deleted: slack for clocks and slow reads.
pub const DELETE_MARGIN: Duration = Duration::from_secs(300);
pub const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(3600);
/// How many block starts `mark` reads the pointers of at a time.
const MARK_WINDOW: usize = 1024;

/// One server's collector: its lease holder id, and what it found
/// unreferenced, since when.
pub struct Gc {
    holder: [u8; 16],
    candidates: HashMap<ObjectName, SystemTime>,
}

impl Default for Gc {
    fn default() -> Self {
        let mut holder = [0; 16];
        getrandom::getrandom(&mut holder).expect("the OS has no randomness to give");
        Gc {
            holder,
            candidates: HashMap::new(),
        }
    }
}

/// What a sweep found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcStats {
    /// Whether this server held the lease, and so swept at all.
    pub swept: bool,
    /// Distinct objects pointed at, live or in a snapshot.
    pub referenced: usize,
    pub snapshots: usize,
    /// Objects listed under the prefix.
    pub listed: usize,
    /// Keys under the prefix that aren't object names of ours.
    pub foreign: usize,
    /// Unreferenced, but minted too recently to be sure of.
    pub young: usize,
    /// Unreferenced, waiting for a later sweep.
    pub waiting: usize,
    pub deleted: usize,
}

impl FsCore {
    /// Sweeps once, if this server keeps objects and gets the lease, as of
    /// `now`. On an error, nothing has been deleted.
    pub async fn gc_once(&self, gc: &mut Gc, now: SystemTime) -> Result<GcStats, String> {
        let mut stats = GcStats::default();
        let (Some(objects), Some(grid)) = (&self.objects, self.grid) else {
            return Ok(stats);
        };
        if !self.take_lease(gc, now).await? {
            return Ok(stats);
        }
        stats.swept = true;
        let mark_start = now;

        let mut referenced = HashSet::new();
        self.mark(View::live(&self.client), grid, &mut referenced)
            .await
            .map_err(|e| format!("marking the live store: {e}"))?;
        let snapshots = self
            .client
            .list_snapshots()
            .await
            .map_err(|e| format!("listing snapshots: {e}"))?;
        for snapshot in &snapshots {
            self.mark(View::at(&self.client, &snapshot.id), grid, &mut referenced)
                .await
                .map_err(|e| {
                    format!(
                        "marking snapshot {}: {e}",
                        String::from_utf8_lossy(&snapshot.id)
                    )
                })?;
            if !self.take_lease(gc, SystemTime::now().max(now)).await? {
                return Err("lost the lease while marking".into());
            }
        }
        stats.referenced = referenced.len();
        stats.snapshots = snapshots.len();

        let listed = objects
            .store
            .list()
            .await
            .map_err(|e| format!("listing objects: {e}"))?;
        stats.listed = listed.len();

        let youngest = mark_start
            .checked_sub(objects.commit_window() + CLOCK_SKEW)
            .map_or(0, millis);
        let wait = objects.get_ttl + DELETE_MARGIN;
        let mut candidates = HashMap::new();
        let mut doomed = Vec::new();
        for object in listed {
            let Some(name) = object.name else {
                stats.foreign += 1;
                continue;
            };
            if referenced.contains(&name) {
                continue;
            }
            if name.minted_ms > youngest {
                stats.young += 1;
                continue;
            }
            match gc.candidates.get(&name) {
                Some(&first) if now.duration_since(first).is_ok_and(|d| d >= wait) => {
                    doomed.push(name)
                }
                Some(&first) => {
                    candidates.insert(name, first);
                }
                None => {
                    candidates.insert(name, mark_start);
                }
            }
        }
        stats.waiting = candidates.len();

        // Still ours, at the last moment it can be checked.
        if !self.take_lease(gc, SystemTime::now().max(now)).await? {
            return Err("lost the lease before deleting".into());
        }
        // From here on, what was found stands: the candidates are this
        // sweep's even if a deletion fails (it is retried next time).
        gc.candidates = candidates;
        if !doomed.is_empty() {
            let deleting = objects.store.delete(&doomed).await;
            if let Err(e) = deleting {
                for name in doomed {
                    gc.candidates.insert(name, mark_start - wait);
                }
                return Err(format!("deleting objects: {e}"));
            }
        }
        stats.deleted = doomed.len();
        Ok(stats)
    }

    /// Sweeps every `interval`, for as long as the server runs, saying
    /// what each sweep did and why one failed.
    pub async fn run_gc(self: Arc<Self>, interval: Duration) {
        let mut gc = Gc::default();
        loop {
            tokio::time::sleep(interval).await;
            match self.gc_once(&mut gc, SystemTime::now()).await {
                Ok(stats) if stats.swept => eprintln!(
                    "object gc: {} referenced ({} snapshots), {} listed, {} deleted, \
                     {} waiting, {} too new, {} not ours",
                    stats.referenced,
                    stats.snapshots,
                    stats.listed,
                    stats.deleted,
                    stats.waiting,
                    stats.young,
                    stats.foreign,
                ),
                Ok(_) => {}
                Err(why) => eprintln!("object gc: sweep abandoned, nothing deleted: {why}"),
            }
        }
    }

    /// Takes or renews the lease for `gc` as of `now`: if no one holds it,
    /// its holder's time is up, or `gc` holds it already.
    async fn take_lease(&self, gc: &Gc, now: SystemTime) -> Result<bool, String> {
        let client = &self.client;
        let holder = gc.holder;
        retrying(move || async move {
            let txn = client.transaction(TXN_TTL).await?;
            if let Some(value) = txn.read_one(GC_LEASE_KEY).await?.value
                && let Some((other, expires_ms)) = decode_lease(&value)
                && other != holder
                && expires_ms > millis(now)
            {
                return Ok(false);
            }
            let expires = millis(now + LEASE_TTL);
            let mut value = holder.to_vec();
            value.extend_from_slice(&expires.to_be_bytes());
            txn.write(GC_LEASE_KEY, Some(&value)).await?;
            txn.commit().await?;
            Ok(true)
        })
        .await
        .map_err(|e| format!("taking the gc lease: {e}"))
    }

    /// Adds every object a block pointer in `view` names to `referenced`.
    /// Only a hybrid file's block starts can hold one, so only those
    /// values are read; the rest of the file's chunks are passed over by
    /// key alone. A chunk whose file's Entry can't be found -- one being
    /// deleted -- is read anyway: what might be a pointer counts.
    async fn mark(
        &self,
        view: View<'_>,
        grid: ObjectGrid,
        referenced: &mut HashSet<ObjectName>,
    ) -> Result<(), KvError> {
        const CHUNKS: u8 = 0x02;
        // Block starts, by inode, a window at a time: their files' Entries
        // in one read, then the hybrid ones' pointers in another.
        let mut window: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut iter = view.key_iterator(&[CHUNKS]);
        while let Some(key) = iter.next().await? {
            if key.first() != Some(&CHUNKS) {
                break;
            }
            let Ok(key_bytes) = <[u8; 17]>::try_from(key.as_slice()) else {
                continue;
            };
            let ino = u64::from_be_bytes(key_bytes[1..9].try_into().unwrap());
            let index = u64::from_be_bytes(key_bytes[9..].try_into().unwrap());
            if !grid.in_blocks(index) || grid.block_start(index) != index {
                continue;
            }
            window.push((ino, key));
            if window.len() == MARK_WINDOW {
                self.mark_window(view, &mut window, referenced).await?;
            }
        }
        self.mark_window(view, &mut window, referenced).await
    }

    /// `mark` for the block starts in `window`, which it empties.
    async fn mark_window(
        &self,
        view: View<'_>,
        window: &mut Vec<(u64, Vec<u8>)>,
        referenced: &mut HashSet<ObjectName>,
    ) -> Result<(), KvError> {
        // Keys come in order, so each inode's are together.
        let mut inos: Vec<u64> = window.iter().map(|&(ino, _)| ino).collect();
        inos.dedup();
        let attr_keys: Vec<Vec<u8>> = inos.iter().map(|&ino| attr_key(ino)).collect();
        let hybrid: HashMap<u64, bool> = inos
            .iter()
            .zip(view.read_many(&attr_keys).await?)
            .map(|(&ino, entry)| {
                let hybrid = match entry.value {
                    Some(bytes) => decode_entry(ino, &bytes).attr.layout == Layout::Hybrid,
                    None => true,
                };
                (ino, hybrid)
            })
            .collect();
        let (inos, keys): (Vec<u64>, Vec<Vec<u8>>) =
            window.drain(..).filter(|(ino, _)| hybrid[ino]).unzip();
        for (ino, entry) in inos.into_iter().zip(view.read_many(&keys).await?) {
            if let Some(value) = entry.value
                && let ChunkValue::Block(block) = ChunkValue::decode(value)
            {
                referenced.insert(ObjectName {
                    ino,
                    minted_ms: block.minted_ms,
                    random: block.random,
                });
            }
        }
        Ok(())
    }
}

fn decode_lease(value: &[u8]) -> Option<([u8; 16], u64)> {
    let value: &[u8; 24] = value.try_into().ok()?;
    Some((
        value[..16].try_into().unwrap(),
        u64::from_be_bytes(value[16..].try_into().unwrap()),
    ))
}
