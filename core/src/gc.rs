//! Garbage collection of object storage: deletes the objects that nothing
//! points to.
//!
//! Every change to a block makes a new object, because objects are written
//! once. In the KV store, a change only removes or rewrites a key. A server
//! tries to delete the object that the change stopped pointing to at once
//! (`discard`). But nothing records the attempt, so a failure or a crash
//! leaves the object. An upload for a commit that failed, or never
//! happened, also leaves an object. This code finds what is left, by mark
//! and sweep:
//!
//! 1. Mark every block pointer in the live store, then in every snapshot.
//!    The live store comes first: a snapshot taken during the live scan is
//!    then always listed after it. So a pointer that the scan passed before
//!    it was overwritten is still found, in that snapshot.
//! 2. List the bucket under the filesystem's prefix.
//! 3. Delete each object that has no pointer now, and had no pointer at a
//!    sweep at least one read URL lifetime ago. So no one can still be
//!    reading it through a URL given out while it had a pointer. Never
//!    delete an object minted too recently to be past the commit window,
//!    because a commit naming it can still come.
//!
//! If anything goes wrong before the delete step (a read fails, a snapshot
//! disappears during the scan, the listing fails, or the lease is lost),
//! the sweep stops and deletes nothing. A key under the prefix that is not
//! one of our object names is never deleted.
//!
//! Reads outside a transaction can be stale. But a stale replica can only
//! miss a *recent* pointer, and the mint-age rule and the two sweeps cover
//! that.
//!
//! Only one server sweeps at a time: the server that holds the lease, a
//! value with an expiry. No lock is held across transactions. The lease
//! holder remembers in memory which objects had no pointer last time. A
//! different server that takes over starts that count again.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use raft5_client::{Client, Error as KvError};
use raft5fs_objstore::name::millis;
use raft5fs_objstore::{ObjectName, S3Store};
use raft5fs_proto::types::{Layout, ObjectGrid};

use crate::entry::decode_entry;
use crate::fs::{FsCore, TXN_TTL, retrying};
use crate::layout::{ChunkValue, GC_LEASE_KEY, attr_key};
use crate::objects::{CLOCK_SKEW, Dropped, object_name};
use crate::timing::next_key;
use crate::view::{ReadKeys, View};

/// How long one sweep can hold the lease before it renews it.
pub const LEASE_TTL: Duration = Duration::from_secs(600);
/// How long an object must have no pointer, in addition to a read URL's
/// lifetime, before it is deleted. This allows for clock differences and
/// slow reads.
pub const DELETE_MARGIN: Duration = Duration::from_secs(300);
pub const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(3600);
/// How many block starts `mark` reads the pointers of at a time.
const MARK_WINDOW: usize = 1024;

/// One server's collector: its lease holder id, and the objects it found
/// with no pointer, with the time it found each.
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
    /// Whether this server held the lease, and so swept.
    pub swept: bool,
    /// Distinct objects with a pointer, live or in a snapshot.
    pub referenced: usize,
    pub snapshots: usize,
    /// Objects listed under the prefix.
    pub listed: usize,
    /// Keys under the prefix that are not our object names.
    pub foreign: usize,
    /// Objects with no pointer, but minted too recently to be sure.
    pub young: usize,
    /// Objects with no pointer that wait for a later sweep.
    pub waiting: usize,
    pub deleted: usize,
}

impl FsCore {
    /// Sweeps once, as of `now`, if this server keeps objects and gets the
    /// lease.
    ///
    /// - Mark the pointers in the live store, then in each snapshot.
    /// - List the bucket.
    /// - Delete objects that had no pointer in this sweep and in a sweep at
    ///   least `DELETE_MARGIN` plus a read URL's lifetime ago, and that are
    ///   past the commit window.
    ///
    /// On an error before the delete step, nothing is deleted.
    pub async fn gc_once(&self, gc: &mut Gc, now: SystemTime) -> Result<GcStats, String> {
        let mut stats = GcStats::default();
        let (Some(objects), Some(grid)) = (&self.objects, self.grid) else {
            return Ok(stats);
        };
        if !take_lease(&self.client, GC_LEASE_KEY, gc.holder, now).await? {
            return Ok(stats);
        }
        stats.swept = true;
        let mark_start = now;

        let mut referenced = HashSet::new();
        mark(View::live(&self.client), grid, &mut referenced)
            .await
            .map_err(|e| format!("marking the live store: {e}"))?;
        let snapshots = self
            .client
            .list_snapshots()
            .await
            .map_err(|e| format!("listing snapshots: {e}"))?;
        for snapshot in &snapshots {
            mark(View::at(&self.client, &snapshot.id), grid, &mut referenced)
                .await
                .map_err(|e| {
                    format!(
                        "marking snapshot {}: {e}",
                        String::from_utf8_lossy(&snapshot.id)
                    )
                })?;
            if !take_lease(
                &self.client,
                GC_LEASE_KEY,
                gc.holder,
                SystemTime::now().max(now),
            )
            .await?
            {
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

        // Check the lease again at the last possible moment.
        if !take_lease(
            &self.client,
            GC_LEASE_KEY,
            gc.holder,
            SystemTime::now().max(now),
        )
        .await?
        {
            return Err("lost the lease before deleting".into());
        }
        // From here, the candidates belong to this sweep even if a deletion
        // fails. The next sweep tries it again.
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

    /// Sweeps every `interval` while the server runs, and logs what each
    /// sweep did, or why it failed.
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
}

/// Takes or renews the lease at `key` for `holder` as of `now`, if no one
/// holds it, if its holder's time is up, or if `holder` already holds it.
/// Leases keep one server at a time doing a job: a GC sweep, or a backup.
pub(crate) async fn take_lease(
    client: &Client,
    key: &[u8],
    holder: [u8; 16],
    now: SystemTime,
) -> Result<bool, String> {
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
        if let Some(value) = txn.read_one(key).await?.value
            && let Some((other, expires_ms)) = decode_lease(&value)
            && other != holder
            && expires_ms > millis(now)
        {
            return Ok(false);
        }
        let expires = millis(now + LEASE_TTL);
        let mut value = holder.to_vec();
        value.extend_from_slice(&expires.to_be_bytes());
        txn.write(key, Some(&value)).await?;
        txn.commit().await?;
        Ok(true)
    })
    .await
    .map_err(|e| format!("taking the lease: {e}"))
}

/// Gives up the lease at `key` if `holder` holds it, so the next job need
/// not wait for it to expire.
pub(crate) async fn release_lease(
    client: &Client,
    key: &[u8],
    holder: [u8; 16],
) -> Result<(), String> {
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
        if let Some(value) = txn.read_one(key).await?.value
            && decode_lease(&value).is_some_and(|(other, _)| other == holder)
        {
            txn.write(key, None).await?;
        }
        txn.commit().await?;
        Ok(())
    })
    .await
    .map_err(|e| format!("releasing the lease: {e}"))
}

/// Adds every object that a block pointer in `view` names to
/// `referenced`. Only a hybrid file's block starts can hold a pointer,
/// so only those values are read. The file's other chunks are skipped
/// by their key. If a chunk's file has no Entry (because it is being
/// deleted), the chunk is read anyway: a value that could be a pointer
/// counts.
pub(crate) async fn mark(
    view: View<'_>,
    grid: ObjectGrid,
    referenced: &mut HashSet<ObjectName>,
) -> Result<(), KvError> {
    const CHUNKS: u8 = 0x02;
    // Block starts, by inode, one window at a time: the files' Entries
    // in one read, then the hybrid files' pointers in another.
    let mut window: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut iter = view.key_iterator(&[CHUNKS]);
    while let Some(key) = next_key(&mut iter).await? {
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
            mark_window(view, &mut window, referenced).await?;
        }
    }
    mark_window(view, &mut window, referenced).await
}

/// Runs `mark` for the block starts in `window`, and empties it.
async fn mark_window(
    view: View<'_>,
    window: &mut Vec<(u64, Vec<u8>)>,
    referenced: &mut HashSet<ObjectName>,
) -> Result<(), KvError> {
    // Keys come in order, so each inode's keys are together.
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

impl FsCore {
    /// Tries, in the background, to delete the objects in `dropped`, which
    /// a committed change stopped pointing to. It does not delete an object
    /// that the store still points to, live or in a snapshot. The change is
    /// done whatever this does: the sweep finds anything that this fails to
    /// delete.
    pub(crate) fn discard(&self, dropped: Vec<Dropped>) {
        let Some(objects) = self.objects.as_ref().filter(|o| o.prompt_delete) else {
            return;
        };
        if dropped.is_empty() {
            return;
        }
        let client = self.client.clone();
        let store = Arc::clone(&objects.store);
        tokio::spawn(async move {
            let count = dropped.len();
            if let Err(why) = discard_now(&client, &store, dropped).await {
                eprintln!("object prompt delete: {count} objects left for gc: {why}");
            }
        });
    }
}

/// The work of `discard`. A snapshot taken after the change committed
/// cannot point to what it dropped, so it checks only the snapshots listed
/// before it. It also reads the live store, because a commit sent again
/// within its mint window could have added a pointer back.
async fn discard_now(
    client: &Client,
    store: &S3Store,
    mut dropped: Vec<Dropped>,
) -> Result<(), String> {
    let snapshots = client
        .list_snapshots()
        .await
        .map_err(|e| format!("listing snapshots: {e}"))?;
    let views = std::iter::once(View::live(client))
        .chain(snapshots.iter().map(|s| View::at(client, &s.id)));
    for view in views {
        if dropped.is_empty() {
            return Ok(());
        }
        let keys: Vec<&[u8]> = dropped.iter().map(|d| d.key.as_slice()).collect();
        let entries = view
            .read_many(&keys)
            .await
            .map_err(|e| format!("checking what still points at them: {e}"))?;
        let held: HashSet<ObjectName> = dropped
            .iter()
            .zip(entries)
            .filter_map(|(d, entry)| match ChunkValue::decode(entry.value?) {
                ChunkValue::Block(block) => Some(object_name(d.name.ino, &block)),
                ChunkValue::Inline(_) => None,
            })
            .collect();
        dropped.retain(|d| !held.contains(&d.name));
    }
    let names: Vec<ObjectName> = dropped.into_iter().map(|d| d.name).collect();
    store
        .delete(&names)
        .await
        .map_err(|e| format!("deleting them: {e}"))
}

fn decode_lease(value: &[u8]) -> Option<([u8; 16], u64)> {
    let value: &[u8; 24] = value.try_into().ok()?;
    Some((
        value[..16].try_into().unwrap(),
        u64::from_be_bytes(value[16..].try_into().unwrap()),
    ))
}
