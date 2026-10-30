//! How much each owner's volumes hold, and how big each folder is.
//!
//! - **Measuring** (`measure`, on a timer with `run_measure`): one server at
//!   a time (a lease) walks the whole tree and works out each folder's size
//!   (everything inside it) and each owner's usage (their volumes' sizes).
//!   It writes a folder's record only if its size changed, deletes the
//!   records of folders that are gone, and sets each owner's usage.
//! - **Tallies** (`count`, applied by `flush_tallies` every second): a write,
//!   a truncate, a deletion or a move between volumes adds its change in
//!   size to an in-memory tally for the owner of the volume. Each second the
//!   tallies are added to the owners' usage records, outside any user's
//!   transaction, so writes never wait on them. Usage is then a second
//!   behind; the next measuring corrects any drift (say a tally that a crash
//!   lost).
//! - Each change in a tally keeps its time, and a usage record keeps when
//!   the measuring that set it started. Only changes after that are added:
//!   the measuring counted the earlier ones already.
//!
//! - **Quotas** (`check_room`): a write that makes a file bigger is
//!   refused (`EDQUOT`) if the owner's usage, with this server's tallies not
//!   stored yet, would go over their quota. Both are read outside the
//!   write's transaction and kept for `ROOM_TTL`, so the check never makes
//!   writes retry. Quotas are soft: other servers' writes of the last
//!   second or so are not seen yet.
//!
//! Sizes are file sizes as users see them. Unowned volumes count against
//! nobody. The servers already see sizes and the tree's shape, so this
//! tells them nothing new.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Notify;

use super::unreachable::{Tree, post_order};
use super::*;
use crate::gc::{release_lease, take_lease};
use crate::layout::{
    FOLDER_SIZE_PREFIX, ROOT_INO, USAGE_LEASE_KEY, USAGE_PREFIX, folder_size_key, usage_key,
    volume_key,
};
use raft5fs_proto::types::{FolderSize, Storage, size_text};

/// How long a volume's owner, as read, is used before reading it again.
const OWNER_TTL: Duration = Duration::from_secs(10);

/// How often tallies go to the store.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// How many records one transaction of a measuring writes.
const WRITE_BATCH: usize = 100;

/// How long an owner's quota and usage, as read, are used before reading
/// them again.
const ROOM_TTL: Duration = Duration::from_secs(5);

/// How often a refused write may ask for a measuring now.
const REMEASURE_GAP: Duration = Duration::from_secs(60);

/// An owner's quota and stored usage, and when they were read.
#[derive(Clone, Copy)]
struct Room {
    seen: Instant,
    quota: Option<u64>,
    used: u64,
}

/// One server's part: its lease id, the tallies not yet stored, and what it
/// knows of which volume each folder is in, and who owns each volume.
pub(crate) struct Usage {
    holder: [u8; 16],
    /// Per owner: each change not yet stored, with when it happened (ms
    /// since the Unix epoch).
    tallies: Mutex<HashMap<String, Vec<(u64, i64)>>>,
    volumes: Mutex<HashMap<u64, u64>>,
    owners: Mutex<HashMap<u64, (Instant, Option<String>)>>,
    rooms: Mutex<HashMap<String, Room>>,
    /// When a refused write last asked for a measuring, and how it asks.
    remeasured: Mutex<Option<Instant>>,
    remeasure: Notify,
}

impl Default for Usage {
    fn default() -> Self {
        let mut holder = [0; 16];
        getrandom::getrandom(&mut holder).expect("the OS has no randomness to give");
        Self {
            holder,
            tallies: Mutex::default(),
            volumes: Mutex::default(),
            owners: Mutex::default(),
            rooms: Mutex::default(),
            remeasured: Mutex::default(),
            remeasure: Notify::new(),
        }
    }
}

/// What a measuring found.
#[derive(Debug, Default)]
pub struct MeasureStats {
    pub folders: usize,
    pub written: usize,
    pub removed: usize,
    pub owners: usize,
}

fn now_secs() -> u64 {
    unix_secs(SystemTime::now())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn encode_size(bytes: u64, files: u64, at: u64) -> Vec<u8> {
    [bytes, files, at]
        .iter()
        .flat_map(|n| n.to_be_bytes())
        .collect()
}

fn decode_size(value: &[u8]) -> Option<(u64, u64, u64)> {
    let n = |i: usize| {
        Some(u64::from_be_bytes(
            value.get(i * 8..i * 8 + 8)?.try_into().ok()?,
        ))
    };
    Some((n(0)?, n(1)?, n(2)?))
}

/// A usage record: bytes, and when the measuring that set it started (ms
/// since the Unix epoch).
fn encode_usage(bytes: u64, at: u64) -> Vec<u8> {
    [bytes, at].iter().flat_map(|n| n.to_be_bytes()).collect()
}

pub(crate) fn decode_usage(value: &[u8]) -> Option<(u64, u64)> {
    let n = |i: usize| {
        Some(u64::from_be_bytes(
            value.get(i * 8..i * 8 + 8)?.try_into().ok()?,
        ))
    };
    Some((n(0)?, n(1)?))
}

/// Every key under `prefix`, with its value, read outside a transaction.
async fn scan(client: &Client, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, FsError> {
    let mut keys = Vec::new();
    let mut iter = client.key_iterator(prefix, Consistency::Stale);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(prefix) {
            break;
        }
        keys.push(key);
    }
    let values = client.get_many(&keys).await?;
    Ok(keys
        .into_iter()
        .zip(values)
        .filter_map(|(k, v)| Some((k, v?)))
        .collect())
}

impl FsCore {
    /// Adds `delta` bytes to the tally of the owner of the volume that
    /// folder `dir` is in. Never fails: if the volume or owner can't be
    /// found, the next measuring counts it.
    pub(crate) async fn count(&self, dir: u64, delta: i64) {
        if delta == 0 {
            return;
        }
        let owner = match self.volume_containing(dir).await {
            Ok(Some(volume)) => self.owner_of(volume).await.ok().flatten(),
            _ => None,
        };
        if let Some(owner) = owner {
            let change = (now_ms(), delta);
            self.usage
                .tallies
                .lock()
                .unwrap()
                .entry(owner)
                .or_default()
                .push(change);
        }
    }

    /// The volume that folder `dir` is in (itself, if it is one), or `None`
    /// for the root or a folder no longer in the tree.
    pub(crate) async fn volume_containing(&self, dir: u64) -> Result<Option<u64>, FsError> {
        if let Some(&volume) = self.usage.volumes.lock().unwrap().get(&dir) {
            return Ok(Some(volume));
        }
        let mut path = vec![];
        let mut at = dir;
        while at != ROOT_INO {
            let Some(bytes) = self.client.read_one(&attr_key(at)).await?.value else {
                return Ok(None);
            };
            let parent = decode_entry(at, &bytes).parent;
            path.push(at);
            if parent == ROOT_INO {
                let mut volumes = self.usage.volumes.lock().unwrap();
                for ino in path {
                    volumes.insert(ino, at);
                }
                return Ok(Some(at));
            }
            at = parent;
        }
        Ok(None)
    }

    /// Who owns `volume`, read again every `OWNER_TTL`.
    pub(crate) async fn owner_of(&self, volume: u64) -> Result<Option<String>, FsError> {
        if let Some((seen, owner)) = self.usage.owners.lock().unwrap().get(&volume)
            && seen.elapsed() < OWNER_TTL
        {
            return Ok(owner.clone());
        }
        let owner = match self.client.read_one(&volume_key(volume)).await?.value {
            Some(bytes) => volumes::decode_volume(volume, &bytes)?.owner,
            None => None,
        };
        self.usage
            .owners
            .lock()
            .unwrap()
            .insert(volume, (Instant::now(), owner.clone()));
        Ok(owner)
    }

    /// Forgets which volume each folder is in, after a folder moved.
    pub(crate) fn forget_volumes(&self) {
        self.usage.volumes.lock().unwrap().clear();
    }

    /// Moves usage between owners after `moved` went from folder `from` to
    /// folder `to`: a file's size, or a folder's last measured size.
    pub(crate) async fn count_move(&self, moved: u64, from: u64, to: u64) {
        self.forget_volumes();
        let (Ok(a), Ok(b)) = (
            self.volume_containing(from).await,
            self.volume_containing(to).await,
        ) else {
            return;
        };
        if a == b {
            return;
        }
        let size = match self.moved_size(moved).await {
            Ok(size) => size as i64,
            Err(_) => return,
        };
        self.count(from, -size).await;
        self.count(to, size).await;
    }

    /// A file's size, or a folder's size as last measured.
    pub(crate) async fn moved_size(&self, ino: u64) -> Result<u64, FsError> {
        let Some(bytes) = self.client.read_one(&attr_key(ino)).await?.value else {
            return Ok(0);
        };
        let entry = decode_entry(ino, &bytes);
        Ok(match entry.attr.kind {
            Kind::File => entry.attr.size,
            Kind::Directory => self
                .client
                .read_one(&folder_size_key(ino))
                .await?
                .value
                .and_then(|v| decode_size(&v))
                .map_or(0, |(bytes, _, _)| bytes),
        })
    }

    /// Adds the tallies to the owners' usage records, never below 0: each
    /// change made after the measuring that set the record started. A
    /// tally stays in memory until it is stored, so quota checks always
    /// see it in one place or the other.
    pub async fn flush_tallies(&self) -> Result<(), FsError> {
        let tallies: Vec<(String, Vec<(u64, i64)>)> = self
            .usage
            .tallies
            .lock()
            .unwrap()
            .iter()
            .map(|(owner, changes)| (owner.clone(), changes.clone()))
            .collect();
        for (owner, changes) in tallies {
            let key = &usage_key(&owner);
            let changes_ref = &changes;
            let bytes = retrying(move || async move {
                let txn = self.client.transaction(TXN_TTL).await?;
                let (bytes, at) = txn
                    .read_one(key)
                    .await?
                    .value
                    .and_then(|v| decode_usage(&v))
                    .unwrap_or((0, 0));
                let delta: i64 = changes_ref
                    .iter()
                    .filter(|(when, _)| *when > at)
                    .map(|(_, d)| d)
                    .sum();
                if delta == 0 {
                    return Ok(bytes);
                }
                let bytes = bytes.saturating_add_signed(delta);
                txn.write(key, Some(&encode_usage(bytes, at))).await?;
                txn.commit().await?;
                Ok(bytes)
            })
            .await?;
            // New changes go after these, so these are still the first.
            let mut tallies = self.usage.tallies.lock().unwrap();
            if let Some(list) = tallies.get_mut(&owner) {
                list.drain(..changes.len());
                if list.is_empty() {
                    tallies.remove(&owner);
                }
            }
            if let Some(room) = self.usage.rooms.lock().unwrap().get_mut(&owner) {
                room.used = bytes;
            }
        }
        Ok(())
    }

    /// Refuses (`EDQUOT`) to make a file in folder `dir` `growth` bytes
    /// bigger if that takes the volume's owner over their quota. Unowned
    /// volumes, and owners with no quota, have no limit.
    pub(crate) async fn check_room(&self, dir: u64, growth: u64) -> Result<(), FsError> {
        if growth == 0 {
            return Ok(());
        }
        let Some(volume) = self.volume_containing(dir).await? else {
            return Ok(());
        };
        let Some(owner) = self.owner_of(volume).await? else {
            return Ok(());
        };
        self.check_owner_room(&owner, growth).await
    }

    /// `check_room` for a known owner.
    pub(crate) async fn check_owner_room(&self, owner: &str, growth: u64) -> Result<(), FsError> {
        // The stored usage first, then the tally: a flush between the two
        // can then only make this count less, never twice.
        let (quota, stored) = self.room_of(owner).await?;
        let Some(quota) = quota else {
            return Ok(());
        };
        let pending: i64 = self
            .usage
            .tallies
            .lock()
            .unwrap()
            .get(owner)
            .map_or(0, |changes| changes.iter().map(|(_, d)| d).sum());
        let used = stored.saturating_add_signed(pending);
        if used.saturating_add(growth) <= quota {
            return Ok(());
        }
        self.ask_remeasure();
        Err(FsError::new(
            libc::EDQUOT,
            format!(
                "{owner}'s storage is full ({} of {})",
                size_text(used),
                size_text(quota)
            ),
        ))
    }

    /// Refuses (`EDQUOT`) a move of `moved` from folder `from` to folder
    /// `to` if it goes to another owner who has no room for it.
    pub(crate) async fn check_move_room(&self, moved: u64, from: u64, to: u64) -> Result<(), FsError> {
        let (Some(a), Some(b)) = (
            self.volume_containing(from).await?,
            self.volume_containing(to).await?,
        ) else {
            return Ok(());
        };
        if a == b {
            return Ok(());
        }
        let Some(owner) = self.owner_of(b).await? else {
            return Ok(());
        };
        if self.owner_of(a).await?.as_deref() == Some(owner.as_str()) {
            return Ok(());
        }
        let size = self.moved_size(moved).await?;
        self.check_owner_room(&owner, size).await
    }

    /// `owner`'s quota and stored usage, read again every `ROOM_TTL`.
    async fn room_of(&self, owner: &str) -> Result<(Option<u64>, u64), FsError> {
        if let Some(room) = self.usage.rooms.lock().unwrap().get(owner)
            && room.seen.elapsed() < ROOM_TTL
        {
            return Ok((room.quota, room.used));
        }
        let quota = crate::accounts::info(&self.client, owner).await?.quota;
        let used = self.stored_usage(owner).await?.0;
        let room = Room {
            seen: Instant::now(),
            quota,
            used,
        };
        self.usage
            .rooms
            .lock()
            .unwrap()
            .insert(owner.to_string(), room);
        Ok((quota, used))
    }

    /// Forgets `user`'s quota as read, after it changed.
    pub fn forget_room(&self, user: &str) {
        self.usage.rooms.lock().unwrap().remove(user);
    }

    /// Asks `run_measure` to measure now, at most once every
    /// `REMEASURE_GAP`: usage may have drifted above what it is.
    fn ask_remeasure(&self) {
        let mut last = self.usage.remeasured.lock().unwrap();
        if last.is_some_and(|at| at.elapsed() < REMEASURE_GAP) {
            return;
        }
        *last = Some(Instant::now());
        self.usage.remeasure.notify_one();
    }

    /// `user`'s usage record: bytes, and when the measuring that set it
    /// started (ms); zeros if there is none.
    async fn stored_usage(&self, user: &str) -> Result<(u64, u64), FsError> {
        Ok(self
            .client
            .read_one(&usage_key(user))
            .await?
            .value
            .and_then(|v| decode_usage(&v))
            .unwrap_or((0, 0)))
    }

    /// Stores the tallies every second, until the process ends.
    pub async fn run_tallies(self: Arc<Self>) {
        loop {
            tokio::time::sleep(FLUSH_INTERVAL).await;
            if let Err(e) = self.flush_tallies().await {
                eprintln!("usage tallies not stored yet: {e}");
            }
        }
    }

    /// Measures every `interval`, when no other server is, and when a
    /// refused write asks.
    pub async fn run_measure(self: Arc<Self>, interval: Duration) {
        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = self.usage.remeasure.notified() => {}
            }
            match self.measure().await {
                Ok(Some(stats)) => eprintln!(
                    "measured {} folders ({} sizes changed, {} gone) and {} owners' usage",
                    stats.folders, stats.written, stats.removed, stats.owners
                ),
                Ok(None) => {}
                Err(e) => eprintln!("measuring usage failed: {e}"),
            }
        }
    }

    /// Measures every folder and every owner's usage now (see the top of
    /// this file). `None` if another server is measuring.
    pub async fn measure(&self) -> Result<Option<MeasureStats>, FsError> {
        let holder = self.usage.holder;
        if !take_lease(&self.client, USAGE_LEASE_KEY, holder, SystemTime::now())
            .await
            .map_err(|e| FsError::new(libc::EIO, e))?
        {
            return Ok(None);
        }
        let measured = self.measure_held().await;
        if let Err(e) = release_lease(&self.client, USAGE_LEASE_KEY, holder).await {
            eprintln!("{e}");
        }
        measured.map(Some)
    }

    async fn measure_held(&self) -> Result<MeasureStats, FsError> {
        // Changes before this are in what the walk finds.
        let started = now_ms();
        let tree = self.load_tree().await?;
        let at = now_secs();
        let sizes = folder_sizes(&tree);
        let mut stats = MeasureStats {
            folders: sizes.len(),
            ..MeasureStats::default()
        };

        // Folder sizes: only what changed, and none for folders gone.
        let mut writes: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        let mut stored: HashMap<u64, (u64, u64)> = HashMap::new();
        for (key, value) in scan(&self.client, FOLDER_SIZE_PREFIX).await? {
            let Some(ino) = key
                .get(1..9)
                .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
            else {
                continue;
            };
            match decode_size(&value) {
                Some((bytes, files, _)) if sizes.contains_key(&ino) => {
                    stored.insert(ino, (bytes, files));
                }
                _ => {
                    writes.push((key, None));
                    stats.removed += 1;
                }
            }
        }
        for (&ino, &(bytes, files)) in &sizes {
            if stored.get(&ino) != Some(&(bytes, files)) {
                writes.push((folder_size_key(ino), Some(encode_size(bytes, files, at))));
                stats.written += 1;
            }
        }

        // Usage: each owner's volumes, and 0 for anyone with a record but
        // no volumes any more.
        let tops: Vec<u64> = tree[&ROOT_INO].children.clone();
        let records = self
            .client
            .get_many(&tops.iter().map(|&v| volume_key(v)).collect::<Vec<_>>())
            .await?;
        let mut usage: HashMap<String, u64> = HashMap::new();
        for (&volume, record) in tops.iter().zip(records) {
            let owner = match record {
                Some(bytes) => volumes::decode_volume(volume, &bytes)?.owner,
                None => None,
            };
            if let (Some(owner), Some(&(bytes, _))) = (owner, sizes.get(&volume)) {
                *usage.entry(owner).or_default() += bytes;
            }
        }
        for (key, _) in scan(&self.client, USAGE_PREFIX).await? {
            let user = String::from_utf8_lossy(&key[USAGE_PREFIX.len()..]).into_owned();
            usage.entry(user).or_default();
        }
        stats.owners = usage.len();
        for (owner, bytes) in usage {
            writes.push((usage_key(&owner), Some(encode_usage(bytes, started))));
        }

        for batch in writes.chunks(WRITE_BATCH) {
            retrying(move || async move {
                let txn = self.client.transaction(TXN_TTL).await?;
                for (key, value) in batch {
                    txn.write(key, value.as_deref()).await?;
                }
                txn.commit().await?;
                Ok(())
            })
            .await?;
        }
        Ok(stats)
    }

    /// How much `user`'s volumes hold, and when it was last measured
    /// (seconds since the Unix epoch; 0 if never).
    pub async fn storage(&self, user: &str) -> Result<Storage, FsError> {
        let (used, measured_ms) = self.stored_usage(user).await?;
        Ok(Storage {
            used,
            measured_at: measured_ms / 1000,
            quota: crate::accounts::info(&self.client, user).await?.quota,
        })
    }

    /// The last measured sizes of the folders in `inos` that `caller` can
    /// read and that have been measured.
    pub async fn folder_sizes(
        &self,
        caller: &Caller,
        inos: &[u64],
    ) -> Result<Vec<FolderSize>, FsError> {
        let view = self.live();
        let mut readable = Vec::new();
        for &ino in inos {
            if self.guard_now(&view, caller, ino, false).await.is_ok() {
                readable.push(ino);
            }
        }
        let keys: Vec<Vec<u8>> = readable.iter().map(|&ino| folder_size_key(ino)).collect();
        Ok(readable
            .into_iter()
            .zip(self.client.get_many(&keys).await?)
            .filter_map(|(ino, value)| {
                let (bytes, files, measured_at) = decode_size(&value?)?;
                Some(FolderSize {
                    ino,
                    bytes,
                    files,
                    measured_at,
                })
            })
            .collect())
    }
}

/// Every folder's size in `tree` (the root left out): the bytes and files
/// of everything inside it.
fn folder_sizes(tree: &Tree) -> HashMap<u64, (u64, u64)> {
    let mut sizes: HashMap<u64, (u64, u64)> = HashMap::new();
    for ino in post_order(tree, ROOT_INO) {
        let node = &tree[&ino];
        if node.kind != Kind::Directory || ino == ROOT_INO {
            continue;
        }
        let (mut bytes, mut files) = (0, 0);
        for child in &node.children {
            let c = &tree[child];
            match c.kind {
                Kind::File => {
                    bytes += c.size;
                    files += 1;
                }
                Kind::Directory => {
                    let (b, f) = sizes[child];
                    bytes += b;
                    files += f;
                }
            }
        }
        sizes.insert(ino, (bytes, files));
    }
    sizes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip() {
        assert_eq!(decode_size(&encode_size(1, 2, 3)), Some((1, 2, 3)));
        assert_eq!(decode_usage(&encode_usage(4, 5)), Some((4, 5)));
        assert_eq!(decode_size(&[1, 2]), None);
    }
}
