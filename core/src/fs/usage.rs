//! How much each owner's volumes hold, how big each folder is, and the
//! limits on both.
//!
//! - **Measuring** (`measure`, on a timer with `run_measure`): one server at
//!   a time (a lease) walks the whole tree and works out each folder's size
//!   (everything inside it) and each owner's usage (their volumes' sizes).
//!   It writes a folder's record only if its size changed, deletes the
//!   records of folders that are gone, and sets each owner's usage.
//! - **Tallies** (`count`, applied by `flush_tallies` every second): a write,
//!   a truncate, a deletion or a move adds its change in size to an
//!   in-memory tally for the owner of the volume, and for each folder with
//!   a size limit above it. Each second the tallies are added to the
//!   owners' usage records and those folders' size records, outside any
//!   user's transaction, so writes never wait on them. They are then a
//!   second behind; the next measuring corrects any drift (say a tally that
//!   a crash lost). Other folders' sizes change only when measured.
//! - Each change in a tally keeps its time, and a record keeps when the
//!   measuring that set it started. Only changes after that are added: the
//!   measuring counted the earlier ones already.
//! - **Quotas and folder limits** (`check_room`): a write that makes a file
//!   bigger is refused (`EDQUOT`) if it would take the owner over their
//!   quota, or a folder above it over its size limit. The stored sizes and
//!   limits are read outside the write's transaction and kept for
//!   `ROOM_TTL`, with this server's tallies not stored yet added, so the
//!   check never makes writes retry. They are soft: other servers' writes
//!   of the last few seconds are not seen yet.
//!
//! Sizes are file sizes as users see them. Unowned volumes count against
//! nobody. The servers already see sizes and the tree's shape, so this
//! tells them nothing new.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Notify;

use super::unreachable::{Tree, post_order};
use super::*;
use crate::gc::{release_lease, take_lease};
use crate::layout::{
    FOLDER_LIMIT_PREFIX, FOLDER_SIZE_PREFIX, ROOT_INO, USAGE_LEASE_KEY, USAGE_PREFIX,
    folder_limit_key, folder_size_key, usage_key,
};
use raft5fs_proto::types::{FolderSize, Storage, size_text};

/// How long a volume's owner, a folder's path, or the set of limited
/// folders, as read, is used before reading it again.
const OWNER_TTL: Duration = Duration::from_secs(10);

/// How often tallies go to the store.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// How many records one transaction of a measuring writes.
const WRITE_BATCH: usize = 100;

/// How long a stored size and its limit, as read, are used before reading
/// them again.
const ROOM_TTL: Duration = Duration::from_secs(5);

/// How often a refused write may ask for a measuring now.
const REMEASURE_GAP: Duration = Duration::from_secs(60);

/// What a tally counts for: an owner's usage, or a limited folder's size.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Tally {
    Owner(String),
    Folder(u64),
}

/// Something read, and when.
type Seen<T> = Mutex<HashMap<u64, (Instant, T)>>;

/// A stored size, its limit, and when they were read.
#[derive(Clone, Copy)]
struct Room {
    seen: Instant,
    limit: Option<u64>,
    used: u64,
}

/// One server's part: its lease id, the tallies not yet stored, and what it
/// knows of each folder's path, each volume's owner, and the limits.
pub(crate) struct Usage {
    holder: [u8; 16],
    /// Each change not yet stored, with when it happened (ms since the Unix
    /// epoch).
    tallies: Mutex<HashMap<Tally, Vec<(u64, i64)>>>,
    /// Per folder: it and the folders above it, up to its volume.
    paths: Seen<Arc<[u64]>>,
    owners: Seen<Option<String>>,
    limited: Mutex<Option<(Instant, Arc<HashSet<u64>>)>>,
    rooms: Mutex<HashMap<Tally, Room>>,
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
            paths: Mutex::default(),
            owners: Mutex::default(),
            limited: Mutex::default(),
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A folder size record: bytes, files, and when the measuring that set it
/// started (ms since the Unix epoch).
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

fn decode_limit(value: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(value.try_into().ok()?))
}

/// Every key under `prefix`, with its value, read outside a transaction.
pub(super) async fn scan(
    client: &Client,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, FsError> {
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

/// The inode at the end of a key of one byte and an inode.
pub(super) fn ino_of(key: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(key.get(1..9)?.try_into().ok()?))
}

impl FsCore {
    /// Adds `delta` bytes to the tallies of what folder `dir` counts for.
    /// Never fails: if those can't be found, the next measuring counts it.
    pub(crate) async fn count(&self, dir: u64, delta: i64) {
        if delta == 0 {
            return;
        }
        let Ok(tallies) = self.tallies_over(dir).await else {
            return;
        };
        let change = (now_ms(), delta);
        let mut all = self.usage.tallies.lock().unwrap();
        for tally in tallies {
            all.entry(tally).or_default().push(change);
        }
    }

    /// What a file in folder `dir` counts for: the owner of its volume, if
    /// it has one, and each limited folder from `dir` up.
    async fn tallies_over(&self, dir: u64) -> Result<Vec<Tally>, FsError> {
        let path = self.path_of(dir).await?;
        let Some(&volume) = path.last() else {
            return Ok(Vec::new());
        };
        let mut tallies = Vec::new();
        if let Some(owner) = self.owner_of(volume).await? {
            tallies.push(Tally::Owner(owner));
        }
        let limited = self.limited().await?;
        tallies.extend(
            path.iter()
                .filter(|ino| limited.contains(ino))
                .map(|&ino| Tally::Folder(ino)),
        );
        Ok(tallies)
    }

    /// Folder `dir` and the folders above it, up to its volume; empty for
    /// the root or a folder no longer in the tree. Read again every
    /// `OWNER_TTL`, or after a move here.
    async fn path_of(&self, dir: u64) -> Result<Arc<[u64]>, FsError> {
        if let Some((seen, path)) = self.usage.paths.lock().unwrap().get(&dir)
            && seen.elapsed() < OWNER_TTL
        {
            return Ok(path.clone());
        }
        let mut path = vec![];
        let mut at = dir;
        loop {
            if at == ROOT_INO {
                return Ok(Arc::from([]));
            }
            let Some(bytes) = self.client.read_one(&attr_key(at)).await?.value else {
                return Ok(Arc::from([]));
            };
            path.push(at);
            let parent = decode_entry(at, &bytes).parent;
            if parent == ROOT_INO {
                break;
            }
            at = parent;
        }
        let now = Instant::now();
        let mut paths = self.usage.paths.lock().unwrap();
        // Each folder on the way has the rest of it as its path.
        for i in (0..path.len()).rev() {
            paths.insert(path[i], (now, Arc::from(&path[i..])));
        }
        Ok(paths[&dir].1.clone())
    }

    /// Who owns `volume` (`volumes::acting_owner`), read again every
    /// `OWNER_TTL`.
    pub(crate) async fn owner_of(&self, volume: u64) -> Result<Option<String>, FsError> {
        if let Some((seen, owner)) = self.usage.owners.lock().unwrap().get(&volume)
            && seen.elapsed() < OWNER_TTL
        {
            return Ok(owner.clone());
        }
        let owner = volumes::acting_owner(&self.client, volume).await?;
        self.usage
            .owners
            .lock()
            .unwrap()
            .insert(volume, (Instant::now(), owner.clone()));
        Ok(owner)
    }

    /// Every folder with a size limit, read again every `OWNER_TTL`.
    async fn limited(&self) -> Result<Arc<HashSet<u64>>, FsError> {
        if let Some((seen, limited)) = &*self.usage.limited.lock().unwrap()
            && seen.elapsed() < OWNER_TTL
        {
            return Ok(limited.clone());
        }
        let limited: Arc<HashSet<u64>> = Arc::new(
            scan(&self.client, FOLDER_LIMIT_PREFIX)
                .await?
                .iter()
                .filter_map(|(key, _)| ino_of(key))
                .collect(),
        );
        *self.usage.limited.lock().unwrap() = Some((Instant::now(), limited.clone()));
        Ok(limited)
    }

    /// Forgets each folder's path, after a folder moved.
    fn forget_paths(&self) {
        self.usage.paths.lock().unwrap().clear();
    }

    /// Moves sizes between tallies after `moved` went from folder `from` to
    /// folder `to`: a file's size, or a folder's last measured size. Only
    /// what one of the two folders counts for and the other doesn't
    /// changes.
    pub(crate) async fn count_move(&self, moved: u64, from: u64, to: u64) {
        self.forget_paths();
        let (Ok(before), Ok(after)) = (self.tallies_over(from).await, self.tallies_over(to).await)
        else {
            return;
        };
        let Ok(size) = self.moved_size(moved).await else {
            return;
        };
        let now = now_ms();
        let mut all = self.usage.tallies.lock().unwrap();
        for tally in before.iter().filter(|t| !after.contains(t)) {
            all.entry(tally.clone())
                .or_default()
                .push((now, -(size as i64)));
        }
        for tally in after.iter().filter(|t| !before.contains(t)) {
            all.entry(tally.clone())
                .or_default()
                .push((now, size as i64));
        }
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

    /// Adds the tallies to the records they count for, never below 0: each
    /// change made after the measuring that set the record started. A
    /// tally stays in memory until it is stored, so checks always see it in
    /// one place or the other.
    pub async fn flush_tallies(&self) -> Result<(), FsError> {
        let tallies: Vec<(Tally, Vec<(u64, i64)>)> = self
            .usage
            .tallies
            .lock()
            .unwrap()
            .iter()
            .map(|(tally, changes)| (tally.clone(), changes.clone()))
            .collect();
        for (tally, changes) in tallies {
            let stored = match &tally {
                Tally::Owner(owner) => self.add_to_usage(owner, &changes).await?,
                Tally::Folder(ino) => self.add_to_size(*ino, &changes).await?,
            };
            // New changes go after these, so these are still the first.
            let mut all = self.usage.tallies.lock().unwrap();
            if let Some(list) = all.get_mut(&tally) {
                list.drain(..changes.len());
                if list.is_empty() {
                    all.remove(&tally);
                }
            }
            if let (Some(room), Some(bytes)) =
                (self.usage.rooms.lock().unwrap().get_mut(&tally), stored)
            {
                room.used = bytes;
            }
        }
        Ok(())
    }

    /// Adds `changes` to `owner`'s usage record; returns what it holds then.
    /// Nothing for an account that is gone: its record went with it.
    async fn add_to_usage(
        &self,
        owner: &str,
        changes: &[(u64, i64)],
    ) -> Result<Option<u64>, FsError> {
        let key = &usage_key(owner);
        Ok(retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let (bytes, at) = txn
                .read_one(key)
                .await?
                .value
                .and_then(|v| decode_usage(&v))
                .unwrap_or((0, 0));
            let delta = since(changes, at);
            if delta == 0 {
                return Ok(Some(bytes));
            }
            if !crate::accounts::exists_in(&txn, owner).await? {
                return Ok(None);
            }
            let bytes = bytes.saturating_add_signed(delta);
            txn.write(key, Some(&encode_usage(bytes, at))).await?;
            txn.commit().await?;
            Ok(Some(bytes))
        })
        .await?)
    }

    /// Adds `changes` to folder `ino`'s size record; returns what it holds
    /// then. A folder with no record (deleted, or not measured yet) gets
    /// none: measuring makes it.
    async fn add_to_size(&self, ino: u64, changes: &[(u64, i64)]) -> Result<Option<u64>, FsError> {
        let key = &folder_size_key(ino);
        Ok(retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let Some((bytes, files, at)) =
                txn.read_one(key).await?.value.and_then(|v| decode_size(&v))
            else {
                return Ok(None);
            };
            let delta = since(changes, at);
            if delta == 0 {
                return Ok(Some(bytes));
            }
            let bytes = bytes.saturating_add_signed(delta);
            txn.write(key, Some(&encode_size(bytes, files, at))).await?;
            txn.commit().await?;
            Ok(Some(bytes))
        })
        .await?)
    }

    /// Refuses (`EDQUOT`) to make a file in folder `dir` `growth` bytes
    /// bigger if that takes the volume's owner over their quota, or a
    /// folder from `dir` up over its size limit.
    pub(crate) async fn check_room(&self, dir: u64, growth: u64) -> Result<(), FsError> {
        if growth == 0 {
            return Ok(());
        }
        for tally in self.tallies_over(dir).await? {
            self.check_tally(&tally, growth).await?;
        }
        Ok(())
    }

    /// Refuses (`EDQUOT`) if `bytes` more in folder `dir` would go over a
    /// quota or a folder limit, for `caller`, who must be able to write
    /// there. So a client can ask before it creates or truncates anything
    /// (an upload), rather than leave an empty file behind.
    pub async fn check_room_for(
        &self,
        caller: &Caller,
        dir: u64,
        bytes: u64,
    ) -> Result<(), FsError> {
        self.guard_now(&self.live(), caller, dir, true).await?;
        self.check_room(dir, bytes).await
    }

    /// Refuses (`EDQUOT`) a move of `moved` from folder `from` to folder
    /// `to` if what it would newly count for has no room for it: another
    /// owner, or a limited folder.
    pub(crate) async fn check_move_room(
        &self,
        moved: u64,
        from: u64,
        to: u64,
    ) -> Result<(), FsError> {
        let before = self.tallies_over(from).await?;
        let gaining: Vec<Tally> = self
            .tallies_over(to)
            .await?
            .into_iter()
            .filter(|t| !before.contains(t))
            .collect();
        if gaining.is_empty() {
            return Ok(());
        }
        let size = self.moved_size(moved).await?;
        for tally in &gaining {
            self.check_tally(tally, size).await?;
        }
        Ok(())
    }

    /// Refuses (`EDQUOT`) `growth` more bytes for `owner` if they take
    /// them over their quota.
    pub(super) async fn check_owner_room(&self, owner: &str, growth: u64) -> Result<(), FsError> {
        self.check_tally(&Tally::Owner(owner.to_string()), growth)
            .await
    }

    /// Moves volume `ino`'s `size` from `old`'s usage to `new`'s, after
    /// `new` took it over.
    pub(super) fn count_transfer(&self, ino: u64, old: Option<String>, new: &str, size: u64) {
        self.usage.owners.lock().unwrap().remove(&ino);
        let now = now_ms();
        let mut all = self.usage.tallies.lock().unwrap();
        if let Some(old) = old {
            all.entry(Tally::Owner(old))
                .or_default()
                .push((now, -(size as i64)));
        }
        all.entry(Tally::Owner(new.to_string()))
            .or_default()
            .push((now, size as i64));
    }

    /// Refuses (`EDQUOT`) `growth` more bytes for `tally` if they take it
    /// over its limit.
    async fn check_tally(&self, tally: &Tally, growth: u64) -> Result<(), FsError> {
        // The stored size first, then the tally: a flush between the two
        // can then only make this count less, never twice.
        let room = self.room_of(tally).await?;
        let Some(limit) = room.limit else {
            return Ok(());
        };
        let pending: i64 = self
            .usage
            .tallies
            .lock()
            .unwrap()
            .get(tally)
            .map_or(0, |changes| changes.iter().map(|(_, d)| d).sum());
        let used = room.used.saturating_add_signed(pending);
        if used.saturating_add(growth) <= limit {
            return Ok(());
        }
        self.ask_remeasure();
        let (used, limit) = (size_text(used), size_text(limit));
        Err(FsError::new(
            libc::EDQUOT,
            match tally {
                Tally::Owner(owner) => format!("{owner}'s storage is full ({used} of {limit})"),
                Tally::Folder(_) => {
                    format!("a folder here has reached its size limit ({used} of {limit})")
                }
            },
        ))
    }

    /// `tally`'s stored size and limit, read again every `ROOM_TTL`.
    async fn room_of(&self, tally: &Tally) -> Result<Room, FsError> {
        if let Some(room) = self.usage.rooms.lock().unwrap().get(tally)
            && room.seen.elapsed() < ROOM_TTL
        {
            return Ok(*room);
        }
        let (limit, used) = match tally {
            Tally::Owner(owner) => (
                crate::accounts::info(&self.client, owner).await?.quota,
                self.stored_usage(owner).await?.0,
            ),
            Tally::Folder(ino) => {
                let keys = [folder_limit_key(*ino), folder_size_key(*ino)];
                let mut values = self.client.get_many(&keys).await?.into_iter();
                let limit = values.next().flatten().and_then(|v| decode_limit(&v));
                let used = values
                    .next()
                    .flatten()
                    .and_then(|v| decode_size(&v))
                    .map_or(0, |(bytes, _, _)| bytes);
                (limit, used)
            }
        };
        let room = Room {
            seen: Instant::now(),
            limit,
            used,
        };
        self.usage.rooms.lock().unwrap().insert(tally.clone(), room);
        Ok(room)
    }

    /// Forgets `user`'s quota as read, after it changed.
    pub fn forget_room(&self, user: &str) {
        self.usage
            .rooms
            .lock()
            .unwrap()
            .remove(&Tally::Owner(user.to_string()));
    }

    /// Asks `run_measure` to measure now, at most once every
    /// `REMEASURE_GAP`: sizes may have drifted above what they are.
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

    /// Sets folder `ino`'s size limit (`None`: no limit), as the owner of
    /// its volume or an admin. Applies to everyone writing there, the
    /// owner too. A new limit measures the folder at once, so its size is
    /// known from the start.
    pub async fn set_folder_limit(
        &self,
        caller: &Caller,
        ino: u64,
        limit: Option<u64>,
    ) -> Result<(), FsError> {
        self.forget_paths();
        let Some(&volume) = self.path_of(ino).await?.last() else {
            return Err(enoent());
        };
        let owner = volumes::acting_owner(&self.client, volume).await?;
        if owner.as_deref() != Some(caller.user.as_str())
            && crate::accounts::is_admin(&self.client, &caller.user)
                .await
                .is_err()
        {
            return Err(FsError::new(
                libc::EACCES,
                "only the volume's owner or an admin sets size limits",
            ));
        }
        let key = &folder_limit_key(ino);
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            // Not for a folder whose deletion has begun: its record would
            // stay after it.
            let entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, Kind::Directory));
            let value = limit.map(u64::to_be_bytes);
            txn.write(key, value.as_ref().map(|v| &v[..])).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await??;
        *self.usage.limited.lock().unwrap() = None;
        self.usage.rooms.lock().unwrap().remove(&Tally::Folder(ino));
        if limit.is_some() {
            self.measure_folder(ino).await?;
        }
        Ok(())
    }

    /// Measures folder `ino` alone, and stores its size.
    async fn measure_folder(&self, ino: u64) -> Result<(), FsError> {
        let started = now_ms();
        let tree = self.load_tree_at(ino).await?;
        let (bytes, files) = folder_sizes(&tree, ino)[&ino];
        let key = &folder_size_key(ino);
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            if live_entry(&txn, ino).await?.is_err() {
                return Ok(());
            }
            txn.write(key, Some(&encode_size(bytes, files, started)))
                .await?;
            txn.commit().await?;
            Ok(())
        })
        .await?;
        Ok(())
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
        let sizes = folder_sizes(&tree, ROOT_INO);
        let mut stats = MeasureStats {
            folders: sizes.len(),
            ..MeasureStats::default()
        };

        // Folder sizes: only what changed, and none for folders gone.
        let mut writes: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        let mut stored: HashMap<u64, (u64, u64)> = HashMap::new();
        for (key, value) in scan(&self.client, FOLDER_SIZE_PREFIX).await? {
            let Some(ino) = ino_of(&key) else {
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
                writes.push((
                    folder_size_key(ino),
                    Some(encode_size(bytes, files, started)),
                ));
                stats.written += 1;
            }
        }

        // Usage: each owner's volumes, and 0 for anyone with a record but
        // no volumes any more.
        let mut usage: HashMap<String, u64> = HashMap::new();
        for &volume in &tree[&ROOT_INO].children {
            let owner = volumes::acting_owner(&self.client, volume).await?;
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

    /// The sizes and limits of the folders in `inos` that `caller` can
    /// read and that have either.
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
        let keys: Vec<Vec<u8>> = readable
            .iter()
            .flat_map(|&ino| [folder_size_key(ino), folder_limit_key(ino)])
            .collect();
        let values = self.client.get_many(&keys).await?;
        Ok(readable
            .into_iter()
            .zip(values.chunks(2))
            .filter_map(|(ino, pair)| {
                let size = pair[0].as_deref().and_then(decode_size);
                let limit = pair[1].as_deref().and_then(decode_limit);
                if size.is_none() && limit.is_none() {
                    return None;
                }
                let (bytes, files, at) = size.unwrap_or((0, 0, 0));
                Some(FolderSize {
                    ino,
                    bytes,
                    files,
                    measured_at: at / 1000,
                    limit,
                })
            })
            .collect())
    }
}

/// The sum of the `changes` made after `at`.
fn since(changes: &[(u64, i64)], at: u64) -> i64 {
    changes
        .iter()
        .filter(|(when, _)| *when > at)
        .map(|(_, d)| d)
        .sum()
}

/// Every folder's size in `tree`, from `top` down (the root left out): the
/// bytes and files of everything inside it.
fn folder_sizes(tree: &Tree, top: u64) -> HashMap<u64, (u64, u64)> {
    let mut sizes: HashMap<u64, (u64, u64)> = HashMap::new();
    for ino in post_order(tree, top) {
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
        assert_eq!(decode_limit(&7u64.to_be_bytes()), Some(7));
    }

    #[test]
    fn only_changes_after_a_measuring_count() {
        assert_eq!(since(&[(5, 10), (6, -3), (9, 100)], 6), 100);
    }
}
