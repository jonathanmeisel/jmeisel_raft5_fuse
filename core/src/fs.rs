//! The filesystem's operations on the store, one async method for each
//! operation. There is no buffering and no FUSE here: a front end (the
//! server) decides when to call these.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, SystemTime};

use raft5_client::{Client, Consistency, Error as KvError, Transaction};
use raft5_shared::MAX_KEYS_PER_READ;

use raft5fs_crypto::data::{CHUNK_OVERHEAD, TAG_LEN, sealed_version};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_objstore::ObjectName;
use raft5fs_proto::types::{
    ActivityOp, Attr, BlockRef, BlockUpload, BlockUrl, Caller, ChunkBody, ChunkWrite, Chunks,
    DirItem, FsError, Grant, GrantedNode, KeyPath, Kind, Layout, NewNode, ObjectGrid,
    PreparedUpload, RESEAL_NAMES_BATCH, ResealedName, Rotation, SealedChunk, SealedEntryName,
    SealedMove, SetAttr, WriteBody,
};

use crate::entry::{Entry, decode_entry, encode_entry};
use crate::grants::{
    self, Reads, check_grantees_version, grantees_key, key_versions, node_keys_key,
    reservation_key, versions_of,
};
use crate::layout::{
    CHUNK_SIZE_KEY, COUNTER_KEY, ChunkValue, DELETE_BATCH, ENCRYPTED_KEY, ROOT_INO, STORE_FORMAT,
    TOMBSTONE_PREFIX, attr_key, chunk_key, chunk_prefix, chunks_per_batch, dirent_ino, dirent_key,
    dirent_prefix, dirent_sealed_name, dirent_value, encode_pointer, is_chunk_key, tombstone_key,
    validate_chunk_size,
};
use crate::objects::{
    self, Dropped, MAX_UPLOADS, ObjectSettings, Objects, check_minted, check_placement,
    object_name, segment_len,
};
use crate::snapshots;
use crate::timing::{self, next_key};
use crate::view::{ReadKeys, View, exactly};
use raft5fs_proto::clock;

pub(crate) const TXN_TTL: Duration = Duration::from_secs(10);

/// access(2)'s read and write bits.
const R: u32 = libc::R_OK as u32;
const W: u32 = libc::W_OK as u32;

/// Runs `attempt`, one whole transaction from its reads to its commit, again
/// each time the store aborts it, and returns its result (see
/// `Client::run_transaction`, which decides when to stop).
///
/// - An attempt that reaches its own decision ("that name is taken", "no such
///   inode") returns it inside `Ok`, as `Ok(Err(..))`, so only the store's
///   aborts are retried.
/// - An attempt can run more than once, so it must not change anything
///   outside the transaction.
/// - If the store keeps aborting it, this gives up, and callers report that
///   as `EBUSY`.
///
/// It takes a closure that returns a new future for each attempt, not an
/// async closure. The compiler cannot show that an async closure's future
/// is `Send` for every lifetime, and the server's runtime needs that. So
/// callers capture only references (which copy) and `move` them into each
/// attempt.
pub(crate) async fn run_txn<T, Fut>(
    client: &Client,
    mut attempt: impl FnMut(Transaction) -> Fut,
) -> Result<T, KvError>
where
    Fut: std::future::Future<Output = Result<T, KvError>>,
{
    let mut attempts = 0u32;
    let out = timing::transaction(client.run_transaction(TXN_TTL, |txn| {
        attempts += 1;
        attempt(txn)
    }))
    .await;
    if attempts > 1 {
        tracing::debug!(attempts, "store transaction retried");
    }
    out
}

/// The most that a sealed name may take. Names are 255 bytes at most on a
/// mount, and this leaves room for longer ones from the web app.
const MAX_SEALED_NAME: usize = 1 << 10;

/// The most that a grant's sealed key, or its sealed label, may take.
const MAX_SEALED_GRANT: usize = 4 << 10;

/// The most that a key record, or a sealed grantee list, may take. Both grow
/// with a folder's history and sharing, but this leaves room for thousands of
/// key versions or grantees.
const MAX_SEALED_RECORD: usize = 1 << 20;

/// Refuses (`EINVAL`) a sealed value longer than `max`. The servers can't read
/// these, but they store them on every node, and they count towards nothing.
fn check_sealed_size(what: &str, sealed: &[u8], max: usize) -> Result<(), FsError> {
    if sealed.len() > max {
        return Err(FsError::new(libc::EINVAL, format!("{what} is too large")));
    }
    Ok(())
}

/// `check_sealed_size` for what a new grant stores.
fn check_sealed_grant(key: &[u8], label: &[u8], grantees: &[u8]) -> Result<(), FsError> {
    check_sealed_size("a grant's key", key, MAX_SEALED_GRANT)?;
    check_sealed_size("a grant's label", label, MAX_SEALED_GRANT)?;
    check_sealed_size("a grantee list", grantees, MAX_SEALED_RECORD)
}

/// How old a reservation must be for `sweep_reservations` to remove it: a
/// create takes moments, so a day leaves room for clocks and slow clients.
pub(crate) const RESERVATION_AGE: Duration = Duration::from_secs(24 * 3600);

/// In a transaction attempt, unwraps a filesystem decision, or ends the
/// attempt with it as `Ok(Err(..))`, the form that `run_txn` does not
/// retry.
macro_rules! decide {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => return Ok(Err(e)),
        }
    };
}

// After `decide!`, which they use.
mod activity;
mod chunks;
mod keys;
mod namespace;
mod pruning;
mod unreachable;
pub mod usage;
pub(crate) mod volumes;

/// `ino`'s Entry as `txn` sees it. It stays locked against changes until
/// `txn` ends. A missing or deleted inode gives `ENOENT`.
async fn live_entry(txn: &Transaction, ino: u64) -> Result<Result<Entry, FsError>, KvError> {
    Ok(live(ino, txn.read_one(&attr_key(ino)).await?.value).ok_or_else(enoent))
}

/// Decodes directory `ino`'s Entry from the value read for its key, to add
/// or remove names, as `modifiable_dir` reads it.
fn dir_entry(ino: u64, value: Option<Vec<u8>>) -> Result<Entry, FsError> {
    let dir = live(ino, value).ok_or_else(enoent)?;
    check_kind(&dir, Kind::Directory)?;
    Ok(dir)
}

/// Decodes `ino`'s Entry from the value read for its key. Returns `None` if
/// it is missing or its deletion has started.
fn live(ino: u64, value: Option<Vec<u8>>) -> Option<Entry> {
    value
        .map(|bytes| decode_entry(ino, &bytes))
        .filter(|entry| !entry.is_deleted())
}

/// Reads directory `ino` to add or remove names. The caller must already
/// have checked `caller` for a writable grant above it.
async fn modifiable_dir(txn: &Transaction, ino: u64) -> Result<Result<Entry, FsError>, KvError> {
    Ok(dir_entry(ino, txn.read_one(&attr_key(ino)).await?.value))
}

/// The inode that a directory entry names, if it exists.
async fn named(txn: &Transaction, dirent: &[u8]) -> Result<Option<u64>, KvError> {
    Ok(txn.read_one(dirent).await?.value.map(|b| dirent_ino(&b)))
}

/// The error for a request that needs object storage, when the filesystem
/// keeps no data there.
fn no_objects() -> FsError {
    FsError::new(
        libc::ENOTSUP,
        "this filesystem keeps no data in object storage",
    )
}

/// Stores `writes` to file `entry` in `txn`. Each write must:
///
/// - be where the file's layout keeps it (see `objects::check_placement`);
/// - be sealed under the file's current key version (`EKEYEXPIRED` if not);
/// - for a block, name an object minted recently enough to commit;
/// - with an `expected_seq`, find the chunk still at that seq (`EAGAIN` if
///   not).
///
/// How much of a file a sealed chunk holds.
fn plain_len(sealed: &[u8]) -> u64 {
    sealed.len().saturating_sub(CHUNK_OVERHEAD) as u64
}

/// Whether `w` stays within a file of `size` bytes. Only a file's size counts
/// towards quotas and folder limits, so a chunk past it would be data that
/// counts for nothing. A block's last segment can run past the end, because
/// segments all have one length.
fn fits_in_size(w: &ChunkWrite, size: u64, chunk_size: u64) -> bool {
    let start = w.index.saturating_mul(chunk_size);
    match &w.body {
        WriteBody::Inline(blob) => start < size && plain_len(blob) <= size - start,
        WriteBody::Block(block) => {
            let last = w.index.saturating_add(u64::from(block.nseg.max(1)) - 1);
            last.saturating_mul(chunk_size) < size
        }
    }
}

/// How much of a file `value`, a stored chunk or pointer, holds.
fn stored_len(value: Vec<u8>, chunk_size: u64) -> u64 {
    match ChunkValue::decode(value) {
        ChunkValue::Inline(blob) => plain_len(&blob),
        ChunkValue::Block(block) => u64::from(block.nseg) * chunk_size,
    }
}

/// How much of a file `w` would hold.
fn write_len(w: &ChunkWrite, chunk_size: u64) -> u64 {
    match &w.body {
        WriteBody::Inline(blob) => plain_len(blob),
        WriteBody::Block(block) => u64::from(block.nseg) * chunk_size,
    }
}

/// With `existing`, every chunk must already exist at its seq. Each chunk
/// must stay within `size` bytes, or with `existing`, hold no more than the
/// chunk it replaces. Returns the objects that the stored blocks replaced,
/// for `discard` after the transaction commits.
async fn put_chunks(
    core: &FsCore,
    txn: &Transaction,
    entry: &Entry,
    writes: &[ChunkWrite],
    existing: bool,
    size: u64,
) -> Result<Result<Vec<Dropped>, FsError>, KvError> {
    let ino = entry.attr.ino;
    let now = SystemTime::now();
    for w in writes {
        decide!(check_placement(ino, entry.attr.layout, core.grid, w));
        if let WriteBody::Block(block) = &w.body {
            let Some(objects) = &core.objects else {
                return Ok(Err(no_objects()));
            };
            decide!(check_minted(block.minted_ms, now, objects.commit_window()));
        }
    }
    let (version, _) = decide!(key_versions(txn, ino).await?);
    // Read every inline chunk's seq in one read, and check each one below.
    // Only seqs are compared, so only seqs are read, and they are locked as
    // a value read would lock them. 0 means a chunk with no value. A
    // block's pointer is read in full with its seq: it is small, and it
    // names the object that the new one replaces.
    let block = |w: &&ChunkWrite| matches!(w.body, WriteBody::Block(_));
    let checked_keys: Vec<Vec<u8>> = writes
        .iter()
        .filter(|w| w.expected_seq.is_some() && !block(w))
        .map(|w| chunk_key(ino, w.index))
        .collect();
    let mut seqs = txn.read_versions_many(&checked_keys).await?.into_iter();
    let block_keys: Vec<Vec<u8>> = writes
        .iter()
        .filter(block)
        .map(|w| chunk_key(ino, w.index))
        .collect();
    let mut pointers = txn.read_many(&block_keys).await?.into_iter();
    let mut dropped = Vec::new();
    for w in writes {
        let seq = if let WriteBody::Block(new) = &w.body {
            let old = pointers.next().expect("a read of every block's pointer");
            if let Some(value) = old.value
                && let ChunkValue::Block(old) = ChunkValue::decode(value)
                && (old.minted_ms, old.random) != (new.minted_ms, new.random)
            {
                dropped.push(Dropped::new(ino, w.index, &old));
            }
            w.expected_seq.map(|_| old.seq)
        } else {
            w.expected_seq
                .map(|_| seqs.next().expect("a seq read for every expected one"))
        };
        let sealed_under = match &w.body {
            WriteBody::Inline(blob) => sealed_version(blob).ok(),
            WriteBody::Block(block) => Some(block.version),
        };
        if sealed_under != Some(version) {
            return Ok(Err(FsError::new(
                raft5fs_proto::errno::EKEYEXPIRED,
                format!("chunks of inode {ino} must be sealed under key version {version}"),
            )));
        }
        if let (Some(expected), Some(seq)) = (w.expected_seq, seq)
            && (seq != expected || (existing && seq == 0))
        {
            return Ok(Err(FsError::new(
                libc::EAGAIN,
                format!("chunk {} of inode {ino} changed meanwhile", w.index),
            )));
        }
        let key = chunk_key(ino, w.index);
        // After the check above, so that a client racing a truncate hears that
        // the chunk changed. A re-seal must still work on a chunk that a race
        // left longer than the file, or its prune could never finish.
        if !fits_in_size(w, size, core.chunk_size) {
            let keeps_length = existing
                && txn.read_one(&key).await?.value.is_some_and(|stored| {
                    stored_len(stored, core.chunk_size) >= write_len(w, core.chunk_size)
                });
            if !keeps_length {
                return Ok(Err(FsError::new(
                    libc::EINVAL,
                    format!(
                        "chunk {} of inode {ino} doesn't fit in a file of {size} bytes",
                        w.index
                    ),
                )));
            }
        }
        let value = match &w.body {
            WriteBody::Inline(blob) => blob.clone(),
            WriteBody::Block(block) => encode_pointer(block),
        };
        txn.write(&key, Some(&value)).await?;
    }
    Ok(Ok(dropped))
}

/// Checks that `sealed_name` is sealed under directory `dir`'s current key
/// version, `version`. Every name filed in the directory must be, so that
/// no name stays under a version that a revoked user has, or that a prune
/// removes.
fn check_name_version(dir: u64, sealed_name: &[u8], version: u32) -> Result<(), FsError> {
    if sealed_version(sealed_name).ok() == Some(version) {
        Ok(())
    } else {
        Err(FsError::new(
            raft5fs_proto::errno::EKEYEXPIRED,
            format!("names in inode {dir} must be sealed under key version {version}"),
        ))
    }
}

/// Whether directory `ino` has no entries. The caller must already have
/// written `ino`'s Entry in this transaction.
///
/// The scan locks only the keys it finds, not the range, so the scan alone
/// cannot stop a create from adding an entry just after it. The lock on the
/// Entry stops it. Every operation that adds a name to a directory reads
/// the directory's Entry and holds it until it commits. An exclusive lock
/// taken before the scan conflicts with that, whatever the timing. So
/// either the create commits first and the scan sees its entry, or the
/// create cannot start until this transaction ends.
async fn is_empty_dir(txn: &Transaction, ino: u64) -> Result<bool, KvError> {
    let prefix = dirent_prefix(ino);
    let mut iter = txn.key_iterator(&prefix);
    Ok(!matches!(next_key(&mut iter).await?, Some(key) if key.starts_with(&prefix)))
}

async fn write_entry(txn: &Transaction, entry: &Entry) -> Result<(), KvError> {
    txn.write(&attr_key(entry.attr.ino), Some(&encode_entry(entry)))
        .await
}

/// Records that a directory's entries changed, as POSIX requires.
async fn touch_dir(txn: &Transaction, dir: &mut Entry, now: SystemTime) -> Result<(), KvError> {
    dir.attr.mtime = now;
    dir.attr.ctime = now;
    write_entry(txn, dir).await
}

/// The chunk size of the filesystem in `client`'s store: the value the
/// store already records, or `preferred` if the store is new, which it then
/// records. Reading and recording in one transaction makes two first mounts
/// at the same time safe: the loser's retry sees the winner's value and
/// uses it.
pub async fn resolve_chunk_size(client: &Client, preferred: u64) -> Result<u64, String> {
    run_txn(client, move |txn| async move {
        if let Some(bytes) = txn.read_one(CHUNK_SIZE_KEY).await?.value {
            return Ok(decode_chunk_size(&bytes));
        }
        if let Err(why) = validate_chunk_size(preferred) {
            return Ok(Err(why));
        }
        txn.write(CHUNK_SIZE_KEY, Some(&preferred.to_be_bytes()))
            .await?;
        txn.commit().await?;
        Ok(Ok(preferred))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Checks that the store in `client` holds a filesystem in this raft5fs's
/// format (`STORE_FORMAT`), or is new, and then records that it does. A
/// store in another format is refused, not opened, because using it would
/// mix the two formats.
pub async fn check_store(client: &Client) -> Result<(), String> {
    run_txn(client, move |txn| async move {
        let refused = || {
            Ok(Err(
                "this store holds a filesystem made by an older raft5fs, in a format \
                 this one can't open"
                    .to_string(),
            ))
        };
        if let Some(bytes) = txn.read_one(ENCRYPTED_KEY).await?.value {
            return if bytes.as_slice() == [STORE_FORMAT] {
                Ok(Ok(()))
            } else {
                refused()
            };
        }
        // A root with no format record is a store in an older format.
        if txn.read_one(&attr_key(ROOT_INO)).await?.value.is_some() {
            return refused();
        }
        txn.write(ENCRYPTED_KEY, Some(&[STORE_FORMAT])).await?;
        txn.commit().await?;
        Ok(Ok(()))
    })
    .await
    .map_err(|e| e.to_string())?
}

fn decode_chunk_size(bytes: &[u8]) -> Result<u64, String> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
        format!(
            "this filesystem's recorded chunk size is {} bytes long, not 8",
            bytes.len()
        )
    })?;
    let stored = u64::from_be_bytes(bytes);
    validate_chunk_size(stored)
        .map_err(|why| format!("this filesystem records an unusable chunk size: {why}"))?;
    Ok(stored)
}

/// Gives out inode numbers. A transaction makes the read-increment-write
/// atomic. The KV store has no other safe counter: with a plain read and
/// write, two `mkdir`s at the same time could get the same inode.
async fn allocate_inode(client: &Client) -> Result<u64, KvError> {
    run_txn(client, move |txn| async move {
        let next = txn
            .read_one(COUNTER_KEY)
            .await?
            .value
            .map(|v| u64::from_be_bytes(v.try_into().unwrap()))
            .unwrap_or(ROOT_INO + 1);
        txn.write(COUNTER_KEY, Some(&(next + 1).to_be_bytes()))
            .await?;
        txn.commit().await?;
        Ok(next)
    })
    .await
}

fn enoent() -> FsError {
    FsError::errno(libc::ENOENT)
}

/// Checks that `entry` is of `kind`. Returns the errno for a file used as a
/// directory, or the reverse.
fn check_kind(entry: &Entry, kind: Kind) -> Result<(), FsError> {
    match (kind, entry.attr.kind) {
        (Kind::File, Kind::Directory) => Err(FsError::errno(libc::EISDIR)),
        (Kind::Directory, Kind::File) => Err(FsError::errno(libc::ENOTDIR)),
        _ => Ok(()),
    }
}

pub struct FsCore {
    pub(crate) client: Client,
    chunk_size: u64,
    /// How hybrid files are laid out, if the filesystem has any. The first
    /// server that kept objects for it records this, and every later server
    /// knows it, with or without object storage.
    pub(crate) grid: Option<ObjectGrid>,
    /// Where this server keeps data in object storage, if it does.
    pub(crate) objects: Option<Objects>,
    /// Where walks up to grants went, so the next walk can check the path
    /// and not walk it again (see `grants::Paths`).
    paths: grants::Paths,
    /// This server's part of measuring usage (see `usage`).
    usage: usage::Usage,
    /// This server's part of the activity log (see `activity`).
    activity: activity::ActivityLog,
}

impl FsCore {
    /// Opens the filesystem in `client`'s store.
    ///
    /// - Checks the store's format (`check_store`).
    /// - Sets the chunk size (`resolve_chunk_size`) and, with `objects`,
    ///   the object grid.
    /// - Makes the real root if the filesystem is new.
    /// - Finishes any deletion that an earlier process left half done
    ///   (`reap_tombstones`).
    pub async fn connect(
        client: Client,
        preferred_chunk_size: u64,
        objects: Option<ObjectSettings>,
    ) -> Result<Self, String> {
        // Check before the root exists, because the root is how it knows
        // that a filesystem is new.
        check_store(&client).await?;
        let chunk_size = resolve_chunk_size(&client, preferred_chunk_size).await?;
        let grid = match &objects {
            Some(settings) => {
                let wanted =
                    objects::grid_for(chunk_size, settings.object_from, settings.object_block)?;
                let grid = objects::resolve_grid(&client, wanted).await?;
                if grid != wanted {
                    eprintln!(
                        "note: this filesystem keeps blocks of {} chunks from chunk {} on; \
                         using that rather than the requested {} from {}",
                        grid.per_block, grid.from_index, wanted.per_block, wanted.from_index
                    );
                }
                Some(grid)
            }
            None => objects::recorded_grid(&client).await?,
        };
        let core = Self {
            client,
            chunk_size,
            grid,
            objects: objects.map(Objects::new),
            paths: grants::Paths::default(),
            usage: usage::Usage::default(),
            activity: activity::ActivityLog::default(),
        };
        core.ensure_root()
            .await
            .map_err(|e| format!("could not create the root directory: {e}"))?;
        // Not fatal: unfinished deletions cost space, not correctness, and
        // the next instance tries again.
        if let Err(e) = core.reap_tombstones().await {
            eprintln!("could not finish interrupted deletions: {e}");
        }
        if let Err(e) = core.sweep_reservations(RESERVATION_AGE).await {
            eprintln!("could not remove old inode reservations: {e}");
        }
        if let Err(e) = core.assign_missing_owners().await {
            eprintln!("could not give older volumes owners: {e}");
        }
        Ok(core)
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// The object grid, if this server keeps data in object storage. A
    /// client needs it to write hybrid files through this server.
    pub fn object_grid(&self) -> Option<ObjectGrid> {
        self.objects.as_ref().and(self.grid)
    }

    /// The store client that this filesystem uses.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The live store, which every write goes to.
    fn live(&self) -> View<'_> {
        View::live(&self.client)
    }

    /// Where a read-only operation reads: the live store, or snapshot `at`.
    /// Returns `ENOENT` if there is no such snapshot.
    async fn view<'a>(&'a self, at: Option<&'a [u8]>) -> Result<View<'a>, FsError> {
        let Some(id) = at else {
            return Ok(self.live());
        };
        if snapshots::exists(&self.client, id).await? {
            Ok(View::at(&self.client, id))
        } else {
            Err(FsError::new(
                libc::ENOENT,
                format!("no snapshot {}", String::from_utf8_lossy(id)),
            ))
        }
    }

    /// An inode's Entry, or `None` if it does not exist. An inode whose
    /// deletion has started also gives `None`: only the deletion itself
    /// still uses it.
    async fn read_entry(&self, view: &View<'_>, ino: u64) -> Result<Option<Entry>, FsError> {
        Ok(live(ino, view.read_one(&attr_key(ino)).await?.value))
    }

    async fn lookup_child(
        &self,
        view: &View<'_>,
        parent: u64,
        name: &OsStr,
    ) -> Result<Option<u64>, FsError> {
        let result = view.read_one(&dirent_key(parent, name)).await?;
        Ok(result.value.map(|b| dirent_ino(&b)))
    }

    /// Makes the root directory if it does not exist. The check and the
    /// create are in one transaction, so several servers can start on a new
    /// filesystem at the same time: the one that commits second finds the
    /// root.
    async fn ensure_root(&self) -> Result<(), KvError> {
        run_txn(&self.client, move |txn| async move {
            if txn.read_one(&attr_key(ROOT_INO)).await?.value.is_some() {
                return Ok(());
            }
            let now = SystemTime::now();
            let entry = Entry {
                attr: Attr {
                    ino: ROOT_INO,
                    kind: Kind::Directory,
                    size: 0,
                    perm: 0o755,
                    nlink: 2,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    layout: Layout::Inline,
                },
                parent: ROOT_INO,
            };
            txn.write(&attr_key(ROOT_INO), Some(&encode_entry(&entry)))
                .await?;
            txn.commit().await?;
            Ok(())
        })
        .await
    }

    /// `read_entry`, with a missing inode as `ENOENT`.
    async fn resolve(&self, view: &View<'_>, ino: u64) -> Result<Entry, FsError> {
        self.read_entry(view, ino).await?.ok_or_else(enoent)
    }

    /// Checks that `caller` reaches `ino` through a grant (a writable one,
    /// for `write`), with `r`'s reads. `r` is the operation's own
    /// transaction, so the check and the change commit together (see
    /// `grants`).
    async fn guard(
        &self,
        r: &impl Reads,
        caller: &Caller,
        ino: u64,
        write: bool,
    ) -> Result<Result<(), FsError>, KvError> {
        Ok(grants::authorize(r, &self.paths, &caller.user, ino, write)
            .await?
            .map(|_| ()))
    }

    /// Checks that `ino` and everything above it up to its volume are
    /// wrapped under their parents' current keys (see
    /// `grants::check_fresh`).
    async fn fresh(&self, txn: &Transaction, ino: u64) -> Result<Result<(), FsError>, KvError> {
        grants::check_fresh(txn, ino).await
    }

    /// `guard` outside a transaction, with `view`'s reads, for operations
    /// that only read. Nothing can be written at a snapshot.
    async fn guard_now(
        &self,
        view: &View<'_>,
        caller: &Caller,
        ino: u64,
        write: bool,
    ) -> Result<(), FsError> {
        if write && view.is_snapshot() {
            return Err(FsError::new(libc::EROFS, "a snapshot is read-only"));
        }
        self.guard(view, caller, ino, write).await?
    }

    /// Checks that a new entry's `name` is a tag and comes with its real
    /// name sealed. So no real name can reach the store, even from a client
    /// that tries.
    fn check_entry_name(name: &OsStr, sealed_name: &[u8]) -> Result<(), FsError> {
        if name.len() != TAG_LEN || sealed_name.is_empty() {
            return Err(FsError::new(
                libc::EINVAL,
                "a name here must be a tag, with the real name sealed",
            ));
        }
        if sealed_name.len() > MAX_SEALED_NAME {
            return Err(FsError::new(libc::ENAMETOOLONG, "that name is too long"));
        }
        Ok(())
    }

    /// Checks a batch of chunks to store: no more than one write takes, and
    /// none larger than a sealed chunk.
    fn check_chunk_writes(&self, writes: &[ChunkWrite]) -> Result<(), FsError> {
        if writes.len() > chunks_per_batch(self.chunk_size) {
            return Err(FsError::new(
                libc::EINVAL,
                "more chunks than one write takes",
            ));
        }
        let largest = self.chunk_size as usize + CHUNK_OVERHEAD;
        for w in writes {
            match &w.body {
                WriteBody::Inline(blob) if blob.len() > largest => {
                    return Err(FsError::new(
                        libc::EINVAL,
                        "a sealed chunk larger than a chunk",
                    ));
                }
                WriteBody::Inline(_) => {}
                WriteBody::Block(_) if self.objects.is_none() => return Err(no_objects()),
                WriteBody::Block(_) => {}
            }
        }
        Ok(())
    }

    /// Every snapshot, oldest first.
    pub async fn snapshots(&self) -> Result<Vec<raft5fs_proto::types::SnapshotInfo>, FsError> {
        snapshots::list(&self.client).await
    }
}

/// Compile-time check only: the server runs these on tonic's multithreaded
/// runtime, which needs every request's future to be `Send`. Generic async
/// closures (`run_txn`) are where that can stop being true without notice.
#[allow(dead_code)]
fn operations_are_send(
    core: &FsCore,
    caller: &Caller,
    name: &OsStr,
    new: &NewNode,
    mv: &SealedMove,
) {
    fn send<T: Send>(_: T) {}
    send(core.getattr(caller, 1, Some(b"s")));
    send(core.lookup(caller, 1, name, None));
    send(core.access(caller, 1, R, None));
    send(core.readdir(caller, 1, None));
    send(core.setattr(caller, 1, SetAttr::default()));
    send(core.create(caller, 1, name, 0o644, new));
    send(core.mkdir(caller, 1, name, 0o755, new));
    send(core.unlink(caller, 1, name));
    send(core.rmdir(caller, 1, name));
    send(core.rename(caller, 1, name, 1, name, false, mv));
    send(core.reserve_inode(caller));
    send(core.key_path(caller, 1, None));
    send(core.grants(caller, None));
    send(core.snapshots());
    send(core.public_key(caller, "u"));
    send(core.read_chunks(caller, 1, 0, 1, &[], true, None));
    send(core.write_chunks(caller, 1, &[], 0));
    send(core.prepare_uploads(caller, 1, &[]));
    send(core.grants_under(caller, 1));
    send(core.rotate(caller, &[]));
    send(core.reseal_chunks(caller, 1, &[]));
    send(core.reseal_names(caller, 1, &[]));
    send(core.prune_keys(caller, 1, 1, &[]));
    send(core.create_volume(caller, new, 0o755, &[], &[], &[]));
    send(core.delete_volume(caller, 1));
    send(FsCore::connect(core.client.clone(), 4096, None));
}
