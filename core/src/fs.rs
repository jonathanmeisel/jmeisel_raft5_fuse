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
    Attr, BlockRef, BlockUpload, BlockUrl, Caller, ChunkBody, ChunkWrite, Chunks, DirItem, FsError,
    Grant, GrantedNode, KeyPath, Kind, Layout, NewNode, ObjectGrid, PreparedUpload,
    RESEAL_NAMES_BATCH, ResealedName, Rotation, SealedChunk, SealedMove, SetAttr, WriteBody,
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
use crate::view::{ReadKeys, View};

pub(crate) const TXN_TTL: Duration = Duration::from_secs(10);

/// access(2)'s read and write bits.
const R: u32 = libc::R_OK as u32;
const W: u32 = libc::W_OK as u32;

/// Runs `attempt` (one whole transaction, from open to commit) until the
/// store stops aborting it, and returns its result.
///
/// - The retry must cover the whole attempt, because `Aborted` can come
///   from any step, not only `commit`. A contended key refuses the `read`
///   or `write` that touches it at once (see the server's wound-wait
///   `acquire`). It does not wait for commit to fail.
/// - `Transaction` does not retry this itself, on purpose (see its doc
///   comment): it does not know what the reads were, so only the caller
///   that made them can do them again.
/// - An aborted transaction wrote nothing, so it is always safe to run the
///   attempt again.
/// - An attempt that reaches its own decision ("that name is taken", "no
///   such inode") returns it inside `Ok`, as `Ok(Err(..))`, so only the
///   store's aborts are retried.
///
/// It takes a closure that returns a new future for each attempt, not an
/// async closure. The compiler cannot show that an async closure's future
/// is `Send` for every lifetime, and the server's runtime needs that. So
/// callers capture only references (which copy) and `move` them into each
/// attempt.
pub(crate) async fn retrying<T, Fut>(mut attempt: impl FnMut() -> Fut) -> Result<T, KvError>
where
    Fut: std::future::Future<Output = Result<T, KvError>>,
{
    loop {
        match timing::attempt(attempt()).await {
            Err(KvError::Aborted { .. }) => continue,
            other => return other,
        }
    }
}

/// In a transaction attempt, unwraps a filesystem decision, or ends the
/// attempt with it as `Ok(Err(..))`, the form that `retrying` does not
/// retry.
macro_rules! decide {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => return Ok(Err(e)),
        }
    };
}

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

/// The entries that a read of a fixed number of keys returned, in order.
fn each<const N: usize>(entries: Vec<raft5_client::Entry>) -> [raft5_client::Entry; N] {
    entries
        .try_into()
        .expect("a read of every key answers each")
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
/// With `existing`, every chunk must already exist at its seq. Returns the
/// objects that the stored blocks replaced, for `discard` after the
/// transaction commits.
async fn put_chunks(
    core: &FsCore,
    txn: &Transaction,
    entry: &Entry,
    writes: &[ChunkWrite],
    existing: bool,
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
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
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
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
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
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
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
        };
        core.ensure_root()
            .await
            .map_err(|e| format!("could not create the root directory: {e}"))?;
        // Not fatal: unfinished deletions cost space, not correctness, and
        // the next instance tries again.
        if let Err(e) = core.reap_tombstones().await {
            eprintln!("could not finish interrupted deletions: {e}");
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
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
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
        if name.len() == TAG_LEN && !sealed_name.is_empty() {
            Ok(())
        } else {
            Err(FsError::new(
                libc::EINVAL,
                "a name here must be a tag, with the real name sealed",
            ))
        }
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

    /// Needs a grant above `ino`, at snapshot `at` if one is given.
    pub async fn getattr(
        &self,
        caller: &Caller,
        ino: u64,
        at: Option<&[u8]>,
    ) -> Result<Attr, FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, false).await?;
        Ok(self.resolve(&view, ino).await?.attr)
    }

    /// The inode that `name` names in `parent`, without reading its
    /// attributes.
    async fn child_ino(&self, view: &View<'_>, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        self.lookup_child(view, parent, name)
            .await?
            .ok_or_else(enoent)
    }

    /// The entry `name` (a tag) in `parent`: its attributes, and its sealed
    /// name as the listing has it, so the client can check that the name
    /// points to that inode.
    pub async fn lookup(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        at: Option<&[u8]>,
    ) -> Result<(Attr, Vec<u8>), FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, parent, false).await?;
        let [dir, dirent] = each(
            view.read_many(&[attr_key(parent), dirent_key(parent, name)])
                .await?,
        );
        let dir = live(parent, dir.value).ok_or_else(enoent)?;
        if dir.attr.kind != Kind::Directory {
            return Err(FsError::errno(libc::ENOTDIR));
        }
        let Some(bytes) = dirent.value else {
            return Err(enoent());
        };
        let attr = self.resolve(&view, dirent_ino(&bytes)).await?.attr;
        Ok((attr, dirent_sealed_name(&bytes).to_vec()))
    }

    /// access(2), and the check for an open: whether `caller` has every
    /// right in `mask` (access(2)'s bits). With a `mask` of 0, only whether
    /// `ino` exists.
    ///
    /// - Any grant above `ino` allows read and search. A writable grant
    ///   allows write.
    /// - Writing a directory's contents is different from writing the
    ///   directory. `EISDIR` refuses the second only when `open` asks.
    /// - Nothing at a snapshot is writable (`EROFS`).
    pub async fn access(
        &self,
        caller: &Caller,
        ino: u64,
        mask: u32,
        at: Option<&[u8]>,
    ) -> Result<(), FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, mask & W != 0).await?;
        self.resolve(&view, ino).await.map(drop)
    }

    pub async fn readdir(
        &self,
        caller: &Caller,
        ino: u64,
        at: Option<&[u8]>,
    ) -> Result<Vec<DirItem>, FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, false).await?;
        let entry = self.resolve(&view, ino).await?;
        if entry.attr.kind != Kind::Directory {
            return Err(FsError::errno(libc::ENOTDIR));
        }

        let mut items = vec![
            DirItem {
                ino,
                kind: Kind::Directory,
                name: OsString::from("."),
                sealed_name: Vec::new(),
            },
            DirItem {
                ino: entry.parent,
                kind: Kind::Directory,
                name: OsString::from(".."),
                sealed_name: Vec::new(),
            },
        ];

        let prefix = dirent_prefix(ino);
        let mut keys = Vec::new();
        let mut iter = view.key_iterator(&prefix);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(&prefix) {
                break;
            }
            keys.push(key);
        }
        // An unlink or rmdir between the scan and this read is the only
        // cause of an empty value. Skip it.
        let dirents: Vec<(Vec<u8>, Vec<u8>)> = view
            .read_many(&keys)
            .await?
            .into_iter()
            .filter_map(|entry| Some((entry.key, entry.value?)))
            .collect();
        let children: Vec<u64> = dirents.iter().map(|(_, bytes)| dirent_ino(bytes)).collect();
        let attr_keys: Vec<Vec<u8>> = children.iter().map(|&child| attr_key(child)).collect();
        let entries = view.read_many(&attr_keys).await?;
        for (((key, bytes), child_ino), entry) in dirents.iter().zip(children).zip(entries) {
            let kind = live(child_ino, entry.value)
                .map(|e| e.attr.kind)
                .unwrap_or(Kind::File);
            items.push(DirItem {
                ino: child_ino,
                kind,
                name: OsStr::from_bytes(&key[prefix.len()..]).to_os_string(),
                sealed_name: dirent_sealed_name(bytes).to_vec(),
            });
        }
        Ok(items)
    }

    /// Applies `changes` (mode, size, and times; there are no owners) if
    /// `caller` has a writable grant above `ino`, including the data work
    /// that a size change needs. The client has already sealed again, cut
    /// short, the chunk that a new smaller size falls inside (see
    /// `write_chunks`), because the server cannot open it to cut it.
    pub async fn setattr(
        &self,
        caller: &Caller,
        ino: u64,
        changes: SetAttr,
    ) -> Result<Attr, FsError> {
        // Delete whole chunks past the new end first, before anything
        // records the smaller size. A crash here loses tail bytes that the
        // caller asked to remove. The other order would leave chunks past
        // EOF, which a later grow would bring back in place of zeros.
        if let Some(new_size) = changes.size {
            // Deleting chunks cannot be undone, and happens outside the
            // transaction below. So check the caller's right to truncate
            // before it, as well as in it.
            self.guard_now(&self.live(), caller, ino, true).await?;
            let layout = self.resolve(&self.live(), ino).await?.attr.layout;
            let first = new_size.div_ceil(self.chunk_size);
            // These chunks are gone, whatever the transaction below does.
            self.discard(self.delete_chunks_from(ino, first, layout).await?);
        }

        let attr = retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let Some(bytes) = txn.read_one(&attr_key(ino)).await?.value else {
                return Ok(Err(enoent()));
            };
            let mut entry = decode_entry(ino, &bytes);
            // A truncate rewrites the boundary chunk. It must not do that
            // to an inode whose deletion could already have removed it.
            if entry.is_deleted() {
                return Ok(Err(enoent()));
            }
            decide!(self.guard(&txn, caller, ino, true).await?);
            if let Some(mode) = changes.mode {
                entry.attr.perm = (mode & 0o7777) as u16;
            }
            if let Some(new_size) = changes.size {
                entry.attr.size = new_size;
                decide!(self.trim_block(&txn, &entry, new_size).await?);
            }
            if let Some(atime) = changes.atime {
                entry.attr.atime = atime.resolve();
            }
            if let Some(mtime) = changes.mtime {
                entry.attr.mtime = mtime.resolve();
            }
            entry.attr.ctime = SystemTime::now();

            txn.write(&attr_key(ino), Some(&encode_entry(&entry)))
                .await?;
            txn.commit().await?;
            Ok(Ok(entry.attr))
        })
        .await??;
        Ok(attr)
    }

    /// `name` is the new entry's tag, and `new` is the rest of what a
    /// create sends (see `NewNode`).
    pub async fn mkdir(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        self.create_child(caller, parent, name, Kind::Directory, perm, new)
            .await
    }

    /// Same as `mkdir`.
    pub async fn create(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        self.create_child(caller, parent, name, Kind::File, perm, new)
            .await
    }

    /// The inode number that `caller`'s next create uses, kept for them
    /// until then. A node's key record is bound to its inode, so the client
    /// needs the number before it can make the record.
    pub async fn reserve_inode(&self, caller: &Caller) -> Result<u64, FsError> {
        let user = caller.user.as_str();
        let ino = allocate_inode(&self.client).await?;
        let key = reservation_key(ino);
        let write = self.client.write(&key, Some(user.as_bytes()));
        timing::other("write", write).await?;
        Ok(ino)
    }

    /// Claims `name` in `parent` for `new`'s reserved inode, and writes the
    /// Entry, its key record, and the directory entry in one transaction.
    ///
    /// - Reading the name in that transaction makes the existence check
    ///   correct: two creates of one name at the same time cannot both find
    ///   it absent.
    /// - Reading the parent there too means that the grant check sees the
    ///   directory as it is at commit, and that a directory whose removal
    ///   has started takes no new entries.
    async fn create_child(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        kind: Kind,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        let ino = new.ino;
        Self::check_entry_name(name, &new.sealed_name)?;
        let dirent = &dirent_key(parent, name);
        let value = &dirent_value(ino, &new.sealed_name);

        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            decide!(self.guard(&txn, caller, parent, true).await?);
            // The new node's key and name are sealed under the parent's
            // key.
            decide!(self.fresh(&txn, parent).await?);
            let [dir, taken, record] = each(
                txn.read_many(&[attr_key(parent), dirent.to_vec(), node_keys_key(parent)])
                    .await?,
            );
            let mut dir = decide!(dir_entry(parent, dir.value));
            if taken.value.is_some() {
                return Ok(Err(FsError::errno(libc::EEXIST)));
            }
            let (parent_version, _) = decide!(versions_of(parent, record.value));
            decide!(check_name_version(parent, &new.sealed_name, parent_version));
            decide!(self.claim(&txn, caller, new, (1, parent_version)).await?);
            let now = SystemTime::now();
            let entry = Entry {
                attr: Attr {
                    ino,
                    kind,
                    size: 0,
                    perm: perm & 0o7777,
                    nlink: if kind == Kind::Directory { 2 } else { 1 },
                    atime: now,
                    mtime: now,
                    ctime: now,
                    // A file made through a server with object storage can
                    // grow into it. A file made without it never will.
                    layout: if kind == Kind::File && self.objects.is_some() {
                        Layout::Hybrid
                    } else {
                        Layout::Inline
                    },
                },
                // Files too: the walk up to a grant goes through the
                // parent, and a file's only parent is the one directory
                // that names it.
                parent,
            };
            write_entry(&txn, &entry).await?;
            txn.write(dirent, Some(value)).await?;
            touch_dir(&txn, &mut dir, now).await?;
            txn.commit().await?;
            Ok(Ok(entry.attr))
        })
        .await?
    }

    /// Uses `new`'s reserved inode for `caller` and stores its key record,
    /// which must have `versions`: version 1, under the parent's current
    /// key. Runs in the creating transaction.
    async fn claim(
        &self,
        txn: &Transaction,
        caller: &Caller,
        new: &NewNode,
        versions: (u32, u32),
    ) -> Result<Result<(), FsError>, KvError> {
        let user = caller.user.as_str();
        let [reserved, existing] = each(
            txn.read_many(&[reservation_key(new.ino), attr_key(new.ino)])
                .await?,
        );
        if reserved.value.as_deref() != Some(user.as_bytes()) {
            return Ok(Err(FsError::new(
                libc::EACCES,
                format!("inode {} isn't reserved for {user}", new.ino),
            )));
        }
        if existing.value.is_some() {
            return Ok(Err(FsError::errno(libc::EEXIST)));
        }
        match NodeKeys::versions(&new.keys) {
            Ok(found) if found == versions => {}
            // Most likely a client with an old version of the parent's key.
            // Fetching the key again fixes that.
            _ => {
                return Ok(Err(FsError::new(
                    raft5fs_proto::errno::EKEYEXPIRED,
                    format!(
                        "a new node's key record must be version {} under parent version {}",
                        versions.0, versions.1
                    ),
                )));
            }
        }
        txn.write(&reservation_key(new.ino), None).await?;
        txn.write(&node_keys_key(new.ino), Some(&new.keys)).await?;
        Ok(Ok(()))
    }

    /// Removes a file and returns its inode.
    pub async fn unlink(&self, caller: &Caller, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let child = self.child_ino(&self.live(), parent, name).await?;
        self.remove_child(caller, parent, name, child, Kind::File, parent)
            .await?;
        Ok(child)
    }

    /// Removes an empty directory and returns its inode.
    pub async fn rmdir(&self, caller: &Caller, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let child = self.child_ino(&self.live(), parent, name).await?;
        self.remove_child(caller, parent, name, child, Kind::Directory, parent)
            .await?;
        Ok(child)
    }

    /// Unlinks `name` from `parent` and removes the inode it named, if
    /// `caller` is allowed. The inode must be of `kind`, and a directory
    /// must be empty.
    ///
    /// It takes several steps, because an inode's chunks might not fit in
    /// one transaction:
    ///
    /// - One transaction checks the caller's rights on `guarded`, removes
    ///   the dirent, marks the Entry deleted, and records a tombstone. It
    ///   reads the dirent again, so it removes `ino` only if the name still
    ///   means `ino`. After this, no write from any process can add a chunk
    ///   (see `write_chunks`), and no create can add an entry to a removed
    ///   directory.
    /// - `finish_removal` then deletes the chunks, the Entry, and the
    ///   tombstone.
    /// - If a crash happens between the two, the tombstone stays, and
    ///   `reap_tombstones` finishes the work.
    ///
    /// The caller needs a writable grant above `guarded`: the parent, or
    /// for a volume the volume itself, because its parent (the real root)
    /// belongs to no one.
    async fn remove_child(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        ino: u64,
        kind: Kind,
        guarded: u64,
    ) -> Result<(), FsError> {
        let dirent = &dirent_key(parent, name);
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            decide!(self.guard(&txn, caller, guarded, true).await?);
            let mut dir = decide!(modifiable_dir(&txn, parent).await?);
            if named(&txn, dirent).await? != Some(ino) {
                return Ok(Err(enoent()));
            }
            let mut entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, kind));
            let now = SystemTime::now();
            entry.mark_deleted();
            entry.attr.ctime = now;
            // Write this before the emptiness check, which needs it. If the
            // check fails, dropping the transaction undoes it.
            write_entry(&txn, &entry).await?;
            if kind == Kind::Directory && !is_empty_dir(&txn, ino).await? {
                return Ok(Err(FsError::errno(libc::ENOTEMPTY)));
            }
            txn.write(dirent, None).await?;
            txn.write(&tombstone_key(ino), Some(&[1])).await?;
            touch_dir(&txn, &mut dir, now).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await??;
        self.finish_removal(ino).await
    }

    /// Moves `name` in `parent` to `new_name` in `new_parent`, and replaces
    /// what `new_name` named unless `noreplace`. Returns the replaced
    /// inode, if any.
    ///
    /// - It is one transaction, so the name is never missing and never in
    ///   both places.
    /// - Data does not move: chunks are keyed by inode, not by name, so the
    ///   file's size does not matter.
    /// - A replaced inode is removed as `unlink` removes one, starting with
    ///   a tombstone in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn rename(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
        sealed: &SealedMove,
    ) -> Result<Option<u64>, FsError> {
        Self::check_entry_name(new_name, &sealed.sealed_name)?;
        let from = &dirent_key(parent, name);
        let to = &dirent_key(new_parent, new_name);
        let replaced = retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            decide!(self.guard(&txn, caller, parent, true).await?);
            if new_parent != parent {
                decide!(self.guard(&txn, caller, new_parent, true).await?);
            }
            // Read both directories and both names in one read, then both
            // inodes they name in another. Check them in the order of a
            // one-at-a-time read.
            let moves = new_parent != parent;
            let mut keys = vec![attr_key(parent), from.to_vec(), to.to_vec()];
            if moves {
                keys.push(attr_key(new_parent));
            }
            let mut found = txn.read_many(&keys).await?.into_iter().map(|e| e.value);
            let mut next = move || found.next().expect("a read of every key answers each");
            let (src_dir, from_value, to_value) = (next(), next(), next());
            let mut src_dir = decide!(dir_entry(parent, src_dir));
            let mut dst_dir = if moves {
                Some(decide!(dir_entry(new_parent, next())))
            } else {
                None
            };

            let Some(ino) = from_value.map(|b| dirent_ino(&b)) else {
                return Ok(Err(enoent()));
            };
            let target = to_value.map(|b| dirent_ino(&b));
            let victim_ino = target.filter(|&victim| victim != ino);
            let mut keys = vec![attr_key(ino)];
            keys.extend(victim_ino.map(attr_key));
            let mut found = txn.read_many(&keys).await?.into_iter().map(|e| e.value);
            let mut next = move || found.next().expect("a read of every key answers each");
            let mut moved = decide!(live(ino, next()).ok_or_else(enoent));
            if target == Some(ino) {
                // Two names for one inode: POSIX says to do nothing. With
                // no hard links, only `rename(a, a)` gets here.
                return Ok(Ok(None));
            }

            let now = SystemTime::now();
            if let Some(victim_ino) = victim_ino {
                if noreplace {
                    return Ok(Err(FsError::errno(libc::EEXIST)));
                }
                let mut victim = decide!(live(victim_ino, next()).ok_or_else(enoent));
                decide!(check_kind(&victim, moved.attr.kind));
                victim.mark_deleted();
                victim.attr.ctime = now;
                write_entry(&txn, &victim).await?;
                if victim.attr.kind == Kind::Directory && !is_empty_dir(&txn, victim_ino).await? {
                    return Ok(Err(FsError::errno(libc::ENOTEMPTY)));
                }
                txn.write(&tombstone_key(victim_ino), Some(&[1])).await?;
            }

            // The sealed name and key record are for one inode, which must
            // be the inode that moves.
            if sealed.ino != ino {
                return Ok(Err(FsError::new(
                    libc::ESTALE,
                    "the name moved meanwhile names another inode now",
                )));
            }
            // Its name is sealed under the new parent's key, and a stale
            // node must not look fresh after the move.
            decide!(self.fresh(&txn, new_parent).await?);
            decide!(self.fresh(&txn, ino).await?);
            let mut records = vec![node_keys_key(new_parent)];
            if moves {
                records.push(node_keys_key(ino));
            }
            let mut records = txn.get_many(&records).await?.into_iter();
            let (dst_version, _) = decide!(versions_of(new_parent, records.next().flatten()));
            decide!(check_name_version(
                new_parent,
                &sealed.sealed_name,
                dst_version
            ));
            if moves {
                // Its key moves with it, wrapped again under the new
                // parent's key.
                let keys = &sealed.node_keys;
                let (version, _) = decide!(versions_of(ino, records.next().flatten()));
                if NodeKeys::versions(keys).ok() != Some((version, dst_version)) {
                    return Ok(Err(FsError::new(
                        raft5fs_proto::errno::EKEYEXPIRED,
                        "the moved node's key record must keep its version, under the new parent's",
                    )));
                }
                txn.write(&node_keys_key(ino), Some(keys)).await?;
            }
            if moved.attr.kind == Kind::Directory && new_parent != parent {
                // A directory cannot move below itself, so walk up from the
                // destination. The walk reads every ancestor, so a rename
                // at the same time that would close a loop the other way
                // (and writes one of them) conflicts with this one and
                // cannot get past it.
                let mut cur = new_parent;
                while cur != ROOT_INO {
                    if cur == ino {
                        return Ok(Err(FsError::errno(libc::EINVAL)));
                    }
                    cur = decide!(live_entry(&txn, cur).await?).parent;
                }
            }
            if new_parent != parent {
                // A file's parent too: see `create_child`.
                moved.parent = new_parent;
            }
            moved.attr.ctime = now;
            write_entry(&txn, &moved).await?;
            txn.write(from, None).await?;
            txn.write(to, Some(&dirent_value(ino, &sealed.sealed_name)))
                .await?;
            touch_dir(&txn, &mut src_dir, now).await?;
            if let Some(dst_dir) = &mut dst_dir {
                touch_dir(&txn, dst_dir, now).await?;
            }
            txn.commit().await?;
            Ok(Ok(target))
        })
        .await??;

        if let Some(victim) = replaced {
            // The rename is done, whatever this returns. A failure here
            // leaves the tombstone, and a later start finishes it.
            if let Err(e) = self.finish_removal(victim).await {
                eprintln!("could not finish removing inode {victim}, replaced by a rename: {e}");
            }
        }
        Ok(replaced)
    }

    /// Reads up to one write batch of `ino`'s sealed chunks from `first`,
    /// with the file's attributes. It returns fewer than `count` if `count`
    /// is more than a batch. Each chunk comes with the store's sequence
    /// number for it.
    ///
    /// - `known[i]`, if present and not 0, is the seq at which the client
    ///   already has chunk `first + i` (decrypted, in its cache). A chunk
    ///   still at that seq comes back `unchanged`, without its bytes. Only
    ///   its version is read, which costs eight bytes whatever the chunk's
    ///   size.
    /// - `objects_ok` says that the client can fetch from object storage.
    ///   If not, a chunk there gives `ENOTSUP`. Otherwise a client that
    ///   cannot read the pointer would take it for a hole and see zeros.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_chunks(
        &self,
        caller: &Caller,
        ino: u64,
        first: u64,
        count: u32,
        known: &[u64],
        objects_ok: bool,
        at: Option<&[u8]>,
    ) -> Result<Chunks, FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, false).await?;
        let attr = self.resolve(&view, ino).await?.attr;
        let grid = match attr.layout {
            Layout::Inline => None,
            Layout::Hybrid => Some(self.grid.ok_or_else(|| {
                FsError::new(
                    libc::EIO,
                    format!("inode {ino} is hybrid, but no object grid is recorded"),
                )
            })?),
        };
        // A block's chunks cost one read and one pointer, so a read in
        // blocks can cover a whole block.
        let mut cap = chunks_per_batch(self.chunk_size) as u64;
        if let Some(g) = grid.filter(|g| g.in_blocks(first)) {
            cap = cap.max(u64::from(g.per_block));
        }
        let count = u64::from(count).min(cap);

        // Each chunk is stored at its own index, or in a block at the
        // block's start: one key for a run of consecutive chunks. A run
        // holds each chunk's index and the seq the client has it at.
        let mut runs: Vec<(u64, Vec<(u64, u64)>)> = Vec::new();
        for (i, index) in (first..first.saturating_add(count)).enumerate() {
            let stored = grid
                .filter(|g| g.in_blocks(index))
                .map_or(index, |g| g.block_start(index));
            let held = known.get(i).copied().unwrap_or(0);
            match runs.last_mut() {
                Some((at, chunks)) if *at == stored => chunks.push((index, held)),
                _ => runs.push((stored, vec![(index, held)])),
            }
        }
        // If the client has every chunk of a run, the key's seq alone shows
        // whether they are still current. That costs eight bytes whatever
        // the value's size, and all of those are read in one read.
        let held_runs: Vec<usize> = (0..runs.len())
            .filter(|&r| runs[r].1.iter().all(|&(_, held)| held != 0))
            .collect();
        let held_keys: Vec<Vec<u8>> = held_runs
            .iter()
            .map(|&r| chunk_key(ino, runs[r].0))
            .collect();
        let mut current: Vec<Option<u64>> = vec![None; runs.len()];
        for (&r, seq) in held_runs
            .iter()
            .zip(view.read_versions_many(&held_keys).await?)
        {
            if runs[r].1.iter().all(|&(_, held)| held == seq) {
                current[r] = Some(seq);
            }
        }
        // Every other run's value, in one read.
        let fetched_runs: Vec<usize> = (0..runs.len()).filter(|&r| current[r].is_none()).collect();
        let fetched_keys: Vec<Vec<u8>> = fetched_runs
            .iter()
            .map(|&r| chunk_key(ino, runs[r].0))
            .collect();
        let mut fetched: Vec<Option<raft5_client::Entry>> = vec![None; runs.len()];
        for (&r, entry) in fetched_runs
            .iter()
            .zip(view.read_many(&fetched_keys).await?)
        {
            fetched[r] = Some(entry);
        }

        let unchanged = |index, seq| SealedChunk {
            index,
            seq,
            body: ChunkBody::Hole,
            unchanged: true,
        };
        let mut chunks = Vec::with_capacity(count as usize);
        let mut blocks = Vec::new();
        for ((stored, run), (current, read)) in
            runs.into_iter().zip(current.into_iter().zip(fetched))
        {
            if let Some(seq) = current {
                chunks.extend(run.into_iter().map(|(index, _)| unchanged(index, seq)));
                continue;
            }
            let read = read.expect("every run not current was read");
            let is_current = |held: u64| held != 0 && held == read.seq;
            if !grid.is_some_and(|g| g.in_blocks(stored)) {
                // An inline chunk has its own key, so its run has one
                // chunk.
                let (index, held) = run[0];
                if is_current(held) {
                    chunks.push(unchanged(index, held));
                    continue;
                }
                let body = match read.value.map(ChunkValue::decode) {
                    None => ChunkBody::Hole,
                    Some(ChunkValue::Inline(blob)) => ChunkBody::Inline(blob),
                    Some(ChunkValue::Block(_)) => {
                        return Err(FsError::new(
                            libc::EIO,
                            format!("inode {ino}: a block pointer where chunk {index} belongs"),
                        ));
                    }
                };
                chunks.push(SealedChunk {
                    index,
                    seq: read.seq,
                    body,
                    unchanged: false,
                });
                continue;
            }
            let block = match read.value.map(ChunkValue::decode) {
                None => None,
                Some(ChunkValue::Block(block)) => {
                    let url = self.read_url(ino, &block, objects_ok)?;
                    blocks.push(BlockUrl { block, url });
                    Some((blocks.len() as u32 - 1, block.nseg))
                }
                Some(ChunkValue::Inline(_)) => {
                    return Err(FsError::new(
                        libc::EIO,
                        format!("inode {ino}: a sealed chunk where block {stored} belongs"),
                    ));
                }
            };
            for (index, held) in run {
                if is_current(held) {
                    chunks.push(unchanged(index, held));
                    continue;
                }
                let segment = (index - stored) as u32;
                let body = match block {
                    Some((block, nseg)) if segment < nseg => ChunkBody::Segment { block, segment },
                    _ => ChunkBody::Hole,
                };
                chunks.push(SealedChunk {
                    index,
                    seq: read.seq,
                    body,
                    unchanged: false,
                });
            }
        }
        Ok(Chunks {
            attr,
            chunks,
            blocks,
        })
    }

    /// A presigned URL that reads `block` of `ino`, for a client that can
    /// read object storage (`objects_ok`). If it cannot, returns `ENOTSUP`.
    /// Otherwise a client that cannot read the pointer would take it for a
    /// hole and see zeros.
    fn read_url(&self, ino: u64, block: &BlockRef, objects_ok: bool) -> Result<String, FsError> {
        if !objects_ok {
            return Err(FsError::new(
                libc::ENOTSUP,
                format!("inode {ino} keeps data in object storage, which this client can't read"),
            ));
        }
        let Some(objects) = &self.objects else {
            return Err(FsError::new(
                libc::EIO,
                format!("inode {ino} keeps data in object storage, which this server can't reach"),
            ));
        };
        Ok(objects
            .store
            .presign_get(&object_name(ino, block), objects.get_ttl))
    }

    /// Names and presigned upload URLs for new blocks of file `ino`, one
    /// for each block asked for, each for exactly the length of its
    /// segments. Needs a writable grant above `ino`, which must be a hybrid
    /// file. Each block must start where the grid says a block starts.
    /// Minting stores nothing: garbage collection removes an upload that
    /// nothing commits.
    pub async fn prepare_uploads(
        &self,
        caller: &Caller,
        ino: u64,
        blocks: &[BlockUpload],
    ) -> Result<Vec<PreparedUpload>, FsError> {
        let (Some(objects), Some(grid)) = (&self.objects, self.grid) else {
            return Err(no_objects());
        };
        if blocks.len() > MAX_UPLOADS {
            return Err(FsError::new(
                libc::EINVAL,
                format!("at most {MAX_UPLOADS} blocks at a time"),
            ));
        }
        let live = self.live();
        self.guard_now(&live, caller, ino, true).await?;
        let entry = self.resolve(&live, ino).await?;
        check_kind(&entry, Kind::File)?;
        if entry.attr.layout != Layout::Hybrid {
            return Err(FsError::new(
                libc::EINVAL,
                format!("inode {ino} keeps nothing in object storage"),
            ));
        }
        let now = SystemTime::now();
        blocks
            .iter()
            .map(|b| {
                if !grid.in_blocks(b.index) || grid.block_start(b.index) != b.index {
                    return Err(FsError::new(
                        libc::EINVAL,
                        format!("no block starts at chunk {}", b.index),
                    ));
                }
                if b.nseg == 0 || b.nseg > grid.per_block {
                    return Err(FsError::new(
                        libc::EINVAL,
                        format!(
                            "a block holds 1 to {} segments, not {}",
                            grid.per_block, b.nseg
                        ),
                    ));
                }
                let name = ObjectName::mint(ino, now);
                let len = u64::from(b.nseg) * segment_len(self.chunk_size);
                Ok(PreparedUpload {
                    minted_ms: name.minted_ms,
                    random: name.random,
                    url: objects.store.presign_put(&name, len, objects.put_ttl),
                })
            })
            .collect()
    }

    /// For a truncate to `new_size`, the block that the new end falls in
    /// keeps only the segments before the end. `delete_chunks_from` already
    /// removed whole blocks past the end. This block stays, but its later
    /// segments must read as zeros if the file grows again, and must not
    /// come back. The pointer is plaintext, so this only lowers `nseg`: no
    /// keys and no upload. The client has already rewritten a segment that
    /// the end cuts part way through.
    async fn trim_block(
        &self,
        txn: &Transaction,
        entry: &Entry,
        new_size: u64,
    ) -> Result<Result<(), FsError>, KvError> {
        let Some(grid) = self.grid.filter(|_| entry.attr.layout == Layout::Hybrid) else {
            return Ok(Ok(()));
        };
        // The first chunk that is completely past the new end.
        let cut = new_size.div_ceil(self.chunk_size);
        if cut == 0 || !grid.in_blocks(cut - 1) {
            return Ok(Ok(()));
        }
        let start = grid.block_start(cut - 1);
        let key = chunk_key(entry.attr.ino, start);
        let Some(value) = txn.read_one(&key).await?.value else {
            return Ok(Ok(()));
        };
        if let ChunkValue::Block(mut block) = ChunkValue::decode(value) {
            let keep = (cut - start) as u32;
            if block.nseg > keep {
                block.nseg = keep;
                txn.write(&key, Some(&encode_pointer(&block))).await?;
            }
        }
        Ok(Ok(()))
    }

    /// Stores sealed chunks of `ino` and grows the file to `end`.
    ///
    /// - If any chunk is not at its `expected_seq`, nothing is stored
    ///   (`EAGAIN`).
    /// - Each chunk must be sealed under the file's current key version
    ///   (`EKEYEXPIRED` if not, so the client fetches the key again).
    ///
    /// Returns the file's attributes, and the seq of every chunk written,
    /// so the client can cache what it wrote.
    pub async fn write_chunks(
        &self,
        caller: &Caller,
        ino: u64,
        writes: &[ChunkWrite],
        end: u64,
    ) -> Result<(Attr, u64), FsError> {
        self.check_chunk_writes(writes)?;
        let (attr, dropped) = retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            decide!(self.guard(&txn, caller, ino, true).await?);
            decide!(self.fresh(&txn, ino).await?);
            // Read the Entry first. This is required: a deletion marks the
            // Entry before it removes the chunks, in a transaction that
            // conflicts with this one on the Entry. So no chunk is stored
            // after the deletion's scan has passed it. The Entry is removed
            // last, so no chunk is stored for an inode that nothing can
            // reach.
            let mut entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, Kind::File));
            let dropped = decide!(put_chunks(self, &txn, &entry, writes, false).await?);
            if end > entry.attr.size {
                entry.attr.size = end;
            }
            let now = SystemTime::now();
            entry.attr.mtime = now;
            entry.attr.ctime = now;
            write_entry(&txn, &entry).await?;
            let seq = txn.commit().await?;
            Ok(Ok(((entry.attr, seq), dropped)))
        })
        .await??;
        self.discard(dropped);
        Ok(attr)
    }

    /// `caller`'s grant above `ino`, and the key records down to it (see
    /// `grants::key_path`), at snapshot `at` if one is given.
    pub async fn key_path(
        &self,
        caller: &Caller,
        ino: u64,
        at: Option<&[u8]>,
    ) -> Result<KeyPath, FsError> {
        let view = self.view(at).await?;
        grants::key_path(&view, &self.paths, &caller.user, ino).await
    }

    /// Every grant made to `caller`, as of snapshot `at` if one is given.
    pub async fn grants(&self, caller: &Caller, at: Option<&[u8]>) -> Result<Vec<Grant>, FsError> {
        let view = self.view(at).await?;
        grants::list(&view, &caller.user).await
    }

    /// Every snapshot, oldest first.
    pub async fn snapshots(&self) -> Result<Vec<raft5fs_proto::types::SnapshotInfo>, FsError> {
        snapshots::list(&self.client).await
    }

    /// `user`'s public key, for sealing grants to them. Returns `ENOENT`
    /// for an account that has not enrolled.
    pub async fn public_key(&self, user: &str) -> Result<Vec<u8>, FsError> {
        crate::accounts::get(&self.client, user)
            .await?
            .map(|keys| keys.public_key)
            .ok_or_else(|| FsError::new(libc::ENOENT, format!("{user} hasn't enrolled")))
    }

    /// Grants directory `grant.ino` to `grantee`, and replaces any grant of
    /// it that they had.
    ///
    /// - `caller` needs a writable grant above it, and the grant must hold
    ///   its current key version.
    /// - `sealed_grantees` is the node's grantee list with this grant
    ///   added, sealed under its current key version. It replaces the
    ///   stored list if that list is still at `expected_grantees_seq`, the
    ///   seq of the list it was made from. If not, returns `EAGAIN`,
    ///   because a grant made in the meantime would be lost from it.
    pub async fn grant(
        &self,
        caller: &Caller,
        grantee: &str,
        grant: &Grant,
        sealed_grantees: &[u8],
        expected_grantees_seq: u64,
    ) -> Result<(), FsError> {
        grants::check_username(grantee)?;
        let ino = grant.ino;
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            decide!(self.guard(&txn, caller, ino, true).await?);
            // A revoked user may still have a stale key.
            decide!(self.fresh(&txn, ino).await?);
            let entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, Kind::Directory));
            if txn
                .read_one(&crate::accounts::keys_key(grantee))
                .await?
                .value
                .is_none()
            {
                return Ok(Err(FsError::new(
                    libc::ENOENT,
                    format!("{grantee} hasn't enrolled"),
                )));
            }
            decide!(
                crate::accounts::check_link_grant(&txn, &caller.user, grantee, ino, grant.writable)
                    .await?
            );
            let (version, _) = decide!(key_versions(&txn, ino).await?);
            if grant.key_version != version {
                return Ok(Err(FsError::new(
                    raft5fs_proto::errno::EKEYEXPIRED,
                    format!("a grant must hold the current key version, {version}"),
                )));
            }
            decide!(check_grantees_version(ino, sealed_grantees, version));
            if txn.read_one(&grantees_key(ino)).await?.seq != expected_grantees_seq {
                return Ok(Err(FsError::new(
                    libc::EAGAIN,
                    format!("inode {ino}'s grantee list changed meanwhile"),
                )));
            }
            grants::put_grant(&txn, grantee, grant).await?;
            txn.write(&grantees_key(ino), Some(sealed_grantees)).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Makes a new volume: a directory under the real root, at `new`'s
    /// reserved inode, granted read-write to `caller` with `sealed_key`
    /// (its key, version 1) and `sealed_label`. Its name is its inode
    /// number. The name people use is only in the grants, where the server
    /// cannot read it. Needs the `volumes` capability (`EACCES`).
    pub async fn create_volume(
        &self,
        caller: &Caller,
        new: &NewNode,
        perm: u16,
        sealed_key: &[u8],
        sealed_label: &[u8],
        sealed_grantees: &[u8],
    ) -> Result<Attr, FsError> {
        let user = caller.user.as_str();
        // Read outside the transaction: it changes rarely, and only by an
        // administrator.
        if !crate::accounts::info(&self.client, user)
            .await?
            .caps
            .contains(raft5fs_proto::types::Caps::VOLUMES)
        {
            return Err(FsError::new(
                libc::EACCES,
                "you can't create volumes on this filesystem",
            ));
        }
        check_grantees_version(new.ino, sealed_grantees, 1)?;
        let dirent = &dirent_key(ROOT_INO, OsStr::new(&new.ino.to_string()));
        let grant = &Grant {
            ino: new.ino,
            writable: true,
            key_version: 1,
            sealed_key: sealed_key.to_vec(),
            sealed_label: sealed_label.to_vec(),
        };
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let mut root = decide!(live_entry(&txn, ROOT_INO).await?);
            if txn.read_one(dirent).await?.value.is_some() {
                return Ok(Err(FsError::errno(libc::EEXIST)));
            }
            // No parent key: only grants give a volume's key to users.
            decide!(self.claim(&txn, caller, new, (1, 0)).await?);
            let now = SystemTime::now();
            let entry = Entry {
                attr: Attr {
                    ino: new.ino,
                    kind: Kind::Directory,
                    size: 0,
                    perm: perm & 0o7777,
                    nlink: 2,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    layout: Layout::Inline,
                },
                parent: ROOT_INO,
            };
            write_entry(&txn, &entry).await?;
            txn.write(dirent, Some(&dirent_value(new.ino, &[]))).await?;
            grants::put_grant(&txn, user, grant).await?;
            txn.write(&grantees_key(new.ino), Some(sealed_grantees))
                .await?;
            touch_dir(&txn, &mut root, now).await?;
            txn.commit().await?;
            Ok(Ok(entry.attr))
        })
        .await?
    }

    /// Every node at or below `top` that is granted to anyone (see
    /// `grants::grants_under`). Needs a writable grant above `top`, because
    /// a rotation of `top`'s key needs this.
    pub async fn grants_under(
        &self,
        caller: &Caller,
        top: u64,
    ) -> Result<Vec<GrantedNode>, FsError> {
        self.guard_now(&self.live(), caller, top, true).await?;
        grants::grants_under(&self.client, top).await
    }

    /// Gives each node in `rotations` (parents before children) a new key,
    /// in one transaction:
    ///
    /// - its record one version higher, wrapped under its parent's key as
    ///   it is now, or as this transaction leaves it;
    /// - every grant of it sealed again, or (sealed empty) removed.
    ///
    /// Returns `EAGAIN` if a node is no longer at its expected version, or
    /// its grants are not the grants that the rotation seals again: another
    /// client changed it in the meantime.
    pub async fn rotate(&self, caller: &Caller, rotations: &[Rotation]) -> Result<(), FsError> {
        let changed = |what: String| Ok(Err(FsError::new(libc::EAGAIN, what)));
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            // Versions that this transaction has changed, for the children
            // that are rotated after their parents.
            let mut rotated: HashMap<u64, u32> = HashMap::new();
            for r in rotations {
                let ino = r.ino;
                decide!(self.guard(&txn, caller, ino, true).await?);
                let [entry, record] =
                    each(txn.read_many(&[attr_key(ino), node_keys_key(ino)]).await?);
                let entry = decide!(live(ino, entry.value).ok_or_else(enoent));
                let (version, wrapped_under) = decide!(versions_of(ino, record.value));
                if version != r.expected_version {
                    return changed(format!("inode {ino} has key version {version} now"));
                }
                let Ok((new_version, new_wrapped_under)) = NodeKeys::versions(&r.node_keys) else {
                    return Ok(Err(FsError::new(libc::EINVAL, "an unreadable key record")));
                };
                let parent_version = if wrapped_under == 0 {
                    0
                } else if let Some(&v) = rotated.get(&entry.parent) {
                    v
                } else {
                    decide!(key_versions(&txn, entry.parent).await?).0
                };
                if new_version != version + 1 {
                    return Ok(Err(FsError::new(
                        libc::EINVAL,
                        format!("inode {ino}'s new key record must be version {}", version + 1),
                    )));
                }
                if new_wrapped_under != parent_version {
                    return changed(format!(
                        "inode {ino}'s new key must be wrapped under its parent's version {parent_version}"
                    ));
                }
                let existing = grants::grants_of(&txn, ino).await?;
                let resealed: HashMap<&str, &[u8]> = r
                    .grants
                    .iter()
                    .map(|(user, sealed)| (user.as_str(), sealed.as_slice()))
                    .collect();
                if resealed.len() != existing.len()
                    || !existing.keys().all(|user| resealed.contains_key(user.as_str()))
                {
                    return changed(format!("inode {ino}'s grants aren't the ones re-sealed"));
                }
                let mut kept = 0;
                for (user, mut grant) in existing {
                    let sealed = resealed[user.as_str()];
                    if sealed.is_empty() {
                        grants::remove_grant(&txn, &user, ino).await?;
                    } else {
                        grant.key_version = new_version;
                        grant.sealed_key = sealed.to_vec();
                        grants::put_grant(&txn, &user, &grant).await?;
                        kept += 1;
                    }
                }
                // The remaining grantees, listed again under the new key.
                if kept > 0 {
                    decide!(check_grantees_version(ino, &r.sealed_grantees, new_version));
                    txn.write(&grantees_key(ino), Some(&r.sealed_grantees))
                        .await?;
                } else {
                    txn.write(&grantees_key(ino), None).await?;
                }
                txn.write(&node_keys_key(ino), Some(&r.node_keys)).await?;
                rotated.insert(ino, new_version);
            }
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Seals chunks of file `ino` again under its current key version. Each
    /// chunk must still be at its `expected_seq`, which is required. The
    /// file's size and times do not change. A prune needs this first. Needs
    /// a writable grant above `ino`, with fresh keys.
    pub async fn reseal_chunks(
        &self,
        caller: &Caller,
        ino: u64,
        writes: &[ChunkWrite],
    ) -> Result<(), FsError> {
        self.check_chunk_writes(writes)?;
        if writes.iter().any(|w| w.expected_seq.is_none()) {
            return Err(FsError::new(
                libc::EINVAL,
                "a re-sealed chunk must say the seq it was read at",
            ));
        }
        let dropped = retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            decide!(self.guard(&txn, caller, ino, true).await?);
            decide!(self.fresh(&txn, ino).await?);
            // As in `write_chunks`, read the Entry first, so no chunk is
            // stored after a deletion has started.
            let entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, Kind::File));
            let dropped = decide!(put_chunks(self, &txn, &entry, writes, true).await?);
            txn.commit().await?;
            Ok(Ok(dropped))
        })
        .await??;
        self.discard(dropped);
        Ok(())
    }

    /// Seals entry names in directory `dir` again under its current key
    /// version, each only if its tag still names the same inode. The
    /// directory's times do not change. Needs a writable grant above `dir`,
    /// with fresh keys.
    pub async fn reseal_names(
        &self,
        caller: &Caller,
        dir: u64,
        names: &[ResealedName],
    ) -> Result<(), FsError> {
        if names.len() > RESEAL_NAMES_BATCH {
            return Err(FsError::new(
                libc::EINVAL,
                "more names than one re-seal takes",
            ));
        }
        for n in names {
            Self::check_entry_name(&n.tag, &n.sealed_name)?;
        }
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            decide!(self.guard(&txn, caller, dir, true).await?);
            decide!(self.fresh(&txn, dir).await?);
            decide!(modifiable_dir(&txn, dir).await?);
            let (version, _) = decide!(key_versions(&txn, dir).await?);
            for n in names {
                decide!(check_name_version(dir, &n.sealed_name, version));
                let dirent = dirent_key(dir, &n.tag);
                if named(&txn, &dirent).await? != Some(n.ino) {
                    return Ok(Err(FsError::new(
                        libc::EAGAIN,
                        format!("an entry of inode {dir} changed meanwhile"),
                    )));
                }
                txn.write(&dirent, Some(&dirent_value(n.ino, &n.sealed_name)))
                    .await?;
            }
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Replaces `ino`'s key record, at `expected_version`, with
    /// `node_keys`: the same record with only its oldest history entries
    /// removed. Returns `EBUSY` while anything is still sealed under a
    /// version that it removes. Needs a writable grant above `ino`.
    ///
    /// The search for data under an old version runs outside any
    /// transaction. The record is then replaced only if it is still the
    /// record that the search started from. That is enough: while the
    /// record stays the same, everything the server takes in for `ino`
    /// (chunks, entry names, children's keys, grants) is checked against
    /// the current version in the transaction that stores it, and the prune
    /// keeps that version. So nothing under a removed version can appear
    /// after the search.
    pub async fn prune_keys(
        &self,
        caller: &Caller,
        ino: u64,
        expected_version: u32,
        node_keys: &[u8],
    ) -> Result<(), FsError> {
        self.guard_now(&self.live(), caller, ino, true).await?;
        let pruned = NodeKeys::decode(node_keys)
            .map_err(|e| FsError::new(libc::EINVAL, format!("inode {ino}: {e}")))?;
        let before_bytes = self
            .client
            .read_one(&node_keys_key(ino))
            .await?
            .value
            .ok_or_else(|| FsError::new(libc::EIO, format!("inode {ino} has no key record")))?;
        let before = NodeKeys::decode(&before_bytes)
            .map_err(|e| FsError::new(libc::EIO, format!("inode {ino}: {e}")))?;
        if before.version != expected_version {
            return Err(FsError::new(
                libc::EAGAIN,
                format!("inode {ino} has key version {} now", before.version),
            ));
        }
        if !pruned.is_pruning_of(&before) {
            return Err(FsError::new(
                libc::EINVAL,
                format!("inode {ino}'s new key record isn't its old one cut short"),
            ));
        }
        if pruned.base() == before.base() {
            return Ok(());
        }
        if let Some(what) = self.sealed_below(ino, pruned.base()).await? {
            return Err(FsError::new(
                libc::EBUSY,
                format!(
                    "{what} of inode {ino} is still sealed under a key version before {}",
                    pruned.base()
                ),
            ));
        }
        let before_bytes = &before_bytes;
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            if txn.read_one(&node_keys_key(ino)).await?.value.as_ref() != Some(before_bytes) {
                return Ok(Err(FsError::new(
                    libc::EAGAIN,
                    format!("inode {ino}'s key record changed meanwhile"),
                )));
            }
            txn.write(&node_keys_key(ino), Some(node_keys)).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Describes the first thing found that is sealed under a version of
    /// `ino`'s key before `base`: a chunk, an entry's name, a child's key,
    /// or a grant. Returns `None` if there is none.
    async fn sealed_below(&self, ino: u64, base: u32) -> Result<Option<String>, FsError> {
        let below = |blob: &[u8]| sealed_version(blob).is_ok_and(|v| v < base);
        let kind = self.resolve(&self.live(), ino).await?.attr.kind;
        if kind == Kind::File {
            let prefix = chunk_prefix(ino);
            let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
            let mut window = Vec::new();
            loop {
                let key = next_key(&mut iter)
                    .await?
                    .filter(|key| key.starts_with(&prefix));
                if let Some(key) = &key
                    && is_chunk_key(key, &prefix)
                {
                    window.push(key.clone());
                }
                if window.len() < MAX_KEYS_PER_READ && key.is_some() {
                    continue;
                }
                // Check each answer as it arrives, not a whole window of
                // chunks at once.
                let mut checked = 0;
                while checked < window.len() {
                    let entries = self.client.read_some(&window[checked..]).await?;
                    checked += entries.len();
                    for entry in entries {
                        if entry.value.as_deref().is_some_and(below) {
                            let index =
                                u64::from_be_bytes(entry.key[prefix.len()..].try_into().unwrap());
                            return Ok(Some(format!("chunk {index}")));
                        }
                    }
                }
                window.clear();
                if key.is_none() {
                    break;
                }
            }
        } else {
            let prefix = dirent_prefix(ino);
            let mut keys = Vec::new();
            let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
            while let Some(key) = next_key(&mut iter).await? {
                if !key.starts_with(&prefix) {
                    break;
                }
                keys.push(key);
            }
            let dirents: Vec<Vec<u8>> = self
                .client
                .get_many(&keys)
                .await?
                .into_iter()
                .flatten()
                .collect();
            let records: Vec<Vec<u8>> = dirents
                .iter()
                .map(|value| node_keys_key(dirent_ino(value)))
                .collect();
            let records = self.client.get_many(&records).await?;
            for (value, record) in dirents.iter().zip(records) {
                let child = dirent_ino(value);
                if below(dirent_sealed_name(value)) {
                    return Ok(Some(format!("the name of entry {child}")));
                }
                if let Ok((_, parent_version)) = versions_of(child, record)
                    && parent_version != 0
                    && parent_version < base
                {
                    return Ok(Some(format!("the key of child {child}")));
                }
            }
        }
        if let Some(sealed) = self.client.read_one(&grantees_key(ino)).await?.value
            && below(&sealed)
        {
            return Ok(Some("the grantee list".to_string()));
        }
        let prefix = grants::grant_prefix(ino);
        let mut keys = Vec::new();
        let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(&prefix) {
                break;
            }
            keys.push(key);
        }
        for (key, bytes) in keys.iter().zip(self.client.get_many(&keys).await?) {
            if let Some(bytes) = bytes
                && grants::decode_grant(ino, &bytes)?.key_version < base
            {
                let user = String::from_utf8_lossy(&key[prefix.len()..]).into_owned();
                return Ok(Some(format!("{user}'s grant")));
            }
        }
        Ok(None)
    }

    /// Removes volume `ino`, which must be empty, and every grant of it.
    /// Needs a writable grant of the volume itself.
    pub async fn delete_volume(&self, caller: &Caller, ino: u64) -> Result<(), FsError> {
        self.guard_now(&self.live(), caller, ino, true).await?;
        if self.resolve(&self.live(), ino).await?.parent != ROOT_INO {
            return Err(FsError::new(
                libc::EINVAL,
                format!("inode {ino} isn't a volume"),
            ));
        }
        let name = ino.to_string();
        self.remove_child(
            caller,
            ROOT_INO,
            OsStr::new(&name),
            ino,
            Kind::Directory,
            ino,
        )
        .await
    }

    /// Does everything after the tombstone: removes the chunks, then the
    /// Entry and the tombstone together. It is idempotent, so several
    /// processes can safely finish the same deletion at the same time.
    async fn finish_removal(&self, ino: u64) -> Result<(), FsError> {
        // The Entry, marked deleted, stays until the chunks are gone. If it
        // is missing, an earlier finish got that far, and the sweep can
        // remove any chunks that are left.
        let layout = match self.client.read_one(&attr_key(ino)).await?.value {
            Some(bytes) => decode_entry(ino, &bytes).attr.layout,
            None => Layout::Inline,
        };
        let dropped = self.delete_chunks_from(ino, 0, layout).await?;
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            txn.write(&attr_key(ino), None).await?;
            txn.write(&tombstone_key(ino), None).await?;
            // Its grants and key record are removed with it.
            grants::forget_inode(&txn, ino).await?;
            txn.commit().await?;
            Ok(())
        })
        .await?;
        self.discard(dropped);
        Ok(())
    }

    /// Finishes every deletion that an earlier process started but did not
    /// complete, and returns how many there were. The tombstone index holds
    /// only unfinished deletions, so this is cheap when there are none.
    async fn reap_tombstones(&self) -> Result<usize, FsError> {
        let mut inos = Vec::new();
        let mut iter = self
            .client
            .key_iterator(TOMBSTONE_PREFIX, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(TOMBSTONE_PREFIX) {
                break;
            }
            if let Ok(ino) = <[u8; 8]>::try_from(&key[TOMBSTONE_PREFIX.len()..]) {
                inos.push(u64::from_be_bytes(ino));
            }
        }
        for &ino in &inos {
            self.finish_removal(ino).await?;
        }
        Ok(inos.len())
    }

    /// Deletes every chunk of `ino` from `first_index` up, in limited
    /// batches. A scan (not a walk of `0..=size/chunk_size`) skips holes,
    /// finds anything an interrupted truncate left, and does not depend on
    /// the recorded size. If the file's `layout` is hybrid, returns the
    /// objects that the deleted pointers named. Only then are block starts'
    /// values read.
    async fn delete_chunks_from(
        &self,
        ino: u64,
        first_index: u64,
        layout: Layout,
    ) -> Result<Vec<Dropped>, KvError> {
        let prefix = chunk_prefix(ino);
        let grid = self.grid.filter(|_| layout == Layout::Hybrid);
        let mut dropped = Vec::new();
        loop {
            let mut iter = self
                .client
                .key_iterator(&chunk_key(ino, first_index), Consistency::Stale);
            let mut batch = Vec::new();
            while batch.len() < DELETE_BATCH {
                match next_key(&mut iter).await? {
                    // `key_iterator` runs to the end of the keyspace, so
                    // the walk ends when it leaves this inode's chunks.
                    Some(key) if !key.starts_with(&prefix) => break,
                    Some(key) if is_chunk_key(&key, &prefix) => batch.push(key),
                    Some(_) => {}
                    None => break,
                }
            }
            if batch.is_empty() {
                return Ok(dropped);
            }

            let batch = &batch;
            let starts: &Vec<(u64, &Vec<u8>)> = &batch
                .iter()
                .filter_map(|key| {
                    let grid = grid?;
                    let index = u64::from_be_bytes(key[prefix.len()..].try_into().unwrap());
                    (grid.in_blocks(index) && grid.block_start(index) == index)
                        .then_some((index, key))
                })
                .collect();
            dropped.extend(
                retrying(move || async move {
                    let txn = self.client.transaction(TXN_TTL).await?;
                    let keys: Vec<&Vec<u8>> = starts.iter().map(|&(_, key)| key).collect();
                    let mut found = Vec::new();
                    for (&(index, _), entry) in starts.iter().zip(txn.read_many(&keys).await?) {
                        if let Some(value) = entry.value
                            && let ChunkValue::Block(block) = ChunkValue::decode(value)
                        {
                            found.push(Dropped::new(ino, index, &block));
                        }
                    }
                    for key in batch {
                        txn.write(key, None).await?;
                    }
                    txn.commit().await?;
                    Ok(found)
                })
                .await?,
            );
        }
    }
}

/// Compile-time check only: the server runs these on tonic's multithreaded
/// runtime, which needs every request's future to be `Send`. Generic async
/// closures (`retrying`) are where that can stop being true without notice.
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
    send(core.public_key("u"));
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
