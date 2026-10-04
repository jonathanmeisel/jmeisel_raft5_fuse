//! The filesystem's operations against the store, one async method per
//! operation. No buffering and no FUSE: a front end (the FUSE client
//! today, the server later) decides when to call these.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use raft5_client::{Client, Error as KvError, Transaction};

use raft5fs_proto::types::{Attr, Caller, DirItem, FsError, Kind, SetAttr, WriteError};

use crate::entry::{Entry, decode_entry, encode_entry};
use crate::layout::{
    CHUNK_SIZE_KEY, COUNTER_KEY, DELETE_BATCH, ENCRYPTED_KEY, ROOT_INO, TOMBSTONE_PREFIX, attr_key,
    chunk_key, chunk_prefix, chunk_spans, chunks_per_batch, dirent_key, dirent_prefix,
    is_chunk_key, tombstone_key, validate_chunk_size,
};
use crate::perm::{self, R, W, X};
use crate::read_cache::{ChunkCache, Lookup};

pub(crate) const TXN_TTL: Duration = Duration::from_secs(10);

/// Default byte budget of the chunk read cache.
pub const DEFAULT_READ_CACHE_BYTES: usize = 64 << 20;
/// How long a cached chunk may go unconfirmed before it is dropped rather
/// than revalidated. Not a staleness bound: every hit confirms the chunk's
/// seq against the store first (see `FsCore::chunk`), so what this buys
/// is only that a chunk nothing has read for this long stops being held
/// against the cache's byte budget. Generous on purpose -- expiring an
/// entry costs a full re-fetch, where confirming one costs eight bytes.
const READ_CACHE_TTL: Duration = Duration::from_secs(60);

/// Runs `attempt` -- one whole transaction, from opening it to committing
/// it -- until the store stops aborting it, and returns what it returned.
///
/// The retry has to cover the whole attempt, because `Aborted` can come
/// from *any* step, not just `commit`: a contended key refuses the `read`
/// or `write` that touches it outright (see the server's wound-wait
/// `acquire`), it doesn't wait and let commit be the one to fail.
/// `Transaction` deliberately does not retry this itself (see its doc
/// comment): it doesn't know what the reads were, so only the caller that
/// issued them can redo it. An aborted transaction wrote nothing, so
/// running the attempt again is always safe.
///
/// An attempt that reaches a decision of its own -- "that name is taken",
/// "no such inode" -- returns it inside `Ok`, as `Ok(Err(..))`, so that
/// only the store's aborts are retried.
///
/// Takes a closure returning a fresh future per attempt, rather than an
/// async closure: an async closure's future can't be shown `Send` for
/// every lifetime, which the server's runtime needs. So callers capture
/// only references (which copy) and `move` them into each attempt.
pub(crate) async fn retrying<T, Fut>(mut attempt: impl FnMut() -> Fut) -> Result<T, KvError>
where
    Fut: std::future::Future<Output = Result<T, KvError>>,
{
    loop {
        match attempt().await {
            Err(KvError::Aborted { .. }) => continue,
            other => return other,
        }
    }
}

/// Inside a transaction attempt, unwraps a filesystem decision, or ends
/// the attempt with it as `Ok(Err(..))` -- the form `retrying` leaves
/// alone.
macro_rules! decide {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => return Ok(Err(e)),
        }
    };
}

/// `ino`'s Entry as `txn` sees it, which holds it against changes until
/// `txn` ends. A missing or deleted inode is `ENOENT`.
async fn live_entry(txn: &Transaction, ino: u64) -> Result<Result<Entry, FsError>, KvError> {
    Ok(match txn.read(&attr_key(ino)).await?.value {
        Some(bytes) => {
            let entry = decode_entry(ino, &bytes);
            if entry.is_deleted() {
                Err(enoent())
            } else {
                Ok(entry)
            }
        }
        None => Err(enoent()),
    })
}

/// A directory `txn` may add or remove names in on `caller`'s behalf.
async fn modifiable_dir(
    txn: &Transaction,
    caller: &Caller,
    ino: u64,
) -> Result<Result<Entry, FsError>, KvError> {
    let dir = decide!(live_entry(txn, ino).await?);
    decide!(perm::check_modify_dir(caller, &dir.attr));
    Ok(Ok(dir))
}

/// The inode a directory entry names, if it exists.
async fn named(txn: &Transaction, dirent: &[u8]) -> Result<Option<u64>, KvError> {
    Ok(txn
        .read(dirent)
        .await?
        .value
        .map(|b| u64::from_be_bytes(b.try_into().unwrap())))
}

/// Whether directory `ino` has no entries. The caller must already have
/// written `ino`'s Entry in this transaction.
///
/// The scan locks only the keys it finds, not the range, so on its own it
/// couldn't stop a concurrent create adding an entry right after. What
/// does is that lock on the Entry: every operation adding a name to a
/// directory reads the directory's Entry and holds it until it commits,
/// and an exclusive lock taken *before* the scan conflicts with that
/// whatever the timing. So either the create commits first, and the scan
/// sees its entry, or it can't start until this transaction is over.
async fn is_empty_dir(txn: &Transaction, ino: u64) -> Result<bool, KvError> {
    let prefix = dirent_prefix(ino);
    let mut iter = txn.key_iterator(&prefix);
    Ok(!matches!(iter.next().await?, Some(key) if key.starts_with(&prefix)))
}

async fn write_entry(txn: &Transaction, entry: &Entry) -> Result<(), KvError> {
    txn.write(&attr_key(entry.attr.ino), Some(&encode_entry(entry)))
        .await
}

/// Records that a directory's entries changed, as POSIX asks.
async fn touch_dir(txn: &Transaction, dir: &mut Entry, now: SystemTime) -> Result<(), KvError> {
    dir.attr.mtime = now;
    dir.attr.ctime = now;
    write_entry(txn, dir).await
}

/// The chunk size in force for the filesystem in `client`'s store: whatever
/// the store already records, or `preferred` if the store is new, which
/// then claims it. Reading and claiming in one transaction is what makes
/// two simultaneous first mounts safe -- the loser's retry sees the
/// winner's value and adopts it.
pub async fn resolve_chunk_size(client: &Client, preferred: u64) -> Result<u64, String> {
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
        if let Some(bytes) = txn.read(CHUNK_SIZE_KEY).await?.value {
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

/// Whether the filesystem in `client`'s store is encrypted: what the store
/// records, or for a new filesystem, `requested`, which it then records.
/// Like the chunk size, settled in one transaction so that servers
/// starting a new filesystem together agree.
///
/// Asking for encryption of a filesystem that already exists unencrypted
/// is an error rather than a note: carrying on would leave its owner
/// believing their data is encrypted when it isn't. The reverse -- an
/// encrypted filesystem opened without asking -- just stays encrypted.
pub async fn resolve_encryption(client: &Client, requested: bool) -> Result<bool, String> {
    retrying(move || async move {
        let refused = || {
            Ok(Err(
                "this filesystem was created unencrypted, and can't be made encrypted".to_string(),
            ))
        };
        let txn = client.transaction(TXN_TTL).await?;
        if let Some(bytes) = txn.read(ENCRYPTED_KEY).await?.value {
            let encrypted = bytes.as_slice() == [1];
            if requested && !encrypted {
                return refused();
            }
            return Ok(Ok(encrypted));
        }
        // No record, but a root: a filesystem from before encryption was
        // recorded, which makes it unencrypted.
        let existing = txn.read(&attr_key(ROOT_INO)).await?.value.is_some();
        if existing && requested {
            return refused();
        }
        let encrypted = requested && !existing;
        txn.write(ENCRYPTED_KEY, Some(&[u8::from(encrypted)]))
            .await?;
        txn.commit().await?;
        Ok(Ok(encrypted))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Whether the filesystem in `client`'s store is encrypted, without
/// settling it: `None` if no server has opened it yet.
pub async fn stored_encryption(client: &Client) -> Result<Option<bool>, FsError> {
    let recorded = client.read(ENCRYPTED_KEY).await?.value;
    if let Some(bytes) = recorded {
        return Ok(Some(bytes.as_slice() == [1]));
    }
    let existing = client.read(&attr_key(ROOT_INO)).await?.value.is_some();
    Ok(existing.then_some(false))
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

/// Hands out inode numbers. A transaction makes the read-increment-write
/// atomic, since the KV store gives us no other way to do a safe counter
/// bump: two `mkdir`s racing on a plain read/write could otherwise hand
/// out the same inode twice.
async fn allocate_inode(client: &Client) -> Result<u64, KvError> {
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
        let next = txn
            .read(COUNTER_KEY)
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

/// `entry` is of `kind`, or the errno for asking a file to be a directory
/// or the reverse.
fn check_kind(entry: &Entry, kind: Kind) -> Result<(), FsError> {
    match (kind, entry.attr.kind) {
        (Kind::File, Kind::Directory) => Err(FsError::errno(libc::EISDIR)),
        (Kind::Directory, Kind::File) => Err(FsError::errno(libc::ENOTDIR)),
        _ => Ok(()),
    }
}

pub struct FsCore {
    client: Client,
    chunk_size: u64,
    encrypted: bool,
    chunk_cache: Mutex<ChunkCache>,
}

impl FsCore {
    /// Opens the filesystem in `client`'s store, settling its chunk size
    /// (see `resolve_chunk_size`), creating the root directory if the
    /// filesystem is new -- owned by `root_owner` (uid, gid), mode 0755 --
    /// and finishing any deletion an earlier process left half done (see
    /// `reap_tombstones`). `read_cache_bytes` of 0 disables the read cache.
    /// `encrypted` only matters to a new filesystem (see
    /// `resolve_encryption`).
    pub async fn connect(
        client: Client,
        preferred_chunk_size: u64,
        read_cache_bytes: usize,
        root_owner: (u32, u32),
        encrypted: bool,
    ) -> Result<Self, String> {
        // Before the root exists, which is how it tells a new filesystem.
        let encrypted = resolve_encryption(&client, encrypted).await?;
        let chunk_size = resolve_chunk_size(&client, preferred_chunk_size).await?;
        let core = Self {
            client,
            chunk_size,
            encrypted,
            chunk_cache: Mutex::new(ChunkCache::new(read_cache_bytes, READ_CACHE_TTL)),
        };
        core.ensure_root(root_owner)
            .await
            .map_err(|e| format!("could not create the root directory: {e}"))?;
        // Not fatal: leftover deletions cost space, not correctness, and
        // the next instance to start tries again.
        if let Err(e) = core.reap_tombstones().await {
            eprintln!("could not finish interrupted deletions: {e}");
        }
        Ok(core)
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Whether this filesystem is encrypted: fixed when it was created.
    pub fn encrypted(&self) -> bool {
        self.encrypted
    }

    /// The store client this filesystem works through.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// An inode's Entry, or `None` if it doesn't exist -- including one
    /// whose deletion has started, which is gone as far as everything but
    /// the deletion itself is concerned.
    async fn read_entry(&self, ino: u64) -> Result<Option<Entry>, FsError> {
        let result = self.client.read(&attr_key(ino)).await?;
        Ok(result
            .value
            .map(|bytes| decode_entry(ino, &bytes))
            .filter(|entry| !entry.is_deleted()))
    }

    async fn lookup_child(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, FsError> {
        let result = self.client.read(&dirent_key(parent, name)).await?;
        Ok(result
            .value
            .map(|b| u64::from_be_bytes(b.try_into().unwrap())))
    }

    /// Creates the root directory unless it exists. Checking and creating
    /// in one transaction is what lets several servers start on a new
    /// filesystem at once: whichever commits second finds the root there.
    async fn ensure_root(&self, (uid, gid): (u32, u32)) -> Result<(), KvError> {
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            if txn.read(&attr_key(ROOT_INO)).await?.value.is_some() {
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
                    uid,
                    gid,
                    atime: now,
                    mtime: now,
                    ctime: now,
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
    async fn resolve(&self, ino: u64) -> Result<Entry, FsError> {
        self.read_entry(ino).await?.ok_or_else(enoent)
    }

    /// Needs no permission on the inode itself: what guards it is search
    /// permission on the path to it, which `lookup` checks.
    pub async fn getattr(&self, ino: u64) -> Result<Attr, FsError> {
        Ok(self.resolve(ino).await?.attr)
    }

    /// The inode `name` names in `parent`, without reading its attributes.
    async fn child_ino(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        self.lookup_child(parent, name).await?.ok_or_else(enoent)
    }

    pub async fn lookup(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
    ) -> Result<Attr, FsError> {
        let dir = self.resolve(parent).await?;
        if dir.attr.kind != Kind::Directory {
            return Err(FsError::errno(libc::ENOTDIR));
        }
        perm::check(caller, &dir.attr, X)?;
        let child = self.child_ino(parent, name).await?;
        Ok(self.resolve(child).await?.attr)
    }

    /// Checks `caller` may open `ino` for `mask` (some of `R` and `W`).
    pub async fn open(&self, caller: &Caller, ino: u64, mask: u32) -> Result<(), FsError> {
        let entry = self.resolve(ino).await?;
        if entry.attr.kind == Kind::Directory && mask & W != 0 {
            return Err(FsError::errno(libc::EISDIR));
        }
        perm::check(caller, &entry.attr, mask)
    }

    /// access(2): whether `caller` holds every right in `mask`, or with a
    /// `mask` of 0, whether `ino` exists.
    pub async fn access(&self, caller: &Caller, ino: u64, mask: u32) -> Result<(), FsError> {
        let entry = self.resolve(ino).await?;
        perm::check(caller, &entry.attr, mask)
    }

    pub async fn readdir(&self, caller: &Caller, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let entry = self.resolve(ino).await?;
        if entry.attr.kind != Kind::Directory {
            return Err(FsError::errno(libc::ENOTDIR));
        }
        perm::check(caller, &entry.attr, R)?;

        let mut items = vec![
            DirItem {
                ino,
                kind: Kind::Directory,
                name: OsString::from("."),
            },
            DirItem {
                ino: entry.parent,
                kind: Kind::Directory,
                name: OsString::from(".."),
            },
        ];

        let prefix = dirent_prefix(ino);
        let mut iter = self.client.key_iterator(&prefix);
        loop {
            let key = match iter.next().await? {
                Some(key) if key.starts_with(&prefix) => key,
                _ => break,
            };
            let name = OsStr::from_bytes(&key[prefix.len()..]).to_os_string();
            // A concurrent unlink/rmdir between the key_iterator batch and
            // this read is the only way the value comes back empty; skip it.
            let Some(bytes) = self.client.read(&key).await?.value else {
                continue;
            };
            let child_ino = u64::from_be_bytes(bytes.try_into().unwrap());
            let kind = self
                .read_entry(child_ino)
                .await?
                .map(|e| e.attr.kind)
                .unwrap_or(Kind::File);
            items.push(DirItem {
                ino: child_ino,
                kind,
                name,
            });
        }
        Ok(items)
    }

    /// `[offset, offset + len)` of `ino`, clamped to its size. End-of-file
    /// lives in the attributes, not in the chunks: an absent chunk is a
    /// hole, not the end, so the size has to come first.
    pub async fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        let size = self.read_entry(ino).await?.ok_or_else(enoent)?.attr.size;
        Ok(self.read_range(ino, offset, len, size).await?)
    }

    /// Absent chunks and chunks shorter than the region asked for both
    /// read as zeros, which falls out of building into an already-zeroed
    /// buffer.
    async fn read_range(
        &self,
        ino: u64,
        offset: u64,
        len: usize,
        size: u64,
    ) -> Result<Vec<u8>, KvError> {
        if offset >= size {
            return Ok(Vec::new());
        }
        let len = (len as u64).min(size - offset) as usize;
        let mut out = vec![0u8; len];

        let mut cursor = 0usize;
        for (index, within, n) in chunk_spans(self.chunk_size, offset, len) {
            let stored = self.chunk(ino, index).await?;
            if within < stored.len() {
                let end = (within + n).min(stored.len());
                out[cursor..cursor + (end - within)].copy_from_slice(&stored[within..end]);
            }
            cursor += n;
        }
        Ok(out)
    }

    /// The stored bytes of one chunk (empty if absent), through the read
    /// cache. The cache lock is released while the store is consulted.
    ///
    /// A cached chunk is never served on trust, because another mount's
    /// writes are invisible here: `get_version` says what seq the chunk
    /// currently holds, and only bytes read at that same seq are handed
    /// back. That call is answered on exactly the terms `read` is -- the
    /// stale, local-read terms -- so a confirmed hit is no less fresh than
    /// re-reading the chunk, and costs eight bytes on the wire instead of
    /// up to `MAX_CHUNK_SIZE`.
    async fn chunk(&self, ino: u64, index: u64) -> Result<Arc<[u8]>, KvError> {
        let key = chunk_key(ino, index);
        // Bound to a name so the cache lock is released here: the arms
        // below both await, and one of them locks the cache again.
        let lookup = self.chunk_cache.lock().unwrap().get(ino, index);
        let generation = match lookup {
            Lookup::Unconfirmed {
                data,
                version,
                generation,
            } => {
                // Both the seq check and the generation check have to pass:
                // the first rules out another mount's write, the second a
                // local one that landed while this was asking.
                if self.client.get_version(&key).await? == version
                    && self
                        .chunk_cache
                        .lock()
                        .unwrap()
                        .confirm(ino, index, generation)
                {
                    return Ok(data);
                }
                generation
            }
            Lookup::Miss { generation } => generation,
        };
        // `seq` is the version these very bytes were read at, so caching
        // the two together costs no extra round trip.
        let fetched = self.client.read(&key).await?;
        let data: Arc<[u8]> = fetched.value.unwrap_or_default().into();
        self.chunk_cache
            .lock()
            .unwrap()
            .insert(ino, index, data.clone(), fetched.seq, generation);
        Ok(data)
    }

    /// Splices `data` in at `offset` and updates the attributes to match.
    ///
    /// The chunks are stored in batches of up to `chunks_per_batch`, each
    /// batch one transaction, so a write spanning many chunks costs one
    /// commit per batch rather than one per chunk -- the commit being the
    /// expensive part, since it is what replicates. The cost is atomicity
    /// *between* batches: a reader can see the early batches of a write
    /// without the later ones, and a failure part-way leaves the batches
    /// already stored in place. Within a batch there is no such seam, as
    /// a transaction commits whole or not at all.
    ///
    /// Every transaction extends the size only to cover what it stored, so
    /// the size never runs ahead of the data. Reading the attributes
    /// inside each one takes their lock, so concurrent writers to one file
    /// still serialize per batch instead of clobbering each other's size.
    ///
    /// On failure the error carries how many leading bytes were stored, so
    /// a caller can report a short write instead of losing track of them.
    /// That count is per batch: a batch that failed contributes nothing,
    /// since none of it can be assumed to have landed. A missing inode is
    /// always reported as `ENOENT` with nothing written.
    pub async fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<Attr, WriteError> {
        let missing = || WriteError {
            written: 0,
            error: enoent(),
        };
        if data.is_empty() {
            // Still a write as far as mtime is concerned.
            return self
                .write_batch(ino, offset, &[], &[])
                .await
                .map_err(|e| log_write_error(ino, offset, e, 0))?
                .ok_or_else(missing);
        }

        // One span per chunk the range touches, ascending, so grouping
        // them by count bounds both what a transaction may hold: at most
        // `per_batch` keys, and at most `per_batch * chunk_size` bytes.
        let spans: Vec<(u64, usize, usize)> =
            chunk_spans(self.chunk_size, offset, data.len()).collect();
        let per_batch = chunks_per_batch(self.chunk_size);

        let mut attr = None;
        let mut cursor = 0usize;
        for group in spans.chunks(per_batch) {
            let bytes: usize = group.iter().map(|&(_, _, n)| n).sum();
            let end = offset + (cursor + bytes) as u64;
            let stored = self
                .write_batch(ino, end, group, &data[cursor..cursor + bytes])
                .await
                .map_err(|e| log_write_error(ino, offset, e, cursor))?;
            cursor += bytes;
            match stored {
                Some(a) => attr = Some(a),
                None => return Err(missing()),
            }
        }
        attr.ok_or_else(missing)
    }

    /// One transaction of `write`: stores every span in `spans` -- each a
    /// chunk index, the offset within that chunk, and how many bytes of
    /// `data` belong to it -- and extends the file to at least `end`.
    /// `data` holds exactly the bytes those spans cover, in order.
    ///
    /// An empty `spans` writes no chunk at all, which is how a zero-length
    /// write still touches mtime.
    async fn write_batch(
        &self,
        ino: u64,
        end: u64,
        spans: &[(u64, usize, usize)],
        data: &[u8],
    ) -> Result<Option<Attr>, KvError> {
        let outcome = retrying(move || self.write_batch_attempt(ino, end, spans, data)).await;
        if outcome.is_err() {
            // The outcome is unknown, so the cache can't be trusted for
            // these chunks either.
            self.chunk_cache.lock().unwrap().invalidate_ino(ino);
        }
        outcome
    }

    /// One attempt at `write_batch`: opens a transaction, applies every
    /// span, updates the attributes, and commits -- all of it, so that
    /// `write_batch`'s retry can treat any failure the same way: throw
    /// this attempt away and do the whole thing again from a fresh
    /// transaction.
    async fn write_batch_attempt(
        &self,
        ino: u64,
        end: u64,
        spans: &[(u64, usize, usize)],
        data: &[u8],
    ) -> Result<Option<Attr>, KvError> {
        let txn = self.client.transaction(TXN_TTL).await?;
        // First, and load-bearing: the attributes are deleted last
        // when a file goes away, so finding them absent here is what
        // stops a batch from storing chunks nothing could ever reach
        // again.
        let Some(bytes) = txn.read(&attr_key(ino)).await?.value else {
            return Ok(None);
        };
        let mut entry = decode_entry(ino, &bytes);
        // Equally load-bearing: a deletion marks the Entry before it
        // removes the chunks, in a transaction that conflicts with this
        // one on the attr key. So either this commit lands first, and its
        // chunks are there for the deletion to remove, or it sees the mark
        // here and stores nothing -- never a chunk written after the
        // deletion has already scanned past it.
        if entry.is_deleted() {
            return Ok(None);
        }

        let mut cursor = 0usize;
        for &(index, within, n) in spans {
            let slice = &data[cursor..cursor + n];
            cursor += n;
            let key = chunk_key(ino, index);
            // A write covering a whole chunk replaces it outright, so
            // there is nothing to preserve and nothing to read first.
            // Batches are aligned to the chunk grid, so this is the
            // path every chunk of an aligned sequential write takes --
            // such a batch reads no chunks at all.
            if within == 0 && n as u64 == self.chunk_size {
                txn.write(&key, Some(slice)).await?;
            } else {
                let mut buf = txn.read(&key).await?.value.unwrap_or_default();
                // Covers both a hole ahead of `within` and extending
                // the chunk to hold the new bytes.
                if buf.len() < within + n {
                    buf.resize(within + n, 0);
                }
                buf[within..within + n].copy_from_slice(slice);
                txn.write(&key, Some(&buf)).await?;
            }
        }

        if end > entry.attr.size {
            entry.attr.size = end;
        }
        let now = SystemTime::now();
        entry.attr.mtime = now;
        entry.attr.ctime = now;
        txn.write(&attr_key(ino), Some(&encode_entry(&entry)))
            .await?;
        txn.commit().await?;

        // One call for the whole batch: `invalidate` bumps the cache's
        // generation each time, and a single bump costs concurrent
        // readers fewer failed confirmations than one per chunk would.
        if let (Some(&(first, ..)), Some(&(last, ..))) = (spans.first(), spans.last()) {
            self.chunk_cache
                .lock()
                .unwrap()
                .invalidate(ino, first..=last);
        }
        Ok(Some(entry.attr))
    }

    /// Applies a `setattr` if `caller` may (see `perm::check_setattr`;
    /// `writable_handle` says it comes through a handle opened for
    /// writing), including the data-side work a size change implies.
    pub async fn setattr(
        &self,
        caller: &Caller,
        ino: u64,
        changes: SetAttr,
        writable_handle: bool,
    ) -> Result<Attr, FsError> {
        // Whole chunks past the new end go first, before anything records
        // the smaller size. A crash here loses tail bytes the caller asked
        // to discard; the other order would leave chunks beyond EOF that a
        // later grow would resurrect instead of reading as zeros.
        if let Some(new_size) = changes.size {
            // Deleting chunks is destructive and happens outside the
            // transaction below, so the caller's right to truncate is
            // checked before it as well as in it.
            let entry = self.resolve(ino).await?;
            perm::check_setattr(caller, &entry.attr, &changes, writable_handle)?;
            let last = new_size / self.chunk_size;
            let rem = (new_size % self.chunk_size) as usize;
            let first_dead = if rem == 0 { last } else { last + 1 };
            // Invalidated before and after: the boundary chunk changes
            // only at commit, and the dead ones vanish right now.
            self.chunk_cache
                .lock()
                .unwrap()
                .invalidate(ino, last..=u64::MAX);
            let deleted = self.delete_chunks_from(ino, first_dead).await;
            self.chunk_cache
                .lock()
                .unwrap()
                .invalidate(ino, last..=u64::MAX);
            deleted?;
        }

        let attr = retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let Some(bytes) = txn.read(&attr_key(ino)).await?.value else {
                return Ok(Err(enoent()));
            };
            let mut entry = decode_entry(ino, &bytes);
            // A truncate rewrites the boundary chunk, which must not happen
            // to an inode whose deletion may already have removed it.
            if entry.is_deleted() {
                return Ok(Err(enoent()));
            }
            if let Err(e) = perm::check_setattr(caller, &entry.attr, &changes, writable_handle) {
                return Ok(Err(e));
            }
            entry.attr.perm = perm::new_perm(caller, &entry.attr, &changes);

            if let Some(new_size) = changes.size {
                let last = new_size / self.chunk_size;
                let rem = (new_size % self.chunk_size) as usize;
                // The chunk EOF now falls inside still holds bytes past
                // it. Cutting it back is what makes a later grow read
                // zeros rather than what used to be there.
                if rem > 0
                    && let Some(mut buf) = txn.read(&chunk_key(ino, last)).await?.value
                    && buf.len() > rem
                {
                    buf.truncate(rem);
                    txn.write(&chunk_key(ino, last), Some(&buf)).await?;
                }
                entry.attr.size = new_size;
            }

            if let Some(uid) = changes.uid {
                entry.attr.uid = uid;
            }
            if let Some(gid) = changes.gid {
                entry.attr.gid = gid;
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

        if let Some(new_size) = changes.size {
            self.chunk_cache
                .lock()
                .unwrap()
                .invalidate(ino, new_size / self.chunk_size..=u64::MAX);
        }
        Ok(attr)
    }

    pub async fn mkdir(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        perm: u16,
    ) -> Result<Attr, FsError> {
        self.create_child(caller, parent, name, Kind::Directory, perm)
            .await
    }

    pub async fn create(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        perm: u16,
    ) -> Result<Attr, FsError> {
        self.create_child(caller, parent, name, Kind::File, perm)
            .await
    }

    /// Allocates an inode and claims `name` in `parent` for it, writing
    /// both the entry and the directory entry in one transaction. Reading
    /// the name inside that transaction is what makes the existence check
    /// authoritative: two concurrent creates of one name can't both find
    /// it absent. Reading the parent there too means the permission check
    /// sees the directory as it is at commit, and that a directory whose
    /// removal has begun takes no new entries.
    async fn create_child(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        kind: Kind,
        perm: u16,
    ) -> Result<Attr, FsError> {
        let ino = allocate_inode(&self.client).await?;
        let dirent = &dirent_key(parent, name);

        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let mut dir = decide!(modifiable_dir(&txn, caller, parent).await?);
            if txn.read(dirent).await?.value.is_some() {
                return Ok(Err(FsError::errno(libc::EEXIST)));
            }
            let (uid, gid, perm) = perm::new_owner(caller, &dir.attr, kind, perm);
            let now = SystemTime::now();
            let entry = Entry {
                attr: Attr {
                    ino,
                    kind,
                    size: 0,
                    perm,
                    nlink: if kind == Kind::Directory { 2 } else { 1 },
                    uid,
                    gid,
                    atime: now,
                    mtime: now,
                    ctime: now,
                },
                parent: if kind == Kind::Directory { parent } else { 0 },
            };
            write_entry(&txn, &entry).await?;
            txn.write(dirent, Some(&ino.to_be_bytes())).await?;
            touch_dir(&txn, &mut dir, now).await?;
            txn.commit().await?;
            Ok(Ok(entry.attr))
        })
        .await?
    }

    /// Removes a file, returning the inode it was.
    pub async fn unlink(&self, caller: &Caller, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let child = self.child_ino(parent, name).await?;
        self.remove_child(caller, parent, name, child, Kind::File)
            .await?;
        Ok(child)
    }

    /// Removes an empty directory, returning the inode it was.
    pub async fn rmdir(&self, caller: &Caller, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let child = self.child_ino(parent, name).await?;
        self.remove_child(caller, parent, name, child, Kind::Directory)
            .await?;
        Ok(child)
    }

    /// Unlinks `name` from `parent` and drops the inode it named, which
    /// must be of `kind` -- and if a directory, empty -- if `caller` may.
    ///
    /// Three steps, because an inode's chunks needn't fit in one
    /// transaction. First, one transaction checks the caller's rights on
    /// `parent`, removes the dirent, marks the Entry deleted and records a
    /// tombstone; it re-reads the dirent, so it only removes `ino` if the
    /// name still means `ino`. From then on no write can add a chunk (see
    /// `write_batch_attempt`), whichever process it comes from, nor a
    /// create add an entry to a removed directory. Then `finish_removal`
    /// deletes the chunks, the Entry and the tombstone. A crash between the
    /// two leaves the tombstone, which `reap_tombstones` finishes.
    async fn remove_child(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        ino: u64,
        kind: Kind,
    ) -> Result<(), FsError> {
        let dirent = &dirent_key(parent, name);
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let mut dir = decide!(modifiable_dir(&txn, caller, parent).await?);
            if named(&txn, dirent).await? != Some(ino) {
                return Ok(Err(enoent()));
            }
            let mut entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, kind));
            decide!(perm::check_sticky(caller, &dir.attr, &entry.attr));
            let now = SystemTime::now();
            entry.mark_deleted();
            entry.attr.ctime = now;
            // Before the emptiness check, which relies on it; if the check
            // fails, dropping the transaction undoes it.
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

    /// Moves `name` in `parent` to `new_name` in `new_parent`, replacing
    /// whatever that named unless `noreplace`, and returns the inode it
    /// replaced, if any.
    ///
    /// One transaction, so the name is never missing and never in both
    /// places. Data stays put -- chunks are keyed by inode, not by name --
    /// so the size of the file makes no difference. A replaced inode is
    /// removed the way `unlink` removes one, starting with a tombstone in
    /// the same transaction.
    pub async fn rename(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
        let from = &dirent_key(parent, name);
        let to = &dirent_key(new_parent, new_name);
        let replaced = retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            let mut src_dir = decide!(modifiable_dir(&txn, caller, parent).await?);
            let mut dst_dir = if new_parent == parent {
                None
            } else {
                Some(decide!(modifiable_dir(&txn, caller, new_parent).await?))
            };
            let dst_attr = dst_dir.as_ref().map_or(src_dir.attr, |d| d.attr);

            let Some(ino) = named(&txn, from).await? else {
                return Ok(Err(enoent()));
            };
            let mut moved = decide!(live_entry(&txn, ino).await?);
            decide!(perm::check_sticky(caller, &src_dir.attr, &moved.attr));
            let target = named(&txn, to).await?;
            if target == Some(ino) {
                // Two names for one inode: POSIX says do nothing. (With no
                // hard links, only `rename(a, a)` gets here.)
                return Ok(Ok(None));
            }

            let now = SystemTime::now();
            if let Some(victim_ino) = target {
                if noreplace {
                    return Ok(Err(FsError::errno(libc::EEXIST)));
                }
                let mut victim = decide!(live_entry(&txn, victim_ino).await?);
                decide!(perm::check_sticky(caller, &dst_attr, &victim.attr));
                decide!(check_kind(&victim, moved.attr.kind));
                victim.mark_deleted();
                victim.attr.ctime = now;
                write_entry(&txn, &victim).await?;
                if victim.attr.kind == Kind::Directory && !is_empty_dir(&txn, victim_ino).await? {
                    return Ok(Err(FsError::errno(libc::ENOTEMPTY)));
                }
                txn.write(&tombstone_key(victim_ino), Some(&[1])).await?;
            }

            if moved.attr.kind == Kind::Directory && new_parent != parent {
                // Its `..` changes, which is a change to the directory.
                decide!(perm::check(caller, &moved.attr, W));
                // Nor may it become its own descendant: walk up from where
                // it is going. The walk reads every ancestor, so a
                // concurrent rename that would close a loop the other way
                // round -- which writes one of them -- conflicts with this
                // one rather than slipping past it.
                let mut cur = new_parent;
                while cur != ROOT_INO {
                    if cur == ino {
                        return Ok(Err(FsError::errno(libc::EINVAL)));
                    }
                    cur = decide!(live_entry(&txn, cur).await?).parent;
                }
                moved.parent = new_parent;
            }
            moved.attr.ctime = now;
            write_entry(&txn, &moved).await?;
            txn.write(from, None).await?;
            txn.write(to, Some(&ino.to_be_bytes())).await?;
            touch_dir(&txn, &mut src_dir, now).await?;
            if let Some(dst_dir) = &mut dst_dir {
                touch_dir(&txn, dst_dir, now).await?;
            }
            txn.commit().await?;
            Ok(Ok(target))
        })
        .await??;

        if let Some(victim) = replaced {
            // The rename has happened whatever this says: a failure here
            // leaves the tombstone, for a later start to finish.
            if let Err(e) = self.finish_removal(victim).await {
                eprintln!("could not finish removing inode {victim}, replaced by a rename: {e}");
            }
        }
        Ok(replaced)
    }

    /// Everything after the tombstone: the chunks, then the Entry and the
    /// tombstone together. Idempotent, so it is safe for several processes
    /// to finish the same deletion at once.
    async fn finish_removal(&self, ino: u64) -> Result<(), FsError> {
        let deleted = self.delete_chunks_from(ino, 0).await;
        self.chunk_cache.lock().unwrap().invalidate_ino(ino);
        deleted?;
        retrying(move || async move {
            let txn = self.client.transaction(TXN_TTL).await?;
            txn.write(&attr_key(ino), None).await?;
            txn.write(&tombstone_key(ino), None).await?;
            txn.commit().await?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Finishes every deletion an earlier process started but didn't
    /// complete, returning how many there were. The tombstone index holds
    /// only in-progress deletions, so this is cheap when there are none.
    async fn reap_tombstones(&self) -> Result<usize, FsError> {
        let mut inos = Vec::new();
        let mut iter = self.client.key_iterator(TOMBSTONE_PREFIX);
        while let Some(key) = iter.next().await? {
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

    /// Deletes every chunk of `ino` from `first_index` on, in bounded
    /// batches. Scanning rather than walking `0..=size/chunk_size` skips
    /// holes, collects anything an interrupted truncate left behind, and
    /// needs no trust in the recorded size.
    async fn delete_chunks_from(&self, ino: u64, first_index: u64) -> Result<(), KvError> {
        let prefix = chunk_prefix(ino);
        loop {
            let mut iter = self.client.key_iterator(&chunk_key(ino, first_index));
            let mut batch = Vec::new();
            while batch.len() < DELETE_BATCH {
                match iter.next().await? {
                    // `key_iterator` runs to the end of the keyspace, so
                    // leaving this inode's chunks is the end of the walk.
                    Some(key) if !key.starts_with(&prefix) => break,
                    Some(key) if is_chunk_key(&key, &prefix) => batch.push(key),
                    Some(_) => {}
                    None => break,
                }
            }
            if batch.is_empty() {
                return Ok(());
            }

            let batch = &batch;
            retrying(move || async move {
                let txn = self.client.transaction(TXN_TTL).await?;
                for key in batch {
                    txn.write(key, None).await?;
                }
                txn.commit().await?;
                Ok(())
            })
            .await?;
        }
    }
}

/// Logs the real cause of a failed batch -- `write_batch` only ever
/// returns `KvError` on a genuine failure (`retrying` absorbs every
/// `Aborted`), and this is the one place every write path funnels
/// through, so it is the one place that needs to log it.
fn log_write_error(ino: u64, offset: u64, e: KvError, written: usize) -> WriteError {
    eprintln!("write to inode {ino} at offset {offset} failed after {written} bytes: {e}");
    WriteError {
        written,
        error: e.into(),
    }
}

/// Compile-time only: the server will run these on tonic's multithreaded
/// runtime, which needs every request's future to be `Send`. Generic async
/// closures (`retrying`) are exactly where that can quietly stop holding.
#[allow(dead_code)]
fn operations_are_send(core: &FsCore, caller: &Caller, name: &OsStr, data: &[u8]) {
    fn send<T: Send>(_: T) {}
    send(core.getattr(1));
    send(core.lookup(caller, 1, name));
    send(core.open(caller, 1, R));
    send(core.access(caller, 1, R));
    send(core.readdir(caller, 1));
    send(core.read(1, 0, 1));
    send(core.write(1, 0, data));
    send(core.setattr(caller, 1, SetAttr::default(), false));
    send(core.create(caller, 1, name, 0o644));
    send(core.mkdir(caller, 1, name, 0o755));
    send(core.unlink(caller, 1, name));
    send(core.rmdir(caller, 1, name));
    send(core.rename(caller, 1, name, 1, name, false));
    send(FsCore::connect(core.client.clone(), 4096, 0, (0, 0), false));
}
