use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    KernelConfig, LockOwner, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use raft5_client::{Client, Error as KvError};
use tokio::runtime::Handle;

use crate::read_cache::{ChunkCache, Lookup};
use crate::write_buffer::{Slot, WriteBuf};

const ROOT_INO: u64 = 1;
const TTL: Duration = Duration::from_secs(1);
const TXN_TTL: Duration = Duration::from_secs(10);

/// Default byte budget of the chunk read cache.
pub const DEFAULT_READ_CACHE_BYTES: usize = 64 << 20;
/// How long a cached chunk may go unconfirmed before it is dropped rather
/// than revalidated. Not a staleness bound: every hit confirms the chunk's
/// seq against the store first (see `Raft5Fs::chunk`), so what this buys
/// is only that a chunk nothing has read for this long stops being held
/// against the cache's byte budget. Generous on purpose -- expiring an
/// entry costs a full re-fetch, where confirming one costs eight bytes.
const READ_CACHE_TTL: Duration = Duration::from_secs(60);
const COUNTER_KEY: &[u8] = b"\x04next_ino";

/// Keys deleted per transaction when tearing down a file's chunks. Each
/// buffered write is its own round trip, so this bounds how long one
/// transaction stays open against its (absolute, 15 s maximum) deadline.
const DELETE_BATCH: usize = 256;

/// Records the chunk size a filesystem was created with, so later mounts
/// adopt it rather than reinterpreting every chunk boundary.
pub const CHUNK_SIZE_KEY: &[u8] = b"\x04chunk_size";

pub const DEFAULT_CHUNK_SIZE: u64 = 1 << 20;
pub const MIN_CHUNK_SIZE: u64 = 4096;
/// The largest chunk we will create. A chunk has to fit in one
/// transaction along with the attributes even when it is the only one in
/// its batch (see `chunks_per_batch`), and a read of it has to fit in one
/// gRPC message. 8 MiB clears both with room to spare; the largest power
/// of two under `MAX_TRANSACTION_BYTES`.
pub const MAX_CHUNK_SIZE: u64 = 8 << 20;

/// Mirrors `raft5_shared::MAX_TRANSACTION_BYTES`, the most a transaction
/// may buffer, which the server enforces.
const SERVER_TXN_LIMIT: u64 = 10 * 1024 * 1024;

/// Mirrors `raft5_shared::MAX_KV_MESSAGE_BYTES`, the decoding limit
/// `raft5_client` sets (`raft5-client/src/routing.rs`): a transaction's
/// worth plus 1 MiB of framing. A value larger than it could be written
/// and then never read back.
const CLIENT_READ_LIMIT: u64 = SERVER_TXN_LIMIT + 1024 * 1024;

// Slack for the attributes and the per-key overhead the server charges
// (64 bytes a key, so a full batch's worth is a kilobyte) alongside the
// chunk data in one transaction.
const TXN_SLACK: u64 = 64 * 1024;
const _: () = assert!(MAX_CHUNK_SIZE + TXN_SLACK <= SERVER_TXN_LIMIT);
const _: () = assert!(MAX_CHUNK_SIZE + TXN_SLACK < CLIENT_READ_LIMIT);

/// How many bytes of chunk data one transaction may carry. Sized well
/// under `SERVER_TXN_LIMIT` so that one commit's replicate-and-apply stays
/// a fraction of `TXN_TTL` even on a slow cluster, and so that an aborted
/// batch is not too much work to redo.
const MAX_BATCH_BYTES: u64 = 4 << 20;

/// How many chunk keys one transaction may touch.
///
/// The byte budget alone would not bound this: at `MIN_CHUNK_SIZE` a
/// batch's worth of bytes is a thousand keys. That matters because every
/// buffered write is its own round trip and every key a transaction takes
/// stays locked until it commits -- including the attributes, the one key
/// everything else on the inode contends for. This caps how long a batch
/// can hold them.
const MAX_BATCH_CHUNKS: usize = 16;

// A batch is at most `MAX_BATCH_CHUNKS` chunks *or* `MAX_BATCH_BYTES`,
// whichever binds first -- except that a single chunk always gets a
// transaction even when it alone is over the budget, which is what the
// `MAX_CHUNK_SIZE` assert above covers.
const _: () = assert!(MAX_BATCH_BYTES + TXN_SLACK <= SERVER_TXN_LIMIT);

/// How long buffered bytes may sit unstored when nothing else flushes
/// them. A writer that stops short of a full batch, and neither closes nor
/// syncs, would otherwise leave them in memory indefinitely.
const AUTO_FLUSH_DELAY: Duration = Duration::from_millis(500);

/// How many chunks one transaction covers at this filesystem's chunk size.
///
/// At least one: a chunk that alone fills the budget still has to be
/// stored. At `chunk_size` of `MAX_BATCH_BYTES` or more this is 1 and
/// batching does nothing, which is the honest outcome -- one chunk already
/// fills a transaction.
fn chunks_per_batch(chunk_size: u64) -> usize {
    ((MAX_BATCH_BYTES / chunk_size) as usize).clamp(1, MAX_BATCH_CHUNKS)
}

/// How much contiguous data one transaction stores at this chunk size, and
/// so how much a buffer accumulates before it is handed off. Public for
/// tests, which need to write exactly a batch to exercise that trigger.
pub fn batch_bytes(chunk_size: u64) -> u64 {
    chunks_per_batch(chunk_size) as u64 * chunk_size
}

// Key layout in the KV store:
//   0x01 ++ ino(BE8)                    -> encoded Entry (attributes + parent)
//   0x02 ++ ino(BE8) ++ index(BE8)      -> one chunk of a file's data
//   0x03 ++ parent(BE8) ++ name         -> child ino(BE8), one per directory entry
//   0x04 ++ name                        -> filesystem-wide singletons
//
// The singletons were once `0x00 ++ name`, which the cluster has since
// reserved for itself (`raft5-server`'s `keyspace`): keys under `\x00`
// are no longer addressable through the client API at all, so those two
// rows can be neither read nor migrated from here. A store written before
// that change therefore has no reachable record of its chunk size or its
// inode counter. It will mount -- adopting the requested chunk size and
// restarting the counter -- and reinterpret every chunk boundary while
// handing out inode numbers that already exist. Such a store must be
// discarded, not mounted.
//
// A file's bytes are split across chunks of `chunk_size` each. A chunk
// that was never written is simply absent and reads as zeros, so holes
// cost nothing; end-of-file lives in the Entry, never in the chunks.
//
// This layout is not compatible with the earlier one that held a whole
// file under `0x02 ++ ino`. Those 9-byte keys are ignored (every scan
// requires the full 17-byte chunk key), so an old database reads as a
// tree of empty files rather than as corrupt data -- but it cannot be
// migrated, only discarded.

fn attr_key(ino: u64) -> Vec<u8> {
    let mut key = vec![0x01];
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// The common prefix of every chunk key belonging to `ino`. Chunk indices
/// are fixed-width and big-endian, so lexicographic order over this prefix
/// is ascending chunk order.
pub fn chunk_prefix(ino: u64) -> Vec<u8> {
    let mut key = vec![0x02];
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

fn chunk_key(ino: u64, index: u64) -> Vec<u8> {
    let mut key = chunk_prefix(ino);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn is_chunk_key(key: &[u8], prefix: &[u8]) -> bool {
    key.starts_with(prefix) && key.len() == prefix.len() + 8
}

fn dirent_prefix(parent: u64) -> Vec<u8> {
    let mut key = vec![0x03];
    key.extend_from_slice(&parent.to_be_bytes());
    key
}

fn dirent_key(parent: u64, name: &OsStr) -> Vec<u8> {
    let mut key = dirent_prefix(parent);
    key.extend_from_slice(name.as_bytes());
    key
}

/// Splits `[offset, offset + len)` into the chunks it touches, as
/// `(index, offset_within_chunk, len_within_chunk)`. A free function
/// taking `chunk_size` rather than a method, so it can be tested without
/// a cluster.
fn chunk_spans(
    chunk_size: u64,
    offset: u64,
    len: usize,
) -> impl Iterator<Item = (u64, usize, usize)> {
    let mut pos = offset;
    let mut remaining = len as u64;
    std::iter::from_fn(move || {
        if remaining == 0 {
            return None;
        }
        let within = pos % chunk_size;
        let n = remaining.min(chunk_size - within);
        let span = (pos / chunk_size, within as usize, n as usize);
        pos += n;
        remaining -= n;
        Some(span)
    })
}

pub fn validate_chunk_size(n: u64) -> Result<(), String> {
    if !n.is_power_of_two() {
        return Err(format!("chunk size must be a power of two, got {n}"));
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&n) {
        return Err(format!(
            "chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes, got {n}"
        ));
    }
    Ok(())
}

/// A directory's attributes plus its parent inode, so `readdir` can answer
/// `..` without a separate lookup. Files leave `parent` at 0 (unused: we
/// don't support hard links, so a file only ever has the one directory
/// entry that named it in `create`).
struct Entry {
    attr: FileAttr,
    parent: u64,
}

fn push_time(buf: &mut Vec<u8>, t: SystemTime) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    buf.extend_from_slice(&d.as_secs().to_be_bytes());
    buf.extend_from_slice(&d.subsec_nanos().to_be_bytes());
}

fn take_time(bytes: &[u8]) -> (SystemTime, &[u8]) {
    let (secs, rest) = bytes.split_at(8);
    let (nanos, rest) = rest.split_at(4);
    let secs = u64::from_be_bytes(secs.try_into().unwrap());
    let nanos = u32::from_be_bytes(nanos.try_into().unwrap());
    (UNIX_EPOCH + Duration::new(secs, nanos), rest)
}

fn encode_entry(entry: &Entry) -> Vec<u8> {
    let a = &entry.attr;
    let mut buf = Vec::with_capacity(67);
    buf.push(match a.kind {
        FileType::Directory => 1,
        _ => 0,
    });
    buf.extend_from_slice(&a.perm.to_be_bytes());
    buf.extend_from_slice(&a.uid.to_be_bytes());
    buf.extend_from_slice(&a.gid.to_be_bytes());
    buf.extend_from_slice(&a.size.to_be_bytes());
    buf.extend_from_slice(&a.nlink.to_be_bytes());
    push_time(&mut buf, a.atime);
    push_time(&mut buf, a.mtime);
    push_time(&mut buf, a.ctime);
    buf.extend_from_slice(&entry.parent.to_be_bytes());
    buf
}

fn decode_entry(ino: u64, bytes: &[u8]) -> Entry {
    let (kind, rest) = bytes.split_at(1);
    let kind = if kind[0] == 1 {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    let (perm, rest) = rest.split_at(2);
    let (uid, rest) = rest.split_at(4);
    let (gid, rest) = rest.split_at(4);
    let (size, rest) = rest.split_at(8);
    let (nlink, rest) = rest.split_at(4);
    let (atime, rest) = take_time(rest);
    let (mtime, rest) = take_time(rest);
    let (ctime, rest) = take_time(rest);
    let parent = u64::from_be_bytes(rest.try_into().unwrap());
    let size = u64::from_be_bytes(size.try_into().unwrap());

    let attr = FileAttr {
        ino: INodeNo(ino),
        size,
        blocks: size.div_ceil(512),
        atime,
        mtime,
        ctime,
        crtime: ctime,
        kind,
        perm: u16::from_be_bytes(perm.try_into().unwrap()),
        nlink: u32::from_be_bytes(nlink.try_into().unwrap()),
        uid: u32::from_be_bytes(uid.try_into().unwrap()),
        gid: u32::from_be_bytes(gid.try_into().unwrap()),
        rdev: 0,
        blksize: 4096,
        flags: 0,
    };
    Entry { attr, parent }
}

fn time_or_now(t: TimeOrNow) -> SystemTime {
    match t {
        TimeOrNow::SpecificTime(t) => t,
        TimeOrNow::Now => SystemTime::now(),
    }
}

/// Hands out inode numbers. A transaction makes the read-increment-write
/// atomic, since the KV store gives us no other way to do a safe counter
/// bump: two `mkdir`s racing on a plain read/write could otherwise hand
/// out the same inode twice.
async fn allocate_inode(client: &Client) -> Result<u64, KvError> {
    loop {
        let txn = client.transaction(TXN_TTL).await?;
        let current = txn.read(COUNTER_KEY).await?;
        let next = current
            .value
            .map(|v| u64::from_be_bytes(v.try_into().unwrap()))
            .unwrap_or(ROOT_INO + 1);
        txn.write(COUNTER_KEY, Some(&(next + 1).to_be_bytes()))
            .await?;
        match txn.commit().await {
            Ok(_) => return Ok(next),
            Err(KvError::Aborted { .. }) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// A failed `write_range`: how many leading bytes of the write had
/// already been stored (each chunk commits on its own). Every failure is
/// reported to the kernel as `EIO`, so the cause is not kept.
struct WriteError {
    written: usize,
}

/// What it takes to store a write: enough of `Raft5Fs` to be cloned into
/// the background tasks that commit a file's chunks.
#[derive(Clone)]
struct Committer {
    client: Client,
    chunk_size: u64,
    chunk_cache: Arc<Mutex<ChunkCache>>,
}

impl Committer {
    /// Splices `data` in at `offset` and updates the attributes to match.
    /// `Ok(None)` means there is no such inode.
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
    /// `write` can report a short write instead of losing track of them.
    /// That count is per batch: a batch that failed contributes nothing,
    /// since none of it can be assumed to have landed.
    async fn write_range(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Option<FileAttr>, WriteError> {
        if data.is_empty() {
            // Still a write as far as mtime is concerned.
            return self
                .write_batch(ino, offset, &[], &[])
                .await
                .map_err(|_| WriteError { written: 0 });
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
                .map_err(|_| WriteError { written: cursor })?;
            cursor += bytes;
            match stored {
                Some(a) => attr = Some(a),
                None => return Ok(None),
            }
        }
        Ok(attr)
    }

    /// One transaction of `write_range`: stores every span in `spans` --
    /// each a chunk index, the offset within that chunk, and how many
    /// bytes of `data` belong to it -- and extends the file to at least
    /// `end`. `data` holds exactly the bytes those spans cover, in order.
    ///
    /// An empty `spans` writes no chunk at all, which is how a zero-length
    /// write still touches mtime.
    async fn write_batch(
        &self,
        ino: u64,
        end: u64,
        spans: &[(u64, usize, usize)],
        data: &[u8],
    ) -> Result<Option<FileAttr>, KvError> {
        loop {
            let txn = self.client.transaction(TXN_TTL).await?;
            // First, and load-bearing: the attributes are deleted last
            // when a file goes away, so finding them absent here is what
            // stops a queued batch from storing chunks nothing could ever
            // reach again.
            let Some(bytes) = txn.read(&attr_key(ino)).await?.value else {
                return Ok(None);
            };
            let mut entry = decode_entry(ino, &bytes);

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
                entry.attr.blocks = end.div_ceil(512);
            }
            let now = SystemTime::now();
            entry.attr.mtime = now;
            entry.attr.ctime = now;
            txn.write(&attr_key(ino), Some(&encode_entry(&entry)))
                .await?;

            match txn.commit().await {
                Ok(_) => {
                    // One call for the whole batch: `invalidate` bumps the
                    // cache's generation each time, and a single bump
                    // costs concurrent readers fewer failed confirmations
                    // than one per chunk would.
                    if let (Some(&(first, ..)), Some(&(last, ..))) = (spans.first(), spans.last()) {
                        self.chunk_cache
                            .lock()
                            .unwrap()
                            .invalidate(ino, first..=last);
                    }
                    return Ok(Some(entry.attr));
                }
                Err(KvError::Aborted { .. }) => continue,
                // The outcome is unknown, so the cache can't be trusted
                // for these chunks either.
                Err(e) => {
                    self.chunk_cache.lock().unwrap().invalidate_ino(ino);
                    return Err(e);
                }
            }
        }
    }
}

/// Queues whatever `buf` holds to be stored, and returns without waiting
/// for it. Waits only for room: at most `MAX_IN_FLIGHT` batches per file
/// are outstanding, so a writer that outruns the store slows down instead
/// of piling up data.
///
/// Batches commit one at a time, in the order they were queued -- each
/// task waits on the one before it. That keeps every transaction whole
/// (attribute read, chunks, size, all together), so the size never covers
/// data that isn't stored and a file deleted mid-flight makes the
/// remaining transactions find no inode rather than leak chunks. A failure
/// is kept in the pipeline for the next `flush`/`fsync`/`write` to report,
/// and batches queued behind it are dropped.
///
/// A free function rather than a method: the auto-flush timer has to do
/// this from a task that holds no `Raft5Fs`, only the cheap clones below.
fn enqueue_flush(rt: &Handle, committer: &Committer, ino: u64, buf: &mut WriteBuf) {
    if buf.is_empty() {
        return;
    }
    buf.pipe.reserve();
    spawn_queued(rt, committer, ino, buf);
}

/// `enqueue_flush` for a caller that must not block, and so may find the
/// pipeline full. Returns whether bytes are still waiting to be stored --
/// that is, whether it is worth trying again.
fn try_enqueue_flush(rt: &Handle, committer: &Committer, ino: u64, buf: &mut WriteBuf) -> bool {
    if buf.is_empty() {
        return false;
    }
    if !buf.pipe.try_reserve() {
        return true;
    }
    spawn_queued(rt, committer, ino, buf);
    false
}

/// Takes `buf`'s run and spawns the task that commits it, chained behind
/// whatever was queued before it. The caller has already reserved the
/// pipeline slot this consumes.
fn spawn_queued(rt: &Handle, committer: &Committer, ino: u64, buf: &mut WriteBuf) {
    let Some((start, data)) = buf.take() else {
        // Nothing to store, so give the reserved slot straight back.
        buf.pipe.complete(None);
        return;
    };
    let slot = Slot::new(Arc::clone(&buf.pipe));
    let pipe = Arc::clone(&buf.pipe);
    let prev = buf.tail.take();
    let committer = committer.clone();
    buf.tail = Some(rt.spawn(async move {
        if let Some(prev) = prev {
            let _ = prev.await;
        }
        if pipe.should_skip() {
            return slot.finish(None);
        }
        slot.finish(match committer.write_range(ino, start, &data).await {
            Ok(Some(_)) => None,
            Ok(None) => Some(Errno::ENOENT),
            Err(_) => Some(Errno::EIO),
        });
    }));
}

pub struct Raft5Fs {
    client: Client,
    rt: Handle,
    /// The size requested by the caller until `init` resolves it against
    /// whatever the store already records, and the size actually in force
    /// after that.
    chunk_size: u64,
    chunk_cache: Arc<Mutex<ChunkCache>>,
    /// Per-inode buffers of accepted-but-unstored writes. The map lock is
    /// only held to find or insert a slot, never across a network call;
    /// the slot's own lock is what serializes a file's writes and flushes.
    write_bufs: Mutex<HashMap<u64, Arc<Mutex<WriteBuf>>>>,
    write_buffering: bool,
}

impl Raft5Fs {
    pub fn new(client: Client, rt: Handle, chunk_size: u64) -> Self {
        Self {
            client,
            rt,
            chunk_size,
            chunk_cache: Arc::new(Mutex::new(ChunkCache::new(
                DEFAULT_READ_CACHE_BYTES,
                READ_CACHE_TTL,
            ))),
            write_bufs: Mutex::new(HashMap::new()),
            write_buffering: true,
        }
    }

    /// Sets the read cache's byte budget; 0 disables it.
    pub fn with_read_cache_bytes(mut self, bytes: usize) -> Self {
        self.chunk_cache = Arc::new(Mutex::new(ChunkCache::new(bytes, READ_CACHE_TTL)));
        self
    }

    /// Turns write buffering on or off (on by default).
    pub fn with_write_buffering(mut self, enabled: bool) -> Self {
        self.write_buffering = enabled;
        self
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    fn committer(&self) -> Committer {
        Committer {
            client: self.client.clone(),
            chunk_size: self.chunk_size,
            chunk_cache: Arc::clone(&self.chunk_cache),
        }
    }

    fn block<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
    }

    /// The chunk size in force for this filesystem: whatever the store
    /// already records, or `preferred` if the store is new, which then
    /// claims it. Reading and claiming in one transaction is what makes
    /// two simultaneous first mounts safe -- the loser's retry sees the
    /// winner's value and adopts it.
    pub fn resolve_chunk_size(&self, preferred: u64) -> Result<u64, String> {
        self.block(self.resolve_chunk_size_inner(preferred))
    }

    async fn resolve_chunk_size_inner(&self, preferred: u64) -> Result<u64, String> {
        loop {
            let txn = self
                .client
                .transaction(TXN_TTL)
                .await
                .map_err(|e| e.to_string())?;
            let stored = txn
                .read(CHUNK_SIZE_KEY)
                .await
                .map_err(|e| e.to_string())?
                .value;

            if let Some(bytes) = stored {
                let bytes: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                    format!(
                        "this filesystem's recorded chunk size is {} bytes long, not 8",
                        bytes.len()
                    )
                })?;
                let stored = u64::from_be_bytes(bytes);
                validate_chunk_size(stored).map_err(|why| {
                    format!("this filesystem records an unusable chunk size: {why}")
                })?;
                return Ok(stored);
            }

            validate_chunk_size(preferred)?;
            txn.write(CHUNK_SIZE_KEY, Some(&preferred.to_be_bytes()))
                .await
                .map_err(|e| e.to_string())?;
            match txn.commit().await {
                Ok(_) => return Ok(preferred),
                Err(KvError::Aborted { .. }) => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    fn read_entry(&self, ino: u64) -> Option<Entry> {
        let result = self.block(self.client.read(&attr_key(ino))).ok()?;
        result.value.map(|bytes| decode_entry(ino, &bytes))
    }

    fn write_entry(&self, entry: &Entry) -> Result<(), KvError> {
        self.block(
            self.client
                .write(&attr_key(entry.attr.ino.0), Some(&encode_entry(entry))),
        )?;
        Ok(())
    }

    fn lookup_child(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, KvError> {
        let result = self.block(self.client.read(&dirent_key(parent, name)))?;
        Ok(result
            .value
            .map(|b| u64::from_be_bytes(b.try_into().unwrap())))
    }

    /// The kernel calls `init` before any request has a real caller (it
    /// reports uid/gid 0 there), so the root directory can't be given its
    /// owner at that point. Instead it's created lazily, the first time
    /// anyone actually resolves inode 1, using whichever request gets
    /// there first.
    fn ensure_root(&self, req: &Request) -> Option<Entry> {
        if let Some(entry) = self.read_entry(ROOT_INO) {
            return Some(entry);
        }
        let now = SystemTime::now();
        let attr = FileAttr {
            ino: INodeNo(ROOT_INO),
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: 4096,
            flags: 0,
        };
        let entry = Entry {
            attr,
            parent: ROOT_INO,
        };
        self.write_entry(&entry).ok()?;
        Some(entry)
    }

    /// Like `read_entry`, but bootstraps the root directory on demand
    /// instead of reporting it missing.
    fn resolve(&self, req: &Request, ino: u64) -> Option<Entry> {
        if ino == ROOT_INO {
            self.ensure_root(req)
        } else {
            self.read_entry(ino)
        }
    }

    /// `[offset, offset + len)` of `ino`, clamped to `size`. Absent chunks
    /// and chunks shorter than the region asked for both read as zeros,
    /// which falls out of building into an already-zeroed buffer.
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

    fn write_slot(&self, ino: u64) -> Arc<Mutex<WriteBuf>> {
        self.write_bufs
            .lock()
            .unwrap()
            .entry(ino)
            .or_default()
            .clone()
    }

    fn existing_write_slot(&self, ino: u64) -> Option<Arc<Mutex<WriteBuf>>> {
        self.write_bufs.lock().unwrap().get(&ino).cloned()
    }

    /// Queues whatever `buf` holds to be stored; see `enqueue_flush`.
    fn flush_buf(&self, ino: u64, buf: &mut WriteBuf) {
        enqueue_flush(&self.rt, &self.committer(), ino, buf);
    }

    /// Arranges for `ino`'s buffer to be stored within `AUTO_FLUSH_DELAY`
    /// even if nothing else asks for it, so a writer that stops short of a
    /// full batch and neither closes nor syncs does not leave its bytes in
    /// memory indefinitely. Called when a buffer goes from empty to
    /// holding something.
    ///
    /// Nothing cancels this, and nothing needs to. If the buffer is
    /// flushed by any other route first, the timer finds it empty and does
    /// nothing. If a later run has started by then, flushing that one
    /// early is harmless -- sooner is always safe -- and the timer it
    /// scheduled for itself then finds nothing to do. `destroy` drains
    /// every buffer before an unmount completes, so correctness never
    /// rests on this firing; and a task parked in `sleep` is at an await
    /// point, so dropping the runtime cancels it rather than waiting.
    fn schedule_auto_flush(&self, ino: u64, slot: Arc<Mutex<WriteBuf>>) {
        let committer = self.committer();
        let rt = self.rt.clone();
        self.rt.spawn(async move {
            loop {
                tokio::time::sleep(AUTO_FLUSH_DELAY).await;
                // Nothing in here may block, because this runs on an
                // async worker and the tasks that commit batches need
                // those workers to make progress. Blocking one while a
                // fuse thread holds this buffer and waits for a commit
                // would deadlock the pair. So: `try_lock` rather than
                // `lock`, and `try_enqueue_flush`, which gives up instead
                // of waiting for a pipeline slot. Either way another
                // interval costs nothing -- whoever holds the lock or
                // filled the pipeline is already storing this file.
                let waiting = match slot.try_lock() {
                    Ok(mut buf) => try_enqueue_flush(&rt, &committer, ino, &mut buf),
                    Err(std::sync::TryLockError::WouldBlock) => true,
                    // Some other thread panicked holding this buffer;
                    // its bytes are not ours to recover.
                    Err(std::sync::TryLockError::Poisoned(_)) => return,
                };
                if !waiting {
                    return;
                }
            }
        });
    }

    /// Queues `buf`'s run, then waits until everything queued for the file
    /// has been stored.
    fn drain_buf(&self, ino: u64, buf: &mut WriteBuf) {
        self.flush_buf(ino, buf);
        buf.pipe.wait_drained();
    }

    /// Stores `ino`'s buffered writes, if any. Called before anything that
    /// must observe them: reads, attribute queries, truncation. An error
    /// from any of them is reported but left for `flush`/`fsync`/`write`
    /// to take.
    fn flush_ino(&self, ino: u64) -> Result<(), Errno> {
        if let Some(slot) = self.existing_write_slot(ino) {
            let mut buf = slot.lock().unwrap();
            self.drain_buf(ino, &mut buf);
            if let Some(e) = buf.pipe.peek_err() {
                return Err(e);
            }
        }
        Ok(())
    }

    /// `flush_ino`, but takes the error it reports.
    fn sync_ino(&self, ino: u64) -> Result<(), Errno> {
        let Some(slot) = self.existing_write_slot(ino) else {
            return Ok(());
        };
        let mut buf = slot.lock().unwrap();
        self.drain_buf(ino, &mut buf);
        match buf.pipe.take_err() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Drops `ino`'s buffered and queued writes because the file is being
    /// deleted. Returns once none is still running, so nothing can store
    /// a chunk after the caller starts deleting them.
    fn discard_ino(&self, ino: u64) {
        if let Some(slot) = self.existing_write_slot(ino) {
            slot.lock().unwrap().discard();
        }
    }

    /// Forgets `ino`'s slot once nothing is using it or waiting in it, so
    /// the map doesn't grow with every file ever written.
    fn prune_slot(&self, ino: u64) {
        let mut bufs = self.write_bufs.lock().unwrap();
        if let Some(slot) = bufs.get(&ino)
            && Arc::strong_count(slot) == 1
            && slot
                .try_lock()
                .is_ok_and(|b| b.is_empty() && b.pipe.is_idle())
        {
            bufs.remove(&ino);
        }
    }

    /// Accepts `data` at `offset` into `ino`'s buffer, queueing the run to
    /// be stored when it fills a batch or stops being contiguous -- or,
    /// failing both, when `AUTO_FLUSH_DELAY` has passed. A write already
    /// big enough to fill a batch is stored before this returns, since
    /// there is nothing left to coalesce it with.
    ///
    /// Returns how many bytes were accepted: all of them, or on a failed
    /// oversized write just the batches that got stored before it. Errors
    /// from earlier queued batches are reported here too.
    fn buffered_write(&self, ino: u64, mut offset: u64, mut data: &[u8]) -> Result<usize, Errno> {
        let total = data.len();
        let batch_bytes = batch_bytes(self.chunk_size);
        let slot = self.write_slot(ino);
        let mut buf = slot.lock().unwrap();
        if let Some(e) = buf.pipe.take_err() {
            return Err(e);
        }

        if data.len() as u64 >= batch_bytes {
            // Stored directly, so everything queued ahead of it has to be
            // stored first.
            self.drain_buf(ino, &mut buf);
            if let Some(e) = buf.pipe.take_err() {
                return Err(e);
            }
            return match self.block(self.committer().write_range(ino, offset, data)) {
                Ok(Some(_)) => Ok(total),
                Ok(None) => Err(Errno::ENOENT),
                Err(WriteError { written: 0 }) => Err(Errno::EIO),
                Err(WriteError { written }) => Ok(written),
            };
        }

        while !data.is_empty() {
            if !buf.accepts(offset) {
                self.flush_buf(ino, &mut buf);
            }
            // Stepping to the batch grid rather than the chunk grid is
            // what lets a run span chunks, and keeps the batch it becomes
            // aligned: a sequential writer then fills every chunk of its
            // batch completely, so storing it reads nothing back.
            let room = (batch_bytes - offset % batch_bytes) as usize;
            let n = room.min(data.len());
            let idle = buf.is_empty();
            buf.append(offset, &data[..n]);
            if idle {
                self.schedule_auto_flush(ino, Arc::clone(&slot));
            }
            offset += n as u64;
            data = &data[n..];
            if offset.is_multiple_of(batch_bytes) {
                self.flush_buf(ino, &mut buf);
            }
        }
        Ok(total)
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

            loop {
                let txn = self.client.transaction(TXN_TTL).await?;
                for key in &batch {
                    txn.write(key, None).await?;
                }
                match txn.commit().await {
                    Ok(_) => break,
                    Err(KvError::Aborted { .. }) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// Applies a `setattr`, including the data-side work a size change
    /// implies. `Ok(None)` means there is no such inode.
    #[allow(clippy::too_many_arguments)]
    async fn apply_setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<Option<FileAttr>, KvError> {
        // Whole chunks past the new end go first, before anything records
        // the smaller size. A crash here loses tail bytes the caller asked
        // to discard; the other order would leave chunks beyond EOF that a
        // later grow would resurrect instead of reading as zeros.
        if let Some(new_size) = size {
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

        loop {
            let txn = self.client.transaction(TXN_TTL).await?;
            let Some(bytes) = txn.read(&attr_key(ino)).await?.value else {
                return Ok(None);
            };
            let mut entry = decode_entry(ino, &bytes);

            if let Some(new_size) = size {
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
                entry.attr.blocks = new_size.div_ceil(512);
            }

            if let Some(mode) = mode {
                entry.attr.perm = (mode & 0o7777) as u16;
            }
            if let Some(uid) = uid {
                entry.attr.uid = uid;
            }
            if let Some(gid) = gid {
                entry.attr.gid = gid;
            }
            if let Some(atime) = atime {
                entry.attr.atime = time_or_now(atime);
            }
            if let Some(mtime) = mtime {
                entry.attr.mtime = time_or_now(mtime);
            }
            entry.attr.ctime = SystemTime::now();

            txn.write(&attr_key(ino), Some(&encode_entry(&entry)))
                .await?;
            match txn.commit().await {
                Ok(_) => {
                    if let Some(new_size) = size {
                        self.chunk_cache
                            .lock()
                            .unwrap()
                            .invalidate(ino, new_size / self.chunk_size..=u64::MAX);
                    }
                    return Ok(Some(entry.attr));
                }
                Err(KvError::Aborted { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Allocates an inode and claims `name` in `parent` for it, writing
    /// both the entry and the directory entry in one transaction. Reading
    /// the name inside that transaction is what makes the existence check
    /// authoritative: two concurrent creates of one name can't both find
    /// it absent. `Ok(None)` means the name was taken.
    async fn create_child(
        &self,
        parent: u64,
        name: &OsStr,
        kind: FileType,
        perm: u16,
        uid: u32,
        gid: u32,
    ) -> Result<Option<FileAttr>, KvError> {
        let ino = allocate_inode(&self.client).await?;
        let now = SystemTime::now();
        let attr = FileAttr {
            ino: INodeNo(ino),
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid,
            gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        };
        let entry = Entry {
            attr,
            parent: if kind == FileType::Directory {
                parent
            } else {
                0
            },
        };
        let dirent = dirent_key(parent, name);

        loop {
            let txn = self.client.transaction(TXN_TTL).await?;
            if txn.read(&dirent).await?.value.is_some() {
                return Ok(None);
            }
            txn.write(&attr_key(ino), Some(&encode_entry(&entry)))
                .await?;
            txn.write(&dirent, Some(&ino.to_be_bytes())).await?;
            match txn.commit().await {
                Ok(_) => return Ok(Some(entry.attr)),
                Err(KvError::Aborted { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Unlinks `name` from `parent` and drops the inode it named. The
    /// chunks go first: once the attributes are gone the inode is
    /// unreachable, so a crash the other way round would strand them with
    /// nothing left able to find them.
    async fn remove_child(&self, parent: u64, name: &OsStr, ino: u64) -> Result<(), KvError> {
        let deleted = self.delete_chunks_from(ino, 0).await;
        self.chunk_cache.lock().unwrap().invalidate_ino(ino);
        deleted?;
        let dirent = dirent_key(parent, name);
        loop {
            let txn = self.client.transaction(TXN_TTL).await?;
            txn.write(&dirent, None).await?;
            txn.write(&attr_key(ino), None).await?;
            match txn.commit().await {
                Ok(_) => return Ok(()),
                Err(KvError::Aborted { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl Filesystem for Raft5Fs {
    /// Resolves the chunk size against the store before any other method
    /// runs -- this is the one call with `&mut self`, so it can settle the
    /// field the rest of them read. Refusing the mount is the right answer
    /// to not knowing the chunk size: guessing would reinterpret every
    /// boundary in the filesystem.
    ///
    /// Unlike the `init` this once had, nothing here reads `req.uid()` --
    /// the kernel reports uid 0 during the handshake, which is why root's
    /// ownership is settled lazily in `ensure_root` instead.
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        let effective = self.resolve_chunk_size(self.chunk_size).map_err(|why| {
            eprintln!("cannot determine this filesystem's chunk size: {why}");
            std::io::Error::from_raw_os_error(libc::EINVAL)
        })?;
        if effective != self.chunk_size {
            eprintln!(
                "note: this filesystem was created with a {effective}-byte chunk size; \
                 using that rather than the requested {}",
                self.chunk_size
            );
        }
        self.chunk_size = effective;
        Ok(())
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if self.resolve(req, parent.0).is_none() {
            return reply.error(Errno::ENOENT);
        }
        let child_ino = match self.lookup_child(parent.0, name) {
            Ok(Some(ino)) => ino,
            Ok(None) => return reply.error(Errno::ENOENT),
            Err(_) => return reply.error(Errno::EIO),
        };
        if let Err(e) = self.flush_ino(child_ino) {
            return reply.error(e);
        }
        match self.read_entry(child_ino) {
            Some(entry) => reply.entry(&TTL, &entry.attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Err(e) = self.flush_ino(ino.0) {
            return reply.error(e);
        }
        match self.resolve(req, ino.0) {
            Some(entry) => reply.attr(&TTL, &entry.attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // Buffered bytes predate this change, so they have to be stored
        // before it applies (a truncate must cut them, not be undone by
        // them landing afterwards).
        if let Err(e) = self.flush_ino(ino.0) {
            return reply.error(e);
        }
        match self.block(self.apply_setattr(ino.0, mode, uid, gid, size, atime, mtime)) {
            Ok(Some(attr)) => reply.attr(&TTL, &attr),
            Ok(None) => reply.error(Errno::ENOENT),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let perm = (mode & !umask & 0o7777) as u16;
        match self.block(self.create_child(
            parent.0,
            name,
            FileType::Directory,
            perm,
            req.uid(),
            req.gid(),
        )) {
            Ok(Some(attr)) => reply.entry(&TTL, &attr, Generation(0)),
            Ok(None) => reply.error(Errno::EEXIST),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let child_ino = match self.lookup_child(parent.0, name) {
            Ok(Some(ino)) => ino,
            Ok(None) => return reply.error(Errno::ENOENT),
            Err(_) => return reply.error(Errno::EIO),
        };
        match self.read_entry(child_ino) {
            Some(entry) if entry.attr.kind != FileType::Directory => {
                return reply.error(Errno::ENOTDIR);
            }
            Some(_) => {}
            None => return reply.error(Errno::ENOENT),
        }

        let prefix = dirent_prefix(child_ino);
        let mut iter = self.client.key_iterator(&prefix);
        match self.block(iter.next()) {
            Ok(Some(key)) if key.starts_with(&prefix) => return reply.error(Errno::ENOTEMPTY),
            Ok(_) => {}
            Err(_) => return reply.error(Errno::EIO),
        }

        self.discard_ino(child_ino);
        match self.block(self.remove_child(parent.0, name, child_ino)) {
            Ok(()) => reply.ok(),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let child_ino = match self.lookup_child(parent.0, name) {
            Ok(Some(ino)) => ino,
            Ok(None) => return reply.error(Errno::ENOENT),
            Err(_) => return reply.error(Errno::EIO),
        };
        match self.read_entry(child_ino) {
            Some(entry) if entry.attr.kind == FileType::Directory => {
                return reply.error(Errno::EISDIR);
            }
            Some(_) => {}
            None => return reply.error(Errno::ENOENT),
        }

        self.discard_ino(child_ino);
        match self.block(self.remove_child(parent.0, name, child_ino)) {
            Ok(()) => reply.ok(),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let perm = (mode & !umask & 0o7777) as u16;
        match self.block(self.create_child(
            parent.0,
            name,
            FileType::RegularFile,
            perm,
            req.uid(),
            req.gid(),
        )) {
            Ok(Some(attr)) => reply.created(
                &TTL,
                &attr,
                Generation(0),
                FileHandle(0),
                FopenFlags::empty(),
            ),
            Ok(None) => reply.error(Errno::EEXIST),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if self.read_entry(ino.0).is_none() {
            return reply.error(Errno::ENOENT);
        }
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        // End-of-file lives in the attributes, not in the chunks: an
        // absent chunk is a hole, not the end, so the size has to come
        // from here before any of the data does.
        if let Err(e) = self.flush_ino(ino.0) {
            return reply.error(e);
        }
        let Some(entry) = self.read_entry(ino.0) else {
            return reply.error(Errno::ENOENT);
        };
        match self.block(self.read_range(ino.0, offset, size as usize, entry.attr.size)) {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if self.write_buffering {
            return match self.buffered_write(ino.0, offset, data) {
                Ok(n) => reply.written(n as u32),
                Err(e) => reply.error(e),
            };
        }
        match self.block(self.committer().write_range(ino.0, offset, data)) {
            Ok(Some(_)) => reply.written(data.len() as u32),
            Ok(None) => reply.error(Errno::ENOENT),
            Err(WriteError { written: 0 }) => reply.error(Errno::EIO),
            Err(WriteError { written }) => reply.written(written as u32),
        }
    }

    /// Called on every `close()` of a descriptor. Storing buffered writes
    /// here is what lets a failure reach the application that wrote them.
    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.sync_ino(ino.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.sync_ino(ino.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // `flush` normally got here first; this covers a release without
        // one, and the error is best-effort since `close()` never sees it.
        let result = self.sync_ino(ino.0);
        self.prune_slot(ino.0);
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// Unmount: nothing after this can store what is still buffered.
    fn destroy(&mut self) {
        let inos: Vec<u64> = self.write_bufs.lock().unwrap().keys().copied().collect();
        for ino in inos {
            if let Err(e) = self.sync_ino(ino) {
                eprintln!("failed to store buffered writes to inode {ino}: {e:?}");
            }
        }
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(entry) = self.resolve(req, ino.0) else {
            return reply.error(Errno::ENOENT);
        };
        if entry.attr.kind != FileType::Directory {
            return reply.error(Errno::ENOTDIR);
        }

        let mut items: Vec<(u64, FileType, OsString)> = vec![
            (ino.0, FileType::Directory, OsString::from(".")),
            (entry.parent, FileType::Directory, OsString::from("..")),
        ];

        let prefix = dirent_prefix(ino.0);
        let mut iter = self.client.key_iterator(&prefix);
        loop {
            let key = match self.block(iter.next()) {
                Ok(Some(key)) if key.starts_with(&prefix) => key,
                Ok(_) => break,
                Err(_) => return reply.error(Errno::EIO),
            };
            let name = OsStr::from_bytes(&key[prefix.len()..]).to_os_string();
            let value = match self.block(self.client.read(&key)) {
                Ok(r) => r.value,
                Err(_) => return reply.error(Errno::EIO),
            };
            // A concurrent unlink/rmdir between the key_iterator batch and
            // this read is the only way `value` comes back empty; skip it.
            let Some(bytes) = value else { continue };
            let child_ino = u64::from_be_bytes(bytes.try_into().unwrap());
            let kind = self
                .read_entry(child_ino)
                .map(|e| e.attr.kind)
                .unwrap_or(FileType::RegularFile);
            items.push((child_ino, kind, name));
        }

        for (i, (child_ino, kind, name)) in items.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(child_ino), (i + 1) as u64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(chunk_size: u64, offset: u64, len: usize) -> Vec<(u64, usize, usize)> {
        chunk_spans(chunk_size, offset, len).collect()
    }

    #[test]
    fn a_zero_length_range_touches_nothing() {
        assert!(spans(1024, 0, 0).is_empty());
        assert!(spans(1024, 5000, 0).is_empty());
    }

    #[test]
    fn a_range_inside_one_chunk_is_one_span() {
        assert_eq!(spans(1024, 0, 10), vec![(0, 0, 10)]);
        assert_eq!(spans(1024, 100, 10), vec![(0, 100, 10)]);
        assert_eq!(spans(1024, 1024, 10), vec![(1, 0, 10)]);
    }

    #[test]
    fn a_range_exactly_filling_a_chunk_is_one_span() {
        assert_eq!(spans(1024, 0, 1024), vec![(0, 0, 1024)]);
        assert_eq!(spans(1024, 2048, 1024), vec![(2, 0, 1024)]);
    }

    #[test]
    fn a_range_crossing_a_boundary_splits() {
        assert_eq!(spans(1024, 1020, 8), vec![(0, 1020, 4), (1, 0, 4)]);
        assert_eq!(spans(1024, 0, 1025), vec![(0, 0, 1024), (1, 0, 1)]);
    }

    #[test]
    fn a_range_spanning_several_chunks_covers_each() {
        assert_eq!(
            spans(1024, 512, 2048),
            vec![(0, 512, 512), (1, 0, 1024), (2, 0, 512)]
        );
    }

    #[test]
    fn spans_cover_the_range_exactly() {
        for &(offset, len) in &[(0u64, 5000usize), (1023, 3000), (4095, 1), (100, 8192)] {
            let spans = spans(1024, offset, len);
            assert_eq!(spans.iter().map(|s| s.2).sum::<usize>(), len);
            let mut pos = offset;
            for (index, within, n) in spans {
                assert_eq!(index * 1024 + within as u64, pos);
                pos += n as u64;
            }
        }
    }

    #[test]
    fn chunk_keys_sort_in_index_order() {
        let mut keys: Vec<_> = [5u64, 0, 300, 1, 70000]
            .iter()
            .map(|&i| chunk_key(9, i))
            .collect();
        keys.sort();
        let expected: Vec<_> = [0u64, 1, 5, 300, 70000]
            .iter()
            .map(|&i| chunk_key(9, i))
            .collect();
        assert_eq!(keys, expected);
    }

    #[test]
    fn a_chunk_key_is_only_recognized_for_its_own_inode() {
        let prefix = chunk_prefix(9);
        assert!(is_chunk_key(&chunk_key(9, 0), &prefix));
        assert!(!is_chunk_key(&chunk_key(10, 0), &prefix));
        // The pre-chunking layout kept a whole file under this key.
        assert!(!is_chunk_key(&chunk_prefix(9), &prefix));
    }

    #[test]
    fn batches_respect_both_the_byte_and_the_chunk_cap() {
        // Small chunks: the count cap binds, which is the point of having
        // it -- the byte budget alone would allow a thousand keys here.
        assert_eq!(chunks_per_batch(MIN_CHUNK_SIZE), MAX_BATCH_CHUNKS);
        assert_eq!(chunks_per_batch(64 * 1024), MAX_BATCH_CHUNKS);

        // Where the two caps meet.
        assert_eq!(
            chunks_per_batch(MAX_BATCH_BYTES / MAX_BATCH_CHUNKS as u64),
            16
        );

        // Large chunks: the byte budget binds.
        assert_eq!(chunks_per_batch(DEFAULT_CHUNK_SIZE), 4);
        assert_eq!(chunks_per_batch(MAX_BATCH_BYTES), 1);

        // A chunk bigger than the whole budget still gets a transaction,
        // rather than rounding down to none.
        assert_eq!(chunks_per_batch(MAX_CHUNK_SIZE), 1);

        for size in [
            MIN_CHUNK_SIZE,
            64 * 1024,
            DEFAULT_CHUNK_SIZE,
            MAX_CHUNK_SIZE,
        ] {
            let bytes = batch_bytes(size);
            assert!(chunks_per_batch(size) <= MAX_BATCH_CHUNKS, "size {size}");
            // The one permitted overshoot is a lone chunk, which the
            // `MAX_CHUNK_SIZE` assert covers instead.
            assert!(
                bytes <= MAX_BATCH_BYTES || chunks_per_batch(size) == 1,
                "size {size} batches {bytes} bytes"
            );
            assert!(bytes + TXN_SLACK <= SERVER_TXN_LIMIT, "size {size}");
        }
    }

    #[test]
    fn chunk_sizes_are_powers_of_two_within_range() {
        assert!(validate_chunk_size(DEFAULT_CHUNK_SIZE).is_ok());
        assert!(validate_chunk_size(MIN_CHUNK_SIZE).is_ok());
        assert!(validate_chunk_size(MAX_CHUNK_SIZE).is_ok());
        assert!(validate_chunk_size(64 * 1024).is_ok());

        assert!(validate_chunk_size(0).is_err());
        assert!(validate_chunk_size(1000).is_err());
        assert!(validate_chunk_size(MIN_CHUNK_SIZE / 2).is_err());
        assert!(validate_chunk_size(MAX_CHUNK_SIZE * 2).is_err());
    }
}
