use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    KernelConfig, LockOwner, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use raft5_client::{Client, Error as KvError};
use tokio::runtime::Handle;

const ROOT_INO: u64 = 1;
const TTL: Duration = Duration::from_secs(1);
const TXN_TTL: Duration = Duration::from_secs(10);
const COUNTER_KEY: &[u8] = b"\x00next_ino";

/// Keys deleted per transaction when tearing down a file's chunks. Each
/// buffered write is its own round trip, so this bounds how long one
/// transaction stays open against its (absolute, 15 s maximum) deadline.
const DELETE_BATCH: usize = 256;

/// Records the chunk size a filesystem was created with, so later mounts
/// adopt it rather than reinterpreting every chunk boundary.
pub const CHUNK_SIZE_KEY: &[u8] = b"\x00chunk_size";

pub const DEFAULT_CHUNK_SIZE: u64 = 1 << 20;
pub const MIN_CHUNK_SIZE: u64 = 4096;
/// `raft5_client` reads through a tonic client that never raises tonic's
/// default decode limit, and a `ReadResponse` wraps the value in ~25
/// bytes of framing -- so a chunk at that limit would write fine and then
/// be impossible to read back. 2 MiB is the largest power of two that
/// clears the ceiling.
pub const MAX_CHUNK_SIZE: u64 = 2 << 20;

/// tonic's default `max_decoding_message_size`, which `raft5_client`
/// leaves alone (`raft5-client/src/routing.rs`). Nothing we store may
/// approach it, because a value that exceeds it can be written and then
/// never read back.
const CLIENT_READ_LIMIT: u64 = 4 * 1024 * 1024;
const _: () = assert!(MAX_CHUNK_SIZE < CLIENT_READ_LIMIT);

// Key layout in the KV store:
//   0x00 ++ name                        -> filesystem-wide singletons
//   0x01 ++ ino(BE8)                    -> encoded Entry (attributes + parent)
//   0x02 ++ ino(BE8) ++ index(BE8)      -> one chunk of a file's data
//   0x03 ++ parent(BE8) ++ name         -> child ino(BE8), one per directory entry
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

pub struct Raft5Fs {
    client: Client,
    rt: Handle,
    /// The size requested by the caller until `init` resolves it against
    /// whatever the store already records, and the size actually in force
    /// after that.
    chunk_size: u64,
}

impl Raft5Fs {
    pub fn new(client: Client, rt: Handle, chunk_size: u64) -> Self {
        Self {
            client,
            rt,
            chunk_size,
        }
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
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
            if let Some(stored) = self.client.read(&chunk_key(ino, index)).await?.value
                && within < stored.len()
            {
                let end = (within + n).min(stored.len());
                out[cursor..cursor + (end - within)].copy_from_slice(&stored[within..end]);
            }
            cursor += n;
        }
        Ok(out)
    }

    /// Splices `data` in at `offset` and updates the attributes to match,
    /// all in one transaction: reading the attributes inside it takes
    /// their lock, so concurrent writers to one file serialize instead of
    /// clobbering each other's size. `Ok(None)` means there is no such
    /// inode.
    async fn write_range(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Option<FileAttr>, KvError> {
        loop {
            let txn = self.client.transaction(TXN_TTL).await?;
            let Some(bytes) = txn.read(&attr_key(ino)).await?.value else {
                return Ok(None);
            };
            let mut entry = decode_entry(ino, &bytes);

            let mut cursor = 0usize;
            for (index, within, n) in chunk_spans(self.chunk_size, offset, data.len()) {
                let key = chunk_key(ino, index);
                let slice = &data[cursor..cursor + n];
                cursor += n;

                // A write covering a whole chunk replaces it outright, so
                // there is nothing to preserve and nothing to read first.
                // This is the path aligned sequential writes take.
                if within == 0 && n as u64 == self.chunk_size {
                    txn.write(&key, Some(slice)).await?;
                    continue;
                }

                let mut buf = txn.read(&key).await?.value.unwrap_or_default();
                // Covers both a hole ahead of `within` and extending the
                // chunk to hold the new bytes.
                if buf.len() < within + n {
                    buf.resize(within + n, 0);
                }
                buf[within..within + n].copy_from_slice(slice);
                txn.write(&key, Some(&buf)).await?;
            }

            let end = offset + data.len() as u64;
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
                Ok(_) => return Ok(Some(entry.attr)),
                Err(KvError::Aborted { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
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
            self.delete_chunks_from(ino, first_dead).await?;
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
                Ok(_) => return Ok(Some(entry.attr)),
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
        self.delete_chunks_from(ino, 0).await?;
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
        match self.read_entry(child_ino) {
            Some(entry) => reply.entry(&TTL, &entry.attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
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
        match self.block(self.write_range(ino.0, offset, data)) {
            Ok(Some(_)) => reply.written(data.len() as u32),
            Ok(None) => reply.error(Errno::ENOENT),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
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
