//! The FUSE front end: turns kernel requests into calls to the filesystem
//! servers, through the vault (see `vault`), which seals and opens what
//! goes to and comes from them, and buffers small writes on the way. All
//! store logic lives behind the servers; what stays here is what belongs
//! to a client -- the write buffers, the auto-flush timer, the virtual
//! root, and mapping errors to errnos.
//!
//! `/.snapshot`, which the root doesn't list, holds the filesystem's
//! snapshots, read-only (see `snapshot_tree`).
//!
//! There are no owners in the filesystem: access goes by grants. A mount
//! shows the local user who made it as the owner of everything, and
//! refuses to give anything to anyone else.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use raft5fs_proto::types::{Attr, DirItem, FsError, Kind, SetAttr, SetTime, WriteError};
use tokio::runtime::Handle;
use tonic::transport::ClientTlsConfig;

use crate::remote::{Credentials, Remote};
use crate::snapshot_tree::{SnapshotTree, is_snapshot_dir, is_snapshot_ino, read_only};
use crate::vault::{DEFAULT_CACHE_BYTES, VIRTUAL_ROOT, Vault};
use crate::write_buffer::WriteBuf;

const TTL: Duration = Duration::from_secs(1);

/// How long buffered bytes may sit unstored when nothing else flushes
/// them. A writer that stops short of a full batch, and neither closes nor
/// syncs, would otherwise leave them in memory indefinitely.
const AUTO_FLUSH_DELAY: Duration = Duration::from_millis(500);

fn errno(e: &FsError) -> Errno {
    Errno::from_i32(e.errno)
}

/// The access an open with `flags` asks for, as an access(2) mask.
/// `O_TRUNC` needs write access even on a read-only open.
fn open_mask(flags: OpenFlags) -> u32 {
    let mut mask = match flags.0 & libc::O_ACCMODE {
        libc::O_RDONLY => libc::R_OK,
        libc::O_WRONLY => libc::W_OK,
        _ => libc::R_OK | libc::W_OK,
    };
    if flags.0 & libc::O_TRUNC != 0 {
        mask |= libc::W_OK;
    }
    mask as u32
}

fn file_type(kind: Kind) -> FileType {
    match kind {
        Kind::Directory => FileType::Directory,
        Kind::File => FileType::RegularFile,
    }
}

fn set_time(t: TimeOrNow) -> SetTime {
    match t {
        TimeOrNow::Now => SetTime::Now,
        TimeOrNow::SpecificTime(t) => SetTime::At(t),
    }
}

/// What a committed run means for its caller: success, or the errno to
/// report. A short write counts as failure here -- a buffered run is
/// either stored or not, from the point of view of whoever is waiting.
fn commit_result(result: Result<Attr, WriteError>) -> Result<(), Errno> {
    result.map(|_| ()).map_err(|e| errno(&e.error))
}

pub struct Raft5Fs {
    rt: Handle,
    /// Servers to use, `http://host:port`; any of them will do.
    servers: Vec<String>,
    /// Who the mount logs in as.
    credentials: Credentials,
    /// How to reach the servers over TLS; `None` for plaintext.
    tls: Option<ClientTlsConfig>,
    /// How much decrypted file data to cache.
    cache_bytes: usize,
    /// Opened by `init`, before the kernel sends any other request.
    vault: OnceLock<Arc<Vault>>,
    /// Who everything seems to belong to: the local user who mounted it.
    uid: u32,
    gid: u32,
    /// The virtual root's timestamps: when the mount was made.
    mounted_at: SystemTime,
    /// Per-inode buffers of accepted-but-unstored writes. The map lock is
    /// only held to find or insert a slot, never across a network call;
    /// the slot's own lock is what serializes a file's writes and flushes.
    write_bufs: Mutex<HashMap<u64, Arc<Mutex<WriteBuf>>>>,
    write_buffering: bool,
    /// `/.snapshot` and everything under it.
    snapshots: SnapshotTree,
}

impl Raft5Fs {
    pub fn new(servers: Vec<String>, credentials: Credentials, rt: Handle) -> Self {
        let mounted_at = SystemTime::now();
        Self {
            rt,
            servers,
            credentials,
            tls: None,
            cache_bytes: DEFAULT_CACHE_BYTES,
            vault: OnceLock::new(),
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            mounted_at,
            write_bufs: Mutex::new(HashMap::new()),
            write_buffering: true,
            snapshots: SnapshotTree::new(mounted_at),
        }
    }

    /// Reaches the servers over TLS, as `tls` says.
    pub fn with_tls(mut self, tls: ClientTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Turns write buffering on or off (on by default).
    pub fn with_write_buffering(mut self, enabled: bool) -> Self {
        self.write_buffering = enabled;
        self
    }

    /// Caches up to `bytes` of decrypted file data (`DEFAULT_CACHE_BYTES`
    /// unless told otherwise; 0 caches none).
    pub fn with_cache_size(mut self, bytes: usize) -> Self {
        self.cache_bytes = bytes;
        self
    }

    fn vault(&self) -> &Arc<Vault> {
        self.vault
            .get()
            .expect("the kernel sends no request before init")
    }

    fn remote(&self) -> &Arc<Remote> {
        self.vault().remote()
    }

    fn to_file_attr(&self, a: &Attr) -> FileAttr {
        FileAttr {
            ino: INodeNo(a.ino),
            size: a.size,
            blocks: a.size.div_ceil(512),
            atime: a.atime,
            mtime: a.mtime,
            ctime: a.ctime,
            crtime: a.ctime,
            kind: file_type(a.kind),
            perm: a.perm,
            nlink: a.nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// The virtual root's attributes: a directory, as the root of a local
    /// filesystem would seem to whoever mounted it.
    fn root_attr(&self) -> Attr {
        Attr {
            ino: VIRTUAL_ROOT,
            kind: Kind::Directory,
            size: 0,
            perm: 0o755,
            nlink: 2,
            atime: self.mounted_at,
            mtime: self.mounted_at,
            ctime: self.mounted_at,
        }
    }

    fn block<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
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

    /// Commits whatever `buf` holds, synchronously. Blocks the calling
    /// thread for the round trip -- fine on a fuse thread (that's what
    /// `n_threads` > 1 is for: an unrelated file's operations don't queue
    /// up behind it).
    ///
    /// The bytes in a buffer were already reported written to the `write`
    /// calls that put them there, so a failed commit loses data those
    /// callers believe is safe. Returning the error only tells whoever
    /// happened to trigger the commit; it is also stashed in `buf.err`,
    /// where every later `write`, `flush` (and so `close`) and `fsync`
    /// reports it until `fsync` or the last close takes it -- the same
    /// promise the kernel makes for writeback errors. Without this, a later
    /// commit succeeding would let `fsync` report success over the gap.
    fn commit_buf(&self, buf: &mut WriteBuf) -> Result<(), Errno> {
        let Some((start, data)) = buf.take() else {
            return Ok(());
        };
        let committed = commit_result(self.block(self.vault().write(buf.ino, start, &data)));
        if let Err(e) = committed {
            buf.err.get_or_insert(e);
        }
        committed
    }

    /// Arranges for `ino`'s buffer to be committed within `AUTO_FLUSH_DELAY`
    /// even if nothing else asks for it, so a writer that stops short of a
    /// full batch and neither closes nor syncs does not leave its bytes in
    /// memory indefinitely. Called when a buffer goes from empty to
    /// holding something.
    ///
    /// One-shot, and nothing cancels it: if the buffer is flushed by any
    /// other route first, the timer finds it empty and does nothing. If a
    /// later run has started by then, flushing that one early is harmless
    /// -- sooner is always safe -- and the timer it scheduled for itself
    /// then finds nothing to do. `destroy` drains every buffer before an
    /// unmount completes, so correctness never rests on this firing.
    fn schedule_auto_flush(&self, slot: Arc<Mutex<WriteBuf>>) {
        let vault = Arc::clone(self.vault());
        let rt = self.rt.clone();
        // `spawn_blocking`, not `spawn`: the commit has to hold this
        // buffer's lock for its whole duration, exactly like every other
        // commit path (`commit_buf`'s callers all keep their `MutexGuard`
        // held across it too) -- otherwise a fresh write on another fuse
        // thread can acquire the lock the moment it's free, start its own
        // commit, and race this one, both touching the same attributes.
        //
        // A plain async task can't hold a `std::sync::MutexGuard` across
        // an `.await` (it isn't `Send`). `spawn_blocking` runs this on a
        // thread outside the async worker pool, where blocking for the
        // round trip -- via an ordinary `lock()` and `Handle::block_on`,
        // the same combination every fuse thread already uses -- costs
        // nothing else waiting on those workers.
        self.rt.spawn_blocking(move || {
            std::thread::sleep(AUTO_FLUSH_DELAY);
            let mut buf = slot.lock().unwrap();
            let Some((start, data)) = buf.take() else {
                return;
            };
            let stored = rt.block_on(vault.write(buf.ino, start, &data));
            if let Err(e) = commit_result(stored) {
                // No one is synchronously waiting on this commit, so the
                // failure has nowhere to go but back into the buffer, for
                // the next flush/fsync/write to report.
                buf.err.get_or_insert(e);
            }
        });
    }

    /// Commits `ino`'s buffered writes, if any. Called before anything
    /// that must observe them: reads, attribute queries, truncation. A
    /// stashed error (from an earlier failed commit) is reported but left
    /// in place for `fsync` or `release` to take, matching how a `read`
    /// surfaces a pending write failure without being the thing that
    /// clears it.
    fn flush_ino(&self, ino: u64) -> Result<(), Errno> {
        if let Some(slot) = self.existing_write_slot(ino) {
            let mut buf = slot.lock().unwrap();
            self.commit_buf(&mut buf)?;
            if let Some(e) = buf.err {
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
        let committed = self.commit_buf(&mut buf);
        // Taken whether or not this commit failed: if it did, the error
        // is stashed too, and this is the call that reports it.
        match buf.err.take() {
            Some(e) => Err(e),
            None => committed,
        }
    }

    /// Drops `ino`'s buffered writes because the file has been deleted.
    ///
    /// Not what keeps chunks from leaking -- the store's deletion mark
    /// does that, for every client at once, and a buffer committed after
    /// it just gets `ENOENT` back. This only spares that wasted commit and
    /// the error it would leave stashed.
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
                .is_ok_and(|b| b.is_empty() && b.err.is_none())
        {
            bufs.remove(&ino);
        }
    }

    /// Accepts `data` at `offset` into `ino`'s buffer, committing the run
    /// when it fills a batch or stops being contiguous -- or, failing
    /// both, when `AUTO_FLUSH_DELAY` has passed. A write already big
    /// enough to fill a batch is committed directly, since there is
    /// nothing left to coalesce it with.
    ///
    /// Returns how many bytes were durably accepted: all of them on
    /// success, or on a failed commit just the bytes from earlier in this
    /// same call whose own commit (if any) already succeeded.
    fn buffered_write(&self, ino: u64, mut offset: u64, mut data: &[u8]) -> Result<usize, Errno> {
        let batch_bytes = self.remote().batch_bytes();
        let slot = self.write_slot(ino);
        let mut buf = slot.lock().unwrap();
        // Reported, not taken: until `fsync` (or the last close) takes it,
        // every write fails. Taking it here would let one write absorb a
        // loss that earlier writes were told was safe -- often one the
        // kernel issued on its own to finish a short write -- and then
        // `fsync`, the call that promises durability and the one many
        // programs actually check, would report success over it.
        if let Some(e) = buf.err {
            return Err(e);
        }

        if data.len() as u64 >= batch_bytes {
            // Committed directly, so whatever was buffered ahead of it has
            // to land first.
            self.commit_buf(&mut buf)?;
            return direct_write_result(
                self.block(self.vault().write(ino, offset, data)),
                data.len(),
            );
        }

        // Only ever appended for iterations of this call whose own commit
        // (if one was triggered) has already succeeded, so it is always
        // safe to report as written.
        let mut written = 0usize;
        while !data.is_empty() {
            // Can only be true on this loop's first iteration: `offset` is
            // otherwise always exactly what the previous iteration just
            // appended, which `accepts` by construction.
            if !buf.accepts(offset)
                && let Err(e) = self.commit_buf(&mut buf)
            {
                return if written > 0 { Ok(written) } else { Err(e) };
            }
            // Stepping to the batch grid rather than the chunk grid is
            // what lets a run span chunks, and keeps the batch it becomes
            // aligned: a sequential writer then fills every chunk of its
            // batch completely, so storing it reads nothing back.
            let room = (batch_bytes - offset % batch_bytes) as usize;
            let n = room.min(data.len());
            let idle = buf.is_empty();
            buf.append(offset, &data[..n]);
            buf.ino = ino;
            if idle {
                self.schedule_auto_flush(Arc::clone(&slot));
            }
            offset += n as u64;
            data = &data[n..];
            if offset.is_multiple_of(batch_bytes)
                && let Err(e) = self.commit_buf(&mut buf)
            {
                // A batch that held only this call's bytes lost nothing
                // anyone else was told about: this call reports it, as a
                // short write or an error, so the stash would only make
                // later writes and `fsync` fail spuriously. One that
                // started earlier (`!idle`) held bytes previous calls were
                // told are written, and keeps its stash.
                if idle {
                    buf.err = None;
                }
                return if written > 0 { Ok(written) } else { Err(e) };
            }
            written += n;
        }
        Ok(written)
    }

    /// Whether `uid`/`gid` would hand something to someone other than the
    /// mount's user, which can't be done: there are no owners to change.
    /// Asking for the mount's own user changes nothing, and is fine.
    fn foreign_owner(&self, uid: Option<u32>, gid: Option<u32>) -> bool {
        uid.is_some_and(|u| u != self.uid) || gid.is_some_and(|g| g != self.gid)
    }
}

/// The result of an unbuffered write of `total` bytes: all of them, a
/// short count if some batches landed before a failure, or the error if
/// none did.
fn direct_write_result(result: Result<Attr, WriteError>, total: usize) -> Result<usize, Errno> {
    match result {
        Ok(_) => Ok(total),
        Err(WriteError { written: 0, error }) => Err(errno(&error)),
        Err(WriteError { written, .. }) => Ok(written),
    }
}

impl Filesystem for Raft5Fs {
    /// Connects to the servers, logs in and opens the account's keys
    /// before any other method runs -- this is the one call with `&mut
    /// self`. With no server reachable there is no filesystem to mount,
    /// and no chunk size to buffer writes against.
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        let remote = self
            .block(Remote::connect(
                &self.servers,
                self.credentials.clone(),
                self.tls.clone(),
            ))
            .map_err(|why| {
                eprintln!("cannot connect to the filesystem: {why}");
                std::io::Error::from_raw_os_error(libc::EHOSTUNREACH)
            })?;
        let vault = Vault::new(Arc::new(remote))
            .map_err(|e| {
                eprintln!("cannot open the account's keys: {e}");
                std::io::Error::from_raw_os_error(libc::EACCES)
            })?
            .with_cache_size(self.cache_bytes);
        let _ = self.vault.set(Arc::new(vault));
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let vault = self.vault();
        if parent.0 == VIRTUAL_ROOT && is_snapshot_dir(name) {
            let attr = self.snapshots.list_attr();
            return reply.entry(&TTL, &self.to_file_attr(&attr), Generation(0));
        }
        if is_snapshot_ino(parent.0) {
            return match self.block(self.snapshots.lookup(vault, parent.0, name)) {
                Ok(attr) => reply.entry(&TTL, &self.to_file_attr(&attr), Generation(0)),
                Err(e) => reply.error(errno(&e)),
            };
        }
        let found = if parent.0 == VIRTUAL_ROOT {
            self.block(async {
                let ino = vault.root_lookup(name).await?;
                self.remote().getattr(ino).await
            })
        } else {
            self.block(vault.lookup(parent.0, name))
        };
        let mut attr = match found {
            Ok(attr) => attr,
            Err(e) => return reply.error(errno(&e)),
        };
        // Buffered writes can make the stored size stale; store them and
        // look again so the kernel learns the size the caller will see.
        if self.existing_write_slot(attr.ino).is_some() {
            if let Err(e) = self.flush_ino(attr.ino) {
                return reply.error(e);
            }
            attr = match self.block(self.remote().getattr(attr.ino)) {
                Ok(attr) => attr,
                Err(e) => return reply.error(errno(&e)),
            };
        }
        reply.entry(&TTL, &self.to_file_attr(&attr), Generation(0));
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino.0 == VIRTUAL_ROOT {
            return reply.attr(&TTL, &self.to_file_attr(&self.root_attr()));
        }
        if is_snapshot_ino(ino.0) {
            return match self.block(self.snapshots.getattr(ino.0)) {
                Ok(attr) => reply.attr(&TTL, &self.to_file_attr(&attr)),
                Err(e) => reply.error(errno(&e)),
            };
        }
        if let Err(e) = self.flush_ino(ino.0) {
            return reply.error(e);
        }
        match self.block(self.remote().getattr(ino.0)) {
            Ok(attr) => reply.attr(&TTL, &self.to_file_attr(&attr)),
            Err(e) => reply.error(errno(&e)),
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
        if is_snapshot_ino(ino.0) {
            return reply.error(errno(&read_only()));
        }
        if ino.0 == VIRTUAL_ROOT || self.foreign_owner(uid, gid) {
            return reply.error(Errno::EPERM);
        }
        // Buffered bytes predate this change, so they have to be stored
        // before it applies (a truncate must cut them, not be undone by
        // them landing afterwards).
        if let Err(e) = self.flush_ino(ino.0) {
            return reply.error(e);
        }
        let changes = SetAttr {
            mode,
            size,
            atime: atime.map(set_time),
            mtime: mtime.map(set_time),
        };
        match self.block(self.vault().setattr(ino.0, changes)) {
            Ok(attr) => reply.attr(&TTL, &self.to_file_attr(&attr)),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if is_snapshot_ino(parent.0) {
            return reply.error(errno(&read_only()));
        }
        let perm = (mode & !umask & 0o7777) as u16;
        let made = if parent.0 == VIRTUAL_ROOT {
            self.block(self.vault().create_volume(name, perm))
        } else {
            self.block(self.vault().mkdir(parent.0, name, perm))
        };
        match made {
            Ok(attr) => reply.entry(&TTL, &self.to_file_attr(&attr), Generation(0)),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if is_snapshot_ino(parent.0) || (parent.0 == VIRTUAL_ROOT && is_snapshot_dir(name)) {
            return reply.error(errno(&read_only()));
        }
        let removed = if parent.0 == VIRTUAL_ROOT {
            self.block(self.vault().delete_volume(name))
        } else {
            self.block(self.vault().rmdir(parent.0, name)).map(drop)
        };
        match removed {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if is_snapshot_ino(parent.0) {
            return reply.error(errno(&read_only()));
        }
        if parent.0 == VIRTUAL_ROOT {
            return reply.error(Errno::EPERM);
        }
        match self.block(self.vault().unlink(parent.0, name)) {
            Ok(ino) => {
                // Anything still buffered for it can only fail now (the
                // store refuses writes to a deleted inode); drop it rather
                // than leave that failure stashed.
                self.discard_ino(ino);
                reply.ok()
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        // Exchanging two names isn't supported; `EINVAL` is what the
        // kernel expects from a filesystem without it.
        if !(flags - RenameFlags::RENAME_NOREPLACE).is_empty() {
            return reply.error(Errno::EINVAL);
        }
        let noreplace = flags.contains(RenameFlags::RENAME_NOREPLACE);
        // Out of a snapshot into the live filesystem, or the reverse, is a
        // move between filesystems, which `mv` knows to do as a copy; within
        // one, nothing moves.
        match (is_snapshot_ino(parent.0), is_snapshot_ino(newparent.0)) {
            (true, true) => return reply.error(errno(&read_only())),
            (true, false) | (false, true) => return reply.error(Errno::EXDEV),
            (false, false) => {}
        }
        // The virtual root's entries are grants, not names to move.
        if parent.0 == VIRTUAL_ROOT || newparent.0 == VIRTUAL_ROOT {
            return reply.error(Errno::EPERM);
        }
        let renamed =
            self.block(
                self.vault()
                    .rename(parent.0, name, newparent.0, newname, noreplace),
            );
        match renamed {
            Ok(replaced) => {
                // As for `unlink`: what was buffered for a replaced file
                // can only fail now.
                if let Some(ino) = replaced {
                    self.discard_ino(ino);
                }
                reply.ok()
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    /// The new file is open for both reading and writing whatever its new
    /// mode says: writing a read-only file through the descriptor that
    /// created it is ordinary (it is how `cp` copies one). Nothing checks
    /// the mode anyway -- grants decide -- so no handle is needed to say so.
    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if is_snapshot_ino(parent.0) {
            return reply.error(errno(&read_only()));
        }
        if parent.0 == VIRTUAL_ROOT {
            return reply.error(Errno::EPERM);
        }
        let perm = (mode & !umask & 0o7777) as u16;
        match self.block(self.vault().create(parent.0, name, perm)) {
            Ok(attr) => reply.created(
                &TTL,
                &self.to_file_attr(&attr),
                Generation(0),
                FileHandle(0),
                FopenFlags::empty(),
            ),
            Err(e) => reply.error(errno(&e)),
        }
    }

    /// Checks the grant allows what the open asks for, so `open(2)` fails
    /// up front as it does locally. Reads and writes are checked again on
    /// their own, so the handle carries nothing.
    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if ino.0 == VIRTUAL_ROOT {
            return reply.error(Errno::EISDIR);
        }
        let access = if is_snapshot_ino(ino.0) {
            self.block(self.snapshots.access(ino.0, open_mask(flags)))
        } else {
            self.block(self.remote().access(ino.0, open_mask(flags)))
        };
        match access {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
            Err(e) => reply.error(errno(&e)),
        }
    }

    /// As `open`, for `opendir(3)`.
    fn opendir(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if ino.0 == VIRTUAL_ROOT {
            return reply.opened(FileHandle(0), FopenFlags::empty());
        }
        let access = if is_snapshot_ino(ino.0) {
            self.block(self.snapshots.access(ino.0, open_mask(flags)))
        } else {
            self.block(self.remote().access(ino.0, open_mask(flags)))
        };
        match access {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
            Err(e) => reply.error(errno(&e)),
        }
    }

    /// Mounted without `default_permissions`, the kernel checks nothing
    /// itself and asks here instead. Answering is what makes access(2) --
    /// and so `test -w` -- agree with what the servers will actually allow.
    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        // Anyone may list the virtual root, and make volumes in it.
        if ino.0 == VIRTUAL_ROOT {
            return reply.ok();
        }
        let access = if is_snapshot_ino(ino.0) {
            self.block(self.snapshots.access(ino.0, mask.bits() as u32))
        } else {
            self.block(self.remote().access(ino.0, mask.bits() as u32))
        };
        match access {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
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
        let read = if is_snapshot_ino(ino.0) {
            self.block(self.snapshots.read(ino.0, offset, size as usize))
        } else {
            if let Err(e) = self.flush_ino(ino.0) {
                return reply.error(e);
            }
            self.block(self.vault().read(ino.0, offset, size as usize))
        };
        match read {
            Ok(data) => reply.data(&data),
            Err(e) => {
                if e.errno != libc::ENOENT {
                    eprintln!("read from inode {} at offset {offset} failed: {e}", ino.0);
                }
                reply.error(errno(&e))
            }
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
        if is_snapshot_ino(ino.0) {
            return reply.error(errno(&read_only()));
        }
        let result = if self.write_buffering {
            self.buffered_write(ino.0, offset, data)
        } else {
            direct_write_result(
                self.block(self.vault().write(ino.0, offset, data)),
                data.len(),
            )
        };
        match result {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(e),
        }
    }

    /// Called on every `close()` of a descriptor. Storing buffered writes
    /// here is what lets a failure reach the application that wrote them.
    ///
    /// Reports a pending write error without consuming it. FLUSH comes
    /// from *every* close of *any* copy of a descriptor -- including the
    /// copies a forked child inherits and closes on exec, which happens
    /// whenever some other process on the machine forks. If this took the
    /// error, a stranger's close could receive it and drop it, and the
    /// application's own `fsync` would then report success over lost data.
    /// `fsync` consumes it; `release`, when the last descriptor goes,
    /// clears it.
    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.flush_ino(ino.0) {
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
        // The last descriptor is gone, so this is where a pending error is
        // finally taken: no one is left to report it to. Best-effort, since
        // `close()` never sees what `release` returns.
        let result = self.sync_ino(ino.0);
        self.prune_slot(ino.0);
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// Unmount: nothing after this can store what is still buffered.
    fn destroy(&mut self) {
        if self.vault.get().is_none() {
            return;
        }
        let inos: Vec<u64> = self.write_bufs.lock().unwrap().keys().copied().collect();
        for ino in inos {
            if let Err(e) = self.sync_ino(ino) {
                eprintln!("failed to store buffered writes to inode {ino}: {e:?}");
            }
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let vault = self.vault();
        let items = if is_snapshot_ino(ino.0) {
            match self.block(self.snapshots.readdir(vault, VIRTUAL_ROOT, ino.0)) {
                Ok(items) => items,
                Err(e) => return reply.error(errno(&e)),
            }
        } else if ino.0 == VIRTUAL_ROOT {
            match self.block(vault.root_entries()) {
                Ok(entries) => {
                    let dots = [".", ".."].map(|n| DirItem {
                        ino: VIRTUAL_ROOT,
                        kind: Kind::Directory,
                        name: n.into(),
                        sealed_name: Vec::new(),
                    });
                    dots.into_iter()
                        .chain(entries.into_iter().map(|(name, ino)| DirItem {
                            ino,
                            kind: Kind::Directory,
                            name,
                            sealed_name: Vec::new(),
                        }))
                        .collect()
                }
                Err(e) => return reply.error(errno(&e)),
            }
        } else {
            match self.block(vault.readdir(ino.0)) {
                Ok(mut items) => {
                    // A grant's `..` is the virtual root: what is really
                    // above it isn't this account's to see.
                    if vault.is_grant_root(ino.0) {
                        for item in &mut items {
                            if item.name == ".." {
                                item.ino = VIRTUAL_ROOT;
                            }
                        }
                    }
                    items
                }
                Err(e) => return reply.error(errno(&e)),
            }
        };
        for (i, item) in items.into_iter().enumerate().skip(offset as usize) {
            if reply.add(
                INodeNo(item.ino),
                (i + 1) as u64,
                file_type(item.kind),
                &item.name,
            ) {
                break;
            }
        }
        reply.ok();
    }
}
