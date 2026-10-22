//! The FUSE front end: turns kernel requests into calls to the session (see
//! `raft5fs_client::session`). The session holds everything that front ends
//! share: the write buffers, the virtual root, and `/.snapshot`. This
//! module keeps what belongs to the kernel's side: attributes in the
//! kernel's form, open flags and access masks, rename flags, and errnos.
//!
//! The filesystem has no owners: grants control access. A mount shows the
//! local user who made it as the owner of everything, and refuses to give
//! anything to anyone else.

use std::ffi::OsStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
    WriteFlags,
};
use raft5fs_client::prune_queue::PruneQueue;
use raft5fs_client::pruner::PrunerConfig;
use raft5fs_client::remote::Credentials;
use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_client::vault::KnownKeys;
use raft5fs_proto::types::{Attr, FsError, Kind, SetAttr, SetTime};
use tokio::runtime::Handle;
use tonic::transport::ClientTlsConfig;

const TTL: Duration = Duration::from_secs(1);

/// The block size that `statfs` counts in.
const BLOCK_SIZE: u32 = 4096;

fn errno(e: &FsError) -> Errno {
    // Not a kernel errno: the session retries on it, so it should never get
    // here.
    if e.errno == raft5fs_proto::errno::EKEYEXPIRED {
        return Errno::EIO;
    }
    Errno::from_i32(e.errno)
}

/// The access that an open with `flags` asks for, as an access(2) mask.
/// `O_TRUNC` needs write access, even on a read-only open.
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

/// Whether a rename with `flags` must not replace its target, or `None` if
/// it asks for something not supported. Only Linux has flags to give.
#[cfg(target_os = "linux")]
fn noreplace(flags: RenameFlags) -> Option<bool> {
    // Exchanging two names is not supported.
    (flags - RenameFlags::RENAME_NOREPLACE)
        .is_empty()
        .then(|| flags.contains(RenameFlags::RENAME_NOREPLACE))
}

#[cfg(not(target_os = "linux"))]
fn noreplace(flags: RenameFlags) -> Option<bool> {
    flags.is_empty().then_some(false)
}

pub struct Raft5Fs {
    rt: Handle,
    /// How `init` opens the session. `init` takes it.
    config: Option<SessionConfig>,
    /// Opened by `init`, before the kernel sends any other request.
    session: OnceLock<Arc<Session>>,
    /// The owner that everything shows: the local user who mounted it.
    uid: u32,
    gid: u32,
}

impl Raft5Fs {
    pub fn new(servers: Vec<String>, credentials: Credentials, rt: Handle) -> Self {
        Self::with_config(SessionConfig::new(servers, credentials), rt)
    }

    /// A mount of the session that `config` opens.
    pub fn with_config(config: SessionConfig, rt: Handle) -> Self {
        Self {
            rt,
            config: Some(config),
            session: OnceLock::new(),
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        }
    }

    fn config(&mut self) -> &mut SessionConfig {
        self.config.as_mut().expect("configured before init")
    }

    /// Connects to the servers over TLS, as `tls` says.
    pub fn with_tls(mut self, tls: ClientTlsConfig) -> Self {
        self.config().tls = Some(tls);
        self
    }

    /// Pins public keys in `known`, not in memory. The pins also decide
    /// which grants this mount trusts enough to write under.
    pub fn with_known_keys(mut self, known: KnownKeys) -> Self {
        self.config().known_keys = Some(known);
        self
    }

    /// Works through `queue` in the background while mounted, at the pace
    /// that `config` sets (see `pruner`).
    pub fn with_prune_queue(mut self, queue: PruneQueue, config: PrunerConfig) -> Self {
        self.config().prune_queue = Some((queue, config));
        self
    }

    /// Turns write buffering on or off (on by default).
    pub fn with_write_buffering(mut self, enabled: bool) -> Self {
        self.config().write_buffering = enabled;
        self
    }

    /// Caches up to `bytes` of decrypted file data (`DEFAULT_CACHE_BYTES`
    /// by default; 0 disables the cache).
    pub fn with_cache_size(mut self, bytes: usize) -> Self {
        self.config().cache_bytes = bytes;
        self
    }

    fn session(&self) -> &Arc<Session> {
        self.session
            .get()
            .expect("the kernel sends no request before init")
    }

    /// Runs `fut` to completion on this fuse thread. It blocks the thread
    /// for the round trips. That is acceptable, because `n_threads` > 1
    /// means that operations on other files do not wait behind it.
    fn block<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
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

    /// Whether `uid`/`gid` would give something to a user other than the
    /// mount's user. That is not possible, because there are no owners to
    /// change. Asking for the mount's own user changes nothing, and is
    /// allowed.
    fn foreign_owner(&self, uid: Option<u32>, gid: Option<u32>) -> bool {
        uid.is_some_and(|u| u != self.uid) || gid.is_some_and(|g| g != self.gid)
    }

    fn reply_entry(&self, reply: ReplyEntry, attr: Result<Attr, FsError>) {
        match attr {
            Ok(attr) => reply.entry(&TTL, &self.to_file_attr(&attr), Generation(0)),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn reply_attr(&self, reply: ReplyAttr, attr: Result<Attr, FsError>) {
        match attr {
            Ok(attr) => reply.attr(&TTL, &self.to_file_attr(&attr)),
            Err(e) => reply.error(errno(&e)),
        }
    }
}

fn reply_empty(reply: ReplyEmpty, result: Result<(), FsError>) {
    match result {
        Ok(()) => reply.ok(),
        Err(e) => reply.error(errno(&e)),
    }
}

fn reply_opened(reply: ReplyOpen, result: Result<(), FsError>) {
    match result {
        Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
        Err(e) => reply.error(errno(&e)),
    }
}

impl Filesystem for Raft5Fs {
    /// Opens the session (connects, logs in, and opens the account's keys)
    /// before any other method runs. This is the only call with `&mut
    /// self`.
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        let config = self.config.take().expect("init runs once");
        let session = self.block(Session::open(config)).map_err(|e| {
            eprintln!("{}", e.message);
            std::io::Error::from_raw_os_error(e.errno)
        })?;
        let _ = self.session.set(session);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.reply_entry(reply, self.block(self.session().lookup(parent.0, name)));
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.reply_attr(reply, self.block(self.session().getattr(ino.0)));
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
        if self.foreign_owner(uid, gid) {
            return reply.error(Errno::EPERM);
        }
        let changes = SetAttr {
            mode,
            size,
            atime: atime.map(set_time),
            mtime: mtime.map(set_time),
        };
        self.reply_attr(reply, self.block(self.session().setattr(ino.0, changes)));
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
        let perm = (mode & !umask & 0o7777) as u16;
        self.reply_entry(
            reply,
            self.block(self.session().mkdir(parent.0, name, perm)),
        );
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        reply_empty(reply, self.block(self.session().rmdir(parent.0, name)));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        reply_empty(reply, self.block(self.session().unlink(parent.0, name)));
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
        // The kernel expects `EINVAL` from a filesystem that does not
        // support what the flags ask for.
        let Some(noreplace) = noreplace(flags) else {
            return reply.error(Errno::EINVAL);
        };
        let renamed = self
            .session()
            .rename(parent.0, name, newparent.0, newname, noreplace);
        reply_empty(reply, self.block(renamed));
    }

    /// No handle is needed: nothing checks the mode, because grants decide.
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
        let perm = (mode & !umask & 0o7777) as u16;
        match self.block(self.session().create(parent.0, name, perm)) {
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

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        reply_opened(
            reply,
            self.block(self.session().open_file(ino.0, open_mask(flags))),
        );
    }

    /// Same as `open`, for `opendir(3)`.
    fn opendir(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        reply_opened(
            reply,
            self.block(self.session().access(ino.0, open_mask(flags))),
        );
    }

    /// The mount does not use `default_permissions`, so the kernel checks
    /// nothing itself and asks here. This answer makes access(2), and so
    /// `test -w`, agree with what the servers allow.
    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        reply_empty(
            reply,
            self.block(self.session().access(ino.0, mask.bits() as u32)),
        );
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
        match self.block(self.session().read(ino.0, offset, size as usize)) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(errno(&e)),
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
        match self.block(self.session().write(ino.0, offset, data)) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(&e)),
        }
    }

    /// Called on every `close()` of a descriptor (see `Session::flush`).
    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply_empty(reply, self.block(self.session().flush(ino.0)));
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply_empty(reply, self.block(self.session().fsync(ino.0)));
    }

    /// Best effort, because `close()` never sees what `release` returns.
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
        reply_empty(reply, self.block(self.session().release(ino.0)));
    }

    /// Unmount: nothing after this can store what is still buffered.
    fn destroy(&mut self) {
        if let Some(session) = self.session.get() {
            self.block(session.shutdown());
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let stats = self.session().statfs();
        let blocks = stats.total_bytes / BLOCK_SIZE as u64;
        let free = stats.free_bytes / BLOCK_SIZE as u64;
        reply.statfs(
            blocks,
            free,
            free,
            0,
            0,
            BLOCK_SIZE,
            stats.name_max,
            BLOCK_SIZE,
        );
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let items = match self.block(self.session().readdir(ino.0)) {
            Ok(items) => items,
            Err(e) => return reply.error(errno(&e)),
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
