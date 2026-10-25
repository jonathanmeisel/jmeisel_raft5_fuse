//! The filesystem as a front end serves it: everything that a FUSE mount
//! and a WebDAV server share. It works by inode, is async, and returns
//! errors as errnos.
//!
//! All store logic is behind the servers, and sealing and opening are in
//! the vault (see `vault`). This module has what belongs only to a client:
//!
//! - the write buffers and the auto-flush timer;
//! - the virtual root, and which changes the virtual root and `/.snapshot`
//!   refuse;
//! - `/.snapshot`, which the root does not list, with the filesystem's
//!   snapshots, read-only (see `snapshot_tree`).
//!
//! Every future here must run to completion. A future dropped half way can
//! leave a write buffer's commit half done, with no place to report its
//! error. A front end that can drop futures (hyper does, when a client goes
//! away during a request) must run them in their own tasks.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use raft5fs_proto::errno;
use raft5fs_proto::types::{Attr, DirItem, FsError, Kind, Layout, SetAttr, WriteError};

use crate::paths::Dentries;
use crate::prune_queue::PruneQueue;
use crate::pruner::{self, PrunerConfig};
use crate::remote::ClientTlsConfig;
use crate::remote::{Credentials, Remote};
use crate::rt::{self, AbortHandle};
use crate::snapshot_tree::{SnapshotTree, is_snapshot_dir, is_snapshot_ino, read_only};
use crate::vault::{DEFAULT_CACHE_BYTES, KnownKeys, VIRTUAL_ROOT, Vault};
use crate::write_buffer::WriteBuf;

/// How long buffered bytes wait, not stored, after the writer's last write,
/// when nothing else flushes them. Without this, a writer that stops
/// before a full batch, and does not close or sync, would leave them in
/// memory with no time limit. It counts from the last write, not the
/// first: a writer that keeps going fills its batch or block, and a block
/// stored in pieces is uploaded again for each piece.
const AUTO_FLUSH_DELAY: Duration = Duration::from_millis(500);

/// The longest that buffered bytes wait, however steadily a slow writer
/// keeps adding to them.
const MAX_BUFFER_AGE: Duration = Duration::from_secs(5);

/// The filesystem size that `statfs` reports, all of it free: there are no
/// quotas, and nothing to measure the store against.
const REPORTED_BYTES: u64 = 1 << 50;

/// The longest directory entry name that `statfs` reports.
const NAME_MAX: u32 = 255;

/// How to open a session.
pub struct SessionConfig {
    /// Servers to use, as `https://host:port`. Any of them will do.
    pub servers: Vec<String>,
    /// The user that the session logs in as.
    pub credentials: Credentials,
    /// How to connect to the servers over TLS. `None` for plaintext.
    pub tls: Option<ClientTlsConfig>,
    /// How much decrypted file data to cache.
    pub cache_bytes: usize,
    /// Where public keys are pinned, or `None` for memory only. The pins
    /// also decide which grants the session trusts enough to write under.
    pub known_keys: Option<KnownKeys>,
    /// The prune queue to work through in the background while the session
    /// is open, and how (see `pruner`).
    pub prune_queue: Option<(PruneQueue, PrunerConfig)>,
    /// Whether to buffer small sequential writes into batches.
    pub write_buffering: bool,
    /// Whether to refuse to create the files where macOS keeps its metadata
    /// (`._*` and `.DS_Store`) when there are no extended attributes for
    /// it. Otherwise each one is one more node sealed and stored next to
    /// every file that its user only looks at.
    pub hide_apple_double: bool,
}

impl SessionConfig {
    pub fn new(servers: Vec<String>, credentials: Credentials) -> Self {
        Self {
            servers,
            credentials,
            tls: None,
            cache_bytes: DEFAULT_CACHE_BYTES,
            known_keys: None,
            prune_queue: None,
            write_buffering: true,
            hide_apple_double: false,
        }
    }
}

/// The filesystem's size, for `statfs` and WebDAV quotas.
pub struct FsStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub name_max: u32,
}

type Slot = Arc<tokio::sync::Mutex<WriteBuf>>;

/// What a committed run means for its caller: success, or the error to
/// report. A short write counts as a failure here: for the caller that
/// waits on it, a buffered run is stored or not.
fn commit_result(ino: u64, start: u64, result: Result<Attr, WriteError>) -> Result<(), FsError> {
    result.map(|_| ()).map_err(|e| {
        eprintln!("write to inode {ino} at offset {start} failed: {}", e.error);
        e.error
    })
}

/// The result of an unbuffered write of `total` bytes: all of them, a short
/// count if some batches were stored before a failure, or the error if none
/// were.
fn direct_write_result(result: Result<Attr, WriteError>, total: usize) -> Result<usize, FsError> {
    match result {
        Ok(_) => Ok(total),
        Err(WriteError { written: 0, error }) => Err(error),
        Err(WriteError { written, .. }) => Ok(written),
    }
}

/// Whether `name` is one of the files where macOS keeps metadata.
fn is_apple_double(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    name.starts_with(b"._") || name == b".DS_Store"
}

pub struct Session {
    vault: Arc<Vault>,
    /// The task that works through the prune queue, if there is one.
    pruner: Mutex<Option<AbortHandle>>,
    /// The virtual root's timestamps: when the session was opened.
    opened_at: SystemTime,
    /// Buffers of writes that were accepted but not stored, one for each
    /// inode. The map lock is only held to find or insert a slot, never
    /// across an `.await`. The slot's own lock puts a file's writes and
    /// flushes in order, and is held across the commit's round trip.
    write_bufs: Mutex<HashMap<u64, Slot>>,
    write_buffering: bool,
    hide_apple_double: bool,
    /// `/.snapshot` and everything below it.
    snapshots: SnapshotTree,
    /// Names resolved by path, for front ends that use paths.
    pub(crate) dentries: Dentries,
}

impl Session {
    /// Connects to the servers, logs in, and opens the account's keys.
    /// Fails if no server is reachable: then there is no filesystem to
    /// serve, and no chunk size to buffer writes against.
    pub async fn open(config: SessionConfig) -> Result<Arc<Self>, FsError> {
        let remote = Remote::connect(&config.servers, config.credentials, config.tls)
            .await
            .map_err(|why| {
                FsError::new(
                    errno::EHOSTUNREACH,
                    format!("cannot connect to the filesystem: {why}"),
                )
            })?;
        let keys = |e: FsError| {
            FsError::new(
                errno::EACCES,
                format!("cannot decrypt this account's keys: {e}"),
            )
        };
        let mut vault = Vault::new(Arc::new(remote))
            .map_err(keys)?
            .with_cache_size(config.cache_bytes)
            .with_untrusted_warnings();
        if let Some(known) = config.known_keys {
            vault = vault.with_known_keys(known);
        }
        let pruner = match config.prune_queue {
            Some((queue, prune_config)) => {
                let pruning = Vault::new(Arc::clone(vault.remote()))
                    .map_err(keys)?
                    .with_known_keys(vault.known_keys().duplicate());
                Some(pruner::spawn(pruning, queue, prune_config))
            }
            None => None,
        };
        let opened_at = raft5fs_proto::clock::now();
        Ok(Arc::new(Self {
            vault: Arc::new(vault),
            pruner: Mutex::new(pruner),
            opened_at,
            write_bufs: Mutex::new(HashMap::new()),
            write_buffering: config.write_buffering,
            hide_apple_double: config.hide_apple_double,
            snapshots: SnapshotTree::new(opened_at),
            dentries: Dentries::default(),
        }))
    }

    pub fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    fn remote(&self) -> &Arc<Remote> {
        self.vault.remote()
    }

    /// The virtual root's attributes: a directory, as the root of a local
    /// filesystem would look to the user who opened the session.
    pub fn root_attr(&self) -> Attr {
        Attr {
            ino: VIRTUAL_ROOT,
            kind: Kind::Directory,
            size: 0,
            perm: 0o755,
            nlink: 2,
            atime: self.opened_at,
            mtime: self.opened_at,
            ctime: self.opened_at,
            layout: Layout::Inline,
        }
    }

    fn write_slot(&self, ino: u64) -> Slot {
        self.write_bufs
            .lock()
            .unwrap()
            .entry(ino)
            .or_default()
            .clone()
    }

    fn existing_write_slot(&self, ino: u64) -> Option<Slot> {
        self.write_bufs.lock().unwrap().get(&ino).cloned()
    }

    /// Commits what `buf` holds, and holds its lock for the round trip, so
    /// at most one commit of a file is in progress.
    ///
    /// The `write` calls that put bytes in a buffer already reported them
    /// as written. So a failed commit loses data that those callers think
    /// is safe. The returned error only tells the caller that triggered the
    /// commit. So the error is also stored in `buf.err`, and every later
    /// `write`, `flush` (and so `close`), and `fsync` reports it until
    /// `fsync` or the last close takes it. The kernel makes the same
    /// promise for writeback errors. Without this, a later successful
    /// commit would let `fsync` report success over the lost data.
    async fn commit_buf(&self, buf: &mut WriteBuf) -> Result<(), FsError> {
        let Some((start, data)) = buf.take() else {
            return Ok(());
        };
        let committed = commit_result(
            buf.ino,
            start,
            self.vault.write(buf.ino, start, &data).await,
        );
        if let Err(e) = &committed {
            buf.err.get_or_insert_with(|| e.clone());
        }
        committed
    }

    /// Makes sure that `ino`'s buffer is committed `AUTO_FLUSH_DELAY` after
    /// its last write, or once it is `MAX_BUFFER_AGE` old, even if nothing
    /// else asks for it. So a writer that stops before a full batch, and
    /// does not close or sync, does not leave its bytes in memory with no
    /// time limit. Called when a buffer goes from empty to not empty.
    ///
    /// - It runs one time, and nothing cancels it. If something else
    ///   flushes the buffer first, the timer finds it empty and does
    ///   nothing.
    /// - If a later run has started by then, flushing it early does no harm
    ///   (sooner is always safe), and that run's own timer then finds
    ///   nothing to do.
    /// - `shutdown` empties every buffer before the session ends, so
    ///   correctness never depends on this timer.
    fn schedule_auto_flush(&self, slot: Slot) {
        let vault = Arc::clone(&self.vault);
        rt::spawn(async move {
            let mut buf = loop {
                let wait = {
                    let buf = slot.lock().await;
                    match buf.due_in(AUTO_FLUSH_DELAY, MAX_BUFFER_AGE) {
                        None => return,
                        Some(wait) => wait,
                    }
                };
                if wait.is_zero() {
                    break slot.lock().await;
                }
                rt::sleep(wait).await;
            };
            let Some((start, data)) = buf.take() else {
                return;
            };
            let stored = vault.write(buf.ino, start, &data).await;
            if let Err(e) = commit_result(buf.ino, start, stored) {
                // No caller waits on this commit, so the only place for the
                // failure is back in the buffer, for the next flush, fsync,
                // or write to report.
                buf.err.get_or_insert(e);
            }
        });
    }

    /// Commits `ino`'s buffered writes, if any. Call it before anything
    /// that must see them (reads, truncation), and on every `close()`, so
    /// that a failure reaches the application that wrote the bytes.
    /// Attribute queries don't: they add the buffer's length (see
    /// `with_buffered`).
    ///
    /// It reports a stored error (from an earlier failed commit) but leaves
    /// it in place for `fsync` or `release` to take, as a `read` reports a
    /// pending write failure without clearing it. This matters for FUSE's
    /// FLUSH, which comes from every close of every copy of a descriptor.
    /// That includes the copies that a forked child inherits and closes on
    /// exec, which happens whenever another process on the machine forks.
    /// If this took the error, an unrelated process's close could get it
    /// and drop it, and the application's own `fsync` would then report
    /// success over lost data.
    pub async fn flush(&self, ino: u64) -> Result<(), FsError> {
        if let Some(slot) = self.existing_write_slot(ino) {
            let mut buf = slot.lock().await;
            self.commit_buf(&mut buf).await?;
            if let Some(e) = &buf.err {
                return Err(e.clone());
            }
        }
        Ok(())
    }

    /// Same as `flush`, but it also takes the error that it reports.
    pub async fn fsync(&self, ino: u64) -> Result<(), FsError> {
        let Some(slot) = self.existing_write_slot(ino) else {
            return Ok(());
        };
        let mut buf = slot.lock().await;
        let committed = self.commit_buf(&mut buf).await;
        // Take the error whether or not this commit failed. If it failed,
        // its error is stored too, and this call reports it.
        match buf.err.take() {
            Some(e) => Err(e),
            None => committed,
        }
    }

    /// The last user of `ino` is done with it, so take any pending error
    /// here: there is no one left to report it to.
    pub async fn release(&self, ino: u64) -> Result<(), FsError> {
        let result = self.fsync(ino).await;
        self.prune_slot(ino);
        result
    }

    /// Drops `ino`'s buffered writes because the file was deleted. This
    /// does not stop chunks from leaking: the store's deletion mark does
    /// that for every client, and a buffer committed after it gets
    /// `ENOENT`. This only saves that wasted commit and the error it would
    /// store.
    async fn discard_ino(&self, ino: u64) {
        if let Some(slot) = self.existing_write_slot(ino) {
            slot.lock().await.discard();
        }
    }

    /// Removes `ino`'s slot when nothing uses it or waits on it, so the map
    /// does not grow with every file ever written.
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

    /// Accepts `data` at `offset` into `ino`'s buffer.
    ///
    /// - Commits the run when it fills a batch or stops being contiguous,
    ///   or else `AUTO_FLUSH_DELAY` after the last write (at most
    ///   `MAX_BUFFER_AGE` after the first).
    /// - Commits a write that already fills a batch directly, because there
    ///   is nothing to join it with.
    ///
    /// Returns how many bytes were accepted for certain: all of them on
    /// success. On a failed commit, only the bytes from earlier in this
    /// call whose own commit (if any) already succeeded.
    async fn buffered_write(
        &self,
        ino: u64,
        mut offset: u64,
        mut data: &[u8],
    ) -> Result<usize, FsError> {
        let slot = self.write_slot(ino);
        let mut buf = slot.lock().await;
        // Report the error but do not take it: every write fails until
        // `fsync` (or the last close) takes it. If a write took it, that
        // write would hide a loss that earlier writes were told was safe
        // (often a write that the kernel sent itself to finish a short
        // write). Then `fsync`, which promises durability and which many
        // programs check, would report success over it.
        if let Some(e) = &buf.err {
            return Err(e.clone());
        }

        // The part of the file stored together with `offset`: a batch, or a
        // block after a hybrid file's grid start.
        let batch = self.vault.batch_at(ino, offset).await?;
        if data.len() as u64 >= batch.end - batch.start {
            // This write is committed directly, so anything buffered before
            // it must be stored first.
            self.commit_buf(&mut buf).await?;
            return direct_write_result(self.vault.write(ino, offset, data).await, data.len());
        }

        // Only counts bytes from iterations of this call whose own commit
        // (if any) already succeeded, so it is always safe to report them
        // as written.
        let mut written = 0usize;
        while !data.is_empty() {
            // This can only be true on the loop's first iteration. After
            // that, `offset` is always exactly what the previous iteration
            // appended, which `accepts` allows by design.
            if !buf.accepts(offset)
                && let Err(e) = self.commit_buf(&mut buf).await
            {
                return if written > 0 { Ok(written) } else { Err(e) };
            }
            // Step on the batch grid, not the chunk grid. This lets a run
            // span chunks and keeps its batch aligned. A sequential writer
            // then fills every chunk of its batch completely, so storing it
            // reads nothing back, and a block that it fills is uploaded
            // once.
            let batch = match self.vault.batch_at(ino, offset).await {
                Ok(batch) => batch,
                Err(e) => return if written > 0 { Ok(written) } else { Err(e) },
            };
            let room = (batch.end - offset) as usize;
            let n = room.min(data.len());
            let idle = buf.is_empty();
            buf.append(offset, &data[..n]);
            buf.ino = ino;
            if idle {
                self.schedule_auto_flush(Arc::clone(&slot));
            }
            offset += n as u64;
            data = &data[n..];
            if offset == batch.end
                && let Err(e) = self.commit_buf(&mut buf).await
            {
                // A batch that held only this call's bytes lost nothing
                // that another caller was told about. This call reports it,
                // as a short write or an error, so storing the error would
                // only make later writes and `fsync` fail for no reason. A
                // batch that started earlier (`!idle`) held bytes that
                // earlier calls were told are written, so it keeps its
                // stored error.
                if idle {
                    buf.err = None;
                }
                return if written > 0 { Ok(written) } else { Err(e) };
            }
            written += n;
        }
        Ok(written)
    }

    /// Ends the session. Nothing after this can store what is still
    /// buffered, so it is stored now.
    pub async fn shutdown(&self) {
        // Anything it was pruning stays in the queue for next time.
        if let Some(pruner) = self.pruner.lock().unwrap().take() {
            pruner.abort();
        }
        let inos: Vec<u64> = self.write_bufs.lock().unwrap().keys().copied().collect();
        for ino in inos {
            if let Err(e) = self.fsync(ino).await {
                eprintln!("failed to store buffered writes to inode {ino}: {e}");
            }
        }
    }

    pub async fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        if parent == VIRTUAL_ROOT && is_snapshot_dir(name) {
            return Ok(self.snapshots.list_attr());
        }
        if is_snapshot_ino(parent) {
            return self.snapshots.lookup(&self.vault, parent, name).await;
        }
        let mut attr = if parent == VIRTUAL_ROOT {
            let ino = self.vault.root_lookup(name).await?;
            self.remote().getattr(ino).await?
        } else {
            self.vault.lookup(parent, name).await?
        };
        self.with_buffered(&mut attr).await;
        Ok(attr)
    }

    /// Counts `attr`'s buffered writes in its size, without storing them.
    /// Storing them here would cut a writer's run short whenever anything
    /// looks at the file (a file manager, a shell prompt), and a block
    /// stored in pieces is uploaded again for each piece. Reads and
    /// truncation still store them first.
    async fn with_buffered(&self, attr: &mut Attr) {
        if let Some(slot) = self.existing_write_slot(attr.ino)
            && let Some(end) = slot.lock().await.end()
        {
            attr.size = attr.size.max(end);
        }
    }

    pub async fn getattr(&self, ino: u64) -> Result<Attr, FsError> {
        if ino == VIRTUAL_ROOT {
            return Ok(self.root_attr());
        }
        if is_snapshot_ino(ino) {
            return self.snapshots.getattr(ino).await;
        }
        let mut attr = self.remote().getattr(ino).await?;
        self.with_buffered(&mut attr).await;
        Ok(attr)
    }

    pub async fn setattr(&self, ino: u64, changes: SetAttr) -> Result<Attr, FsError> {
        if is_snapshot_ino(ino) {
            return Err(read_only());
        }
        if ino == VIRTUAL_ROOT {
            return Err(FsError::errno(errno::EPERM));
        }
        // Buffered bytes are older than this change, so they must be stored
        // before it. A truncate must cut them, and not be undone when they
        // are stored later.
        self.flush(ino).await?;
        self.vault.setattr(ino, changes).await
    }

    /// Makes a directory, or in the virtual root, a new volume.
    pub async fn mkdir(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        if is_snapshot_ino(parent) {
            return Err(read_only());
        }
        if parent == VIRTUAL_ROOT {
            self.vault.create_volume(name, perm).await
        } else {
            self.vault.mkdir(parent, name, perm).await
        }
    }

    /// Removes an empty directory, or in the virtual root, a volume.
    pub async fn rmdir(&self, parent: u64, name: &OsStr) -> Result<(), FsError> {
        if is_snapshot_ino(parent) || (parent == VIRTUAL_ROOT && is_snapshot_dir(name)) {
            return Err(read_only());
        }
        let removed = if parent == VIRTUAL_ROOT {
            self.vault.delete_volume(name).await
        } else {
            self.vault.rmdir(parent, name).await.map(drop)
        };
        self.dentries.forget(parent, name);
        removed
    }

    pub async fn unlink(&self, parent: u64, name: &OsStr) -> Result<(), FsError> {
        if is_snapshot_ino(parent) {
            return Err(read_only());
        }
        if parent == VIRTUAL_ROOT {
            return Err(FsError::errno(errno::EPERM));
        }
        let ino = self.vault.unlink(parent, name).await;
        self.dentries.forget(parent, name);
        // Anything still buffered for it can only fail now (the store
        // refuses writes to a deleted inode). Drop it, so no failure is
        // stored.
        self.discard_ino(ino?).await;
        Ok(())
    }

    /// Moves `name` in `parent` to `new_name` in `new_parent`, and replaces
    /// what is there unless `noreplace`.
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<(), FsError> {
        // A move from a snapshot into the live filesystem, or the reverse,
        // is a move between filesystems, which `mv` does as a copy. Inside
        // a snapshot, nothing moves.
        match (is_snapshot_ino(parent), is_snapshot_ino(new_parent)) {
            (true, true) => return Err(read_only()),
            (true, false) | (false, true) => return Err(FsError::errno(errno::EXDEV)),
            (false, false) => {}
        }
        // The virtual root's entries are grants, not names that can move.
        if parent == VIRTUAL_ROOT || new_parent == VIRTUAL_ROOT {
            return Err(FsError::errno(errno::EPERM));
        }
        let renamed = self
            .vault
            .rename(parent, name, new_parent, new_name, noreplace)
            .await;
        self.dentries.forget(parent, name);
        self.dentries.forget(new_parent, new_name);
        // As for `unlink`: anything buffered for a replaced file can only
        // fail now.
        if let Some(ino) = renamed? {
            self.discard_ino(ino).await;
        }
        Ok(())
    }

    /// Makes a new, empty file. It is open for reading and writing whatever
    /// its mode says: writing a read-only file through the descriptor that
    /// created it is normal (it is how `cp` copies one). Nothing checks the
    /// mode anyway, because grants decide.
    pub async fn create(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        if is_snapshot_ino(parent) {
            return Err(read_only());
        }
        if parent == VIRTUAL_ROOT {
            return Err(FsError::errno(errno::EPERM));
        }
        if self.hide_apple_double && is_apple_double(name) {
            return Err(FsError::new(
                errno::EACCES,
                "macOS metadata files are not stored here",
            ));
        }
        self.vault.create(parent, name, perm).await
    }

    /// access(2): whether the grant allows what `mask` asks. Anyone can
    /// list the virtual root and make volumes in it.
    pub async fn access(&self, ino: u64, mask: u32) -> Result<(), FsError> {
        if ino == VIRTUAL_ROOT {
            return Ok(());
        }
        if is_snapshot_ino(ino) {
            self.snapshots.access(ino, mask).await
        } else {
            self.remote().access(ino, mask).await
        }
    }

    /// Checks that the grant allows opening file `ino` for `mask`, so an
    /// open fails early, as it does locally. Reads and writes are checked
    /// again on their own, so nothing is kept open.
    pub async fn open_file(&self, ino: u64, mask: u32) -> Result<(), FsError> {
        if ino == VIRTUAL_ROOT {
            return Err(FsError::errno(errno::EISDIR));
        }
        self.access(ino, mask).await
    }

    pub async fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        let read = if is_snapshot_ino(ino) {
            self.snapshots.read(ino, offset, len).await
        } else {
            self.flush(ino).await?;
            self.vault.read(ino, offset, len).await
        };
        if let Err(e) = &read
            && e.errno != errno::ENOENT
        {
            eprintln!("read from inode {ino} at offset {offset} failed: {e}");
        }
        read
    }

    /// Writes `data` at `offset`, buffered unless the session was opened
    /// without buffering. Returns how many bytes were accepted: all of them
    /// unless a commit failed part way.
    pub async fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        if is_snapshot_ino(ino) {
            return Err(read_only());
        }
        if self.write_buffering {
            self.buffered_write(ino, offset, data).await
        } else {
            direct_write_result(self.vault.write(ino, offset, data).await, data.len())
        }
    }

    /// The part of `ino` stored together with `offset` (see
    /// `Vault::batch_at`): the most that a write there can store at once.
    pub async fn batch_at(&self, ino: u64, offset: u64) -> Result<std::ops::Range<u64>, FsError> {
        self.vault.batch_at(ino, offset).await
    }

    /// A directory's entries, including `.` and `..`.
    pub async fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        if is_snapshot_ino(ino) {
            return self.snapshots.readdir(&self.vault, VIRTUAL_ROOT, ino).await;
        }
        if ino == VIRTUAL_ROOT {
            let entries = self.vault.root_entries().await?;
            let dots = [".", ".."].map(|n| DirItem {
                ino: VIRTUAL_ROOT,
                kind: Kind::Directory,
                name: n.into(),
                sealed_name: Vec::new(),
            });
            return Ok(dots
                .into_iter()
                .chain(entries.into_iter().map(|(name, ino)| DirItem {
                    ino,
                    kind: Kind::Directory,
                    name,
                    sealed_name: Vec::new(),
                }))
                .collect());
        }
        let mut items = self.vault.readdir(ino).await?;
        // A grant's `..` is the virtual root: what is really above it is
        // not this account's to see.
        if self.vault.is_grant_root(ino) {
            for item in &mut items {
                if item.name == ".." {
                    item.ino = VIRTUAL_ROOT;
                }
            }
        }
        Ok(items)
    }

    pub fn statfs(&self) -> FsStats {
        FsStats {
            total_bytes: REPORTED_BYTES,
            free_bytes: REPORTED_BYTES,
            name_max: NAME_MAX,
        }
    }

    /// Copies file `src` to a new file `name` in `parent`, one batch at a
    /// time, and stores it before it returns its attributes. A copy from a
    /// snapshot into the live filesystem is how a file is restored.
    pub async fn copy_file(&self, src: u64, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        let from = self.getattr(src).await?;
        if from.kind != Kind::File {
            return Err(FsError::errno(errno::EISDIR));
        }
        let to = self.create(parent, name, from.perm).await?.ino;
        let mut offset = 0;
        while offset < from.size {
            let batch = self.batch_at(to, offset).await?;
            let len = (batch.end - offset).min(from.size - offset) as usize;
            let data = self.read(src, offset, len).await?;
            if data.is_empty() {
                break;
            }
            let mut done = 0;
            while done < data.len() {
                done += self.write(to, offset + done as u64, &data[done..]).await?;
            }
            offset += data.len() as u64;
        }
        self.release(to).await?;
        self.getattr(to).await
    }
}
