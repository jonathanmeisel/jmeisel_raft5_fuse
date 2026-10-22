//! The filesystem as a front end serves it: everything a FUSE mount and a
//! WebDAV server have in common, by inode, async, with errors as errnos.
//! All store logic lives behind the servers, and sealing and opening in
//! the vault (see `vault`); what is here is what belongs to a client --
//! the write buffers, the auto-flush timer, the virtual root, and which
//! changes the virtual root and `/.snapshot` refuse.
//!
//! `/.snapshot`, which the root doesn't list, holds the filesystem's
//! snapshots, read-only (see `snapshot_tree`).
//!
//! Every future here must be driven to completion: one dropped halfway
//! can leave a write buffer's commit half done, with nowhere for its error
//! to go. A front end that may drop them -- hyper does, when a client goes
//! away mid-request -- runs them in tasks of their own.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use raft5fs_proto::types::{Attr, DirItem, FsError, Kind, Layout, SetAttr, WriteError};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tonic::transport::ClientTlsConfig;

use crate::paths::Dentries;
use crate::prune_queue::PruneQueue;
use crate::pruner::{self, PrunerConfig};
use crate::remote::{Credentials, Remote};
use crate::snapshot_tree::{SnapshotTree, is_snapshot_dir, is_snapshot_ino, read_only};
use crate::vault::{DEFAULT_CACHE_BYTES, KnownKeys, VIRTUAL_ROOT, Vault};
use crate::write_buffer::WriteBuf;

/// How long buffered bytes may sit unstored when nothing else flushes
/// them. A writer that stops short of a full batch, and neither closes nor
/// syncs, would otherwise leave them in memory indefinitely.
const AUTO_FLUSH_DELAY: Duration = Duration::from_millis(500);

/// What `statfs` reports as the filesystem's size, and all of it free:
/// there are no quotas, and nothing to measure the store against.
const REPORTED_BYTES: u64 = 1 << 50;

/// The longest name `statfs` reports a directory entry may have.
const NAME_MAX: u32 = 255;

/// How to open a session.
pub struct SessionConfig {
    /// Servers to use, `https://host:port`; any of them will do.
    pub servers: Vec<String>,
    /// Who the session logs in as.
    pub credentials: Credentials,
    /// How to reach the servers over TLS; `None` for plaintext.
    pub tls: Option<ClientTlsConfig>,
    /// How much decrypted file data to cache.
    pub cache_bytes: usize,
    /// Where public keys are pinned -- whose pins also decide which grants
    /// the session trusts enough to write under -- or in memory only.
    pub known_keys: Option<KnownKeys>,
    /// The prune queue to work through in the background while the session
    /// is open, and how (see `pruner`).
    pub prune_queue: Option<(PruneQueue, PrunerConfig)>,
    /// Whether small sequential writes are buffered into batches.
    pub write_buffering: bool,
    /// Whether to refuse creating the files macOS keeps its metadata in
    /// (`._*` and `.DS_Store`) where there are no extended attributes to
    /// keep it in instead: each would otherwise be one more node sealed and
    /// stored next to every file its user so much as looks at.
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
/// report. A short write counts as failure here -- a buffered run is
/// either stored or not, from the point of view of whoever is waiting.
fn commit_result(ino: u64, start: u64, result: Result<Attr, WriteError>) -> Result<(), FsError> {
    result.map(|_| ()).map_err(|e| {
        eprintln!("write to inode {ino} at offset {start} failed: {}", e.error);
        e.error
    })
}

/// The result of an unbuffered write of `total` bytes: all of them, a
/// short count if some batches landed before a failure, or the error if
/// none did.
fn direct_write_result(result: Result<Attr, WriteError>, total: usize) -> Result<usize, FsError> {
    match result {
        Ok(_) => Ok(total),
        Err(WriteError { written: 0, error }) => Err(error),
        Err(WriteError { written, .. }) => Ok(written),
    }
}

/// Whether `name` is one of the files macOS keeps metadata in.
fn is_apple_double(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    name.starts_with(b"._") || name == b".DS_Store"
}

pub struct Session {
    vault: Arc<Vault>,
    /// The task working through the prune queue, if there is one.
    pruner: Mutex<Option<JoinHandle<()>>>,
    /// The virtual root's timestamps: when the session was opened.
    opened_at: SystemTime,
    /// Per-inode buffers of accepted-but-unstored writes. The map lock is
    /// only held to find or insert a slot, never across an `.await`; the
    /// slot's own lock is what serializes a file's writes and flushes, and
    /// is held across the commit's round trip.
    write_bufs: Mutex<HashMap<u64, Slot>>,
    write_buffering: bool,
    hide_apple_double: bool,
    /// `/.snapshot` and everything under it.
    snapshots: SnapshotTree,
    /// Names resolved by path, for front ends that work by path.
    pub(crate) dentries: Dentries,
}

impl Session {
    /// Connects to the servers, logs in and opens the account's keys. With
    /// no server reachable there is no filesystem to serve, and no chunk
    /// size to buffer writes against.
    pub async fn open(config: SessionConfig) -> Result<Arc<Self>, FsError> {
        let remote = Remote::connect(&config.servers, config.credentials, config.tls)
            .await
            .map_err(|why| {
                FsError::new(
                    libc::EHOSTUNREACH,
                    format!("cannot connect to the filesystem: {why}"),
                )
            })?;
        let keys =
            |e: FsError| FsError::new(libc::EACCES, format!("cannot open the account's keys: {e}"));
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
                Some(pruner::spawn(
                    &Handle::current(),
                    pruning,
                    queue,
                    prune_config,
                ))
            }
            None => None,
        };
        let opened_at = SystemTime::now();
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
    /// filesystem would seem to whoever opened the session.
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

    /// Commits whatever `buf` holds, holding its lock for the round trip,
    /// so that at most one commit of a file is ever in flight.
    ///
    /// The bytes in a buffer were already reported written to the `write`
    /// calls that put them there, so a failed commit loses data those
    /// callers believe is safe. Returning the error only tells whoever
    /// happened to trigger the commit; it is also stashed in `buf.err`,
    /// where every later `write`, `flush` (and so `close`) and `fsync`
    /// reports it until `fsync` or the last close takes it -- the same
    /// promise the kernel makes for writeback errors. Without this, a later
    /// commit succeeding would let `fsync` report success over the gap.
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
    /// then finds nothing to do. `shutdown` drains every buffer before the
    /// session ends, so correctness never rests on this firing.
    fn schedule_auto_flush(&self, slot: Slot) {
        let vault = Arc::clone(&self.vault);
        tokio::spawn(async move {
            tokio::time::sleep(AUTO_FLUSH_DELAY).await;
            let mut buf = slot.lock().await;
            let Some((start, data)) = buf.take() else {
                return;
            };
            let stored = vault.write(buf.ino, start, &data).await;
            if let Err(e) = commit_result(buf.ino, start, stored) {
                // No one is synchronously waiting on this commit, so the
                // failure has nowhere to go but back into the buffer, for
                // the next flush/fsync/write to report.
                buf.err.get_or_insert(e);
            }
        });
    }

    /// Commits `ino`'s buffered writes, if any. Called before anything
    /// that must observe them: reads, attribute queries, truncation -- and
    /// on every `close()`, which is what lets a failure reach the
    /// application that wrote them. A stashed error (from an earlier failed
    /// commit) is reported but left in place for `fsync` or `release` to
    /// take, matching how a `read` surfaces a pending write failure without
    /// being the thing that clears it.
    ///
    /// Not taking it matters for FUSE's FLUSH, which comes from *every*
    /// close of *any* copy of a descriptor -- including the copies a forked
    /// child inherits and closes on exec, which happens whenever some other
    /// process on the machine forks. If this took the error, a stranger's
    /// close could receive it and drop it, and the application's own
    /// `fsync` would then report success over lost data.
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

    /// `flush`, but takes the error it reports.
    pub async fn fsync(&self, ino: u64) -> Result<(), FsError> {
        let Some(slot) = self.existing_write_slot(ino) else {
            return Ok(());
        };
        let mut buf = slot.lock().await;
        let committed = self.commit_buf(&mut buf).await;
        // Taken whether or not this commit failed: if it did, the error
        // is stashed too, and this is the call that reports it.
        match buf.err.take() {
            Some(e) => Err(e),
            None => committed,
        }
    }

    /// The last user of `ino` is done with it, so this is where a pending
    /// error is finally taken: no one is left to report it to.
    pub async fn release(&self, ino: u64) -> Result<(), FsError> {
        let result = self.fsync(ino).await;
        self.prune_slot(ino);
        result
    }

    /// Drops `ino`'s buffered writes because the file has been deleted.
    ///
    /// Not what keeps chunks from leaking -- the store's deletion mark
    /// does that, for every client at once, and a buffer committed after
    /// it just gets `ENOENT` back. This only spares that wasted commit and
    /// the error it would leave stashed.
    async fn discard_ino(&self, ino: u64) {
        if let Some(slot) = self.existing_write_slot(ino) {
            slot.lock().await.discard();
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
    async fn buffered_write(
        &self,
        ino: u64,
        mut offset: u64,
        mut data: &[u8],
    ) -> Result<usize, FsError> {
        let slot = self.write_slot(ino);
        let mut buf = slot.lock().await;
        // Reported, not taken: until `fsync` (or the last close) takes it,
        // every write fails. Taking it here would let one write absorb a
        // loss that earlier writes were told was safe -- often one the
        // kernel issued on its own to finish a short write -- and then
        // `fsync`, the call that promises durability and the one many
        // programs actually check, would report success over it.
        if let Some(e) = &buf.err {
            return Err(e.clone());
        }

        // The run of the file stored together with `offset`: a batch, or
        // past a hybrid file's grid start, a block.
        let batch = self.vault.batch_at(ino, offset).await?;
        if data.len() as u64 >= batch.end - batch.start {
            // Committed directly, so whatever was buffered ahead of it has
            // to land first.
            self.commit_buf(&mut buf).await?;
            return direct_write_result(self.vault.write(ino, offset, data).await, data.len());
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
                && let Err(e) = self.commit_buf(&mut buf).await
            {
                return if written > 0 { Ok(written) } else { Err(e) };
            }
            // Stepping to the batch grid rather than the chunk grid is
            // what lets a run span chunks, and keeps the batch it becomes
            // aligned: a sequential writer then fills every chunk of its
            // batch completely, so storing it reads nothing back -- and a
            // block it fills is uploaded once.
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

    /// Ends the session: nothing after this can store what is still
    /// buffered, so it is stored now.
    pub async fn shutdown(&self) {
        // Whatever it was pruning stays queued, for next time.
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
        // Buffered writes can make the stored size stale; store them and
        // look again so the caller learns the size it will see.
        if self.existing_write_slot(attr.ino).is_some() {
            self.flush(attr.ino).await?;
            attr = self.remote().getattr(attr.ino).await?;
        }
        Ok(attr)
    }

    pub async fn getattr(&self, ino: u64) -> Result<Attr, FsError> {
        if ino == VIRTUAL_ROOT {
            return Ok(self.root_attr());
        }
        if is_snapshot_ino(ino) {
            return self.snapshots.getattr(ino).await;
        }
        self.flush(ino).await?;
        self.remote().getattr(ino).await
    }

    pub async fn setattr(&self, ino: u64, changes: SetAttr) -> Result<Attr, FsError> {
        if is_snapshot_ino(ino) {
            return Err(read_only());
        }
        if ino == VIRTUAL_ROOT {
            return Err(FsError::errno(libc::EPERM));
        }
        // Buffered bytes predate this change, so they have to be stored
        // before it applies (a truncate must cut them, not be undone by
        // them landing afterwards).
        self.flush(ino).await?;
        self.vault.setattr(ino, changes).await
    }

    /// A directory -- in the virtual root, a new volume.
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

    /// Removes an empty directory -- in the virtual root, a volume.
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
            return Err(FsError::errno(libc::EPERM));
        }
        let ino = self.vault.unlink(parent, name).await;
        self.dentries.forget(parent, name);
        // Anything still buffered for it can only fail now (the store
        // refuses writes to a deleted inode); drop it rather than leave
        // that failure stashed.
        self.discard_ino(ino?).await;
        Ok(())
    }

    /// Moves `name` in `parent` to `new_name` in `new_parent`, replacing
    /// what is there unless `noreplace`.
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<(), FsError> {
        // Out of a snapshot into the live filesystem, or the reverse, is a
        // move between filesystems, which `mv` knows to do as a copy; within
        // one, nothing moves.
        match (is_snapshot_ino(parent), is_snapshot_ino(new_parent)) {
            (true, true) => return Err(read_only()),
            (true, false) | (false, true) => return Err(FsError::errno(libc::EXDEV)),
            (false, false) => {}
        }
        // The virtual root's entries are grants, not names to move.
        if parent == VIRTUAL_ROOT || new_parent == VIRTUAL_ROOT {
            return Err(FsError::errno(libc::EPERM));
        }
        let renamed = self
            .vault
            .rename(parent, name, new_parent, new_name, noreplace)
            .await;
        self.dentries.forget(parent, name);
        self.dentries.forget(new_parent, new_name);
        // As for `unlink`: what was buffered for a replaced file can only
        // fail now.
        if let Some(ino) = renamed? {
            self.discard_ino(ino).await;
        }
        Ok(())
    }

    /// A new, empty file. It is open for both reading and writing whatever
    /// its new mode says: writing a read-only file through the descriptor
    /// that created it is ordinary (it is how `cp` copies one). Nothing
    /// checks the mode anyway -- grants decide.
    pub async fn create(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        if is_snapshot_ino(parent) {
            return Err(read_only());
        }
        if parent == VIRTUAL_ROOT {
            return Err(FsError::errno(libc::EPERM));
        }
        if self.hide_apple_double && is_apple_double(name) {
            return Err(FsError::new(
                libc::EACCES,
                "macOS metadata files are not stored here",
            ));
        }
        self.vault.create(parent, name, perm).await
    }

    /// access(2): whether the grant allows what `mask` asks. Anyone may
    /// list the virtual root, and make volumes in it.
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

    /// Checks the grant allows opening file `ino` for `mask`, so an open
    /// fails up front as it does locally. Reads and writes are checked
    /// again on their own, so nothing is kept open.
    pub async fn open_file(&self, ino: u64, mask: u32) -> Result<(), FsError> {
        if ino == VIRTUAL_ROOT {
            return Err(FsError::errno(libc::EISDIR));
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
            && e.errno != libc::ENOENT
        {
            eprintln!("read from inode {ino} at offset {offset} failed: {e}");
        }
        read
    }

    /// Writes `data` at `offset`, buffered unless the session was opened
    /// without: how many bytes were accepted, all of them unless a commit
    /// failed partway.
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

    /// The run of `ino` stored together with `offset` (see
    /// `Vault::batch_at`): the most a write there can store in one go.
    pub async fn batch_at(&self, ino: u64, offset: u64) -> Result<std::ops::Range<u64>, FsError> {
        self.vault.batch_at(ino, offset).await
    }

    /// A directory's entries, `.` and `..` included.
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
        // A grant's `..` is the virtual root: what is really above it isn't
        // this account's to see.
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

    /// Copies file `src` to a new file `name` in `parent`, a batch at a
    /// time, and stores it before returning its attributes. From a
    /// snapshot into the live filesystem, it is how a file is restored.
    pub async fn copy_file(&self, src: u64, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        let from = self.getattr(src).await?;
        if from.kind != Kind::File {
            return Err(FsError::errno(libc::EISDIR));
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
