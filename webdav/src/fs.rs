//! The session as a `dav_server` filesystem: paths resolved through the
//! session (see `raft5fs_client::paths`), and everything else exactly what
//! a mount does, by inode.
//!
//! Each call runs in a task of its own. hyper drops a request's future
//! when its client goes away, and a session future dropped halfway can
//! leave a write buffer's commit half done (see `Session`); a task runs
//! on to the end whoever is still waiting for it.

use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::io::SeekFrom;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError as DavError, FsFuture, FsResult,
    FsStream, OpenOptions, ReadDirMeta,
};
use futures_util::{FutureExt, StreamExt, stream};
use raft5fs_client::session::Session;
use raft5fs_proto::types::{Attr, FsError, Kind, SetAttr, SetTime};

/// What new files and directories are made with.
const FILE_PERM: u16 = 0o644;
const DIR_PERM: u16 = 0o755;

/// How many entries' attributes a listing asks for at once.
const LISTING_CONCURRENCY: usize = 16;

/// What `e` is to a WebDAV client: `dav_server` makes a status of it.
fn dav_err(e: FsError) -> DavError {
    match e.errno {
        libc::ENOENT => DavError::NotFound,
        libc::EACCES | libc::EPERM | libc::EROFS | libc::ENOTDIR | libc::EISDIR => {
            DavError::Forbidden
        }
        libc::ENOTEMPTY => DavError::Forbidden,
        libc::EEXIST => DavError::Exists,
        libc::EXDEV => DavError::IsRemote,
        libc::ENOSPC | libc::EDQUOT => DavError::InsufficientStorage,
        libc::EFBIG => DavError::TooLarge,
        libc::ENAMETOOLONG => DavError::PathTooLong,
        _ => {
            eprintln!("webdav: {e}");
            DavError::GeneralFailure
        }
    }
}

/// Runs `fut` to the end in a task of its own (see the module's comment).
async fn run<T: Send + 'static>(
    fut: impl Future<Output = Result<T, FsError>> + Send + 'static,
) -> FsResult<T> {
    match tokio::spawn(fut).await {
        Ok(result) => result.map_err(dav_err),
        Err(e) => {
            eprintln!("webdav: a request's task failed: {e}");
            Err(DavError::GeneralFailure)
        }
    }
}

/// The session as `dav_server` wants a filesystem: cheap to clone, one
/// per handler.
#[derive(Clone)]
pub struct DavFs {
    session: Arc<Session>,
}

impl DavFs {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    /// Runs `op` with the session and `path`'s bytes, owned, in a task.
    fn with_path<'a, T, F, Fut>(&self, path: &DavPath, op: F) -> FsFuture<'a, T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Session>, Vec<u8>) -> Fut,
        Fut: Future<Output = Result<T, FsError>> + Send + 'static,
    {
        let fut = op(Arc::clone(&self.session), path.as_bytes().to_vec());
        run(fut).boxed()
    }
}

/// An inode's attributes, as `dav_server` asks for them.
#[derive(Debug, Clone)]
struct Meta(Attr);

impl DavMetaData for Meta {
    fn len(&self) -> u64 {
        self.0.size
    }

    fn modified(&self) -> FsResult<SystemTime> {
        Ok(self.0.mtime)
    }

    fn is_dir(&self) -> bool {
        self.0.kind == Kind::Directory
    }

    fn accessed(&self) -> FsResult<SystemTime> {
        Ok(self.0.atime)
    }

    fn status_changed(&self) -> FsResult<SystemTime> {
        Ok(self.0.ctime)
    }

    fn executable(&self) -> FsResult<bool> {
        Ok(self.0.perm & 0o100 != 0)
    }

    /// The inode too, unlike `dav_server`'s own: a file replaced by one
    /// of the same size within a microsecond is still a different file.
    fn etag(&self) -> Option<String> {
        let at = self.0.mtime.duration_since(UNIX_EPOCH).ok()?;
        Some(format!(
            "{:x}-{:x}-{:x}",
            self.0.ino,
            self.0.size,
            at.as_micros()
        ))
    }
}

struct Entry {
    name: Vec<u8>,
    meta: Meta,
}

impl DavDirEntry for Entry {
    fn name(&self) -> Vec<u8> {
        self.name.clone()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: Box<dyn DavMetaData> = Box::new(self.meta.clone());
        Box::pin(std::future::ready(Ok(meta)))
    }
}

/// The access an open with `options` asks for, as an access(2) mask.
fn open_mask(options: &OpenOptions) -> u32 {
    let mut mask = 0;
    if options.read {
        mask |= libc::R_OK;
    }
    if options.write || options.append || options.truncate {
        mask |= libc::W_OK;
    }
    mask as u32
}

/// The file `path` names, opened as `options` says: made if it isn't
/// there and they say to, and emptied if they say that.
async fn open(
    session: Arc<Session>,
    path: Vec<u8>,
    options: OpenOptions,
) -> Result<Handle, FsError> {
    let attr = loop {
        match session.resolve(&path).await {
            Ok(_) if options.create_new => return Err(FsError::errno(libc::EEXIST)),
            Ok(attr) if attr.kind == Kind::Directory => {
                return Err(FsError::errno(libc::EISDIR));
            }
            Ok(attr) => break attr,
            Err(e) if e.errno == libc::ENOENT && (options.create || options.create_new) => {
                let (parent, name) = session.resolve_parent(&path).await?;
                match session.create(parent, &name, FILE_PERM).await {
                    // Made by someone else meanwhile: open theirs.
                    Err(e) if e.errno == libc::EEXIST && !options.create_new => continue,
                    created => break created?,
                }
            }
            Err(e) => return Err(e),
        }
    };
    session.open_file(attr.ino, open_mask(&options)).await?;
    let mut size = attr.size;
    if options.truncate && size > 0 {
        let empty = SetAttr {
            size: Some(0),
            ..SetAttr::default()
        };
        size = session.setattr(attr.ino, empty).await?.size;
    }
    Ok(Handle {
        session,
        ino: attr.ino,
        pos: if options.append { size } else { 0 },
        wrote: false,
    })
}

/// A directory's entries, `.` and `..` left out, each with its attributes
/// -- asked for a few at a time, rather than one round trip after another.
async fn list(session: Arc<Session>, path: Vec<u8>) -> Result<Vec<Entry>, FsError> {
    let dir = session.resolve(&path).await?;
    if dir.kind != Kind::Directory {
        return Err(FsError::errno(libc::ENOTDIR));
    }
    let items = session.readdir(dir.ino).await?;
    let attrs = stream::iter(
        items
            .into_iter()
            .filter(|i| i.name != "." && i.name != ".."),
    )
    .map(|item| {
        let session = Arc::clone(&session);
        async move { (item.name, session.getattr(item.ino).await) }
    })
    .buffered(LISTING_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    let mut entries = Vec::with_capacity(attrs.len());
    for (name, attr) in attrs {
        match attr {
            Ok(attr) => entries.push(Entry {
                name: name.into_encoded_bytes(),
                meta: Meta(attr),
            }),
            // Gone since the listing: as if it had been gone before.
            Err(e) if e.errno == libc::ENOENT => {}
            Err(e) => return Err(e),
        }
    }
    Ok(entries)
}

async fn set_time(
    session: Arc<Session>,
    path: Vec<u8>,
    at: SystemTime,
    modified: bool,
) -> Result<(), FsError> {
    let ino = session.resolve(&path).await?.ino;
    let mut changes = SetAttr::default();
    if modified {
        changes.mtime = Some(SetTime::At(at));
    } else {
        changes.atime = Some(SetTime::At(at));
    }
    session.setattr(ino, changes).await.map(drop)
}

/// `from` and `to`, each as its parent and name.
async fn parents(
    session: &Session,
    from: &[u8],
    to: &[u8],
) -> Result<((u64, OsString), (u64, OsString)), FsError> {
    Ok((
        session.resolve_parent(from).await?,
        session.resolve_parent(to).await?,
    ))
}

impl DavFileSystem for DavFs {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        self.with_path(path, move |session, path| async move {
            let file: Box<dyn DavFile> = Box::new(open(session, path, options).await?);
            Ok(file)
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        self.with_path(path, |session, path| async move {
            let entries = list(session, path).await?;
            let stream: FsStream<Box<dyn DavDirEntry>> = Box::pin(stream::iter(
                entries
                    .into_iter()
                    .map(|e| Ok(Box::new(e) as Box<dyn DavDirEntry>)),
            ));
            Ok(stream)
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        self.with_path(path, |session, path| async move {
            let meta: Box<dyn DavMetaData> = Box::new(Meta(session.resolve(&path).await?));
            Ok(meta)
        })
    }

    /// In the root, a new volume.
    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        self.with_path(path, |session, path| async move {
            let (parent, name) = session.resolve_parent(&path).await?;
            session.mkdir(parent, &name, DIR_PERM).await.map(drop)
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        self.with_path(path, |session, path| async move {
            let (parent, name) = session.resolve_parent(&path).await?;
            session.rmdir(parent, &name).await
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        self.with_path(path, |session, path| async move {
            let (parent, name) = session.resolve_parent(&path).await?;
            session.unlink(parent, &name).await
        })
    }

    /// `dav_server` has already removed what `to` named, if the request
    /// said to overwrite it, and refused the request if not.
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let to = to.as_bytes().to_vec();
        self.with_path(from, move |session, from| async move {
            let ((parent, name), (new_parent, new_name)) = parents(&session, &from, &to).await?;
            session
                .rename(parent, &name, new_parent, &new_name, false)
                .await
        })
    }

    /// A file only: `dav_server` copies a directory itself, making each
    /// directory and copying each file in it.
    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let to = to.as_bytes().to_vec();
        self.with_path(from, move |session, from| async move {
            let src = session.resolve(&from).await?.ino;
            let (parent, name) = session.resolve_parent(&to).await?;
            session.copy_file(src, parent, &name).await.map(drop)
        })
    }

    fn set_accessed<'a>(&'a self, path: &'a DavPath, at: SystemTime) -> FsFuture<'a, ()> {
        self.with_path(path, move |session, path| {
            set_time(session, path, at, false)
        })
    }

    fn set_modified<'a>(&'a self, path: &'a DavPath, at: SystemTime) -> FsFuture<'a, ()> {
        self.with_path(path, move |session, path| set_time(session, path, at, true))
    }

    /// Used and available, as `dav_server` reports them.
    fn get_quota(&self) -> FsFuture<'_, (u64, Option<u64>)> {
        let stats = self.session.statfs();
        let used = stats.total_bytes - stats.free_bytes;
        Box::pin(std::future::ready(Ok((used, Some(stats.free_bytes)))))
    }
}

/// An open file: an inode and a position in it. Nothing is held open
/// with the servers -- each read and write goes by inode, as a mount's do.
struct Handle {
    session: Arc<Session>,
    ino: u64,
    pos: u64,
    /// Whether anything was written through this handle, for dropping it
    /// to release what is buffered.
    wrote: bool,
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Handle")
            .field("ino", &self.ino)
            .field("pos", &self.pos)
            .finish()
    }
}

impl Handle {
    fn write(&mut self, data: Bytes) -> FsFuture<'_, ()> {
        let session = Arc::clone(&self.session);
        let (ino, pos) = (self.ino, self.pos);
        self.wrote = true;
        Box::pin(async move {
            let len = data.len();
            run(async move {
                let mut done = 0;
                while done < data.len() {
                    done += session.write(ino, pos + done as u64, &data[done..]).await?;
                }
                Ok(())
            })
            .await?;
            self.pos += len as u64;
            Ok(())
        })
    }
}

impl DavFile for Handle {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let session = Arc::clone(&self.session);
        let ino = self.ino;
        run(async move {
            let meta: Box<dyn DavMetaData> = Box::new(Meta(session.getattr(ino).await?));
            Ok(meta)
        })
        .boxed()
    }

    fn write_buf(&mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        let data = buf.copy_to_bytes(buf.remaining());
        self.write(data)
    }

    fn write_bytes(&mut self, data: Bytes) -> FsFuture<'_, ()> {
        self.write(data)
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        let session = Arc::clone(&self.session);
        let (ino, pos) = (self.ino, self.pos);
        Box::pin(async move {
            let data = run(async move { session.read(ino, pos, count).await }).await?;
            self.pos += data.len() as u64;
            Ok(Bytes::from(data))
        })
    }

    fn seek(&mut self, to: SeekFrom) -> FsFuture<'_, u64> {
        let session = Arc::clone(&self.session);
        let ino = self.ino;
        Box::pin(async move {
            let (base, delta) = match to {
                SeekFrom::Start(at) => (at, 0),
                SeekFrom::Current(delta) => (self.pos, delta),
                SeekFrom::End(delta) => {
                    let size = run(async move { session.getattr(ino).await }).await?.size;
                    (size, delta)
                }
            };
            self.pos = base
                .checked_add_signed(delta)
                .ok_or(DavError::GeneralFailure)?;
            Ok(self.pos)
        })
    }

    /// Stores everything written, and reports it if any of it was lost:
    /// a PUT answers only once its body is stored.
    fn flush(&mut self) -> FsFuture<'_, ()> {
        let session = Arc::clone(&self.session);
        let ino = self.ino;
        run(async move { session.fsync(ino).await }).boxed()
    }
}

impl Drop for Handle {
    /// The last of the file's users through here is done with it: what it
    /// left buffered is stored, and the buffer forgotten.
    fn drop(&mut self) {
        if !self.wrote {
            return;
        }
        let session = Arc::clone(&self.session);
        let ino = self.ino;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Err(e) = session.release(ino).await {
                    eprintln!("webdav: storing what was written to inode {ino}: {e}");
                }
            });
        }
    }
}
