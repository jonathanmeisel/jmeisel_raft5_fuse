//! The filesystem server: the raft5fs protocol over `FsCore`.
//!
//! Stateless by design, so any number can run against one store and a
//! client can use any of them: nothing here outlives a request except two
//! caches -- the read cache inside `FsCore`, which revalidates every hit
//! against the store, and the identity cache here, which holds a user
//! table row for at most `identity_ttl`. Write buffering lives in the
//! client; sessions and open files live in signed tokens the client holds
//! (see `auth`).

pub mod auth;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use raft5_client::{Client, ClientTls, Error as KvError};
use raft5fs_core::perm::{R, W};
use raft5fs_core::{Caller, FsCore, FsError, MAX_CHUNK_SIZE, WriteError, batch_bytes, users};
use raft5fs_proto::convert::session_from_metadata;
use raft5fs_proto::pb::fs_server::{Fs, FsServer};
use raft5fs_proto::pb::{
    AccessRequest, AttrResponse, CreateRequest, CreateResponse, EmptyResponse, HelloRequest,
    HelloResponse, InoResponse, InodeRequest, LoginRequest, LoginResponse, NameRequest,
    OpenResponse, ReadDirResponse, ReadRequest, ReadResponse, RenameRequest, SetAttrRequest,
    WriteRequest, WriteResponse,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};

use crate::auth::Signer;

/// The largest request the server accepts: one write batch, which is at
/// most one maximum-size chunk, plus room for framing. Above tonic's 4 MiB
/// default, which a batch of large chunks would exceed.
const MAX_MESSAGE_BYTES: usize = MAX_CHUNK_SIZE as usize + (1 << 20);

/// How long a server may act on a user table row it has read before
/// reading it again, unless told otherwise: how long a changed group list
/// or a removed account takes to reach a mounted user. Costs at most one
/// store read per active user per this long.
pub const DEFAULT_IDENTITY_TTL: Duration = Duration::from_secs(5);

/// How to reach the store: what the server's own client was built from,
/// so that logins can be checked on clients of their own.
#[derive(Clone)]
pub struct Store {
    pub seeds: Vec<String>,
    pub tls: Option<ClientTls>,
}

impl Store {
    /// A fresh client, sharing nothing with any other -- in particular
    /// not its login, which a clone would.
    pub fn client(&self) -> Result<Client, KvError> {
        match &self.tls {
            Some(tls) => Client::with_tls(&self.seeds, tls.clone()),
            None => Client::new(&self.seeds),
        }
    }
}

pub struct FsService {
    core: Arc<FsCore>,
    signer: Signer,
    store: Store,
    /// What each account acted as when its row was last read, and when
    /// that was.
    identities: Mutex<HashMap<String, (Instant, Caller)>>,
    identity_ttl: Duration,
}

impl FsService {
    /// `identity_ttl` is how long a user table row is trusted before being
    /// read again (`DEFAULT_IDENTITY_TTL`; zero reads it every request).
    pub fn new(core: Arc<FsCore>, signer: Signer, store: Store, identity_ttl: Duration) -> Self {
        Self {
            core,
            signer,
            store,
            identities: Mutex::new(HashMap::new()),
            identity_ttl,
        }
    }

    /// Who `request` is from, per its session and the user table, and
    /// its message.
    async fn caller<T>(&self, request: Request<T>) -> Result<(Caller, T), Status> {
        let token = session_from_metadata(request.metadata())
            .ok_or_else(|| Status::unauthenticated("the request carries no session"))?;
        let name = self.signer.verify_session(token)?;
        let caller = self.identity(&name).await?;
        Ok((caller, request.into_inner()))
    }

    /// What account `name` acts as now, give or take `identity_ttl`. An
    /// account whose row is gone is `UNAUTHENTICATED`: the client then
    /// logs in again, which is refused, so removing a row cuts a mounted
    /// user off without waiting for their session to expire.
    async fn identity(&self, name: &str) -> Result<Caller, Status> {
        if let Some((read_at, caller)) = self.identities.lock().unwrap().get(name)
            && read_at.elapsed() < self.identity_ttl
        {
            return Ok(caller.clone());
        }
        match users::get(self.core.client(), name).await {
            Ok(Some(a)) => {
                let caller = Caller::new(a.uid, a.gid, a.groups);
                self.remember(name, &caller);
                Ok(caller)
            }
            Ok(None) => {
                self.identities.lock().unwrap().remove(name);
                Err(Status::unauthenticated(format!(
                    "{name} no longer has a filesystem account"
                )))
            }
            Err(e) => Err(Status::unavailable(format!(
                "cannot read the user table: {e}"
            ))),
        }
    }

    fn remember(&self, name: &str, caller: &Caller) {
        self.identities
            .lock()
            .unwrap()
            .insert(name.to_string(), (Instant::now(), caller.clone()));
    }

    /// The inode `handle` opened, if `caller` may use it for writing (or
    /// with `write` false, reading).
    fn handle_ino(&self, caller: &Caller, handle: &str, write: bool) -> Result<u64, FsError> {
        let h = self.signer.verify_handle(caller, handle)?;
        if (write && !h.write) || (!write && !h.read) {
            return Err(FsError::new(
                libc::EBADF,
                format!(
                    "handle not open for {}",
                    if write { "writing" } else { "reading" }
                ),
            ));
        }
        Ok(h.ino)
    }

    /// Checks `username`'s password against the store, and looks up what
    /// the account acts as. `Ok(Err)` is a refusal; `Err` means the store
    /// couldn't be asked, which is this server's failure, not the
    /// caller's.
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Result<Caller, FsError>, Status> {
        let unavailable = |e: KvError| Status::unavailable(format!("cannot reach the store: {e}"));
        // A client of its own: logging in on a clone of the server's
        // client would replace the server's own login.
        let store = self.store.client().map_err(unavailable)?;
        match store.login(username, password).await {
            Ok(()) => {}
            Err(
                e @ (KvError::Denied { .. }
                | KvError::Unauthenticated(_)
                | KvError::PermissionDenied(_)),
            ) => {
                return Ok(Err(FsError::new(
                    libc::EACCES,
                    format!("login refused: {e}"),
                )));
            }
            Err(e) => return Err(unavailable(e)),
        }
        drop(store);
        match users::get(self.core.client(), username).await {
            Ok(Some(a)) => {
                let caller = Caller::new(a.uid, a.gid, a.groups);
                self.remember(username, &caller);
                Ok(Ok(caller))
            }
            Ok(None) => Ok(Err(FsError::new(
                libc::EACCES,
                format!("{username} has no filesystem account"),
            ))),
            Err(e) => Err(Status::unavailable(format!(
                "cannot read the user table: {e}"
            ))),
        }
    }
}

/// The service, ready to add to a tonic `Server`.
pub fn service(fs: FsService) -> FsServer<FsService> {
    FsServer::new(fs).max_decoding_message_size(MAX_MESSAGE_BYTES)
}

/// Serves on `listener` until `shutdown` completes, over TLS if `tls` is
/// given.
pub async fn serve(
    fs: FsService,
    listener: TcpListener,
    tls: Option<ServerTlsConfig>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = tls {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(service(fs))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
}

fn name(bytes: &[u8]) -> &OsStr {
    OsStr::from_bytes(bytes)
}

#[tonic::async_trait]
impl Fs for FsService {
    async fn hello(&self, _: Request<HelloRequest>) -> Result<Response<HelloResponse>, Status> {
        let chunk_size = self.core.chunk_size();
        Ok(Response::new(HelloResponse {
            chunk_size,
            batch_bytes: batch_bytes(chunk_size),
        }))
    }

    async fn login(&self, r: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let r = r.into_inner();
        let session = self
            .authenticate(&r.username, &r.password)
            .await?
            .map(|_| self.signer.session(&r.username));
        Ok(Response::new(session.into()))
    }

    async fn get_attr(&self, r: Request<InodeRequest>) -> Result<Response<AttrResponse>, Status> {
        let (_, r) = self.caller(r).await?;
        Ok(Response::new(self.core.getattr(r.ino).await.into()))
    }

    async fn lookup(&self, r: Request<NameRequest>) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let found = self.core.lookup(&caller, r.parent, name(&r.name)).await;
        Ok(Response::new(found.into()))
    }

    async fn open(&self, r: Request<AccessRequest>) -> Result<Response<OpenResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let opened = self.core.open(&caller, r.ino, r.mask).await.map(|()| {
            self.signer
                .handle(&caller, r.ino, r.mask & R != 0, r.mask & W != 0)
        });
        Ok(Response::new(opened.into()))
    }

    async fn access(&self, r: Request<AccessRequest>) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core.access(&caller, r.ino, r.mask).await.into(),
        ))
    }

    async fn read_dir(
        &self,
        r: Request<InodeRequest>,
    ) -> Result<Response<ReadDirResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core.readdir(&caller, r.ino).await.into(),
        ))
    }

    async fn read(&self, r: Request<ReadRequest>) -> Result<Response<ReadResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let data = match self.handle_ino(&caller, &r.handle, false) {
            Ok(ino) => self.core.read(ino, r.offset, r.len as usize).await,
            Err(e) => Err(e),
        };
        Ok(Response::new(data.into()))
    }

    async fn write(&self, r: Request<WriteRequest>) -> Result<Response<WriteResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let written = match self.handle_ino(&caller, &r.handle, true) {
            Ok(ino) => self.core.write(ino, r.offset, &r.data).await,
            Err(error) => Err(WriteError { written: 0, error }),
        };
        Ok(Response::new(written.into()))
    }

    async fn set_attr(&self, r: Request<SetAttrRequest>) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        // A handle that doesn't check out just doesn't help: the change
        // is then judged on the caller's permissions alone.
        let writable_handle = r
            .handle
            .as_deref()
            .is_some_and(|h| self.handle_ino(&caller, h, true).ok() == Some(r.ino));
        let changed = self
            .core
            .setattr(&caller, r.ino, r.changes(), writable_handle)
            .await;
        Ok(Response::new(changed.into()))
    }

    async fn mkdir(&self, r: Request<CreateRequest>) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let made = self
            .core
            .mkdir(&caller, r.parent, name(&r.name), r.perm as u16)
            .await;
        Ok(Response::new(made.into()))
    }

    async fn create(&self, r: Request<CreateRequest>) -> Result<Response<CreateResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        // Open for both whatever the new mode says: creating a file
        // read-only and writing it through the descriptor that created
        // it is ordinary (it is how `cp` copies a read-only file).
        let made = self
            .core
            .create(&caller, r.parent, name(&r.name), r.perm as u16)
            .await
            .map(|attr| (attr, self.signer.handle(&caller, attr.ino, true, true)));
        Ok(Response::new(made.into()))
    }

    async fn unlink(&self, r: Request<NameRequest>) -> Result<Response<InoResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core
                .unlink(&caller, r.parent, name(&r.name))
                .await
                .into(),
        ))
    }

    async fn rename(&self, r: Request<RenameRequest>) -> Result<Response<InoResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let moved = self
            .core
            .rename(
                &caller,
                r.parent,
                name(&r.name),
                r.new_parent,
                name(&r.new_name),
                r.noreplace,
            )
            .await
            .map(|replaced| replaced.unwrap_or(0));
        Ok(Response::new(moved.into()))
    }

    async fn rmdir(&self, r: Request<NameRequest>) -> Result<Response<InoResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core
                .rmdir(&caller, r.parent, name(&r.name))
                .await
                .into(),
        ))
    }
}
