//! The filesystem server: the raft5fs protocol over `FsCore`.
//!
//! Stateless by design, so any number can run against one store and a
//! client can use any of them: nothing here outlives a request except the
//! account cache, which remembers that an account is still enrolled for at
//! most `identity_ttl`, and the core's paths up to grants, which only say
//! what to read and are checked against the store every time (see
//! `raft5fs_core`'s `grants::Paths`). Write buffering and the chunk cache
//! live in the client; sessions live in signed tokens the client holds
//! (see `auth`).

pub mod auth;
pub mod timing;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use raft5_client::{Client, ClientTls, Error as KvError};
use raft5fs_core::{
    BlockUpload, Caller, ChunkWrite, FsCore, FsError, MAX_CHUNK_SIZE, NewNode, ResealedName,
    Rotation, SealedMove, accounts, batch_bytes,
};
use raft5fs_crypto::password::KdfParams;
use raft5fs_proto::convert::session_from_metadata;
use raft5fs_proto::pb::fs_server::{Fs, FsServer};
use raft5fs_proto::pb::{
    AccessRequest, AttrResponse, ChangePasswordRequest, CreateRequest, CreateVolumeRequest,
    EmptyResponse, EnrolRequest, GrantListResponse, GrantRequest, GrantsUnderResponse,
    HelloRequest, HelloResponse, InoResponse, InodeRequest, KdfSettings, KeyPathResponse,
    ListGrantsRequest, LoginRequest, LoginResponse, LookupResponse, NameRequest, NoArgs,
    PreloginRequest, PreloginResponse, PrepareUploadsRequest, PrepareUploadsResponse,
    PruneKeysRequest, PublicKeyRequest, PublicKeyResponse, ReadChunksRequest, ReadChunksResponse,
    ReadDirResponse, RenameRequest, ResealChunksRequest, ResealNamesRequest, RotateRequest,
    Session, SetAttrRequest, SnapshotListResponse, WriteChunksRequest, WriteChunksResponse,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};

use crate::auth::Signer;
use crate::timing::Timed;

/// The largest request the server accepts: one write batch, which is at
/// most one maximum-size chunk, plus room for framing. Above tonic's 4 MiB
/// default, which a batch of large chunks would exceed.
const MAX_MESSAGE_BYTES: usize = MAX_CHUNK_SIZE as usize + (1 << 20);

/// How long a server may go on trusting that an account is enrolled before
/// looking again, unless told otherwise: how long removing an account
/// takes to reach a user who is already mounted. Costs at most one store
/// read per active user per this long.
pub const DEFAULT_IDENTITY_TTL: Duration = Duration::from_secs(5);

/// How to reach the store: the seeds and TLS settings a server's client is
/// built from.
#[derive(Clone)]
pub struct Store {
    pub seeds: Vec<String>,
    pub tls: Option<ClientTls>,
}

impl Store {
    /// A fresh client, sharing nothing with any other.
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
    /// When each account was last seen enrolled.
    enrolled: Mutex<HashMap<String, Instant>>,
    identity_ttl: Duration,
    /// Whether answers say where their time went (see `timing`).
    timing_header: bool,
}

impl FsService {
    /// `identity_ttl` is how long an account is trusted to still be
    /// enrolled before looking again (`DEFAULT_IDENTITY_TTL`; zero looks
    /// on every request).
    pub fn new(core: Arc<FsCore>, signer: Signer, identity_ttl: Duration) -> Self {
        Self {
            core,
            signer,
            enrolled: Mutex::new(HashMap::new()),
            identity_ttl,
            timing_header: false,
        }
    }

    /// Answers every request with `raft5fs_proto::timing::HEADER`: how
    /// long it took to handle, and how much of that went on the store.
    /// Off by default -- see that module for why.
    pub fn with_timing_header(mut self, on: bool) -> Self {
        self.timing_header = on;
        self
    }

    /// Who `request` is from, per its session, and its message.
    async fn caller<T>(&self, request: Request<T>) -> Result<(Caller, T), Status> {
        let token = session_from_metadata(request.metadata())
            .ok_or_else(|| Status::unauthenticated("the request carries no session"))?;
        let name = self.signer.verify_session(token)?;
        self.check_enrolled(&name).await?;
        Ok((Caller::new(name), request.into_inner()))
    }

    /// That account `name` is still enrolled, give or take
    /// `identity_ttl`. One removed is `UNAUTHENTICATED`: the client then
    /// logs in again, which is refused, so removing an account cuts a
    /// mounted user off without waiting for their session to expire.
    async fn check_enrolled(&self, name: &str) -> Result<(), Status> {
        if let Some(seen) = self.enrolled.lock().unwrap().get(name)
            && seen.elapsed() < self.identity_ttl
        {
            return Ok(());
        }
        match accounts::get(self.core.client(), name).await {
            Ok(Some(_)) => {
                self.remember(name);
                Ok(())
            }
            Ok(None) => {
                self.enrolled.lock().unwrap().remove(name);
                Err(Status::unauthenticated(format!(
                    "{name} no longer has an account"
                )))
            }
            Err(e) => Err(store_unavailable(e)),
        }
    }

    fn remember(&self, name: &str) {
        self.enrolled
            .lock()
            .unwrap()
            .insert(name.to_string(), Instant::now());
    }
}

/// A store failure: the server's problem, so a status, which sends the
/// client to another server.
fn store_unavailable(e: FsError) -> Status {
    Status::unavailable(format!("cannot reach the store: {e}"))
}

/// The service, ready to add to a tonic `Server`.
pub fn service(fs: FsService) -> FsServer<FsService> {
    FsServer::new(fs).max_decoding_message_size(MAX_MESSAGE_BYTES)
}

/// Serves on `listener` until `shutdown` completes, over TLS if `tls` is
/// given, timing every request (see `timing`).
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
    let header = fs.timing_header;
    builder
        .add_service(Timed::new(service(fs), header))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
}

fn name(bytes: &[u8]) -> &OsStr {
    OsStr::from_bytes(bytes)
}

/// The snapshot a read-only request asks to read at, if any.
fn at(snapshot: &str) -> Option<&[u8]> {
    (!snapshot.is_empty()).then_some(snapshot.as_bytes())
}

/// Refuses a snapshot on a request that writes, which shares its message
/// with ones that only read.
fn live_only(snapshot: &str) -> Result<(), FsError> {
    if snapshot.is_empty() {
        Ok(())
    } else {
        Err(FsError::new(libc::EROFS, "a snapshot is read-only"))
    }
}

/// The chunks a write or reseal carries, `EINVAL` if one can't mean
/// anything.
fn chunk_writes(chunks: Vec<raft5fs_proto::pb::ChunkWrite>) -> Result<Vec<ChunkWrite>, FsError> {
    chunks.into_iter().map(ChunkWrite::try_from).collect()
}

#[tonic::async_trait]
impl Fs for FsService {
    async fn hello(&self, _: Request<HelloRequest>) -> Result<Response<HelloResponse>, Status> {
        let chunk_size = self.core.chunk_size();
        Ok(Response::new(HelloResponse {
            chunk_size,
            batch_bytes: batch_bytes(chunk_size),
            grid: self.core.object_grid().map(Into::into),
        }))
    }

    async fn prelogin(
        &self,
        r: Request<PreloginRequest>,
    ) -> Result<Response<PreloginResponse>, Status> {
        let username = r.into_inner().username;
        let settings = match accounts::get(self.core.client(), &username).await {
            Ok(Some(keys)) => KdfSettings {
                salt: keys.salt,
                params: keys.kdf_params,
            },
            // Indistinguishable from a real account's: the same made-up
            // salt every time, and the parameters new accounts get.
            Ok(None) => KdfSettings {
                salt: self.signer.decoy_salt(&username).to_vec(),
                params: KdfParams::DEFAULT.encode().to_vec(),
            },
            Err(e) => return Err(store_unavailable(e)),
        };
        Ok(Response::new(Ok(settings).into()))
    }

    /// Checks `auth` against the account's verifier, and hands back the
    /// wrapped private key. A wrong `auth` and an unknown account are
    /// refused alike.
    async fn login(&self, r: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let r = r.into_inner();
        let session = match accounts::check_login(self.core.client(), &r.username, &r.auth).await {
            Ok(Some(keys)) => {
                self.remember(&r.username);
                let (token, expires_at) = self.signer.session(&r.username);
                Ok(Session {
                    token,
                    expires_at,
                    wrapped_private_key: keys.wrapped_private_key,
                })
            }
            Ok(None) => Err(FsError::new(
                libc::EACCES,
                "login refused: the username or password was wrong",
            )),
            Err(e) => return Err(store_unavailable(e)),
        };
        Ok(Response::new(session.into()))
    }

    async fn enrol(&self, r: Request<EnrolRequest>) -> Result<Response<EmptyResponse>, Status> {
        let r = r.into_inner();
        let enrolled = match r.keys {
            None => Err(FsError::new(libc::EINVAL, "an enrolment needs keys")),
            Some(keys) => {
                accounts::enrol(self.core.client(), &r.username, &r.code, &keys.into()).await
            }
        };
        Ok(Response::new(enrolled.into()))
    }

    async fn change_password(
        &self,
        r: Request<ChangePasswordRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let r = r.into_inner();
        let changed = match r.keys {
            None => Err(FsError::new(libc::EINVAL, "a password change needs keys")),
            Some(keys) => {
                accounts::change_password(
                    self.core.client(),
                    &r.username,
                    &r.old_auth,
                    &keys.into(),
                )
                .await
            }
        };
        Ok(Response::new(changed.into()))
    }

    async fn get_attr(&self, r: Request<InodeRequest>) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core
                .getattr(&caller, r.ino, at(&r.snapshot))
                .await
                .into(),
        ))
    }

    async fn lookup(&self, r: Request<NameRequest>) -> Result<Response<LookupResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let found = self
            .core
            .lookup(&caller, r.parent, name(&r.name), at(&r.snapshot))
            .await;
        Ok(Response::new(found.into()))
    }

    async fn access(&self, r: Request<AccessRequest>) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core
                .access(&caller, r.ino, r.mask, at(&r.snapshot))
                .await
                .into(),
        ))
    }

    async fn read_dir(
        &self,
        r: Request<InodeRequest>,
    ) -> Result<Response<ReadDirResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core
                .readdir(&caller, r.ino, at(&r.snapshot))
                .await
                .into(),
        ))
    }

    async fn set_attr(&self, r: Request<SetAttrRequest>) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let changed = self.core.setattr(&caller, r.ino, r.changes()).await;
        Ok(Response::new(changed.into()))
    }

    async fn mkdir(&self, r: Request<CreateRequest>) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let made = self
            .core
            .mkdir(
                &caller,
                r.parent,
                name(&r.name),
                r.perm as u16,
                &new_node(&r),
            )
            .await;
        Ok(Response::new(made.into()))
    }

    async fn create(&self, r: Request<CreateRequest>) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let made = self
            .core
            .create(
                &caller,
                r.parent,
                name(&r.name),
                r.perm as u16,
                &new_node(&r),
            )
            .await;
        Ok(Response::new(made.into()))
    }

    async fn unlink(&self, r: Request<NameRequest>) -> Result<Response<InoResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            async {
                live_only(&r.snapshot)?;
                self.core.unlink(&caller, r.parent, name(&r.name)).await
            }
            .await
            .into(),
        ))
    }

    async fn rename(&self, r: Request<RenameRequest>) -> Result<Response<InoResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let sealed = SealedMove {
            ino: r.moved_ino,
            node_keys: r.node_keys.clone(),
            sealed_name: r.sealed_new_name.clone(),
        };
        let moved = self
            .core
            .rename(
                &caller,
                r.parent,
                name(&r.name),
                r.new_parent,
                name(&r.new_name),
                r.noreplace,
                &sealed,
            )
            .await
            .map(|replaced| replaced.unwrap_or(0));
        Ok(Response::new(moved.into()))
    }

    async fn rmdir(&self, r: Request<NameRequest>) -> Result<Response<InoResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            async {
                live_only(&r.snapshot)?;
                self.core.rmdir(&caller, r.parent, name(&r.name)).await
            }
            .await
            .into(),
        ))
    }

    async fn allocate_inode(&self, r: Request<NoArgs>) -> Result<Response<InoResponse>, Status> {
        let (caller, _) = self.caller(r).await?;
        Ok(Response::new(self.core.reserve_inode(&caller).await.into()))
    }

    async fn get_key_path(
        &self,
        r: Request<InodeRequest>,
    ) -> Result<Response<KeyPathResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core
                .key_path(&caller, r.ino, at(&r.snapshot))
                .await
                .into(),
        ))
    }

    async fn list_grants(
        &self,
        r: Request<ListGrantsRequest>,
    ) -> Result<Response<GrantListResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core.grants(&caller, at(&r.snapshot)).await.into(),
        ))
    }

    async fn list_snapshots(
        &self,
        r: Request<NoArgs>,
    ) -> Result<Response<SnapshotListResponse>, Status> {
        self.caller(r).await?;
        Ok(Response::new(self.core.snapshots().await.into()))
    }

    async fn public_key(
        &self,
        r: Request<PublicKeyRequest>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        let (_, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core.public_key(&r.username).await.into(),
        ))
    }

    async fn grant(&self, r: Request<GrantRequest>) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let granted = match r.grant {
            Some(grant) => {
                self.core
                    .grant(
                        &caller,
                        &r.username,
                        &grant.into(),
                        &r.sealed_grantees,
                        r.expected_grantees_seq,
                    )
                    .await
            }
            None => Err(FsError::new(libc::EINVAL, "a grant request needs a grant")),
        };
        Ok(Response::new(granted.into()))
    }

    async fn create_volume(
        &self,
        r: Request<CreateVolumeRequest>,
    ) -> Result<Response<AttrResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let new = NewNode {
            ino: r.ino,
            keys: r.node_keys,
            sealed_name: Vec::new(),
        };
        let made = self
            .core
            .create_volume(
                &caller,
                &new,
                r.perm as u16,
                &r.sealed_key,
                &r.sealed_label,
                &r.sealed_grantees,
            )
            .await;
        Ok(Response::new(made.into()))
    }

    async fn delete_volume(
        &self,
        r: Request<InodeRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            async {
                live_only(&r.snapshot)?;
                self.core.delete_volume(&caller, r.ino).await
            }
            .await
            .into(),
        ))
    }

    async fn read_chunks(
        &self,
        r: Request<ReadChunksRequest>,
    ) -> Result<Response<ReadChunksResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let read = self
            .core
            .read_chunks(
                &caller,
                r.ino,
                r.first,
                r.count,
                &r.known_seqs,
                r.objects_ok,
                at(&r.snapshot),
            )
            .await;
        Ok(Response::new(read.into()))
    }

    async fn write_chunks(
        &self,
        r: Request<WriteChunksRequest>,
    ) -> Result<Response<WriteChunksResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let written = async {
            let writes = chunk_writes(r.chunks)?;
            self.core.write_chunks(&caller, r.ino, &writes, r.end).await
        }
        .await;
        Ok(Response::new(written.into()))
    }

    async fn prepare_uploads(
        &self,
        r: Request<PrepareUploadsRequest>,
    ) -> Result<Response<PrepareUploadsResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let blocks: Vec<BlockUpload> = r.blocks.into_iter().map(Into::into).collect();
        Ok(Response::new(
            self.core
                .prepare_uploads(&caller, r.ino, &blocks)
                .await
                .into(),
        ))
    }

    async fn grants_under(
        &self,
        r: Request<InodeRequest>,
    ) -> Result<Response<GrantsUnderResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            async {
                live_only(&r.snapshot)?;
                self.core.grants_under(&caller, r.ino).await
            }
            .await
            .into(),
        ))
    }

    async fn rotate(&self, r: Request<RotateRequest>) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let rotations: Vec<Rotation> = r.rotations.into_iter().map(Into::into).collect();
        Ok(Response::new(
            self.core.rotate(&caller, &rotations).await.into(),
        ))
    }

    async fn reseal_chunks(
        &self,
        r: Request<ResealChunksRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            async {
                let writes = chunk_writes(r.chunks)?;
                self.core.reseal_chunks(&caller, r.ino, &writes).await
            }
            .await
            .into(),
        ))
    }

    async fn reseal_names(
        &self,
        r: Request<ResealNamesRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        let names: Vec<ResealedName> = r.names.into_iter().map(Into::into).collect();
        Ok(Response::new(
            self.core.reseal_names(&caller, r.dir, &names).await.into(),
        ))
    }

    async fn prune_keys(
        &self,
        r: Request<PruneKeysRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let (caller, r) = self.caller(r).await?;
        Ok(Response::new(
            self.core
                .prune_keys(&caller, r.ino, r.expected_version, &r.node_keys)
                .await
                .into(),
        ))
    }
}

/// What a create brings besides the parent, tag and mode.
fn new_node(r: &CreateRequest) -> NewNode {
    NewNode {
        ino: r.ino,
        keys: r.node_keys.clone(),
        sealed_name: r.sealed_name.clone(),
    }
}
