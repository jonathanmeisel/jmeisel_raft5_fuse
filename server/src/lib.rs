//! The filesystem server: the raft5fs protocol on top of `FsCore`.
//!
//! It is stateless, so any number of servers can run on one store, and a
//! client can use any of them. Only two things last longer than a request:
//!
//! - the account cache, which remembers that an account is still enrolled
//!   for at most `identity_ttl`;
//! - the core's paths up to grants, which only say what to read, and are
//!   checked against the store every time (see `raft5fs_core`'s
//!   `grants::Paths`).
//!
//! Write buffering and the chunk cache are in the client. Sessions are
//! signed tokens that the client holds (see `auth`).
//!
//! It serves native clients plain gRPC (`serve`), and can also serve
//! browsers gRPC-Web on a second port (`serve_web`), with the same service.

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
use tonic::codegen::http::{HeaderName, HeaderValue, Method, header};
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::auth::Signer;
use crate::timing::Timed;

/// The largest request that the server accepts: one write batch, which is
/// at most one maximum-size chunk, plus space for framing. This is above
/// tonic's 4 MiB default, which a batch of large chunks would exceed.
const MAX_MESSAGE_BYTES: usize = MAX_CHUNK_SIZE as usize + (1 << 20);

/// How long a server can trust that an account is enrolled before it checks
/// again, by default. This is how long it takes for an account removal to
/// reach a user who is already mounted. It costs at most one store read for
/// each active user in this time.
pub const DEFAULT_IDENTITY_TTL: Duration = Duration::from_secs(5);

/// How to connect to the store: the seeds and TLS settings for a server's
/// client.
#[derive(Clone)]
pub struct Store {
    pub seeds: Vec<String>,
    pub tls: Option<ClientTls>,
}

impl Store {
    /// A new client that shares nothing with any other client.
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
    /// Whether responses say where their time went (see `timing`).
    timing_header: bool,
}

impl FsService {
    /// `identity_ttl` is how long to trust that an account is still
    /// enrolled before checking again (`DEFAULT_IDENTITY_TTL`; zero checks
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

    /// Adds `raft5fs_proto::timing::HEADER` to every response: how long the
    /// request took to handle, and how much of that went to the store. Off
    /// by default; that module says why.
    pub fn with_timing_header(mut self, on: bool) -> Self {
        self.timing_header = on;
        self
    }

    /// Who sent `request`, from its session, and its message.
    async fn caller<T>(&self, request: Request<T>) -> Result<(Caller, T), Status> {
        let token = session_from_metadata(request.metadata())
            .ok_or_else(|| Status::unauthenticated("the request carries no session"))?;
        let name = self.signer.verify_session(token)?;
        self.check_enrolled(&name).await?;
        Ok((Caller::new(name), request.into_inner()))
    }

    /// Checks that account `name` is still enrolled, within `identity_ttl`.
    /// A removed account gives `UNAUTHENTICATED`. The client then logs in
    /// again, which fails, so removing an account cuts off a mounted user
    /// without waiting for their session to expire.
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

/// A store failure is the server's problem, so it becomes a gRPC status,
/// which sends the client to another server.
fn store_unavailable(e: FsError) -> Status {
    Status::unavailable(format!("cannot reach the store: {e}"))
}

/// The service, ready to add to a tonic `Server`.
pub fn service(fs: impl Into<Arc<FsService>>) -> FsServer<FsService> {
    FsServer::from_arc(fs.into()).max_decoding_message_size(MAX_MESSAGE_BYTES)
}

/// Serves on `listener` until `shutdown` completes, over TLS if `tls` is
/// given, and times every request (see `timing`).
pub async fn serve(
    fs: impl Into<Arc<FsService>>,
    listener: TcpListener,
    tls: Option<ServerTlsConfig>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    let fs = fs.into();
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

/// The port for browsers: gRPC-Web, answered only for one web app.
pub struct WebPort {
    pub listener: TcpListener,
    /// Without it, the port is plain HTTP: only for tests and local
    /// development, because sessions would cross the network in the clear.
    pub tls: Option<ServerTlsConfig>,
    /// The web app's origin, from `parse_origin`.
    pub origin: HeaderValue,
}

/// How long a browser can keep a CORS preflight's answer.
const PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// Serves browsers on `web.listener` until `shutdown` completes, with the
/// same service as `serve`.
///
/// - gRPC-Web (`tonic_web`) over HTTP/1.1 or HTTP/2. Over TLS, tonic offers
///   only HTTP/2, which every browser speaks; one connection then carries
///   every request at once.
/// - CORS lets only `web.origin` read the answers. A browser asks first
///   (a preflight), because every request is a POST with a gRPC-Web body,
///   and sends nothing more if the origin isn't allowed. A session is a
///   bearer token in a header, not a cookie, so another site's page can't
///   send one on a user's behalf.
/// - Plain gRPC requests also work here, because `tonic_web` passes them
///   through unchanged.
pub async fn serve_web(
    fs: impl Into<Arc<FsService>>,
    web: WebPort,
    shutdown: impl Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    let fs = fs.into();
    let mut builder = tonic::transport::Server::builder().accept_http1(true);
    if let Some(tls) = web.tls {
        builder = builder.tls_config(tls)?;
    }
    let header = fs.timing_header;
    builder
        .layer(cors(web.origin))
        .layer(tonic_web::GrpcWebLayer::new())
        .add_service(Timed::new(service(fs), header))
        .serve_with_incoming_shutdown(TcpListenerStream::new(web.listener), shutdown)
        .await
}

/// CORS for the web app at `origin`: the headers that gRPC-Web and the
/// client send, and the ones the client reads back. Another origin gets no
/// `Access-Control-Allow-Origin` at all. The layer also says `Vary:
/// origin`, so no cache gives one origin's answer to another.
fn cors(origin: HeaderValue) -> CorsLayer {
    let name = HeaderName::from_static;
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |asked, _| *asked == origin))
        .allow_methods([Method::POST])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            name("x-grpc-web"),
            name("x-user-agent"),
            name("grpc-timeout"),
        ])
        .expose_headers([
            name("grpc-status"),
            name("grpc-message"),
            name("grpc-status-details-bin"),
            name(raft5fs_proto::timing::HEADER),
        ])
        .max_age(PREFLIGHT_MAX_AGE)
}

/// Checks that `origin` is a web origin as browsers send it in `Origin`:
/// `https://host` or `https://host:port` (or `http://` for local
/// development), lowercase, with no path. CORS compares it byte for byte,
/// so anything else would never match.
pub fn parse_origin(origin: &str) -> Result<HeaderValue, String> {
    let bad = |why: &str| Err(format!("{origin:?} isn't a web origin: {why}"));
    let Some(host) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return bad("it must start with https://");
    };
    if host.is_empty() {
        return bad("it has no host");
    }
    if host.contains('/') {
        return bad("it must have no path, not even a trailing /");
    }
    if host.contains(|c: char| c.is_ascii_uppercase()) {
        return bad("browsers send it in lowercase");
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return bad("the host has characters a host name can't have");
    }
    HeaderValue::from_str(origin).or_else(|_| bad("not a header value"))
}

fn name(bytes: &[u8]) -> &OsStr {
    OsStr::from_bytes(bytes)
}

/// The snapshot that a read-only request asks to read at, if any.
fn at(snapshot: &str) -> Option<&[u8]> {
    (!snapshot.is_empty()).then_some(snapshot.as_bytes())
}

/// Refuses a snapshot on a request that writes. Such requests share their
/// message type with requests that only read.
fn live_only(snapshot: &str) -> Result<(), FsError> {
    if snapshot.is_empty() {
        Ok(())
    } else {
        Err(FsError::new(libc::EROFS, "a snapshot is read-only"))
    }
}

/// The chunks in a write or reseal. Returns `EINVAL` for a chunk with no
/// valid meaning.
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
            protocol: raft5fs_proto::PROTOCOL,
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
            // The same as a real account's settings: the same made-up salt
            // each time, and the settings that new accounts get.
            Ok(None) => KdfSettings {
                salt: self.signer.decoy_salt(&username).to_vec(),
                params: KdfParams::DEFAULT.encode().to_vec(),
            },
            Err(e) => return Err(store_unavailable(e)),
        };
        Ok(Response::new(Ok(settings).into()))
    }

    /// Checks `auth` against the account's verifier, and returns the
    /// wrapped private key. A wrong `auth` and an unknown account give the
    /// same error.
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

/// What a create sends in addition to the parent, tag, and mode.
fn new_node(r: &CreateRequest) -> NewNode {
    NewNode {
        ino: r.ino,
        keys: r.node_keys.clone(),
        sealed_name: r.sealed_name.clone(),
    }
}
