//! The client side of the raft5fs protocol: the same operations as
//! `FsCore`, answered by whichever of several servers is reachable.
//!
//! **Failover.** Servers are stateless, so any server can answer any
//! request. Whether a request can be sent again to another server after a
//! failure depends on the request (see `Retry`):
//!
//! - Read-only requests are sent again on any failure. Running them twice
//!   changes nothing.
//! - Writes and attribute changes are sent again unless the request timed
//!   out. Sending one again after it was stored does no harm (the same
//!   bytes at the same offset, the same mode). But a request that might
//!   still be *running* must not be sent again. A server that only timed
//!   out could commit after the resend, and after a later write to the same
//!   range, and so put the older bytes back without notice. Every other
//!   failure means that the request is not running anywhere: the server was
//!   not reachable, or its connection broke during the request (tonic
//!   reports this as `Unknown`, not `Unavailable`). The server itself never
//!   answers with a status, because filesystem errors come inside the
//!   response. So only a timeout gives `EIO` in place of a failover.
//! - Create, mkdir, unlink, rmdir, and rename are never sent again. If one
//!   reached the old server, a retry would report a false `EEXIST` or
//!   `ENOENT`. They fail with `EIO`, and the next request starts at the
//!   next server.
//!
//! Every request has a deadline, so a server that stops answering cannot
//! hang a FUSE handler. A hung handler would block the mount, and anything
//! that touches it.
//!
//! **Sessions.** A mount logs in as one user when it connects, and every
//! request sends that session. When a server refuses a session (for
//! example, because it expired), the client logs in again with the same
//! credentials and retries the request. That is why the credentials are
//! kept for the life of the mount.
//!
//! **The password** never goes to a server. The first login stretches it
//! (with the salt from Prelogin) into `auth`, which logs in, and into a key
//! that opens the account's private key from the login's reply. After that,
//! only `auth` is kept, for renewals, and the password is dropped.
//!
//! `auth` and the session are as good as the password to anyone who sees
//! them: `auth` lets an attacker check password guesses offline. So they
//! only go over TLS. An address that is not `https://`, or a connection
//! without TLS settings, is refused unless the credentials allow plaintext
//! (`Credentials::allow_plaintext`). Use that only for tests and temporary
//! setups.

use std::ffi::OsStr;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use std::sync::{Arc, RwLock};
use std::time::Duration;

use raft5fs_crypto::Key;
use raft5fs_crypto::identity::{Identity, PUBLIC_KEY_LEN};
use raft5fs_crypto::password::{self, AUTH_LEN, KdfParams, PasswordKeys, new_salt, verifier};
use raft5fs_objstore::http::{self, HttpConfig};
use zeroize::Zeroizing;

use raft5fs_proto::convert::{name_bytes, session_to_metadata};
use raft5fs_proto::errno;
use raft5fs_proto::pb::fs_client::FsClient;
use raft5fs_proto::pb::{
    AccessRequest, AccountKeys, ChangePasswordRequest, CreateRequest, CreateVolumeRequest,
    EnrolRequest, GrantRequest, HelloRequest, InodeRequest, IssueInviteRequest, ListGrantsRequest,
    LoginRequest, NameRequest, NoArgs, PreloginRequest, PrepareUploadsRequest, PruneKeysRequest,
    PublicKeyRequest, ReadChunksRequest, RenameRequest, ResealChunksRequest, ResealNamesRequest,
    RotateRequest, SetAttrRequest, WriteChunksRequest,
};
use raft5fs_proto::pb::{
    CreateLinkAccountRequest, PutPinsRequest, SetCapabilitiesRequest, UsernameRequest,
};
use raft5fs_proto::types::{
    AccountInfo, Attr, BlockUpload, Caps, ChunkWrite, Chunks, DirItem, FsError, Grant, GrantedNode,
    KeyPath, NewNode, ObjectGrid, PreparedUpload, ResealedName, Rotation, SealedMove, SetAttr,
    SnapshotInfo,
};
use raft5fs_proto::types::{LinkAccount, Unreachable, UserEntry, VolumeInfo};
use tonic::Code;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
#[cfg(not(target_arch = "wasm32"))]
pub use tonic::transport::ClientTlsConfig;
#[cfg(not(target_arch = "wasm32"))]
use tonic::transport::{Channel, Endpoint};

use crate::timing::Timed;

#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::ClientTlsConfig;
#[cfg(target_arch = "wasm32")]
use web::WebChannel as Channel;

/// The largest message that the client sends: one write batch, which is at
/// most one maximum-size chunk (8 MiB), plus framing.
const MAX_MESSAGE_BYTES: usize = 9 << 20;

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Long on purpose: a write commits a batch of up to 8 MiB through raft,
/// and can retry under contention. A request that takes longer counts as a
/// failure of that server.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Sends pings on idle connections, so the client notices a server that
/// stopped without a message before the next request times out on it.
#[cfg(not(target_arch = "wasm32"))]
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
#[cfg(not(target_arch = "wasm32"))]
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// The user that a mount logs in as.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// The weakest key stretching that a login accepts from a server (see
    /// `KdfParams::check`).
    pub min_kdf: KdfParams,
    /// Whether to connect to servers without TLS. Off unless asked for; see
    /// the module doc.
    pub allow_plaintext: bool,
    /// How to connect to the object store that holds large files' blocks,
    /// through the URLs that servers sign: which CAs to trust, and whether
    /// `http://` is allowed. By default it is not, because the URLs are
    /// bearer credentials.
    pub objects: HttpConfig,
    /// Log in with these, from an earlier login's `Remote::unlock_keys`,
    /// instead of `password`, which is then unused.
    pub keys: Option<UnlockKeys>,
}

/// What a password gives a login: `auth`, which the server checks, and
/// `kek`, which opens the account's private key. A device that stays
/// unlocked keeps these instead of the password. They work only for this
/// account and only until its password changes, and the password can't be
/// found from them.
#[derive(Clone)]
pub struct UnlockKeys {
    pub auth: Zeroizing<[u8; AUTH_LEN]>,
    pub kek: Key,
}

impl Credentials {
    /// `username` and `password`. Accepts no weaker stretching than new
    /// accounts get.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            min_kdf: KdfParams::DEFAULT,
            allow_plaintext: false,
            objects: HttpConfig::default(),
            keys: None,
        }
    }
}

/// The session token that every request sends. Empty until the first login.
type Session = Arc<RwLock<String>>;

/// Adds the current session to every request.
#[derive(Clone)]
struct Authorize(Session);

impl Interceptor for Authorize {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let token = self.0.read().unwrap();
        if !token.is_empty() {
            session_to_metadata(&token, request.metadata_mut());
        }
        Ok(request)
    }
}

type Client = FsClient<InterceptedService<Timed<Channel>, Authorize>>;

/// What a login sends: the password, until the first login turns it into
/// the keys it gives.
enum Secret {
    Password(Zeroizing<String>),
    Keys(UnlockKeys),
}

pub struct Remote {
    servers: Vec<(String, Client)>,
    username: String,
    secret: RwLock<Secret>,
    min_kdf: KdfParams,
    /// The account's key pair, after a login opens it.
    identity: RwLock<Option<Arc<Identity>>>,
    /// How many chunks were asked for. Tests of the client's cache check
    /// that the cache keeps this low.
    chunk_reads: AtomicU64,
    session: Session,
    /// Where to start: the last server that answered.
    current: AtomicUsize,
    chunk_size: u64,
    batch_bytes: u64,
    /// The protocol version that the server said hello with.
    protocol: u32,
    /// How hybrid files group chunks into blocks, if the filesystem keeps
    /// data in object storage.
    grid: Option<ObjectGrid>,
    /// The client that fetches blocks from object storage.
    objects: http::Client,
    /// Whether reads say that this client can fetch chunks from object
    /// storage (see `ReadChunksRequest.objects_ok`). Off only to test what
    /// a client that cannot is told.
    objects_ok: bool,
    /// The snapshot that this client reads at, or empty for the live
    /// filesystem. A client at a snapshot only reads (see `at`).
    snapshot: String,
}

/// A connection to `address`, made when the first request needs it.
#[cfg(not(target_arch = "wasm32"))]
fn channel(address: &str, tls: Option<&ClientTlsConfig>) -> Result<Channel, String> {
    let mut endpoint =
        Endpoint::from_shared(address.to_string()).map_err(|e| format!("{address}: {e}"))?;
    if let Some(tls) = tls {
        endpoint = endpoint
            .tls_config(tls.clone())
            .map_err(|e| format!("{address}: {e}"))?;
    }
    Ok(endpoint
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
        .connect_lazy())
}

/// gRPC-Web to `address`. The browser does TLS (see `ClientTlsConfig`).
#[cfg(target_arch = "wasm32")]
fn channel(address: &str, _tls: Option<&ClientTlsConfig>) -> Result<Channel, String> {
    Ok(Channel::new(address, REQUEST_TIMEOUT))
}

/// Stretches `password` away from the async threads, because Argon2 is slow
/// on purpose.
async fn derive(
    password: &str,
    username: &str,
    salt: Vec<u8>,
    params: KdfParams,
) -> Result<PasswordKeys, FsError> {
    let password = Zeroizing::new(password.to_string());
    let username = username.to_string();
    crate::rt::blocking(move || password::derive(password.as_bytes(), &username, &salt, params))
        .await
        .map_err(|e| FsError::new(errno::EIO, e.to_string()))
}

/// What the server keeps for an account with password `password` and key
/// pair `identity`, under a new salt, and the `auth` that it will accept.
async fn account_keys(
    username: &str,
    password: &str,
    params: KdfParams,
    identity: &Identity,
) -> Result<(AccountKeys, UnlockKeys), FsError> {
    let salt = new_salt();
    let keys = derive(password, username, salt.to_vec(), params).await?;
    let account = AccountKeys {
        salt: salt.to_vec(),
        kdf_params: params.encode().to_vec(),
        verifier: verifier(&keys.auth).to_vec(),
        public_key: identity.public_key().to_vec(),
        wrapped_private_key: identity.wrap(&keys.kek, username),
    };
    let unlock = UnlockKeys {
        auth: Zeroizing::new(keys.auth),
        kek: keys.kek.clone(),
    };
    Ok((account, unlock))
}

/// When a request can be sent again to another server; see the module doc.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retry {
    /// After any failure.
    ReadOnly,
    /// After any failure except a timeout.
    Idempotent,
    /// Never.
    Once,
}

impl Retry {
    fn allows(self, status: &tonic::Status) -> bool {
        match self {
            Self::ReadOnly => true,
            Self::Idempotent => status.code() != Code::DeadlineExceeded,
            Self::Once => false,
        }
    }
}

impl Remote {
    /// Connects to whichever of `addresses` answers first
    /// (`https://host:port`, or `http://` without `tls`), gets the
    /// filesystem's chunk layout from it, and logs in with `credentials`.
    pub async fn connect(
        addresses: &[String],
        credentials: Credentials,
        tls: Option<ClientTlsConfig>,
    ) -> Result<Self, String> {
        Self::open(addresses, credentials, tls)
            .await
            .map_err(|e| e.message)
    }

    /// `connect`, keeping what went wrong: `EHOSTUNREACH` if it couldn't
    /// connect, or the login's own error (`EACCES` for a refused one).
    pub async fn open(
        addresses: &[String],
        credentials: Credentials,
        tls: Option<ClientTlsConfig>,
    ) -> Result<Self, FsError> {
        let remote = Self::dial(addresses, credentials, tls)
            .await
            .map_err(|why| FsError::new(errno::EHOSTUNREACH, why))?;
        remote.login().await?;
        Ok(remote)
    }

    /// Connects and says hello, without logging in.
    async fn dial(
        addresses: &[String],
        credentials: Credentials,
        tls: Option<ClientTlsConfig>,
    ) -> Result<Self, String> {
        if addresses.is_empty() {
            return Err("no server addresses".to_string());
        }
        raft5fs_proto::types::check_username(&credentials.username).map_err(|e| e.message)?;
        if !credentials.allow_plaintext {
            if tls.is_none() {
                return Err(
                    "refusing to log in without TLS: the login and the session would \
                     cross the network in the clear (give the servers' CA certificate)"
                        .to_string(),
                );
            }
            if let Some(plain) = addresses.iter().find(|a| !a.starts_with("https://")) {
                return Err(format!(
                    "refusing {plain}: only https:// addresses are used, so the login \
                     and the session never cross the network in the clear"
                ));
            }
        }
        let objects = http::client(&credentials.objects).map_err(|e| e.to_string())?;
        let session = Session::default();
        let authorize = Authorize(Arc::clone(&session));
        let mut servers = Vec::new();
        for address in addresses {
            let channel = Timed::new(channel(address, tls.as_ref())?, address);
            let client = FsClient::with_interceptor(channel, authorize.clone())
                .max_encoding_message_size(MAX_MESSAGE_BYTES);
            servers.push((address.clone(), client));
        }
        let mut remote = Self {
            servers,
            username: credentials.username,
            secret: RwLock::new(match credentials.keys {
                Some(keys) => Secret::Keys(keys),
                None => Secret::Password(Zeroizing::new(credentials.password)),
            }),
            min_kdf: credentials.min_kdf,
            identity: RwLock::new(None),
            chunk_reads: AtomicU64::new(0),
            session,
            current: AtomicUsize::new(0),
            chunk_size: 0,
            batch_bytes: 0,
            protocol: 0,
            grid: None,
            objects,
            objects_ok: true,
            snapshot: String::new(),
        };
        let hello = remote
            .call(Retry::ReadOnly, |mut c| async move {
                c.hello(HelloRequest {}).await
            })
            .await
            .map_err(|e| e.message)?;
        remote.chunk_size = hello.chunk_size;
        remote.batch_bytes = hello.batch_bytes;
        remote.protocol = hello.protocol;
        remote.grid = hello
            .grid
            .map(ObjectGrid::try_from)
            .transpose()
            .map_err(|e| e.message)?;
        Ok(remote)
    }

    /// Enrols `credentials.username` on the filesystem at `addresses`, with
    /// the one-time `code` from an administrator. It makes a key pair for
    /// the account, and stores it wrapped under the key from
    /// `credentials.password`. Returns the new public key, so the user can
    /// note its fingerprint.
    pub async fn enrol(
        addresses: &[String],
        tls: Option<ClientTlsConfig>,
        credentials: Credentials,
        code: &str,
        params: KdfParams,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        let username = credentials.username.clone();
        let password = Zeroizing::new(credentials.password.clone());
        let (username, password) = (username.as_str(), password.as_str());
        let remote = Self::dial(addresses, credentials, tls)
            .await
            .map_err(|e| FsError::new(errno::EIO, e))?;
        let identity = Identity::generate();
        let (keys, _) = account_keys(username, password, params, &identity).await?;
        let req = EnrolRequest {
            username: username.to_string(),
            code: code.to_string(),
            keys: Some(keys),
        };
        // Never sent again: the first enrolment uses up the code, so a
        // resend after it was stored would report a false refusal.
        remote
            .call(Retry::Once, |mut c| {
                let req = req.clone();
                async move { c.enrol(req).await }
            })
            .await?
            .into_result()?;
        Ok(identity.public_key())
    }

    /// Changes this account's password to `new_password`. The key pair
    /// stays the same (only its wrapping changes), so everything shared
    /// with it stays readable. Needs a login, which proves the old
    /// password.
    pub async fn change_password(
        &self,
        new_password: &str,
        params: KdfParams,
    ) -> Result<(), FsError> {
        let identity = self
            .identity()
            .ok_or_else(|| FsError::new(errno::EACCES, "not logged in: no key pair to re-wrap"))?;
        let old_auth = match &*self.secret.read().unwrap() {
            Secret::Keys(keys) => keys.auth.to_vec(),
            Secret::Password(_) => {
                return Err(FsError::new(errno::EACCES, "not logged in"));
            }
        };
        let (keys, new_keys) =
            account_keys(&self.username, new_password, params, &identity).await?;
        let req = ChangePasswordRequest {
            username: self.username.clone(),
            old_auth,
            keys: Some(keys),
        };
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.change_password(req).await }
        })
        .await?
        .into_result()?;
        *self.secret.write().unwrap() = Secret::Keys(new_keys);
        Ok(())
    }

    /// A client that reads snapshot `name`. It uses the same servers and
    /// the same session (a renewal by either client works for both). Every
    /// read is made at the snapshot, and every write is refused with
    /// `EROFS` before it is sent.
    pub fn at(&self, name: &str) -> Remote {
        let secret = match &*self.secret.read().unwrap() {
            Secret::Password(p) => Secret::Password(p.clone()),
            Secret::Keys(k) => Secret::Keys(k.clone()),
        };
        Remote {
            servers: self.servers.clone(),
            username: self.username.clone(),
            secret: RwLock::new(secret),
            min_kdf: self.min_kdf,
            identity: RwLock::new(self.identity()),
            chunk_reads: AtomicU64::new(0),
            session: Arc::clone(&self.session),
            current: AtomicUsize::new(self.current.load(Ordering::Relaxed)),
            chunk_size: self.chunk_size,
            batch_bytes: self.batch_bytes,
            protocol: self.protocol,
            grid: self.grid,
            objects: self.objects.clone(),
            objects_ok: self.objects_ok,
            snapshot: name.to_string(),
        }
    }

    /// The snapshot that this client reads at, if it is not the live
    /// filesystem.
    pub fn snapshot(&self) -> Option<&str> {
        (!self.snapshot.is_empty()).then_some(self.snapshot.as_str())
    }

    /// The account that this client logs in as.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The account's key pair. `None` until a login opens it.
    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.identity.read().unwrap().clone()
    }

    /// How many chunks this client asked a server for, not counting
    /// unchanged ones.
    pub fn chunk_reads(&self) -> u64 {
        self.chunk_reads.load(Ordering::Relaxed)
    }

    /// Logs in on whichever server answers, and keeps the session for every
    /// later request. A refusal (a wrong password, or an account with no
    /// filesystem identity) comes back as the server's errno. This does not
    /// use `call`, which logs in itself when a session is refused: a login
    /// must work with no session, and must not recurse.
    async fn login(&self) -> Result<(), FsError> {
        let mut req = LoginRequest {
            username: self.username.clone(),
            auth: Vec::new(),
        };
        // The first login with a password: the keys from it, kept until
        // the server accepts them.
        let mut derived = None;
        let password = match &*self.secret.read().unwrap() {
            Secret::Keys(keys) => {
                req.auth = keys.auth.to_vec();
                derived = Some(keys.clone());
                None
            }
            Secret::Password(password) => Some(password.clone()),
        };
        if let Some(password) = password {
            let settings = self
                .first_answer("a prelogin", |mut c| {
                    let req = PreloginRequest {
                        username: self.username.clone(),
                    };
                    async move { c.prelogin(req).await }
                })
                .await?
                .into_result()?;
            let params = KdfParams::decode(&settings.params)
                .map_err(|e| FsError::new(errno::EIO, e.to_string()))?;
            params
                .check(self.min_kdf)
                .map_err(|e| FsError::new(errno::EACCES, format!("login refused: {e}")))?;
            let keys = derive(&password, &self.username, settings.salt, params).await?;
            req.auth = keys.auth.to_vec();
            derived = Some(UnlockKeys {
                auth: Zeroizing::new(keys.auth),
                kek: keys.kek.clone(),
            });
        }
        let session = self
            .first_answer("a login", |mut c| {
                let req = req.clone();
                async move { c.login(req).await }
            })
            .await?
            .into_result()?;
        if let Some(keys) = derived
            && self.identity().is_none()
        {
            // The server accepted `auth`, so the password was correct. If
            // the private key does not open now, it was changed, not
            // mistyped.
            let identity =
                Identity::unwrap(&keys.kek, &self.username, &session.wrapped_private_key)
                    .map_err(|e| FsError::new(errno::EIO, format!("login: {e}")))?;
            *self.identity.write().unwrap() = Some(Arc::new(identity));
            *self.secret.write().unwrap() = Secret::Keys(keys);
        }
        *self.session.write().unwrap() = session.token;
        Ok(())
    }

    /// The first answer that any server gives to `request`, trying each
    /// server in turn from the current one. For requests that come before a
    /// session. A login must not go through `call`, which logs in itself
    /// when a session is refused.
    async fn first_answer<T, Fut>(
        &self,
        what: &str,
        request: impl Fn(Client) -> Fut,
    ) -> Result<T, FsError>
    where
        Fut: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        let n = self.servers.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut failures = Vec::new();
        for attempt in 0..n {
            let i = (start + attempt) % n;
            let (address, client) = &self.servers[i];
            match request(client.clone()).await {
                Ok(response) => {
                    self.current.store(i, Ordering::Relaxed);
                    return Ok(response.into_inner());
                }
                Err(status) => failures.push(format!("{address}: {}", status.message())),
            }
        }
        Err(FsError::new(
            errno::EIO,
            format!("no server answered {what}: {}", failures.join("; ")),
        ))
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// The keys that log this account in without its password, once a
    /// login has them (see `UnlockKeys`).
    pub fn unlock_keys(&self) -> Option<UnlockKeys> {
        match &*self.secret.read().unwrap() {
            Secret::Keys(keys) => Some(keys.clone()),
            Secret::Password(_) => None,
        }
    }

    /// The protocol version of the server that said hello (see
    /// `raft5fs_proto::PROTOCOL`); 0 for a server too old to say.
    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    pub fn batch_bytes(&self) -> u64 {
        self.batch_bytes
    }

    pub fn grid(&self) -> Option<ObjectGrid> {
        self.grid
    }

    /// The client that fetches from object storage, through URLs that the
    /// servers sign.
    pub fn objects(&self) -> &http::Client {
        &self.objects
    }

    /// This client, reading as a client that cannot fetch from object
    /// storage. For tests of what such a client is told.
    pub fn without_object_reads(mut self) -> Self {
        self.objects_ok = false;
        self
    }

    /// Runs `request` on the current server, and moves through the other
    /// servers as `retry` allows. A gRPC status always means that no
    /// filesystem answer came back, because filesystem errors come inside
    /// the response. So every status is a failure of the server, never of
    /// the request.
    async fn call<T, Fut>(
        &self,
        retry: Retry,
        request: impl Fn(Client) -> Fut,
    ) -> Result<T, FsError>
    where
        Fut: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        if retry != Retry::ReadOnly && !self.snapshot.is_empty() {
            return Err(FsError::new(errno::EROFS, "a snapshot is read-only"));
        }
        let n = self.servers.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut failures = Vec::new();
        let mut renewed = false;
        for attempt in 0..n {
            let i = (start + attempt) % n;
            let (address, client) = &self.servers[i];
            let mut outcome = request(client.clone()).await;
            // The only status about the request and not the server: the
            // session is not valid. Renew it once for each call (a request
            // refused just after a new login has a problem that a second
            // login will not fix), and send the request again. This is safe
            // even for requests that are never sent again, because a
            // request refused for its session was never run.
            if let Err(status) = &outcome
                && status.code() == Code::Unauthenticated
                && !renewed
            {
                renewed = true;
                self.login().await?;
                outcome = request(client.clone()).await;
            }
            match outcome {
                Ok(response) => {
                    self.current.store(i, Ordering::Relaxed);
                    return Ok(response.into_inner());
                }
                Err(status) if status.code() == Code::Unauthenticated => {
                    return Err(FsError::new(
                        errno::EACCES,
                        format!("{address} refused a fresh session: {}", status.message()),
                    ));
                }
                Err(status) => {
                    failures.push(format!("{address}: {}", status.message()));
                    // Whatever happens next, the next request should start
                    // at a different server.
                    self.current.store((i + 1) % n, Ordering::Relaxed);
                    if !retry.allows(&status) {
                        break;
                    }
                }
            }
        }
        Err(FsError::new(
            errno::EIO,
            format!("no server answered: {}", failures.join("; ")),
        ))
    }

    pub async fn getattr(&self, ino: u64) -> Result<Attr, FsError> {
        let req = InodeRequest {
            ino,
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.get_attr(req).await }
        })
        .await?
        .into_result()
    }

    /// The entry `name` (a tag) in `parent`: its attributes, and its sealed
    /// name as the listing has it. The caller must check the name, because
    /// only that proves that the entry names the inode the server says.
    pub async fn lookup(&self, parent: u64, name: &OsStr) -> Result<(Attr, Vec<u8>), FsError> {
        let req = NameRequest {
            parent,
            name: name_bytes(name),
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.lookup(req).await }
        })
        .await?
        .into_result()
    }

    /// access(2).
    pub async fn access(&self, ino: u64, mask: u32) -> Result<(), FsError> {
        let req = AccessRequest {
            ino,
            mask,
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.access(req).await }
        })
        .await?
        .into_result()
    }

    pub async fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let req = InodeRequest {
            ino,
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.read_dir(req).await }
        })
        .await?
        .into_result()
    }

    /// Changes mode, size, or times. To make a file shorter, the client
    /// must first seal its new last chunk again (see `Vault::setattr`).
    pub async fn setattr(&self, ino: u64, changes: SetAttr) -> Result<Attr, FsError> {
        let req = SetAttrRequest::new(ino, changes);
        self.call(
            Retry::Idempotent,
            |mut c| async move { c.set_attr(req).await },
        )
        .await?
        .into_result()
    }

    fn create_request(parent: u64, name: &OsStr, perm: u16, new: &NewNode) -> CreateRequest {
        CreateRequest {
            parent,
            name: name_bytes(name),
            perm: perm.into(),
            ino: new.ino,
            node_keys: new.keys.clone(),
            sealed_name: new.sealed_name.clone(),
        }
    }

    /// `name` is the tag, and `new` holds the reserved inode, its key
    /// record, and its sealed name (see `vault`).
    pub async fn mkdir(
        &self,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        let req = Self::create_request(parent, name, perm, new);
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.mkdir(req).await }
        })
        .await?
        .into_result()
    }

    /// Same as `mkdir`, for a file.
    pub async fn create(
        &self,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        let req = Self::create_request(parent, name, perm, new);
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.create(req).await }
        })
        .await?
        .into_result()
    }

    /// Removes a file and returns its inode.
    pub async fn unlink(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let req = NameRequest {
            parent,
            name: name_bytes(name),
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.unlink(req).await }
        })
        .await?
        .into_result()
    }

    /// Moves a name and returns the inode it replaced, if any. `sealed` has
    /// the moved inode, its new name sealed, and, for a move to another
    /// directory, its key record wrapped again (see `SealedMove`).
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
        sealed: &SealedMove,
    ) -> Result<Option<u64>, FsError> {
        let req = RenameRequest {
            parent,
            name: name_bytes(name),
            new_parent,
            new_name: name_bytes(new_name),
            noreplace,
            node_keys: sealed.node_keys.clone(),
            moved_ino: sealed.ino,
            sealed_new_name: sealed.sealed_name.clone(),
        };
        let replaced = self
            .call(Retry::Once, |mut c| {
                let req = req.clone();
                async move { c.rename(req).await }
            })
            .await?
            .into_result()?;
        Ok((replaced != 0).then_some(replaced))
    }

    /// Removes an empty directory and returns its inode.
    pub async fn rmdir(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let req = NameRequest {
            parent,
            name: name_bytes(name),
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.rmdir(req).await }
        })
        .await?
        .into_result()
    }

    /// An inode number reserved for this account's next create. A resend
    /// only reserves another number, which nothing uses.
    pub async fn allocate_inode(&self) -> Result<u64, FsError> {
        self.call(Retry::Idempotent, |mut c| async move {
            c.allocate_inode(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// This account's grant above `ino`, and the key records from the
    /// granted directory down to it.
    pub async fn key_path(&self, ino: u64) -> Result<KeyPath, FsError> {
        let req = InodeRequest {
            ino,
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.get_key_path(req).await }
        })
        .await?
        .into_result()
    }

    /// Every grant made to this account.
    pub async fn list_grants(&self) -> Result<Vec<Grant>, FsError> {
        let req = ListGrantsRequest {
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.list_grants(req).await }
        })
        .await?
        .into_result()
    }

    /// Every snapshot, oldest first.
    pub async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>, FsError> {
        self.call(Retry::ReadOnly, |mut c| async move {
            c.list_snapshots(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// `user`'s public key, as the server has it.
    pub async fn public_key(&self, user: &str) -> Result<Vec<u8>, FsError> {
        let req = PublicKeyRequest {
            username: user.to_string(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.public_key(req).await }
        })
        .await?
        .into_result()
    }

    /// Grants `grant.ino` to `user`, with the node's new grantee list
    /// sealed under its key. It replaces the list at
    /// `expected_grantees_seq` (`EAGAIN` if that changed in the meantime).
    /// A resend after the grant was stored gets `EAGAIN` for the same
    /// reason. The caller then reads again and finds the grant there.
    pub async fn grant(
        &self,
        user: &str,
        grant: Grant,
        sealed_grantees: Vec<u8>,
        expected_grantees_seq: u64,
        listed: Vec<String>,
    ) -> Result<(), FsError> {
        let req = GrantRequest {
            username: user.to_string(),
            grant: Some(grant.into()),
            sealed_grantees,
            expected_grantees_seq,
            listed,
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.grant(req).await }
        })
        .await?
        .into_result()
    }

    /// Makes a volume at reserved inode `new.ino`, granted to this account.
    pub async fn create_volume(
        &self,
        new: &NewNode,
        perm: u16,
        sealed_key: Vec<u8>,
        sealed_label: Vec<u8>,
        sealed_grantees: Vec<u8>,
    ) -> Result<Attr, FsError> {
        let req = CreateVolumeRequest {
            ino: new.ino,
            perm: perm.into(),
            node_keys: new.keys.clone(),
            sealed_key,
            sealed_label,
            sealed_grantees,
        };
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.create_volume(req).await }
        })
        .await?
        .into_result()
    }

    /// Removes an empty volume.
    pub async fn delete_volume(&self, ino: u64) -> Result<(), FsError> {
        let req = InodeRequest {
            ino,
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.delete_volume(req).await }
        })
        .await?
        .into_result()
    }

    /// Reads up to one batch of `ino`'s sealed chunks from `first`, and its
    /// attributes. Can return fewer than `count`. `known_seqs[i]`, if not
    /// 0, is the seq that chunk `first + i` is cached at here. A chunk
    /// still at that seq comes back `unchanged`, without its bytes.
    pub async fn read_chunks(
        &self,
        ino: u64,
        first: u64,
        count: u32,
        known_seqs: &[u64],
    ) -> Result<Chunks, FsError> {
        let req = ReadChunksRequest {
            ino,
            first,
            count,
            known_seqs: known_seqs.to_vec(),
            snapshot: self.snapshot.clone(),
            objects_ok: self.objects_ok,
        };
        let read = self
            .call(Retry::ReadOnly, |mut c| {
                let req = req.clone();
                async move { c.read_chunks(req).await }
            })
            .await?
            .into_result()?;
        let sent = read.chunks.iter().filter(|c| !c.unchanged).count();
        self.chunk_reads.fetch_add(sent as u64, Ordering::Relaxed);
        Ok(read)
    }

    /// Stores sealed chunks of `ino` if each one is at its `expected_seq`,
    /// and grows the file to `end`. Returns its attributes and the chunks'
    /// new seq. Sent again after any failure except a timeout (see the
    /// module doc): every chunk is replaced whole or guarded by its seq, so
    /// a resend after it was stored changes nothing more.
    pub async fn write_chunks(
        &self,
        ino: u64,
        chunks: &[ChunkWrite],
        end: u64,
    ) -> Result<(Attr, u64), FsError> {
        let req = WriteChunksRequest {
            ino,
            chunks: chunks.iter().cloned().map(Into::into).collect(),
            end,
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.write_chunks(req).await }
        })
        .await?
        .into_result()
    }

    /// Names and upload URLs for new blocks of `ino`, one for each block in
    /// `blocks`. A resend only mints names that nothing uses, which garbage
    /// collection removes.
    pub async fn prepare_uploads(
        &self,
        ino: u64,
        blocks: &[BlockUpload],
    ) -> Result<Vec<PreparedUpload>, FsError> {
        let req = PrepareUploadsRequest {
            ino,
            blocks: blocks.iter().copied().map(Into::into).collect(),
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.prepare_uploads(req).await }
        })
        .await?
        .into_result()
    }

    /// Every node at or below `top` that is granted to anyone.
    pub async fn grants_under(&self, top: u64) -> Result<Vec<GrantedNode>, FsError> {
        let req = InodeRequest {
            ino: top,
            snapshot: self.snapshot.clone(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.grants_under(req).await }
        })
        .await?
        .into_result()
    }

    /// Gives nodes new keys (see `FsCore::rotate`). A resend after it was
    /// stored finds new versions and gets `EAGAIN`, which the caller
    /// already handles by checking again.
    pub async fn rotate(&self, rotations: Vec<Rotation>) -> Result<(), FsError> {
        let req = RotateRequest {
            rotations: rotations.into_iter().map(Into::into).collect(),
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.rotate(req).await }
        })
        .await?
        .into_result()
    }

    /// Seals chunks of `ino` again under its current key version (see
    /// `FsCore::reseal_chunks`). Each chunk is guarded by its seq, so a
    /// resend after it was stored gets `EAGAIN`. The caller then reads
    /// again and finds the work done.
    pub async fn reseal_chunks(&self, ino: u64, chunks: &[ChunkWrite]) -> Result<(), FsError> {
        let req = ResealChunksRequest {
            ino,
            chunks: chunks.iter().cloned().map(Into::into).collect(),
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.reseal_chunks(req).await }
        })
        .await?
        .into_result()
    }

    /// Seals entry names of `dir` again under its current key version (see
    /// `FsCore::reseal_names`). Storing the same names twice changes
    /// nothing more.
    pub async fn reseal_names(&self, dir: u64, names: &[ResealedName]) -> Result<(), FsError> {
        let req = ResealNamesRequest {
            dir,
            names: names.iter().cloned().map(Into::into).collect(),
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.reseal_names(req).await }
        })
        .await?
        .into_result()
    }

    /// `ENOTSUP` unless the servers speak protocol `version` or later.
    fn needs_protocol(&self, version: u32, what: &str) -> Result<(), FsError> {
        if self.protocol >= version {
            Ok(())
        } else {
            Err(FsError::new(
                errno::ENOTSUP,
                format!("the servers are too old for {what}"),
            ))
        }
    }

    /// This account's record: its capabilities, and where it came from.
    pub async fn account(&self) -> Result<AccountInfo, FsError> {
        self.needs_protocol(2, "capabilities")?;
        self.call(Retry::ReadOnly, |mut c| async move {
            c.get_account(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// Invites a new user `user`, who gets `caps`, as an admin. Returns the
    /// one-time code, and the whole invitation if the servers know how
    /// users reach them.
    pub async fn issue_invite(
        &self,
        user: &str,
        caps: Caps,
    ) -> Result<(String, Option<String>), FsError> {
        self.needs_protocol(2, "invitations")?;
        let req = IssueInviteRequest {
            username: user.to_string(),
            capabilities: caps.bits(),
        };
        // Not sent again: a resend after it was stored would say the name
        // is taken.
        let issued = self
            .call(Retry::Once, |mut c| {
                let req = req.clone();
                async move { c.issue_invite(req).await }
            })
            .await?
            .into_result()?;
        let invitation = (!issued.invitation.is_empty()).then_some(issued.invitation);
        Ok((issued.code, invitation))
    }

    /// Every account, for an admin: enrolled ones, unused invitations, and
    /// public links.
    pub async fn list_users(&self) -> Result<Vec<UserEntry>, FsError> {
        self.needs_protocol(4, "user management")?;
        self.call(Retry::ReadOnly, |mut c| async move {
            c.list_users(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// Turns `user`'s capabilities in `on` on, and those in `off` off, as an
    /// admin. Returns their account as it is then.
    pub async fn set_capabilities(
        &self,
        user: &str,
        on: Caps,
        off: Caps,
    ) -> Result<AccountInfo, FsError> {
        self.needs_protocol(4, "user management")?;
        let req = SetCapabilitiesRequest {
            username: user.to_string(),
            on: on.bits(),
            off: off.bits(),
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.set_capabilities(req).await }
        })
        .await?
        .into_result()
    }

    /// A new invitation for existing user `user`, so they can enroll again,
    /// as an admin: the code, and the whole invitation if the servers know
    /// how users reach them.
    pub async fn reissue_invite(&self, user: &str) -> Result<(String, Option<String>), FsError> {
        self.needs_protocol(4, "user management")?;
        let req = UsernameRequest {
            username: user.to_string(),
        };
        // Not sent again: a second code would replace the first.
        let issued = self
            .call(Retry::Once, |mut c| {
                let req = req.clone();
                async move { c.reissue_invite(req).await }
            })
            .await?
            .into_result()?;
        let invitation = (!issued.invitation.is_empty()).then_some(issued.invitation);
        Ok((issued.code, invitation))
    }

    /// Who owns volume `ino`, and any transfer offered.
    pub async fn get_volume(&self, ino: u64) -> Result<VolumeInfo, FsError> {
        self.needs_protocol(6, "volume owners")?;
        let req = InodeRequest {
            ino,
            snapshot: String::new(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.get_volume(req).await }
        })
        .await?
        .into_result()
    }

    /// Folders and files that no account can reach any more, as an admin.
    pub async fn list_unreachable(&self) -> Result<Vec<Unreachable>, FsError> {
        self.needs_protocol(5, "finding unreachable folders")?;
        self.call(Retry::ReadOnly, |mut c| async move {
            c.list_unreachable(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// Deletes unreachable part `ino`, with everything in it, as an admin.
    pub async fn delete_unreachable(&self, ino: u64) -> Result<(), FsError> {
        self.needs_protocol(5, "finding unreachable folders")?;
        let req = InodeRequest {
            ino,
            snapshot: String::new(),
        };
        // Not sent again: a resend after it was done would find nothing
        // to remove.
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.delete_unreachable(req).await }
        })
        .await?
        .into_result()
    }

    /// What removing `user`, or letting them enroll again, would leave that
    /// no account can reach, as an admin.
    pub async fn removal_impact(&self, user: &str) -> Result<Vec<Unreachable>, FsError> {
        self.needs_protocol(5, "finding unreachable folders")?;
        let req = UsernameRequest {
            username: user.to_string(),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.removal_impact(req).await }
        })
        .await?
        .into_result()
    }

    /// Removes `user`, as an admin.
    pub async fn delete_user(&self, user: &str) -> Result<(), FsError> {
        self.needs_protocol(4, "user management")?;
        let req = UsernameRequest {
            username: user.to_string(),
        };
        // Not sent again: a resend after it was done would say there is no
        // such user.
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.delete_user(req).await }
        })
        .await?
        .into_result()
    }

    /// Makes the account for a public link to folder `folder`: `user`, with
    /// a new key pair wrapped under `secret`, and `note` for this account
    /// alone. Returns the link's public key, to pin and grant to.
    pub async fn create_link_account(
        &self,
        user: &str,
        secret: &str,
        expires: Option<u64>,
        folder: u64,
        note: Vec<u8>,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        self.needs_protocol(2, "public links")?;
        let identity = Identity::generate();
        let (keys, _) = account_keys(user, secret, KdfParams::SECRET, &identity).await?;
        let req = CreateLinkAccountRequest {
            username: user.to_string(),
            keys: Some(keys),
            expires: expires.unwrap_or(0),
            folder,
            note,
        };
        // Not sent again: a resend after it was stored would say the name
        // is taken.
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.create_link_account(req).await }
        })
        .await?
        .into_result()?;
        Ok(identity.public_key())
    }

    /// This account's sealed trusted keys and their version (see
    /// `Vault::sync_pins`): 0 and nothing if there are none yet.
    pub async fn get_pins(&self) -> Result<(u64, Vec<u8>), FsError> {
        self.needs_protocol(3, "trusted keys on the servers")?;
        self.call(Retry::ReadOnly, |mut c| async move {
            c.get_pins(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// Replaces them if they are still at `expected`; returns the new
    /// version. `EAGAIN` if another device changed them meanwhile, and also
    /// for a resend after it was stored: either way, read them again.
    pub async fn put_pins(&self, expected: u64, sealed: Vec<u8>) -> Result<u64, FsError> {
        self.needs_protocol(3, "trusted keys on the servers")?;
        let req = PutPinsRequest {
            expected_version: expected,
            sealed,
        };
        Ok(self
            .call(Retry::Idempotent, |mut c| {
                let req = req.clone();
                async move { c.put_pins(req).await }
            })
            .await?
            .into_result()?
            .0)
    }

    /// The public links that this account made.
    pub async fn list_links(&self) -> Result<Vec<LinkAccount>, FsError> {
        self.needs_protocol(2, "public links")?;
        self.call(Retry::ReadOnly, |mut c| async move {
            c.list_links(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// Cuts `ino`'s key history short (see `FsCore::prune_keys`). A resend
    /// after it was stored finds the record already cut, and does nothing.
    pub async fn prune_keys(
        &self,
        ino: u64,
        expected_version: u32,
        node_keys: Vec<u8>,
    ) -> Result<(), FsError> {
        let req = PruneKeysRequest {
            ino,
            expected_version,
            node_keys,
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.prune_keys(req).await }
        })
        .await?
        .into_result()
    }
}
