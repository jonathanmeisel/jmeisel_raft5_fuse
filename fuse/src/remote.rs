//! The client end of the raft5fs protocol: the same operations as
//! `FsCore`, answered by whichever of several servers is reachable.
//!
//! Servers are stateless, so any of them can answer any request. What may
//! be resent to another after a failure depends on the request (see
//! `Retry`):
//!
//! - Read-only requests are resent on any failure: running them twice
//!   changes nothing.
//! - Writes and attribute changes are resent unless the request timed
//!   out. Resending one that already landed is harmless -- the same bytes
//!   at the same offset, the same mode -- but not one that might still be
//!   *running*: a server that merely timed out could commit after the
//!   resend and after a later write to the same range, silently putting
//!   the older bytes back. Every other failure means the request is not
//!   running anywhere -- the server was unreachable, or its connection
//!   broke under the request (which tonic reports as `Unknown`, not
//!   `Unavailable`), and the server itself never answers with a status,
//!   since filesystem errors travel inside the response. So only a
//!   timeout reports `EIO` rather than failing over.
//! - Create, mkdir, unlink, rmdir and rename are never resent: if one reached the
//!   old server, a retry would report a false `EEXIST` or `ENOENT`. They
//!   fail with `EIO`, and the next request starts from the next server.
//!
//! Every request has a deadline, so a server that stops answering can't
//! hang a FUSE handler -- which would wedge the mount, and anything that
//! touches it.
//!
//! A mount logs in as one user, when connecting, and every request
//! carries that session. A session that has expired (or that a server
//! otherwise refuses) is renewed by logging in again with the same
//! credentials, and the request then retried -- which is why they are
//! kept for the life of the mount.
//!
//! On an encrypted filesystem the password itself never goes to a server.
//! The first login stretches it (with the salt Prelogin hands out) into
//! `auth`, which is what logs in, and a key that opens the account's
//! private key from the login's reply. From then on only `auth` is kept,
//! for renewals; the password is dropped.

use std::ffi::OsStr;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::{Arc, RwLock};
use std::time::Duration;

use raft5fs_crypto::identity::{Identity, PUBLIC_KEY_LEN};
use raft5fs_crypto::password::{self, AUTH_LEN, KdfParams, PasswordKeys, new_salt, verifier};
use zeroize::Zeroizing;

use raft5fs_proto::convert::{name_bytes, session_to_metadata};
use raft5fs_proto::pb::fs_client::FsClient;
use raft5fs_proto::pb::{
    AccessRequest, AccountKeys, ChangePasswordRequest, CreateRequest, CreateVolumeRequest,
    EnrolRequest, GrantRequest, HelloRequest, InodeRequest, LoginRequest, NameRequest, NoArgs,
    PreloginRequest, PublicKeyRequest, ReadChunksRequest, ReadRequest, RenameRequest,
    SetAttrRequest, WriteChunksRequest, WriteRequest,
};
use raft5fs_proto::types::{
    Attr, ChunkWrite, DirItem, FsError, Grant, KeyPath, NewNode, SealedChunk, SealedMove, SetAttr,
    WriteError,
};
use tonic::Code;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

/// The largest message the client sends: one write batch, which is at most
/// one maximum-size chunk (8 MiB), plus framing.
const MAX_MESSAGE_BYTES: usize = 9 << 20;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Generous: a write commits a batch of up to 8 MiB through raft, and
/// may retry under contention. A request that takes longer is treated as
/// a failure of that server.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Pings on idle connections, so a server that died silently is noticed
/// before the next request has to time out on it.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Who a mount logs in as.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// The session token every request carries; empty until the first login.
type Session = Arc<RwLock<String>>;

/// Stamps every request with the current session.
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

type Client = FsClient<InterceptedService<Channel, Authorize>>;

/// What a login presents: the password, until an encrypted filesystem's
/// first login has turned it into `auth`.
enum Secret {
    Password(Zeroizing<String>),
    Auth(Zeroizing<[u8; AUTH_LEN]>),
}

pub struct Remote {
    servers: Vec<(String, Client)>,
    username: String,
    secret: RwLock<Secret>,
    /// Whether the filesystem is encrypted, from Hello.
    encrypted: bool,
    /// The account's key pair, once an encrypted login has opened it.
    identity: RwLock<Option<Arc<Identity>>>,
    session: Session,
    /// Where to start: the last server that answered.
    current: AtomicUsize,
    chunk_size: u64,
    batch_bytes: u64,
}

/// Stretches `password` off the async threads: Argon2 is slow on purpose.
async fn derive(password: &str, salt: Vec<u8>, params: KdfParams) -> Result<PasswordKeys, FsError> {
    let password = Zeroizing::new(password.to_string());
    tokio::task::spawn_blocking(move || password::derive(password.as_bytes(), &salt, params))
        .await
        .expect("key derivation panicked")
        .map_err(|e| FsError::new(libc::EIO, e.to_string()))
}

/// What the server keeps for an account whose password is `password` and
/// key pair `identity`, under a fresh salt; and the `auth` it will take.
async fn account_keys(
    username: &str,
    password: &str,
    params: KdfParams,
    identity: &Identity,
) -> Result<(AccountKeys, Zeroizing<[u8; AUTH_LEN]>), FsError> {
    let salt = new_salt();
    let keys = derive(password, salt.to_vec(), params).await?;
    let account = AccountKeys {
        salt: salt.to_vec(),
        kdf_params: params.encode().to_vec(),
        verifier: verifier(&keys.auth).to_vec(),
        public_key: identity.public_key().to_vec(),
        wrapped_private_key: identity.wrap(&keys.kek, username),
    };
    Ok((account, Zeroizing::new(keys.auth)))
}

/// When a request may be resent to another server; see the module doc.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retry {
    /// After any failure.
    ReadOnly,
    /// After any failure but a timeout.
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
    /// Connects to whichever of `addresses` (`https://host:port`, or
    /// `http://` without `tls`) answers first, learns the filesystem's
    /// chunk geometry from it, and logs in with `credentials`.
    pub async fn connect(
        addresses: &[String],
        credentials: Credentials,
        tls: Option<ClientTlsConfig>,
    ) -> Result<Self, String> {
        let remote = Self::dial(addresses, credentials, tls).await?;
        remote.login().await.map_err(|e| e.message)?;
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
        let session = Session::default();
        let authorize = Authorize(Arc::clone(&session));
        let mut servers = Vec::new();
        for address in addresses {
            let mut endpoint =
                Endpoint::from_shared(address.clone()).map_err(|e| format!("{address}: {e}"))?;
            if let Some(tls) = &tls {
                endpoint = endpoint
                    .tls_config(tls.clone())
                    .map_err(|e| format!("{address}: {e}"))?;
            }
            let channel = endpoint
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
                .keep_alive_timeout(KEEPALIVE_TIMEOUT)
                .keep_alive_while_idle(true)
                .connect_lazy();
            let client = FsClient::with_interceptor(channel, authorize.clone())
                .max_encoding_message_size(MAX_MESSAGE_BYTES);
            servers.push((address.clone(), client));
        }
        let mut remote = Self {
            servers,
            username: credentials.username,
            secret: RwLock::new(Secret::Password(Zeroizing::new(credentials.password))),
            encrypted: false,
            identity: RwLock::new(None),
            session,
            current: AtomicUsize::new(0),
            chunk_size: 0,
            batch_bytes: 0,
        };
        let hello = remote
            .call(Retry::ReadOnly, |mut c| async move {
                c.hello(HelloRequest {}).await
            })
            .await
            .map_err(|e| e.message)?;
        remote.chunk_size = hello.chunk_size;
        remote.batch_bytes = hello.batch_bytes;
        remote.encrypted = hello.encrypted;
        Ok(remote)
    }

    /// Enrols `username` on the encrypted filesystem at `addresses`, with
    /// the one-time `code` an administrator issued: makes the account a
    /// key pair, and stores it wrapped under what `password` yields.
    /// Returns the new public key, for the user to note its fingerprint.
    pub async fn enrol(
        addresses: &[String],
        tls: Option<ClientTlsConfig>,
        username: &str,
        code: &str,
        password: &str,
        params: KdfParams,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        let credentials = Credentials {
            username: username.to_string(),
            password: String::new(),
        };
        let remote = Self::dial(addresses, credentials, tls)
            .await
            .map_err(|e| FsError::new(libc::EIO, e))?;
        remote.require_encrypted()?;
        let identity = Identity::generate();
        let (keys, _) = account_keys(username, password, params, &identity).await?;
        let req = EnrolRequest {
            username: username.to_string(),
            code: code.to_string(),
            keys: Some(keys),
        };
        // Never resent: a code is used up by the first enrolment, so a
        // resend of one that landed would report a false refusal.
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
    /// stays -- only its wrapping changes -- so everything shared with it
    /// stays readable. Needs an encrypted login, which proves the old one.
    pub async fn change_password(
        &self,
        new_password: &str,
        params: KdfParams,
    ) -> Result<(), FsError> {
        self.require_encrypted()?;
        let identity = self
            .identity()
            .ok_or_else(|| FsError::new(libc::EACCES, "not logged in: no key pair to re-wrap"))?;
        let old_auth = match &*self.secret.read().unwrap() {
            Secret::Auth(auth) => auth.to_vec(),
            Secret::Password(_) => {
                return Err(FsError::new(libc::EACCES, "not logged in"));
            }
        };
        let (keys, new_auth) =
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
        *self.secret.write().unwrap() = Secret::Auth(new_auth);
        Ok(())
    }

    /// Whether the filesystem is encrypted.
    pub fn encrypted(&self) -> bool {
        self.encrypted
    }

    /// The account's key pair: there after an encrypted filesystem's login.
    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.identity.read().unwrap().clone()
    }

    fn require_encrypted(&self) -> Result<(), FsError> {
        if self.encrypted {
            Ok(())
        } else {
            Err(FsError::new(
                libc::EOPNOTSUPP,
                "this filesystem isn't encrypted",
            ))
        }
    }

    /// Logs in, on whichever server answers, and keeps the session for
    /// every request after. A refusal (a wrong password, an account with
    /// no filesystem identity) comes back as the server's errno.
    ///
    /// Not through `call`, which logs in itself when a session is
    /// refused: this has to work with no session, and must not recurse.
    async fn login(&self) -> Result<(), FsError> {
        let mut req = LoginRequest {
            username: self.username.clone(),
            password: String::new(),
            auth: Vec::new(),
        };
        // An encrypted filesystem's first login: the keys the password
        // yields, kept until the server has accepted them.
        let mut derived = None;
        let password = match &*self.secret.read().unwrap() {
            Secret::Auth(auth) => {
                req.auth = auth.to_vec();
                None
            }
            Secret::Password(password) => Some(password.clone()),
        };
        if let Some(password) = password {
            if self.encrypted {
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
                    .map_err(|e| FsError::new(libc::EIO, e.to_string()))?;
                let keys = derive(&password, settings.salt, params).await?;
                req.auth = keys.auth.to_vec();
                derived = Some(keys);
            } else {
                req.password = password.to_string();
            }
        }
        let session = self
            .first_answer("a login", |mut c| {
                let req = req.clone();
                async move { c.login(req).await }
            })
            .await?
            .into_result()?;
        if let Some(keys) = derived {
            // The server took `auth`, so the password was right: what
            // fails to open now was tampered with, not mistyped.
            let identity =
                Identity::unwrap(&keys.kek, &self.username, &session.wrapped_private_key)
                    .map_err(|e| FsError::new(libc::EIO, format!("login: {e}")))?;
            *self.identity.write().unwrap() = Some(Arc::new(identity));
            *self.secret.write().unwrap() = Secret::Auth(Zeroizing::new(keys.auth));
        }
        *self.session.write().unwrap() = session.token;
        Ok(())
    }

    /// The first answer any server gives `request`, trying each in turn
    /// from the current one. For the requests that come before a session
    /// -- not through `call`, which logs in itself when a session is
    /// refused, and so must never be what a login goes through.
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
            libc::EIO,
            format!("no server answered {what}: {}", failures.join("; ")),
        ))
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    pub fn batch_bytes(&self) -> u64 {
        self.batch_bytes
    }

    /// Runs `request` against the current server, moving through the rest
    /// as `retry` allows. A gRPC status always means no filesystem answer
    /// came back -- filesystem errors travel inside the response -- so
    /// every status is a failure of the server, never of the request.
    async fn call<T, Fut>(
        &self,
        retry: Retry,
        request: impl Fn(Client) -> Fut,
    ) -> Result<T, FsError>
    where
        Fut: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        let n = self.servers.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut failures = Vec::new();
        let mut renewed = false;
        for attempt in 0..n {
            let i = (start + attempt) % n;
            let (address, client) = &self.servers[i];
            let mut outcome = request(client.clone()).await;
            // The one status about the request rather than the server:
            // the session is no good. Renewed once per call -- a request
            // refused straight after a fresh login has a problem a second
            // login won't fix -- and the request sent again. That is safe
            // even for requests that are never resent: one refused for its
            // session was never carried out.
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
                        libc::EACCES,
                        format!("{address} refused a fresh session: {}", status.message()),
                    ));
                }
                Err(status) => {
                    failures.push(format!("{address}: {}", status.message()));
                    // Whatever happens next, the next request should start
                    // somewhere else.
                    self.current.store((i + 1) % n, Ordering::Relaxed);
                    if !retry.allows(&status) {
                        break;
                    }
                }
            }
        }
        Err(FsError::new(
            libc::EIO,
            format!("no server answered: {}", failures.join("; ")),
        ))
    }

    pub async fn getattr(&self, ino: u64) -> Result<Attr, FsError> {
        let req = InodeRequest { ino };
        self.call(
            Retry::ReadOnly,
            |mut c| async move { c.get_attr(req).await },
        )
        .await?
        .into_result()
    }

    pub async fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        let req = NameRequest {
            parent,
            name: name_bytes(name),
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.lookup(req).await }
        })
        .await?
        .into_result()
    }

    /// Opens the inode for `mask` (`R_OK`/`W_OK`), returning the handle
    /// that reads and writes through this open need.
    pub async fn open(&self, ino: u64, mask: u32) -> Result<String, FsError> {
        let req = AccessRequest { ino, mask };
        self.call(Retry::ReadOnly, |mut c| async move { c.open(req).await })
            .await?
            .into_result()
    }

    /// access(2).
    pub async fn access(&self, ino: u64, mask: u32) -> Result<(), FsError> {
        let req = AccessRequest { ino, mask };
        self.call(Retry::ReadOnly, |mut c| async move { c.access(req).await })
            .await?
            .into_result()
    }

    pub async fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let req = InodeRequest { ino };
        self.call(
            Retry::ReadOnly,
            |mut c| async move { c.read_dir(req).await },
        )
        .await?
        .into_result()
    }

    pub async fn read(&self, handle: &str, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        let req = ReadRequest {
            handle: handle.to_string(),
            offset,
            len: len as u32,
        };
        self.call(Retry::ReadOnly, |mut c| {
            let req = req.clone();
            async move { c.read(req).await }
        })
        .await?
        .into_result()
    }

    /// Resendable despite being a write: a batch commits whole or not at
    /// all, and storing the same bytes at the same offset again changes
    /// nothing. So a batch whose server went away mid-request is simply
    /// resent to another (but not one whose server only timed out; see
    /// the module doc).
    pub async fn write(&self, handle: &str, offset: u64, data: &[u8]) -> Result<Attr, WriteError> {
        let req = WriteRequest {
            handle: handle.to_string(),
            offset,
            data: data.to_vec(),
        };
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.write(req).await }
        })
        .await
        .map_err(|error| WriteError { written: 0, error })?
        .into_result()
    }

    /// `handle`, if the change comes through an open file, may permit a
    /// size change the mode alone wouldn't.
    pub async fn setattr(
        &self,
        ino: u64,
        changes: SetAttr,
        handle: Option<&str>,
    ) -> Result<Attr, FsError> {
        let req = SetAttrRequest::new(ino, changes, handle.map(str::to_string));
        self.call(Retry::Idempotent, |mut c| {
            let req = req.clone();
            async move { c.set_attr(req).await }
        })
        .await?
        .into_result()
    }

    fn create_request(
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: Option<&NewNode>,
    ) -> CreateRequest {
        CreateRequest {
            parent,
            name: name_bytes(name),
            perm: perm.into(),
            ino: new.map_or(0, |n| n.ino),
            node_keys: new.map(|n| n.keys.clone()).unwrap_or_default(),
            sealed_name: new.map(|n| n.sealed_name.clone()).unwrap_or_default(),
        }
    }

    /// `new`: on an encrypted filesystem, the reserved inode and its key
    /// record (see `vault`); `None` elsewhere.
    pub async fn mkdir(
        &self,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: Option<&NewNode>,
    ) -> Result<Attr, FsError> {
        let req = Self::create_request(parent, name, perm, new);
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.mkdir(req).await }
        })
        .await?
        .into_result()
    }

    /// Creates a file and opens it for reading and writing, returning its
    /// attributes and the handle.
    pub async fn create(
        &self,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: Option<&NewNode>,
    ) -> Result<(Attr, String), FsError> {
        let req = Self::create_request(parent, name, perm, new);
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.create(req).await }
        })
        .await?
        .into_result()
    }

    /// Removes a file, returning the inode it was.
    pub async fn unlink(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let req = NameRequest {
            parent,
            name: name_bytes(name),
        };
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.unlink(req).await }
        })
        .await?
        .into_result()
    }

    /// Moves a name, returning the inode it replaced, if any. `sealed`: on
    /// an encrypted filesystem, the moved inode, its new name sealed, and
    /// on a move to another directory its key record re-wrapped (see
    /// `SealedMove`).
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
        sealed: Option<&SealedMove>,
    ) -> Result<Option<u64>, FsError> {
        let req = RenameRequest {
            parent,
            name: name_bytes(name),
            new_parent,
            new_name: name_bytes(new_name),
            noreplace,
            node_keys: sealed.map(|m| m.node_keys.clone()).unwrap_or_default(),
            moved_ino: sealed.map_or(0, |m| m.ino),
            sealed_new_name: sealed.map(|m| m.sealed_name.clone()).unwrap_or_default(),
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

    /// Removes an empty directory, returning the inode it was.
    pub async fn rmdir(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let req = NameRequest {
            parent,
            name: name_bytes(name),
        };
        self.call(Retry::Once, |mut c| {
            let req = req.clone();
            async move { c.rmdir(req).await }
        })
        .await?
        .into_result()
    }

    /// An inode number reserved for this account's next create. Resending
    /// only reserves another, which nothing then uses.
    pub async fn allocate_inode(&self) -> Result<u64, FsError> {
        self.call(Retry::Idempotent, |mut c| async move {
            c.allocate_inode(NoArgs {}).await
        })
        .await?
        .into_result()
    }

    /// This account's grant over `ino`, and the key records from the
    /// granted directory down to it.
    pub async fn key_path(&self, ino: u64) -> Result<KeyPath, FsError> {
        let req = InodeRequest { ino };
        self.call(
            Retry::ReadOnly,
            |mut c| async move { c.get_key_path(req).await },
        )
        .await?
        .into_result()
    }

    /// Every grant made to this account.
    pub async fn list_grants(&self) -> Result<Vec<Grant>, FsError> {
        self.call(Retry::ReadOnly, |mut c| async move {
            c.list_grants(NoArgs {}).await
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

    /// Grants `grant.ino` to `user`. Resending one that landed writes the
    /// same grant again.
    pub async fn grant(&self, user: &str, grant: Grant) -> Result<(), FsError> {
        let req = GrantRequest {
            username: user.to_string(),
            grant: Some(grant.into()),
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
    ) -> Result<Attr, FsError> {
        let req = CreateVolumeRequest {
            ino: new.ino,
            perm: perm.into(),
            node_keys: new.keys.clone(),
            sealed_key,
            sealed_label,
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
        let req = InodeRequest { ino };
        self.call(
            Retry::Once,
            |mut c| async move { c.delete_volume(req).await },
        )
        .await?
        .into_result()
    }

    /// Up to a batch's worth of `ino`'s sealed chunks from `first` on,
    /// and its attributes. May return fewer than `count`.
    pub async fn read_chunks(
        &self,
        ino: u64,
        first: u64,
        count: u32,
    ) -> Result<(Attr, Vec<SealedChunk>), FsError> {
        let req = ReadChunksRequest { ino, first, count };
        self.call(
            Retry::ReadOnly,
            |mut c| async move { c.read_chunks(req).await },
        )
        .await?
        .into_result()
    }

    /// Stores sealed chunks of `ino`, if each is as its `expected_seq`
    /// says, and grows the file to `end`. Resent like `write`: every
    /// chunk replaced whole, or guarded by its seq, lands the same way
    /// twice.
    pub async fn write_chunks(
        &self,
        ino: u64,
        chunks: &[ChunkWrite],
        end: u64,
    ) -> Result<Attr, FsError> {
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
}
