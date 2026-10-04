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

use std::ffi::OsStr;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::{Arc, RwLock};
use std::time::Duration;

use raft5fs_proto::convert::{name_bytes, session_to_metadata};
use raft5fs_proto::pb::fs_client::FsClient;
use raft5fs_proto::pb::{
    AccessRequest, CreateRequest, HelloRequest, InodeRequest, LoginRequest, NameRequest,
    ReadRequest, RenameRequest, SetAttrRequest, WriteRequest,
};
use raft5fs_proto::types::{Attr, DirItem, FsError, SetAttr, WriteError};
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

pub struct Remote {
    servers: Vec<(String, Client)>,
    credentials: Credentials,
    session: Session,
    /// Where to start: the last server that answered.
    current: AtomicUsize,
    chunk_size: u64,
    batch_bytes: u64,
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
            credentials,
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
        remote.login().await.map_err(|e| e.message)?;
        Ok(remote)
    }

    /// Logs in, on whichever server answers, and keeps the session for
    /// every request after. A refusal (a wrong password, an account with
    /// no filesystem identity) comes back as the server's errno.
    ///
    /// Not through `call`, which logs in itself when a session is
    /// refused: this has to work with no session, and must not recurse.
    async fn login(&self) -> Result<(), FsError> {
        let req = LoginRequest {
            username: self.credentials.username.clone(),
            password: self.credentials.password.clone(),
        };
        let n = self.servers.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut failures = Vec::new();
        for attempt in 0..n {
            let i = (start + attempt) % n;
            let (address, client) = &self.servers[i];
            match client.clone().login(req.clone()).await {
                Ok(response) => {
                    self.current.store(i, Ordering::Relaxed);
                    let (token, _) = response.into_inner().into_result()?;
                    *self.session.write().unwrap() = token;
                    return Ok(());
                }
                Err(status) => failures.push(format!("{address}: {}", status.message())),
            }
        }
        Err(FsError::new(
            libc::EIO,
            format!("no server answered a login: {}", failures.join("; ")),
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

    fn create_request(parent: u64, name: &OsStr, perm: u16) -> CreateRequest {
        CreateRequest {
            parent,
            name: name_bytes(name),
            perm: perm.into(),
        }
    }

    pub async fn mkdir(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        let req = Self::create_request(parent, name, perm);
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
    ) -> Result<(Attr, String), FsError> {
        let req = Self::create_request(parent, name, perm);
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

    /// Moves a name, returning the inode it replaced, if any.
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
        let req = RenameRequest {
            parent,
            name: name_bytes(name),
            new_parent,
            new_name: name_bytes(new_name),
            noreplace,
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
}
