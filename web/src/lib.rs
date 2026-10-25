//! raft5fs in a browser: the client library behind a JavaScript API, for
//! the web app's Web Worker. Everything is sealed and opened here, so the
//! servers see what they see from a native client.
//!
//! - `enrol` and `login` are functions; `login` gives an `Fs`, which holds
//!   the session. Dropping it (the app ends the Worker) drops every key.
//! - Paths are strings from the root (`/`, `/<volume>/a/b`), as WebDAV
//!   uses them. Inodes stay inside, except as file handles (`open`).
//! - Failures reject with an `Error` whose `code` names the errno
//!   (`ENOENT`, ...), or `EFINGERPRINT` for a first share that needs the
//!   other user's fingerprint.
//! - Nothing secret is stored: only pins and the prune queue, through the
//!   app's `persist` function (see `store`).
#![cfg(target_arch = "wasm32")]

mod store;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use futures_util::future::{AbortHandle, LocalBoxFuture, join_all};
use js_sys::{Function, Promise, Uint8Array};
use raft5fs_client::prune_queue::PruneQueue;
use raft5fs_client::pruner::{self, PrunerConfig};
use raft5fs_client::remote::{ClientTlsConfig, Credentials, Remote, UnlockKeys};
use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_client::store::Store;
use raft5fs_client::vault::{KnownKeys, ShareTrust, Vault};
use raft5fs_crypto::identity::{PUBLIC_KEY_LEN, fingerprint, fingerprint_words};
use raft5fs_crypto::password::{AUTH_LEN, KdfParams, check_new_password};
use raft5fs_crypto::{KEY_LEN, Key};
use raft5fs_proto::errno;
use raft5fs_proto::invite::Invite;
use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{Attr, FsError, Kind, SetAttr};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use zeroize::Zeroizing;

use crate::store::BrowserStore;

/// The oldest server protocol (`raft5fs_proto::PROTOCOL`) this app works
/// with. Servers are built from source and the app ships on tags, so they
/// can drift apart.
const MIN_SERVER_PROTOCOL: u32 = 1;

/// The blob names in the browser store.
const PINS: &str = "known_keys";

/// The mode of what the app makes; grants decide access anyway.
const DIR_MODE: u16 = 0o755;
const FILE_MODE: u16 = 0o644;

/// One filesystem the app is built for: its servers.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    /// The servers' web ports, as `https://host:port`.
    servers: Vec<String>,
    /// The filesystem's id (`raft5fs_client::fs_id` of its CA).
    fs_id: String,
    /// Plain HTTP, for local development only.
    #[serde(default)]
    plaintext: bool,
}

impl Config {
    fn parse(value: JsValue) -> Result<Self, JsValue> {
        let config: Self = serde_wasm_bindgen::from_value(value)
            .map_err(|e| failure("EINVAL", &format!("the app's config: {e}")))?;
        if config.servers.is_empty() {
            return Err(failure("EINVAL", "the app's config lists no servers"));
        }
        Ok(config)
    }

    fn credentials(&self, username: String, password: String) -> Credentials {
        let mut credentials = Credentials::new(username, password);
        credentials.allow_plaintext = self.plaintext;
        credentials.objects.allow_plaintext = self.plaintext;
        credentials
    }

    fn tls(&self) -> Option<ClientTlsConfig> {
        (!self.plaintext).then(ClientTlsConfig::default)
    }
}

/// A rejected promise's value: an `Error` with `message` and `code`.
fn failure(code: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    let _ = js_sys::Reflect::set(&error, &"code".into(), &code.into());
    error.into()
}

/// The JavaScript error for `e`, with its errno's name as the code.
fn fs_failure(e: FsError) -> JsValue {
    failure(errno_name(e.errno), &e.message)
}

fn errno_name(code: i32) -> &'static str {
    use errno::*;
    match code {
        c if c == EPERM => "EPERM",
        c if c == ENOENT => "ENOENT",
        c if c == EIO => "EIO",
        c if c == EAGAIN => "EAGAIN",
        c if c == EACCES => "EACCES",
        c if c == EBUSY => "EBUSY",
        c if c == EEXIST => "EEXIST",
        c if c == EXDEV => "EXDEV",
        c if c == ENOTDIR => "ENOTDIR",
        c if c == EISDIR => "EISDIR",
        c if c == EINVAL => "EINVAL",
        c if c == EROFS => "EROFS",
        c if c == ENAMETOOLONG => "ENAMETOOLONG",
        c if c == ENOTEMPTY => "ENOTEMPTY",
        c if c == EHOSTUNREACH => "EHOSTUNREACH",
        c if c == ENOTCONN => "ENOTCONN",
        c if c == ETIMEDOUT => "ETIMEDOUT",
        c if c == EKEYEXPIRED => "EKEYEXPIRED",
        _ => "EIO",
    }
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| failure("EIO", &e.to_string()))
}

/// A promise of what `work` gives, as JavaScript values.
fn promise<T: Serialize>(work: impl Future<Output = Result<T, FsError>> + 'static) -> Promise {
    future_to_promise(async move { work.await.map_err(fs_failure).and_then(|v| to_js(&v)) })
}

/// A key's fingerprint, as words to read out and as hex.
#[derive(Serialize)]
struct Fingerprint {
    words: String,
    hex: String,
}

impl Fingerprint {
    fn of(key: &[u8; PUBLIC_KEY_LEN]) -> Self {
        Self {
            words: fingerprint_words(key),
            hex: fingerprint(key),
        }
    }
}

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// The id of the filesystem whose CA certificate (DER) is `ca`, for the
/// app's config.
#[wasm_bindgen(js_name = fsId)]
pub fn fs_id(ca: &[u8]) -> String {
    raft5fs_client::fs_id(ca)
}

/// The id of the filesystem that `invitation` is for, so the app can
/// enrol with that filesystem's servers.
#[wasm_bindgen(js_name = invitationFsId)]
pub fn invitation_fs_id(invitation: &str) -> Result<String, JsValue> {
    let invite = Invite::decode(invitation).map_err(|_| invalid_invitation())?;
    Ok(raft5fs_client::fs_id(&invite.ca))
}

/// One message for every invitation that doesn't parse: the user can only
/// ask for a new one anyway.
fn invalid_invitation() -> JsValue {
    failure("EINVAL", "not a valid invitation")
}

/// Whether `password` is good enough for a new account; rejects with why
/// not.
#[wasm_bindgen(js_name = checkNewPassword)]
pub fn check_password(password: &str) -> Result<(), JsValue> {
    check_new_password(password).map_err(|why| failure("EINVAL", &why))
}

/// Enrols with `invitation` (from `raft5fs-server user add`), choosing
/// `password`. The invitation must be for the app's filesystem: its
/// servers' addresses are the native ones, so the app's own are used, and
/// its CA must be the one the app was built for. Gives the user name and
/// the new key's fingerprint, for the user to give to those they share
/// with.
#[wasm_bindgen]
pub async fn enrol(
    config: JsValue,
    invitation: String,
    password: String,
) -> Result<JsValue, JsValue> {
    let config = Config::parse(config)?;
    let invite = Invite::decode(&invitation).map_err(|_| invalid_invitation())?;
    if raft5fs_client::fs_id(&invite.ca) != config.fs_id {
        return Err(failure(
            "EINVAL",
            "this invitation is for another filesystem than this app's",
        ));
    }
    check_new_password(&password).map_err(|why| failure("EINVAL", &why))?;
    let user = invite.user.clone();
    let key = Remote::enrol(
        &config.servers,
        config.tls(),
        config.credentials(invite.user, password),
        &invite.code,
        KdfParams::DEFAULT,
    )
    .await
    // The servers refuse a used or wrong code with EACCES, in their own
    // words.
    .map_err(|e| match e.errno {
        errno::EACCES => failure("EACCES", "invalid enrollment code"),
        _ => fs_failure(e),
    })?;
    #[derive(Serialize)]
    struct Enrolled {
        user: String,
        fingerprint: Fingerprint,
    }
    to_js(&Enrolled {
        user,
        fingerprint: Fingerprint::of(&key),
    })
}

/// Logs `username` in. `stored` holds the account's blobs from the
/// browser (name to bytes), and `persist(name, bytes)` saves one (see
/// `store`). Refuses servers older than this app needs.
#[wasm_bindgen]
pub async fn login(
    config: JsValue,
    username: String,
    password: String,
    stored: js_sys::Map,
    persist: Function,
) -> Result<Fs, JsValue> {
    let config = Config::parse(config)?;
    let credentials = config.credentials(username, password);
    open(config, credentials, stored, persist).await
}

/// Logs `username` in with `keys`, from an earlier session's `unlockKeys`,
/// for a device that stays unlocked. Fails as a login with a wrong
/// password would once the password has changed.
#[wasm_bindgen]
pub async fn resume(
    config: JsValue,
    username: String,
    keys: Vec<u8>,
    stored: js_sys::Map,
    persist: Function,
) -> Result<Fs, JsValue> {
    let config = Config::parse(config)?;
    let keys = Zeroizing::new(keys);
    let (auth, kek) = keys
        .split_first_chunk::<AUTH_LEN>()
        .and_then(|(auth, rest)| Some((*auth, <[u8; KEY_LEN]>::try_from(rest).ok()?)))
        .ok_or_else(|| failure("EINVAL", "the remembered keys are malformed"))?;
    let mut credentials = config.credentials(username, String::new());
    credentials.keys = Some(UnlockKeys {
        auth: Zeroizing::new(auth),
        kek: Key::from_bytes(kek),
    });
    open(config, credentials, stored, persist).await
}

/// A session for `credentials`, with this browser's pins and prune queue.
async fn open(
    config: Config,
    credentials: Credentials,
    stored: js_sys::Map,
    persist: Function,
) -> Result<Fs, JsValue> {
    let mut blobs = HashMap::new();
    stored.for_each(&mut |value, key| {
        if let (Some(name), Some(bytes)) = (key.as_string(), value.dyn_ref::<Uint8Array>()) {
            blobs.insert(name, bytes.to_vec());
        }
    });
    let browser = Arc::new(BrowserStore::new(blobs, persist));
    let store: Arc<dyn Store> = browser.clone();
    let known = KnownKeys::open(Arc::clone(&store), PINS)
        .map_err(|e| failure("EIO", &format!("the pinned keys in this browser: {e}")))?;
    let queue = PruneQueue::new(store);

    let mut session_config = SessionConfig::new(config.servers.clone(), credentials);
    session_config.tls = config.tls();
    session_config.known_keys = Some(known);
    let session = Session::open(session_config).await.map_err(fs_failure)?;
    let protocol = session.vault().remote().protocol();
    if protocol < MIN_SERVER_PROTOCOL {
        session.shutdown().await;
        return Err(failure(
            "EPROTO",
            &format!(
                "the servers are too old for this app (protocol {protocol}, it needs \
                 {MIN_SERVER_PROTOCOL}): update them"
            ),
        ));
    }
    // The app starts the background prune (`resumePruning`) once this tab
    // is the one to run it.
    Ok(Fs(Rc::new(Inner {
        session,
        store: browser,
        queue,
        pruner: RefCell::new(None),
        handles: RefCell::new(HashMap::new()),
        next_handle: Cell::new(1),
    })))
}

/// A logged-in session.
#[wasm_bindgen]
pub struct Fs(Rc<Inner>);

struct Inner {
    session: Arc<Session>,
    /// This tab's copy of the account's pins and prune queue.
    store: Arc<BrowserStore>,
    queue: PruneQueue,
    /// The background prune of the queue, while it runs.
    pruner: RefCell<Option<AbortHandle>>,
    /// Open files: handle to inode. Inodes don't fit in a JavaScript
    /// number (snapshots' are above 2^63), so the app gets small handles.
    handles: RefCell<HashMap<u32, u64>>,
    next_handle: Cell<u32>,
}

/// One entry of a listing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    name: String,
    /// `file` or `folder`.
    kind: &'static str,
    size: u64,
    /// Milliseconds since the Unix epoch.
    modified: f64,
}

impl Entry {
    fn new(name: &OsStr, attr: &Attr) -> Self {
        Self {
            // A name from a Linux client need not be UTF-8.
            name: String::from_utf8_lossy(os_bytes::bytes(name)).into_owned(),
            kind: match attr.kind {
                Kind::File => "file",
                Kind::Directory => "folder",
            },
            size: attr.size,
            modified: attr
                .mtime
                .duration_since(UNIX_EPOCH)
                .map_or(0.0, |d| d.as_millis() as f64),
        }
    }
}

impl Inner {
    fn vault(&self) -> &Arc<Vault> {
        self.session.vault()
    }

    async fn resolve(&self, path: &str) -> Result<Attr, FsError> {
        self.session.resolve(path.as_bytes()).await
    }

    fn start_pruner(&self) -> Result<(), FsError> {
        let vault = Vault::new(Arc::clone(self.vault().remote()))?
            .with_known_keys(self.vault().known_keys().duplicate());
        let handle = pruner::spawn(vault, self.queue.clone(), PrunerConfig::default());
        if let Some(old) = self.pruner.replace(Some(handle)) {
            old.abort();
        }
        Ok(())
    }

    fn stop_pruner(&self) {
        if let Some(handle) = self.pruner.take() {
            handle.abort();
        }
    }

    fn inode(&self, handle: u32) -> Result<u64, FsError> {
        self.handles
            .borrow()
            .get(&handle)
            .copied()
            .ok_or_else(|| FsError::new(errno::EINVAL, "that file isn't open"))
    }

    fn add_handle(&self, ino: u64) -> u32 {
        let handle = self.next_handle.get();
        self.next_handle.set(handle.wrapping_add(1).max(1));
        self.handles.borrow_mut().insert(handle, ino);
        handle
    }

    /// Removes everything below directory `ino`, depth first.
    fn empty_dir(self: Rc<Self>, ino: u64) -> LocalBoxFuture<'static, Result<(), FsError>> {
        Box::pin(async move {
            for item in self.session.readdir(ino).await? {
                if item.name == "." || item.name == ".." {
                    continue;
                }
                if item.kind == Kind::Directory {
                    Rc::clone(&self).empty_dir(item.ino).await?;
                    self.session.rmdir(ino, &item.name).await?;
                } else {
                    self.session.unlink(ino, &item.name).await?;
                }
            }
            Ok(())
        })
    }

    /// Copies directory `from` and everything in it to a new directory
    /// `name` in `parent`.
    fn copy_dir(
        self: Rc<Self>,
        from: u64,
        parent: u64,
        name: std::ffi::OsString,
    ) -> LocalBoxFuture<'static, Result<(), FsError>> {
        Box::pin(async move {
            let to = self.session.mkdir(parent, &name, DIR_MODE).await?.ino;
            for item in self.session.readdir(from).await? {
                if item.name == "." || item.name == ".." {
                    continue;
                }
                match item.kind {
                    Kind::Directory => {
                        Rc::clone(&self)
                            .copy_dir(item.ino, to, item.name.clone())
                            .await?
                    }
                    Kind::File => {
                        self.session.copy_file(item.ino, to, &item.name).await?;
                    }
                }
            }
            Ok(())
        })
    }
}

#[wasm_bindgen]
impl Fs {
    /// This account's name and key fingerprint, to read out to those who
    /// share with it.
    pub fn whoami(&self) -> Result<JsValue, JsValue> {
        let remote = self.0.vault().remote();
        let identity = remote
            .identity()
            .ok_or_else(|| failure("EACCES", "logged in, but with no key pair"))?;
        #[derive(Serialize)]
        struct WhoAmI {
            user: String,
            fingerprint: Fingerprint,
        }
        to_js(&WhoAmI {
            user: remote.username().to_string(),
            fingerprint: Fingerprint::of(&identity.public_key()),
        })
    }

    /// What logs this account in without its password, for `resume`: 64
    /// bytes, as secret as the password while it is unchanged. The app
    /// stores them only encrypted under a key that can't leave the browser.
    #[wasm_bindgen(js_name = unlockKeys)]
    pub fn unlock_keys(&self) -> Result<Vec<u8>, JsValue> {
        let keys = self
            .0
            .vault()
            .remote()
            .unlock_keys()
            .ok_or_else(|| failure("EACCES", "not logged in"))?;
        let mut bytes = keys.auth.to_vec();
        bytes.extend_from_slice(keys.kek.as_bytes());
        Ok(bytes)
    }

    /// The entries of directory `path`, without `.` and `..`. The root also
    /// lists `.snapshot`, the read-only snapshots.
    pub fn readdir(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let dir = inner.resolve(&path).await?;
            let items: Vec<_> = inner
                .session
                .readdir(dir.ino)
                .await?
                .into_iter()
                .filter(|i| i.name != "." && i.name != "..")
                .collect();
            let attrs = join_all(
                items
                    .iter()
                    .map(|item| inner.session.lookup(dir.ino, &item.name)),
            )
            .await;
            let mut entries = Vec::with_capacity(items.len() + 1);
            for (item, attr) in items.iter().zip(attrs) {
                match attr {
                    Ok(attr) => entries.push(Entry::new(&item.name, &attr)),
                    // Removed since the listing.
                    Err(e) if e.errno == errno::ENOENT => {}
                    Err(e) => return Err(e),
                }
            }
            if path.trim_matches('/').is_empty() {
                let snapshots = inner
                    .session
                    .lookup(dir.ino, OsStr::new(".snapshot"))
                    .await?;
                entries.push(Entry::new(OsStr::new(".snapshot"), &snapshots));
            }
            Ok(entries)
        })
    }

    /// What `path` is.
    pub fn stat(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let attr = inner.resolve(&path).await?;
            let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            Ok(Entry::new(OsStr::new(name), &attr))
        })
    }

    /// Makes directory `path`; in the root, a new volume.
    pub fn mkdir(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (parent, name) = inner.session.resolve_parent(path.as_bytes()).await?;
            inner.session.mkdir(parent, &name, DIR_MODE).await?;
            Ok(())
        })
    }

    /// Removes `path`: a file, or a directory with everything in it.
    pub fn remove(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let attr = inner.resolve(&path).await?;
            let (parent, name) = inner.session.resolve_parent(path.as_bytes()).await?;
            if attr.kind == Kind::Directory {
                Rc::clone(&inner).empty_dir(attr.ino).await?;
                inner.session.rmdir(parent, &name).await
            } else {
                inner.session.unlink(parent, &name).await
            }
        })
    }

    /// Moves `from` to `to`, which must not exist.
    pub fn rename(&self, from: String, to: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (parent, name) = inner.session.resolve_parent(from.as_bytes()).await?;
            let (new_parent, new_name) = inner.session.resolve_parent(to.as_bytes()).await?;
            inner
                .session
                .rename(parent, &name, new_parent, &new_name, true)
                .await
        })
    }

    /// Copies `from` (a file, or a directory and everything in it) to
    /// `to`, which must not exist.
    pub fn copy(&self, from: String, to: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let source = inner.resolve(&from).await?;
            let (parent, name) = inner.session.resolve_parent(to.as_bytes()).await?;
            match source.kind {
                Kind::Directory => Rc::clone(&inner).copy_dir(source.ino, parent, name).await,
                Kind::File => inner
                    .session
                    .copy_file(source.ino, parent, &name)
                    .await
                    .map(drop),
            }
        })
    }

    /// Opens file `path` for `read` and `write`, and gives its handle.
    /// With `create`, makes it first if it isn't there; with `truncate`,
    /// empties it.
    pub fn open(&self, path: String, create: bool, truncate: bool) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let attr = match inner.resolve(&path).await {
                Err(e) if e.errno == errno::ENOENT && create => {
                    let (parent, name) = inner.session.resolve_parent(path.as_bytes()).await?;
                    inner.session.create(parent, &name, FILE_MODE).await?
                }
                other => other?,
            };
            if attr.kind != Kind::File {
                return Err(FsError::errno(errno::EISDIR));
            }
            if truncate && attr.size > 0 {
                let empty = SetAttr {
                    mode: None,
                    size: Some(0),
                    atime: None,
                    mtime: None,
                };
                inner.session.setattr(attr.ino, empty).await?;
            }
            Ok(inner.add_handle(attr.ino))
        })
    }

    /// Up to `len` bytes of open file `handle` from `offset`; fewer at its
    /// end.
    pub fn read(&self, handle: u32, offset: f64, len: u32) -> Promise {
        let inner = Rc::clone(&self.0);
        future_to_promise(async move {
            let ino = inner.inode(handle).map_err(fs_failure)?;
            let bytes = inner
                .session
                .read(ino, offset as u64, len as usize)
                .await
                .map_err(fs_failure)?;
            Ok(Uint8Array::from(bytes.as_slice()).into())
        })
    }

    /// Writes `data` to open file `handle` at `offset`. It may only be
    /// buffered until `close`.
    pub fn write(&self, handle: u32, offset: f64, data: Vec<u8>) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.inode(handle)?;
            let mut done = 0;
            while done < data.len() {
                done += inner
                    .session
                    .write(ino, offset as u64 + done as u64, &data[done..])
                    .await?;
            }
            Ok(())
        })
    }

    /// Stores what is buffered for `handle` and closes it. Fails if
    /// anything written through it was not stored.
    pub fn close(&self, handle: u32) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.inode(handle)?;
            inner.handles.borrow_mut().remove(&handle);
            inner.session.release(ino).await
        })
    }

    /// Whether `user`'s key is pinned in this browser, so sharing with
    /// them needs no fingerprint.
    #[wasm_bindgen(js_name = isPinned)]
    pub fn is_pinned(&self, user: String) -> bool {
        self.0.vault().known_keys().pinned(&user).is_some()
    }

    /// Shares directory `path` with `user`, under `label` in their root.
    /// The first share with someone needs `fingerprint`, the words they
    /// read out; the share goes through only if it matches their key.
    /// Gives the key it was sealed to.
    pub fn share(
        &self,
        path: String,
        user: String,
        writable: bool,
        label: String,
        fingerprint: Option<String>,
    ) -> Promise {
        let inner = Rc::clone(&self.0);
        future_to_promise(async move {
            let vault = inner.vault();
            if vault.known_keys().pinned(&user).is_none() {
                let Some(expected) = &fingerprint else {
                    return Err(failure(
                        "EFINGERPRINT",
                        &format!("{user}'s key isn't pinned yet: ask them for their fingerprint"),
                    ));
                };
                vault.trust(&user, expected).await.map_err(fs_failure)?;
            }
            let ino = inner.resolve(&path).await.map_err(fs_failure)?.ino;
            let key = vault
                .grant(ino, &user, writable, OsStr::new(&label))
                .await
                .map_err(fs_failure)?;
            to_js(&Fingerprint::of(&key))
        })
    }

    /// Who directory `path` is shared with: its own grants, which
    /// `revoke` can undo, and those of the folders above it, which also
    /// reach it. An inherited entry names the folder it comes from in
    /// `via`; only there can it be revoked.
    #[wasm_bindgen(js_name = sharedWith)]
    pub fn shared_with(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            struct Shared {
                user: String,
                writable: bool,
                fingerprint: Option<Fingerprint>,
                /// The folder above that it is shared through, if not
                /// this one.
                via: Option<String>,
            }
            let entries = |grantees: Vec<raft5fs_proto::types::Grantee>, via: Option<&str>| {
                grantees
                    .into_iter()
                    .map(|g| Shared {
                        fingerprint: <[u8; PUBLIC_KEY_LEN]>::try_from(g.public_key.as_slice())
                            .ok()
                            .map(|k| Fingerprint::of(&k)),
                        user: g.user,
                        writable: g.writable,
                        via: via.map(str::to_string),
                    })
                    .collect::<Vec<_>>()
            };
            let ino = inner.resolve(&path).await?.ino;
            let mut shared = entries(inner.vault().grantees(ino).await?, None);

            // The folders above, from the volume down: one look at what is
            // granted under the volume says which of them to ask about.
            let names: Vec<&str> = path.split('/').filter(|n| !n.is_empty()).collect();
            if names.len() < 2 || names[0] == ".snapshot" {
                return Ok(shared);
            }
            let mut above = Vec::new();
            for depth in 1..names.len() {
                let folder = format!("/{}", names[..depth].join("/"));
                above.push((inner.resolve(&folder).await?.ino, folder));
            }
            // Listing grants needs write access to the volume; without it,
            // say only what this folder's own grants say.
            let Ok(granted) = inner.vault().remote().grants_under(above[0].0).await else {
                return Ok(shared);
            };
            let me = inner.vault().remote().username().to_string();
            for (folder_ino, folder) in above.iter().rev() {
                if !granted.iter().any(|g| g.ino == *folder_ino) {
                    continue;
                }
                let grantees = inner.vault().grantees(*folder_ino).await?;
                shared.extend(
                    entries(grantees, Some(folder))
                        .into_iter()
                        .filter(|e| e.user != me),
                );
            }
            Ok(shared)
        })
    }

    /// Revokes `user`'s share of directory `path`, and queues it for
    /// pruning, which this app does in the background while it is open.
    /// Until that is done, what was written there before is still sealed
    /// under keys `user` had.
    pub fn revoke(&self, path: String, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.resolve(&path).await?.ino;
            inner.vault().revoke(ino, &user).await?;
            inner
                .queue
                .add(ino, &format!("{path} (revoked {user})"))
                .map_err(|e| {
                    FsError::new(
                        errno::EIO,
                        format!("revoked, but not queued for pruning: {e}"),
                    )
                })
        })
    }

    /// Shares from people whose keys aren't pinned here: read-only until
    /// trusted (`trust`), or not opening at all.
    pub fn pending(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            struct Pending {
                label: String,
                sender: String,
                /// `untrusted` or `unreadable`.
                state: &'static str,
                message: String,
            }
            let mut pending = Vec::new();
            for share in inner.vault().shares().await? {
                let (state, message) = match share.trust {
                    ShareTrust::Trusted => continue,
                    ShareTrust::Untrusted { .. } => ("untrusted", String::new()),
                    ShareTrust::Unreadable(e) => ("unreadable", e.message),
                };
                pending.push(Pending {
                    label: share.label.to_string_lossy().into_owned(),
                    sender: share.sender,
                    state,
                    message,
                });
            }
            Ok(pending)
        })
    }

    /// Pins `user`'s key if its fingerprint is `words`, as they read it
    /// out. What they share becomes writable.
    pub fn trust(&self, user: String, words: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let key = inner.vault().trust(&user, &words).await?;
            Ok(Fingerprint::of(&key))
        })
    }

    /// Forgets `user`'s pinned key, after they enrolled again.
    #[wasm_bindgen(js_name = forgetKey)]
    pub fn forget_key(&self, user: String) -> Result<(), JsValue> {
        self.0
            .vault()
            .known_keys()
            .forget(&user)
            .map_err(|e| failure("EIO", &e.to_string()))
    }

    /// What waits to be pruned, with each entry's latest status.
    #[wasm_bindgen(js_name = pruneStatus)]
    pub fn prune_status(&self) -> Result<JsValue, JsValue> {
        #[derive(Serialize)]
        struct Queued {
            note: String,
            /// Milliseconds since the Unix epoch.
            since: f64,
            status: String,
        }
        let io = |e: std::io::Error| failure("EIO", &e.to_string());
        let statuses = self.0.queue.statuses().map_err(io)?;
        let entries: Vec<_> = self
            .0
            .queue
            .entries()
            .map_err(io)?
            .into_iter()
            .map(|e| Queued {
                status: statuses
                    .get(&e.ino)
                    .cloned()
                    .unwrap_or_else(|| "waiting".into()),
                note: e.note,
                since: e.since as f64 * 1000.0,
            })
            .collect();
        to_js(&entries)
    }

    /// How much a prune of directory `path` would re-seal now: a walk that
    /// changes nothing.
    #[wasm_bindgen(js_name = pruneEstimate)]
    pub fn prune_estimate(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            struct Estimate {
                nodes: usize,
                chunks: usize,
                bytes: f64,
            }
            let ino = inner.resolve(&path).await?.ino;
            let stats = inner.vault().prune_tree(ino, true).await;
            let chunk = inner.vault().remote().chunk_size();
            Ok(Estimate {
                nodes: stats.nodes,
                chunks: stats.chunks,
                bytes: stats.chunks as f64 * chunk as f64,
            })
        })
    }

    /// Queues directory `path` for pruning again, as after browser storage
    /// was cleared mid-prune.
    #[wasm_bindgen(js_name = pruneAgain)]
    pub fn prune_again(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.resolve(&path).await?.ino;
            inner
                .queue
                .add(ino, &format!("{path} (pruned again)"))
                .map_err(|e| FsError::new(errno::EIO, e.to_string()))
        })
    }

    /// Takes another tab's save of blob `name` (see `store`).
    #[wasm_bindgen(js_name = storeUpdated)]
    pub fn store_updated(&self, name: String, data: Vec<u8>) {
        self.0.store.refresh(&name, &data);
    }

    /// Stops the background prune; what it was doing stays queued.
    #[wasm_bindgen(js_name = pausePruning)]
    pub fn pause_pruning(&self) {
        self.0.stop_pruner();
    }

    #[wasm_bindgen(js_name = resumePruning)]
    pub fn resume_pruning(&self) -> Result<(), JsValue> {
        self.0.start_pruner().map_err(fs_failure)
    }

    /// Whether the background prune runs.
    #[wasm_bindgen(getter)]
    pub fn pruning(&self) -> bool {
        self.0.pruner.borrow().is_some()
    }

    /// Stores everything buffered and stops background work, before the
    /// app ends the Worker.
    pub fn logout(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            inner.stop_pruner();
            inner.handles.borrow_mut().clear();
            inner.session.shutdown().await;
            Ok(())
        })
    }
}
