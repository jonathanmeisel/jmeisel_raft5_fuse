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
use raft5fs_crypto::identity::{PUBLIC_KEY_LEN, fingerprint, fingerprint_words, grant_sender};
use raft5fs_crypto::password::{AUTH_LEN, KdfParams, check_new_password};
use raft5fs_crypto::{KEY_LEN, Key};
use raft5fs_proto::errno;
use raft5fs_proto::invite::Invite;
use raft5fs_proto::os_bytes;
use raft5fs_proto::public_link::PublicLink;
use raft5fs_proto::types::{AccountInfo, AccountKind, Attr, Caps, FsError, Kind, SetAttr};
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
        c if c == ENOTSUP => "ENOTSUP",
        c if c == EDQUOT => "EDQUOT",
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

/// The id of the filesystem that public link `link` (a `#link=`
/// fragment's value) is for.
#[wasm_bindgen(js_name = linkFsId)]
pub fn link_fs_id(link: &str) -> Result<String, JsValue> {
    PublicLink::decode(link)
        .map(|link| link.fs_id)
        .map_err(|_| dead_link())
}

/// One message for every link that doesn't work, whatever the reason:
/// garbled, revoked or expired. A visitor can only ask for a new one.
fn dead_link() -> JsValue {
    failure("ELINK", "This link no longer works.")
}

/// Opens public link `link`: logs in as the link's account. Nothing is kept
/// in the browser: `persist` should do nothing, and the app starts no
/// prune. The secret is random, so its key stretching is minimal.
#[wasm_bindgen]
pub async fn visit(config: JsValue, link: String, persist: Function) -> Result<Fs, JsValue> {
    let config = Config::parse(config)?;
    let link = PublicLink::decode(&link).map_err(|_| dead_link())?;
    if link.fs_id != config.fs_id {
        return Err(dead_link());
    }
    let mut credentials = config.credentials(link.user, link.secret);
    credentials.min_kdf = KdfParams::SECRET;
    open(config, credentials, js_sys::Map::new(), persist)
        .await
        .map_err(|e| {
            let code = js_sys::Reflect::get(&e, &"code".into())
                .ok()
                .and_then(|c| c.as_string());
            // A refused login is a revoked or expired link; anything else
            // (servers down) says what it is.
            if code.as_deref() == Some("EACCES") {
                dead_link()
            } else {
                e
            }
        })
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
        fs_id: config.fs_id.clone(),
        store: browser,
        queue,
        pruner: RefCell::new(None),
        handles: RefCell::new(HashMap::new()),
        next_handle: Cell::new(1),
        sharing: RefCell::new(HashMap::new()),
    })))
}

/// A logged-in session.
#[wasm_bindgen]
pub struct Fs(Rc<Inner>);

struct Inner {
    session: Arc<Session>,
    /// The filesystem's id, for public links.
    fs_id: String,
    /// This tab's copy of the account's pins and prune queue.
    store: Arc<BrowserStore>,
    queue: PruneQueue,
    /// The background prune of the queue, while it runs.
    pruner: RefCell<Option<AbortHandle>>,
    /// Open files: handle to inode. Inodes don't fit in a JavaScript
    /// number (snapshots' are above 2^63), so the app gets small handles.
    handles: RefCell<HashMap<u32, u64>>,
    next_handle: Cell<u32>,
    /// Each volume's sharing, by inode, and when it was read (see
    /// `sharing`). Any share or revoke here empties it.
    sharing: RefCell<HashMap<u64, (f64, Option<Sharing>)>>,
}

/// One entry of a listing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    name: String,
    /// `file` or `folder`.
    kind: &'static str,
    /// A file's size; a folder's, as last measured (see `mark_sizes`), or
    /// none.
    size: Option<u64>,
    /// Milliseconds since the Unix epoch.
    modified: f64,
    /// For a folder: `link` if it has a public link, `people` if it is
    /// shared with anyone else (or with this account, by someone else).
    shared: Option<&'static str>,
    #[serde(skip)]
    ino: u64,
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
            size: (attr.kind == Kind::File).then_some(attr.size),
            modified: attr
                .mtime
                .duration_since(UNIX_EPOCH)
                .map_or(0.0, |d| d.as_millis() as f64),
            shared: None,
            ino: attr.ino,
        }
    }
}

/// How each shared node in a volume is shared, by inode (see
/// `Entry::shared`).
type Sharing = Rc<HashMap<u64, NodeSharing>>;

/// Whom a node is shared with besides this account, as the server says.
#[derive(Serialize, Clone)]
struct NodeSharing {
    /// Their names, in order; public links aren't among them.
    people: Vec<String>,
    /// Whether it has a public link.
    link: bool,
}

impl NodeSharing {
    /// How a folder's mark shows it (see `Entry::shared`).
    fn mark(&self) -> &'static str {
        if self.link { "link" } else { "people" }
    }
}

/// How a folder is shared, for the bar above the files.
#[derive(Serialize)]
struct Here {
    /// The folders, from the top down, whose sharing reaches it: it and
    /// those above it.
    sources: Vec<Source>,
    /// For a folder that this account can only read: who shared it.
    from: Option<String>,
    /// Who owns the top-level folder it is in, if not this account.
    owner: Option<String>,
}

#[derive(Serialize)]
struct Source {
    path: String,
    #[serde(flatten)]
    sharing: NodeSharing,
}

/// An unreachable part of the tree, for JavaScript.
#[derive(Serialize)]
struct UnreachableJs {
    ino: f64,
    volume: bool,
    files: u64,
    folders: u64,
    bytes: u64,
    modified: f64,
}

impl From<&raft5fs_proto::types::Unreachable> for UnreachableJs {
    fn from(u: &raft5fs_proto::types::Unreachable) -> Self {
        Self {
            ino: u.ino as f64,
            volume: u.volume,
            files: u.files,
            folders: u.folders,
            bytes: u.bytes,
            modified: u
                .modified
                .duration_since(UNIX_EPOCH)
                .map_or(0.0, |d| d.as_millis() as f64),
        }
    }
}

/// An orphaned top-level folder, for JavaScript (see `Fs::list_orphans`).
#[derive(Serialize)]
struct OrphanJs {
    ino: f64,
    path: Option<String>,
    owner: Option<String>,
    writers: Vec<String>,
    reachable: bool,
    bytes: u64,
}

/// The capabilities called `names`.
fn caps_named(names: &[String]) -> Result<Caps, FsError> {
    names.iter().try_fold(Caps::NONE, |caps, name| {
        Caps::named(name)
            .map(|cap| caps | cap)
            .ok_or_else(|| FsError::new(errno::EINVAL, format!("no capability {name:?}")))
    })
}

/// How long a volume's sharing, as `Inner::sharing` reads it, is reused.
const SHARING_TTL_MS: f64 = 30_000.0;

/// Whom a node with `grantees` is shared with besides `me`, if anyone.
fn sharing_of(grantees: &[raft5fs_proto::types::Grantee], me: &str) -> Option<NodeSharing> {
    let link = grantees
        .iter()
        .any(|g| g.user.starts_with(raft5fs_proto::types::LINK_PREFIX));
    let mut people: Vec<String> = grantees
        .iter()
        .filter(|g| g.user != me && !g.user.starts_with(raft5fs_proto::types::LINK_PREFIX))
        .map(|g| g.user.clone())
        .collect();
    people.sort();
    (link || !people.is_empty()).then_some(NodeSharing { people, link })
}

impl Inner {
    fn vault(&self) -> &Arc<Vault> {
        self.session.vault()
    }

    /// How each shared node in volume `volume` is shared, by inode (see
    /// `Entry::shared`), or `None` if this account can't list the volume's
    /// grants: it only reads it. Only for showing: it is the server's word.
    async fn sharing(&self, volume: u64) -> Option<Sharing> {
        let now = js_sys::Date::now();
        if let Some((at, known)) = self.sharing.borrow().get(&volume)
            && now - at < SHARING_TTL_MS
        {
            return known.clone();
        }
        let me = self.vault().remote().username().to_string();
        let known = match self.vault().remote().grants_under(volume).await {
            Ok(nodes) => Some(Rc::new(
                nodes
                    .iter()
                    .filter_map(|n| sharing_of(&n.grantees, &me).map(|how| (n.ino, how)))
                    .collect(),
            )),
            Err(e) if e.errno == errno::EACCES || e.errno == errno::EROFS => None,
            // Not known this time; ask again next time.
            Err(_) => return Some(Rc::new(HashMap::new())),
        };
        self.sharing
            .borrow_mut()
            .insert(volume, (now, known.clone()));
        known
    }

    /// Marks the folders among `entries` (of directory `path`) that are
    /// shared. A top-level folder that this account can't list the grants
    /// of was shared with it by someone else.
    async fn mark_shared(&self, path: &str, entries: &mut [Entry]) -> Result<(), FsError> {
        let names: Vec<&str> = path.split('/').filter(|n| !n.is_empty()).collect();
        if names.first() == Some(&".snapshot") {
            return Ok(());
        }
        if names.is_empty() {
            let folders: Vec<&mut Entry> = entries
                .iter_mut()
                .filter(|e| e.kind == "folder" && e.name != ".snapshot")
                .collect();
            let known = join_all(folders.iter().map(|e| self.sharing(e.ino))).await;
            for (entry, known) in folders.into_iter().zip(known) {
                entry.shared = match known {
                    Some(known) => known.get(&entry.ino).map(NodeSharing::mark),
                    None => Some("people"),
                };
            }
            return Ok(());
        }
        let volume = self.resolve(&format!("/{}", names[0])).await?.ino;
        if let Some(known) = self.sharing(volume).await {
            for entry in entries.iter_mut().filter(|e| e.kind == "folder") {
                entry.shared = known.get(&entry.ino).map(NodeSharing::mark);
            }
        }
        Ok(())
    }

    /// How folder `path` is shared, for the bar above the files (see
    /// `Fs::sharing_here`).
    async fn sharing_here(&self, path: &str) -> Result<Option<Here>, FsError> {
        let names: Vec<&str> = path.split('/').filter(|n| !n.is_empty()).collect();
        if names.is_empty() || names[0] == ".snapshot" {
            return Ok(None);
        }
        let top = self.resolve(&format!("/{}", names[0])).await?.ino;
        let Some(known) = self.sharing(top).await else {
            // Only shared with this account, to read: say by whom.
            let sender = self
                .vault()
                .remote()
                .list_grants()
                .await?
                .into_iter()
                .find(|g| g.ino == top)
                .and_then(|g| grant_sender(&g.sealed_key).ok().map(str::to_string));
            return Ok(Some(Here {
                sources: Vec::new(),
                from: sender,
                owner: self.others_owner(top).await,
            }));
        };
        let mut sources = Vec::new();
        for depth in 1..=names.len() {
            let folder = format!("/{}", names[..depth].join("/"));
            let ino = if depth == 1 {
                top
            } else {
                self.resolve(&folder).await?.ino
            };
            if let Some(shared) = known.get(&ino) {
                sources.push(Source {
                    path: folder,
                    sharing: shared.clone(),
                });
            }
        }
        let owner = self.others_owner(top).await;
        Ok((!sources.is_empty() || owner.is_some()).then_some(Here {
            sources,
            from: None,
            owner,
        }))
    }

    /// Who owns volume `ino`, if someone other than this account. Only for
    /// showing: none if the servers can't say.
    async fn others_owner(&self, ino: u64) -> Option<String> {
        let me = self.vault().remote().username();
        let owner = self.vault().remote().get_volume(ino).await.ok()?.owner?;
        (owner != me).then_some(owner)
    }

    /// Gives the folders among `entries` (of directory `path`) their size
    /// as last measured. Folders not measured yet, or on servers too old
    /// to say, have none.
    async fn mark_sizes(&self, path: &str, entries: &mut [Entry]) {
        if path.trim_start_matches('/').starts_with(".snapshot") {
            return;
        }
        let folders: Vec<u64> = entries
            .iter()
            .filter(|e| e.kind == "folder" && e.name != ".snapshot")
            .map(|e| e.ino)
            .collect();
        if folders.is_empty() {
            return;
        }
        let Ok(sizes) = self.vault().remote().folder_sizes(&folders).await else {
            return;
        };
        let sizes: HashMap<u64, u64> = sizes
            .into_iter()
            .filter(|s| s.measured_at > 0)
            .map(|s| (s.ino, s.bytes))
            .collect();
        for entry in entries.iter_mut().filter(|e| e.kind == "folder") {
            entry.size = sizes.get(&entry.ino).copied();
        }
    }

    /// The inode of top-level folder `path`; `EINVAL` for any other path.
    async fn volume_at(&self, path: &str) -> Result<u64, FsError> {
        let names: Vec<&str> = path.split('/').filter(|n| !n.is_empty()).collect();
        if names.len() != 1 || names[0] == ".snapshot" {
            return Err(FsError::new(
                errno::EINVAL,
                format!("{path} isn't a top-level folder"),
            ));
        }
        Ok(self.resolve(path).await?.ino)
    }

    /// Each top-level folder's path, by inode, as this account sees them.
    async fn volume_paths(&self) -> Result<HashMap<u64, String>, FsError> {
        Ok(self
            .vault()
            .root_entries()
            .await?
            .into_iter()
            .map(|(name, ino)| {
                let name = String::from_utf8_lossy(os_bytes::bytes(&name)).into_owned();
                (ino, format!("/{name}"))
            })
            .collect())
    }

    /// `orphans` for JavaScript, with the paths this account sees them at.
    async fn orphans_js(
        &self,
        orphans: Vec<raft5fs_proto::types::Orphan>,
    ) -> Result<Vec<OrphanJs>, FsError> {
        let paths = if orphans.is_empty() {
            HashMap::new()
        } else {
            self.volume_paths().await?
        };
        Ok(orphans
            .into_iter()
            .map(|o| OrphanJs {
                ino: o.volume as f64,
                path: paths.get(&o.volume).cloned(),
                owner: o.owner,
                writers: o.writers,
                reachable: o.reachable,
                bytes: o.bytes,
            })
            .collect())
    }

    /// Forgets what `sharing` read, after this tab changed it.
    fn sharing_changed(&self) {
        self.sharing.borrow_mut().clear();
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
            inner.mark_shared(&path, &mut entries).await?;
            inner.mark_sizes(&path, &mut entries).await;
            Ok(entries)
        })
    }

    /// How folder `path` is shared, or null if it isn't: `{sources: [{path,
    /// people, link}], from}`. `sources` are the folders, from the top down,
    /// whose sharing reaches it (it, and those above it), with whom each is
    /// shared besides this account, and whether it has a public link. For
    /// a folder that this account can only read, `sources` is empty and
    /// `from` names who shared it. Only for showing: it is the server's
    /// word.
    #[wasm_bindgen(js_name = sharingHere)]
    pub fn sharing_here(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move { inner.sharing_here(&path).await })
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
            // Asked before the grant, which would only say the keys differ.
            if vault.key_changed(&user).await.map_err(fs_failure)? {
                return Err(failure(
                    "EKEYCHANGED",
                    &format!(
                        "{user}'s key has changed since you last shared with them: they may \
                         have enrolled again. Ask them for their new fingerprint."
                    ),
                ));
            }
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
            inner.sharing_changed();
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
                /// For a public link: the `#link=` fragment's value.
                link: Option<String>,
            }
            let fs_id = inner.fs_id.clone();
            let entries = |(grantees, secrets): (
                Vec<raft5fs_proto::types::Grantee>,
                HashMap<String, String>,
            ),
                           via: Option<&str>| {
                grantees
                    .into_iter()
                    .map(|g| Shared {
                        fingerprint: <[u8; PUBLIC_KEY_LEN]>::try_from(g.public_key.as_slice())
                            .ok()
                            .map(|k| Fingerprint::of(&k)),
                        link: secrets.get(&g.user).map(|secret| {
                            PublicLink {
                                fs_id: fs_id.clone(),
                                user: g.user.clone(),
                                secret: secret.clone(),
                            }
                            .encode()
                        }),
                        user: g.user,
                        writable: g.writable,
                        via: via.map(str::to_string),
                    })
                    .collect::<Vec<_>>()
            };
            let ino = inner.resolve(&path).await?.ino;
            let mut shared = entries(inner.vault().grantees_with_links(ino).await?, None);

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
                let grantees = inner.vault().grantees_with_links(*folder_ino).await?;
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
            inner.sharing_changed();
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

    /// What this account may do, as `{caps, kind, invitedBy}`: `caps`
    /// names its capabilities, and `kind` is `person` or `link`. Servers
    /// too old to say give what every account could do then.
    pub fn account(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let info = match inner.vault().remote().account().await {
                Err(e) if e.errno == errno::ENOTSUP => AccountInfo::default(),
                other => other?,
            };
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Account {
                caps: Vec<&'static str>,
                kind: &'static str,
                invited_by: String,
            }
            Ok(Account {
                caps: info.caps.names(),
                kind: match info.kind {
                    AccountKind::Person => "person",
                    AccountKind::Link => "link",
                },
                invited_by: info.invited_by,
            })
        })
    }

    /// Invites a new user `user`, who may do what `caps` names, as an
    /// admin. Returns
    /// `{invitation, code}`: the whole invitation, or null if the servers
    /// don't say how users reach them, and the bare code.
    #[wasm_bindgen(js_name = issueInvite)]
    pub fn issue_invite(&self, user: String, caps: Vec<String>) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let wanted = caps_named(&caps)?;
            let (code, invitation) = inner.vault().remote().issue_invite(&user, wanted).await?;
            #[derive(Serialize)]
            struct Issued {
                invitation: Option<String>,
                code: String,
            }
            Ok(Issued { invitation, code })
        })
    }

    /// Every account, for an admin, as `[{user, enrolled, caps, kind,
    /// invitedBy, owner, used, quota}]`: `enrolled` is false for an
    /// invitation nobody used yet, `kind` is `person` or `link` (made by
    /// `owner`), and `used` and `quota` are bytes (`quota` null for no
    /// limit).
    #[wasm_bindgen(js_name = listUsers)]
    pub fn list_users(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct User {
                user: String,
                enrolled: bool,
                caps: Vec<&'static str>,
                kind: &'static str,
                invited_by: String,
                owner: String,
                used: u64,
                quota: Option<u64>,
            }
            let mut users = inner.vault().remote().list_users().await?;
            users.sort_by(|a, b| a.user.cmp(&b.user));
            Ok(users
                .into_iter()
                .map(|u| User {
                    user: u.user,
                    enrolled: u.enrolled,
                    caps: u.info.caps.names(),
                    kind: match u.info.kind {
                        AccountKind::Person => "person",
                        AccountKind::Link => "link",
                    },
                    invited_by: u.info.invited_by,
                    owner: u.info.owner,
                    used: u.used,
                    quota: u.info.quota,
                })
                .collect::<Vec<_>>())
        })
    }

    /// Turns `user`'s capabilities named in `on` on and those in `off` off,
    /// as an admin. Gives the names they have then.
    #[wasm_bindgen(js_name = setCapabilities)]
    pub fn set_capabilities(&self, user: String, on: Vec<String>, off: Vec<String>) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let info = inner
                .vault()
                .remote()
                .set_capabilities(&user, caps_named(&on)?, caps_named(&off)?)
                .await?;
            Ok(info.caps.names())
        })
    }

    /// A new invitation for existing user `user`, so they can enroll again,
    /// as an admin: `{invitation, code}`, as `issueInvite` gives.
    #[wasm_bindgen(js_name = reissueInvite)]
    pub fn reissue_invite(&self, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (code, invitation) = inner.vault().remote().reissue_invite(&user).await?;
            #[derive(Serialize)]
            struct Issued {
                invitation: Option<String>,
                code: String,
            }
            Ok(Issued { invitation, code })
        })
    }

    /// Folders and files that no account can reach any more, as an admin:
    /// `[{ino, volume, files, folders, bytes, modified}]` (`modified` in
    /// milliseconds since 1970). Their names can't be read by anyone.
    #[wasm_bindgen(js_name = listUnreachable)]
    pub fn list_unreachable(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let found = inner.vault().remote().list_unreachable().await?;
            Ok(found.iter().map(UnreachableJs::from).collect::<Vec<_>>())
        })
    }

    /// Deletes unreachable part `ino`, with everything in it, as an admin.
    #[wasm_bindgen(js_name = deleteUnreachable)]
    pub fn delete_unreachable(&self, ino: f64) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move { inner.vault().remote().delete_unreachable(ino as u64).await })
    }

    /// What removing `user`, or letting them enroll again, would leave that
    /// no account can reach, as `listUnreachable` lists them.
    #[wasm_bindgen(js_name = removalImpact)]
    pub fn removal_impact(&self, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let found = inner.vault().remote().removal_impact(&user).await?;
            Ok(found.iter().map(UnreachableJs::from).collect::<Vec<_>>())
        })
    }

    /// Sets how much the volumes `user` owns may hold, in bytes (null for
    /// no limit), as an admin.
    #[wasm_bindgen(js_name = setQuota)]
    pub fn set_quota(&self, user: String, quota: Option<f64>) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let quota = quota.map(|q| q as u64);
            inner.vault().remote().set_quota(&user, quota).await
        })
    }

    /// Measures every folder's size and every owner's usage now, as an
    /// admin. `EBUSY` if a server is measuring already.
    #[wasm_bindgen(js_name = measureUsage)]
    pub fn measure_usage(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move { inner.vault().remote().measure_usage().await })
    }

    /// Orphaned top-level folders, as an admin: their owner can't write
    /// them any more, or they have none. `[{ino, path, owner, writers,
    /// reachable, bytes}]`: `path` if this account sees it, `owner` the
    /// one the servers have, `writers` who could own it.
    #[wasm_bindgen(js_name = listOrphans)]
    pub fn list_orphans(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let found = inner.vault().remote().orphans().await?;
            inner.orphans_js(found).await
        })
    }

    /// The top-level folders that removing `user`, or letting them enroll
    /// again, would orphan, as `listOrphans` gives them.
    #[wasm_bindgen(js_name = removalOrphans)]
    pub fn removal_orphans(&self, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let found = inner.vault().remote().removal_orphans(&user).await?;
            inner.orphans_js(found).await
        })
    }

    /// Makes `user` the owner of top-level folder `ino`, as an admin.
    #[wasm_bindgen(js_name = assignOwner)]
    pub fn assign_owner(&self, ino: f64, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move { inner.vault().remote().assign_owner(ino as u64, &user).await })
    }

    /// How much this account's top-level folders hold: `{used, quota,
    /// measuredAt}`, in bytes (`quota` null for no limit) and milliseconds
    /// since 1970 (0 if never measured). Null from servers too old to say.
    pub fn storage(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct StorageJs {
                used: u64,
                quota: Option<u64>,
                measured_at: f64,
            }
            Ok(match inner.vault().remote().storage().await {
                Ok(s) => Some(StorageJs {
                    used: s.used,
                    quota: s.quota,
                    measured_at: s.measured_at as f64 * 1000.0,
                }),
                Err(e) if e.errno == errno::ENOTSUP => None,
                Err(e) => return Err(e),
            })
        })
    }

    /// Who owns top-level folder `path`, and to whom it is offered:
    /// `{owner, offeredTo}`, either null. Null for any other folder, and
    /// from servers too old to say.
    pub fn volume(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct VolumeJs {
                owner: Option<String>,
                offered_to: Option<String>,
            }
            let Ok(ino) = inner.volume_at(&path).await else {
                return Ok(None);
            };
            Ok(match inner.vault().remote().get_volume(ino).await {
                Ok(v) => Some(VolumeJs {
                    owner: v.owner,
                    offered_to: v.offer.map(|(to, _)| to),
                }),
                Err(e) if e.errno == errno::ENOTSUP => None,
                Err(e) => return Err(e),
            })
        })
    }

    /// Offers top-level folder `path` to `user`, as its owner. They must
    /// have read-write access to it already.
    #[wasm_bindgen(js_name = offerVolume)]
    pub fn offer_volume(&self, path: String, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.volume_at(&path).await?;
            inner.vault().remote().offer_volume(ino, &user).await
        })
    }

    /// Withdraws the offer of top-level folder `path`, as its owner.
    #[wasm_bindgen(js_name = withdrawOffer)]
    pub fn withdraw_offer(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.volume_at(&path).await?;
            inner.vault().remote().withdraw_offer(ino).await
        })
    }

    /// Accepts, or declines, top-level folder `path`, offered to this
    /// account.
    #[wasm_bindgen(js_name = answerOffer)]
    pub fn answer_offer(&self, path: String, accept: bool) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.volume_at(&path).await?;
            inner.vault().remote().answer_offer(ino, accept).await
        })
    }

    /// The offers of top-level folders made to this account, and by it:
    /// `[{path, from, to, bytes}]`, `path` null if this account doesn't
    /// see the folder. None from servers too old to say.
    pub fn offers(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            struct OfferJs {
                path: Option<String>,
                from: String,
                to: String,
                bytes: u64,
            }
            let offers = match inner.vault().remote().offers().await {
                Err(e) if e.errno == errno::ENOTSUP => Vec::new(),
                other => other?,
            };
            if offers.is_empty() {
                return Ok(Vec::new());
            }
            let paths = inner.volume_paths().await?;
            Ok(offers
                .into_iter()
                .map(|o| OfferJs {
                    path: paths.get(&o.volume).cloned(),
                    from: o.from,
                    to: o.to,
                    bytes: o.bytes,
                })
                .collect::<Vec<_>>())
        })
    }

    /// Folder `path`'s size and size limit: `{bytes, files, measuredAt,
    /// limit}` (`measuredAt` in milliseconds since 1970, 0 if never;
    /// `limit` null for none). Null if neither is known.
    #[wasm_bindgen(js_name = folderSize)]
    pub fn folder_size(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct SizeJs {
                bytes: u64,
                files: u64,
                measured_at: f64,
                limit: Option<u64>,
            }
            let ino = inner.resolve(&path).await?.ino;
            let sizes = match inner.vault().remote().folder_sizes(&[ino]).await {
                Err(e) if e.errno == errno::ENOTSUP => Vec::new(),
                other => other?,
            };
            Ok(sizes.into_iter().next().map(|s| SizeJs {
                bytes: s.bytes,
                files: s.files,
                measured_at: s.measured_at as f64 * 1000.0,
                limit: s.limit,
            }))
        })
    }

    /// Fails with `EDQUOT` if `bytes` more in folder `path` would go over
    /// its owner's quota or a folder limit; servers too old to say never
    /// do. For asking before an upload creates or truncates anything.
    #[wasm_bindgen(js_name = checkRoom)]
    pub fn check_room(&self, path: String, bytes: f64) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.resolve(&path).await?.ino;
            match inner.vault().remote().check_room(ino, bytes as u64).await {
                Err(e) if e.errno == errno::ENOTSUP => Ok(()),
                other => other,
            }
        })
    }

    /// Sets folder `path`'s size limit in bytes (null for none), as the
    /// owner of its top-level folder or an admin.
    #[wasm_bindgen(js_name = setFolderLimit)]
    pub fn set_folder_limit(&self, path: String, limit: Option<f64>) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.resolve(&path).await?.ino;
            let limit = limit.map(|l| l as u64);
            inner.vault().remote().set_folder_limit(ino, limit).await
        })
    }

    /// Removes `user` (an account, an unused invitation, or a public link),
    /// as an admin.
    #[wasm_bindgen(js_name = deleteUser)]
    pub fn delete_user(&self, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move { inner.vault().remote().delete_user(&user).await })
    }

    /// Makes a public link to folder `path`, under which visitors see it
    /// as `label`, that stops working at `expires` (seconds since 1970) if
    /// given. Returns `{user, link}`: the link's account name and the
    /// `#link=` fragment's value, which is shown once and kept nowhere.
    #[wasm_bindgen(js_name = createLink)]
    pub fn create_link(&self, path: String, label: String, expires: Option<f64>) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let ino = inner.resolve(&path).await?.ino;
            let (user, secret) = inner
                .vault()
                .create_link(ino, &path, OsStr::new(&label), expires.map(|at| at as u64))
                .await?;
            inner.sharing_changed();
            #[derive(Serialize)]
            struct Made {
                user: String,
                link: String,
            }
            let link = PublicLink {
                fs_id: inner.fs_id.clone(),
                user: user.clone(),
                secret,
            }
            .encode();
            Ok(Made { user, link })
        })
    }

    /// The public links that this account made, as `[{user, path, created,
    /// expires, expired, link}]` (times in seconds since 1970; `expires`
    /// null for never; `path` null if it can't be read; `link`, the
    /// `#link=` fragment's value, null if this account can no longer
    /// change the folder or the link predates keeping it).
    #[wasm_bindgen(js_name = listLinks)]
    pub fn list_links(&self) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            #[derive(Serialize)]
            struct Made {
                user: String,
                path: Option<String>,
                created: u64,
                expires: Option<u64>,
                expired: bool,
                link: Option<String>,
            }
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let mut made = Vec::new();
            for (link, path) in inner.vault().links().await? {
                let secret = match inner.vault().grantees_with_links(link.info.folder).await {
                    Ok((_, mut secrets)) => secrets.remove(&link.user),
                    Err(_) => None,
                };
                made.push(Made {
                    expired: link.info.expired(now),
                    link: secret.map(|secret| {
                        PublicLink {
                            fs_id: inner.fs_id.clone(),
                            user: link.user.clone(),
                            secret,
                        }
                        .encode()
                    }),
                    user: link.user,
                    path,
                    created: link.info.created,
                    expires: link.info.expires,
                });
            }
            Ok(made)
        })
    }

    /// Revokes public link `user`, which this account made, wherever its
    /// folder now is, and queues the folder for pruning, as `revoke` does.
    #[wasm_bindgen(js_name = revokeLink)]
    pub fn revoke_link(&self, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (link, path) = inner
                .vault()
                .links()
                .await?
                .into_iter()
                .find(|(link, _)| link.user == user)
                .ok_or_else(|| FsError::new(errno::ENOENT, "there's no such link"))?;
            let ino = link.info.folder;
            inner.vault().revoke(ino, &user).await?;
            inner.sharing_changed();
            let path = path.unwrap_or_else(|| format!("folder {ino}"));
            inner
                .queue
                .add(ino, &format!("{path} (revoked a public link)"))
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
            #[serde(rename_all = "camelCase")]
            struct Pending {
                label: String,
                sender: String,
                /// `untrusted` or `unreadable`.
                state: &'static str,
                message: String,
                /// The sender's key differs from the one pinned here, so
                /// trusting them means replacing it (`replaceKey`).
                key_changed: bool,
            }
            let mut pending = Vec::new();
            for share in inner.vault().shares().await? {
                let (state, message) = match share.trust {
                    ShareTrust::Trusted => continue,
                    ShareTrust::Untrusted { .. } => ("untrusted", String::new()),
                    ShareTrust::Unreadable(e) => ("unreadable", e.message),
                };
                let key_changed = inner
                    .vault()
                    .key_changed(&share.sender)
                    .await
                    .unwrap_or(false);
                pending.push(Pending {
                    label: share.label.to_string_lossy().into_owned(),
                    sender: share.sender,
                    state,
                    message,
                    key_changed,
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

    /// Pins `user`'s new key in place of the old one, after they enrolled
    /// again, if its fingerprint is `words`. The old one stays if not.
    #[wasm_bindgen(js_name = replaceKey)]
    pub fn replace_key(&self, user: String, words: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let key = inner.vault().replace_key(&user, &words).await?;
            Ok(Fingerprint::of(&key))
        })
    }

    /// Forgets `user`'s pinned key, here and on the account's other
    /// devices.
    #[wasm_bindgen(js_name = forgetKey)]
    pub fn forget_key(&self, user: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move { inner.vault().forget_key(&user).await })
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
