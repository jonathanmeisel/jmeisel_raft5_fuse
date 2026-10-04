//! Runs a whole raft5fs installation on this machine, in one process: a
//! three-node raft5 cluster, a filesystem server over it, and the
//! filesystem mounted for whoever runs this.
//!
//! Everything lives under one directory: each node's database, the
//! certificates, the secrets and passwords, and `local-fs.json`, which
//! records the ports and the mount's account. Pointed at an empty or
//! missing directory this bootstraps a new installation there; pointed at
//! one it bootstrapped before, it starts that one again.
//!
//! The ports are chosen once, at bootstrap, and reused on every restart:
//! each node's peer address is recorded in the cluster configuration in
//! the Raft log, so a node that came back on a different port would be
//! unreachable to the others.
//!
//! Every tier runs over TLS from material minted at bootstrap: mTLS
//! between the nodes and on the store's client API (so only holders of
//! the node key -- the filesystem server -- can reach the store at all),
//! and TLS from the mount to the filesystem server.
//!
//! Ctrl-C (or SIGTERM, or SIGHUP) unmounts the filesystem, storing what
//! the mount buffered, before the server and the cluster stop.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use fuser::{BackgroundSession, Config, MountOption};
use raft5_client::{Certificate, Client, ClientTls, Identity, Principal, Right};
use raft5_server::auth::{AuthConfig, InitialAdmin, hash_password};
use raft5_server::{ClientApiTls, PeerTls, ServerConfig, serve_config};
use raft5fs_core::users::{self, Account};
use raft5fs_core::{DEFAULT_CHUNK_SIZE, DEFAULT_READ_CACHE_BYTES, FsCore};
use raft5fs_fuse::filesystem::Raft5Fs;
use raft5fs_fuse::remote::Credentials;
use raft5fs_server::auth::{DEFAULT_SESSION_TTL, Signer};
use raft5fs_server::{FsService, Store};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tonic::transport::{ClientTlsConfig, ServerTlsConfig};
use tracing::{info, warn};

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Starts a local raft5fs installation and mounts it, bootstrapping it
/// first if need be. Ctrl-C unmounts and stops everything.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Directory holding the store's databases, certificates and secrets.
    /// A missing or empty one gets a new installation; one this tool
    /// bootstrapped before has that installation started again.
    dir: PathBuf,
    /// Where to mount the filesystem. Created if missing.
    mountpoint: PathBuf,
}

/// How many store nodes a new installation gets: the fewest that survive
/// losing one.
const NODES: usize = 3;

/// The store's administrator, created at bootstrap.
const ADMIN_USER: &str = "admin";

/// The store account the filesystem server works as: the only one the
/// empty-prefix ACL lets at any key.
const SERVICE_USER: &str = "raft5fs";

/// What the mount's account is called when the local user's name is
/// unusable (unset, or taken by one of the accounts above).
const FALLBACK_USER: &str = "user";

/// How long the store's tokens last.
const TOKEN_TTL: Duration = Duration::from_secs(3600);

/// How long bootstrapping waits for the first node to start answering.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long shutting down waits for the mount to go away. Longer only if
/// something still has a file open in it, or its working directory there.
const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(10);

/// Names the node certificate covers. Everything is on loopback, so one
/// certificate serves every node and the filesystem server.
const CERT_NAMES: &[&str] = &["localhost", "127.0.0.1"];

const MANIFEST: &str = "local-fs.json";
const CA_CERT: &str = "certs/ca.pem";
const NODE_CERT: &str = "certs/node.pem";
const NODE_KEY: &str = "certs/node.key";
const JWT_SECRET: &str = "jwt_secret";
const TOKEN_KEY: &str = "token_key";
const ADMIN_PASSWORD: &str = "admin_password";
const SERVICE_PASSWORD: &str = "service_password";
const USER_PASSWORD: &str = "user_password";

/// What has to stay the same across restarts.
///
/// Written only once bootstrapping has fully succeeded, so its presence
/// is what marks a directory as holding a working installation -- one
/// with files in it but no manifest is a bootstrap that was interrupted.
#[derive(Serialize, Deserialize)]
struct Manifest {
    admin_user: String,
    nodes: Vec<NodeSpec>,
    fs_port: u16,
    /// The store account the mount logs in as.
    user: String,
    /// What that account acts as in the filesystem: whoever ran the
    /// bootstrap. Also the root directory's owner.
    uid: u32,
    gid: u32,
}

impl Manifest {
    fn seeds(&self) -> Vec<String> {
        self.nodes.iter().map(NodeSpec::client_url).collect()
    }

    fn fs_addr(&self) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, self.fs_port).into()
    }

    fn fs_url(&self) -> String {
        format!("https://{}", self.fs_addr())
    }
}

#[derive(Serialize, Deserialize)]
struct NodeSpec {
    id: String,
    client_port: u16,
    peer_port: u16,
}

impl NodeSpec {
    fn client_addr(&self) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, self.client_port).into()
    }

    fn peer_addr(&self) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, self.peer_port).into()
    }

    fn client_url(&self) -> String {
        format!("https://{}", self.client_addr())
    }

    fn db(&self, dir: &Path) -> PathBuf {
        dir.join("nodes").join(&self.id)
    }
}

/// The one certificate everything serves and presents, and the CA that
/// signed it, which everything trusts.
struct Tls {
    identity: Identity,
    ca: Certificate,
}

impl Tls {
    fn load(dir: &Path) -> Result<Self, Error> {
        Ok(Self {
            identity: Identity::from_pem(read(&dir.join(NODE_CERT))?, read(&dir.join(NODE_KEY))?),
            ca: Certificate::from_pem(read(&dir.join(CA_CERT))?),
        })
    }

    /// How a client reaches the store, which requires a certificate.
    fn store_client(&self) -> ClientTls {
        ClientTls::new(self.ca.clone()).identity(self.identity.clone())
    }
}

/// The store nodes and the filesystem server, running.
struct Stack {
    /// Every node, and the filesystem server once it has started. None of
    /// them finishes before being told to, short of failing.
    tasks: JoinSet<Result<(), String>>,
    /// Stops the filesystem server.
    fs_cancel: CancellationToken,
    /// Stops the nodes.
    nodes_cancel: CancellationToken,
}

impl Stack {
    /// The server first, then the nodes it was using, and waits for all
    /// of it: each node drains and releases its database before this
    /// returns -- see `serve_config`.
    async fn stop(mut self) -> Result<(), Error> {
        self.fs_cancel.cancel();
        self.nodes_cancel.cancel();
        let mut failure = None;
        while let Some(result) = self.tasks.join_next().await {
            failure = failure.or(task_failure(result));
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn task_failure(result: Result<Result<(), String>, tokio::task::JoinError>) -> Option<Error> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.into()),
        Err(e) => Some(e.into()),
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "raft5_server=warn,local_fs=info".into()),
        )
        .init();
    if let Err(e) = run(Args::parse()) {
        eprintln!("local-fs: {e}");
        std::process::exit(1);
    }
}

/// Runs everything until a signal, or until something fails.
///
/// One multi-threaded runtime carries it all, the mount included: the
/// mount's request threads `block_on` it from outside, which only a
/// multi-threaded runtime supports.
fn run(args: Args) -> Result<(), Error> {
    let runtime = Runtime::new()?;
    let dir = args.dir;
    let mountpoint = args.mountpoint;

    let (stack, manifest) = runtime.block_on(start(&dir))?;
    let session = match mount(&dir, &manifest, &mountpoint, &runtime) {
        Ok(session) => session,
        Err(e) => {
            let _ = runtime.block_on(stack.stop());
            return Err(e);
        }
    };
    print_connection_info(&dir, &manifest, &mountpoint);

    let mut stack = stack;
    let waited = runtime.block_on(wait_for_shutdown(&mut stack, &session));
    info!("shutting down...");
    // The mount first, while the server is still up to store what it
    // buffered.
    unmount(session, &mountpoint);
    let stopped = runtime.block_on(stack.stop());
    // A mount that outlived the timeout can leave a request thread
    // blocked on the runtime; don't wait for it.
    runtime.shutdown_timeout(Duration::from_secs(1));
    waited.and(stopped)
}

/// Starts the cluster -- bootstrapping it first if `dir` is empty -- and
/// the filesystem server over it.
async fn start(dir: &Path) -> Result<(Stack, Manifest), Error> {
    let fresh = is_empty_or_missing(dir)?;
    let manifest = if fresh {
        info!(
            "{} is empty -- bootstrapping a new installation there",
            dir.display()
        );
        create_files(dir)?
    } else {
        read_manifest(dir)?
    };
    let tls = Tls::load(dir)?;
    let auth = auth_config(dir, &manifest.admin_user).await?;

    let mut stack = Stack {
        tasks: JoinSet::new(),
        fs_cancel: CancellationToken::new(),
        nodes_cancel: CancellationToken::new(),
    };
    for node in &manifest.nodes {
        let config = ServerConfig {
            id: node.id.clone(),
            db: node.db(dir),
            client_addr: node.client_addr(),
            peer_addr: node.peer_addr(),
            advertise: None,
            advertise_client: None,
            auth: Some(auth.clone()),
            peer_tls: Some(PeerTls {
                identity: tls.identity.clone(),
                ca: tls.ca.clone(),
                server_name: None,
            }),
            client_tls: Some(ClientApiTls {
                identity: tls.identity.clone(),
                client_ca: Some(tls.ca.clone()),
            }),
        };
        let id = node.id.clone();
        let cancel = stack.nodes_cancel.clone();
        stack.tasks.spawn(async move {
            serve_config(config, cancel)
                .await
                .map_err(|e| format!("node {id}: {e}"))
        });
    }

    if fresh {
        let formed = tokio::select! {
            result = bootstrap(dir, &manifest, &tls, &auth) => result,
            // A node that fails to start (a port taken in the meantime,
            // say) would otherwise leave bootstrapping to time out.
            Some(result) = stack.tasks.join_next() => {
                Err(task_failure(result).unwrap_or_else(|| "a node stopped".into()))
            }
        };
        if let Err(e) = formed {
            let _ = stack.stop().await;
            return Err(format!(
                "bootstrapping failed: {e}\n{} is left half-made; delete it before trying again",
                dir.display()
            )
            .into());
        }
        write_manifest(dir, &manifest)?;
    }

    if let Err(e) = start_fs_server(dir, &manifest, &tls, &mut stack).await {
        let _ = stack.stop().await;
        return Err(e);
    }
    Ok((stack, manifest))
}

fn is_empty_or_missing(dir: &Path) -> Result<bool, Error> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(format!("could not read {}: {e}", dir.display()).into()),
    }
}

fn read_manifest(dir: &Path) -> Result<Manifest, Error> {
    let path = dir.join(MANIFEST);
    let bytes = std::fs::read(&path).map_err(|e| {
        format!(
            "{} is not empty but has no readable {MANIFEST} ({e}) -- either it is not a \
             local-fs directory, or bootstrapping it was interrupted and it should be deleted",
            dir.display()
        )
    })?;
    Ok(serde_json::from_slice(&bytes)
        .map_err(|e| format!("could not parse {}: {e}", path.display()))?)
}

/// Written to a temporary file and renamed into place, so an interrupted
/// write can't leave a manifest that parses as something it isn't.
fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<(), Error> {
    let tmp = dir.join(format!("{MANIFEST}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(manifest)?)?;
    std::fs::rename(&tmp, dir.join(MANIFEST))?;
    Ok(())
}

/// Picks the ports and the mount's account, and mints the certificates,
/// secrets and passwords for a new installation in `dir`. The manifest
/// itself is left for after the cluster has formed.
fn create_files(dir: &Path) -> Result<Manifest, Error> {
    std::fs::create_dir_all(dir.join("certs"))?;

    let ports = free_ports(NODES * 2 + 1)?;
    let nodes = (0..NODES)
        .map(|i| NodeSpec {
            id: format!("n{}", i + 1),
            client_port: ports[2 * i],
            peer_port: ports[2 * i + 1],
        })
        .collect();

    let (ca, cert, key) = mint_certificates()?;
    write_private(&dir.join(CA_CERT), ca.as_bytes())?;
    write_private(&dir.join(NODE_CERT), cert.as_bytes())?;
    write_private(&dir.join(NODE_KEY), key.as_bytes())?;
    for secret in [
        JWT_SECRET,
        TOKEN_KEY,
        ADMIN_PASSWORD,
        SERVICE_PASSWORD,
        USER_PASSWORD,
    ] {
        write_private(&dir.join(secret), random_string()?.as_bytes())?;
    }

    let (uid, gid, _) = own_ids();
    Ok(Manifest {
        admin_user: ADMIN_USER.to_string(),
        nodes,
        fs_port: ports[NODES * 2],
        user: mount_user_name(),
        uid,
        gid,
    })
}

/// The local user's name, if it can be a store account of its own.
fn mount_user_name() -> String {
    match std::env::var("USER") {
        Ok(name) if !name.is_empty() && name != ADMIN_USER && name != SERVICE_USER => name,
        _ => FALLBACK_USER.to_string(),
    }
}

/// Whoever runs this: the mount's identity in the filesystem.
fn own_ids() -> (u32, u32, Vec<u32>) {
    // SAFETY: plain libc calls; `getgroups` writes at most `n` entries
    // into a buffer of that many.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut());
        let mut groups = vec![0; n.max(0) as usize];
        let n = libc::getgroups(groups.len() as i32, groups.as_mut_ptr());
        groups.truncate(n.max(0) as usize);
        (libc::getuid(), libc::getgid(), groups)
    }
}

/// `count` distinct ports the OS considers free right now.
///
/// Every listener is held until all have been picked, so the OS can't
/// hand the same port out twice. They are released before the nodes and
/// server bind them, so something else could still take one in between
/// -- in which case that node fails to start and bootstrapping reports it.
fn free_ports(count: usize) -> Result<Vec<u16>, Error> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(listeners
        .iter()
        .map(|l| l.local_addr().map(|a| a.port()))
        .collect::<Result<_, _>>()?)
}

/// A private CA, and one certificate it signs for the nodes and the
/// filesystem server to share: `(ca_pem, node_cert_pem, node_key_pem)`.
///
/// The certificate is both a server and a client certificate, since a
/// node is both to its peers, and the filesystem server presents it to
/// the store. The CA's key is thrown away once it has signed.
fn mint_certificates() -> Result<(String, String, String), Error> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_pem = ca_params.self_signed(&ca_key)?.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let node_key = KeyPair::generate()?;
    let mut node_params =
        CertificateParams::new(CERT_NAMES.iter().map(|n| n.to_string()).collect::<Vec<_>>())?;
    node_params.is_ca = IsCa::ExplicitNoCa;
    node_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let node_cert = node_params.signed_by(&node_key, &issuer)?;
    Ok((ca_pem, node_cert.pem(), node_key.serialize_pem()))
}

/// 32 random bytes, as URL-safe base64: long enough for a signing secret,
/// and pasteable as a password.
fn random_string() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("could not get random bytes: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Writes a file only its owner can read: everything here is either a
/// secret or sits next to one.
fn write_private(path: &Path, contents: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .and_then(|mut f| f.write_all(contents))
        .map_err(|e| format!("could not write {}: {e}", path.display()).into())
}

fn read(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()).into())
}

fn read_trimmed(path: &Path) -> Result<String, Error> {
    Ok(String::from_utf8(read(path)?)
        .map_err(|_| format!("{} is not text", path.display()))?
        .trim()
        .to_string())
}

/// The same for every node: they must all share the signing secret.
///
/// The initial administrator is passed on every start, not just the
/// first. It only matters until the cluster has a configuration, after
/// which the account stored at bootstrap is the one that counts.
async fn auth_config(dir: &Path, admin_user: &str) -> Result<AuthConfig, Error> {
    let secret = read_trimmed(&dir.join(JWT_SECRET))?;
    let password = read_trimmed(&dir.join(ADMIN_PASSWORD))?;
    Ok(AuthConfig::new(
        secret.as_bytes(),
        TOKEN_TTL,
        Some(InitialAdmin {
            username: admin_user.to_string(),
            password_hash: hash_password(password).await?,
        }),
    ))
}

/// Forms the cluster -- the first node bootstrapped into a single-node
/// cluster, then the rest added to it -- and sets up its accounts: the
/// service account, with the store locked down to it, and the mount's
/// account, with its filesystem identity.
async fn bootstrap(
    dir: &Path,
    manifest: &Manifest,
    tls: &Tls,
    auth: &AuthConfig,
) -> Result<(), Error> {
    let first = &manifest.nodes[0];
    let admin = Client::with_tls([first.client_url()], tls.store_client())?;
    // Signed here rather than fetched with `login`, which this process
    // could do only slowly: against a cluster with no leader yet, the
    // client spends its whole retry deadline looking for one before
    // falling back to asking the node directly.
    let (token, _) = auth.issue(&manifest.admin_user)?;
    admin.login_with_token(token);

    // `Bootstrap` doesn't retry, and the node may not be listening yet,
    // so keep asking until it answers.
    let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
    loop {
        match admin.bootstrap(&first.id).await {
            Ok(()) => break,
            Err(raft5_client::Error::Unavailable(e)) if Instant::now() < deadline => {
                tracing::debug!("{} not ready to bootstrap yet: {e}", first.id);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(format!("could not bootstrap {}: {e}", first.id).into()),
        }
    }
    info!("bootstrapped {}", first.id);
    for node in &manifest.nodes[1..] {
        admin
            .add_server(&format!("https://{}", node.peer_addr()))
            .await
            .map_err(|e| format!("could not add {}: {e}", node.id))?;
        info!("added {}", node.id);
    }

    let service_password = read_trimmed(&dir.join(SERVICE_PASSWORD))?;
    admin
        .create_user(SERVICE_USER, &service_password, false)
        .await
        .map_err(|e| format!("could not create {SERVICE_USER}: {e}"))?;
    // An ACL on the empty prefix governs every key: only the service
    // account may read or write anything.
    admin
        .set_acl(b"", &[(Principal::user(SERVICE_USER), Right::Write)])
        .await
        .map_err(|e| format!("could not lock the store down: {e}"))?;
    admin
        .create_user(
            &manifest.user,
            &read_trimmed(&dir.join(USER_PASSWORD))?,
            false,
        )
        .await
        .map_err(|e| format!("could not create {}: {e}", manifest.user))?;

    // The user table is the service account's to write.
    let service = Client::with_tls(manifest.seeds(), tls.store_client())?;
    service
        .login(SERVICE_USER, &service_password)
        .await
        .map_err(|e| format!("could not log in as {SERVICE_USER}: {e}"))?;
    let (_, _, groups) = own_ids();
    let account = Account {
        uid: manifest.uid,
        gid: manifest.gid,
        groups,
    };
    users::set(&service, &manifest.user, &account)
        .await
        .map_err(|e| format!("could not add {} to the user table: {e}", manifest.user))?;
    info!(
        "created {} as uid {} gid {}",
        manifest.user, manifest.uid, manifest.gid
    );
    Ok(())
}

/// Starts the filesystem server over the cluster, as a task of `stack`.
/// Opening the filesystem creates it, on the first start.
async fn start_fs_server(
    dir: &Path,
    manifest: &Manifest,
    tls: &Tls,
    stack: &mut Stack,
) -> Result<(), Error> {
    let store = Store {
        seeds: manifest.seeds(),
        tls: Some(tls.store_client()),
    };
    let client = store.client()?;
    client
        .login(SERVICE_USER, &read_trimmed(&dir.join(SERVICE_PASSWORD))?)
        .await
        .map_err(|e| format!("could not log in to the store as {SERVICE_USER}: {e}"))?;
    let core = FsCore::connect(
        client,
        DEFAULT_CHUNK_SIZE,
        DEFAULT_READ_CACHE_BYTES,
        (manifest.uid, manifest.gid),
    )
    .await
    .map_err(|e| format!("could not open the filesystem: {e}"))?;

    let signer = Signer::new(&read(&dir.join(TOKEN_KEY))?, DEFAULT_SESSION_TTL);
    let listener = tokio::net::TcpListener::bind(manifest.fs_addr())
        .await
        .map_err(|e| format!("could not listen on {}: {e}", manifest.fs_addr()))?;
    let fs = FsService::new(Arc::new(core), signer, store);
    let server_tls = ServerTlsConfig::new().identity(tls.identity.clone());
    let cancel = stack.fs_cancel.clone();
    stack.tasks.spawn(async move {
        raft5fs_server::serve(fs, listener, Some(server_tls), cancel.cancelled_owned())
            .await
            .map_err(|e| format!("filesystem server: {e}"))
    });
    Ok(())
}

/// Mounts the filesystem at `mountpoint`, logged in as the manifest's
/// user, and checks the mount answers.
fn mount(
    dir: &Path,
    manifest: &Manifest,
    mountpoint: &Path,
    runtime: &Runtime,
) -> Result<BackgroundSession, Error> {
    clear_stale_mount(mountpoint);
    std::fs::create_dir_all(mountpoint)
        .map_err(|e| format!("could not create {}: {e}", mountpoint.display()))?;

    let credentials = Credentials {
        username: manifest.user.clone(),
        password: read_trimmed(&dir.join(USER_PASSWORD))?,
    };
    let tls =
        ClientTlsConfig::new().ca_certificate(Certificate::from_pem(read(&dir.join(CA_CERT))?));
    let fs = Raft5Fs::new(
        vec![manifest.fs_url()],
        credentials,
        runtime.handle().clone(),
    )
    .with_tls(tls);

    let mut options = Config::default();
    // As in raft5fs-fuse: the server checks every request against the
    // mount's one identity, so no `default_permissions`, and no
    // `allow_other` to hand that identity to other local users.
    options.mount_options = vec![MountOption::FSName("raft5fs".to_string())];
    // Writes commit synchronously; more than one thread keeps one file's
    // commit from stalling every other request.
    options.n_threads = Some(8);
    let session = fuser::spawn_mount(fs, mountpoint, &options)
        .map_err(|e| format!("could not mount {}: {e}", mountpoint.display()))?;

    // The mount's `init` connects and logs in; a failure there only shows
    // as a mount that doesn't answer. Asking it something waits for
    // `init` to finish.
    if let Err(e) = std::fs::read_dir(mountpoint) {
        unmount(session, mountpoint);
        return Err(format!("{} was mounted but doesn't work: {e}", mountpoint.display()).into());
    }
    Ok(session)
}

/// Detaches a mount left behind at `mountpoint` by a run that was killed
/// before it could unmount: one whose process is gone, so every access
/// fails with ENOTCONN.
fn clear_stale_mount(mountpoint: &Path) {
    let Err(e) = std::fs::metadata(mountpoint) else {
        return;
    };
    if e.raw_os_error() != Some(libc::ENOTCONN) {
        return;
    }
    warn!(
        "{} has a stale mount on it; detaching it",
        mountpoint.display()
    );
    let status = std::process::Command::new("fusermount3")
        .args(["-u", "-z", "--"])
        .arg(mountpoint)
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        warn!(
            "could not detach the stale mount at {}",
            mountpoint.display()
        );
    }
}

/// Unmounts and waits for the mount's requests to finish -- including the
/// final one, in which it stores what it buffered.
///
/// The unmount is lazy, so it succeeds even while something is using the
/// mount, but the filesystem then lives on until that lets go. That wait
/// is bounded: past it, whatever is still open there loses its buffered
/// writes once the server stops.
fn unmount(session: BackgroundSession, mountpoint: &Path) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(session.umount_and_join());
    });
    match rx.recv_timeout(UNMOUNT_TIMEOUT) {
        Ok(Ok(())) => info!("unmounted {}", mountpoint.display()),
        Ok(Err(e)) => warn!("unmounting {}: {e}", mountpoint.display()),
        Err(_) => warn!(
            "{} is detached, but something still has it open; \
             writes still buffered there are lost",
            mountpoint.display()
        ),
    }
}

/// Waits for a reason to stop: a signal (`Ok`), the mount going away from
/// outside (`Ok`), or a node or the server failing (`Err`).
async fn wait_for_shutdown(stack: &mut Stack, session: &BackgroundSession) -> Result<(), Error> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            _ = interrupt.recv() => return Ok(()),
            _ = terminate.recv() => return Ok(()),
            _ = hangup.recv() => return Ok(()),
            Some(result) = stack.tasks.join_next() => {
                return Err(task_failure(result)
                    .unwrap_or_else(|| "a node or the server stopped unexpectedly".into()));
            }
            _ = tick.tick() => {
                if session.guard.is_finished() {
                    info!("the filesystem was unmounted from outside");
                    return Ok(());
                }
            }
        }
    }
}

fn print_connection_info(dir: &Path, manifest: &Manifest, mountpoint: &Path) {
    let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mountpoint = std::fs::canonicalize(mountpoint).unwrap_or_else(|_| mountpoint.to_path_buf());
    let path = |name: &str| dir.join(name).display().to_string();
    let seeds = manifest.seeds().join(" ");
    let shell_seeds = manifest
        .nodes
        .iter()
        .map(|n| n.client_addr().to_string())
        .collect::<Vec<_>>()
        .join(",");

    println!();
    println!("raft5fs running from {}", dir.display());
    for node in &manifest.nodes {
        println!(
            "  store {}:  client {}  peer {}",
            node.id,
            node.client_url(),
            node.peer_addr()
        );
    }
    println!("  filesystem server: {}", manifest.fs_url());
    println!(
        "  mounted at {} as {} (uid {} gid {})",
        mountpoint.display(),
        manifest.user,
        manifest.uid,
        manifest.gid
    );
    println!();
    println!("store admin shell (password in {}):", path(ADMIN_PASSWORD));
    println!(
        "  raft --nodes {shell_seeds} --ca-cert {} --cert {} --key {} --user {}",
        path(CA_CERT),
        path(NODE_CERT),
        path(NODE_KEY),
        manifest.admin_user
    );
    println!();
    println!("filesystem users (after create_user in the admin shell):");
    println!(
        "  export RAFT5FS_STORE_PASSWORD=$(cat {})",
        path(SERVICE_PASSWORD)
    );
    println!(
        "  raft5fs-server user add <NAME> --uid <UID> --gid <GID> --store-user {SERVICE_USER} \\"
    );
    println!(
        "    --store-ca {} --store-cert {} --store-key {} {seeds}",
        path(CA_CERT),
        path(NODE_CERT),
        path(NODE_KEY)
    );
    println!();
    println!("another mount (password in {}):", path(USER_PASSWORD));
    println!(
        "  raft5fs-fuse --user {} --ca {} <MOUNTPOINT> {}",
        manifest.user,
        path(CA_CERT),
        manifest.fs_url()
    );
    println!();
    println!("Ctrl-C to unmount and stop.");
}
