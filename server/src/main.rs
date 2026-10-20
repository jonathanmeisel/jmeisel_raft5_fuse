use std::env;
use std::future::pending;
use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use raft5_client::{Certificate, Client, ClientTls, Identity};
use raft5fs_core::gc::DEFAULT_GC_INTERVAL;
use raft5fs_core::objects::{
    DEFAULT_GET_TTL, DEFAULT_OBJECT_BLOCK, DEFAULT_OBJECT_FROM, DEFAULT_PUT_TTL, ObjectSettings,
};
use raft5fs_core::{DEFAULT_CHUNK_SIZE, FsCore, accounts, snapshots, validate_chunk_size};
use raft5fs_objstore::http::HttpConfig;
use raft5fs_objstore::{S3Config, S3Store};
use raft5fs_proto::invite::{Invite, pem_to_der};
use raft5fs_server::auth::{DEFAULT_SESSION_TTL, Signer};
use raft5fs_server::{DEFAULT_IDENTITY_TTL, FsService, Store};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tonic::transport::ServerTlsConfig;

const USAGE: &str = "\
usage: raft5fs-server --listen <ADDR> --token-key-file <PATH>
                      [--tls-cert <PEM> --tls-key <PEM>] [options]
                      <store options> <kv-seed-address>...
       raft5fs-server user add <NAME> [<invite options>] <store options>
                      <kv-seed-address>...
       raft5fs-server user del <NAME> <store options> <kv-seed-address>...
       raft5fs-server user list <store options> <kv-seed-address>...
       raft5fs-server snapshot create [<NAME>] <store options> <kv-seed-address>...
       raft5fs-server snapshot del <NAME> <store options> <kv-seed-address>...
       raft5fs-server snapshot list <store options> <kv-seed-address>...

Serving:
  --listen <ADDR>      address to serve clients on, e.g. 0.0.0.0:7700.
  --token-key-file <PATH>
                       the key sessions are signed with. Every server of
                       one filesystem needs the same key, and anyone
                       holding it can act as any user -- though, with
                       everything encrypted, still not read what they
                       couldn't before -- so keep it secret.
  --tls-cert <PEM>, --tls-key <PEM>
                       serve over TLS with this certificate and key.
                       Without them clients connect in plaintext: what
                       they store stays encrypted, but sessions cross the
                       network in the clear, for anyone watching to reuse.
  --session-ttl <SECS> how long a login lasts before the client must log
                       in again (default 86400).
  --identity-ttl <SECS>
                       how long an account is trusted to still exist
                       before looking again (default 5): how long removing
                       one takes to reach a user who is already mounted.
  --chunk-size <SIZE>  size of each stored file chunk, as a byte count or
                       with a K/M suffix (default 1M). Only applies when
                       creating a new filesystem: an existing one keeps
                       the size it was created with, since chunk
                       boundaries are baked into its keys.

Object storage (large files): with --object-bucket, files made through
this server keep their data from --object-from on in an S3-compatible
bucket, in blocks of --object-block, rather than in the store. Clients
read and write the blocks directly, through URLs this server signs once
it has checked their grant; the bucket only ever sees sealed data. Every
server of one filesystem should have the same object options.
  --object-endpoint <URL>
                       the store's base URL, e.g.
                       https://s3.eu-west-1.amazonaws.com.
  --object-bucket <NAME>
  --object-region <NAME>
                       (default us-east-1)
  --object-path-style  address the bucket as <endpoint>/<bucket>/, as
                       MinIO and most self-hosted stores need.
  --object-prefix <PATH>
                       what every object's key starts with, ending in '/'
                       (default raft5fs/).
  --object-from <SIZE> where in a file its data starts going to blocks
                       (default 10M).
  --object-block <SIZE>
                       how much of a file one block holds, a whole number
                       of chunks (default 16M). Bigger means fewer
                       objects, and more to re-upload for a small write
                       inside one. This and --object-from are fixed by
                       the first server to use them on a filesystem.
  --object-put-ttl <SECS>, --object-get-ttl <SECS>
                       how long an upload and a read URL stay good
                       (defaults 600 and 900).
  --object-ca <PEM>    trust this CA for the object store, besides the
                       system's.
  --gc-interval <SECS> how often to look for objects nothing points at
                       any more, and delete them (default 3600; 0 never).
                       Several servers can have it on: one sweeps at a
                       time. An object goes only once two sweeps at least
                       --object-get-ttl apart have found it unreferenced.
  The store's credentials are read from RAFT5FS_OBJECT_ACCESS_KEY and
  RAFT5FS_OBJECT_SECRET_KEY.

Users: `user add` prints a one-time code the user enrols with
(`raft5fs enrol`), choosing their password; only their own machine ever
has it, or their keys. With the invite options it also prints an
invitation: one line holding the code, the filesystem servers'
addresses and their CA certificate, which is all `raft5fs enrol` needs.
An invitation is as secret as the code: hand it to the user alone. A new code for an existing user lets them
enrol again after forgetting it -- losing access to whatever was shared
with them until it is shared again. `user del` removes a user and every
grant made to them, cutting them off within --identity-ttl.

Snapshots: `snapshot create` pins the whole filesystem as it is now,
under NAME (letters, digits, '.', '_', '-', ':' and '+'; the time if left
out), and every mount shows it, read-only, at /.snapshot/NAME. What each
user sees there is what they could see when it was taken. Until `snapshot
del` removes it, a snapshot keeps every version of everything changed
since, and the store holds at most 32. Taking and removing them needs a
store administrator's account (e.g. --store-user admin), not the
filesystem servers' own.

Invite options (user add):
  --invite-server <URL>
                       a filesystem server's address, as users reach it
                       (https://...). May be given more than once.
  --invite-ca <PEM>    the CA certificate users' clients should trust for
                       those servers.
  --invite-server-name <NAME>
                       the name to check the servers' certificates
                       against, if not the addresses' hosts.

Store options:
  --store-user <NAME>  the store account to work as; it needs write access
                       to every key. Its password is read from the
                       RAFT5FS_STORE_PASSWORD environment variable.
  --store-ca <PEM>     reach the store over TLS, trusting servers whose
                       certificate chains to this (and nothing else).
  --store-cert <PEM>, --store-key <PEM>
                       present this certificate to the store, for a
                       cluster that requires mTLS. Needs --store-ca.
  --store-server-name <NAME>
                       check the store's certificate against this name
                       instead of the host in each address.

Finding out where time goes, when serving:
  RAFT5FS_LOG=<FILTER> log through `tracing`, filtered as RUST_LOG would
                       be: raft5fs_server=info is a line per request
                       saying how long it took to handle and how much of
                       that went on the store; raft5fs_core=debug adds a
                       line per store call, under the request it was for.
  RAFT5FS_TIMING=1     answer every request with how long it took to
                       handle and what it spent on the store, for clients
                       (also with RAFT5FS_TIMING=1) to set against how
                       long it took from where they are. Off by default:
                       it says a little about what a request found, even
                       to callers who aren't logged in.

Any number of servers can serve one store at once.";

fn usage(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(1);
}

fn fail(why: impl std::fmt::Display) -> ! {
    eprintln!("{why}");
    std::process::exit(1);
}

fn parse_size(s: &str) -> Result<u64, String> {
    let (digits, unit) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1024),
        Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    digits
        .parse::<u64>()
        .map_err(|_| format!("not a size: {s}"))?
        .checked_mul(unit)
        .ok_or_else(|| format!("size too large: {s}"))
}

fn parse_number(flag: &str, s: &str) -> u32 {
    s.parse()
        .unwrap_or_else(|_| usage(&format!("{flag} takes a number, not {s:?}")))
}

/// Every flag, from either mode; each mode then checks it got what it
/// needs and nothing it doesn't use matters.
#[derive(Default)]
struct Args {
    positional: Vec<String>,
    listen: Option<String>,
    token_key_file: Option<String>,
    session_ttl: Option<Duration>,
    chunk_size: Option<u64>,
    store_user: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    store_ca: Option<String>,
    store_cert: Option<String>,
    store_key: Option<String>,
    store_server_name: Option<String>,
    identity_ttl: Option<Duration>,
    object_endpoint: Option<String>,
    object_bucket: Option<String>,
    object_region: Option<String>,
    object_path_style: bool,
    object_prefix: Option<String>,
    object_from: Option<u64>,
    object_block: Option<u64>,
    object_put_ttl: Option<Duration>,
    object_get_ttl: Option<Duration>,
    object_ca: Option<String>,
    gc_interval: Option<Duration>,
    invite_servers: Vec<String>,
    invite_ca: Option<String>,
    invite_server_name: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .unwrap_or_else(|| usage(&format!("{flag} needs a value")))
        };
        match arg.as_str() {
            "--listen" => a.listen = Some(value("--listen")),
            "--token-key-file" => a.token_key_file = Some(value("--token-key-file")),
            "--session-ttl" => {
                let secs = parse_number("--session-ttl", &value("--session-ttl"));
                a.session_ttl = Some(Duration::from_secs(secs.into()));
            }
            "--chunk-size" => {
                a.chunk_size =
                    Some(parse_size(&value("--chunk-size")).unwrap_or_else(|why| usage(&why)));
            }
            "--store-user" => a.store_user = Some(value("--store-user")),
            "--tls-cert" => a.tls_cert = Some(value("--tls-cert")),
            "--tls-key" => a.tls_key = Some(value("--tls-key")),
            "--store-ca" => a.store_ca = Some(value("--store-ca")),
            "--store-cert" => a.store_cert = Some(value("--store-cert")),
            "--store-key" => a.store_key = Some(value("--store-key")),
            "--store-server-name" => a.store_server_name = Some(value("--store-server-name")),
            "--identity-ttl" => {
                let secs = parse_number("--identity-ttl", &value("--identity-ttl"));
                a.identity_ttl = Some(Duration::from_secs(secs.into()));
            }
            "--object-endpoint" => a.object_endpoint = Some(value("--object-endpoint")),
            "--object-bucket" => a.object_bucket = Some(value("--object-bucket")),
            "--object-region" => a.object_region = Some(value("--object-region")),
            "--object-path-style" => a.object_path_style = true,
            "--object-prefix" => a.object_prefix = Some(value("--object-prefix")),
            "--object-from" => {
                a.object_from =
                    Some(parse_size(&value("--object-from")).unwrap_or_else(|why| usage(&why)));
            }
            "--object-block" => {
                a.object_block =
                    Some(parse_size(&value("--object-block")).unwrap_or_else(|why| usage(&why)));
            }
            "--object-put-ttl" => {
                let secs = parse_number("--object-put-ttl", &value("--object-put-ttl"));
                a.object_put_ttl = Some(Duration::from_secs(secs.into()));
            }
            "--object-get-ttl" => {
                let secs = parse_number("--object-get-ttl", &value("--object-get-ttl"));
                a.object_get_ttl = Some(Duration::from_secs(secs.into()));
            }
            "--object-ca" => a.object_ca = Some(value("--object-ca")),
            "--gc-interval" => {
                let secs = parse_number("--gc-interval", &value("--gc-interval"));
                a.gc_interval = Some(Duration::from_secs(secs.into()));
            }
            "--invite-server" => a.invite_servers.push(value("--invite-server")),
            "--invite-ca" => a.invite_ca = Some(value("--invite-ca")),
            "--invite-server-name" => a.invite_server_name = Some(value("--invite-server-name")),
            flag if flag.starts_with("--") => usage(&format!("unknown option {flag}")),
            _ => a.positional.push(arg),
        }
    }
    a
}

fn read_file(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| fail(format!("cannot read {path}: {e}")))
}

/// A certificate and key from two PEM files, if both were named.
fn identity(cert: &Option<String>, key: &Option<String>, what: &str) -> Option<Identity> {
    match (cert, key) {
        (Some(cert), Some(key)) => Some(Identity::from_pem(read_file(cert), read_file(key))),
        (None, None) => None,
        _ => usage(&format!("{what} needs both a certificate and a key")),
    }
}

/// How to dial the store over TLS, if at all.
fn store_tls(a: &Args) -> Option<ClientTls> {
    let identity = identity(&a.store_cert, &a.store_key, "--store-cert/--store-key");
    let Some(ca) = &a.store_ca else {
        if identity.is_some() || a.store_server_name.is_some() {
            usage("--store-cert, --store-key and --store-server-name need --store-ca");
        }
        return None;
    };
    let mut tls = ClientTls::new(Certificate::from_pem(read_file(ca)));
    if let Some(identity) = identity {
        tls = tls.identity(identity);
    }
    if let Some(name) = &a.store_server_name {
        tls = tls.server_name(name);
    }
    Some(tls)
}

/// Where to keep large files' data, if the object options ask for it.
fn object_settings(a: &Args) -> Option<ObjectSettings> {
    let Some(bucket) = &a.object_bucket else {
        if a.object_endpoint.is_some() {
            usage("--object-endpoint needs --object-bucket");
        }
        return None;
    };
    let endpoint = a
        .object_endpoint
        .clone()
        .unwrap_or_else(|| usage("--object-bucket needs --object-endpoint"));
    let credential = |var: &str| {
        env::var(var).unwrap_or_else(|_| usage(&format!("--object-bucket needs {var} set")))
    };
    let http = raft5fs_objstore::http::client(&HttpConfig {
        extra_roots_pem: a.object_ca.as_deref().map(read_file),
        allow_plaintext: endpoint.starts_with("http://"),
        ..HttpConfig::default()
    })
    .unwrap_or_else(|e| fail(e));
    if endpoint.starts_with("http://") {
        eprintln!(
            "warning: reaching the object store without TLS; the URLs it signs \
             cross the network in the clear"
        );
    }
    let store = S3Store::new(
        &S3Config {
            endpoint,
            bucket: bucket.clone(),
            region: a
                .object_region
                .clone()
                .unwrap_or_else(|| "us-east-1".into()),
            path_style: a.object_path_style,
            access_key: credential("RAFT5FS_OBJECT_ACCESS_KEY"),
            secret_key: credential("RAFT5FS_OBJECT_SECRET_KEY"),
            prefix: a.object_prefix.clone().unwrap_or_else(|| "raft5fs/".into()),
        },
        http,
    )
    .unwrap_or_else(|e| usage(&e.to_string()));
    Some(ObjectSettings {
        store,
        object_from: a.object_from.unwrap_or(DEFAULT_OBJECT_FROM),
        object_block: a.object_block.unwrap_or(DEFAULT_OBJECT_BLOCK),
        put_ttl: a.object_put_ttl.unwrap_or(DEFAULT_PUT_TTL),
        get_ttl: a.object_get_ttl.unwrap_or(DEFAULT_GET_TTL),
    })
}

/// A client logged in as the store account.
async fn store_client(a: &Args, seeds: Vec<String>) -> Client {
    if seeds.is_empty() {
        usage("at least one seed address is required");
    }
    let user = a
        .store_user
        .as_deref()
        .unwrap_or_else(|| usage("--store-user is required"));
    let password = env::var("RAFT5FS_STORE_PASSWORD")
        .unwrap_or_else(|_| usage("RAFT5FS_STORE_PASSWORD is not set"));
    let store = Store {
        seeds,
        tls: store_tls(a),
    };
    let client = store
        .client()
        .unwrap_or_else(|e| fail(format!("cannot create a store client: {e}")));
    client
        .login(user, &password)
        .await
        .unwrap_or_else(|e| fail(format!("cannot log in to the store as {user}: {e}")));
    client
}

async fn user_command(a: Args) {
    let mut positional = a.positional.iter().skip(1);
    let command = positional.next().map(String::as_str);
    let name = match command {
        Some("add" | "del") => Some(
            positional
                .next()
                .cloned()
                .unwrap_or_else(|| usage("which user?")),
        ),
        Some("list") => None,
        _ => usage("user takes add, del or list"),
    };
    let seeds = positional.cloned().collect();
    // Checked before a code is issued, so a mistake here wastes none.
    let invite_ca = invite_ca(&a);
    let client = store_client(&a, seeds).await;
    let result = match (command, name) {
        (Some("add"), Some(name)) => accounts::issue_code(&client, &name).await.map(|code| {
            println!("enrolment code for {name}: {code}");
            match invite_ca {
                Some(ca) => {
                    let invite = Invite {
                        user: name.clone(),
                        code,
                        servers: a.invite_servers.clone(),
                        tls_server_name: a.invite_server_name.clone(),
                        ca,
                    };
                    println!("invitation for {name} (as secret as the code -- for {name} alone):");
                    println!("{}", invite.encode());
                    println!("(they run `raft5fs enrol '<invitation>'`)");
                }
                None => println!(
                    "(they run `raft5fs enrol {code} --user {name} --ca <PEM> --server <URL>`)"
                ),
            }
        }),
        (Some("del"), Some(name)) => accounts::remove(&client, &name).await.map(|existed| {
            if !existed {
                eprintln!("there was no user {name}");
            }
        }),
        _ => accounts::list(&client).await.map(|rows| {
            for (name, enrolled) in rows {
                let state = if enrolled { "enrolled" } else { "code issued" };
                println!("{name}\t{state}");
            }
        }),
    };
    result.unwrap_or_else(|e| fail(e));
}

/// The invite options' CA certificate, DER, if invitations were asked
/// for -- after checking they were asked for in full.
fn invite_ca(a: &Args) -> Option<Vec<u8>> {
    let asked = !a.invite_servers.is_empty() || a.invite_ca.is_some();
    if !asked {
        if a.invite_server_name.is_some() {
            usage("--invite-server-name needs --invite-server and --invite-ca");
        }
        return None;
    }
    let Some(path) = &a.invite_ca else {
        usage("an invitation needs --invite-ca");
    };
    if a.invite_servers.is_empty() {
        usage("an invitation needs at least one --invite-server");
    }
    if let Some(plain) = a.invite_servers.iter().find(|s| !s.starts_with("https://")) {
        usage(&format!(
            "--invite-server {plain}: clients only use https:// addresses"
        ));
    }
    let pem = String::from_utf8(read_file(path))
        .unwrap_or_else(|_| fail(format!("{path} isn't a PEM certificate")));
    Some(pem_to_der(&pem).unwrap_or_else(|e| fail(format!("{path}: {e}"))))
}

async fn snapshot_command(a: Args) {
    let mut positional = a.positional.iter().skip(1).peekable();
    let command = positional.next().map(String::as_str);
    let name = match command {
        // A name can't hold a '/', which every seed address does.
        Some("create") => positional.next_if(|p| !p.contains('/')).cloned(),
        Some("del") => Some(
            positional
                .next()
                .cloned()
                .unwrap_or_else(|| usage("which snapshot?")),
        ),
        Some("list") => None,
        _ => usage("snapshot takes create, del or list"),
    };
    let seeds = positional.cloned().collect();
    let client = store_client(&a, seeds).await;
    let result = match (command, name) {
        (Some("create"), name) => snapshots::create(&client, name.as_deref())
            .await
            .map(|made| println!("took snapshot {}", made.name)),
        (Some("del"), Some(name)) => snapshots::remove(&client, &name).await,
        _ => snapshots::list(&client)
            .await
            .map_err(|e| e.to_string())
            .map(|list| {
                for s in list {
                    let secs = s
                        .created
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    println!("{}\t{secs}", s.name);
                }
            }),
    };
    result.unwrap_or_else(|e| fail(e));
}

/// Logs through `tracing` as RAFT5FS_LOG says, if it says anything.
fn init_logging() {
    let Ok(filter) = env::var("RAFT5FS_LOG") else {
        return;
    };
    let filter = tracing_subscriber::EnvFilter::try_new(&filter)
        .unwrap_or_else(|e| usage(&format!("RAFT5FS_LOG: {e}")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
}

async fn serve_command(a: Args) {
    init_logging();
    let listen = a
        .listen
        .clone()
        .unwrap_or_else(|| usage("--listen is required"));
    let key_file = a
        .token_key_file
        .as_deref()
        .unwrap_or_else(|| usage("--token-key-file is required"));
    let key =
        std::fs::read(key_file).unwrap_or_else(|e| fail(format!("cannot read {key_file}: {e}")));
    if key.len() < 32 {
        fail(format!(
            "{key_file} holds {} bytes; use at least 32",
            key.len()
        ));
    }
    let chunk_size = a.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if let Err(why) = validate_chunk_size(chunk_size) {
        usage(&why);
    }

    let objects = object_settings(&a);
    let client = store_client(&a, a.positional.clone()).await;
    let core = FsCore::connect(client, chunk_size, objects)
        .await
        .unwrap_or_else(|why| fail(format!("cannot open the filesystem: {why}")));
    if core.chunk_size() != chunk_size {
        eprintln!(
            "note: this filesystem was created with a {}-byte chunk size; \
             using that rather than the requested {chunk_size}",
            core.chunk_size()
        );
    }
    if let Some(grid) = core.object_grid() {
        eprintln!(
            "keeping hybrid files' data in object storage from chunk {} on, {} chunks to a block",
            grid.from_index, grid.per_block
        );
    }
    let tls = identity(&a.tls_cert, &a.tls_key, "--tls-cert/--tls-key")
        .map(|identity| ServerTlsConfig::new().identity(identity));
    if tls.is_none() {
        eprintln!("warning: serving without TLS; sessions will cross the network in the clear");
    }
    let signer = Signer::new(&key, a.session_ttl.unwrap_or(DEFAULT_SESSION_TTL));
    let listener = TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| usage(&format!("cannot listen on {listen}: {e}")));
    eprintln!("serving on {}", listener.local_addr().unwrap());
    let core = Arc::new(core);
    let gc_interval = a.gc_interval.unwrap_or(DEFAULT_GC_INTERVAL);
    if core.object_grid().is_some() && !gc_interval.is_zero() {
        tokio::spawn(Arc::clone(&core).run_gc(gc_interval));
    }
    let fs = FsService::new(core, signer, a.identity_ttl.unwrap_or(DEFAULT_IDENTITY_TTL))
        .with_timing_header(env::var("RAFT5FS_TIMING").is_ok_and(|v| v == "1"));
    if let Err(e) = raft5fs_server::serve(fs, listener, tls, pending()).await {
        fail(format!("server stopped: {e}"));
    }
}

fn main() {
    let args = parse_args();
    let runtime = Runtime::new().expect("failed to start tokio runtime");
    match args.positional.first().map(String::as_str) {
        Some("user") => runtime.block_on(user_command(args)),
        Some("snapshot") => runtime.block_on(snapshot_command(args)),
        _ => runtime.block_on(serve_command(args)),
    }
}
