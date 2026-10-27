use std::env;
use std::future::pending;
use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use raft5_client::{Certificate, Client, ClientTls, Identity};
use raft5fs_core::backup::{self, BackupStore};
use raft5fs_core::gc::DEFAULT_GC_INTERVAL;
use raft5fs_core::objects::{
    DEFAULT_GET_TTL, DEFAULT_OBJECT_BLOCK, DEFAULT_OBJECT_FROM, DEFAULT_PUT_TTL, ObjectSettings,
};
use raft5fs_core::{DEFAULT_CHUNK_SIZE, FsCore, accounts, snapshots, validate_chunk_size};
use raft5fs_crypto::backup::{BACKUP_KEY_LEN, BackupKeyPair};
use raft5fs_objstore::http::HttpConfig;
use raft5fs_objstore::{S3Config, S3Store};
use raft5fs_proto::invite::{Invite, pem_to_der};
use raft5fs_proto::types::{AccountKind, Caps};
use raft5fs_server::auth::{DEFAULT_SESSION_TTL, Signer};
use raft5fs_server::{
    DEFAULT_IDENTITY_TTL, FsService, InviteSettings, Store, WebPort, parse_origin,
};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tonic::transport::ServerTlsConfig;

const USAGE: &str = "\
usage: raft5fs-server --listen <ADDR> --token-key-file <PATH>
                      [--tls-cert <PEM> --tls-key <PEM>]
                      [--web-listen <ADDR> --web-origin <URL>
                       [--web-tls-cert <PEM> --web-tls-key <PEM>]] [options]
                      <store options> <kv-seed-address>...
       raft5fs-server user add <NAME> [<capabilities>] [<invite options>]
                      <store options> <kv-seed-address>...
       raft5fs-server user set <NAME> <capabilities> <store options>
                      <kv-seed-address>...
       raft5fs-server user del <NAME> <store options> <kv-seed-address>...
       raft5fs-server user list <store options> <kv-seed-address>...
       raft5fs-server snapshot create [<NAME>] <store options> <kv-seed-address>...
       raft5fs-server snapshot del <NAME> <store options> <kv-seed-address>...
       raft5fs-server snapshot list <store options> <kv-seed-address>...
       raft5fs-server backup create <SNAPSHOT> <store options> <object options>
                      <backup options> <kv-seed-address>...
       raft5fs-server backup del <NAME> <store options> <backup options>
                      <kv-seed-address>...
       raft5fs-server backup list <backup options>
       raft5fs-server backup keygen <PRIVATE-KEY-FILE>
       raft5fs-server backup fetch-kv <NAME> <OUT-FILE>
                      --backup-private-key <FILE> <backup options>
       raft5fs-server backup restore-objects <NAME> <object options>
                      <backup options>

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

The web port: browsers can't use the --listen port (plain gRPC, under
the filesystem's own CA). With --web-listen, the server also serves them
gRPC-Web, the same service, on a second port, for the web app at
--web-origin only.
  --web-listen <ADDR>  address to serve browsers on, e.g. 0.0.0.0:27061.
  --web-origin <URL>   the web app's origin, e.g. https://app.example.com
                       (no path). Browsers may read answers only for pages
                       from there.
  --web-tls-cert <PEM>, --web-tls-key <PEM>
                       the web port's certificate and key. Browsers trust
                       only public CAs, so this is not the filesystem's
                       CA: e.g. a Let's Encrypt certificate. It is read at
                       start, so restart the server after a renewal.
                       Without them the port is plain HTTP, for local
                       development only.

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
  --no-prompt-delete   don't try deleting an object as soon as a change
                       stops pointing at it; leave it all to the sweeps.
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
grant made to them, cutting them off within --identity-ttl. `user list`
shows each user's capabilities, under whoever invited them.

Capabilities: what a user may start, beyond what is shared with them.
  --volumes [on|off]   make new top-level folders (volumes). New users
                       have it unless --no-volumes; users added before
                       capabilities existed have it too.
  --invite [on|off]    invite new users themselves, giving them at most
                       their own capabilities. (Serving servers need the
                       invite options for these invitations to be whole.)
  --links [on|off]     make public links to folders.
  --no-volumes, --no-invite, --no-links
                       the same as `off`.
`user add` applies them to a new user, or to an existing user's current
ones; `user set` changes an existing user's.

Snapshots: `snapshot create` pins the whole filesystem as it is now,
under NAME (letters, digits, '.', '_', '-', ':' and '+'; the time if left
out), and every mount shows it, read-only, at /.snapshot/NAME. What each
user sees there is what they could see when it was taken. Until `snapshot
del` removes it, a snapshot keeps every version of everything changed
since, and the store holds at most 32. Taking and removing them needs a
store account in raft5's backup-operators group (or admins): add the
filesystem servers' account to backup-operators.

Backups: `backup create` copies a snapshot to a backup space, an
S3-compatible bucket that is not the one the servers keep objects in. It
holds the store's own backup of the snapshot, sealed to an operator key,
and every object the snapshot points to. Take the snapshot first, then
back it up under the same name:
  raft5fs-server snapshot create nightly-1 ...
  raft5fs-server backup create nightly-1 ...
Backups share their objects, so each one copies only objects that no
earlier backup has. A backup is whole once its manifest is written; one
that fails part way is cleaned up by the next `backup del`. `backup del`
deletes a backup and every object no other backup uses; it leaves the
snapshot. Only one backup job runs at a time.
  `backup keygen FILE` makes the operator key pair: it writes the private
key to FILE, and the public key to FILE.pub. Give the servers only the
public key (--backup-public-key), and keep the private key offline: it
opens every backup's store contents.
  To restore: `backup fetch-kv NAME OUT` opens the store backup with the
private key; `raft bootstrap <id> --restore-from OUT` starts a new store
from it; `backup restore-objects NAME` copies the objects into the
bucket the restored servers will use (--object-* options, same prefix
as before). Then start the servers. The restored store has no snapshots.

Backup options:
  --backup-endpoint <URL>, --backup-bucket <NAME>, --backup-region <NAME>,
  --backup-path-style, --backup-ca <PEM>
                       the backup space, as for the --object-* options.
                       Its credentials are read from
                       RAFT5FS_BACKUP_ACCESS_KEY and
                       RAFT5FS_BACKUP_SECRET_KEY.
  --backup-prefix <PATH>
                       what every key in the backup space starts with,
                       ending in '/' (default raft5fs-backup/).
  --backup-public-key <FILE>
                       the operator public key to seal backups to (from
                       `backup keygen`). Needed by `backup create`.
  --backup-private-key <FILE>
                       the operator private key. Needed by
                       `backup fetch-kv`.

Invite options (user add, and serving: for invitations users issue):
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

/// Every flag from both modes. Each mode checks that it got the flags it
/// needs, and ignores the rest.
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
    no_prompt_delete: bool,
    backup_endpoint: Option<String>,
    backup_bucket: Option<String>,
    backup_region: Option<String>,
    backup_path_style: bool,
    backup_prefix: Option<String>,
    backup_ca: Option<String>,
    backup_public_key: Option<String>,
    backup_private_key: Option<String>,
    invite_servers: Vec<String>,
    invite_ca: Option<String>,
    invite_server_name: Option<String>,
    /// Capability flags, in order: each turns one on or off.
    caps: Vec<(Caps, bool)>,
    web_listen: Option<String>,
    web_origin: Option<String>,
    web_tls_cert: Option<String>,
    web_tls_key: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if let Some((cap, on)) = cap_flag(&arg) {
            let on = match args.peek().map(String::as_str) {
                Some("on") => true,
                Some("off") => false,
                _ => {
                    a.caps.push((cap, on));
                    continue;
                }
            };
            args.next();
            if arg.starts_with("--no-") {
                usage(&format!("{arg} takes no value"));
            }
            a.caps.push((cap, on));
            continue;
        }
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
            "--web-listen" => a.web_listen = Some(value("--web-listen")),
            "--web-origin" => a.web_origin = Some(value("--web-origin")),
            "--web-tls-cert" => a.web_tls_cert = Some(value("--web-tls-cert")),
            "--web-tls-key" => a.web_tls_key = Some(value("--web-tls-key")),
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
            "--no-prompt-delete" => a.no_prompt_delete = true,
            "--backup-endpoint" => a.backup_endpoint = Some(value("--backup-endpoint")),
            "--backup-bucket" => a.backup_bucket = Some(value("--backup-bucket")),
            "--backup-region" => a.backup_region = Some(value("--backup-region")),
            "--backup-path-style" => a.backup_path_style = true,
            "--backup-prefix" => a.backup_prefix = Some(value("--backup-prefix")),
            "--backup-ca" => a.backup_ca = Some(value("--backup-ca")),
            "--backup-public-key" => a.backup_public_key = Some(value("--backup-public-key")),
            "--backup-private-key" => a.backup_private_key = Some(value("--backup-private-key")),
            "--invite-server" => a.invite_servers.push(value("--invite-server")),
            "--invite-ca" => a.invite_ca = Some(value("--invite-ca")),
            "--invite-server-name" => a.invite_server_name = Some(value("--invite-server-name")),
            flag if flag.starts_with("--") => usage(&format!("unknown option {flag}")),
            _ => a.positional.push(arg),
        }
    }
    a
}

/// The capability that a flag such as `--invite` or `--no-links` names,
/// and whether it turns it on.
fn cap_flag(flag: &str) -> Option<(Caps, bool)> {
    let name = flag.strip_prefix("--")?;
    match name.strip_prefix("no-") {
        Some(name) => Caps::named(name).map(|cap| (cap, false)),
        None => Caps::named(name).map(|cap| (cap, true)),
    }
}

fn read_file(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| fail(format!("cannot read {path}: {e}")))
}

/// A certificate and key from two PEM files, if both were given.
fn identity(cert: &Option<String>, key: &Option<String>, what: &str) -> Option<Identity> {
    match (cert, key) {
        (Some(cert), Some(key)) => Some(Identity::from_pem(read_file(cert), read_file(key))),
        (None, None) => None,
        _ => usage(&format!("{what} needs both a certificate and a key")),
    }
}

/// How to connect to the store over TLS, if at all.
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

/// One S3-compatible space's options, from `--object-*` or `--backup-*`.
struct SpaceOptions<'a> {
    /// The options' start, `--object` or `--backup`.
    flag: &'a str,
    endpoint: &'a Option<String>,
    bucket: &'a Option<String>,
    region: &'a Option<String>,
    path_style: bool,
    ca: &'a Option<String>,
    /// The start of the credential variables' names.
    env: &'a str,
}

/// The settings and HTTP client for a space, if its options name a
/// bucket.
fn space(o: SpaceOptions, prefix: String) -> Option<(S3Config, raft5fs_objstore::http::Client)> {
    let flag = o.flag;
    let Some(bucket) = o.bucket else {
        if o.endpoint.is_some() {
            usage(&format!("{flag}-endpoint needs {flag}-bucket"));
        }
        return None;
    };
    let endpoint = o
        .endpoint
        .clone()
        .unwrap_or_else(|| usage(&format!("{flag}-bucket needs {flag}-endpoint")));
    let credential = |var: String| {
        env::var(&var).unwrap_or_else(|_| usage(&format!("{flag}-bucket needs {var} set")))
    };
    let http = raft5fs_objstore::http::client(&HttpConfig {
        extra_roots_pem: o.ca.as_deref().map(read_file),
        allow_plaintext: endpoint.starts_with("http://"),
        ..HttpConfig::default()
    })
    .unwrap_or_else(|e| fail(e));
    if endpoint.starts_with("http://") {
        eprintln!(
            "warning: reaching {endpoint} without TLS; what is signed for it crosses the \
             network in the clear"
        );
    }
    let config = S3Config {
        endpoint,
        bucket: bucket.clone(),
        region: o.region.clone().unwrap_or_else(|| "us-east-1".into()),
        path_style: o.path_style,
        access_key: credential(format!("{}_ACCESS_KEY", o.env)),
        secret_key: credential(format!("{}_SECRET_KEY", o.env)),
        prefix,
    };
    Some((config, http))
}

fn store_for(config: &S3Config, http: raft5fs_objstore::http::Client) -> S3Store {
    S3Store::new(config, http).unwrap_or_else(|e| usage(&e.to_string()))
}

fn object_space(a: &Args) -> Option<(S3Config, raft5fs_objstore::http::Client)> {
    space(
        SpaceOptions {
            flag: "--object",
            endpoint: &a.object_endpoint,
            bucket: &a.object_bucket,
            region: &a.object_region,
            path_style: a.object_path_style,
            ca: &a.object_ca,
            env: "RAFT5FS_OBJECT",
        },
        a.object_prefix.clone().unwrap_or_else(|| "raft5fs/".into()),
    )
}

/// Where to keep large files' data, if the object options ask for object
/// storage.
fn object_settings(a: &Args) -> Option<ObjectSettings> {
    let (config, http) = object_space(a)?;
    Some(ObjectSettings {
        store: store_for(&config, http),
        object_from: a.object_from.unwrap_or(DEFAULT_OBJECT_FROM),
        object_block: a.object_block.unwrap_or(DEFAULT_OBJECT_BLOCK),
        put_ttl: a.object_put_ttl.unwrap_or(DEFAULT_PUT_TTL),
        get_ttl: a.object_get_ttl.unwrap_or(DEFAULT_GET_TTL),
        prompt_delete: !a.no_prompt_delete,
    })
}

/// The backup space from the backup options, which a backup command needs.
/// It refuses a backup space that is the serving space: a backup must
/// outlive what happens to that.
fn backup_store(a: &Args, serving: Option<&S3Config>) -> BackupStore {
    let prefix = a
        .backup_prefix
        .clone()
        .unwrap_or_else(|| "raft5fs-backup/".into());
    let (config, http) = space(
        SpaceOptions {
            flag: "--backup",
            endpoint: &a.backup_endpoint,
            bucket: &a.backup_bucket,
            region: &a.backup_region,
            path_style: a.backup_path_style,
            ca: &a.backup_ca,
            env: "RAFT5FS_BACKUP",
        },
        prefix.clone(),
    )
    .unwrap_or_else(|| usage("a backup command needs --backup-endpoint and --backup-bucket"));
    if let Some(serving) = serving
        && serving.bucket == config.bucket
        && serving.endpoint.trim_end_matches('/') == config.endpoint.trim_end_matches('/')
    {
        usage("the backup space must be another bucket than the one objects are served from");
    }
    let pool = S3Config {
        prefix: format!("{prefix}objects/"),
        ..config.clone()
    };
    BackupStore::new(store_for(&pool, http.clone()), store_for(&config, http))
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
        Some("add" | "set" | "del") => Some(
            positional
                .next()
                .cloned()
                .unwrap_or_else(|| usage("which user?")),
        ),
        Some("list") => None,
        _ => usage("user takes add, set, del or list"),
    };
    let (mut on, mut off) = (Caps::NONE, Caps::NONE);
    for &(cap, turn_on) in &a.caps {
        on = on.with(cap, turn_on);
        off = off.with(cap, !turn_on);
    }
    match command {
        Some("set") if a.caps.is_empty() => {
            usage("user set needs --volumes, --invite or --links, each on or off")
        }
        Some("add" | "set") => {}
        _ if !a.caps.is_empty() => usage("only user add and user set take capabilities"),
        _ => {}
    }
    let seeds = positional.cloned().collect();
    // Check this before a code is issued, so a mistake does not use up a
    // code.
    let invite_ca = invite_ca(&a);
    let client = store_client(&a, seeds).await;
    let result = match (command, name) {
        (Some("add"), Some(name)) => accounts::add(&client, &name, on, off).await.map(|code| {
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
        (Some("set"), Some(name)) => accounts::set_caps(&client, &name, on, off)
            .await
            .map(|caps| println!("{name} can now: {}", caps_text(caps))),
        _ => accounts::list(&client).await.map(print_accounts),
    };
    result.unwrap_or_else(|e| fail(e));
}

fn caps_text(caps: Caps) -> String {
    if caps == Caps::NONE {
        "-".to_string()
    } else {
        caps.names().join(",")
    }
}

/// Prints every account, each under the user who invited it (or, for a
/// link, made it), indented a level per step.
fn print_accounts(rows: Vec<accounts::Listed>) {
    let names: std::collections::HashSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    let parent = |row: &accounts::Listed| -> Option<String> {
        let parent = match row.info.kind {
            AccountKind::Link => &row.info.owner,
            AccountKind::Person => &row.info.invited_by,
        };
        names.contains(parent.as_str()).then(|| parent.clone())
    };
    let mut children: std::collections::BTreeMap<Option<String>, Vec<&accounts::Listed>> =
        Default::default();
    for row in &rows {
        children.entry(parent(row)).or_default().push(row);
    }
    // Each account has one parent and is printed under it once. Every
    // record names its parent at creation, so there are no loops; the
    // `seen` set only guards against a damaged store.
    let mut seen = std::collections::HashSet::new();
    let mut stack: Vec<(&accounts::Listed, usize)> = children
        .get(&None)
        .into_iter()
        .flatten()
        .rev()
        .map(|row| (*row, 0))
        .collect();
    while let Some((row, depth)) = stack.pop() {
        if !seen.insert(row.name.as_str()) {
            continue;
        }
        let state = if row.enrolled {
            "enrolled"
        } else {
            "code issued"
        };
        let what = match row.info.kind {
            AccountKind::Link => match row.info.expires {
                Some(at) => format!("public link, expires {at}"),
                None => "public link".to_string(),
            },
            AccountKind::Person => caps_text(row.info.caps),
        };
        println!("{}{}\t{state}\t{what}", "  ".repeat(depth), row.name);
        if let Some(kids) = children.get(&Some(row.name.clone())) {
            stack.extend(kids.iter().rev().map(|kid| (*kid, depth + 1)));
        }
    }
}

/// The invite options, for a server to put in the invitations that users
/// issue, if they were given.
fn invite_settings(a: &Args) -> Option<InviteSettings> {
    invite_ca(a).map(|ca| InviteSettings {
        servers: a.invite_servers.clone(),
        tls_server_name: a.invite_server_name.clone(),
        ca,
    })
}

/// The CA certificate from the invite options, in DER, if invitations were
/// asked for. It first checks that all the invite options were given.
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
        // A name cannot contain '/', and every seed address does.
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

/// Reads a key file that `backup keygen` wrote: the key in hex.
fn read_key_file(path: &str) -> [u8; BACKUP_KEY_LEN] {
    let text = String::from_utf8(read_file(path)).unwrap_or_default();
    let text = text.trim();
    let bytes: Option<Vec<u8>> = (text.len() == 2 * BACKUP_KEY_LEN)
        .then(|| {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
                .collect()
        })
        .flatten();
    bytes
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| fail(format!("{path} doesn't hold a backup key")))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes `text` to a new file at `path` that only its owner can read.
fn write_secret_file(path: &str, text: &str) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .unwrap_or_else(|e| fail(format!("cannot write {path}: {e}")));
}

async fn backup_command(a: Args) {
    let mut positional = a.positional.iter().skip(1);
    let command = positional.next().map(String::as_str);
    let mut arg = |what: &str| {
        positional
            .next()
            .cloned()
            .unwrap_or_else(|| usage(&format!("which {what}?")))
    };
    match command {
        Some("keygen") => {
            let path = arg("file");
            let pair = BackupKeyPair::generate();
            let public = hex(&pair.public_key());
            write_secret_file(&path, &format!("{}\n", hex(pair.to_bytes().as_ref())));
            let public_path = format!("{path}.pub");
            std::fs::write(&public_path, format!("{public}\n"))
                .unwrap_or_else(|e| fail(format!("cannot write {public_path}: {e}")));
            println!("private key written to {path}: keep it offline");
            println!("public key written to {public_path}: {public}");
        }
        Some("create") => {
            let snapshot = arg("snapshot");
            let seeds = positional.cloned().collect();
            let public_key = read_key_file(
                a.backup_public_key
                    .as_deref()
                    .unwrap_or_else(|| usage("backup create needs --backup-public-key")),
            );
            let serving = object_space(&a);
            let backup = backup_store(&a, serving.as_ref().map(|(c, _)| c));
            let serving = serving.map(|(config, http)| Arc::new(store_for(&config, http)));
            let client = store_client(&a, seeds).await;
            let stats = backup::create(&client, serving, &backup, &public_key, &snapshot)
                .await
                .unwrap_or_else(|e| fail(format!("backup of {snapshot} failed: {e}")));
            println!(
                "backed up {snapshot}: {} objects ({} new), {} bytes of store contents",
                stats.objects, stats.copied, stats.kv_bytes
            );
        }
        Some("del") => {
            let name = arg("backup");
            let seeds = positional.cloned().collect();
            let backup = backup_store(&a, None);
            let client = store_client(&a, seeds).await;
            let stats = backup::delete(&client, &backup, &name)
                .await
                .unwrap_or_else(|e| fail(e));
            if !stats.existed {
                eprintln!("there was no backup {name}");
            }
            println!(
                "deleted {} unused objects and {} failed backups",
                stats.objects_deleted, stats.leftovers_deleted
            );
        }
        Some("list") => {
            let backup = backup_store(&a, None);
            for b in backup::list(&backup).await.unwrap_or_else(|e| fail(e)) {
                let secs = b
                    .created
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                println!(
                    "{}\t{secs}\t{} objects\t{} object bytes\t{} store bytes",
                    b.name, b.objects, b.object_bytes, b.kv_bytes
                );
            }
        }
        Some("fetch-kv") => {
            let name = arg("backup");
            let out = arg("output file");
            let private_key = read_key_file(
                a.backup_private_key
                    .as_deref()
                    .unwrap_or_else(|| usage("backup fetch-kv needs --backup-private-key")),
            );
            let backup = backup_store(&a, None);
            let pair = BackupKeyPair::from_bytes(private_key);
            let written = backup::fetch_kv(&backup, &pair, &name, std::path::Path::new(&out))
                .await
                .unwrap_or_else(|e| fail(e));
            println!(
                "wrote {written} bytes to {out}; restore with `raft bootstrap <id> --restore-from {out}`"
            );
        }
        Some("restore-objects") => {
            let name = arg("backup");
            let (config, http) = object_space(&a)
                .unwrap_or_else(|| usage("backup restore-objects needs the --object-* options"));
            let backup = backup_store(&a, Some(&config));
            let serving = Arc::new(store_for(&config, http));
            let count = backup::restore_objects(&backup, serving, &name)
                .await
                .unwrap_or_else(|e| fail(e));
            println!("copied {count} objects into {}", config.bucket);
        }
        _ => usage("backup takes create, del, list, keygen, fetch-kv or restore-objects"),
    }
}

/// Logs through `tracing` as RAFT5FS_LOG says, if it is set.
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
    let web = web_port(&a).await;
    let core = Arc::new(core);
    let gc_interval = a.gc_interval.unwrap_or(DEFAULT_GC_INTERVAL);
    if core.object_grid().is_some() && !gc_interval.is_zero() {
        tokio::spawn(Arc::clone(&core).run_gc(gc_interval));
    }
    let fs = FsService::new(core, signer, a.identity_ttl.unwrap_or(DEFAULT_IDENTITY_TTL))
        .with_timing_header(env::var("RAFT5FS_TIMING").is_ok_and(|v| v == "1"))
        .with_invites(invite_settings(&a));
    let fs = Arc::new(fs);
    let native = raft5fs_server::serve(Arc::clone(&fs), listener, tls, pending());
    let served = match web {
        Some(web) => {
            let web = raft5fs_server::serve_web(fs, web, pending());
            tokio::try_join!(native, web).map(|_| ())
        }
        None => native.await,
    };
    if let Err(e) = served {
        fail(format!("server stopped: {e}"));
    }
}

/// The web port, if `--web-listen` asks for one.
async fn web_port(a: &Args) -> Option<WebPort> {
    let Some(listen) = &a.web_listen else {
        if a.web_origin.is_some() || a.web_tls_cert.is_some() || a.web_tls_key.is_some() {
            usage("--web-origin, --web-tls-cert and --web-tls-key need --web-listen");
        }
        return None;
    };
    let origin = a
        .web_origin
        .as_deref()
        .unwrap_or_else(|| usage("--web-listen needs --web-origin"));
    let origin = parse_origin(origin).unwrap_or_else(|why| usage(&format!("--web-origin: {why}")));
    let tls = identity(
        &a.web_tls_cert,
        &a.web_tls_key,
        "--web-tls-cert/--web-tls-key",
    )
    .map(|identity| ServerTlsConfig::new().identity(identity));
    if tls.is_none() {
        eprintln!("warning: the web port is plain HTTP; use it only for local development");
    }
    let listener = TcpListener::bind(listen)
        .await
        .unwrap_or_else(|e| usage(&format!("cannot listen on {listen}: {e}")));
    eprintln!(
        "serving browsers on {} for {}",
        listener.local_addr().unwrap(),
        origin.to_str().unwrap_or("?")
    );
    Some(WebPort {
        listener,
        tls,
        origin,
    })
}

fn main() {
    let args = parse_args();
    let runtime = Runtime::new().expect("failed to start tokio runtime");
    match args.positional.first().map(String::as_str) {
        Some("user") => runtime.block_on(user_command(args)),
        Some("snapshot") => runtime.block_on(snapshot_command(args)),
        Some("backup") => runtime.block_on(backup_command(args)),
        _ => runtime.block_on(serve_command(args)),
    }
}
