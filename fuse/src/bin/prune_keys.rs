use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use raft5fs_fuse::cli;
use raft5fs_fuse::remote::{Credentials, Remote};
use raft5fs_fuse::vault::{KnownKeys, PruneStats, Vault};
use raft5fs_proto::types::Kind;
use tokio::runtime::Runtime;

const USAGE: &str = "\
usage: raft5fs-prune-keys --user <NAME> [--ca <PEM> [--tls-server-name <NAME>]]
                          [--path <PATH>]... [--dry-run] <server-address>...

Seals everything still under an old version of a key again under the
current one, then drops the old versions from the key's history. A key
gets a new version whenever a grant is revoked; what was sealed under the
old one stays readable, given the ciphertext, by whoever was revoked,
until it is pruned.

Every directory and file under the account's writable grants is pruned
(or with --path, under those directories only: a PATH starts with an entry
of your root, as for raft5fs-share). Read-only grants are skipped -- a
prune writes. A node that can't be pruned is reported and skipped, with
everything under it; the rest goes on. Mounts may stay in use meanwhile.

Every client of the filesystem must be one that understands pruned key
histories before this is run: older ones can't read a pruned node's keys.

  --user <NAME>        the account.
  --path <PATH>        a directory to prune, instead of every grant; may
                       be given more than once.
  --dry-run            count what would be done, and change nothing.
  --ca <PEM>           reach the servers over TLS, trusting certificates
                       that chain to this (and nothing else). Required,
                       unless --insecure-plaintext.
  --insecure-plaintext talk to http:// servers without TLS. Only for
                       throwaway setups.
  --tls-server-name <NAME>
                       check the servers' certificates against this name
                       instead of the host in each address.
  --known-keys <PATH>  where pinned keys are kept (as for raft5fs-share):
                       grants from users not pinned there are skipped,
                       and giving a stale child a new key re-seals its
                       grants only to the keys its key holders sealed
                       them to.

The password is asked for on the terminal, or read from RAFT5FS_PASSWORD.";

fn usage(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(1);
}

fn fail(why: impl std::fmt::Display) -> ! {
    eprintln!("{why}");
    std::process::exit(1);
}

fn report(what: &str, stats: &PruneStats, dry_run: bool) {
    let verb = if dry_run {
        "would re-seal"
    } else {
        "re-sealed"
    };
    println!(
        "{what}: {} nodes; {verb} {} chunks and {} names; {} {} stale children; {} {} old key versions",
        stats.nodes,
        stats.chunks,
        stats.names,
        if dry_run { "would rotate" } else { "rotated" },
        stats.rotated,
        if dry_run { "would drop" } else { "dropped" },
        stats.dropped,
    );
    for (ino, e) in &stats.skipped {
        println!("  skipped inode {ino}, and everything under it: {e}");
    }
}

fn main() {
    let mut username = None;
    let mut ca = None;
    let mut server_name = None;
    let mut known_keys_file = None;
    let mut paths = Vec::new();
    let mut dry_run = false;
    let mut plaintext = false;
    let mut servers = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .unwrap_or_else(|| usage(&format!("{flag} needs a value")))
        };
        match arg.as_str() {
            "--user" => username = Some(value("--user")),
            "--ca" => ca = Some(value("--ca")),
            "--tls-server-name" => server_name = Some(value("--tls-server-name")),
            "--known-keys" => known_keys_file = Some(PathBuf::from(value("--known-keys"))),
            "--path" => paths.push(value("--path")),
            "--dry-run" => dry_run = true,
            "--insecure-plaintext" => plaintext = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            flag if flag.starts_with("--") => usage(&format!("unknown option {flag}")),
            _ => servers.push(arg),
        }
    }
    let username = username.unwrap_or_else(|| usage("--user is required"));
    if servers.is_empty() {
        usage("at least one server address is required");
    }
    let tls = ca.map(|path| cli::tls(&path, server_name.as_deref()).unwrap_or_else(|e| fail(e)));
    if tls.is_none() && server_name.is_some() {
        usage("--tls-server-name needs --ca");
    }
    if tls.is_none() && !plaintext {
        usage("--ca is required (or --insecure-plaintext, for a throwaway setup)");
    }
    let known_keys_file = known_keys_file.unwrap_or_else(cli::default_known_keys);
    let known_keys = KnownKeys::load(known_keys_file.clone()).unwrap_or_else(|e| {
        fail(format!(
            "cannot read the known keys in {}: {e}",
            known_keys_file.display()
        ))
    });

    let runtime = Runtime::new().expect("failed to start tokio runtime");
    let password = cli::password_from("RAFT5FS_PASSWORD", &format!("password for {username}: "))
        .unwrap_or_else(|e| fail(format!("cannot read a password: {e}")));
    let mut credentials = Credentials::new(username, password);
    credentials.allow_plaintext = plaintext;
    let remote = runtime
        .block_on(Remote::connect(&servers, credentials, tls))
        .unwrap_or_else(|e| fail(format!("cannot log in: {e}")));
    let vault = Vault::new(Arc::new(remote))
        .unwrap_or_else(|e| fail(e))
        .with_known_keys(known_keys);

    let mut tops = Vec::new();
    if paths.is_empty() {
        let roots = runtime
            .block_on(vault.grant_roots())
            .unwrap_or_else(|e| fail(format!("cannot list this account's grants: {e}")));
        for root in roots {
            let label = root.label.to_string_lossy().into_owned();
            if root.writable {
                tops.push((label, root.ino));
            } else {
                println!("{label}: skipped, a read-only grant");
            }
        }
    } else {
        for path in paths {
            let ino = runtime
                .block_on(async {
                    let ino = vault.resolve(&path).await?;
                    let attr = vault.remote().getattr(ino).await?;
                    if attr.kind != Kind::Directory {
                        return Err(raft5fs_proto::types::FsError::errno(libc::ENOTDIR));
                    }
                    Ok(ino)
                })
                .unwrap_or_else(|e| fail(format!("cannot prune {path}: {e}")));
            tops.push((path, ino));
        }
    }

    let mut skipped = false;
    for (what, ino) in tops {
        let stats = runtime.block_on(vault.prune_tree(ino, dry_run));
        report(&what, &stats, dry_run);
        skipped |= !stats.skipped.is_empty();
    }
    if skipped {
        std::process::exit(2);
    }
}
