use std::env;

use fuser::{Config, MountOption};
use raft5fs_fuse::cli;
use raft5fs_fuse::filesystem::Raft5Fs;
use raft5fs_fuse::remote::Credentials;
use raft5fs_fuse::vault::KnownKeys;
use tokio::runtime::Runtime;

const USAGE: &str = "\
usage: raft5fs-fuse --user <NAME> --ca <PEM> [--tls-server-name <NAME>]
                    [--known-keys <PATH>] [--cache-size <SIZE>]
                    [--no-write-buffer] <mountpoint> <server-address>...

  --user <NAME>        the account to use the filesystem as. Its password
                       is read from the RAFT5FS_PASSWORD environment
                       variable, or asked for on the terminal.
  --ca <PEM>           reach the servers over TLS, trusting certificates
                       that chain to this (and nothing else). Required:
                       what a login sends is enough to test password
                       guesses against, and to act as the user.
  --tls-server-name <NAME>
                       check the servers' certificates against this name
                       instead of the host in each address.
  --insecure-plaintext talk to http:// servers without TLS instead. Only
                       for throwaway setups.
  --known-keys <PATH>  where users' public keys are pinned (as for
                       raft5fs-share; by default
                       ~/.config/raft5fs/known_keys). Writing under a
                       grant takes its sender's key pinned there -- see
                       `raft5fs-share trust`.
  <server-address>     a filesystem server, e.g. https://fs1:7700. Give
                       several: requests go to whichever answers, and move
                       on to the next if one goes away.
  --cache-size <SIZE>  memory for caching file data this machine has read
                       or written, decrypted, as a byte count or with a
                       K/M suffix (default 64M, 0 disables). A cached
                       chunk is still checked with a server on every
                       read, at the cost of a few bytes, so it is never
                       stale.
  --no-write-buffer    store every write immediately instead of buffering
                       small sequential writes until a batch fills, the
                       file is closed, or fsync is called.";

fn usage(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(1);
}

/// A byte count, or a number with a K or M suffix.
fn parse_size(s: &str) -> Result<usize, String> {
    let (digits, unit) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1024),
        Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    digits
        .parse::<usize>()
        .map_err(|_| format!("not a size: {s}"))?
        .checked_mul(unit)
        .ok_or_else(|| format!("size too large: {s}"))
}

fn main() {
    let mut write_buffering = true;
    let mut cache_bytes = None;
    let mut username = None;
    let mut ca = None;
    let mut server_name = None;
    let mut known_keys_file = None;
    let mut plaintext = false;
    let mut positional = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-write-buffer" => write_buffering = false,
            "--cache-size" => {
                let size = args
                    .next()
                    .unwrap_or_else(|| usage("--cache-size needs a value"));
                cache_bytes = Some(parse_size(&size).unwrap_or_else(|why| usage(&why)));
            }
            "--ca" => ca = Some(args.next().unwrap_or_else(|| usage("--ca needs a value"))),
            "--tls-server-name" => {
                server_name = Some(
                    args.next()
                        .unwrap_or_else(|| usage("--tls-server-name needs a value")),
                );
            }
            "--insecure-plaintext" => plaintext = true,
            "--known-keys" => {
                known_keys_file = Some(std::path::PathBuf::from(
                    args.next()
                        .unwrap_or_else(|| usage("--known-keys needs a value")),
                ));
            }
            "--user" => {
                username = Some(args.next().unwrap_or_else(|| usage("--user needs a value")));
            }
            _ => positional.push(arg),
        }
    }
    if positional.len() < 2 {
        usage("a mountpoint and at least one server address are required");
    }
    let mountpoint = positional.remove(0);
    let username = username.unwrap_or_else(|| usage("--user is required"));
    let password = cli::password_from("RAFT5FS_PASSWORD", &format!("password for {username}: "))
        .unwrap_or_else(|e| {
            eprintln!("cannot read a password: {e}");
            std::process::exit(1);
        });
    let mut credentials = Credentials::new(username, password);
    credentials.allow_plaintext = plaintext;
    if ca.is_none() && !plaintext {
        usage("--ca is required (or --insecure-plaintext, for a throwaway setup)");
    }
    let known_keys_file = known_keys_file.unwrap_or_else(cli::default_known_keys);
    let known_keys = KnownKeys::load(known_keys_file.clone()).unwrap_or_else(|e| {
        eprintln!(
            "cannot read the known keys in {}: {e}",
            known_keys_file.display()
        );
        std::process::exit(1);
    });
    let tls = ca.map(|path| {
        cli::tls(&path, server_name.as_deref()).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        })
    });
    if tls.is_none() && server_name.is_some() {
        usage("--tls-server-name needs --ca");
    }

    let runtime = Runtime::new().expect("failed to start tokio runtime");
    let mut fs = Raft5Fs::new(positional, credentials, runtime.handle().clone())
        .with_write_buffering(write_buffering)
        .with_known_keys(known_keys);
    if let Some(bytes) = cache_bytes {
        fs = fs.with_cache_size(bytes);
    }
    if let Some(tls) = tls {
        fs = fs.with_tls(tls);
    }

    let mut options = Config::default();
    // Neither `default_permissions` nor `allow_other`: the servers check
    // every request against the mount's one identity, so the kernel
    // checking the local caller too would only get in the way -- and
    // letting other local users in would hand them that identity.
    options.mount_options = vec![MountOption::FSName("raft5fs".to_string())];
    // Writes commit synchronously, so without this, one file's slow commit
    // would stall every other fuse request on the mount -- `fuser`
    // dispatches from a single thread unless told otherwise.
    options.n_threads = Some(8);

    // `init` has already said why, if it was the connection or the login
    // that failed.
    if let Err(e) = fuser::mount(fs, &mountpoint, &options) {
        eprintln!("cannot mount {mountpoint}: {e}");
        std::process::exit(1);
    }
}
