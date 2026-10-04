use std::env;

use fuser::{Config, MountOption};
use raft5fs_fuse::cli;
use raft5fs_fuse::filesystem::Raft5Fs;
use raft5fs_fuse::remote::Credentials;
use tokio::runtime::Runtime;

const USAGE: &str = "\
usage: raft5fs-fuse --user <NAME> [--ca <PEM> [--tls-server-name <NAME>]]
                    [--no-write-buffer] <mountpoint> <server-address>...

  --user <NAME>        the account to use the filesystem as. Its password
                       is read from the RAFT5FS_PASSWORD environment
                       variable, or asked for on the terminal.
  --ca <PEM>           reach the servers over TLS, trusting certificates
                       that chain to this (and nothing else). Without it
                       the password and all file data cross the network
                       in the clear.
  --tls-server-name <NAME>
                       check the servers' certificates against this name
                       instead of the host in each address.
  <server-address>     a filesystem server, e.g. https://fs1:7700. Give
                       several: requests go to whichever answers, and move
                       on to the next if one goes away.
  --no-write-buffer    store every write immediately instead of buffering
                       small sequential writes until a batch fills, the
                       file is closed, or fsync is called.";

fn usage(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(1);
}

fn main() {
    let mut write_buffering = true;
    let mut username = None;
    let mut ca = None;
    let mut server_name = None;
    let mut positional = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-write-buffer" => write_buffering = false,
            "--ca" => ca = Some(args.next().unwrap_or_else(|| usage("--ca needs a value"))),
            "--tls-server-name" => {
                server_name = Some(
                    args.next()
                        .unwrap_or_else(|| usage("--tls-server-name needs a value")),
                );
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
    let credentials = Credentials { username, password };
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
        .with_write_buffering(write_buffering);
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
