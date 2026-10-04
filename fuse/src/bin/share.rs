use std::env;
use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_crypto::identity::fingerprint;
use raft5fs_crypto::password::KdfParams;
use raft5fs_fuse::cli;
use raft5fs_fuse::remote::{Credentials, Remote};
use raft5fs_fuse::vault::Vault;
use tokio::runtime::Runtime;

const USAGE: &str = "\
usage: raft5fs-share --user <NAME> [--ca <PEM> [--tls-server-name <NAME>]]
                     <command> <server-address>...

Account commands, for encrypted filesystems:
  enrol <CODE>         set up this account with the one-time code an
                       administrator issued (`raft5fs-server user enrol`),
                       choosing its password. Makes the account's key
                       pair and prints its fingerprint.
  passwd               change this account's password. Everything shared
                       with the account stays readable.

Sharing commands. A <PATH> starts with an entry of your root -- what a
mount shows at its top -- and goes on below it: `photos/2024`.
  grant <PATH> <USER> [--ro] [--name <NAME>]
                       give USER the directory at PATH and everything
                       under it, read-write unless --ro. It shows up in
                       their root as NAME (by default, PATH's last part).
                       Prints the fingerprint of the key it was sealed
                       to: check it with USER, who saw it when enrolling.

Passwords are asked for on the terminal, or read from RAFT5FS_PASSWORD
(the current password, or for enrol the new one) and RAFT5FS_NEW_PASSWORD
(passwd's new one).

  --user <NAME>        the account.
  --ca <PEM>           reach the servers over TLS, trusting certificates
                       that chain to this (and nothing else).
  --tls-server-name <NAME>
                       check the servers' certificates against this name
                       instead of the host in each address.";

fn usage(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(1);
}

fn fail(why: impl std::fmt::Display) -> ! {
    eprintln!("{why}");
    std::process::exit(1);
}

/// A new password: from `var`, or asked for twice on the terminal.
fn new_password(var: &str, username: &str) -> String {
    if let Ok(password) = env::var(var) {
        return password;
    }
    let read = |prompt: &str| {
        cli::prompt_password(prompt)
            .unwrap_or_else(|e| fail(format!("cannot read a password: {e}")))
    };
    let first = read(&format!("new password for {username}: "));
    if first.is_empty() {
        fail("the password can't be empty");
    }
    if read("again: ") != first {
        fail("the passwords didn't match");
    }
    first
}

/// Logs in to an encrypted filesystem and opens the account's keys.
fn log_in(
    runtime: &Runtime,
    username: &str,
    servers: &[String],
    tls: Option<tonic::transport::ClientTlsConfig>,
) -> Vault {
    let password = cli::password_from("RAFT5FS_PASSWORD", &format!("password for {username}: "))
        .unwrap_or_else(|e| fail(format!("cannot read a password: {e}")));
    let credentials = Credentials {
        username: username.to_string(),
        password,
    };
    let remote = runtime
        .block_on(Remote::connect(servers, credentials, tls))
        .unwrap_or_else(|e| fail(format!("cannot log in: {e}")));
    Vault::new(Arc::new(remote)).unwrap_or_else(|e| fail(e))
}

fn main() {
    let mut username = None;
    let mut ca = None;
    let mut server_name = None;
    let mut read_only = false;
    let mut label = None;
    let mut positional = Vec::new();
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
            "--ro" => read_only = true,
            "--name" => label = Some(value("--name")),
            flag if flag.starts_with("--") => usage(&format!("unknown option {flag}")),
            _ => positional.push(arg),
        }
    }
    let username = username.unwrap_or_else(|| usage("--user is required"));
    if positional.is_empty() {
        usage("which command?");
    }
    let command = positional.remove(0);
    let tls = ca.map(|path| cli::tls(&path, server_name.as_deref()).unwrap_or_else(|e| fail(e)));
    if tls.is_none() && server_name.is_some() {
        usage("--tls-server-name needs --ca");
    }

    let runtime = Runtime::new().expect("failed to start tokio runtime");
    match command.as_str() {
        "enrol" => {
            if positional.is_empty() {
                usage("enrol needs the code");
            }
            let code = positional.remove(0);
            if positional.is_empty() {
                usage("at least one server address is required");
            }
            let password = new_password("RAFT5FS_PASSWORD", &username);
            let public_key = runtime
                .block_on(Remote::enrol(
                    &positional,
                    tls,
                    &username,
                    &code,
                    &password,
                    KdfParams::DEFAULT,
                ))
                .unwrap_or_else(|e| fail(format!("cannot enrol: {e}")));
            println!("enrolled {username}");
            println!("key fingerprint: {}", fingerprint(&public_key));
        }
        "passwd" => {
            if positional.is_empty() {
                usage("at least one server address is required");
            }
            let password = cli::password_from(
                "RAFT5FS_PASSWORD",
                &format!("current password for {username}: "),
            )
            .unwrap_or_else(|e| fail(format!("cannot read a password: {e}")));
            let credentials = Credentials {
                username: username.clone(),
                password,
            };
            let remote = runtime
                .block_on(Remote::connect(&positional, credentials, tls))
                .unwrap_or_else(|e| fail(format!("cannot log in: {e}")));
            let new = new_password("RAFT5FS_NEW_PASSWORD", &username);
            runtime
                .block_on(remote.change_password(&new, KdfParams::DEFAULT))
                .unwrap_or_else(|e| fail(format!("cannot change the password: {e}")));
            println!("password changed");
        }
        "grant" => {
            if positional.len() < 3 {
                usage("grant needs a path, a user, and at least one server address");
            }
            let path = positional.remove(0);
            let grantee = positional.remove(0);
            let label = label.unwrap_or_else(|| {
                path.trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_string()
            });
            let vault = log_in(&runtime, &username, &positional, tls);
            let public_key = runtime
                .block_on(async {
                    let ino = vault.resolve(&path).await?;
                    vault
                        .grant(ino, &grantee, !read_only, OsStr::new(&label))
                        .await
                })
                .unwrap_or_else(|e| fail(format!("cannot grant {path}: {e}")));
            println!(
                "granted {path} to {grantee} {} as {label:?}",
                if read_only { "read-only" } else { "read-write" }
            );
            println!("sealed to key fingerprint: {}", fingerprint(&public_key));
        }
        other => usage(&format!("unknown command {other:?}")),
    }
}
