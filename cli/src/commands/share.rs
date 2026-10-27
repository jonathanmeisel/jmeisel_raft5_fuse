//! `raft5fs grant`, `revoke`, `grants`, `trust`, `forget-key`, and
//! `pending`. A path starts with an entry of the account's root (what a
//! mount shows at its top) and continues below it, for example
//! `photos/2024`.

use std::ffi::OsStr;

use clap::Args;
use raft5fs_crypto::identity::fingerprint_words;

use super::{ConnectArgs, Outcome, log_in, runtime, show_fingerprint};
use raft5fs_client::cli::Context;
use raft5fs_client::vault::ShareTrust;

#[derive(Args)]
pub struct GrantArgs {
    /// The directory to share.
    pub path: String,
    /// The user to share it with. (Not `user`: that is the name of the
    /// global `--user`, which this would replace.)
    #[arg(value_name = "USER")]
    pub grantee: String,
    /// Read-only: their writes below it fail.
    #[arg(long)]
    pub ro: bool,
    /// Its label in their root (by default, the last part of the path).
    #[arg(long)]
    pub name: Option<String>,
    /// Their key's fingerprint, as they saw it when they enrolled (`raft5fs
    /// whoami` shows it), in words or hex. Needed the first time you share
    /// with them, unless you `trust` them first.
    #[arg(long)]
    pub fingerprint: Option<String>,
}

#[derive(Args)]
pub struct RevokeArgs {
    /// The directory.
    pub path: String,
    /// The user whose share to remove.
    #[arg(value_name = "USER")]
    pub grantee: String,
    /// Do not add the directory to the prune queue (see `raft5fs prune`).
    #[arg(long)]
    pub no_prune: bool,
}

#[derive(Args)]
pub struct PathArg {
    /// The directory.
    pub path: String,
}

#[derive(Args)]
pub struct UserArg {
    /// The user.
    #[arg(value_name = "USER")]
    pub who: String,
}

#[derive(Args)]
pub struct TrustArgs {
    /// The user.
    #[arg(value_name = "USER")]
    pub who: String,
    /// Their key's fingerprint, as they read it to you: the 12 words (no
    /// quotes needed), or the hex.
    #[arg(required = true, num_args = 1..)]
    pub fingerprint: Vec<String>,
}

pub fn grant(connect: &ConnectArgs, args: GrantArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let label = args.name.clone().unwrap_or_else(|| {
        args.path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string()
    });
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let public_key = runtime
        .block_on(async {
            // A first share with a user: trust their key only if the
            // fingerprint matches, never only because the server says so.
            if vault.known_keys().pinned(&args.grantee).is_none() {
                let Some(expected) = &args.fingerprint else {
                    let served = vault.served_key(&args.grantee).await?;
                    return Err(raft5fs_proto::types::FsError::new(
                        libc::EPERM,
                        format!(
                            "{user}'s key isn't pinned yet. The server says its fingerprint is\n\
                             {}\ncheck that with {user} (`raft5fs whoami` shows it to them), \
                             then share again with --fingerprint",
                            show_fingerprint(&served),
                            user = args.grantee,
                        ),
                    ));
                };
                vault.trust(&args.grantee, expected).await?;
            }
            let ino = vault.resolve(&args.path).await?;
            vault
                .grant(ino, &args.grantee, !args.ro, OsStr::new(&label))
                .await
        })
        .map_err(|e| format!("cannot share {}: {e}", args.path))?;
    println!(
        "shared {} with {} {} as {label:?}, sealed to their key:",
        args.path,
        args.grantee,
        if args.ro { "read-only" } else { "read-write" }
    );
    println!("{}", show_fingerprint(&public_key));
    Ok(0)
}

pub fn revoke(connect: &ConnectArgs, args: RevokeArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let ino = runtime
        .block_on(async {
            let ino = vault.resolve(&args.path).await?;
            vault.revoke(ino, &args.grantee).await?;
            Ok::<_, raft5fs_proto::types::FsError>(ino)
        })
        .map_err(|e| {
            format!(
                "cannot revoke {}'s share of {}: {e}",
                args.grantee, args.path
            )
        })?;
    println!("revoked {}'s share of {}", args.grantee, args.path);
    if args.no_prune {
        println!(
            "not queued for pruning: what was written there before stays sealed under keys \
             {} had until `raft5fs prune {}`",
            args.grantee, args.path
        );
        return Ok(0);
    }
    let queue = ctx.prune_queue();
    queue
        .add(ino, &format!("{} (revoked {})", args.path, args.grantee))
        .map_err(|e| format!("revoked, but cannot queue it for pruning: {e}"))?;
    println!(
        "queued for pruning, which a running mount does in the background (or run \
         `raft5fs prune` now). Until it is done, what was written there before is still \
         sealed under keys {} had; `raft5fs prune --status` shows how it is going.",
        args.grantee
    );
    Ok(0)
}

pub fn grants(connect: &ConnectArgs, args: PathArg) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let (grantees, secrets) = runtime
        .block_on(async {
            let ino = vault.resolve(&args.path).await?;
            vault.grantees_with_links(ino).await
        })
        .map_err(|e| format!("cannot list the shares of {}: {e}", args.path))?;
    for g in grantees {
        let key = <[u8; 32]>::try_from(g.public_key.as_slice())
            .map(|k| fingerprint_words(&k))
            .unwrap_or_else(|_| "(no key)".to_string());
        let mode = if g.writable {
            "read-write"
        } else {
            "read-only"
        };
        if g.user.starts_with(raft5fs_proto::types::LINK_PREFIX) {
            let link = match (secrets.get(&g.user), &ctx.ca_id) {
                (Some(secret), Some(fs_id)) => {
                    super::link::fragment(fs_id, &g.user, secret.clone())
                }
                _ => "(revoke it like a user)".to_string(),
            };
            println!("{}\tpublic link\t{link}", g.user);
        } else {
            println!("{}\t{mode}\t{key}", g.user);
        }
    }
    Ok(0)
}

pub fn trust(connect: &ConnectArgs, args: TrustArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let key = runtime
        .block_on(vault.trust(&args.who, &args.fingerprint.join(" ")))
        .map_err(|e| format!("cannot trust {}: {e}", args.who))?;
    println!("pinned {}'s key:", args.who);
    println!("{}", show_fingerprint(&key));
    println!(
        "what {} shares with you is writable now, mounts included",
        args.who
    );
    Ok(0)
}

pub fn forget_key(connect: &ConnectArgs, args: UserArg) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), false)?;
    ctx.known_keys()?
        .forget(&args.who)
        .map_err(|e| format!("cannot forget {}'s key: {e}", args.who))?;
    println!("forgot {}'s pinned key", args.who);
    Ok(0)
}

pub fn pending(connect: &ConnectArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let shares = runtime
        .block_on(vault.shares())
        .map_err(|e| format!("cannot list what is shared with you: {e}"))?;
    let mut any = false;
    for share in shares {
        let label = share.label.to_string_lossy();
        match share.trust {
            ShareTrust::Trusted => continue,
            ShareTrust::Untrusted { key } => {
                println!(
                    "{label}: shared by {}, whose key isn't pinned, so it is read-only. \
                     The server says their fingerprint is",
                    share.sender
                );
                println!("{}", show_fingerprint(&key));
                println!(
                    "  if {} reads you the same, run: raft5fs trust {} {}",
                    share.sender,
                    share.sender,
                    fingerprint_words(&key)
                );
            }
            ShareTrust::Unreadable(e) => {
                println!(
                    "{label}: says it is from {}, but doesn't open: {e}",
                    share.sender
                );
            }
        }
        any = true;
    }
    if !any {
        println!("nothing pending: everything shared with you is from someone trusted");
    }
    Ok(0)
}
