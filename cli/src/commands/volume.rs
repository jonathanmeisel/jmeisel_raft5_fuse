//! `raft5fs volume`: give a volume (a top-level folder) to another user,
//! and answer such offers. A volume's owner is who its size counts
//! against, and always has read-write access to it.

use std::ffi::OsStr;

use clap::{Args, Subcommand};
use raft5fs_client::cli::Context;
use raft5fs_proto::types::{FsError, size_text};

use super::{ConnectArgs, Outcome, log_in, runtime};

#[derive(Subcommand)]
pub enum VolumeCommand {
    /// Show who owns a volume, and any offer of it.
    Owner(PathArg),
    /// Offer a volume you own to another user. It is theirs once they
    /// accept; you keep your share until they revoke it. Shares it with
    /// them read-write first if needed (their key must be pinned).
    Transfer(TransferArgs),
    /// List the offers made to you, and by you.
    Offers,
    /// Accept a volume offered to you. Its size then counts against you.
    Accept(PathArg),
    /// Decline a volume offered to you.
    Decline(PathArg),
    /// Withdraw your offer of a volume.
    Withdraw(PathArg),
    /// Show whether a volume is indexed for search, or, as its owner, turn
    /// that on or off for everyone.
    Indexing(IndexingArgs),
}

#[derive(Args)]
pub struct IndexingArgs {
    /// The volume, as your root shows it.
    pub path: String,
    /// `on` or `off`; leave out to show which.
    #[arg(value_parser = ["on", "off"])]
    pub state: Option<String>,
    /// With `off`: also remove the index the volume has, to free its space.
    #[arg(long)]
    pub delete_index: bool,
}

#[derive(Args)]
pub struct PathArg {
    /// The volume, as your root shows it.
    pub path: String,
}

#[derive(Args)]
pub struct TransferArgs {
    /// The volume, as your root shows it.
    pub path: String,
    /// Who to give it to.
    #[arg(value_name = "USER")]
    pub to: String,
}

pub fn run(connect: &ConnectArgs, command: VolumeCommand) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let remote = vault.remote();
    let volume = |path: &str| -> Result<u64, String> {
        let path = path.trim_matches('/');
        if path.contains('/') {
            return Err(format!("{path} isn't a volume: a top-level folder is"));
        }
        runtime
            .block_on(vault.resolve(path))
            .map_err(|e| format!("cannot find {path}: {e}"))
    };
    match command {
        VolumeCommand::Owner(args) => {
            let ino = volume(&args.path)?;
            let info = runtime
                .block_on(remote.get_volume(ino))
                .map_err(|e| format!("cannot tell who owns {}: {e}", args.path))?;
            println!("owner: {}", info.owner.as_deref().unwrap_or("nobody"));
            if let Some((to, _)) = info.offer {
                println!("offered to: {to}");
            }
        }
        VolumeCommand::Transfer(args) => {
            let ino = volume(&args.path)?;
            runtime
                .block_on(async {
                    let writes = vault
                        .grantees(ino)
                        .await?
                        .iter()
                        .any(|g| g.user == args.to && g.writable);
                    if !writes {
                        if vault.known_keys().pinned(&args.to).is_none() {
                            return Err(FsError::new(
                                libc::EPERM,
                                format!(
                                    "{to} needs read-write access first: \
                                     `raft5fs grant {path} {to} --fingerprint ...`",
                                    to = args.to,
                                    path = args.path
                                ),
                            ));
                        }
                        vault
                            .grant(ino, &args.to, true, OsStr::new(args.path.trim_matches('/')))
                            .await?;
                    }
                    remote.offer_volume(ino, &args.to).await
                })
                .map_err(|e| format!("cannot offer {} to {}: {e}", args.path, args.to))?;
            println!(
                "offered {} to {}: it is theirs once they accept it",
                args.path, args.to
            );
        }
        VolumeCommand::Offers => {
            let (offers, roots) = runtime
                .block_on(async {
                    Ok::<_, FsError>((remote.offers().await?, vault.grant_paths().await?))
                })
                .map_err(|e| format!("cannot list offers: {e}"))?;
            let names = roots;
            if offers.is_empty() {
                println!("no offers");
            }
            for o in offers {
                let name = names
                    .get(&o.volume)
                    .cloned()
                    .unwrap_or_else(|| format!("volume {}", o.volume));
                println!(
                    "{name}\tfrom {}\tto {}\t{}",
                    o.from,
                    o.to,
                    size_text(o.bytes)
                );
            }
        }
        VolumeCommand::Accept(args) => {
            let ino = volume(&args.path)?;
            runtime
                .block_on(remote.answer_offer(ino, true))
                .map_err(|e| format!("cannot accept {}: {e}", args.path))?;
            println!("{} is yours now", args.path);
        }
        VolumeCommand::Decline(args) => {
            let ino = volume(&args.path)?;
            runtime
                .block_on(remote.answer_offer(ino, false))
                .map_err(|e| format!("cannot decline {}: {e}", args.path))?;
            println!("declined {}", args.path);
        }
        VolumeCommand::Indexing(args) => {
            let ino = volume(&args.path)?;
            let Some(state) = args.state.as_deref() else {
                let info = runtime
                    .block_on(remote.get_volume(ino))
                    .map_err(|e| format!("cannot read {}: {e}", args.path))?;
                let shown = if info.indexing_off { "off" } else { "on" };
                println!("search indexing of {}: {shown}", args.path);
                return Ok(0);
            };
            if args.delete_index && state != "off" {
                return Err("--delete-index is for turning indexing off".into());
            }
            runtime
                .block_on(remote.set_volume_indexing(ino, state == "on"))
                .map_err(|e| format!("cannot turn indexing of {} {state}: {e}", args.path))?;
            println!("search indexing of {} is {state}, for everyone", args.path);
            if args.delete_index {
                let freed = runtime
                    .block_on(raft5fs_client::indexer::delete_index(&vault, ino))
                    .map_err(|e| format!("cannot remove the index of {}: {e}", args.path))?;
                println!("removed its index ({})", size_text(freed));
            } else if state == "off" {
                println!("its index stays until you give --delete-index");
            }
        }
        VolumeCommand::Withdraw(args) => {
            let ino = volume(&args.path)?;
            runtime
                .block_on(remote.withdraw_offer(ino))
                .map_err(|e| format!("cannot withdraw the offer of {}: {e}", args.path))?;
            println!("withdrew the offer of {}", args.path);
        }
    }
    Ok(0)
}
