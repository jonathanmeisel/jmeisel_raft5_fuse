//! `raft5fs prune`.

use clap::Args;
use raft5fs_proto::types::{FsError, Kind};

use super::{ConnectArgs, Outcome, log_in, runtime};
use raft5fs_client::cli::Context;
use raft5fs_client::pruner::{PrunerConfig, describe, new_holder, prune_claimed};
use raft5fs_client::vault::{PruneStats, Vault};
use raft5fs_proto::errno;

/// Seals everything still under an old version of a key again under the
/// current version, then removes the old versions from the key's history. A
/// key gets a new version when a share is revoked. Until a prune, a revoked
/// user who has the ciphertext can still read what was sealed under the old
/// version. The servers list what waits for a prune; any mount, WebDAV
/// server or web app that can write it prunes it in the background.
#[derive(Args)]
#[command(verbatim_doc_comment)]
pub struct PruneArgs {
    /// Directories to prune now, in place of what the servers list.
    pub paths: Vec<String>,
    /// Prune everything shared with this account with write access, now.
    #[arg(long, conflicts_with = "paths")]
    pub all: bool,
    /// With paths or --all: count what would be done, and change nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Show what waits for a prune, and who is pruning it. Changes
    /// nothing.
    #[arg(long, conflicts_with_all = ["paths", "all", "dry_run"])]
    pub status: bool,
}

fn report(what: &str, stats: &PruneStats, dry_run: bool) {
    if dry_run {
        println!(
            "{what} (dry run): {} nodes; would re-seal {} chunks and {} names; would rotate {} \
             stale children; would drop {} old key versions",
            stats.nodes, stats.chunks, stats.names, stats.rotated, stats.dropped
        );
    } else {
        println!("{what}: {}", describe(stats));
    }
    for (ino, e) in &stats.skipped {
        println!("  skipped inode {ino}, and everything under it: {e}");
    }
}

/// About how long from now `ms` (milliseconds since the epoch) is.
fn from_now(ms: u64) -> String {
    let now = raft5fs_proto::clock::now_millis();
    let secs = ms.saturating_sub(now) / 1000;
    match secs {
        0..120 => format!("{secs}s"),
        _ => format!("{}m", secs / 60),
    }
}

/// Where inode `ino` is, for people.
async fn shown(vault: &Vault, ino: u64) -> String {
    match vault.locate(ino).await {
        Ok(Some(path)) => path,
        _ => format!("inode {ino}"),
    }
}

pub fn run(connect: &ConnectArgs, args: PruneArgs) -> Outcome {
    if args.dry_run && args.paths.is_empty() && !args.all {
        return Err("--dry-run is for paths or --all; what is listed is pruned for real".into());
    }
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let mut skipped = false;
    if args.paths.is_empty() && !args.all {
        let waiting = runtime
            .block_on(vault.remote().list_unpruned())
            .map_err(|e| format!("cannot list what waits for a prune: {e}"))?;
        if waiting.is_empty() {
            println!("nothing waits for a prune");
            return Ok(0);
        }
        let holder = new_holder();
        let config = PrunerConfig::default();
        for node in waiting {
            let what = runtime.block_on(shown(&vault, node.ino));
            if args.status {
                match node.claim {
                    Some(c) => println!(
                        "{what}: being pruned by {} (claim ends in {})",
                        c.user,
                        from_now(c.expires_ms)
                    ),
                    None => println!("{what}: waiting"),
                }
                continue;
            }
            let pruned = runtime.block_on(prune_claimed(
                &vault,
                node.ino,
                holder,
                &PrunerConfig {
                    pace: std::time::Duration::ZERO,
                    ..config
                },
                &mut |_| {},
            ));
            match pruned {
                Ok(stats) => {
                    report(&what, &stats, false);
                    skipped |= !stats.skipped.is_empty();
                }
                Err(e) if e.errno == errno::EBUSY => println!("{what}: skipped: {e}"),
                Err(e) => {
                    println!("{what}: {e}");
                    skipped = true;
                }
            }
        }
        return Ok(if skipped { 2 } else { 0 });
    }

    let mut tops = Vec::new();
    if args.all {
        let roots = runtime
            .block_on(vault.grant_roots())
            .map_err(|e| format!("cannot list what is shared with this account: {e}"))?;
        for root in roots {
            let label = root.label.to_string_lossy().into_owned();
            if root.writable {
                tops.push((label, root.ino));
            } else {
                println!("{label}: skipped, shared read-only");
            }
        }
    } else {
        for path in &args.paths {
            let ino = runtime
                .block_on(async {
                    let ino = vault.resolve(path).await?;
                    if vault.remote().getattr(ino).await?.kind != Kind::Directory {
                        return Err(FsError::errno(libc::ENOTDIR));
                    }
                    Ok(ino)
                })
                .map_err(|e| format!("cannot prune {path}: {e}"))?;
            tops.push((path.clone(), ino));
        }
    }
    for (what, ino) in tops {
        let stats = runtime.block_on(vault.prune_tree(ino, args.dry_run));
        report(&what, &stats, args.dry_run);
        skipped |= !stats.skipped.is_empty();
    }
    Ok(if skipped { 2 } else { 0 })
}
