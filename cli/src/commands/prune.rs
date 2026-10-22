//! `raft5fs prune`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Args;
use raft5fs_proto::types::{FsError, Kind};

use super::{ConnectArgs, Outcome, log_in, runtime};
use crate::cli::Context;
use crate::pruner::{describe, prune_entry};
use crate::vault::PruneStats;

/// Seals everything still under an old version of a key again under the
/// current one, then drops the old versions from the key's history. A key
/// gets a new version whenever a share is revoked; what was sealed under
/// the old one stays readable, given the ciphertext, by whoever was
/// revoked, until it is pruned. Revoking queues the directory for it,
/// which a running mount works through in the background.
#[derive(Args)]
#[command(verbatim_doc_comment)]
pub struct PruneArgs {
    /// Directories to prune now, instead of what is queued.
    pub paths: Vec<String>,
    /// Prune everything shared with this account writably, now.
    #[arg(long, conflicts_with = "paths")]
    pub all: bool,
    /// With paths or --all: count what would be done, changing nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Show what is queued, and how each prune is going; changes nothing.
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

/// How long ago `since` (seconds since the epoch) was, roughly.
fn ago(since: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let secs = now.saturating_sub(since);
    match secs {
        0..120 => format!("{secs}s"),
        120..7200 => format!("{}m", secs / 60),
        7200..172800 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86400),
    }
}

pub fn run(connect: &ConnectArgs, args: PruneArgs) -> Outcome {
    if args.dry_run && args.paths.is_empty() && !args.all {
        return Err("--dry-run is for paths or --all; what is queued is pruned for real".into());
    }
    let ctx = Context::resolve(&connect.overrides(), !args.status)?;
    let queue = ctx.prune_queue();
    if args.status {
        let entries = queue.entries().map_err(|e| e.to_string())?;
        if entries.is_empty() {
            println!("nothing queued for pruning");
            return Ok(0);
        }
        let statuses = queue.statuses().map_err(|e| e.to_string())?;
        for entry in entries {
            let status = statuses.get(&entry.ino).map_or("waiting", String::as_str);
            let note = if entry.note.is_empty() {
                format!("inode {}", entry.ino)
            } else {
                entry.note.clone()
            };
            println!("{note}: queued {} ago; {status}", ago(entry.since));
        }
        return Ok(0);
    }

    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let mut skipped = false;
    if args.paths.is_empty() && !args.all {
        let entries = queue.entries().map_err(|e| e.to_string())?;
        if entries.is_empty() {
            println!("nothing queued for pruning");
        }
        for entry in entries {
            let what = if entry.note.is_empty() {
                format!("inode {}", entry.ino)
            } else {
                entry.note.clone()
            };
            let stats = runtime.block_on(prune_entry(&vault, &queue, entry.ino, Duration::ZERO));
            report(&what, &stats, false);
            skipped |= !stats.skipped.is_empty();
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
        // Done by hand: no need for it to stay queued.
        if !args.dry_run && stats.skipped.is_empty() {
            let _ = queue.remove(ino);
        }
    }
    Ok(if skipped { 2 } else { 0 })
}
