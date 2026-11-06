//! What files were, and who changed them: `versions`, from the snapshots,
//! and `activity`, from the servers' log.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use raft5fs_client::versions;
use raft5fs_proto::errno;
use raft5fs_proto::types::{Attr, FsError, Kind};

use super::{ConnectArgs, Outcome, log_in, runtime};
use raft5fs_client::cli::Context;

#[derive(Args)]
pub struct PathArgs {
    /// A path from the root, as a mount shows it.
    pub path: String,
}

/// `t` as a date and time in UTC, such as `2026-11-05 14:03 UTC`.
fn utc(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn described(attr: &Attr) -> String {
    match attr.kind {
        Kind::File => format!("edited {}, {} bytes", utc(attr.mtime), attr.size),
        Kind::Directory => format!("a folder, changed {}", utc(attr.mtime)),
    }
}

#[derive(Args)]
pub struct ActivityArgs {
    /// A folder, from the root, as a mount shows it.
    pub path: String,
    /// Every line the servers keep, not only the newest page.
    #[arg(long)]
    pub all: bool,
}

pub fn activity(connect: &ConnectArgs, args: ActivityArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let failed = |e: FsError| format!("cannot read the activity in {}: {e}", args.path);
    let ino = runtime
        .block_on(vault.resolve(&args.path))
        .map_err(failed)?;
    let mut after = Vec::new();
    let mut any = false;
    loop {
        let page = runtime
            .block_on(vault.activity(ino, &after, 0))
            .map_err(failed)?;
        for line in &page.lines {
            any = true;
            let name = |n: &Option<String>| n.clone().unwrap_or_else(|| "(can't be named)".into());
            let what = match &line.from {
                Some(from) => format!("{from} -> {}", name(&line.name)),
                None => name(&line.name),
            };
            println!(
                "{}\t{}\t{}\t{what}",
                utc(UNIX_EPOCH + std::time::Duration::from_millis(line.at_ms)),
                line.user,
                line.change.as_str()
            );
        }
        if page.next.is_empty() {
            break;
        }
        if !args.all {
            println!("(more: --all)");
            break;
        }
        after = page.next;
    }
    if !any {
        println!("nothing has changed there lately");
    }
    Ok(0)
}

pub fn versions(connect: &ConnectArgs, args: PathArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let path = args.path.trim_matches('/').to_string();
    let (now, found, unreadable) = runtime
        .block_on(async {
            let now = match vault.resolve(&path).await {
                Ok(ino) => Some(vault.remote().getattr(ino).await?),
                Err(e) if e.errno == errno::ENOENT => None,
                Err(e) => return Err(e),
            };
            let snapshots = vault.remote().list_snapshots().await?;
            // Each snapshot's vault reads only attributes, so the chunk
            // cache's space only needs to differ between them.
            let space = AtomicU64::new(1);
            let (found, unreadable) = versions::find(snapshots, |name| {
                let snap = vault.at_snapshot(&name, space.fetch_add(1, Ordering::Relaxed));
                let path = path.clone();
                async move {
                    let ino = snap.resolve(&path).await?;
                    snap.remote().getattr(ino).await
                }
            })
            .await;
            Ok::<_, FsError>((now, found, unreadable))
        })
        .map_err(|e| format!("cannot list the versions of {}: {e}", args.path))?;
    match &now {
        Some(attr) => println!("now\t{}", described(attr)),
        None => println!("now\tnothing is at {path}"),
    }
    let shown = versions::collapse(now.as_ref(), found);
    if shown.is_empty() {
        println!("no other versions in the snapshots");
    }
    for v in shown {
        println!(
            "as of {}\t{}\t.snapshot/{}/{path}",
            utc(v.taken),
            described(&v.attr),
            v.snapshot
        );
    }
    if unreadable > 0 {
        eprintln!("{unreadable} snapshots couldn't be read");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn times_show_in_utc() {
        let at = |secs| utc(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01 00:00 UTC");
        assert_eq!(at(1_762_351_380), "2025-11-05 14:03 UTC");
        assert_eq!(at(951_782_400), "2000-02-29 00:00 UTC");
    }
}
