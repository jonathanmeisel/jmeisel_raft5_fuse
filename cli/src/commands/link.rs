//! `raft5fs link create` and `link list`: public links, which let anyone
//! with the URL read one directory. Revoking one is `raft5fs revoke`, as
//! for a person.

use std::ffi::OsStr;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use raft5fs_client::cli::Context;
use raft5fs_proto::public_link::PublicLink;

use super::{ConnectArgs, Outcome, log_in, runtime};

#[derive(Subcommand)]
pub enum LinkCommand {
    /// Make a public link to a directory. Anyone with the link can read
    /// the directory, until it expires or anyone who can write the
    /// directory revokes it (`raft5fs revoke <PATH> <LINK-NAME>`).
    Create(CreateArgs),
    /// List the links you made, with each link while you can still
    /// change its directory.
    List,
}

#[derive(Args)]
pub struct CreateArgs {
    /// The directory.
    pub path: String,
    /// When the link stops working: a number of days, hours or minutes,
    /// such as 7d, 12h or 30m. By default it never does.
    #[arg(long)]
    pub expires: Option<String>,
    /// The name the directory shows under for visitors (by default, the
    /// last part of the path).
    #[arg(long)]
    pub name: Option<String>,
    /// The web app's address, such as https://files.example.com, to print
    /// the whole link. Without it, only the part after the address.
    #[arg(long)]
    pub app: Option<String>,
}

pub fn run(connect: &ConnectArgs, command: LinkCommand) -> Outcome {
    match command {
        LinkCommand::Create(args) => create(connect, args),
        LinkCommand::List => list(connect),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Seconds in a span such as `7d`, `12h` or `30m`.
fn parse_span(span: &str) -> Result<u64, String> {
    let bad = || format!("{span:?} isn't a span such as 7d, 12h or 30m");
    let (digits, unit) = span.split_at(span.len().saturating_sub(1));
    let unit = match unit {
        "d" => 86_400,
        "h" => 3_600,
        "m" => 60,
        _ => return Err(bad()),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(bad());
    }
    n.checked_mul(unit).ok_or_else(bad)
}

/// How long until `at`, roughly, as people say it.
fn until(at: u64) -> String {
    let left = at.saturating_sub(now());
    match left {
        0 => "expired".to_string(),
        s if s < 3_600 => format!("expires in {} min", s.div_ceil(60)),
        s if s < 2 * 86_400 => format!("expires in {} h", s.div_ceil(3_600)),
        s => format!("expires in {} days", s / 86_400),
    }
}

fn create(connect: &ConnectArgs, args: CreateArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let fs_id = ctx
        .ca_id
        .clone()
        .ok_or("a public link names the filesystem by its CA: give --ca")?;
    let expires = match &args.expires {
        Some(span) => Some(now() + parse_span(span)?),
        None => None,
    };
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
    let (user, secret) = runtime
        .block_on(async {
            let ino = vault.resolve(&args.path).await?;
            vault
                .create_link(ino, &args.path, OsStr::new(&label), expires)
                .await
        })
        .map_err(|e| format!("cannot make a link to {}: {e}", args.path))?;
    let fragment = fragment(&fs_id, &user, secret);
    println!("public link {user} to {}, read-only:", args.path);
    match &args.app {
        Some(app) => println!("{}/{fragment}", app.trim_end_matches('/')),
        None => {
            println!("{fragment}");
            println!("(put the web app's address in front, or give --app)");
        }
    }
    println!(
        "anyone with it can read {} until {}; `raft5fs link list` shows it again. To revoke \
         it: raft5fs revoke {} {user}",
        args.path,
        match expires {
            Some(at) => until(at).replace("expires in", "it expires in"),
            None => "you revoke it".to_string(),
        },
        args.path,
    );
    Ok(0)
}

fn list(connect: &ConnectArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let links = runtime
        .block_on(vault.links())
        .map_err(|e| format!("cannot list links: {e}"))?;
    if links.is_empty() {
        println!("no public links");
    }
    for (link, path) in links {
        let expiry = link
            .info
            .expires
            .map_or_else(|| "never expires".to_string(), until);
        println!(
            "{}\t{}\t{expiry}",
            link.user,
            path.as_deref().unwrap_or("(unknown folder)")
        );
        // The secret is in the folder's sealed grantee list, which only
        // those who can change the folder get.
        let secret = runtime
            .block_on(vault.grantees_with_links(link.info.folder))
            .ok()
            .and_then(|(_, mut secrets)| secrets.remove(&link.user));
        if let (Some(secret), Some(fs_id)) = (secret, &ctx.ca_id) {
            println!("  {}", fragment(fs_id, &link.user, secret));
        }
    }
    Ok(0)
}

/// What goes after the web app's address for a link.
pub fn fragment(fs_id: &str, user: &str, secret: String) -> String {
    let link = PublicLink {
        fs_id: fs_id.to_string(),
        user: user.to_string(),
        secret,
    };
    format!("#link={}", link.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_parse() {
        assert_eq!(parse_span("7d"), Ok(7 * 86_400));
        assert_eq!(parse_span("12h"), Ok(12 * 3_600));
        assert_eq!(parse_span("30m"), Ok(1_800));
        for bad in ["", "d", "0d", "7", "7w", "-1d", "x7d"] {
            assert!(parse_span(bad).is_err(), "{bad}");
        }
    }
}
