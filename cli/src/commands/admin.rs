//! `raft5fs admin`: user management, for accounts with the `admin`
//! capability. Backups, restores and snapshots stay with the servers' own
//! tools (`raft5fs-admin`).

use clap::{Args, Subcommand, ValueEnum};
use raft5fs_client::cli::Context;
use raft5fs_proto::types::{AccountKind, Caps};

use super::account::caps_text;
use super::{ConnectArgs, Outcome, log_in, runtime};

#[derive(Subcommand)]
pub enum AdminCommand {
    /// List every user, invitation not used yet, and public link, with
    /// what each may do.
    Users,
    /// Invite a new user. Prints an invitation, for them alone.
    Invite(InviteArgs),
    /// Change what a user may do.
    Set(SetArgs),
    /// Let a user enroll again, after they forgot their password. Prints
    /// a new invitation, for them alone.
    Reenroll(ConfirmArg),
    /// Remove a user (or an invitation, or a public link) and every share
    /// made to them.
    Delete(ConfirmArg),
    /// List folders and files that no account can reach any more (their
    /// account was removed, or enrolled again), or delete one.
    Unreachable(UnreachableArgs),
}

#[derive(Args)]
pub struct ConfirmArg {
    #[arg(value_name = "USER")]
    pub name: String,
    /// Go ahead even though it leaves folders that nobody can reach.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct UnreachableArgs {
    /// Delete this one (an inode from the list), with everything in it.
    #[arg(long, value_name = "INODE")]
    pub delete: Option<u64>,
}

#[derive(Args)]
pub struct InviteArgs {
    /// The new user's account name. It must not exist yet.
    #[arg(value_name = "USER")]
    pub name: String,
    /// Let them make top-level folders (volumes) of their own.
    #[arg(long)]
    pub volumes: bool,
    /// Let them make public links.
    #[arg(long)]
    pub links: bool,
    /// Let them manage users, as you do.
    #[arg(long)]
    pub admin: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

#[derive(Args)]
pub struct SetArgs {
    #[arg(value_name = "USER")]
    pub name: String,
    #[arg(long, value_name = "on|off")]
    pub volumes: Option<Switch>,
    #[arg(long, value_name = "on|off")]
    pub links: Option<Switch>,
    #[arg(long, value_name = "on|off")]
    pub admin: Option<Switch>,
}

#[derive(Args)]
pub struct NameArg {
    #[arg(value_name = "USER")]
    pub name: String,
}

pub fn run(connect: &ConnectArgs, command: AdminCommand) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let remote = vault.remote();
    match command {
        AdminCommand::Users => {
            let mut users = runtime
                .block_on(remote.list_users())
                .map_err(|e| format!("cannot list users: {e}"))?;
            users.sort_by(|a, b| a.user.cmp(&b.user));
            for u in users {
                let state = if u.enrolled { "enrolled" } else { "invited" };
                let what = match u.info.kind {
                    AccountKind::Link => format!("public link made by {}", u.info.owner),
                    AccountKind::Person => caps_text(u.info.caps),
                };
                println!("{}\t{state}\t{what}", u.user);
            }
        }
        AdminCommand::Invite(args) => {
            let mut caps = Caps::NONE;
            for (on, cap) in [
                (args.volumes, Caps::VOLUMES),
                (args.links, Caps::LINKS),
                (args.admin, Caps::ADMIN),
            ] {
                caps = caps.with(cap, on);
            }
            let issued = runtime
                .block_on(remote.issue_invite(&args.name, caps))
                .map_err(|e| format!("cannot invite {}: {e}", args.name))?;
            print_invitation(&args.name, issued);
            println!("they can: {}", caps_text(caps));
        }
        AdminCommand::Set(args) => {
            let (mut on, mut off) = (Caps::NONE, Caps::NONE);
            for (switch, cap) in [
                (args.volumes, Caps::VOLUMES),
                (args.links, Caps::LINKS),
                (args.admin, Caps::ADMIN),
            ] {
                match switch {
                    Some(Switch::On) => on = on | cap,
                    Some(Switch::Off) => off = off | cap,
                    None => {}
                }
            }
            if on == Caps::NONE && off == Caps::NONE {
                return Err("give --volumes, --links or --admin, each on or off".to_string());
            }
            let info = runtime
                .block_on(remote.set_capabilities(&args.name, on, off))
                .map_err(|e| format!("cannot change {}: {e}", args.name))?;
            println!("{} can now: {}", args.name, caps_text(info.caps));
        }
        AdminCommand::Reenroll(args) => {
            check_impact(&runtime, remote, &args, "letting them enroll again")?;
            let issued = runtime
                .block_on(remote.reissue_invite(&args.name))
                .map_err(|e| format!("cannot let {} enroll again: {e}", args.name))?;
            print_invitation(&args.name, issued);
            println!(
                "enrolling with it gives {} a new key: what was shared with them must be shared \
                 again, and those who share with them are told their key changed",
                args.name
            );
        }
        AdminCommand::Delete(args) => {
            check_impact(&runtime, remote, &args, "removing them")?;
            runtime
                .block_on(remote.delete_user(&args.name))
                .map_err(|e| format!("cannot remove {}: {e}", args.name))?;
            println!("removed {} and every share made to them", args.name);
        }
        AdminCommand::Unreachable(args) => match args.delete {
            Some(ino) => {
                runtime
                    .block_on(remote.delete_unreachable(ino))
                    .map_err(|e| format!("cannot delete inode {ino}: {e}"))?;
                println!("deleted inode {ino} and everything in it");
            }
            None => {
                let found = runtime
                    .block_on(remote.list_unreachable())
                    .map_err(|e| format!("cannot list unreachable folders: {e}"))?;
                if found.is_empty() {
                    println!("every folder and file is reachable by some account");
                }
                for u in &found {
                    println!("{}\t{}", u.ino, describe(u));
                }
                if !found.is_empty() {
                    println!("(raft5fs admin unreachable --delete <INODE> deletes one, for good)");
                }
            }
        },
    }
    Ok(0)
}

/// Refuses to go on, unless `--yes`, when `doing` to the user would leave
/// folders that nobody can reach, and says what they hold.
fn check_impact(
    runtime: &tokio::runtime::Runtime,
    remote: &raft5fs_client::remote::Remote,
    args: &ConfirmArg,
    doing: &str,
) -> Result<(), String> {
    let lost = runtime
        .block_on(remote.removal_impact(&args.name))
        .map_err(|e| format!("cannot tell what {doing} would leave: {e}"))?;
    if lost.is_empty() || args.yes {
        return Ok(());
    }
    let mut why = format!(
        "{doing} leaves what only {} can reach now, which nobody could then open:",
        args.name
    );
    for u in &lost {
        why.push_str(&format!("\n  {}", describe(u)));
    }
    why.push_str("\ngive --yes to go ahead; `raft5fs admin unreachable` can delete it later");
    Err(why)
}

/// What an unreachable part holds, as people read it.
fn describe(u: &raft5fs_proto::types::Unreachable) -> String {
    let what = if u.volume {
        "a top-level folder"
    } else if u.folders > 0 {
        "a folder"
    } else {
        "a file"
    };
    let days = std::time::SystemTime::now()
        .duration_since(u.modified)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    format!(
        "{what}: {} files, {} folders, {}, last changed {days} days ago",
        u.files,
        u.folders,
        size(u.bytes)
    )
}

fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{b} bytes"),
    }
}

fn print_invitation(name: &str, (code, invitation): (String, Option<String>)) {
    match invitation {
        Some(invitation) => {
            println!("invitation for {name} (as secret as a password -- for {name} alone):");
            println!("{invitation}");
            println!(
                "(they run `raft5fs enrol '<invitation>'`, or paste it into the web app's \
                 enroll screen)"
            );
        }
        None => {
            println!("enrollment code for {name} (as secret as a password): {code}");
            println!("(the servers don't say how to reach them; give {name} the addresses too)");
        }
    }
}
