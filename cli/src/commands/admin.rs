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
    Reenroll(NameArg),
    /// Remove a user (or an invitation, or a public link) and every share
    /// made to them.
    Delete(NameArg),
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
            runtime
                .block_on(remote.delete_user(&args.name))
                .map_err(|e| format!("cannot remove {}: {e}", args.name))?;
            println!("removed {} and every share made to them", args.name);
        }
    }
    Ok(0)
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
