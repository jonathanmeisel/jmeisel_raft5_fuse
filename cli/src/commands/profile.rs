//! `raft5fs profile`.

use std::path::Path;

use clap::Subcommand;
use raft5fs_client::cli::{Profile, ca_id, config_dir, default_known_keys, install_profile};
use raft5fs_client::vault::KnownKeys;
use raft5fs_proto::invite::{der_to_pem, pem_to_der};
use raft5fs_proto::link::Link;

use super::Outcome;

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// List the profiles.
    List,
    /// Show a profile (by default, the only one).
    Show { name: Option<String> },
    /// Print a profile as one line, to set up another device for this
    /// account with `raft5fs profile import`: the servers, their CA, and the
    /// keys you have pinned. Nothing in it is secret, but it decides whom
    /// the other device trusts: move it yourself.
    Export { name: Option<String> },
    /// Make a profile from a line that `raft5fs profile export` printed on
    /// another device. You log in with your usual password.
    Import {
        line: String,
        /// The profile's name (by default, the account's).
        #[arg(long)]
        name: Option<String>,
    },
}

/// Profile `name`, or else the only one there is.
fn chosen(names: &[String], name: Option<String>) -> Result<String, String> {
    match name {
        Some(name) => Ok(name),
        None if names.len() == 1 => Ok(names[0].clone()),
        None if names.is_empty() => Err("no profiles yet: `raft5fs enrol` makes one".to_string()),
        None => Err(format!("which profile? ({})", names.join(", "))),
    }
}

fn export(base: &Path, name: &str) -> Result<String, String> {
    let profile = Profile::load(base, name)?;
    let ca_path = profile
        .ca
        .as_ref()
        .ok_or("this profile has no CA certificate (plaintext), so there is nothing to trust")?;
    let pem =
        std::fs::read(ca_path).map_err(|e| format!("cannot read {}: {e}", ca_path.display()))?;
    let pem_text =
        std::str::from_utf8(&pem).map_err(|_| format!("{} isn't PEM", ca_path.display()))?;
    let ca = pem_to_der(pem_text).map_err(|e| format!("{}: {e}", ca_path.display()))?;
    let pins_path = match profile.known_keys {
        Some(path) => path,
        None => default_known_keys(base, &ca_id(&pem)?),
    };
    let pins = KnownKeys::load(pins_path.clone())
        .map_err(|e| format!("cannot read the known keys in {}: {e}", pins_path.display()))?
        .entries();
    Ok(Link {
        user: profile.user,
        servers: profile.servers,
        tls_server_name: profile.tls_server_name,
        ca,
        pins,
    }
    .encode())
}

fn import(base: &Path, line: &str, name: Option<String>) -> Outcome {
    let link = Link::decode(line)?;
    let name = name.unwrap_or(link.user.clone());
    let pem = der_to_pem(&link.ca);
    let profile = Profile {
        user: link.user.clone(),
        servers: link.servers.clone(),
        tls_server_name: link.tls_server_name.clone(),
        ..Profile::default()
    };
    let saved = install_profile(base, &name, profile, Some(pem.as_bytes()))
        .map_err(|e| format!("{e} (--name)"))?;
    println!(
        "saved profile {name} for {} ({})",
        link.user,
        saved.display()
    );

    // Pins go where every command for this filesystem looks for them.
    let pins_path = default_known_keys(base, &ca_id(pem.as_bytes())?);
    let pins = KnownKeys::load(pins_path.clone())
        .map_err(|e| format!("cannot read the known keys in {}: {e}", pins_path.display()))?;
    // A pin already here wins: this device's own trust is not replaced.
    let mut status = 0;
    let mut pinned = 0;
    for (user, key) in &link.pins {
        match pins.pinned(user) {
            Some(here) if here != *key => {
                eprintln!(
                    "kept the key this device already pins for {user}, not the link's; if theirs \
                     changed, check their fingerprint with them, then `raft5fs forget-key {user}` \
                     and `raft5fs trust {user} <fingerprint>`"
                );
                status = 1;
            }
            _ => {
                pins.check(user, key).map_err(|e| e.message)?;
                pinned += 1;
            }
        }
    }
    println!(
        "pinned {pinned} of the link's {} keys for other users",
        link.pins.len()
    );
    println!("next: raft5fs mount <MOUNTPOINT>, or raft5fs webdav");
    Ok(status)
}

pub fn run(command: ProfileCommand) -> Outcome {
    let base = config_dir();
    let names = Profile::list(&base).map_err(|e| format!("cannot list profiles: {e}"))?;
    match command {
        ProfileCommand::Export { name } => {
            println!("{}", export(&base, &chosen(&names, name)?)?);
        }
        ProfileCommand::Import { line, name } => return import(&base, &line, name),
        ProfileCommand::List => {
            if names.is_empty() {
                println!("no profiles yet: `raft5fs enrol` makes one");
            }
            for name in &names {
                let profile = Profile::load(&base, name)?;
                let default = if names.len() == 1 {
                    " (used by default)"
                } else {
                    ""
                };
                println!(
                    "{name}: {} at {}{default}",
                    profile.user,
                    profile.servers.join(", ")
                );
            }
        }
        ProfileCommand::Show { name } => {
            let name = chosen(&names, name)?;
            let path = Profile::path(&base, &name);
            let profile = Profile::load(&base, &name)?;
            println!("# {}", path.display());
            print!("{}", toml::to_string(&profile).map_err(|e| e.to_string())?);
        }
    }
    Ok(0)
}
