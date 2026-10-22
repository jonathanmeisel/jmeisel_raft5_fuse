//! `raft5fs profile`.

use clap::Subcommand;

use super::Outcome;
use raft5fs_client::cli::{Profile, config_dir};

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// List the profiles.
    List,
    /// Show a profile (by default, the only one).
    Show { name: Option<String> },
}

pub fn run(command: ProfileCommand) -> Outcome {
    let base = config_dir();
    let names = Profile::list(&base).map_err(|e| format!("cannot list profiles: {e}"))?;
    match command {
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
            let name = match name {
                Some(name) => name,
                None if names.len() == 1 => names[0].clone(),
                None => return Err(format!("which profile? ({})", names.join(", "))),
            };
            let path = Profile::path(&base, &name);
            let profile = Profile::load(&base, &name)?;
            println!("# {}", path.display());
            print!("{}", toml::to_string(&profile).map_err(|e| e.to_string())?);
        }
    }
    Ok(0)
}
