//! `raft5fs folder size` and `folder limit`: how much a folder holds, and
//! a cap on it.

use clap::{Args, Subcommand};
use raft5fs_client::cli::Context;
use raft5fs_proto::types::size_text;

use super::{ConnectArgs, Outcome, SizeLimit, log_in, parse_size_limit, runtime};

#[derive(Subcommand)]
pub enum FolderCommand {
    /// Show how much a folder holds, as last measured (every few minutes),
    /// and its size limit.
    Size(PathArg),
    /// Cap how much a folder may hold, everything inside it counted, as the
    /// owner of its volume or an admin. Writes that would go over it are
    /// refused, whoever writes, the owner too.
    Limit(LimitArgs),
}

#[derive(Args)]
pub struct PathArg {
    /// The folder.
    pub path: String,
}

#[derive(Args)]
pub struct LimitArgs {
    /// The folder.
    pub path: String,
    /// Such as 5G (K, M, G, T: powers of 1024), or `none` for no limit.
    #[arg(value_name = "SIZE|none", value_parser = parse_size_limit)]
    pub limit: SizeLimit,
}

pub fn run(connect: &ConnectArgs, command: FolderCommand) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    match command {
        FolderCommand::Size(args) => {
            let size = runtime
                .block_on(async {
                    let ino = vault.resolve(&args.path).await?;
                    vault.remote().folder_sizes(&[ino]).await
                })
                .map_err(|e| format!("cannot get the size of {}: {e}", args.path))?
                .pop();
            match &size {
                Some(s) if s.measured_at > 0 => {
                    println!("{} in {} files", size_text(s.bytes), s.files)
                }
                _ => println!("not measured yet"),
            }
            if let Some(limit) = size.and_then(|s| s.limit) {
                println!("size limit: {}", size_text(limit));
            }
        }
        FolderCommand::Limit(args) => {
            let SizeLimit(limit) = args.limit;
            runtime
                .block_on(async {
                    let ino = vault.resolve(&args.path).await?;
                    vault.remote().set_folder_limit(ino, limit).await
                })
                .map_err(|e| format!("cannot set the size limit of {}: {e}", args.path))?;
            match limit {
                Some(limit) => println!("{} may now hold {}", args.path, size_text(limit)),
                None => println!("{} has no size limit now", args.path),
            }
        }
    }
    Ok(0)
}
