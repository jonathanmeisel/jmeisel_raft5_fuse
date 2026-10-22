//! `raft5fs mount`.

use std::path::PathBuf;

use clap::Args;
use fuser::{Config, MountOption};
use raft5fs_client::cli::Context;
use raft5fs_fuse::filesystem::Raft5Fs;

use super::{ConnectArgs, Outcome, SessionArgs, runtime};

#[derive(Args)]
pub struct MountArgs {
    /// Where to mount it. Only the local user who mounts it can use it:
    /// everything done there is done as the account.
    pub mountpoint: PathBuf,
    #[command(flatten)]
    pub session: SessionArgs,
}

pub fn run(connect: &ConnectArgs, args: MountArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let config = args.session.config(&ctx)?;
    let runtime = runtime();
    let fs = Raft5Fs::with_config(config, runtime.handle().clone());

    let mut options = Config::default();
    // Neither `default_permissions` nor `allow_other`: the servers check
    // every request against the mount's one identity, so the kernel
    // checking the local caller too would only get in the way -- and
    // letting other local users in would hand them that identity.
    options.mount_options = vec![MountOption::FSName("raft5fs".to_string())];
    // Writes commit synchronously, so without this, one file's slow commit
    // would stall every other fuse request on the mount -- `fuser`
    // dispatches from a single thread unless told otherwise.
    options.n_threads = Some(8);

    // `init` has already said why, if it was the connection or the login
    // that failed.
    fuser::mount(fs, &args.mountpoint, &options)
        .map_err(|e| format!("cannot mount {}: {e}", args.mountpoint.display()))?;
    Ok(0)
}
