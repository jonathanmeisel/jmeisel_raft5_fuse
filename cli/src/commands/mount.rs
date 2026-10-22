//! `raft5fs mount`.

use std::path::PathBuf;

use clap::Args;
use fuser::{Config, MountOption};
use raft5fs_client::cli::Context;
use raft5fs_fuse::filesystem::Raft5Fs;

use super::{ConnectArgs, Outcome, SessionArgs, runtime};

#[derive(Args)]
pub struct MountArgs {
    /// Where to mount it. Only the local user who mounts it can use it,
    /// because everything done there is done as the account.
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
    // Use neither `default_permissions` nor `allow_other`. The servers
    // check every request against the mount's one identity, so a kernel
    // check of the local caller would only get in the way. Letting other
    // local users in would give them that identity.
    options.mount_options = vec![MountOption::FSName("raft5fs".to_string())];
    // Writes commit synchronously. `fuser` sends requests from a single
    // thread by default, so without this, one file's slow commit would stop
    // every other fuse request on the mount.
    options.n_threads = Some(8);

    // If the connection or the login failed, `init` already printed why.
    fuser::mount(fs, &args.mountpoint, &options)
        .map_err(|e| format!("cannot mount {}: {e}", args.mountpoint.display()))?;
    Ok(0)
}
