//! `raft5fs mount`.

use std::path::PathBuf;

use clap::Args;
use fuser::{Config, MountOption};

use super::{ConnectArgs, Outcome, runtime};
use crate::cli::{Context, parse_size, password_from};
use crate::filesystem::Raft5Fs;
use crate::pruner::PrunerConfig;

#[derive(Args)]
pub struct MountArgs {
    /// Where to mount it. Only the local user who mounts it can use it:
    /// everything done there is done as the account.
    pub mountpoint: PathBuf,
    /// Memory for caching file data this machine has read or written,
    /// decrypted: a byte count, or with a K/M suffix (default 64M; 0
    /// disables). A cached chunk is still checked with a server on every
    /// read, at the cost of a few bytes, so it is never stale.
    #[arg(long)]
    pub cache_size: Option<String>,
    /// Store every write at once instead of buffering small sequential
    /// writes until a batch fills, the file is closed, or fsync is called.
    #[arg(long)]
    pub no_write_buffer: bool,
    /// Don't work through this account's prune queue (see `raft5fs prune`)
    /// in the background while mounted.
    #[arg(long)]
    pub no_background_prune: bool,
}

pub fn run(connect: &ConnectArgs, args: MountArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let cache = args.cache_size.or(ctx.cache_size.clone());
    let cache_bytes = cache.as_deref().map(parse_size).transpose()?;
    let known_keys = ctx.known_keys()?;
    let password = password_from("RAFT5FS_PASSWORD", &format!("password for {}: ", ctx.user))
        .map_err(|e| format!("cannot read a password: {e}"))?;

    let runtime = runtime();
    let mut fs = Raft5Fs::new(
        ctx.servers.clone(),
        ctx.credentials(password),
        runtime.handle().clone(),
    )
    .with_write_buffering(!args.no_write_buffer)
    .with_known_keys(known_keys);
    if let Some(bytes) = cache_bytes {
        fs = fs.with_cache_size(bytes);
    }
    if let Some(tls) = ctx.tls.clone() {
        fs = fs.with_tls(tls);
    }
    if !args.no_background_prune {
        fs = fs.with_prune_queue(ctx.prune_queue(), PrunerConfig::default());
    }

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
