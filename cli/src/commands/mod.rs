//! The `raft5fs` command: mounting, accounts, sharing and pruning, each a
//! subcommand. What reaches a filesystem comes from a profile (see `cli`),
//! with any of it overridden on the command line.

mod account;
#[cfg(feature = "fuse")]
mod mount;
mod profile;
mod prune;
mod share;
#[cfg(feature = "webdav")]
mod webdav;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use raft5fs_client::cli::{Context, Overrides, parse_size, password_from};
use raft5fs_client::pruner::PrunerConfig;
use raft5fs_client::remote::Remote;
use raft5fs_client::session::SessionConfig;
use raft5fs_client::vault::Vault;
use tokio::runtime::Runtime;

#[derive(Parser)]
#[command(
    name = "raft5fs",
    version,
    about = "Mount, share and look after a raft5fs filesystem.",
    long_about = "Mount, share and look after a raft5fs filesystem.\n\n\
        Everything is encrypted on this machine: the servers never see a password, \
        a file's contents or a name. How to reach a filesystem comes from a profile \
        (~/.config/raft5fs/profiles/), which `enrol` makes; the options below \
        override it."
)]
pub struct Cli {
    #[command(flatten)]
    pub connect: ConnectArgs,
    #[command(subcommand)]
    pub command: Command,
}

/// How to reach the filesystem, over the profile's say.
#[derive(Args, Debug, Clone, Default)]
pub struct ConnectArgs {
    /// The profile to use (by default, the only one there is).
    #[arg(long, global = true)]
    pub profile: Option<String>,
    /// The account.
    #[arg(long, global = true)]
    pub user: Option<String>,
    /// A filesystem server, https://host:port. May be given more than once:
    /// requests go to whichever answers.
    #[arg(long = "server", global = true)]
    pub servers: Vec<String>,
    /// The CA certificate (PEM) the servers' certificates chain to.
    #[arg(long, global = true)]
    pub ca: Option<PathBuf>,
    /// Check the servers' certificates against this name instead of the
    /// host in each address.
    #[arg(long, global = true)]
    pub tls_server_name: Option<String>,
    /// Where other users' public keys are pinned (by default, per
    /// filesystem, under ~/.config/raft5fs/filesystems/).
    #[arg(long, global = true)]
    pub known_keys: Option<PathBuf>,
    /// Talk to http:// servers without TLS. Only for throwaway setups: a
    /// login is enough to test password guesses against, and to act as
    /// the user.
    #[arg(long, global = true)]
    pub insecure_plaintext: bool,
}

impl ConnectArgs {
    fn overrides(&self) -> Overrides {
        Overrides {
            profile: self.profile.clone(),
            user: self.user.clone(),
            ca: self.ca.clone(),
            tls_server_name: self.tls_server_name.clone(),
            servers: self.servers.clone(),
            known_keys: self.known_keys.clone(),
            insecure_plaintext: self.insecure_plaintext,
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Mount the filesystem, in the foreground, as the profile's account.
    #[cfg(feature = "fuse")]
    Mount(mount::MountArgs),
    /// Serve the filesystem over WebDAV, on this machine only, in the
    /// foreground, as the profile's account.
    #[cfg(feature = "webdav")]
    Webdav(webdav::WebdavArgs),
    /// Set up an account from an invitation (or a bare enrolment code),
    /// choosing its password; saves a profile for it.
    Enrol(account::EnrolArgs),
    /// Change the account's password. Everything shared with it stays
    /// readable.
    Passwd,
    /// Show the account's key fingerprint, for others to check when
    /// sharing with it.
    Whoami,
    /// Share a directory, and everything under it, with a user.
    Grant(share::GrantArgs),
    /// Take a user's share of a directory back. What is written there from
    /// then on is sealed under keys they never had.
    Revoke(share::RevokeArgs),
    /// Who a directory is shared with.
    Grants(share::PathArg),
    /// Pin a user's key, after checking its fingerprint with them: what
    /// makes their shares writable here.
    Trust(share::TrustArgs),
    /// Forget a user's pinned key (after they enrolled again).
    ForgetKey(share::UserArg),
    /// What is shared with this account by someone not trusted yet.
    Pending,
    /// Prune old key versions: what is queued, or the given directories.
    Prune(prune::PruneArgs),
    /// List profiles, or show one.
    #[command(subcommand)]
    Profile(profile::ProfileCommand),
}

/// Runs the command line, returning the process's exit status.
pub fn run(cli: Cli) -> i32 {
    let result = match cli.command {
        #[cfg(feature = "fuse")]
        Command::Mount(args) => mount::run(&cli.connect, args),
        #[cfg(feature = "webdav")]
        Command::Webdav(args) => webdav::run(&cli.connect, args),
        Command::Enrol(args) => account::enrol(&cli.connect, args),
        Command::Passwd => account::passwd(&cli.connect),
        Command::Whoami => account::whoami(&cli.connect),
        Command::Grant(args) => share::grant(&cli.connect, args),
        Command::Revoke(args) => share::revoke(&cli.connect, args),
        Command::Grants(args) => share::grants(&cli.connect, args),
        Command::Trust(args) => share::trust(&cli.connect, args),
        Command::ForgetKey(args) => share::forget_key(&cli.connect, args),
        Command::Pending => share::pending(&cli.connect),
        Command::Prune(args) => prune::run(&cli.connect, args),
        Command::Profile(command) => profile::run(command),
    };
    match result {
        Ok(status) => status,
        Err(why) => {
            eprintln!("{why}");
            1
        }
    }
}

/// What a subcommand comes to: an exit status, or why it failed.
type Outcome = Result<i32, String>;

/// How a mount or a WebDAV server keeps its session.
#[derive(Args)]
pub struct SessionArgs {
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
    /// in the background while running.
    #[arg(long)]
    pub no_background_prune: bool,
}

impl SessionArgs {
    /// The session these say to open as `ctx`'s account, asking for its
    /// password (or reading it from RAFT5FS_PASSWORD).
    #[cfg_attr(not(any(feature = "fuse", feature = "webdav")), allow(dead_code))]
    fn config(&self, ctx: &Context) -> Result<SessionConfig, String> {
        let cache = self.cache_size.clone().or(ctx.cache_size.clone());
        let cache_bytes = cache.as_deref().map(parse_size).transpose()?;
        let known_keys = ctx.known_keys()?;
        let password = password_from("RAFT5FS_PASSWORD", &format!("password for {}: ", ctx.user))
            .map_err(|e| format!("cannot read a password: {e}"))?;
        let mut config = SessionConfig::new(ctx.servers.clone(), ctx.credentials(password));
        config.tls = ctx.tls.clone();
        config.known_keys = Some(known_keys);
        config.write_buffering = !self.no_write_buffer;
        if let Some(bytes) = cache_bytes {
            config.cache_bytes = bytes;
        }
        if !self.no_background_prune {
            config.prune_queue = Some((ctx.prune_queue(), PrunerConfig::default()));
        }
        Ok(config)
    }
}

fn runtime() -> Runtime {
    Runtime::new().expect("failed to start tokio runtime")
}

/// Logs in as `ctx`'s account -- asking for the password, or reading it
/// from RAFT5FS_PASSWORD -- and opens its keys, with its pins.
fn log_in(runtime: &Runtime, ctx: &Context) -> Result<Vault, String> {
    let password = password_from("RAFT5FS_PASSWORD", &format!("password for {}: ", ctx.user))
        .map_err(|e| format!("cannot read a password: {e}"))?;
    let remote = runtime
        .block_on(Remote::connect(
            &ctx.servers,
            ctx.credentials(password),
            ctx.tls.clone(),
        ))
        .map_err(|e| format!("cannot log in: {e}"))?;
    Ok(Vault::new(Arc::new(remote))
        .map_err(|e| e.to_string())?
        .with_known_keys(ctx.known_keys()?))
}

/// A key's fingerprint as people read it out: words, then hex.
fn show_fingerprint(key: &[u8; raft5fs_crypto::identity::PUBLIC_KEY_LEN]) -> String {
    format!(
        "  {}\n  ({})",
        raft5fs_crypto::identity::fingerprint_words(key),
        raft5fs_crypto::identity::fingerprint(key)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn connection_options_go_anywhere_on_the_line() {
        let cli = Cli::try_parse_from([
            "raft5fs",
            "grant",
            "photos",
            "bob",
            "--profile",
            "work",
            "--server",
            "https://a",
            "--server",
            "https://b",
        ])
        .unwrap();
        assert_eq!(cli.connect.profile.as_deref(), Some("work"));
        assert_eq!(cli.connect.servers, ["https://a", "https://b"]);
        let cli =
            Cli::try_parse_from(["raft5fs", "trust", "bob", "abandon", "ability", "able"]).unwrap();
        let Command::Trust(args) = cli.command else {
            panic!("not trust");
        };
        assert_eq!(args.fingerprint.join(" "), "abandon ability able");
    }

    #[test]
    fn a_positional_user_is_never_taken_for_the_global_one() {
        for line in [
            ["raft5fs", "--user", "alice", "grant", "photos", "bob"],
            ["raft5fs", "grant", "photos", "bob", "--user", "alice"],
        ] {
            let cli = Cli::try_parse_from(line).unwrap();
            assert_eq!(cli.connect.user.as_deref(), Some("alice"));
            let Command::Grant(args) = cli.command else {
                panic!("not grant");
            };
            assert_eq!(args.grantee, "bob");
        }
        for line in [
            vec!["raft5fs", "--user", "alice", "revoke", "p", "bob"],
            vec!["raft5fs", "--user", "alice", "forget-key", "bob"],
            vec!["raft5fs", "--user", "alice", "trust", "bob", "w"],
        ] {
            let cli = Cli::try_parse_from(line).unwrap();
            assert_eq!(cli.connect.user.as_deref(), Some("alice"));
            let who = match cli.command {
                Command::Revoke(a) => a.grantee,
                Command::ForgetKey(a) => a.who,
                Command::Trust(a) => a.who,
                _ => panic!("wrong command"),
            };
            assert_eq!(who, "bob");
        }
    }
}
