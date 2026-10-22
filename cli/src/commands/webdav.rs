//! `raft5fs webdav`.

use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use clap::Args;
use raft5fs_client::cli::{Context, make_private_dir, runtime_dir};
use raft5fs_client::session::Session;
use raft5fs_webdav::{Auth, is_loopback, serve};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

use super::{ConnectArgs, Outcome, SessionArgs, runtime};

#[derive(Args)]
pub struct WebdavArgs {
    /// Where to listen: a loopback address and port only. Only this
    /// machine's user can use it, because everything done there is done as
    /// the account. Clients must give the password that it prints.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    /// Store the files where macOS keeps metadata (`._*`, `.DS_Store`).
    /// They are refused by default, because Finder makes them next to
    /// everything.
    #[arg(long)]
    pub keep_apple_double: bool,
    #[command(flatten)]
    pub session: SessionArgs,
}

/// Where the server's password is kept while it runs, for clients to read.
/// The file is named after the profile, or else the account.
fn password_file(ctx: &Context) -> PathBuf {
    let name = ctx.profile.as_deref().unwrap_or(&ctx.user);
    runtime_dir().join(format!("{name}.webdav"))
}

/// Writes `password` to `path`, readable only by its owner.
fn write_password(path: &Path, password: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        make_private_dir(dir)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{password}")
}

pub fn run(connect: &ConnectArgs, args: WebdavArgs) -> Outcome {
    if !is_loopback(&args.listen) {
        return Err(format!(
            "{} isn't a loopback address: a WebDAV server is for this machine only",
            args.listen
        ));
    }
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let mut config = args.session.config(&ctx)?;
    config.hide_apple_double = !args.keep_apple_double;
    let auth = Auth::generate(&ctx.user).map_err(|e| format!("cannot make a password: {e}"))?;
    let password_path = password_file(&ctx);

    let runtime = runtime();
    runtime.block_on(async {
        let listener = TcpListener::bind(args.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
        let session = Session::open(config).await.map_err(|e| e.message)?;
        write_password(&password_path, auth.password()).map_err(|e| {
            format!(
                "cannot write the password to {}: {e}",
                password_path.display()
            )
        })?;
        println!("serving at http://{}/ until interrupted", args.listen);
        println!("  user:     {}", auth.user());
        println!("  password: {}", auth.password());
        println!("  (also in {})", password_path.display());

        let mut terminate =
            signal(SignalKind::terminate()).map_err(|e| format!("cannot catch signals: {e}"))?;
        let mut hangup =
            signal(SignalKind::hangup()).map_err(|e| format!("cannot catch signals: {e}"))?;
        let stopped = async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
                _ = hangup.recv() => {}
            }
            eprintln!("stopping: storing what is buffered");
        };
        let served = serve(session, listener, auth, stopped).await;
        let _ = std::fs::remove_file(&password_path);
        served.map_err(|e| format!("serving: {e}"))
    })?;
    Ok(0)
}
