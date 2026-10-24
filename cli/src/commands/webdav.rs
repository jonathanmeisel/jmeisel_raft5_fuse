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
    /// Keep the password in this file, and use it again on the next start,
    /// so clients need it only once. Made, readable only by you, if it
    /// doesn't exist. Without this, each start makes a new password.
    #[arg(long, value_name = "FILE")]
    pub password_file: Option<PathBuf>,
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

/// The password kept in `path`, or a new one written there if the file is
/// missing or empty.
fn kept_auth(user: &str, path: &Path) -> Result<Auth, String> {
    let kept = match std::fs::read_to_string(path) {
        Ok(text) => text.lines().next().unwrap_or("").trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    if !kept.is_empty() {
        return Auth::with_password(user, &kept).map_err(|e| format!("{}: {e}", path.display()));
    }
    let auth = Auth::generate(user).map_err(|e| format!("cannot make a password: {e}"))?;
    write_password(path, auth.password())
        .map_err(|e| format!("cannot write the password to {}: {e}", path.display()))?;
    Ok(auth)
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
    // A kept password stays when the server stops; a new one goes with it.
    let (auth, password_path, keep) = match &args.password_file {
        Some(path) => (kept_auth(&ctx.user, path)?, path.clone(), true),
        None => {
            let auth =
                Auth::generate(&ctx.user).map_err(|e| format!("cannot make a password: {e}"))?;
            (auth, password_file(&ctx), false)
        }
    };

    let runtime = runtime();
    runtime.block_on(async {
        let listener = TcpListener::bind(args.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
        let session = Session::open(config).await.map_err(|e| e.message)?;
        if !keep {
            write_password(&password_path, auth.password()).map_err(|e| {
                format!(
                    "cannot write the password to {}: {e}",
                    password_path.display()
                )
            })?;
        }
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
        if !keep {
            let _ = std::fs::remove_file(&password_path);
        }
        served.map_err(|e| format!("serving: {e}"))
    })?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("raft5fs-webdav-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("webdav.pw")
    }

    #[test]
    fn a_kept_password_is_made_once_and_used_again() {
        let path = temp_file("kept");
        let first = kept_auth("alice", &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let second = kept_auth("alice", &path).unwrap();
        assert_eq!(first.password(), second.password());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_short_kept_password_is_refused() {
        let path = temp_file("short");
        write_password(&path, "short").unwrap();
        assert!(kept_auth("alice", &path).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
