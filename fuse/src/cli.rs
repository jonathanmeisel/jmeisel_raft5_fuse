//! What the client binaries share: reading passwords, building TLS
//! settings from their command lines, and where pinned keys are kept.

use std::env;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use tonic::transport::{Certificate, ClientTlsConfig};

/// Reads a password from the terminal without echoing it, after showing
/// `prompt`.
pub fn prompt_password(prompt: &str) -> std::io::Result<String> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&tty);
    write!(&tty, "{prompt}")?;
    // SAFETY: `termios` is plain data, filled in by `tcgetattr` before use.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let echo_off = unsafe { libc::tcgetattr(fd, &mut saved) } == 0 && {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) == 0 }
    };
    let mut line = String::new();
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    if echo_off {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    }
    writeln!(&tty)?;
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// A password from the environment variable `var`, or else asked for on
/// the terminal with `prompt`.
pub fn password_from(var: &str, prompt: &str) -> std::io::Result<String> {
    match std::env::var(var) {
        Ok(password) => Ok(password),
        Err(_) => prompt_password(prompt),
    }
}

/// TLS settings trusting the CA certificate at `ca` (a PEM file), and
/// checking the servers' certificates against `server_name` if given.
pub fn tls(ca: &str, server_name: Option<&str>) -> Result<ClientTlsConfig, String> {
    let pem = std::fs::read(ca).map_err(|e| format!("cannot read {ca}: {e}"))?;
    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem));
    if let Some(name) = server_name {
        tls = tls.domain_name(name);
    }
    Ok(tls)
}

/// Where pinned public keys are kept unless `--known-keys` says otherwise.
pub fn default_known_keys() -> PathBuf {
    let config = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    config.join("raft5fs").join("known_keys")
}
