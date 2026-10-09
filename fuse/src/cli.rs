//! What the `raft5fs` command's subcommands share: reading passwords,
//! profiles, and turning a command line and a profile into everything
//! needed to reach a filesystem (`Context`).
//!
//! **Profiles.** `~/.config/raft5fs/profiles/<name>.toml` holds what would
//! otherwise be repeated on every command line: the account, the servers,
//! the CA certificate to trust for them. `raft5fs enrol` writes one. A
//! command uses `--profile`'s, or else the only one there is; flags given
//! on the command line win over the profile's.
//!
//! **Where trust is kept** comes from the user's own CA certificate, never
//! from a server: pins of other users' keys (`KnownKeys`) are kept per
//! filesystem, in `~/.config/raft5fs/filesystems/<CA id>/known_keys`,
//! where the CA id is a hash of the certificate. A server that could pick
//! which pin file a client used could have it start an empty one.

use std::env;
use std::io::{BufRead, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use raft5fs_crypto::password::KdfParams;
use raft5fs_proto::invite::pem_to_der;
use raft5fs_proto::types::check_username;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, ClientTlsConfig};

use crate::prune_queue::PruneQueue;
use crate::remote::Credentials;
use crate::vault::KnownKeys;

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

/// TLS settings trusting the CA certificate `pem`, and checking the
/// servers' certificates against `server_name` if given.
pub fn tls_from_pem(pem: Vec<u8>, server_name: Option<&str>) -> ClientTlsConfig {
    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem));
    if let Some(name) = server_name {
        tls = tls.domain_name(name);
    }
    tls
}

/// A byte count, or a number with a K or M suffix.
pub fn parse_size(s: &str) -> Result<usize, String> {
    let (digits, unit) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1024),
        Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    digits
        .parse::<usize>()
        .map_err(|_| format!("not a size: {s}"))?
        .checked_mul(unit)
        .ok_or_else(|| format!("size too large: {s}"))
}

fn home_dir(var: &str, under_home: &str) -> PathBuf {
    env::var_os(var)
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(under_home)))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("raft5fs")
}

/// `~/.config/raft5fs` (or under `$XDG_CONFIG_HOME`): profiles and pins.
pub fn config_dir() -> PathBuf {
    home_dir("XDG_CONFIG_HOME", ".config")
}

/// `~/.local/state/raft5fs` (or under `$XDG_STATE_HOME`): prune queues.
pub fn state_dir() -> PathBuf {
    home_dir("XDG_STATE_HOME", ".local/state")
}

/// Makes `dir` and those above it, readable by their owner only.
pub fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Writes `contents` to a new `file`, readable by its owner only. An
/// existing one is an error: nothing here overwrites what someone set up.
pub fn write_new_private(file: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = file.parent() {
        make_private_dir(dir)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)?;
    f.write_all(contents)
}

/// The first 16 hex digits of the SHA-256 of `bytes`.
fn short_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What names a filesystem here: a hash of the CA certificate its
/// servers chain to (`pem`, as the user has it).
pub fn ca_id(pem: &[u8]) -> Result<String, String> {
    let pem = std::str::from_utf8(pem).map_err(|_| "not a PEM certificate".to_string())?;
    Ok(short_hash(&pem_to_der(pem)?))
}

/// Where pins of other users' keys are kept for the filesystem whose CA
/// has id `ca_id`, unless told otherwise, under config directory `base`.
pub fn default_known_keys(base: &Path, ca_id: &str) -> PathBuf {
    base.join("filesystems").join(ca_id).join("known_keys")
}

/// `user`'s prune queue on this machine, for the filesystem with id
/// `fs_id` (`ca_id`): the one `raft5fs revoke` adds to and a mount works
/// through.
pub fn prune_queue_for(user: &str, fs_id: &str) -> PruneQueue {
    PruneQueue::at(state_dir().join(format!("{user}@{fs_id}")))
}

/// A profile: what a command would otherwise need on its command line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The account.
    pub user: String,
    /// The filesystem servers, `https://host:port`.
    pub servers: Vec<String>,
    /// The CA certificate (PEM) the servers' certificates chain to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    /// Where pins are kept, if not where `ca` says (`default_known_keys`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_keys: Option<PathBuf>,
    /// For `mount`: how much decrypted data to cache (see `parse_size`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_size: Option<String>,
    /// Talk to `http://` servers without TLS: throwaway setups only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure_plaintext: bool,
}

impl Profile {
    /// Where profile `name` is kept, under config directory `base`.
    pub fn path(base: &Path, name: &str) -> PathBuf {
        base.join("profiles").join(format!("{name}.toml"))
    }

    /// The names of every profile under `base`, sorted.
    pub fn list(base: &Path) -> std::io::Result<Vec<String>> {
        let dir = base.join("profiles");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut names = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            if let Some(name) = name.to_str().and_then(|n| n.strip_suffix(".toml")) {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn load(base: &Path, name: &str) -> Result<Self, String> {
        check_profile_name(name)?;
        let path = Self::path(base, name);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read profile {name} ({}): {e}", path.display()))?;
        let profile: Self = toml::from_str(&text)
            .map_err(|e| format!("profile {name} ({}): {e}", path.display()))?;
        check_username(&profile.user).map_err(|e| format!("profile {name}: {}", e.message))?;
        Ok(profile)
    }

    /// Saves this as profile `name` under `base`, which mustn't exist yet.
    pub fn save_new(&self, base: &Path, name: &str) -> Result<PathBuf, String> {
        check_profile_name(name)?;
        let path = Self::path(base, name);
        let text = toml::to_string(self).map_err(|e| e.to_string())?;
        write_new_private(&path, text.as_bytes()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "there is already a profile {name} ({}); choose another name with --profile",
                    path.display()
                )
            } else {
                format!("cannot save profile {name} in {}: {e}", path.display())
            }
        })?;
        Ok(path)
    }
}

/// Profile names follow the same rule as account names: they end up in
/// file names.
fn check_profile_name(name: &str) -> Result<(), String> {
    check_username(name).map_err(|e| e.message.replace("username", "profile name"))
}

/// What a command line says about how to reach a filesystem; anything
/// left out comes from the profile.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub profile: Option<String>,
    pub user: Option<String>,
    pub ca: Option<PathBuf>,
    pub tls_server_name: Option<String>,
    pub servers: Vec<String>,
    pub known_keys: Option<PathBuf>,
    pub insecure_plaintext: bool,
}

/// Everything needed to reach a filesystem as one account, as a command
/// line and a profile together say.
#[derive(Debug, Clone)]
pub struct Context {
    /// The profile used, if one was.
    pub profile: Option<String>,
    pub user: String,
    pub servers: Vec<String>,
    pub tls: Option<ClientTlsConfig>,
    pub plaintext: bool,
    /// The CA's id (`ca_id`), if there is a CA.
    pub ca_id: Option<String>,
    /// Where pins are kept; `None` to keep them in memory only.
    pub known_keys: Option<PathBuf>,
    pub cache_size: Option<String>,
}

impl Context {
    /// Puts `o` together with its profile: `o.profile`'s, or else the only
    /// one there is (or with several, the one named for `o.user`).
    /// `servers_needed`: whether the command talks to the servers at all.
    pub fn resolve(o: &Overrides, servers_needed: bool) -> Result<Self, String> {
        Self::resolve_in(&config_dir(), o, servers_needed)
    }

    /// `resolve`, with profiles and pins under config directory `base`.
    pub fn resolve_in(base: &Path, o: &Overrides, servers_needed: bool) -> Result<Self, String> {
        let names = Profile::list(base).map_err(|e| format!("cannot list profiles: {e}"))?;
        let chosen = match &o.profile {
            Some(name) => Some(name.clone()),
            None if names.len() == 1 => names.first().cloned(),
            None => o.user.as_ref().filter(|u| names.contains(u)).cloned(),
        };
        let profile = match &chosen {
            Some(name) => Profile::load(base, name)?,
            None => Profile::default(),
        };
        let user = o.user.clone().unwrap_or(profile.user);
        if user.is_empty() {
            return Err(match names.len() {
                0 => "which account? Give --user (or enrol, which makes a profile)".to_string(),
                _ => format!("which profile? Give --profile ({})", names.join(", ")),
            });
        }
        check_username(&user).map_err(|e| e.message)?;
        let servers = if o.servers.is_empty() {
            profile.servers
        } else {
            o.servers.clone()
        };
        let plaintext = o.insecure_plaintext || profile.insecure_plaintext;
        let ca = o.ca.clone().or(profile.ca);
        let server_name = o.tls_server_name.clone().or(profile.tls_server_name);
        if servers_needed && servers.is_empty() {
            return Err("which servers? Give --server (or use a profile)".to_string());
        }
        let (tls, ca_id) = match &ca {
            Some(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                let id = ca_id(&pem).map_err(|e| format!("{}: {e}", path.display()))?;
                (Some(tls_from_pem(pem, server_name.as_deref())), Some(id))
            }
            None if server_name.is_some() => {
                return Err("--tls-server-name needs --ca".to_string());
            }
            None if servers_needed && !plaintext => {
                return Err(
                    "--ca is required (or --insecure-plaintext, for a throwaway setup)".to_string(),
                );
            }
            None => (None, None),
        };
        let known_keys = o
            .known_keys
            .clone()
            .or(profile.known_keys)
            .or_else(|| ca_id.as_deref().map(|id| default_known_keys(base, id)));
        Ok(Self {
            profile: chosen,
            user,
            servers,
            tls,
            plaintext,
            ca_id,
            known_keys,
            cache_size: profile.cache_size,
        })
    }

    /// The pins, from their file -- or, with none (plaintext, without
    /// `--known-keys`), in memory only, which is said.
    pub fn known_keys(&self) -> Result<KnownKeys, String> {
        warn_of_legacy_pins();
        match &self.known_keys {
            Some(path) => KnownKeys::load(path.clone())
                .map_err(|e| format!("cannot read the known keys in {}: {e}", path.display())),
            None => {
                eprintln!(
                    "note: no CA and no --known-keys, so keys pinned now are forgotten \
                     when this ends"
                );
                Ok(KnownKeys::in_memory())
            }
        }
    }

    /// This account's prune queue on this machine, for this filesystem.
    pub fn prune_queue(&self) -> PruneQueue {
        let fs = match &self.ca_id {
            Some(id) => id.clone(),
            None => format!("plain-{}", short_hash(self.servers.join(" ").as_bytes())),
        };
        prune_queue_for(&self.user, &fs)
    }

    /// The credentials to log in with, given the password.
    pub fn credentials(&self, password: String) -> Credentials {
        let mut credentials = Credentials::new(self.user.clone(), password);
        credentials.allow_plaintext = self.plaintext;
        credentials.min_kdf = KdfParams::DEFAULT;
        credentials
    }
}

/// Says so if the known-keys file of before pins were kept per filesystem
/// is still there: it is no longer read, and can't be merged without
/// knowing which filesystem each pin was for.
fn warn_of_legacy_pins() {
    let legacy = config_dir().join("known_keys");
    if legacy.exists() {
        eprintln!(
            "note: {} is no longer read. Pins are now kept per filesystem, in {}; \
             move the lines for this filesystem there, then remove it.",
            legacy.display(),
            config_dir().join("filesystems/<id>/known_keys").display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAECAwQ=\n-----END CERTIFICATE-----\n";

    #[test]
    fn the_ca_id_follows_the_certificate_not_its_layout() {
        let a = ca_id(PEM.as_bytes()).unwrap();
        assert_eq!(a.len(), 16);
        let relaid =
            "junk\n-----BEGIN CERTIFICATE-----\r\nAAEC\r\nAwQ=\r\n-----END CERTIFICATE-----";
        assert_eq!(ca_id(relaid.as_bytes()).unwrap(), a);
        let other = "-----BEGIN CERTIFICATE-----\nAAECAwU=\n-----END CERTIFICATE-----\n";
        assert_ne!(ca_id(other.as_bytes()).unwrap(), a);
        assert!(ca_id(b"nothing").is_err());
        assert!(
            default_known_keys(Path::new("/c"), &a)
                .ends_with(format!("filesystems/{a}/known_keys"))
        );
    }

    #[test]
    fn profiles_round_trip_and_refuse_unknown_fields() {
        let p = Profile {
            user: "alice".into(),
            servers: vec!["https://fs1:27060".into()],
            ca: Some("/home/alice/.config/raft5fs/profiles/alice.ca.pem".into()),
            ..Profile::default()
        };
        let text = toml::to_string(&p).unwrap();
        assert!(!text.contains("insecure_plaintext"));
        assert_eq!(toml::from_str::<Profile>(&text).unwrap(), p);
        assert!(toml::from_str::<Profile>(&format!("{text}\nsurprise = 1\n")).is_err());
        assert!(check_profile_name("../evil").is_err());
    }

    fn temp_base(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("raft5fs-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    #[test]
    fn a_command_line_and_a_profile_combine_flags_first() {
        let base = temp_base("resolve");
        let ca = base.join("ca.pem");
        write_new_private(&ca, PEM.as_bytes()).unwrap();
        let none = Overrides::default();
        // No profile: everything from flags, CA required.
        assert!(Context::resolve_in(&base, &none, true).is_err());
        let flags = Overrides {
            user: Some("alice".into()),
            servers: vec!["https://fs1".into()],
            ..Overrides::default()
        };
        let err = Context::resolve_in(&base, &flags, true).unwrap_err();
        assert!(err.contains("--ca"), "{err}");

        let profile = Profile {
            user: "alice".into(),
            servers: vec!["https://fs1".into()],
            ca: Some(ca.clone()),
            ..Profile::default()
        };
        profile.save_new(&base, "alice").unwrap();
        assert!(
            profile.save_new(&base, "alice").is_err(),
            "never overwritten"
        );
        // The only profile: used without asking.
        let ctx = Context::resolve_in(&base, &none, true).unwrap();
        assert_eq!(
            (ctx.profile.as_deref(), ctx.user.as_str()),
            (Some("alice"), "alice")
        );
        let id = ca_id(PEM.as_bytes()).unwrap();
        assert_eq!(ctx.known_keys, Some(default_known_keys(&base, &id)));
        assert!(ctx.tls.is_some());
        assert!(ctx.prune_queue().dir().ends_with(format!("alice@{id}")));
        // Flags win over it.
        let over = Overrides {
            servers: vec!["https://fs2".into()],
            known_keys: Some("/pins".into()),
            ..Overrides::default()
        };
        let ctx = Context::resolve_in(&base, &over, true).unwrap();
        assert_eq!(ctx.servers, ["https://fs2"]);
        assert_eq!(ctx.known_keys, Some("/pins".into()));

        // With two, one must be picked -- by name, or by the user's.
        Profile {
            user: "bob".into(),
            ..profile.clone()
        }
        .save_new(&base, "bob")
        .unwrap();
        let err = Context::resolve_in(&base, &none, true).unwrap_err();
        assert!(err.contains("alice, bob"), "{err}");
        let by_user = Overrides {
            user: Some("bob".into()),
            ..Overrides::default()
        };
        assert_eq!(
            Context::resolve_in(&base, &by_user, true)
                .unwrap()
                .profile
                .as_deref(),
            Some("bob")
        );
        let missing = Overrides {
            profile: Some("carol".into()),
            ..Overrides::default()
        };
        assert!(Context::resolve_in(&base, &missing, true).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn plaintext_needs_saying_and_keeps_pins_only_where_told() {
        let base = temp_base("plain");
        let o = Overrides {
            user: Some("alice".into()),
            servers: vec!["http://fs1".into()],
            insecure_plaintext: true,
            ..Overrides::default()
        };
        let ctx = Context::resolve_in(&base, &o, true).unwrap();
        assert!(ctx.tls.is_none() && ctx.plaintext);
        assert_eq!(ctx.known_keys, None);
        assert!(ctx.credentials("pw".into()).allow_plaintext);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("64M").unwrap(), 64 << 20);
        assert_eq!(parse_size("8k").unwrap(), 8192);
        assert_eq!(parse_size("100").unwrap(), 100);
        assert!(parse_size("lots").is_err());
    }
}
