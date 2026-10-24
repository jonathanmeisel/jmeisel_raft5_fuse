//! Links: a profile, in one line, to set up a second device for an account
//! that already exists (`raft5fs profile export` / `import`).
//!
//! The format is `raft5fs-link:1:` and then, in base64url:
//!
//! - the account's name;
//! - the filesystem servers' addresses;
//! - the name to check their certificates against, if it is not the
//!   addresses' hosts;
//! - the certificate of the CA that their certificates chain to;
//! - the keys of other users that this account has pinned.
//!
//! Nothing in a link is secret: logging in still needs the password. But it
//! decides whom the new device trusts, so it must arrive unchanged. A
//! changed CA would point the device at other servers, and a changed pin at
//! another user. Move it yourself, not through anyone else.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::wire::{Reader, put, put_u32};

const PREFIX: &str = "raft5fs-link:1:";

/// The length of a user's public key.
pub const KEY_LEN: usize = 32;

/// The most servers and pins that a link may hold, so a damaged link fails
/// rather than asks for a huge allocation.
const MAX_SERVERS: u32 = 64;
const MAX_PINS: u32 = 10_000;

/// What a link holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub user: String,
    pub servers: Vec<String>,
    pub tls_server_name: Option<String>,
    /// The CA certificate, in DER.
    pub ca: Vec<u8>,
    /// Other users' pinned keys, by name.
    pub pins: Vec<(String, [u8; KEY_LEN])>,
}

impl Link {
    /// The link as one line.
    pub fn encode(&self) -> String {
        let mut out = Vec::new();
        put(&mut out, self.user.as_bytes());
        put_u32(&mut out, self.servers.len());
        for server in &self.servers {
            put(&mut out, server.as_bytes());
        }
        put(
            &mut out,
            self.tls_server_name.as_deref().unwrap_or("").as_bytes(),
        );
        put(&mut out, &self.ca);
        put_u32(&mut out, self.pins.len());
        for (user, key) in &self.pins {
            put(&mut out, user.as_bytes());
            put(&mut out, key);
        }
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(out))
    }

    /// Reads a link in the format that `encode` writes. Whitespace around it
    /// is allowed. Anything else is refused, with the reason.
    pub fn decode(line: &str) -> Result<Self, String> {
        let line = line.trim();
        let Some(body) = line.strip_prefix(PREFIX) else {
            return Err(if line.starts_with("raft5fs-link:") {
                "this link is for another version of raft5fs".to_string()
            } else if line.starts_with("raft5fs-invite:") {
                "this is an invitation: use `raft5fs enrol` with it".to_string()
            } else {
                "not a raft5fs link".to_string()
            });
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| "the link is garbled".to_string())?;
        let mut r = Reader::new(&bytes, "link");
        let user = r.string()?;
        let count = r.u32()?;
        if count == 0 || count > MAX_SERVERS {
            return Err("the link names no servers".to_string());
        }
        let servers = (0..count).map(|_| r.string()).collect::<Result<_, _>>()?;
        let name = r.string()?;
        let ca = r.bytes()?.to_vec();
        let count = r.u32()?;
        if count > MAX_PINS {
            return Err(r.garbled());
        }
        let mut pins = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let pinned = r.string()?;
            crate::types::check_username(&pinned).map_err(|e| e.message)?;
            let key: [u8; KEY_LEN] = r.bytes()?.try_into().map_err(|_| r.garbled())?;
            pins.push((pinned, key));
        }
        if !r.rest.is_empty() || ca.is_empty() {
            return Err(r.garbled());
        }
        crate::types::check_username(&user).map_err(|e| e.message)?;
        Ok(Self {
            user,
            servers,
            tls_server_name: (!name.is_empty()).then_some(name),
            ca,
            pins,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> Link {
        Link {
            user: "alice".into(),
            servers: vec!["https://fs1:27060".into(), "https://fs2:27060".into()],
            tls_server_name: Some("fs.example".into()),
            ca: vec![0x30, 0x82, 1, 2, 3],
            pins: vec![("bob".into(), [7; KEY_LEN]), ("carol".into(), [9; KEY_LEN])],
        }
    }

    #[test]
    fn a_link_round_trips() {
        let line = link().encode();
        assert!(line.starts_with(PREFIX));
        assert_eq!(Link::decode(&format!("  {line}\n")).unwrap(), link());
        let bare = Link {
            tls_server_name: None,
            pins: Vec::new(),
            ..link()
        };
        assert_eq!(Link::decode(&bare.encode()).unwrap(), bare);
    }

    #[test]
    fn a_damaged_link_is_refused() {
        let line = link().encode();
        assert!(Link::decode(&line[..line.len() - 6]).is_err());
        assert!(Link::decode(&format!("{line}AAAA")).is_err());
        assert!(
            Link::decode("raft5fs-link:2:AAAA")
                .unwrap_err()
                .contains("version")
        );
        assert!(
            Link::decode("raft5fs-invite:1:AAAA")
                .unwrap_err()
                .contains("enrol")
        );
        assert!(Link::decode("hello").is_err());
    }

    #[test]
    fn a_bad_pinned_name_is_refused() {
        let bad = Link {
            pins: vec![("bob\nmallory".into(), [1; KEY_LEN])],
            ..link()
        };
        assert!(Link::decode(&bad.encode()).is_err());
    }
}
