//! Public links: what a web app URL's `#link=` fragment holds, so that
//! anyone with the URL can read one folder.
//!
//! A link is an account of its own (a name that starts with `link-`), and
//! the fragment holds its name and password, with the filesystem it is on.
//! The password is a random secret that only the link holds. Browsers never
//! send a fragment to a server, so the servers never see it, as for any
//! password.
//!
//! The format is base64url, without padding, of a version byte (1) and
//! then the filesystem's id (`raft5fs_client::fs_id`), the account's name,
//! and the secret, each length-prefixed.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::wire::{Reader, put};

const VERSION: u8 = 1;

/// What a public link holds. It is as secret as a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicLink {
    pub fs_id: String,
    pub user: String,
    pub secret: String,
}

impl PublicLink {
    /// The link as a URL fragment's value.
    pub fn encode(&self) -> String {
        let mut out = vec![VERSION];
        put(&mut out, self.fs_id.as_bytes());
        put(&mut out, self.user.as_bytes());
        put(&mut out, self.secret.as_bytes());
        URL_SAFE_NO_PAD.encode(out)
    }

    /// Reads a link that `encode` wrote. Anything else is refused.
    pub fn decode(text: &str) -> Result<Self, String> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text.trim())
            .map_err(|_| "the link is garbled".to_string())?;
        let Some((&version, body)) = bytes.split_first() else {
            return Err("the link is empty".to_string());
        };
        if version != VERSION {
            return Err("this link is for another version of raft5fs".to_string());
        }
        let mut r = Reader::new(body, "link");
        let link = Self {
            fs_id: r.string()?,
            user: r.string()?,
            secret: r.string()?,
        };
        if !r.rest.is_empty() || link.user.is_empty() || link.secret.is_empty() {
            return Err(r.garbled());
        }
        Ok(link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_round_trip_and_garbage_is_refused() {
        let link = PublicLink {
            fs_id: "0123456789abcdef".into(),
            user: "link-abcdefghijkl".into(),
            secret: "ab".repeat(32),
        };
        let text = link.encode();
        assert!(!text.contains(['+', '/', '=']));
        assert_eq!(PublicLink::decode(&text).unwrap(), link);
        assert!(PublicLink::decode(&text[..text.len() - 2]).is_err());
        assert!(PublicLink::decode("not base64!").is_err());
        let mut other = URL_SAFE_NO_PAD.decode(&text).unwrap();
        other[0] = 2;
        assert!(PublicLink::decode(&URL_SAFE_NO_PAD.encode(other)).is_err());
    }
}
