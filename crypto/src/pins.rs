//! An account's trusted keys (its pins), sealed for the servers to keep,
//! so that every device of the account trusts the same keys.
//!
//! - The list is sealed under a key that only the account's private key
//!   gives, and bound to the account's name. The servers can't read it,
//!   and can't add or change an entry.
//! - Each entry has a time, and a forgotten key stays as an entry with no
//!   key, so that devices that merge their changes agree on the latest.
//! - The servers could give an older list. That only takes away what was
//!   trusted since: the device asks for a fingerprint again. It never adds
//!   a key that the account didn't check.

use crate::identity::{Identity, PUBLIC_KEY_LEN};
use crate::{Error, Reader, aad, open, put_bytes, seal};

/// The format of a sealed list.
const VERSION: u8 = 1;

/// One user's pin, as of `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinEntry {
    pub user: String,
    /// The trusted key, or `None` if it was forgotten.
    pub key: Option<[u8; PUBLIC_KEY_LEN]>,
    /// When it was set, in seconds since the Unix epoch.
    pub at: u64,
}

/// Seals `entries` as `user`'s trusted keys, sorted by name.
pub fn seal_pins(identity: &Identity, user: &str, entries: &[PinEntry]) -> Vec<u8> {
    let mut sorted: Vec<&PinEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.user.cmp(&b.user));
    let mut plain = (sorted.len() as u32).to_be_bytes().to_vec();
    for entry in sorted {
        put_bytes(&mut plain, entry.user.as_bytes());
        match &entry.key {
            Some(key) => {
                plain.push(1);
                plain.extend_from_slice(key);
            }
            None => plain.push(0),
        }
        plain.extend_from_slice(&entry.at.to_be_bytes());
    }
    let key = identity.derive_key("pins");
    let mut out = vec![VERSION];
    out.extend_from_slice(&seal(&key, &aad("pins", &[user.as_bytes()]), &plain));
    out
}

/// Opens `user`'s trusted keys, as `seal_pins` sealed them.
pub fn open_pins(identity: &Identity, user: &str, sealed: &[u8]) -> Result<Vec<PinEntry>, Error> {
    let what = "the trusted keys";
    let (&version, sealed) = sealed.split_first().ok_or(Error(what))?;
    if version != VERSION {
        return Err(Error(what));
    }
    let key = identity.derive_key("pins");
    let plain = open(&key, &aad("pins", &[user.as_bytes()]), sealed, what)?;
    let mut r = Reader(&plain);
    let count = r.u32(what)?;
    let mut entries: Vec<PinEntry> = Vec::new();
    for _ in 0..count {
        let user = std::str::from_utf8(r.bytes(what)?)
            .map_err(|_| Error(what))?
            .to_string();
        let key = match r.take(1, what)?[0] {
            0 => None,
            1 => Some(r.take(PUBLIC_KEY_LEN, what)?.try_into().unwrap()),
            _ => return Err(Error(what)),
        };
        let at = u64::from_be_bytes(r.take(8, what)?.try_into().unwrap());
        if entries.iter().any(|e| e.user == user) {
            return Err(Error(what));
        }
        entries.push(PinEntry { user, key, at });
    }
    r.finish(what)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(user: &str, key: Option<u8>, at: u64) -> PinEntry {
        PinEntry {
            user: user.to_string(),
            key: key.map(|b| [b; PUBLIC_KEY_LEN]),
            at,
        }
    }

    #[test]
    fn pins_open_only_for_their_account() {
        let me = Identity::generate();
        let list = vec![entry("bob", Some(2), 20), entry("alice", None, 10)];
        let sealed = seal_pins(&me, "carol", &list);
        assert_eq!(
            open_pins(&me, "carol", &sealed).unwrap(),
            vec![entry("alice", None, 10), entry("bob", Some(2), 20)]
        );
        assert!(open_pins(&me, "dave", &sealed).is_err(), "another account");
        assert!(open_pins(&Identity::generate(), "carol", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_pins(&me, "carol", &tampered).is_err());
        assert!(open_pins(&me, "carol", &[]).is_err());
        assert!(
            open_pins(&me, "carol", &seal_pins(&me, "carol", &[]))
                .unwrap()
                .is_empty()
        );
    }
}
