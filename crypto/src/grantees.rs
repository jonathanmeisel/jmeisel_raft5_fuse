//! The users a node is granted to, sealed under the node's own key.
//!
//! The server keeps the grants and says who has them. But if the server
//! could add a name to that list, the next rotation would seal the node's
//! new key to any user the server chose. So the server also keeps this
//! list, which only the node's key holders can make. It holds each
//! grantee's name, the public key their grant was sealed to, and whether
//! they can write. A rotation seals grants again only to the users on this
//! list, with the keys on it. The server can still remove a grant (it can
//! always refuse access), but it cannot add one.
//!
//! A public link's entry also holds the link's secret, so that whoever can
//! change the node can copy the link again. The servers give the list only
//! to them, and can't read it.
//!
//! Like chunks and names, the list starts with the key version it was
//! sealed under, not encrypted. A revoked user could have written a list
//! under an old version, so only a list under the node's current version
//! counts.

use crate::identity::PUBLIC_KEY_LEN;
use crate::{Error, Key, Reader, aad, open, put_bytes, seal};

/// One grant, as its maker sealed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GranteeEntry {
    pub user: String,
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub writable: bool,
    /// For a public link: its secret, the password in the link.
    pub link_secret: Option<String>,
}

/// An entry's flags byte: whether the grantee can write, and whether a
/// link secret follows. A list from before link secrets has only the
/// first.
const WRITABLE: u8 = 1;
const HAS_LINK_SECRET: u8 = 2;

fn grantees_aad(ino: u64, version: u32) -> Vec<u8> {
    aad("grantees", &[&ino.to_be_bytes(), &version.to_be_bytes()])
}

/// Seals `entries` as the grantees of `ino`, under its key at `version`. It
/// sorts the entries by name first, so the same grantees always give the
/// same encoding.
pub fn seal_grantees(key: &Key, version: u32, ino: u64, entries: &[GranteeEntry]) -> Vec<u8> {
    let mut sorted: Vec<&GranteeEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.user.cmp(&b.user));
    let mut plain = Vec::new();
    plain.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for entry in sorted {
        put_bytes(&mut plain, entry.user.as_bytes());
        plain.extend_from_slice(&entry.public_key);
        let mut flags = 0;
        if entry.writable {
            flags |= WRITABLE;
        }
        if entry.link_secret.is_some() {
            flags |= HAS_LINK_SECRET;
        }
        plain.push(flags);
        if let Some(secret) = &entry.link_secret {
            put_bytes(&mut plain, secret.as_bytes());
        }
    }
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&seal(key, &grantees_aad(ino, version), &plain));
    out
}

/// Opens `ino`'s grantee list with its key at the version that the list was
/// sealed under (see `data::sealed_version`). Fails if the list names a
/// user twice, because an honest client does not make such a list.
pub fn open_grantees(key: &Key, ino: u64, blob: &[u8]) -> Result<Vec<GranteeEntry>, Error> {
    let what = "a grantee list";
    let mut r = Reader(blob);
    let version = r.u32(what)?;
    let plain = open(key, &grantees_aad(ino, version), r.0, what)?;
    let mut r = Reader(&plain);
    let count = r.u32(what)?;
    let mut entries: Vec<GranteeEntry> = Vec::new();
    for _ in 0..count {
        let user = std::str::from_utf8(r.bytes(what)?)
            .map_err(|_| Error(what))?
            .to_string();
        let public_key = r.take(PUBLIC_KEY_LEN, what)?.try_into().unwrap();
        let flags = r.take(1, what)?[0];
        if flags & !(WRITABLE | HAS_LINK_SECRET) != 0 {
            return Err(Error(what));
        }
        let link_secret = if flags & HAS_LINK_SECRET != 0 {
            let secret = std::str::from_utf8(r.bytes(what)?).map_err(|_| Error(what))?;
            Some(secret.to_string())
        } else {
            None
        };
        if entries.iter().any(|e| e.user == user) {
            return Err(Error(what));
        }
        entries.push(GranteeEntry {
            user,
            public_key,
            writable: flags & WRITABLE != 0,
            link_secret,
        });
    }
    r.finish(what)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::sealed_version;

    fn entry(user: &str, byte: u8, writable: bool) -> GranteeEntry {
        GranteeEntry {
            user: user.to_string(),
            public_key: [byte; PUBLIC_KEY_LEN],
            writable,
            link_secret: None,
        }
    }

    #[test]
    fn a_link_keeps_its_secret_and_old_lists_still_open() {
        let key = Key::random();
        let link = GranteeEntry {
            link_secret: Some("ab".repeat(32)),
            ..entry("link-abc", 3, false)
        };
        let list = vec![entry("alice", 1, true), link];
        let blob = seal_grantees(&key, 2, 9, &list);
        assert_eq!(open_grantees(&key, 9, &blob).unwrap(), list);

        // A list sealed before link secrets: one flags byte, 0 or 1.
        let mut plain = 1u32.to_be_bytes().to_vec();
        put_bytes(&mut plain, b"bob");
        plain.extend_from_slice(&[2; PUBLIC_KEY_LEN]);
        plain.push(1);
        let mut old = 2u32.to_be_bytes().to_vec();
        old.extend_from_slice(&seal(&key, &grantees_aad(9, 2), &plain));
        assert_eq!(
            open_grantees(&key, 9, &old).unwrap(),
            [entry("bob", 2, true)]
        );

        // Flags it doesn't know are refused.
        *plain.last_mut().unwrap() = 4;
        let mut odd = 2u32.to_be_bytes().to_vec();
        odd.extend_from_slice(&seal(&key, &grantees_aad(9, 2), &plain));
        assert!(open_grantees(&key, 9, &odd).is_err());
    }

    #[test]
    fn a_list_opens_only_for_its_node_and_key() {
        let key = Key::random();
        let list = vec![entry("bob", 2, false), entry("alice", 1, true)];
        let blob = seal_grantees(&key, 3, 9, &list);
        assert_eq!(sealed_version(&blob).unwrap(), 3);
        let opened = open_grantees(&key, 9, &blob).unwrap();
        assert_eq!(
            opened,
            vec![entry("alice", 1, true), entry("bob", 2, false)]
        );
        assert!(open_grantees(&key, 10, &blob).is_err(), "another node");
        assert!(open_grantees(&Key::random(), 9, &blob).is_err());
        let mut relabelled = blob.clone();
        relabelled[3] = 2;
        assert!(
            open_grantees(&key, 9, &relabelled).is_err(),
            "version bound"
        );
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_grantees(&key, 9, &tampered).is_err());
    }

    #[test]
    fn an_empty_list_round_trips() {
        let key = Key::random();
        let blob = seal_grantees(&key, 1, 4, &[]);
        assert!(open_grantees(&key, 4, &blob).unwrap().is_empty());
    }

    #[test]
    fn a_list_naming_someone_twice_is_refused() {
        let key = Key::random();
        let blob = seal_grantees(&key, 1, 4, &[entry("bob", 1, false), entry("bob", 2, true)]);
        assert!(open_grantees(&key, 4, &blob).is_err());
    }
}
