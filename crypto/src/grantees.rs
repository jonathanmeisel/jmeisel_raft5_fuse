//! Who a node is granted to, sealed under the node's own key.
//!
//! The server keeps the grants, and says who holds them -- but a server
//! that could add a name to that list would have the next rotation seal
//! the node's new key to whoever it liked. So beside the grants the server
//! keeps this list, which only the node's key holders can make: each
//! grantee's name, the public key their grant was sealed to, and whether
//! it lets them write. A rotation re-seals grants only to who is on it,
//! with the keys on it. The server can still drop a grant (it can always
//! refuse access), but never add one.
//!
//! The list starts with the key version it was sealed under, unencrypted,
//! like chunks and names: one sealed under an old version is one a
//! revoked user could have written, so only one under the node's current
//! version counts.

use crate::identity::PUBLIC_KEY_LEN;
use crate::{Error, Key, Reader, aad, open, put_bytes, seal};

/// One grant, as its maker sealed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GranteeEntry {
    pub user: String,
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub writable: bool,
}

fn grantees_aad(ino: u64, version: u32) -> Vec<u8> {
    aad("grantees", &[&ino.to_be_bytes(), &version.to_be_bytes()])
}

/// `entries`, as the grantees of `ino`, sealed under its key at `version`.
/// Sorted by name first, so one set of grantees always encodes the same.
pub fn seal_grantees(key: &Key, version: u32, ino: u64, entries: &[GranteeEntry]) -> Vec<u8> {
    let mut sorted: Vec<&GranteeEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.user.cmp(&b.user));
    let mut plain = Vec::new();
    plain.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for entry in sorted {
        put_bytes(&mut plain, entry.user.as_bytes());
        plain.extend_from_slice(&entry.public_key);
        plain.push(u8::from(entry.writable));
    }
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&seal(key, &grantees_aad(ino, version), &plain));
    out
}

/// Opens `ino`'s grantee list with its key at the version the list was
/// sealed under (see `data::sealed_version`). A list naming anyone twice
/// isn't one an honest client made.
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
        let writable = match r.take(1, what)?[0] {
            0 => false,
            1 => true,
            _ => return Err(Error(what)),
        };
        if entries.iter().any(|e| e.user == user) {
            return Err(Error(what));
        }
        entries.push(GranteeEntry {
            user,
            public_key,
            writable,
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
        }
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
