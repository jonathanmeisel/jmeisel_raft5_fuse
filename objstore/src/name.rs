//! Object names: `{prefix}{ino:016x}/{minted_ms:016x}-{random:032x}`.
//!
//! - The server mints every name. So the inode in a name is the inode whose
//!   grant the server checked, and the mint time comes from the server's
//!   clock.
//! - A KV pointer holds only the mint time and the random part. The inode
//!   comes from the chunk key that holds the pointer. So a pointer can only
//!   name objects of its own inode, whatever a client commits. Inode
//!   numbers are never used again, so names are never used again either.
//! - Garbage collection uses the mint time. After some time, a name can no
//!   longer be committed. So if nothing points to an old object, nothing
//!   ever will.
//!
//! Parsing is strict (exact lengths, lower-case hex), so each key has only
//! one spelling. This also separates our objects from anything else under
//! the prefix, which this code never deletes.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::Error;

pub const RANDOM_LEN: usize = 16;

/// The part after the prefix: 16 hex digits, `/`, 16 hex digits, `-`, 32
/// hex digits.
const SUFFIX_LEN: usize = 16 + 1 + 16 + 1 + 2 * RANDOM_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectName {
    pub ino: u64,
    /// When the server minted the name, in milliseconds since the epoch.
    pub minted_ms: u64,
    pub random: [u8; RANDOM_LEN],
}

impl ObjectName {
    /// A new name for an object of `ino`, minted at `now`.
    pub fn mint(ino: u64, now: SystemTime) -> Self {
        let mut random = [0; RANDOM_LEN];
        getrandom::getrandom(&mut random).expect("the OS has no randomness to give");
        ObjectName {
            ino,
            minted_ms: millis(now),
            random,
        }
    }

    /// The object's key under `prefix`.
    pub fn key(&self, prefix: &str) -> String {
        let mut key = inode_prefix(prefix, self.ino);
        key.push_str(&format!("{:016x}-", self.minted_ms));
        for b in self.random {
            key.push_str(&format!("{b:02x}"));
        }
        key
    }

    /// Parses `key` under `prefix`. Returns `None` if it is not an object
    /// name.
    pub fn parse(prefix: &str, key: &str) -> Option<Self> {
        let rest = key.strip_prefix(prefix)?;
        if rest.len() != SUFFIX_LEN {
            return None;
        }
        let (ino, rest) = rest.split_at(16);
        let rest = rest.strip_prefix('/')?;
        let (minted_ms, rest) = rest.split_at(16);
        let rest = rest.strip_prefix('-')?;
        let mut random = [0; RANDOM_LEN];
        for (i, b) in random.iter_mut().enumerate() {
            *b = u8::try_from(hex(&rest[2 * i..2 * i + 2])?).ok()?;
        }
        Some(ObjectName {
            ino: hex(ino)?,
            minted_ms: hex(minted_ms)?,
            random,
        })
    }
}

/// The prefix that every object of `ino` under `prefix` starts with.
pub fn inode_prefix(prefix: &str, ino: u64) -> String {
    format!("{prefix}{ino:016x}/")
}

/// Milliseconds since the epoch, as names count them.
pub fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

/// Lower-case hex only: an upper-case digit would give one name two keys.
fn hex(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

/// Whether `prefix` can hold objects. It must be empty (the whole bucket),
/// or a path of URL-safe characters that ends in `/`. The `/` makes sure
/// that one filesystem's objects never share a key prefix with another
/// filesystem whose prefix only starts the same way.
pub fn validate_prefix(prefix: &str) -> Result<(), Error> {
    if prefix.is_empty() {
        return Ok(());
    }
    if !prefix.ends_with('/') || prefix.starts_with('/') || prefix.contains("//") {
        return Err(Error::Config(format!(
            "an object prefix must be empty or a path ending in '/', not {prefix:?}"
        )));
    }
    if !prefix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
    {
        return Err(Error::Config(format!(
            "an object prefix may contain only letters, digits, '/', '-', '_' and '.', not {prefix:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn name() -> ObjectName {
        ObjectName {
            ino: 0x2a,
            minted_ms: 1_760_000_000_123,
            random: [0xab; RANDOM_LEN],
        }
    }

    #[test]
    fn keys_round_trip() {
        let n = name();
        let key = n.key("fs/");
        assert_eq!(
            key,
            "fs/000000000000002a/00000199c82cc07b-abababababababababababababababab"
        );
        assert_eq!(ObjectName::parse("fs/", &key), Some(n));
        assert_eq!(ObjectName::parse("", &n.key("")), Some(n));
    }

    #[test]
    fn minted_names_differ_and_carry_the_time() {
        let now = UNIX_EPOCH + Duration::from_millis(1_760_000_000_123);
        let (a, b) = (ObjectName::mint(7, now), ObjectName::mint(7, now));
        assert_ne!(a, b);
        assert_eq!((a.ino, a.minted_ms), (7, 1_760_000_000_123));
    }

    #[test]
    fn a_key_has_one_spelling() {
        let key = name().key("fs/");
        for bad in [
            key.to_uppercase().replace("FS/", "fs/"),
            format!("{key}0"),
            key[..key.len() - 1].to_string(),
            key.replacen('/', "-", 2).replacen('-', "/", 1),
            key.replace("fs/", "other/"),
            format!("x{key}"),
        ] {
            assert_eq!(ObjectName::parse("fs/", &bad), None, "{bad}");
        }
        // Another inode's objects are not under this inode's prefix.
        assert!(key.starts_with(&inode_prefix("fs/", 0x2a)));
        assert!(!key.starts_with(&inode_prefix("fs/", 0x2)));
    }

    #[test]
    fn prefixes() {
        for good in ["", "raft5fs/", "a/b-c_d.e/"] {
            validate_prefix(good).unwrap();
        }
        for bad in ["raft5fs", "/raft5fs/", "a//b/", "a b/", "ü/"] {
            assert!(validate_prefix(bad).is_err(), "{bad:?}");
        }
    }
}
