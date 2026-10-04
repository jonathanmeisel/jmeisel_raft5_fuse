//! Users' key pairs, and grants: node keys sealed to a user.
//!
//! A user's private key is random, not derived from the password, so a
//! password change only re-wraps it (`wrap`) rather than changing who
//! the user is to every grant already sealed to them.
//!
//! Grants are libsodium-style sealed boxes: anyone with the public key can
//! make one, only the private key opens it. They carry no sender, so a
//! grant shows the key works, not who gave it -- a malicious server could
//! seal its own key to a user and present a fabricated tree. What it can't
//! do is open any genuine grant.

use crypto_box::{PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::{Error, KEY_LEN, Key, Reader, aad, open, seal};

pub const PUBLIC_KEY_LEN: usize = 32;

/// A user's key pair.
pub struct Identity {
    secret: SecretKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(&mut OsRng),
        }
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.secret.public_key().to_bytes()
    }

    /// The private key sealed under `kek`, for the server to keep. Bound
    /// to `user`, so one account's blob can't be handed to another.
    pub fn wrap(&self, kek: &Key, user: &str) -> Vec<u8> {
        let secret = zeroize::Zeroizing::new(self.secret.to_bytes());
        seal(kek, &aad("identity", &[user.as_bytes()]), secret.as_ref())
    }

    pub fn unwrap(kek: &Key, user: &str, wrapped: &[u8]) -> Result<Self, Error> {
        let what = "the account's private key";
        let bytes = zeroize::Zeroizing::new(open(
            kek,
            &aad("identity", &[user.as_bytes()]),
            wrapped,
            what,
        )?);
        let bytes: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| Error(what))?;
        Ok(Self {
            secret: SecretKey::from_bytes(bytes),
        })
    }

    /// Opens a grant of `ino` sealed to this identity: the node's key and
    /// which version of it the grant holds.
    pub fn open_grant(&self, ino: u64, sealed: &[u8]) -> Result<(u32, Key), Error> {
        let what = "a grant";
        let plain = zeroize::Zeroizing::new(self.unseal(sealed, what)?);
        let mut r = Reader(&plain);
        if r.take(8, what)? != ino.to_be_bytes() {
            return Err(Error(what));
        }
        let version = r.u32(what)?;
        let key = Key::from_slice(r.take(KEY_LEN, what)?)?;
        r.finish(what)?;
        Ok((version, key))
    }

    /// Opens the name a grant of `ino` was given.
    pub fn open_label(&self, ino: u64, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        let what = "a grant's name";
        let plain = self.unseal(sealed, what)?;
        let mut r = Reader(&plain);
        if r.take(8, what)? != ino.to_be_bytes() {
            return Err(Error(what));
        }
        Ok(r.0.to_vec())
    }

    fn unseal(&self, sealed: &[u8], what: &'static str) -> Result<Vec<u8>, Error> {
        self.secret.unseal(sealed).map_err(|_| Error(what))
    }
}

/// `ino`'s key at `version`, sealed to the holder of `public_key`. The
/// inode goes inside, so a grant moved onto another inode won't open.
pub fn seal_grant(public_key: &[u8; PUBLIC_KEY_LEN], ino: u64, version: u32, key: &Key) -> Vec<u8> {
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(8 + 4 + KEY_LEN));
    plain.extend_from_slice(&ino.to_be_bytes());
    plain.extend_from_slice(&version.to_be_bytes());
    plain.extend_from_slice(key.as_bytes());
    seal_to(public_key, &plain)
}

/// The name a grant of `ino` shows up as in the grantee's root, sealed to
/// them: they can't read the node's real name, which is encrypted under
/// its parent's key.
pub fn seal_label(public_key: &[u8; PUBLIC_KEY_LEN], ino: u64, name: &[u8]) -> Vec<u8> {
    let mut plain = ino.to_be_bytes().to_vec();
    plain.extend_from_slice(name);
    seal_to(public_key, &plain)
}

fn seal_to(public_key: &[u8; PUBLIC_KEY_LEN], plain: &[u8]) -> Vec<u8> {
    PublicKey::from_bytes(*public_key)
        .seal(&mut OsRng, plain)
        .expect("sealing in-memory data can't fail")
}

/// A short, readable digest of a public key, for people to compare out of
/// band: `ab12 cd34 ...`, 16 bytes of SHA-256 in groups of two.
pub fn fingerprint(public_key: &[u8; PUBLIC_KEY_LEN]) -> String {
    let digest = Sha256::digest(public_key);
    digest[..16]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrapped_identity_opens_only_with_its_kek_and_user() {
        let id = Identity::generate();
        let kek = Key::random();
        let wrapped = id.wrap(&kek, "alice");
        let back = Identity::unwrap(&kek, "alice", &wrapped).unwrap();
        assert_eq!(back.public_key(), id.public_key());
        assert!(Identity::unwrap(&Key::random(), "alice", &wrapped).is_err());
        assert!(Identity::unwrap(&kek, "bob", &wrapped).is_err());
    }

    #[test]
    fn a_grant_opens_for_its_grantee_and_inode_only() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let key = Key::random();
        let grant = seal_grant(&alice.public_key(), 42, 3, &key);
        let (version, opened) = alice.open_grant(42, &grant).unwrap();
        assert_eq!((version, opened), (3, key));
        assert!(bob.open_grant(42, &grant).is_err());
        assert!(alice.open_grant(43, &grant).is_err());
    }

    #[test]
    fn a_label_opens_for_its_grantee_and_inode_only() {
        let alice = Identity::generate();
        let label = seal_label(&alice.public_key(), 7, b"photos");
        assert_eq!(alice.open_label(7, &label).unwrap(), b"photos");
        assert!(alice.open_label(8, &label).is_err());
        assert!(Identity::generate().open_label(7, &label).is_err());
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let a = Identity::generate().public_key();
        let b = Identity::generate().public_key();
        assert_eq!(fingerprint(&a), fingerprint(&a));
        assert_ne!(fingerprint(&a), fingerprint(&b));
        assert_eq!(fingerprint(&a).len(), 8 * 4 + 7);
    }
}
