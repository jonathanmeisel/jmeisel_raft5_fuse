//! From a password to the two secrets a login needs.
//!
//! Argon2id stretches the password (with a per-user salt the server keeps
//! and hands out before login) into a master secret, and HKDF splits that
//! into:
//!
//! - `auth`, sent to the server at login. The server stores only
//!   `verifier(auth)`, a plain hash: `auth` is already 256 uniformly
//!   random bits, so there is nothing left to slow down.
//! - `kek`, which wraps the user's private key and never leaves the
//!   client. Knowing `auth` (or the verifier) gives no handle on it.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, KEY_LEN, Key, Reader};

pub const SALT_LEN: usize = 16;
pub const AUTH_LEN: usize = 32;

/// Argon2id's cost settings, kept beside the salt so they can be raised
/// for new enrolments without breaking existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// OWASP's suggested Argon2id settings: 19 MiB, two passes.
    pub const DEFAULT: Self = Self {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };

    /// Cheap settings for tests, which derive keys for every login.
    pub const TESTING: Self = Self {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    pub fn encode(&self) -> [u8; 12] {
        let mut out = [0; 12];
        out[..4].copy_from_slice(&self.memory_kib.to_be_bytes());
        out[4..8].copy_from_slice(&self.iterations.to_be_bytes());
        out[8..].copy_from_slice(&self.parallelism.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let what = "KDF parameters";
        let mut r = Reader(bytes);
        let params = Self {
            memory_kib: r.u32(what)?,
            iterations: r.u32(what)?,
            parallelism: r.u32(what)?,
        };
        r.finish(what)?;
        Ok(params)
    }
}

pub fn new_salt() -> [u8; SALT_LEN] {
    let mut salt = [0; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// What one password yields. Wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasswordKeys {
    pub auth: [u8; AUTH_LEN],
    pub kek: Key,
}

/// Stretches `password`. Slow on purpose (see `KdfParams`); unusable
/// parameters -- which only a tampered record would hold -- are an error.
pub fn derive(password: &[u8], salt: &[u8], params: KdfParams) -> Result<PasswordKeys, Error> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error("the account's KDF parameters"))?;
    let mut master = [0; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(password, salt, &mut master)
        .map_err(|_| Error("the account's KDF parameters"))?;
    let hkdf = Hkdf::<Sha256>::new(None, &master);
    master.zeroize();
    let mut keys = PasswordKeys {
        auth: [0; AUTH_LEN],
        kek: Key::from_bytes([0; KEY_LEN]),
    };
    hkdf.expand(b"raft5fs/auth", &mut keys.auth)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    hkdf.expand(b"raft5fs/kek", &mut keys.kek.0)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Ok(keys)
}

/// What the server keeps to check an `auth` against.
pub fn verifier(auth: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"raft5fs/verifier");
    hash.update(auth);
    hash.finalize().into()
}

/// Whether `auth` matches `stored`, in time that doesn't depend on where
/// they differ.
pub fn check_verifier(auth: &[u8], stored: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    stored.len() == 32 && bool::from(verifier(auth).ct_eq(stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_password_and_salt_always_give_the_same_keys() {
        let salt = new_salt();
        let a = derive(b"hunter2", &salt, KdfParams::TESTING).unwrap();
        let b = derive(b"hunter2", &salt, KdfParams::TESTING).unwrap();
        assert_eq!(a.auth, b.auth);
        assert_eq!(a.kek, b.kek);
    }

    #[test]
    fn auth_and_kek_are_unrelated_and_depend_on_password_and_salt() {
        let salt = new_salt();
        let keys = derive(b"hunter2", &salt, KdfParams::TESTING).unwrap();
        assert_ne!(&keys.auth, keys.kek.as_bytes());
        let other_password = derive(b"hunter3", &salt, KdfParams::TESTING).unwrap();
        assert_ne!(keys.auth, other_password.auth);
        let other_salt = derive(b"hunter2", &new_salt(), KdfParams::TESTING).unwrap();
        assert_ne!(keys.kek, other_salt.kek);
    }

    #[test]
    fn the_verifier_accepts_only_its_auth() {
        let keys = derive(b"pw", &new_salt(), KdfParams::TESTING).unwrap();
        let stored = verifier(&keys.auth);
        assert!(check_verifier(&keys.auth, &stored));
        assert!(!check_verifier(&[0; AUTH_LEN], &stored));
        assert!(!check_verifier(&keys.auth, &stored[..31]));
    }

    #[test]
    fn params_round_trip_and_absurd_ones_are_refused() {
        let p = KdfParams::DEFAULT;
        assert_eq!(KdfParams::decode(&p.encode()).unwrap(), p);
        assert!(KdfParams::decode(&[0; 11]).is_err());
        let zero = KdfParams {
            memory_kib: 0,
            iterations: 0,
            parallelism: 0,
        };
        assert!(derive(b"pw", &new_salt(), zero).is_err());
    }
}
