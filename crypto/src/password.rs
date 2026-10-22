//! Turns a password into the two secrets that a login needs.
//!
//! Argon2id stretches the password into a master secret, and HKDF splits
//! that into two secrets:
//!
//! - `auth`, which the client sends to the server at login. The server
//!   stores only `verifier(auth)`, a plain hash. `auth` is already 256
//!   random bits, so a slow hash adds nothing.
//! - `kek`, which wraps the user's private key and never leaves the client.
//!   `auth` and the verifier give no information about it.
//!
//! The salt is the server's salt for the user (which it keeps and gives out
//! before login), hashed here with the user's name. So if a server gave
//! many users one salt, it still could not attack their `auth` values
//! together, because each one uses its own salt.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, KEY_LEN, Key, Reader};

pub const SALT_LEN: usize = 16;
pub const AUTH_LEN: usize = 32;
/// The shortest password that a client accepts. All of a user's keys depend
/// on the password.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Fails if `password` is shorter than `MIN_PASSWORD_LEN` characters.
pub fn check_new_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "a password must be at least {MIN_PASSWORD_LEN} characters long"
        ));
    }
    Ok(())
}

/// Argon2id's cost settings. They are stored with the salt, so new accounts
/// can use higher settings without breaking existing accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// 64 MiB and three passes: RFC 9106's second recommended setting, in
    /// one lane. Every filesystem server sees `auth`, and a bad server
    /// could test password guesses against it offline, at this cost for
    /// each guess. So the cost is as high as a login can accept.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Low-cost settings for tests, which derive keys for every login.
    pub const TESTING: Self = Self {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    /// The highest cost that a client accepts for a login: 4 GiB, 64
    /// passes, 16 lanes. This is much more than an honest account needs.
    pub const MAXIMUM: Self = Self {
        memory_kib: 4 * 1024 * 1024,
        iterations: 64,
        parallelism: 16,
    };

    /// Refuses settings below `floor` or above `MAXIMUM`. The server gives
    /// these settings at login. A client that accepted any settings could
    /// be made to stretch its password weakly, which makes the `auth` it
    /// sends easy to attack, or to use all its memory.
    pub fn check(&self, floor: KdfParams) -> Result<(), String> {
        let max = Self::MAXIMUM;
        if self.memory_kib < floor.memory_kib || self.iterations < floor.iterations {
            return Err(format!(
                "the server asked for weaker key stretching ({} KiB, {} passes) \
                 than this client accepts ({} KiB, {} passes)",
                self.memory_kib, self.iterations, floor.memory_kib, floor.iterations
            ));
        }
        if self.memory_kib > max.memory_kib
            || self.iterations > max.iterations
            || self.parallelism > max.parallelism
        {
            return Err(format!(
                "the server asked for more key stretching ({} KiB, {} passes, {} lanes) \
                 than this client allows",
                self.memory_kib, self.iterations, self.parallelism
            ));
        }
        Ok(())
    }

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

/// The two secrets from one password. They are erased from memory when
/// dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasswordKeys {
    pub auth: [u8; AUTH_LEN],
    pub kek: Key,
}

/// The salt for Argon2: the server's salt, bound to the account's name.
fn user_salt(user: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"raft5fs/salt");
    hash.update((user.len() as u32).to_be_bytes());
    hash.update(user.as_bytes());
    hash.update(salt);
    hash.finalize().into()
}

/// Stretches `user`'s `password`. This is slow on purpose (see
/// `KdfParams`). Returns an error for parameters that Argon2 cannot use,
/// which only a changed record would have.
pub fn derive(
    password: &[u8],
    user: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<PasswordKeys, Error> {
    let salt = user_salt(user, salt);
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error("the account's KDF parameters"))?;
    let mut master = [0; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(password, &salt, &mut master)
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

/// The hash that the server keeps to check an `auth` value.
pub fn verifier(auth: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"raft5fs/verifier");
    hash.update(auth);
    hash.finalize().into()
}

/// Whether `auth` matches `stored`. The time taken does not depend on where
/// they differ.
pub fn check_verifier(auth: &[u8], stored: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    stored.len() == 32 && bool::from(verifier(auth).ct_eq(stored))
}

/// The salt that Prelogin gives for an account that does not exist. It is
/// made from a server secret and the name, so every server always gives the
/// same salt, like a real one. A stranger cannot tell a real account from a
/// missing one.
pub fn decoy_salt(server_secret: &[u8], user: &str) -> [u8; SALT_LEN] {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(server_secret).expect("HMAC takes any key length");
    mac.update(b"raft5fs/decoy-salt/");
    mac.update(user.as_bytes());
    let digest = mac.finalize().into_bytes();
    digest[..SALT_LEN].try_into().unwrap()
}

/// A one-time enrolment code: 128 random bits, as 32 hex digits.
pub fn new_enrolment_code() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash of an enrolment code that the server keeps. A plain hash is
/// enough, because the code is random and not chosen by a person.
pub fn enrolment_code_hash(code: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"raft5fs/enrolment-code");
    hash.update(code.trim().to_ascii_lowercase().as_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_salts_are_stable_per_user_and_secret() {
        assert_eq!(decoy_salt(b"s", "eve"), decoy_salt(b"s", "eve"));
        assert_ne!(decoy_salt(b"s", "eve"), decoy_salt(b"s", "mallory"));
        assert_ne!(decoy_salt(b"s", "eve"), decoy_salt(b"t", "eve"));
    }

    #[test]
    fn enrolment_codes_are_fresh_and_hash_forgivingly() {
        let code = new_enrolment_code();
        assert_eq!(code.len(), 32);
        assert_ne!(code, new_enrolment_code());
        assert_eq!(
            enrolment_code_hash(&code),
            enrolment_code_hash(&format!(" {} \n", code.to_uppercase()))
        );
        assert_ne!(
            enrolment_code_hash(&code),
            enrolment_code_hash(&new_enrolment_code())
        );
    }

    #[test]
    fn one_password_and_salt_always_give_the_same_keys() {
        let salt = new_salt();
        let a = derive(b"hunter2", "u", &salt, KdfParams::TESTING).unwrap();
        let b = derive(b"hunter2", "u", &salt, KdfParams::TESTING).unwrap();
        assert_eq!(a.auth, b.auth);
        assert_eq!(a.kek, b.kek);
    }

    #[test]
    fn auth_and_kek_are_unrelated_and_depend_on_password_and_salt() {
        let salt = new_salt();
        let keys = derive(b"hunter2", "u", &salt, KdfParams::TESTING).unwrap();
        assert_ne!(&keys.auth, keys.kek.as_bytes());
        let other_password = derive(b"hunter3", "u", &salt, KdfParams::TESTING).unwrap();
        assert_ne!(keys.auth, other_password.auth);
        let other_salt = derive(b"hunter2", "u", &new_salt(), KdfParams::TESTING).unwrap();
        assert_ne!(keys.kek, other_salt.kek);
        // Two users with the same server salt still get different keys.
        let other_user = derive(b"hunter2", "v", &salt, KdfParams::TESTING).unwrap();
        assert_ne!(keys.auth, other_user.auth);
        assert_ne!(keys.kek, other_user.kek);
    }

    #[test]
    fn the_verifier_accepts_only_its_auth() {
        let keys = derive(b"pw", "u", &new_salt(), KdfParams::TESTING).unwrap();
        let stored = verifier(&keys.auth);
        assert!(check_verifier(&keys.auth, &stored));
        assert!(!check_verifier(&[0; AUTH_LEN], &stored));
        assert!(!check_verifier(&keys.auth, &stored[..31]));
    }

    #[test]
    fn params_outside_the_floor_and_ceiling_are_refused() {
        let floor = KdfParams::DEFAULT;
        floor.check(floor).unwrap();
        KdfParams::MAXIMUM.check(floor).unwrap();
        assert!(KdfParams::TESTING.check(floor).is_err());
        KdfParams::TESTING.check(KdfParams::TESTING).unwrap();
        let fewer_passes = KdfParams {
            iterations: 1,
            ..floor
        };
        assert!(fewer_passes.check(floor).is_err());
        for too_much in [
            KdfParams {
                memory_kib: u32::MAX,
                ..floor
            },
            KdfParams {
                iterations: u32::MAX,
                ..floor
            },
            KdfParams {
                parallelism: u32::MAX,
                ..floor
            },
        ] {
            assert!(too_much.check(floor).is_err());
        }
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
        assert!(derive(b"pw", "u", &new_salt(), zero).is_err());
    }

    #[test]
    fn short_passwords_are_refused() {
        assert!(check_new_password("short").is_err());
        assert!(check_new_password("elevenchars").is_err());
        check_new_password("twelve chars").unwrap();
        // The limit counts characters, not bytes.
        assert!(check_new_password("ééééééééééé").is_err());
    }
}
