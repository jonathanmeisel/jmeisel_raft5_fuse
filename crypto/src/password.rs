//! From a password to the two secrets a login needs.
//!
//! Argon2id stretches the password into a master secret, and HKDF splits
//! that into the two below. The salt is the server's per-user one (which
//! it keeps and hands out before login) hashed with the user's name, here:
//! a server that handed many users one salt still couldn't crack their
//! `auth`s together, since each is stretched with a salt of its own.
//!
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
/// The shortest password a client will set. The password is what every
/// key a user holds comes down to.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Whether `password` is long enough to set (see `MIN_PASSWORD_LEN`), in
/// characters.
pub fn check_new_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "a password must be at least {MIN_PASSWORD_LEN} characters long"
        ));
    }
    Ok(())
}

/// Argon2id's cost settings, kept beside the salt so they can be raised
/// for new enrolments without breaking existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// 64 MiB, three passes: RFC 9106's second recommended setting, in
    /// one lane. Every filesystem server sees `auth`, and a server that
    /// shouldn't could test password guesses against it offline at this
    /// cost per guess, so it is set as high as a login can bear.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Cheap settings for tests, which derive keys for every login.
    pub const TESTING: Self = Self {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    /// The most a client will spend on a login: 4 GiB, 64 passes, 16
    /// lanes -- far above anything an honest account needs.
    pub const MAXIMUM: Self = Self {
        memory_kib: 4 * 1024 * 1024,
        iterations: 64,
        parallelism: 16,
    };

    /// Refuses settings outside `floor` and `MAXIMUM`. The server hands
    /// these out at login, so a client that took them as given could be
    /// talked into stretching its password cheaply -- making the `auth`
    /// it sends back fast to brute-force -- or into exhausting its memory.
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

/// What one password yields. Wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasswordKeys {
    pub auth: [u8; AUTH_LEN],
    pub kek: Key,
}

/// The salt Argon2 is given: the server's, bound to the account's name.
fn user_salt(user: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"raft5fs/salt");
    hash.update((user.len() as u32).to_be_bytes());
    hash.update(user.as_bytes());
    hash.update(salt);
    hash.finalize().into()
}

/// Stretches `user`'s `password`. Slow on purpose (see `KdfParams`);
/// unusable parameters -- which only a tampered record would hold -- are
/// an error.
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

/// The salt Prelogin hands out for an account that doesn't exist: made up
/// from a server secret and the name, so it is the same on every server
/// and every ask, like a real one -- a stranger can't tell the two apart.
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

/// What the server keeps of an enrolment code. A plain hash is enough:
/// the code is random, not something a person chose.
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
        // One server salt handed to two users still stretches differently.
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
        // Characters, not bytes.
        assert!(check_new_password("ééééééééééé").is_err());
    }
}
