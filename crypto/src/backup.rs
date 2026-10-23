//! Backup encryption: the store's backup file, sealed so that only the
//! holder of an operator key pair can read it.
//!
//! - Each backup has its own random data key. The data key is sealed to
//!   the operator's public key (an anonymous sealed box), so the servers
//!   that take backups can seal but never open one.
//! - The backup file is cut into parts. Each part is sealed under the data
//!   key, bound to the backup's name, its index, and whether it is the
//!   last. So a part does not open in another place or another backup,
//!   and a cut-short file does not open as whole.

use crypto_box::{PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Key, aad, open, seal};

pub const BACKUP_KEY_LEN: usize = 32;

/// The operator's key pair. Only the public key goes on the servers.
pub struct BackupKeyPair {
    secret: SecretKey,
}

impl BackupKeyPair {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: [u8; BACKUP_KEY_LEN]) -> Self {
        Self {
            secret: SecretKey::from_bytes(bytes),
        }
    }

    /// The private key, to store offline.
    pub fn to_bytes(&self) -> Zeroizing<[u8; BACKUP_KEY_LEN]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public_key(&self) -> [u8; BACKUP_KEY_LEN] {
        self.secret.public_key().to_bytes()
    }

    /// Opens a data key that `seal_data_key` sealed to this key pair.
    pub fn open_data_key(&self, sealed: &[u8]) -> Result<Key, Error> {
        let what = "a backup's data key";
        let plain = Zeroizing::new(self.secret.unseal(sealed).map_err(|_| Error(what))?);
        Key::from_slice(&plain).map_err(|_| Error(what))
    }
}

/// Seals a backup's data key to the operator's `public_key`.
pub fn seal_data_key(public_key: &[u8; BACKUP_KEY_LEN], key: &Key) -> Vec<u8> {
    PublicKey::from_bytes(*public_key)
        .seal(&mut OsRng, key.as_bytes())
        .expect("sealing in-memory data can't fail")
}

fn part_aad(name: &str, index: u32, last: bool) -> Vec<u8> {
    aad(
        "backup-part",
        &[name.as_bytes(), &index.to_be_bytes(), &[last as u8]],
    )
}

/// Seals part `index` of backup `name`. `last` marks the final part.
pub fn seal_part(key: &Key, name: &str, index: u32, last: bool, plain: &[u8]) -> Vec<u8> {
    seal(key, &part_aad(name, index, last), plain)
}

pub fn open_part(
    key: &Key,
    name: &str,
    index: u32,
    last: bool,
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    open(key, &part_aad(name, index, last), sealed, "a backup part")
}

/// The SHA-256 of a stored part, to find a part damaged at rest before
/// trying to open it.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_round_trip() {
        let pair = BackupKeyPair::generate();
        let key = Key::random();
        let sealed_key = seal_data_key(&pair.public_key(), &key);
        let opened = pair.open_data_key(&sealed_key).unwrap();
        assert_eq!(opened, key);

        let part = seal_part(&key, "nightly", 3, true, b"store contents");
        assert_eq!(
            open_part(&opened, "nightly", 3, true, &part).unwrap(),
            b"store contents"
        );
    }

    #[test]
    fn a_part_opens_only_in_its_place() {
        let key = Key::random();
        let part = seal_part(&key, "nightly", 3, false, b"data");
        assert!(open_part(&key, "nightly", 4, false, &part).is_err());
        assert!(open_part(&key, "weekly", 3, false, &part).is_err());
        assert!(open_part(&key, "nightly", 3, true, &part).is_err());
        assert!(open_part(&Key::random(), "nightly", 3, false, &part).is_err());
    }

    #[test]
    fn only_the_operator_opens_the_data_key() {
        let pair = BackupKeyPair::generate();
        let sealed = seal_data_key(&pair.public_key(), &Key::random());
        assert!(BackupKeyPair::generate().open_data_key(&sealed).is_err());
        let restored = BackupKeyPair::from_bytes(*pair.to_bytes());
        assert!(restored.open_data_key(&sealed).is_ok());
    }
}
