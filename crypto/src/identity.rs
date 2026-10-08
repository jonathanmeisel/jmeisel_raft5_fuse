//! Users' key pairs, and grants: node keys sealed to a user.
//!
//! A user's private key is random, not derived from the password, so a
//! password change only re-wraps it (`wrap`) rather than changing who
//! the user is to every grant already sealed to them.
//!
//! Grants are authenticated boxes from the granter to the grantee
//! (X25519 between their two key pairs, then XChaCha20-Poly1305): only the
//! grantee opens one, and opening it proves which key pair made it. The
//! granter's name travels in the clear in front, so the grantee knows
//! whose public key to open it with -- and inside too, with the grantee's
//! public key and the inode, so a box can't be passed off as from someone
//! else, to someone else, or of another inode. A grant is only as good as
//! the grantee's trust in its sender's public key: a malicious server can
//! still make up a user and grant from it, but not pass that off as from
//! anyone the grantee has pinned.
//!
//! Labels -- what a grant shows up as -- are only cosmetic, so they stay
//! anonymous sealed boxes.

use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::{Error, KEY_LEN, Key, Reader, aad, open, put_bytes, seal};

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

    /// Opens a grant of `ino` made to this identity by the holder of
    /// `sender_key` -- whose name the grant gives (`grant_sender`): the
    /// node's key and which version of it the grant holds. Fails unless
    /// `sender_key` really made it, for this identity, of `ino`.
    pub fn open_grant(
        &self,
        sender_key: &[u8; PUBLIC_KEY_LEN],
        ino: u64,
        sealed: &[u8],
    ) -> Result<(u32, Key), Error> {
        let what = "a grant";
        let mut r = Reader(sealed);
        let sender = r.bytes(what)?;
        let nonce = r.take(NONCE_LEN, what)?;
        let boxed = r.0;
        let plain = zeroize::Zeroizing::new(
            ChaChaBox::new(&PublicKey::from_bytes(*sender_key), &self.secret)
                .decrypt(nonce.into(), boxed)
                .map_err(|_| Error(what))?,
        );
        let mut r = Reader(&plain);
        if r.take(GRANT_DOMAIN.len(), what)? != GRANT_DOMAIN
            || r.bytes(what)? != sender
            || r.take(PUBLIC_KEY_LEN, what)? != self.public_key()
            || r.take(8, what)? != ino.to_be_bytes()
        {
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

const NONCE_LEN: usize = 24;
const GRANT_DOMAIN: &[u8] = b"raft5fs/grant";

/// `ino`'s key at `version`, from `sender` (whose account is
/// `sender_name`) to the holder of `public_key`. See the module doc.
pub fn seal_grant(
    sender: &Identity,
    sender_name: &str,
    public_key: &[u8; PUBLIC_KEY_LEN],
    ino: u64,
    version: u32,
    key: &Key,
) -> Vec<u8> {
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(128));
    plain.extend_from_slice(GRANT_DOMAIN);
    put_bytes(&mut plain, sender_name.as_bytes());
    plain.extend_from_slice(public_key);
    plain.extend_from_slice(&ino.to_be_bytes());
    plain.extend_from_slice(&version.to_be_bytes());
    plain.extend_from_slice(key.as_bytes());
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let boxed = ChaChaBox::new(&PublicKey::from_bytes(*public_key), &sender.secret)
        .encrypt(&nonce, plain.as_slice())
        .expect("sealing in-memory data can't fail");
    let mut out = Vec::with_capacity(4 + sender_name.len() + NONCE_LEN + boxed.len());
    put_bytes(&mut out, sender_name.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&boxed);
    out
}

/// Whose account a grant says it is from: the name to fetch the public
/// key to open it with. Unproven until `open_grant` succeeds.
pub fn grant_sender(sealed: &[u8]) -> Result<&str, Error> {
    let what = "a grant's sender";
    let name = Reader(sealed).bytes(what)?;
    std::str::from_utf8(name).map_err(|_| Error(what))
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
    fn a_grant_opens_for_its_grantee_inode_and_sender_only() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let key = Key::random();
        let grant = seal_grant(&carol, "carol", &alice.public_key(), 42, 3, &key);
        assert_eq!(grant_sender(&grant).unwrap(), "carol");
        let (version, opened) = alice.open_grant(&carol.public_key(), 42, &grant).unwrap();
        assert_eq!((version, opened), (3, key));
        assert!(bob.open_grant(&carol.public_key(), 42, &grant).is_err());
        assert!(alice.open_grant(&carol.public_key(), 43, &grant).is_err());
        assert!(
            alice.open_grant(&bob.public_key(), 42, &grant).is_err(),
            "only its real sender's key opens it"
        );
    }

    #[test]
    fn a_grant_cant_be_relabelled_or_reflected() {
        let alice = Identity::generate();
        let carol = Identity::generate();
        let key = Key::random();
        let grant = seal_grant(&carol, "carol", &alice.public_key(), 42, 3, &key);
        // The same box under another sender's name in front.
        let mut relabelled = Vec::new();
        put_bytes(&mut relabelled, b"dave");
        relabelled.extend_from_slice(&grant[4 + "carol".len()..]);
        assert!(
            alice
                .open_grant(&carol.public_key(), 42, &relabelled)
                .is_err()
        );
        // Carol and alice share one box key either way round, so a grant
        // from alice to carol would open for alice "from carol" -- but it
        // names its sender and grantee inside.
        let back = seal_grant(&alice, "alice", &carol.public_key(), 42, 3, &key);
        let mut reflected = Vec::new();
        put_bytes(&mut reflected, b"carol");
        reflected.extend_from_slice(&back[4 + "alice".len()..]);
        assert!(
            alice
                .open_grant(&carol.public_key(), 42, &reflected)
                .is_err()
        );
        assert!(alice.open_grant(&carol.public_key(), 42, &back).is_err());
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
