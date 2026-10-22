//! Users' key pairs, and grants: node keys sealed to a user.
//!
//! A user's private key is random, not derived from the password. So a
//! password change only wraps it again (`wrap`), and grants already sealed
//! to the user stay valid.
//!
//! A grant is an authenticated box from the granter to the grantee (X25519
//! between their key pairs, then XChaCha20-Poly1305). Only the grantee can
//! open it, and opening it proves which key pair made it.
//!
//! - The granter's name is in clear text at the start, so the grantee knows
//!   which public key opens the box.
//! - The granter's name is also inside the box, with the grantee's public
//!   key and the inode. So the server cannot show a box as from another
//!   user, to another user, or for another inode.
//!
//! A grant is only as safe as the grantee's trust in the sender's public
//! key. A malicious server can make up a user and grant from it, but it
//! cannot show that grant as from a user the grantee has pinned.
//!
//! Labels (the names that grants show as) are only for display, so they are
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

    /// Seals the private key under `kek`, for the server to keep. The
    /// result is bound to `user`, so the server cannot give one account's
    /// private key to another account.
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
    /// `sender_key`. The grant names its sender (`grant_sender`).
    ///
    /// Returns the node's key and the key version that the grant holds.
    /// Fails unless `sender_key` made the grant, for this identity, of
    /// `ino`.
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

    /// Opens the label that a grant of `ino` shows as.
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

/// Seals `ino`'s key at `version` from `sender` (whose account is
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

/// The account that a grant says it comes from: the name to get the public
/// key that opens it. This is not proven until `open_grant` succeeds.
pub fn grant_sender(sealed: &[u8]) -> Result<&str, Error> {
    let what = "a grant's sender";
    let name = Reader(sealed).bytes(what)?;
    std::str::from_utf8(name).map_err(|_| Error(what))
}

/// Seals the label that a grant of `ino` shows as in the grantee's root.
/// The grantee cannot read the node's real name, which is sealed under its
/// parent's key.
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

/// How many words `fingerprint_words` gives for a key.
pub const FINGERPRINT_WORDS: usize = 12;

/// A public key's fingerprint as words, for people to read to each other on
/// another channel. It is the first 132 bits of the key's SHA-256, 11 bits
/// for each word from the BIP-39 English list. That is a little more than
/// the 128 bits of the hex form, and much easier to compare by phone.
pub fn fingerprint_words(public_key: &[u8; PUBLIC_KEY_LEN]) -> String {
    let digest = Sha256::digest(public_key);
    (0..FINGERPRINT_WORDS)
        .map(|i| crate::wordlist::WORDS[bits_at(&digest, i * 11, 11) as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Reads `n` bits of `bytes` from bit `start`, most significant bit first.
fn bits_at(bytes: &[u8], start: usize, n: usize) -> u32 {
    (start..start + n).fold(0, |acc, bit| {
        (acc << 1) | u32::from((bytes[bit / 8] >> (7 - bit % 8)) & 1)
    })
}

/// Whether `written` is `public_key`'s fingerprint, in either form:
/// `fingerprint`'s 32 hex digits, or `fingerprint_words`' 12 words. Case,
/// spaces, and hyphens do not matter.
///
/// Text in neither form returns an error, not a mismatch, so a typo is not
/// taken as a different key.
pub fn fingerprint_matches(
    public_key: &[u8; PUBLIC_KEY_LEN],
    written: &str,
) -> Result<bool, String> {
    let lower = written.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| c.is_whitespace() || c == '-' || c == ',')
        .filter(|w| !w.is_empty())
        .collect();
    let digest = Sha256::digest(public_key);
    let hex: String = words.concat();
    if hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let theirs = (0..16)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        return Ok(theirs == digest[..16]);
    }
    if words.len() != FINGERPRINT_WORDS {
        return Err(format!(
            "a fingerprint is {FINGERPRINT_WORDS} words, or 32 hex digits"
        ));
    }
    let mut matches = true;
    for (i, word) in words.iter().enumerate() {
        let Some(index) = crate::wordlist::WORDS.iter().position(|w| w == word) else {
            return Err(format!("{word:?} isn't a fingerprint word"));
        };
        matches &= index as u32 == bits_at(&digest, i * 11, 11);
    }
    Ok(matches)
}

/// A short digest of a public key, for people to compare on another
/// channel: `ab12 cd34 ...`, the first 16 bytes of SHA-256 in groups of
/// two. `fingerprint_words` gives an easier form.
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
        // The same box, with another sender's name at the start.
        let mut relabelled = Vec::new();
        put_bytes(&mut relabelled, b"dave");
        relabelled.extend_from_slice(&grant[4 + "carol".len()..]);
        assert!(
            alice
                .open_grant(&carol.public_key(), 42, &relabelled)
                .is_err()
        );
        // Carol and alice share one box key in both directions. So a grant
        // from alice to carol would open for alice as "from carol", but the
        // box names its sender and grantee inside.
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
    fn the_word_list_is_the_bip39_one() {
        use crate::wordlist::WORDS;
        assert_eq!((WORDS[0], WORDS[2047]), ("abandon", "zoo"));
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]), "sorted, no repeats");
        let mut prefixes: Vec<&str> = WORDS.iter().map(|w| &w[..w.len().min(4)]).collect();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 2048, "no two share four letters");
    }

    #[test]
    fn a_fingerprint_matches_in_either_form_and_only_its_key() {
        let a = Identity::generate().public_key();
        let b = Identity::generate().public_key();
        let words = fingerprint_words(&a);
        assert_eq!(words.split(' ').count(), FINGERPRINT_WORDS);
        assert_eq!(fingerprint_words(&a), words, "stable");
        assert!(fingerprint_matches(&a, &words).unwrap());
        assert!(fingerprint_matches(&a, &words.to_uppercase().replace(' ', "-")).unwrap());
        assert!(fingerprint_matches(&a, &fingerprint(&a)).unwrap());
        assert!(fingerprint_matches(&a, &fingerprint(&a).replace(' ', "")).unwrap());
        assert!(!fingerprint_matches(&b, &words).unwrap());
        assert!(!fingerprint_matches(&b, &fingerprint(&a)).unwrap());
        // One word changed to another real word is a mismatch, not a match.
        let mut one_off: Vec<&str> = words.split(' ').collect();
        one_off[11] = if one_off[11] == "zoo" {
            "abandon"
        } else {
            "zoo"
        };
        assert!(!fingerprint_matches(&a, &one_off.join(" ")).unwrap());
        // Text in neither form is an error, so a typo is not read as
        // another key.
        assert!(fingerprint_matches(&a, "not a fingerprint").is_err());
        let typo = words.replacen(one_off[0], "zzzz", 1);
        assert!(fingerprint_matches(&a, &typo).is_err());
        assert!(fingerprint_matches(&a, &fingerprint(&a)[..20]).is_err());
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
