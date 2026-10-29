//! Client-side encryption for raft5fs. The client makes and uses every
//! secret. The servers and the store only hold what this crate outputs.
//!
//! - `password`: turns one password into two unrelated secrets: an `auth`
//!   value that the client logs in with, and a key-encryption key that
//!   never leaves the client. A server that sees `auth` learns nothing
//!   about the other secret.
//! - `identity`: each user's X25519 key pair, with the private key wrapped
//!   under the key-encryption key. Also grants: a node's key sealed to one
//!   user's public key.
//! - `node`: each inode's key record. A node's current key is wrapped under
//!   its parent's key. Each rotation wraps the old key under the new one,
//!   so a key opens all older versions and no newer one.
//! - `data`: file chunks and directory entry names, encrypted under their
//!   node's key.
//! - `backup`: the store backup file, sealed to an operator key pair.
//! - `grantees`: the users a node is granted to, sealed under its key. The
//!   server cannot add a user that a rotation would then seal the key to.
//!
//! Each ciphertext is bound (as associated data) to its purpose, its inode,
//! and its versions. So the server cannot use one ciphertext in place of
//! another: a chunk moved to another index, or a wrapped key copied to
//! another inode, does not open.

pub mod backup;
pub mod data;
pub mod grantees;
pub mod identity;
pub mod node;
pub mod password;
pub mod pins;
mod wordlist;

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// The bytes that sealing adds to a plaintext: the nonce before it and the
/// tag after it.
pub const AEAD_OVERHEAD: usize = NONCE_LEN + 16;

/// A symmetric key. It is erased from memory when dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn random() -> Self {
        let mut bytes = [0; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error("a key of the wrong length"))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

/// A ciphertext did not open or parse: a wrong key, a changed or moved
/// ciphertext, or bad data. The message tells what was being opened, but
/// not why it failed, on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot decrypt {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Associated data: a purpose label, then the fields that bind a ciphertext
/// to its place. Each field has a length prefix, so fields cannot be
/// shifted into each other.
fn aad(purpose: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"raft5fs/");
    out.extend_from_slice(purpose.as_bytes());
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// Returns `nonce ‖ ciphertext ‖ tag`, with a new random nonce. XChaCha's
/// 24-byte nonces make random nonces safe for any number of messages under
/// one key.
fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption can't fail for in-memory input");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

fn open(key: &Key, aad: &[u8], sealed: &[u8], what: &'static str) -> Result<Vec<u8>, Error> {
    if sealed.len() < AEAD_OVERHEAD {
        return Err(Error(what));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
    XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error(what))
}

/// A cursor over an encoded record for the decoders. Each step returns an
/// error on short input, and does not panic.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error(what));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4, what)?.try_into().unwrap()))
    }

    /// Reads a field written by `put_bytes`: its length, then its bytes.
    fn bytes(&mut self, what: &'static str) -> Result<&'a [u8], Error> {
        let n = self.u32(what)? as usize;
        self.take(n, what)
    }

    fn finish(self, what: &'static str) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error(what))
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_message_opens_only_with_its_key_and_aad() {
        let key = Key::random();
        let sealed = seal(&key, b"here", b"secret");
        assert_eq!(open(&key, b"here", &sealed, "t").unwrap(), b"secret");
        assert!(open(&key, b"there", &sealed, "t").is_err());
        assert!(open(&Key::random(), b"here", &sealed, "t").is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"here", &tampered, "t").is_err());
        assert!(open(&key, b"here", &sealed[..10], "t").is_err());
    }

    #[test]
    fn two_seals_of_one_message_differ() {
        let key = Key::random();
        assert_ne!(seal(&key, b"", b"same"), seal(&key, b"", b"same"));
    }

    #[test]
    fn aad_fields_cannot_be_reshuffled_into_each_other() {
        assert_ne!(aad("p", &[b"ab", b"c"]), aad("p", &[b"a", b"bc"]));
    }
}
