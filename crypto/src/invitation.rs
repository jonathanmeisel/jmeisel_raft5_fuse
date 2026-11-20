//! The proof that ties a new account's key to the invitation it enrolled
//! with, so the person who invited them can trust that key without
//! comparing safety codes.
//!
//! - The inviter's client makes a secret and puts it in the invitation,
//!   which travels to the new user on a private channel. The servers never
//!   see it.
//! - The new user's client sends `invite_proof` of its new public key with
//!   the enrollment. The servers keep it.
//! - The inviter's client checks the proof against the key that the servers
//!   give for the new user. A server that gives another key can't make a
//!   proof for it without the secret.

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::identity::PUBLIC_KEY_LEN;
use crate::put_bytes;

/// The length of an invitation's secret and of a proof.
pub const INVITE_SECRET_LEN: usize = 32;
pub const INVITE_PROOF_LEN: usize = 32;

const DOMAIN: &[u8] = b"raft5fs/invite-proof";

/// A new secret for one invitation.
pub fn new_invite_secret() -> [u8; INVITE_SECRET_LEN] {
    let mut secret = [0; INVITE_SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// Proves that `public_key` is the key that `user` enrolled with, using the
/// invitation from `inviter` that held `secret`.
pub fn invite_proof(
    secret: &[u8; INVITE_SECRET_LEN],
    user: &str,
    inviter: &str,
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> [u8; INVITE_PROOF_LEN] {
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, secret);
    let mut key = zeroize::Zeroizing::new([0; 32]);
    hkdf.expand(DOMAIN, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref()).expect("HMAC takes any key length");
    let mut msg = DOMAIN.to_vec();
    put_bytes(&mut msg, user.as_bytes());
    put_bytes(&mut msg, inviter.as_bytes());
    msg.extend_from_slice(public_key);
    mac.update(&msg);
    mac.finalize().into_bytes().into()
}

/// Whether `proof` is `invite_proof` of these values. The comparison takes
/// the same time whatever the proof holds.
pub fn check_invite_proof(
    secret: &[u8; INVITE_SECRET_LEN],
    user: &str,
    inviter: &str,
    public_key: &[u8; PUBLIC_KEY_LEN],
    proof: &[u8],
) -> bool {
    let expected = invite_proof(secret, user, inviter, public_key);
    proof.len() == INVITE_PROOF_LEN && bool::from(expected.ct_eq(proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_checks_only_for_its_own_values() {
        let secret = new_invite_secret();
        let key = [7; PUBLIC_KEY_LEN];
        let proof = invite_proof(&secret, "carol", "alice", &key);
        assert!(check_invite_proof(&secret, "carol", "alice", &key, &proof));
        assert!(!check_invite_proof(
            &new_invite_secret(),
            "carol",
            "alice",
            &key,
            &proof
        ));
        assert!(!check_invite_proof(&secret, "dave", "alice", &key, &proof));
        assert!(!check_invite_proof(&secret, "carol", "bob", &key, &proof));
        assert!(!check_invite_proof(
            &secret,
            "carol",
            "alice",
            &[8; PUBLIC_KEY_LEN],
            &proof
        ));
        assert!(!check_invite_proof(
            &secret,
            "carol",
            "alice",
            &key,
            &proof[..31]
        ));
        assert!(!check_invite_proof(&secret, "carol", "alice", &key, &[]));
    }

    /// Fields can't shift into each other: "ca"+"rolalice" is not
    /// "carol"+"alice".
    #[test]
    fn names_are_bound_with_their_lengths() {
        let secret = new_invite_secret();
        let key = [7; PUBLIC_KEY_LEN];
        let proof = invite_proof(&secret, "carol", "alice", &key);
        assert!(!check_invite_proof(&secret, "ca", "rolalice", &key, &proof));
    }
}
