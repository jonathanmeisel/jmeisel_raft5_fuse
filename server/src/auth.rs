//! Sessions: what lets a stateless server know who a request is from
//! without remembering it.
//!
//! A session is a token signed with a key every server instance shares, so
//! any instance can check what any other issued, and a server restart
//! loses nothing. It says which account a client logged in as, and
//! expires. Every request but the login ones carries one. What the account
//! may do isn't in it: grants decide that, on every request, and whether
//! the account still exists is looked up too (through a short-lived
//! cache), so removing it cuts a mounted user off within seconds.

use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tonic::Status;

const ALGORITHM: Algorithm = Algorithm::HS256;

/// How long a session lasts unless the server is told otherwise: how
/// often a client proves again that it knows the password. Removing an
/// account doesn't wait for it (see the server's account cache).
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

/// What a token is. There is only the one kind now, but the claim stays:
/// the file handles older servers signed with the same key must never
/// pass as sessions.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Session,
}

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    kind: Kind,
    /// The account name.
    sub: String,
    exp: u64,
}

pub struct Signer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    session_ttl: Duration,
    /// The key itself, for the one other thing every server must agree on
    /// without talking: the decoy salts of accounts that don't exist.
    secret: Vec<u8>,
}

impl Signer {
    pub fn new(key: &[u8], session_ttl: Duration) -> Self {
        Self {
            encoding: EncodingKey::from_secret(key),
            decoding: DecodingKey::from_secret(key),
            session_ttl,
            secret: key.to_vec(),
        }
    }

    /// The salt to hand out for an account that has none, the same on
    /// every server (see `raft5fs_crypto::password::decoy_salt`).
    pub fn decoy_salt(&self, user: &str) -> [u8; raft5fs_crypto::password::SALT_LEN] {
        raft5fs_crypto::password::decoy_salt(&self.secret, user)
    }

    fn sign(&self, claims: &impl Serialize) -> String {
        encode(&Header::new(ALGORITHM), claims, &self.encoding)
            .expect("HMAC signing of plain claims can't fail")
    }

    /// A session for account `name`, and when it expires (seconds since
    /// the epoch).
    pub fn session(&self, name: &str) -> (String, u64) {
        let exp = jsonwebtoken::get_current_timestamp() + self.session_ttl.as_secs();
        let token = self.sign(&SessionClaims {
            kind: Kind::Session,
            sub: name.to_string(),
            exp,
        });
        (token, exp)
    }

    /// The account a session token is for. Anything wrong with it --
    /// forged, expired, not a session at all -- is `UNAUTHENTICATED`, which
    /// tells the client to log in again.
    pub fn verify_session(&self, token: &str) -> Result<String, Status> {
        let refused = |why: String| Status::unauthenticated(format!("session refused: {why}"));
        // `Validation::new` pins the algorithm and requires `exp`.
        let claims = decode::<SessionClaims>(token, &self.decoding, &Validation::new(ALGORITHM))
            .map_err(|e| refused(e.to_string()))?
            .claims;
        if claims.kind != Kind::Session {
            return Err(refused("not a session token".into()));
        }
        Ok(claims.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::new(b"test key", DEFAULT_SESSION_TTL)
    }

    #[test]
    fn a_session_names_who_it_was_issued_to() {
        let s = signer();
        let (token, _) = s.session("alice");
        assert_eq!(s.verify_session(&token).unwrap(), "alice");
    }

    #[test]
    fn another_key_or_a_tampered_token_is_refused() {
        let (token, _) = signer().session("alice");
        let other = Signer::new(b"other key", DEFAULT_SESSION_TTL);
        assert!(other.verify_session(&token).is_err());
        let mut tampered = token.into_bytes();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 1;
        assert!(
            signer()
                .verify_session(&String::from_utf8_lossy(&tampered))
                .is_err()
        );
    }

    #[test]
    fn an_expired_session_is_refused() {
        // Past the default 60 s leeway.
        let s = signer();
        let token = s.sign(&SessionClaims {
            kind: Kind::Session,
            sub: "alice".into(),
            exp: jsonwebtoken::get_current_timestamp() - 3600,
        });
        let status = s.verify_session(&token).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn an_old_file_handle_is_not_a_session() {
        #[derive(Serialize)]
        struct Handle {
            kind: &'static str,
            sub: String,
            exp: u64,
        }
        let s = signer();
        let token = s.sign(&Handle {
            kind: "handle",
            sub: "alice".into(),
            exp: jsonwebtoken::get_current_timestamp() + 60,
        });
        assert!(s.verify_session(&token).is_err());
    }
}
