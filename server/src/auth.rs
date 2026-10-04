//! Sessions and handles: what lets a stateless server know who a request
//! is from and what an open allowed, without remembering either.
//!
//! Both are tokens signed with a key every server instance shares, so any
//! instance can check what any other issued, and a server restart loses
//! nothing. That is the whole of the servers' shared state.
//!
//! - A **session** says which account a client logged in as, and
//!   expires. Every request but Hello and Login carries one. It doesn't
//!   say what the account acts as: the server looks that up in the user
//!   table (through a short-lived cache), so a changed group list or a
//!   removed account applies to a mounted user within seconds, without
//!   their logging in again.
//! - A **handle** says that one inode was opened for reading and/or
//!   writing, and by which uid. It doesn't expire by itself -- it is only
//!   honoured alongside a live session of the same uid -- so an open file
//!   keeps working across session renewals, as POSIX says it should even
//!   if its mode changes after the open.

use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use raft5fs_core::{Caller, FsError};
use serde::{Deserialize, Serialize};
use tonic::Status;

const ALGORITHM: Algorithm = Algorithm::HS256;

/// How long a session lasts unless the server is told otherwise: how
/// often a client proves again that it knows the password. Changes to the
/// user table don't wait for it (see the server's identity cache).
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

/// Tells the two kinds of token apart, since one key signs both: a handle
/// must never pass as a session, or the reverse.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Session,
    Handle,
}

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    kind: Kind,
    /// The account name.
    sub: String,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct HandleClaims {
    kind: Kind,
    ino: u64,
    read: bool,
    write: bool,
    uid: u32,
}

/// What a verified handle allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle {
    pub ino: u64,
    pub read: bool,
    pub write: bool,
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
    ///
    /// A token from before sessions stopped carrying the identity still
    /// verifies (its extra claims are ignored), but the reverse doesn't:
    /// an older server can't read these, so upgrade every server at once.
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

    /// A handle recording that `caller` opened `ino` as `read`/`write`.
    pub fn handle(&self, caller: &Caller, ino: u64, read: bool, write: bool) -> String {
        self.sign(&HandleClaims {
            kind: Kind::Handle,
            ino,
            read,
            write,
            uid: caller.uid,
        })
    }

    /// What `token` allows `caller`. A handle that is forged, or that
    /// another uid opened, is `EBADF`: to the application it is simply
    /// not a valid descriptor, and it isn't the session's fault.
    pub fn verify_handle(&self, caller: &Caller, token: &str) -> Result<Handle, FsError> {
        let mut validation = Validation::new(ALGORITHM);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let bad = |why: &str| FsError::new(libc::EBADF, format!("handle refused: {why}"));
        let claims = decode::<HandleClaims>(token, &self.decoding, &validation)
            .map_err(|e| bad(&e.to_string()))?
            .claims;
        if claims.kind != Kind::Handle {
            return Err(bad("not a handle"));
        }
        if claims.uid != caller.uid {
            return Err(bad("opened by someone else"));
        }
        Ok(Handle {
            ino: claims.ino,
            read: claims.read,
            write: claims.write,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::new(b"test key", DEFAULT_SESSION_TTL)
    }

    fn alice() -> Caller {
        Caller::new(1000, 100, vec![4, 27])
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
    fn a_session_that_still_carries_an_identity_verifies() {
        #[derive(Serialize)]
        struct Old {
            kind: Kind,
            sub: String,
            uid: u32,
            gid: u32,
            groups: Vec<u32>,
            exp: u64,
        }
        let s = signer();
        let token = s.sign(&Old {
            kind: Kind::Session,
            sub: "alice".into(),
            uid: 1000,
            gid: 100,
            groups: vec![4],
            exp: jsonwebtoken::get_current_timestamp() + 60,
        });
        assert_eq!(s.verify_session(&token).unwrap(), "alice");
    }

    #[test]
    fn a_handle_is_not_a_session_and_a_session_is_not_a_handle() {
        let s = signer();
        let handle = s.handle(&alice(), 7, true, false);
        assert!(s.verify_session(&handle).is_err());
        let (session, _) = s.session("alice");
        assert_eq!(
            s.verify_handle(&alice(), &session).unwrap_err().errno,
            libc::EBADF
        );
    }

    #[test]
    fn a_handle_carries_its_access_and_only_works_for_its_opener() {
        let s = signer();
        let handle = s.handle(&alice(), 7, true, false);
        assert_eq!(
            s.verify_handle(&alice(), &handle).unwrap(),
            Handle {
                ino: 7,
                read: true,
                write: false
            }
        );
        let bob = Caller::new(1001, 100, vec![]);
        assert_eq!(
            s.verify_handle(&bob, &handle).unwrap_err().errno,
            libc::EBADF
        );
    }
}
