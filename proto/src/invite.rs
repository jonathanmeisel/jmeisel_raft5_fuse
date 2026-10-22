//! Invitations: everything that a new user needs to enrol, in one line that
//! an administrator can give them.
//!
//! The format is `raft5fs-invite:1:` and then, in base64url:
//!
//! - the account's name and its one-time enrolment code;
//! - the filesystem servers' addresses;
//! - the name to check their certificates against, if it is not the
//!   addresses' hosts;
//! - the certificate of the CA that their certificates chain to.
//!
//! The invite holds the CA certificate itself, not a hash. So the user does
//! not need to fetch a certificate and trust it the first time it is seen.
//! The user's client then always trusts the CA in the invite.
//!
//! An invite holds the enrolment code, so it is as secret as the code:
//! anyone who has it can enrol as the user. Send it the same way as the
//! code: on a separate channel, only to the user.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

const PREFIX: &str = "raft5fs-invite:1:";

/// What an invitation holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub user: String,
    pub code: String,
    pub servers: Vec<String>,
    pub tls_server_name: Option<String>,
    /// The CA certificate, in DER.
    pub ca: Vec<u8>,
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("the invitation is cut short".to_string());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| "the invitation is garbled".to_string())
    }
}

impl Invite {
    /// The invitation as one line.
    pub fn encode(&self) -> String {
        let mut out = Vec::new();
        put(&mut out, self.user.as_bytes());
        put(&mut out, self.code.as_bytes());
        out.extend_from_slice(&(self.servers.len() as u32).to_be_bytes());
        for server in &self.servers {
            put(&mut out, server.as_bytes());
        }
        put(
            &mut out,
            self.tls_server_name.as_deref().unwrap_or("").as_bytes(),
        );
        put(&mut out, &self.ca);
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(out))
    }

    /// Reads an invitation in the format that `encode` writes. Whitespace
    /// around it is allowed. Anything else is refused, with the reason.
    pub fn decode(line: &str) -> Result<Self, String> {
        let line = line.trim();
        let Some(body) = line.strip_prefix(PREFIX) else {
            return Err(if line.starts_with("raft5fs-invite:") {
                "this invitation is for another version of raft5fs".to_string()
            } else {
                "not a raft5fs invitation".to_string()
            });
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| "the invitation is garbled".to_string())?;
        let mut r = Reader(&bytes);
        let user = r.string()?;
        let code = r.string()?;
        let count = r.u32()?;
        if count == 0 || count > 64 {
            return Err("the invitation names no servers".to_string());
        }
        let servers = (0..count).map(|_| r.string()).collect::<Result<_, _>>()?;
        let name = r.string()?;
        let ca = r.bytes()?.to_vec();
        if !r.0.is_empty() || ca.is_empty() {
            return Err("the invitation is garbled".to_string());
        }
        crate::types::check_username(&user).map_err(|e| e.message)?;
        Ok(Self {
            user,
            code,
            servers,
            tls_server_name: (!name.is_empty()).then_some(name),
            ca,
        })
    }
}

/// The DER of the first certificate in `pem`.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem
        .find(begin)
        .ok_or_else(|| "no certificate in it".to_string())?
        + begin.len();
    let stop = pem[start..]
        .find(end)
        .ok_or_else(|| "a certificate with no end".to_string())?
        + start;
    let body: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(body)
        .map_err(|_| "a garbled certificate".to_string())
}

/// `der` as a PEM certificate.
pub fn der_to_pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Invite {
        Invite {
            user: "bob".to_string(),
            code: "0123456789abcdef0123456789abcdef".to_string(),
            servers: vec!["https://fs1:27060".into(), "https://fs2:27060".into()],
            tls_server_name: Some("raft5fs".into()),
            ca: vec![0x30, 0x82, 1, 2, 3, 4, 5],
        }
    }

    #[test]
    fn an_invitation_round_trips_on_one_line() {
        for i in [
            invite(),
            Invite {
                tls_server_name: None,
                ..invite()
            },
        ] {
            let line = i.encode();
            assert!(!line.contains(char::is_whitespace));
            assert_eq!(Invite::decode(&format!("  {line}\n")).unwrap(), i);
        }
    }

    #[test]
    fn anything_else_is_refused() {
        let line = invite().encode();
        assert!(Invite::decode("hello").is_err());
        assert!(
            Invite::decode(&line.replace(":1:", ":2:"))
                .unwrap_err()
                .contains("another version")
        );
        assert!(Invite::decode(&line[..line.len() - 4]).is_err());
        assert!(Invite::decode(&format!("{line}AAAA")).is_err());
        assert!(Invite::decode(&format!("{line}!")).is_err());
        let bad_name = Invite {
            user: "x\nbob".into(),
            ..invite()
        };
        assert!(Invite::decode(&bad_name.encode()).is_err());
        let no_servers = Invite {
            servers: vec![],
            ..invite()
        };
        assert!(Invite::decode(&no_servers.encode()).is_err());
    }

    #[test]
    fn pem_and_der_convert_both_ways() {
        let der: Vec<u8> = (0..=255).collect();
        let pem = der_to_pem(&der);
        assert_eq!(pem_to_der(&pem).unwrap(), der);
        assert_eq!(pem_to_der(&format!("junk\n{pem}more")).unwrap(), der);
        assert!(pem_to_der("nothing").is_err());
    }
}
