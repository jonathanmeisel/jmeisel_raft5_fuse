//! An account's trusted keys (its pins), sealed for the servers to keep,
//! so that every device of the account trusts the same keys.
//!
//! - The list is sealed under a key that only the account's private key
//!   gives, and bound to the account's name. The servers can't read it,
//!   and can't add or change an entry.
//! - Each entry has a time, and a forgotten key stays as an entry with no
//!   key, so that devices that merge their changes agree on the latest.
//! - Each list has a counter, sealed with it, that goes up with every change.
//!   A device remembers the highest it has seen and refuses a lower one, so
//!   the servers can't give it an older list to bring back a key the account
//!   has since replaced. A device that has seen no list has nothing to compare
//!   with. An older list can still only hold keys the account once checked.
//! - Each pin says how its key was checked, and whether the account trusts
//!   that person's introductions of others (see `PinSource`).
//! - The list also holds the secrets of the account's open invitations, so
//!   whichever of its devices is online next can check the new account's
//!   key (see `invitation`).

use crate::identity::{Identity, PUBLIC_KEY_LEN};
use crate::invitation::INVITE_SECRET_LEN;
use crate::{Error, Reader, aad, open, put_bytes, seal};

/// The format of a sealed list. Version 1 had no counter: it reads as 0.
/// Version 2 had no sources, introducers or invitations: its pins read as
/// checked by the account.
const VERSION: u8 = 3;
const VERSION_2: u8 = 2;
const VERSION_1: u8 = 1;

/// How the account came to trust a key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PinSource {
    /// Someone using the account compared its safety code.
    #[default]
    Checked,
    /// It enrolled with an invitation that this account made, or it made
    /// the invitation that this account enrolled with.
    Invited,
    /// Someone that this account trusts to check keys introduced it.
    Introduced { by: String },
}

impl PinSource {
    /// Whether the account checked the key itself. Only such keys are
    /// introduced on to others, so an introduction is one step at most.
    pub fn first_hand(&self) -> bool {
        !matches!(self, PinSource::Introduced { .. })
    }
}

/// One user's pin, as of `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinEntry {
    pub user: String,
    /// The trusted key, or `None` if it was forgotten.
    pub key: Option<[u8; PUBLIC_KEY_LEN]>,
    /// When it was set, in seconds since the Unix epoch.
    pub at: u64,
    pub source: PinSource,
    /// Whether the account trusts this user's introductions of others.
    pub introducer: bool,
}

/// An invitation that the account made, as of `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvite {
    pub user: String,
    /// The invitation's secret, or `None` once it is closed: the new key
    /// was checked, or the check failed, or the invitation expired.
    pub secret: Option<[u8; INVITE_SECRET_LEN]>,
    /// When it was made or closed, in seconds since the Unix epoch.
    pub at: u64,
}

/// An account's list of trusted keys, as of one change.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PinList {
    /// Goes up with every change. The servers can't read or change it.
    pub counter: u64,
    /// Whether a device of this account has signed its old grant labels. Any
    /// unsigned label after that didn't come from this account's check.
    pub labels_signed: bool,
    pub entries: Vec<PinEntry>,
    pub invites: Vec<PendingInvite>,
}

/// Seals `list` as `user`'s trusted keys, sorted by name.
pub fn seal_pins(identity: &Identity, user: &str, list: &PinList) -> Vec<u8> {
    let mut sorted: Vec<&PinEntry> = list.entries.iter().collect();
    sorted.sort_by(|a, b| a.user.cmp(&b.user));
    let mut plain = list.counter.to_be_bytes().to_vec();
    plain.push(u8::from(list.labels_signed));
    plain.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for entry in sorted {
        put_bytes(&mut plain, entry.user.as_bytes());
        match &entry.key {
            Some(key) => {
                plain.push(1);
                plain.extend_from_slice(key);
            }
            None => plain.push(0),
        }
        plain.extend_from_slice(&entry.at.to_be_bytes());
        match &entry.source {
            PinSource::Checked => plain.push(0),
            PinSource::Invited => plain.push(1),
            PinSource::Introduced { by } => {
                plain.push(2);
                put_bytes(&mut plain, by.as_bytes());
            }
        }
        plain.push(u8::from(entry.introducer));
    }
    let mut invites: Vec<&PendingInvite> = list.invites.iter().collect();
    invites.sort_by(|a, b| a.user.cmp(&b.user));
    plain.extend_from_slice(&(invites.len() as u32).to_be_bytes());
    for invite in invites {
        put_bytes(&mut plain, invite.user.as_bytes());
        match &invite.secret {
            Some(secret) => {
                plain.push(1);
                plain.extend_from_slice(secret);
            }
            None => plain.push(0),
        }
        plain.extend_from_slice(&invite.at.to_be_bytes());
    }
    let key = identity.derive_key("pins");
    let mut out = vec![VERSION];
    out.extend_from_slice(&seal(&key, &aad("pins", &[user.as_bytes()]), &plain));
    out
}

/// Opens `user`'s trusted keys, as `seal_pins` sealed them.
pub fn open_pins(identity: &Identity, user: &str, sealed: &[u8]) -> Result<PinList, Error> {
    let what = "the trusted keys";
    let (&version, sealed) = sealed.split_first().ok_or(Error(what))?;
    if ![VERSION, VERSION_2, VERSION_1].contains(&version) {
        return Err(Error(what));
    }
    let key = identity.derive_key("pins");
    let plain = open(&key, &aad("pins", &[user.as_bytes()]), sealed, what)?;
    let mut r = Reader(&plain);
    let (counter, labels_signed) = if version >= VERSION_2 {
        let counter = u64::from_be_bytes(r.take(8, what)?.try_into().unwrap());
        (counter, r.take(1, what)?[0] != 0)
    } else {
        (0, false)
    };
    let count = r.u32(what)?;
    let mut entries: Vec<PinEntry> = Vec::new();
    for _ in 0..count {
        let user = std::str::from_utf8(r.bytes(what)?)
            .map_err(|_| Error(what))?
            .to_string();
        let key = match r.take(1, what)?[0] {
            0 => None,
            1 => Some(r.take(PUBLIC_KEY_LEN, what)?.try_into().unwrap()),
            _ => return Err(Error(what)),
        };
        let at = u64::from_be_bytes(r.take(8, what)?.try_into().unwrap());
        let (source, introducer) = if version >= VERSION {
            let source = match r.take(1, what)?[0] {
                0 => PinSource::Checked,
                1 => PinSource::Invited,
                2 => PinSource::Introduced {
                    by: name(&mut r, what)?,
                },
                _ => return Err(Error(what)),
            };
            (source, flag(&mut r, what)?)
        } else {
            (PinSource::Checked, false)
        };
        if entries.iter().any(|e| e.user == user) {
            return Err(Error(what));
        }
        entries.push(PinEntry {
            user,
            key,
            at,
            source,
            introducer,
        });
    }
    let mut invites: Vec<PendingInvite> = Vec::new();
    if version >= VERSION {
        for _ in 0..r.u32(what)? {
            let user = name(&mut r, what)?;
            let secret = if flag(&mut r, what)? {
                Some(r.take(INVITE_SECRET_LEN, what)?.try_into().unwrap())
            } else {
                None
            };
            let at = u64::from_be_bytes(r.take(8, what)?.try_into().unwrap());
            if invites.iter().any(|i| i.user == user) {
                return Err(Error(what));
            }
            invites.push(PendingInvite { user, secret, at });
        }
    }
    r.finish(what)?;
    Ok(PinList {
        counter,
        labels_signed,
        entries,
        invites,
    })
}

fn name(r: &mut Reader<'_>, what: &'static str) -> Result<String, Error> {
    std::str::from_utf8(r.bytes(what)?)
        .map(str::to_string)
        .map_err(|_| Error(what))
}

fn flag(r: &mut Reader<'_>, what: &'static str) -> Result<bool, Error> {
    match r.take(1, what)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error(what)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(user: &str, key: Option<u8>, at: u64) -> PinEntry {
        PinEntry {
            user: user.to_string(),
            key: key.map(|b| [b; PUBLIC_KEY_LEN]),
            at,
            source: PinSource::Checked,
            introducer: false,
        }
    }

    #[test]
    fn pins_open_only_for_their_account() {
        let me = Identity::generate();
        let list = PinList {
            counter: 7,
            labels_signed: true,
            entries: vec![entry("bob", Some(2), 20), entry("alice", None, 10)],
            invites: Vec::new(),
        };
        let sealed = seal_pins(&me, "carol", &list);
        assert_eq!(
            open_pins(&me, "carol", &sealed).unwrap(),
            PinList {
                counter: 7,
                labels_signed: true,
                entries: vec![entry("alice", None, 10), entry("bob", Some(2), 20)],
                invites: Vec::new(),
            }
        );
        assert!(open_pins(&me, "dave", &sealed).is_err(), "another account");
        assert!(open_pins(&Identity::generate(), "carol", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_pins(&me, "carol", &tampered).is_err());
        assert!(open_pins(&me, "carol", &[]).is_err());
        let empty = seal_pins(&me, "carol", &PinList::default());
        assert_eq!(open_pins(&me, "carol", &empty).unwrap(), PinList::default());
    }

    /// A list sealed before counters reads as counter 0, so a device that
    /// has seen a newer list refuses it.
    #[test]
    fn a_list_without_a_counter_reads_as_zero() {
        let me = Identity::generate();
        let mut plain = 1u32.to_be_bytes().to_vec();
        put_bytes(&mut plain, b"bob");
        plain.push(0);
        plain.extend_from_slice(&5u64.to_be_bytes());
        let mut sealed = vec![VERSION_1];
        let key = me.derive_key("pins");
        sealed.extend_from_slice(&seal(&key, &aad("pins", &[b"carol"]), &plain));
        assert_eq!(
            open_pins(&me, "carol", &sealed).unwrap(),
            PinList {
                counter: 0,
                labels_signed: false,
                entries: vec![entry("bob", None, 5)],
                invites: Vec::new(),
            }
        );
    }

    #[test]
    fn sources_introducers_and_invitations_round_trip() {
        let me = Identity::generate();
        let mut alice = entry("alice", Some(1), 10);
        alice.source = PinSource::Invited;
        alice.introducer = true;
        let mut bob = entry("bob", Some(2), 20);
        bob.source = PinSource::Introduced { by: "alice".into() };
        let list = PinList {
            counter: 3,
            labels_signed: true,
            entries: vec![alice, bob],
            invites: vec![
                PendingInvite {
                    user: "dave".into(),
                    secret: None,
                    at: 40,
                },
                PendingInvite {
                    user: "carol".into(),
                    secret: Some([9; INVITE_SECRET_LEN]),
                    at: 30,
                },
            ],
        };
        let opened = open_pins(&me, "me", &seal_pins(&me, "me", &list)).unwrap();
        let mut sorted = list.clone();
        sorted.invites.reverse();
        assert_eq!(opened, sorted);
    }

    /// A list from before sources reads with every key checked by the
    /// account, no introducers, and no invitations.
    #[test]
    fn a_version_2_list_reads_as_checked_pins() {
        let me = Identity::generate();
        let mut plain = 4u64.to_be_bytes().to_vec();
        plain.push(1);
        plain.extend_from_slice(&1u32.to_be_bytes());
        put_bytes(&mut plain, b"bob");
        plain.push(1);
        plain.extend_from_slice(&[2; PUBLIC_KEY_LEN]);
        plain.extend_from_slice(&5u64.to_be_bytes());
        let mut sealed = vec![VERSION_2];
        let key = me.derive_key("pins");
        sealed.extend_from_slice(&seal(&key, &aad("pins", &[b"carol"]), &plain));
        assert_eq!(
            open_pins(&me, "carol", &sealed).unwrap(),
            PinList {
                counter: 4,
                labels_signed: true,
                entries: vec![entry("bob", Some(2), 5)],
                invites: Vec::new(),
            }
        );
    }
}
