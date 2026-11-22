//! Introductions: one user's key, vouched for by another user, left for a
//! third (see raft5fs-crypto's `seal_introduction`).
//!
//! The servers only keep and hand out the sealed boxes. They can't read
//! them, and can't make one that opens: only the introducer can. Each one
//! is stored under its recipient, so the recipient reads theirs with one
//! scan:
//!
//!   0x06 ++ "i/" ++ recipient ++ 0x00 ++ subject ++ 0x00 ++ introducer
//!     -> made at (seconds since the Unix epoch, BE8) ++ sealed
//!
//! Usernames hold no 0x00 (`check_username`), so the key splits one way.
//! An introduction older than `INTRODUCTION_LIFETIME_SECS` is dropped when
//! its recipient reads them.

use raft5_client::{Client, Transaction};
use raft5fs_proto::types::{FsError, LINK_PREFIX, check_username};

use crate::accounts::refuse_link;
use crate::fs::run_txn;
use crate::grants::Reads;
use crate::layout::INTRODUCTIONS_PREFIX;
use crate::timing::next_key;
use raft5fs_proto::clock;
use raft5fs_proto::errno;

/// How long an introduction waits for its recipient: long enough for them
/// to come back from a trip, and to mark the introducer (see the client's
/// `merge_pins`).
pub const INTRODUCTION_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// The most introductions that one call may leave, and the most bytes in
/// one: an introduction is a name, two keys and a box.
pub const MAX_INTRODUCTIONS: usize = 1000;
pub const MAX_INTRODUCTION_BYTES: usize = 1024;

/// One introduction as the servers keep it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Introduction {
    pub recipient: String,
    pub subject: String,
    pub introducer: String,
    pub sealed: Vec<u8>,
}

fn prefix_of(recipient: &str) -> Vec<u8> {
    let mut key = INTRODUCTIONS_PREFIX.to_vec();
    key.extend_from_slice(recipient.as_bytes());
    key.push(0);
    key
}

fn key_of(recipient: &str, subject: &str, introducer: &str) -> Vec<u8> {
    let mut key = prefix_of(recipient);
    key.extend_from_slice(subject.as_bytes());
    key.push(0);
    key.extend_from_slice(introducer.as_bytes());
    key
}

/// The three names in a key, or `None` for a key that isn't one.
fn names_of(key: &[u8]) -> Option<(String, String, String)> {
    let rest = key.strip_prefix(INTRODUCTIONS_PREFIX)?;
    let mut parts = rest.split(|&b| b == 0);
    let mut next = || String::from_utf8(parts.next()?.to_vec()).ok();
    let names = (next()?, next()?, next()?);
    parts.next().is_none().then_some(names)
}

/// Leaves `introductions` from `introducer`, replacing any earlier one of
/// the same subject to the same recipient. Their `introducer` field is
/// ignored: it is always the caller.
pub async fn put(
    client: &Client,
    introducer: &str,
    introductions: &[Introduction],
) -> Result<(), FsError> {
    refuse_link(introducer)?;
    if introductions.len() > MAX_INTRODUCTIONS {
        return Err(FsError::new(
            errno::EINVAL,
            format!("at most {MAX_INTRODUCTIONS} introductions at once"),
        ));
    }
    for i in introductions {
        check_username(&i.recipient)?;
        check_username(&i.subject)?;
        if i.sealed.is_empty() || i.sealed.len() > MAX_INTRODUCTION_BYTES {
            return Err(FsError::new(
                errno::EINVAL,
                "an introduction of the wrong size",
            ));
        }
        // A link has no one to vouch for it, and checks nobody.
        if i.subject.starts_with(LINK_PREFIX) || i.recipient.starts_with(LINK_PREFIX) {
            return Err(FsError::new(
                errno::EINVAL,
                "a public link isn't introduced",
            ));
        }
    }
    let made = clock::now_secs().to_be_bytes();
    run_txn(client, |txn| async move {
        for i in introductions {
            let mut value = made.to_vec();
            value.extend_from_slice(&i.sealed);
            txn.write(&key_of(&i.recipient, &i.subject, introducer), Some(&value))
                .await?;
        }
        txn.commit().await?;
        Ok(())
    })
    .await
}

/// The introductions left for `recipient`. Removes those too old to keep.
pub async fn get(client: &Client, recipient: &str) -> Result<Vec<Introduction>, FsError> {
    let oldest = clock::now_secs().saturating_sub(INTRODUCTION_LIFETIME_SECS);
    run_txn(client, |txn| async move {
        let mut found = Vec::new();
        for (key, value) in scan(&txn, &prefix_of(recipient)).await? {
            let made = value
                .get(..8)
                .map(|b| u64::from_be_bytes(b.try_into().unwrap()));
            match (names_of(&key), made) {
                (Some((recipient, subject, introducer)), Some(made)) if made >= oldest => {
                    found.push(Introduction {
                        recipient,
                        subject,
                        introducer,
                        sealed: value[8..].to_vec(),
                    });
                }
                _ => txn.write(&key, None).await?,
            }
        }
        txn.commit().await?;
        Ok(found)
    })
    .await
}

/// Removes the introductions left for `recipient` of each `(subject,
/// introducer)`.
pub async fn delete(
    client: &Client,
    recipient: &str,
    which: &[(String, String)],
) -> Result<(), FsError> {
    if which.len() > MAX_INTRODUCTIONS {
        return Err(FsError::new(
            errno::EINVAL,
            format!("at most {MAX_INTRODUCTIONS} introductions at once"),
        ));
    }
    for (subject, introducer) in which {
        check_username(subject)?;
        check_username(introducer)?;
    }
    run_txn(client, |txn| async move {
        for (subject, introducer) in which {
            txn.write(&key_of(recipient, subject, introducer), None)
                .await?;
        }
        txn.commit().await?;
        Ok(())
    })
    .await
}

/// Removes every introduction that names `user`, as recipient, subject or
/// introducer, in `txn`: the account is going, or starting again with a new
/// key pair. It scans them all, which is few for a family.
pub(crate) async fn forget_user(txn: &Transaction, user: &str) -> Result<(), raft5_client::Error> {
    for (key, _) in scan(txn, INTRODUCTIONS_PREFIX).await? {
        if let Some((recipient, subject, introducer)) = names_of(&key)
            && (recipient == user || subject == user || introducer == user)
        {
            txn.write(&key, None).await?;
        }
    }
    Ok(())
}

/// Every key under `prefix` and its value, as `txn` sees them.
async fn scan(
    txn: &Transaction,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, raft5_client::Error> {
    let mut keys = Vec::new();
    let mut iter = txn.key_iterator(prefix);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(prefix) {
            break;
        }
        keys.push(key);
    }
    let values = txn.get_many(&keys).await?;
    Ok(keys
        .into_iter()
        .zip(values)
        .filter_map(|(key, value)| Some((key, value?)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_splits_back_into_its_names() {
        let key = key_of("bob", "carol", "alice");
        assert_eq!(
            names_of(&key),
            Some(("bob".into(), "carol".into(), "alice".into()))
        );
        assert!(key.starts_with(&prefix_of("bob")));
        assert!(!key.starts_with(&prefix_of("bo")));
        assert_eq!(names_of(b"\x06i/bob\x00carol"), None);
        assert_eq!(names_of(b"\x06i/a\x00b\x00c\x00d"), None);
    }
}
