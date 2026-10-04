//! The group table: names for gids.
//!
//! Membership isn't kept here -- it stays on each user's row (`users`),
//! and a gid works there whether or not it has a name. A name only lets
//! the admin commands say `devs` instead of `3000`. Each name has one gid
//! and each gid at most one name, which the reverse rows (`gid -> name`)
//! enforce: two groups claiming one gid both write its row, so one
//! transaction aborts and its retry sees the gid taken.

use std::collections::BTreeSet;

use raft5_client::Client;

use crate::fs::{TXN_TTL, retrying};
use crate::layout::{GIDS_PREFIX, GROUPS_PREFIX};
use crate::users;
use raft5fs_proto::types::FsError;

/// Where `add` starts looking for a free gid when given none, leaving the
/// numbers below to system groups, as local systems do.
pub const FIRST_ALLOCATED_GID: u32 = 1000;

const MAX_NAME_LEN: usize = 32;

fn name_key(name: &str) -> Vec<u8> {
    let mut key = GROUPS_PREFIX.to_vec();
    key.extend_from_slice(name.as_bytes());
    key
}

fn gid_key(gid: u32) -> Vec<u8> {
    let mut key = GIDS_PREFIX.to_vec();
    key.extend_from_slice(&gid.to_be_bytes());
    key
}

fn decode_gid(name: &str, bytes: &[u8]) -> Result<u32, FsError> {
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| {
        FsError::new(
            libc::EIO,
            format!("the group table's row for {name:?} is garbled"),
        )
    })?;
    Ok(u32::from_be_bytes(bytes))
}

/// Whether `name` can name a group. An all-digit name is refused so that
/// a number always means a gid, and the separators the commands and
/// listings use are refused so that they never appear inside a name.
pub fn validate_name(name: &str) -> Result<(), FsError> {
    let refuse = |why: &str| {
        Err(FsError::new(
            libc::EINVAL,
            format!("group name {name:?} {why}"),
        ))
    };
    if name.is_empty() {
        return refuse("is empty");
    }
    if name.len() > MAX_NAME_LEN {
        return refuse(&format!("is longer than {MAX_NAME_LEN} bytes"));
    }
    if name.bytes().all(|b| b.is_ascii_digit()) {
        return refuse("is a number; names must not be, so numbers always mean gids");
    }
    if name
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ',' | ':' | '/' | '(' | ')'))
    {
        return refuse("contains whitespace or one of , : / ( )");
    }
    Ok(())
}

/// Every gid some user row uses, as primary or supplementary group: what
/// an allocated gid must avoid, or it would silently name a group people
/// are already in.
async fn gids_in_use(client: &Client) -> Result<BTreeSet<u32>, FsError> {
    Ok(users::list(client)
        .await?
        .into_iter()
        .flat_map(|(_, a)| std::iter::once(a.gid).chain(a.groups))
        .collect())
}

/// Names a new group `name`, with gid `gid` or, given none, the lowest
/// free gid from `FIRST_ALLOCATED_GID` up, and returns the gid. A name or
/// gid that is already taken is `EEXIST`.
pub async fn add(client: &Client, name: &str, gid: Option<u32>) -> Result<u32, FsError> {
    validate_name(name)?;
    // Read outside the transaction: a user row changing meanwhile can't
    // make the result wrong, only make the gid a group people just joined.
    let in_use = match gid {
        Some(_) => BTreeSet::new(),
        None => gids_in_use(client).await?,
    };
    retrying(|| {
        let in_use = &in_use;
        async move {
            let txn = client.transaction(TXN_TTL).await?;
            if let Some(bytes) = txn.read(&name_key(name)).await?.value {
                let held = match decode_gid(name, &bytes) {
                    Ok(gid) => gid.to_string(),
                    Err(_) => "?".to_string(),
                };
                return Ok(Err(FsError::new(
                    libc::EEXIST,
                    format!("group {name} already exists, with gid {held}"),
                )));
            }
            let gid = match gid {
                Some(gid) => {
                    if let Some(holder) = txn.read(&gid_key(gid)).await?.value {
                        return Ok(Err(FsError::new(
                            libc::EEXIST,
                            format!(
                                "gid {gid} is already group {}",
                                String::from_utf8_lossy(&holder)
                            ),
                        )));
                    }
                    gid
                }
                None => {
                    // Gid rows sort in numeric order (big-endian keys), so
                    // one pass finds the first gap.
                    let mut named = BTreeSet::new();
                    let mut iter = txn.key_iterator(GIDS_PREFIX);
                    while let Some(key) = iter.next().await? {
                        let Some(rest) = key.strip_prefix(GIDS_PREFIX) else {
                            break;
                        };
                        if let Ok(bytes) = <[u8; 4]>::try_from(rest) {
                            named.insert(u32::from_be_bytes(bytes));
                        }
                    }
                    match (FIRST_ALLOCATED_GID..=u32::MAX)
                        .find(|g| !named.contains(g) && !in_use.contains(g))
                    {
                        Some(gid) => gid,
                        None => {
                            return Ok(Err(FsError::new(libc::ENOSPC, "no gid is free")));
                        }
                    }
                }
            };
            txn.write(&name_key(name), Some(&gid.to_be_bytes())).await?;
            txn.write(&gid_key(gid), Some(name.as_bytes())).await?;
            txn.commit().await?;
            Ok(Ok(gid))
        }
    })
    .await?
}

/// Removes group `name`'s name, returning the gid it had, or `None` if
/// there was no such group. User rows listing the gid keep it: it is
/// still a group, just an unnamed one.
pub async fn remove(client: &Client, name: &str) -> Result<Option<u32>, FsError> {
    retrying(|| async move {
        let txn = client.transaction(TXN_TTL).await?;
        let Some(bytes) = txn.read(&name_key(name)).await?.value else {
            return Ok(Ok(None));
        };
        let gid = match decode_gid(name, &bytes) {
            Ok(gid) => gid,
            Err(e) => return Ok(Err(e)),
        };
        txn.write(&name_key(name), None).await?;
        txn.write(&gid_key(gid), None).await?;
        txn.commit().await?;
        Ok(Ok(Some(gid)))
    })
    .await?
}

/// Every group, in name order.
pub async fn list(client: &Client) -> Result<Vec<(String, u32)>, FsError> {
    let mut rows = Vec::new();
    let mut iter = client.key_iterator(GROUPS_PREFIX);
    while let Some(key) = iter.next().await? {
        if !key.starts_with(GROUPS_PREFIX) {
            break;
        }
        let name = String::from_utf8_lossy(&key[GROUPS_PREFIX.len()..]).into_owned();
        if let Some(bytes) = client.read(&key).await?.value {
            let gid = decode_gid(&name, &bytes)?;
            rows.push((name, gid));
        }
    }
    Ok(rows)
}

/// The gid `group` means: a number is itself, named or not, and a name
/// must be in the table (`ENOENT` if it isn't).
pub async fn resolve(client: &Client, group: &str) -> Result<u32, FsError> {
    if let Ok(gid) = group.parse() {
        return Ok(gid);
    }
    match client.read(&name_key(group)).await?.value {
        Some(bytes) => decode_gid(group, &bytes),
        None => Err(FsError::new(
            libc::ENOENT,
            format!("no group named {group:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_are_accepted() {
        for name in ["devs", "staff-2", "a_b.c", "1st", "x"] {
            validate_name(name).unwrap();
        }
    }

    #[test]
    fn numbers_separators_and_empties_are_refused() {
        let long = "g".repeat(MAX_NAME_LEN + 1);
        for name in [
            "", "3000", "a,b", "a:b", "a/b", "a b", "a\tb", "a(b)", &long,
        ] {
            assert_eq!(
                validate_name(name).unwrap_err().errno,
                libc::EINVAL,
                "{name:?}"
            );
        }
    }

    #[test]
    fn gid_rows_sort_in_numeric_order() {
        assert!(gid_key(999) < gid_key(1000));
        assert!(gid_key(1000) < gid_key(65_536));
    }

    #[test]
    fn a_garbled_gid_is_eio_not_a_panic() {
        assert_eq!(decode_gid("g", &[0; 3]).unwrap_err().errno, libc::EIO);
        assert_eq!(decode_gid("g", &3000u32.to_be_bytes()).unwrap(), 3000);
    }
}
