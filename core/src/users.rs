//! The user table: which uid, primary gid and supplementary groups each
//! store account acts as in the filesystem.
//!
//! An account the table doesn't list can log in to the store but gets no
//! filesystem session. The table is filesystem data like any other, so
//! whatever keeps users away from the filesystem's keys keeps them from
//! editing their own row too.

use raft5_client::Client;

use crate::fs::{TXN_TTL, retrying};
use crate::layout::USERS_PREFIX;
use raft5fs_proto::types::FsError;

/// What one account acts as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

fn user_key(name: &str) -> Vec<u8> {
    let mut key = USERS_PREFIX.to_vec();
    key.extend_from_slice(name.as_bytes());
    key
}

fn encode(account: &Account) -> Vec<u8> {
    [account.uid, account.gid]
        .iter()
        .chain(&account.groups)
        .flat_map(|n| n.to_be_bytes())
        .collect()
}

fn decode(name: &str, bytes: &[u8]) -> Result<Account, FsError> {
    if bytes.len() < 8 || !bytes.len().is_multiple_of(4) {
        return Err(FsError::new(
            libc::EIO,
            format!("the user table's row for {name:?} is garbled"),
        ));
    }
    let mut numbers = bytes
        .chunks_exact(4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()));
    Ok(Account {
        uid: numbers.next().unwrap(),
        gid: numbers.next().unwrap(),
        groups: numbers.collect(),
    })
}

/// `name`'s row, if it has one.
pub async fn get(client: &Client, name: &str) -> Result<Option<Account>, FsError> {
    match client.read(&user_key(name)).await?.value {
        Some(bytes) => Ok(Some(decode(name, &bytes)?)),
        None => Ok(None),
    }
}

/// Adds `name`'s row, or replaces it. Takes effect at that account's next
/// request, once each server's identity cache has let go of the old row:
/// a mounted user needn't log in again.
pub async fn set(client: &Client, name: &str, account: &Account) -> Result<(), FsError> {
    if name.is_empty() {
        return Err(FsError::new(libc::EINVAL, "a username can't be empty"));
    }
    client
        .write(&user_key(name), Some(&encode(account)))
        .await?;
    Ok(())
}

/// Adds the gids in `add` to `name`'s supplementary groups and takes out
/// those in `remove`, returning the row as it now is. Read and written in
/// one transaction, so two changes at once can't undo each other. A user
/// with no row is `ENOENT`. Like `set`, applies at the account's next
/// request (see the server's identity cache), not just its next login.
pub async fn modify(
    client: &Client,
    name: &str,
    add: &[u32],
    remove: &[u32],
) -> Result<Account, FsError> {
    let key = user_key(name);
    retrying(|| {
        let key = &key;
        async move {
            let txn = client.transaction(TXN_TTL).await?;
            let Some(bytes) = txn.read(key).await?.value else {
                return Ok(Err(FsError::new(
                    libc::ENOENT,
                    format!("{name} has no filesystem account"),
                )));
            };
            let mut account = match decode(name, &bytes) {
                Ok(account) => account,
                Err(e) => return Ok(Err(e)),
            };
            apply(&mut account.groups, add, remove);
            txn.write(key, Some(&encode(&account))).await?;
            txn.commit().await?;
            Ok(Ok(account))
        }
    })
    .await?
}

/// `groups` with `add` appended (skipping any already there) and `remove`
/// taken out, keeping the order the rest were in.
fn apply(groups: &mut Vec<u32>, add: &[u32], remove: &[u32]) {
    for &gid in add {
        if !groups.contains(&gid) {
            groups.push(gid);
        }
    }
    groups.retain(|gid| !remove.contains(gid));
}

/// Removes `name`'s row, reporting whether there was one.
pub async fn remove(client: &Client, name: &str) -> Result<bool, FsError> {
    let existed = client.read(&user_key(name)).await?.value.is_some();
    client.write(&user_key(name), None).await?;
    Ok(existed)
}

/// Every row, in username order.
pub async fn list(client: &Client) -> Result<Vec<(String, Account)>, FsError> {
    let mut rows = Vec::new();
    let mut iter = client.key_iterator(USERS_PREFIX);
    while let Some(key) = iter.next().await? {
        if !key.starts_with(USERS_PREFIX) {
            break;
        }
        let name = String::from_utf8_lossy(&key[USERS_PREFIX.len()..]).into_owned();
        if let Some(bytes) = client.read(&key).await?.value {
            let account = decode(&name, &bytes)?;
            rows.push((name, account));
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_round_trips() {
        for account in [
            Account {
                uid: 1000,
                gid: 100,
                groups: vec![4, 27, 50_100],
            },
            Account {
                uid: 0,
                gid: 0,
                groups: vec![],
            },
        ] {
            assert_eq!(decode("u", &encode(&account)).unwrap(), account);
        }
    }

    #[test]
    fn modifying_groups_keeps_order_and_skips_duplicates() {
        let mut groups = vec![4, 27, 50];
        apply(&mut groups, &[27, 100, 100], &[4]);
        assert_eq!(groups, [27, 50, 100]);
        apply(&mut groups, &[], &[999]);
        assert_eq!(groups, [27, 50, 100]);
    }

    #[test]
    fn a_garbled_row_is_eio_not_a_panic() {
        for bytes in [&[][..], &[0; 7], &[0; 10]] {
            assert_eq!(decode("u", bytes).unwrap_err().errno, libc::EIO);
        }
    }
}
