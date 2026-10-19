//! Accounts: what checks a login, and the user's
//! wrapped private key.
//!
//! The server never sees a password here. Each account holds what the
//! client derived from one (see raft5fs-crypto's `password`): a salt and
//! cost settings to stretch it with, a verifier to check the resulting
//! `auth` against, and the user's key pair -- the public half, and the
//! private half wrapped under a key only the password yields.
//!
//! An account is its keys. It gets them by enrolling with a one-time code
//! an administrator issued (`issue_code`), which is all there is to adding
//! a user. Only the code's hash is stored,
//! and enrolling consumes it. Issuing a new code lets a user who lost
//! their password enrol again -- with a new key pair, so whatever was
//! granted to the old one is out of reach until granted again.

use raft5_client::{Client, Error as KvError, Transaction};
use raft5fs_crypto::identity::PUBLIC_KEY_LEN;
use raft5fs_crypto::password::{
    KdfParams, SALT_LEN, check_verifier, enrolment_code_hash, new_enrolment_code,
};

use crate::fs::{TXN_TTL, retrying};
use crate::layout::{ACCOUNT_KEYS_PREFIX, ENROLMENT_PREFIX};
use crate::view::ReadKeys;
use raft5fs_proto::types::{AccountKeys, FsError};

pub(crate) fn keys_key(user: &str) -> Vec<u8> {
    let mut key = ACCOUNT_KEYS_PREFIX.to_vec();
    key.extend_from_slice(user.as_bytes());
    key
}

fn code_key(user: &str) -> Vec<u8> {
    let mut key = ENROLMENT_PREFIX.to_vec();
    key.extend_from_slice(user.as_bytes());
    key
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn encode(keys: &AccountKeys) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [
        &keys.salt,
        &keys.kdf_params,
        &keys.verifier,
        &keys.public_key,
        &keys.wrapped_private_key,
    ] {
        put(&mut out, field);
    }
    out
}

fn decode(user: &str, mut bytes: &[u8]) -> Result<AccountKeys, FsError> {
    let garbled = || {
        FsError::new(
            libc::EIO,
            format!("the account keys stored for {user:?} are garbled"),
        )
    };
    let mut field = || -> Result<Vec<u8>, FsError> {
        if bytes.len() < 4 {
            return Err(garbled());
        }
        let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let value = bytes.get(4..4 + n).ok_or_else(garbled)?.to_vec();
        bytes = &bytes[4 + n..];
        Ok(value)
    };
    let keys = AccountKeys {
        salt: field()?,
        kdf_params: field()?,
        verifier: field()?,
        public_key: field()?,
        wrapped_private_key: field()?,
    };
    if !bytes.is_empty() {
        return Err(garbled());
    }
    Ok(keys)
}

/// Refuses keys a client couldn't have made honestly: the wrong sizes, or
/// cost settings Argon2 would reject. What they open isn't checked -- it
/// can't be, here.
fn validate(keys: &AccountKeys) -> Result<(), FsError> {
    let bad = |what: &str| {
        Err(FsError::new(
            libc::EINVAL,
            format!("bad account keys: {what}"),
        ))
    };
    if keys.salt.len() != SALT_LEN {
        return bad("the salt is the wrong length");
    }
    if KdfParams::decode(&keys.kdf_params).is_err() {
        return bad("unreadable KDF parameters");
    }
    if keys.verifier.len() != 32 {
        return bad("the verifier is the wrong length");
    }
    if keys.public_key.len() != PUBLIC_KEY_LEN {
        return bad("the public key is the wrong length");
    }
    if keys.wrapped_private_key.is_empty() || keys.wrapped_private_key.len() > 1024 {
        return bad("the wrapped private key is the wrong length");
    }
    Ok(())
}

/// `user`'s keys, if they have enrolled.
pub async fn get(client: &Client, user: &str) -> Result<Option<AccountKeys>, FsError> {
    match client.read_one(&keys_key(user)).await?.value {
        Some(bytes) => Ok(Some(decode(user, &bytes)?)),
        None => Ok(None),
    }
}

/// Every one of `users`' keys, in order, as `get` reads one.
pub(crate) async fn get_many(
    client: &Client,
    users: &[&str],
) -> Result<Vec<Option<AccountKeys>>, FsError> {
    let keys: Vec<Vec<u8>> = users.iter().map(|user| keys_key(user)).collect();
    let entries = client.read_many(&keys).await?;
    users
        .iter()
        .zip(entries)
        .map(|(user, entry)| entry.value.map(|bytes| decode(user, &bytes)).transpose())
        .collect()
}

/// `user`'s keys, if `auth` is right for them. A wrong `auth` and an
/// account with no keys look the same, so a login can't tell a stranger
/// which accounts exist.
pub async fn check_login(
    client: &Client,
    user: &str,
    auth: &[u8],
) -> Result<Option<AccountKeys>, FsError> {
    if crate::grants::check_username(user).is_err() {
        return Ok(None);
    }
    Ok(get(client, user)
        .await?
        .filter(|keys| check_verifier(auth, &keys.verifier)))
}

/// A fresh one-time code `user` can enrol with, replacing any code issued
/// before. Only its hash is stored.
pub async fn issue_code(client: &Client, user: &str) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    let code = new_enrolment_code();
    client
        .write(&code_key(user), Some(&enrolment_code_hash(&code)))
        .await?;
    Ok(code)
}

/// Stores `user`'s keys, if `code` is the one issued to them, and uses the
/// code up. A wrong or used code is `EACCES`.
///
/// Enrolling again replaces the key pair, and takes every grant the
/// account held with it. The server decides what an account may do by
/// its grants, by name, not by what it can decrypt -- so grants left in
/// place would let whoever holds the new code delete and overwrite what
/// they can't read. A grant made concurrently can't slip past this: it
/// reads the account's keys in its own transaction, which this one
/// writes, so one of the two retries.
pub async fn enrol(
    client: &Client,
    user: &str,
    code: &str,
    keys: &AccountKeys,
) -> Result<(), FsError> {
    crate::grants::check_username(user)?;
    validate(keys)?;
    let hash = enrolment_code_hash(code);
    let encoded = encode(keys);
    retrying(|| {
        let (hash, encoded) = (&hash, &encoded);
        async move {
            let txn = client.transaction(TXN_TTL).await?;
            let issued = txn.read_one(&code_key(user)).await?.value;
            if issued.as_deref() != Some(hash.as_slice()) {
                return Ok(Err(FsError::new(
                    libc::EACCES,
                    format!("no such enrolment code for {user}"),
                )));
            }
            if txn.read_one(&keys_key(user)).await?.value.is_some() {
                for ino in granted_in(&txn, user).await? {
                    crate::grants::remove_grant(&txn, user, ino).await?;
                }
            }
            txn.write(&code_key(user), None).await?;
            txn.write(&keys_key(user), Some(encoded)).await?;
            txn.commit().await?;
            Ok(Ok(()))
        }
    })
    .await?
}

/// The inodes `user` holds grants of, per their grant index, as `txn`
/// sees it.
async fn granted_in(txn: &Transaction, user: &str) -> Result<Vec<u64>, KvError> {
    let prefix = crate::grants::index_prefix(user);
    let mut granted = Vec::new();
    let mut iter = txn.key_iterator(&prefix);
    while let Some(key) = iter.next().await? {
        if !key.starts_with(&prefix) {
            break;
        }
        if let Ok(ino) = <[u8; 8]>::try_from(&key[prefix.len()..]) {
            granted.push(u64::from_be_bytes(ino));
        }
    }
    Ok(granted)
}

/// Replaces `user`'s password-derived material, if `old_auth` is right.
/// The key pair must stay the same: what was granted to it has to keep
/// opening.
pub async fn change_password(
    client: &Client,
    user: &str,
    old_auth: &[u8],
    keys: &AccountKeys,
) -> Result<(), FsError> {
    validate(keys)?;
    let encoded = encode(keys);
    retrying(|| {
        let encoded = &encoded;
        async move {
            let txn = client.transaction(TXN_TTL).await?;
            let current = match txn.read_one(&keys_key(user)).await?.value {
                Some(bytes) => match decode(user, &bytes) {
                    Ok(current) => Some(current),
                    Err(e) => return Ok(Err(e)),
                },
                None => None,
            };
            let Some(current) = current.filter(|c| check_verifier(old_auth, &c.verifier)) else {
                return Ok(Err(FsError::new(
                    libc::EACCES,
                    "the username or old password was wrong",
                )));
            };
            if current.public_key != keys.public_key {
                return Ok(Err(FsError::new(
                    libc::EINVAL,
                    "a password change can't replace the key pair",
                )));
            }
            txn.write(&keys_key(user), Some(encoded)).await?;
            txn.commit().await?;
            Ok(Ok(()))
        }
    })
    .await?
}

/// Removes `user`: their keys, any code issued them, and every grant made
/// to them. Returns whether there was anything to remove. A session
/// already issued to them stops working once servers notice the keys are
/// gone (their identity cache).
pub async fn remove(client: &Client, user: &str) -> Result<bool, FsError> {
    let prefix = crate::grants::index_prefix(user);
    let mut granted = Vec::new();
    let mut iter = client.key_iterator(&prefix);
    while let Some(key) = iter.next().await? {
        if !key.starts_with(&prefix) {
            break;
        }
        if let Ok(ino) = <[u8; 8]>::try_from(&key[prefix.len()..]) {
            granted.push(u64::from_be_bytes(ino));
        }
    }
    let granted = &granted;
    retrying(|| async move {
        let txn = client.transaction(TXN_TTL).await?;
        let existed = txn.read_one(&keys_key(user)).await?.value.is_some()
            || txn.read_one(&code_key(user)).await?.value.is_some()
            || !granted.is_empty();
        txn.write(&keys_key(user), None).await?;
        txn.write(&code_key(user), None).await?;
        for &ino in granted {
            crate::grants::remove_grant(&txn, user, ino).await?;
        }
        txn.commit().await?;
        Ok(Ok(existed))
    })
    .await?
}

/// Every account with keys, and every one with a code it hasn't used yet,
/// in name order: `(name, enrolled)`.
pub async fn list(client: &Client) -> Result<Vec<(String, bool)>, FsError> {
    let mut accounts = std::collections::BTreeMap::new();
    for (prefix, enrolled) in [(ACCOUNT_KEYS_PREFIX, true), (ENROLMENT_PREFIX, false)] {
        let mut iter = client.key_iterator(prefix);
        while let Some(key) = iter.next().await? {
            if !key.starts_with(prefix) {
                break;
            }
            let name = String::from_utf8_lossy(&key[prefix.len()..]).into_owned();
            let entry = accounts.entry(name).or_insert(false);
            *entry |= enrolled;
        }
    }
    Ok(accounts.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> AccountKeys {
        AccountKeys {
            salt: vec![1; SALT_LEN],
            kdf_params: KdfParams::TESTING.encode().to_vec(),
            verifier: vec![2; 32],
            public_key: vec![3; PUBLIC_KEY_LEN],
            wrapped_private_key: vec![4; 72],
        }
    }

    #[test]
    fn keys_round_trip_and_garbage_is_eio() {
        let k = keys();
        assert_eq!(decode("u", &encode(&k)).unwrap(), k);
        let bytes = encode(&k);
        assert_eq!(
            decode("u", &bytes[..bytes.len() - 1]).unwrap_err().errno,
            libc::EIO
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode("u", &longer).unwrap_err().errno, libc::EIO);
    }

    #[test]
    fn malformed_keys_are_refused() {
        validate(&keys()).unwrap();
        let mut short_salt = keys();
        short_salt.salt.pop();
        let mut no_private = keys();
        no_private.wrapped_private_key.clear();
        let mut bad_params = keys();
        bad_params.kdf_params = vec![0; 5];
        for k in [short_salt, no_private, bad_params] {
            assert_eq!(validate(&k).unwrap_err().errno, libc::EINVAL);
        }
    }
}
