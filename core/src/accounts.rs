//! Accounts: what checks a login, and the user's wrapped private key.
//!
//! The server never sees a password. Each account holds what the client
//! derived from one (see raft5fs-crypto's `password`):
//!
//! - a salt and cost settings to stretch the password with;
//! - a verifier to check the resulting `auth` against;
//! - the user's key pair: the public key, and the private key wrapped under
//!   a key that only the password gives.
//!
//! An account is its keys. A user gets keys by enrolling with a one-time
//! code from an administrator (`issue_code`). This is the only step to add
//! a user. Only the code's hash is stored, and enrolling uses it up. A new
//! code lets a user who lost their password enrol again, with a new key
//! pair. Anything granted to the old key pair is then out of reach until
//! someone grants it again.
//!
//! Beside its keys, an account can have a record (`AccountInfo`): its
//! capabilities, its kind, and who invited it. It is kept apart from the
//! keys, so enrolling again keeps it. An account with no record (one added
//! before records existed) may make volumes and nothing else.
//!
//! Users with the `invite` capability can invite others (`issue_invite`),
//! but only under new names: a code for an existing account would let its
//! holder replace that account's keys.

use raft5_client::{Client, Consistency, Error as KvError, Transaction};
use raft5fs_crypto::identity::PUBLIC_KEY_LEN;
use raft5fs_crypto::password::{
    KdfParams, SALT_LEN, check_verifier, enrolment_code_hash, new_enrolment_code,
};

use crate::fs::{TXN_TTL, retrying};
use crate::layout::{ACCOUNT_INFO_PREFIX, ACCOUNT_KEYS_PREFIX, ENROLMENT_PREFIX};
use crate::timing::next_key;
use crate::view::ReadKeys;
use raft5fs_proto::types::{
    AccountInfo, AccountKeys, AccountKind, Caps, FsError, LINK_PREFIX, MAX_PENDING_INVITES,
    PendingInvite,
};

/// In a transaction attempt, unwraps a decision, or ends the attempt with
/// it as `Ok(Err(..))`, which `retrying` does not retry (as in `fs`).
macro_rules! decide {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => return Ok(Err(e)),
        }
    };
}

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

fn info_key(user: &str) -> Vec<u8> {
    let mut key = ACCOUNT_INFO_PREFIX.to_vec();
    key.extend_from_slice(user.as_bytes());
    key
}

/// The format version of an account record.
const INFO_VERSION: u8 = 1;

fn encode_info(info: &AccountInfo) -> Vec<u8> {
    let mut out = vec![INFO_VERSION];
    out.extend_from_slice(&info.caps.bits().to_be_bytes());
    out.push(match info.kind {
        AccountKind::Person => 0,
        AccountKind::Link => 1,
    });
    put(&mut out, info.invited_by.as_bytes());
    out.extend_from_slice(&info.created.to_be_bytes());
    put(&mut out, info.owner.as_bytes());
    out.extend_from_slice(&info.expires.unwrap_or(0).to_be_bytes());
    out
}

fn decode_info(user: &str, bytes: &[u8]) -> Result<AccountInfo, FsError> {
    let garbled = || {
        FsError::new(
            libc::EIO,
            format!("the account record stored for {user:?} is garbled"),
        )
    };
    let mut rest = bytes;
    let mut take = |n: usize| -> Result<&[u8], FsError> {
        let (head, tail) = rest.split_at_checked(n).ok_or_else(garbled)?;
        rest = tail;
        Ok(head)
    };
    if take(1)? != [INFO_VERSION] {
        return Err(garbled());
    }
    let caps = Caps::from_bits(u32::from_be_bytes(take(4)?.try_into().unwrap()));
    let kind = match take(1)? {
        [0] => AccountKind::Person,
        [1] => AccountKind::Link,
        _ => return Err(garbled()),
    };
    let n = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
    let invited_by = String::from_utf8(take(n)?.to_vec()).map_err(|_| garbled())?;
    let created = u64::from_be_bytes(take(8)?.try_into().unwrap());
    let n = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
    let owner = String::from_utf8(take(n)?.to_vec()).map_err(|_| garbled())?;
    let expires = u64::from_be_bytes(take(8)?.try_into().unwrap());
    if !rest.is_empty() {
        return Err(garbled());
    }
    Ok(AccountInfo {
        caps,
        kind,
        invited_by,
        created,
        owner,
        expires: (expires != 0).then_some(expires),
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

/// Refuses keys that an honest client could not make: wrong sizes, or cost
/// settings that Argon2 rejects. This cannot check what the keys open.
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

/// The keys of each user in `users`, in order, read as `get` reads them.
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

/// Returns `user`'s keys if `auth` is correct for them. A wrong `auth` and
/// an account with no keys give the same result, so a login does not show a
/// stranger which accounts exist.
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

/// Makes a new one-time code that `user` can enrol with, and replaces any
/// earlier code. Only its hash is stored.
pub async fn issue_code(client: &Client, user: &str) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    let code = new_enrolment_code();
    client
        .write(&code_key(user), Some(&enrolment_code_hash(&code)))
        .await?;
    Ok(code)
}

/// `user`'s record, or the default for an account with none.
pub async fn info(client: &Client, user: &str) -> Result<AccountInfo, FsError> {
    match client.read_one(&info_key(user)).await?.value {
        Some(bytes) => decode_info(user, &bytes),
        None => Ok(AccountInfo::default()),
    }
}

/// `user`'s record as `txn` sees it, if there is one.
async fn info_in(
    txn: &Transaction,
    user: &str,
) -> Result<Result<Option<AccountInfo>, FsError>, KvError> {
    Ok(match txn.read_one(&info_key(user)).await?.value {
        Some(bytes) => decode_info(user, &bytes).map(Some),
        None => Ok(None),
    })
}

/// For an administrator: issues `user` a one-time code, as `issue_code`
/// does, and gives the account a record if it has none. A new record has
/// `Caps::VOLUMES`. Then the capabilities in `on` are turned on, and those
/// in `off` turned off.
pub async fn add(client: &Client, user: &str, on: Caps, off: Caps) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    let code = new_enrolment_code();
    let hash = enrolment_code_hash(&code);
    retrying(|| {
        let hash = &hash;
        async move {
            let txn = client.transaction(TXN_TTL).await?;
            let mut info = decide!(info_in(&txn, user).await?).unwrap_or_else(|| AccountInfo {
                created: now_secs(),
                ..AccountInfo::default()
            });
            info.caps = (info.caps | on).with(off, false);
            txn.write(&code_key(user), Some(hash)).await?;
            txn.write(&info_key(user), Some(&encode_info(&info)))
                .await?;
            txn.commit().await?;
            Ok(Ok(()))
        }
    })
    .await??;
    Ok(code)
}

/// For an administrator: turns on the capabilities in `on` and off those
/// in `off` for `user`, and returns what they then have. `ENOENT` if
/// there is no such account and no code for one.
pub async fn set_caps(client: &Client, user: &str, on: Caps, off: Caps) -> Result<Caps, FsError> {
    retrying(|| async move {
        let txn = client.transaction(TXN_TTL).await?;
        let exists = txn.read_one(&keys_key(user)).await?.value.is_some()
            || txn.read_one(&code_key(user)).await?.value.is_some();
        if !exists {
            return Ok(Err(FsError::new(
                libc::ENOENT,
                format!("there is no user {user}"),
            )));
        }
        let mut info = decide!(info_in(&txn, user).await?).unwrap_or_default();
        info.caps = (info.caps | on).with(off, false);
        txn.write(&info_key(user), Some(&encode_info(&info)))
            .await?;
        txn.commit().await?;
        Ok(Ok(info.caps))
    })
    .await?
}

/// `inviter` invites a new user `user`, who gets `caps`. Returns the
/// one-time code that `user` enrols with.
///
/// - `inviter` needs the `invite` capability, and `caps` must be among
///   theirs, so a chain of invitations never gains anything (`EACCES`).
/// - `user` must be new: no keys, code or record (`EEXIST`). A code for an
///   existing account would let whoever holds it replace the account's keys,
///   which removes every grant it has.
/// - `inviter` can have at most `MAX_PENDING_INVITES` unused invitations
///   (`EDQUOT`).
pub async fn issue_invite(
    client: &Client,
    inviter: &str,
    user: &str,
    caps: Caps,
) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    if user.starts_with(LINK_PREFIX) {
        return Err(FsError::new(
            libc::EINVAL,
            format!("names that start with {LINK_PREFIX} are for public links"),
        ));
    }
    let code = new_enrolment_code();
    let hash = enrolment_code_hash(&code);
    retrying(|| {
        let hash = &hash;
        async move {
            let txn = client.transaction(TXN_TTL).await?;
            let mine = decide!(info_in(&txn, inviter).await?).unwrap_or_default();
            if mine.kind != AccountKind::Person || !mine.caps.contains(Caps::INVITE) {
                return Ok(Err(FsError::new(
                    libc::EACCES,
                    "you can't invite users to this filesystem",
                )));
            }
            if !mine.caps.contains(caps) {
                return Ok(Err(FsError::new(
                    libc::EACCES,
                    "you can only give others what you can do yourself",
                )));
            }
            let taken = txn.read_one(&keys_key(user)).await?.value.is_some()
                || txn.read_one(&code_key(user)).await?.value.is_some()
                || txn.read_one(&info_key(user)).await?.value.is_some();
            if taken {
                return Ok(Err(FsError::new(
                    libc::EEXIST,
                    format!("the name {user} is taken"),
                )));
            }
            let waiting = decide!(pending_in(&txn, inviter).await?);
            if waiting.len() >= MAX_PENDING_INVITES {
                return Ok(Err(FsError::new(
                    libc::EDQUOT,
                    format!(
                        "you have {MAX_PENDING_INVITES} invitations nobody has used yet: \
                         cancel one first"
                    ),
                )));
            }
            let info = AccountInfo {
                caps,
                kind: AccountKind::Person,
                invited_by: inviter.to_string(),
                created: now_secs(),
                ..AccountInfo::default()
            };
            txn.write(&code_key(user), Some(hash)).await?;
            txn.write(&info_key(user), Some(&encode_info(&info)))
                .await?;
            txn.commit().await?;
            Ok(Ok(()))
        }
    })
    .await??;
    Ok(code)
}

/// `inviter`'s invitations that nobody has enrolled with yet, as `txn`
/// sees them, in name order.
async fn pending_in(
    txn: &Transaction,
    inviter: &str,
) -> Result<Result<Vec<PendingInvite>, FsError>, KvError> {
    let mut pending = Vec::new();
    let mut iter = txn.key_iterator(ENROLMENT_PREFIX);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(ENROLMENT_PREFIX) {
            break;
        }
        let user = String::from_utf8_lossy(&key[ENROLMENT_PREFIX.len()..]).into_owned();
        // A code for an account that has keys is a second enrolment, not
        // an invitation.
        if txn.read_one(&keys_key(&user)).await?.value.is_some() {
            continue;
        }
        if let Some(info) = decide!(info_in(txn, &user).await?)
            && info.invited_by == inviter
        {
            pending.push(PendingInvite {
                user,
                caps: info.caps,
                created: info.created,
            });
        }
    }
    Ok(Ok(pending))
}

/// `inviter`'s invitations that nobody has enrolled with yet.
pub async fn pending_invites(
    client: &Client,
    inviter: &str,
) -> Result<Vec<PendingInvite>, FsError> {
    retrying(|| async move {
        let txn = client.transaction(TXN_TTL).await?;
        pending_in(&txn, inviter).await
    })
    .await?
}

/// Withdraws `inviter`'s unused invitation of `user`: removes its code and
/// the record. `ENOENT` if `inviter` has no such invitation.
pub async fn cancel_invite(client: &Client, inviter: &str, user: &str) -> Result<(), FsError> {
    retrying(|| async move {
        let txn = client.transaction(TXN_TTL).await?;
        let info = decide!(info_in(&txn, user).await?);
        let pending = info.is_some_and(|info| info.invited_by == inviter)
            && txn.read_one(&code_key(user)).await?.value.is_some()
            && txn.read_one(&keys_key(user)).await?.value.is_none();
        if !pending {
            return Ok(Err(FsError::new(
                libc::ENOENT,
                format!("you have no unused invitation for {user}"),
            )));
        }
        txn.write(&code_key(user), None).await?;
        txn.write(&info_key(user), None).await?;
        txn.commit().await?;
        Ok(Ok(()))
    })
    .await?
}

/// Stores `user`'s keys if `code` is the code issued to them, and uses the
/// code up. A wrong or used code gives `EACCES`.
///
/// Enrolling again replaces the key pair and removes every grant the
/// account had. The server decides what an account can do by its grants, by
/// name, not by what it can decrypt. So if the grants stayed, the holder of
/// the new code could delete and overwrite data that they cannot read.
///
/// A grant made at the same time cannot get past this. The grant reads the
/// account's keys in its own transaction, and this transaction writes them,
/// so one of the two retries.
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

/// The inodes that `user` has grants of, from their grant index, as `txn`
/// sees it.
async fn granted_in(txn: &Transaction, user: &str) -> Result<Vec<u64>, KvError> {
    let prefix = crate::grants::index_prefix(user);
    let mut granted = Vec::new();
    let mut iter = txn.key_iterator(&prefix);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(&prefix) {
            break;
        }
        if let Ok(ino) = <[u8; 8]>::try_from(&key[prefix.len()..]) {
            granted.push(u64::from_be_bytes(ino));
        }
    }
    Ok(granted)
}

/// Replaces the parts of `user`'s account that come from the password, if
/// `old_auth` is correct. The key pair must stay the same, so that what was
/// granted to it still opens.
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

/// Removes `user`: their keys, any code issued to them, their record, and
/// every grant made to them. Returns whether there was anything to remove. A session
/// already issued to them stops working when the servers see that the keys
/// are gone (their identity cache).
pub async fn remove(client: &Client, user: &str) -> Result<bool, FsError> {
    let prefix = crate::grants::index_prefix(user);
    let mut granted = Vec::new();
    let mut iter = client.key_iterator(&prefix, Consistency::Stale);
    while let Some(key) = next_key(&mut iter).await? {
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
            || txn.read_one(&info_key(user)).await?.value.is_some()
            || !granted.is_empty();
        txn.write(&keys_key(user), None).await?;
        txn.write(&code_key(user), None).await?;
        txn.write(&info_key(user), None).await?;
        for &ino in granted {
            crate::grants::remove_grant(&txn, user, ino).await?;
        }
        txn.commit().await?;
        Ok(Ok(existed))
    })
    .await?
}

/// An account, as `list` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    /// Whether it has keys. If not, it has only a code.
    pub enrolled: bool,
    pub info: AccountInfo,
}

/// Every account with keys, and every account with an unused code, in name
/// order.
pub async fn list(client: &Client) -> Result<Vec<Listed>, FsError> {
    let mut accounts = std::collections::BTreeMap::new();
    for (prefix, enrolled) in [(ACCOUNT_KEYS_PREFIX, true), (ENROLMENT_PREFIX, false)] {
        let mut iter = client.key_iterator(prefix, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(prefix) {
                break;
            }
            let name = String::from_utf8_lossy(&key[prefix.len()..]).into_owned();
            let entry = accounts.entry(name).or_insert(false);
            *entry |= enrolled;
        }
    }
    let names: Vec<&String> = accounts.keys().collect();
    let keys: Vec<Vec<u8>> = names.iter().map(|name| info_key(name)).collect();
    let records = client.read_many(&keys).await?;
    accounts
        .iter()
        .zip(records)
        .map(|((name, &enrolled), record)| {
            let info = match record.value {
                Some(bytes) => decode_info(name, &bytes)?,
                None => AccountInfo::default(),
            };
            Ok(Listed {
                name: name.clone(),
                enrolled,
                info,
            })
        })
        .collect()
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
    fn records_round_trip_and_garbage_is_eio() {
        let info = AccountInfo {
            caps: Caps::VOLUMES | Caps::LINKS,
            kind: AccountKind::Link,
            invited_by: "alice".into(),
            created: 1_700_000_000,
            owner: "bob".into(),
            expires: Some(1_800_000_000),
        };
        assert_eq!(decode_info("u", &encode_info(&info)).unwrap(), info);
        let plain = AccountInfo::default();
        assert_eq!(decode_info("u", &encode_info(&plain)).unwrap(), plain);
        let bytes = encode_info(&info);
        assert_eq!(
            decode_info("u", &bytes[..bytes.len() - 1])
                .unwrap_err()
                .errno,
            libc::EIO
        );
        let mut other_version = bytes.clone();
        other_version[0] = 2;
        assert_eq!(
            decode_info("u", &other_version).unwrap_err().errno,
            libc::EIO
        );
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
