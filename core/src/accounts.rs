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
//! Users with the `admin` capability manage users: invite them under new
//! names (`issue_invite`), let existing users enroll again
//! (`reissue_invite`), change what they may do, and remove them. The
//! server's own tools (`add`, `set_caps`, `remove`) need no account.
//!
//! A public link is an account too (`create_link`), whose password only the
//! link holds. Its name starts with `LINK_PREFIX`, which nothing else may
//! use. It can only read the one folder its maker grants it, and it lasts
//! only as long as that grant (`drop_unused_link`) and until it expires. Its
//! holders share one secret, so nothing lets one of them change the account
//! or store anything under it (`refuse_link`).

use raft5_client::{Client, Consistency, Error as KvError, Transaction};
use raft5fs_crypto::identity::PUBLIC_KEY_LEN;
use raft5fs_crypto::password::{
    KdfParams, SALT_LEN, check_verifier, enrolment_code_hash, new_enrolment_code,
};

use crate::fs::{TxnError, run_txn};
use crate::layout::{
    ACCOUNT_INFO_PREFIX, ACCOUNT_KEYS_PREFIX, ENROLLMENT_PROOF_PREFIX, ENROLMENT_PREFIX,
    PINS_PREFIX, usage_key,
};
use crate::timing::next_key;
use crate::view::{ReadKeys, exactly};
use raft5fs_proto::clock;
use raft5fs_proto::errno;
use raft5fs_proto::types::{
    AccountInfo, AccountKeys, AccountKind, Caps, FsError, LINK_PREFIX, LinkAccount, MAX_LINK_NOTE,
    UserEntry,
};

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

fn pins_key(user: &str) -> Vec<u8> {
    let mut key = PINS_PREFIX.to_vec();
    key.extend_from_slice(user.as_bytes());
    key
}

fn proof_key(user: &str) -> Vec<u8> {
    let mut key = ENROLLMENT_PROOF_PREFIX.to_vec();
    key.extend_from_slice(user.as_bytes());
    key
}

/// The most bytes an invitation proof may take. A proof is 32.
pub const MAX_INVITE_PROOF: usize = 64;

/// What `user` enrolled with: their public key, and the proof of it from
/// their invitation (empty for none; raft5fs-crypto's `invitation`).
/// `ENOENT` if they have not enrolled. Both come from one transaction, so
/// they belong together.
pub async fn enrollment(client: &Client, user: &str) -> Result<(Vec<u8>, Vec<u8>), FsError> {
    run_txn(client, |txn| async move {
        let [keys, proof] = exactly(txn.read_many(&[keys_key(user), proof_key(user)]).await?);
        let Some(keys) = keys.value else {
            return Err(FsError::new(errno::ENOENT, format!("{user} hasn't enrolled")).into());
        };
        let keys = decode(user, &keys)?;
        Ok((keys.public_key, proof.value.unwrap_or_default()))
    })
    .await
}

/// The most that an account's sealed trusted keys may take: some thousands
/// of users.
pub const MAX_PINS_BYTES: usize = 256 * 1024;

/// `user`'s sealed trusted keys and their version: 0 and nothing if they
/// have none. The servers keep them only to give back; they can't open
/// them (raft5fs-crypto's `pins`).
pub async fn pins(client: &Client, user: &str) -> Result<(u64, Vec<u8>), FsError> {
    Ok(match client.read_one(&pins_key(user)).await?.value {
        Some(stored) => decode_pins(user, &stored)?,
        None => (0, Vec::new()),
    })
}

/// Refuses (`EACCES`) what only a person may do. Everyone who has a public
/// link has its secret, so one of them could otherwise end it for the rest,
/// or use it to store things.
pub(crate) fn refuse_link(user: &str) -> Result<(), FsError> {
    if user.starts_with(LINK_PREFIX) {
        return Err(FsError::new(errno::EACCES, "a public link can only read"));
    }
    Ok(())
}

/// Replaces `user`'s sealed trusted keys with `sealed` if they are still at
/// `expected`, the version that the caller read. Returns the new version.
/// `EAGAIN` if another device changed them since: read, merge, try again.
pub async fn put_pins(
    client: &Client,
    user: &str,
    expected: u64,
    sealed: &[u8],
) -> Result<u64, FsError> {
    refuse_link(user)?;
    if sealed.len() > MAX_PINS_BYTES {
        return Err(FsError::new(errno::EINVAL, "too many trusted keys"));
    }
    run_txn(client, |txn| async move {
        let current = match txn.read_one(&pins_key(user)).await?.value {
            Some(stored) => decode_pins(user, &stored)?.0,
            None => 0,
        };
        if current != expected {
            return Err(
                FsError::new(errno::EAGAIN, "the trusted keys changed in the meantime").into(),
            );
        }
        let mut stored = (current + 1).to_be_bytes().to_vec();
        stored.extend_from_slice(sealed);
        txn.write(&pins_key(user), Some(&stored)).await?;
        txn.commit().await?;
        Ok(current + 1)
    })
    .await
}

/// A stored pins record: its version, then the sealed list.
fn decode_pins(user: &str, stored: &[u8]) -> Result<(u64, Vec<u8>), FsError> {
    let mut r = raft5fs_wire::Reader::new(stored, "trusted keys");
    let version = r.u64().map_err(|_| {
        FsError::new(
            errno::EIO,
            format!("the trusted keys stored for {user:?} are garbled"),
        )
    })?;
    Ok((version, r.rest().to_vec()))
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
    raft5fs_wire::put_bytes(&mut out, info.invited_by.as_bytes());
    out.extend_from_slice(&info.created.to_be_bytes());
    raft5fs_wire::put_bytes(&mut out, info.owner.as_bytes());
    out.extend_from_slice(&info.expires.unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&info.folder.to_be_bytes());
    raft5fs_wire::put_bytes(&mut out, &info.note);
    // Added later: a record without it has no quota.
    if let Some(quota) = info.quota {
        out.extend_from_slice(&quota.to_be_bytes());
    }
    out
}

fn decode_info(user: &str, bytes: &[u8]) -> Result<AccountInfo, FsError> {
    let parse = || -> Result<AccountInfo, raft5fs_wire::Error> {
        let mut r = raft5fs_wire::Reader::new(bytes, "account record");
        if r.u8()? != INFO_VERSION {
            return Err(r.garbled());
        }
        let caps = Caps::from_bits(r.u32()?);
        let kind = match r.u8()? {
            0 => AccountKind::Person,
            1 => AccountKind::Link,
            _ => return Err(r.garbled()),
        };
        let invited_by = r.string()?;
        let created = r.u64()?;
        let owner = r.string()?;
        let expires = r.u64()?;
        let folder = r.u64()?;
        let note = r.bytes()?.to_vec();
        // Added later: older records end here.
        let quota = if r.is_empty() { None } else { Some(r.u64()?) };
        r.finish()?;
        Ok(AccountInfo {
            caps,
            kind,
            invited_by,
            created,
            owner,
            expires: (expires != 0).then_some(expires),
            folder,
            note,
            quota,
        })
    };
    parse().map_err(|_| {
        FsError::new(
            errno::EIO,
            format!("the account record stored for {user:?} is garbled"),
        )
    })
}

/// How long an enrollment code works. Whoever finds an old invitation, in a
/// mailbox or a chat, can enroll as that person.
const CODE_LIFETIME_SECS: u64 = 14 * 24 * 3600;

/// How a code is kept: its hash, then when it was issued.
fn stored_code(code: &str) -> Vec<u8> {
    let mut stored = enrolment_code_hash(code).to_vec();
    stored.extend_from_slice(&clock::now_secs().to_be_bytes());
    stored
}

/// When a stored code stops working, in seconds since the epoch. 0 for a code
/// from before they had an end, which is the hash alone.
fn code_expires(stored: &[u8]) -> u64 {
    stored
        .get(32..)
        .and_then(|issued| <[u8; 8]>::try_from(issued).ok())
        .map_or(0, |issued| {
            u64::from_be_bytes(issued).saturating_add(CODE_LIFETIME_SECS)
        })
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
        raft5fs_wire::put_bytes(&mut out, field);
    }
    out
}

fn decode(user: &str, bytes: &[u8]) -> Result<AccountKeys, FsError> {
    let parse = || -> Result<AccountKeys, raft5fs_wire::Error> {
        let mut r = raft5fs_wire::Reader::new(bytes, "account keys");
        let mut field = || r.bytes().map(<[u8]>::to_vec);
        let keys = AccountKeys {
            salt: field()?,
            kdf_params: field()?,
            verifier: field()?,
            public_key: field()?,
            wrapped_private_key: field()?,
        };
        r.finish()?;
        Ok(keys)
    };
    parse().map_err(|_| {
        FsError::new(
            errno::EIO,
            format!("the account keys stored for {user:?} are garbled"),
        )
    })
}

/// Refuses keys that an honest client could not make: wrong sizes, or cost
/// settings that Argon2 rejects. This cannot check what the keys open.
fn validate(keys: &AccountKeys) -> Result<(), FsError> {
    let bad = |what: &str| {
        Err(FsError::new(
            errno::EINVAL,
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
    let Some(keys) = get(client, user)
        .await?
        .filter(|keys| check_verifier(auth, &keys.verifier))
    else {
        return Ok(None);
    };
    if user.starts_with(LINK_PREFIX) && info(client, user).await?.expired(clock::now_secs()) {
        return Ok(None);
    }
    Ok(Some(keys))
}

/// `user`'s keys if they can still use a session: they have keys, and are not
/// a link that has expired.
pub async fn active_keys(client: &Client, user: &str) -> Result<Option<AccountKeys>, FsError> {
    let Some(keys) = get(client, user).await? else {
        return Ok(None);
    };
    if user.starts_with(LINK_PREFIX) && info(client, user).await?.expired(clock::now_secs()) {
        return Ok(None);
    }
    Ok(Some(keys))
}

/// Makes a new one-time code that `user` can enrol with, and replaces any
/// earlier code. Only its hash is stored.
pub async fn issue_code(client: &Client, user: &str) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    let code = new_enrolment_code();
    client
        .write(&code_key(user), Some(&stored_code(&code)))
        .await?;
    Ok(code)
}

fn refuse_link_name(user: &str) -> Result<(), FsError> {
    if user.starts_with(LINK_PREFIX) {
        return Err(FsError::new(
            errno::EINVAL,
            format!("names that start with {LINK_PREFIX} are for public links"),
        ));
    }
    Ok(())
}

/// How long a link may go without a grant after it is made: its maker
/// grants it a folder at once, so one without is left over from a failure.
const LINK_SETUP_GRACE: u64 = 3600;

/// `owner` makes the account for a public link: `user` (which starts with
/// `LINK_PREFIX`) with `keys`, which the owner made from the link's secret.
///
/// - `owner` needs the `links` capability (`EACCES`).
/// - The name must be new (`EEXIST`).
/// - The account may do nothing beyond its grant. Only `owner` can grant
///   it anything, and only `folder`, read-only (`check_link_grant`).
/// - From `expires` on, it can't log in.
///
/// It also removes `owner`'s earlier links that never got their grant.
pub async fn create_link(
    client: &Client,
    owner: &str,
    user: &str,
    keys: &AccountKeys,
    expires: Option<u64>,
    folder: u64,
    note: &[u8],
) -> Result<(), FsError> {
    crate::grants::check_username(user)?;
    if !user.starts_with(LINK_PREFIX) {
        return Err(FsError::new(
            errno::EINVAL,
            format!("a link's name starts with {LINK_PREFIX}"),
        ));
    }
    validate(keys)?;
    if note.len() > MAX_LINK_NOTE {
        return Err(FsError::new(errno::EINVAL, "the link's note is too long"));
    }
    let now = clock::now_secs();
    if expires.is_some_and(|at| at <= now) {
        return Err(FsError::new(errno::EINVAL, "the link would expire at once"));
    }
    for stale in links_of(client, owner).await? {
        if stale.info.created + LINK_SETUP_GRACE < now
            && list_granted(client, &stale.user).await?.is_empty()
        {
            remove(client, &stale.user).await?;
        }
    }
    let encoded = encode(keys);
    let info = AccountInfo {
        caps: Caps::NONE,
        kind: AccountKind::Link,
        created: now,
        owner: owner.to_string(),
        expires,
        folder,
        note: note.to_vec(),
        ..AccountInfo::default()
    };
    let record = encode_info(&info);
    run_txn(client, |txn| {
        let (encoded, record) = (&encoded, &record);
        async move {
            let mine = info_in(&txn, owner).await?.unwrap_or_default();
            if mine.kind != AccountKind::Person || !mine.caps.contains(Caps::LINKS) {
                return Err(FsError::new(
                    errno::EACCES,
                    "you can't make public links on this filesystem",
                )
                .into());
            }
            let taken = txn.read_one(&keys_key(user)).await?.value.is_some()
                || txn.read_one(&code_key(user)).await?.value.is_some()
                || txn.read_one(&info_key(user)).await?.value.is_some();
            if taken {
                return Err(
                    FsError::new(errno::EEXIST, format!("the name {user} is taken")).into(),
                );
            }
            txn.write(&keys_key(user), Some(encoded)).await?;
            txn.write(&info_key(user), Some(record)).await?;
            txn.commit().await?;
            Ok(())
        }
    })
    .await
}

/// The public links that `owner` made, in name order.
pub async fn links_of(client: &Client, owner: &str) -> Result<Vec<LinkAccount>, FsError> {
    let mut prefix = ACCOUNT_INFO_PREFIX.to_vec();
    prefix.extend_from_slice(LINK_PREFIX.as_bytes());
    let mut names = Vec::new();
    let mut iter = client.key_iterator(&prefix, Consistency::Stale);
    while let Some(key) = next_key(&mut iter).await? {
        if !key.starts_with(&prefix) {
            break;
        }
        names.push(String::from_utf8_lossy(&key[ACCOUNT_INFO_PREFIX.len()..]).into_owned());
    }
    let keys: Vec<Vec<u8>> = names.iter().map(|name| info_key(name)).collect();
    let records = client.read_many(&keys).await?;
    let mut links = Vec::new();
    for (user, record) in names.into_iter().zip(records) {
        let Some(bytes) = record.value else { continue };
        let info = decode_info(&user, &bytes)?;
        if info.kind == AccountKind::Link && info.owner == owner {
            links.push(LinkAccount { user, info });
        }
    }
    Ok(links)
}

/// Refuses a grant to a link, unless the link's maker grants it its own
/// folder, read-only. The servers give links no other way in.
pub(crate) async fn check_link_grant(
    txn: &Transaction,
    granter: &str,
    grantee: &str,
    ino: u64,
    writable: bool,
) -> Result<(), TxnError> {
    if !grantee.starts_with(LINK_PREFIX) {
        return Ok(());
    }
    let info = info_in(txn, grantee).await?.unwrap_or_default();
    let ok =
        info.kind == AccountKind::Link && info.owner == granter && info.folder == ino && !writable;
    if ok {
        Ok(())
    } else {
        Err(FsError::new(
            errno::EPERM,
            "a public link can only be shared by its maker, read-only, with its own folder",
        )
        .into())
    }
}

/// Removes link account `user` if `txn` leaves it no grant: a link lasts
/// only as long as its grant. Called by everything that removes a grant, so
/// a revoke by anyone, or deleting the folder, ends the link.
pub(crate) async fn drop_unused_link(txn: &Transaction, user: &str) -> Result<(), KvError> {
    if !user.starts_with(LINK_PREFIX) || !granted_in(txn, user).await?.is_empty() {
        return Ok(());
    }
    txn.write(&keys_key(user), None).await?;
    txn.write(&code_key(user), None).await?;
    txn.write(&pins_key(user), None).await?;
    txn.write(&info_key(user), None).await
}

/// The inodes that `user` has grants of, read without a transaction.
async fn list_granted(client: &Client, user: &str) -> Result<Vec<u64>, FsError> {
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
    Ok(granted)
}

/// Whether `user` has an account (keys, or a code to enroll with), as
/// `txn` sees it.
pub(crate) async fn exists_in(txn: &Transaction, user: &str) -> Result<bool, KvError> {
    Ok(txn.read_one(&keys_key(user)).await?.value.is_some()
        || txn.read_one(&code_key(user)).await?.value.is_some())
}

/// `user`'s record, or the default for an account with none.
pub async fn info(client: &Client, user: &str) -> Result<AccountInfo, FsError> {
    match client.read_one(&info_key(user)).await?.value {
        Some(bytes) => decode_info(user, &bytes),
        None => Ok(AccountInfo::default()),
    }
}

/// `user`'s record as `txn` sees it, if there is one.
async fn info_in(txn: &Transaction, user: &str) -> Result<Option<AccountInfo>, TxnError> {
    Ok(match txn.read_one(&info_key(user)).await?.value {
        Some(bytes) => Some(decode_info(user, &bytes)?),
        None => None,
    })
}

/// For an administrator: issues `user` a one-time code, as `issue_code`
/// does, and gives the account a record if it has none. A new record has
/// `Caps::VOLUMES`. Then the capabilities in `on` are turned on, and those
/// in `off` turned off.
pub async fn add(client: &Client, user: &str, on: Caps, off: Caps) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    refuse_link_name(user)?;
    let code = new_enrolment_code();
    let stored = stored_code(&code);
    run_txn(client, |txn| {
        let stored = &stored;
        async move {
            let mut info = info_in(&txn, user).await?.unwrap_or_else(|| AccountInfo {
                created: clock::now_secs(),
                ..AccountInfo::default()
            });
            info.caps = (info.caps | on).with(off, false);
            txn.write(&code_key(user), Some(stored)).await?;
            txn.write(&info_key(user), Some(&encode_info(&info)))
                .await?;
            txn.commit().await?;
            Ok(())
        }
    })
    .await?;
    Ok(code)
}

/// For an administrator: turns on the capabilities in `on` and off those
/// in `off` for `user`, and returns what they then have. `ENOENT` if
/// there is no such account and no code for one.
pub async fn set_caps(client: &Client, user: &str, on: Caps, off: Caps) -> Result<Caps, FsError> {
    run_txn(client, |txn| async move {
        let exists = txn.read_one(&keys_key(user)).await?.value.is_some()
            || txn.read_one(&code_key(user)).await?.value.is_some();
        if !exists {
            return Err(FsError::new(errno::ENOENT, format!("there is no user {user}")).into());
        }
        let mut info = info_in(&txn, user).await?.unwrap_or_default();
        info.caps = (info.caps | on).with(off, false);
        txn.write(&info_key(user), Some(&encode_info(&info)))
            .await?;
        txn.commit().await?;
        Ok(info.caps)
    })
    .await
}

/// For an administrator: sets how much the volumes `user` owns may hold
/// (`None`: no limit). `ENOENT` if there is no such account and no code
/// for one.
pub async fn set_quota(client: &Client, user: &str, quota: Option<u64>) -> Result<(), FsError> {
    run_txn(client, |txn| async move {
        change_info(&txn, user, |info| info.quota = quota).await?;
        txn.commit().await?;
        Ok(())
    })
    .await
}

/// Admin `caller` sets `user`'s quota (`set_quota`).
pub async fn admin_set_quota(
    client: &Client,
    caller: &str,
    user: &str,
    quota: Option<u64>,
) -> Result<(), FsError> {
    refuse_link_quota(user)?;
    run_txn(client, |txn| async move {
        require_admin(&txn, caller).await?;
        change_info(&txn, user, |info| info.quota = quota).await?;
        txn.commit().await?;
        Ok(())
    })
    .await
}

fn refuse_link_quota(user: &str) -> Result<(), FsError> {
    if user.starts_with(LINK_PREFIX) {
        return Err(FsError::new(
            errno::EINVAL,
            "a public link owns nothing, so has no quota",
        ));
    }
    Ok(())
}

/// Changes `user`'s record with `change`, in `txn`. `ENOENT` if there is
/// no such account and no code for one.
async fn change_info(
    txn: &Transaction,
    user: &str,
    change: impl FnOnce(&mut AccountInfo),
) -> Result<AccountInfo, TxnError> {
    let exists = txn.read_one(&keys_key(user)).await?.value.is_some()
        || txn.read_one(&code_key(user)).await?.value.is_some();
    if !exists {
        return Err(FsError::new(errno::ENOENT, format!("there is no user {user}")).into());
    }
    let mut info = info_in(txn, user).await?.unwrap_or_default();
    change(&mut info);
    txn.write(&info_key(user), Some(&encode_info(&info)))
        .await?;
    Ok(info)
}

/// Refuses (`EACCES`) unless `caller` is a person with the `admin`
/// capability, as `txn` sees it. Read in the same transaction as what it
/// allows, so an admin who just lost the capability can't still act.
async fn require_admin(txn: &Transaction, caller: &str) -> Result<(), TxnError> {
    let info = info_in(txn, caller).await?.unwrap_or_default();
    if info.kind == AccountKind::Person && info.caps.contains(Caps::ADMIN) {
        Ok(())
    } else {
        Err(FsError::new(errno::EACCES, "only administrators can manage users").into())
    }
}

/// Admin `caller` invites a new user `user`, who gets `caps`. Returns the
/// one-time code that `user` enrolls with. `user` must be new: no keys,
/// code or record (`EEXIST`); `reissue_invite` is for existing accounts.
pub async fn issue_invite(
    client: &Client,
    caller: &str,
    user: &str,
    caps: Caps,
) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    refuse_link_name(user)?;
    let code = new_enrolment_code();
    let stored = stored_code(&code);
    run_txn(client, |txn| {
        let stored = &stored;
        async move {
            require_admin(&txn, caller).await?;
            let taken = txn.read_one(&keys_key(user)).await?.value.is_some()
                || txn.read_one(&code_key(user)).await?.value.is_some()
                || txn.read_one(&info_key(user)).await?.value.is_some();
            if taken {
                return Err(
                    FsError::new(errno::EEXIST, format!("the name {user} is taken")).into(),
                );
            }
            let info = AccountInfo {
                caps,
                kind: AccountKind::Person,
                invited_by: caller.to_string(),
                created: clock::now_secs(),
                ..AccountInfo::default()
            };
            txn.write(&code_key(user), Some(stored)).await?;
            txn.write(&info_key(user), Some(&encode_info(&info)))
                .await?;
            txn.commit().await?;
            Ok(())
        }
    })
    .await?;
    Ok(code)
}

/// Admin `caller` lets existing user `user` enroll again: issues them a new
/// one-time code, in place of any earlier one. Enrolling with it replaces
/// their key pair and removes every grant made to them (see `enrol`).
/// `ENOENT` for no such user; `EINVAL` for a public link, which never
/// enrolls.
pub async fn reissue_invite(client: &Client, caller: &str, user: &str) -> Result<String, FsError> {
    crate::grants::check_username(user)?;
    refuse_link_name(user)?;
    let code = new_enrolment_code();
    let stored = stored_code(&code);
    run_txn(client, |txn| {
        let stored = &stored;
        async move {
            require_admin(&txn, caller).await?;
            let exists = txn.read_one(&keys_key(user)).await?.value.is_some()
                || txn.read_one(&code_key(user)).await?.value.is_some();
            if !exists {
                return Err(FsError::new(errno::ENOENT, format!("there is no user {user}")).into());
            }
            txn.write(&code_key(user), Some(stored)).await?;
            txn.commit().await?;
            Ok(())
        }
    })
    .await?;
    Ok(code)
}

/// Admin `caller` turns `user`'s capabilities in `on` on and those in `off`
/// off (`set_caps`). An admin can't take away their own `admin` (`EPERM`):
/// so there is always one, another admin or the server's tools must.
pub async fn admin_set_caps(
    client: &Client,
    caller: &str,
    user: &str,
    on: Caps,
    off: Caps,
) -> Result<AccountInfo, FsError> {
    if user == caller && off.contains(Caps::ADMIN) {
        return Err(FsError::new(
            errno::EPERM,
            "you can't take away your own admin capability",
        ));
    }
    if user.starts_with(LINK_PREFIX) {
        return Err(FsError::new(
            errno::EINVAL,
            "a public link has no capabilities",
        ));
    }
    run_txn(client, |txn| async move {
        require_admin(&txn, caller).await?;
        let exists = txn.read_one(&keys_key(user)).await?.value.is_some()
            || txn.read_one(&code_key(user)).await?.value.is_some();
        if !exists {
            return Err(FsError::new(errno::ENOENT, format!("there is no user {user}")).into());
        }
        let mut info = info_in(&txn, user).await?.unwrap_or_default();
        info.caps = (info.caps | on).with(off, false);
        txn.write(&info_key(user), Some(&encode_info(&info)))
            .await?;
        txn.commit().await?;
        Ok(info)
    })
    .await
}

/// Admin `caller` removes `user` (`remove`): an account, an invitation not
/// used yet, or a public link. An admin can't remove themselves (`EPERM`).
/// `ENOENT` if there was nothing to remove.
pub async fn admin_remove(client: &Client, caller: &str, user: &str) -> Result<(), FsError> {
    if user == caller {
        return Err(FsError::new(errno::EPERM, "you can't remove yourself"));
    }
    is_admin(client, caller).await?;
    if remove(client, user).await? {
        Ok(())
    } else {
        Err(FsError::new(
            errno::ENOENT,
            format!("there is no user {user}"),
        ))
    }
}

/// Every account, for admin `caller` (`list`).
pub async fn admin_list(client: &Client, caller: &str) -> Result<Vec<UserEntry>, FsError> {
    is_admin(client, caller).await?;
    list(client).await
}

/// Refuses (`EACCES`) unless `caller` is an admin (`require_admin`, outside
/// a transaction).
pub async fn is_admin(client: &Client, caller: &str) -> Result<(), FsError> {
    run_txn(
        client,
        |txn| async move { require_admin(&txn, caller).await },
    )
    .await
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
/// `invite_proof` is from an invitation with an introduction, or empty. It
/// is kept for the inviter to check (`enrollment`), and replaces any proof
/// from an earlier enrollment.
pub async fn enrol(
    client: &Client,
    user: &str,
    code: &str,
    keys: &AccountKeys,
    invite_proof: &[u8],
) -> Result<(), FsError> {
    crate::grants::check_username(user)?;
    if invite_proof.len() > MAX_INVITE_PROOF {
        return Err(FsError::new(
            errno::EINVAL,
            "an invitation proof of the wrong size",
        ));
    }
    validate(keys)?;
    let hash = enrolment_code_hash(code);
    let encoded = encode(keys);
    run_txn(client, |txn| {
        let (hash, encoded) = (&hash, &encoded);
        async move {
            let issued = txn.read_one(&code_key(user)).await?.value;
            let Some(issued) = issued.filter(|i| i.get(..32) == Some(hash.as_slice())) else {
                return Err(FsError::new(
                    errno::EACCES,
                    format!("no such enrolment code for {user}"),
                )
                .into());
            };
            let expires = code_expires(&issued);
            if expires != 0 && expires < clock::now_secs() {
                return Err(FsError::new(
                    errno::EACCES,
                    format!("{user}'s invitation has expired: ask an admin for a new one"),
                )
                .into());
            }
            // Whatever this name had was sealed to another key pair, so it is
            // no use to the new one. Not only for a name with keys now: a
            // grant made as a user was removed can outlive them.
            for ino in granted_in(&txn, user).await? {
                crate::grants::remove_grant_unlisted(&txn, user, ino).await?;
            }
            // Introductions of the old key, and to it, no longer hold.
            crate::introductions::forget_user(&txn, user).await?;
            txn.write(&pins_key(user), None).await?;
            txn.write(&code_key(user), None).await?;
            txn.write(
                &proof_key(user),
                (!invite_proof.is_empty()).then_some(invite_proof),
            )
            .await?;
            txn.write(&keys_key(user), Some(encoded)).await?;
            txn.commit().await?;
            Ok(())
        }
    })
    .await
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
    refuse_link(user)?;
    validate(keys)?;
    let encoded = encode(keys);
    run_txn(client, |txn| {
        let encoded = &encoded;
        async move {
            let current = match txn.read_one(&keys_key(user)).await?.value {
                Some(bytes) => match decode(user, &bytes) {
                    Ok(current) => Some(current),
                    Err(e) => return Err(e.into()),
                },
                None => None,
            };
            let Some(current) = current.filter(|c| check_verifier(old_auth, &c.verifier)) else {
                return Err(
                    FsError::new(errno::EACCES, "the username or old password was wrong").into(),
                );
            };
            if current.public_key != keys.public_key {
                return Err(FsError::new(
                    errno::EINVAL,
                    "a password change can't replace the key pair",
                )
                .into());
            }
            txn.write(&keys_key(user), Some(encoded)).await?;
            txn.commit().await?;
            Ok(())
        }
    })
    .await
}

/// Removes `user`: their keys, any code issued to them, their record, and
/// every grant made to them. Returns whether there was anything to remove. A session
/// already issued to them stops working when the servers see that the keys
/// are gone (their identity cache).
pub async fn remove(client: &Client, user: &str) -> Result<bool, FsError> {
    run_txn(client, |txn| async move {
        // In the transaction: a grant made meanwhile doesn't stay behind.
        let granted = granted_in(&txn, user).await?;
        let existed = txn.read_one(&keys_key(user)).await?.value.is_some()
            || txn.read_one(&code_key(user)).await?.value.is_some()
            || txn.read_one(&info_key(user)).await?.value.is_some()
            || !granted.is_empty();
        txn.write(&keys_key(user), None).await?;
        txn.write(&code_key(user), None).await?;
        txn.write(&info_key(user), None).await?;
        txn.write(&pins_key(user), None).await?;
        txn.write(&usage_key(user), None).await?;
        txn.write(&proof_key(user), None).await?;
        crate::introductions::forget_user(&txn, user).await?;
        for ino in granted {
            crate::grants::remove_grant_unlisted(&txn, user, ino).await?;
        }
        txn.commit().await?;
        Ok(existed)
    })
    .await
}

/// Every account with keys, and every account with an unused code, in name
/// order.
pub async fn list(client: &Client) -> Result<Vec<UserEntry>, FsError> {
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
    let keys: Vec<Vec<u8>> = names.iter().map(|name| usage_key(name)).collect();
    let usage = client.read_many(&keys).await?;
    let keys: Vec<Vec<u8>> = names.iter().map(|name| code_key(name)).collect();
    let codes = client.read_many(&keys).await?;
    accounts
        .iter()
        .zip(records)
        .zip(usage)
        .zip(codes)
        .map(|((((name, &enrolled), record), usage), code)| {
            let info = match record.value {
                Some(bytes) => decode_info(name, &bytes)?,
                None => AccountInfo::default(),
            };
            let used = usage
                .value
                .and_then(|v| crate::fs::usage::decode_usage(&v))
                .map_or(0, |(bytes, _)| bytes);
            Ok(UserEntry {
                user: name.clone(),
                enrolled,
                info,
                used,
                code_expires: code.value.as_deref().map(code_expires),
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
            errno::EIO
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode("u", &longer).unwrap_err().errno, errno::EIO);
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
            folder: 42,
            note: vec![7; 20],
            quota: Some(10 << 30),
        };
        assert_eq!(decode_info("u", &encode_info(&info)).unwrap(), info);
        let plain = AccountInfo::default();
        assert_eq!(decode_info("u", &encode_info(&plain)).unwrap(), plain);
        let bytes = encode_info(&info);
        // A record from before quotas: no quota.
        let older = decode_info("u", &bytes[..bytes.len() - 8]).unwrap();
        assert_eq!(older.quota, None);
        assert_eq!(
            decode_info("u", &bytes[..bytes.len() - 1])
                .unwrap_err()
                .errno,
            errno::EIO
        );
        let mut other_version = bytes.clone();
        other_version[0] = 2;
        assert_eq!(
            decode_info("u", &other_version).unwrap_err().errno,
            errno::EIO
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
            assert_eq!(validate(&k).unwrap_err().errno, errno::EINVAL);
        }
    }
}

/// The stored layouts of accounts, pinned.
#[cfg(test)]
mod golden {
    use super::*;

    fn info(quota: Option<u64>) -> AccountInfo {
        AccountInfo {
            caps: Caps::VOLUMES | Caps::LINKS,
            kind: AccountKind::Link,
            invited_by: "alice".into(),
            created: 1_700_000_000,
            owner: "bob".into(),
            expires: Some(1_800_000_000),
            folder: 42,
            note: vec![1, 2, 3],
            quota,
        }
    }

    #[test]
    fn account_records_keep_their_bytes() {
        for (quota, golden) in [
            (
                Some(5_000),
                "01000000050100000005616c696365000000006553f10000000003626f62000000006b49d200000000000000002a000000030102030000000000001388",
            ),
            (
                None,
                "01000000050100000005616c696365000000006553f10000000003626f62000000006b49d200000000000000002a00000003010203",
            ),
        ] {
            assert_eq!(raft5fs_wire::hex(&encode_info(&info(quota))), golden);
            let back = decode_info("u", &raft5fs_wire::from_hex(golden).unwrap()).unwrap();
            assert_eq!(raft5fs_wire::hex(&encode_info(&back)), golden);
        }
        let keys = AccountKeys {
            salt: vec![1],
            kdf_params: vec![2, 2],
            verifier: vec![3, 3, 3],
            public_key: vec![4; 4],
            wrapped_private_key: vec![5; 5],
        };
        let golden = "0000000101000000020202000000030303030000000404040404000000050505050505";
        assert_eq!(raft5fs_wire::hex(&encode(&keys)), golden);
        let back = decode("u", &raft5fs_wire::from_hex(golden).unwrap()).unwrap();
        assert_eq!(raft5fs_wire::hex(&encode(&back)), golden);

        let mut code = vec![9; 32];
        code.extend_from_slice(&1000u64.to_be_bytes());
        assert_eq!(code_expires(&code), 1000 + CODE_LIFETIME_SECS);
        assert_eq!(code_expires(&code[..32]), 0);

        let mut pins = 7u64.to_be_bytes().to_vec();
        pins.extend_from_slice(b"sealed");
        assert_eq!(decode_pins("u", &pins).unwrap(), (7, b"sealed".to_vec()));
    }
}
