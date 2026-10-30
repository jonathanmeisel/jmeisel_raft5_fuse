//! Volume ownership: each volume has an owner, whose quota everything in it
//! counts against, and who always has read-write access to it.
//!
//! - `create_volume` makes the creator the owner.
//! - Volumes from before owners get one when a server starts
//!   (`assign_missing_owners`): the only user with a writable grant of the
//!   volume, if there is exactly one. Otherwise the volume stays without an
//!   owner, and counts against nobody, until an admin assigns one.
//! - Nobody can drop the owner's grant of their volume, or make it
//!   read-only (`check_owner_kept`, from `rotate` and `grant`). Removing the
//!   owner's account, or enrolling it again, still drops it: the volume is
//!   then orphaned.
//!
//! A record, under `VOLUME_PREFIX`, is a format byte, the owner (empty for
//! none), and a pending transfer offer: to whom (empty for none), and when.

use super::*;
use crate::layout::{ROOT_INO, dirent_ino, dirent_prefix, volume_key};
use raft5fs_proto::types::{LINK_PREFIX, VolumeInfo};

const FORMAT: u8 = 1;

pub(crate) fn encode_volume(v: &VolumeInfo) -> Vec<u8> {
    let mut out = vec![FORMAT];
    let field = |out: &mut Vec<u8>, s: &str| {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    };
    field(&mut out, v.owner.as_deref().unwrap_or(""));
    let (to, at) = v.offer.clone().unwrap_or_default();
    field(&mut out, &to);
    out.extend_from_slice(&at.to_be_bytes());
    out
}

pub(crate) fn decode_volume(ino: u64, bytes: &[u8]) -> Result<VolumeInfo, FsError> {
    let garbled = || FsError::new(libc::EIO, format!("volume {ino}'s record is garbled"));
    let mut rest = bytes;
    let mut take = |n: usize| -> Result<&[u8], FsError> {
        let (head, tail) = rest.split_at_checked(n).ok_or_else(garbled)?;
        rest = tail;
        Ok(head)
    };
    if take(1)? != [FORMAT] {
        return Err(garbled());
    }
    let n = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
    let owner = String::from_utf8(take(n)?.to_vec()).map_err(|_| garbled())?;
    let n = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
    let to = String::from_utf8(take(n)?.to_vec()).map_err(|_| garbled())?;
    let at = u64::from_be_bytes(take(8)?.try_into().unwrap());
    if !rest.is_empty() {
        return Err(garbled());
    }
    Ok(VolumeInfo {
        owner: (!owner.is_empty()).then_some(owner),
        offer: (!to.is_empty()).then_some((to, at)),
    })
}

/// Volume `ino`'s record as `r` sees it, if it has one: `None` for an inode
/// that isn't a volume, and for a volume from before records.
pub(crate) async fn volume_of(
    r: &impl Reads,
    ino: u64,
) -> Result<Result<Option<VolumeInfo>, FsError>, KvError> {
    Ok(match r.get(&volume_key(ino)).await? {
        Some(bytes) => decode_volume(ino, &bytes).map(Some),
        None => Ok(None),
    })
}

/// Refuses (`EPERM`) to leave `user`, the owner of volume `ino`, without a
/// writable grant of it: `writable` is what their grant would be after the
/// change, `None` if it goes.
pub(crate) async fn check_owner_kept(
    txn: &Transaction,
    ino: u64,
    user: &str,
    writable: Option<bool>,
) -> Result<Result<(), FsError>, KvError> {
    if writable == Some(true) {
        return Ok(Ok(()));
    }
    let record = decide!(volume_of(txn, ino).await?);
    Ok(if record.and_then(|v| v.owner).as_deref() == Some(user) {
        Err(FsError::new(
            libc::EPERM,
            format!("{user} owns this volume, so keeps read-write access to it: transfer it first"),
        ))
    } else {
        Ok(())
    })
}

impl FsCore {
    /// Who owns volume `ino`, for `caller`, who needs access to it.
    pub async fn volume_info(&self, caller: &Caller, ino: u64) -> Result<VolumeInfo, FsError> {
        let view = self.live();
        self.guard_now(&view, caller, ino, false).await?;
        if self.resolve(&view, ino).await?.parent != ROOT_INO {
            return Err(FsError::new(
                libc::EINVAL,
                format!("inode {ino} isn't a volume"),
            ));
        }
        Ok(volume_of(&view, ino).await??.unwrap_or_default())
    }

    /// Gives every volume without a record one (see the top of this file).
    /// Returns how many it gave an owner.
    pub(crate) async fn assign_missing_owners(&self) -> Result<usize, FsError> {
        let prefix = dirent_prefix(ROOT_INO);
        let mut keys = Vec::new();
        let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(&prefix) {
                break;
            }
            keys.push(key);
        }
        let mut owned = 0;
        for value in self.client.get_many(&keys).await?.into_iter().flatten() {
            let ino = dirent_ino(&value);
            let given = retrying(move || async move {
                let txn = self.client.transaction(TXN_TTL).await?;
                if txn.read_one(&volume_key(ino)).await?.value.is_some() {
                    return Ok(false);
                }
                let writers: Vec<String> = grants::grants_of(&txn, ino)
                    .await?
                    .into_iter()
                    .filter(|(user, grant)| grant.writable && !user.starts_with(LINK_PREFIX))
                    .map(|(user, _)| user)
                    .collect();
                let owner = match writers.as_slice() {
                    [only] => Some(only.clone()),
                    _ => None,
                };
                let record = VolumeInfo {
                    owner: owner.clone(),
                    offer: None,
                };
                txn.write(&volume_key(ino), Some(&encode_volume(&record)))
                    .await?;
                txn.commit().await?;
                Ok(owner.is_some())
            })
            .await?;
            owned += usize::from(given);
        }
        Ok(owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_garbage_is_eio() {
        for v in [
            VolumeInfo::default(),
            VolumeInfo {
                owner: Some("alice".into()),
                offer: Some(("bob".into(), 1_800_000_000)),
            },
        ] {
            assert_eq!(decode_volume(9, &encode_volume(&v)).unwrap(), v);
        }
        let bytes = encode_volume(&VolumeInfo::default());
        assert_eq!(
            decode_volume(9, &bytes[..bytes.len() - 1])
                .unwrap_err()
                .errno,
            libc::EIO
        );
    }
}
