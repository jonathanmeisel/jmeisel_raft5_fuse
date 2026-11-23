//! Search indexing, as the servers see it: who is indexing which volume, and
//! whether its owner lets it be indexed at all.
//!
//! - Clients build each volume's index and keep it in the volume, sealed.
//!   The servers can't read it, so they only keep claims: one indexer works
//!   on a volume at a time, as with prunes (`fs::pruning`).
//! - Anyone who can write a volume can claim it. Claims last `CLAIM_TTL`
//!   unless renewed.
//! - The owner can turn indexing off for everyone (`indexing_off` in the
//!   volume record). Then no one can claim the volume.

use super::*;
use crate::layout::{ROOT_INO, index_claim_key, volume_key};
use raft5fs_proto::types::ClaimOutcome;

use super::pruning::{claim, holder_of};
use super::volumes::{encode_volume, volume_of};

impl FsCore {
    /// Claims the indexing of volume `volume` for `holder` (as `caller`),
    /// renews `holder`'s claim, or with `release` gives it up. Needs
    /// read-write access to the volume. `EPERM` while its owner has turned
    /// indexing off, except to release.
    pub async fn claim_index(
        &self,
        caller: &Caller,
        volume: u64,
        holder: &[u8],
        release: bool,
    ) -> Result<ClaimOutcome, FsError> {
        crate::accounts::refuse_link(&caller.user)?;
        let holder = holder_of(holder)?;
        let view = self.live();
        self.guard_now(&view, caller, volume, true).await?;
        if self.resolve(&view, volume).await?.parent != ROOT_INO {
            return Err(FsError::new(
                errno::EINVAL,
                format!("inode {volume} isn't a volume"),
            ));
        }
        let off = volume_of(&view, volume)
            .await?
            .is_some_and(|v| v.indexing_off);
        if off && !release {
            return Err(FsError::new(
                errno::EPERM,
                "the volume's owner has turned search indexing off",
            ));
        }
        claim(
            &self.client,
            index_claim_key(volume),
            holder,
            &caller.user,
            release,
        )
        .await
    }

    /// Turns search indexing of volume `volume` on or off, for everyone.
    /// Only its owner, with read-write access, can.
    pub async fn set_volume_indexing(
        &self,
        caller: &Caller,
        volume: u64,
        on: bool,
    ) -> Result<(), FsError> {
        run_txn(&self.client, move |txn| async move {
            let mut record = volume_of(&txn, volume).await?.ok_or_else(|| {
                FsError::new(errno::EINVAL, format!("inode {volume} isn't a volume"))
            })?;
            let writes = match txn
                .read_one(&grants::grant_key(volume, &caller.user))
                .await?
                .value
            {
                Some(bytes) => grants::decode_grant(volume, &bytes)?.writable,
                None => false,
            };
            if record.owner.as_deref() != Some(caller.user.as_str()) || !writes {
                return Err(FsError::new(
                    errno::EPERM,
                    "only the volume's owner can turn search indexing on or off",
                )
                .into());
            }
            record.indexing_off = !on;
            txn.write(&volume_key(volume), Some(&encode_volume(&record)))
                .await?;
            if !on {
                // Nobody may go on indexing it.
                txn.write(&index_claim_key(volume), None).await?;
            }
            txn.commit().await?;
            Ok(())
        })
        .await
    }
}
