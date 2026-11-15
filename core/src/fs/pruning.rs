//! What waits to be pruned, and who is pruning it, so that any client that
//! can write a tree can finish its prune.
//!
//! - A node waits for a prune exactly while its key record keeps older
//!   versions: a rotation adds them, and a prune removes them. Every write of
//!   a key record keeps the index `UNPRUNED_PREFIX` in step
//!   (`grants::put_node_keys`), so the index is the queue, and nothing has
//!   to remember to add to it.
//! - A prune rotates a folder's stale children (which gives them older
//!   versions) before it cuts the folder's own, so every node still sealed
//!   under a revoked key has itself or a folder above it in the index.
//! - A pruner claims a node for `CLAIM_TTL`, and renews the claim while it
//!   works, so that two pruners don't do the same work. Two at once would
//!   still be safe: the server refuses a cut that would lose data.
//! - Key records from before the index are added once, by the server that
//!   measures usage (`index_unpruned`).

use std::time::{Duration, SystemTime};

use super::*;
use crate::layout::{
    NODE_KEYS_PREFIX, UNPRUNED_INDEXED_KEY, UNPRUNED_PREFIX, prune_claim_key, unpruned_key,
};
use crate::timing::next_key;
use raft5fs_proto::types::{ClaimOutcome, PruneClaim, Unpruned};

/// How long a claim on a prune lasts unless renewed.
pub const CLAIM_TTL: Duration = Duration::from_secs(600);

/// The most index rows one listing looks at, and the most it returns.
const SCAN_LIMIT: usize = 5000;
const LIST_LIMIT: usize = 200;

/// How many key records each transaction of `index_unpruned` checks.
const INDEX_BATCH: usize = 100;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The inode at the end of a key of one byte and an inode.
fn ino_of(key: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(key.get(1..9)?.try_into().ok()?))
}

/// A claim's value: holder (16 bytes), expiry (milliseconds, BE8), user.
fn encode_claim(holder: &[u8; 16], expires_ms: u64, user: &str) -> Vec<u8> {
    let mut value = holder.to_vec();
    value.extend_from_slice(&expires_ms.to_be_bytes());
    value.extend_from_slice(user.as_bytes());
    value
}

fn decode_claim(value: &[u8]) -> Option<([u8; 16], PruneClaim)> {
    let holder = value.get(..16)?.try_into().ok()?;
    let expires_ms = u64::from_be_bytes(value.get(16..24)?.try_into().ok()?);
    let user = String::from_utf8(value.get(24..)?.to_vec()).ok()?;
    Some((holder, PruneClaim { user, expires_ms }))
}

/// Whether key record `value` keeps older versions.
fn waiting(value: Option<&[u8]>) -> bool {
    value
        .and_then(|v| NodeKeys::decode(v).ok())
        .is_some_and(|k| k.has_history())
}

impl FsCore {
    /// The nodes waiting for a prune that `caller` can write, with any
    /// claim that hasn't run out. A row whose key record no longer keeps
    /// older versions is left out, and removed.
    pub async fn unpruned(&self, caller: &Caller) -> Result<Vec<Unpruned>, FsError> {
        crate::accounts::refuse_link(&caller.user)?;
        let mut inos = Vec::new();
        let mut iter = self
            .client
            .key_iterator(UNPRUNED_PREFIX, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(UNPRUNED_PREFIX) || inos.len() == SCAN_LIMIT {
                break;
            }
            if let Some(ino) = ino_of(&key) {
                inos.push(ino);
            }
        }
        let now = now_ms();
        let mut found = Vec::new();
        for ino in inos {
            if found.len() == LIST_LIMIT {
                break;
            }
            let [keys, claim] = self
                .client
                .get_many(&[node_keys_key(ino), prune_claim_key(ino)])
                .await?
                .try_into()
                .expect("two keys read");
            if !waiting(keys.as_deref()) {
                self.drop_stale_row(ino).await;
                continue;
            }
            if self
                .guard_now(&self.live(), caller, ino, true)
                .await
                .is_err()
            {
                continue;
            }
            let claim = claim
                .as_deref()
                .and_then(decode_claim)
                .map(|(_, c)| c)
                .filter(|c| c.expires_ms > now);
            found.push(Unpruned { ino, claim });
        }
        Ok(found)
    }

    /// Removes `ino`'s index row if its key record keeps no older versions,
    /// checked again in the same transaction. Only tidies: never fails.
    async fn drop_stale_row(&self, ino: u64) {
        let dropped = run_txn(&self.client, move |txn| async move {
            let keys = txn.read_one(&node_keys_key(ino)).await?.value;
            if !waiting(keys.as_deref()) {
                txn.write(&unpruned_key(ino), None).await?;
            }
            txn.commit().await
        })
        .await;
        if let Err(e) = dropped {
            eprintln!("could not remove inode {ino} from the prune index: {e}");
        }
    }

    /// Claims the prune of `ino` for `holder` (as `caller`) for
    /// `CLAIM_TTL`, renews `holder`'s claim, or with `release` gives it up.
    /// A claim that someone else holds and that hasn't run out stands.
    pub async fn claim_prune(
        &self,
        caller: &Caller,
        ino: u64,
        holder: &[u8],
        release: bool,
    ) -> Result<ClaimOutcome, FsError> {
        crate::accounts::refuse_link(&caller.user)?;
        let holder: [u8; 16] = holder
            .try_into()
            .map_err(|_| FsError::new(libc::EINVAL, "a pruner names itself with 16 bytes"))?;
        self.guard_now(&self.live(), caller, ino, true).await?;
        let user = caller.user.as_str();
        let outcome = run_txn(&self.client, move |txn| async move {
            let key = prune_claim_key(ino);
            let now = now_ms();
            let held = txn
                .read_one(&key)
                .await?
                .value
                .as_deref()
                .and_then(decode_claim)
                .filter(|(_, c)| c.expires_ms > now);
            let outcome = match held {
                Some((other, claim)) if other != holder => ClaimOutcome {
                    granted: false,
                    claim: Some(claim),
                },
                _ if release => {
                    txn.write(&key, None).await?;
                    ClaimOutcome {
                        granted: false,
                        claim: None,
                    }
                }
                _ => {
                    let expires_ms = now + CLAIM_TTL.as_millis() as u64;
                    txn.write(&key, Some(&encode_claim(&holder, expires_ms, user)))
                        .await?;
                    ClaimOutcome {
                        granted: true,
                        claim: Some(PruneClaim {
                            user: user.to_string(),
                            expires_ms,
                        }),
                    }
                }
            };
            txn.commit().await?;
            Ok(outcome)
        })
        .await?;
        Ok(outcome)
    }

    /// Adds every key record with older versions to the prune index, once:
    /// those written before the index was kept. Does nothing once done.
    /// Each row is checked again in the transaction that writes it, so a
    /// prune that finishes meanwhile leaves no row behind. Returns how many
    /// rows it added.
    pub(crate) async fn index_unpruned(&self) -> Result<usize, FsError> {
        if self
            .client
            .read_one(UNPRUNED_INDEXED_KEY)
            .await?
            .value
            .is_some()
        {
            return Ok(0);
        }
        let mut candidates = Vec::new();
        let mut batch = Vec::new();
        let mut iter = self
            .client
            .key_iterator(NODE_KEYS_PREFIX, Consistency::Stale);
        loop {
            let key = next_key(&mut iter)
                .await?
                .filter(|k| k.starts_with(NODE_KEYS_PREFIX));
            let end = key.is_none();
            if let Some(key) = key {
                batch.push(key);
            }
            if batch.len() < INDEX_BATCH && !end {
                continue;
            }
            let values = self.client.get_many(&batch).await?;
            for (key, value) in batch.drain(..).zip(values) {
                if waiting(value.as_deref())
                    && let Some(ino) = ino_of(&key)
                {
                    candidates.push(ino);
                }
            }
            if end {
                break;
            }
        }
        let mut added = 0;
        for chunk in candidates.chunks(INDEX_BATCH) {
            added += run_txn(&self.client, move |txn| async move {
                let mut added = 0;
                for &ino in chunk {
                    let keys = txn.read_one(&node_keys_key(ino)).await?.value;
                    if waiting(keys.as_deref()) {
                        txn.write(&unpruned_key(ino), Some(&[])).await?;
                        added += 1;
                    }
                }
                txn.commit().await?;
                Ok(added)
            })
            .await?;
        }
        self.client.write(UNPRUNED_INDEXED_KEY, Some(&[1])).await?;
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_read_back() {
        let holder = [7u8; 16];
        let value = encode_claim(&holder, 1234, "alice");
        let (h, claim) = decode_claim(&value).unwrap();
        assert_eq!(h, holder);
        assert_eq!(
            claim,
            PruneClaim {
                user: "alice".into(),
                expires_ms: 1234
            }
        );
        assert!(decode_claim(&value[..20]).is_none());
    }
}
