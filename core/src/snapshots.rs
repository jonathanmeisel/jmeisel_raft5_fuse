//! Snapshots: the store's own (raft5's), each pinning the whole filesystem
//! as it stood when it was taken, for mounts to browse read-only under
//! `/.snapshot/<name>`.
//!
//! Taking and removing one is the store administrator's: raft5 allows it
//! no one else, since a snapshot holds every version of every key changed
//! after it until it is removed. Listing and reading at one are open to the
//! filesystem servers' account like any other read. Everything read at a
//! snapshot is read as of it, the grants deciding access included.

use std::time::{Duration, UNIX_EPOCH};

use raft5_client::Client;
use raft5fs_proto::types::{FsError, SnapshotInfo};

use crate::timing;

/// Whether `name` can be a snapshot's: what raft5 takes as an id, and what
/// can be a file name besides -- not `.` or `..`.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 128 {
        return Err("a snapshot name must be 1 to 128 bytes long".to_string());
    }
    if name == "." || name == ".." {
        return Err(format!("a snapshot can't be called {name:?}"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'+'))
    {
        return Err(
            "a snapshot name may contain only letters, digits, '.', '_', '-', ':' and '+'"
                .to_string(),
        );
    }
    Ok(())
}

fn info(s: raft5_client::SnapshotInfo) -> Option<SnapshotInfo> {
    let name = String::from_utf8(s.id).ok()?;
    validate_name(&name).ok()?;
    Some(SnapshotInfo {
        name,
        created: UNIX_EPOCH + Duration::from_millis(s.created_unix_ms),
    })
}

/// Every snapshot, oldest first. One whose id can't be a file name -- taken
/// some other way than `create` -- isn't listed: no path could reach it.
pub async fn list(client: &Client) -> Result<Vec<SnapshotInfo>, FsError> {
    let mut snapshots: Vec<_> = timing::other("snapshot list", client.list_snapshots())
        .await?
        .into_iter()
        .filter_map(info)
        .collect();
    snapshots.sort_by(|a, b| (a.created, &a.name).cmp(&(b.created, &b.name)));
    Ok(snapshots)
}

/// Whether snapshot `name` exists. Asked before reading at one, since the
/// store keeps retrying a read at an unknown snapshot until its deadline.
pub async fn exists(client: &Client, name: &[u8]) -> Result<bool, FsError> {
    Ok(client.list_snapshots().await?.iter().any(|s| s.id == name))
}

/// Takes a snapshot of the filesystem as it is now, named `name`, or by
/// the time if `None`. `client` must be logged in as a store administrator.
pub async fn create(client: &Client, name: Option<&str>) -> Result<SnapshotInfo, String> {
    if let Some(name) = name {
        validate_name(name)?;
    }
    let made = client
        .create_snapshot(name.map(str::as_bytes))
        .await
        .map_err(|e| format!("cannot take the snapshot: {e}"))?;
    info(made).ok_or_else(|| "the store named the snapshot something unusable".to_string())
}

/// Removes snapshot `name`, releasing what it held. `client` must be
/// logged in as a store administrator.
pub async fn remove(client: &Client, name: &str) -> Result<(), String> {
    client
        .remove_snapshot(name.as_bytes())
        .await
        .map(drop)
        .map_err(|e| format!("cannot remove snapshot {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_must_be_store_ids_and_file_names() {
        validate_name("daily-2026-10-06").unwrap();
        validate_name("2026-10-06T12:00:00.000Z").unwrap();
        validate_name("a+b_c.d").unwrap();
        for bad in ["", ".", "..", "a/b", "a b", "ü", &"x".repeat(129)] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }
}
