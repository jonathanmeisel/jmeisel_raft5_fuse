//! Snapshots: the store's own (raft5) snapshots. Each one keeps the whole
//! filesystem as it was when it was taken, and mounts show it read-only
//! under `/.snapshot/<name>`.
//!
//! - Only the store administrator can take or remove a snapshot. raft5
//!   allows no one else, because a snapshot keeps every version of every
//!   key changed after it until it is removed.
//! - The filesystem servers' account can list and read snapshots like any
//!   other read.
//! - A read at a snapshot reads everything as it was then, including the
//!   grants that control access.

use std::time::{Duration, UNIX_EPOCH};

use raft5_client::Client;
use raft5fs_proto::types::{FsError, SnapshotInfo};

use crate::timing;

/// Whether `name` is a valid snapshot name: a valid raft5 id that is also a
/// valid file name, so not `.` or `..`.
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

/// Every snapshot, oldest first. A snapshot whose id is not a valid file
/// name (taken in some way other than `create`) is not listed, because no
/// path could reach it.
pub async fn list(client: &Client) -> Result<Vec<SnapshotInfo>, FsError> {
    let mut snapshots: Vec<_> = timing::other("snapshot list", client.list_snapshots())
        .await?
        .into_iter()
        .filter_map(info)
        .collect();
    snapshots.sort_by(|a, b| (a.created, &a.name).cmp(&(b.created, &b.name)));
    Ok(snapshots)
}

/// Whether snapshot `name` exists. Check this before reading at a snapshot,
/// because the store keeps retrying a read at an unknown snapshot until its
/// deadline.
pub async fn exists(client: &Client, name: &[u8]) -> Result<bool, FsError> {
    Ok(client.list_snapshots().await?.iter().any(|s| s.id == name))
}

/// Takes a snapshot of the filesystem as it is now, named `name`, or named
/// by the time if `None`. `client` must be logged in as a store
/// administrator.
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

/// Removes snapshot `name` and frees what it held. `client` must be logged
/// in as a store administrator.
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
