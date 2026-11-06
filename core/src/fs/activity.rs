//! The activity log: who created, edited, renamed or deleted what, in which
//! volume, for the past few days (`set_activity_days`).
//!
//! - The servers already see who changes which inode, and when, so keeping
//!   it for a while tells them nothing new. Names are copied as the request
//!   sealed them, so the servers still can't read them. They vouch for who
//!   did what: nothing is signed.
//! - Each entry is written after its change commits, outside its
//!   transaction, so the log never makes a change wait or retry. A failed
//!   write only loses that entry.
//! - An edit is noted at most once each `EDIT_EVERY` for each user and file,
//!   on each server: a save is one line, not one for each write.
//! - Keys are by volume and newest first (see `layout`), so a folder's log is
//!   one scan of its volume's, from the start.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use super::*;
use crate::layout::{ACTIVITY_PREFIX, DELETE_BATCH};
use raft5fs_proto::types::{Activity, ActivityOp, ActivityPage, LINK_PREFIX, SealedEntryName};

/// The format of an entry's value.
const FORMAT: u8 = 1;
/// How often an edit by one user to one file is noted, at most.
const EDIT_EVERY: Duration = Duration::from_secs(600);
/// The most keys one page looks at, so that a page of a quiet folder in a
/// busy volume ends anyway. It then says where the next one starts.
const SCAN_LIMIT: usize = 2000;
/// How many entries a page holds when the caller asks for none or many.
const PAGE: usize = 200;

/// How many days the log keeps entries, unless `set_activity_days` says.
pub const DEFAULT_ACTIVITY_DAYS: u64 = 7;

/// This server's part of the activity log.
pub(crate) struct ActivityLog {
    /// How many days to keep entries; 0 keeps none.
    days: u64,
    /// When each user's last edit of each file was noted here.
    edits: Mutex<HashMap<(String, u64), Instant>>,
}

impl Default for ActivityLog {
    fn default() -> Self {
        Self {
            days: DEFAULT_ACTIVITY_DAYS,
            edits: Mutex::default(),
        }
    }
}

fn op_byte(op: ActivityOp) -> u8 {
    match op {
        ActivityOp::Created => 0,
        ActivityOp::Edited => 1,
        ActivityOp::Renamed => 2,
        ActivityOp::Deleted => 3,
    }
}

fn op_of(byte: u8) -> Option<ActivityOp> {
    Some(match byte {
        0 => ActivityOp::Created,
        1 => ActivityOp::Edited,
        2 => ActivityOp::Renamed,
        3 => ActivityOp::Deleted,
        _ => return None,
    })
}

fn volume_prefix(volume: u64) -> Vec<u8> {
    let mut key = ACTIVITY_PREFIX.to_vec();
    key.extend_from_slice(&volume.to_be_bytes());
    key
}

fn activity_key(volume: u64, at_ms: u64, ino: u64, op: ActivityOp) -> Vec<u8> {
    let mut key = volume_prefix(volume);
    key.extend_from_slice(&(u64::MAX - at_ms).to_be_bytes());
    key.extend_from_slice(&ino.to_be_bytes());
    key.push(op_byte(op));
    key
}

/// When the entry under `key` happened, in ms since the Unix epoch.
fn key_time(key: &[u8]) -> Option<u64> {
    let inverted = u64::from_be_bytes(key.get(9..17)?.try_into().ok()?);
    Some(u64::MAX - inverted)
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn put_name(out: &mut Vec<u8>, name: &Option<SealedEntryName>) {
    match name {
        None => out.push(0),
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.parent.to_be_bytes());
            put(out, &n.tag);
            put(out, &n.sealed);
        }
    }
}

fn encode(a: &Activity) -> Vec<u8> {
    let mut out = vec![
        FORMAT,
        u8::from(a.kind == Kind::Directory),
        u8::from(a.replaced),
    ];
    put(&mut out, a.user.as_bytes());
    out.extend_from_slice(&a.parent.to_be_bytes());
    put_name(&mut out, &a.name);
    put_name(&mut out, &a.from);
    out
}

/// The entry under `key`, or `None` for one this code can't read.
fn decode(key: &[u8], value: &[u8]) -> Option<Activity> {
    let at_ms = key_time(key)?;
    let ino = u64::from_be_bytes(key.get(17..25)?.try_into().ok()?);
    let op = op_of(*key.get(25)?)?;
    let mut r = Reader(value);
    let [format, dir, replaced] = r.take(3)?.try_into().ok()?;
    if format != FORMAT {
        return None;
    }
    let user = String::from_utf8(r.field()?).ok()?;
    let parent = r.u64()?;
    let name = r.name()?;
    let from = r.name()?;
    Some(Activity {
        at_ms,
        user,
        op,
        kind: if dir == 1 {
            Kind::Directory
        } else {
            Kind::File
        },
        ino,
        parent,
        name,
        from,
        replaced: replaced == 1,
        moved_out: false,
        path: Vec::new(),
    })
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn field(&mut self) -> Option<Vec<u8>> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        Some(self.take(len)?.to_vec())
    }

    fn name(&mut self) -> Option<Option<SealedEntryName>> {
        Some(match self.take(1)?[0] {
            0 => None,
            _ => Some(SealedEntryName {
                parent: self.u64()?,
                tag: self.field()?,
                sealed: self.field()?,
            }),
        })
    }
}

impl FsCore {
    /// Keeps the activity log `days` days; 0 keeps none, and notes nothing.
    pub fn set_activity_days(&mut self, days: u64) {
        self.activity.days = days;
    }

    /// The volume that folder `dir` is in, if any: none for the root.
    async fn volume_of(&self, dir: u64) -> Option<u64> {
        self.path_of(dir).await.ok()?.last().copied()
    }

    /// Notes a change, in the volume of each folder it touched. Never fails:
    /// see the top of this file.
    pub(crate) async fn note(&self, caller: &Caller, mut activity: Activity) {
        if self.activity.days == 0 || caller.user.starts_with(LINK_PREFIX) {
            return;
        }
        activity.at_ms = now_ms();
        activity.user = caller.user.clone();
        let mut volumes = Vec::new();
        for dir in [
            Some(activity.parent),
            activity.from.as_ref().map(|f| f.parent),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(volume) = self.volume_of(dir).await
                && !volumes.contains(&volume)
            {
                volumes.push(volume);
            }
        }
        let value = encode(&activity);
        for volume in volumes {
            let key = activity_key(volume, activity.at_ms, activity.ino, activity.op);
            if let Err(e) = self.client.write(&key, Some(&value)).await {
                eprintln!(
                    "the activity log missed a change to inode {}: {e}",
                    activity.ino
                );
            }
        }
    }

    /// Notes that `caller` edited file `ino` in `parent`, unless they did a
    /// little while ago.
    pub(crate) async fn note_edit(&self, caller: &Caller, ino: u64, parent: u64) {
        {
            let mut edits = self.activity.edits.lock().unwrap();
            let key = (caller.user.clone(), ino);
            if edits.get(&key).is_some_and(|at| at.elapsed() < EDIT_EVERY) {
                return;
            }
            if edits.len() > 4096 {
                edits.retain(|_, at| at.elapsed() < EDIT_EVERY);
            }
            edits.insert(key, Instant::now());
        }
        self.note(
            caller,
            change(ActivityOp::Edited, Kind::File, ino, parent, None),
        )
        .await;
    }

    /// The changes in folder `folder` and below it, newest first, from where
    /// `after` (a page's `next`) says. The caller must be able to read it.
    pub async fn activity(
        &self,
        caller: &Caller,
        folder: u64,
        after: &[u8],
        limit: usize,
    ) -> Result<ActivityPage, FsError> {
        crate::accounts::refuse_link(&caller.user)?;
        self.access(caller, folder, 0, None).await?;
        let limit = if limit == 0 { PAGE } else { limit.min(PAGE) };
        let Some(volume) = self.volume_of(folder).await else {
            return Ok(ActivityPage::default());
        };
        let prefix = volume_prefix(volume);
        let mut start = prefix.clone();
        if !after.is_empty() {
            if !after.starts_with(&prefix) {
                return Err(FsError::new(libc::EINVAL, "that page isn't this folder's"));
            }
            start = after.to_vec();
            // The next key after it.
            start.push(0);
        }
        let mut page = ActivityPage::default();
        let mut iter = self.client.key_iterator(&start, Consistency::Stale);
        let mut scanned = 0;
        let mut batch = Vec::new();
        loop {
            let key = next_key(&mut iter)
                .await?
                .filter(|k| k.starts_with(&prefix));
            let end = key.is_none();
            if let Some(key) = key {
                batch.push(key);
            }
            if batch.len() < MAX_KEYS_PER_READ.min(64) && !end {
                continue;
            }
            let values = self.client.read_many(&batch).await?;
            for (key, value) in batch.drain(..).zip(values) {
                scanned += 1;
                if let Some(activity) = value.value.and_then(|v| decode(&key, &v))
                    && let Some(activity) = self.within(folder, activity).await
                {
                    page.entries.push(activity);
                }
                if page.entries.len() == limit || scanned == SCAN_LIMIT {
                    page.next = key;
                    return Ok(page);
                }
            }
            if end {
                return Ok(page);
            }
        }
    }

    /// `activity` with its `path` from `folder`, if it was in `folder` or
    /// below it.
    async fn within(&self, folder: u64, mut activity: Activity) -> Option<Activity> {
        if let Some(path) = self.path_below(folder, activity.parent).await {
            activity.path = path;
            return Some(activity);
        }
        let from = activity.from.as_ref()?.parent;
        activity.path = self.path_below(folder, from).await?;
        activity.moved_out = true;
        Some(activity)
    }

    /// The folders from `folder` down to `dir`, not counting `folder`, if
    /// `dir` is in it.
    async fn path_below(&self, folder: u64, dir: u64) -> Option<Vec<u64>> {
        if dir == folder {
            return Some(Vec::new());
        }
        let up = self.path_of(dir).await.ok()?;
        let at = up.iter().position(|&d| d == folder)?;
        Some(up[..at].iter().rev().copied().collect())
    }

    /// Removes entries older than the log keeps. Under the measuring lease.
    pub(crate) async fn trim_activity(&self) -> Result<usize, FsError> {
        if self.activity.days == 0 {
            return Ok(0);
        }
        let oldest = now_ms().saturating_sub(self.activity.days * 86_400_000);
        let mut old = Vec::new();
        let mut iter = self
            .client
            .key_iterator(ACTIVITY_PREFIX, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(ACTIVITY_PREFIX) {
                break;
            }
            if key_time(&key).is_some_and(|at| at < oldest) {
                old.push(key);
            }
        }
        self.remove_keys(&old).await?;
        Ok(old.len())
    }

    /// Removes volume `volume`'s log, once the volume is gone.
    pub(crate) async fn forget_activity(&self, volume: u64) {
        let prefix = volume_prefix(volume);
        let mut keys = Vec::new();
        let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
        loop {
            match next_key(&mut iter).await {
                Ok(Some(key)) if key.starts_with(&prefix) => keys.push(key),
                Ok(_) => break,
                Err(e) => {
                    eprintln!("the activity log of volume {volume} stays: {e}");
                    return;
                }
            }
        }
        if let Err(e) = self.remove_keys(&keys).await {
            eprintln!("the activity log of volume {volume} stays: {e}");
        }
    }

    async fn remove_keys(&self, keys: &[Vec<u8>]) -> Result<(), FsError> {
        for batch in keys.chunks(DELETE_BATCH) {
            run_txn(&self.client, move |txn| async move {
                for key in batch {
                    txn.write(key, None).await?;
                }
                txn.commit().await?;
                Ok(Ok::<(), FsError>(()))
            })
            .await??;
        }
        Ok(())
    }
}

/// A change, to be noted with `FsCore::note`, which sets who and when.
pub(crate) fn change(
    op: ActivityOp,
    kind: Kind,
    ino: u64,
    parent: u64,
    name: Option<SealedEntryName>,
) -> Activity {
    Activity {
        at_ms: 0,
        user: String::new(),
        op,
        kind,
        ino,
        parent,
        name,
        from: None,
        replaced: false,
        moved_out: false,
        path: Vec::new(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_read_back_and_sort_newest_first() {
        let name = |parent| {
            Some(SealedEntryName {
                parent,
                tag: vec![1, 2],
                sealed: vec![3; 40],
            })
        };
        let mut a = change(ActivityOp::Renamed, Kind::Directory, 9, 4, name(4));
        a.at_ms = 1_700_000_000_000;
        a.user = "alice".into();
        a.from = name(5);
        a.replaced = true;
        let key = activity_key(3, a.at_ms, a.ino, a.op);
        assert_eq!(decode(&key, &encode(&a)), Some(a.clone()));
        let later = activity_key(3, a.at_ms + 1, a.ino, a.op);
        assert!(later < key, "newer sorts first");
        assert_eq!(decode(&key, &encode(&a)[..10]), None);
    }
}
