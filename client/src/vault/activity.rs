//! The activity log as people read it (see raft5fs-core's `fs::activity`):
//! names opened, folders named along the way, and the way editors save shown
//! as the edit it is.

use std::collections::HashMap;

use raft5fs_proto::types::{Activity, ActivityOp, Kind, SealedEntryName};

use super::*;

/// How close together a create and the steps that finish it are, for them to
/// show as one change.
const TOGETHER_MS: u64 = 120_000;

/// What a line of the log says happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Edited,
    /// A new name in the same folder.
    Renamed,
    /// To another folder.
    Moved,
    /// To somewhere outside the folder asked about.
    MovedOut,
    Deleted,
}

impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Created => "created",
            Change::Edited => "edited",
            Change::Renamed => "renamed",
            Change::Moved => "moved",
            Change::MovedOut => "moved out",
            Change::Deleted => "deleted",
        }
    }
}

/// One line of the log.
#[derive(Debug, Clone)]
pub struct ActivityLine {
    /// Milliseconds since the Unix epoch, by the server's clock.
    pub at_ms: u64,
    pub user: String,
    pub change: Change,
    pub kind: Kind,
    pub ino: u64,
    /// Where it is after the change, from the folder asked about, with `/`
    /// between names: where it was for a deletion or a move out. `…` stands
    /// for a folder that can't be named now. `None` if the name can't be
    /// opened.
    pub name: Option<String>,
    /// For a rename or move, where it was.
    pub from: Option<String>,
    /// For a rename or move, whether it replaced something with its new name.
    pub replaced: bool,
}

/// A page of lines, newest first, and where the next page starts: empty
/// when there is no more.
#[derive(Debug, Default)]
pub struct ActivityLines {
    pub lines: Vec<ActivityLine>,
    pub next: Vec<u8>,
}

impl Vault {
    /// What changed in folder `folder` and below it, newest first (see
    /// `Remote::list_activity`), as people read it.
    ///
    /// - An edit's file is named by the latest name the page gives it, or
    ///   else by its folder's listing now.
    /// - A file made and then renamed over another, by one person within
    ///   `TOGETHER_MS`, is how editors save: one "edited" line, with the name
    ///   it took. An edit right after a create is part of the create.
    pub async fn activity(
        &self,
        folder: u64,
        after: &[u8],
        limit: u32,
    ) -> Result<ActivityLines, FsError> {
        let page = self.remote.list_activity(folder, after, limit).await?;
        let mut listings = HashMap::new();
        let mut lines = Vec::with_capacity(page.entries.len());
        for (i, entry) in page.entries.iter().enumerate() {
            let dir = self.folder_names(folder, &entry.path, &mut listings).await;
            let mut name = if entry.moved_out {
                self.open_logged(&entry.from, entry.ino).await
            } else {
                self.open_logged(&entry.name, entry.ino).await
            };
            if entry.op == ActivityOp::Edited {
                name = self
                    .name_of_edited(entry, &page.entries[i + 1..], &mut listings)
                    .await;
            }
            let change = match entry.op {
                ActivityOp::Created => Change::Created,
                ActivityOp::Edited => Change::Edited,
                ActivityOp::Deleted => Change::Deleted,
                ActivityOp::Renamed if entry.moved_out => Change::MovedOut,
                ActivityOp::Renamed
                    if entry
                        .from
                        .as_ref()
                        .is_some_and(|f| f.parent != entry.parent) =>
                {
                    Change::Moved
                }
                ActivityOp::Renamed => Change::Renamed,
            };
            let from = match change {
                Change::Renamed => self
                    .open_logged(&entry.from, entry.ino)
                    .await
                    .map(|n| join(&dir, &n)),
                Change::Moved => match &entry.from {
                    Some(from) => {
                        self.name_of_moved(folder, from, entry.ino, &mut listings)
                            .await
                    }
                    None => None,
                },
                _ => None,
            };
            lines.push(ActivityLine {
                at_ms: entry.at_ms,
                user: entry.user.clone(),
                change,
                kind: entry.kind,
                ino: entry.ino,
                name: name.map(|n| join(&dir, &n)),
                from,
                replaced: entry.replaced,
            });
        }
        Ok(ActivityLines {
            lines: merge_saves(lines),
            next: page.next,
        })
    }

    /// `open_logged_name` for a name the log may not have.
    async fn open_logged(&self, name: &Option<SealedEntryName>, child: u64) -> Option<String> {
        self.open_logged_name(name.as_ref()?, child).await
    }

    /// Opens a name the log copied, for inode `child`, or `None`.
    async fn open_logged_name(&self, name: &SealedEntryName, child: u64) -> Option<String> {
        let dir = self.node(name.parent).await.ok()?;
        let opened = dir
            .open_entry(name.parent, child, &name.tag, &name.sealed)
            .ok()
            .filter(|n| good_name(n))?;
        Some(String::from_utf8_lossy(&opened).into_owned())
    }

    /// The names of the folders `path` goes down through from `folder`, with
    /// `/` after each: `a/b/`, or `""` for none.
    async fn folder_names(
        &self,
        folder: u64,
        path: &[u64],
        listings: &mut HashMap<u64, Vec<DirItem>>,
    ) -> String {
        let mut names = String::new();
        let mut at = folder;
        for &dir in path {
            match self.listed_name(at, dir, listings).await {
                Some(name) => names.push_str(&name),
                None => names.push('…'),
            }
            names.push('/');
            at = dir;
        }
        names
    }

    /// What `child` is called in `dir` now, from its listing, kept in
    /// `listings` for the rest of the page.
    async fn listed_name(
        &self,
        dir: u64,
        child: u64,
        listings: &mut HashMap<u64, Vec<DirItem>>,
    ) -> Option<String> {
        if let std::collections::hash_map::Entry::Vacant(slot) = listings.entry(dir) {
            slot.insert(self.readdir(dir).await.unwrap_or_default());
        }
        let item = listings[&dir].iter().find(|i| i.ino == child)?;
        Some(item.name.to_string_lossy().into_owned())
    }

    /// The name of the file an edit was to: the latest name an older entry
    /// gives it, or else what its folder calls it now.
    async fn name_of_edited(
        &self,
        edit: &Activity,
        older: &[Activity],
        listings: &mut HashMap<u64, Vec<DirItem>>,
    ) -> Option<String> {
        for entry in older.iter().filter(|e| e.ino == edit.ino) {
            if let Some(name) = entry.name.as_ref().filter(|n| n.parent == edit.parent) {
                return self.open_logged_name(name, edit.ino).await;
            }
        }
        self.listed_name(edit.parent, edit.ino, listings).await
    }

    /// Where a moved inode was, from `folder`: its folders as they are named
    /// now, if they are under `folder`, and its old name.
    async fn name_of_moved(
        &self,
        folder: u64,
        from: &SealedEntryName,
        ino: u64,
        listings: &mut HashMap<u64, Vec<DirItem>>,
    ) -> Option<String> {
        let name = self.open_logged_name(from, ino).await?;
        if from.parent == folder {
            return Some(name);
        }
        // The folder it left is named by its listing in its own parent, if
        // that is still here to look in.
        let listed = listings.values().flatten().find(|i| i.ino == from.parent);
        Some(match listed {
            Some(dir) => format!("{}/{name}", dir.name.to_string_lossy()),
            None => format!("…/{name}"),
        })
    }
}

fn join(dir: &str, name: &str) -> String {
    format!("{dir}{name}")
}

/// `lines`, newest first, with the steps of a save shown as one edit (see
/// `Vault::activity`).
fn merge_saves(mut lines: Vec<ActivityLine>) -> Vec<ActivityLine> {
    let mut gone = vec![false; lines.len()];
    for i in 0..lines.len() {
        let line = &lines[i];
        let created_before = |j: usize| {
            let other = &lines[j];
            other.ino == line.ino
                && other.user == line.user
                && other.change == Change::Created
                && line.at_ms.saturating_sub(other.at_ms) <= TOGETHER_MS
        };
        // An edit goes with its create even when the create went into a save.
        let made = (i + 1..lines.len()).find(|&j| created_before(j));
        let unused = (i + 1..lines.len()).find(|&j| !gone[j] && created_before(j));
        match (line.change, made, unused) {
            (Change::Edited, Some(_), _) => gone[i] = true,
            (Change::Renamed, _, Some(j)) if line.kind == Kind::File && line.replaced => {
                gone[j] = true;
                lines[i].change = Change::Edited;
                lines[i].from = None;
                lines[i].replaced = false;
            }
            _ => {}
        }
    }
    lines
        .into_iter()
        .zip(gone)
        .filter_map(|(line, gone)| (!gone).then_some(line))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(at_ms: u64, user: &str, change: Change, ino: u64, name: &str) -> ActivityLine {
        ActivityLine {
            at_ms,
            user: user.into(),
            change,
            kind: Kind::File,
            ino,
            name: Some(name.into()),
            from: None,
            replaced: change == Change::Renamed,
        }
    }

    fn said(lines: &[ActivityLine]) -> Vec<(Change, &str)> {
        lines
            .iter()
            .map(|l| (l.change, l.name.as_deref().unwrap()))
            .collect()
    }

    #[test]
    fn a_save_by_renaming_shows_as_one_edit() {
        let lines = vec![
            line(5_000, "alice", Change::Renamed, 9, "report.docx"),
            line(4_000, "alice", Change::Edited, 9, "~report.tmp"),
            line(3_000, "alice", Change::Created, 9, "~report.tmp"),
            line(1_000, "bob", Change::Created, 7, "notes.txt"),
        ];
        assert_eq!(
            said(&merge_saves(lines)),
            [
                (Change::Edited, "report.docx"),
                (Change::Created, "notes.txt")
            ]
        );
    }

    #[test]
    fn steps_far_apart_or_by_others_stay_apart() {
        let lines = vec![
            line(400_000, "alice", Change::Renamed, 9, "b.txt"),
            line(300_000, "bob", Change::Edited, 9, "a.txt"),
            line(1_000, "alice", Change::Created, 9, "a.txt"),
        ];
        assert_eq!(
            said(&merge_saves(lines)),
            [
                (Change::Renamed, "b.txt"),
                (Change::Edited, "a.txt"),
                (Change::Created, "a.txt")
            ]
        );
    }
}
