//! A volume's index as one: every indexer's entries merged, and searched.
//!
//! - For each inode, the newest entry from any indexer wins. A tombstone
//!   that wins hides the file.
//! - `Progress` is what the next indexer goes on from: the newest cursor,
//!   the files still to check again, and the last full walk.

use std::collections::HashMap;

use crate::bm25::{Bm25, ChunkRef};
use crate::manifest::Manifest;
use crate::record::{DocKind, Entry, Record};

/// The newest entry for each inode in `entries`.
pub fn latest(entries: impl IntoIterator<Item = Entry>) -> HashMap<u64, Entry> {
    let mut out: HashMap<u64, Entry> = HashMap::new();
    for e in entries {
        match out.get(&e.ino()) {
            Some(old) if old.at_ms() > e.at_ms() => {}
            _ => {
                out.insert(e.ino(), e);
            }
        }
    }
    out
}

/// What the manifests say about how far indexing got.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Progress {
    pub cursor_ms: u64,
    pub full_walk_ms: u64,
    /// The newest pass of any indexer, and whose it was.
    pub updated_ms: u64,
    pub updated_by: Option<(String, String)>,
    /// Files to check again, each until the latest time any manifest says.
    pub recent: HashMap<u64, u64>,
}

pub fn progress(manifests: &[Manifest]) -> Progress {
    let mut p = Progress::default();
    for m in manifests {
        p.cursor_ms = p.cursor_ms.max(m.cursor_ms);
        p.full_walk_ms = p.full_walk_ms.max(m.full_walk_ms);
        if m.updated_ms >= p.updated_ms {
            p.updated_ms = m.updated_ms;
            p.updated_by = Some((m.user.clone(), m.device.clone()));
        }
        for &(ino, until) in &m.recent {
            let slot = p.recent.entry(ino).or_default();
            *slot = (*slot).max(until);
        }
    }
    p
}

/// One search result.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub ino: u64,
    pub path: String,
    pub kind: DocKind,
    /// The best matching chunk's preview (the first chunk's, for a match
    /// on the path).
    pub preview: String,
    pub score: f32,
}

/// The live records of a volume, ready to search.
#[derive(Default)]
pub struct View {
    docs: Vec<Record>,
    keywords: Bm25,
}

impl View {
    /// A view of `entries`: every entry in every segment of the volume.
    pub fn new(entries: impl IntoIterator<Item = Entry>) -> Self {
        let mut view = View::default();
        let mut live: Vec<Record> = latest(entries)
            .into_values()
            .filter_map(|e| match e {
                Entry::Record(r) => Some(r),
                Entry::Gone { .. } => None,
            })
            .collect();
        // A fixed order, so equal scores rank the same way each time.
        live.sort_by_key(|r| r.ino);
        for (doc, r) in live.iter().enumerate() {
            view.keywords.add_path(doc, &r.path);
            for (i, c) in r.chunks.iter().enumerate() {
                let at = ChunkRef {
                    doc,
                    chunk: Some(i),
                };
                view.keywords.add(at, &c.terms, c.len);
            }
        }
        view.docs = live;
        view
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// The files that best match `query` by keyword, best first.
    pub fn search(&self, query: &str, limit: usize) -> Vec<Hit> {
        self.keywords
            .search(query, limit)
            .into_iter()
            .map(|(doc, score, chunk)| {
                let r = &self.docs[doc];
                let preview = chunk
                    .or(if r.chunks.is_empty() { None } else { Some(0) })
                    .map(|i| r.chunks[i].preview.clone())
                    .unwrap_or_default();
                Hit {
                    ino: r.ino,
                    path: r.path.clone(),
                    kind: r.kind,
                    preview,
                    score,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Stamp;
    use crate::text::chunks;

    fn record(ino: u64, at_ms: u64, path: &str, text: &str) -> Entry {
        Entry::Record(Record {
            ino,
            at_ms,
            stamp: Stamp {
                mtime_ns: at_ms,
                size: text.len() as u64,
            },
            path: path.into(),
            kind: DocKind::Text,
            model: String::new(),
            chunks: chunks(text),
        })
    }

    #[test]
    fn the_newest_entry_wins_and_a_tombstone_hides() {
        let view = View::new([
            record(1, 10, "old.txt", "apples"),
            // The same file, indexed again later by another indexer.
            record(1, 20, "new.txt", "pears"),
            record(2, 10, "gone.txt", "apples"),
            Entry::Gone { ino: 2, at_ms: 30 },
            // A tombstone older than the record does not hide it.
            Entry::Gone { ino: 3, at_ms: 5 },
            record(3, 6, "back.txt", "apples again"),
        ]);
        assert_eq!(view.len(), 2);
        assert!(view.search("pears", 5)[0].path == "new.txt");
        let apples: Vec<_> = view
            .search("apples", 5)
            .into_iter()
            .map(|h| h.ino)
            .collect();
        assert_eq!(apples, [3]);
    }

    #[test]
    fn hits_carry_a_preview() {
        let view = View::new([record(1, 1, "notes/tax.txt", "receipts for the tax return")]);
        let hit = &view.search("tax", 5)[0];
        assert_eq!(hit.preview, "receipts for the tax return");
        let hit = &view.search("notes", 5)[0];
        assert_eq!(hit.preview, "receipts for the tax return", "path match");
    }

    #[test]
    fn progress_takes_the_newest_of_each() {
        let a = Manifest {
            user: "al".into(),
            device: "pc".into(),
            cursor_ms: 50,
            full_walk_ms: 10,
            updated_ms: 60,
            recent: vec![(7, 100)],
            ..Manifest::default()
        };
        let b = Manifest {
            user: "bo".into(),
            device: "web".into(),
            cursor_ms: 40,
            full_walk_ms: 20,
            updated_ms: 70,
            recent: vec![(7, 90), (8, 5)],
            ..Manifest::default()
        };
        let p = progress(&[a, b]);
        assert_eq!((p.cursor_ms, p.full_walk_ms, p.updated_ms), (50, 20, 70));
        assert_eq!(p.updated_by, Some(("bo".into(), "web".into())));
        assert_eq!(p.recent[&7], 100);
        assert_eq!(p.recent[&8], 5);
    }
}
