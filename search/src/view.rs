//! A volume's index as one: every indexer's entries merged, and searched.
//!
//! - For each inode, the newest entry from any indexer wins. A tombstone
//!   that wins hides the file.
//! - `Progress` is what the next indexer goes on from: the newest cursor,
//!   the files still to check again, and the last full walk.
//! - A search ranks files by keyword (BM25) and, given the query's vector,
//!   by meaning. The two lists are merged by rank (`rank::fuse`). Only
//!   chunks embedded by the query's model count for meaning.

use std::collections::HashMap;

use crate::bm25::{Bm25, ChunkRef};
use crate::manifest::Manifest;
use crate::rank::fuse;
use crate::record::{DocKind, Entry, Record};
use crate::vector::dot;

/// How a chunk matches a query by meaning, with multilingual-e5. Its
/// cosines bunch together, so no one number tells a match from a miss:
///
/// - Text on the query's subject scores 0.79 to 0.87, in any language, and
///   text on another subject 0.70 to 0.78 (raft5fs-indexer's tests, and the
///   web app's search test).
/// - Very short text ("the", a single name) scores about 0.80 against
///   almost any query, so it matches by meaning only with at least
///   `MIN_MEANING_WORDS` words. It is still found by its words.
/// - So a chunk matches if it is within `MEANING_MARGIN` of the best match
///   in the volume, and above `MIN_SIMILARITY` at all.
pub const MIN_SIMILARITY: f32 = 0.75;
pub const MEANING_MARGIN: f32 = 0.05;
pub const MIN_MEANING_WORDS: u32 = 8;

/// How a photo matches a query by what it shows, with CLIP, whose cosines
/// are lower: a photo of what the query says scores 0.27 to 0.37, in any
/// language, and others 0.13 to 0.22 (raft5fs-indexer's `clip` tests). As
/// for text, a photo matches if it is within `IMAGE_MARGIN` of the best
/// match in the volume, and above `MIN_IMAGE_SIMILARITY`.
pub const MIN_IMAGE_SIMILARITY: f32 = 0.24;
pub const IMAGE_MARGIN: f32 = 0.05;

/// A query's embedding, and the model that made it.
pub struct QueryVector<'a> {
    pub model: &'a str,
    pub values: &'a [f32],
}

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
    /// A photo's thumbnail, if it has one.
    pub thumb: Option<crate::record::Thumb>,
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
        self.search_with(query, None, None, limit)
    }

    /// Whether any photo here has an image vector from `model`.
    pub fn has_image_model(&self, model: &str) -> bool {
        self.docs
            .iter()
            .any(|r| r.extra.image.as_ref().is_some_and(|(m, _)| m == model))
    }

    /// Whether any file here has vectors from `model`: if none does, a
    /// query need not be embedded.
    pub fn has_model(&self, model: &str) -> bool {
        self.docs.iter().any(|r| r.model == model)
    }

    /// The files that best match `query`, best first: by keyword; with
    /// `vector`, by meaning; and with `image`, photos by what they show;
    /// merged by rank.
    pub fn search_with(
        &self,
        query: &str,
        vector: Option<QueryVector<'_>>,
        image: Option<QueryVector<'_>>,
        limit: usize,
    ) -> Vec<Hit> {
        // Each list looks deeper than the result, so a file a little way
        // down both still rises.
        let depth = limit.saturating_mul(3).max(10);
        let keyword: Vec<(usize, Option<usize>)> = self
            .keywords
            .search(query, depth)
            .into_iter()
            .map(|(doc, _, chunk)| (doc, chunk))
            .collect();
        let meaning = vector.map(|q| self.nearest(&q, depth)).unwrap_or_default();
        // The chunk each list matched, keyword first: its words are what the
        // user typed.
        let mut best_chunk: HashMap<usize, Option<usize>> = HashMap::new();
        for &(doc, chunk) in meaning.iter().chain(&keyword).rev() {
            best_chunk.insert(doc, chunk);
        }
        let shown = image
            .map(|q| self.nearest_images(&q, depth))
            .unwrap_or_default();
        let lists = [
            keyword.iter().map(|&(d, _)| d).collect::<Vec<_>>(),
            meaning.iter().map(|&(d, _)| d).collect(),
            shown,
        ];
        fuse(&lists)
            .into_iter()
            .take(limit)
            .map(|(doc, score)| {
                let r = &self.docs[doc];
                let chunk = best_chunk.get(&doc).copied().flatten();
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
                    thumb: r.extra.thumb.clone(),
                }
            })
            .collect()
    }

    /// The photos whose image vector is nearest `q` (see
    /// `MIN_IMAGE_SIMILARITY`), best first.
    fn nearest_images(&self, q: &QueryVector<'_>, limit: usize) -> Vec<usize> {
        let mut scored: Vec<(usize, f32)> = self
            .docs
            .iter()
            .enumerate()
            .filter_map(|(doc, r)| {
                let (model, v) = r.extra.image.as_ref()?;
                (model == q.model).then(|| (doc, dot(v, q.values)))
            })
            .collect();
        let best = scored.iter().map(|s| s.1).fold(f32::MIN, f32::max);
        scored.retain(|&(_, s)| s >= MIN_IMAGE_SIMILARITY && s >= best - IMAGE_MARGIN);
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        scored.truncate(limit);
        scored.into_iter().map(|(doc, _)| doc).collect()
    }

    /// The files whose best chunk is nearest `q` in meaning (see
    /// `MIN_SIMILARITY`), best first, with that chunk.
    fn nearest(&self, q: &QueryVector<'_>, limit: usize) -> Vec<(usize, Option<usize>)> {
        let mut scored: Vec<(usize, usize, f32)> = self
            .docs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.model == q.model)
            .filter_map(|(doc, r)| {
                r.chunks
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.len >= MIN_MEANING_WORDS)
                    .filter_map(|(i, c)| Some((i, dot(c.vector.as_ref()?, q.values))))
                    .max_by(|a, b| a.1.total_cmp(&b.1))
                    .map(|(i, s)| (doc, i, s))
            })
            .collect();
        let best = scored.iter().map(|s| s.2).fold(f32::MIN, f32::max);
        scored.retain(|&(_, _, s)| s >= MIN_SIMILARITY && s >= best - MEANING_MARGIN);
        scored.sort_by(|a, b| b.2.total_cmp(&a.2).then(a.0.cmp(&b.0)));
        scored.truncate(limit);
        scored
            .into_iter()
            .map(|(doc, i, _)| (doc, Some(i)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Stamp;
    use crate::text::chunks;
    use crate::vector::{normalize, quantize};

    /// A record whose one chunk has vector `v`, from model "m".
    fn embedded(ino: u64, path: &str, text: &str, v: &[f32]) -> Entry {
        let Entry::Record(mut r) = record(ino, 1, path, text) else {
            unreachable!()
        };
        let mut v = v.to_vec();
        normalize(&mut v);
        r.chunks[0].vector = Some(quantize(&v));
        r.model = "m".into();
        Entry::Record(r)
    }

    #[test]
    fn meaning_finds_what_words_miss_and_both_rank_first() {
        let view = View::new([
            embedded(
                1,
                "a.txt",
                "cycling over the gap and down to the lake",
                &[1.0, 0.0, 0.0],
            ),
            embedded(
                2,
                "b.txt",
                "bike repair notes: chain, brakes and the gears",
                &[0.9, 0.1, 0.0],
            ),
            embedded(
                3,
                "c.txt",
                "the tax return is due in April this year",
                &[0.0, 0.0, 1.0],
            ),
        ]);
        let mut q = vec![1.0, 0.05, 0.0];
        normalize(&mut q);
        let vector = || QueryVector {
            model: "m",
            values: &q,
        };
        // "bike" is a word only in b; a matches by meaning too; c by neither.
        let hits: Vec<u64> = view
            .search_with("bike", Some(vector()), None, 10)
            .iter()
            .map(|h| h.ino)
            .collect();
        assert_eq!(hits, [2, 1]);
        // With no words matching, meaning alone.
        let hits = view.search_with("velo", Some(vector()), None, 10);
        assert_eq!(hits.iter().map(|h| h.ino).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(hits[0].preview, "cycling over the gap and down to the lake");
        // Another model's vectors don't count.
        let other = QueryVector {
            model: "other",
            values: &q,
        };
        assert!(view.search_with("velo", Some(other), None, 10).is_empty());
        assert!(view.has_model("m") && !view.has_model("other"));
    }

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
            extra: Default::default(),
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

    #[test]
    fn short_text_and_far_matches_dont_count_by_meaning() {
        let view = View::new([
            embedded(
                1,
                "best.txt",
                "a long enough piece of text about the subject",
                &[1.0, 0.0, 0.0],
            ),
            // Pointing the same way, but too short to trust.
            embedded(2, "short.txt", "raft5fs", &[1.0, 0.0, 0.0]),
            // Close enough overall, but much further than the best match.
            embedded(
                3,
                "far.txt",
                "another long enough piece of text, on something else",
                &[0.85, 0.53, 0.0],
            ),
        ]);
        let q = [1.0, 0.0, 0.0];
        let vector = QueryVector {
            model: "m",
            values: &q,
        };
        let hits: Vec<u64> = view
            .search_with("unrelated", Some(vector), None, 10)
            .iter()
            .map(|h| h.ino)
            .collect();
        assert_eq!(hits, [1]);
        // Found by its words all the same.
        assert_eq!(view.search("raft5fs", 10)[0].ino, 2);
    }

    #[test]
    fn photos_match_by_what_they_show() {
        let photo = |ino: u64, path: &str, v: &[f32]| {
            let Entry::Record(mut r) = record(ino, 1, path, "Photo") else {
                unreachable!()
            };
            r.kind = DocKind::Photo;
            let mut v = v.to_vec();
            normalize(&mut v);
            r.extra.image = Some(("clip".into(), quantize(&v)));
            Entry::Record(r)
        };
        let view = View::new([
            photo(1, "beach.jpg", &[1.0, 0.0, 0.0]),
            photo(2, "forest.jpg", &[0.0, 1.0, 0.0]),
            record(3, 1, "notes.txt", "notes on nothing"),
        ]);
        assert!(view.has_image_model("clip") && !view.has_image_model("other"));
        // A query near the beach's vector (a cosine of 0.3, as CLIP gives).
        let mut q = vec![0.3, 0.1, (1.0f32 - 0.09 - 0.01).sqrt()];
        normalize(&mut q);
        let image = QueryVector {
            model: "clip",
            values: &q,
        };
        let hits: Vec<u64> = view
            .search_with("strand", None, Some(image), 10)
            .iter()
            .map(|h| h.ino)
            .collect();
        assert_eq!(hits, [1]);
    }
}
