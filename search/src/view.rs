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

use crate::bm25::{Bm25, ChunkRef, Stats, query_terms};
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
///   in all the volumes searched, above `MIN_SIMILARITY` at all, and
///   stands out from the other scores (`Cutoff`).
pub const MIN_SIMILARITY: f32 = 0.75;
pub const MEANING_MARGIN: f32 = 0.05;
pub const MIN_MEANING_WORDS: u32 = 8;

/// How a photo matches a query by what it shows, with CLIP, whose cosines
/// are low and close together. On real photos (20 from Wikimedia Commons,
/// ten subjects, scored with raft5fs-indexer's `clip_scores` example), a
/// photo of what the query says scores 0.214 to 0.294, in any language,
/// and is first for every query; others score 0.18 to 0.225. Drawn test
/// pictures score higher, which is why they don't set these. A photo
/// matches if it is within `IMAGE_MARGIN` of the best match in all the
/// volumes searched, stands out from the others (`Cutoff`),
/// and is above `MIN_IMAGE_SIMILARITY`; rank decides the rest.
pub const MIN_IMAGE_SIMILARITY: f32 = 0.215;
pub const IMAGE_MARGIN: f32 = 0.04;

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

/// How big a view is (`View::stats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViewStats {
    /// Docs, counting those a newer entry replaced, and live ones.
    pub docs: usize,
    pub live: usize,
    /// Live chunks, the words their records keep, and their vectors.
    pub chunks: usize,
    pub chunk_words: usize,
    pub vectors: usize,
    /// Distinct words in the keyword index, and its postings.
    pub words: usize,
    pub postings: usize,
}

/// The live records of a volume, ready to search.
///
/// A view grows: `add` takes the entries of segments it hasn't seen, so a
/// client that reads one new segment doesn't build the view again.
/// - A record that a newer entry replaces stays in the keyword index, as
///   a dead doc that search skips.
/// - Past `REBUILD_DEAD` dead docs, the view builds itself again from its
///   live ones.
#[derive(Default)]
pub struct View {
    /// Each doc's record, or `None` once a newer entry replaced it.
    docs: Vec<Option<Record>>,
    keywords: Bm25,
    /// For each inode, the time of its newest entry, and its doc if that
    /// entry is a record.
    newest: HashMap<u64, (u64, Option<usize>)>,
    live: usize,
}

/// The share of dead docs at which a view builds itself again. Dead docs
/// cost memory and skew keyword statistics a little.
const REBUILD_DEAD: f32 = 0.25;

impl View {
    /// A view of `entries`: every entry in every segment of the volume.
    pub fn new(entries: impl IntoIterator<Item = Entry>) -> Self {
        let mut view = View::default();
        view.add(entries);
        view.shrink();
        view
    }

    /// Gives back the room its lists grew into: after a load, once its
    /// last `add`.
    pub fn shrink(&mut self) {
        self.keywords.shrink();
        self.docs.shrink_to_fit();
        self.newest.shrink_to_fit();
    }

    /// Adds `entries`, from segments the view hasn't seen. For each inode
    /// the newest entry wins, as in `latest`: one older than what the view
    /// has is left out.
    pub fn add(&mut self, entries: impl IntoIterator<Item = Entry>) {
        let mut fresh: Vec<Entry> = latest(entries)
            .into_values()
            .filter(|e| {
                self.newest
                    .get(&e.ino())
                    .is_none_or(|&(at, _)| e.at_ms() >= at)
            })
            .collect();
        // A fixed order, so equal scores rank the same way each time.
        fresh.sort_by_key(|e| e.ino());
        for e in fresh {
            if let Some(&(_, Some(doc))) = self.newest.get(&e.ino()) {
                self.docs[doc] = None;
                self.live -= 1;
            }
            match e {
                Entry::Record(r) => {
                    let (ino, at) = (r.ino, r.at_ms);
                    let doc = self.push(r);
                    self.newest.insert(ino, (at, Some(doc)));
                }
                Entry::Gone { ino, at_ms } => {
                    self.newest.insert(ino, (at_ms, None));
                }
            }
        }
        let dead = self.docs.len() - self.live;
        if dead as f32 > self.docs.len() as f32 * REBUILD_DEAD {
            self.rebuild();
        }
    }

    /// Indexes `r` as a new doc, and gives its number. Its chunks' word
    /// lists go into the keyword index and are not kept with the record.
    fn push(&mut self, mut r: Record) -> usize {
        let doc = self.docs.len();
        self.keywords.add_path(doc, &r.path);
        for (i, c) in r.chunks.iter_mut().enumerate() {
            let at = ChunkRef {
                doc,
                chunk: Some(i),
            };
            self.keywords.add(at, &c.terms, c.len);
            c.terms = Vec::new();
        }
        self.docs.push(Some(r));
        self.live += 1;
        doc
    }

    /// Keeps only the live docs, renumbered in inode order, and the keyword
    /// index's entries for them.
    fn rebuild(&mut self) {
        let mut live: Vec<(u64, usize)> = self
            .docs
            .iter()
            .enumerate()
            .filter_map(|(doc, r)| Some((r.as_ref()?.ino, doc)))
            .collect();
        live.sort();
        let mut renumber = vec![None; self.docs.len()];
        let mut docs = Vec::with_capacity(live.len());
        for (new, &(ino, old)) in live.iter().enumerate() {
            renumber[old] = Some(new);
            docs.push(self.docs[old].take());
            if let Some(slot) = self.newest.get_mut(&ino) {
                slot.1 = Some(new);
            }
        }
        self.keywords.compact(|old| renumber[old]);
        self.docs = docs;
    }

    /// The live docs, with their numbers.
    fn records(&self) -> impl Iterator<Item = (usize, &Record)> + Clone {
        self.docs
            .iter()
            .enumerate()
            .filter_map(|(doc, r)| Some((doc, r.as_ref()?)))
    }

    pub fn len(&self) -> usize {
        self.live
    }

    /// How big the view is, for measuring its memory.
    pub fn stats(&self) -> ViewStats {
        let (words, postings) = self.keywords.size();
        let mut s = ViewStats {
            docs: self.docs.len(),
            live: self.live,
            words,
            postings,
            ..ViewStats::default()
        };
        for (_, r) in self.records() {
            s.chunks += r.chunks.len();
            s.chunk_words += r.chunks.iter().map(|c| c.terms.len()).sum::<usize>();
            s.vectors += r.chunks.iter().filter(|c| c.vector.is_some()).count();
        }
        s
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// The files that best match `query` by keyword, best first.
    pub fn search(&self, query: &str, limit: usize) -> Vec<Hit> {
        self.search_with(query, None, None, limit)
    }

    /// How many photos there are here, and how many of them have an image
    /// vector from `model`, so can be found by what they show. An empty
    /// vector (a picture the model couldn't decode) doesn't count.
    pub fn photos(&self, model: &str) -> (usize, usize) {
        let photos = self.records().filter(|(_, r)| r.kind == DocKind::Photo);
        let with = photos
            .clone()
            .filter(|(_, r)| {
                r.extra
                    .image
                    .as_ref()
                    .is_some_and(|(m, v)| m == model && !v.values.is_empty())
            })
            .count();
        (photos.count(), with)
    }

    /// Whether any photo here has an image vector from `model`.
    pub fn has_image_model(&self, model: &str) -> bool {
        self.records().any(|(_, r)| {
            r.extra
                .image
                .as_ref()
                .is_some_and(|(m, v)| m == model && !v.values.is_empty())
        })
    }

    /// Whether any file here has vectors from `model`: if none does, a
    /// query need not be embedded.
    pub fn has_model(&self, model: &str) -> bool {
        self.records().any(|(_, r)| r.model == model)
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
        search_many(&[self], query, vector, image, limit)
            .into_iter()
            .map(|(_, hit)| hit)
            .collect()
    }

    /// Each live doc's best chunk by meaning, and its score: chunks of at
    /// least `MIN_MEANING_WORDS` words, with vectors from `q`'s model.
    fn meaning_scores(&self, q: &QueryVector<'_>) -> Vec<(usize, usize, f32)> {
        self.records()
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
            .collect()
    }

    /// Each photo's score by what it shows, with image vectors from `q`'s
    /// model. An empty vector (a picture the model couldn't decode) has
    /// none.
    fn image_scores(&self, q: &QueryVector<'_>) -> Vec<(usize, f32)> {
        self.records()
            .filter_map(|(doc, r)| {
                let (model, v) = r.extra.image.as_ref()?;
                (model == q.model && !v.values.is_empty()).then(|| (doc, dot(v, q.values)))
            })
            .collect()
    }
}

/// Which scores by meaning (or by what a photo shows) count as matches,
/// out of every file's score in the whole search: all the volumes
/// searched, not one at a time.
///
/// - At least `floor`, and within `margin` of the best match.
/// - With `MIN_SPREAD_POPULATION` scores or more, also at least `z`
///   standard deviations above their mean. A match stands out from the
///   rest; when nothing matches, the best is only a little better than
///   the others.
struct Cutoff {
    floor: f32,
    margin: f32,
    z: f32,
}

/// How far above the mean a match by meaning is, in standard deviations.
/// These are first estimates, from the score ranges above (matches 0.79
/// to 0.87 against others at 0.70 to 0.78; photos 0.214 to 0.294 against
/// 0.18 to 0.225): check them against real volumes.
pub const MEANING_Z: f32 = 2.0;
pub const IMAGE_Z: f32 = 1.5;

/// The fewest scores the spread rule (`Cutoff::z`) needs: with fewer, the
/// mean and deviation say little.
pub const MIN_SPREAD_POPULATION: usize = 30;

impl Cutoff {
    fn keeps(&self, scores: &[f32]) -> impl Fn(f32) -> bool + use<> {
        let best = scores.iter().copied().fold(f32::MIN, f32::max);
        let mut least = self.floor.max(best - self.margin);
        if scores.len() >= MIN_SPREAD_POPULATION {
            let n = scores.len() as f32;
            let mean = scores.iter().sum::<f32>() / n;
            let var = scores.iter().map(|s| (s - mean) * (s - mean)).sum::<f32>() / n;
            least = least.max(mean + self.z * var.sqrt());
        }
        move |s| s >= least
    }
}

/// Searches `views` as one, best first. Each hit comes with the index in
/// `views` of the view it is from.
///
/// - Keyword scores use statistics from every view together, so they
///   compare across views.
/// - The matches by meaning and by what photos show are chosen from every
///   view's scores together (`Cutoff`): a view with nothing relevant
///   gives none, and a view's weak best doesn't count as much as
///   another's strong one.
/// - The three lists are merged by rank (`rank::fuse`), once, over all
///   views.
pub fn search_many(
    views: &[&View],
    query: &str,
    vector: Option<QueryVector<'_>>,
    image: Option<QueryVector<'_>>,
    limit: usize,
) -> Vec<(usize, Hit)> {
    // Each list looks deeper than the result, so a file a little way
    // down both still rises.
    let depth = limit.saturating_mul(3).max(10);
    type Key = (usize, usize);

    let terms = query_terms(query);
    let mut stats = Stats::default();
    for v in views {
        v.keywords.add_stats(&terms, &mut stats);
    }
    let mut keyword: Vec<(Key, f32, Option<usize>)> = Vec::new();
    for (i, v) in views.iter().enumerate() {
        let found = v
            .keywords
            .search_with(&terms, &stats, depth, |doc| v.docs[doc].is_some());
        keyword.extend(found.into_iter().map(|(doc, s, c)| ((i, doc), s, c)));
    }
    keyword.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    keyword.truncate(depth);

    let mut meaning: Vec<(Key, usize, f32)> = Vec::new();
    if let Some(q) = &vector {
        for (i, v) in views.iter().enumerate() {
            meaning.extend(
                v.meaning_scores(q)
                    .into_iter()
                    .map(|(d, c, s)| ((i, d), c, s)),
            );
        }
        let scores: Vec<f32> = meaning.iter().map(|m| m.2).collect();
        let keeps = Cutoff {
            floor: MIN_SIMILARITY,
            margin: MEANING_MARGIN,
            z: MEANING_Z,
        }
        .keeps(&scores);
        meaning.retain(|m| keeps(m.2));
        meaning.sort_by(|a, b| b.2.total_cmp(&a.2).then(a.0.cmp(&b.0)));
        meaning.truncate(depth);
    }

    let mut shown: Vec<(Key, f32)> = Vec::new();
    if let Some(q) = &image {
        for (i, v) in views.iter().enumerate() {
            shown.extend(v.image_scores(q).into_iter().map(|(d, s)| ((i, d), s)));
        }
        let scores: Vec<f32> = shown.iter().map(|m| m.1).collect();
        let keeps = Cutoff {
            floor: MIN_IMAGE_SIMILARITY,
            margin: IMAGE_MARGIN,
            z: IMAGE_Z,
        }
        .keeps(&scores);
        shown.retain(|m| keeps(m.1));
        shown.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        shown.truncate(depth);
    }

    // The chunk each list matched, keyword first: its words are what the
    // user typed.
    let mut best_chunk: HashMap<Key, Option<usize>> = HashMap::new();
    for (key, chunk) in meaning
        .iter()
        .map(|m| (m.0, Some(m.1)))
        .chain(keyword.iter().map(|k| (k.0, k.2)))
        .rev()
    {
        best_chunk.insert(key, chunk);
    }
    let lists = [
        keyword.iter().map(|k| k.0).collect::<Vec<_>>(),
        meaning.iter().map(|m| m.0).collect(),
        shown.iter().map(|s| s.0).collect(),
    ];
    fuse(&lists)
        .into_iter()
        .take(limit)
        .map(|((i, doc), score)| {
            let r = views[i].docs[doc].as_ref().expect("search finds live docs");
            let chunk = best_chunk.get(&(i, doc)).copied().flatten();
            let preview = chunk
                .or(if r.chunks.is_empty() { None } else { Some(0) })
                .map(|c| r.chunks[c].preview.clone())
                .unwrap_or_default();
            let hit = Hit {
                ino: r.ino,
                path: r.path.clone(),
                kind: r.kind,
                preview,
                score,
                thumb: r.extra.thumb.clone(),
            };
            (i, hit)
        })
        .collect()
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

    fn paths(view: &View, query: &str) -> Vec<String> {
        view.search(query, 10).into_iter().map(|h| h.path).collect()
    }

    #[test]
    fn a_view_grown_in_steps_searches_as_one_built_at_once() {
        let first = vec![
            record(1, 1, "a.txt", "apples and pears"),
            record(2, 1, "b.txt", "pears only"),
            record(3, 1, "c.txt", "plums"),
        ];
        let second = vec![
            // Newer: replaces 1. Older: ignored. A tombstone hides 3.
            record(1, 5, "a2.txt", "apples now"),
            record(2, 0, "old.txt", "pears from before"),
            Entry::Gone { ino: 3, at_ms: 2 },
            record(4, 1, "d.txt", "pears and plums"),
        ];
        let mut grown = View::new(first.clone());
        grown.add(second.clone());
        let whole = View::new(first.into_iter().chain(second));
        for q in ["pears", "apples", "plums", "before"] {
            assert_eq!(paths(&grown, q), paths(&whole, q), "{q}");
        }
        assert_eq!(paths(&grown, "pears"), ["b.txt", "d.txt"]);
        assert_eq!(grown.len(), 3);
        assert_eq!(whole.len(), 3);
    }

    #[test]
    fn a_view_loaded_a_segment_at_a_time_searches_as_one_loaded_whole() {
        let words = ["pears", "plums", "apples", "figs", "dates", "limes"];
        let mut segments: Vec<Vec<Entry>> = Vec::new();
        for s in 0..6u64 {
            // Each segment writes 20 files again, some as tombstones: past
            // a quarter dead, the view rebuilds.
            segments.push(
                (0..20u64)
                    .map(|i| {
                        let ino = (i * 7 + s * 3) % 40;
                        if (i + s) % 9 == 0 {
                            Entry::Gone { ino, at_ms: s + 1 }
                        } else {
                            let w = words[((i + s) % 6) as usize];
                            let text = format!("{w} and {} on day {s}", words[(i % 6) as usize]);
                            record(ino, s + 1, &format!("{ino}.txt"), &text)
                        }
                    })
                    .collect(),
            );
        }
        let mut grown = View::default();
        for seg in &segments {
            grown.add(seg.clone());
        }
        grown.shrink();
        let whole = View::new(segments.concat());
        assert_eq!(grown.len(), whole.len());
        assert_eq!(grown.stats().words, whole.stats().words);
        for q in words.iter().chain(&["day", "and"]) {
            let mut a = paths(&grown, q);
            let mut b = paths(&whole, q);
            a.sort();
            b.sort();
            assert_eq!(a, b, "{q}");
        }
    }

    #[test]
    fn a_view_with_many_dead_docs_builds_itself_again() {
        let mut view = View::new((0..8).map(|i| record(i, 1, &format!("{i}.txt"), "pears")));
        view.add((0..3).map(|i| record(i, 2, &format!("new-{i}.txt"), "plums")));
        // 3 dead of 11 is past a quarter: only live docs are left.
        assert_eq!(view.docs.len(), 8);
        assert!(view.docs.iter().all(Option::is_some));
        assert_eq!(
            paths(&view, "plums"),
            ["new-0.txt", "new-1.txt", "new-2.txt"]
        );
        assert_eq!(paths(&view, "pears").len(), 5);
        view.add([record(0, 3, "last.txt", "plums")]);
        // Equal scores rank in the order docs came in, so compare sorted.
        let mut plums = paths(&view, "plums");
        plums.sort();
        assert_eq!(plums, ["last.txt", "new-1.txt", "new-2.txt"]);
    }

    /// A record whose one chunk scores `cos` against the query `[1, 0, 0]`.
    fn scoring(ino: u64, path: &str, cos: f32) -> Entry {
        let text = "some words about a thing that are long enough to embed";
        embedded(ino, path, text, &[cos, (1.0 - cos * cos).sqrt(), 0.0])
    }

    fn found(views: &[&View], query: &str, q: Option<QueryVector<'_>>) -> Vec<(usize, String)> {
        search_many(views, query, q, None, 10)
            .into_iter()
            .map(|(i, h)| (i, h.path))
            .collect()
    }

    const Q: [f32; 3] = [1.0, 0.0, 0.0];

    #[test]
    fn a_volume_with_nothing_relevant_gives_nothing_by_meaning() {
        let strong = View::new([scoring(1, "match.txt", 0.86), scoring(2, "near.txt", 0.83)]);
        // Its best is over the floor, but far below the other volume's.
        let weak = View::new([scoring(1, "off.txt", 0.77)]);
        let q = || {
            Some(QueryVector {
                model: "m",
                values: &Q,
            })
        };
        let hits = found(&[&strong, &weak], "zzz", q());
        assert_eq!(hits, [(0, "match.txt".into()), (0, "near.txt".into())]);
        // Alone, it still has its best.
        assert_eq!(found(&[&weak], "zzz", q()), [(0, "off.txt".into())]);
    }

    #[test]
    fn a_strong_match_in_one_volume_ranks_above_a_weak_one_in_another() {
        let weak = View::new([record(
            1,
            1,
            "weak.txt",
            "a long note about many things, one of which is a lake, among trees and hills and roads",
        )]);
        let strong = View::new([record(1, 1, "strong.txt", "lake lake lake")]);
        for views in [[&weak, &strong], [&strong, &weak]] {
            let hits = found(&views, "lake", None);
            assert_eq!(hits.len(), 2);
            assert_eq!(hits[0].1, "strong.txt");
        }
    }

    #[test]
    fn keyword_statistics_count_every_volume_searched() {
        // "lake" is in every file of one volume, and rare overall.
        let lakes = View::new((0..5).map(|i| record(i, 1, &format!("l{i}.txt"), "lake shore")));
        let mut others: Vec<Entry> = (0..40)
            .map(|i| record(i, 1, &format!("o{i}.txt"), "hill road"))
            .collect();
        others.push(record(99, 1, "one.txt", "lake hill"));
        let others = View::new(others);
        let alone = lakes.search("lake", 10)[0].score;
        let mut stats = Stats::default();
        let terms = query_terms("lake");
        lakes.keywords.add_stats(&terms, &mut stats);
        let within = lakes.keywords.search_with(&terms, &stats, 1, |_| true)[0].1;
        others.keywords.add_stats(&terms, &mut stats);
        let together = lakes.keywords.search_with(&terms, &stats, 1, |_| true)[0].1;
        assert!(together > within, "{together} vs {within}");
        assert!(alone > 0.0);
    }

    #[test]
    fn when_nothing_stands_out_nothing_matches_by_meaning() {
        // 40 files scoring 0.75 to 0.79: over the floor and close to the
        // best, but none stands out.
        let flat =
            View::new((0..40).map(|i| scoring(i, &format!("{i}.txt"), 0.75 + 0.001 * i as f32)));
        let q = || {
            Some(QueryVector {
                model: "m",
                values: &Q,
            })
        };
        let hits = found(&[&flat], "zzz", q());
        assert!(hits.len() <= 3, "{hits:?}");
        // One that does stand out is kept.
        let mut entries: Vec<Entry> = (0..40)
            .map(|i| scoring(i, &format!("{i}.txt"), 0.72 + 0.001 * i as f32))
            .collect();
        entries.push(scoring(100, "match.txt", 0.84));
        let hits = found(&[&View::new(entries)], "zzz", q());
        assert_eq!(hits, [(0, "match.txt".into())]);
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
        assert_eq!(view.photos("clip"), (2, 2));
        assert_eq!(view.photos("other"), (2, 0));
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
