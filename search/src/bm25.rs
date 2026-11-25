//! Keyword ranking (Okapi BM25) over chunks, built in memory from records.
//!
//! - Each chunk is a document. A file's score is its best chunk's score, so
//!   a long file does not win only by being long.
//! - A file's path counts as one more chunk, so "vermont" finds files in a
//!   `vermont/` folder.

use std::collections::HashMap;

use crate::text::{counted, terms};

const K1: f32 = 1.2;
const B: f32 = 0.75;

/// One chunk's place: which document (by the caller's number) and which
/// chunk of it. `chunk` is `None` for the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkRef {
    pub doc: usize,
    pub chunk: Option<usize>,
}

/// A chunk as the index keeps it: its doc, which chunk (`PATH` for the
/// path), and its length in words.
#[derive(Debug, Clone, Copy)]
struct Slot {
    doc: u32,
    chunk: u32,
    len: u32,
}

const PATH: u32 = u32::MAX;

impl Slot {
    fn at(self) -> ChunkRef {
        ChunkRef {
            doc: self.doc as usize,
            chunk: (self.chunk != PATH).then_some(self.chunk as usize),
        }
    }
}

/// The chunks a word is in, and how often, as two lists (6 bytes a
/// posting, where pairs would take 8).
#[derive(Default, Clone)]
struct Postings {
    chunks: Vec<u32>,
    counts: Vec<u16>,
}

impl Postings {
    fn len(&self) -> usize {
        self.chunks.len()
    }

    fn iter(&self) -> impl Iterator<Item = (u32, u16)> + '_ {
        self.chunks.iter().copied().zip(self.counts.iter().copied())
    }
}

/// The index: each word once, by number, and for each word the chunks it
/// is in and how often.
#[derive(Default)]
pub struct Bm25 {
    words: HashMap<String, u32>,
    postings: Vec<Postings>,
    chunks: Vec<Slot>,
    total_len: u64,
}

impl Bm25 {
    /// Adds a chunk with its counted terms and its length in words.
    pub fn add(&mut self, at: ChunkRef, terms: &[(String, u16)], len: u32) {
        let id = self.chunks.len() as u32;
        self.chunks.push(Slot {
            doc: at.doc as u32,
            chunk: at.chunk.map_or(PATH, |c| c as u32),
            len: len.max(1),
        });
        self.total_len += u64::from(len.max(1));
        for (term, count) in terms {
            let word = match self.words.get(term) {
                Some(&w) => w,
                None => {
                    let w = self.postings.len() as u32;
                    self.words.insert(term.clone(), w);
                    self.postings.push(Postings::default());
                    w
                }
            };
            let p = &mut self.postings[word as usize];
            p.chunks.push(id);
            p.counts.push(*count);
        }
    }

    /// Adds `doc`'s path as a chunk of its own. Names like `photo.jpg` and
    /// `tax_2024-v2` are one word to the Unicode rules, so the path is cut
    /// at `.`, `_` and `-` too, and each part found alone.
    pub fn add_path(&mut self, doc: usize, path: &str) {
        let t = terms(&path.replace(['/', '.', '_', '-'], " "));
        if !t.is_empty() {
            self.add(ChunkRef { doc, chunk: None }, &counted(&t), t.len() as u32);
        }
    }

    /// Keeps only the chunks of docs that `doc` maps, renumbered as it
    /// says, and drops words no chunk has any more.
    pub fn compact(&mut self, doc: impl Fn(usize) -> Option<usize>) {
        let mut renumber = vec![u32::MAX; self.chunks.len()];
        let mut chunks = Vec::new();
        self.total_len = 0;
        for (old, slot) in self.chunks.iter().enumerate() {
            if let Some(d) = doc(slot.doc as usize) {
                renumber[old] = chunks.len() as u32;
                self.total_len += u64::from(slot.len);
                chunks.push(Slot {
                    doc: d as u32,
                    ..*slot
                });
            }
        }
        self.chunks = chunks;
        let mut postings = Vec::new();
        let old_postings = std::mem::take(&mut self.postings);
        let mut words: Vec<(String, u32)> = self.words.drain().collect();
        words.sort_by_key(|(_, w)| *w);
        for (word, w) in words {
            let mut kept: Vec<(u32, u16)> = old_postings[w as usize]
                .iter()
                .filter_map(|(chunk, n)| {
                    let new = renumber[chunk as usize];
                    (new != u32::MAX).then_some((new, n))
                })
                .collect();
            kept.sort_by_key(|(chunk, _)| *chunk);
            if !kept.is_empty() {
                self.words.insert(word, postings.len() as u32);
                postings.push(Postings {
                    chunks: kept.iter().map(|k| k.0).collect(),
                    counts: kept.iter().map(|k| k.1).collect(),
                });
            }
        }
        self.postings = postings;
    }

    /// Gives back the room the lists grew into and don't use.
    pub fn shrink(&mut self) {
        for p in &mut self.postings {
            p.chunks.shrink_to_fit();
            p.counts.shrink_to_fit();
        }
        self.postings.shrink_to_fit();
        self.chunks.shrink_to_fit();
        self.words.shrink_to_fit();
    }

    /// The documents that match `query`, best first, each with its score and
    /// best chunk. At most `limit`.
    pub fn search(&self, query: &str, limit: usize) -> Vec<(usize, f32, Option<usize>)> {
        let terms = query_terms(query);
        let mut stats = Stats::default();
        self.add_stats(&terms, &mut stats);
        self.search_with(&terms, &stats, limit, |_| true)
    }

    /// How many distinct words it has, and how many postings in all.
    pub fn size(&self) -> (usize, usize) {
        (
            self.words.len(),
            self.postings.iter().map(Postings::len).sum(),
        )
    }

    /// Adds this index's counts for `terms` to `stats`.
    pub fn add_stats(&self, terms: &[String], stats: &mut Stats) {
        stats.chunks += self.chunks.len() as u64;
        stats.total_len += self.total_len;
        for term in terms {
            let df = self
                .words
                .get(term)
                .map_or(0, |&w| self.postings[w as usize].len()) as u64;
            *stats.df.entry(term.clone()).or_default() += df;
        }
    }

    /// The documents that match `terms` (`query_terms`), scored with
    /// `stats`, over only the documents that `live` keeps.
    ///
    /// With `stats` from several indexes (`add_stats`), scores compare
    /// across them: a word rare in one small volume but common in the
    /// others doesn't count for more there.
    pub fn search_with(
        &self,
        terms: &[String],
        stats: &Stats,
        limit: usize,
        live: impl Fn(usize) -> bool,
    ) -> Vec<(usize, f32, Option<usize>)> {
        if self.chunks.is_empty() || stats.chunks == 0 {
            return Vec::new();
        }
        let n = stats.chunks as f32;
        let avg = stats.total_len as f32 / n;
        let mut scores: HashMap<u32, f32> = HashMap::new();
        for term in terms {
            let Some(list) = self.words.get(term).map(|&w| &self.postings[w as usize]) else {
                continue;
            };
            let df = stats
                .df
                .get(term)
                .copied()
                .unwrap_or(0)
                .max(list.len() as u64) as f32;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            for (id, tf) in list.iter() {
                let len = self.chunks[id as usize].len as f32;
                let tf = f32::from(tf);
                let s = idf * tf * (K1 + 1.0) / (tf + K1 * (1.0 - B + B * len / avg));
                *scores.entry(id).or_default() += s;
            }
        }
        let mut best: HashMap<usize, (f32, Option<usize>)> = HashMap::new();
        for (id, score) in scores {
            let at = self.chunks[id as usize].at();
            if !live(at.doc) {
                continue;
            }
            let slot = best.entry(at.doc).or_insert((f32::MIN, None));
            // Show a chunk of text rather than the path when they tie.
            if score > slot.0 || (score == slot.0 && slot.1.is_none()) {
                *slot = (score, at.chunk);
            }
        }
        let mut out: Vec<_> = best.into_iter().map(|(d, (s, c))| (d, s, c)).collect();
        out.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        out.truncate(limit);
        out
    }
}

/// The words of a query, each once.
pub fn query_terms(query: &str) -> Vec<String> {
    let mut t = terms(query);
    t.sort();
    t.dedup();
    t
}

/// What BM25 scores by, over one index or several: how many chunks, their
/// total length, and how many chunks have each query word.
#[derive(Debug, Default)]
pub struct Stats {
    pub chunks: u64,
    pub total_len: u64,
    pub df: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_text(index: &mut Bm25, doc: usize, chunk: usize, text: &str) {
        let t = terms(text);
        index.add(
            ChunkRef {
                doc,
                chunk: Some(chunk),
            },
            &counted(&t),
            t.len() as u32,
        );
    }

    #[test]
    fn rarer_and_more_frequent_terms_rank_higher() {
        let mut index = Bm25::default();
        add_text(&mut index, 0, 0, "the bike ride along the lake");
        add_text(&mut index, 1, 0, "the the the the lake");
        add_text(&mut index, 2, 0, "bike bike bike repair notes");
        let hits = index.search("bike", 10);
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), [2, 0]);
        // "the" is in most chunks, so it adds little next to "lake".
        let hits = index.search("the lake", 10);
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.0 != 2));
    }

    #[test]
    fn a_file_scores_by_its_best_chunk_and_its_path_counts() {
        let mut index = Bm25::default();
        add_text(&mut index, 0, 0, "nothing here");
        add_text(&mut index, 0, 1, "receipts for the tax return");
        index.add_path(1, "vermont/routes/kingdom_loop.gpx");
        let hits = index.search("tax", 10);
        assert_eq!(hits, [(0, hits[0].1, Some(1))]);
        let hits = index.search("Vermont", 10);
        assert_eq!(hits[0].0, 1);
        assert_eq!(hits[0].2, None, "found by its path");
        assert_eq!(index.search("kingdom gpx", 10)[0].0, 1);
    }

    #[test]
    fn nothing_matches_an_empty_index_or_query() {
        assert!(Bm25::default().search("x", 5).is_empty());
        let mut index = Bm25::default();
        add_text(&mut index, 0, 0, "words");
        assert!(index.search("", 5).is_empty());
        assert!(index.search("other", 5).is_empty());
    }
}
