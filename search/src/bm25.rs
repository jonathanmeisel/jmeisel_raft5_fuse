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

#[derive(Default)]
pub struct Bm25 {
    /// For each term, the chunks it is in and how often.
    postings: HashMap<String, Vec<(u32, u16)>>,
    chunks: Vec<(ChunkRef, u32)>,
    total_len: u64,
}

impl Bm25 {
    /// Adds a chunk with its counted terms and its length in words.
    pub fn add(&mut self, at: ChunkRef, terms: &[(String, u16)], len: u32) {
        let id = self.chunks.len() as u32;
        self.chunks.push((at, len.max(1)));
        self.total_len += u64::from(len.max(1));
        for (term, count) in terms {
            self.postings
                .entry(term.clone())
                .or_default()
                .push((id, *count));
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
            self.postings.len(),
            self.postings.values().map(Vec::len).sum(),
        )
    }

    /// Adds this index's counts for `terms` to `stats`.
    pub fn add_stats(&self, terms: &[String], stats: &mut Stats) {
        stats.chunks += self.chunks.len() as u64;
        stats.total_len += self.total_len;
        for term in terms {
            let df = self.postings.get(term).map_or(0, Vec::len) as u64;
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
            let Some(list) = self.postings.get(term) else {
                continue;
            };
            let df = stats
                .df
                .get(term)
                .copied()
                .unwrap_or(0)
                .max(list.len() as u64) as f32;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            for &(id, tf) in list {
                let len = self.chunks[id as usize].1 as f32;
                let tf = f32::from(tf);
                let s = idf * tf * (K1 + 1.0) / (tf + K1 * (1.0 - B + B * len / avg));
                *scores.entry(id).or_default() += s;
            }
        }
        let mut best: HashMap<usize, (f32, Option<usize>)> = HashMap::new();
        for (id, score) in scores {
            let at = self.chunks[id as usize].0;
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
