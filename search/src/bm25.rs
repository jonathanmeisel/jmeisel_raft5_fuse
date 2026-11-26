//! Keyword ranking (Okapi BM25) over files, built in memory from records.
//!
//! - Each file is a document: a word's count is its count in the whole
//!   file, and a file's length is all its words. A long file that names a
//!   word once ranks below a short one about it; search by meaning still
//!   finds a long file's focused passage.
//! - Paths are not words here: `paths` searches them.
//! - Words in more than `COMMON_SHARE` of the files searched (with at
//!   least `COMMON_MIN_FILES` files) count for nothing, as the index drops
//!   them at compaction: they say little and cost the most.
//! - A match also gives its coverage: the share of the query's weight
//!   (each word by its rarity) that the file has.

use std::collections::HashMap;

use crate::text::terms;
use crate::vector::{RANKING_COMMON_MIN_FILES, RANKING_COMMON_SHARE};

const K1: f32 = 1.2;
const B: f32 = 0.75;

/// One word's BM25 score in a file: its weight (`Stats::weights`), its
/// count there, the file's length, and the files' mean length.
pub fn term_score(idf: f32, tf: f32, len: f32, avg: f32) -> f32 {
    idf * tf * (K1 + 1.0) / (tf + K1 * (1.0 - B + B * len / avg))
}

/// Words in more than this share of the files count for nothing...
pub const COMMON_SHARE: f64 = RANKING_COMMON_SHARE;
/// ... once there are at least this many files. Fewer files say too
/// little about which words are common.
pub const COMMON_MIN_FILES: u64 = RANKING_COMMON_MIN_FILES;

/// The files a word is in, and how often, as two lists.
#[derive(Default, Clone)]
struct Postings {
    docs: Vec<u32>,
    counts: Vec<u16>,
}

impl Postings {
    fn len(&self) -> usize {
        self.docs.len()
    }

    fn iter(&self) -> impl Iterator<Item = (u32, u16)> + '_ {
        self.docs.iter().copied().zip(self.counts.iter().copied())
    }
}

/// The index: each word once, by number, and for each word the files it
/// is in and how often. Docs are numbered by the caller.
#[derive(Default)]
pub struct Bm25 {
    words: HashMap<String, u32>,
    postings: Vec<Postings>,
    /// Each doc's length in words; 0 for numbers never added.
    lens: Vec<u32>,
    docs: u64,
    total_len: u64,
}

/// One keyword match: the doc, its score, and its coverage (0–1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Match {
    pub doc: usize,
    pub score: f32,
    pub coverage: f32,
}

impl Bm25 {
    /// Adds `doc` with its chunks' counted terms (sorted by word, as
    /// records keep them) and lengths.
    pub fn add_doc<'a>(
        &mut self,
        doc: usize,
        chunks: impl IntoIterator<Item = (&'a [(String, u16)], u32)>,
    ) {
        let mut counts: HashMap<&str, u32> = HashMap::new();
        let mut len = 0u32;
        for (terms, l) in chunks {
            len = len.saturating_add(l);
            for (t, n) in terms {
                *counts.entry(t.as_str()).or_default() += u32::from(*n);
            }
        }
        if self.lens.len() <= doc {
            self.lens.resize(doc + 1, 0);
        }
        let len = len.max(1);
        self.lens[doc] = len;
        self.docs += 1;
        self.total_len += u64::from(len);
        let mut sorted: Vec<(&str, u32)> = counts.into_iter().collect();
        sorted.sort_unstable();
        for (term, count) in sorted {
            let word = match self.words.get(term) {
                Some(&w) => w,
                None => {
                    let w = self.postings.len() as u32;
                    self.words.insert(term.to_string(), w);
                    self.postings.push(Postings::default());
                    w
                }
            };
            let p = &mut self.postings[word as usize];
            p.docs.push(doc as u32);
            p.counts.push(count.min(u32::from(u16::MAX)) as u16);
        }
    }

    /// Keeps only the docs that `doc` maps, renumbered as it says, and
    /// drops words no doc has any more.
    pub fn compact(&mut self, doc: impl Fn(usize) -> Option<usize>) {
        let mut lens = Vec::new();
        self.docs = 0;
        self.total_len = 0;
        for (old, &len) in self.lens.iter().enumerate() {
            if len == 0 {
                continue;
            }
            if let Some(d) = doc(old) {
                if lens.len() <= d {
                    lens.resize(d + 1, 0);
                }
                lens[d] = len;
                self.docs += 1;
                self.total_len += u64::from(len);
            }
        }
        self.lens = lens;
        let old_postings = std::mem::take(&mut self.postings);
        let mut words: Vec<(String, u32)> = self.words.drain().collect();
        words.sort_by_key(|(_, w)| *w);
        for (word, w) in words {
            let mut kept: Vec<(u32, u16)> = old_postings[w as usize]
                .iter()
                .filter_map(|(d, n)| doc(d as usize).map(|new| (new as u32, n)))
                .collect();
            kept.sort_by_key(|(d, _)| *d);
            if !kept.is_empty() {
                self.words.insert(word, self.postings.len() as u32);
                self.postings.push(Postings {
                    docs: kept.iter().map(|k| k.0).collect(),
                    counts: kept.iter().map(|k| k.1).collect(),
                });
            }
        }
    }

    /// Gives back the room the lists grew into and don't use.
    pub fn shrink(&mut self) {
        for p in &mut self.postings {
            p.docs.shrink_to_fit();
            p.counts.shrink_to_fit();
        }
        self.postings.shrink_to_fit();
        self.lens.shrink_to_fit();
        self.words.shrink_to_fit();
    }

    /// The docs that match `query`, best first. At most `limit`.
    pub fn search(&self, query: &str, limit: usize) -> Vec<Match> {
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
        stats.docs += self.docs;
        stats.total_len += self.total_len;
        for term in terms {
            let df = self
                .words
                .get(term)
                .map_or(0, |&w| self.postings[w as usize].len()) as u64;
            *stats.df.entry(term.clone()).or_default() += df;
        }
    }

    /// The docs that match `terms` (`query_terms`), scored with `stats`,
    /// over only the docs that `live` keeps.
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
    ) -> Vec<Match> {
        if self.docs == 0 || stats.docs == 0 {
            return Vec::new();
        }
        let n = stats.docs as f32;
        let avg = stats.total_len as f32 / n;
        let weights = stats.weights(terms);
        let total: f32 = weights.iter().map(|w| w.1).sum();
        if total <= 0.0 {
            return Vec::new();
        }
        let mut scores: HashMap<u32, (f32, f32)> = HashMap::new();
        for (term, idf) in weights {
            let Some(list) = self.words.get(term).map(|&w| &self.postings[w as usize]) else {
                continue;
            };
            for (d, tf) in list.iter() {
                let len = self.lens[d as usize] as f32;
                let s = term_score(idf, f32::from(tf), len, avg);
                let e = scores.entry(d).or_default();
                e.0 += s;
                e.1 += idf;
            }
        }
        let mut out: Vec<Match> = scores
            .into_iter()
            .filter(|(d, _)| live(*d as usize))
            .map(|(d, (score, w))| Match {
                doc: d as usize,
                score,
                coverage: w / total,
            })
            .collect();
        out.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.doc.cmp(&b.doc)));
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

/// What BM25 scores by, over one index or several: how many docs, their
/// total length, and how many docs have each query word.
#[derive(Debug, Default)]
pub struct Stats {
    pub docs: u64,
    pub total_len: u64,
    pub df: HashMap<String, u64>,
}

impl Stats {
    /// Whether `term` is too common to count.
    pub fn is_common(&self, term: &str) -> bool {
        self.docs >= COMMON_MIN_FILES
            && self.df.get(term).copied().unwrap_or(0) as f64 > self.docs as f64 * COMMON_SHARE
    }

    /// Each term that counts, with its weight (inverse document
    /// frequency). A word no doc has counts too, at the highest weight:
    /// no file matches it, so each file's coverage falls. A query whose
    /// rarest word is in no text (a photo's subject, say) then gives weak
    /// keyword matches, not full ones on its other words.
    pub fn weights<'a>(&self, terms: &'a [String]) -> Vec<(&'a str, f32)> {
        let n = self.docs as f32;
        terms
            .iter()
            .filter(|t| !self.is_common(t))
            .map(|t| {
                let df = self.df.get(t.as_str()).copied().unwrap_or(0) as f32;
                (t.as_str(), ((n - df + 0.5) / (df + 0.5) + 1.0).ln())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::counted;

    fn add_text(index: &mut Bm25, doc: usize, chunks: &[&str]) {
        let counted: Vec<(Vec<(String, u16)>, u32)> = chunks
            .iter()
            .map(|c| {
                let t = terms(c);
                (counted(&t), t.len() as u32)
            })
            .collect();
        index.add_doc(doc, counted.iter().map(|(t, l)| (t.as_slice(), *l)));
    }

    #[test]
    fn rarer_and_more_frequent_terms_rank_higher() {
        let mut index = Bm25::default();
        add_text(&mut index, 0, &["the bike ride along the lake"]);
        add_text(&mut index, 1, &["the the the the lake"]);
        add_text(&mut index, 2, &["bike bike bike repair notes"]);
        let hits = index.search("bike", 10);
        assert_eq!(hits.iter().map(|h| h.doc).collect::<Vec<_>>(), [2, 0]);
        // "the" is in most files, so it adds little next to "lake".
        let hits = index.search("the lake", 10);
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.doc != 2));
    }

    #[test]
    fn a_file_counts_its_words_across_chunks() {
        let mut index = Bm25::default();
        add_text(&mut index, 0, &["receipts and more", "tax return receipts"]);
        add_text(&mut index, 1, &["tax notes"]);
        let hits = index.search("tax receipts", 10);
        assert_eq!(hits[0].doc, 0);
        assert!((hits[0].coverage - 1.0).abs() < 1e-6);
        assert!(hits[1].coverage < 1.0);
    }

    #[test]
    fn common_words_count_for_nothing_in_a_large_index() {
        let mut index = Bm25::default();
        let files = COMMON_MIN_FILES as usize;
        for d in 0..files {
            let text = if d % 10 == 0 {
                "the kayak trip"
            } else {
                "the notes"
            };
            add_text(&mut index, d, &[text]);
        }
        // "the" is in every file: it finds nothing alone, and adds nothing.
        assert!(index.search("the", 10).is_empty());
        let hits = index.search("the kayak", 10);
        assert!((hits[0].coverage - 1.0).abs() < 1e-6);
    }

    #[test]
    fn compacting_renumbers_and_drops_dead_docs() {
        let mut index = Bm25::default();
        add_text(&mut index, 0, &["alpha"]);
        add_text(&mut index, 1, &["beta"]);
        add_text(&mut index, 2, &["alpha beta"]);
        index.compact(|d| [None, Some(0), Some(1)][d]);
        assert_eq!(index.size(), (2, 3));
        let hits: Vec<usize> = index.search("alpha", 10).iter().map(|h| h.doc).collect();
        assert_eq!(hits, [1]);
    }

    #[test]
    fn nothing_matches_an_empty_index_or_query() {
        assert!(Bm25::default().search("x", 5).is_empty());
        let mut index = Bm25::default();
        add_text(&mut index, 0, &["words"]);
        assert!(index.search("", 5).is_empty());
        assert!(index.search("other", 5).is_empty());
    }
}
