//! Finding files by their paths: an index of the words in folder and file
//! names, built in memory from records.
//!
//! - Each folder is kept once, with its parent and its name's words, so a
//!   path costs only its file name's words and a folder number.
//! - A query word matches a name word that it equals, or that it starts
//!   (at least `PREFIX_MIN` letters), so "tax" finds `taxes/`.
//! - A match in the file name counts more than one in a folder, and a
//!   whole word more than a start.
//! - A file's score is its matches' weights, each word weighted by its
//!   rarity among paths, over the query's whole weight (0–1). Shorter names
//!   win ties.
//! - Names like `photo.jpg` and `tax_2024-v2` are one word to the Unicode
//!   rules, so names are cut at `.`, `_` and `-` too.

use std::collections::HashMap;

use crate::text::terms;

/// The fewest letters a query word needs to match the start of a name
/// word.
pub const PREFIX_MIN: usize = 3;
/// Weights of a match: whole word or start, in the file name or a folder.
const NAME_WORD: f32 = 1.0;
const NAME_START: f32 = 0.8;
const FOLDER_WORD: f32 = 0.6;
const FOLDER_START: f32 = 0.5;

/// One file's place: its folder and its name's words.
#[derive(Debug, Clone)]
struct File {
    folder: u32,
    words: Box<[u32]>,
}

#[derive(Debug, Clone)]
struct Folder {
    /// `u32::MAX` for the root.
    parent: u32,
    words: Box<[u32]>,
}

/// The path index. Docs are numbered by the caller.
#[derive(Debug, Default, Clone)]
pub struct Paths {
    /// Every name word, sorted, so a start finds a range.
    dictionary: Vec<String>,
    /// Words added since the dictionary was sorted.
    unsorted: HashMap<String, u32>,
    /// Word ids by text, for words in `dictionary`; ids never change.
    ids: HashMap<String, u32>,
    /// For each dictionary position, its word id.
    order: Vec<u32>,
    folders: Vec<Folder>,
    folder_ids: HashMap<String, u32>,
    files: Vec<Option<File>>,
}

/// What `Paths::matching` found in one index: the matching docs, each
/// query word's count of matching docs, and the docs searched.
#[derive(Debug, Default)]
pub struct PathMatches {
    rows: Vec<(usize, Vec<f32>, usize)>,
    pub df: Vec<usize>,
    pub docs: usize,
}

impl PathMatches {
    /// The docs, best first, with their scores (0–1) by `weights` (from
    /// `word_weights`). At most `limit`. Shorter names win ties.
    pub fn ranked(self, weights: &[f32], limit: usize) -> Vec<(usize, f32)> {
        let total: f32 = weights.iter().sum();
        if total <= 0.0 {
            return Vec::new();
        }
        let mut out: Vec<(usize, f32, usize)> = self
            .rows
            .into_iter()
            .map(|(doc, row, len)| {
                let s: f32 = row.iter().zip(weights).map(|(w, i)| w * i).sum();
                (doc, s / total, len)
            })
            .collect();
        out.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.2.cmp(&b.2)).then(a.0.cmp(&b.0)));
        out.truncate(limit);
        out.into_iter().map(|(d, s, _)| (d, s)).collect()
    }
}

/// Each query word's weight, by its rarity: `df` docs of `docs` match it.
/// Pooled counts make scores from several indexes compare.
pub fn word_weights(df: &[usize], docs: usize) -> Vec<f32> {
    let n = docs as f32;
    df.iter()
        .map(|&d| (1.0 + n / (1.0 + d as f32)).ln())
        .collect()
}

/// The words of one path part.
fn name_words(part: &str) -> Vec<String> {
    terms(&part.replace(['.', '_', '-'], " "))
}

impl Paths {
    fn word(&mut self, w: &str) -> u32 {
        if let Some(&id) = self.ids.get(w).or_else(|| self.unsorted.get(w)) {
            return id;
        }
        let id = (self.ids.len() + self.unsorted.len()) as u32;
        self.unsorted.insert(w.to_string(), id);
        id
    }

    fn folder(&mut self, path: &str) -> u32 {
        if let Some(&id) = self.folder_ids.get(path) {
            return id;
        }
        let (parent, name) = match path.rsplit_once('/') {
            Some((p, n)) => (self.folder(p), n),
            None => (u32::MAX, path),
        };
        let words: Vec<u32> = name_words(name).iter().map(|w| self.word(w)).collect();
        let id = self.folders.len() as u32;
        self.folders.push(Folder {
            parent,
            words: words.into(),
        });
        self.folder_ids.insert(path.to_string(), id);
        id
    }

    /// Adds `doc` at `path` (from the volume's root, no leading `/`).
    pub fn add(&mut self, doc: usize, path: &str) {
        let (folder, name) = match path.rsplit_once('/') {
            Some((f, n)) => (self.folder(f), n),
            None => (u32::MAX, path),
        };
        let words: Vec<u32> = name_words(name).iter().map(|w| self.word(w)).collect();
        if self.files.len() <= doc {
            self.files.resize(doc + 1, None);
        }
        self.files[doc] = Some(File {
            folder,
            words: words.into(),
        });
    }

    /// Forgets `doc`.
    pub fn remove(&mut self, doc: usize) {
        if let Some(f) = self.files.get_mut(doc) {
            *f = None;
        }
    }

    /// Keeps only the docs that `doc` maps, renumbered as it says.
    pub fn compact(&mut self, doc: impl Fn(usize) -> Option<usize>) {
        let mut files = Vec::new();
        for (old, f) in self.files.drain(..).enumerate() {
            if let (Some(f), Some(new)) = (f, doc(old)) {
                if files.len() <= new {
                    files.resize(new + 1, None);
                }
                files[new] = Some(f);
            }
        }
        self.files = files;
    }

    /// Sorts the words added since the last search into the dictionary.
    /// Searching needs it; it is called once a load is done.
    pub fn settle(&mut self) {
        if self.unsorted.is_empty() {
            return;
        }
        let mut all: Vec<(String, u32)> = self.ids.drain().chain(self.unsorted.drain()).collect();
        all.sort();
        self.dictionary = all.iter().map(|w| w.0.clone()).collect();
        self.order = all.iter().map(|w| w.1).collect();
        self.ids = all.into_iter().collect();
        self.dictionary.shrink_to_fit();
        self.files.shrink_to_fit();
        self.folders.shrink_to_fit();
    }

    /// For each query word, the ids of name words it matches, with the
    /// weight of a whole word or a start.
    fn matches(&self, query: &[String]) -> Vec<HashMap<u32, bool>> {
        query
            .iter()
            .map(|q| {
                let mut out = HashMap::new();
                let from = self.dictionary.partition_point(|w| w.as_str() < q.as_str());
                for (i, w) in self.dictionary[from..].iter().enumerate() {
                    if !w.starts_with(q.as_str()) {
                        break;
                    }
                    let whole = w == q;
                    if whole || q.chars().count() >= PREFIX_MIN {
                        out.insert(self.order[from + i], whole);
                    }
                }
                out
            })
            .collect()
    }

    /// The docs whose paths match `query`, best first, with their scores
    /// (0–1), over the docs `live` keeps. At most `limit`. Word weights
    /// come from this index alone; `matching` and `PathMatches::ranked`
    /// pool them over several.
    pub fn search(
        &self,
        query: &[String],
        limit: usize,
        live: impl Fn(usize) -> bool,
    ) -> Vec<(usize, f32)> {
        let m = self.matching(query, live);
        let weights = word_weights(&m.df, m.docs);
        m.ranked(&weights, limit)
    }

    /// The docs that `live` keeps whose paths match a word of `query`,
    /// with each word's match weight, and the counts that weigh words.
    pub fn matching(&self, query: &[String], live: impl Fn(usize) -> bool) -> PathMatches {
        let mut out = PathMatches {
            rows: Vec::new(),
            df: vec![0; query.len()],
            docs: 0,
        };
        if query.is_empty() || self.files.is_empty() {
            return out;
        }
        let matches = self.matches(query);
        let any = !matches.iter().all(HashMap::is_empty);
        // Each folder's best match for each query word, its own or its
        // parent's. Parents come before their children.
        let best_in = |words: &[u32], m: &HashMap<u32, bool>, whole: f32, start: f32| -> f32 {
            words
                .iter()
                .filter_map(|w| m.get(w))
                .map(|&is_whole| if is_whole { whole } else { start })
                .fold(0.0, f32::max)
        };
        let mut folder_best: Vec<Vec<f32>> = Vec::with_capacity(self.folders.len());
        if any {
            for f in &self.folders {
                let own: Vec<f32> = matches
                    .iter()
                    .map(|m| best_in(&f.words, m, FOLDER_WORD, FOLDER_START))
                    .collect();
                let row = match folder_best.get(f.parent as usize) {
                    Some(parent) => own.iter().zip(parent).map(|(a, b)| a.max(*b)).collect(),
                    None => own,
                };
                folder_best.push(row);
            }
        }
        let none = vec![0.0; query.len()];
        for (doc, f) in self.files.iter().enumerate() {
            let Some(f) = f else { continue };
            if !live(doc) {
                continue;
            }
            out.docs += 1;
            if !any {
                continue;
            }
            let folder = folder_best.get(f.folder as usize).unwrap_or(&none);
            let row: Vec<f32> = matches
                .iter()
                .zip(folder)
                .map(|(m, &in_folder)| best_in(&f.words, m, NAME_WORD, NAME_START).max(in_folder))
                .collect();
            if row.iter().any(|&w| w > 0.0) {
                for (d, &w) in out.df.iter_mut().zip(&row) {
                    *d += usize::from(w > 0.0);
                }
                out.rows.push((doc, row, f.words.len()));
            }
        }
        out
    }
    /// Rough bytes held, for measuring memory.
    pub fn size(&self) -> usize {
        let words: usize = self.dictionary.iter().map(|w| w.len() + 24 + 8 + 4).sum();
        let files: usize = self
            .files
            .iter()
            .flatten()
            .map(|f| 24 + f.words.len() * 4)
            .sum();
        words + files + self.folders.len() * 24
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(paths: &[&str]) -> Paths {
        let mut p = Paths::default();
        for (i, path) in paths.iter().enumerate() {
            p.add(i, path);
        }
        p.settle();
        p
    }

    fn q(text: &str) -> Vec<String> {
        crate::bm25::query_terms(text)
    }

    #[test]
    fn a_file_name_beats_a_folder_and_a_whole_word_beats_a_start() {
        let p = index(&[
            "taxes/2024/notes.txt",
            "misc/tax-return.pdf",
            "misc/taxonomy.txt",
            "photos/beach.jpg",
        ]);
        let hits = p.search(&q("tax"), 10, |_| true);
        let docs: Vec<usize> = hits.iter().map(|h| h.0).collect();
        assert_eq!(docs, [1, 2, 0]);
        assert!(
            p.search(&q("ta"), 10, |_| true).is_empty(),
            "too short to be a start"
        );
    }

    #[test]
    fn every_query_word_counts_and_folders_count_for_their_files() {
        let p = index(&[
            "vermont/routes/kingdom_loop.gpx",
            "vermont/notes.txt",
            "kingdom.txt",
        ]);
        let hits = p.search(&q("vermont kingdom"), 10, |_| true);
        assert_eq!(hits[0].0, 0);
        assert!((hits[0].1 - 1.0).abs() < 1e-6 || hits[0].1 > hits[1].1);
        assert!(hits.iter().all(|h| h.1 > 0.0 && h.1 <= 1.0));
    }

    #[test]
    fn dead_and_removed_docs_are_skipped_and_shorter_names_win_ties() {
        let mut p = index(&["a/report.txt", "a/report final copy.txt", "b/report.txt"]);
        let hits = p.search(&q("report"), 10, |d| d != 2);
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), [0, 1]);
        p.remove(0);
        p.compact(|d| [None, Some(0), Some(1)][d]);
        let hits = p.search(&q("report"), 10, |_| true);
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), [1, 0]);
    }
}
