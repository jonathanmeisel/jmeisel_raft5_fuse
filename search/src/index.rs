//! A volume's index as search reads it: its generation, of which only the
//! small parts stay in memory, and its recent segments, all in memory as
//! a `View`.
//!
//! - **In memory:** the generation's records (one row per file), a word
//!   index over their paths, the clusters' centres, and the words it
//!   dropped; and the recent segments.
//! - **Dead files:** a generation file whose inode has a newer entry in
//!   the recent segments (a record or a tombstone) is dead: search skips
//!   it. A newer move changes only its path.
//! - **A search runs in steps**, so that the caller can load pieces from
//!   wherever it keeps them, even asynchronously:
//!   1. `needs`: the keyword shards of the query's words, and the clusters
//!      nearest its vectors;
//!   2. `search`: the ranked files;
//!   3. `preview_needs`: the previews pieces of the generation's hits;
//!   4. `hits`: the results, with their previews.
//! - A `View` alone (no generation) searches the same way, with no pieces.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::Error;
use crate::bm25::{Stats, query_terms, term_score};
use crate::cluster::{self, Centres};
use crate::filter::{Facts, Filter, Sort};
use crate::generation::{
    ClusterEntry, FILES_PER_PIECE, FilePreviews, Header, Kind, PieceId, Row, decode_centres,
    decode_cluster, decode_previews, decode_rows, decode_shard,
};
use crate::paths::{PathMatches, Paths, word_weights};
use crate::query::Vocabulary;
use crate::rank::{Ranking, Spread, merge};
use crate::record::DocKind;
use crate::view::{
    Cutoff, Hit, IMAGE_MARGIN, IMAGE_Z, MEANING_MARGIN, MEANING_Z, MIN_IMAGE_SIMILARITY,
    MIN_MEANING_WORDS, MIN_SIMILARITY, QueryVector, View, chunk_with,
};

/// Vectors a query looks at in a generation's clusters, at least...
pub const PROBE_VECTORS: usize = 20_000;
/// ... and at least this share of them, ...
///
/// raft5fs-eval's recall, on 53,000 text vectors in 230 clusters: of a
/// full scan's results, 0.80 are found probing 3.5% of the vectors (the
/// fewest clusters), 0.92 at 10%, 0.97 at 20%; about 0.95 here.
pub const PROBE_SHARE: f64 = 0.15;
/// ... in at least this many clusters.
pub const PROBE_CLUSTERS: usize = 8;

/// The parts of a generation that stay in memory.
pub struct Generation {
    pub header: Header,
    rows: Vec<Row>,
    paths: Paths,
    text: Option<Centres>,
    /// The mean text centres were trained around.
    text_mean: Vec<f32>,
    photo: Option<Centres>,
    text_sizes: Vec<usize>,
    photo_sizes: Vec<usize>,
    /// The samples' vectors, and how many files with vectors each sampled
    /// file stands for.
    text_sample: Vec<ClusterEntry>,
    photo_sample: Vec<ClusterEntry>,
    text_weight: f32,
    photo_weight: f32,
    by_ino: HashMap<u64, u32>,
    dropped: HashSet<String>,
    /// The places, cameras and people its files name, for reading
    /// queries.
    vocabulary: Vocabulary,
}

impl Generation {
    /// The pieces `load` reads: records and centres.
    pub fn resident(header: &Header) -> Vec<PieceId> {
        header
            .pieces
            .iter()
            .filter(|p| {
                matches!(
                    p.id.kind,
                    Kind::Records
                        | Kind::TextCentres
                        | Kind::PhotoCentres
                        | Kind::TextSample
                        | Kind::PhotoSample
                )
            })
            .map(|p| p.id)
            .collect()
    }

    /// The generation `header` describes, with its resident pieces from
    /// `piece`.
    pub fn load(header: Header, piece: impl Fn(PieceId) -> Option<Vec<u8>>) -> Result<Self, Error> {
        let missing = || Error {
            what: "a search index generation without one of its pieces",
            short: true,
        };
        let mut records: Vec<_> = header.pieces_of(Kind::Records).map(|p| p.id).collect();
        records.sort();
        let mut rows = Vec::with_capacity(header.files as usize);
        for id in records {
            rows.extend(decode_rows(&piece(id).ok_or_else(missing)?)?);
        }
        let centres = |kind| -> Result<Option<(Centres, Vec<f32>)>, Error> {
            match header.pieces_of(kind).next() {
                None => Ok(None),
                Some(p) => Ok(Some(decode_centres(
                    kind,
                    &piece(p.id).ok_or_else(missing)?,
                )?)),
            }
        };
        let (text, text_mean) = match centres(Kind::TextCentres)? {
            Some((c, m)) => (Some(c), m),
            None => (None, Vec::new()),
        };
        let photo = centres(Kind::PhotoCentres)?.map(|c| c.0);
        let sizes = |kind, k: usize| -> Vec<usize> {
            let mut out = vec![0; k];
            for p in header.pieces_of(kind) {
                if let Some(slot) = out.get_mut(p.id.n as usize) {
                    *slot = p.items as usize;
                }
            }
            out
        };
        let text_sizes = sizes(Kind::TextCluster, text.as_ref().map_or(0, Centres::len));
        let photo_sizes = sizes(Kind::PhotoCluster, photo.as_ref().map_or(0, Centres::len));
        let sample = |kind| -> Result<Vec<ClusterEntry>, Error> {
            match header.pieces_of(kind).next() {
                None => Ok(Vec::new()),
                Some(p) => decode_cluster(kind, &piece(p.id).ok_or_else(missing)?),
            }
        };
        let text_sample = sample(Kind::TextSample)?;
        let photo_sample = sample(Kind::PhotoSample)?;
        let weight = |s: &[ClusterEntry], files: usize| -> f32 {
            let mut sampled: Vec<u32> = s.iter().map(|e| e.file).collect();
            sampled.dedup();
            if sampled.is_empty() {
                0.0
            } else {
                files as f32 / sampled.len() as f32
            }
        };
        let text_files = rows
            .iter()
            .filter(|r| r.embeddable && r.model == header.text_model)
            .count();
        let photo_files = rows
            .iter()
            .filter(|r| {
                r.image
                    .as_ref()
                    .is_some_and(|(m, has)| *has && *m == header.clip_model)
            })
            .count();
        let text_weight = weight(&text_sample, text_files);
        let photo_weight = weight(&photo_sample, photo_files);
        let mut paths = Paths::default();
        let mut by_ino = HashMap::with_capacity(rows.len());
        let mut vocabulary = Vocabulary::default();
        for (i, r) in rows.iter().enumerate() {
            paths.add(i, &r.path);
            by_ino.insert(r.ino, i as u32);
            vocabulary.add_meta(&r.meta);
        }
        paths.settle();
        rows.shrink_to_fit();
        Ok(Self {
            dropped: header.dropped.iter().cloned().collect(),
            header,
            rows,
            paths,
            text,
            text_mean,
            photo,
            text_sizes,
            photo_sizes,
            text_sample,
            photo_sample,
            text_weight,
            photo_weight,
            by_ino,
            vocabulary,
        })
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The text vectors of the sampled files.
    pub fn text_sample(&self) -> &[ClusterEntry] {
        &self.text_sample
    }

    /// The image vectors of the sampled photos.
    pub fn photo_sample(&self) -> &[ClusterEntry] {
        &self.photo_sample
    }

    /// The file number of `ino`, if the generation has it.
    pub fn file_of(&self, ino: u64) -> Option<u32> {
        self.by_ino.get(&ino).copied()
    }
}

/// A volume's index: its generation, if compacted, and its recent
/// segments.
pub struct Index {
    pub generation: Option<Arc<Generation>>,
    pub recent: View,
    /// One bit per generation file: set if dead.
    dead: Vec<u64>,
    /// The dead files' words, which keyword statistics leave out.
    dead_words: u64,
    /// Generation files at new paths, and a path index of them.
    moved: HashMap<u32, String>,
    moved_paths: Paths,
}

/// Where a file is: in the generation (by number) or in the recent
/// segments (by the view's doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum At {
    Generation(u32),
    Recent(usize),
}

/// One index to search, borrowed: what `Index` and a lone `View` give.
#[derive(Clone, Copy)]
pub struct Source<'a> {
    pub(crate) generation: Option<&'a Generation>,
    recent: &'a View,
    dead: &'a [u64],
    dead_words: u64,
    moved: Option<(&'a HashMap<u32, String>, &'a Paths)>,
}

impl View {
    /// This view, to search alone.
    pub fn source(&self) -> Source<'_> {
        Source {
            generation: None,
            recent: self,
            dead: &[],
            dead_words: 0,
            moved: None,
        }
    }
}

impl Index {
    pub fn new(generation: Option<Arc<Generation>>, recent: View) -> Self {
        let mut index = Self {
            generation,
            recent,
            dead: Vec::new(),
            dead_words: 0,
            moved: HashMap::new(),
            moved_paths: Paths::default(),
        };
        index.settle();
        index
    }

    /// Adds entries from recent segments it hasn't seen.
    pub fn add_recent(&mut self, entries: impl IntoIterator<Item = crate::record::Entry>) {
        self.recent.add(entries);
        self.settle();
    }

    /// Works out again which generation files are dead or moved.
    fn settle(&mut self) {
        let Some(g) = &self.generation else { return };
        self.dead = vec![0; g.rows.len().div_ceil(64)];
        self.dead_words = 0;
        for (ino, at, _) in self.recent.newest() {
            if let Some(f) = g.file_of(ino)
                && at >= g.rows[f as usize].at_ms
                && self.dead[f as usize / 64] & (1 << (f % 64)) == 0
            {
                self.dead[f as usize / 64] |= 1 << (f % 64);
                self.dead_words += u64::from(g.rows[f as usize].words);
            }
        }
        self.moved.clear();
        self.moved_paths = Paths::default();
        for (ino, (at, path)) in self.recent.moves() {
            if let Some(f) = g.file_of(*ino)
                && *at >= g.rows[f as usize].at_ms
            {
                self.moved.insert(f, path.clone());
                self.moved_paths.add(f as usize, path);
            }
        }
        self.moved_paths.settle();
    }

    pub fn source(&self) -> Source<'_> {
        Source {
            generation: self.generation.as_deref(),
            recent: &self.recent,
            dead: &self.dead,
            dead_words: self.dead_words,
            moved: Some((&self.moved, &self.moved_paths)),
        }
    }

    /// Live files in all.
    pub fn len(&self) -> usize {
        self.source().gen_live().count() + self.recent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The live generation files' rows, at their paths now.
    pub fn rows(&self) -> Vec<Row> {
        let s = self.source();
        s.gen_live()
            .map(|(f, r)| {
                let mut r = r.clone();
                if let Some(p) = s.moved_path(f) {
                    r.path = p.to_string();
                }
                r
            })
            .collect()
    }

    /// The places, cameras and people its files name, for reading queries
    /// (`query::parse`). A dead file's names may linger until the next
    /// compaction: they only let a query name them.
    pub fn vocabulary(&self) -> Vocabulary {
        let mut v = self
            .generation
            .as_ref()
            .map(|g| g.vocabulary.clone())
            .unwrap_or_default();
        for r in self.recent.live_records() {
            v.add_meta(&r.extra.meta);
        }
        v
    }

    /// Live file `ino`'s row, at its path now: from the recent segments if
    /// they have it, else from the generation.
    pub fn row(&self, ino: u64) -> Option<Row> {
        if let Some(r) = self.recent.live_records().find(|r| r.ino == ino) {
            return Some(Row::of(r, crate::view::MIN_MEANING_WORDS));
        }
        let s = self.source();
        let g = s.generation?;
        let f = g.file_of(ino)?;
        if s.is_dead(f) {
            return None;
        }
        let mut row = g.rows.get(f as usize)?.clone();
        if let Some(p) = s.moved_path(f) {
            row.path = p.to_string();
        }
        Some(row)
    }

    /// Every live file's row: the generation's, then the recent records'.
    pub fn all_rows(&self) -> Vec<Row> {
        let mut out = self.rows();
        out.extend(
            self.recent
                .live_records()
                .map(|r| Row::of(r, crate::view::MIN_MEANING_WORDS)),
        );
        out
    }

    /// Photos, and how many have an image vector from `model`.
    pub fn photos(&self, model: &str) -> (usize, usize) {
        let (mut n, mut with) = self.recent.photos(model);
        for (_, r) in self.source().gen_live() {
            if r.kind == DocKind::Photo {
                n += 1;
                with += usize::from(r.image.as_ref().is_some_and(|(m, has)| m == model && *has));
            }
        }
        (n, with)
    }

    /// Whether any file has text vectors from `model`.
    pub fn has_model(&self, model: &str) -> bool {
        self.recent.has_model(model) || self.source().gen_live().any(|(_, r)| r.model == model)
    }

    /// Whether any photo has an image vector from `model`.
    pub fn has_image_model(&self, model: &str) -> bool {
        self.recent.has_image_model(model)
            || self
                .source()
                .gen_live()
                .any(|(_, r)| r.image.as_ref().is_some_and(|(m, has)| m == model && *has))
    }
}

impl<'a> Source<'a> {
    pub(crate) fn is_dead(&self, f: u32) -> bool {
        self.dead
            .get(f as usize / 64)
            .is_some_and(|w| w & (1 << (f % 64)) != 0)
    }

    pub(crate) fn moved_path(&self, f: u32) -> Option<&'a str> {
        self.moved.and_then(|(m, _)| m.get(&f)).map(String::as_str)
    }

    pub(crate) fn gen_live(&self) -> impl Iterator<Item = (u32, &'a Row)> + '_ {
        let rows: &'a [Row] = self.generation.map_or(&[], |g| g.rows.as_slice());
        rows.iter()
            .enumerate()
            .map(|(f, r)| (f as u32, r))
            .filter(|(f, _)| !self.is_dead(*f))
    }
}

/// Pieces a search has loaded: by index (in the list searched) and id.
pub type Pieces = HashMap<(usize, PieceId), Vec<u8>>;

/// Which of one source's live files a filter keeps.
struct Kept {
    generation: Vec<bool>,
    recent: Vec<bool>,
    /// Live generation files, and how many of them it keeps.
    live: usize,
    kept: usize,
}

impl Kept {
    fn of(s: &Source<'_>, filter: &Filter) -> Self {
        let rows: &[Row] = s.generation.map_or(&[], |g| g.rows.as_slice());
        let mut live = 0;
        let generation = rows
            .iter()
            .enumerate()
            .map(|(f, r)| {
                let f = f as u32;
                if s.is_dead(f) {
                    return false;
                }
                live += 1;
                let facts = Facts::of_row(r);
                let facts = s.moved_path(f).map_or(facts, |p| facts.at_path(p));
                filter.keeps(&facts)
            })
            .collect::<Vec<_>>();
        let kept = generation.iter().filter(|k| **k).count();
        let recent = s
            .recent
            .docs
            .iter()
            .map(|d| {
                d.as_ref()
                    .is_some_and(|r| filter.keeps(&Facts::of_record(r)))
            })
            .collect();
        Self {
            generation,
            recent,
            live,
            kept,
        }
    }

    fn keeps(&self, at: At) -> bool {
        match at {
            At::Generation(f) => self.generation.get(f as usize).copied().unwrap_or(false),
            At::Recent(d) => self.recent.get(d).copied().unwrap_or(false),
        }
    }

    /// The share of the generation's live files it keeps.
    fn share(&self) -> f64 {
        if self.live == 0 {
            1.0
        } else {
            self.kept as f64 / self.live as f64
        }
    }
}

/// What a filter keeps of each source: `None` for no filter, which keeps
/// every live file.
struct Keeps(Option<Vec<Kept>>);

impl Keeps {
    fn of(sources: &[Source<'_>], filter: Option<&Filter>) -> Self {
        Self(
            filter
                .filter(|f| !f.is_empty())
                .map(|f| sources.iter().map(|s| Kept::of(s, f)).collect()),
        )
    }

    fn keeps(&self, i: usize, at: At) -> bool {
        self.0.as_ref().is_none_or(|k| k[i].keeps(at))
    }

    fn is_on(&self) -> bool {
        self.0.is_some()
    }

    fn get(&self, i: usize) -> Option<&Kept> {
        self.0.as_ref().map(|k| &k[i])
    }
}

/// The keyword shards and clusters a search of `sources` needs: probing
/// `PROBE_VECTORS` vectors or `PROBE_SHARE` of them, whichever is more.
///
/// With a filter, each source probes more in proportion to the share of
/// its files the filter drops, so that about as many kept files are
/// scored. A query with no words or vectors needs nothing: it lists what
/// the filter keeps.
pub fn needs(
    sources: &[Source<'_>],
    query: &str,
    vector: Option<&QueryVector<'_>>,
    image: Option<&QueryVector<'_>>,
    filter: Option<&Filter>,
) -> Vec<(usize, PieceId)> {
    let total: usize = sources
        .iter()
        .filter_map(|s| s.generation)
        .map(|g| g.text_sizes.iter().sum::<usize>())
        .max()
        .unwrap_or(0);
    let vectors = PROBE_VECTORS.max((total as f64 * PROBE_SHARE).ceil() as usize);
    let keeps = Keeps::of(sources, filter);
    if keeps.is_on() && query_terms(query).is_empty() && vector.is_none() && image.is_none() {
        return Vec::new();
    }
    let scale: Vec<f64> = (0..sources.len())
        .map(|i| keeps.get(i).map_or(1.0, |k| 1.0 / k.share().max(1e-6)))
        .collect();
    needs_scaled(
        sources,
        query,
        vector,
        image,
        vectors,
        PROBE_CLUSTERS,
        &scale,
    )
}

/// `needs`, probing clusters until they hold `vectors` vectors, in at
/// least `clusters` clusters.
pub fn needs_with(
    sources: &[Source<'_>],
    query: &str,
    vector: Option<&QueryVector<'_>>,
    image: Option<&QueryVector<'_>>,
    vectors: usize,
    clusters: usize,
) -> Vec<(usize, PieceId)> {
    let scale = vec![1.0; sources.len()];
    needs_scaled(sources, query, vector, image, vectors, clusters, &scale)
}

/// `needs_with`, with source `i` probing `scale[i]` times as many vectors.
fn needs_scaled(
    sources: &[Source<'_>],
    query: &str,
    vector: Option<&QueryVector<'_>>,
    image: Option<&QueryVector<'_>>,
    vectors: usize,
    clusters: usize,
    scale: &[f64],
) -> Vec<(usize, PieceId)> {
    let terms = query_terms(query);
    let mut out = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        let vectors = (vectors as f64 * scale[i]).min(usize::MAX as f64 / 2.0) as usize;
        let Some(g) = s.generation else { continue };
        let mut shards: Vec<u32> = terms
            .iter()
            .filter(|t| !g.dropped.contains(*t))
            .map(|t| g.header.shard_of(t))
            .collect();
        shards.sort_unstable();
        shards.dedup();
        out.extend(
            shards
                .into_iter()
                .map(|n| (i, PieceId::new(Kind::Shard, n))),
        );
        let probe = |q: Option<&QueryVector<'_>>,
                     model: &str,
                     c: &Option<Centres>,
                     sizes: &[usize],
                     mean: &[f32],
                     kind| {
            let (Some(q), Some(c)) = (q, c) else {
                return Vec::new();
            };
            if q.model != model || q.values.len() != c.dims {
                return Vec::new();
            }
            let q = crate::generation::centred(q.values, mean);
            cluster::probe(c, &q, sizes, vectors, clusters)
                .into_iter()
                .map(|n| (i, PieceId::new(kind, n as u32)))
                .collect()
        };
        out.extend(probe(
            vector,
            &g.header.text_model,
            &g.text,
            &g.text_sizes,
            &g.text_mean,
            Kind::TextCluster,
        ));
        out.extend(probe(
            image,
            &g.header.clip_model,
            &g.photo,
            &g.photo_sizes,
            &[],
            Kind::PhotoCluster,
        ));
    }
    out
}

/// A file a search found, before its preview is known.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub index: usize,
    pub at: At,
    pub score: f32,
    /// Whether it matched by keyword, so the preview shows the query's
    /// words.
    keyword: bool,
    /// The chunk that matched by meaning, if one did.
    chunk: Option<usize>,
}

type Key = (usize, At);

/// The scores of a generation's sampled live files (each its best chunk),
/// each standing for `weight` files.
fn sampled(
    s: &Source<'_>,
    sample: &[ClusterEntry],
    weight: f32,
    q: &QueryVector<'_>,
) -> Vec<(f32, f32)> {
    let mut best: HashMap<u32, f32> = HashMap::new();
    for e in sample.iter().filter(|e| !s.is_dead(e.file)) {
        let sc = crate::vector::dot(&e.vector, q.values);
        let slot = best.entry(e.file).or_insert(f32::MIN);
        *slot = slot.max(sc);
    }
    best.into_values().map(|sc| (sc, weight)).collect()
}

fn decoded_cluster(pieces: &Pieces, i: usize, id: PieceId) -> Vec<ClusterEntry> {
    pieces
        .get(&(i, id))
        .and_then(|b| decode_cluster(id.kind, b).ok())
        .unwrap_or_default()
}

/// Searches `sources` as one, best first, with the pieces `needs` named.
/// Missing pieces count as empty.
///
/// - **Paths:** query words in folder and file names (`paths`).
/// - **Keywords:** BM25 over files, with statistics from every source
///   together, so scores compare across them. A match needs
///   `min_coverage` of the query's weight and `keyword_margin` of the best
///   score. It grades its score over an ideal match's, times its coverage
///   to the power `coverage_power`.
/// - **Meaning and photos:** chosen from every source's scores together
///   (`Cutoff`), so a source with nothing relevant gives none. A match
///   grades by how far it stands above chance over every source's files
///   (`Spread`), so the best of unrelated files grades about 0.
/// - The lists are merged by score (`rank::merge`), once, over all.
/// - **A filter** drops files before any list is cut, so a strong match
///   that the filter drops never cuts one it keeps. Keyword statistics
///   and the spreads still count every file: a match must stand out from
///   the whole volume, not from the files the filter chose, which may all
///   be about the query. With no
///   words or vectors, the result is every file the filter keeps, newest
///   first.
#[allow(clippy::too_many_arguments)]
pub fn search(
    sources: &[Source<'_>],
    query: &str,
    vector: Option<&QueryVector<'_>>,
    image: Option<&QueryVector<'_>>,
    limit: usize,
    pieces: &Pieces,
    ranking: &Ranking,
    filter: Option<&Filter>,
) -> Vec<Found> {
    // Each list looks deeper than the result, so a file a little way down
    // several still rises.
    let depth = limit.saturating_mul(3).max(10);
    let terms = query_terms(query);
    let keeps = Keeps::of(sources, filter);
    if keeps.is_on() && terms.is_empty() && vector.is_none() && image.is_none() {
        return listed(sources, &keeps, filter.and_then(|f| f.sort), limit);
    }
    let sort = filter.and_then(|f| f.sort);

    // Paths, with word weights from every source together.
    // (source, matches, where a doc number points)
    type FromPaths = (usize, PathMatches, fn(usize) -> At);
    let mut path_matches: Vec<FromPaths> = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        let v = s.recent;
        let k = &keeps;
        let m = v.paths.matching(&terms, |doc| {
            v.docs[doc].is_some() && k.keeps(i, At::Recent(doc))
        });
        path_matches.push((i, m, At::Recent));
        if let Some(g) = s.generation {
            let m = g.paths.matching(&terms, |f| {
                !s.is_dead(f as u32)
                    && s.moved_path(f as u32).is_none()
                    && k.keeps(i, At::Generation(f as u32))
            });
            path_matches.push((i, m, |f| At::Generation(f as u32)));
            if let Some((_, moved)) = s.moved {
                let m = moved.matching(&terms, |f| {
                    !s.is_dead(f as u32) && k.keeps(i, At::Generation(f as u32))
                });
                path_matches.push((i, m, |f| At::Generation(f as u32)));
            }
        }
    }
    let mut df = vec![0usize; terms.len()];
    let mut docs = 0;
    for (_, m, _) in &path_matches {
        docs += m.docs;
        for (d, n) in df.iter_mut().zip(&m.df) {
            *d += n;
        }
    }
    let weights = word_weights(&df, docs);
    let mut paths: Vec<(Key, f32)> = Vec::new();
    for (i, m, at) in path_matches {
        paths.extend(
            m.ranked(&weights, depth)
                .into_iter()
                .map(|(doc, sc)| ((i, at(doc)), sc)),
        );
    }
    paths.retain(|p| p.1 >= ranking.min_coverage * 0.5);
    paths.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    paths.truncate(depth);

    // Keywords: statistics over everything first.
    let mut stats = Stats::default();
    let mut shards: Vec<Vec<(usize, crate::generation::ShardWord)>> =
        vec![Vec::new(); sources.len()];
    let dropped: HashSet<&str> = sources
        .iter()
        .filter_map(|s| s.generation)
        .flat_map(|g| g.dropped.iter().map(String::as_str))
        .collect();
    let terms: Vec<String> = terms
        .into_iter()
        .filter(|t| !dropped.contains(t.as_str()))
        .collect();
    for (i, s) in sources.iter().enumerate() {
        s.recent.keywords.add_stats(&terms, &mut stats);
        let Some(g) = s.generation else { continue };
        stats.docs += s.gen_live().count() as u64;
        stats.total_len += g.header.total_len.saturating_sub(s.dead_words);
        let mut ids: Vec<u32> = terms.iter().map(|t| g.header.shard_of(t)).collect();
        ids.sort_unstable();
        ids.dedup();
        for n in ids {
            let Some(bytes) = pieces.get(&(i, PieceId::new(Kind::Shard, n))) else {
                continue;
            };
            for w in decode_shard(bytes).unwrap_or_default() {
                if terms.contains(&w.word) {
                    let live = w.postings.iter().filter(|p| !s.is_dead(p.0)).count();
                    *stats.df.entry(w.word.clone()).or_default() += live as u64;
                    shards[i].push((n as usize, w));
                }
            }
        }
    }
    let mut keyword: Vec<(Key, f32, f32)> = Vec::new();
    let weights = stats.weights(&terms);
    // An ideal match's score: every query word once, in a file of average
    // length, scores its word's weight.
    let total: f32 = weights.iter().map(|w| w.1).sum();
    if stats.docs > 0 && total > 0.0 {
        let avg = stats.total_len as f32 / stats.docs as f32;
        for (i, s) in sources.iter().enumerate() {
            let v = s.recent;
            let k = &keeps;
            let found = v.keywords.search_with(&terms, &stats, depth, |doc| {
                v.docs[doc].is_some() && k.keeps(i, At::Recent(doc))
            });
            keyword.extend(
                found
                    .into_iter()
                    .map(|m| ((i, At::Recent(m.doc)), m.score, m.coverage)),
            );
            let Some(g) = s.generation else { continue };
            let mut scores: HashMap<u32, (f32, f32)> = HashMap::new();
            for (_, w) in &shards[i] {
                let Some(&(_, idf)) = weights.iter().find(|(t, _)| *t == w.word) else {
                    continue;
                };
                for &(f, tf) in &w.postings {
                    if s.is_dead(f) || !keeps.keeps(i, At::Generation(f)) {
                        continue;
                    }
                    let len = g.rows.get(f as usize).map_or(1, |r| r.words.max(1)) as f32;
                    let e = scores.entry(f).or_default();
                    e.0 += term_score(idf, f32::from(tf), len, avg);
                    e.1 += idf;
                }
            }
            keyword.extend(
                scores
                    .into_iter()
                    .map(|(f, (sc, w))| ((i, At::Generation(f)), sc, w / total)),
            );
        }
    }
    keyword.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    let best_keyword = keyword.first().map_or(0.0, |k| k.1);
    keyword.retain(|k| k.2 >= ranking.min_coverage && k.1 >= best_keyword * ranking.keyword_margin);
    keyword.truncate(depth);

    // Meaning: the recent chunks, and the probed clusters' vectors.
    let mut meaning: Vec<(Key, usize, f32)> = Vec::new();
    let mut meaning_spread = None;
    let mut population: Vec<(f32, f32)> = Vec::new();
    if let Some(q) = vector {
        for (i, s) in sources.iter().enumerate() {
            for (d, c, sc) in s.recent.meaning_scores(q) {
                population.push((sc, 1.0));
                if keeps.keeps(i, At::Recent(d)) {
                    meaning.push(((i, At::Recent(d)), c, sc));
                }
            }
            let Some(g) = s.generation else { continue };
            if g.header.text_model != q.model {
                continue;
            }
            let mut best: HashMap<u32, (usize, f32)> = HashMap::new();
            for n in 0..g.text_sizes.len() as u32 {
                for e in decoded_cluster(pieces, i, PieceId::new(Kind::TextCluster, n)) {
                    if s.is_dead(e.file) || !keeps.keeps(i, At::Generation(e.file)) {
                        continue;
                    }
                    let sc = crate::vector::dot(&e.vector, q.values);
                    let slot = best.entry(e.file).or_insert((0, f32::MIN));
                    if sc > slot.1 {
                        *slot = (e.chunk as usize, sc);
                    }
                }
            }
            population.extend(sampled(s, &g.text_sample, g.text_weight, q));
            meaning.extend(
                best.into_iter()
                    .map(|(f, (c, sc))| ((i, At::Generation(f)), c, sc)),
            );
        }
        let best = meaning.iter().map(|m| m.2).fold(f32::MIN, f32::max);
        meaning_spread = Spread::of(&population);
        let meaning_cut = Cutoff {
            floor: MIN_SIMILARITY,
            margin: MEANING_MARGIN,
            z: MEANING_Z,
        }
        .threshold_with(best, &population);
        meaning.retain(|m| m.2 >= meaning_cut);
        meaning.sort_by(|a, b| b.2.total_cmp(&a.2).then(a.0.cmp(&b.0)));
        meaning.truncate(depth);
    }

    // Photos, by what they show.
    let mut shown: Vec<(Key, f32)> = Vec::new();
    let mut shown_spread = None;
    let mut photo_population: Vec<(f32, f32)> = Vec::new();
    if let Some(q) = image {
        for (i, s) in sources.iter().enumerate() {
            for (d, sc) in s.recent.image_scores(q) {
                photo_population.push((sc, 1.0));
                if keeps.keeps(i, At::Recent(d)) {
                    shown.push(((i, At::Recent(d)), sc));
                }
            }
            let Some(g) = s.generation else { continue };
            if g.header.clip_model != q.model {
                continue;
            }
            for n in 0..g.photo_sizes.len() as u32 {
                for e in decoded_cluster(pieces, i, PieceId::new(Kind::PhotoCluster, n)) {
                    if !s.is_dead(e.file) && keeps.keeps(i, At::Generation(e.file)) {
                        shown.push((
                            (i, At::Generation(e.file)),
                            crate::vector::dot(&e.vector, q.values),
                        ));
                    }
                }
            }
            photo_population.extend(sampled(s, &g.photo_sample, g.photo_weight, q));
        }
        let best = shown.iter().map(|m| m.1).fold(f32::MIN, f32::max);
        shown_spread = Spread::of(&photo_population);
        let shown_cut = Cutoff {
            floor: MIN_IMAGE_SIMILARITY,
            margin: IMAGE_MARGIN,
            z: IMAGE_Z,
        }
        .threshold_with(best, &photo_population);
        shown.retain(|m| m.1 >= shown_cut);
        shown.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        shown.truncate(depth);
    }

    let lists = [
        (ranking.weight_path, paths),
        (
            ranking.weight_keyword,
            keyword
                .iter()
                .map(|k| {
                    let ideal = (k.1 / total.max(f32::MIN_POSITIVE)).min(1.0);
                    (k.0, ideal * k.2.powf(ranking.coverage_power))
                })
                .collect(),
        ),
        (
            ranking.weight_meaning,
            meaning
                .iter()
                .map(|m| {
                    let g =
                        Spread::grade(meaning_spread.as_ref(), m.2, ranking.z_low, ranking.z_span);
                    (m.0, g)
                })
                .collect(),
        ),
        (
            ranking.weight_photo,
            shown
                .iter()
                .map(|s| {
                    let g =
                        Spread::grade(shown_spread.as_ref(), s.1, ranking.z_low, ranking.z_span);
                    (s.0, g)
                })
                .collect(),
        ),
    ];
    let by_keyword: HashSet<Key> = keyword.iter().map(|k| k.0).collect();
    let by_meaning: HashMap<Key, usize> = meaning.iter().map(|m| (m.0, m.1)).collect();
    let mut found: Vec<Found> = merge(&lists, ranking.bonus, ranking.keep)
        .into_iter()
        .take(limit)
        .map(|((index, at), score)| Found {
            index,
            at,
            score,
            keyword: by_keyword.contains(&(index, at)),
            chunk: by_meaning.get(&(index, at)).copied(),
        })
        .collect();
    if let Some(sort) = sort {
        sort_by_date(sources, &mut found, sort);
    }
    found
}

/// When a found file was taken (or made), for sorting by date.
fn date_of(sources: &[Source<'_>], f: &Found) -> u64 {
    let s = &sources[f.index];
    match f.at {
        At::Recent(d) => s.recent.docs[d]
            .as_ref()
            .map_or(0, |r| Facts::of_record(r).taken_ms()),
        At::Generation(n) => s
            .generation
            .and_then(|g| g.rows.get(n as usize))
            .map_or(0, |r| Facts::of_row(r).taken_ms()),
    }
}

fn sort_by_date(sources: &[Source<'_>], found: &mut [Found], sort: Sort) {
    found.sort_by_cached_key(|f| {
        let d = date_of(sources, f);
        match sort {
            Sort::Newest => u64::MAX - d,
            Sort::Oldest => d,
        }
    });
}

/// Every file `keeps` keeps, by date (newest first unless `sort` says),
/// at most `limit`: a search by filter alone.
fn listed(sources: &[Source<'_>], keeps: &Keeps, sort: Option<Sort>, limit: usize) -> Vec<Found> {
    let mut found = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        for (f, _) in s.gen_live() {
            if keeps.keeps(i, At::Generation(f)) {
                found.push(Found::listed(i, At::Generation(f)));
            }
        }
        for (d, r) in s.recent.docs.iter().enumerate() {
            if r.is_some() && keeps.keeps(i, At::Recent(d)) {
                found.push(Found::listed(i, At::Recent(d)));
            }
        }
    }
    sort_by_date(sources, &mut found, sort.unwrap_or(Sort::Newest));
    found.truncate(limit);
    found
}

impl Found {
    fn listed(index: usize, at: At) -> Self {
        Self {
            index,
            at,
            score: 1.0,
            keyword: false,
            chunk: None,
        }
    }
}

/// The previews pieces that the generation's files in `found` are in.
pub fn preview_needs(found: &[Found]) -> Vec<(usize, PieceId)> {
    let mut out: Vec<(usize, PieceId)> = found
        .iter()
        .filter_map(|f| match f.at {
            At::Generation(n) => Some((f.index, PieceId::new(Kind::Previews, n / FILES_PER_PIECE))),
            At::Recent(_) => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The results for `found`, with their previews from `pieces`.
pub fn hits(
    sources: &[Source<'_>],
    query: &str,
    found: &[Found],
    pieces: &Pieces,
) -> Vec<(usize, Hit)> {
    let terms = query_terms(query);
    let mut previews: HashMap<(usize, u32), Vec<FilePreviews>> = HashMap::new();
    found
        .iter()
        .filter_map(|f| {
            let s = &sources[f.index];
            let hit = match f.at {
                At::Recent(doc) => {
                    let v = s.recent;
                    let r = v.docs[doc].as_ref()?;
                    let weights: Vec<(u16, f32)> = terms
                        .iter()
                        .map(|t| (crate::view::word_code(t), 1.0))
                        .collect();
                    let chunk = f
                        .keyword
                        .then(|| chunk_with(&v.codes[doc], &weights))
                        .flatten()
                        .or(f.chunk)
                        .or(if r.chunks.is_empty() { None } else { Some(0) });
                    Hit {
                        ino: r.ino,
                        path: r.path.clone(),
                        kind: r.kind,
                        preview: chunk
                            .map(|c| r.chunks[c].preview.clone())
                            .unwrap_or_default(),
                        score: f.score,
                        thumb: r.extra.thumb.clone(),
                    }
                }
                At::Generation(n) => {
                    let g = s.generation?;
                    let r = g.rows.get(n as usize)?;
                    let piece = n / FILES_PER_PIECE;
                    let list = previews.entry((f.index, piece)).or_insert_with(|| {
                        pieces
                            .get(&(f.index, PieceId::new(Kind::Previews, piece)))
                            .and_then(|b| decode_previews(b).ok())
                            .unwrap_or_default()
                    });
                    let file = list.get((n % FILES_PER_PIECE) as usize);
                    let codes: Vec<Box<[u16]>> = file
                        .map(|p| {
                            p.chunks
                                .iter()
                                .map(|c| c.1.clone().into_boxed_slice())
                                .collect()
                        })
                        .unwrap_or_default();
                    let weights: Vec<(u16, f32)> =
                        terms.iter().map(|t| (g.header.code_of(t), 1.0)).collect();
                    let chunk = f
                        .keyword
                        .then(|| chunk_with(&codes, &weights))
                        .flatten()
                        .or(f.chunk)
                        .or(if r.chunks == 0 { None } else { Some(0) });
                    let preview = chunk
                        .and_then(|c| file?.chunks.get(c))
                        .map(|c| c.0.clone())
                        .unwrap_or_default();
                    Hit {
                        ino: r.ino,
                        path: s.moved_path(n).unwrap_or(&r.path).to_string(),
                        kind: r.kind,
                        preview,
                        score: f.score,
                        thumb: r.thumb.clone(),
                    }
                }
            };
            Some((f.index, hit))
        })
        .collect()
}

/// Every step at once, for sources with every piece at hand (`piece`):
/// what native clients and tests use.
#[allow(clippy::too_many_arguments)]
pub fn search_all(
    sources: &[Source<'_>],
    query: &str,
    vector: Option<&QueryVector<'_>>,
    image: Option<&QueryVector<'_>>,
    limit: usize,
    ranking: &Ranking,
    filter: Option<&Filter>,
    piece: impl Fn(usize, PieceId) -> Option<Vec<u8>>,
) -> Vec<(usize, Hit)> {
    let mut pieces = Pieces::new();
    for (i, id) in needs(sources, query, vector, image, filter) {
        if let Some(b) = piece(i, id) {
            pieces.insert((i, id), b);
        }
    }
    let found = search(
        sources, query, vector, image, limit, &pieces, ranking, filter,
    );
    for (i, id) in preview_needs(&found) {
        if let Some(b) = piece(i, id) {
            pieces.insert((i, id), b);
        }
    }
    hits(sources, query, &found, &pieces)
}

/// Chunks of fewer words than this are not embedded.
pub const MIN_WORDS: u32 = MIN_MEANING_WORDS;
