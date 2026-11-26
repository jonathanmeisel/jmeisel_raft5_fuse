//! Building a generation: what compaction computes. No I/O: the caller
//! reads the old generation and the recent segments, and writes what this
//! gives back.
//!
//! - **Count** (`Counts`): every live file once, for each word the files
//!   that have it, and a sample of the vectors.
//! - **Plan** (`Counts::plan`): which words to drop as common (once
//!   dropped, a word stays dropped: older files' postings are gone), how
//!   many keyword shards, and the clusters' centres, trained on the
//!   sample. Retrained every time, so they follow the data.
//! - **Text centres are trained around the vectors' mean**, taken from
//!   each vector first: the model's vectors all point much the same way,
//!   and clusters of what is left are far better separated (raft5fs-eval's
//!   recall: 0.82 against 0.73 of the first 10 results at the fewest
//!   clusters probed). Scores don't change: the mean is taken only to
//!   choose clusters.
//! - **Photos have one cluster**, always, so photo search compares every
//!   photo: text queries find photos poorly through image centres (0.69
//!   of results even at a tenth of the photos probed), and a photo vector
//!   is small.
//! - **Write** (`Writer`): files are numbered in the order given, the old
//!   generation's first. Records and previews go into pieces as they come;
//!   postings and vectors go into `Buckets` (one per shard and per
//!   cluster), which a native client keeps on disk, so memory stays small.
//!   `finish` sorts each bucket into its piece.
//! - **Kept words:** each chunk keeps its `keep_words` most telling words
//!   (count times rarity). A file's posting for a kept word counts all its
//!   uses. Short chunks (a photo's date and place) keep all their words.

use std::collections::{BTreeMap, HashMap, HashSet};

use raft5fs_wire::{self as wire, Reader};

use crate::cluster::{self, Centres};
use crate::generation::{
    self, ClusterEntry, FILES_PER_PIECE, FilePreviews, GenId, Header, Kind, Packer, PieceId, Row,
    ServerFiles, ShardWord, code_of, encode_centres, encode_cluster, encode_previews, encode_rows,
    encode_shard, shard_of,
};
use crate::record::{Record, Vector};

/// About how big a keyword shard is, compressed.
pub const SHARD_BYTES: u64 = 512 << 10;
/// About how many files' vectors the samples hold.
pub const SAMPLE_FILES: u64 = 512;

/// What a generation is built with.
#[derive(Debug, Clone)]
pub struct Config {
    pub id: GenId,
    pub key: [u8; 32],
    pub now_ms: u64,
    pub text_model: String,
    pub clip_model: String,
    /// The fewest words a chunk needs to be embedded.
    pub min_words: u32,
    /// Words each chunk keeps.
    pub keep_words: usize,
    /// Fewer vectors than this get one cluster: a full scan.
    pub flat: usize,
    /// Vectors k-means trains on, at most.
    pub sample: usize,
    pub seed: u64,
    /// Words in more than this share of the files are dropped...
    pub common_share: f64,
    /// ... once there are this many files.
    pub common_min_files: u64,
    /// At least this many keyword shards (a power of two), as tests ask;
    /// 1 lets the size decide.
    pub min_shards: u32,
}

impl Config {
    /// The usual settings, for generation `id` with key `key`.
    pub fn new(id: GenId, key: [u8; 32], now_ms: u64) -> Self {
        Self {
            id,
            key,
            now_ms,
            text_model: crate::vector::TEXT_MODEL.to_string(),
            clip_model: crate::vector::CLIP_MODEL.to_string(),
            min_words: crate::view::MIN_MEANING_WORDS,
            keep_words: 50,
            flat: 50_000,
            sample: 100_000,
            seed: 1,
            common_share: crate::bm25::COMMON_SHARE,
            common_min_files: crate::bm25::COMMON_MIN_FILES,
            min_shards: 1,
        }
    }
}

/// A generation of `records` alone, built in memory: its header and every
/// server file.
pub fn build(records: &[Record], config: Config) -> std::io::Result<(Header, ServerFiles)> {
    let mut counts = Counts::new(config, &[]);
    for r in records {
        counts.record(r);
    }
    let mut w = Writer::new(counts.plan(), MemoryBuckets::default());
    let mut files = Vec::new();
    for r in records {
        w.record(r)?;
        files.extend(w.take_files());
    }
    let (header, rest) = w.finish()?;
    files.extend(rest);
    Ok((header, files))
}

/// Where postings and vectors wait to be sorted into pieces.
pub trait Buckets {
    fn append(&mut self, bucket: u32, bytes: &[u8]) -> std::io::Result<()>;
    /// What bucket `bucket` holds, which it then forgets.
    fn take(&mut self, bucket: u32) -> std::io::Result<Vec<u8>>;
}

/// Buckets in memory, for small generations and tests.
#[derive(Debug, Default)]
pub struct MemoryBuckets(HashMap<u32, Vec<u8>>);

impl Buckets for MemoryBuckets {
    fn append(&mut self, bucket: u32, bytes: &[u8]) -> std::io::Result<()> {
        self.0.entry(bucket).or_default().extend_from_slice(bytes);
        Ok(())
    }

    fn take(&mut self, bucket: u32) -> std::io::Result<Vec<u8>> {
        Ok(self.0.remove(&bucket).unwrap_or_default())
    }
}

/// A fixed random sequence (SplitMix64), so a plan is the same each time.
struct Seq(u64);

impl Seq {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

/// A uniform sample of at most `size` vectors (reservoir sampling).
struct Sample {
    size: usize,
    seen: u64,
    dims: usize,
    values: Vec<f32>,
    seq: Seq,
}

impl Sample {
    /// The mean of the vectors held.
    fn mean(&self) -> Vec<f32> {
        let mut mean = vec![0f32; self.dims];
        let n = self.values.len() / self.dims.max(1);
        for row in self.values.chunks(self.dims.max(1)) {
            mean.iter_mut().zip(row).for_each(|(m, x)| *m += x);
        }
        mean.iter_mut().for_each(|m| *m /= n.max(1) as f32);
        mean
    }

    fn new(size: usize, seed: u64) -> Self {
        Self {
            size,
            seen: 0,
            dims: 0,
            values: Vec::new(),
            seq: Seq(seed),
        }
    }

    fn add(&mut self, v: &Vector) {
        if v.values.is_empty() || (self.dims != 0 && v.values.len() != self.dims) {
            return;
        }
        self.dims = v.values.len();
        self.seen += 1;
        let row: Vec<f32> = v.values.iter().map(|&x| f32::from(x) * v.scale).collect();
        let held = self.values.len() / self.dims;
        if held < self.size {
            self.values.extend(row);
        } else {
            let at = self.seq.next() % self.seen;
            if (at as usize) < self.size {
                let i = at as usize * self.dims;
                self.values[i..i + self.dims].copy_from_slice(&row);
            }
        }
    }
}

/// Step one: counting.
pub struct Counts {
    config: Config,
    df: HashMap<String, u32>,
    files: u64,
    postings: u64,
    dropped: HashSet<String>,
    text: Sample,
    photo: Sample,
}

impl Counts {
    /// Counting starts with the words the old generation dropped.
    pub fn new(config: Config, old_dropped: &[String]) -> Self {
        let text = Sample::new(config.sample, config.seed);
        let photo = Sample::new(config.sample, config.seed ^ 1);
        Self {
            config,
            df: HashMap::new(),
            files: 0,
            postings: 0,
            dropped: old_dropped.iter().cloned().collect(),
            text,
            photo,
        }
    }

    /// Adds `n` live files of the old generation.
    pub fn old_files(&mut self, n: u64) {
        self.files += n;
    }

    /// Adds an old shard's postings of live files.
    pub fn old_shard(&mut self, words: &[ShardWord], live: impl Fn(u32) -> bool) {
        for w in words {
            let n = w.postings.iter().filter(|p| live(p.0)).count() as u32;
            if n > 0 {
                *self.df.entry(w.word.clone()).or_default() += n;
                self.postings += u64::from(n);
            }
        }
    }

    /// Adds an old cluster's vectors of live files, if of this plan's model.
    pub fn old_cluster(
        &mut self,
        kind: Kind,
        model: &str,
        entries: &[ClusterEntry],
        live: impl Fn(u32) -> bool,
    ) {
        let (sample, want) = match kind {
            Kind::PhotoCluster => (&mut self.photo, &self.config.clip_model),
            _ => (&mut self.text, &self.config.text_model),
        };
        if model != want {
            return;
        }
        for e in entries.iter().filter(|e| live(e.file)) {
            sample.add(&e.vector);
        }
    }

    /// Adds a recent record, which will be a new file.
    pub fn record(&mut self, r: &Record) {
        self.files += 1;
        let mut words: HashSet<&str> = HashSet::new();
        for c in &r.chunks {
            words.extend(c.terms.iter().map(|(t, _)| t.as_str()));
            if r.model == self.config.text_model
                && c.len >= self.config.min_words
                && let Some(v) = &c.vector
            {
                self.text.add(v);
            }
        }
        self.postings += words.len() as u64;
        for w in words {
            *self.df.entry(w.to_string()).or_default() += 1;
        }
        if let Some((m, v)) = &r.extra.image
            && *m == self.config.clip_model
        {
            self.photo.add(v);
        }
    }

    /// Step two: the plan.
    pub fn plan(mut self) -> Plan {
        let c = &self.config;
        if self.files >= c.common_min_files {
            let limit = self.files as f64 * c.common_share;
            for (w, &n) in &self.df {
                if f64::from(n) > limit {
                    self.dropped.insert(w.clone());
                }
            }
        }
        // About 2 bytes a posting, compressed, and the words themselves.
        let bytes = self.postings * 2 + self.df.len() as u64 * 8;
        let shards = (bytes.div_ceil(SHARD_BYTES).max(1).next_power_of_two() as u32)
            .max(c.min_shards.next_power_of_two());
        let train = |s: &Sample, k: usize, mean: &[f32]| -> Centres {
            if s.seen == 0 {
                return Centres {
                    dims: 0,
                    values: Vec::new(),
                };
            }
            if k == 1 {
                // One cluster: its centre only needs to exist.
                let mut mean = vec![0f32; s.dims];
                for row in s.values.chunks(s.dims) {
                    mean.iter_mut().zip(row).for_each(|(m, x)| *m += x);
                }
                let n = cluster::dot(&mean, &mean).sqrt().max(f32::MIN_POSITIVE);
                mean.iter_mut().for_each(|m| *m /= n);
                return Centres {
                    dims: s.dims,
                    values: mean,
                };
            }
            let centred: Vec<f32> = s
                .values
                .chunks(s.dims)
                .flat_map(|row| generation::centred(row, mean))
                .collect();
            cluster::train(&centred, s.dims, k, 10, c.seed)
        };
        let text_k = cluster::count_for(self.text.seen as usize, c.flat);
        let text_mean = if text_k > 1 {
            self.text.mean()
        } else {
            Vec::new()
        };
        let text = train(&self.text, text_k, &text_mean);
        let photo = train(&self.photo, 1, &[]);
        let mut dropped: Vec<String> = self.dropped.into_iter().collect();
        dropped.sort();
        Plan {
            config: self.config,
            dropped,
            df: self.df,
            files: self.files,
            shards,
            text,
            text_mean,
            photo,
        }
    }
}

/// Step two's result: what the writer follows.
pub struct Plan {
    pub config: Config,
    pub dropped: Vec<String>,
    df: HashMap<String, u32>,
    files: u64,
    pub shards: u32,
    pub text: Centres,
    /// The mean text centres were trained around (empty for one cluster).
    pub text_mean: Vec<f32>,
    pub photo: Centres,
}

impl Plan {
    /// The words of `chunk` (counted terms) that it keeps.
    fn kept<'a>(
        &self,
        terms: &'a [(String, u16)],
        dropped: &HashSet<&str>,
    ) -> Vec<&'a (String, u16)> {
        let n = self.files.max(1) as f32;
        let mut scored: Vec<(&(String, u16), f32)> = terms
            .iter()
            .filter(|(t, _)| !dropped.contains(t.as_str()))
            .map(|t| {
                let df = self.df.get(&t.0).copied().unwrap_or(1).max(1) as f32;
                (t, f32::from(t.1) * (1.0 + n / df).ln())
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.0.cmp(&b.0.0)));
        scored.truncate(self.config.keep_words);
        scored.into_iter().map(|(t, _)| t).collect()
    }
}

/// Step three: writing.
pub struct Writer<B: Buckets> {
    plan: Plan,
    dropped: HashSet<String>,
    buckets: B,
    packer: Packer,
    rows: Vec<Row>,
    previews: Vec<FilePreviews>,
    next_file: u32,
    next_piece: u32,
    chunks: u64,
    total_len: u64,
    text_sizes: Vec<u32>,
    photo_sizes: Vec<u32>,
    /// Every `stride`-th file is in the samples.
    stride: u32,
    ready: Vec<(u32, Vec<u8>)>,
}

impl<B: Buckets> Writer<B> {
    pub fn new(plan: Plan, buckets: B) -> Self {
        let mut packer = Packer::default();
        let mut ready = Vec::new();
        for (kind, c, mean) in [
            (Kind::TextCentres, &plan.text, &plan.text_mean[..]),
            (Kind::PhotoCentres, &plan.photo, &[][..]),
        ] {
            if !c.is_empty() {
                ready.extend(packer.add(
                    PieceId::new(kind, 0),
                    c.len() as u32,
                    &encode_centres(kind, c, mean),
                ));
            }
        }
        Self {
            dropped: plan.dropped.iter().cloned().collect(),
            text_sizes: vec![0; plan.text.len()],
            photo_sizes: vec![0; plan.photo.len()],
            stride: (plan.files / SAMPLE_FILES).max(1) as u32,
            plan,
            buckets,
            packer,
            rows: Vec::new(),
            previews: Vec::new(),
            next_file: 0,
            next_piece: 0,
            chunks: 0,
            total_len: 0,
            ready,
        }
    }

    /// Full server files, to write now: (number, bytes).
    pub fn take_files(&mut self) -> Vec<(u32, Vec<u8>)> {
        std::mem::take(&mut self.ready)
    }

    fn key(&self) -> &[u8; 32] {
        &self.plan.config.key
    }

    fn push_file(&mut self, row: Row, previews: FilePreviews) -> u32 {
        let n = self.next_file;
        self.next_file += 1;
        self.chunks += u64::from(row.chunks);
        self.total_len += u64::from(row.words);
        self.rows.push(row);
        self.previews.push(previews);
        if self.rows.len() as u32 == FILES_PER_PIECE {
            self.flush_rows();
        }
        n
    }

    fn flush_rows(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let rows = std::mem::take(&mut self.rows);
        let previews = std::mem::take(&mut self.previews);
        let n = self.next_piece;
        self.next_piece += 1;
        let count = rows.len() as u32;
        self.ready.extend(self.packer.add(
            PieceId::new(Kind::Records, n),
            count,
            &encode_rows(&rows),
        ));
        self.ready.extend(self.packer.add(
            PieceId::new(Kind::Previews, n),
            count,
            &encode_previews(&previews),
        ));
    }

    fn shard_bucket(&self, word: &str) -> u32 {
        shard_of(self.key(), self.plan.shards, word)
    }

    fn cluster_bucket(&self, kind: Kind, cluster: usize) -> u32 {
        let base = self.plan.shards
            + if kind == Kind::PhotoCluster {
                self.plan.text.len() as u32
            } else {
                0
            };
        base + cluster as u32
    }

    fn sample_bucket(&self, kind: Kind) -> u32 {
        self.plan.shards
            + (self.plan.text.len() + self.plan.photo.len()) as u32
            + u32::from(kind == Kind::PhotoCluster)
    }

    fn posting(&mut self, word: &str, file: u32, count: u16) -> std::io::Result<()> {
        let mut b = Vec::new();
        wire::put_short_bytes(&mut b, word.as_bytes());
        wire::put_varint(&mut b, file.into());
        wire::put_varint(&mut b, count.into());
        let bucket = self.shard_bucket(word);
        self.buckets.append(bucket, &b)
    }

    fn vector(&mut self, kind: Kind, file: u32, chunk: u32, v: &Vector) -> std::io::Result<()> {
        let centres = if kind == Kind::PhotoCluster {
            &self.plan.photo
        } else {
            &self.plan.text
        };
        if centres.is_empty() || v.values.len() != centres.dims {
            return Ok(());
        }
        let row: Vec<f32> = v.values.iter().map(|&x| f32::from(x) * v.scale).collect();
        let mean = if kind == Kind::PhotoCluster {
            &[][..]
        } else {
            &self.plan.text_mean[..]
        };
        let c = cluster::nearest(centres, &generation::centred(&row, mean)).0;
        let sizes = if kind == Kind::PhotoCluster {
            &mut self.photo_sizes
        } else {
            &mut self.text_sizes
        };
        sizes[c] += 1;
        let mut b = Vec::new();
        wire::put_varint(&mut b, file.into());
        wire::put_varint(&mut b, chunk.into());
        wire::put_u32(&mut b, v.scale.to_bits());
        b.extend(v.values.iter().map(|&x| x as u8));
        let bucket = self.cluster_bucket(kind, c);
        self.buckets.append(bucket, &b)?;
        if file.is_multiple_of(self.stride) {
            let bucket = self.sample_bucket(kind);
            self.buckets.append(bucket, &b)?;
        }
        Ok(())
    }

    /// An old generation's live file, in its order, with its previews.
    /// Gives its new number.
    pub fn old_file(&mut self, row: Row, previews: FilePreviews) -> u32 {
        self.push_file(row, previews)
    }

    /// An old shard's postings, by `map` (old number to new; `None` for a
    /// dead file). Words dropped now are left out.
    pub fn old_shard(
        &mut self,
        words: &[ShardWord],
        map: impl Fn(u32) -> Option<u32>,
    ) -> std::io::Result<()> {
        for w in words {
            if self.dropped.contains(&w.word) {
                continue;
            }
            for &(file, count) in &w.postings {
                if let Some(new) = map(file) {
                    self.posting(&w.word, new, count)?;
                }
            }
        }
        Ok(())
    }

    /// An old cluster's vectors, by `map`, if of this plan's model.
    pub fn old_cluster(
        &mut self,
        kind: Kind,
        model: &str,
        entries: &[ClusterEntry],
        map: impl Fn(u32) -> Option<u32>,
    ) -> std::io::Result<()> {
        let want = if kind == Kind::PhotoCluster {
            &self.plan.config.clip_model
        } else {
            &self.plan.config.text_model
        };
        if model != want {
            return Ok(());
        }
        for e in entries {
            if let Some(new) = map(e.file) {
                self.vector(kind, new, e.chunk, &e.vector)?;
            }
        }
        Ok(())
    }

    /// A recent record, as a new file. Gives its number.
    pub fn record(&mut self, r: &Record) -> std::io::Result<u32> {
        let file = self.next_file;
        let dropped: HashSet<&str> = self.dropped.iter().map(String::as_str).collect();
        let mut kept: BTreeMap<String, u32> = BTreeMap::new();
        let mut chunks = Vec::new();
        for c in &r.chunks {
            let words = self.plan.kept(&c.terms, &dropped);
            let mut codes: Vec<u16> = words.iter().map(|(t, _)| code_of(self.key(), t)).collect();
            codes.sort_unstable();
            codes.dedup();
            for (t, _) in words {
                kept.entry(t.clone()).or_default();
            }
            chunks.push((c.preview.clone(), codes));
        }
        for c in &r.chunks {
            for (t, n) in &c.terms {
                if let Some(total) = kept.get_mut(t) {
                    *total += u32::from(*n);
                }
            }
        }
        for (word, count) in &kept {
            self.posting(word, file, (*count).min(u32::from(u16::MAX)) as u16)?;
        }
        if r.model == self.plan.config.text_model {
            for (i, c) in r.chunks.iter().enumerate() {
                if c.len >= self.plan.config.min_words
                    && let Some(v) = &c.vector
                {
                    self.vector(Kind::TextCluster, file, i as u32, v)?;
                }
            }
        }
        if let Some((m, v)) = &r.extra.image
            && *m == self.plan.config.clip_model
            && !v.values.is_empty()
        {
            self.vector(Kind::PhotoCluster, file, 0, v)?;
        }
        let row = Row::of(r, self.plan.config.min_words);
        Ok(self.push_file(row, FilePreviews { chunks }))
    }

    /// Sorts the buckets into pieces, and gives the header with every
    /// server file not yet taken.
    pub fn finish(mut self) -> std::io::Result<(Header, ServerFiles)> {
        self.flush_rows();
        for shard in 0..self.plan.shards {
            let bytes = self.buckets.take(shard)?;
            let words = read_postings(&bytes).map_err(bad)?;
            let list: Vec<ShardWord> = words
                .into_iter()
                .map(|(word, mut postings)| {
                    postings.sort_unstable();
                    ShardWord { word, postings }
                })
                .collect();
            let piece = encode_shard(&list);
            self.ready.extend(self.packer.add(
                PieceId::new(Kind::Shard, shard),
                list.len() as u32,
                &piece,
            ));
        }
        for (kind, k, dims) in [
            (Kind::TextCluster, self.plan.text.len(), self.plan.text.dims),
            (
                Kind::PhotoCluster,
                self.plan.photo.len(),
                self.plan.photo.dims,
            ),
        ] {
            for c in 0..k {
                let bytes = self.buckets.take(self.cluster_bucket(kind, c))?;
                let mut entries = read_vectors(&bytes, dims).map_err(bad)?;
                entries.sort_by_key(|e| (e.file, e.chunk));
                let piece = encode_cluster(kind, dims, &entries);
                self.ready.extend(self.packer.add(
                    PieceId::new(kind, c as u32),
                    entries.len() as u32,
                    &piece,
                ));
            }
        }
        for (cluster, kind, dims) in [
            (Kind::TextCluster, Kind::TextSample, self.plan.text.dims),
            (Kind::PhotoCluster, Kind::PhotoSample, self.plan.photo.dims),
        ] {
            let bytes = self.buckets.take(self.sample_bucket(cluster))?;
            if bytes.is_empty() {
                continue;
            }
            let mut entries = read_vectors(&bytes, dims).map_err(bad)?;
            entries.sort_by_key(|e| (e.file, e.chunk));
            let piece = encode_cluster(kind, dims, &entries);
            self.ready.extend(
                self.packer
                    .add(PieceId::new(kind, 0), entries.len() as u32, &piece),
            );
        }
        let packed = self.packer.finish();
        self.ready.extend(packed.last);
        let (pieces, server_files, bytes) = (packed.pieces, packed.server_files, packed.bytes);
        let c = &self.plan.config;
        let header = Header {
            id: c.id,
            created_ms: c.now_ms,
            key: c.key,
            files: u64::from(self.next_file),
            chunks: self.chunks,
            total_len: self.total_len,
            bytes,
            text_model: if self.plan.text.is_empty() {
                String::new()
            } else {
                c.text_model.clone()
            },
            clip_model: if self.plan.photo.is_empty() {
                String::new()
            } else {
                c.clip_model.clone()
            },
            text_dims: self.plan.text.dims as u32,
            clip_dims: self.plan.photo.dims as u32,
            shards: self.plan.shards,
            dropped: self.plan.dropped.clone(),
            server_files,
            pieces,
        };
        Ok((header, self.ready))
    }
}

/// A whole compaction: a new generation from `old` (the generation and
/// what the recent segments say of its files) and `recent` (every live
/// record of the recent segments, which become new files).
///
/// - `old_piece` gives the old generation's pieces, from the device's
///   cache; each is read when needed, and twice for shards and clusters
///   (to count, then to write), so memory holds one at a time.
/// - `out` takes each server file as it is done.
/// - Gives the new header.
pub fn compact<B: Buckets>(
    old: Option<&crate::index::Index>,
    old_piece: &dyn Fn(PieceId) -> std::io::Result<Vec<u8>>,
    recent: &[Record],
    config: Config,
    buckets: B,
    out: &mut dyn FnMut(u32, Vec<u8>) -> std::io::Result<()>,
) -> std::io::Result<Header> {
    use crate::generation::{decode_cluster, decode_previews, decode_rows, decode_shard};
    let source = old.map(crate::index::Index::source);
    let generation = source.and_then(|s| s.generation);
    // Old live files, numbered anew in order.
    let mut map: Vec<Option<u32>> = Vec::new();
    if let Some(s) = &source {
        let mut next = 0u32;
        map = s
            .generation
            .map_or(&[][..], |g| g.rows())
            .iter()
            .enumerate()
            .map(|(f, _)| {
                (!s.is_dead(f as u32)).then(|| {
                    next += 1;
                    next - 1
                })
            })
            .collect();
    }
    let renumber = |f: u32| map.get(f as usize).copied().flatten();
    let live = |f: u32| renumber(f).is_some();
    let ids = |kind: Kind| -> Vec<PieceId> {
        let mut v: Vec<PieceId> = generation
            .map(|g| g.header.pieces_of(kind).map(|p| p.id).collect())
            .unwrap_or_default();
        v.sort();
        v
    };

    let mut counts = Counts::new(config, generation.map_or(&[][..], |g| &g.header.dropped));
    counts.old_files(map.iter().flatten().count() as u64);
    for id in ids(Kind::Shard) {
        counts.old_shard(&decode_shard(&old_piece(id)?).map_err(bad)?, live);
    }
    for kind in [Kind::TextCluster, Kind::PhotoCluster] {
        let model = generation.map_or("", |g| {
            if kind == Kind::TextCluster {
                &g.header.text_model
            } else {
                &g.header.clip_model
            }
        });
        for id in ids(kind) {
            counts.old_cluster(
                kind,
                model,
                &decode_cluster(kind, &old_piece(id)?).map_err(bad)?,
                live,
            );
        }
    }
    for r in recent {
        counts.record(r);
    }
    let mut w = Writer::new(counts.plan(), buckets);
    let mut emit = |w: &mut Writer<B>| -> std::io::Result<()> {
        for (n, bytes) in w.take_files() {
            out(n, bytes)?;
        }
        Ok(())
    };
    emit(&mut w)?;
    if let (Some(s), Some(g)) = (&source, generation) {
        let records = ids(Kind::Records);
        let previews = ids(Kind::Previews);
        for (r, p) in records.iter().zip(&previews) {
            let rows = decode_rows(&old_piece(*r)?).map_err(bad)?;
            let mut shown = decode_previews(&old_piece(*p)?).map_err(bad)?.into_iter();
            for (i, mut row) in rows.into_iter().enumerate() {
                let f = r.n * crate::generation::FILES_PER_PIECE + i as u32;
                let preview = shown.next().unwrap_or_default();
                if s.is_dead(f) {
                    continue;
                }
                if let Some(path) = s.moved_path(f) {
                    row.path = path.to_string();
                }
                w.old_file(row, preview);
                emit(&mut w)?;
            }
        }
        for id in ids(Kind::Shard) {
            w.old_shard(&decode_shard(&old_piece(id)?).map_err(bad)?, renumber)?;
        }
        for (kind, model) in [
            (Kind::TextCluster, &g.header.text_model),
            (Kind::PhotoCluster, &g.header.clip_model),
        ] {
            for id in ids(kind) {
                w.old_cluster(
                    kind,
                    model,
                    &decode_cluster(kind, &old_piece(id)?).map_err(bad)?,
                    renumber,
                )?;
            }
        }
    }
    for r in recent {
        w.record(r)?;
        emit(&mut w)?;
    }
    let (header, rest) = w.finish()?;
    for (n, bytes) in rest {
        out(n, bytes)?;
    }
    Ok(header)
}

fn bad(e: crate::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// A shard bucket's postings, by word.
fn read_postings(bytes: &[u8]) -> Result<BTreeMap<String, Vec<(u32, u16)>>, crate::Error> {
    let mut words: BTreeMap<String, Vec<(u32, u16)>> = BTreeMap::new();
    let mut r = Reader::new(bytes, "a compaction bucket");
    while !r.is_empty() {
        let word = String::from_utf8(r.short_bytes()?.to_vec()).map_err(|_| r.garbled())?;
        let file = r.varint()? as u32;
        let count = r.varint()? as u16;
        words.entry(word).or_default().push((file, count));
    }
    Ok(words)
}

/// A cluster bucket's vectors, each `dims` long.
fn read_vectors(bytes: &[u8], dims: usize) -> Result<Vec<ClusterEntry>, crate::Error> {
    let mut entries = Vec::new();
    let mut r = Reader::new(bytes, "a compaction bucket");
    while !r.is_empty() {
        let file = r.varint()? as u32;
        let chunk = r.varint()? as u32;
        let scale = f32::from_bits(r.u32()?);
        let values = r.take(dims)?.iter().map(|&x| x as i8).collect();
        entries.push(ClusterEntry {
            file,
            chunk,
            vector: Vector { scale, values },
        });
    }
    Ok(entries)
}
