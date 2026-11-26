//! A generation: the index as compaction writes it, in pieces that a
//! search loads only when it needs them.
//!
//! - **The header** (`gen-<id>-head`) says what the generation holds: its
//!   counts, its keyed-hash key, the words it dropped as common, and where
//!   each piece is.
//! - **Server files** (`gen-<id>-<n>`, about `FILE_BYTES` each) hold the
//!   pieces one after another. A client downloads a whole server file and
//!   keeps each piece apart, so a query decrypts and reads only its own.
//! - **Pieces**, each compressed on its own:
//!   - records: one row per file, by file number;
//!   - previews: each file's chunk previews, with codes of their kept words;
//!   - keyword shards: the words whose keyed hash picks the shard, each
//!     with the files that have it and how often;
//!   - text and photo clusters: the vectors nearest one centre;
//!   - text and photo centres;
//!   - text and photo samples: the vectors of a few hundred files, which
//!     stand for every file in the cutoff's spread rule (`index`).
//! - **File numbers** run 0..files within a generation, in the order of the
//!   records pieces. Shards, clusters and previews name files by number.
//! - **Keyed hashes** (SHA-256 of the key and the word) pick a word's shard
//!   and its code. The key is random for each generation and kept in the
//!   sealed header, so the server can't tell which shard holds which word.

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use raft5fs_wire::{self as wire, Reader};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use crate::Error;
use crate::cluster::Centres;
use crate::record::{DocKind, Record, Stamp, Thumb, Vector};

const HEAD_MAGIC: &[u8; 4] = b"r5gh";
const PIECE_MAGIC: &[u8; 4] = b"r5gp";
const FORMAT: u8 = 1;
/// The most bytes a piece may hold once inflated: a larger one is not ours.
pub const MAX_PIECE: u64 = 128 << 20;
/// About how big a server file is: pieces go into one until it passes this.
pub const FILE_BYTES: usize = 8 << 20;
/// Files in each records piece and each previews piece.
pub const FILES_PER_PIECE: u32 = 4096;

/// A generation's id: random, so names never repeat.
pub type GenId = [u8; 8];

/// The header's file name.
pub fn head_name(id: &GenId) -> String {
    format!("gen-{}-head", wire::hex(id))
}

/// Server file `n`'s name.
pub fn file_name(id: &GenId, n: u32) -> String {
    format!("gen-{}-{n}", wire::hex(id))
}

/// What a piece holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Records,
    Previews,
    Shard,
    TextCluster,
    PhotoCluster,
    TextCentres,
    PhotoCentres,
    TextSample,
    PhotoSample,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Records => 1,
            Kind::Previews => 2,
            Kind::Shard => 3,
            Kind::TextCluster => 4,
            Kind::PhotoCluster => 5,
            Kind::TextCentres => 6,
            Kind::PhotoCentres => 7,
            Kind::TextSample => 8,
            Kind::PhotoSample => 9,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Kind::Records,
            2 => Kind::Previews,
            3 => Kind::Shard,
            4 => Kind::TextCluster,
            5 => Kind::PhotoCluster,
            6 => Kind::TextCentres,
            7 => Kind::PhotoCentres,
            8 => Kind::TextSample,
            9 => Kind::PhotoSample,
            _ => return None,
        })
    }

    fn letter(self) -> char {
        match self {
            Kind::Records => 'r',
            Kind::Previews => 'p',
            Kind::Shard => 's',
            Kind::TextCluster => 't',
            Kind::PhotoCluster => 'i',
            Kind::TextCentres => 'T',
            Kind::PhotoCentres => 'I',
            Kind::TextSample => 'x',
            Kind::PhotoSample => 'y',
        }
    }
}

/// One piece: its kind and number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PieceId {
    pub kind: Kind,
    pub n: u32,
}

impl PieceId {
    pub fn new(kind: Kind, n: u32) -> Self {
        Self { kind, n }
    }

    /// A short name, for cache keys: "s17".
    pub fn short(&self) -> String {
        format!("{}{}", self.kind.letter(), self.n)
    }
}

/// Where a piece is, and how many items (rows, words, vectors) it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PieceRef {
    pub id: PieceId,
    pub file: u32,
    pub offset: u64,
    pub len: u32,
    pub items: u32,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Header {
    pub id: GenId,
    pub created_ms: u64,
    /// The keyed hashes' key.
    pub key: [u8; 32],
    /// Files, chunks, and all files' words: what BM25 scores by.
    pub files: u64,
    pub chunks: u64,
    pub total_len: u64,
    /// Every server file's size, added up.
    pub bytes: u64,
    /// The models of the clusters' vectors.
    pub text_model: String,
    pub clip_model: String,
    pub text_dims: u32,
    pub clip_dims: u32,
    /// How many keyword shards: a power of two.
    pub shards: u32,
    /// Words no shard holds, being in too many files.
    pub dropped: Vec<String>,
    /// How many server files there are.
    pub server_files: u32,
    pub pieces: Vec<PieceRef>,
}

/// A keyed hash of `word`, for one use (`tag`).
fn keyed(key: &[u8; 32], tag: u8, word: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.update([tag]);
    h.update(word.as_bytes());
    h.finalize().into()
}

impl Header {
    /// The shard that holds `word`.
    pub fn shard_of(&self, word: &str) -> u32 {
        shard_of(&self.key, self.shards, word)
    }

    /// `word`'s code in previews.
    pub fn code_of(&self, word: &str) -> u16 {
        code_of(&self.key, word)
    }

    pub fn piece(&self, id: PieceId) -> Option<&PieceRef> {
        self.pieces.iter().find(|p| p.id == id)
    }

    pub fn pieces_of(&self, kind: Kind) -> impl Iterator<Item = &PieceRef> {
        self.pieces.iter().filter(move |p| p.id.kind == kind)
    }

    /// The pieces in server file `file`.
    pub fn in_file(&self, file: u32) -> impl Iterator<Item = &PieceRef> {
        self.pieces.iter().filter(move |p| p.file == file)
    }

    /// The records or previews piece that holds file number `file`.
    pub fn piece_of_file(file: u32) -> u32 {
        file / FILES_PER_PIECE
    }
}

/// The shard of `shards` that holds `word`, under `key`.
pub fn shard_of(key: &[u8; 32], shards: u32, word: &str) -> u32 {
    let h = keyed(key, b's', word);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]]) & (shards.max(1) - 1)
}

/// `word`'s 16-bit code under `key`.
pub fn code_of(key: &[u8; 32], word: &str) -> u16 {
    let h = keyed(key, b'c', word);
    u16::from_le_bytes([h[0], h[1]])
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    wire::put_short_bytes(out, s.as_bytes());
}

fn get_str(r: &mut Reader) -> Result<String, Error> {
    String::from_utf8(r.short_bytes()?.to_vec()).map_err(|_| r.garbled())
}

fn small(r: &mut Reader) -> Result<u32, Error> {
    u32::try_from(r.varint()?).map_err(|_| r.garbled())
}

pub fn encode_header(h: &Header) -> Vec<u8> {
    let mut out = HEAD_MAGIC.to_vec();
    wire::put_u8(&mut out, FORMAT);
    out.extend_from_slice(&h.id);
    wire::put_varint(&mut out, h.created_ms);
    out.extend_from_slice(&h.key);
    wire::put_varint(&mut out, h.files);
    wire::put_varint(&mut out, h.chunks);
    wire::put_varint(&mut out, h.total_len);
    wire::put_varint(&mut out, h.bytes);
    put_str(&mut out, &h.text_model);
    put_str(&mut out, &h.clip_model);
    wire::put_varint(&mut out, h.text_dims.into());
    wire::put_varint(&mut out, h.clip_dims.into());
    wire::put_varint(&mut out, h.shards.into());
    wire::put_varint(&mut out, h.dropped.len() as u64);
    for w in &h.dropped {
        put_str(&mut out, w);
    }
    wire::put_varint(&mut out, h.server_files.into());
    wire::put_varint(&mut out, h.pieces.len() as u64);
    for p in &h.pieces {
        wire::put_u8(&mut out, p.id.kind.byte());
        wire::put_varint(&mut out, p.id.n.into());
        wire::put_varint(&mut out, p.file.into());
        wire::put_varint(&mut out, p.offset);
        wire::put_varint(&mut out, p.len.into());
        wire::put_varint(&mut out, p.items.into());
    }
    out
}

pub fn decode_header(bytes: &[u8]) -> Result<Header, Error> {
    let mut r = Reader::new(bytes, "a search index generation");
    if r.array::<4>()? != *HEAD_MAGIC || r.u8()? != FORMAT {
        return Err(r.garbled());
    }
    let id = r.array()?;
    let created_ms = r.varint()?;
    let key = r.array()?;
    let files = r.varint()?;
    let chunks = r.varint()?;
    let total_len = r.varint()?;
    let bytes_ = r.varint()?;
    let text_model = get_str(&mut r)?;
    let clip_model = get_str(&mut r)?;
    let text_dims = small(&mut r)?;
    let clip_dims = small(&mut r)?;
    let shards = small(&mut r)?;
    if !shards.is_power_of_two() {
        return Err(r.garbled());
    }
    let mut dropped = Vec::new();
    for _ in 0..r.varint()? {
        dropped.push(get_str(&mut r)?);
    }
    let server_files = small(&mut r)?;
    let mut pieces = Vec::new();
    for _ in 0..r.varint()? {
        let kind = Kind::from_byte(r.u8()?).ok_or_else(|| r.garbled())?;
        let n = small(&mut r)?;
        let file = small(&mut r)?;
        if file >= server_files {
            return Err(r.garbled());
        }
        pieces.push(PieceRef {
            id: PieceId { kind, n },
            file,
            offset: r.varint()?,
            len: small(&mut r)?,
            items: small(&mut r)?,
        });
    }
    r.finish()?;
    Ok(Header {
        id,
        created_ms,
        key,
        files,
        chunks,
        total_len,
        bytes: bytes_,
        text_model,
        clip_model,
        text_dims,
        clip_dims,
        shards,
        dropped,
        server_files,
        pieces,
    })
}

/// A piece's bytes: its kind, then its body compressed.
fn seal(kind: Kind, body: &[u8]) -> Vec<u8> {
    let mut out = PIECE_MAGIC.to_vec();
    wire::put_u8(&mut out, FORMAT);
    wire::put_u8(&mut out, kind.byte());
    let mut z = DeflateEncoder::new(out, Compression::default());
    z.write_all(body).expect("writing to memory doesn't fail");
    z.finish().expect("writing to memory doesn't fail")
}

/// A piece's body, if it is a piece of `kind`.
fn open(kind: Kind, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(bytes, "a search index piece");
    if r.array::<4>()? != *PIECE_MAGIC || r.u8()? != FORMAT || r.u8()? != kind.byte() {
        return Err(r.garbled());
    }
    let mut body = Vec::new();
    DeflateDecoder::new(r.rest())
        .take(MAX_PIECE + 1)
        .read_to_end(&mut body)
        .map_err(|_| r.garbled())?;
    if body.len() as u64 > MAX_PIECE {
        return Err(r.garbled());
    }
    Ok(body)
}

/// One file as a generation keeps it: what search shows and filters by,
/// and what an indexer needs to tell whether the file changed.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub ino: u64,
    pub at_ms: u64,
    pub stamp: Stamp,
    pub path: String,
    pub kind: DocKind,
    /// The model of its text vectors; empty for none.
    pub model: String,
    /// The readers' version that read it (`extract::READER`).
    pub reader: u32,
    pub when_ms: u64,
    pub at: Option<(i32, i32)>,
    pub distance_m: u32,
    pub climb_m: u32,
    pub thumb: Option<Thumb>,
    /// A photo's image vector's model, and whether it has one (a picture
    /// the model couldn't decode has none).
    pub image: Option<(String, bool)>,
    /// Its length in words, and its chunks.
    pub words: u32,
    pub chunks: u32,
    /// Whether a chunk is long enough to be embedded.
    pub embeddable: bool,
}

impl Row {
    /// `r`'s row. `min_words` is the fewest words a chunk needs to be
    /// embedded.
    pub fn of(r: &Record, min_words: u32) -> Self {
        Self {
            ino: r.ino,
            at_ms: r.at_ms,
            stamp: r.stamp,
            path: r.path.clone(),
            kind: r.kind,
            model: r.model.clone(),
            reader: r.extra.reader,
            when_ms: r.extra.when_ms,
            at: r.extra.at,
            distance_m: r.extra.distance_m,
            climb_m: r.extra.climb_m,
            thumb: r.extra.thumb.clone(),
            image: r
                .extra
                .image
                .as_ref()
                .map(|(m, v)| (m.clone(), !v.values.is_empty())),
            words: r.chunks.iter().map(|c| c.len).fold(0, u32::saturating_add),
            chunks: r.chunks.len() as u32,
            embeddable: r.chunks.iter().any(|c| c.len >= min_words),
        }
    }
}

pub fn encode_rows(rows: &[Row]) -> Vec<u8> {
    let mut b = Vec::new();
    wire::put_varint(&mut b, rows.len() as u64);
    for row in rows {
        wire::put_varint(&mut b, row.ino);
        wire::put_varint(&mut b, row.at_ms);
        wire::put_varint(&mut b, row.stamp.mtime_ns);
        wire::put_varint(&mut b, row.stamp.size);
        put_str(&mut b, &row.path);
        wire::put_u8(&mut b, row.kind.byte());
        put_str(&mut b, &row.model);
        wire::put_varint(&mut b, row.reader.into());
        wire::put_varint(&mut b, row.when_ms);
        match row.at {
            None => wire::put_u8(&mut b, 0),
            Some((lat, lon)) => {
                wire::put_u8(&mut b, 1);
                wire::put_u32(&mut b, lat as u32);
                wire::put_u32(&mut b, lon as u32);
            }
        }
        wire::put_varint(&mut b, row.distance_m.into());
        wire::put_varint(&mut b, row.climb_m.into());
        match &row.thumb {
            None => wire::put_u8(&mut b, 0),
            Some(t) => {
                wire::put_u8(&mut b, 1);
                put_str(&mut b, &t.file);
                wire::put_varint(&mut b, t.offset);
                wire::put_varint(&mut b, t.len.into());
            }
        }
        match &row.image {
            None => wire::put_u8(&mut b, 0),
            Some((m, has)) => {
                wire::put_u8(&mut b, 1 + u8::from(*has));
                put_str(&mut b, m);
            }
        }
        wire::put_varint(&mut b, row.words.into());
        wire::put_varint(&mut b, row.chunks.into());
        wire::put_u8(&mut b, u8::from(row.embeddable));
    }
    seal(Kind::Records, &b)
}

pub fn decode_rows(bytes: &[u8]) -> Result<Vec<Row>, Error> {
    let body = open(Kind::Records, bytes)?;
    let mut r = Reader::new(&body, "a search index records piece");
    let mut rows = Vec::new();
    for _ in 0..r.varint()? {
        let ino = r.varint()?;
        let at_ms = r.varint()?;
        let stamp = Stamp {
            mtime_ns: r.varint()?,
            size: r.varint()?,
        };
        let path = get_str(&mut r)?;
        let kind = DocKind::from_byte(r.u8()?).ok_or_else(|| r.garbled())?;
        let model = get_str(&mut r)?;
        let reader = small(&mut r)?;
        let when_ms = r.varint()?;
        let at = match r.u8()? {
            0 => None,
            1 => Some((r.u32()? as i32, r.u32()? as i32)),
            _ => return Err(r.garbled()),
        };
        let distance_m = small(&mut r)?;
        let climb_m = small(&mut r)?;
        let thumb = match r.u8()? {
            0 => None,
            1 => Some(Thumb {
                file: get_str(&mut r)?,
                offset: r.varint()?,
                len: small(&mut r)?,
            }),
            _ => return Err(r.garbled()),
        };
        let image = match r.u8()? {
            0 => None,
            t @ (1 | 2) => Some((get_str(&mut r)?, t == 2)),
            _ => return Err(r.garbled()),
        };
        let words = small(&mut r)?;
        let chunks = small(&mut r)?;
        let embeddable = r.u8()? != 0;
        rows.push(Row {
            ino,
            at_ms,
            stamp,
            path,
            kind,
            model,
            reader,
            when_ms,
            at,
            distance_m,
            climb_m,
            thumb,
            image,
            words,
            chunks,
            embeddable,
        });
    }
    r.finish()?;
    Ok(rows)
}

/// A word in a keyword shard, and the files that have it with how often,
/// by file number, ascending.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ShardWord {
    pub word: String,
    pub postings: Vec<(u32, u16)>,
}

/// A shard's words, sorted by word.
pub fn encode_shard(words: &[ShardWord]) -> Vec<u8> {
    let mut b = Vec::new();
    wire::put_varint(&mut b, words.len() as u64);
    for w in words {
        put_str(&mut b, &w.word);
        wire::put_varint(&mut b, w.postings.len() as u64);
        let mut last = 0u32;
        for &(file, count) in &w.postings {
            wire::put_varint(&mut b, u64::from(file - last));
            wire::put_varint(&mut b, count.into());
            last = file;
        }
    }
    seal(Kind::Shard, &b)
}

pub fn decode_shard(bytes: &[u8]) -> Result<Vec<ShardWord>, Error> {
    let body = open(Kind::Shard, bytes)?;
    let mut r = Reader::new(&body, "a search index shard");
    let mut out = Vec::new();
    for _ in 0..r.varint()? {
        let word = get_str(&mut r)?;
        let mut postings = Vec::new();
        let mut file = 0u32;
        for _ in 0..r.varint()? {
            file = file
                .checked_add(small(&mut r)?)
                .ok_or_else(|| r.garbled())?;
            let count = u16::try_from(r.varint()?).map_err(|_| r.garbled())?;
            postings.push((file, count));
        }
        out.push(ShardWord { word, postings });
    }
    r.finish()?;
    Ok(out)
}

/// A vector in a cluster: the file (by number), the chunk (0 for a photo's
/// image vector), and the vector.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterEntry {
    pub file: u32,
    pub chunk: u32,
    pub vector: Vector,
}

/// A cluster's vectors, each `dims` long, sorted by file.
pub fn encode_cluster(kind: Kind, dims: usize, entries: &[ClusterEntry]) -> Vec<u8> {
    let mut b = Vec::new();
    wire::put_varint(&mut b, dims as u64);
    wire::put_varint(&mut b, entries.len() as u64);
    let mut last = 0u32;
    for e in entries {
        wire::put_varint(&mut b, u64::from(e.file - last));
        wire::put_varint(&mut b, e.chunk.into());
        wire::put_u32(&mut b, e.vector.scale.to_bits());
        b.extend(e.vector.values.iter().map(|&x| x as u8));
        last = e.file;
    }
    seal(kind, &b)
}

pub fn decode_cluster(kind: Kind, bytes: &[u8]) -> Result<Vec<ClusterEntry>, Error> {
    let body = open(kind, bytes)?;
    let mut r = Reader::new(&body, "a search index cluster");
    let dims = r.varint()? as usize;
    let mut out = Vec::new();
    let mut file = 0u32;
    for _ in 0..r.varint()? {
        file = file
            .checked_add(small(&mut r)?)
            .ok_or_else(|| r.garbled())?;
        let chunk = small(&mut r)?;
        let scale = f32::from_bits(r.u32()?);
        let values = r.take(dims)?.iter().map(|&x| x as i8).collect();
        out.push(ClusterEntry {
            file,
            chunk,
            vector: Vector { scale, values },
        });
    }
    r.finish()?;
    Ok(out)
}

/// Centres, and the mean their vectors were trained around (empty for
/// none): vectors are compared with the centres once the mean is taken
/// from them (`centred`).
pub fn encode_centres(kind: Kind, c: &Centres, mean: &[f32]) -> Vec<u8> {
    let mut b = Vec::new();
    wire::put_varint(&mut b, c.dims as u64);
    wire::put_varint(&mut b, c.len() as u64);
    for x in &c.values {
        b.extend_from_slice(&x.to_le_bytes());
    }
    wire::put_varint(&mut b, mean.len() as u64);
    for x in mean {
        b.extend_from_slice(&x.to_le_bytes());
    }
    seal(kind, &b)
}

fn floats(r: &mut Reader, n: usize) -> Result<Vec<f32>, Error> {
    let bytes = n.checked_mul(4).ok_or_else(|| r.garbled())?;
    Ok(r.take(bytes)?
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| f32::from_le_bytes(*b))
        .collect())
}

pub fn decode_centres(kind: Kind, bytes: &[u8]) -> Result<(Centres, Vec<f32>), Error> {
    let body = open(kind, bytes)?;
    let mut r = Reader::new(&body, "a search index's centres");
    let dims = r.varint()? as usize;
    let k = r.varint()? as usize;
    let n = dims.checked_mul(k).ok_or_else(|| r.garbled())?;
    let values = floats(&mut r, n)?;
    let m = r.varint()? as usize;
    if m != 0 && m != dims {
        return Err(r.garbled());
    }
    let mean = floats(&mut r, m)?;
    r.finish()?;
    Ok((Centres { dims, values }, mean))
}

/// `x` less `mean` (none if empty), unit length again: how a vector is
/// compared with centres trained around that mean.
pub fn centred(x: &[f32], mean: &[f32]) -> Vec<f32> {
    if mean.len() != x.len() {
        return x.to_vec();
    }
    let mut out: Vec<f32> = x.iter().zip(mean).map(|(a, b)| a - b).collect();
    let n = crate::cluster::dot(&out, &out)
        .sqrt()
        .max(f32::MIN_POSITIVE);
    out.iter_mut().for_each(|a| *a /= n);
    out
}

/// One file's chunks, as results show them: each preview, with the sorted
/// codes (`code_of`) of the words the chunk keeps.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FilePreviews {
    pub chunks: Vec<(String, Vec<u16>)>,
}

pub fn encode_previews(files: &[FilePreviews]) -> Vec<u8> {
    let mut b = Vec::new();
    wire::put_varint(&mut b, files.len() as u64);
    for f in files {
        wire::put_varint(&mut b, f.chunks.len() as u64);
        for (preview, codes) in &f.chunks {
            put_str(&mut b, preview);
            wire::put_varint(&mut b, codes.len() as u64);
            let mut last = 0u16;
            for &c in codes {
                wire::put_varint(&mut b, u64::from(c - last));
                last = c;
            }
        }
    }
    seal(Kind::Previews, &b)
}

pub fn decode_previews(bytes: &[u8]) -> Result<Vec<FilePreviews>, Error> {
    let body = open(Kind::Previews, bytes)?;
    let mut r = Reader::new(&body, "a search index previews piece");
    let mut out = Vec::new();
    for _ in 0..r.varint()? {
        let mut chunks = Vec::new();
        for _ in 0..r.varint()? {
            let preview = get_str(&mut r)?;
            let mut codes = Vec::new();
            let mut code = 0u16;
            for _ in 0..r.varint()? {
                let d = u16::try_from(r.varint()?).map_err(|_| r.garbled())?;
                code = code.checked_add(d).ok_or_else(|| r.garbled())?;
                codes.push(code);
            }
            chunks.push((preview, codes));
        }
        out.push(FilePreviews { chunks });
    }
    r.finish()?;
    Ok(out)
}

/// Server files, each its number and its bytes.
pub type ServerFiles = Vec<(u32, Vec<u8>)>;

/// What `Packer::finish` gives: the last server file, if it has anything,
/// and what the header needs.
pub struct Packed {
    pub last: Option<(u32, Vec<u8>)>,
    pub pieces: Vec<PieceRef>,
    pub server_files: u32,
    pub bytes: u64,
}

/// Packs pieces into server files of about `FILE_BYTES`.
#[derive(Debug, Default)]
pub struct Packer {
    current: Vec<u8>,
    next_file: u32,
    pieces: Vec<PieceRef>,
    bytes: u64,
}

impl Packer {
    /// Adds a piece. Gives a server file (its number and bytes) to write
    /// once one is full.
    pub fn add(&mut self, id: PieceId, items: u32, piece: &[u8]) -> Option<(u32, Vec<u8>)> {
        self.pieces.push(PieceRef {
            id,
            file: self.next_file,
            offset: self.current.len() as u64,
            len: piece.len() as u32,
            items,
        });
        self.current.extend_from_slice(piece);
        (self.current.len() >= FILE_BYTES).then(|| self.take())
    }

    fn take(&mut self) -> (u32, Vec<u8>) {
        let n = self.next_file;
        self.next_file += 1;
        let bytes = std::mem::take(&mut self.current);
        self.bytes += bytes.len() as u64;
        (n, bytes)
    }

    /// The last server file, and what the header needs.
    pub fn finish(mut self) -> Packed {
        let last = (!self.current.is_empty()).then(|| self.take());
        Packed {
            last,
            pieces: self.pieces,
            server_files: self.next_file,
            bytes: self.bytes,
        }
    }
}

/// Every piece of `files` (server files by number), by id.
pub fn pieces(
    header: &Header,
    files: &[(u32, Vec<u8>)],
) -> Option<std::collections::HashMap<PieceId, Vec<u8>>> {
    let mut out = std::collections::HashMap::new();
    for (n, bytes) in files {
        for (id, b) in split(header, *n, bytes)? {
            out.insert(id, b.to_vec());
        }
    }
    Some(out)
}

/// The pieces of server file `file`, as (id, bytes), from its whole bytes.
/// `None` if a piece the header lists doesn't fit in it.
pub fn split<'a>(header: &Header, file: u32, bytes: &'a [u8]) -> Option<Vec<(PieceId, &'a [u8])>> {
    header
        .in_file(file)
        .map(|p| {
            let start = usize::try_from(p.offset).ok()?;
            let end = start.checked_add(p.len as usize)?;
            Some((p.id, bytes.get(start..end)?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ino: u64) -> Row {
        Row {
            ino,
            at_ms: 5,
            stamp: Stamp {
                mtime_ns: 7,
                size: 9,
            },
            path: format!("a/b/{ino}.jpg"),
            kind: DocKind::Photo,
            model: "m".into(),
            reader: 2,
            when_ms: 11,
            at: Some((-5, 6)),
            distance_m: 1,
            climb_m: 2,
            thumb: Some(Thumb {
                file: "thumbs-x-1".into(),
                offset: 3,
                len: 4,
            }),
            image: Some(("clip".into(), true)),
            words: 40,
            chunks: 2,
            embeddable: true,
        }
    }

    #[test]
    fn every_piece_reads_back_as_written() {
        let rows = vec![
            row(1),
            Row {
                image: None,
                thumb: None,
                at: None,
                ..row(2)
            },
        ];
        assert_eq!(decode_rows(&encode_rows(&rows)).unwrap(), rows);

        let words = vec![
            ShardWord {
                word: "kayak".into(),
                postings: vec![(0, 2), (7, 1), (4000, 9)],
            },
            ShardWord::default(),
        ];
        assert_eq!(decode_shard(&encode_shard(&words)).unwrap(), words);

        let entries = vec![
            ClusterEntry {
                file: 3,
                chunk: 1,
                vector: Vector {
                    scale: 0.5,
                    values: vec![1, -2, 3],
                },
            },
            ClusterEntry {
                file: 3,
                chunk: 2,
                vector: Vector {
                    scale: 0.25,
                    values: vec![-127, 0, 127],
                },
            },
        ];
        let bytes = encode_cluster(Kind::TextCluster, 3, &entries);
        assert_eq!(decode_cluster(Kind::TextCluster, &bytes).unwrap(), entries);
        assert!(
            decode_cluster(Kind::PhotoCluster, &bytes).is_err(),
            "kinds don't mix"
        );

        let c = Centres {
            dims: 2,
            values: vec![0.6, 0.8, 1.0, 0.0],
        };
        let mean = vec![0.1, 0.2];
        let piece = encode_centres(Kind::TextCentres, &c, &mean);
        assert_eq!(
            decode_centres(Kind::TextCentres, &piece).unwrap(),
            (c, mean)
        );

        let previews = vec![FilePreviews {
            chunks: vec![("Hello there".into(), vec![3, 900, 65535])],
        }];
        assert_eq!(
            decode_previews(&encode_previews(&previews)).unwrap(),
            previews
        );
    }

    #[test]
    fn a_header_reads_back_and_rejects_what_isnt_one() {
        let h = Header {
            id: [1; 8],
            created_ms: 9,
            key: [7; 32],
            files: 3,
            chunks: 4,
            total_len: 100,
            bytes: 2000,
            text_model: "t".into(),
            clip_model: "c".into(),
            text_dims: 384,
            clip_dims: 512,
            shards: 8,
            dropped: vec!["the".into()],
            server_files: 2,
            pieces: vec![PieceRef {
                id: PieceId::new(Kind::Shard, 5),
                file: 1,
                offset: 10,
                len: 20,
                items: 3,
            }],
        };
        assert_eq!(decode_header(&encode_header(&h)).unwrap(), h);
        let mut bad = encode_header(&Header {
            shards: 6,
            ..h.clone()
        });
        assert!(
            decode_header(&bad).is_err(),
            "shards must be a power of two"
        );
        bad.truncate(10);
        assert!(decode_header(&bad).is_err());
        assert!(decode_rows(b"r5gp\x01\x03").is_err());
    }

    #[test]
    fn keyed_hashes_depend_on_the_key() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(shard_of(&a, 16, "kayak") < 16);
        let differ = (0..50)
            .filter(|i| code_of(&a, &format!("w{i}")) != code_of(&b, &format!("w{i}")))
            .count();
        assert!(differ > 40);
        assert_eq!(shard_of(&a, 1, "anything"), 0);
    }

    #[test]
    fn pieces_pack_into_files_and_split_back() {
        let mut p = Packer::default();
        let big = vec![7u8; FILE_BYTES];
        let mut files = Vec::new();
        assert!(p.add(PieceId::new(Kind::Shard, 0), 1, b"abc").is_none());
        files.extend(p.add(PieceId::new(Kind::Shard, 1), 1, &big));
        assert!(p.add(PieceId::new(Kind::Shard, 2), 1, b"xyz").is_none());
        let packed = p.finish();
        files.extend(packed.last);
        assert_eq!(packed.server_files, 2);
        assert_eq!(packed.bytes, (FILE_BYTES + 6) as u64);
        let h = Header {
            shards: 1,
            server_files: packed.server_files,
            pieces: packed.pieces,
            ..Header::default()
        };
        let first = split(&h, 0, &files[0].1).unwrap();
        assert_eq!(first[0], (PieceId::new(Kind::Shard, 0), &b"abc"[..]));
        assert_eq!(first[1].1.len(), FILE_BYTES);
        assert_eq!(
            split(&h, 1, &files[1].1).unwrap(),
            [(PieceId::new(Kind::Shard, 2), &b"xyz"[..])]
        );
        assert!(split(&h, 1, b"x").is_none());
    }
}
