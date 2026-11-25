//! The test corpus: files as the index keeps them, and judged queries.
//!
//! One file holds it all:
//! - the models that made its vectors;
//! - its records, as index segments (`encode_segment`);
//! - its queries, each with its text, the files that answer it (with a
//!   grade), and its vectors from both models, so a run needs no model.

use raft5fs_search::Error;
use raft5fs_search::record::{Entry, Record};
use raft5fs_search::segment::{decode_segment, encode_segment};
use raft5fs_wire::{self as wire, Reader};

const MAGIC: &[u8; 4] = b"r5ev";
const FORMAT: u8 = 1;
/// Records per segment: segments are read whole.
const SEGMENT: usize = 2000;

/// A judged query.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    /// Which set it is in, such as "miracl-es" or "xm-de-short".
    pub set: String,
    pub text: String,
    /// The files that answer it, by inode, each with a grade above 0.
    pub relevant: Vec<(u64, u8)>,
    /// Its vector from the text model, with the query prefix.
    pub vector: Vec<f32>,
    /// Its vector from the photo model's text side.
    pub clip: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Corpus {
    pub text_model: String,
    pub clip_model: String,
    pub records: Vec<Record>,
    pub queries: Vec<Query>,
}

fn put_vector(out: &mut Vec<u8>, v: &[f32]) {
    wire::put_varint(out, v.len() as u64);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
}

fn vector(r: &mut Reader) -> Result<Vec<f32>, Error> {
    let n = r.varint()? as usize;
    let bytes = r.take(n.checked_mul(4).ok_or_else(|| r.garbled())?)?;
    Ok(bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| f32::from_le_bytes(*b))
        .collect())
}

impl Corpus {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        wire::put_u8(&mut out, FORMAT);
        wire::put_short_bytes(&mut out, self.text_model.as_bytes());
        wire::put_short_bytes(&mut out, self.clip_model.as_bytes());
        let entries: Vec<Entry> = self.records.iter().cloned().map(Entry::Record).collect();
        let segments: Vec<&[Entry]> = entries.chunks(SEGMENT).collect();
        wire::put_varint(&mut out, segments.len() as u64);
        for s in segments {
            wire::put_bytes(&mut out, &encode_segment(s));
        }
        wire::put_varint(&mut out, self.queries.len() as u64);
        for q in &self.queries {
            wire::put_short_bytes(&mut out, q.set.as_bytes());
            wire::put_short_bytes(&mut out, q.text.as_bytes());
            wire::put_varint(&mut out, q.relevant.len() as u64);
            for &(ino, grade) in &q.relevant {
                wire::put_varint(&mut out, ino);
                wire::put_u8(&mut out, grade);
            }
            put_vector(&mut out, &q.vector);
            put_vector(&mut out, &q.clip);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, "a search test corpus");
        if r.array::<4>()? != *MAGIC || r.u8()? != FORMAT {
            return Err(r.garbled());
        }
        let text = |r: &mut Reader| -> Result<String, Error> {
            String::from_utf8(r.short_bytes()?.to_vec()).map_err(|_| r.garbled())
        };
        let text_model = text(&mut r)?;
        let clip_model = text(&mut r)?;
        let mut records = Vec::new();
        for _ in 0..r.varint()? {
            for e in decode_segment(r.bytes()?)? {
                if let Entry::Record(rec) = e {
                    records.push(rec);
                }
            }
        }
        let mut queries = Vec::new();
        for _ in 0..r.varint()? {
            let set = text(&mut r)?;
            let q = text(&mut r)?;
            let mut relevant = Vec::new();
            for _ in 0..r.varint()? {
                relevant.push((r.varint()?, r.u8()?));
            }
            queries.push(Query {
                set,
                text: q,
                relevant,
                vector: vector(&mut r)?,
                clip: vector(&mut r)?,
            });
        }
        r.finish()?;
        Ok(Self {
            text_model,
            clip_model,
            records,
            queries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raft5fs_search::record::{DocKind, Extra, Stamp};
    use raft5fs_search::text::chunks;

    #[test]
    fn a_corpus_reads_back_as_written() {
        let records = (0..3)
            .map(|i| Record {
                ino: i,
                at_ms: 1,
                stamp: Stamp {
                    mtime_ns: 0,
                    size: 0,
                },
                path: format!("a/{i}.txt"),
                kind: DocKind::Text,
                model: String::new(),
                chunks: chunks("some words here"),
                extra: Extra::default(),
            })
            .collect();
        let c = Corpus {
            text_model: "t".into(),
            clip_model: "c".into(),
            records,
            queries: vec![Query {
                set: "s".into(),
                text: "words".into(),
                relevant: vec![(1, 1)],
                vector: vec![0.5, -0.25],
                clip: vec![1.0],
            }],
        };
        assert_eq!(Corpus::decode(&c.encode()).unwrap(), c);
        assert!(Corpus::decode(b"r5ev\x09").is_err());
    }
}
