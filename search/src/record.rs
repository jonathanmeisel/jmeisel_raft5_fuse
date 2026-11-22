//! What the index keeps for one file.
//!
//! An `Entry` is either a `Record` of a file as it was when indexed, or a
//! tombstone that says the file left the volume. Each entry carries the
//! time it was written (`at_ms`). For each inode, the newest entry from any
//! indexer wins. Indexers of one volume take turns under a claim, so times
//! from different indexers do not race.
//!
//! The full text is not kept: only a short preview and the word counts of
//! each chunk. That keeps the index small enough for a browser to cache.

use raft5fs_wire::{self as wire, Reader};

use crate::Error;

/// The format byte at the start of every entry.
const FORMAT: u8 = 1;

/// What the indexer saw of a file: if this changes, the file changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stamp {
    /// Modification time, in nanoseconds since the Unix epoch.
    pub mtime_ns: u64,
    pub size: u64,
}

/// What sort of file a record is of. Search can show or filter by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocKind {
    Text,
    /// A GPS track or route (GPX, TCX).
    Track,
    /// A photo. Phase 4 fills these in.
    Photo,
    /// A file with no text this indexer can read. Kept, so its name is
    /// still found and the indexer does not try it again until it changes.
    Opaque,
}

impl DocKind {
    fn byte(self) -> u8 {
        match self {
            DocKind::Text => 0,
            DocKind::Track => 1,
            DocKind::Photo => 2,
            DocKind::Opaque => 3,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => DocKind::Text,
            1 => DocKind::Track,
            2 => DocKind::Photo,
            3 => DocKind::Opaque,
            _ => return None,
        })
    }
}

/// A chunk's embedding, quantized to one byte per dimension: the real
/// value of dimension `i` is `values[i] as f32 * scale`.
#[derive(Debug, Clone, PartialEq)]
pub struct Vector {
    pub scale: f32,
    pub values: Vec<i8>,
}

/// One piece of a file's text.
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    /// The start of the chunk, for showing with a result.
    pub preview: String,
    /// How many times each word occurs, sorted by word.
    pub terms: Vec<(String, u16)>,
    /// How many words the chunk has in all.
    pub len: u32,
    pub vector: Option<Vector>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub ino: u64,
    pub at_ms: u64,
    pub stamp: Stamp,
    /// The file's path in the volume when it was indexed, from the volume's
    /// root. A rename writes a new record.
    pub path: String,
    pub kind: DocKind,
    /// The embedding model of the chunks' vectors; empty for none.
    pub model: String,
    pub chunks: Vec<Chunk>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    Record(Record),
    Gone { ino: u64, at_ms: u64 },
}

impl Entry {
    pub fn ino(&self) -> u64 {
        match self {
            Entry::Record(r) => r.ino,
            Entry::Gone { ino, .. } => *ino,
        }
    }

    pub fn at_ms(&self) -> u64 {
        match self {
            Entry::Record(r) => r.at_ms,
            Entry::Gone { at_ms, .. } => *at_ms,
        }
    }
}

pub fn encode_entry(entry: &Entry) -> Vec<u8> {
    let mut out = vec![FORMAT];
    match entry {
        Entry::Gone { ino, at_ms } => {
            wire::put_u8(&mut out, 1);
            wire::put_u64(&mut out, *ino);
            wire::put_u64(&mut out, *at_ms);
        }
        Entry::Record(r) => {
            wire::put_u8(&mut out, 0);
            wire::put_u64(&mut out, r.ino);
            wire::put_u64(&mut out, r.at_ms);
            wire::put_u64(&mut out, r.stamp.mtime_ns);
            wire::put_u64(&mut out, r.stamp.size);
            wire::put_bytes(&mut out, r.path.as_bytes());
            wire::put_u8(&mut out, r.kind.byte());
            wire::put_bytes(&mut out, r.model.as_bytes());
            wire::put_u32(&mut out, r.chunks.len() as u32);
            for c in &r.chunks {
                wire::put_bytes(&mut out, c.preview.as_bytes());
                wire::put_u32(&mut out, c.len);
                wire::put_u32(&mut out, c.terms.len() as u32);
                for (term, count) in &c.terms {
                    wire::put_bytes(&mut out, term.as_bytes());
                    wire::put_u16(&mut out, *count);
                }
                match &c.vector {
                    None => wire::put_u8(&mut out, 0),
                    Some(v) => {
                        wire::put_u8(&mut out, 1);
                        wire::put_u32(&mut out, v.scale.to_bits());
                        let bytes: Vec<u8> = v.values.iter().map(|&x| x as u8).collect();
                        wire::put_bytes(&mut out, &bytes);
                    }
                }
            }
        }
    }
    out
}

pub fn decode_entry(bytes: &[u8]) -> Result<Entry, Error> {
    let mut r = Reader::new(bytes, "a search index entry");
    if r.u8()? != FORMAT {
        return Err(r.garbled());
    }
    let tag = r.u8()?;
    let ino = r.u64()?;
    let at_ms = r.u64()?;
    let entry = match tag {
        1 => Entry::Gone { ino, at_ms },
        0 => {
            let stamp = Stamp {
                mtime_ns: r.u64()?,
                size: r.u64()?,
            };
            let path = r.string()?;
            let kind = DocKind::from_byte(r.u8()?).ok_or_else(|| r.garbled())?;
            let model = r.string()?;
            let count = r.u32()?;
            let mut chunks = Vec::new();
            for _ in 0..count {
                let preview = r.string()?;
                let len = r.u32()?;
                let nterms = r.u32()?;
                let mut terms = Vec::new();
                for _ in 0..nterms {
                    let term = r.string()?;
                    terms.push((term, r.u16()?));
                }
                let vector = match r.u8()? {
                    0 => None,
                    1 => {
                        let scale = f32::from_bits(r.u32()?);
                        let values = r.bytes()?.iter().map(|&b| b as i8).collect();
                        Some(Vector { scale, values })
                    }
                    _ => return Err(r.garbled()),
                };
                chunks.push(Chunk {
                    preview,
                    terms,
                    len,
                    vector,
                });
            }
            Entry::Record(Record {
                ino,
                at_ms,
                stamp,
                path,
                kind,
                model,
                chunks,
            })
        }
        _ => return Err(r.garbled()),
    };
    r.finish()?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Entry {
        Entry::Record(Record {
            ino: 7,
            at_ms: 1000,
            stamp: Stamp {
                mtime_ns: 5,
                size: 9,
            },
            path: "a/b.txt".into(),
            kind: DocKind::Text,
            model: "m".into(),
            chunks: vec![Chunk {
                preview: "hi".into(),
                terms: vec![("hi".into(), 2)],
                len: 2,
                vector: Some(Vector {
                    scale: 0.5,
                    values: vec![-1, 2],
                }),
            }],
        })
    }

    #[test]
    fn entries_round_trip() {
        let gone = Entry::Gone { ino: 3, at_ms: 4 };
        for e in [sample(), gone] {
            assert_eq!(decode_entry(&encode_entry(&e)).unwrap(), e);
        }
    }

    #[test]
    fn a_bad_entry_is_refused() {
        let mut bytes = encode_entry(&sample());
        assert!(decode_entry(&bytes[..bytes.len() - 1]).is_err());
        bytes.push(0);
        assert!(decode_entry(&bytes).is_err(), "bytes left over");
        bytes[0] = 9;
        assert!(decode_entry(&bytes).is_err(), "another format");
    }

    /// The stored layout of an entry, pinned.
    #[test]
    fn an_entry_keeps_its_bytes() {
        let golden = "0100000000000000000700000000000003e8\
                      00000000000000050000000000000009\
                      00000007612f622e74787400000000016d00000001\
                      0000000268690000000200000001000000026869000201\
                      3f00000000000002ff02";
        assert_eq!(raft5fs_wire::hex(&encode_entry(&sample())), golden);
        let gone = "0101000000000000000300000000000000\
                    04";
        assert_eq!(
            raft5fs_wire::hex(&encode_entry(&Entry::Gone { ino: 3, at_ms: 4 })),
            gone
        );
    }
}
