//! A segment: one index file that holds many entries, so that a client
//! fetches a volume's index in a few large reads, not one read per file.
//!
//! Segments are append-only: an indexer writes a new segment for new
//! entries and never changes an old one, except when it compacts its own
//! segments into fewer.
//!
//! Format 2: the magic, the format byte, then a deflated body:
//! - the segment's words (`record::Words`), which its entries name by number;
//! - its entries (record format 3).
//!
//! Format 1, still read: the entries, one after another, uncompressed.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use raft5fs_wire::{self as wire, Reader};

use crate::Error;
use crate::record::{Entry, Words, decode_entry, encode_entry};

const MAGIC: &[u8; 4] = b"r5sg";
const FORMAT: u8 = 2;
const FORMAT_1: u8 = 1;

/// The most a segment's body may grow to when inflated. Indexers write
/// a few MB at most; this stops a damaged or hostile segment filling
/// memory.
const MAX_BODY: u64 = 256 << 20;

/// The body of a segment, before compression.
fn encode_body(entries: &[Entry]) -> Vec<u8> {
    let mut words = Words::default();
    let encoded: Vec<Vec<u8>> = entries
        .iter()
        .map(|e| encode_entry(e, &mut words))
        .collect();
    let words = words.into_list();
    let mut out = Vec::new();
    wire::put_varint(&mut out, words.len() as u64);
    for w in &words {
        wire::put_short_bytes(&mut out, w.as_bytes());
    }
    wire::put_varint(&mut out, encoded.len() as u64);
    for e in &encoded {
        wire::put_short_bytes(&mut out, e);
    }
    out
}

pub fn encode_segment(entries: &[Entry]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    wire::put_u8(&mut out, FORMAT);
    let mut z = DeflateEncoder::new(out, Compression::default());
    z.write_all(&encode_body(entries))
        .expect("writing to memory doesn't fail");
    z.finish().expect("writing to memory doesn't fail")
}

/// The entries of a segment. One bad entry makes the whole segment fail:
/// a segment is written in one piece, so a bad one is not ours.
pub fn decode_segment(bytes: &[u8]) -> Result<Vec<Entry>, Error> {
    let mut r = Reader::new(bytes, "a search index segment");
    if r.array::<4>()? != *MAGIC {
        return Err(r.garbled());
    }
    match r.u8()? {
        FORMAT => {
            let mut body = Vec::new();
            DeflateDecoder::new(r.rest())
                .take(MAX_BODY + 1)
                .read_to_end(&mut body)
                .map_err(|_| r.garbled())?;
            if body.len() as u64 > MAX_BODY {
                return Err(r.garbled());
            }
            decode_body(&body)
        }
        FORMAT_1 => {
            let count = r.u32()?;
            let mut entries = Vec::with_capacity(count.min(1 << 16) as usize);
            for _ in 0..count {
                entries.push(decode_entry(r.bytes()?, &[])?);
            }
            r.finish()?;
            Ok(entries)
        }
        _ => Err(r.garbled()),
    }
}

fn decode_body(body: &[u8]) -> Result<Vec<Entry>, Error> {
    let mut r = Reader::new(body, "a search index segment");
    let count = r.varint()?;
    let mut words = Vec::with_capacity(count.min(1 << 16) as usize);
    for _ in 0..count {
        let w = r.short_bytes()?;
        words.push(String::from_utf8(w.to_vec()).map_err(|_| r.garbled())?);
    }
    let count = r.varint()?;
    let mut entries = Vec::with_capacity(count.min(1 << 16) as usize);
    for _ in 0..count {
        entries.push(decode_entry(r.short_bytes()?, &words)?);
    }
    r.finish()?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Chunk, DocKind, Extra, Record, Stamp, Vector};

    fn record(ino: u64, words: &[&str]) -> Entry {
        Entry::Record(Record {
            ino,
            at_ms: 1_700_000_000_000 + ino,
            stamp: Stamp {
                mtime_ns: 1_700_000_000_000_000_000,
                size: 4096,
            },
            path: format!("notes/file-{ino}.txt"),
            kind: DocKind::Text,
            model: "multilingual-e5-small-int8@761b726".into(),
            chunks: vec![Chunk {
                preview: words.join(" "),
                terms: words.iter().map(|w| (w.to_string(), 1)).collect(),
                len: words.len() as u32,
                vector: Some(Vector {
                    scale: 0.01,
                    values: (0..384).map(|i| (i % 50) as i8).collect(),
                }),
            }],
            extra: Extra::default(),
        })
    }

    #[test]
    fn segments_round_trip_and_refuse_damage() {
        let entries = vec![
            Entry::Gone { ino: 1, at_ms: 2 },
            record(3, &["apple", "pear"]),
            record(4, &["pear", "plum"]),
        ];
        let bytes = encode_segment(&entries);
        assert_eq!(decode_segment(&bytes).unwrap(), entries);
        assert!(decode_segment(&bytes[..bytes.len() - 2]).is_err());
        assert!(decode_segment(b"nope").is_err());
        assert!(decode_segment(&[]).is_err());
    }

    /// The stored layout of a segment's body, pinned. (Compressed bytes
    /// may change with the deflate library, so they aren't pinned.)
    #[test]
    fn a_segment_keeps_its_bytes() {
        let body = encode_body(&[Entry::Gone { ino: 1, at_ms: 2 }, record(3, &["hi"])]);
        assert_eq!(raft5fs_wire::hex(&body[..9]), "010268690204040101");
        let bytes = encode_segment(&[Entry::Gone { ino: 1, at_ms: 2 }]);
        assert_eq!(raft5fs_wire::hex(&bytes[..5]), "7235736702");
    }

    /// Segments from before format 2 still read.
    #[test]
    fn a_format_1_segment_still_reads() {
        let golden = "7235736701000000010000001202010000000000000001\
                      0000000000000002";
        let bytes = raft5fs_wire::from_hex(golden).unwrap();
        assert_eq!(
            decode_segment(&bytes).unwrap(),
            [Entry::Gone { ino: 1, at_ms: 2 }]
        );
    }

    /// A body that inflates past `MAX_BODY` is refused.
    #[test]
    fn a_segment_too_big_to_inflate_is_refused() {
        let mut out = MAGIC.to_vec();
        out.push(FORMAT);
        let mut z = DeflateEncoder::new(out, Compression::best());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..=(MAX_BODY >> 20) {
            z.write_all(&zeros).unwrap();
        }
        assert!(decode_segment(&z.finish().unwrap()).is_err());
    }

    /// How much smaller format 2 is than format 1, on records like real
    /// ones. Run with `--nocapture` to see the sizes.
    #[test]
    fn format_2_is_much_smaller() {
        let vocab: Vec<String> = (0..3000)
            .map(|i| format!("word{}", i * 7919 % 3000))
            .collect();
        let entries: Vec<Entry> = (0..200u64)
            .map(|ino| {
                let ws: Vec<&str> = (0..150)
                    .map(|j| vocab[((ino * 131 + j * 17) % 3000) as usize].as_str())
                    .collect();
                record(ino, &ws)
            })
            .collect();
        let old: usize = entries.iter().map(|e| old_size(e) + 4).sum::<usize>() + 9;
        let new = encode_segment(&entries).len();
        println!("format 1: {old} bytes, format 2: {new} bytes");
        assert!(new * 2 < old, "{new} vs {old}");
    }

    /// The size of an entry in format 2 (fixed widths, words in full).
    fn old_size(e: &Entry) -> usize {
        let Entry::Record(r) = e else { return 18 };
        let chunks: usize = r
            .chunks
            .iter()
            .map(|c| {
                4 + c.preview.len()
                    + 8
                    + c.terms.iter().map(|(t, _)| 4 + t.len() + 2).sum::<usize>()
                    + 1
                    + c.vector.as_ref().map_or(0, |v| 8 + v.values.len())
            })
            .sum();
        1 + 1 + 32 + 4 + r.path.len() + 1 + 4 + r.model.len() + 4 + chunks + 26
    }
}
