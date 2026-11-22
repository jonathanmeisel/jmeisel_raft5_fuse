//! A segment: one index file that holds many entries, so that a client
//! fetches a volume's index in a few large reads, not one read per file.
//!
//! Segments are append-only: an indexer writes a new segment for new
//! entries and never changes an old one, except when it compacts its own
//! segments into one.

use raft5fs_wire::{self as wire, Reader};

use crate::Error;
use crate::record::{Entry, decode_entry, encode_entry};

const MAGIC: &[u8; 4] = b"r5sg";
const FORMAT: u8 = 1;

pub fn encode_segment(entries: &[Entry]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    wire::put_u8(&mut out, FORMAT);
    wire::put_u32(&mut out, entries.len() as u32);
    for e in entries {
        wire::put_bytes(&mut out, &encode_entry(e));
    }
    out
}

/// The entries of a segment. One bad entry makes the whole segment fail:
/// a segment is written in one piece, so a bad one is not ours.
pub fn decode_segment(bytes: &[u8]) -> Result<Vec<Entry>, Error> {
    let mut r = Reader::new(bytes, "a search index segment");
    if r.array::<4>()? != *MAGIC || r.u8()? != FORMAT {
        return Err(r.garbled());
    }
    let count = r.u32()?;
    let mut entries = Vec::with_capacity(count.min(1 << 16) as usize);
    for _ in 0..count {
        entries.push(decode_entry(r.bytes()?)?);
    }
    r.finish()?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_round_trip_and_refuse_damage() {
        let entries = vec![
            Entry::Gone { ino: 1, at_ms: 2 },
            Entry::Gone { ino: 3, at_ms: 4 },
        ];
        let bytes = encode_segment(&entries);
        assert_eq!(decode_segment(&bytes).unwrap(), entries);
        assert!(decode_segment(&bytes[..bytes.len() - 2]).is_err());
        assert!(decode_segment(b"nope").is_err());
    }

    /// The stored layout of a segment, pinned.
    #[test]
    fn a_segment_keeps_its_bytes() {
        let golden = "7235736701000000010000001201010000000000000001\
                      0000000000000002";
        let bytes = encode_segment(&[Entry::Gone { ino: 1, at_ms: 2 }]);
        assert_eq!(raft5fs_wire::hex(&bytes), golden);
    }
}
