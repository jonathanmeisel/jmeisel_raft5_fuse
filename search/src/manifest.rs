//! An indexer's manifest: which segments it wrote, and how far it got.
//!
//! Each indexer (one device) has its own manifest, named by its id, and
//! changes only that one. Whoever indexes next reads every manifest and
//! goes on from the newest cursor, so a pass cut short on one device is
//! finished on another.

use raft5fs_wire::{self as wire, Reader};

use crate::Error;

const MAGIC: &[u8; 4] = b"r5mf";
const FORMAT: u8 = 1;

/// The id of one indexer: one device's index files are named by it.
pub type IndexerId = [u8; 16];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub id: IndexerId,
    /// Who ran this indexer, and on what, for the status that search shows.
    pub user: String,
    pub device: String,
    /// The segments that hold this indexer's entries, oldest first.
    pub segments: Vec<String>,
    /// The number of the next segment this indexer writes.
    pub next_segment: u32,
    /// Changes in the activity log up to this time (ms) are indexed.
    pub cursor_ms: u64,
    /// When this indexer last finished a walk of the whole volume (ms), or 0.
    pub full_walk_ms: u64,
    /// When this indexer last finished a pass (ms).
    pub updated_ms: u64,
    /// Files edited lately, to check again until the time given (ms): the
    /// activity log notes an edit only once in a while (see `indexer`).
    pub recent: Vec<(u64, u64)>,
    /// The embedding model of this indexer's vectors; empty for none.
    pub model: String,
}

impl Manifest {
    /// The file name of this indexer's manifest.
    pub fn file_name(id: &IndexerId) -> String {
        format!("manifest-{}", raft5fs_wire::hex(id))
    }

    /// The file name of this indexer's segment `n`.
    pub fn segment_name(id: &IndexerId, n: u32) -> String {
        format!("seg-{}-{n}", raft5fs_wire::hex(id))
    }
}

pub fn encode_manifest(m: &Manifest) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    wire::put_u8(&mut out, FORMAT);
    out.extend_from_slice(&m.id);
    wire::put_bytes(&mut out, m.user.as_bytes());
    wire::put_bytes(&mut out, m.device.as_bytes());
    wire::put_u32(&mut out, m.segments.len() as u32);
    for s in &m.segments {
        wire::put_bytes(&mut out, s.as_bytes());
    }
    wire::put_u32(&mut out, m.next_segment);
    wire::put_u64(&mut out, m.cursor_ms);
    wire::put_u64(&mut out, m.full_walk_ms);
    wire::put_u64(&mut out, m.updated_ms);
    wire::put_u32(&mut out, m.recent.len() as u32);
    for (ino, until) in &m.recent {
        wire::put_u64(&mut out, *ino);
        wire::put_u64(&mut out, *until);
    }
    wire::put_bytes(&mut out, m.model.as_bytes());
    out
}

pub fn decode_manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    let mut r = Reader::new(bytes, "a search index manifest");
    if r.array::<4>()? != *MAGIC || r.u8()? != FORMAT {
        return Err(r.garbled());
    }
    let id = r.array()?;
    let user = r.string()?;
    let device = r.string()?;
    let mut segments = Vec::new();
    for _ in 0..r.u32()? {
        segments.push(r.string()?);
    }
    let next_segment = r.u32()?;
    let cursor_ms = r.u64()?;
    let full_walk_ms = r.u64()?;
    let updated_ms = r.u64()?;
    let mut recent = Vec::new();
    for _ in 0..r.u32()? {
        recent.push((r.u64()?, r.u64()?));
    }
    let model = r.string()?;
    r.finish()?;
    Ok(Manifest {
        id,
        user,
        device,
        segments,
        next_segment,
        cursor_ms,
        full_walk_ms,
        updated_ms,
        recent,
        model,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            id: [0xab; 16],
            user: "al".into(),
            device: "pc".into(),
            segments: vec!["s".into()],
            next_segment: 1,
            cursor_ms: 2,
            full_walk_ms: 3,
            updated_ms: 4,
            recent: vec![(5, 6)],
            model: String::new(),
        }
    }

    #[test]
    fn manifests_round_trip() {
        let m = sample();
        assert_eq!(decode_manifest(&encode_manifest(&m)).unwrap(), m);
        assert!(decode_manifest(&encode_manifest(&m)[1..]).is_err());
    }

    /// The stored layout of a manifest, pinned.
    #[test]
    fn a_manifest_keeps_its_bytes() {
        let golden = "72356d6601abababababababababababababababab\
                      00000002616c000000027063000000010000000173\
                      00000001000000000000000200000000000000030000000000000004\
                      000000010000000000000005000000000000000600000000";
        assert_eq!(raft5fs_wire::hex(&encode_manifest(&sample())), golden);
    }

    #[test]
    fn names_carry_the_id() {
        let id = [1; 16];
        assert_eq!(
            Manifest::file_name(&id),
            "manifest-01010101010101010101010101010101"
        );
        assert_eq!(
            Manifest::segment_name(&id, 3),
            "seg-01010101010101010101010101010101-3"
        );
    }
}
