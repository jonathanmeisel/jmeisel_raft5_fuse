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

use std::collections::HashMap;

use raft5fs_wire::{self as wire, Reader};

use crate::Error;
use crate::geo::Place;

/// The format byte at the start of every entry.
/// - Format 4 is format 3 with `Meta`.
/// - Format 3 has varints, and words by number in the segment's list.
/// - Format 2 has fixed-width numbers and words in full.
/// - Format 1 is format 2 without `Extra`: its records read with none.
const FORMAT: u8 = 4;
const FORMAT_3: u8 = 3;
const FORMAT_2: u8 = 2;
const FORMAT_1: u8 = 1;

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
    Photo,
    /// A video or a recording: its headers' date, place and length.
    Video,
    Audio,
    /// A file with no text this indexer can read. Kept, so its name is
    /// still found and the indexer does not try it again until it changes.
    Opaque,
    /// A file in a format that has text, which the device that indexed it
    /// couldn't read (a browser, with a PDF): a device that can reads it
    /// at its next walk.
    Unread,
}

impl DocKind {
    pub(crate) fn byte(self) -> u8 {
        match self {
            DocKind::Text => 0,
            DocKind::Track => 1,
            DocKind::Photo => 2,
            DocKind::Opaque => 3,
            DocKind::Unread => 4,
            DocKind::Video => 5,
            DocKind::Audio => 6,
        }
    }

    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => DocKind::Text,
            1 => DocKind::Track,
            2 => DocKind::Photo,
            3 => DocKind::Opaque,
            4 => DocKind::Unread,
            5 => DocKind::Video,
            6 => DocKind::Audio,
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
    pub extra: Extra,
}

/// What a record knows besides text: from a track or a photo.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extra {
    /// The version of the readers that read the file (`extract::READER`):
    /// a file read by an older one is read again.
    pub reader: u32,
    /// When it was taken or recorded (ms since the Unix epoch), or 0.
    pub when_ms: u64,
    /// Where (a photo) or where it starts (a track): latitude and
    /// longitude in 1e-4 degrees.
    pub at: Option<(i32, i32)>,
    pub distance_m: u32,
    pub climb_m: u32,
    /// A small picture of it, in another index file.
    pub thumb: Option<Thumb>,
    /// A photo's image vector, and the model that made it.
    pub image: Option<(String, Vector)>,
    pub meta: Meta,
}

/// The facts that search filters by, besides `Extra`'s dates and places.
/// Each is empty or 0 where it is not known.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Meta {
    /// Where it is: one place for a photo, the places along a track.
    pub places: Vec<Place>,
    /// The camera's make and model.
    pub camera: String,
    /// A picture's size in pixels, upright (after its EXIF orientation).
    pub width: u32,
    pub height: u32,
    /// A photo taken with a phone's front camera.
    pub selfie: bool,
    /// A document's pages.
    pub pages: u32,
    pub activity: Activity,
    /// How long a track, a video or a recording lasts.
    pub duration_ms: u64,
    /// When the file was made, and by which account, from the volume's
    /// activity log; 0 and empty for a file made before the indexer saw
    /// the log.
    pub added_ms: u64,
    pub added_by: String,
    /// The account that last made or changed it, from the log.
    pub changed_by: String,
}

/// What a track records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Activity {
    #[default]
    Unknown,
    Ride,
    Run,
    Hike,
    Walk,
    Other,
}

impl Activity {
    pub fn byte(self) -> u8 {
        match self {
            Activity::Unknown => 0,
            Activity::Ride => 1,
            Activity::Run => 2,
            Activity::Hike => 3,
            Activity::Walk => 4,
            Activity::Other => 5,
        }
    }

    /// The activity a byte names; a byte from a newer writer is `Other`.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Activity::Unknown,
            1 => Activity::Ride,
            2 => Activity::Run,
            3 => Activity::Hike,
            4 => Activity::Walk,
            _ => Activity::Other,
        }
    }

    /// The activity a file names ("cycling", "Biking", "Hiking").
    pub fn of(name: &str) -> Self {
        let a = name.to_ascii_lowercase();
        if ["bik", "cycl", "ride", "mtb", "gravel"]
            .iter()
            .any(|w| a.contains(w))
        {
            Activity::Ride
        } else if a.contains("run") {
            Activity::Run
        } else if ["hik", "trek"].iter().any(|w| a.contains(w)) {
            Activity::Hike
        } else if a.contains("walk") {
            Activity::Walk
        } else if a.trim().is_empty() {
            Activity::Unknown
        } else {
            Activity::Other
        }
    }
}

/// Where a thumbnail is: bytes `offset..offset + len` of index file `file`.
#[derive(Debug, Clone, PartialEq)]
pub struct Thumb {
    pub file: String,
    pub offset: u64,
    pub len: u32,
}

// Nearly every entry is a record, so boxing it would only add an
// allocation to each.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    Record(Record),
    Gone {
        ino: u64,
        at_ms: u64,
    },
    /// The file moved to `path`; its content is as its record says. A
    /// rename costs this, not the whole record again.
    Moved {
        ino: u64,
        at_ms: u64,
        path: String,
    },
}

impl Entry {
    pub fn ino(&self) -> u64 {
        match self {
            Entry::Record(r) => r.ino,
            Entry::Gone { ino, .. } | Entry::Moved { ino, .. } => *ino,
        }
    }

    pub fn at_ms(&self) -> u64 {
        match self {
            Entry::Record(r) => r.at_ms,
            Entry::Gone { at_ms, .. } | Entry::Moved { at_ms, .. } => *at_ms,
        }
    }

    /// `self`, with `newer` (for the same file) on top: the newer wins,
    /// but a move keeps the content of the record it moves.
    pub fn then(self, newer: Entry) -> Entry {
        match (self, newer) {
            (Entry::Record(mut r), Entry::Moved { at_ms, path, .. }) => {
                r.path = path;
                r.at_ms = at_ms;
                Entry::Record(r)
            }
            (_, newer) => newer,
        }
    }
}

/// The words of one segment's entries, each kept once: an entry names a
/// word by its number here. Numbers go in the order words are first seen.
#[derive(Debug, Default)]
pub struct Words {
    ids: HashMap<String, u32>,
    list: Vec<String>,
}

impl Words {
    fn id(&mut self, word: &str) -> u32 {
        if let Some(&id) = self.ids.get(word) {
            return id;
        }
        let id = self.list.len() as u32;
        self.ids.insert(word.to_owned(), id);
        self.list.push(word.to_owned());
        id
    }

    /// The words, by number.
    pub fn into_list(self) -> Vec<String> {
        self.list
    }
}

/// Writes `entry` in the current format, with its words as numbers in
/// `words`. Most numbers are varints: nearly all are small.
pub fn encode_entry(entry: &Entry, words: &mut Words) -> Vec<u8> {
    let mut out = vec![FORMAT];
    match entry {
        Entry::Gone { ino, at_ms } => {
            wire::put_u8(&mut out, 1);
            wire::put_varint(&mut out, *ino);
            wire::put_varint(&mut out, *at_ms);
        }
        Entry::Moved { ino, at_ms, path } => {
            wire::put_u8(&mut out, 2);
            wire::put_varint(&mut out, *ino);
            wire::put_varint(&mut out, *at_ms);
            wire::put_short_bytes(&mut out, path.as_bytes());
        }
        Entry::Record(r) => {
            wire::put_u8(&mut out, 0);
            wire::put_varint(&mut out, r.ino);
            wire::put_varint(&mut out, r.at_ms);
            wire::put_varint(&mut out, r.stamp.mtime_ns);
            wire::put_varint(&mut out, r.stamp.size);
            wire::put_short_bytes(&mut out, r.path.as_bytes());
            wire::put_u8(&mut out, r.kind.byte());
            wire::put_short_bytes(&mut out, r.model.as_bytes());
            wire::put_varint(&mut out, r.chunks.len() as u64);
            for c in &r.chunks {
                wire::put_short_bytes(&mut out, c.preview.as_bytes());
                wire::put_varint(&mut out, c.len.into());
                wire::put_varint(&mut out, c.terms.len() as u64);
                for (term, count) in &c.terms {
                    wire::put_varint(&mut out, words.id(term).into());
                    wire::put_varint(&mut out, (*count).into());
                }
                put_option(&mut out, c.vector.as_ref(), put_vector);
            }
            put_extra(&mut out, &r.extra);
        }
    }
    out
}

fn put_option<T>(out: &mut Vec<u8>, v: Option<&T>, put: impl FnOnce(&mut Vec<u8>, &T)) {
    match v {
        None => wire::put_u8(out, 0),
        Some(v) => {
            wire::put_u8(out, 1);
            put(out, v);
        }
    }
}

fn put_vector(out: &mut Vec<u8>, v: &Vector) {
    wire::put_u32(out, v.scale.to_bits());
    let bytes: Vec<u8> = v.values.iter().map(|&x| x as u8).collect();
    wire::put_short_bytes(out, &bytes);
}

fn put_extra(out: &mut Vec<u8>, e: &Extra) {
    wire::put_varint(out, e.reader.into());
    wire::put_varint(out, e.when_ms);
    put_option(out, e.at.as_ref(), |out, &(lat, lon)| {
        wire::put_u32(out, lat as u32);
        wire::put_u32(out, lon as u32);
    });
    wire::put_varint(out, e.distance_m.into());
    wire::put_varint(out, e.climb_m.into());
    put_option(out, e.thumb.as_ref(), |out, t| {
        wire::put_short_bytes(out, t.file.as_bytes());
        wire::put_varint(out, t.offset);
        wire::put_varint(out, t.len.into());
    });
    put_option(out, e.image.as_ref(), |out, (model, v)| {
        wire::put_short_bytes(out, model.as_bytes());
        put_vector(out, v);
    });
    put_meta(out, &e.meta);
}

fn put_place_part(out: &mut Vec<u8>, part: &Option<String>) {
    put_option(out, part.as_ref(), |out, s| {
        wire::put_short_bytes(out, s.as_bytes())
    });
}

fn put_meta(out: &mut Vec<u8>, m: &Meta) {
    wire::put_varint(out, m.places.len() as u64);
    for p in &m.places {
        for part in [&p.town, &p.region, &p.region_local, &p.country, &p.code] {
            put_place_part(out, part);
        }
    }
    wire::put_short_bytes(out, m.camera.as_bytes());
    wire::put_varint(out, m.width.into());
    wire::put_varint(out, m.height.into());
    wire::put_u8(out, u8::from(m.selfie));
    wire::put_varint(out, m.pages.into());
    wire::put_u8(out, m.activity.byte());
    wire::put_varint(out, m.duration_ms);
    wire::put_varint(out, m.added_ms);
    wire::put_short_bytes(out, m.added_by.as_bytes());
    wire::put_short_bytes(out, m.changed_by.as_bytes());
}

/// Reads the fields of an entry in any format: formats 1 and 2 have
/// fixed-width numbers and words in full, format 3 varints and words by
/// number.
struct Fields<'a, 'w> {
    r: Reader<'a>,
    compact: bool,
    words: &'w [String],
}

impl Fields<'_, '_> {
    fn n64(&mut self) -> Result<u64, Error> {
        if self.compact {
            self.r.varint()
        } else {
            self.r.u64()
        }
    }

    fn n32(&mut self) -> Result<u32, Error> {
        if self.compact {
            let n = self.r.varint()?;
            u32::try_from(n).map_err(|_| self.r.garbled())
        } else {
            self.r.u32()
        }
    }

    fn n16(&mut self) -> Result<u16, Error> {
        if self.compact {
            let n = self.r.varint()?;
            u16::try_from(n).map_err(|_| self.r.garbled())
        } else {
            self.r.u16()
        }
    }

    fn bytes(&mut self) -> Result<&[u8], Error> {
        if self.compact {
            self.r.short_bytes()
        } else {
            self.r.bytes()
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        if !self.compact {
            return self.r.string();
        }
        let bytes = self.r.short_bytes()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| self.r.garbled())
    }

    fn word(&mut self) -> Result<String, Error> {
        if !self.compact {
            return self.r.string();
        }
        let id = self.r.varint()?;
        let words = self.words;
        usize::try_from(id)
            .ok()
            .and_then(|id| words.get(id))
            .cloned()
            .ok_or_else(|| self.r.garbled())
    }

    fn flag(&mut self) -> Result<bool, Error> {
        match self.r.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(self.r.garbled()),
        }
    }

    fn vector(&mut self) -> Result<Vector, Error> {
        let scale = f32::from_bits(self.r.u32()?);
        let values = self.bytes()?.iter().map(|&b| b as i8).collect();
        Ok(Vector { scale, values })
    }

    fn extra(&mut self) -> Result<Extra, Error> {
        let reader = self.n32()?;
        let when_ms = self.n64()?;
        let at = if self.flag()? {
            Some((self.r.u32()? as i32, self.r.u32()? as i32))
        } else {
            None
        };
        let distance_m = self.n32()?;
        let climb_m = self.n32()?;
        let thumb = if self.flag()? {
            Some(Thumb {
                file: self.string()?,
                offset: self.n64()?,
                len: self.n32()?,
            })
        } else {
            None
        };
        let image = if self.flag()? {
            Some((self.string()?, self.vector()?))
        } else {
            None
        };
        Ok(Extra {
            reader,
            when_ms,
            at,
            distance_m,
            climb_m,
            thumb,
            image,
            meta: Meta::default(),
        })
    }

    fn place_part(&mut self) -> Result<Option<String>, Error> {
        if self.flag()? {
            Ok(Some(self.string()?))
        } else {
            Ok(None)
        }
    }

    /// `Meta`, which only format 4 has.
    fn meta(&mut self) -> Result<Meta, Error> {
        let count = self.n32()?;
        if count > MAX_PLACES {
            return Err(self.r.garbled());
        }
        let mut places = Vec::new();
        for _ in 0..count {
            places.push(Place {
                town: self.place_part()?,
                region: self.place_part()?,
                region_local: self.place_part()?,
                country: self.place_part()?,
                code: self.place_part()?,
            });
        }
        Ok(Meta {
            places,
            camera: self.string()?,
            width: self.n32()?,
            height: self.n32()?,
            selfie: self.flag()?,
            pages: self.n32()?,
            activity: Activity::from_byte(self.r.u8()?),
            duration_ms: self.n64()?,
            added_ms: self.n64()?,
            added_by: self.string()?,
            changed_by: self.string()?,
        })
    }
}

/// The most places one record may name: a longer list is not ours.
pub const MAX_PLACES: u32 = 64;

/// Reads an entry of any format. `words` are its segment's words, which a
/// format 3 entry names by number; older formats ignore them.
pub fn decode_entry(bytes: &[u8], words: &[String]) -> Result<Entry, Error> {
    let mut r = Reader::new(bytes, "a search index entry");
    let format = r.u8()?;
    if ![FORMAT, FORMAT_3, FORMAT_2, FORMAT_1].contains(&format) {
        return Err(r.garbled());
    }
    let compact = format >= FORMAT_3;
    let mut f = Fields { r, compact, words };
    let tag = f.r.u8()?;
    let ino = f.n64()?;
    let at_ms = f.n64()?;
    let entry = match tag {
        1 => Entry::Gone { ino, at_ms },
        2 if compact => Entry::Moved {
            ino,
            at_ms,
            path: f.string()?,
        },
        0 => {
            let stamp = Stamp {
                mtime_ns: f.n64()?,
                size: f.n64()?,
            };
            let path = f.string()?;
            let kind = DocKind::from_byte(f.r.u8()?).ok_or_else(|| f.r.garbled())?;
            let model = f.string()?;
            let count = f.n32()?;
            let mut chunks = Vec::new();
            for _ in 0..count {
                let preview = f.string()?;
                let len = f.n32()?;
                let nterms = f.n32()?;
                let mut terms = Vec::new();
                for _ in 0..nterms {
                    let term = f.word()?;
                    terms.push((term, f.n16()?));
                }
                let vector = if f.flag()? { Some(f.vector()?) } else { None };
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
                extra: if format == FORMAT_1 {
                    Extra::default()
                } else {
                    let mut extra = f.extra()?;
                    if format >= FORMAT {
                        extra.meta = f.meta()?;
                    }
                    extra
                },
            })
        }
        _ => return Err(f.r.garbled()),
    };
    f.r.finish()?;
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
            extra: Extra::default(),
        })
    }

    /// `sample`, with everything a photo has.
    fn photo() -> Entry {
        let Entry::Record(mut r) = sample() else {
            unreachable!()
        };
        r.extra = Extra {
            reader: 2,
            when_ms: 3,
            at: Some((-1, 2)),
            distance_m: 4,
            climb_m: 5,
            thumb: Some(Thumb {
                file: "t".into(),
                offset: 6,
                len: 7,
            }),
            image: Some((
                "c".into(),
                Vector {
                    scale: 0.5,
                    values: vec![1],
                },
            )),
            meta: Meta::default(),
        };
        Entry::Record(r)
    }

    /// `photo`, with every fact filters read.
    fn photo_with_meta() -> Entry {
        let Entry::Record(mut r) = photo() else {
            unreachable!()
        };
        r.extra.meta = Meta {
            places: vec![Place {
                town: Some("Lisbon".into()),
                region: None,
                region_local: Some("Lisboa".into()),
                country: Some("Portugal".into()),
                code: Some("PT".into()),
            }],
            camera: "Fuji X100".into(),
            width: 8,
            height: 6,
            selfie: true,
            pages: 2,
            activity: Activity::Ride,
            duration_ms: 9,
            added_ms: 10,
            added_by: "ann".into(),
            changed_by: "bo".into(),
        };
        Entry::Record(r)
    }

    fn round_trip(e: &Entry) -> Entry {
        let mut words = Words::default();
        let bytes = encode_entry(e, &mut words);
        decode_entry(&bytes, &words.into_list()).unwrap()
    }

    #[test]
    fn entries_round_trip() {
        let gone = Entry::Gone { ino: 3, at_ms: 4 };
        for e in [sample(), photo(), photo_with_meta(), gone] {
            assert_eq!(round_trip(&e), e);
        }
    }

    #[test]
    fn words_are_kept_once_per_segment() {
        let mut words = Words::default();
        let a = encode_entry(&sample(), &mut words);
        let b = encode_entry(&photo(), &mut words);
        let list = words.into_list();
        assert_eq!(list, ["hi"]);
        assert!(decode_entry(&a, &list).is_ok() && decode_entry(&b, &list).is_ok());
        assert!(decode_entry(&a, &[]).is_err(), "a word not in the list");
    }

    #[test]
    fn a_bad_entry_is_refused() {
        let mut words = Words::default();
        let mut bytes = encode_entry(&sample(), &mut words);
        let words = words.into_list();
        assert!(decode_entry(&bytes[..bytes.len() - 1], &words).is_err());
        bytes.push(0);
        assert!(decode_entry(&bytes, &words).is_err(), "bytes left over");
        bytes[0] = 9;
        assert!(decode_entry(&bytes, &words).is_err(), "another format");
    }

    /// The stored layout of an entry, pinned.
    #[test]
    fn an_entry_keeps_its_bytes() {
        let golden = "040007e807050907612f622e74787400016d01\
                      02686902010002013f00000002ff02\
                      020301ffffffff0000000204050101740607\
                      0101633f0000000101\
                      0101064c6973626f6e0001064c6973626f61\
                      0108506f72747567616c0102505409\
                      46756a6920583130300806010201090a\
                      03616e6e02626f";
        let mut words = Words::default();
        assert_eq!(
            raft5fs_wire::hex(&encode_entry(&photo_with_meta(), &mut words)),
            golden
        );
        assert_eq!(words.into_list(), ["hi"]);
        assert_eq!(
            raft5fs_wire::hex(&encode_entry(
                &Entry::Gone { ino: 3, at_ms: 4 },
                &mut Words::default()
            )),
            "04010304"
        );
    }

    /// Entries in format 3 still read, with no `Meta`.
    #[test]
    fn a_format_3_entry_still_reads() {
        let golden = "030007e807050907612f622e74787400016d01\
                      02686902010002013f00000002ff02\
                      020301ffffffff0000000204050101740607\
                      0101633f0000000101";
        let bytes = raft5fs_wire::from_hex(golden).unwrap();
        assert_eq!(decode_entry(&bytes, &["hi".into()]).unwrap(), photo());
        let gone = raft5fs_wire::from_hex("03010304").unwrap();
        assert_eq!(
            decode_entry(&gone, &[]).unwrap(),
            Entry::Gone { ino: 3, at_ms: 4 }
        );
    }

    #[test]
    fn activities_read_from_what_files_call_them() {
        assert_eq!(Activity::of("Biking"), Activity::Ride);
        assert_eq!(Activity::of("cycling"), Activity::Ride);
        assert_eq!(Activity::of("Running"), Activity::Run);
        assert_eq!(Activity::of("hiking"), Activity::Hike);
        assert_eq!(Activity::of("Walking"), Activity::Walk);
        assert_eq!(Activity::of("Swimming"), Activity::Other);
        assert_eq!(Activity::of(""), Activity::Unknown);
        for a in [Activity::Ride, Activity::Run, Activity::Other] {
            assert_eq!(Activity::from_byte(a.byte()), a);
        }
    }

    /// Entries in format 2 still read.
    #[test]
    fn a_format_2_entry_still_reads() {
        let golden = "0200000000000000000700000000000003e8\
                      00000000000000050000000000000009\
                      00000007612f622e74787400000000016d00000001\
                      0000000268690000000200000001000000026869000201\
                      3f00000000000002ff02\
                      00000002000000000000000301ffffffff00000002\
                      000000040000000501000000017400000000000000060000000701\
                      00000001633f0000000000000101";
        let bytes = raft5fs_wire::from_hex(golden).unwrap();
        assert_eq!(decode_entry(&bytes, &[]).unwrap(), photo());
        let gone = "0201000000000000000300000000000000\
                    04";
        let bytes = raft5fs_wire::from_hex(gone).unwrap();
        assert_eq!(
            decode_entry(&bytes, &[]).unwrap(),
            Entry::Gone { ino: 3, at_ms: 4 }
        );
    }

    /// Entries from before format 2 still read, with no `Extra`.
    #[test]
    fn a_format_1_entry_still_reads() {
        let golden = "0100000000000000000700000000000003e8\
                      00000000000000050000000000000009\
                      00000007612f622e74787400000000016d00000001\
                      0000000268690000000200000001000000026869000201\
                      3f00000000000002ff02";
        let bytes = raft5fs_wire::from_hex(golden).unwrap();
        assert_eq!(decode_entry(&bytes, &[]).unwrap(), sample());
        let gone = raft5fs_wire::from_hex("010100000000000000030000000000000004").unwrap();
        assert_eq!(
            decode_entry(&gone, &[]).unwrap(),
            Entry::Gone { ino: 3, at_ms: 4 }
        );
    }
}
