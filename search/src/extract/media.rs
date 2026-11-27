//! Videos and recordings: when and where they were made and how long
//! they last, from their headers alone, so that indexing a video doesn't
//! download it.
//!
//! - **MP4 and QuickTime** (mp4, mov, m4v, 3gp, m4a): the `moov` box.
//!   Its `mvhd` says how long and when; a video track's `tkhd` how big
//!   (turned by its matrix); and the place, from Apple's
//!   `com.apple.quicktime.location.ISO6709` key or the `©xyz` box that
//!   Android writes. Apple's `com.apple.quicktime.creationdate` gives the
//!   time with its offset, which `mvhd` (UTC) lacks.
//! - **FLAC:** `STREAMINFO`. **WAV:** `fmt ` and the `data` chunk's size.
//!   **MP3:** a Xing or VBRI header's frame count, else the bit rate and
//!   the file's size.
//! - Other formats (Ogg, Matroska, AVI) are only named: video or audio.
//!
//! `moov` may be at the start of the file or at its end, after the media.
//! The caller finds it with `next_box` over the top-level boxes, reading
//! only their headers, and passes it here.

use super::{Extracted, READER};
use crate::extract::track::iso_ms;
use crate::geo::Places;
use crate::record::{DocKind, Extra, Meta};

/// Seconds from 1904-01-01 (MP4's epoch) to 1970-01-01.
const MP4_EPOCH: u64 = 2_082_844_800;
/// The most of a `moov` box that is read: a larger one is not one.
pub const MOOV_MAX: u64 = 64 << 20;
/// How much of the start of a file is read.
pub const HEAD: u64 = 256 << 10;

/// A top-level box: its type, where it starts, how long it is (to the
/// file's end if its header says 0), and how long its header is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxAt {
    pub kind: [u8; 4],
    pub offset: u64,
    pub len: u64,
    pub head: u64,
}

/// The box whose header starts `bytes` (at least 16 bytes, or what is
/// left of the file), at `offset` in a file of `size` bytes.
pub fn next_box(bytes: &[u8], offset: u64, size: u64) -> Option<BoxAt> {
    let small = u64::from(u32::from_be_bytes(bytes.get(0..4)?.try_into().ok()?));
    let kind: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
    let (len, head) = match small {
        0 => (size.checked_sub(offset)?, 8),
        1 => (u64::from_be_bytes(bytes.get(8..16)?.try_into().ok()?), 16),
        n => (n, 8),
    };
    (len >= head && offset.checked_add(len)? <= size).then_some(BoxAt {
        kind,
        offset,
        len,
        head,
    })
}

/// What the headers of a media file say.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MediaInfo {
    pub when_ms: u64,
    pub duration_ms: u64,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub width: u32,
    pub height: u32,
}

/// The boxes directly inside `bytes`: (type, body).
fn children(bytes: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= bytes.len() {
        let size = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let kind: [u8; 4] = bytes[at + 4..at + 8].try_into().unwrap();
        let (head, len) = match size {
            0 => (8, bytes.len() - at),
            1 => {
                let Some(b) = bytes.get(at + 8..at + 16) else {
                    break;
                };
                (16, u64::from_be_bytes(b.try_into().unwrap()) as usize)
            }
            n => (8, n),
        };
        if len < head || at + len > bytes.len() {
            break;
        }
        out.push((kind, &bytes[at + head..at + len]));
        at += len;
    }
    out
}

fn child<'a>(bytes: &'a [u8], kind: &[u8; 4]) -> Option<&'a [u8]> {
    children(bytes)
        .into_iter()
        .find(|(k, _)| k == kind)
        .map(|(_, b)| b)
}

fn be32(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from(u32::from_be_bytes(
        b.get(at..at + 4)?.try_into().ok()?,
    )))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// An ISO 6709 point, "+38.7223-009.1393+010.000/": latitude, longitude.
fn iso6709(s: &str) -> Option<(f64, f64)> {
    let s = s.trim().trim_end_matches('/');
    let mut parts = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices().skip(1) {
        if c == '+' || c == '-' {
            parts.push(&s[start..i]);
            start = i;
        }
    }
    parts.push(&s[start..]);
    let lat: f64 = parts.first()?.parse().ok()?;
    let lon: f64 = parts.get(1)?.parse().ok()?;
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) && (lat, lon) != (0.0, 0.0))
        .then_some((lat, lon))
}

/// Apple's metadata: `meta` with `keys` and `ilst`. Each named key's
/// UTF-8 value.
fn quicktime_keys(meta: &[u8]) -> Vec<(String, String)> {
    // An ISO `meta` is a full box: version and flags first.
    let meta = if meta.get(0..4) == Some(&[0, 0, 0, 0]) && child(&meta[4..], b"hdlr").is_some() {
        &meta[4..]
    } else {
        meta
    };
    let Some(keys) = child(meta, b"keys") else {
        return Vec::new();
    };
    let Some(ilst) = child(meta, b"ilst") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut at = 8usize;
    let count = be32(keys, 4).unwrap_or(0);
    for _ in 0..count {
        let Some(size) = be32(keys, at).map(|s| s as usize) else {
            break;
        };
        let Some(name) = keys.get(at + 8..at + size) else {
            break;
        };
        names.push(String::from_utf8_lossy(name).into_owned());
        at += size.max(8);
    }
    let mut out = Vec::new();
    for (kind, item) in children(ilst) {
        let index = u32::from_be_bytes(kind) as usize;
        let (Some(name), Some(data)) = (
            index.checked_sub(1).and_then(|i| names.get(i)),
            child(item, b"data"),
        ) else {
            continue;
        };
        // Type 1 is UTF-8, after the type and locale.
        if be32(data, 0) == Some(1)
            && let Some(v) = data.get(8..)
        {
            out.push((name.clone(), String::from_utf8_lossy(v).into_owned()));
        }
    }
    out
}

/// What an MP4 or QuickTime `moov` box's body says.
pub fn moov_info(moov: &[u8]) -> MediaInfo {
    let mut info = MediaInfo::default();
    if let Some(mvhd) = child(moov, b"mvhd") {
        let (created, scale, duration) = if mvhd.first() == Some(&1) {
            (be64(mvhd, 4), be32(mvhd, 20), be64(mvhd, 24))
        } else {
            (be32(mvhd, 4), be32(mvhd, 12), be32(mvhd, 16))
        };
        if let (Some(scale), Some(d)) = (scale.filter(|s| *s > 0), duration) {
            info.duration_ms = d.saturating_mul(1000) / scale;
        }
        if let Some(c) = created.filter(|c| *c > MP4_EPOCH) {
            info.when_ms = (c - MP4_EPOCH) * 1000;
        }
    }
    for (kind, trak) in children(moov) {
        if &kind != b"trak" {
            continue;
        }
        let Some(tkhd) = child(trak, b"tkhd") else {
            continue;
        };
        let at = if tkhd.first() == Some(&1) {
            4 + 32
        } else {
            4 + 20
        };
        // Reserved 8, layer, group, volume, reserved, then the matrix.
        let matrix = at + 16;
        let (Some(w), Some(h)) = (be32(tkhd, matrix + 36), be32(tkhd, matrix + 40)) else {
            continue;
        };
        let (w, h) = ((w >> 16) as u32, (h >> 16) as u32);
        if w == 0 || h == 0 {
            continue;
        }
        // A quarter turn: the matrix's first number is 0.
        let a = be32(tkhd, matrix).unwrap_or(0x10000);
        (info.width, info.height) = if a == 0 { (h, w) } else { (w, h) };
        break;
    }
    let mut metas: Vec<&[u8]> = child(moov, b"meta").into_iter().collect();
    if let Some(udta) = child(moov, b"udta") {
        metas.extend(child(udta, b"meta"));
        // Android: "©xyz", a length, a language, then ISO 6709.
        if let Some(xyz) = child(udta, &[0xa9, b'x', b'y', b'z'])
            && let Some(s) = xyz.get(4..).map(String::from_utf8_lossy)
            && let Some((lat, lon)) = iso6709(&s)
        {
            (info.lat, info.lon) = (Some(lat), Some(lon));
        }
    }
    for meta in metas {
        for (key, value) in quicktime_keys(meta) {
            match key.as_str() {
                "com.apple.quicktime.location.ISO6709" => {
                    if let Some((lat, lon)) = iso6709(&value) {
                        (info.lat, info.lon) = (Some(lat), Some(lon));
                    }
                }
                "com.apple.quicktime.creationdate" => {
                    if let Some(ms) = iso_ms(&value) {
                        info.when_ms = ms;
                    }
                }
                _ => {}
            }
        }
    }
    info
}

/// How long a FLAC file lasts, from its head.
fn flac_ms(head: &[u8]) -> Option<u64> {
    if head.get(0..4)? != b"fLaC" || head.get(4)? & 0x7f != 0 {
        return None;
    }
    let s = head.get(8..8 + 34)?;
    let rate = (u64::from(s[10]) << 12) | (u64::from(s[11]) << 4) | (u64::from(s[12]) >> 4);
    let samples = (u64::from(s[13] & 0x0f) << 32) | be32(s, 14)?;
    (rate > 0).then(|| samples * 1000 / rate)
}

/// How long a WAV file lasts, from its head.
fn wav_ms(head: &[u8]) -> Option<u64> {
    if head.get(0..4)? != b"RIFF" || head.get(8..12)? != b"WAVE" {
        return None;
    }
    let le32 = |at: usize| {
        Some(u64::from(u32::from_le_bytes(
            head.get(at..at + 4)?.try_into().ok()?,
        )))
    };
    let mut at = 12;
    let mut rate = None;
    while at + 8 <= head.len() {
        let id = &head[at..at + 4];
        let len = le32(at + 4)?;
        if id == b"fmt " {
            rate = le32(at + 8 + 8);
        } else if id == b"data" {
            return rate.filter(|r| *r > 0).map(|r| len * 1000 / r);
        }
        at += 8 + len as usize + (len as usize & 1);
    }
    None
}

/// How long an MP3 file of `size` bytes lasts, from its head.
fn mp3_ms(head: &[u8], size: u64) -> Option<u64> {
    let mut at = 0usize;
    if head.get(0..3)? == b"ID3" {
        let s = head.get(6..10)?;
        let len = s
            .iter()
            .fold(0usize, |n, b| (n << 7) | usize::from(b & 0x7f));
        at = 10 + len;
    }
    let start = at;
    while at + 4 <= head.len() && !(head[at] == 0xff && head[at + 1] & 0xe0 == 0xe0) {
        at += 1;
    }
    let h = head.get(at..at + 4)?;
    let version = (h[1] >> 3) & 3; // 3: MPEG 1, 2: MPEG 2, 0: MPEG 2.5
    let layer = (h[1] >> 1) & 3; // 1: layer III
    if layer != 1 || version == 1 {
        return None;
    }
    const RATES_1: [u64; 15] = [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ];
    const RATES_2: [u64; 15] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    let index = usize::from(h[2] >> 4);
    let kbps = if version == 3 {
        RATES_1.get(index)?
    } else {
        RATES_2.get(index)?
    };
    let rate = [44_100u64, 48_000, 32_000].get(usize::from((h[2] >> 2) & 3))?
        / match version {
            3 => 1,
            2 => 2,
            _ => 4,
        };
    let per_frame: u64 = if version == 3 { 1152 } else { 576 };
    let mono = h[3] >> 6 == 3;
    let side = match (version == 3, mono) {
        (true, false) => 32,
        (true, true) => 17,
        (false, false) => 17,
        (false, true) => 9,
    };
    let x = at + 4 + side;
    if matches!(head.get(x..x + 4), Some(b"Xing" | b"Info"))
        && head[x + 7] & 1 == 1
        && let Some(frames) = be32(head, x + 8)
    {
        return Some(frames * per_frame * 1000 / rate);
    }
    if head.get(at + 36..at + 40) == Some(b"VBRI")
        && let Some(frames) = be32(head, at + 36 + 14)
    {
        return Some(frames * per_frame * 1000 / rate);
    }
    (*kbps > 0).then(|| (size - start as u64) * 8 / kbps)
}

/// Whether file `name` is MP4 or QuickTime, whose `moov` box says the
/// most.
pub fn has_boxes(name: &str) -> bool {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    matches!(ext.as_deref(), Some("mp4" | "mov" | "m4v" | "3gp" | "m4a"))
}

/// What kind of media a file name says, if any.
pub fn kind_of(format: super::Format) -> Option<DocKind> {
    match format {
        super::Format::Video => Some(DocKind::Video),
        super::Format::Audio => Some(DocKind::Audio),
        _ => None,
    }
}

/// "3 min", "1 h 5 min", "45 s".
fn length_words(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min", (s + 30) / 60),
        _ => format!("{} h {} min", s / 3600, (s % 3600) / 60),
    }
}

/// The media file `name`, of `size` bytes, from its `head` (the first
/// `HEAD` bytes) and, for MP4 and QuickTime, its `moov` box's body.
pub fn extracted(
    name: &str,
    size: u64,
    head: &[u8],
    moov: Option<&[u8]>,
    places: Option<&Places>,
) -> Option<Extracted> {
    let kind = kind_of(super::Format::of(name))?;
    let mut info = moov.map(moov_info).unwrap_or_default();
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    if info.duration_ms == 0 {
        info.duration_ms = match ext.as_str() {
            "flac" => flac_ms(head),
            "wav" => wav_ms(head),
            "mp3" => mp3_ms(head, size),
            _ => None,
        }
        .unwrap_or(0);
    }
    let mut words = vec![
        if kind == DocKind::Video {
            "Video"
        } else {
            "Recording"
        }
        .to_string(),
    ];
    if info.when_ms > 0 {
        let day = (info.when_ms / 86_400_000) as i64;
        let (y, m, _) = crate::filter::civil_from_days(day);
        words.push(format!("{} {y}", super::photo::MONTHS[m as usize - 1]));
    }
    let mut at_places = Vec::new();
    if let (Some(lat), Some(lon), Some(places)) = (info.lat, info.lon, places) {
        let place = places.locate(lat, lon);
        words.extend(place.names());
        if !place.names().is_empty() {
            at_places.push(place);
        }
    }
    if info.duration_ms > 0 {
        words.push(length_words(info.duration_ms));
    }
    let units = |deg: f64| (deg * 1e4).round() as i32;
    Some(Extracted {
        kind,
        text: words.join(", "),
        extra: Extra {
            reader: READER,
            when_ms: info.when_ms,
            at: info.lat.zip(info.lon).map(|(a, o)| (units(a), units(o))),
            meta: Meta {
                places: at_places,
                width: info.width,
                height: info.height,
                duration_ms: info.duration_ms,
                ..Meta::default()
            },
            ..Extra::default()
        },
        thumb: None,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn boxed(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out
    }

    /// A `moov` body: 90 s long, made 2024-06-12 09:15:02 UTC, a 1920 by
    /// 1080 video track turned a quarter, and Apple's place and date keys.
    pub(crate) fn moov() -> Vec<u8> {
        let created = 1_718_183_702 + MP4_EPOCH;
        let mut mvhd = vec![0, 0, 0, 0];
        mvhd.extend((created as u32).to_be_bytes());
        mvhd.extend((created as u32).to_be_bytes());
        mvhd.extend(600u32.to_be_bytes());
        mvhd.extend((90 * 600u32).to_be_bytes());
        mvhd.extend([0u8; 80]);
        let mut tkhd = vec![0, 0, 0, 7];
        tkhd.extend([0u8; 20]);
        tkhd.extend([0u8; 16]);
        // A quarter turn: 0 1 0 / -1 0 0 / 0 0 1.
        for n in [0u32, 0x10000, 0, 0xffff_0000, 0, 0, 0, 0, 0x4000_0000] {
            tkhd.extend(n.to_be_bytes());
        }
        tkhd.extend((1920u32 << 16).to_be_bytes());
        tkhd.extend((1080u32 << 16).to_be_bytes());
        let trak = boxed(b"trak", &boxed(b"tkhd", &tkhd));
        let key = |name: &str| {
            let mut k = ((name.len() + 8) as u32).to_be_bytes().to_vec();
            k.extend_from_slice(b"mdta");
            k.extend_from_slice(name.as_bytes());
            k
        };
        let mut keys = vec![0, 0, 0, 0, 0, 0, 0, 2];
        keys.extend(key("com.apple.quicktime.location.ISO6709"));
        keys.extend(key("com.apple.quicktime.creationdate"));
        let item = |n: u32, v: &str| {
            let mut data = 1u32.to_be_bytes().to_vec();
            data.extend([0u8; 4]);
            data.extend_from_slice(v.as_bytes());
            boxed(&n.to_be_bytes(), &boxed(b"data", &data))
        };
        let mut ilst = item(1, "+38.7223-009.1393+010.000/");
        ilst.extend(item(2, "2024-06-12T11:15:02+0200"));
        let mut meta = boxed(b"hdlr", &[0u8; 24]);
        meta.extend(boxed(b"keys", &keys));
        meta.extend(boxed(b"ilst", &ilst));
        let mut out = boxed(b"mvhd", &mvhd);
        out.extend(trak);
        out.extend(boxed(b"meta", &meta));
        out
    }

    #[test]
    fn a_quicktime_movie_says_when_where_how_long_and_how_big() {
        let info = moov_info(&moov());
        assert_eq!(info.duration_ms, 90_000);
        assert_eq!(info.when_ms, iso_ms("2024-06-12T09:15:02Z").unwrap());
        assert!((info.lat.unwrap() - 38.7223).abs() < 1e-6);
        assert!((info.lon.unwrap() + 9.1393).abs() < 1e-6);
        assert_eq!((info.width, info.height), (1080, 1920), "turned upright");
    }

    #[test]
    fn android_writes_its_place_in_udta() {
        let mut xyz = vec![0, 18, 0x15, 0xc7];
        xyz.extend_from_slice(b"+40.4168-003.7038/");
        let udta = boxed(b"udta", &boxed(&[0xa9, b'x', b'y', b'z'], &xyz));
        let info = moov_info(&udta);
        assert!((info.lat.unwrap() - 40.4168).abs() < 1e-6);
        assert!((info.lon.unwrap() + 3.7038).abs() < 1e-6);
    }

    #[test]
    fn top_level_boxes_are_found_by_their_headers() {
        let mut file = boxed(b"ftyp", b"qt  ");
        let mdat_at = file.len() as u64;
        file.extend(boxed(b"mdat", &[7u8; 1000]));
        let moov_at = file.len() as u64;
        file.extend(boxed(b"moov", &moov()));
        let size = file.len() as u64;
        let mut at = 0;
        let mut seen = Vec::new();
        while let Some(b) = next_box(&file[at as usize..], at, size) {
            seen.push((b.kind, b.offset));
            at += b.len;
        }
        assert_eq!(
            seen,
            [(*b"ftyp", 0), (*b"mdat", mdat_at), (*b"moov", moov_at)]
        );
        assert_eq!(
            next_box(&[0, 0, 0, 200, b'm', b'o', b'o', b'v'], 0, 100),
            None,
            "past the end"
        );
    }

    #[test]
    fn a_video_is_found_by_its_words() {
        let places = Places::decode(include_bytes!("../../data/places.bin")).unwrap();
        let got = extracted("IMG_0001.MOV", 1 << 30, &[], Some(&moov()), Some(&places)).unwrap();
        assert_eq!(got.kind, DocKind::Video);
        for want in ["Video", "June 2024", "Lisbon", "Portugal", "2 min"] {
            assert!(got.text.contains(want), "{want} in {}", got.text);
        }
        assert_eq!(got.extra.meta.duration_ms, 90_000);
        assert_eq!(got.extra.meta.places[0].code.as_deref(), Some("PT"));
    }

    #[test]
    fn audio_lengths_from_heads() {
        // FLAC: 44.1 kHz, 441,000 samples: 10 s.
        let mut flac = b"fLaC".to_vec();
        flac.extend([0x80, 0, 0, 34]);
        let mut info = vec![0u8; 34];
        let rate: u32 = 44_100;
        info[10] = (rate >> 12) as u8;
        info[11] = (rate >> 4) as u8;
        info[12] = ((rate & 0xf) << 4) as u8 | 0x02;
        info[14..18].copy_from_slice(&441_000u32.to_be_bytes());
        flac.extend(info);
        assert_eq!(flac_ms(&flac), Some(10_000));
        // WAV: 8 kHz, 8-bit mono, 16,000 bytes: 2 s.
        let mut wav = b"RIFF\0\0\0\0WAVEfmt ".to_vec();
        wav.extend(16u32.to_le_bytes());
        wav.extend([1, 0, 1, 0]);
        wav.extend(8000u32.to_le_bytes());
        wav.extend(8000u32.to_le_bytes());
        wav.extend([1, 0, 8, 0]);
        wav.extend(b"data");
        wav.extend(16_000u32.to_le_bytes());
        assert_eq!(wav_ms(&wav), Some(2000));
        // MP3, MPEG 1 layer III, 128 kb/s, 44.1 kHz, no Xing: by its size.
        let mp3 = [0xff, 0xfb, 0x90, 0x00, 0, 0, 0, 0];
        assert_eq!(mp3_ms(&mp3, 1_600_000), Some(100_000));
        let got = extracted("song.mp3", 1_600_000, &mp3, None, None).unwrap();
        assert_eq!(got.kind, DocKind::Audio);
        assert_eq!(got.extra.meta.duration_ms, 100_000);
    }

    /// A small QuickTime file, as phones write them: `ftyp`, the media,
    /// then `moov` at the end.
    pub(crate) fn movie() -> Vec<u8> {
        let mut file = boxed(b"ftyp", b"qt  \0\0\0\0qt  ");
        file.extend(boxed(b"mdat", &[0u8; 4096]));
        file.extend(boxed(b"moov", &moov()));
        file
    }

    /// Writes the fixtures that client and web app tests upload
    /// (search/src/extract/testdata/lisbon.mov, and the web app's copy):
    /// 90 s, filmed in Lisbon in June 2024. Run with --ignored to make
    /// them again.
    #[test]
    #[ignore = "writes fixtures"]
    fn write_the_movie_fixtures() {
        let root = env!("CARGO_MANIFEST_DIR");
        for path in [
            format!("{root}/src/extract/testdata/lisbon.mov"),
            format!("{root}/../webapp/tests/fixtures/lisbon.mov"),
        ] {
            std::fs::write(path, movie()).unwrap();
        }
    }

    #[test]
    fn the_movie_fixture_is_current() {
        assert_eq!(include_bytes!("testdata/lisbon.mov").as_slice(), movie());
    }

    #[test]
    fn iso_6709_points_read() {
        assert_eq!(
            iso6709("+38.7223-009.1393+010.000/"),
            Some((38.7223, -9.1393))
        );
        assert_eq!(iso6709("-33.8688+151.2093/"), Some((-33.8688, 151.2093)));
        assert_eq!(iso6709("+00.0000+000.0000/"), None, "no fix");
        assert_eq!(iso6709("nonsense"), None);
    }
}
