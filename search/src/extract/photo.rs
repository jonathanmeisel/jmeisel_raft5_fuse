//! Photos: when and where each was taken, and with what, from its EXIF
//! data, so that "Lisbon 2024" finds the photos from there and then.
//!
//! - **When:** `DateTimeOriginal` (else `DateTime`), with its offset from
//!   UTC (`OffsetTimeOriginal`) if the camera recorded one; else read as
//!   UTC.
//! - **Where:** the GPS position, named with a places table (`geo`).
//! - **With what:** the camera's make and model, and whether it was a
//!   phone's front camera (its lens model says so).
//! - **Size:** in pixels, upright, from the EXIF size tags.
//!
//! A photo with no EXIF data is still a photo, found by its name.

use std::io::Cursor;

use exif::{Field, In, Reader, Tag, Value};

use super::{Extracted, READER};
use crate::extract::track::iso_ms;
use crate::geo::Places;
use crate::record::{DocKind, Extra, Meta};

/// What a photo's EXIF data says.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PhotoInfo {
    pub when_ms: u64,
    /// As the camera recorded it, "2024:06:12 09:15:02".
    pub when: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub camera: Option<String>,
    /// How the picture is turned (EXIF `Orientation`, 1 to 8; 1 or 0 for
    /// as stored), for a thumbnail to turn it upright.
    pub orientation: u16,
    /// Its size in pixels as stored (before `orientation`), or 0.
    pub width: u32,
    pub height: u32,
    /// Taken with a phone's front camera.
    pub selfie: bool,
}

fn ascii(f: &Field) -> Option<String> {
    match &f.value {
        Value::Ascii(parts) => parts
            .first()
            .map(|p| String::from_utf8_lossy(p).trim().to_string())
            .filter(|s| !s.is_empty()),
        _ => None,
    }
}

/// Degrees from an EXIF degrees-minutes-seconds triple, signed by its
/// reference (`S` and `W` are negative).
fn degrees(f: &Field, reference: Option<String>) -> Option<f64> {
    let Value::Rational(r) = &f.value else {
        return None;
    };
    let part = |i: usize| r.get(i).map(|x| x.to_f64()).filter(|x| x.is_finite());
    let d = part(0)? + part(1).unwrap_or(0.0) / 60.0 + part(2).unwrap_or(0.0) / 3600.0;
    let negative = matches!(reference.as_deref(), Some("S" | "W"));
    Some(if negative { -d } else { d })
}

/// What `bytes` (a JPEG, HEIC, PNG, WebP or TIFF file) says about itself;
/// all empty if it has no EXIF data.
pub fn photo_info(bytes: &[u8]) -> PhotoInfo {
    let Ok(exif) = Reader::new().read_from_container(&mut Cursor::new(bytes)) else {
        return PhotoInfo::default();
    };
    let get = |tag| exif.get_field(tag, In::PRIMARY);
    let text = |tag| get(tag).and_then(ascii);
    let mut info = PhotoInfo {
        when: text(Tag::DateTimeOriginal).or_else(|| text(Tag::DateTime)),
        ..PhotoInfo::default()
    };
    if let Some(when) = &info.when {
        // "2024:06:12 09:15:02" as ISO 8601, with any offset.
        let mut iso = when.replacen(':', "-", 2).replacen(' ', "T", 1);
        if let Some(offset) = text(Tag::OffsetTimeOriginal) {
            iso.push_str(&offset);
        }
        info.when_ms = iso_ms(&iso).unwrap_or(0);
    }
    info.lat = get(Tag::GPSLatitude).and_then(|f| degrees(f, text(Tag::GPSLatitudeRef)));
    info.lon = get(Tag::GPSLongitude).and_then(|f| degrees(f, text(Tag::GPSLongitudeRef)));
    // A position of exactly 0, 0 is a camera that had no fix.
    if info.lat == Some(0.0) && info.lon == Some(0.0) {
        info.lat = None;
        info.lon = None;
    }
    info.orientation = get(Tag::Orientation)
        .and_then(|f| f.value.get_uint(0))
        .map_or(0, |o| o as u16);
    let size = |tags: [Tag; 2]| {
        tags.iter()
            .find_map(|&t| get(t).and_then(|f| f.value.get_uint(0)))
            .unwrap_or(0)
    };
    info.width = size([Tag::PixelXDimension, Tag::ImageWidth]);
    info.height = size([Tag::PixelYDimension, Tag::ImageLength]);
    // Phones name the lens: "iPhone 12 front camera 2.71mm f/2.2".
    info.selfie = text(Tag::LensModel).is_some_and(|l| l.to_ascii_lowercase().contains("front"));
    let make = text(Tag::Make);
    let model = text(Tag::Model);
    info.camera = match (make, model) {
        // Models often repeat the make: "Canon Canon EOS R6" is one name.
        (Some(make), Some(model)) if model.starts_with(&make) => Some(model),
        (Some(make), Some(model)) => Some(format!("{make} {model}")),
        (make, model) => make.or(model),
    };
    info
}

impl PhotoInfo {
    /// The photo as raft5fs-search indexes it: words for when, where and
    /// with what, and its facts.
    pub fn extracted(&self, places: Option<&Places>) -> Extracted {
        let mut words = vec!["Photo".to_string()];
        if let Some(when) = &self.when
            && let Some(month) = month_year_of(when)
        {
            words.push(month);
        }
        let mut at_places = Vec::new();
        if let (Some(lat), Some(lon), Some(places)) = (self.lat, self.lon, places) {
            let place = places.locate(lat, lon);
            words.extend(place.names());
            if !place.names().is_empty() {
                at_places.push(place);
            }
        }
        if let Some(camera) = &self.camera {
            words.push(camera.clone());
        }
        let units = |deg: f64| (deg * 1e4).round() as i32;
        let (width, height) = self.upright_size();
        Extracted {
            kind: DocKind::Photo,
            text: words.join(", "),
            extra: Extra {
                reader: READER,
                when_ms: self.when_ms,
                at: self.lat.zip(self.lon).map(|(a, o)| (units(a), units(o))),
                meta: Meta {
                    places: at_places,
                    camera: self.camera.clone().unwrap_or_default(),
                    width,
                    height,
                    selfie: self.selfie,
                    ..Meta::default()
                },
                ..Extra::default()
            },
            thumb: None,
        }
    }

    /// Its size as it is seen: orientations 5 to 8 turn it a quarter.
    pub fn upright_size(&self) -> (u32, u32) {
        if (5..=8).contains(&self.orientation) {
            (self.height, self.width)
        } else {
            (self.width, self.height)
        }
    }
}

pub(crate) const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// "June 2024" from "2024:06:12 09:15:02".
fn month_year_of(when: &str) -> Option<String> {
    let year: u32 = when.get(0..4)?.parse().ok()?;
    let month: usize = when.get(5..7)?.parse().ok()?;
    Some(format!("{} {year}", MONTHS.get(month.checked_sub(1)?)?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A little-endian TIFF block with the given entries in IFD0, the Exif
    /// IFD and the GPS IFD: (tag, type, count, value bytes).
    fn tiff(
        ifd0: &[(u16, u16, u32, Vec<u8>)],
        exif: &[(u16, u16, u32, Vec<u8>)],
        gps: &[(u16, u16, u32, Vec<u8>)],
    ) -> Vec<u8> {
        // Lays the three IFDs out one after another, each value that
        // doesn't fit in 4 bytes after its IFD.
        fn ifd(entries: &[(u16, u16, u32, Vec<u8>)], at: u32, links: &[(u16, u32)]) -> Vec<u8> {
            let n = entries.len() + links.len();
            let mut head = (n as u16).to_le_bytes().to_vec();
            let mut tail = Vec::new();
            let data_at = at + 2 + 12 * n as u32 + 4;
            let mut all: Vec<(u16, u16, u32, Vec<u8>)> = entries.to_vec();
            for &(tag, offset) in links {
                all.push((tag, 4, 1, offset.to_le_bytes().to_vec()));
            }
            all.sort_by_key(|e| e.0);
            for (tag, ty, count, value) in all {
                head.extend_from_slice(&tag.to_le_bytes());
                head.extend_from_slice(&ty.to_le_bytes());
                head.extend_from_slice(&count.to_le_bytes());
                if value.len() <= 4 {
                    let mut v = value.clone();
                    v.resize(4, 0);
                    head.extend_from_slice(&v);
                } else {
                    head.extend_from_slice(&(data_at + tail.len() as u32).to_le_bytes());
                    tail.extend_from_slice(&value);
                    if tail.len() % 2 == 1 {
                        tail.push(0);
                    }
                }
            }
            head.extend_from_slice(&0u32.to_le_bytes());
            head.extend(tail);
            head
        }
        // Sizes first, to know the offsets.
        let size = |e: &[(u16, u16, u32, Vec<u8>)], links: usize| {
            let data: usize = e
                .iter()
                .filter(|x| x.3.len() > 4)
                .map(|x| x.3.len().div_ceil(2) * 2)
                .sum();
            2 + 12 * (e.len() + links) + 4 + data
        };
        let at0 = 8u32;
        let at_exif = at0 + size(ifd0, 2) as u32;
        let at_gps = at_exif + size(exif, 0) as u32;
        let mut out = b"II\x2a\x00".to_vec();
        out.extend_from_slice(&at0.to_le_bytes());
        out.extend(ifd(ifd0, at0, &[(0x8769, at_exif), (0x8825, at_gps)]));
        out.extend(ifd(exif, at_exif, &[]));
        out.extend(ifd(gps, at_gps, &[]));
        out
    }

    fn ascii_value(s: &str) -> (u16, u32, Vec<u8>) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        (2, v.len() as u32, v)
    }

    fn rationals(parts: &[(u32, u32)]) -> (u16, u32, Vec<u8>) {
        let mut v = Vec::new();
        for (n, d) in parts {
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(&d.to_le_bytes());
        }
        (5, parts.len() as u32, v)
    }

    /// A GPS position as EXIF keeps it: degrees, minutes and seconds × 100,
    /// north or south; the same, east or west.
    type Gps = ((u32, u32, u32), char, (u32, u32, u32), char);

    /// `jpeg` with an Exif block saying it was taken at `when` (with
    /// `offset`), at `lat`/`lon` (degrees, minutes, seconds × 100), with
    /// `make` and `model`.
    pub(crate) fn with_exif(
        jpeg: &[u8],
        when: &str,
        offset: Option<&str>,
        gps: Option<Gps>,
        make: &str,
        model: &str,
    ) -> Vec<u8> {
        let e = |tag: u16, (ty, count, v): (u16, u32, Vec<u8>)| (tag, ty, count, v);
        let ifd0 = vec![e(0x010f, ascii_value(make)), e(0x0110, ascii_value(model))];
        let mut exif = vec![e(0x9003, ascii_value(when))];
        if let Some(o) = offset {
            exif.push(e(0x9011, ascii_value(o)));
        }
        let gps = match gps {
            Some(((d, m, s), ns, (d2, m2, s2), ew)) => vec![
                e(1, ascii_value(&ns.to_string())),
                e(2, rationals(&[(d, 1), (m, 1), (s, 100)])),
                e(3, ascii_value(&ew.to_string())),
                e(4, rationals(&[(d2, 1), (m2, 1), (s2, 100)])),
            ],
            None => Vec::new(),
        };
        let block = tiff(&ifd0, &exif, &gps);
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend(block);
        let mut out = jpeg[..2].to_vec();
        out.extend_from_slice(&[0xff, 0xe1]);
        out.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
        out.extend(app1);
        out.extend_from_slice(&jpeg[2..]);
        out
    }

    pub(crate) const LAKE: &[u8] = include_bytes!("testdata/lake.jpg");

    #[test]
    fn a_photo_says_when_where_and_with_what() {
        // Lisbon: 38°43'20.28" N, 9°8'21.48" W.
        let bytes = with_exif(
            LAKE,
            "2024:06:12 11:15:02",
            Some("+02:00"),
            Some(((38, 43, 2028), 'N', (9, 8, 2148), 'W')),
            "Apple",
            "iPhone 13",
        );
        let info = photo_info(&bytes);
        assert_eq!(info.when_ms, iso_ms("2024-06-12T09:15:02Z").unwrap());
        assert!((info.lat.unwrap() - 38.7223).abs() < 1e-3, "{info:?}");
        assert!((info.lon.unwrap() + 9.1393).abs() < 1e-3, "{info:?}");
        assert_eq!(info.camera.as_deref(), Some("Apple iPhone 13"));
        let places = Places::decode(include_bytes!("../../data/places.bin")).unwrap();
        let got = info.extracted(Some(&places));
        assert_eq!(got.kind, DocKind::Photo);
        for want in ["June 2024", "Lisbon", "Portugal", "iPhone 13"] {
            assert!(got.text.contains(want), "{want} in {}", got.text);
        }
        assert_eq!(got.extra.at, Some((387_223, -91_393)));
        let meta = &got.extra.meta;
        assert_eq!(meta.camera, "Apple iPhone 13");
        assert_eq!(meta.places.len(), 1);
        assert_eq!(meta.places[0].town.as_deref(), Some("Lisbon"));
        assert_eq!(meta.places[0].code.as_deref(), Some("PT"));
    }

    #[test]
    fn a_photo_says_its_size_and_front_camera() {
        let e = |tag: u16, (ty, count, v): (u16, u32, Vec<u8>)| (tag, ty, count, v);
        let long = |n: u32| (4u16, 1u32, n.to_le_bytes().to_vec());
        let short = |n: u16| (3u16, 1u32, n.to_le_bytes().to_vec());
        let ifd0 = vec![e(0x0112, short(6))];
        let exif = vec![
            e(0xa002, long(4032)),
            e(0xa003, long(3024)),
            e(0xa434, ascii_value("iPhone 12 front camera 2.71mm f/2.2")),
        ];
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend(tiff(&ifd0, &exif, &[]));
        let mut bytes = LAKE[..2].to_vec();
        bytes.extend_from_slice(&[0xff, 0xe1]);
        bytes.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
        bytes.extend(app1);
        bytes.extend_from_slice(&LAKE[2..]);
        let info = photo_info(&bytes);
        assert_eq!((info.width, info.height), (4032, 3024));
        assert!(info.selfie);
        let meta = info.extracted(None).extra.meta;
        assert_eq!((meta.width, meta.height), (3024, 4032), "turned upright");
        assert!(meta.selfie);
    }

    #[test]
    fn a_photo_without_gps_or_exif() {
        let bytes = with_exif(
            LAKE,
            "2023:12:24 18:00:00",
            None,
            None,
            "Canon",
            "Canon EOS R6",
        );
        let info = photo_info(&bytes);
        assert_eq!(info.when_ms, iso_ms("2023-12-24T18:00:00Z").unwrap());
        assert_eq!((info.lat, info.lon), (None, None));
        assert_eq!(
            info.camera.as_deref(),
            Some("Canon EOS R6"),
            "the make once"
        );
        assert_eq!(photo_info(LAKE), PhotoInfo::default());
        assert_eq!(PhotoInfo::default().extracted(None).text, "Photo");
    }

    /// Writes the web app's photo fixture (webapp/tests/fixtures/lisbon.jpg):
    /// the lake picture, taken in Lisbon in June 2024 on an iPhone. Run with
    /// --ignored to make it again.
    #[test]
    #[ignore = "writes a fixture"]
    fn write_the_web_apps_photo_fixture() {
        let bytes = with_exif(
            LAKE,
            "2024:06:12 11:15:02",
            Some("+02:00"),
            Some(((38, 43, 2028), 'N', (9, 8, 2148), 'W')),
            "Apple",
            "iPhone 13",
        );
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../webapp/tests/fixtures/lisbon.jpg"
        );
        std::fs::write(path, bytes).unwrap();
    }
}
