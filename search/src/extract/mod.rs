//! The text of a file, from its name and bytes, for the formats that pure
//! Rust can read the same way everywhere:
//!
//! - plain text and source code (by extension), including chat exports;
//! - HTML, without its tags, scripts and styles;
//! - Office Open XML (docx, pptx, xlsx) and OpenDocument (odt, odp, ods);
//! - GPS tracks and routes (GPX, TCX): their names, descriptions and
//!   activity, and with a places table, where they go;
//! - photos (JPEG, HEIC, PNG, WebP, TIFF): when, where and with what they
//!   were taken, from their EXIF data.
//!
//! PDF is not here: each client reads it with its own library (see
//! `Format::Pdf`). A file's format comes from its extension only.

mod markup;
mod office;
pub mod photo;
pub mod track;

use crate::geo::Places;
use crate::record::{DocKind, Extra};

/// The formats that the indexer knows, by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Plain,
    Html,
    Docx,
    Pptx,
    Xlsx,
    OpenDocument,
    Gpx,
    Tcx,
    /// JPEG, HEIC, PNG, WebP or TIFF: a photo, by its EXIF data.
    Photo,
    /// Read by the client's own PDF library, not by this crate.
    Pdf,
    Other,
}

/// Plain text and source code, as the web app's previews list them.
const PLAIN: &[&str] = &[
    "txt", "md", "markdown", "log", "csv", "tsv", "json", "yaml", "yml", "toml", "ini", "conf",
    "cfg", "env", "sh", "bash", "zsh", "py", "js", "mjs", "ts", "rs", "go", "c", "h", "cc", "cpp",
    "hpp", "java", "kt", "swift", "rb", "php", "pl", "lua", "sql", "css", "xml", "tex", "srt",
    "vtt", "eml", "org", "rst",
];

impl Format {
    pub fn of(name: &str) -> Format {
        let ext = name
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase())
            .unwrap_or_default();
        match ext.as_str() {
            "html" | "htm" | "xhtml" => Format::Html,
            "docx" | "docm" => Format::Docx,
            "pptx" => Format::Pptx,
            "xlsx" | "xlsm" => Format::Xlsx,
            "odt" | "odp" | "ods" => Format::OpenDocument,
            "gpx" => Format::Gpx,
            "tcx" => Format::Tcx,
            "pdf" => Format::Pdf,
            "jpg" | "jpeg" | "heic" | "heif" | "png" | "webp" | "tif" | "tiff" => Format::Photo,
            e if PLAIN.contains(&e) => Format::Plain,
            _ => Format::Other,
        }
    }
}

/// What a file's text is, and what sort of file it is.
#[derive(Debug, Clone, PartialEq)]
pub struct Extracted {
    pub kind: DocKind,
    pub text: String,
    /// What else the file says: when and where, for a track or a photo.
    pub extra: Extra,
    /// A photo's thumbnail (JPEG), which the client makes, not this crate:
    /// it needs an image decoder (see `THUMB_PX`).
    pub thumb: Option<Vec<u8>>,
}

/// The longest side of a photo's thumbnail, in pixels.
pub const THUMB_PX: u32 = 256;

/// The version of these readers, which records keep (`Extra::reader`).
/// It goes up when a reader finds more in a file than before, so that
/// files read by an older one are read again.
///
/// - 2: place names in tracks, and photos' dates, cameras and places.
pub const READER: u32 = 2;

/// The text of file `name`, or `None` if this crate does not read its
/// format (`Other` and `Pdf`) or the file is damaged.
pub fn extract(name: &str, bytes: &[u8]) -> Option<Extracted> {
    extract_with(name, bytes, None)
}

/// `extract`, with `places` to name where tracks and photos are.
pub fn extract_with(name: &str, bytes: &[u8], places: Option<&Places>) -> Option<Extracted> {
    let text = |text: String| {
        Some(Extracted {
            kind: DocKind::Text,
            text,
            extra: Extra {
                reader: READER,
                ..Extra::default()
            },
            thumb: None,
        })
    };
    match Format::of(name) {
        Format::Plain => text(plain(bytes)?),
        Format::Html => text(markup::html_text(&String::from_utf8_lossy(bytes))),
        Format::Docx => text(office::docx(bytes)?),
        Format::Pptx => text(office::pptx(bytes)?),
        Format::Xlsx => text(office::xlsx(bytes)?),
        Format::OpenDocument => text(office::open_document(bytes)?),
        Format::Gpx => Some(track::parse_gpx(bytes)?.extracted(places)),
        Format::Tcx => Some(track::parse_tcx(bytes)?.extracted(places)),
        Format::Photo => Some(photo::photo_info(bytes).extracted(places)),
        Format::Pdf | Format::Other => None,
    }
}

/// Bytes as text: UTF-8 (with a BOM or not) or UTF-16 with a BOM. Bytes
/// with NULs in them and no UTF-16 BOM are binary, not text.
fn plain(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return Some(utf16(rest, u16::from_le_bytes));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return Some(utf16(rest, u16::from_be_bytes));
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if bytes.contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn utf16(bytes: &[u8], read: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| read(*c)).collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_come_from_the_extension() {
        assert_eq!(Format::of("Notes.TXT"), Format::Plain);
        assert_eq!(Format::of("a.b/report.docx"), Format::Docx);
        assert_eq!(Format::of("ride.gpx"), Format::Gpx);
        assert_eq!(Format::of("scan.pdf"), Format::Pdf);
        assert_eq!(Format::of("photo.JPG"), Format::Photo);
        assert_eq!(Format::of("clip.mov"), Format::Other);
        assert_eq!(Format::of("Makefile"), Format::Other);
    }

    #[test]
    fn plain_text_in_its_encodings() {
        assert_eq!(plain(b"\xEF\xBB\xBFhi").unwrap(), "hi");
        assert_eq!(plain(&[0xFF, 0xFE, b'h', 0, b'i', 0]).unwrap(), "hi");
        assert_eq!(plain(&[0xFE, 0xFF, 0, b'h', 0, b'i']).unwrap(), "hi");
        assert!(plain(b"bin\0ary").is_none());
    }

    #[test]
    fn formats_this_crate_does_not_read_give_none() {
        assert!(extract("a.pdf", b"%PDF-1.7").is_none());
        assert!(extract("a.mov", b"\x00\x00").is_none());
        assert!(extract("a.docx", b"not a zip").is_none());
    }

    #[test]
    fn a_chat_export_is_plain_text() {
        let chat = "[12/06/2024, 09:15:02] Alice: Ride on Saturday?\n\
                    [12/06/2024, 09:16:40] Bob: Yes, the lake loop";
        let got = extract("WhatsApp Chat with Bob.txt", chat.as_bytes()).unwrap();
        assert_eq!(got.kind, DocKind::Text);
        assert!(got.text.contains("lake loop"));
    }
}
