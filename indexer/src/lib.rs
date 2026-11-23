//! Search indexing for native clients: `Native` reads everything that
//! raft5fs-search reads, and PDF too; `embed` runs the embedding model.
//!
//! PDF parsing is slow and can panic on damaged files, so it runs on a
//! blocking thread, and a panic there only means "no text".

pub mod clip;
pub mod embed;
pub mod manifest;

use std::sync::Arc;

use raft5fs_client::indexer::{BuiltIn, Extract, Tools};
use raft5fs_search::extract::{Extracted, Format};
use raft5fs_search::geo::Places;
use raft5fs_search::record::DocKind;

/// The most bytes of a PDF that are read.
const PDF_MAX: u64 = 64 << 20;

/// The places table, built into native clients (5 MB; the web app fetches
/// it apart, only when it indexes).
static PLACES_BIN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../search/data/places.bin"
));

/// The places table, read the first time a track or photo needs it.
pub fn places() -> &'static Places {
    static PLACES: std::sync::OnceLock<Places> = std::sync::OnceLock::new();
    PLACES.get_or_init(|| Places::decode(PLACES_BIN).expect("the built-in places table reads"))
}

/// The text reader for mounts, WebDAV servers and the CLI.
pub struct Native;

impl Extract for Native {
    fn reads(&self, name: &str) -> u64 {
        match Format::of(name) {
            Format::Pdf => PDF_MAX,
            _ => BuiltIn.reads(name),
        }
    }

    fn extract<'a>(
        &'a self,
        name: &'a str,
        bytes: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<Extracted>> + Send + 'a>> {
        Box::pin(async move {
            match Format::of(name) {
                Format::Pdf => {}
                Format::Gpx | Format::Tcx => {
                    let places = places();
                    return raft5fs_search::extract::extract_with(name, &bytes, Some(places));
                }
                Format::Photo => {
                    let name = name.to_string();
                    // Decoding a photo takes a while: not on the runtime.
                    return tokio::task::spawn_blocking(move || {
                        let mut got =
                            raft5fs_search::extract::extract_with(&name, &bytes, Some(places()))?;
                        let turned = raft5fs_search::extract::photo::photo_info(&bytes).orientation;
                        got.thumb = thumbnail(&bytes, turned);
                        Some(got)
                    })
                    .await
                    .ok()
                    .flatten();
                }
                _ => return BuiltIn.extract(name, bytes).await,
            }
            let text = tokio::task::spawn_blocking(move || pdf_text(&bytes))
                .await
                .ok()
                .flatten()?;
            Some(Extracted {
                kind: DocKind::Text,
                text,
                extra: raft5fs_search::record::Extra {
                    reader: raft5fs_search::extract::READER,
                    ..Default::default()
                },
                thumb: None,
            })
        })
    }
}

/// What mounts, WebDAV servers and the CLI index with: `Native`, the text
/// model, and CLIP for photos (both downloaded on first use).
pub fn native_tools() -> Tools {
    Tools {
        extract: Arc::new(Native),
        embed: Some(Arc::new(embed::Embedder::cached())),
        image: Some(Arc::new(clip::ImageEmbedder::cached())),
    }
}

/// A photo's thumbnail: at most `THUMB_PX` on its longest side, turned
/// upright by its EXIF `orientation`, as a JPEG. `None` for a format this
/// can't decode (HEIC) or a damaged file.
pub fn thumbnail(bytes: &[u8], orientation: u16) -> Option<Vec<u8>> {
    use image::imageops::FilterType;
    let px = raft5fs_search::extract::THUMB_PX;
    let decoded = std::panic::catch_unwind(|| image::load_from_memory(bytes))
        .ok()?
        .ok()?;
    let small = decoded.resize(px, px, FilterType::Triangle);
    let upright = match orientation {
        2 => small.fliph(),
        3 => small.rotate180(),
        4 => small.flipv(),
        5 => small.rotate90().fliph(),
        6 => small.rotate90(),
        7 => small.rotate270().fliph(),
        8 => small.rotate270(),
        _ => small,
    };
    let mut out = Vec::new();
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 75);
    upright.to_rgb8().write_with_encoder(encoder).ok()?;
    Some(out)
}

/// The text of a PDF, or `None` if it has none or can't be read.
pub fn pdf_text(bytes: &[u8]) -> Option<String> {
    let text = std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(bytes))
        .ok()?
        .ok()?;
    (!text.trim().is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-page PDF that says `text`, with a correct cross-reference
    /// table.
    fn pdf(text: &str) -> Vec<u8> {
        let stream = format!("BT /F1 24 Tf 72 720 Td ({text}) Tj ET");
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
                .to_string(),
            format!(
                "<< /Length {} >>\nstream\n{stream}\nendstream",
                stream.len()
            ),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        ];
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
        );
        for o in offsets {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    #[test]
    fn a_pdf_gives_its_text() {
        let text = pdf_text(&pdf("Quarterly tax receipts")).expect("text");
        assert!(text.contains("Quarterly tax receipts"), "{text:?}");
    }

    #[test]
    fn a_damaged_pdf_gives_none() {
        assert!(pdf_text(b"%PDF-1.4 nothing here").is_none());
        let mut cut = pdf("words");
        cut.truncate(cut.len() / 2);
        assert!(pdf_text(&cut).is_none());
    }

    /// The search crate's fixture, 320 by 240.
    const LAKE: &[u8] = include_bytes!("../../search/src/extract/testdata/lake.jpg");

    #[test]
    fn a_thumbnail_is_small_and_upright() {
        let thumb = thumbnail(LAKE, 1).unwrap();
        let img = image::load_from_memory(&thumb).unwrap();
        assert_eq!((img.width(), img.height()), (256, 192));
        assert!(thumb.len() < 20_000, "{}", thumb.len());
        // Orientation 6: the camera was turned, so the picture is too.
        let img = image::load_from_memory(&thumbnail(LAKE, 6).unwrap()).unwrap();
        assert_eq!((img.width(), img.height()), (192, 256));
        assert!(thumbnail(b"not a picture", 1).is_none());
    }

    #[test]
    fn other_formats_go_to_the_built_in_reader() {
        assert_eq!(Native.reads("a.pdf"), PDF_MAX);
        assert_eq!(Native.reads("a.mov"), 0);
        assert_eq!(Native.reads("a.jpg"), BuiltIn.reads("a.jpg"));
        assert_eq!(Native.reads("a.txt"), BuiltIn.reads("a.txt"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let got = rt
            .block_on(Native.extract("a.txt", b"plain words".to_vec()))
            .unwrap();
        assert_eq!(got.text, "plain words");
        let got = rt
            .block_on(Native.extract("a.pdf", pdf("from a pdf")))
            .unwrap();
        assert!(got.text.contains("from a pdf"));
    }
}
