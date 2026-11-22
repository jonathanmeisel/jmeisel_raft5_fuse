//! Search indexing for native clients: `Native` reads everything that
//! raft5fs-search reads, and PDF too; `embed` runs the embedding model.
//!
//! PDF parsing is slow and can panic on damaged files, so it runs on a
//! blocking thread, and a panic there only means "no text".

pub mod embed;

use std::sync::Arc;

use raft5fs_client::indexer::{BuiltIn, Extract, Tools};
use raft5fs_search::extract::{Extracted, Format};
use raft5fs_search::record::DocKind;

/// The most bytes of a PDF that are read.
const PDF_MAX: u64 = 64 << 20;

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
            if Format::of(name) != Format::Pdf {
                return BuiltIn.extract(name, bytes).await;
            }
            let text = tokio::task::spawn_blocking(move || pdf_text(&bytes))
                .await
                .ok()
                .flatten()?;
            Some(Extracted {
                kind: DocKind::Text,
                text,
            })
        })
    }
}

/// What mounts, WebDAV servers and the CLI index with: `Native`, and the
/// embedding model (downloaded on first use).
pub fn native_tools() -> Tools {
    Tools {
        extract: Arc::new(Native),
        embed: Some(Arc::new(embed::Embedder::cached())),
    }
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

    #[test]
    fn other_formats_go_to_the_built_in_reader() {
        assert_eq!(Native.reads("a.pdf"), PDF_MAX);
        assert_eq!(Native.reads("a.jpg"), 0);
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
