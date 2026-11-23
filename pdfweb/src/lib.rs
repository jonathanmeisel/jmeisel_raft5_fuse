//! The text of a PDF, for the web app's indexer (see raft5fs-indexer's
//! `pdf_text`, which native clients use: the same reader, so a PDF gives
//! the same text everywhere). Builds only for wasm32; elsewhere it is
//! empty.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

/// The text of a PDF, or `undefined` if it has none or can't be read. A
/// PDF that makes the reader panic traps this module: the caller loads it
/// again.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = pdfText)]
pub fn pdf_text(bytes: &[u8]) -> Option<String> {
    let text = pdf_extract::extract_text_from_mem(bytes).ok()?;
    (!text.trim().is_empty()).then_some(text)
}
