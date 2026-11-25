//! Search embeddings on candle, the same on every client.
//!
//! - **Models** are Q8_0 GGUF files made once by the `convert` example
//!   and pinned in `search/data/models.json`. A text model comes as a body
//!   (`body.gguf`: the encoder, its settings as metadata) and a word table
//!   (`table.q8`: one Q8_0 row per token), read a row at a time
//!   (`Rows`), so the table needn't be in memory.
//! - **`TextModel`** runs a BERT-family encoder (BERT, XLM-R, DistilBERT:
//!   `encoder`), pooled and projected as `TextOptions` says.
//! - **`Vision`** (feature `vision`) is CLIP ViT-B/32's image side.
//! - The same code builds for native clients and the browser, so both
//!   give the same vectors; only the summation order of their SIMD
//!   kernels differs.

mod encoder;
mod gguf;
mod q8;
mod text;
mod tokenize;
#[cfg(feature = "vision")]
mod vision;

pub use gguf::Body;
pub use q8::{GivenRows, NoRows, Rows, quantize_row, row_bytes};
pub use text::{Pooling, TextModel, TextOptions};
pub use tokenize::{Tokenizer, write_unigram, write_wordpiece};
#[cfg(feature = "vision")]
pub use vision::{SIDE, Vision};

#[cfg(not(target_arch = "wasm32"))]
pub use q8::MappedRows;
pub use q8::MemoryRows;

/// What went wrong, in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<candle_core::Error> for Error {
    fn from(e: candle_core::Error) -> Self {
        Error(e.to_string())
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error(e)
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
