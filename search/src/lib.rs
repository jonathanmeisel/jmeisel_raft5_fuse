//! Search over a volume's files. The servers can't read the files, so
//! clients build the index and keep it in the volume itself, as ordinary
//! files under `INDEX_DIR`, sealed like every other file there.
//!
//! - `record`: what the index knows about one file, and the tombstone that
//!   says a file is gone.
//! - `segment` and `manifest`: how records are packed into index files. Each
//!   indexer writes only its own files.
//! - `text`: words for keyword search, and chunks of text.
//! - `extract`: the text of a file, from its bytes and name.
//! - `geo`: which town, region and country a point is in, offline.
//! - `bm25` and `rank`: keyword ranking, and the merge of ranked lists.
//! - `vector`: embeddings kept small, and how close two are.
//! - `view`: every indexer's records for a volume, merged, and searched.
//!
//! Nothing here does I/O or runs a model, so the same code runs in native
//! clients and in the browser.

pub mod bm25;
pub mod cluster;
pub mod extract;
pub mod geo;
pub mod manifest;
pub mod paths;
pub mod rank;
pub mod record;
pub mod segment;
pub mod text;
pub mod vector;
pub mod view;

/// The directory at a volume's root that holds its index. Clients hide it
/// from listings and refuse to let users make or rename anything to it.
pub const INDEX_DIR: &str = ".raft5fs-search";

pub use raft5fs_wire::Error;
