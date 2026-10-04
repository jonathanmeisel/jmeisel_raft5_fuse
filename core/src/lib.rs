//! The filesystem's store logic, independent of how requests arrive.

mod entry;
mod fs;
mod layout;
pub mod perm;
mod read_cache;
pub mod users;

pub use fs::{DEFAULT_READ_CACHE_BYTES, FsCore, resolve_chunk_size};
pub use layout::{
    CHUNK_SIZE_KEY, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, batch_bytes, chunk_prefix,
    dirent_prefix, tombstone_key, validate_chunk_size,
};
pub use raft5fs_proto::types::{
    Attr, Caller, DirItem, FsError, Kind, SetAttr, SetTime, WriteError,
};
