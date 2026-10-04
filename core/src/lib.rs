//! The filesystem's store logic, independent of how requests arrive.

pub mod accounts;
mod entry;
mod fs;
pub mod groups;
mod layout;
pub mod perm;
mod read_cache;
pub mod users;

pub use fs::{
    DEFAULT_READ_CACHE_BYTES, FsCore, resolve_chunk_size, resolve_encryption, stored_encryption,
};
pub use layout::{
    CHUNK_SIZE_KEY, DEFAULT_CHUNK_SIZE, ENCRYPTED_KEY, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, batch_bytes,
    chunk_prefix, dirent_prefix, tombstone_key, validate_chunk_size,
};
pub use raft5fs_proto::types::{
    AccountKeys, Attr, Caller, DirItem, FsError, Kind, SetAttr, SetTime, WriteError,
};
