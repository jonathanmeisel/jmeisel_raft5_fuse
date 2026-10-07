//! The filesystem's store logic, independent of how requests arrive.

pub mod accounts;
mod entry;
mod fs;
pub mod grants;
mod layout;
pub mod snapshots;
mod view;

pub use fs::{FsCore, check_store, resolve_chunk_size};
pub use layout::{
    CHUNK_SIZE_KEY, DEFAULT_CHUNK_SIZE, ENCRYPTED_KEY, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, batch_bytes,
    chunk_prefix, dirent_prefix, tombstone_key, validate_chunk_size,
};
pub use raft5fs_proto::types::{
    AccountKeys, Attr, Caller, ChunkWrite, DirItem, FsError, Grant, GrantedNode, Grantee, KeyPath,
    Kind, NewNode, RESEAL_NAMES_BATCH, ResealedName, Rotation, SealedChunk, SealedMove, SetAttr,
    SetTime, SnapshotInfo,
};
