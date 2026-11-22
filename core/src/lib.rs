//! The filesystem's store logic, separate from how requests arrive.

pub mod accounts;
pub mod backup;
mod entry;
mod fs;
pub mod gc;
pub mod grants;
pub mod introductions;
mod layout;
pub mod objects;
pub mod snapshots;
pub mod timing;
mod view;

pub use fs::{FsCore, check_store, resolve_chunk_size};
pub use layout::{
    CHUNK_SIZE_KEY, DEFAULT_CHUNK_SIZE, ENCRYPTED_KEY, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
    STORE_FORMAT, batch_bytes, chunk_prefix, dirent_prefix, tombstone_key, validate_chunk_size,
};
pub use raft5fs_proto::types::{
    AccountKeys, Attr, BlockRef, BlockUpload, BlockUrl, Caller, ChunkBody, ChunkWrite, Chunks,
    DirItem, FsError, Grant, GrantedNode, Grantee, KeyPath, Kind, Layout, NewNode, ObjectGrid,
    PreparedUpload, RESEAL_NAMES_BATCH, ResealedName, Rotation, SealedChunk, SealedMove, SetAttr,
    SetTime, SnapshotInfo, WriteBody,
};

/// The servers answer with `raft5fs_proto::errno` values, which every
/// client reads, on any platform. On Linux, where the servers run, they
/// must be the system's own, so a mount reports the right error.
#[cfg(all(test, target_os = "linux"))]
mod errno_tests {
    use raft5fs_proto::errno;

    #[test]
    fn the_protocols_errnos_are_linuxs() {
        let pairs = [
            (errno::EPERM, libc::EPERM),
            (errno::ENOENT, libc::ENOENT),
            (errno::EIO, libc::EIO),
            (errno::EAGAIN, libc::EAGAIN),
            (errno::EACCES, libc::EACCES),
            (errno::EBUSY, libc::EBUSY),
            (errno::EEXIST, libc::EEXIST),
            (errno::EXDEV, libc::EXDEV),
            (errno::ENOTDIR, libc::ENOTDIR),
            (errno::EISDIR, libc::EISDIR),
            (errno::EINVAL, libc::EINVAL),
            (errno::EROFS, libc::EROFS),
            (errno::ENAMETOOLONG, libc::ENAMETOOLONG),
            (errno::ENOSYS, libc::ENOSYS),
            (errno::ENOTEMPTY, libc::ENOTEMPTY),
            (errno::ENOTSUP, libc::ENOTSUP),
            (errno::ENOTCONN, libc::ENOTCONN),
            (errno::ETIMEDOUT, libc::ETIMEDOUT),
            (errno::ECONNREFUSED, libc::ECONNREFUSED),
            (errno::EHOSTUNREACH, libc::EHOSTUNREACH),
            (errno::ESTALE, libc::ESTALE),
            (errno::EDQUOT, libc::EDQUOT),
            (errno::EKEYEXPIRED, libc::EKEYEXPIRED),
        ];
        for (ours, linux) in pairs {
            assert_eq!(ours, linux);
        }
    }
}
