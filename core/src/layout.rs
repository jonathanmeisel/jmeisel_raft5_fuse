//! How the filesystem is laid out in the KV store, and the size limits that
//! the layout must respect. Only pure functions: nothing here talks to the
//! store, so all of it can be tested without a cluster.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use raft5fs_crypto::data::CHUNK_OVERHEAD;
use raft5fs_proto::types::{BLOCK_RANDOM_LEN, BlockRef};

pub(crate) const ROOT_INO: u64 = 1;
pub(crate) const COUNTER_KEY: &[u8] = b"\x04next_ino";

/// Keys deleted in each transaction when a file's chunks are removed. Each
/// buffered write is its own round trip, so this limits how long one
/// transaction stays open against its deadline (at most 15 s).
pub(crate) const DELETE_BATCH: usize = 256;

/// Records the chunk size that the filesystem was created with, so later
/// mounts use it and do not misread every chunk boundary.
pub const CHUNK_SIZE_KEY: &[u8] = b"\x04chunk_size";

/// Records the object grid that hybrid files use (see `objects`), after a
/// server with object storage opens the filesystem.
pub(crate) const OBJECT_GRID_KEY: &[u8] = b"\x04object_grid";

/// Which server sweeps object storage for garbage, and until when (see
/// `gc`).
pub(crate) const GC_LEASE_KEY: &[u8] = b"\x04gc_lease";

/// Which server runs a backup job, and until when (see `backup`).
pub(crate) const BACKUP_LEASE_KEY: &[u8] = b"\x04backup_lease";

/// Marks a store as holding a filesystem in this raft5fs format (one byte,
/// `STORE_FORMAT`). This raft5fs refuses a store with a root but no such
/// key, or with another byte here (see `check_store`). 0 means an
/// unencrypted store, and 1 means a store whose grants, names, and grantees
/// are not sealed as this version seals them.
pub const ENCRYPTED_KEY: &[u8] = b"\x04encrypted";

/// The format that `ENCRYPTED_KEY` records.
pub const STORE_FORMAT: u8 = 2;

pub const DEFAULT_CHUNK_SIZE: u64 = 1 << 20;
pub const MIN_CHUNK_SIZE: u64 = 4096;
/// The largest chunk size. A chunk must fit in one transaction with the
/// attributes, even when it is the only chunk in its batch (see
/// `chunks_per_batch`). A read of it must fit in one gRPC message. 8 MiB is
/// well within both: it is the largest power of two below
/// `MAX_TRANSACTION_BYTES`.
pub const MAX_CHUNK_SIZE: u64 = 8 << 20;

/// Same as `raft5_shared::MAX_TRANSACTION_BYTES`: the most that a
/// transaction can buffer. The server enforces it.
const SERVER_TXN_LIMIT: u64 = 10 * 1024 * 1024;

/// Same as `raft5_shared::MAX_KV_MESSAGE_BYTES`, the decoding limit that
/// `raft5_client` sets (`raft5-client/src/routing.rs`): one transaction
/// plus 1 MiB for framing. A value larger than this could be written but
/// never read back.
const CLIENT_READ_LIMIT: u64 = SERVER_TXN_LIMIT + 1024 * 1024;

// Space for the attributes and the server's cost for each key (64 bytes a
// key, so about a kilobyte for a full batch), next to the chunk data in one
// transaction.
const TXN_SLACK: u64 = 64 * 1024;
const _: () = assert!(MAX_CHUNK_SIZE + TXN_SLACK <= SERVER_TXN_LIMIT);
const _: () = assert!(MAX_CHUNK_SIZE + TXN_SLACK < CLIENT_READ_LIMIT);

/// How many bytes of chunk data one transaction can hold. It is much less
/// than `SERVER_TXN_LIMIT`, so that one commit's replicate-and-apply takes
/// only a part of `TXN_TTL` even on a slow cluster, and an aborted batch is
/// not too much work to do again.
const MAX_BATCH_BYTES: u64 = 4 << 20;

/// How many chunk keys one transaction can touch. The byte limit alone does
/// not limit this: at `MIN_CHUNK_SIZE`, a batch of bytes is a thousand
/// keys. That matters because each buffered write is its own round trip,
/// and each key a transaction takes stays locked until it commits. This
/// includes the attributes, the one key that every other operation on the
/// inode needs. This limit stops a batch from holding them for too long.
const MAX_BATCH_CHUNKS: usize = 16;

// A batch is at most `MAX_BATCH_CHUNKS` chunks or `MAX_BATCH_BYTES`,
// whichever limit comes first. The one exception is a single chunk, which
// always gets a transaction even if it alone is over the limit. The
// `MAX_CHUNK_SIZE` assert above covers that case.
const _: () = assert!(MAX_BATCH_BYTES + TXN_SLACK <= SERVER_TXN_LIMIT);

/// How many chunks one transaction covers at this chunk size. At least one:
/// a chunk that fills the limit alone must still be stored. At a
/// `chunk_size` of `MAX_BATCH_BYTES` or more this is 1, so batching does
/// nothing: one chunk already fills a transaction.
pub(crate) fn chunks_per_batch(chunk_size: u64) -> usize {
    ((MAX_BATCH_BYTES / chunk_size) as usize).clamp(1, MAX_BATCH_CHUNKS)
}

/// How much contiguous data one transaction stores at this chunk size. A
/// buffer collects this much before it sends it. Public for tests, which
/// must write exactly one batch to test that trigger.
pub fn batch_bytes(chunk_size: u64) -> u64 {
    chunks_per_batch(chunk_size) as u64 * chunk_size
}

// Key layout in the KV store:
//   0x01 ++ ino(BE8)                    -> encoded Entry (attributes + parent)
//   0x02 ++ ino(BE8) ++ index(BE8)      -> one chunk of a file's data
//   0x03 ++ parent(BE8) ++ name         -> child ino(BE8) [++ sealed name], one per directory entry
//   0x04 ++ name                        -> filesystem-wide singletons
//   0x05 ++ ino(BE8)                    -> marker: this inode's deletion is under way
//   0x06 ++ "k/" ++ username            -> the account's keys (`accounts`)
//   0x06 ++ "e/" ++ username            -> a pending enrolment code's hash (`accounts`)
//   0x06 ++ "c/" ++ username            -> the account record: capabilities, kind,
//                                          who invited it (`accounts`)
//   0x06 ++ "p/" ++ username            -> the account's trusted keys, sealed to it (`accounts`)
//   0x07 ++ ino(BE8) ++ username        -> a grant of that directory to that user (`grants`)
//   0x08 ++ ino(BE8)                    -> the inode's key record
//   0x09 ++ username ++ 0x00 ++ ino(BE8) -> index of a user's grants (`grants`)
//   0x0A ++ ino(BE8)                    -> an inode number reserved for a create, by username
//   0x0B ++ ino(BE8)                    -> who ino is granted to, sealed under its key (`grants`)
//   0x0C ++ ino(BE8)                    -> a volume's record: its owner, any transfer offer
//                                          (`fs::volumes`)
//
// **Deleting an inode** takes several transactions, because its chunks
// cannot all fit in one. So the deletion is announced first:
//
// - One transaction removes the dirent, marks the Entry deleted (`nlink ==
//   0`), and writes the `0x05` marker. Writes read the Entry in their own
//   transaction and refuse a marked one, so after the mark commits, no new
//   chunk can appear.
// - Later transactions remove the chunks, then the Entry and the marker.
// - If a crash stops this part way, the marker stays, and the deletion is
//   finished later. Without the marker, an inode with no dirent could not
//   be reached, and its chunks would leak.
//
// **Singletons must not be under `0x00`.** The cluster reserves that prefix
// (`raft5-server`'s `keyspace`), and the client API cannot reach it. A
// store with its singletons there has no readable chunk size or inode
// counter. It would mount, use the requested chunk size, and start the
// counter again, so it would misread every chunk boundary and give out
// inode numbers that already exist. Discard such a store. Do not mount it.
//
// **Chunks.** A file's bytes are split into chunks of `chunk_size` each. A
// chunk that was never written is absent and reads as zeros, so holes cost
// nothing. The end of the file is in the Entry, never in the chunks.
//
// A hybrid file (see the Entry's layout in `entry`) keeps its chunks from
// the filesystem's `ObjectGrid::from_index` up in object storage, one block
// of `per_block` chunks in each object. A block's pointer is stored under
// its first chunk's key, and the block's other keys are never written. So a
// chunk key holds one of two values, which differ by length:
//
//   inline:  version(BE4) ++ AEAD                      >= CHUNK_OVERHEAD (44) bytes
//   pointer: version(BE4) ++ minted_ms(BE8) ++ random(16) ++ nseg(BE4)   = POINTER_LEN (32)
//
// Both start with the key version they were sealed under. So everything
// that checks versions (writes, pruning) reads both in the same way, and
// neither needs the object. Pointers are also under 0x02, so deleting and
// scanning a file's chunks finds them with no change.
//
// **Whole-file keys.** A 9-byte key `0x02 ++ ino` (a whole file under one
// key) is ignored, because every scan requires the full 17-byte chunk key.
// A store with such keys reads as a tree of empty files, not as corrupt
// data. It cannot be migrated, only discarded.

pub(crate) fn attr_key(ino: u64) -> Vec<u8> {
    let mut key = vec![0x01];
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// The prefix of every account key row; see `accounts`.
pub(crate) const ACCOUNT_KEYS_PREFIX: &[u8] = b"\x06k/";

/// The prefix of every grant row; see `grants`.
pub(crate) const GRANTS_PREFIX: &[u8] = &[0x07];
/// The prefix of every inode key record.
pub(crate) const NODE_KEYS_PREFIX: &[u8] = &[0x08];
/// The prefix of the per-user grant index; see `grants`.
pub(crate) const GRANT_INDEX_PREFIX: &[u8] = &[0x09];
/// The prefix of every inode reservation; see `grants`.
pub(crate) const RESERVATION_PREFIX: &[u8] = &[0x0A];
/// The prefix of every sealed grantee list; see `grants`.
pub(crate) const GRANTEES_PREFIX: &[u8] = &[0x0B];

/// The prefix of every volume record; see `fs::volumes`.
pub(crate) const VOLUME_PREFIX: &[u8] = &[0x0C];

pub(crate) fn volume_key(ino: u64) -> Vec<u8> {
    let mut key = VOLUME_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// The prefix of every pending enrolment code; see `accounts`.
pub(crate) const ENROLMENT_PREFIX: &[u8] = b"\x06e/";

/// The prefix of every account record (capabilities, kind, and who
/// invited the account); see `accounts`.
pub(crate) const ACCOUNT_INFO_PREFIX: &[u8] = b"\x06c/";

/// The prefix of every account's sealed trusted keys; see `accounts`.
pub(crate) const PINS_PREFIX: &[u8] = b"\x06p/";

/// The prefix of every deletion marker; see the layout notes above.
pub(crate) const TOMBSTONE_PREFIX: &[u8] = &[0x05];

/// The marker that records that `ino`'s deletion has started. Public for
/// tests, which stop a deletion part way.
pub fn tombstone_key(ino: u64) -> Vec<u8> {
    let mut key = TOMBSTONE_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// The prefix of every chunk key of `ino`. Chunk indices are fixed-width
/// and big-endian, so byte order under this prefix is ascending chunk
/// order.
pub fn chunk_prefix(ino: u64) -> Vec<u8> {
    let mut key = vec![0x02];
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// The length of a block pointer. It is shorter than any sealed chunk, so
/// the length shows which kind a value is.
pub(crate) const POINTER_LEN: usize = 4 + 8 + BLOCK_RANDOM_LEN + 4;
const _: () = assert!(POINTER_LEN < CHUNK_OVERHEAD);

/// What a chunk key holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChunkValue {
    /// A sealed chunk.
    Inline(Vec<u8>),
    /// A pointer to the block that starts at this index.
    Block(BlockRef),
}

impl ChunkValue {
    pub(crate) fn decode(value: Vec<u8>) -> Self {
        if value.len() != POINTER_LEN {
            // Anything else is a sealed chunk, or bad data that does not
            // open as one. The client finds that when it opens it.
            return ChunkValue::Inline(value);
        }
        let at = |range: std::ops::Range<usize>| &value[range];
        ChunkValue::Block(BlockRef {
            version: u32::from_be_bytes(at(0..4).try_into().unwrap()),
            minted_ms: u64::from_be_bytes(at(4..12).try_into().unwrap()),
            random: at(12..28).try_into().unwrap(),
            nseg: u32::from_be_bytes(at(28..32).try_into().unwrap()),
        })
    }
}

pub(crate) fn encode_pointer(block: &BlockRef) -> Vec<u8> {
    let mut value = Vec::with_capacity(POINTER_LEN);
    value.extend_from_slice(&block.version.to_be_bytes());
    value.extend_from_slice(&block.minted_ms.to_be_bytes());
    value.extend_from_slice(&block.random);
    value.extend_from_slice(&block.nseg.to_be_bytes());
    value
}

pub(crate) fn chunk_key(ino: u64, index: u64) -> Vec<u8> {
    let mut key = chunk_prefix(ino);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

pub(crate) fn is_chunk_key(key: &[u8], prefix: &[u8]) -> bool {
    key.starts_with(prefix) && key.len() == prefix.len() + 8
}

/// The prefix of every directory entry in `parent`. Public for tests, which
/// check that a removed directory left no entries.
pub fn dirent_prefix(parent: u64) -> Vec<u8> {
    let mut key = vec![0x03];
    key.extend_from_slice(&parent.to_be_bytes());
    key
}

/// A directory entry's value: the child's inode, then its real name,
/// sealed. The key holds only a tag.
pub(crate) fn dirent_value(ino: u64, sealed_name: &[u8]) -> Vec<u8> {
    let mut value = ino.to_be_bytes().to_vec();
    value.extend_from_slice(sealed_name);
    value
}

/// The inode that a directory entry's value names.
pub(crate) fn dirent_ino(value: &[u8]) -> u64 {
    u64::from_be_bytes(value[..8].try_into().unwrap())
}

/// The sealed name in a directory entry's value, if any.
pub(crate) fn dirent_sealed_name(value: &[u8]) -> &[u8] {
    &value[8..]
}

pub(crate) fn dirent_key(parent: u64, name: &OsStr) -> Vec<u8> {
    let mut key = dirent_prefix(parent);
    key.extend_from_slice(name.as_bytes());
    key
}

pub fn validate_chunk_size(n: u64) -> Result<(), String> {
    if !n.is_power_of_two() {
        return Err(format!("chunk size must be a power of two, got {n}"));
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&n) {
        return Err(format!(
            "chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes, got {n}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_keys_sort_in_index_order() {
        let mut keys: Vec<_> = [5u64, 0, 300, 1, 70000]
            .iter()
            .map(|&i| chunk_key(9, i))
            .collect();
        keys.sort();
        let expected: Vec<_> = [0u64, 1, 5, 300, 70000]
            .iter()
            .map(|&i| chunk_key(9, i))
            .collect();
        assert_eq!(keys, expected);
    }

    #[test]
    fn a_pointer_round_trips_and_is_told_from_a_sealed_chunk() {
        let block = BlockRef {
            version: 0x0102_0304,
            minted_ms: 1_760_000_000_000,
            random: [9; BLOCK_RANDOM_LEN],
            nseg: 16,
        };
        let value = encode_pointer(&block);
        assert_eq!(value.len(), POINTER_LEN);
        // It starts with its key version, like a sealed chunk.
        assert_eq!(
            raft5fs_crypto::data::sealed_version(&value).unwrap(),
            block.version
        );
        assert_eq!(ChunkValue::decode(value), ChunkValue::Block(block));

        let key = raft5fs_crypto::Key::random();
        for len in [0, 1, 4096] {
            let sealed = raft5fs_crypto::data::seal_chunk(&key, 1, 9, 0, &vec![0; len]);
            assert!(sealed.len() >= CHUNK_OVERHEAD);
            assert_eq!(
                ChunkValue::decode(sealed.clone()),
                ChunkValue::Inline(sealed)
            );
        }
    }

    #[test]
    fn a_chunk_key_is_only_recognized_for_its_own_inode() {
        let prefix = chunk_prefix(9);
        assert!(is_chunk_key(&chunk_key(9, 0), &prefix));
        assert!(!is_chunk_key(&chunk_key(10, 0), &prefix));
        // A whole-file key, with no chunk index, is not a chunk key.
        assert!(!is_chunk_key(&chunk_prefix(9), &prefix));
    }

    #[test]
    fn batches_respect_both_the_byte_and_the_chunk_cap() {
        // Small chunks: the count limit applies. This is why it exists: the
        // byte limit alone would allow a thousand keys here.
        assert_eq!(chunks_per_batch(MIN_CHUNK_SIZE), MAX_BATCH_CHUNKS);
        assert_eq!(chunks_per_batch(64 * 1024), MAX_BATCH_CHUNKS);

        // Where the two limits are equal.
        assert_eq!(
            chunks_per_batch(MAX_BATCH_BYTES / MAX_BATCH_CHUNKS as u64),
            16
        );

        // Large chunks: the byte limit applies.
        assert_eq!(chunks_per_batch(DEFAULT_CHUNK_SIZE), 4);
        assert_eq!(chunks_per_batch(MAX_BATCH_BYTES), 1);

        // A chunk larger than the whole limit still gets a transaction. The
        // count does not round down to zero.
        assert_eq!(chunks_per_batch(MAX_CHUNK_SIZE), 1);

        for size in [
            MIN_CHUNK_SIZE,
            64 * 1024,
            DEFAULT_CHUNK_SIZE,
            MAX_CHUNK_SIZE,
        ] {
            let bytes = batch_bytes(size);
            assert!(chunks_per_batch(size) <= MAX_BATCH_CHUNKS, "size {size}");
            // Only a single chunk can go over the limit. The
            // `MAX_CHUNK_SIZE` assert covers that case.
            assert!(
                bytes <= MAX_BATCH_BYTES || chunks_per_batch(size) == 1,
                "size {size} batches {bytes} bytes"
            );
            assert!(bytes + TXN_SLACK <= SERVER_TXN_LIMIT, "size {size}");
        }
    }

    #[test]
    fn chunk_sizes_are_powers_of_two_within_range() {
        assert!(validate_chunk_size(DEFAULT_CHUNK_SIZE).is_ok());
        assert!(validate_chunk_size(MIN_CHUNK_SIZE).is_ok());
        assert!(validate_chunk_size(MAX_CHUNK_SIZE).is_ok());
        assert!(validate_chunk_size(64 * 1024).is_ok());

        assert!(validate_chunk_size(0).is_err());
        assert!(validate_chunk_size(1000).is_err());
        assert!(validate_chunk_size(MIN_CHUNK_SIZE / 2).is_err());
        assert!(validate_chunk_size(MAX_CHUNK_SIZE * 2).is_err());
    }
}
