//! How the filesystem is laid out in the KV store, and the size limits
//! that layout has to respect. Pure functions only: nothing here talks to
//! the store, so all of it can be tested without a cluster.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

pub(crate) const ROOT_INO: u64 = 1;
pub(crate) const COUNTER_KEY: &[u8] = b"\x04next_ino";

/// Keys deleted per transaction when tearing down a file's chunks. Each
/// buffered write is its own round trip, so this bounds how long one
/// transaction stays open against its (absolute, 15 s maximum) deadline.
pub(crate) const DELETE_BATCH: usize = 256;

/// Records the chunk size a filesystem was created with, so later mounts
/// adopt it rather than reinterpreting every chunk boundary.
pub const CHUNK_SIZE_KEY: &[u8] = b"\x04chunk_size";

/// Marks a store as holding a filesystem in this raft5fs's format (one
/// byte, `STORE_FORMAT`). An older raft5fs's store has a root but no such
/// key, or another byte here -- 0 for an unencrypted one, 1 for one whose
/// grants, names and grantees aren't sealed the way this one's are --
/// which this one refuses (see `check_store`).
pub const ENCRYPTED_KEY: &[u8] = b"\x04encrypted";

/// The format `ENCRYPTED_KEY` records.
pub const STORE_FORMAT: u8 = 2;

pub const DEFAULT_CHUNK_SIZE: u64 = 1 << 20;
pub const MIN_CHUNK_SIZE: u64 = 4096;
/// The largest chunk we will create. A chunk has to fit in one
/// transaction along with the attributes even when it is the only one in
/// its batch (see `chunks_per_batch`), and a read of it has to fit in one
/// gRPC message. 8 MiB clears both with room to spare; the largest power
/// of two under `MAX_TRANSACTION_BYTES`.
pub const MAX_CHUNK_SIZE: u64 = 8 << 20;

/// Mirrors `raft5_shared::MAX_TRANSACTION_BYTES`, the most a transaction
/// may buffer, which the server enforces.
const SERVER_TXN_LIMIT: u64 = 10 * 1024 * 1024;

/// Mirrors `raft5_shared::MAX_KV_MESSAGE_BYTES`, the decoding limit
/// `raft5_client` sets (`raft5-client/src/routing.rs`): a transaction's
/// worth plus 1 MiB of framing. A value larger than it could be written
/// and then never read back.
const CLIENT_READ_LIMIT: u64 = SERVER_TXN_LIMIT + 1024 * 1024;

// Slack for the attributes and the per-key overhead the server charges
// (64 bytes a key, so a full batch's worth is a kilobyte) alongside the
// chunk data in one transaction.
const TXN_SLACK: u64 = 64 * 1024;
const _: () = assert!(MAX_CHUNK_SIZE + TXN_SLACK <= SERVER_TXN_LIMIT);
const _: () = assert!(MAX_CHUNK_SIZE + TXN_SLACK < CLIENT_READ_LIMIT);

/// How many bytes of chunk data one transaction may carry. Sized well
/// under `SERVER_TXN_LIMIT` so that one commit's replicate-and-apply stays
/// a fraction of `TXN_TTL` even on a slow cluster, and so that an aborted
/// batch is not too much work to redo.
const MAX_BATCH_BYTES: u64 = 4 << 20;

/// How many chunk keys one transaction may touch.
///
/// The byte budget alone would not bound this: at `MIN_CHUNK_SIZE` a
/// batch's worth of bytes is a thousand keys. That matters because every
/// buffered write is its own round trip and every key a transaction takes
/// stays locked until it commits -- including the attributes, the one key
/// everything else on the inode contends for. This caps how long a batch
/// can hold them.
const MAX_BATCH_CHUNKS: usize = 16;

// A batch is at most `MAX_BATCH_CHUNKS` chunks *or* `MAX_BATCH_BYTES`,
// whichever binds first -- except that a single chunk always gets a
// transaction even when it alone is over the budget, which is what the
// `MAX_CHUNK_SIZE` assert above covers.
const _: () = assert!(MAX_BATCH_BYTES + TXN_SLACK <= SERVER_TXN_LIMIT);

/// How many chunks one transaction covers at this filesystem's chunk size.
///
/// At least one: a chunk that alone fills the budget still has to be
/// stored. At `chunk_size` of `MAX_BATCH_BYTES` or more this is 1 and
/// batching does nothing, which is the honest outcome -- one chunk already
/// fills a transaction.
pub(crate) fn chunks_per_batch(chunk_size: u64) -> usize {
    ((MAX_BATCH_BYTES / chunk_size) as usize).clamp(1, MAX_BATCH_CHUNKS)
}

/// How much contiguous data one transaction stores at this chunk size, and
/// so how much a buffer accumulates before it is handed off. Public for
/// tests, which need to write exactly a batch to exercise that trigger.
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
//   0x07 ++ ino(BE8) ++ username        -> a grant of that directory to that user (`grants`)
//   0x08 ++ ino(BE8)                    -> the inode's key record
//   0x09 ++ username ++ 0x00 ++ ino(BE8) -> index of a user's grants (`grants`)
//   0x0A ++ ino(BE8)                    -> an inode number reserved for a create, by username
//   0x0B ++ ino(BE8)                    -> who ino is granted to, sealed under its key (`grants`)
//
// Deleting an inode takes several transactions (its chunks can't all fit
// in one), so it is announced first: one transaction removes the dirent,
// marks the Entry deleted (`nlink == 0`) and writes the `0x05` marker.
// Writes read the Entry inside their own transaction and refuse a marked
// one, so once the mark commits no new chunk can appear; the chunks and
// then the Entry and marker are removed after. A crash part-way leaves
// the marker, which is how the deletion gets finished later -- without
// it, an inode with no dirent would be unreachable and its chunks leaked.
//
// The singletons were once `0x00 ++ name`, which the cluster has since
// reserved for itself (`raft5-server`'s `keyspace`): keys under `\x00`
// are no longer addressable through the client API at all, so those two
// rows can be neither read nor migrated from here. A store written before
// that change therefore has no reachable record of its chunk size or its
// inode counter. It will mount -- adopting the requested chunk size and
// restarting the counter -- and reinterpret every chunk boundary while
// handing out inode numbers that already exist. Such a store must be
// discarded, not mounted.
//
// A file's bytes are split across chunks of `chunk_size` each. A chunk
// that was never written is simply absent and reads as zeros, so holes
// cost nothing; end-of-file lives in the Entry, never in the chunks.
//
// This layout is not compatible with the earlier one that held a whole
// file under `0x02 ++ ino`. Those 9-byte keys are ignored (every scan
// requires the full 17-byte chunk key), so an old database reads as a
// tree of empty files rather than as corrupt data -- but it cannot be
// migrated, only discarded.

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

/// The prefix of every pending enrolment code; see `accounts`.
pub(crate) const ENROLMENT_PREFIX: &[u8] = b"\x06e/";

/// The prefix every deletion marker shares; see the layout notes above.
pub(crate) const TOMBSTONE_PREFIX: &[u8] = &[0x05];

/// The marker recording that `ino`'s deletion has started. Public for
/// tests, which simulate a deletion interrupted part-way.
pub fn tombstone_key(ino: u64) -> Vec<u8> {
    let mut key = TOMBSTONE_PREFIX.to_vec();
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

/// The common prefix of every chunk key belonging to `ino`. Chunk indices
/// are fixed-width and big-endian, so lexicographic order over this prefix
/// is ascending chunk order.
pub fn chunk_prefix(ino: u64) -> Vec<u8> {
    let mut key = vec![0x02];
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

pub(crate) fn chunk_key(ino: u64, index: u64) -> Vec<u8> {
    let mut key = chunk_prefix(ino);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

pub(crate) fn is_chunk_key(key: &[u8], prefix: &[u8]) -> bool {
    key.starts_with(prefix) && key.len() == prefix.len() + 8
}

/// The common prefix of every directory entry in `parent`. Public for
/// tests, which check a removed directory left no entries behind.
pub fn dirent_prefix(parent: u64) -> Vec<u8> {
    let mut key = vec![0x03];
    key.extend_from_slice(&parent.to_be_bytes());
    key
}

/// A directory entry's value: the child's inode, then its real name,
/// sealed (the key's name being only a tag).
pub(crate) fn dirent_value(ino: u64, sealed_name: &[u8]) -> Vec<u8> {
    let mut value = ino.to_be_bytes().to_vec();
    value.extend_from_slice(sealed_name);
    value
}

/// The inode a directory entry's value names.
pub(crate) fn dirent_ino(value: &[u8]) -> u64 {
    u64::from_be_bytes(value[..8].try_into().unwrap())
}

/// The sealed name a directory entry's value holds, if any.
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
    fn a_chunk_key_is_only_recognized_for_its_own_inode() {
        let prefix = chunk_prefix(9);
        assert!(is_chunk_key(&chunk_key(9, 0), &prefix));
        assert!(!is_chunk_key(&chunk_key(10, 0), &prefix));
        // The pre-chunking layout kept a whole file under this key.
        assert!(!is_chunk_key(&chunk_prefix(9), &prefix));
    }

    #[test]
    fn batches_respect_both_the_byte_and_the_chunk_cap() {
        // Small chunks: the count cap binds, which is the point of having
        // it -- the byte budget alone would allow a thousand keys here.
        assert_eq!(chunks_per_batch(MIN_CHUNK_SIZE), MAX_BATCH_CHUNKS);
        assert_eq!(chunks_per_batch(64 * 1024), MAX_BATCH_CHUNKS);

        // Where the two caps meet.
        assert_eq!(
            chunks_per_batch(MAX_BATCH_BYTES / MAX_BATCH_CHUNKS as u64),
            16
        );

        // Large chunks: the byte budget binds.
        assert_eq!(chunks_per_batch(DEFAULT_CHUNK_SIZE), 4);
        assert_eq!(chunks_per_batch(MAX_BATCH_BYTES), 1);

        // A chunk bigger than the whole budget still gets a transaction,
        // rather than rounding down to none.
        assert_eq!(chunks_per_batch(MAX_CHUNK_SIZE), 1);

        for size in [
            MIN_CHUNK_SIZE,
            64 * 1024,
            DEFAULT_CHUNK_SIZE,
            MAX_CHUNK_SIZE,
        ] {
            let bytes = batch_bytes(size);
            assert!(chunks_per_batch(size) <= MAX_BATCH_CHUNKS, "size {size}");
            // The one permitted overshoot is a lone chunk, which the
            // `MAX_CHUNK_SIZE` assert covers instead.
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
