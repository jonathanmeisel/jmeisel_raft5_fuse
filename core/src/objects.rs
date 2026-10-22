//! The rules for data in object storage, after the size that a hybrid file
//! keeps in the store. See `layout` for how blocks are laid out, and
//! `ObjectGrid` for which chunks are in them.
//!
//! The server never sees a block's contents. The client seals each segment,
//! uploads the object through a URL that the server signed, and only then
//! commits a pointer to it. So the server checks the pointer:
//!
//! - It is at the start of a block.
//! - It is sealed under the file's current key version. This keeps
//!   `prune_keys` correct without a download.
//! - It names an object minted recently. So if nothing points to an object
//!   minted long ago, garbage collection knows that nothing ever will: no
//!   commit naming it would be accepted.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use raft5_client::Client;
use raft5fs_crypto::data::CHUNK_OVERHEAD;
use raft5fs_objstore::{ObjectName, S3Store, name::millis};
use raft5fs_proto::types::{BlockRef, ChunkWrite, FsError, Layout, ObjectGrid, WriteBody};

use crate::fs::{TXN_TTL, retrying};
use crate::layout::{OBJECT_GRID_KEY, chunk_key};
use crate::view::ReadKeys;

pub const DEFAULT_OBJECT_FROM: u64 = 10 << 20;
pub const DEFAULT_OBJECT_BLOCK: u64 = 16 << 20;
/// The largest block. A client may need to hold this much in memory to
/// write a block, and to upload it again for a small change inside it.
pub const MAX_OBJECT_BLOCK: u64 = 256 << 20;
pub const DEFAULT_PUT_TTL: Duration = Duration::from_secs(600);
pub const DEFAULT_GET_TTL: Duration = Duration::from_secs(900);
/// How far apart the servers' clocks can be. One server can commit a name
/// that another server minted, by its own clock.
pub const CLOCK_SKEW: Duration = Duration::from_secs(120);

/// The most blocks that one `prepare_uploads` request names.
pub const MAX_UPLOADS: usize = 64;

/// What a server needs to keep data in object storage.
pub struct ObjectSettings {
    pub store: S3Store,
    /// Where hybrid files' blocks start, in bytes, and the size of each
    /// block. The first server with object storage sets both when it opens
    /// the filesystem. Later servers use what it recorded.
    pub object_from: u64,
    pub object_block: u64,
    /// How long an upload URL or a read URL stays valid.
    pub put_ttl: Duration,
    pub get_ttl: Duration,
    /// Whether to try to delete an object as soon as a change removes the
    /// last pointer to it, and not leave it all to garbage collection (see
    /// `FsCore::discard`).
    pub prompt_delete: bool,
}

pub(crate) struct Objects {
    /// Shared with the deletions that `FsCore::discard` starts.
    pub(crate) store: Arc<S3Store>,
    pub(crate) put_ttl: Duration,
    pub(crate) get_ttl: Duration,
    pub(crate) prompt_delete: bool,
}

impl Objects {
    pub(crate) fn new(settings: ObjectSettings) -> Self {
        Objects {
            store: Arc::new(settings.store),
            put_ttl: settings.put_ttl,
            get_ttl: settings.get_ttl,
            prompt_delete: settings.prompt_delete,
        }
    }

    /// How long after minting a name can still be committed: the upload
    /// URL's lifetime, plus one transaction's lifetime for the commit after
    /// it.
    pub(crate) fn commit_window(&self) -> Duration {
        self.put_ttl + TXN_TTL
    }
}

/// The grid that `object_from` and `object_block` give at this chunk size.
pub fn grid_for(
    chunk_size: u64,
    object_from: u64,
    object_block: u64,
) -> Result<ObjectGrid, String> {
    if object_block < chunk_size || !object_block.is_multiple_of(chunk_size) {
        return Err(format!(
            "an object block must be a whole number of {chunk_size}-byte chunks, not {object_block} bytes"
        ));
    }
    if object_block > MAX_OBJECT_BLOCK {
        return Err(format!(
            "an object block may be at most {MAX_OBJECT_BLOCK} bytes, not {object_block}"
        ));
    }
    Ok(ObjectGrid {
        from_index: object_from.div_ceil(chunk_size),
        per_block: (object_block / chunk_size) as u32,
    })
}

/// The grid recorded for the filesystem in `client`'s store, if there is
/// one.
pub(crate) async fn recorded_grid(client: &Client) -> Result<Option<ObjectGrid>, String> {
    let value = client
        .read_one(OBJECT_GRID_KEY)
        .await
        .map_err(|e| e.to_string())?
        .value;
    value.map(|v| decode_grid(&v)).transpose()
}

/// The grid to use: the recorded grid, or `wanted` for a filesystem that no
/// server has kept objects for yet. In that case it records `wanted`. It
/// runs in one transaction, so two first servers at the same time agree.
pub(crate) async fn resolve_grid(
    client: &Client,
    wanted: ObjectGrid,
) -> Result<ObjectGrid, String> {
    retrying(move || async move {
        let txn = client.transaction(TXN_TTL).await?;
        if let Some(bytes) = txn.read_one(OBJECT_GRID_KEY).await?.value {
            return Ok(decode_grid(&bytes));
        }
        txn.write(OBJECT_GRID_KEY, Some(&encode_grid(wanted)))
            .await?;
        txn.commit().await?;
        Ok(Ok(wanted))
    })
    .await
    .map_err(|e| e.to_string())?
}

fn encode_grid(g: ObjectGrid) -> Vec<u8> {
    let mut v = g.from_index.to_be_bytes().to_vec();
    v.extend_from_slice(&g.per_block.to_be_bytes());
    v
}

fn decode_grid(bytes: &[u8]) -> Result<ObjectGrid, String> {
    let bytes: [u8; 12] = bytes.try_into().map_err(|_| {
        format!(
            "this filesystem's recorded object grid is {} bytes long, not 12",
            bytes.len()
        )
    })?;
    let grid = ObjectGrid {
        from_index: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
        per_block: u32::from_be_bytes(bytes[8..].try_into().unwrap()),
    };
    if grid.per_block == 0 {
        return Err("this filesystem records empty object blocks".into());
    }
    Ok(grid)
}

/// How many bytes one sealed segment of a block takes.
pub(crate) fn segment_len(chunk_size: u64) -> u64 {
    chunk_size + CHUNK_OVERHEAD as u64
}

pub(crate) fn object_name(ino: u64, block: &BlockRef) -> ObjectName {
    ObjectName {
        ino,
        minted_ms: block.minted_ms,
        random: block.random,
    }
}

/// An object that a change just stopped pointing to, with the chunk key
/// that pointed to it. Only that key can ever point to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dropped {
    pub(crate) key: Vec<u8>,
    pub(crate) name: ObjectName,
}

impl Dropped {
    pub(crate) fn new(ino: u64, index: u64, block: &BlockRef) -> Self {
        Dropped {
            key: chunk_key(ino, index),
            name: object_name(ino, block),
        }
    }
}

/// Whether `w` stores its index as a file of `layout` keeps it. In a hybrid
/// file, chunks before the grid's start are inline, and chunks from the
/// start on are blocks at each block's first index. Any other file keeps
/// all chunks inline.
pub(crate) fn check_placement(
    ino: u64,
    layout: Layout,
    grid: Option<ObjectGrid>,
    w: &ChunkWrite,
) -> Result<(), FsError> {
    let invalid = |why: String| Err(FsError::new(libc::EINVAL, format!("inode {ino}: {why}")));
    let grid = match (layout, grid) {
        (Layout::Inline, _) => None,
        (Layout::Hybrid, Some(grid)) => Some(grid),
        (Layout::Hybrid, None) => {
            return Err(FsError::new(
                libc::EIO,
                format!("inode {ino} is hybrid, but no object grid is recorded"),
            ));
        }
    };
    let in_blocks = grid.is_some_and(|g| g.in_blocks(w.index));
    match (&w.body, grid) {
        (WriteBody::Inline(_), _) if !in_blocks => Ok(()),
        (WriteBody::Inline(_), _) => invalid(format!("chunk {} is kept in a block", w.index)),
        (WriteBody::Block(_), Some(_)) if !in_blocks => {
            invalid(format!("chunk {} is kept inline, not in a block", w.index))
        }
        (WriteBody::Block(_), None) => invalid("the file keeps nothing in blocks".into()),
        (WriteBody::Block(block), Some(g)) => {
            if g.block_start(w.index) != w.index {
                return invalid(format!("no block starts at chunk {}", w.index));
            }
            if block.nseg == 0 || block.nseg > g.per_block {
                return invalid(format!(
                    "a block holds 1 to {} segments, not {}",
                    g.per_block, block.nseg
                ));
            }
            Ok(())
        }
    }
}

/// Whether a block named at `minted_ms` can still be committed at `now`.
pub(crate) fn check_minted(
    minted_ms: u64,
    now: SystemTime,
    window: Duration,
) -> Result<(), FsError> {
    let now = millis(now);
    let oldest = now.saturating_sub(millis_of(window));
    let newest = now.saturating_add(millis_of(CLOCK_SKEW));
    if (oldest..=newest).contains(&minted_ms) {
        Ok(())
    } else {
        Err(FsError::new(
            libc::EINVAL,
            "the block's name wasn't minted recently enough to commit; upload it again",
        ))
    }
}

fn millis_of(d: Duration) -> u64 {
    d.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: u64 = 64 * 1024;

    fn grid() -> ObjectGrid {
        grid_for(C, 2 * C, 4 * C).unwrap()
    }

    fn write(index: u64, body: WriteBody) -> ChunkWrite {
        ChunkWrite {
            index,
            expected_seq: None,
            body,
        }
    }

    fn block(nseg: u32) -> WriteBody {
        WriteBody::Block(BlockRef {
            version: 1,
            minted_ms: 0,
            random: [0; 16],
            nseg,
        })
    }

    #[test]
    fn grids() {
        assert_eq!(
            grid(),
            ObjectGrid {
                from_index: 2,
                per_block: 4
            }
        );
        // A start part way into a chunk moves to the next chunk.
        assert_eq!(grid_for(C, C + 1, C).unwrap().from_index, 2);
        assert!(grid_for(C, 0, C / 2).is_err());
        assert!(grid_for(C, 0, C * 3 / 2).is_err());
        assert!(grid_for(C, 0, MAX_OBJECT_BLOCK * 2).is_err());
        let g = grid();
        assert_eq!(decode_grid(&encode_grid(g)), Ok(g));
        assert!(decode_grid(&[0; 11]).is_err());
    }

    #[test]
    fn placement() {
        let g = Some(grid());
        let ok = |layout, w| check_placement(9, layout, g, &w);
        let errno = |layout, w| ok(layout, w).unwrap_err().errno;
        let inline = || WriteBody::Inline(vec![0; 50]);

        ok(Layout::Hybrid, write(1, inline())).unwrap();
        ok(Layout::Hybrid, write(2, block(4))).unwrap();
        ok(Layout::Hybrid, write(6, block(1))).unwrap();
        ok(Layout::Inline, write(2, inline())).unwrap();

        assert_eq!(errno(Layout::Hybrid, write(2, inline())), libc::EINVAL);
        assert_eq!(errno(Layout::Hybrid, write(1, block(1))), libc::EINVAL);
        assert_eq!(errno(Layout::Hybrid, write(3, block(1))), libc::EINVAL);
        assert_eq!(errno(Layout::Hybrid, write(2, block(5))), libc::EINVAL);
        assert_eq!(errno(Layout::Hybrid, write(2, block(0))), libc::EINVAL);
        assert_eq!(errno(Layout::Inline, write(2, block(1))), libc::EINVAL);
        assert_eq!(
            check_placement(9, Layout::Hybrid, None, &write(0, inline()))
                .unwrap_err()
                .errno,
            libc::EIO
        );
    }

    #[test]
    fn the_mint_window() {
        let now = SystemTime::now();
        let window = Duration::from_secs(600);
        let at = |d: i64| {
            let t = if d < 0 {
                now - Duration::from_secs(d.unsigned_abs())
            } else {
                now + Duration::from_secs(d as u64)
            };
            check_minted(millis(t), now, window)
        };
        at(0).unwrap();
        at(-599).unwrap();
        at(119).unwrap();
        assert!(at(-601).is_err());
        assert!(at(121).is_err());
    }
}
