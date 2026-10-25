//! Writes a hybrid file's blocks (see `ObjectGrid`).
//!
//! Objects are written once, so every change to a block makes a new object:
//! a write into it, a truncate that cuts a segment short, or a prune that
//! seals it again under a newer key. So each change is a read-modify-write
//! of the whole block:
//!
//! - Read the block's pointer.
//! - Fetch the segments that the change keeps, and change them.
//! - Seal every segment again under the current key.
//! - Upload the block through a URL that the servers mint.
//! - Commit a pointer to it, guarded by the block's seq. If another client
//!   changed the block in between, the commit gives `EAGAIN` and all the
//!   steps run again.
//!
//! A change that overwrites the whole block reads nothing. A sequential
//! writer that buffers one block at a time always does this. The servers'
//! garbage collection removes the object that a commit replaces, and any
//! object uploaded for a commit that then failed.

use std::collections::HashMap;
use std::ops::Range;

use raft5fs_crypto::data::seal_chunk;
use raft5fs_proto::errno;
use raft5fs_proto::types::{
    Attr, BlockRef, BlockUpload, ChunkBody, ChunkWrite, Chunks, FsError, Layout, ObjectGrid,
    WriteBody,
};

use super::{CHANGE_RETRIES, Node, Vault, changed, sealed_blob};
use crate::chunk_cache::Lookup;

/// What a rewrite of a block changes.
pub(super) enum BlockEdit<'a> {
    /// `data` at `spans` (index, offset in the chunk, length: see `spans`),
    /// all in the block. The file grows to `end`.
    Write {
        spans: &'a [(u64, usize, usize)],
        data: &'a [u8],
        end: u64,
    },
    /// Removes everything from byte `keep` of chunk `index` up: the chunk
    /// that a truncate's new end falls part way into. The server removes
    /// later segments itself (see `FsCore::setattr`), but it cannot open
    /// this one to cut it.
    Truncate { index: u64, keep: usize },
    /// Seals the block again under the current key, if it is sealed under a
    /// version before `below`.
    Reseal { below: u32 },
}

/// What a rewrite did.
pub(super) enum Rewritten {
    /// Stored a new block of `nseg` segments. `attr` has the file's
    /// attributes, except for a reseal, which does not change them.
    Stored { attr: Option<Attr>, nseg: u32 },
    /// Nothing to do: there is no block, or nothing in it to change.
    Unchanged,
}

impl Vault {
    /// Where file `ino` keeps its data. It does not change after the file
    /// is made, so it is asked for once and remembered. A filesystem with
    /// no object grid has only inline files.
    pub(super) async fn layout(&self, ino: u64) -> Result<Layout, FsError> {
        if self.remote.grid().is_none() {
            return Ok(Layout::Inline);
        }
        if let Some(&layout) = self.layouts.lock().unwrap().get(&ino) {
            return Ok(layout);
        }
        let layout = self.remote.getattr(ino).await?.layout;
        self.layouts.lock().unwrap().insert(ino, layout);
        Ok(layout)
    }

    /// The bytes of file `ino` that are stored together with byte `offset`:
    /// its write batch for inline chunks, or its block after the grid's
    /// start. A write buffer fills this range before it sends a run, so a
    /// writer that goes through a file stores each batch, and each block,
    /// once.
    pub async fn batch_at(&self, ino: u64, offset: u64) -> Result<Range<u64>, FsError> {
        let chunk_size = self.remote.chunk_size();
        let batch = self.remote.batch_bytes().max(chunk_size);
        let inline = |limit: u64| {
            let start = offset / batch * batch;
            start..(start + batch).min(limit)
        };
        let Some(grid) = self.remote.grid() else {
            return Ok(inline(u64::MAX));
        };
        if self.layout(ino).await? != Layout::Hybrid {
            return Ok(inline(u64::MAX));
        }
        let index = offset / chunk_size;
        if !grid.in_blocks(index) {
            // Stop where the blocks start.
            return Ok(inline(grid.from_index * chunk_size));
        }
        let start = grid.block_start(index) * chunk_size;
        Ok(start..start + u64::from(grid.per_block) * chunk_size)
    }

    /// Applies `edit` to the block at chunk `start` of hybrid file `ino`,
    /// and seals under `node`'s key (see the module doc).
    ///
    /// Steps, repeated up to `CHANGE_RETRIES` times:
    ///
    /// - If the edit overwrites every segment whole, skip the read.
    ///   Otherwise read the block (`read_block`).
    /// - Build each new segment's plaintext, padded to a whole chunk, and
    ///   apply the edit.
    /// - Upload the block (`upload_block`) and commit its pointer,
    ///   expecting the block's seq.
    /// - If another client changed the block first (`EAGAIN`), drop the
    ///   block's cached chunks and start again.
    ///
    /// Returns `Rewritten::Unchanged` if there is nothing to do. On any
    /// other error, the result is not known, so it drops the file's whole
    /// cache.
    pub(super) async fn rewrite_block(
        &self,
        node: &Node,
        ino: u64,
        grid: ObjectGrid,
        start: u64,
        edit: BlockEdit<'_>,
    ) -> Result<Rewritten, FsError> {
        let chunk_size = self.remote.chunk_size() as usize;
        let per = grid.per_block;
        // For each segment that the edit writes: the offset in the chunk,
        // and the range of `data`.
        let mut writes: HashMap<u32, Vec<(usize, Range<usize>)>> = HashMap::new();
        if let BlockEdit::Write { spans, .. } = &edit {
            let mut cursor = 0;
            for &(index, within, n) in *spans {
                let j = (index - start) as u32;
                writes
                    .entry(j)
                    .or_default()
                    .push((within, cursor..cursor + n));
                cursor += n;
            }
        }
        let whole = |j: u32| {
            writes.get(&j).is_some_and(|w| {
                w.iter()
                    .any(|(within, r)| *within == 0 && r.len() == chunk_size)
            })
        };
        // Every segment is overwritten whole, so there is no need to read
        // what was there.
        let blind = matches!(edit, BlockEdit::Write { .. }) && (0..per).all(whole);

        for _ in 0..CHANGE_RETRIES {
            let generation = self
                .cache
                .lock()
                .unwrap()
                .get(self.space, ino, start)
                .generation();
            let mut old_plain: HashMap<u32, Vec<u8>> = HashMap::new();
            let (old, seq) = if blind {
                (None, None)
            } else {
                let (old, seq, plains) = self
                    .read_block(node, ino, start, per, &edit, &whole)
                    .await?;
                old_plain = plains;
                (old, Some(seq))
            };
            let old_nseg = old.map_or(0, |b: BlockRef| b.nseg);
            let nseg = match &edit {
                BlockEdit::Write { .. } => {
                    let last = writes.keys().max().copied().unwrap_or(0);
                    old_nseg.max(last + 1)
                }
                BlockEdit::Truncate { index, .. } => {
                    let j = (index - start) as u32;
                    if j >= old_nseg {
                        return Ok(Rewritten::Unchanged);
                    }
                    j + 1
                }
                BlockEdit::Reseal { below } => match old {
                    Some(b) if b.version < *below => b.nseg,
                    _ => return Ok(Rewritten::Unchanged),
                },
            };

            // The new segments' plaintexts, each a whole chunk, so ranged
            // reads can find each segment.
            let mut plains = Vec::with_capacity(nseg as usize);
            for j in 0..nseg {
                let mut plain = old_plain.remove(&j).unwrap_or_default();
                plain.resize(chunk_size, 0);
                match &edit {
                    BlockEdit::Write { data, .. } => {
                        for (within, r) in writes.get(&j).into_iter().flatten() {
                            plain[*within..*within + r.len()].copy_from_slice(&data[r.clone()]);
                        }
                    }
                    BlockEdit::Truncate { index, keep } if u64::from(j) == index - start => {
                        plain[*keep..].fill(0);
                    }
                    _ => {}
                }
                plains.push(plain);
            }

            let block = self.upload_block(node, ino, start, &plains).await?;
            let write = ChunkWrite {
                index: start,
                expected_seq: seq,
                body: WriteBody::Block(block),
            };
            let stored = match &edit {
                BlockEdit::Write { end, .. } => self
                    .remote
                    .write_chunks(ino, &[write], *end)
                    .await
                    .map(|(attr, seq)| (Some(attr), seq)),
                BlockEdit::Truncate { .. } => self
                    .remote
                    .write_chunks(ino, &[write], 0)
                    .await
                    .map(|(attr, seq)| (Some(attr), seq)),
                // A reseal does not return the seq it stored at, so a later
                // read finds it.
                BlockEdit::Reseal { .. } => self
                    .remote
                    .reseal_chunks(ino, &[write])
                    .await
                    .map(|()| (None, 0)),
            };
            let blocks = start..=start + u64::from(per) - 1;
            match stored {
                Err(e) if changed(&e) => {
                    self.cache
                        .lock()
                        .unwrap()
                        .invalidate(self.space, ino, blocks);
                }
                Err(e) => {
                    // It is not known whether the commit was stored, so do
                    // not trust the cache.
                    self.cache.lock().unwrap().invalidate_ino(self.space, ino);
                    return Err(e);
                }
                Ok((attr, seq)) => {
                    let mut cache = self.cache.lock().unwrap();
                    cache.invalidate(self.space, ino, blocks);
                    if seq != 0 {
                        for (j, plain) in plains.into_iter().enumerate() {
                            let index = start + j as u64;
                            cache.insert(self.space, ino, index, plain.into(), seq, generation);
                        }
                    }
                    return Ok(Rewritten::Stored { attr, nseg });
                }
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("block {start} of inode {ino} kept changing under this change"),
        ))
    }

    /// Reads the block at chunk `start` as it is now, for `edit` to change.
    ///
    /// Returns:
    ///
    /// - its pointer (`None` if there is no block);
    /// - the seq that a commit replacing it must expect (0 for none);
    /// - the plaintext of each segment that the edit keeps. It uses the
    ///   cache where the cache still has the block's current seq, and
    ///   fetches the rest.
    async fn read_block(
        &self,
        node: &Node,
        ino: u64,
        start: u64,
        per: u32,
        edit: &BlockEdit<'_>,
        whole: &(dyn Fn(u32) -> bool + Sync),
    ) -> Result<(Option<BlockRef>, u64, HashMap<u32, Vec<u8>>), FsError> {
        let lookups: Vec<Lookup> = {
            let mut cache = self.cache.lock().unwrap();
            (0..u64::from(per))
                .map(|j| cache.get(self.space, ino, start + j))
                .collect()
        };
        // Always ask for the first chunk in full. Only then does the server
        // send the pointer, which gives the number of segments.
        let known: Vec<u64> = lookups
            .iter()
            .enumerate()
            .map(|(j, l)| match l {
                Lookup::Unconfirmed { version, .. } if j > 0 => *version,
                _ => 0,
            })
            .collect();
        let mut read = self.remote.read_chunks(ino, start, per, &known).await?;
        if read.chunks.len() != per as usize || read.chunks[0].index != start {
            return Err(FsError::new(
                errno::EIO,
                format!("inode {ino}: block {start} came back cut short"),
            ));
        }
        let seq = read.chunks[0].seq;
        let old = match read.chunks[0].body {
            ChunkBody::Segment { block, .. } => Some(read.blocks[block as usize].block),
            _ => None,
        };
        let old_nseg = old.map_or(0, |b| b.nseg);
        let keeps = |j: u32| match edit {
            BlockEdit::Write { .. } => !whole(j),
            BlockEdit::Truncate { index, .. } => u64::from(j) <= index - start,
            BlockEdit::Reseal { .. } => true,
        };

        let mut plains = HashMap::new();
        // Fetch only the segments that the edit keeps, and only those not
        // cached at the block's seq.
        for (j, (chunk, lookup)) in read.chunks.iter_mut().zip(&lookups).enumerate() {
            let j = j as u32;
            if j >= old_nseg || !keeps(j) {
                chunk.body = ChunkBody::Hole;
            } else if let Lookup::Unconfirmed { data, version, .. } = lookup
                && (chunk.unchanged || *version == seq)
            {
                plains.insert(j, data.to_vec());
                chunk.body = ChunkBody::Hole;
            }
        }
        let fetched = self
            .fetch_segments(
                ino,
                vec![Chunks {
                    attr: read.attr,
                    chunks: read.chunks,
                    blocks: read.blocks,
                }],
            )
            .await?;
        for (j, chunk) in fetched.into_iter().enumerate() {
            if let Some(blob) = sealed_blob(ino, &chunk.body)? {
                plains.insert(j as u32, self.open(node, ino, chunk.index, blob)?);
            }
        }
        Ok((old, seq, plains))
    }

    /// Seals `plains` (whole chunks) as the block at chunk `start`, uploads
    /// it, and returns the pointer that would commit it.
    async fn upload_block(
        &self,
        node: &Node,
        ino: u64,
        start: u64,
        plains: &[Vec<u8>],
    ) -> Result<BlockRef, FsError> {
        let nseg = plains.len() as u32;
        let version = node.record.version;
        let mut body = Vec::new();
        for (j, plain) in plains.iter().enumerate() {
            body.extend(seal_chunk(&node.key, version, ino, start + j as u64, plain));
        }
        let up = self
            .remote
            .prepare_uploads(ino, &[BlockUpload { index: start, nseg }])
            .await?
            .pop()
            .ok_or_else(|| FsError::new(errno::EIO, "the server named no upload"))?;
        raft5fs_objstore::http::put(self.remote.objects(), &up.url, body)
            .await
            .map_err(|e| {
                FsError::new(errno::EIO, format!("inode {ino}: uploading a block: {e}"))
            })?;
        Ok(BlockRef {
            version,
            minted_ms: up.minted_ms,
            random: up.random,
            nseg,
        })
    }
}
