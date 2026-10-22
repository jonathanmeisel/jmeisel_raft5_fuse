//! Writing a hybrid file's blocks (see `ObjectGrid`): every change to one
//! -- a write into it, a truncate cutting a segment short, a prune
//! sealing it again under a newer key -- is a new object, since objects
//! are written once. So each is a read-modify-write of the whole block:
//! read its pointer, fetch whichever of its segments the change keeps,
//! change them, seal every segment again under the current key, upload
//! the lot through a URL the servers mint, and commit a pointer to it,
//! guarded by the block's seq. Someone else's change in between makes the
//! commit `EAGAIN`, and it is all done over.
//!
//! A block the change overwrites whole needs nothing read: what a
//! sequential writer, buffering a block at a time, always does. The
//! object a commit replaces, and one uploaded for a commit that then
//! failed, are left for the servers' garbage collection.

use std::collections::HashMap;
use std::ops::Range;

use raft5fs_crypto::data::seal_chunk;
use raft5fs_proto::types::{
    Attr, BlockRef, BlockUpload, ChunkBody, ChunkWrite, Chunks, FsError, Layout, ObjectGrid,
    WriteBody,
};

use super::{CHANGE_RETRIES, Node, Vault, changed, sealed_blob};
use crate::chunk_cache::Lookup;

/// What a rewrite of a block changes.
pub(super) enum BlockEdit<'a> {
    /// `data` at `spans` (index, where in the chunk, how long: see
    /// `spans`), all within the block; the file grows to `end`.
    Write {
        spans: &'a [(u64, usize, usize)],
        data: &'a [u8],
        end: u64,
    },
    /// Everything from byte `keep` of chunk `index` on, gone: the chunk a
    /// truncate's new end falls part-way into. Segments after it the
    /// server drops itself (see `FsCore::setattr`); this one it can't
    /// open to cut.
    Truncate { index: u64, keep: usize },
    /// Sealed again under the current key, if sealed under a version
    /// before `below`.
    Reseal { below: u32 },
}

/// What a rewrite did.
pub(super) enum Rewritten {
    /// Stored a new block of `nseg` segments; with the file's attributes,
    /// unless it was a reseal (which leaves them be).
    Stored { attr: Option<Attr>, nseg: u32 },
    /// Nothing needed doing: no block there, or nothing in it to change.
    Unchanged,
}

impl Vault {
    /// Where file `ino` keeps its data. Fixed when the file is made, so
    /// asked for once and remembered. A filesystem with no object grid
    /// has nothing but inline files.
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

    /// The bytes of file `ino` that are stored together with byte
    /// `offset`: its write batch inline, its block past the grid's start.
    /// What a write buffer fills before handing a run over, so a writer
    /// going through a file stores each batch, and each block, once.
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
            // Up to where the blocks start, never into them.
            return Ok(inline(grid.from_index * chunk_size));
        }
        let start = grid.block_start(index) * chunk_size;
        Ok(start..start + u64::from(grid.per_block) * chunk_size)
    }

    /// Applies `edit` to the block at chunk `start` of hybrid file `ino`,
    /// sealing under `node`'s key: see the module doc.
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
        // Each segment the edit writes, and how much of it.
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
        // Written whole, segment by segment: no need to see what was there.
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

            // The new segments' plaintexts, each a whole chunk.
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
                // A reseal doesn't say the seq it stored at; what it
                // stored, a read finds anew.
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
                    // Whether it landed is unknown: trust nothing cached.
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
            libc::EAGAIN,
            format!("block {start} of inode {ino} kept changing under this change"),
        ))
    }

    /// The block at chunk `start` as it is now, for `edit` to change: its
    /// pointer (`None` if there is no block), the seq a commit replacing
    /// it must expect (0 for none), and the plaintext of each segment the
    /// edit keeps -- from the cache where it still holds the block's
    /// current seq, else fetched.
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
        // The first one is always asked for in full, which is what makes
        // the server send the pointer, and so how many segments there are.
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
                libc::EIO,
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
        // Only what the edit keeps is fetched, and only what isn't cached
        // at the block's seq.
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

    /// Seals `plains` -- whole chunks -- as the block at chunk `start`,
    /// uploads it, and returns the pointer that would commit it.
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
            .ok_or_else(|| FsError::new(libc::EIO, "the server named no upload"))?;
        raft5fs_objstore::http::put(self.remote.objects(), &up.url, body)
            .await
            .map_err(|e| FsError::new(libc::EIO, format!("inode {ino}: uploading a block: {e}")))?;
        Ok(BlockRef {
            version,
            minted_ms: up.minted_ms,
            random: up.random,
            nseg,
        })
    }
}
