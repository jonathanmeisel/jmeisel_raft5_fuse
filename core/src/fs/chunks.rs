//! File data: reading and writing chunks, blocks in object storage, and the
//! uploads for them.

use super::*;

impl FsCore {
    /// Reads up to one write batch of `ino`'s sealed chunks from `first`,
    /// with the file's attributes. It returns fewer than `count` if `count`
    /// is more than a batch. Each chunk comes with the store's sequence
    /// number for it.
    ///
    /// - `known[i]`, if present and not 0, is the seq at which the client
    ///   already has chunk `first + i` (decrypted, in its cache). A chunk
    ///   still at that seq comes back `unchanged`, without its bytes. Only
    ///   its version is read, which costs eight bytes whatever the chunk's
    ///   size.
    /// - `objects_ok` says that the client can fetch from object storage.
    ///   If not, a chunk there gives `ENOTSUP`. Otherwise a client that
    ///   cannot read the pointer would take it for a hole and see zeros.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_chunks(
        &self,
        caller: &Caller,
        ino: u64,
        first: u64,
        count: u32,
        known: &[u64],
        objects_ok: bool,
        at: Option<&[u8]>,
    ) -> Result<Chunks, FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, false).await?;
        let attr = self.resolve(&view, ino).await?.attr;
        let grid = match attr.layout {
            Layout::Inline => None,
            Layout::Hybrid => Some(self.grid.ok_or_else(|| {
                FsError::new(
                    libc::EIO,
                    format!("inode {ino} is hybrid, but no object grid is recorded"),
                )
            })?),
        };
        // A block's chunks cost one read and one pointer, so a read in
        // blocks can cover a whole block.
        let mut cap = chunks_per_batch(self.chunk_size) as u64;
        if let Some(g) = grid.filter(|g| g.in_blocks(first)) {
            cap = cap.max(u64::from(g.per_block));
        }
        let count = u64::from(count).min(cap);

        // Each chunk is stored at its own index, or in a block at the
        // block's start: one key for a run of consecutive chunks. A run
        // holds each chunk's index and the seq the client has it at.
        let mut runs: Vec<(u64, Vec<(u64, u64)>)> = Vec::new();
        for (i, index) in (first..first.saturating_add(count)).enumerate() {
            let stored = grid
                .filter(|g| g.in_blocks(index))
                .map_or(index, |g| g.block_start(index));
            let held = known.get(i).copied().unwrap_or(0);
            match runs.last_mut() {
                Some((at, chunks)) if *at == stored => chunks.push((index, held)),
                _ => runs.push((stored, vec![(index, held)])),
            }
        }
        // If the client has every chunk of a run, the key's seq alone shows
        // whether they are still current. That costs eight bytes whatever
        // the value's size, and all of those are read in one read.
        let held_runs: Vec<usize> = (0..runs.len())
            .filter(|&r| runs[r].1.iter().all(|&(_, held)| held != 0))
            .collect();
        let held_keys: Vec<Vec<u8>> = held_runs
            .iter()
            .map(|&r| chunk_key(ino, runs[r].0))
            .collect();
        let mut current: Vec<Option<u64>> = vec![None; runs.len()];
        for (&r, seq) in held_runs
            .iter()
            .zip(view.read_versions_many(&held_keys).await?)
        {
            if runs[r].1.iter().all(|&(_, held)| held == seq) {
                current[r] = Some(seq);
            }
        }
        // Every other run's value, in one read.
        let fetched_runs: Vec<usize> = (0..runs.len()).filter(|&r| current[r].is_none()).collect();
        let fetched_keys: Vec<Vec<u8>> = fetched_runs
            .iter()
            .map(|&r| chunk_key(ino, runs[r].0))
            .collect();
        let mut fetched: Vec<Option<raft5_client::Entry>> = vec![None; runs.len()];
        for (&r, entry) in fetched_runs
            .iter()
            .zip(view.read_many(&fetched_keys).await?)
        {
            fetched[r] = Some(entry);
        }

        let unchanged = |index, seq| SealedChunk {
            index,
            seq,
            body: ChunkBody::Hole,
            unchanged: true,
        };
        let mut chunks = Vec::with_capacity(count as usize);
        let mut blocks = Vec::new();
        for ((stored, run), (current, read)) in
            runs.into_iter().zip(current.into_iter().zip(fetched))
        {
            if let Some(seq) = current {
                chunks.extend(run.into_iter().map(|(index, _)| unchanged(index, seq)));
                continue;
            }
            let read = read.expect("every run not current was read");
            let is_current = |held: u64| held != 0 && held == read.seq;
            if !grid.is_some_and(|g| g.in_blocks(stored)) {
                // An inline chunk has its own key, so its run has one
                // chunk.
                let (index, held) = run[0];
                if is_current(held) {
                    chunks.push(unchanged(index, held));
                    continue;
                }
                let body = match read.value.map(ChunkValue::decode) {
                    None => ChunkBody::Hole,
                    Some(ChunkValue::Inline(blob)) => ChunkBody::Inline(blob),
                    Some(ChunkValue::Block(_)) => {
                        return Err(FsError::new(
                            libc::EIO,
                            format!("inode {ino}: a block pointer where chunk {index} belongs"),
                        ));
                    }
                };
                chunks.push(SealedChunk {
                    index,
                    seq: read.seq,
                    body,
                    unchanged: false,
                });
                continue;
            }
            let block = match read.value.map(ChunkValue::decode) {
                None => None,
                Some(ChunkValue::Block(block)) => {
                    let url = self.read_url(ino, &block, objects_ok)?;
                    blocks.push(BlockUrl { block, url });
                    Some((blocks.len() as u32 - 1, block.nseg))
                }
                Some(ChunkValue::Inline(_)) => {
                    return Err(FsError::new(
                        libc::EIO,
                        format!("inode {ino}: a sealed chunk where block {stored} belongs"),
                    ));
                }
            };
            for (index, held) in run {
                if is_current(held) {
                    chunks.push(unchanged(index, held));
                    continue;
                }
                let segment = (index - stored) as u32;
                let body = match block {
                    Some((block, nseg)) if segment < nseg => ChunkBody::Segment { block, segment },
                    _ => ChunkBody::Hole,
                };
                chunks.push(SealedChunk {
                    index,
                    seq: read.seq,
                    body,
                    unchanged: false,
                });
            }
        }
        Ok(Chunks {
            attr,
            chunks,
            blocks,
        })
    }

    /// A presigned URL that reads `block` of `ino`, for a client that can
    /// read object storage (`objects_ok`). If it cannot, returns `ENOTSUP`.
    /// Otherwise a client that cannot read the pointer would take it for a
    /// hole and see zeros.
    pub(super) fn read_url(
        &self,
        ino: u64,
        block: &BlockRef,
        objects_ok: bool,
    ) -> Result<String, FsError> {
        if !objects_ok {
            return Err(FsError::new(
                libc::ENOTSUP,
                format!("inode {ino} keeps data in object storage, which this client can't read"),
            ));
        }
        let Some(objects) = &self.objects else {
            return Err(FsError::new(
                libc::EIO,
                format!("inode {ino} keeps data in object storage, which this server can't reach"),
            ));
        };
        Ok(objects
            .store
            .presign_get(&object_name(ino, block), objects.get_ttl))
    }

    /// Names and presigned upload URLs for new blocks of file `ino`, one
    /// for each block asked for, each for exactly the length of its
    /// segments. Needs a writable grant above `ino`, which must be a hybrid
    /// file. Each block must start where the grid says a block starts.
    /// Minting stores nothing: garbage collection removes an upload that
    /// nothing commits.
    pub async fn prepare_uploads(
        &self,
        caller: &Caller,
        ino: u64,
        blocks: &[BlockUpload],
    ) -> Result<Vec<PreparedUpload>, FsError> {
        let (Some(objects), Some(grid)) = (&self.objects, self.grid) else {
            return Err(no_objects());
        };
        if blocks.len() > MAX_UPLOADS {
            return Err(FsError::new(
                libc::EINVAL,
                format!("at most {MAX_UPLOADS} blocks at a time"),
            ));
        }
        let live = self.live();
        self.guard_now(&live, caller, ino, true).await?;
        let entry = self.resolve(&live, ino).await?;
        check_kind(&entry, Kind::File)?;
        if entry.attr.layout != Layout::Hybrid {
            return Err(FsError::new(
                libc::EINVAL,
                format!("inode {ino} keeps nothing in object storage"),
            ));
        }
        // Refuse before the client uploads a block that the write would
        // refuse. Up to the start of each block's last segment, since that
        // segment may be short.
        let ends = blocks.iter().map(|b| {
            (b.index.saturating_add(u64::from(b.nseg.max(1)) - 1))
                .saturating_mul(self.chunk_size)
                .saturating_add(1)
        });
        let growth = ends.max().unwrap_or(0).saturating_sub(entry.attr.size);
        self.check_room(entry.parent, growth).await?;
        let now = SystemTime::now();
        blocks
            .iter()
            .map(|b| {
                if !grid.in_blocks(b.index) || grid.block_start(b.index) != b.index {
                    return Err(FsError::new(
                        libc::EINVAL,
                        format!("no block starts at chunk {}", b.index),
                    ));
                }
                if b.nseg == 0 || b.nseg > grid.per_block {
                    return Err(FsError::new(
                        libc::EINVAL,
                        format!(
                            "a block holds 1 to {} segments, not {}",
                            grid.per_block, b.nseg
                        ),
                    ));
                }
                let name = ObjectName::mint(ino, now);
                let len = u64::from(b.nseg) * segment_len(self.chunk_size);
                Ok(PreparedUpload {
                    minted_ms: name.minted_ms,
                    random: name.random,
                    url: objects.store.presign_put(&name, len, objects.put_ttl),
                })
            })
            .collect()
    }

    /// Refuses a truncate to `new_size` (`EAGAIN`) while the inline chunk that
    /// the new end falls in holds more than it keeps. The client seals that
    /// chunk again, cut short, before it asks. If it still holds more, another
    /// write came in between, and the client should do that again. Otherwise
    /// the bytes past the end would be data that counts for nothing.
    pub(super) async fn check_cut_short(
        &self,
        txn: &Transaction,
        ino: u64,
        new_size: u64,
    ) -> Result<Result<(), FsError>, KvError> {
        let keep = new_size % self.chunk_size;
        if keep == 0 {
            return Ok(Ok(()));
        }
        let index = new_size / self.chunk_size;
        let Some(value) = txn.read_one(&chunk_key(ino, index)).await?.value else {
            return Ok(Ok(()));
        };
        Ok(match ChunkValue::decode(value) {
            ChunkValue::Inline(blob) if plain_len(&blob) > keep => Err(FsError::new(
                libc::EAGAIN,
                format!("chunk {index} of inode {ino} holds more than a truncate keeps"),
            )),
            _ => Ok(()),
        })
    }

    /// For a truncate to `new_size`, the block that the new end falls in
    /// keeps only the segments before the end. `delete_chunks_from` already
    /// removed whole blocks past the end. This block stays, but its later
    /// segments must read as zeros if the file grows again, and must not
    /// come back. The pointer is plaintext, so this only lowers `nseg`: no
    /// keys and no upload. The client has already rewritten a segment that
    /// the end cuts part way through.
    pub(super) async fn trim_block(
        &self,
        txn: &Transaction,
        entry: &Entry,
        new_size: u64,
    ) -> Result<Result<(), FsError>, KvError> {
        let Some(grid) = self.grid.filter(|_| entry.attr.layout == Layout::Hybrid) else {
            return Ok(Ok(()));
        };
        // The first chunk that is completely past the new end.
        let cut = new_size.div_ceil(self.chunk_size);
        if cut == 0 || !grid.in_blocks(cut - 1) {
            return Ok(Ok(()));
        }
        let start = grid.block_start(cut - 1);
        let key = chunk_key(entry.attr.ino, start);
        let Some(value) = txn.read_one(&key).await?.value else {
            return Ok(Ok(()));
        };
        if let ChunkValue::Block(mut block) = ChunkValue::decode(value) {
            let keep = (cut - start) as u32;
            if block.nseg > keep {
                block.nseg = keep;
                txn.write(&key, Some(&encode_pointer(&block))).await?;
            }
        }
        Ok(Ok(()))
    }

    /// Stores sealed chunks of `ino` and grows the file to `end`.
    ///
    /// - If any chunk is not at its `expected_seq`, nothing is stored
    ///   (`EAGAIN`).
    /// - Each chunk must be sealed under the file's current key version
    ///   (`EKEYEXPIRED` if not, so the client fetches the key again).
    ///
    /// Returns the file's attributes, and the seq of every chunk written,
    /// so the client can cache what it wrote.
    pub async fn write_chunks(
        &self,
        caller: &Caller,
        ino: u64,
        writes: &[ChunkWrite],
        end: u64,
    ) -> Result<(Attr, u64), FsError> {
        self.check_chunk_writes(writes)?;
        let (attr, dropped, grown, parent) = run_txn(&self.client, move |txn| async move {
            decide!(self.guard(&txn, caller, ino, true).await?);
            decide!(self.fresh(&txn, ino).await?);
            // Read the Entry first. This is required: a deletion marks the
            // Entry before it removes the chunks, in a transaction that
            // conflicts with this one on the Entry. So no chunk is stored
            // after the deletion's scan has passed it. The Entry is removed
            // last, so no chunk is stored for an inode that nothing can
            // reach.
            let mut entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, Kind::File));
            if let Err(e) = self
                .check_room(entry.parent, end.saturating_sub(entry.attr.size))
                .await
            {
                return Ok(Err(e));
            }
            let before = entry.attr.size;
            let dropped =
                decide!(put_chunks(self, &txn, &entry, writes, false, before.max(end)).await?);
            if end > entry.attr.size {
                entry.attr.size = end;
            }
            let now = SystemTime::now();
            entry.attr.mtime = now;
            entry.attr.ctime = now;
            write_entry(&txn, &entry).await?;
            let seq = txn.commit().await?;
            let grown = entry.attr.size - before;
            Ok(Ok(((entry.attr, seq), dropped, grown, entry.parent)))
        })
        .await??;
        self.discard(dropped);
        self.count(parent, grown as i64).await;
        self.note_edit(caller, ino, parent).await;
        Ok(attr)
    }

    /// Deletes every chunk of `ino` from `first_index` up, in limited
    /// batches. A scan (not a walk of `0..=size/chunk_size`) skips holes,
    /// finds anything an interrupted truncate left, and does not depend on
    /// the recorded size. If the file's `layout` is hybrid, returns the
    /// objects that the deleted pointers named. Only then are block starts'
    /// values read.
    pub(super) async fn delete_chunks_from(
        &self,
        ino: u64,
        first_index: u64,
        layout: Layout,
    ) -> Result<Vec<Dropped>, KvError> {
        let prefix = chunk_prefix(ino);
        let grid = self.grid.filter(|_| layout == Layout::Hybrid);
        let mut dropped = Vec::new();
        loop {
            let mut iter = self
                .client
                .key_iterator(&chunk_key(ino, first_index), Consistency::Stale);
            let mut batch = Vec::new();
            while batch.len() < DELETE_BATCH {
                match next_key(&mut iter).await? {
                    // `key_iterator` runs to the end of the keyspace, so
                    // the walk ends when it leaves this inode's chunks.
                    Some(key) if !key.starts_with(&prefix) => break,
                    Some(key) if is_chunk_key(&key, &prefix) => batch.push(key),
                    Some(_) => {}
                    None => break,
                }
            }
            if batch.is_empty() {
                return Ok(dropped);
            }

            let batch = &batch;
            let starts: &Vec<(u64, &Vec<u8>)> = &batch
                .iter()
                .filter_map(|key| {
                    let grid = grid?;
                    let index = u64::from_be_bytes(key[prefix.len()..].try_into().unwrap());
                    (grid.in_blocks(index) && grid.block_start(index) == index)
                        .then_some((index, key))
                })
                .collect();
            dropped.extend(
                run_txn(&self.client, move |txn| async move {
                    let keys: Vec<&Vec<u8>> = starts.iter().map(|&(_, key)| key).collect();
                    let mut found = Vec::new();
                    for (&(index, _), entry) in starts.iter().zip(txn.read_many(&keys).await?) {
                        if let Some(value) = entry.value
                            && let ChunkValue::Block(block) = ChunkValue::decode(value)
                        {
                            found.push(Dropped::new(ino, index, &block));
                        }
                    }
                    for key in batch {
                        txn.write(key, None).await?;
                    }
                    txn.commit().await?;
                    Ok(found)
                })
                .await?,
            );
        }
    }
}
