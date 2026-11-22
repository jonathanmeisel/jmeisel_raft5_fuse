//! File data: reading and writing chunks, through the cache.

use super::*;

impl Vault {
    /// Returns bytes `[offset, offset + len)` of file `ino`.
    ///
    /// - Stops at the end of the file. Returns nothing if `offset` is at or
    ///   past the end.
    /// - Holes read as zeros.
    /// - Uses a cached chunk only after the server confirms that it has not
    ///   changed.
    pub async fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let chunk_size = self.remote.chunk_size();
        let first = offset / chunk_size;
        let last = (offset + len as u64 - 1) / chunk_size;
        let lookups: Vec<Lookup> = {
            let mut cache = self.cache.lock().unwrap();
            (first..=last)
                .map(|index| cache.get(self.space, ino, index))
                .collect()
        };
        let known: Vec<u64> = lookups
            .iter()
            .map(|l| match l {
                Lookup::Unconfirmed { version, .. } => *version,
                Lookup::Miss { .. } => 0,
            })
            .collect();
        let (size, chunks) = self.fetch(ino, first, last, &known).await?;
        if offset >= size {
            return Ok(Vec::new());
        }
        let end = (offset + len as u64).min(size);
        let mut out = vec![0; (end - offset) as usize];
        let mut node = None;
        for (chunk, lookup) in chunks.into_iter().zip(lookups) {
            let index = chunk.index;
            let plain = self.chunk_from(ino, chunk, lookup, &mut node).await?;
            let start = index * chunk_size;
            let lo = start.max(offset);
            let hi = (start + plain.len() as u64).min(end);
            if lo < hi {
                out[(lo - offset) as usize..(hi - offset) as usize]
                    .copy_from_slice(&plain[(lo - start) as usize..(hi - start) as usize]);
            }
        }
        Ok(out)
    }

    /// Reads chunks `chunks` of `ino` into the cache, for a reader that will
    /// want them soon (see `readahead`).
    ///
    /// - Fetches the chunks in up to `PREFETCH_PIECES` pieces at the same
    ///   time, because a store limits the speed of each request.
    /// - Skips a piece whose chunks are all cached. The read that uses them
    ///   confirms them.
    /// - Drops errors: the read that wants a chunk fetches it again.
    pub async fn prefetch(&self, ino: u64, chunks: std::ops::RangeInclusive<u64>) {
        let (first, last) = (*chunks.start(), *chunks.end());
        let per = (last - first + 1).div_ceil(PREFETCH_PIECES);
        let pieces = (first..=last).step_by(per as usize).map(|start| {
            let end = (start + per - 1).min(last);
            self.cache_chunks(ino, start, end)
        });
        futures_util::future::join_all(pieces).await;
    }

    /// `prefetch` for one piece.
    pub(super) async fn cache_chunks(&self, ino: u64, first: u64, last: u64) {
        let lookups: Vec<Lookup> = {
            let mut cache = self.cache.lock().unwrap();
            (first..=last)
                .map(|index| cache.get(self.space, ino, index))
                .collect()
        };
        if lookups
            .iter()
            .all(|l| matches!(l, Lookup::Unconfirmed { .. }))
        {
            return;
        }
        let known: Vec<u64> = lookups
            .iter()
            .map(|l| match l {
                Lookup::Unconfirmed { version, .. } => *version,
                Lookup::Miss { .. } => 0,
            })
            .collect();
        let Ok((_, chunks)) = self.fetch(ino, first, last, &known).await else {
            return;
        };
        let mut node = None;
        for (chunk, lookup) in chunks.into_iter().zip(lookups) {
            if self
                .chunk_from(ino, chunk, lookup, &mut node)
                .await
                .is_err()
            {
                return;
            }
        }
    }

    /// Returns the plaintext for one chunk of a read: the cached bytes that
    /// the server confirmed, or the bytes that the server sent, opened and
    /// cached. `node` holds the file's key, fetched the first time it is
    /// needed.
    pub(super) async fn chunk_from(
        &self,
        ino: u64,
        chunk: SealedChunk,
        lookup: Lookup,
        node: &mut Option<Arc<Node>>,
    ) -> Result<Arc<[u8]>, FsError> {
        let index = chunk.index;
        if chunk.unchanged {
            if let Lookup::Unconfirmed {
                data, generation, ..
            } = lookup
                && self
                    .cache
                    .lock()
                    .unwrap()
                    .confirm(self.space, ino, index, generation)
            {
                return Ok(data);
            }
            // The server confirmed that the chunk did not change, but the
            // cache dropped it in the meantime, possibly because of a write
            // from this client. Read it again.
            let fresh = self.fetch_one(ino, index, 0).await?;
            let generation = self
                .cache
                .lock()
                .unwrap()
                .get(self.space, ino, index)
                .generation();
            return self.open_and_keep(ino, fresh, generation, node).await;
        }
        let generation = match lookup {
            Lookup::Unconfirmed { generation, .. } | Lookup::Miss { generation } => generation,
        };
        self.open_and_keep(ino, chunk, generation, node).await
    }

    /// Opens a chunk as the server sent it (a hole is empty) and caches it
    /// at its seq.
    pub(super) async fn open_and_keep(
        &self,
        ino: u64,
        chunk: SealedChunk,
        generation: u64,
        node: &mut Option<Arc<Node>>,
    ) -> Result<Arc<[u8]>, FsError> {
        let plain: Arc<[u8]> = match sealed_blob(ino, &chunk.body)? {
            Some(blob) => {
                let version = sealed_version(blob).map_err(|e| corrupt(ino, e))?;
                let known = match node.take() {
                    Some(known) => known,
                    None => self.node(ino).await?,
                };
                // The chunk is sealed under a newer key than the one known
                // here, so another client rotated the key.
                let current = if version > known.record.version {
                    self.refresh(ino).await?
                } else {
                    known
                };
                let opened = self.open(&current, ino, chunk.index, blob)?;
                *node = Some(current);
                opened.into()
            }
            None => Arc::from(Vec::new()),
        };
        self.cache.lock().unwrap().insert(
            self.space,
            ino,
            chunk.index,
            Arc::clone(&plain),
            chunk.seq,
            generation,
        );
        Ok(plain)
    }

    /// Fetches chunks `first..=last` of `ino`, in as many requests as the
    /// server's limit needs, and returns the file's size from the last
    /// reply. `known[i]` is the seq that chunk `first + i` is cached at, or
    /// 0. Chunks in object storage come back fetched, as if they were
    /// inline (see `fetch_segments`).
    pub(super) async fn fetch(
        &self,
        ino: u64,
        first: u64,
        last: u64,
        known: &[u64],
    ) -> Result<(u64, Vec<SealedChunk>), FsError> {
        let mut reads = Vec::new();
        let mut size = 0;
        let mut next = first;
        while next <= last {
            let count = (last - next + 1).min(u64::from(u32::MAX)) as u32;
            let known = &known[(next - first) as usize..];
            let read = self.remote.read_chunks(ino, next, count, known).await?;
            size = read.attr.size;
            let Some(after) = read.chunks.last().map(|c| c.index + 1) else {
                return Err(FsError::new(errno::EIO, "the server returned no chunks"));
            };
            next = after;
            reads.push(read);
        }
        Ok((size, self.fetch_segments(ino, reads).await?))
    }

    /// Fetches one chunk of `ino` and its seq. If the chunk is still at
    /// `known` (0 for none), it comes back `unchanged`, with no bytes.
    pub(super) async fn fetch_one(
        &self,
        ino: u64,
        index: u64,
        known: u64,
    ) -> Result<SealedChunk, FsError> {
        let read = self.remote.read_chunks(ino, index, 1, &[known]).await?;
        let mut got = self.fetch_segments(ino, vec![read]).await?;
        got.pop().filter(|c| c.index == index).ok_or_else(|| {
            FsError::new(errno::EIO, format!("chunk {index} of inode {ino} missing"))
        })
    }

    /// Fetches each chunk in `reads` that is in object storage, and puts
    /// its sealed bytes in its place. Later code can then read it like an
    /// inline chunk.
    ///
    /// - Groups consecutive segments of one block into one ranged GET.
    /// - Runs up to `MAX_FETCHES` GETs at the same time.
    ///
    /// A range can be cut from a block without reading the rest, because
    /// each segment is padded with zeros to a full chunk before sealing. So
    /// all segments have the same length.
    pub(super) async fn fetch_segments(
        &self,
        ino: u64,
        reads: Vec<Chunks>,
    ) -> Result<Vec<SealedChunk>, FsError> {
        let segment_len = self.remote.chunk_size() + CHUNK_OVERHEAD as u64;
        let mut chunks = Vec::new();
        // The runs to fetch: the URL, the first segment, and the place in
        // `chunks` for each segment of the run.
        let mut runs: Vec<(String, u32, Vec<usize>)> = Vec::new();
        for read in reads {
            let mut wanted: Vec<(u32, u32, usize)> = Vec::new();
            for chunk in read.chunks {
                if let ChunkBody::Segment { block, segment } = chunk.body {
                    wanted.push((block, segment, chunks.len()));
                }
                chunks.push(chunk);
            }
            wanted.sort_unstable();
            for (block, segment, at) in wanted {
                match runs.last_mut() {
                    Some((url, start, ats))
                        if *url == read.blocks[block as usize].url
                            && *start + ats.len() as u32 == segment =>
                    {
                        ats.push(at)
                    }
                    _ => runs.push((read.blocks[block as usize].url.clone(), segment, vec![at])),
                }
            }
        }

        // Several downloads in flight at once. They only fetch: opening the
        // chunks happens below, so one task polling them all loses nothing.
        let mut fetching = FuturesUnordered::new();
        let mut runs = runs.into_iter();
        loop {
            while fetching.len() < MAX_FETCHES {
                let Some((url, start, ats)) = runs.next() else {
                    break;
                };
                let client = self.remote.objects().clone();
                let range = u64::from(start) * segment_len
                    ..(u64::from(start) + ats.len() as u64) * segment_len;
                fetching.push(async move {
                    let bytes = raft5fs_objstore::http::get_range(&client, &url, range).await;
                    (bytes, ats)
                });
            }
            let Some((bytes, ats)) = fetching.next().await else {
                break;
            };
            let bytes = bytes.map_err(|e| {
                FsError::new(errno::EIO, format!("inode {ino}: fetching a block: {e}"))
            })?;
            for (sealed, at) in bytes.chunks(segment_len as usize).zip(ats) {
                chunks[at].body = ChunkBody::Inline(sealed.to_vec());
            }
        }
        Ok(chunks)
    }

    /// Opens a sealed chunk of `ino` with the key version that it was
    /// sealed under.
    pub(super) fn open(
        &self,
        node: &Node,
        ino: u64,
        index: u64,
        blob: &[u8],
    ) -> Result<Vec<u8>, FsError> {
        let version = sealed_version(blob).map_err(|e| corrupt(ino, e))?;
        let key = node.key_at(ino, version)?;
        open_chunk(&key, ino, index, blob).map_err(|e| corrupt(ino, e))
    }

    /// Returns the current plaintext of chunk `index` and its seq, to
    /// change and write back. It uses the cached copy without asking the
    /// server, because the write sends the seq it expects, and the server
    /// refuses the write if the copy is out of date. If there is no cached
    /// copy, it fetches the chunk.
    pub(super) async fn base(
        &self,
        node: &Node,
        ino: u64,
        index: u64,
    ) -> Result<(Vec<u8>, u64), FsError> {
        if let Lookup::Unconfirmed { data, version, .. } =
            self.cache.lock().unwrap().get(self.space, ino, index)
        {
            return Ok((data.to_vec(), version));
        }
        let chunk = self.fetch_one(ino, index, 0).await?;
        let plain = match sealed_blob(ino, &chunk.body)? {
            Some(blob) => self.open(node, ino, index, blob)?,
            None => Vec::new(),
        };
        Ok((plain, chunk.seq))
    }

    /// Writes `data` at `offset` in file `ino`, and makes the file larger
    /// if necessary.
    ///
    /// Steps:
    ///
    /// - Split the range into one span for each chunk.
    /// - Group the spans: one group for each block in a hybrid file's block
    ///   region, and at most one batch for each group of inline chunks.
    /// - Store each group in order: `rewrite_block` for a block,
    ///   `write_batch` for inline chunks. If the key is stale, get new keys
    ///   and try that group once more.
    ///
    /// Returns the file's attributes after the last group.
    ///
    /// Edge cases:
    ///
    /// - An empty write stores nothing, but still changes mtime.
    /// - On failure, `WriteError::written` counts the bytes stored, in
    ///   whole groups. The groups before the failed one stay stored.
    pub async fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<Attr, WriteError> {
        let failed = |written, error| WriteError { written, error };
        let mut node = self.fresh_node(ino).await.map_err(|e| failed(0, e))?;
        if data.is_empty() {
            // An empty write still changes mtime.
            let touched = match self.remote.write_chunks(ino, &[], offset).await {
                Err(e) if expired(&e) => {
                    self.freshen(ino).await.map_err(|e| failed(0, e))?;
                    self.remote.write_chunks(ino, &[], offset).await
                }
                other => other,
            };
            return touched.map(|(attr, _)| attr).map_err(|e| failed(0, e));
        }
        let chunk_size = self.remote.chunk_size();
        let per_batch = (self.remote.batch_bytes() / chunk_size).max(1) as usize;
        let spans = spans(chunk_size, offset, data.len());
        // Spans are in order, so if the last span is not in a block, no
        // span is.
        let grid = match self.remote.grid() {
            Some(grid)
                if spans
                    .last()
                    .is_some_and(|&(index, ..)| grid.in_blocks(index)) =>
            {
                match self.layout(ino).await.map_err(|e| failed(0, e))? {
                    Layout::Hybrid => Some(grid),
                    Layout::Inline => None,
                }
            }
            _ => None,
        };
        let block_of = |index: u64| {
            grid.filter(|g| g.in_blocks(index))
                .map(|g| g.block_start(index))
        };
        // Each group is stored in one commit. An inline group holds at most
        // one batch, to stay below the server's transaction size limit.
        let mut groups: Vec<(Option<u64>, &[Span])> = Vec::new();
        let mut rest = &spans[..];
        while let Some(&(index, ..)) = rest.first() {
            let block = block_of(index);
            let len = rest
                .iter()
                .take_while(|&&(i, ..)| block_of(i) == block)
                .count()
                .min(if block.is_some() {
                    usize::MAX
                } else {
                    per_batch
                });
            groups.push((block, &rest[..len]));
            rest = &rest[len..];
        }

        let mut attr = None;
        let mut cursor = 0;
        for (block, group) in groups {
            let bytes: usize = group.iter().map(|&(_, _, n)| n).sum();
            let end = offset + (cursor + bytes) as u64;
            let piece = &data[cursor..cursor + bytes];
            let once = |node: Arc<Node>| async move {
                match (block, grid) {
                    (Some(start), Some(grid)) => {
                        let edit = BlockEdit::Write {
                            spans: group,
                            data: piece,
                            end,
                        };
                        match self.rewrite_block(&node, ino, grid, start, edit).await? {
                            Rewritten::Stored {
                                attr: Some(attr), ..
                            } => Ok(attr),
                            _ => Err(FsError::new(errno::EIO, "a write stored nothing")),
                        }
                    }
                    _ => self.write_batch(&node, ino, group, piece, end).await,
                }
            };
            let stored = match once(Arc::clone(&node)).await {
                // The key is stale, here or above. Get new keys and try
                // again.
                Err(e) if expired(&e) => {
                    node = self.freshen(ino).await.map_err(|e| failed(cursor, e))?;
                    once(Arc::clone(&node)).await
                }
                other => other,
            }
            .map_err(|e| failed(cursor, e))?;
            attr = Some(stored);
            cursor += bytes;
        }
        Ok(attr.expect("a non-empty write has at least one batch"))
    }

    /// Stores one inline group of spans in one transaction, and caches what
    /// it stores.
    ///
    /// Steps:
    ///
    /// - Seal each span's chunk. A whole-chunk span seals the new bytes
    ///   directly. A partial span changes the chunk's current bytes
    ///   (`base`), and the write expects the chunk's seq.
    /// - Send all chunks in one `write_chunks` call.
    /// - If another writer changed a chunk first (`EAGAIN`), drop the
    ///   cached copies and do it again, up to `CHANGE_RETRIES` times.
    ///
    /// On any other error, the result is not known, so it drops the file's
    /// whole cache.
    pub(super) async fn write_batch(
        &self,
        node: &Node,
        ino: u64,
        spans: &[(u64, usize, usize)],
        data: &[u8],
        end: u64,
    ) -> Result<Attr, FsError> {
        let chunk_size = self.remote.chunk_size();
        for _ in 0..CHANGE_RETRIES {
            let generation = self
                .cache
                .lock()
                .unwrap()
                .get(self.space, ino, spans[0].0)
                .generation();
            let mut writes = Vec::with_capacity(spans.len());
            let mut plains = Vec::with_capacity(spans.len());
            let mut cursor = 0;
            for &(index, within, n) in spans {
                let piece = &data[cursor..cursor + n];
                cursor += n;
                let (plain, expected_seq) = if within == 0 && n as u64 == chunk_size {
                    (piece.to_vec(), None)
                } else {
                    let (mut plain, seq) = self.base(node, ino, index).await?;
                    if plain.len() < within + n {
                        plain.resize(within + n, 0);
                    }
                    plain[within..within + n].copy_from_slice(piece);
                    (plain, Some(seq))
                };
                writes.push(ChunkWrite {
                    index,
                    expected_seq,
                    body: WriteBody::Inline(seal_chunk(
                        &node.key,
                        node.record.version,
                        ino,
                        index,
                        &plain,
                    )),
                });
                plains.push((index, plain));
            }
            match self.remote.write_chunks(ino, &writes, end).await {
                Err(e) if changed(&e) => {
                    // A cached base was out of date. Drop it and fetch it
                    // again.
                    let mut cache = self.cache.lock().unwrap();
                    for &(index, ..) in spans {
                        cache.invalidate(self.space, ino, index..=index);
                    }
                }
                Err(e) => {
                    // It is not known whether the write was stored, so do
                    // not trust the cache.
                    self.cache.lock().unwrap().invalidate_ino(self.space, ino);
                    return Err(e);
                }
                Ok((attr, seq)) => {
                    let mut cache = self.cache.lock().unwrap();
                    for (index, plain) in plains {
                        cache.insert(self.space, ino, index, plain.into(), seq, generation);
                    }
                    return Ok(attr);
                }
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s chunks kept changing under this write"),
        ))
    }

    /// Seals the chunk that `new_size` falls in again, without the bytes
    /// after `new_size`.
    pub(super) async fn truncate(&self, ino: u64, new_size: u64) -> Result<(), FsError> {
        self.with_fresh_keys(ino, || self.truncate_once(ino, new_size))
            .await
    }

    pub(super) async fn truncate_once(&self, ino: u64, new_size: u64) -> Result<(), FsError> {
        let chunk_size = self.remote.chunk_size();
        let keep = (new_size % chunk_size) as usize;
        if keep == 0 {
            return Ok(());
        }
        let index = new_size / chunk_size;
        let node = self.fresh_node(ino).await?;
        if let Some(grid) = self.remote.grid().filter(|g| g.in_blocks(index))
            && self.layout(ino).await? == Layout::Hybrid
        {
            let start = grid.block_start(index);
            let edit = BlockEdit::Truncate { index, keep };
            return self
                .rewrite_block(&node, ino, grid, start, edit)
                .await
                .map(drop);
        }
        for _ in 0..CHANGE_RETRIES {
            let (mut plain, seq) = self.base(&node, ino, index).await?;
            if plain.len() <= keep {
                return Ok(());
            }
            plain.truncate(keep);
            let write = ChunkWrite {
                index,
                expected_seq: Some(seq),
                body: WriteBody::Inline(seal_chunk(
                    &node.key,
                    node.record.version,
                    ino,
                    index,
                    &plain,
                )),
            };
            let written = self.remote.write_chunks(ino, &[write], 0).await;
            // Whatever happened, the cached copy is now out of date.
            self.cache
                .lock()
                .unwrap()
                .invalidate(self.space, ino, index..=index);
            match written {
                Err(e) if changed(&e) => continue,
                other => return other.map(drop),
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s last chunk kept changing under this truncate"),
        ))
    }
}
