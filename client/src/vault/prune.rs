//! Pruning: seals everything still under an old version of a node's key
//! again under the current version, then removes the old versions from the
//! node's key history (raft5fs-crypto's `NodeKeys::pruned`).
//!
//! A rotation leaves data sealed before it under the old version. A user
//! that the rotation was meant to shut out can still read it, if they have
//! the ciphertext. Pruning a tree puts all of it under keys that they never
//! had.
//!
//! - Each node is pruned against its own key: a file's chunks are sealed
//!   under the file's key, and a directory's entry names under the
//!   directory's key.
//! - A directory's key also wraps its children's keys. A stale child (still
//!   wrapped under an old version of its parent's key) can only be opened
//!   through the parent's history. So the directory's stale children get
//!   their own new keys before the directory's history is cut. This must be
//!   a rotation, never a re-wrap, because a user shut out by the parent's
//!   rotation also knows the child's key.
//! - Each rotation adds an entry to the child's history, which the child's
//!   own visit then removes. The walk goes from the top down, so one pass
//!   over a tree is enough.
//!
//! The server refuses a prune that would remove a version that anything is
//! still sealed under (`EBUSY`). So a write under an old version during the
//! walk is not lost: the node is visited again.

use std::collections::{HashSet, VecDeque};
use std::ffi::OsString;
use std::time::Duration;

use raft5fs_crypto::data::{open_name, seal_chunk, sealed_version};
use raft5fs_proto::errno;
use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{
    ChunkBody, ChunkWrite, DirItem, FsError, Kind, Layout, RESEAL_NAMES_BATCH, ResealedName,
    WriteBody,
};

use super::blocks::{BlockEdit, Rewritten};
use super::{CHANGE_RETRIES, Node, Vault, changed, corrupt, expired, sealed_blob};

/// What pruning a tree did, or for a dry run, would do.
#[derive(Debug, Default)]
pub struct PruneStats {
    /// Nodes visited.
    pub nodes: usize,
    /// File chunks sealed again under their file's current key.
    pub chunks: usize,
    /// Entry names sealed again under their directory's current key.
    pub names: usize,
    /// Stale children given new keys.
    pub rotated: usize,
    /// Key versions removed from histories.
    pub dropped: usize,
    /// Nodes not changed, and why. A skipped directory also skips
    /// everything below it.
    pub skipped: Vec<(u64, FsError)>,
}

impl PruneStats {
    fn add(&mut self, other: PruneStats) {
        self.nodes += other.nodes;
        self.chunks += other.chunks;
        self.names += other.names;
        self.rotated += other.rotated;
        self.dropped += other.dropped;
        self.skipped.extend(other.skipped);
    }
}

/// A node for the walk to visit. `rotates` is a dry run's note that its
/// parent's visit would have given it a new key.
#[derive(Clone, Copy)]
struct Visit {
    ino: u64,
    kind: Kind,
    rotates: bool,
}

/// A grant that this account has: its label, and whether it lets this
/// account write, which pruning needs.
#[derive(Debug, Clone)]
pub struct GrantRoot {
    pub label: OsString,
    pub ino: u64,
    pub writable: bool,
}

impl Vault {
    /// Every grant made to this account.
    pub async fn grant_roots(&self) -> Result<Vec<GrantRoot>, FsError> {
        let mut grants = self.remote.list_grants().await?;
        grants.sort_by_key(|g| g.ino);
        Ok(grants
            .into_iter()
            .map(|grant| GrantRoot {
                label: self
                    .identity
                    .open_label(grant.ino, &grant.sealed_label)
                    .map(os_bytes::into_name)
                    .unwrap_or_else(|_| OsString::from(format!("unreadable-{}", grant.ino))),
                ino: grant.ino,
                writable: grant.writable,
            })
            .collect())
    }

    /// Prunes directory `top` and everything below it, from the top down. A
    /// node that cannot be pruned is skipped, with everything below it, and
    /// the walk continues. With `dry_run`, it only counts what it would do.
    pub async fn prune_tree(&self, top: u64, dry_run: bool) -> PruneStats {
        self.prune_tree_paced(top, dry_run, Duration::ZERO, &mut |_| {})
            .await
    }

    /// `prune_tree` that waits `pace` after each node, so a background
    /// prune leaves the store free for other work. After each node, it
    /// tells `progress` how far it got.
    pub async fn prune_tree_paced(
        &self,
        top: u64,
        dry_run: bool,
        pace: Duration,
        progress: &mut (dyn FnMut(&PruneStats) + Send),
    ) -> PruneStats {
        let mut stats = PruneStats::default();
        let mut queue = VecDeque::from([Visit {
            ino: top,
            kind: Kind::Directory,
            rotates: false,
        }]);
        while let Some(visit) = queue.pop_front() {
            let ino = visit.ino;
            match self.prune_node(visit, dry_run).await {
                Ok((node_stats, children)) => {
                    stats.add(node_stats);
                    queue.extend(children);
                }
                // Removed before the walk got to it.
                Err(e) if e.errno == errno::ENOENT => {}
                Err(e) => stats.skipped.push((ino, e)),
            }
            progress(&stats);
            if !pace.is_zero() && !queue.is_empty() {
                crate::rt::sleep(pace).await;
            }
        }
        stats
    }

    /// Prunes one node, and returns what it did and the node's children to
    /// visit next. It starts again if something changed under it: a write,
    /// a rotation, or a new entry under an old key.
    async fn prune_node(
        &self,
        visit: Visit,
        dry_run: bool,
    ) -> Result<(PruneStats, Vec<Visit>), FsError> {
        let ino = visit.ino;
        let mut last = None;
        for _ in 0..CHANGE_RETRIES {
            match self.prune_node_once(visit, dry_run).await {
                Err(e) if changed(&e) || expired(&e) || e.errno == errno::EBUSY => last = Some(e),
                other => return other,
            }
        }
        Err(last
            .unwrap_or_else(|| FsError::new(errno::EAGAIN, format!("inode {ino} kept changing"))))
    }

    async fn prune_node_once(
        &self,
        visit: Visit,
        dry_run: bool,
    ) -> Result<(PruneStats, Vec<Visit>), FsError> {
        let ino = visit.ino;
        let mut stats = PruneStats {
            nodes: 1,
            ..PruneStats::default()
        };
        let node = if dry_run {
            self.refresh(ino).await?
        } else {
            // Stale nodes above it, and this node, get new keys first.
            let node = self.freshen(ino).await?;
            node.sealable(ino)?;
            node
        };
        // A dry run rotates nothing, so it counts the rotation that its
        // parent's visit would have given this node: one version higher,
        // with everything sealed so far under an old version.
        let imagined = dry_run && visit.rotates;
        let target = node.record.version + u32::from(imagined);
        let mut children = Vec::new();
        match visit.kind {
            Kind::Directory => {
                let items: Vec<_> = self
                    .remote
                    .readdir(ino)
                    .await?
                    .into_iter()
                    .filter(|i| i.name != "." && i.name != "..")
                    .collect();
                for item in &items {
                    let child = self.node(item.ino).await?;
                    let rotates = imagined || child.record.is_stale(node.record.version);
                    if rotates {
                        if !dry_run {
                            self.freshen(item.ino).await?;
                        }
                        stats.rotated += 1;
                    }
                    children.push(Visit {
                        ino: item.ino,
                        kind: item.kind,
                        rotates: dry_run && rotates,
                    });
                }
                let mut resealed = Vec::new();
                for item in items.iter().filter(|i| !i.sealed_name.is_empty()) {
                    let version = sealed_version(&item.sealed_name).map_err(|e| corrupt(ino, e))?;
                    if version >= target {
                        continue;
                    }
                    stats.names += 1;
                    if !dry_run {
                        resealed.push(reseal_name(&node, ino, item)?);
                    }
                }
                for batch in resealed.chunks(RESEAL_NAMES_BATCH) {
                    self.remote.reseal_names(ino, batch).await?;
                }
            }
            Kind::File => stats.chunks = self.reseal_chunks(ino, &node, target, dry_run).await?,
        }

        // Read the record as it is now. A child's rotation may have made it
        // newer than `node`. The server says if it changed.
        self.nodes.lock().unwrap().remove(&ino);
        let current = self.node(ino).await?;
        let record = &current.record;
        stats.dropped = (record.version - record.base()) as usize + usize::from(imagined);
        if stats.dropped > 0 && !dry_run {
            let pruned = record.pruned(record.version);
            self.remote
                .prune_keys(ino, record.version, pruned.encode())
                .await?;
            self.nodes.lock().unwrap().remove(&ino);
        }
        Ok((stats, children))
    }

    /// Seals every chunk of file `ino` that is under a key version before
    /// `target` again under the current version (`node`'s), one write batch
    /// at a time. Returns how many chunks there were. Only a dry run's
    /// `target` can be past the current version (see `prune_node_once`).
    async fn reseal_chunks(
        &self,
        ino: u64,
        node: &Node,
        target: u32,
        dry_run: bool,
    ) -> Result<usize, FsError> {
        let chunk_size = self.remote.chunk_size();
        let per_batch = (self.remote.batch_bytes() / chunk_size).max(1) as u32;
        let version = node.record.version;
        let grid = match self.remote.grid() {
            Some(grid) if self.layout(ino).await? == Layout::Hybrid => Some(grid),
            _ => None,
        };
        // Blocks seen, by first index. Each block is sealed again whole,
        // one time.
        let mut blocks_seen = HashSet::new();
        let mut count = 0;
        let mut first = 0;
        loop {
            let read = self.remote.read_chunks(ino, first, per_batch, &[]).await?;
            let end = read.attr.size.div_ceil(chunk_size);
            let Some(next) = read.chunks.last().map(|c| c.index + 1) else {
                break;
            };
            let mut writes = Vec::new();
            for chunk in read.chunks.iter().filter(|c| c.index < end) {
                if let ChunkBody::Segment { block, .. } = chunk.body {
                    let (Some(grid), Some(found)) = (grid, read.blocks.get(block as usize)) else {
                        return Err(corrupt(ino, "a block where the file keeps none"));
                    };
                    let start = grid.block_start(chunk.index);
                    if !blocks_seen.insert(start) || found.block.version >= target {
                        continue;
                    }
                    if dry_run {
                        count += found.block.nseg as usize;
                        continue;
                    }
                    let edit = BlockEdit::Reseal { below: target };
                    if let Rewritten::Stored { nseg, .. } =
                        self.rewrite_block(node, ino, grid, start, edit).await?
                    {
                        count += nseg as usize;
                    }
                    continue;
                }
                let Some(blob) = sealed_blob(ino, &chunk.body)? else {
                    continue;
                };
                if sealed_version(blob).map_err(|e| corrupt(ino, e))? >= target {
                    continue;
                }
                count += 1;
                if !dry_run {
                    let plain = self.open(node, ino, chunk.index, blob)?;
                    writes.push(ChunkWrite {
                        index: chunk.index,
                        expected_seq: Some(chunk.seq),
                        body: WriteBody::Inline(seal_chunk(
                            &node.key,
                            version,
                            ino,
                            chunk.index,
                            &plain,
                        )),
                    });
                }
            }
            if !writes.is_empty() {
                self.remote.reseal_chunks(ino, &writes).await?;
                // The same bytes, at a new seq.
                let mut cache = self.cache.lock().unwrap();
                for w in &writes {
                    cache.invalidate(self.space, ino, w.index..=w.index);
                }
            }
            if next >= end {
                break;
            }
            first = next;
        }
        Ok(count)
    }
}

/// Opens the name of entry `item` of directory `dir` (as the server lists
/// it, by tag), sealed under an older version of `node`'s key, and seals it
/// again under the current version.
fn reseal_name(node: &Node, dir: u64, item: &DirItem) -> Result<ResealedName, FsError> {
    let version = sealed_version(&item.sealed_name).map_err(|e| corrupt(dir, e))?;
    let key = node.key_at(dir, version)?;
    let name = open_name(
        &key,
        &node.name_key,
        dir,
        item.ino,
        os_bytes::bytes(&item.name),
        &item.sealed_name,
    )
    .map_err(|e| corrupt(dir, e))?;
    Ok(ResealedName {
        tag: item.name.clone(),
        ino: item.ino,
        sealed_name: node.seal(dir, item.ino, &item.name, os_bytes::as_name(&name)),
    })
}
