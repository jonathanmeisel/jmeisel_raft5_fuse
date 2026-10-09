//! Pruning: sealing everything still under an old version of a node's key
//! again under the current one, then dropping the old versions from the
//! node's key history (raft5fs-crypto's `NodeKeys::pruned`).
//!
//! A rotation leaves what was sealed before it under the old version --
//! readable, given the ciphertext, by whoever the rotation was meant to
//! shut out. Pruning a tree puts it all under keys they never had.
//!
//! Every node is pruned against its own key: a file's chunks are sealed
//! under the file's key, a directory's entry names under the directory's.
//! A directory's key also wraps its children's, and a stale child -- one
//! still wrapped under an old version of its parent's key -- can only be
//! opened through the parent's history. So a directory's stale children
//! get new keys of their own (a rotation, never a re-wrap: whoever the
//! parent's rotation shut out knows the child's key too) before the
//! directory's history is cut. Each rotation adds an entry to that child's
//! history, which the child's own visit then drops: the walk goes top
//! down, so one pass over a tree is enough.
//!
//! The server refuses a prune that would drop a version anything is still
//! sealed under (`EBUSY`), so a write landing under an old version while
//! the walk runs can't be lost: the node is visited again.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::time::Duration;

use raft5fs_crypto::data::{open_name, seal_chunk, sealed_version};
use raft5fs_proto::types::{ChunkWrite, DirItem, FsError, Kind, RESEAL_NAMES_BATCH, ResealedName};

use super::{CHANGE_RETRIES, Node, Vault, changed, corrupt, expired};

/// What pruning a tree did -- or, for a dry run, would do.
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
    /// Key versions dropped from histories.
    pub dropped: usize,
    /// Nodes left as they were, and why. A directory skipped takes
    /// everything under it with it.
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

/// A node for the walk to visit. `rotates`: a dry run's note that its
/// parent's visit would have given it a new key.
#[derive(Clone, Copy)]
struct Visit {
    ino: u64,
    kind: Kind,
    rotates: bool,
}

/// A grant this account holds: what it shows up as, and whether it lets
/// this account write -- which pruning takes.
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
                    .map(OsString::from_vec)
                    .unwrap_or_else(|_| OsString::from(format!("unreadable-{}", grant.ino))),
                ino: grant.ino,
                writable: grant.writable,
            })
            .collect())
    }

    /// Prunes directory `top` and everything under it, top down. A node
    /// that can't be pruned is skipped, with everything under it, and the
    /// walk goes on. With `dry_run`, only counts what it would do.
    pub async fn prune_tree(&self, top: u64, dry_run: bool) -> PruneStats {
        self.prune_tree_paced(top, dry_run, Duration::ZERO, &mut |_| {})
            .await
    }

    /// `prune_tree`, waiting `pace` after each node -- so that a prune in
    /// the background leaves the store to whatever else is going on -- and
    /// telling `progress` how far it has got after each.
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
                // Removed while the walk was on its way to it.
                Err(e) if e.errno == libc::ENOENT => {}
                Err(e) => stats.skipped.push((ino, e)),
            }
            progress(&stats);
            if !pace.is_zero() && !queue.is_empty() {
                tokio::time::sleep(pace).await;
            }
        }
        stats
    }

    /// Prunes one node, returning what it did and the node's children to
    /// visit next. Done over from the start when something changed under
    /// it -- a write, a rotation, a new entry under an old key.
    async fn prune_node(
        &self,
        visit: Visit,
        dry_run: bool,
    ) -> Result<(PruneStats, Vec<Visit>), FsError> {
        let ino = visit.ino;
        let mut last = None;
        for _ in 0..CHANGE_RETRIES {
            match self.prune_node_once(visit, dry_run).await {
                Err(e) if changed(&e) || expired(&e) || e.errno == libc::EBUSY => last = Some(e),
                other => return other,
            }
        }
        Err(last
            .unwrap_or_else(|| FsError::new(libc::EAGAIN, format!("inode {ino} kept changing"))))
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
            // Whatever above it is stale gets new keys first, this too.
            let node = self.freshen(ino).await?;
            node.sealable(ino)?;
            node
        };
        // A dry run rotates nothing, so it reckons with the rotation its
        // parent's visit would have given this node: a version on, with
        // everything sealed so far under an old one.
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

        // The record as it is now, which a rotation of a child may have
        // left newer than `node` -- the server says if it no longer is.
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

    /// Seals every chunk of file `ino` under a version of its key before
    /// `target` again under the current one, `node`'s, a write batch at a
    /// time. Returns how many there were. (Only a dry run's `target` is
    /// ever past the current version: see `prune_node_once`.)
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
        let mut count = 0;
        let mut first = 0;
        loop {
            let (attr, got) = self.remote.read_chunks(ino, first, per_batch, &[]).await?;
            let end = attr.size.div_ceil(chunk_size);
            let Some(next) = got.last().map(|c| c.index + 1) else {
                break;
            };
            let mut writes = Vec::new();
            for chunk in got.iter().filter(|c| c.index < end) {
                let Some(blob) = &chunk.blob else { continue };
                if sealed_version(blob).map_err(|e| corrupt(ino, e))? >= target {
                    continue;
                }
                count += 1;
                if !dry_run {
                    let plain = self.open(node, ino, chunk.index, blob)?;
                    writes.push(ChunkWrite {
                        index: chunk.index,
                        expected_seq: Some(chunk.seq),
                        blob: seal_chunk(&node.key, version, ino, chunk.index, &plain),
                    });
                }
            }
            if !writes.is_empty() {
                self.remote.reseal_chunks(ino, &writes).await?;
                // The same bytes, but at a new seq.
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

/// Entry `item` of directory `dir` -- as the server lists it, by tag --
/// its name, sealed under an older version of `node`'s key, opened and
/// sealed again under the current one.
fn reseal_name(node: &Node, dir: u64, item: &DirItem) -> Result<ResealedName, FsError> {
    let version = sealed_version(&item.sealed_name).map_err(|e| corrupt(dir, e))?;
    let key = node.key_at(dir, version)?;
    let name = open_name(
        &key,
        &node.name_key,
        dir,
        item.ino,
        item.name.as_bytes(),
        &item.sealed_name,
    )
    .map_err(|e| corrupt(dir, e))?;
    Ok(ResealedName {
        tag: item.name.clone(),
        ino: item.ino,
        sealed_name: node.seal(dir, item.ino, &item.name, OsStr::from_bytes(&name)),
    })
}
