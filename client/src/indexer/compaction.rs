//! Compaction on a native device: the recent segments and the generation
//! folded into a new generation, under the claim.
//!
//! - The old generation's pieces and the work in progress go to a spill
//!   folder on local disk (`spill`), sealed, so memory stays small.
//! - The order keeps the index whole for a reader at every step: the new
//!   generation's files first, then the manifest that names it, then the
//!   other indexers' manifests are deleted.
//! - What the new generation replaces (the old generation, every recent
//!   segment, thumbnail files nothing shows) is retired: kept for
//!   `IndexerConfig::grace`, then deleted by a later pass.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_proto::types::FsError;
use raft5fs_proto::{clock, errno};
use raft5fs_search::compact::{Config, compact};
use raft5fs_search::generation::{self, GenId};
use raft5fs_search::index::Index;
use raft5fs_search::record::{Entry, Record};
use raft5fs_search::view::View;

use super::spill::Spill;
use super::{Pass, read_all, write_fresh};

fn io(e: std::io::Error) -> FsError {
    FsError::new(raft5fs_proto::errno::EIO, format!("compaction: {e}"))
}

impl Pass<'_> {
    /// Writes the index again as one generation, this indexer's.
    pub(super) async fn compact(&mut self, full_walk_ms: u64) -> Result<(), FsError> {
        self.flush().await?;
        self.store().await?;
        let (Some(base), Some(identity)) = (
            self.config.cache_dir.clone(),
            self.vault.remote().identity(),
        ) else {
            return Ok(());
        };
        Spill::clean_old(&base);
        let spill = Arc::new(Spill::new(&base, identity).map_err(io)?);

        // The old generation's pieces, to local disk.
        if let Some(h) = &self.header {
            for n in 0..h.server_files {
                self.beat();
                let name = generation::file_name(&h.id, n);
                let &ino = self.listing.get(&name).ok_or_else(|| {
                    FsError::new(errno::ENOENT, "a file of the index's generation is gone")
                })?;
                let bytes = read_all(self.vault, ino).await?;
                let pieces = generation::split(h, n, &bytes).ok_or_else(|| {
                    FsError::new(errno::EIO, "a file of the index's generation is short")
                })?;
                for (id, piece) in pieces {
                    spill
                        .put(&format!("old-{}", id.short()), piece)
                        .map_err(io)?;
                }
            }
        }

        let old = Index::new(
            self.generation.clone(),
            View::new(self.recent.values().cloned()),
        );
        let mut records: Vec<Record> = self
            .recent
            .values()
            .filter_map(|e| match e {
                Entry::Record(r) => Some(r.clone()),
                _ => None,
            })
            .collect();
        records.sort_by_key(|r| r.ino);
        // Thumbnails that the new generation shows.
        let mut shown: HashSet<String> = old
            .rows()
            .into_iter()
            .filter_map(|r| Some(r.thumb?.file))
            .collect();
        shown.extend(
            records
                .iter()
                .filter_map(|r| Some(r.extra.thumb.as_ref()?.file.clone())),
        );

        let id: GenId = crate::pruner::new_holder()[..8]
            .try_into()
            .expect("8 bytes");
        let key: [u8; 32] = *raft5fs_crypto::Key::random().as_bytes();
        let config = Config::new(id, key, clock::now_millis());
        let work = Arc::clone(&spill);
        let header = crate::rt::blocking(move || {
            let get = |id: generation::PieceId| work.get(&format!("old-{}", id.short()));
            let mut out = |n: u32, bytes: Vec<u8>| work.put(&format!("new-{n}"), &bytes);
            compact(Some(&old), &get, &records, config, work.buckets(), &mut out)
        })
        .await
        .map_err(io)?;

        // The new generation's files, then its header.
        for n in 0..header.server_files {
            self.beat();
            let bytes = spill.get(&format!("new-{n}")).map_err(io)?;
            write_fresh(self.vault, self.dir, &generation::file_name(&id, n), &bytes).await?;
        }
        write_fresh(
            self.vault,
            self.dir,
            &generation::head_name(&id),
            &generation::encode_header(&header),
        )
        .await?;

        // The manifest that names it, with what it replaces retired.
        let until = clock::now_millis() + self.config.grace.as_millis() as u64;
        let mut retired: Vec<(String, u64)> = std::mem::take(&mut self.mine.retired);
        for m in &self.others {
            retired.extend(m.retired.iter().cloned());
        }
        let keep: HashSet<String> = (0..header.server_files)
            .map(|n| generation::file_name(&id, n))
            .chain([generation::head_name(&id)])
            .chain(retired.iter().map(|r| r.0.clone()))
            .collect();
        for name in self.listing.keys() {
            let replaced = name.starts_with("gen-")
                || name.starts_with("recent-")
                || (name.starts_with("thumbs-") && !shown.contains(name));
            if replaced && !keep.contains(name) {
                retired.push((name.clone(), until));
            }
        }
        for name in self.mine.segments.drain(..) {
            if !self.listing.contains_key(&name) {
                retired.push((name, until));
            }
        }
        retired.sort();
        retired.dedup_by(|a, b| a.0 == b.0);
        self.mine.retired = retired;
        self.mine.generation = Some(id);
        self.mine.full_walk_ms = self
            .others
            .iter()
            .map(|m| m.full_walk_ms)
            .fold(self.mine.full_walk_ms.max(full_walk_ms), u64::max);
        self.mine.cursor_ms = self
            .others
            .iter()
            .map(|m| m.cursor_ms)
            .fold(self.mine.cursor_ms, u64::max);
        self.mine.updated_ms = clock::now_millis();
        self.save_manifest().await?;

        // Other indexers' manifests: their segments are in the generation.
        for m in &self.others {
            let name = raft5fs_search::manifest::Manifest::file_name(&m.id);
            match self.vault.unlink(self.dir, OsStr::new(&name)).await {
                Ok(_) => {}
                Err(e) if e.errno == errno::ENOENT => {}
                Err(e) => return Err(e),
            }
        }
        self.stats.compacted = true;
        Ok(())
    }
}
