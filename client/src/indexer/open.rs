//! Reading a volume's index to search it: the generation's server files,
//! kept piece by piece in a cache, and the recent segments.
//!
//! - `open`: the whole index. Every server file not cached yet is
//!   downloaded, so what a client fetches never depends on a query.
//! - `refresh`: what changed since, reading only new recent segments. A
//!   new generation is downloaded in full before the index switches to
//!   it, so search goes on meanwhile.
//! - `search`: loads each query's pieces from the cache.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use raft5fs_proto::errno;
use raft5fs_proto::types::FsError;
use raft5fs_search::generation::{self, GenId, Header, PieceId};
use raft5fs_search::index::{self, Generation, Index, Pieces};
use raft5fs_search::rank::Ranking;
use raft5fs_search::view::{self, Hit, Progress, QueryVector, View};

use super::{SegmentCache, load_with, read_all};
use crate::vault::Vault;

/// What names a piece of a generation in a cache.
pub fn piece_key(volume: u64, id: &GenId, piece: PieceId) -> String {
    format!("{volume}/g{}/{}", raft5fs_wire::hex(id), piece.short())
}

/// Hears how far a download got: bytes done, of bytes in all.
#[cfg(not(target_arch = "wasm32"))]
pub type Downloaded<'a> = &'a mut (dyn FnMut(u64, u64) + Send);
#[cfg(target_arch = "wasm32")]
pub type Downloaded<'a> = &'a mut dyn FnMut(u64, u64);

/// A volume's index, open to search.
pub struct Opened {
    pub volume: u64,
    /// Where its pieces are kept.
    pub cache: Arc<dyn SegmentCache>,
    pub index: Index,
    pub progress: Progress,
    pub header: Option<Header>,
    /// The recent segments read, by cache key.
    recent: HashSet<String>,
}

impl Opened {
    /// The id of its generation, if it has one.
    pub fn generation(&self) -> Option<GenId> {
        self.header.as_ref().map(|h| h.id)
    }

    /// An index with nothing in it, for a volume with none yet.
    pub fn empty(volume: u64, cache: Arc<dyn SegmentCache>) -> Self {
        Self {
            volume,
            cache,
            index: Index::new(None, View::default()),
            progress: Progress::default(),
            header: None,
            recent: HashSet::new(),
        }
    }

    /// Every cache key it uses: to keep, while dropping the rest.
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.recent.iter().cloned().collect();
        if let Some(h) = &self.header {
            keys.extend(h.pieces.iter().map(|p| piece_key(self.volume, &h.id, p.id)));
        }
        keys
    }

    /// How big the generation is, in bytes: what a first download costs.
    pub fn bytes(&self) -> u64 {
        self.header.as_ref().map_or(0, |h| h.bytes)
    }
}

/// Downloads every server file of `header` whose pieces `cache` lacks,
/// and keeps its pieces there.
pub async fn fetch_generation(
    vault: &Vault,
    volume: u64,
    files: &HashMap<String, u64>,
    header: &Header,
    cache: &dyn SegmentCache,
    progress: Downloaded<'_>,
) -> Result<(), FsError> {
    let mut done = 0u64;
    for n in 0..header.server_files {
        let pieces: Vec<_> = header.in_file(n).collect();
        let size: u64 = pieces.iter().map(|p| u64::from(p.len)).sum();
        // Pieces go in in order, so the last one says the file is in.
        let have = match pieces.last() {
            Some(p) => cache
                .get(&piece_key(volume, &header.id, p.id))
                .await
                .is_some(),
            None => true,
        };
        if !have {
            let name = generation::file_name(&header.id, n);
            let &ino = files.get(&name).ok_or_else(|| {
                FsError::new(errno::ENOENT, "a file of the index's generation is gone")
            })?;
            let bytes = read_all(vault, ino).await?;
            let split = generation::split(header, n, &bytes).ok_or_else(|| {
                FsError::new(errno::EIO, "a file of the index's generation is short")
            })?;
            for (id, piece) in split {
                cache.put(&piece_key(volume, &header.id, id), piece).await;
            }
        }
        done += size;
        progress(done, header.bytes);
    }
    Ok(())
}

/// The generation `header` describes, from the cache's pieces.
pub(crate) async fn generation_of(
    volume: u64,
    header: &Header,
    cache: &dyn SegmentCache,
) -> Result<Generation, FsError> {
    let mut resident = HashMap::new();
    for id in Generation::resident(header) {
        if let Some(b) = cache.get(&piece_key(volume, &header.id, id)).await {
            resident.insert(id, b);
        }
    }
    Generation::load(header.clone(), |id| resident.get(&id).cloned())
        .map_err(|e| FsError::new(errno::EIO, e.to_string()))
}

/// What `head` says of an index.
#[derive(Debug, Clone, Default)]
pub struct Head {
    /// The generation's id and size in bytes, if the index was compacted.
    pub generation: Option<(GenId, u64)>,
    pub progress: Progress,
}

/// `volume`'s index's manifests and generation header only, reading no
/// segment: what tells how big a download it is, and whether it changed.
/// `None` if it has no index.
pub async fn head(vault: &Vault, volume: u64) -> Result<Option<Head>, FsError> {
    // A known segment that can't be listed makes `load_with` read none.
    let none: HashSet<String> = [String::from("-")].into_iter().collect();
    let mut sink = |_: Vec<raft5fs_search::record::Entry>| {};
    let Some(loaded) = load_with(vault, volume, false, None, &none, Some(&mut sink)).await? else {
        return Ok(None);
    };
    Ok(Some(Head {
        generation: loaded.header.as_ref().map(|h| (h.id, h.bytes)),
        progress: view::progress(&loaded.manifests),
    }))
}

/// `volume`'s whole index, or `None` if it has none. `progress` hears how
/// far the generation's download got.
pub async fn open(
    vault: &Vault,
    volume: u64,
    cache: Arc<dyn SegmentCache>,
    progress: Downloaded<'_>,
) -> Result<Option<Opened>, FsError> {
    let c = cache.as_ref();
    let Some(loaded) = load_with(vault, volume, false, Some(c), &HashSet::new(), None).await?
    else {
        return Ok(None);
    };
    let generation = match &loaded.header {
        Some(h) => {
            fetch_generation(vault, volume, &loaded.files, h, c, progress).await?;
            Some(Arc::new(generation_of(volume, h, c).await?))
        }
        None => None,
    };
    let opened = Opened {
        volume,
        cache: Arc::clone(&cache),
        index: Index::new(generation, View::new(loaded.entries.into_values())),
        progress: view::progress(&loaded.manifests),
        header: loaded.header,
        recent: loaded.keys.into_iter().collect(),
    };
    c.keep_only(volume, &opened.keys()).await;
    Ok(Some(opened))
}

/// Brings `opened` up to date: new recent segments only, or, after a
/// compaction, the new generation (downloaded first) with its recent
/// segments.
pub async fn refresh(
    vault: &Vault,
    opened: Opened,
    progress: Downloaded<'_>,
) -> Result<Option<Opened>, FsError> {
    let mut delta = Vec::new();
    let mut sink = |e: Vec<raft5fs_search::record::Entry>| delta.extend(e);
    let cache = Arc::clone(&opened.cache);
    let Some(loaded) = load_with(
        vault,
        opened.volume,
        false,
        Some(cache.as_ref()),
        &opened.recent,
        Some(&mut sink),
    )
    .await?
    else {
        return Ok(None);
    };
    let same = loaded.header.as_ref().map(|h| h.id) == opened.header.as_ref().map(|h| h.id);
    if same && !loaded.reset {
        let mut opened = opened;
        opened.index.add_recent(delta);
        opened.progress = view::progress(&loaded.manifests);
        opened.recent = loaded.keys.into_iter().collect();
        return Ok(Some(opened));
    }
    let fresh = open(vault, opened.volume, cache, progress).await?;
    Ok(fresh)
}

/// Searches `opened` as one, best first, loading each piece a query needs
/// from its cache (where `open` put them). Each hit comes with the index
/// in `opened` of the volume it is in.
pub async fn search(
    opened: &[&Opened],
    query: &str,
    vector: Option<QueryVector<'_>>,
    image: Option<QueryVector<'_>>,
    limit: usize,
) -> Vec<(usize, Hit)> {
    let sources: Vec<_> = opened.iter().map(|o| o.index.source()).collect();
    let mut pieces = Pieces::new();
    let load = async |pieces: &mut Pieces, ids: Vec<(usize, PieceId)>| {
        for (i, id) in ids {
            let Some(h) = &opened[i].header else { continue };
            if let Some(b) = opened[i]
                .cache
                .get(&piece_key(opened[i].volume, &h.id, id))
                .await
            {
                pieces.insert((i, id), b);
            }
        }
    };
    load(
        &mut pieces,
        index::needs(&sources, query, vector.as_ref(), image.as_ref()),
    )
    .await;
    let found = index::search(
        &sources,
        query,
        vector.as_ref(),
        image.as_ref(),
        limit,
        &pieces,
        &Ranking::default(),
    );
    load(&mut pieces, index::preview_needs(&found)).await;
    index::hits(&sources, query, &found, &pieces)
}

/// What `check_recall` found.
#[derive(Debug, Default)]
pub struct RecallCheck {
    /// Result recall by meaning, and how many queries counted.
    pub text: Option<(f64, usize)>,
    /// The same for photos.
    pub photos: Option<(f64, usize)>,
    /// Files found by their own name in the first 10 results, of those
    /// tried.
    pub names: (usize, usize),
    /// Why a part was left out, if one was.
    pub note: Option<String>,
}

/// The most bytes of clusters `check_recall` loads to compare with.
const CHECK_BYTES: u64 = 512 << 20;

/// How much searching only the nearest clusters loses on `opened`: up to
/// `queries` of its own sampled vectors as queries, each searched as usual
/// and with every cluster, and the share of the second's results the first
/// also shows. Then files searched by their names. Changes nothing.
pub async fn check_recall(opened: &Opened, queries: usize) -> RecallCheck {
    use raft5fs_search::generation::Kind;
    let mut out = RecallCheck::default();
    let Some(g) = opened.index.generation.as_deref() else {
        out.note = Some("not compacted yet: every search reads every vector".into());
        return out;
    };
    let h = &g.header;
    let cluster_bytes: u64 = h
        .pieces
        .iter()
        .filter(|p| matches!(p.id.kind, Kind::TextCluster | Kind::PhotoCluster))
        .map(|p| u64::from(p.len))
        .sum();
    if cluster_bytes <= CHECK_BYTES {
        let mut all = Pieces::new();
        for p in &h.pieces {
            if matches!(
                p.id.kind,
                Kind::TextCluster | Kind::PhotoCluster | Kind::Previews
            ) && let Some(b) = opened
                .cache
                .get(&piece_key(opened.volume, &h.id, p.id))
                .await
            {
                all.insert((0, p.id), b);
            }
        }
        let sources = [opened.index.source()];
        let measure = |sample: &[raft5fs_search::generation::ClusterEntry],
                       model: &str,
                       photos: bool| {
            let mut sum = 0.0;
            let mut counted = 0;
            let mut files: Vec<u32> = sample.iter().map(|e| e.file).collect();
            files.dedup();
            let step = files.len().div_ceil(queries.max(1)).max(1);
            for e in sample.iter().filter(|e| e.chunk == 0).step_by(step) {
                let values: Vec<f32> = e
                    .vector
                    .values
                    .iter()
                    .map(|&x| f32::from(x) * e.vector.scale)
                    .collect();
                let q = QueryVector {
                    model,
                    values: &values,
                };
                let (v, i) = if photos {
                    (None, Some(&q))
                } else {
                    (Some(&q), None)
                };
                let run = |ids: Vec<(usize, PieceId)>| -> Vec<index::At> {
                    let pieces: Pieces = ids
                        .into_iter()
                        .filter_map(|k| Some((k, all.get(&k)?.clone())))
                        .collect();
                    index::search(&sources, "", v, i, 50, &pieces, &Ranking::default())
                        .into_iter()
                        .map(|f| f.at)
                        .collect()
                };
                let full = run(index::needs_with(&sources, "", v, i, usize::MAX, 1));
                if full.is_empty() {
                    continue;
                }
                let part = run(index::needs(&sources, "", v, i));
                sum += part.iter().filter(|a| full.contains(a)).count() as f64 / full.len() as f64;
                counted += 1;
            }
            (counted > 0).then(|| (sum / counted as f64, counted))
        };
        out.text = measure(g.text_sample(), &h.text_model, false);
        out.photos = measure(g.photo_sample(), &h.clip_model, true);
    } else {
        out.note = Some(format!(
            "clusters too big to compare at once ({} MB): meaning not checked",
            cluster_bytes >> 20
        ));
    }
    let rows = g.rows();
    let step = rows.len().div_ceil(queries.max(1)).max(1);
    for r in rows.iter().step_by(step) {
        let name = r.path.rsplit('/').next().unwrap_or(&r.path);
        let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
        if stem.is_empty() {
            continue;
        }
        let found = search(&[opened], stem, None, None, 10).await;
        out.names.1 += 1;
        out.names.0 += usize::from(found.iter().any(|(_, hit)| hit.ino == r.ino));
    }
    out
}
