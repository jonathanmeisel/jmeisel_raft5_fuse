//! Search quality on a fixed public corpus.
//!
//! - `corpus`: the corpus file, records and judged queries.
//! - `metrics`: nDCG, reciprocal rank, recall, and how many weak or
//!   wrong-kind results show.
//! - `run`: searches every query as the apps do (`search_many`), over the
//!   corpus as one volume or split into several, and sums the measures
//!   per query set.
//! - `run_indexed`: the same over generations built from the corpus
//!   (`compact::build`), as clients search a compacted index: kept words
//!   only, and only the nearest clusters' vectors.
//! - `fetch`: the pinned corpus (data/corpus.json), downloaded once into
//!   the cache and checked against its SHA-256.

pub mod corpus;
pub mod metrics;
pub mod recall;
pub mod tune;

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use raft5fs_search::compact::{Config, build};
use raft5fs_search::generation::{PieceId, pieces};
use raft5fs_search::index::{Generation, Index, search_all};
use raft5fs_search::rank::Ranking;
use raft5fs_search::record::{DocKind, Entry, Record};
use raft5fs_search::view::{QueryVector, View, search_many_with};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use corpus::{Corpus, Query};
use metrics::Totals;

/// The corpus's records split into `volumes` volumes, by inode.
pub fn split(records: &[Record], volumes: usize) -> Vec<View> {
    let n = volumes.max(1);
    let mut parts: Vec<Vec<Entry>> = vec![Vec::new(); n];
    for r in records {
        parts[(r.ino as usize) % n].push(Entry::Record(r.clone()));
    }
    parts.into_iter().map(View::new).collect()
}

/// The inodes that `query` finds over `views`, best first.
pub fn ranked(
    corpus: &Corpus,
    views: &[&View],
    query: &Query,
    limit: usize,
    ranking: &Ranking,
) -> Vec<u64> {
    let text = QueryVector {
        model: &corpus.text_model,
        values: &query.vector,
    };
    let image = QueryVector {
        model: &corpus.clip_model,
        values: &query.clip,
    };
    search_many_with(views, &query.text, Some(text), Some(image), limit, ranking)
        .into_iter()
        .map(|(_, hit)| hit.ino)
        .collect()
}

/// Whether a query of `set` wants photos.
fn wants_photos(set: &str) -> bool {
    set.starts_with("xm-") || set.starts_with("place")
}

/// Every query searched over `views`, with the measures summed per set and
/// over all sets ("all"). Runs on `threads` threads.
pub fn run(
    corpus: &Corpus,
    views: &[View],
    limit: usize,
    threads: usize,
) -> BTreeMap<String, Totals> {
    run_with(
        corpus,
        &corpus.queries,
        views,
        limit,
        threads,
        &Ranking::default(),
    )
}

/// `run`, over `queries`, ranked by `ranking`.
pub fn run_with(
    corpus: &Corpus,
    queries: &[Query],
    views: &[View],
    limit: usize,
    threads: usize,
    ranking: &Ranking,
) -> BTreeMap<String, Totals> {
    let refs: Vec<&View> = views.iter().collect();
    let kinds: HashMap<u64, DocKind> = corpus.records.iter().map(|r| (r.ino, r.kind)).collect();
    let threads = threads.max(1);
    let per = queries.len().div_ceil(threads).max(1);
    let parts: Vec<BTreeMap<String, Totals>> = std::thread::scope(|s| {
        let handles: Vec<_> = queries
            .chunks(per)
            .map(|qs| {
                let refs = &refs;
                let kinds = &kinds;
                s.spawn(move || {
                    let mut out: BTreeMap<String, Totals> = BTreeMap::new();
                    for q in qs {
                        let found = ranked(corpus, refs, q, limit, ranking);
                        let relevant: HashMap<u64, u8> = q.relevant.iter().copied().collect();
                        let photos = wants_photos(&q.set);
                        let wrong = |ino: u64| (kinds.get(&ino) == Some(&DocKind::Photo)) != photos;
                        out.entry(q.set.clone())
                            .or_default()
                            .add(&found, &relevant, wrong);
                    }
                    out
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all: BTreeMap<String, Totals> = BTreeMap::new();
    for part in parts {
        for (set, t) in part {
            merge(all.entry(set).or_default(), &t);
        }
    }
    let mut total = Totals::default();
    for t in all.values() {
        merge(&mut total, t);
    }
    all.insert("all".into(), total);
    all
}

/// The corpus's records split into `volumes` generations, each with its
/// pieces.
pub fn indexed(corpus: &Corpus, volumes: usize) -> Vec<(Index, HashMap<PieceId, Vec<u8>>)> {
    let n = volumes.max(1);
    let mut parts: Vec<Vec<Record>> = vec![Vec::new(); n];
    for r in &corpus.records {
        parts[(r.ino as usize) % n].push(r.clone());
    }
    parts
        .into_iter()
        .enumerate()
        .map(|(i, records)| {
            let config = Config {
                text_model: corpus.text_model.clone(),
                clip_model: corpus.clip_model.clone(),
                ..Config::new([i as u8; 8], [7; 32], 1)
            };
            let (header, files) = build(&records, config).expect("a generation builds in memory");
            let all = pieces(&header, &files).expect("its pieces split");
            let g = Generation::load(header, |id| all.get(&id).cloned()).expect("it loads");
            (Index::new(Some(Arc::new(g)), View::default()), all)
        })
        .collect()
}

/// `run_with`, over generations (`indexed`).
pub fn run_indexed(
    corpus: &Corpus,
    queries: &[Query],
    indexes: &[(Index, HashMap<PieceId, Vec<u8>>)],
    limit: usize,
    threads: usize,
    ranking: &Ranking,
) -> BTreeMap<String, Totals> {
    let kinds: HashMap<u64, DocKind> = corpus.records.iter().map(|r| (r.ino, r.kind)).collect();
    let per = queries.len().div_ceil(threads.max(1)).max(1);
    let parts: Vec<BTreeMap<String, Totals>> = std::thread::scope(|s| {
        let handles: Vec<_> = queries
            .chunks(per)
            .map(|qs| {
                let kinds = &kinds;
                s.spawn(move || {
                    let sources: Vec<_> = indexes.iter().map(|(i, _)| i.source()).collect();
                    let mut out: BTreeMap<String, Totals> = BTreeMap::new();
                    for q in qs {
                        let text = QueryVector {
                            model: &corpus.text_model,
                            values: &q.vector,
                        };
                        let image = QueryVector {
                            model: &corpus.clip_model,
                            values: &q.clip,
                        };
                        let found: Vec<u64> = search_all(
                            &sources,
                            &q.text,
                            Some(&text),
                            Some(&image),
                            limit,
                            ranking,
                            |i, id| indexes[i].1.get(&id).cloned(),
                        )
                        .into_iter()
                        .map(|(_, h)| h.ino)
                        .collect();
                        let relevant: HashMap<u64, u8> = q.relevant.iter().copied().collect();
                        let photos = wants_photos(&q.set);
                        let wrong = |ino: u64| (kinds.get(&ino) == Some(&DocKind::Photo)) != photos;
                        out.entry(q.set.clone())
                            .or_default()
                            .add(&found, &relevant, wrong);
                    }
                    out
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all: BTreeMap<String, Totals> = BTreeMap::new();
    for part in parts {
        for (set, t) in part {
            merge(all.entry(set).or_default(), &t);
        }
    }
    let mut total = Totals::default();
    for t in all.values() {
        merge(&mut total, t);
    }
    all.insert("all".into(), total);
    all
}

fn merge(into: &mut Totals, t: &Totals) {
    into.queries += t.queries;
    into.ndcg10 += t.ndcg10;
    into.mrr10 += t.mrr10;
    into.hit1 += t.hit1;
    into.hit10 += t.hit10;
    into.recall50 += t.recall50;
    into.shown += t.shown;
    into.shown_relevant += t.shown_relevant;
    into.wrong_kind10 += t.wrong_kind10;
    into.empty += t.empty;
}

/// The measures as a table, one row per set.
pub fn table(results: &BTreeMap<String, Totals>) -> String {
    let mut out = String::new();
    let names: Vec<&str> = Totals::default().means().iter().map(|m| m.0).collect();
    out.push_str(&format!("{:18} {:>6}", "set", "n"));
    for n in &names {
        out.push_str(&format!(" {n:>9}"));
    }
    out.push('\n');
    for (set, t) in results {
        out.push_str(&format!("{set:18} {:>6}", t.queries));
        for (_, v) in t.means() {
            out.push_str(&format!(" {v:>9.3}"));
        }
        out.push('\n');
    }
    out
}

#[derive(Deserialize)]
struct Pin {
    name: String,
    url: String,
    sha256: String,
    size: u64,
}

/// The pinned corpus's file in the cache, downloaded first if missing or
/// wrong.
pub fn fetch() -> Result<PathBuf, String> {
    let pin: Pin = serde_json::from_str(include_str!("../data/corpus.json"))
        .map_err(|e| format!("data/corpus.json: {e}"))?;
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or("no cache directory: set XDG_CACHE_HOME or HOME")?;
    let dir = base.join("raft5fs").join("eval").join(&pin.name);
    let path = dir.join("corpus.bin");
    if matches(&path, &pin.sha256) {
        return Ok(path);
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    eprintln!("downloading the test corpus ({} MB)", pin.size >> 20);
    let mut body = ureq::get(&pin.url)
        .call()
        .map_err(|e| format!("{}: {e}", pin.url))?
        .into_body();
    let mut bytes = Vec::new();
    body.as_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", pin.url))?;
    if raft5fs_wire::hex(&Sha256::digest(&bytes)) != pin.sha256 {
        return Err(format!("{} doesn't match its pinned SHA-256", pin.url));
    }
    let part = dir.join("corpus.bin.part");
    std::fs::write(&part, &bytes).map_err(|e| format!("{}: {e}", part.display()))?;
    std::fs::rename(&part, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

fn matches(path: &Path, sha: &str) -> bool {
    std::fs::read(path).is_ok_and(|b| raft5fs_wire::hex(&Sha256::digest(&b)) == sha)
}
