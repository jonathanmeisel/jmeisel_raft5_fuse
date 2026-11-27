//! A generation must search as the plain view of the same files: sharded
//! keywords, clusters probed in full, dead and moved files, and a
//! generation compacted with recent segments, all give what a view of the
//! newest entries gives. Clusters probed in part lose little.
use std::collections::HashMap;
use std::sync::Arc;

use raft5fs_search::compact::{Config, MemoryBuckets, build, compact};
use raft5fs_search::generation::{PieceId, pieces};
use raft5fs_search::index::{self, Generation, Index, Pieces};
use raft5fs_search::rank::Ranking;
use raft5fs_search::record::{DocKind, Entry, Extra, Record, Stamp};
use raft5fs_search::text::chunks;
use raft5fs_search::vector::{CLIP_MODEL, TEXT_MODEL, quantize};
use raft5fs_search::view::{QueryVector, View, latest};

const DIMS: usize = 16;
const TOPICS: [&str; 6] = ["kayak", "garden", "taxes", "piano", "hiking", "baking"];

/// A unit vector near topic `t`'s direction, moved by `jitter`.
fn vector(t: usize, jitter: u64) -> Vec<f32> {
    let mut v: Vec<f32> = (0..DIMS)
        .map(|i| {
            let base = if i % TOPICS.len() == t { 1.0 } else { 0.05 };
            let noise = ((jitter
                .wrapping_mul(2654435761)
                .wrapping_add(i as u64 * 40503))
                % 1000) as f32
                / 4000.0;
            base + noise
        })
        .collect();
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    v.iter_mut().for_each(|x| *x /= n);
    v
}

/// File `ino` about topic `t`: a few words of it, and filler, embedded.
fn record(ino: u64, at_ms: u64, t: usize, extra_word: &str) -> Record {
    let text = format!(
        "notes {} {} about {} number {ino} with some more words to make it long enough {extra_word}",
        TOPICS[t],
        TOPICS[(t + 1) % TOPICS.len()],
        TOPICS[t]
    );
    let mut cs = chunks(&text);
    for (i, c) in cs.iter_mut().enumerate() {
        c.vector = Some(quantize(&vector(t, ino * 7 + i as u64)));
    }
    let photo = ino.is_multiple_of(5);
    Record {
        ino,
        at_ms,
        stamp: Stamp {
            mtime_ns: at_ms,
            size: text.len() as u64,
        },
        path: format!("{}/sub{}/file {ino}.txt", TOPICS[t], ino % 3),
        kind: if photo { DocKind::Photo } else { DocKind::Text },
        model: TEXT_MODEL.to_string(),
        chunks: cs,
        extra: Extra {
            image: photo.then(|| (CLIP_MODEL.to_string(), quantize(&vector(t, ino)))),
            ..Extra::default()
        },
    }
}

fn config(flat: usize, shards: u32) -> Config {
    Config {
        flat,
        min_shards: shards,
        ..Config::new([3; 8], [9; 32], 1)
    }
}

/// An index of `generation`'s records, compacted, with `recent` on top.
fn indexed(
    generation: &[Record],
    recent: Vec<Entry>,
    config: Config,
) -> (Index, HashMap<PieceId, Vec<u8>>) {
    let (header, files) = build(generation, config).unwrap();
    let all = pieces(&header, &files).unwrap();
    let g = Generation::load(header, |id| all.get(&id).cloned()).unwrap();
    (Index::new(Some(Arc::new(g)), View::new(recent)), all)
}

fn search_index(
    index: &Index,
    all: &HashMap<PieceId, Vec<u8>>,
    query: &str,
    q: Option<&[f32]>,
) -> Vec<(String, f32)> {
    let v = q.map(|values| QueryVector {
        model: TEXT_MODEL,
        values,
    });
    let im = q.map(|values| QueryVector {
        model: CLIP_MODEL,
        values,
    });
    index::search_all(
        &[index.source()],
        query,
        v.as_ref(),
        im.as_ref(),
        20,
        &Ranking::default(),
        None,
        |_, id| all.get(&id).cloned(),
    )
    .into_iter()
    .map(|(_, h)| (h.path, h.score))
    .collect()
}

fn search_view(view: &View, query: &str, q: Option<&[f32]>) -> Vec<(String, f32)> {
    let v = q.map(|values| QueryVector {
        model: TEXT_MODEL,
        values,
    });
    let im = q.map(|values| QueryVector {
        model: CLIP_MODEL,
        values,
    });
    view.search_with(query, v, im, 20)
        .into_iter()
        .map(|h| (h.path, h.score))
        .collect()
}

fn queries() -> Vec<(String, Option<Vec<f32>>)> {
    let mut out = Vec::new();
    for (t, topic) in TOPICS.iter().enumerate() {
        out.push((topic.to_string(), None));
        out.push((format!("{topic} number"), Some(vector(t, 999))));
        out.push((format!("sub1 {topic}"), None));
        out.push((String::new(), Some(vector(t, 31))));
    }
    out.push(("file 17".into(), None));
    out.push(("zebra".into(), Some(vector(2, 5))));
    out
}

fn same(index: &Index, all: &HashMap<PieceId, Vec<u8>>, view: &View) {
    for (q, v) in queries() {
        let a = search_index(index, all, &q, v.as_deref());
        let b = search_view(view, &q, v.as_deref());
        same_up_to_ties(&a, &b, &q);
    }
}

/// Whether two result lists rank alike: the same scores at each place,
/// and the same files at each score. Files that tie may come in any
/// order, and those tied at the last score may differ, as the limit cuts
/// them.
fn same_up_to_ties(a: &[(String, f32)], b: &[(String, f32)], q: &str) {
    const CLOSE: f32 = 1e-4;
    assert_eq!(a.len(), b.len(), "query {q:?}: {a:?} {b:?}");
    for (x, y) in a.iter().zip(b) {
        assert!((x.1 - y.1).abs() < CLOSE, "query {q:?}: {a:?} {b:?}");
    }
    let Some(last) = a.last().map(|h| h.1) else {
        return;
    };
    let above = |x: &[(String, f32)]| {
        let mut p: Vec<String> = x
            .iter()
            .filter(|h| h.1 > last + CLOSE)
            .map(|h| h.0.clone())
            .collect();
        p.sort();
        p
    };
    assert_eq!(above(a), above(b), "query {q:?}");
}

#[test]
fn a_generation_searches_as_the_view_of_its_records() {
    let records: Vec<Record> = (1..=300)
        .map(|i| record(i, 10, i as usize % TOPICS.len(), ""))
        .collect();
    let view = View::new(records.iter().cloned().map(Entry::Record));
    // Keywords in 8 shards, vectors in clusters, all probed: as a full scan.
    let (index, all) = indexed(&records, Vec::new(), config(50, 8));
    let g = index.generation.as_ref().unwrap();
    assert_eq!(g.header.shards, 8);
    assert!(
        g.header
            .pieces_of(raft5fs_search::generation::Kind::TextCluster)
            .count()
            > 1
    );
    same(&index, &all, &view);
    // One cluster: a full scan too.
    let (index, all) = indexed(&records, Vec::new(), config(50_000, 1));
    same(&index, &all, &view);
    assert_eq!(index.len(), 300);
    assert_eq!(index.photos(CLIP_MODEL), (60, 60));
}

/// Generation files changed, deleted and moved in recent segments, and
/// new files there.
fn changes() -> (Vec<Record>, Vec<Entry>) {
    let old: Vec<Record> = (1..=200)
        .map(|i| record(i, 10, i as usize % TOPICS.len(), ""))
        .collect();
    let mut recent = Vec::new();
    for i in 1..=20u64 {
        recent.push(Entry::Gone { ino: i, at_ms: 20 });
    }
    for i in 21..=40u64 {
        recent.push(Entry::Record(record(
            i,
            20,
            (i as usize + 1) % TOPICS.len(),
            "zebra",
        )));
    }
    for i in 41..=45u64 {
        recent.push(Entry::Moved {
            ino: i,
            at_ms: 20,
            path: format!("moved/away {i}.txt"),
        });
    }
    for i in 300..330u64 {
        recent.push(Entry::Record(record(
            i,
            20,
            i as usize % TOPICS.len(),
            "zebra",
        )));
    }
    (old, recent)
}

#[test]
fn dead_and_moved_files_search_as_the_newest_entries() {
    let (old, recent) = changes();
    let mut both: Vec<Entry> = old.iter().cloned().map(Entry::Record).collect();
    both.extend(recent.iter().cloned());
    let view = View::new(latest(both).into_values());
    let (index, all) = indexed(&old, recent, config(50, 4));
    same(&index, &all, &view);
    assert_eq!(index.len(), 200 - 20 + 30);
    let moved = search_index(&index, &all, "moved away", None);
    assert_eq!(moved.len(), 5);
    assert!(
        search_index(&index, &all, "number 7", None)
            .iter()
            .all(|h| !h.0.contains("file 7.txt"))
    );
}

#[test]
fn a_compacted_generation_searches_as_a_fresh_build_of_the_same_files() {
    let (old, recent) = changes();
    let (index, all) = indexed(&old, recent.clone(), config(50, 4));
    let mut live: Vec<Record> = latest(recent.iter().cloned())
        .into_values()
        .filter_map(|e| match e {
            Entry::Record(r) => Some(r),
            _ => None,
        })
        .collect();
    live.sort_by_key(|r| r.ino);
    let mut files = Vec::new();
    let header = compact(
        Some(&index),
        &|id| Ok(all.get(&id).cloned().unwrap_or_default()),
        &live,
        Config {
            id: [4; 8],
            ..config(50, 4)
        },
        MemoryBuckets::default(),
        &mut |n, b| {
            files.push((n, b));
            Ok(())
        },
    )
    .unwrap();
    let new = pieces(&header, &files).unwrap();
    let g = Generation::load(header, |id| new.get(&id).cloned()).unwrap();
    let compacted = Index::new(Some(Arc::new(g)), View::default());

    let mut both: Vec<Entry> = old.iter().cloned().map(Entry::Record).collect();
    both.extend(recent);
    let view = View::new(latest(both).into_values());
    same(&compacted, &new, &view);
    assert_eq!(compacted.len(), index.len());
}

#[test]
fn probing_a_few_clusters_finds_nearly_what_a_full_scan_finds() {
    let n = 30_000u64;
    let records: Vec<Record> = (1..=n)
        .map(|i| {
            let mut r = record(i, 10, i as usize % TOPICS.len(), "");
            // Spread each topic out, so clusters split it.
            for (k, c) in r.chunks.iter_mut().enumerate() {
                let mut v = vector(i as usize % TOPICS.len(), i * 13 + k as u64);
                v[(i % DIMS as u64) as usize] += 0.6;
                let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                v.iter_mut().for_each(|x| *x /= norm);
                c.vector = Some(quantize(&v));
            }
            r
        })
        .collect();
    let (index, all) = indexed(&records, Vec::new(), config(1000, 1));
    let s = [index.source()];
    let mut recall = 0.0;
    let mut counted = 0;
    for j in 0..60u64 {
        let mut q = vector(j as usize % TOPICS.len(), 5000 + j);
        q[(j % DIMS as u64) as usize] += 0.6;
        let norm = q.iter().map(|x| x * x).sum::<f32>().sqrt();
        q.iter_mut().for_each(|x| *x /= norm);
        let v = QueryVector {
            model: TEXT_MODEL,
            values: &q,
        };
        let run = |needs: Vec<(usize, PieceId)>| -> Vec<u64> {
            let pieces: Pieces = needs
                .into_iter()
                .filter_map(|k| Some((k, all.get(&k.1)?.clone())))
                .collect();
            let found = index::search(
                &s,
                "",
                Some(&v),
                None,
                50,
                &pieces,
                &Ranking::default(),
                None,
            );
            index::hits(&s, "", &found, &pieces)
                .into_iter()
                .map(|h| h.1.ino)
                .collect()
        };
        let full = run(index::needs_with(&s, "", Some(&v), None, usize::MAX, 1));
        if full.is_empty() {
            continue;
        }
        // About 2% of the vectors, as at a large volume.
        let part = run(index::needs_with(&s, "", Some(&v), None, 600, 8));
        let hit = part.iter().filter(|i| full.contains(i)).count();
        recall += hit as f64 / full.len() as f64;
        counted += 1;
    }
    assert!(counted > 40);
    let recall = recall / f64::from(counted);
    assert!(recall >= 0.9, "result recall {recall:.3}");
}

/// `query` over `index`, with `filter` (in the syntax), as paths.
fn filtered(
    index: &Index,
    all: &HashMap<PieceId, Vec<u8>>,
    query: &str,
    q: Option<&[f32]>,
    filter: &str,
) -> Vec<String> {
    let (filter, rest) = raft5fs_search::filter::Filter::parse_syntax(filter, 0);
    assert!(rest.is_empty());
    let v = q.map(|values| QueryVector {
        model: TEXT_MODEL,
        values,
    });
    let im = q.map(|values| QueryVector {
        model: CLIP_MODEL,
        values,
    });
    index::search_all(
        &[index.source()],
        query,
        v.as_ref(),
        im.as_ref(),
        20,
        &Ranking::default(),
        Some(&filter),
        |_, id| all.get(&id).cloned(),
    )
    .into_iter()
    .map(|(_, h)| h.path)
    .collect()
}

#[test]
fn a_filter_keeps_only_its_files_in_a_generation_and_recent_segments() {
    let (records, recent) = changes();
    let (index, all) = indexed(&records, recent, config(50, 4));
    let q = vector(0, 1);
    for (query, vector) in [("kayak", None), ("kayak", Some(q.as_slice())), ("", None)] {
        let found = filtered(&index, &all, query, vector, "type:photo");
        assert!(!found.is_empty(), "{query:?} finds photos");
        for path in &found {
            let ino: u64 = path
                .rsplit(' ')
                .next()
                .and_then(|n| n.strip_suffix(".txt"))
                .and_then(|n| n.parse().ok())
                .unwrap();
            assert!(ino.is_multiple_of(5), "{path} is a photo");
        }
        let found = filtered(&index, &all, query, vector, "-type:photo in:sub1");
        assert!(found.iter().all(|p| p.contains("/sub1/")), "{found:?}");
    }
}

#[test]
fn a_filter_drops_files_before_a_strong_match_cuts_the_rest() {
    // Every tenth file says "paddle" once; one text file says it over and
    // over, a far better match than any photo.
    let mut records: Vec<Record> = (1..=200)
        .map(|i| {
            let word = if i % 10 == 0 { "paddle" } else { "" };
            record(i, 10, i as usize % TOPICS.len(), word)
        })
        .collect();
    let mut strong = record(1000, 10, 0, &"paddle ".repeat(30));
    strong.kind = DocKind::Text;
    strong.extra.image = None;
    records.push(strong);
    let (index, all) = indexed(&records, Vec::new(), config(50, 4));
    let unfiltered = filtered(&index, &all, "paddle", None, "");
    assert!(unfiltered[0].ends_with("file 1000.txt"), "{unfiltered:?}");
    // The photos that say it (every tenth file is a photo too) all come
    // back: the strong text match was dropped before it could cut them.
    let photos = filtered(&index, &all, "paddle", None, "type:photo");
    assert_eq!(photos.len(), 20, "{photos:?}");
}

#[test]
fn a_filter_alone_lists_its_files_newest_first() {
    let records: Vec<Record> = (1..=60)
        .map(|i| {
            let mut r = record(i, 10, i as usize % TOPICS.len(), "");
            r.stamp.mtime_ns = i * 86_400_000_000_000;
            r
        })
        .collect();
    let (index, all) = indexed(&records, Vec::new(), config(50, 4));
    let found = filtered(&index, &all, "", None, "type:photo");
    let inos: Vec<u64> = found
        .iter()
        .map(|p| {
            p.rsplit(' ')
                .next()
                .unwrap()
                .trim_end_matches(".txt")
                .parse()
                .unwrap()
        })
        .collect();
    assert_eq!(inos, [60, 55, 50, 45, 40, 35, 30, 25, 20, 15, 10, 5]);
    let found = filtered(&index, &all, "", None, "type:photo sort:oldest");
    assert!(found[0].ends_with("file 5.txt"), "{found:?}");
}

#[test]
fn a_narrow_filter_probes_more_clusters_to_find_its_files() {
    let n = 6_000u64;
    let records: Vec<Record> = (1..=n)
        .map(|i| {
            let mut r = record(i, 10, i as usize % TOPICS.len(), "");
            for (k, c) in r.chunks.iter_mut().enumerate() {
                let mut v = vector(i as usize % TOPICS.len(), i * 13 + k as u64);
                v[(i % DIMS as u64) as usize] += 0.6;
                let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                v.iter_mut().for_each(|x| *x /= norm);
                c.vector = Some(quantize(&v));
            }
            r
        })
        .collect();
    let (index, all) = indexed(&records, Vec::new(), config(100, 1));
    let s = [index.source()];
    // A third of the files, the query's topic among them.
    let (filter, _) = raft5fs_search::filter::Filter::parse_syntax("in:sub0", 0);
    // Near files of topic 0 whose spread put them along dimension 0.
    let mut q = vector(0, 77);
    q[0] += 0.6;
    let norm = q.iter().map(|x| x * x).sum::<f32>().sqrt();
    q.iter_mut().for_each(|x| *x /= norm);
    let v = QueryVector {
        model: TEXT_MODEL,
        values: &q,
    };
    let run = |needs: Vec<(usize, PieceId)>| -> Vec<u64> {
        let pieces: Pieces = needs
            .into_iter()
            .filter_map(|k| Some((k, all.get(&k.1)?.clone())))
            .collect();
        let found = index::search(
            &s,
            "",
            Some(&v),
            None,
            50,
            &pieces,
            &Ranking::default(),
            Some(&filter),
        );
        index::hits(&s, "", &found, &pieces)
            .into_iter()
            .map(|h| h.1.ino)
            .collect()
    };
    let full = run(index::needs_with(&s, "", Some(&v), None, usize::MAX, 1));
    assert!(!full.is_empty());
    let few = index::needs_with(&s, "", Some(&v), None, 600, 8).len();
    let scaled = index::needs(&s, "", Some(&v), None, Some(&filter));
    assert!(scaled.len() > few, "{} clusters, not {few}", scaled.len());
    let part = run(scaled);
    let hit = part.iter().filter(|i| full.contains(i)).count();
    assert!(
        hit as f64 / full.len() as f64 >= 0.9,
        "{hit} of {}",
        full.len()
    );
}
