//! Choosing the ranking's numbers (data/models.json `ranking`) by
//! measuring: one number at a time, each tried at a few values, keeping
//! the best, twice over.
//!
//! - The score to raise weighs groups of query sets (`score`): nDCG@10
//!   for MIRACL's (judged passages), MRR@10 for the rest (one answer
//!   each), less a little for each wrong-kind result in the first 10
//!   (photos for a text query, text for a photo query).
//! - It searches the corpus split into several volumes, as the problem
//!   it fixes (weak results across volumes) shows there.
//! - It tunes on a sample of the queries, then reports all of them.

use std::collections::BTreeMap;

use raft5fs_search::rank::Ranking;

use crate::corpus::{Corpus, Query};
use crate::metrics::Totals;
use crate::{run_with, split};

/// What one ranking scores: higher is better. Each group of query sets
/// counts for a fixed share, so that the many photo sets don't outweigh
/// text: text (MIRACL, nDCG@10) 40%, photos (XM3600, MRR@10) 30%, names
/// and places (MRR@10) 15% each, less a little for each wrong-kind result
/// in the first 10.
///
/// A ranking that loses text quality is not a choice: each MIRACL set's
/// nDCG@10 below its `TEXT_FLOOR` costs five times the shortfall.
pub fn score(results: &BTreeMap<String, Totals>) -> f64 {
    let groups: [(&str, f64); 4] = [
        ("miracl", 0.4),
        ("xm-", 0.3),
        ("path", 0.15),
        ("place", 0.15),
    ];
    let shortfall: f64 = TEXT_FLOOR
        .iter()
        .filter_map(|&(set, floor)| {
            let t = results.get(set)?;
            Some((floor - t.ndcg10 / t.queries.max(1) as f64).max(0.0))
        })
        .sum();
    let quality: f64 = groups
        .iter()
        .map(|&(prefix, share)| {
            let sets: Vec<&Totals> = results
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(_, t)| t)
                .collect();
            if sets.is_empty() {
                return 0.0;
            }
            let mean: f64 = sets
                .iter()
                .map(|t| {
                    let n = t.queries.max(1) as f64;
                    let main = if prefix == "miracl" {
                        t.ndcg10
                    } else {
                        t.mrr10
                    };
                    main / n - 0.01 * t.wrong_kind10 / n
                })
                .sum::<f64>()
                / sets.len() as f64;
            share * mean
        })
        .sum();
    quality - 5.0 * shortfall
}

/// The lowest nDCG@10 each MIRACL set may have: what ranking by rank
/// order (reciprocal rank fusion) scores on the corpus, less 0.01.
pub const TEXT_FLOOR: [(&str, f64); 3] = [
    ("miracl-en", 0.789),
    ("miracl-es", 0.776),
    ("miracl-de", 0.708),
];

/// One part of the ranking: its name, the values tried, and how to set it.
type Try = (&'static str, Vec<f32>, fn(&mut Ranking, f32));

/// The numbers tried for each part of the ranking.
fn tries() -> Vec<Try> {
    vec![
        ("weight_path", vec![0.25, 0.5, 1.0, 1.5, 2.0], |r, v| {
            r.weight_path = v
        }),
        ("weight_keyword", vec![0.25, 0.5, 1.0, 1.5, 2.0], |r, v| {
            r.weight_keyword = v
        }),
        ("weight_meaning", vec![0.5, 1.0, 1.5, 2.0, 3.0], |r, v| {
            r.weight_meaning = v
        }),
        ("weight_photo", vec![0.5, 1.0, 1.5, 2.0, 3.0], |r, v| {
            r.weight_photo = v
        }),
        ("bonus", vec![0.0, 0.1, 0.2, 0.4, 0.6], |r, v| r.bonus = v),
        ("keep", vec![0.0, 0.15, 0.3, 0.45, 0.6], |r, v| r.keep = v),
        ("min_coverage", vec![0.0, 0.2, 0.35, 0.5, 0.65], |r, v| {
            r.min_coverage = v
        }),
        ("coverage_power", vec![1.0, 1.5, 2.0, 3.0, 4.0], |r, v| {
            r.coverage_power = v
        }),
        ("keyword_margin", vec![0.0, 0.1, 0.2, 0.35, 0.5], |r, v| {
            r.keyword_margin = v
        }),
        (
            "meaning_span",
            vec![0.02, 0.035, 0.05, 0.08, 0.12],
            |r, v| r.meaning_span = v,
        ),
        ("photo_span", vec![0.02, 0.03, 0.04, 0.06, 0.09], |r, v| {
            r.photo_span = v
        }),
    ]
}

/// The best ranking found from `start`, with its score, printing each
/// step.
pub fn tune(corpus: &Corpus, volumes: usize, sample: usize, start: Ranking) -> (Ranking, f64) {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let views = split(&corpus.records, volumes);
    let step = corpus.queries.len().div_ceil(sample.max(1)).max(1);
    let queries: Vec<Query> = corpus.queries.iter().step_by(step).cloned().collect();
    let measure = |r: &Ranking| score(&run_with(corpus, &queries, &views, 50, threads, r));
    let mut best = start;
    let mut best_score = measure(&best);
    eprintln!("start: {best_score:.4}");
    for round in 0..2 {
        for (name, values, set) in tries() {
            for v in values {
                let mut r = best;
                set(&mut r, v);
                if r == best {
                    continue;
                }
                let sc = measure(&r);
                if sc > best_score + 1e-6 {
                    best = r;
                    best_score = sc;
                    eprintln!("round {round}: {name} = {v}: {sc:.4}");
                }
            }
        }
    }
    (best, best_score)
}
