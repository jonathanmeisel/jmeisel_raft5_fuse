//! How good one ranked result list is, given the judged answers.

use std::collections::HashMap;

/// Normalized discounted cumulative gain of the first `k` results: 1 when
/// the best answers come first, 0 when none show.
pub fn ndcg(ranked: &[u64], relevant: &HashMap<u64, u8>, k: usize) -> f64 {
    let gain = |g: u8| f64::from(g);
    let dcg: f64 = ranked
        .iter()
        .take(k)
        .enumerate()
        .map(|(i, ino)| gain(relevant.get(ino).copied().unwrap_or(0)) / (i as f64 + 2.0).log2())
        .sum();
    let mut best: Vec<u8> = relevant.values().copied().collect();
    best.sort_unstable_by(|a, b| b.cmp(a));
    let ideal: f64 = best
        .iter()
        .take(k)
        .enumerate()
        .map(|(i, &g)| gain(g) / (i as f64 + 2.0).log2())
        .sum();
    if ideal == 0.0 { 0.0 } else { dcg / ideal }
}

/// One over the rank of the first answer within `k`, or 0.
pub fn reciprocal_rank(ranked: &[u64], relevant: &HashMap<u64, u8>, k: usize) -> f64 {
    ranked
        .iter()
        .take(k)
        .position(|ino| relevant.contains_key(ino))
        .map_or(0.0, |i| 1.0 / (i as f64 + 1.0))
}

/// The share of the answers within the first `k` results.
pub fn recall(ranked: &[u64], relevant: &HashMap<u64, u8>, k: usize) -> f64 {
    if relevant.is_empty() {
        return 0.0;
    }
    let found = ranked
        .iter()
        .take(k)
        .filter(|ino| relevant.contains_key(ino))
        .count();
    found as f64 / relevant.len() as f64
}

/// Sums of each measure over a set's queries.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct Totals {
    pub queries: usize,
    pub ndcg10: f64,
    pub mrr10: f64,
    pub hit1: f64,
    pub hit10: f64,
    pub recall50: f64,
    /// Results shown, in all.
    pub shown: f64,
    /// Shown results that are judged answers.
    pub shown_relevant: f64,
    /// Results in the first 10 of the wrong kind: photos for a text query,
    /// text for a photo query. They are never answers.
    pub wrong_kind10: f64,
    /// Queries with nothing shown.
    pub empty: f64,
}

impl Totals {
    /// Adds one query's results. `wrong` says which inodes are of the
    /// wrong kind for it.
    pub fn add(
        &mut self,
        ranked: &[u64],
        relevant: &HashMap<u64, u8>,
        wrong: impl Fn(u64) -> bool,
    ) {
        self.queries += 1;
        self.ndcg10 += ndcg(ranked, relevant, 10);
        self.mrr10 += reciprocal_rank(ranked, relevant, 10);
        self.hit1 += f64::from(u8::from(reciprocal_rank(ranked, relevant, 1) > 0.0));
        self.hit10 += f64::from(u8::from(reciprocal_rank(ranked, relevant, 10) > 0.0));
        self.recall50 += recall(ranked, relevant, 50);
        self.shown += ranked.len() as f64;
        self.shown_relevant += ranked.iter().filter(|i| relevant.contains_key(i)).count() as f64;
        self.wrong_kind10 += ranked.iter().take(10).filter(|&&i| wrong(i)).count() as f64;
        self.empty += f64::from(u8::from(ranked.is_empty()));
    }

    /// The means, for printing: (name, value).
    pub fn means(&self) -> Vec<(&'static str, f64)> {
        let n = self.queries.max(1) as f64;
        let precision = if self.shown == 0.0 {
            0.0
        } else {
            self.shown_relevant / self.shown
        };
        vec![
            ("nDCG@10", self.ndcg10 / n),
            ("MRR@10", self.mrr10 / n),
            ("hit@1", self.hit1 / n),
            ("hit@10", self.hit10 / n),
            ("recall@50", self.recall50 / n),
            ("shown", self.shown / n),
            ("precision", precision),
            ("wrong@10", self.wrong_kind10 / n),
            ("empty", self.empty / n),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(pairs: &[(u64, u8)]) -> HashMap<u64, u8> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn the_best_order_scores_one_and_none_scores_zero() {
        let r = rel(&[(1, 1), (2, 1)]);
        assert!((ndcg(&[1, 2, 3], &r, 10) - 1.0).abs() < 1e-9);
        assert_eq!(ndcg(&[3, 4], &r, 10), 0.0);
        assert!(ndcg(&[3, 1, 2], &r, 10) < 1.0);
    }

    #[test]
    fn reciprocal_rank_and_recall_count_the_first_k() {
        let r = rel(&[(5, 1)]);
        assert_eq!(reciprocal_rank(&[1, 5], &r, 10), 0.5);
        assert_eq!(reciprocal_rank(&[1, 5], &r, 1), 0.0);
        assert_eq!(recall(&[5], &rel(&[(5, 1), (6, 1)]), 50), 0.5);
    }
}
