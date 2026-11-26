//! Merging the result lists (paths, keywords, meaning, photos) into one, by
//! score.
//!
//! - Each list gives its items a grade from 0 to 1 against a fixed
//!   reference, not against the list's own best, so a list with nothing
//!   relevant gives low grades and a strong match in one list beats weak
//!   matches in all:
//!   - **Meaning and photos** (`Spread`): how far a match stands above
//!     what the same query scores on the volume's typical files, less
//!     what the luckiest of that many unrelated files would reach. A
//!     "best of a bad lot" grades about 0.
//!   - **Keywords:** the match's BM25 score over an ideal match's (every
//!     query word once in a file of average length), times its coverage
//!     to the power `coverage_power`.
//!   - **Paths:** the share of the query's word weight a path matches.
//! - An item's merged score is the weighted sum of its lists' grades,
//!   plus `bonus` for each list beyond its first.
//! - Items below `keep` times the best merged score are dropped: they are
//!   weak next to what the search found.
//!
//! The weights and limits are in data/models.json (`ranking`), set by
//! measuring with raft5fs-eval.

use std::collections::HashMap;
use std::hash::Hash;

use crate::vector::{
    RANKING_BONUS, RANKING_COVERAGE_POWER, RANKING_KEEP, RANKING_KEYWORD_MARGIN,
    RANKING_MIN_COVERAGE, RANKING_WEIGHT_KEYWORD, RANKING_WEIGHT_MEANING, RANKING_WEIGHT_PATH,
    RANKING_WEIGHT_PHOTO, RANKING_Z_LOW, RANKING_Z_SPAN,
};

/// How results are ranked. `Default` is what data/models.json says;
/// raft5fs-eval tries others.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ranking {
    pub weight_path: f32,
    pub weight_keyword: f32,
    pub weight_meaning: f32,
    pub weight_photo: f32,
    pub bonus: f32,
    pub keep: f32,
    /// A keyword match needs at least this coverage...
    pub min_coverage: f32,
    /// ... and at least this share of the best keyword score.
    pub keyword_margin: f32,
    /// A keyword match's grade is multiplied by its coverage to this
    /// power, so a match on few of the query's words counts for little
    /// without being cut.
    pub coverage_power: f32,
    /// A match by meaning or by what a photo shows grades 0 at this many
    /// standard deviations above luck (`Spread::excess`)...
    pub z_low: f32,
    /// ... and 1 this many further.
    pub z_span: f32,
}

impl Default for Ranking {
    fn default() -> Self {
        Self {
            weight_path: RANKING_WEIGHT_PATH,
            weight_keyword: RANKING_WEIGHT_KEYWORD,
            weight_meaning: RANKING_WEIGHT_MEANING,
            weight_photo: RANKING_WEIGHT_PHOTO,
            bonus: RANKING_BONUS,
            keep: RANKING_KEEP,
            min_coverage: RANKING_MIN_COVERAGE,
            keyword_margin: RANKING_KEYWORD_MARGIN,
            coverage_power: RANKING_COVERAGE_POWER,
            z_low: RANKING_Z_LOW,
            z_span: RANKING_Z_SPAN,
        }
    }
}

/// The fewest files a spread is measured over: with fewer, the mean and
/// deviation say little, and matches grade in full. Over few files z can't
/// grow large (at most (n − 1) / √n), so a small search grades its
/// matches low rather than wrongly.
pub const MIN_SPREAD_FILES: f32 = 10.0;
/// The least standard deviation counted, so a population of near-equal
/// scores doesn't make tiny differences look large.
pub const MIN_DEVIATION: f32 = 0.005;

/// One search's similarity scores over everything searched, for grading
/// its matches against chance. Per query and per model: scores from the
/// text model and from CLIP are on different scales.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spread {
    mean: f32,
    deviation: f32,
    /// How many standard deviations above the mean the best of this many
    /// unrelated files is expected to be.
    luck: f32,
}

impl Spread {
    /// The spread of `population`: each score with the number of files it
    /// stands for (a sample's scores stand for many). `None` with fewer
    /// than `MIN_SPREAD_FILES` files.
    pub fn of(population: &[(f32, f32)]) -> Option<Self> {
        let n: f32 = population.iter().map(|p| p.1).sum();
        if n < MIN_SPREAD_FILES {
            return None;
        }
        let mean = population.iter().map(|p| p.0 * p.1).sum::<f32>() / n;
        let var = population
            .iter()
            .map(|p| (p.0 - mean) * (p.0 - mean) * p.1)
            .sum::<f32>()
            / n;
        Some(Self {
            mean,
            deviation: var.sqrt().max(MIN_DEVIATION),
            luck: expected_best(n),
        })
    }

    /// How many standard deviations `score` stands above the mean, less
    /// the luck of the best of this many files: about 0 for the best of
    /// unrelated files, clearly more for a real match.
    pub fn excess(&self, score: f32) -> f32 {
        (score - self.mean) / self.deviation - self.luck
    }

    /// The grade (0–1) of `score`: 0 at `low` standard deviations above
    /// luck, 1 at `span` more. Without a spread (too few files), 1.
    pub fn grade(spread: Option<&Self>, score: f32, low: f32, span: f32) -> f32 {
        match spread {
            None => 1.0,
            Some(s) if span > 0.0 => ((s.excess(score) - low) / span).clamp(0.0, 1.0),
            Some(s) => f32::from(u8::from(s.excess(score) >= low)),
        }
    }
}

/// The expected best of `n` draws from a standard normal distribution, in
/// standard deviations above the mean (Blom's approximation:
/// Φ⁻¹((n − 0.375) / (n + 0.25))). About 1.5 for 10, 3.2 for 1,000 and 4.2
/// for 50,000.
pub fn expected_best(n: f32) -> f32 {
    if n <= 1.0 {
        return 0.0;
    }
    inverse_normal(((n - 0.375) / (n + 0.25)) as f64) as f32
}

/// The standard normal distribution's quantile function, Φ⁻¹(p), for
/// 0 < p < 1 (Acklam's rational approximation, relative error under
/// 1.2e-9).
fn inverse_normal(p: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969683028665376e1,
        2.209460984245205e2,
        -2.759285104469687e2,
        1.38357751867269e2,
        -3.066479806614716e1,
        2.506628277459239,
    ];
    const B: [f64; 5] = [
        -5.447609879822406e1,
        1.615858368580409e2,
        -1.556989798598866e2,
        6.680131188771972e1,
        -1.328068155288572e1,
    ];
    const C: [f64; 6] = [
        -7.784894002430293e-3,
        -3.223964580411365e-1,
        -2.400758277161838,
        -2.549732539343734,
        4.374664141464968,
        2.938163982698783,
    ];
    const D: [f64; 4] = [
        7.784695709041462e-3,
        3.224671290700398e-1,
        2.445134137142996,
        3.754408661907416,
    ];
    let p = p.clamp(1e-300, 1.0 - 1e-16);
    let low = 0.02425;
    let tail = |q: f64| {
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    };
    if p < low {
        tail((-2.0 * p.ln()).sqrt())
    } else if p > 1.0 - low {
        -tail((-2.0 * (1.0 - p).ln()).sqrt())
    } else {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    }
}

/// The items of `lists` merged, best first. Each list has a weight and
/// its items' scores (0–1); an item in several lists gets the sum of its
/// weighted scores, plus `bonus` for each list beyond the first. Items
/// below `keep` times the best are left out. Ties go to the item seen
/// first, so the result does not depend on a hash map's order.
pub fn merge<T: Clone + Eq + Hash>(
    lists: &[(f32, Vec<(T, f32)>)],
    bonus: f32,
    keep: f32,
) -> Vec<(T, f32)> {
    let mut scores: HashMap<T, (f32, usize, usize)> = HashMap::new();
    let mut order = 0;
    for (weight, list) in lists {
        for (item, s) in list {
            let slot = scores.entry(item.clone()).or_insert_with(|| {
                order += 1;
                (0.0, 0, order)
            });
            slot.0 += weight * s;
            slot.1 += 1;
        }
    }
    let mut out: Vec<(T, f32, usize)> = scores
        .into_iter()
        .map(|(item, (s, lists, seen))| (item, s + bonus * lists.saturating_sub(1) as f32, seen))
        .collect();
    out.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.2.cmp(&b.2)));
    let best = out.first().map_or(0.0, |o| o.1);
    out.into_iter()
        .take_while(|o| o.1 >= best * keep)
        .map(|(item, s, _)| (item, s))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_item_in_both_lists_beats_one_on_top_of_one() {
        let merged = merge(
            &[
                (1.0, vec![("a", 0.9), ("b", 0.8), ("c", 0.5)]),
                (1.0, vec![("d", 0.9), ("b", 0.6)]),
            ],
            0.1,
            0.0,
        );
        let names: Vec<_> = merged.iter().map(|m| m.0).collect();
        assert_eq!(names[0], "b");
        assert_eq!(names.len(), 4);
        // a and d tie: a was seen first.
        assert_eq!(&names[1..3], ["a", "d"]);
    }

    #[test]
    fn a_strong_match_in_one_list_beats_weak_ones_in_all() {
        let merged = merge(
            &[
                (1.0, vec![("weak", 0.2), ("strong", 1.0)]),
                (1.0, vec![("weak", 0.2)]),
                (1.0, vec![("weak", 0.2)]),
            ],
            0.05,
            0.0,
        );
        assert_eq!(merged[0].0, "strong");
    }

    #[test]
    fn items_far_below_the_best_are_dropped() {
        let merged = merge(&[(1.0, vec![(1, 1.0), (2, 0.6), (3, 0.2)])], 0.0, 0.5);
        assert_eq!(merged.iter().map(|m| m.0).collect::<Vec<_>>(), [1, 2]);
    }

    #[test]
    fn the_best_of_more_files_is_expected_higher() {
        assert_eq!(expected_best(1.0), 0.0);
        assert!((expected_best(10.0) - 1.54).abs() < 0.03);
        assert!((expected_best(1000.0) - 3.24).abs() < 0.03);
        assert!(expected_best(50_000.0) > 4.1 && expected_best(50_000.0) < 4.3);
        assert!((inverse_normal(0.5)).abs() < 1e-9);
        assert!((inverse_normal(0.975) - 1.959964).abs() < 1e-6);
        assert!((inverse_normal(0.01) + 2.326348).abs() < 1e-6);
    }

    #[test]
    fn a_match_grades_by_how_far_it_stands_above_luck() {
        // 1,000 files around 0.5, spread 0.1: luck is about 3.24
        // deviations, so the best of unrelated files scores about 0.82.
        let population: Vec<(f32, f32)> = (0..1000)
            .map(|i| (0.5 + 0.1 * if i % 2 == 0 { 1.0 } else { -1.0 }, 1.0))
            .collect();
        let s = Spread::of(&population).unwrap();
        assert!(s.excess(0.82).abs() < 0.05);
        assert_eq!(Spread::grade(Some(&s), 0.7, 0.0, 2.0), 0.0);
        assert!((Spread::grade(Some(&s), 0.924, 0.0, 2.0) - 0.5).abs() < 0.05);
        assert_eq!(Spread::grade(Some(&s), 1.2, 0.0, 2.0), 1.0);
        // Too few files: no spread, and every match grades in full.
        assert_eq!(Spread::of(&population[..9]), None);
        assert!(Spread::of(&population[..10]).is_some());
        assert_eq!(Spread::grade(None, 0.1, 0.0, 2.0), 1.0);
    }

    #[test]
    fn a_sampled_score_stands_for_many_files() {
        // Ten scores standing for 100 files each: 1,000 files' luck.
        let sample: Vec<(f32, f32)> = (0..10).map(|i| (0.4 + 0.02 * i as f32, 100.0)).collect();
        let s = Spread::of(&sample).unwrap();
        assert!((s.luck - expected_best(1000.0)).abs() < 1e-6);
    }
}
