//! Merging the result lists (paths, keywords, meaning, photos) into one, by
//! score.
//!
//! - Each list gives its items a score from 0 to 1 (`search_many` says
//!   how), so a strong match in one list beats weak matches in all.
//! - An item's merged score is the weighted sum of its lists' scores,
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
    RANKING_MEANING_SPAN, RANKING_MIN_COVERAGE, RANKING_PHOTO_SPAN, RANKING_WEIGHT_KEYWORD,
    RANKING_WEIGHT_MEANING, RANKING_WEIGHT_PATH, RANKING_WEIGHT_PHOTO,
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
    /// A keyword match scores its share of the best score times its
    /// coverage to this power, so a match on few of the query's words
    /// counts for little without being cut.
    pub coverage_power: f32,
    /// A match by meaning scores 1 this far above its list's cutoff.
    pub meaning_span: f32,
    pub photo_span: f32,
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
            meaning_span: RANKING_MEANING_SPAN,
            photo_span: RANKING_PHOTO_SPAN,
        }
    }
}

/// A score by similarity, from 0 to 1: half for being at the cutoff,
/// the rest as it rises above it, full at `span` above.
pub fn above_cutoff(score: f32, cutoff: f32, span: f32) -> f32 {
    let rise = if span > 0.0 {
        ((score - cutoff) / span).clamp(0.0, 1.0)
    } else {
        1.0
    };
    0.5 + 0.5 * rise
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
    fn similarity_scales_from_half_at_the_cutoff() {
        assert_eq!(above_cutoff(0.8, 0.8, 0.1), 0.5);
        assert_eq!(above_cutoff(0.95, 0.8, 0.1), 1.0);
        assert!((above_cutoff(0.85, 0.8, 0.1) - 0.75).abs() < 1e-6);
    }
}
