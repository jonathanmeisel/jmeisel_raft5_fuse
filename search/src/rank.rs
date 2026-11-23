//! Merging ranked lists (reciprocal rank fusion): keyword and vector
//! results, and results from several volumes. Scores from different lists
//! do not compare, but ranks do: an item scores `1 / (K + rank)` in each
//! list it is in, and the sums decide.

use std::collections::HashMap;
use std::hash::Hash;

/// The usual constant: it keeps the top few ranks from counting too much.
const K: f32 = 60.0;

/// The items of `lists` (each best first), merged best first. An item in
/// several lists gets the sum of its scores.
pub fn fuse<T: Clone + Eq + Hash>(lists: &[Vec<T>]) -> Vec<(T, f32)> {
    let mut scores: HashMap<T, (f32, usize)> = HashMap::new();
    let mut order = 0;
    for list in lists {
        for (rank, item) in list.iter().enumerate() {
            let slot = scores.entry(item.clone()).or_insert_with(|| {
                order += 1;
                (0.0, order)
            });
            slot.0 += 1.0 / (K + rank as f32 + 1.0);
        }
    }
    let mut out: Vec<_> = scores.into_iter().collect();
    // Ties go to the item seen first, so the result does not depend on
    // the order of a hash map.
    out.sort_by(|a, b| b.1.0.total_cmp(&a.1.0).then(a.1.1.cmp(&b.1.1)));
    out.into_iter()
        .map(|(item, (score, _))| (item, score))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_item_in_both_lists_beats_one_on_top_of_one() {
        let merged = fuse(&[vec!["a", "b", "c"], vec!["d", "b"]]);
        let names: Vec<_> = merged.iter().map(|m| m.0).collect();
        assert_eq!(names[0], "b");
        assert_eq!(names.len(), 4);
        // a and d are both first in one list: a was seen first.
        assert_eq!(&names[1..3], ["a", "d"]);
    }

    #[test]
    fn one_list_keeps_its_order() {
        let merged = fuse(&[vec![3, 1, 2]]);
        assert_eq!(merged.iter().map(|m| m.0).collect::<Vec<_>>(), [3, 1, 2]);
    }
}
