//! Embeddings as the index keeps them: one byte for each dimension, and a
//! scale. A model gives each chunk a vector of unit length, so that how
//! close two chunks are in meaning is their dot product (cosine).
//!
//! Quantizing to one byte loses little: a dot product moves by about 0.01,
//! much less than what tells a match from a miss.
//!
//! **Changing a model** (`TEXT_MODEL` or `CLIP_MODEL`):
//!
//! - Convert it (raft5fs-embed's `convert` example; `fetch-sources.sh`
//!   pins its sources), attach the files to a release (the models
//!   workflow checks and uploads them), and pin them in `data/models.json`
//!   with a new name: every client reads it.
//! - A model of the BERT family (BERT, XLM-R, DistilBERT) needs no code:
//!   its settings travel in its file, and models.json says what goes
//!   before a query and a passage, and how it pools. Another kind needs
//!   raft5fs-embed to learn it.
//! - Put the old name in its `replaces`. Devices on the new version embed
//!   the old records again at their next pass; devices still on the old
//!   version leave the new records alone.
//! - Fetch it for the web app (`npm run model` in webapp).
//! - Write the parity fixtures again (raft5fs-indexer's ignored
//!   `write_the_web_apps_*` tests), and run `npm run test:parity`.
//! - Measure again what scores tell a match from a miss (the real-model
//!   tests print them), and set its `search` numbers in models.json to fit
//!   (see `view`). For photos, measure on real photos, not drawings, which
//!   score higher: raft5fs-indexer's `clip_scores` example scores queries
//!   against a folder of them.
//! - Build the test corpus again with the new model (raft5fs-eval's
//!   `build_corpus` example), release it, pin it in eval/data/corpus.json,
//!   and run raft5fs-eval (and `raft5fs-eval recall`): the ranking's
//!   numbers in models.json (`ranking`) and the probing in `index` were
//!   set by measuring with the old one.
//! - For a text model: write data/type_vectors.bin again (raft5fs-eval's
//!   `build_type_vectors` example), and set `suggestMin` and `suggestGap`
//!   in models.json from raft5fs-eval's `suggest` example. Until then,
//!   search suggests no types.
//! - A generation's clusters hold vectors of one model. After the change,
//!   the next compaction trains new centres on the new vectors, and leaves
//!   the old model's vectors out: until then, search by meaning finds only
//!   what was embedded again since.

use crate::record::Vector;

// The models' names, sizes, the models they replace and their search
// thresholds, from data/models.json (build.rs):
//
// - `TEXT_MODEL`: the model every client embeds text with (now
//   multilingual-e5-small, Q8_0; raft5fs-embed's `TextModel`).
//   `TEXT_DIMS`: the size of its vectors.
// - `TEXT_REPLACES`: the text models it supersedes. Records that name one
//   are embedded again at a device's next pass; a device still on the old
//   version doesn't know the new name, so it leaves new records alone.
// - `CLIP_MODEL`: the model photos are searched by what they show with
//   (now CLIP ViT-B/32 with a multilingual text side, Q8_0; raft5fs-embed).
//   `CLIP_DIMS`, `CLIP_REPLACES`: as for text.
// - `*_FLOOR`, `*_MARGIN`, `*_Z`, `TEXT_MIN_WORDS`: see `view`.
include!(concat!(env!("OUT_DIR"), "/models.rs"));

/// A vector of unit length as one byte per dimension.
pub fn quantize(v: &[f32]) -> Vector {
    let max = v.iter().fold(0f32, |m, x| m.max(x.abs()));
    if max == 0.0 {
        return Vector {
            scale: 0.0,
            values: vec![0; v.len()],
        };
    }
    let scale = max / 127.0;
    Vector {
        scale,
        values: v
            .iter()
            .map(|x| (x / scale).round().clamp(-127.0, 127.0) as i8)
            .collect(),
    }
}

/// The dot product of a stored vector and a query's. 0 for vectors of
/// different sizes: from different models, they don't compare.
pub fn dot(stored: &Vector, query: &[f32]) -> f32 {
    if stored.values.len() != query.len() {
        return 0.0;
    }
    let sum: f32 = stored
        .values
        .iter()
        .zip(query)
        .map(|(&a, &b)| f32::from(a) * b)
        .sum();
    sum * stored.scale
}

/// `v` made unit length; a zero vector stays zero.
pub fn normalize(v: &mut [f32]) {
    let len = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if len > 0.0 {
        v.iter_mut().for_each(|x| *x /= len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(v: &[f32]) -> Vec<f32> {
        let mut v = v.to_vec();
        normalize(&mut v);
        v
    }

    #[test]
    fn quantizing_keeps_dot_products_close() {
        let a = unit(&[0.3, -0.2, 0.9, 0.1, -0.5, 0.05]);
        let b = unit(&[0.25, -0.1, 0.8, 0.3, -0.4, 0.0]);
        let exact: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        let close = dot(&quantize(&a), &b);
        assert!((exact - close).abs() < 0.01, "{exact} vs {close}");
        assert!((dot(&quantize(&a), &a) - 1.0).abs() < 0.01);
    }

    #[test]
    fn zero_and_mismatched_vectors() {
        let z = quantize(&[0.0, 0.0]);
        assert_eq!(dot(&z, &[1.0, 0.0]), 0.0);
        assert_eq!(dot(&quantize(&[1.0]), &[1.0, 0.0]), 0.0);
        let mut v = vec![0.0, 0.0];
        normalize(&mut v);
        assert_eq!(v, [0.0, 0.0]);
    }
}
