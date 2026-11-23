//! Embeddings as the index keeps them: one byte for each dimension, and a
//! scale. A model gives each chunk a vector of unit length, so that how
//! close two chunks are in meaning is their dot product (cosine).
//!
//! Quantizing to one byte loses little: a dot product moves by about 0.01,
//! much less than what tells a match from a miss.

use crate::record::Vector;

/// The model that every client embeds with: multilingual-e5-small, the int8
/// export at Hugging Face revision 761b726 (see raft5fs-indexer's `embed`
/// and the web app's `embedWorker.js`). A new export or revision needs a
/// new name, as vectors from two exports don't compare.
pub const E5_MODEL: &str = "multilingual-e5-small-int8@761b726";

/// The size of its vectors.
pub const E5_DIMS: usize = 384;

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
