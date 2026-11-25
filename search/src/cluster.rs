//! Groups unit vectors around centres (spherical k-means), so a search by
//! meaning compares the query with every centre but with the vectors of
//! only the nearest clusters.
//!
//! - `train`: centres from a sample. Starts from distinct sample vectors
//!   chosen by a fixed seed, then moves each centre to the mean of its
//!   vectors (made unit length again), `iterations` times. A cluster left
//!   empty starts again from the vector its centre fits worst.
//! - `nearest`: the centre a vector belongs to.
//! - `probe`: the clusters a query looks in, nearest first, until they
//!   hold enough vectors.
//!
//! With one centre, every vector is in the one cluster, so probing it is
//! a full scan and the results are exact.

/// `k` centres of `dims` values each, unit length.
#[derive(Debug, Clone, PartialEq)]
pub struct Centres {
    pub dims: usize,
    pub values: Vec<f32>,
}

impl Centres {
    pub fn len(&self) -> usize {
        self.values.len().checked_div(self.dims).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn centre(&self, i: usize) -> &[f32] {
        &self.values[i * self.dims..(i + 1) * self.dims]
    }
}

/// The dot product, with eight sums, so the compiler can use SIMD.
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let (ca, ta) = a[..n].as_chunks::<8>();
    let (cb, tb) = b[..n].as_chunks::<8>();
    let mut lanes = [0f32; 8];
    for (x, y) in ca.iter().zip(cb) {
        for i in 0..8 {
            lanes[i] += x[i] * y[i];
        }
    }
    let tail: f32 = ta.iter().zip(tb).map(|(x, y)| x * y).sum();
    lanes.iter().sum::<f32>() + tail
}

/// How many clusters suit `vectors` vectors: about √n, and 1 for fewer
/// than `flat` vectors, which a full scan searches fast enough.
pub fn count_for(vectors: usize, flat: usize) -> usize {
    if vectors < flat {
        1
    } else {
        ((vectors as f64).sqrt().round() as usize).max(1)
    }
}

/// The index of the centre nearest `v`, and its similarity.
pub fn nearest(centres: &Centres, v: &[f32]) -> (usize, f32) {
    let mut best = (0, f32::MIN);
    for i in 0..centres.len() {
        let s = dot(centres.centre(i), v);
        if s > best.1 {
            best = (i, s);
        }
    }
    best
}

/// A small fixed random sequence (SplitMix64), so training gives the same
/// centres for the same sample.
struct Seq(u64);

impl Seq {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

fn unit(v: &mut [f32]) {
    let n = dot(v, v).sqrt();
    if n > 0.0 {
        v.iter_mut().for_each(|x| *x /= n);
    }
}

/// Each sample vector's nearest centre and similarity, on several threads
/// natively.
fn assign_all(centres: &Centres, sample: &[f32], dims: usize) -> Vec<(usize, f32)> {
    let n = sample.len() / dims;
    #[cfg(not(target_arch = "wasm32"))]
    {
        let threads = std::thread::available_parallelism()
            .map_or(1, |t| t.get())
            .min(16);
        if threads > 1 && n >= 4096 {
            let per = n.div_ceil(threads);
            return std::thread::scope(|s| {
                let handles: Vec<_> = sample
                    .chunks(per * dims)
                    .map(|part| {
                        s.spawn(move || {
                            part.chunks_exact(dims)
                                .map(|v| nearest(centres, v))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().expect("a k-means thread doesn't panic"))
                    .collect()
            });
        }
    }
    (0..n)
        .map(|i| nearest(centres, &sample[i * dims..(i + 1) * dims]))
        .collect()
}

/// `k` centres for `sample`, a flat list of unit vectors of `dims` values.
/// Fewer when the sample has fewer vectors than `k`.
pub fn train(sample: &[f32], dims: usize, k: usize, iterations: usize, seed: u64) -> Centres {
    let n = sample.len() / dims;
    let k = k.clamp(1, n.max(1));
    if n == 0 {
        return Centres {
            dims,
            values: Vec::new(),
        };
    }
    let mut seq = Seq(seed);
    let mut picked = std::collections::HashSet::new();
    let mut values = Vec::with_capacity(k * dims);
    while picked.len() < k {
        let i = (seq.next() % n as u64) as usize;
        if picked.insert(i) {
            values.extend_from_slice(&sample[i * dims..(i + 1) * dims]);
        }
    }
    let mut centres = Centres { dims, values };
    for _ in 0..iterations {
        let assigned = assign_all(&centres, sample, dims);
        let mut sums = vec![0f32; k * dims];
        let mut counts = vec![0usize; k];
        for (i, &(c, _)) in assigned.iter().enumerate() {
            counts[c] += 1;
            let v = &sample[i * dims..(i + 1) * dims];
            for (s, x) in sums[c * dims..(c + 1) * dims].iter_mut().zip(v) {
                *s += x;
            }
        }
        // Empty clusters start again from the worst-fitting vectors.
        let mut worst: Vec<usize> = (0..n).collect();
        worst.sort_by(|&a, &b| assigned[a].1.total_cmp(&assigned[b].1));
        let mut spare = worst.into_iter();
        for c in 0..k {
            let s = &mut sums[c * dims..(c + 1) * dims];
            if counts[c] == 0
                && let Some(i) = spare.next()
            {
                s.copy_from_slice(&sample[i * dims..(i + 1) * dims]);
            }
            unit(s);
        }
        centres.values = sums;
    }
    centres
}

/// The clusters a query looks in: nearest centre first, until they hold
/// at least `min_vectors` vectors and number at least `min_clusters`.
/// `sizes[i]` is how many vectors cluster `i` holds.
pub fn probe(
    centres: &Centres,
    query: &[f32],
    sizes: &[usize],
    min_vectors: usize,
    min_clusters: usize,
) -> Vec<usize> {
    let mut order: Vec<(usize, f32)> = (0..centres.len())
        .map(|i| (i, dot(centres.centre(i), query)))
        .collect();
    order.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut out = Vec::new();
    let mut covered = 0;
    for (i, _) in order {
        if covered >= min_vectors && out.len() >= min_clusters {
            break;
        }
        covered += sizes.get(i).copied().unwrap_or(0);
        out.push(i);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` unit vectors of `dims` values around `groups` directions.
    fn grouped(n: usize, dims: usize, groups: usize, seed: u64) -> Vec<f32> {
        let mut seq = Seq(seed);
        let mut r = || (seq.next() % 2000) as f32 / 1000.0 - 1.0;
        let dirs: Vec<Vec<f32>> = (0..groups)
            .map(|_| {
                let mut d: Vec<f32> = (0..dims).map(|_| r()).collect();
                unit(&mut d);
                d
            })
            .collect();
        let mut out = Vec::new();
        for i in 0..n {
            let mut v: Vec<f32> = dirs[i % groups].iter().map(|x| x + 0.15 * r()).collect();
            unit(&mut v);
            out.extend(v);
        }
        out
    }

    #[test]
    fn dot_matches_a_plain_sum() {
        let a: Vec<f32> = (0..19).map(|i| i as f32 * 0.1).collect();
        let b: Vec<f32> = (0..19).map(|i| 1.0 - i as f32 * 0.05).collect();
        let plain: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        assert!((dot(&a, &b) - plain).abs() < 1e-5);
    }

    #[test]
    fn training_finds_the_groups() {
        let sample = grouped(800, 16, 4, 1);
        let c = train(&sample, 16, 4, 10, 7);
        assert_eq!(c.len(), 4);
        // Vectors of one group share a centre.
        for g in 0..4 {
            let first = nearest(&c, &sample[g * 16..(g + 1) * 16]).0;
            for i in (g..800).step_by(4) {
                assert_eq!(nearest(&c, &sample[i * 16..(i + 1) * 16]).0, first);
            }
        }
        // The same sample and seed give the same centres.
        assert_eq!(train(&sample, 16, 4, 10, 7), c);
    }

    #[test]
    fn probing_stops_once_enough_vectors_are_covered() {
        let sample = grouped(400, 8, 4, 2);
        let c = train(&sample, 8, 4, 5, 3);
        let sizes = [100, 100, 100, 100];
        assert_eq!(probe(&c, &sample[..8], &sizes, 150, 1).len(), 2);
        assert_eq!(probe(&c, &sample[..8], &sizes, 0, 3).len(), 3);
        assert_eq!(probe(&c, &sample[..8], &sizes, 10_000, 1).len(), 4);
    }

    #[test]
    fn small_sets_get_one_cluster_and_large_ones_about_their_root() {
        assert_eq!(count_for(49_999, 50_000), 1);
        assert_eq!(count_for(1_000_000, 50_000), 1000);
        let sample = grouped(10, 4, 2, 4);
        assert_eq!(train(&sample, 4, 50, 3, 1).len(), 10);
    }
}
