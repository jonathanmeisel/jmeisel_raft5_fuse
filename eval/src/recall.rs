//! How much clustering loses: "result recall", the share of the files a
//! full scan shows (after the cutoff) that a search over probed clusters
//! shows too.
//!
//! - Text uses every embedded chunk; photos use the image vectors.
//! - The clustered search can't see every score, which the cutoff's
//!   spread rule needs (a match stands out from all the files). It is
//!   measured two ways: with the spread taken from the scores it saw only
//!   ("probed"), and from a sample of about 512 files standing for all of
//!   them ("sampled"), as a generation keeps one.
//! - Probing is tried at several shares of the vectors, so the numbers
//!   carry over to larger volumes, where the same number of vectors is a
//!   smaller share.
//! - Text centres are trained around the vectors' mean, as a
//!   generation's are (RAFT5FS_EVAL_UNCENTRED compares without).
//! - For photos, it also tries centres trained on image vectors and query
//!   vectors together: CLIP keeps text and images somewhat apart, so a
//!   text query's nearest image centre may be a poor guide. Half the
//!   caption queries train; the other half measure.

use std::collections::{HashMap, HashSet};

use raft5fs_search::cluster::{self, Centres};
use raft5fs_search::view::{
    Cutoff, IMAGE_MARGIN, IMAGE_Z, MEANING_MARGIN, MEANING_Z, MIN_IMAGE_SIMILARITY,
    MIN_MEANING_WORDS, MIN_SIMILARITY, MIN_SPREAD_POPULATION,
};

use crate::corpus::{Corpus, Query};

/// Shares of the vectors probed.
pub const SHARES: [f64; 9] = [0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 1.0];
/// The fewest clusters a query probes.
pub const MIN_CLUSTERS: usize = 8;
/// Files a search shows at most: 50, as the web app asks, unless `report`
/// is given another number.
static LIMIT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(50);

/// Vectors to search: a flat list, and the file each belongs to.
pub struct Vectors {
    pub dims: usize,
    pub values: Vec<f32>,
    pub files: Vec<u64>,
    pub cutoff: Cutoff,
    /// Whether its centres are trained around its mean.
    pub centre: bool,
}

impl Vectors {
    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    fn row(&self, i: usize) -> &[f32] {
        &self.values[i * self.dims..(i + 1) * self.dims]
    }
}

fn push(out: &mut Vec<f32>, scale: f32, values: &[i8]) {
    out.extend(values.iter().map(|&x| f32::from(x) * scale));
}

/// Every embedded chunk of text, as the meaning search reads them.
pub fn text_vectors(corpus: &Corpus) -> Vectors {
    let mut v = Vectors {
        dims: 0,
        values: Vec::new(),
        files: Vec::new(),
        cutoff: Cutoff {
            floor: MIN_SIMILARITY,
            margin: MEANING_MARGIN,
            z: MEANING_Z,
        },
        centre: true,
    };
    for r in corpus
        .records
        .iter()
        .filter(|r| r.model == corpus.text_model)
    {
        for c in r.chunks.iter().filter(|c| c.len >= MIN_MEANING_WORDS) {
            if let Some(vec) = &c.vector {
                v.dims = vec.values.len();
                push(&mut v.values, vec.scale, &vec.values);
                v.files.push(r.ino);
            }
        }
    }
    v
}

/// Every photo's image vector.
pub fn image_vectors(corpus: &Corpus) -> Vectors {
    let mut v = Vectors {
        dims: 0,
        values: Vec::new(),
        files: Vec::new(),
        cutoff: Cutoff {
            floor: MIN_IMAGE_SIMILARITY,
            margin: IMAGE_MARGIN,
            z: IMAGE_Z,
        },
        centre: false,
    };
    for r in &corpus.records {
        if let Some((model, vec)) = &r.extra.image
            && *model == corpus.clip_model
            && !vec.values.is_empty()
        {
            v.dims = vec.values.len();
            push(&mut v.values, vec.scale, &vec.values);
            v.files.push(r.ino);
        }
    }
    v
}

/// Each file's best score among the vectors `rows`.
fn best_of(v: &Vectors, rows: impl Iterator<Item = usize>, query: &[f32]) -> HashMap<u64, f32> {
    let mut best: HashMap<u64, f32> = HashMap::new();
    for i in rows {
        let s = cluster::dot(v.row(i), query);
        let e = best.entry(v.files[i]).or_insert(f32::MIN);
        *e = e.max(s);
    }
    best
}

/// The lowest score shown, given the best and the scores the spread rule
/// sees, each standing for a weight of files.
fn threshold(c: &Cutoff, best: f32, population: &[(f32, f32)]) -> f32 {
    let mut least = c.floor.max(best - c.margin);
    let n: f32 = population.iter().map(|p| p.1).sum();
    if n >= MIN_SPREAD_POPULATION as f32 {
        let mean = population.iter().map(|p| p.0 * p.1).sum::<f32>() / n;
        let var = population
            .iter()
            .map(|p| (p.0 - mean) * (p.0 - mean) * p.1)
            .sum::<f32>()
            / n;
        least = least.max(mean + c.z * var.sqrt());
    }
    least
}

/// The files shown for `query` among the vectors `rows`: each file's best
/// score, cut off, best first. With `sample` (the rows of files standing
/// for all of them), the spread rule comes from it; else from the scores
/// seen.
fn shown(
    v: &Vectors,
    rows: impl Iterator<Item = usize>,
    query: &[f32],
    sample: Option<&Sample>,
) -> Vec<u64> {
    let best = best_of(v, rows, query);
    let top = best.values().copied().fold(f32::MIN, f32::max);
    let population: Vec<(f32, f32)> = match sample {
        None => best.values().map(|&s| (s, 1.0)).collect(),
        Some(sample) => best_of(v, sample.rows.iter().copied(), query)
            .into_values()
            .map(|s| (s, sample.weight))
            .collect(),
    };
    let least = threshold(&v.cutoff, top, &population);
    let mut out: Vec<(u64, f32)> = best.into_iter().filter(|&(_, s)| s >= least).collect();
    out.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    out.truncate(LIMIT.load(std::sync::atomic::Ordering::Relaxed));
    out.into_iter().map(|(f, _)| f).collect()
}

/// The rows of about 512 files, every so many files, as a generation's
/// sample holds, and how many files each stands for.
struct Sample {
    rows: Vec<usize>,
    weight: f32,
}

fn sample_of(v: &Vectors) -> Sample {
    let mut files: Vec<u64> = v.files.clone();
    files.dedup();
    let stride = (files.len() / 512).max(1);
    let chosen: HashSet<u64> = files.iter().step_by(stride).copied().collect();
    Sample {
        rows: (0..v.len())
            .filter(|&i| chosen.contains(&v.files[i]))
            .collect(),
        weight: files.len() as f32 / chosen.len().max(1) as f32,
    }
}

/// Result recall at each of `SHARES`, over `queries`, with `centres`, with
/// the spread rule from what was probed and from a sample. Queries a full
/// scan shows nothing for don't count. Gives (share, probed, sampled) and
/// the number of queries counted.
pub fn measure(
    v: &Vectors,
    centres: &Centres,
    queries: &[&[f32]],
) -> (Vec<(f64, f64, f64)>, usize) {
    let mean = mean_of(v);
    let mut members: Vec<Vec<usize>> = vec![Vec::new(); centres.len()];
    for i in 0..v.len() {
        members[cluster::nearest(centres, &centred(v.row(i), &mean)).0].push(i);
    }
    let sizes: Vec<usize> = members.iter().map(Vec::len).collect();
    let sample = sample_of(v);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let per = queries.len().div_ceil(threads).max(1);
    let parts: Vec<(Vec<(f64, f64)>, usize)> = std::thread::scope(|s| {
        let handles: Vec<_> = queries
            .chunks(per)
            .map(|qs| {
                let (members, sizes, sample, mean) = (&members, &sizes, &sample, &mean);
                s.spawn(move || {
                    let mut sums = vec![(0f64, 0f64); SHARES.len()];
                    let mut counted = 0;
                    for q in qs {
                        let full: HashSet<u64> =
                            shown(v, 0..v.len(), q, None).into_iter().collect();
                        if full.is_empty() {
                            continue;
                        }
                        counted += 1;
                        let recall = |got: Vec<u64>| {
                            got.iter().filter(|f| full.contains(f)).count() as f64
                                / full.len() as f64
                        };
                        for (k, share) in SHARES.iter().enumerate() {
                            let want = (v.len() as f64 * share).ceil() as usize;
                            let probed = cluster::probe(
                                centres,
                                &centred(q, mean),
                                sizes,
                                want,
                                MIN_CLUSTERS,
                            );
                            let rows = || probed.iter().flat_map(|&c| members[c].iter().copied());
                            sums[k].0 += recall(shown(v, rows(), q, None));
                            sums[k].1 += recall(shown(v, rows(), q, Some(sample)));
                        }
                    }
                    (sums, counted)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut sums = vec![(0f64, 0f64); SHARES.len()];
    let mut counted = 0;
    for (s, c) in parts {
        counted += c;
        for (a, b) in sums.iter_mut().zip(s) {
            a.0 += b.0;
            a.1 += b.1;
        }
    }
    let n = counted.max(1) as f64;
    let rows = SHARES
        .iter()
        .zip(sums)
        .map(|(&s, (probed, sampled))| (s, probed / n, sampled / n))
        .collect();
    (rows, counted)
}

/// The vectors' mean, which text centres are trained around, as a
/// generation's are; photos' are not (`compact`). With
/// RAFT5FS_EVAL_UNCENTRED set, neither is, to compare.
fn mean_of(v: &Vectors) -> Vec<f32> {
    let mut mean = vec![0f32; v.dims];
    if !v.centre || std::env::var_os("RAFT5FS_EVAL_UNCENTRED").is_some() || v.is_empty() {
        return Vec::new();
    }
    for i in 0..v.len() {
        mean.iter_mut().zip(v.row(i)).for_each(|(m, x)| *m += x);
    }
    mean.iter_mut().for_each(|m| *m /= v.len() as f32);
    mean
}

fn centred(x: &[f32], mean: &[f32]) -> Vec<f32> {
    raft5fs_search::generation::centred(x, mean)
}

/// Centres for `v`: about √n of them, trained on up to 100k vectors.
pub fn centres_for(v: &Vectors, extra: &[f32]) -> Centres {
    let k = cluster::count_for(v.len(), 0);
    let step = v.len().div_ceil(100_000).max(1);
    let mean = mean_of(v);
    let mut sample: Vec<f32> = (0..v.len())
        .step_by(step)
        .flat_map(|i| centred(v.row(i), &mean))
        .collect();
    sample.extend_from_slice(extra);
    cluster::train(&sample, v.dims, k, 10, 1)
}

/// Prints result recall for text and for photos, of the first `limit`
/// results.
pub fn report(corpus: &Corpus, limit: usize) {
    LIMIT.store(limit, std::sync::atomic::Ordering::Relaxed);
    let text = text_vectors(corpus);
    let images = image_vectors(corpus);
    let all_text: Vec<&[f32]> = corpus.queries.iter().map(|q| q.vector.as_slice()).collect();
    let started = std::time::Instant::now();
    let c = centres_for(&text, &[]);
    let (rows, n) = measure(&text, &c, &all_text);
    println!(
        "text: {} vectors, {} clusters, {n} queries with results ({:.1}s)",
        text.len(),
        c.len(),
        started.elapsed().as_secs_f64()
    );
    print_rows(&rows);

    let all_clip: Vec<&[f32]> = corpus.queries.iter().map(|q| q.clip.as_slice()).collect();
    let c = centres_for(&images, &[]);
    let (rows, n) = measure(&images, &c, &all_clip);
    println!(
        "photos: {} vectors, {} clusters, {n} queries with results",
        images.len(),
        c.len()
    );
    print_rows(&rows);

    // Image centres alone, against centres also trained on queries.
    let captions: Vec<&Query> = corpus
        .queries
        .iter()
        .filter(|q| q.set.starts_with("xm-"))
        .collect();
    let train_q: Vec<f32> = captions
        .iter()
        .step_by(2)
        .flat_map(|q| q.clip.clone())
        .collect();
    let test_q: Vec<&[f32]> = captions
        .iter()
        .skip(1)
        .step_by(2)
        .map(|q| q.clip.as_slice())
        .collect();
    let alone = centres_for(&images, &[]);
    let joint = centres_for(&images, &train_q);
    let (a, n) = measure(&images, &alone, &test_q);
    let (j, _) = measure(&images, &joint, &test_q);
    println!(
        "photos, held-out captions ({n} with results), spread from a sample: image centres | image and query centres"
    );
    for ((s, _, x), (_, _, y)) in a.iter().zip(&j) {
        println!("  probe {:>5.1}%: {x:.3} | {y:.3}", s * 100.0);
    }
}

fn print_rows(rows: &[(f64, f64, f64)]) {
    for (s, probed, sampled) in rows {
        println!(
            "  probe {:>5.1}%: result recall {sampled:.3} (spread from a sample), {probed:.3} (from what was probed)",
            s * 100.0
        );
    }
}
