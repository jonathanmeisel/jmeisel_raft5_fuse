//! Scores queries against a folder of photos with CLIP, to calibrate
//! photo search: `cargo run --release -p raft5fs-indexer --example
//! clip_scores -- <photos> <query>...`. Prints, for each query, every
//! photo's cosine, best first, and which ones search would return.
use std::path::PathBuf;

use raft5fs_indexer::clip::Clip;
use raft5fs_search::view::{IMAGE_MARGIN, MIN_IMAGE_SIMILARITY};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("a folder of photos"));
    let clip = std::env::var_os("RAFT5FS_CLIP_DIR")
        .map(|d| Clip::new(PathBuf::from(d)))
        .unwrap_or_else(Clip::cached);
    let mut photos: Vec<(String, Vec<f32>)> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "jpg"))
        .filter_map(|e| {
            let bytes = std::fs::read(e.path()).ok()?;
            let v = clip.image_now(&bytes, 1).ok()??;
            Some((e.file_name().to_string_lossy().into_owned(), v))
        })
        .collect();
    photos.sort_by(|a, b| a.0.cmp(&b.0));
    for query in args {
        let q = clip.text_now(&query).unwrap();
        let mut scores: Vec<(f32, &str)> = photos
            .iter()
            .map(|(n, v)| (v.iter().zip(&q).map(|(a, b)| a * b).sum(), n.as_str()))
            .collect();
        scores.sort_by(|a, b| b.0.total_cmp(&a.0));
        let best = scores[0].0;
        let shown: Vec<&str> = scores
            .iter()
            .filter(|(s, _)| *s >= MIN_IMAGE_SIMILARITY && *s >= best - IMAGE_MARGIN)
            .map(|(_, n)| *n)
            .collect();
        let top: Vec<String> = scores
            .iter()
            .take(5)
            .map(|(s, n)| format!("{n} {s:.3}"))
            .collect();
        println!(
            "{query:22} shown {shown:?}\n{:22} top {}",
            "",
            top.join(", ")
        );
    }
}
