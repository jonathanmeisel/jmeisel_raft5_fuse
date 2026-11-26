//! `cargo run -p raft5fs-eval --release -- [options]`: search quality on
//! the test corpus.
//!
//! - `--corpus FILE`: a corpus file; else the pinned one, downloaded once.
//! - `--volumes N`: split the corpus into N volumes (default 1).
//! - `--compare`: one volume and four, side by side.
//! - `--limit N`: results per search (default 50, as the web app asks).
//! - `--report FILE`: also write the measures as JSON.
//! - `recall` (first): result recall of clustered search, text and photos.
//! - `tune` (first): the ranking's numbers that score best (`tune`), over
//!   `--volumes` volumes (default 4) and every query.
use std::path::PathBuf;

use raft5fs_eval::corpus::Corpus;
use raft5fs_eval::{fetch, run, split, table};

fn main() {
    let mut corpus_path: Option<PathBuf> = None;
    let mut volumes = vec![1usize];
    let mut limit = 50;
    let mut report: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1).peekable();
    let recall = args.next_if(|a| a == "recall").is_some();
    let tune = args.next_if(|a| a == "tune").is_some();
    if tune {
        volumes = vec![4];
    }
    while let Some(a) = args.next() {
        let mut value = || {
            args.next()
                .unwrap_or_else(|| fail(&format!("{a} needs a value")))
        };
        match a.as_str() {
            "--corpus" => corpus_path = Some(PathBuf::from(value())),
            "--volumes" => volumes = vec![value().parse().unwrap_or_else(|_| fail("--volumes N"))],
            "--compare" => volumes = vec![1, 4],
            "--limit" => limit = value().parse().unwrap_or_else(|_| fail("--limit N")),
            "--report" => report = Some(PathBuf::from(value())),
            _ => fail(&format!("unknown argument {a}")),
        }
    }
    let path = corpus_path.unwrap_or_else(|| fetch().unwrap_or_else(|e| fail(&e)));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| fail(&format!("{}: {e}", path.display())));
    let corpus =
        Corpus::decode(&bytes).unwrap_or_else(|e| fail(&format!("{}: {e}", path.display())));
    eprintln!(
        "{} files, {} queries; models {} and {}",
        corpus.records.len(),
        corpus.queries.len(),
        corpus.text_model,
        corpus.clip_model
    );
    if recall {
        raft5fs_eval::recall::report(&corpus);
        return;
    }
    if tune {
        let start = raft5fs_search::rank::Ranking::default();
        let (best, score) =
            raft5fs_eval::tune::tune(&corpus, volumes[0], corpus.queries.len(), start);
        println!("best ({score:.4}): {best:#?}");
        let views = split(&corpus.records, volumes[0]);
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let results =
            raft5fs_eval::run_with(&corpus, &corpus.queries, &views, limit, threads, &best);
        println!("{}", table(&results));
        return;
    }
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut json = serde_json::Map::new();
    for n in volumes {
        let views = split(&corpus.records, n);
        let started = std::time::Instant::now();
        let results = run(&corpus, &views, limit, threads);
        println!(
            "\n{n} volume(s), {:.1}s\n{}",
            started.elapsed().as_secs_f64(),
            table(&results)
        );
        json.insert(
            format!("volumes-{n}"),
            serde_json::to_value(&results).expect("measures serialize"),
        );
    }
    if let Some(r) = report {
        let text = serde_json::to_string_pretty(&json).expect("measures serialize");
        std::fs::write(&r, text).unwrap_or_else(|e| fail(&format!("{}: {e}", r.display())));
    }
}

fn fail(message: &str) -> ! {
    eprintln!("raft5fs-eval: {message}");
    std::process::exit(2)
}
