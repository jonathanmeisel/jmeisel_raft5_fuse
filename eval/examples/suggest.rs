//! How well e5 type suggestions (`query::suggest`) do on
//! eval/data/suggest.json, at the thresholds in models.json and at
//! others:
//!
//!   cargo run -p raft5fs-eval --release --example suggest
//!
//! A word of a type should suggest it; an everyday word nothing.
use raft5fs_indexer::embed::{TextModel, query_prefix};
use raft5fs_search::filter::FileType;
use raft5fs_search::query::suggest::{pinned, suggest_with};
use raft5fs_search::vector::{SUGGEST_GAP, SUGGEST_MIN};
use serde::Deserialize;

#[derive(Deserialize)]
struct Set {
    words: Vec<Word>,
}

#[derive(Deserialize)]
struct Word {
    word: String,
    #[serde(rename = "type")]
    kind: Option<String>,
}

fn main() {
    let set: Set = serde_json::from_str(include_str!("../data/suggest.json")).unwrap();
    let types = pinned().expect("type vectors for the pinned model");
    let model = TextModel::cached();
    let texts: Vec<String> = set.words.iter().map(|w| w.word.clone()).collect();
    let vectors = model.embed_now(query_prefix(), &texts).unwrap();
    let run = |min: f32, gap: f32, show: bool| {
        let (mut right, mut wrong, mut wanted) = (0, 0, 0);
        for (w, v) in set.words.iter().zip(&vectors) {
            let want = w.kind.as_deref().and_then(FileType::of_name);
            wanted += usize::from(want.is_some());
            let got = suggest_with(types, &[(w.word.clone(), v.clone())], min, gap);
            match (got, want) {
                (Some(g), Some(t)) if g == t => {
                    right += 1;
                    if show {
                        println!("  right: {:?} suggested {}", w.word, g.name());
                    }
                }
                (Some(g), _) => {
                    wrong += 1;
                    if show {
                        println!("  wrong: {:?} suggested {}", w.word, g.name());
                    }
                }
                _ => {}
            }
        }
        let made = right + wrong;
        let precision = right as f64 / made.max(1) as f64;
        let recall = right as f64 / wanted.max(1) as f64;
        (precision, recall, made)
    };
    println!("min   gap   precision recall suggested");
    for min in [0.35f32, 0.4, 0.45, 0.5, 0.55, 0.6] {
        for gap in [0.05f32, 0.1, 0.15, 0.2] {
            let (p, r, n) = run(min, gap, false);
            println!("{min:.2}  {gap:.2}  {p:9.3} {r:6.3} {n:5}");
        }
    }
    let (p, r, n) = run(SUGGEST_MIN, SUGGEST_GAP, true);
    println!(
        "models.json ({SUGGEST_MIN}, {SUGGEST_GAP}): precision {p:.3}, recall {r:.3}, {n} suggested"
    );
}
