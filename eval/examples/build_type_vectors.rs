//! Writes search/data/type_vectors.bin (`query::suggest`): each type's
//! vector, the mean of a few phrases for it, and the mean of everyday
//! words that centres them, all embedded as queries with the pinned text
//! model. Run again when the text model changes:
//!
//!   cargo run -p raft5fs-eval --release --example build_type_vectors
//!
//! The everyday words are not in eval/data/suggest.json, which measures
//! the result.
use raft5fs_indexer::embed::{TextModel, query_prefix};
use raft5fs_search::filter::FileType;
use raft5fs_search::query::suggest::{TypeVectors, unit};
use raft5fs_search::vector::TEXT_MODEL;

/// Phrases for each type: ones the rule lists have, so the vectors say
/// what the lists mean.
const PHRASES: &[(FileType, &[&str])] = &[
    (
        FileType::Photo,
        &[
            "photos",
            "pictures",
            "photographs",
            "images",
            "camera photos",
        ],
    ),
    (
        FileType::Video,
        &["videos", "video clips", "movies", "recorded video"],
    ),
    (
        FileType::Audio,
        &[
            "audio recordings",
            "songs",
            "music",
            "voice memos",
            "sound files",
        ],
    ),
    (FileType::Pdf, &["pdf files", "pdf documents"]),
    (
        FileType::Document,
        &["documents", "text documents", "word documents"],
    ),
    (
        FileType::Spreadsheet,
        &["spreadsheets", "excel sheets", "tables of numbers"],
    ),
    (
        FileType::Presentation,
        &["presentations", "slides", "slide decks"],
    ),
    (FileType::Track, &["gps tracks", "bike rides", "routes"]),
    (
        FileType::Archive,
        &["archives", "zip files", "compressed files"],
    ),
    (FileType::Code, &["source code", "programs", "scripts"]),
];

/// Everyday words, for the centre.
const EVERYDAY: &[&str] = &[
    "house",
    "car",
    "friend",
    "river",
    "dinner",
    "holiday",
    "city",
    "family",
    "money",
    "weather",
    "street",
    "morning",
    "book",
    "children",
    "hospital",
    "forest",
    "ocean",
    "bread",
    "winter",
    "party",
    "phone",
    "window",
    "shoes",
    "doctor",
    "lunch",
    "neighbour",
    "village",
    "kitchen",
    "evening",
    "uncle",
    "chair",
    "table lamp",
    "breakfast",
    "summer",
    "teacher",
    "road trip",
    "apple",
    "blanket",
    "clock",
    "jacket",
];

fn mean(vs: &[Vec<f32>]) -> Vec<f32> {
    let mut m = vec![0f32; vs[0].len()];
    for v in vs {
        for (a, b) in m.iter_mut().zip(v) {
            *a += b / vs.len() as f32;
        }
    }
    m
}

fn main() {
    let model = TextModel::cached();
    let embed = |words: &[&str]| {
        let texts: Vec<String> = words.iter().map(|s| s.to_string()).collect();
        model
            .embed_now(query_prefix(), &texts)
            .expect("the text model runs")
    };
    let centre = mean(&embed(EVERYDAY));
    let mut out = TypeVectors {
        model: TEXT_MODEL.to_string(),
        centre,
        types: Vec::new(),
    };
    for (t, phrases) in PHRASES {
        let centred: Vec<Vec<f32>> = embed(phrases).iter().map(|v| out.centred(v)).collect();
        out.types.push((*t, unit(mean(&centred))));
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../search/data/type_vectors.bin"
    );
    std::fs::write(path, out.encode()).expect("write type_vectors.bin");
    println!("wrote {path}: {} types", out.types.len());
}
