//! Builds the search test corpus. It is run by hand, once per model
//! change, never by a build:
//!
//! `cargo run --release -p raft5fs-eval --example build_corpus -- WORK OUT`
//!
//! - WORK keeps downloads and partial results, so a second run is quick.
//! - OUT gets `corpus.bin` and `NOTICE.txt`, for a `testdata-…` release.
//!   It prints the SHA-256 and size for data/corpus.json.
//!
//! What goes in:
//! - **MIRACL** (dev sets, English, Spanish and German): every judged
//!   Wikipedia article, plus a sample of others as distractors. Each
//!   article is one file of up to `PASSAGES` passages, plus every judged
//!   one. An article answers a query when one of its passages does.
//! - **XM3600:** its 3,600 photos, as photo files with image vectors. Some
//!   get a made-up place and date, as a camera would record them.
//! - **Queries:**
//!   - MIRACL's dev queries;
//!   - XM3600 captions, whole and cut to four words, for 500 photos per
//!     language;
//!   - article titles, to find the file by its name;
//!   - "place month year", to find the photos taken there and then.
//!
//! Every vector comes from the models search uses now.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::{GzDecoder, MultiGzDecoder};
use raft5fs_eval::corpus::{Corpus, Query};
use raft5fs_indexer::clip::{self, Clip};
use raft5fs_indexer::embed::{self, TextModel, passage_prefix, query_prefix};
use raft5fs_indexer::{manifest, places};
use raft5fs_search::extract::READER;
use raft5fs_search::extract::photo::PhotoInfo;
use raft5fs_search::record::{DocKind, Extra, Record, Stamp};
use raft5fs_search::text::chunks_with_text;
use raft5fs_search::vector::{CLIP_MODEL, TEXT_MODEL, quantize};
use raft5fs_search::view::MIN_MEANING_WORDS;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Each language, and one in how many other articles is kept as a
/// distractor: about 4,000 each.
const LANGS: [(&str, u64); 3] = [("en", 1400), ("es", 350), ("de", 650)];
/// Passages an article keeps, from its start, besides its judged ones.
const PASSAGES: u32 = 6;
const MIRACL: &str = "https://huggingface.co/datasets/miracl";
const XM_CAPTIONS: &str = "https://google.github.io/crossmodal-3600/web-data/captions.zip";
const XM_IMAGES: &str = "https://open-images-dataset.s3.amazonaws.com/crossmodal-3600/images.tgz";
/// Caption queries per language.
const CAPTIONS: usize = 500;
/// Title queries per language.
const TITLES: usize = 100;
/// Places for the made-up photo places, as (latitude, longitude).
const CITIES: [(f64, f64); 20] = [
    (38.7223, -9.1393),
    (37.3891, -5.9845),
    (40.4168, -3.7038),
    (41.3874, 2.1686),
    (48.8566, 2.3522),
    (52.5200, 13.4050),
    (48.1351, 11.5820),
    (48.2082, 16.3738),
    (41.9028, 12.4964),
    (51.5072, -0.1276),
    (40.7128, -74.0060),
    (42.3601, -71.0589),
    (45.5019, -73.5674),
    (19.4326, -99.1332),
    (-34.6037, -58.3816),
    (35.6762, 139.6503),
    (-33.8688, 151.2093),
    (-33.9249, 18.4241),
    (64.1466, -21.9426),
    (50.0755, 14.4378),
];
/// The made-up dates, as (year, month).
const DATES: [(i64, u32); 6] = [
    (2019, 4),
    (2020, 8),
    (2021, 12),
    (2022, 6),
    (2023, 10),
    (2024, 6),
];
/// Photos per place and date.
const PER_PLACE: usize = 5;
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const NOTICE: &str = "\
raft5fs search test corpus

This file holds text, captions and vectors derived from:

- MIRACL (https://project-miracl.github.io): queries and relevance
  judgments under the Apache License 2.0; passages from Wikipedia, under
  CC BY-SA 3.0 (https://creativecommons.org/licenses/by-sa/3.0/). The text
  of Wikipedia articles was cut into passages by the MIRACL authors.
- Crossmodal-3600 (https://google.github.io/crossmodal-3600/): captions
  under CC BY 4.0. The photos are from Open Images, under CC BY 2.0; this
  file holds only their image vectors, not the photos.

The vectors were made with the search models named in the file.
";

#[derive(Serialize, Deserialize)]
struct Article {
    id: String,
    title: String,
    passages: BTreeMap<u32, String>,
}

#[derive(Deserialize)]
struct Doc {
    docid: String,
    title: String,
    text: String,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let work = PathBuf::from(args.next().expect("a work directory"));
    let out = PathBuf::from(args.next().expect("an output directory"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&out).unwrap();

    manifest::model("text").fetch(&embed::cache_dir()).unwrap();
    manifest::model("clip").fetch(&clip::cache_dir()).unwrap();
    let text = TextModel::cached();
    let clip = Clip::cached();

    let mut records: Vec<Record> = Vec::new();
    let mut queries: Vec<Query> = Vec::new();
    let mut pending: Vec<(usize, usize, String)> = Vec::new();
    let mut titles: Vec<(String, u64, String)> = Vec::new();

    for (lang, every) in LANGS {
        let topics = text_of(
            &work,
            &format!("topics-{lang}.tsv"),
            &format!(
                "{MIRACL}/miracl/resolve/main/miracl-v1.0-{lang}/topics/topics.miracl-v1.0-{lang}-dev.tsv"
            ),
        );
        let qrels = text_of(
            &work,
            &format!("qrels-{lang}.tsv"),
            &format!(
                "{MIRACL}/miracl/resolve/main/miracl-v1.0-{lang}/qrels/qrels.miracl-v1.0-{lang}-dev.tsv"
            ),
        );
        let mut judged: HashMap<String, HashSet<u32>> = HashMap::new();
        let mut answers: HashMap<String, HashSet<String>> = HashMap::new();
        for line in qrels.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            let Some((article, n)) = f[2].split_once('#') else {
                continue;
            };
            judged
                .entry(article.into())
                .or_default()
                .insert(n.parse().unwrap());
            if f[3].trim() != "0" {
                answers
                    .entry(f[0].into())
                    .or_default()
                    .insert(article.into());
            }
        }
        let articles = articles(&work, lang, every, &judged);
        let mut ino_of: HashMap<String, u64> = HashMap::new();
        for a in articles {
            let ino = records.len() as u64 + 1;
            let body: Vec<&str> = a.passages.values().map(String::as_str).collect();
            let body = body.join("\n\n");
            let name: String = a.title.replace(['/', '\\'], "-").chars().take(80).collect();
            let chunks = chunks_with_text(&body);
            for (i, (c, t)) in chunks.iter().enumerate() {
                if c.len >= MIN_MEANING_WORDS {
                    pending.push((records.len(), i, t.clone()));
                }
            }
            records.push(Record {
                ino,
                at_ms: 1,
                stamp: Stamp {
                    mtime_ns: 0,
                    size: body.len() as u64,
                },
                path: format!("wiki/{lang}/{name}.txt"),
                kind: DocKind::Text,
                model: TEXT_MODEL.to_string(),
                chunks: chunks.into_iter().map(|(c, _)| c).collect(),
                extra: Extra {
                    reader: READER,
                    ..Extra::default()
                },
            });
            ino_of.insert(a.id, ino);
            titles.push((lang.to_string(), ino, a.title));
        }
        for line in topics.lines() {
            let Some((qid, q)) = line.split_once('\t') else {
                continue;
            };
            let relevant: Vec<(u64, u8)> = answers
                .get(qid)
                .into_iter()
                .flatten()
                .filter_map(|a| ino_of.get(a).map(|&i| (i, 1)))
                .collect();
            if !relevant.is_empty() {
                queries.push(query(&format!("miracl-{lang}"), q.trim(), relevant));
            }
        }
        eprintln!(
            "miracl-{lang}: {} files so far, {} queries",
            records.len(),
            queries.len()
        );
    }

    // Titles, to find a file by its name.
    for (lang, _, _) in LANGS.map(|l| (l.0, 0, 0)) {
        let mut mine: Vec<&(String, u64, String)> = titles.iter().filter(|t| t.0 == lang).collect();
        mine.sort_by_key(|t| fnv(&format!("title:{}", t.1)));
        for t in mine.into_iter().take(TITLES) {
            queries.push(query("path", &t.2, vec![(t.1, 1)]));
        }
    }

    // XM3600's photos and captions.
    let captions = xm_captions(&work);
    let images = xm_images(&work);
    let mut keys: Vec<&String> = captions.keys().collect();
    keys.sort();
    let mut places_queries: BTreeMap<usize, (String, Vec<u64>)> = BTreeMap::new();
    let mut xm_ino: HashMap<String, u64> = HashMap::new();
    for (i, key) in keys.iter().enumerate() {
        let bytes = std::fs::read(images.join(format!("{key}.jpg"))).unwrap();
        let Some(v) = clip.image_now(&bytes, 1).unwrap() else {
            eprintln!("{key}: not decoded, left out");
            continue;
        };
        let ino = records.len() as u64 + 1;
        let made_up = i < CITIES.len() * DATES.len() * PER_PLACE;
        let (info, folder) = if made_up {
            let combo = i / PER_PLACE;
            let (lat, lon) = CITIES[combo % CITIES.len()];
            let (year, month) = DATES[combo / CITIES.len()];
            let day = 1 + (i % 28) as u32;
            let jitter = (i % PER_PLACE) as f64 * 0.003;
            let info = PhotoInfo {
                when_ms: epoch_ms(year, month, day),
                when: Some(format!("{year}:{month:02}:{day:02} 12:00:00")),
                lat: Some(lat + jitter),
                lon: Some(lon - jitter),
                camera: None,
                orientation: 1,
                ..PhotoInfo::default()
            };
            let name = places()
                .locate(lat, lon)
                .names()
                .into_iter()
                .next()
                .unwrap_or_default();
            let q = format!("{name} {} {year}", MONTHS[month as usize - 1]);
            places_queries
                .entry(combo)
                .or_insert((q, Vec::new()))
                .1
                .push(ino);
            (info, year.to_string())
        } else {
            let info = PhotoInfo {
                when_ms: 0,
                when: None,
                lat: None,
                lon: None,
                camera: None,
                orientation: 1,
                ..PhotoInfo::default()
            };
            (info, "unsorted".to_string())
        };
        let ex = info.extracted(Some(places()));
        let chunks = chunks_with_text(&ex.text);
        for (c, (chunk, t)) in chunks.iter().enumerate() {
            if chunk.len >= MIN_MEANING_WORDS {
                pending.push((records.len(), c, t.clone()));
            }
        }
        let mut extra = ex.extra;
        extra.image = Some((CLIP_MODEL.to_string(), quantize(&v)));
        records.push(Record {
            ino,
            at_ms: 1,
            stamp: Stamp {
                mtime_ns: 0,
                size: bytes.len() as u64,
            },
            path: format!("photos/{folder}/IMG_{key}.jpg"),
            kind: DocKind::Photo,
            model: TEXT_MODEL.to_string(),
            chunks: chunks.into_iter().map(|(c, _)| c).collect(),
            extra,
        });
        xm_ino.insert((*key).clone(), ino);
        if i % 200 == 0 {
            eprintln!("photos: {i} of {}", keys.len());
        }
    }
    for (q, inos) in places_queries.into_values() {
        queries.push(query(
            "place",
            &q,
            inos.into_iter().map(|i| (i, 1)).collect(),
        ));
    }
    for (lang, _) in LANGS {
        let mut chosen: Vec<&&String> = keys.iter().filter(|k| xm_ino.contains_key(**k)).collect();
        chosen.sort_by_key(|k| fnv(&format!("{lang}:{k}")));
        for key in chosen.into_iter().take(CAPTIONS) {
            let Some(caption) = captions[*key].get(lang) else {
                continue;
            };
            let ino = xm_ino[*key];
            queries.push(query(&format!("xm-{lang}"), caption, vec![(ino, 1)]));
            let short: Vec<&str> = caption.split_whitespace().take(4).collect();
            queries.push(query(
                &format!("xm-{lang}-short"),
                &short.join(" "),
                vec![(ino, 1)],
            ));
        }
    }

    // The vectors: passages, then queries.
    eprintln!("embedding {} passages", pending.len());
    let started = std::time::Instant::now();
    for (n, batch) in pending.chunks(256).enumerate() {
        let texts: Vec<String> = batch.iter().map(|p| p.2.clone()).collect();
        let vs = text.embed_now(passage_prefix(), &texts).unwrap();
        for ((r, c, _), v) in batch.iter().zip(vs) {
            records[*r].chunks[*c].vector = Some(quantize(&v));
        }
        if n % 20 == 0 {
            let done = (n + 1) * 256;
            let rate = done as f64 / started.elapsed().as_secs_f64();
            eprintln!("  {done} of {}, {rate:.0}/s", pending.len());
        }
    }
    eprintln!("embedding {} queries", queries.len());
    let texts: Vec<String> = queries.iter().map(|q| q.text.clone()).collect();
    for (qs, batch) in queries.chunks_mut(256).zip(texts.chunks(256)) {
        let vs = text.embed_now(query_prefix(), batch).unwrap();
        for (q, v) in qs.iter_mut().zip(vs) {
            q.vector = v;
            q.clip = clip.text_now(&q.text).unwrap();
        }
    }

    let corpus = Corpus {
        text_model: TEXT_MODEL.to_string(),
        clip_model: CLIP_MODEL.to_string(),
        records,
        queries,
    };
    let bytes = corpus.encode();
    std::fs::write(out.join("corpus.bin"), &bytes).unwrap();
    std::fs::write(out.join("NOTICE.txt"), NOTICE).unwrap();
    let mut sets: BTreeMap<&str, usize> = BTreeMap::new();
    for q in &corpus.queries {
        *sets.entry(&q.set).or_default() += 1;
    }
    println!("{} files, queries {sets:?}", corpus.records.len());
    println!(
        "corpus.bin: size {}, sha256 {}",
        bytes.len(),
        raft5fs_wire::hex(&Sha256::digest(&bytes))
    );
}

fn query(set: &str, text: &str, relevant: Vec<(u64, u8)>) -> Query {
    Query {
        set: set.to_string(),
        text: text.to_string(),
        relevant,
        vector: Vec::new(),
        clip: Vec::new(),
    }
}

/// FNV-1a: a stable hash, so the same articles and queries are chosen on
/// every run.
fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf29ce484222325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
    })
}

fn get(url: &str) -> Box<dyn Read> {
    let body = ureq::get(url)
        .header("User-Agent", "raft5fs-eval")
        .call()
        .unwrap_or_else(|e| panic!("{url}: {e}"))
        .into_body();
    Box::new(body.into_reader())
}

/// `url`'s text, kept in `work` as `name`.
fn text_of(work: &Path, name: &str, url: &str) -> String {
    let path = work.join(name);
    if let Ok(t) = std::fs::read_to_string(&path) {
        return t;
    }
    let mut t = String::new();
    get(url).read_to_string(&mut t).unwrap();
    std::fs::write(&path, &t).unwrap();
    t
}

/// `lang`'s judged articles and distractors, read from MIRACL's corpus
/// once (about 1.5–5 GB a language, streamed) and kept in `work`.
fn articles(
    work: &Path,
    lang: &str,
    every: u64,
    judged: &HashMap<String, HashSet<u32>>,
) -> Vec<Article> {
    let path = work.join(format!("articles-{lang}.json"));
    if let Ok(bytes) = std::fs::read(&path) {
        return serde_json::from_slice(&bytes).unwrap();
    }
    #[derive(Deserialize)]
    struct Entry {
        path: String,
    }
    let mut listing = String::new();
    get(&format!(
        "https://huggingface.co/api/datasets/miracl/miracl-corpus/tree/main/miracl-corpus-v1.0-{lang}"
    ))
    .read_to_string(&mut listing)
    .unwrap();
    let mut shards: Vec<String> = serde_json::from_str::<Vec<Entry>>(&listing)
        .unwrap()
        .into_iter()
        .map(|e| e.path)
        .filter(|p| p.ends_with(".jsonl.gz"))
        .collect();
    shards.sort();
    let mut kept: BTreeMap<String, Article> = BTreeMap::new();
    for (i, shard) in shards.iter().enumerate() {
        eprintln!("miracl-{lang}: shard {} of {}", i + 1, shards.len());
        let reader = BufReader::new(MultiGzDecoder::new(get(&format!(
            "{MIRACL}/miracl-corpus/resolve/main/{shard}"
        ))));
        for line in reader.lines() {
            let doc: Doc = serde_json::from_str(&line.unwrap()).unwrap();
            let Some((id, n)) = doc.docid.split_once('#') else {
                continue;
            };
            let n: u32 = n.parse().unwrap();
            let marks = judged.get(id);
            if marks.is_none() && !fnv(&format!("{lang}:{id}")).is_multiple_of(every) {
                continue;
            }
            if n >= PASSAGES && !marks.is_some_and(|m| m.contains(&n)) {
                continue;
            }
            kept.entry(id.to_string())
                .or_insert_with(|| Article {
                    id: id.to_string(),
                    title: doc.title.clone(),
                    passages: BTreeMap::new(),
                })
                .passages
                .insert(n, doc.text);
        }
    }
    let articles: Vec<Article> = kept.into_values().collect();
    std::fs::write(&path, serde_json::to_vec(&articles).unwrap()).unwrap();
    articles
}

/// XM3600's captions in English, Spanish and German, by photo key.
fn xm_captions(work: &Path) -> HashMap<String, HashMap<String, String>> {
    let path = work.join("captions.jsonl");
    if !path.exists() {
        let mut zipped = Vec::new();
        get(XM_CAPTIONS).read_to_end(&mut zipped).unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(zipped)).unwrap();
        let mut file = zip.by_name("captions.jsonl").unwrap();
        let mut out = std::fs::File::create(&path).unwrap();
        std::io::copy(&mut file, &mut out).unwrap();
    }
    let mut all = HashMap::new();
    for line in BufReader::new(std::fs::File::open(&path).unwrap()).lines() {
        let v: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let key = v["image/key"].as_str().unwrap().to_string();
        let mut by_lang = HashMap::new();
        for (lang, _) in LANGS {
            if let Some(c) = v[lang]["caption"][0].as_str() {
                by_lang.insert(lang.to_string(), c.to_string());
            }
        }
        all.insert(key, by_lang);
    }
    all
}

/// The folder of XM3600's photos, as `<key>.jpg`, downloaded once.
fn xm_images(work: &Path) -> PathBuf {
    let dir = work.join("xm3600");
    let done = dir.join(".done");
    if done.exists() {
        return dir;
    }
    std::fs::create_dir_all(&dir).unwrap();
    let mut archive = tar::Archive::new(GzDecoder::new(get(XM_IMAGES)));
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().file_name().map(|n| n.to_os_string());
        let Some(name) = name.filter(|n| n.to_string_lossy().ends_with(".jpg")) else {
            continue;
        };
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        std::fs::File::create(dir.join(name))
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    std::fs::write(done, b"").unwrap();
    dir
}

/// Milliseconds since the Unix epoch at noon UTC on a day.
fn epoch_ms(year: i64, month: u32, day: u32) -> u64 {
    // Days from 1970-01-01 (Howard Hinnant's days_from_civil).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    (days * 86_400_000 + 12 * 3_600_000) as u64
}
