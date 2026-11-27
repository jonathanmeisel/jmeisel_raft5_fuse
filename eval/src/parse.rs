//! `raft5fs-eval parse`: how well plain English queries read as filters,
//! on the queries in data/parse.json.
//!
//! - **Exact:** the share of queries whose terms (as a set) and text are
//!   both as expected.
//! - **Wrong terms:** terms the parser made that the query doesn't ask
//!   for, over all the terms it made. A wrong term hides files, so this
//!   should stay near 0.
//! - **Missed terms:** terms the query asks for that the parser didn't
//!   make, over all expected terms. A missed term only searches as text.

use std::collections::BTreeSet;

use raft5fs_search::filter::Filter;
use raft5fs_search::geo::Place;
use raft5fs_search::query::{Vocabulary, parse};
use raft5fs_search::record::Meta;
use serde::Deserialize;

/// The test set, as data/parse.json has it.
#[derive(Debug, Deserialize)]
pub struct Set {
    pub now: String,
    pub vocabulary: Names,
    pub queries: Vec<Case>,
}

#[derive(Debug, Deserialize)]
pub struct Names {
    /// Town, region, country, country code.
    pub places: Vec<[String; 4]>,
    pub people: Vec<String>,
    pub cameras: Vec<String>,
    pub volumes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Case {
    pub query: String,
    /// The terms, in the filter syntax.
    pub filter: String,
    pub text: String,
}

/// The pinned set.
pub fn pinned() -> Set {
    serde_json::from_str(include_str!("../data/parse.json")).expect("data/parse.json reads")
}

impl Set {
    pub fn vocabulary(&self) -> Vocabulary {
        let mut v = Vocabulary::default();
        let meta = Meta {
            places: self
                .vocabulary
                .places
                .iter()
                .map(|[town, region, country, code]| Place {
                    town: Some(town.clone()),
                    region: Some(region.clone()),
                    region_local: None,
                    country: Some(country.clone()),
                    code: Some(code.clone()),
                })
                .collect(),
            ..Meta::default()
        };
        v.add_meta(&meta);
        for who in &self.vocabulary.people {
            v.add_person(who);
        }
        for camera in &self.vocabulary.cameras {
            v.add_meta(&Meta {
                camera: camera.clone(),
                ..Meta::default()
            });
        }
        for label in &self.vocabulary.volumes {
            v.add_volume(label);
        }
        v
    }

    pub fn now_ms(&self) -> u64 {
        raft5fs_search::extract::track::iso_ms(&self.now).expect("`now` is an ISO time")
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub queries: usize,
    pub exact: usize,
    pub made: usize,
    pub wrong: usize,
    pub expected: usize,
    pub missed: usize,
    /// Each query not read as expected: the query, what it gave, and what
    /// it should give.
    pub misses: Vec<(String, String, String)>,
}

impl Report {
    pub fn exact_share(&self) -> f64 {
        self.exact as f64 / self.queries.max(1) as f64
    }

    pub fn wrong_share(&self) -> f64 {
        self.wrong as f64 / self.made.max(1) as f64
    }

    pub fn missed_share(&self) -> f64 {
        self.missed as f64 / self.expected.max(1) as f64
    }
}

/// A filter's terms and order, as a set of their syntax.
fn terms_of(f: &Filter) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = f.terms.iter().map(|t| t.id()).collect();
    if f.sort.is_some() {
        let sort_only = Filter {
            terms: Vec::new(),
            ..f.clone()
        };
        out.insert(sort_only.to_string());
    }
    out
}

fn words(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn run(set: &Set) -> Report {
    let vocab = set.vocabulary();
    let now = set.now_ms();
    let mut r = Report::default();
    for case in &set.queries {
        let parsed = parse(&case.query, &vocab, now, 0);
        let (want, rest) = Filter::parse_syntax(&case.filter, 0);
        assert!(rest.is_empty(), "{:?} is all terms", case.filter);
        let (got, want) = (terms_of(&parsed.filter), terms_of(&want));
        r.queries += 1;
        r.made += got.len();
        r.expected += want.len();
        r.wrong += got.difference(&want).count();
        r.missed += want.difference(&got).count();
        let text_right = words(&parsed.text).to_lowercase() == words(&case.text).to_lowercase();
        if got == want && text_right {
            r.exact += 1;
        } else {
            let show = |t: &BTreeSet<String>, text: &str| {
                let terms: Vec<&str> = t.iter().map(String::as_str).collect();
                format!("[{}] {text:?}", terms.join(" "))
            };
            r.misses.push((
                case.query.clone(),
                show(&got, &parsed.text),
                show(&want, &case.text),
            ));
        }
    }
    r
}

pub fn print(r: &Report) {
    for (q, got, want) in &r.misses {
        println!("{q:?}\n    got  {got}\n    want {want}");
    }
    println!(
        "{} queries: {:.1}% exact; wrong terms {:.1}% of {} made; missed {:.1}% of {} expected",
        r.queries,
        100.0 * r.exact_share(),
        100.0 * r.wrong_share(),
        r.made,
        100.0 * r.missed_share(),
        r.expected
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned set reads as written: no wrong terms, and nearly every
    /// query exact. The set was written beside the rules, so this guards
    /// what they do; it does not measure phrasings nobody planned.
    #[test]
    fn the_pinned_set_reads_as_written() {
        let r = run(&pinned());
        print(&r);
        assert!(r.queries >= 150);
        assert!(r.wrong_share() <= 0.01, "wrong {:.3}", r.wrong_share());
        assert!(r.exact_share() >= 0.95, "exact {:.3}", r.exact_share());
    }
}
