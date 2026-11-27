//! Plain English queries into filters: "photos from guatemala last
//! summer" is `type:photo place:GT taken:2025-06..2025-08`, with the text
//! left over to search ("pictures of volcanoes" searches "volcanoes").
//!
//! - Words are matched by rules and word lists (`lexicon`), and dates by
//!   a small grammar (`dates`). Places, people, cameras and volumes match
//!   only what the searched indexes hold (`Vocabulary`), so a name that is
//!   also a common word ("nice", "turkey") filters only where the files
//!   have it.
//! - **When unsure, a word stays text:** a missed filter costs little,
//!   since the index has place and date words too, but a wrong one hides
//!   files.
//! - Terms in the filter syntax (`type:pdf`) are taken as written.
//!
//! Steps:
//! 1. Split off any terms in the syntax.
//! 2. Fold the other words (lower case, no accents).
//! 3. From each word, try the rules, longest match first: dates, types,
//!    sizes and lengths, places, people, cameras, volumes and folders.
//!    A cue word before a match ("from", "in", "by") is taken with it,
//!    and so is "not" or "without", which makes the term exclude.
//! 4. Drop filler words; the rest is the text.

pub mod dates;
pub mod lexicon;

use std::collections::{HashMap, HashSet};

use crate::filter::{Clause, Dates, Filter, Measure, Range, Sort, Term, fold};
use crate::geo::Place;
use crate::record::Meta;
use dates::Today;
use lexicon::{ENGLISH, Lexicon};

/// A place name a query may use: the clause it gives, and the name to
/// show.
#[derive(Debug, Clone, PartialEq)]
struct PlaceName {
    /// A country code, or the name.
    value: String,
    shown: String,
    /// The country the place is in.
    country: Option<String>,
}

/// The names a query may filter by: what the searched indexes hold.
#[derive(Debug, Clone, Default)]
pub struct Vocabulary {
    /// Place names, folded.
    places: HashMap<String, PlaceName>,
    /// Account names, folded, with the name as written.
    people: HashMap<String, String>,
    /// Words of camera names, folded.
    cameras: HashSet<String>,
    /// Volume labels, folded (the whole label and its last part), with the
    /// label as written.
    volumes: HashMap<String, String>,
}

impl Vocabulary {
    /// Adds the names in a file's facts.
    pub fn add_meta(&mut self, meta: &Meta) {
        for p in &meta.places {
            self.add_place(p);
        }
        for who in [&meta.added_by, &meta.changed_by] {
            if !who.is_empty() {
                self.people.insert(fold(who), who.clone());
            }
        }
        if !meta.camera.is_empty() {
            for w in fold(&meta.camera).split_whitespace() {
                if w.len() >= 3 || w.chars().any(|c| c.is_ascii_digit()) {
                    self.cameras.insert(w.to_string());
                }
            }
        }
    }

    fn add_place(&mut self, p: &Place) {
        for name in [&p.town, &p.region, &p.region_local].into_iter().flatten() {
            self.add_place_name(
                fold(name),
                PlaceName {
                    value: name.clone(),
                    shown: name.clone(),
                    country: p.code.clone(),
                },
            );
        }
        if let (Some(code), Some(country)) = (&p.code, &p.country) {
            let name = PlaceName {
                value: code.clone(),
                shown: country.clone(),
                country: Some(code.clone()),
            };
            self.add_place_name(fold(country), name.clone());
            for alias in lexicon::country_aliases(code) {
                self.add_place_name(alias.to_string(), name.clone());
            }
        }
    }

    /// Adds a name. A name that two places have: a country's code if one
    /// is a country and the other is in it ("Guatemala"); else the name,
    /// which matches both ("Georgia", "Paris").
    fn add_place_name(&mut self, key: String, new: PlaceName) {
        let is_code = |n: &PlaceName| n.value == n.country.clone().unwrap_or_default();
        match self.places.get_mut(&key) {
            None => {
                self.places.insert(key, new);
            }
            Some(old) if old.value == new.value => {}
            Some(old) if is_code(old) && new.country == old.country => {}
            Some(old) if is_code(&new) && old.country == new.country => *old = new,
            Some(old) => {
                old.value = new.shown.clone();
                old.shown = new.shown;
                old.country = None;
            }
        }
    }

    /// Adds a volume by the label the app shows it under: "Family", or
    /// "CS101/alice" in group "CS101", which names its group too.
    pub fn add_volume(&mut self, label: &str) {
        self.volumes.insert(fold(label), label.to_string());
        if let Some((group, _)) = label.split_once('/') {
            self.volumes
                .entry(fold(group))
                .or_insert_with(|| group.to_string());
        }
    }

    /// Whether `w` is a word of a camera's name, or the start of one
    /// ("fuji" for "FUJIFILM").
    fn camera_word(&self, w: &str) -> bool {
        self.cameras.contains(w) || (w.len() >= 3 && self.cameras.iter().any(|c| c.starts_with(w)))
    }

    pub fn add_person(&mut self, name: &str) {
        self.people.insert(fold(name), name.to_string());
    }

    /// Adds everything in `other`.
    pub fn extend(&mut self, other: &Vocabulary) {
        self.places.extend(other.places.clone());
        self.people.extend(other.people.clone());
        self.cameras.extend(other.cameras.iter().cloned());
        self.volumes.extend(other.volumes.clone());
    }
}

/// What a query asks for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parsed {
    pub filter: Filter,
    /// The words left to search.
    pub text: String,
    /// Text words that no rule took and that aren't filler: what e5 may
    /// suggest a type for.
    pub unknown: Vec<String>,
}

/// One word of the query.
#[derive(Debug)]
struct Word {
    /// As typed.
    raw: String,
    /// Folded, without the punctuation around it.
    norm: String,
    used: bool,
}

/// What the rules found starting at one word: terms, or an order, and
/// how many words that took.
struct Found {
    terms: Vec<Term>,
    sort: Option<Sort>,
    len: usize,
}

impl Found {
    fn terms(terms: Vec<Term>, len: usize) -> Self {
        Self {
            terms,
            sort: None,
            len,
        }
    }
}

/// Reads `query` as of `now_ms`, in a time zone `offset_ms` from UTC.
pub fn parse(query: &str, vocab: &Vocabulary, now_ms: u64, offset_ms: i64) -> Parsed {
    parse_with(query, vocab, &ENGLISH, now_ms, offset_ms)
}

pub fn parse_with(
    query: &str,
    vocab: &Vocabulary,
    lex: &Lexicon,
    now_ms: u64,
    offset_ms: i64,
) -> Parsed {
    let (mut filter, rest) = Filter::parse_syntax(query, offset_ms);
    let today = Today::of(now_ms, offset_ms);
    let mut words: Vec<Word> = rest
        .split_whitespace()
        .map(|raw| Word {
            raw: raw.to_string(),
            norm: normal(raw),
            used: false,
        })
        .filter(|w| !w.norm.is_empty())
        .collect();
    // Which date the query means: when taken, unless it says added or
    // changed.
    let date_kind = date_kind(&words, lex);
    let syntax_terms = filter.terms.len();
    let mut i = 0;
    while i < words.len() {
        let norms: Vec<&str> = words[i..].iter().map(|w| w.norm.as_str()).collect();
        let prev = i.checked_sub(1).map(|p| words[p].norm.as_str());
        let Some(found) = rule(&norms, prev, i == 0, vocab, lex, today, date_kind) else {
            i += 1;
            continue;
        };
        // "not" or "without" just before: the terms exclude.
        let not =
            i > 0 && !words[i - 1].used && lex.negations.contains(&words[i - 1].norm.as_str());
        if not && !found.terms.is_empty() {
            words[i - 1].used = true;
        }
        for mut t in found.terms {
            t.not = not;
            filter.add(t);
        }
        if let Some(s) = found.sort {
            filter.sort = Some(s);
        }
        for w in &mut words[i..i + found.len] {
            w.used = true;
        }
        i += found.len.max(1);
    }
    // No rule matched: the text is as typed.
    if filter.terms.len() == syntax_terms && filter.sort.is_none() {
        let unknown = words
            .iter()
            .filter(|w| {
                !lex.stop.contains(&w.norm.as_str()) && !lex.filler.contains(&w.norm.as_str())
            })
            .map(|w| w.norm.clone())
            .collect();
        return Parsed {
            filter,
            text: rest,
            unknown,
        };
    }
    // The verbs that chose the date kind or a person are filler once
    // they did.
    let mut text = Vec::new();
    let mut unknown = Vec::new();
    for (n, w) in words.iter().enumerate() {
        if w.used {
            continue;
        }
        let joins = lex.joiners.contains(&w.norm.as_str())
            && n > 0
            && words[n - 1].used
            && words.get(n + 1).is_some_and(|x| x.used);
        let verb = lex.date_verbs(&w.norm).is_some() && !filter.terms.is_empty();
        if lex.filler.contains(&w.norm.as_str()) || joins || verb {
            continue;
        }
        text.push(w.raw.clone());
        if !lex.stop.contains(&w.norm.as_str()) {
            unknown.push(w.norm.clone());
        }
    }
    Parsed {
        filter,
        text: text.join(" "),
        unknown,
    }
}

/// How a word is matched: folded, with quotes, commas and full stops
/// around it gone.
fn normal(raw: &str) -> String {
    let f = fold(raw);
    let f =
        f.trim_matches(|c: char| matches!(c, '"' | ',' | '.' | '!' | '?' | ';' | ':' | '(' | ')'));
    let f = f.replace(['’', '‘'], "'");
    // "1,000" is a number.
    if f.chars().any(|c| c.is_ascii_digit()) && f.contains(',') {
        return f.replace(',', "");
    }
    f
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DateKind {
    Taken,
    Added,
    Modified,
}

fn date_kind(words: &[Word], lex: &Lexicon) -> DateKind {
    words
        .iter()
        .find_map(|w| lex.date_verbs(&w.norm))
        .unwrap_or(DateKind::Taken)
}

fn term(clause: Clause, shown: Option<String>) -> Term {
    Term {
        clause,
        not: false,
        shown,
    }
}

/// The rules, from the first of `w`: what they find, if anything.
fn rule(
    w: &[&str],
    prev: Option<&str>,
    first: bool,
    vocab: &Vocabulary,
    lex: &Lexicon,
    today: Today,
    kind: DateKind,
) -> Option<Found> {
    let w0 = *w.first()?;
    let w1 = w.get(1).copied();

    // Sort words take no term.
    for (words, sort) in lex.sorts {
        if w.starts_with(words) {
            return Some(Found {
                terms: Vec::new(),
                sort: Some(*sort),
                len: words.len(),
            });
        }
    }

    // Dates, with any date word before them.
    if let Some((d, n)) = dates::read(w, today) {
        let unit_follows = w.get(n).is_some_and(|u| lex.is_unit(u));
        let year_alone = n == 1 && w0.len() == 4 && w0.chars().all(|c| c.is_ascii_digit());
        if !(unit_follows && year_alone) {
            let said = w[..n]
                .iter()
                .skip_while(|x| matches!(**x, "in" | "from" | "during" | "on" | "of" | "the"))
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            return Some(Found::terms(vec![date_term(d, kind, &said)], n));
        }
    }

    // Types: "photos", "pdfs", "bike rides"; not after "of" or "with",
    // where they are what the files show or hold.
    let after_of = prev.is_some_and(|p| lex.content_cues.contains(&p)) && !first;
    // "photo album", "video game": a name, not a type.
    let names_a_thing =
        lex.modifiers.contains(&w0) && w1.is_some_and(|next| plain_word(next, &w[1..], lex, today));
    if !after_of && !names_a_thing {
        for (words, what) in lex.types {
            if w.starts_with(words) {
                let terms = match what {
                    lexicon::TypeWord::Type(t) => vec![term(Clause::Type(*t), None)],
                    lexicon::TypeWord::Activity(a) => vec![term(Clause::Activity(*a), None)],
                    lexicon::TypeWord::Selfie => vec![term(Clause::Selfie, None)],
                    lexicon::TypeWord::Shape(s) => vec![term(Clause::Shape(*s), None)],
                };
                return Some(Found::terms(terms, words.len()));
            }
        }
    }

    // Sizes, lengths, distances, climbs and pages: "over 50 km",
    // "longer than 10 minutes", "with 1000 m of climbing".
    if let Some(f) = measure(w, lex) {
        return Some(f);
    }

    // Cue words before a name: "from", "in", "by", "taken with".
    let cue = lex.cues.iter().find(|(c, _)| w.starts_with(c));
    let (cue_len, cue_kind) = cue.map_or((0, None), |(c, k)| (c.len(), Some(*k)));
    let rest = &w[cue_len..];
    let rest = if rest.first() == Some(&"the") || rest.first() == Some(&"my") {
        &rest[1..]
    } else {
        rest
    };
    let skipped = w.len() - cue_len - rest.len();
    let took = |n: usize| cue_len + skipped + n;

    // Folders: "in my taxes folder", "in the folder taxes".
    if matches!(cue_kind, Some(lexicon::Cue::In)) {
        if let Some(end) = rest
            .iter()
            .take(4)
            .position(|x| *x == "folder" || *x == "directory")
            && end > 0
        {
            return Some(Found::terms(
                vec![term(Clause::In(rest[..end].join(" ")), None)],
                took(end + 1),
            ));
        }
        if rest.first().is_some_and(|x| *x == "folder") && rest.len() > 1 {
            return Some(Found::terms(
                vec![term(Clause::In(rest[1].to_string()), None)],
                took(2),
            ));
        }
        // Volumes, by their label.
        for n in (1..=rest.len().min(3)).rev() {
            let name = rest[..n].join(" ");
            if let Some(label) = vocab.volumes.get(&name) {
                return Some(Found::terms(
                    vec![term(Clause::Volume(label.clone()), None)],
                    took(n),
                ));
            }
        }
    }

    // People: "by alice", "from alice", "alice's", "alice added".
    if matches!(cue_kind, Some(lexicon::Cue::By | lexicon::Cue::From))
        && let Some(name) = rest.first()
        && let Some(who) = vocab.people.get(*name)
        && !(matches!(cue_kind, Some(lexicon::Cue::From)) && vocab.places.contains_key(*name))
    {
        return Some(Found::terms(
            vec![term(Clause::By(who.clone()), None)],
            took(1),
        ));
    }
    if let Some(name) = w0.strip_suffix("'s")
        && let Some(who) = vocab.people.get(name)
    {
        return Some(Found::terms(vec![term(Clause::By(who.clone()), None)], 1));
    }
    if cue.is_none()
        && let Some(who) = vocab.people.get(w0)
        && w1.is_some_and(|v| lex.added_verbs.contains(&v))
    {
        return Some(Found::terms(vec![term(Clause::By(who.clone()), None)], 2));
    }

    // Cameras: "taken with an iphone", "shot on my pixel 7".
    if matches!(cue_kind, Some(lexicon::Cue::With)) || cue.is_none() {
        let rest = if rest.first().is_some_and(|x| matches!(*x, "a" | "an")) {
            &rest[1..]
        } else {
            rest
        };
        let skipped = w.len() - cue_len - rest.len();
        let n = rest
            .iter()
            .take(3)
            .take_while(|x| vocab.camera_word(x))
            .count();
        let known_brand = rest.first().is_some_and(|x| lex.camera_brands.contains(x));
        if n > 0 && (cue.is_some() || known_brand) {
            return Some(Found::terms(
                vec![term(Clause::Camera(rest[..n].join(" ")), None)],
                cue_len + skipped + n,
            ));
        }
    }

    // Places: "from guatemala", "in new york", "near lisbon"; without a
    // cue, only a name the files have that isn't a common word.
    let place_cue = matches!(
        cue_kind,
        Some(lexicon::Cue::In | lexicon::Cue::From | lexicon::Cue::Near | lexicon::Cue::At)
    );
    if place_cue || cue.is_none() {
        for n in (1..=rest.len().min(4)).rev() {
            let name = rest[..n].join(" ");
            let Some(place) = vocab.places.get(&name) else {
                continue;
            };
            if cue.is_none() && (n == 1 && lex.common.contains(&name.as_str())) {
                continue;
            }
            let t = term(
                Clause::Place(place.value.clone()),
                Some(place.shown.clone()),
            );
            return Some(Found::terms(vec![t], took(n)));
        }
    }
    None
}

/// Whether `w` (the start of `rest`) is a plain word: not one that joins,
/// cues, sorts or filters.
fn plain_word(w: &str, rest: &[&str], lex: &Lexicon, today: Today) -> bool {
    let connector = lex.content_cues.contains(&w)
        || lex.joiners.contains(&w)
        || lex.negations.contains(&w)
        || lex.filler.contains(&w)
        || lex.cues.iter().any(|(c, _)| c[0] == w)
        || lex.sorts.iter().any(|(s, _)| s[0] == w)
        || lex.comparisons.iter().any(|(c, _)| c[0] == w);
    let typed = lex.types.iter().any(|(t, _)| rest.starts_with(t));
    !connector && !typed && dates::read(rest, today).is_none()
}

fn date_term(d: Dates, kind: DateKind, said: &str) -> Term {
    let (clause, verb) = match kind {
        DateKind::Taken => (Clause::Taken(d), "Taken"),
        DateKind::Added => (Clause::Added(d), "Added"),
        DateKind::Modified => (Clause::Modified(d), "Changed"),
    };
    let shown = (!said.is_empty()).then(|| format!("{verb} {said}"));
    term(clause, shown)
}

/// "over 50 km", "under 10 mb", "between 1 and 2 hours", "100 pages",
/// "with 1000 m of climbing".
fn measure(w: &[&str], lex: &Lexicon) -> Option<Found> {
    let with = usize::from(w.first() == Some(&"with"));
    let w = &w[with..];
    let mut found = measure_after_with(w, lex)?;
    found.len += with;
    Some(found)
}

fn measure_after_with(w: &[&str], lex: &Lexicon) -> Option<Found> {
    let (cmp_len, cmp) = lex
        .comparisons
        .iter()
        .find(|(c, _)| w.starts_with(c))
        .map_or((0, None), |(c, k)| (c.len(), Some(*k)));
    let rest = &w[cmp_len..];
    // "between 1 and 2 hours".
    if cmp == Some(lexicon::Compare::Between)
        && rest.len() >= 4
        && rest[1] == "and"
        && let Some((m, a, _)) = amount(rest[0], Some(rest[3]), lex)
        && let Some((_, b, _)) = amount(rest[2], Some(rest[3]), lex)
    {
        let (mut m, mut n) = (m, 4);
        if let Some(c) = climb_after(&rest[4..]) {
            m = Measure::Climb;
            n += c;
        }
        return Some(Found::terms(
            vec![term(
                Clause::Measure(
                    m,
                    Range {
                        from: Some(a),
                        to: Some(b),
                    },
                ),
                None,
            )],
            cmp_len + n,
        ));
    }
    let first = *rest.first()?;
    let (mut m, n, mut used) = amount(first, rest.get(1).copied(), lex)?;
    if let Some(c) = climb_after(&rest[used..]) {
        m = Measure::Climb;
        used += c;
    }
    // A bare number with a unit and no comparison: pages only ("100
    // pages"), or with "of climbing".
    let range = match cmp {
        Some(lexicon::Compare::Over) => Range {
            from: Some(n),
            to: None,
        },
        Some(lexicon::Compare::Under) => Range {
            from: None,
            to: Some(n),
        },
        Some(lexicon::Compare::Between) => return None,
        None if matches!(m, Measure::Pages | Measure::Climb) => Range {
            from: Some(n),
            to: None,
        },
        None => return None,
    };
    Some(Found::terms(
        vec![term(Clause::Measure(m, range), None)],
        cmp_len + used,
    ))
}

/// "of climbing", "climbing", "climb", "elevation gain" after a number:
/// how many words.
fn climb_after(w: &[&str]) -> Option<usize> {
    match w {
        ["of", "climbing" | "climb" | "elevation", ..] => Some(2),
        ["climbing" | "climb" | "elevation", "gain", ..] => Some(2),
        ["climbing" | "climb" | "elevation", ..] => Some(1),
        _ => None,
    }
}

/// A number and its unit, in one word ("50km") or two ("50 km"): the
/// measure, the amount in its base unit, and the words it took.
fn amount(word: &str, next: Option<&str>, lex: &Lexicon) -> Option<(Measure, u64, usize)> {
    let split = word
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(word.len());
    let (num, unit) = word.split_at(split);
    let num: f64 = num
        .parse()
        .ok()
        .filter(|n: &f64| n.is_finite() && *n > 0.0)?;
    let (unit, used) = if unit.is_empty() {
        (next?, 2)
    } else {
        (unit, 1)
    };
    let (m, scale) = lex.unit_of(unit)?;
    Some((m, (num * scale).round() as u64, used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::days_from_civil;

    pub(crate) fn place(town: &str, region: &str, country: &str, code: &str) -> Place {
        Place {
            town: Some(town.into()).filter(|t: &String| !t.is_empty()),
            region: Some(region.into()),
            region_local: None,
            country: Some(country.into()),
            code: Some(code.into()),
        }
    }

    /// What a family's volumes might hold.
    pub(crate) fn vocab() -> Vocabulary {
        let mut v = Vocabulary::default();
        let meta = Meta {
            places: vec![
                place("Lisbon", "Lisbon", "Portugal", "PT"),
                place("Antigua Guatemala", "Sacatepéquez", "Guatemala", "GT"),
                place("Burlington", "Vermont", "United States", "US"),
                place("New York City", "New York", "United States", "US"),
                place("Paris", "Île-de-France", "France", "FR"),
                place("Nice", "Provence-Alpes-Côte d'Azur", "France", "FR"),
            ],
            camera: "Apple iPhone 13".into(),
            added_by: "alice".into(),
            changed_by: "bo".into(),
            ..Meta::default()
        };
        v.add_meta(&meta);
        v.add_meta(&Meta {
            camera: "Canon EOS R6".into(),
            ..Meta::default()
        });
        v.add_volume("Family");
        v.add_volume("CS101/alice");
        v
    }

    /// Friday 27 November 2026, at noon UTC.
    const NOW: u64 = (days_from_civil(2026, 11, 27) as u64) * 86_400_000 + 12 * 3_600_000;

    fn parsed(q: &str) -> (String, String) {
        let p = parse(q, &vocab(), NOW, 0);
        (p.filter.to_string(), p.text)
    }

    #[test]
    fn types_places_and_dates() {
        assert_eq!(
            parsed("photos from guatemala"),
            ("type:photo place:GT".into(), "".into())
        );
        assert_eq!(
            parsed("pictures of volcanoes in guatemala last summer"),
            (
                "type:photo place:GT taken:2025-06..2025-08".into(),
                "of volcanoes".into()
            )
        );
        assert_eq!(parsed("paddle board"), ("".into(), "paddle board".into()));
        assert_eq!(
            parsed("photos of documents"),
            ("type:photo".into(), "of documents".into())
        );
        assert_eq!(
            parsed("rides in vermont"),
            ("activity:ride place:Vermont".into(), "".into())
        );
        assert_eq!(
            parsed("photos from the usa"),
            ("type:photo place:US".into(), "".into())
        );
    }

    #[test]
    fn people_cameras_volumes_and_measures() {
        assert_eq!(
            parsed("pdfs alice uploaded since march"),
            ("type:pdf by:alice added:2026-03..".into(), "".into())
        );
        assert_eq!(
            parsed("photos taken with an iphone"),
            ("type:photo camera:iphone".into(), "".into())
        );
        assert_eq!(
            parsed("rides over 50 km"),
            ("activity:ride distance:>50km".into(), "".into())
        );
        assert_eq!(
            parsed("videos longer than 10 minutes"),
            ("type:video length:>10min".into(), "".into())
        );
        assert_eq!(
            parsed("notes in family"),
            ("volume:Family".into(), "notes".into())
        );
        assert_eq!(
            parsed("receipts in my taxes folder"),
            ("in:taxes".into(), "receipts".into())
        );
        assert_eq!(
            parsed("documents not pdfs"),
            ("type:document -type:pdf".into(), "".into())
        );
        assert_eq!(
            parsed("newest photos"),
            ("type:photo sort:newest".into(), "".into())
        );
    }

    #[test]
    fn doubtful_words_stay_text() {
        assert_eq!(parsed("may be useful"), ("".into(), "may be useful".into()));
        assert_eq!(parsed("nice sunset"), ("".into(), "nice sunset".into()));
        assert_eq!(
            parsed("sunset in nice"),
            ("place:Nice".into(), "sunset".into())
        );
        assert_eq!(parsed("2000 km ride"), ("".into(), "2000 km ride".into()));
        assert_eq!(
            parsed("tax return 2023"),
            ("taken:2023".into(), "tax return".into())
        );
    }

    #[test]
    fn chips_say_what_was_typed() {
        let p = parse("photos from guatemala last summer", &vocab(), NOW, 0);
        let labels: Vec<String> = p.filter.terms.iter().map(Term::label).collect();
        assert_eq!(labels, ["Photos", "Guatemala", "Taken last summer"]);
    }
}
