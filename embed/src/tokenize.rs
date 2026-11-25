//! Tokenizers, compact: the two kinds the search models use, read from
//! `tokenizer.bin` (written by `convert` from the model's
//! `tokenizer.json`). They give exactly the ids Hugging Face's
//! `tokenizers` gives (the tests compare them), in a few MB, where
//! `tokenizers` holds hundreds for a 250k-piece vocabulary.
//!
//! - **Unigram** (SentencePiece; XLM-R, multilingual-e5): the precompiled
//!   normalization map, runs of spaces made one, "▁" for each space and
//!   before the text, words split before each "▁", then for each word the
//!   pieces with the best total score (unknown characters scored below
//!   any piece, and runs of them one unknown token). Then `<s>` and
//!   `</s>` around it.
//! - **WordPiece** (BERT; the multilingual CLIP text side): control
//!   characters dropped and spaces made " ", CJK ideographs spaced apart,
//!   words split at spaces and around punctuation, then each word as its
//!   longest pieces from the start ("##" before all but the first; a word
//!   that can't be made, or of more than `max_chars` characters, is one
//!   unknown token). Then `[CLS]` and `[SEP]` around it.
//!
//! `tokenizer.bin`: "r5tk", a format byte (1), a kind byte (1 Unigram,
//! 2 WordPiece), then little-endian fields:
//! - Unigram: unknown, start and end ids (u32); the normalization map (u32
//!   length, bytes); the pieces (u32 count; each a u16 length, its bytes,
//!   and its score as f64).
//! - WordPiece: unknown, start and end ids, the most characters in a word
//!   (u32); the pieces (u32 count; each a u16 length and its bytes).

use spm_precompiled::Precompiled;
use unicode_categories::UnicodeCategories;
use unicode_segmentation::UnicodeSegmentation;

use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"r5tk";
const FORMAT: u8 = 1;
const UNIGRAM: u8 = 1;
const WORDPIECE: u8 = 2;
/// How far below the lowest piece an unknown character scores
/// (SentencePiece's kUnkPenalty).
const UNK_PENALTY: f64 = 10.0;
const SPACE: char = '▁';

/// Every piece's bytes in one buffer, and the ids sorted by bytes, to find
/// a piece by binary search.
struct Pieces {
    bytes: Vec<u8>,
    /// Where piece `i` starts; `starts[i + 1]` where it ends.
    starts: Vec<u32>,
    /// Ids by bytes, then by id: of equal pieces, the last id counts, as
    /// `tokenizers` keeps the last.
    sorted: Vec<u32>,
}

impl Pieces {
    fn new(pieces: Vec<&[u8]>) -> Self {
        let mut bytes = Vec::with_capacity(pieces.iter().map(|p| p.len()).sum());
        let mut starts = Vec::with_capacity(pieces.len() + 1);
        for p in &pieces {
            starts.push(bytes.len() as u32);
            bytes.extend_from_slice(p);
        }
        starts.push(bytes.len() as u32);
        let mut sorted: Vec<u32> = (0..pieces.len() as u32).collect();
        let at = |i: u32| &bytes[starts[i as usize] as usize..starts[i as usize + 1] as usize];
        sorted.sort_by(|&a, &b| at(a).cmp(at(b)).then(a.cmp(&b)));
        Self {
            bytes,
            starts,
            sorted,
        }
    }

    fn get(&self, id: u32) -> &[u8] {
        &self.bytes[self.starts[id as usize] as usize..self.starts[id as usize + 1] as usize]
    }

    /// The id of piece `s` (the last, of equal ones).
    fn find(&self, s: &[u8]) -> Option<u32> {
        let end = self.sorted.partition_point(|&i| self.get(i) <= s);
        let id = *self.sorted.get(end.checked_sub(1)?)?;
        (self.get(id) == s).then_some(id)
    }

    fn len(&self) -> usize {
        self.starts.len() - 1
    }
}

enum Kind {
    Unigram {
        map: Option<Precompiled>,
        scores: Vec<f64>,
        min_score: f64,
    },
    WordPiece {
        max_chars: usize,
    },
}

pub struct Tokenizer {
    kind: Kind,
    pieces: Pieces,
    unk: u32,
    start: u32,
    end: u32,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::from("a tokenizer file cut short"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

impl Tokenizer {
    /// Reads `tokenizer.bin`.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(4)? != MAGIC || r.u8()? != FORMAT {
            return Err(Error::from("not a tokenizer file"));
        }
        let kind = r.u8()?;
        let (unk, start, end) = (r.u32()?, r.u32()?, r.u32()?);
        match kind {
            UNIGRAM => {
                let n = r.u32()? as usize;
                let map_bytes = r.take(n)?;
                let map = if map_bytes.is_empty() {
                    None
                } else {
                    Some(
                        Precompiled::from(map_bytes)
                            .map_err(|e| Error(format!("a tokenizer's normalization map: {e}")))?,
                    )
                };
                let count = r.u32()? as usize;
                let mut pieces = Vec::with_capacity(count);
                let mut scores = Vec::with_capacity(count);
                for _ in 0..count {
                    let len = r.u16()? as usize;
                    pieces.push(r.take(len)?);
                    scores.push(r.f64()?);
                }
                let min_score = scores.iter().copied().fold(f64::INFINITY, f64::min);
                Ok(Self {
                    pieces: Pieces::new(pieces),
                    kind: Kind::Unigram {
                        map,
                        scores,
                        min_score,
                    },
                    unk,
                    start,
                    end,
                })
            }
            WORDPIECE => {
                let max_chars = r.u32()? as usize;
                let count = r.u32()? as usize;
                let mut pieces = Vec::with_capacity(count);
                for _ in 0..count {
                    let len = r.u16()? as usize;
                    pieces.push(r.take(len)?);
                }
                Ok(Self {
                    pieces: Pieces::new(pieces),
                    kind: Kind::WordPiece { max_chars },
                    unk,
                    start,
                    end,
                })
            }
            _ => Err(Error::from("a tokenizer of an unknown kind")),
        }
    }

    /// How many pieces it has.
    pub fn vocab(&self) -> usize {
        self.pieces.len()
    }

    /// The ids of `text`, between the start and end ids, at most `most`
    /// in all (the first ones of the text are kept).
    pub fn encode(&self, text: &str, most: usize) -> Vec<u32> {
        let mut ids = vec![self.start];
        match &self.kind {
            Kind::Unigram {
                map,
                scores,
                min_score,
            } => {
                let cleaned = collapse_spaces(&precompiled(map.as_ref(), text));
                // An empty text has no words, not even "▁".
                let normalized = if cleaned.is_empty() {
                    cleaned
                } else {
                    metaspace(&cleaned)
                };
                for word in split_before_space(&normalized) {
                    self.unigram(word, scores, *min_score, &mut ids);
                }
            }
            Kind::WordPiece { max_chars } => {
                for word in bert_words(&bert_normalize(text)) {
                    self.wordpiece(word, *max_chars, &mut ids);
                }
            }
        }
        ids.truncate(most.max(2) - 1);
        ids.push(self.end);
        ids
    }

    /// The best-scoring pieces of `word`, as `tokenizers`' Unigram
    /// (`encode_optimized`) finds them: shorter pieces first, and of equal
    /// scores the first found.
    fn unigram(&self, word: &str, scores: &[f64], min_score: f64, ids: &mut Vec<u32>) {
        #[derive(Clone, Copy)]
        struct Best {
            id: u32,
            score: f64,
            from: Option<usize>,
        }
        let n = word.len();
        let unk_score = min_score - UNK_PENALTY;
        let mut best = vec![
            Best {
                id: 0,
                score: 0.0,
                from: None
            };
            n + 1
        ];
        let bounds: Vec<usize> = word
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(n))
            .collect();
        for (k, &at) in bounds.iter().enumerate().take(bounds.len() - 1) {
            let here = best[at].score;
            let char_end = bounds[k + 1];
            let mut single = false;
            for &end in &bounds[k + 1..] {
                let Some(id) = self.pieces.find(&word.as_bytes()[at..end]) else {
                    continue;
                };
                let score = scores[id as usize] + here;
                let node = &mut best[end];
                if node.from.is_none() || score > node.score {
                    *node = Best {
                        id,
                        score,
                        from: Some(at),
                    };
                }
                if end == char_end {
                    single = true;
                }
            }
            if !single {
                let score = unk_score + here;
                let node = &mut best[char_end];
                if node.from.is_none() || score > node.score {
                    *node = Best {
                        id: self.unk,
                        score,
                        from: Some(at),
                    };
                }
            }
        }
        let mut path = Vec::new();
        let mut end = n;
        while end > 0 {
            let node = best[end];
            // Runs of unknown characters are one unknown token.
            if !(node.id == self.unk && path.last() == Some(&self.unk)) {
                path.push(node.id);
            }
            end = node.from.unwrap_or(0);
        }
        ids.extend(path.into_iter().rev());
    }

    fn wordpiece(&self, word: &str, max_chars: usize, ids: &mut Vec<u32>) {
        if word.chars().count() > max_chars {
            ids.push(self.unk);
            return;
        }
        let mut out = Vec::new();
        let mut start = 0;
        let mut key = Vec::new();
        while start < word.len() {
            let mut end = word.len();
            let mut found = None;
            while start < end {
                key.clear();
                if start > 0 {
                    key.extend_from_slice(b"##");
                }
                key.extend_from_slice(&word.as_bytes()[start..end]);
                if let Some(id) = self.pieces.find(&key) {
                    found = Some(id);
                    break;
                }
                end -= word[start..end].chars().last().map_or(1, char::len_utf8);
            }
            match found {
                Some(id) => {
                    out.push(id);
                    start = end;
                }
                None => {
                    ids.push(self.unk);
                    return;
                }
            }
        }
        ids.extend(out);
    }
}

/// The normalization map applied to each grapheme of fewer than 6 bytes
/// as a whole, else to each of its characters, as `tokenizers` does.
fn precompiled(map: Option<&Precompiled>, text: &str) -> String {
    let Some(map) = map else {
        return text.to_string();
    };
    let mut out = String::with_capacity(text.len());
    for g in text.graphemes(true) {
        if g.len() < 6
            && let Some(norm) = map.transform(g)
        {
            out.push_str(norm);
            continue;
        }
        for (i, c) in g.char_indices() {
            let part = &g[i..i + c.len_utf8()];
            match map.transform(part) {
                Some(norm) => out.push_str(norm),
                None => out.push(c),
            }
        }
    }
    out
}

/// Runs of two or more spaces as one.
fn collapse_spaces(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut spaces = 0;
    for c in text.chars() {
        if c == ' ' {
            spaces += 1;
            continue;
        }
        if spaces > 0 {
            out.push(' ');
            spaces = 0;
        }
        out.push(c);
    }
    if spaces > 0 {
        out.push(' ');
    }
    out
}

/// Spaces as "▁", and one before the text unless it starts with one.
fn metaspace(text: &str) -> String {
    let replaced = text.replace(' ', "▁");
    if replaced.starts_with(SPACE) {
        replaced
    } else {
        format!("{SPACE}{replaced}")
    }
}

/// `text` cut before each "▁" (each word keeps its "▁").
fn split_before_space(text: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut from = 0;
    for (i, c) in text.char_indices() {
        if c == SPACE && i > from {
            words.push(&text[from..i]);
            from = i;
        }
    }
    if from < text.len() {
        words.push(&text[from..]);
    }
    words
}

fn bert_whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || c.is_whitespace()
}

fn bert_control(c: char) -> bool {
    !matches!(c, '\t' | '\n' | '\r') && c.is_other()
}

fn cjk(c: char) -> bool {
    matches!(c as u32,
        0x4E00..=0x9FFF
        | 0x3400..=0x4DBF
        | 0x20000..=0x2A6DF
        | 0x2A700..=0x2B73F
        | 0x2B740..=0x2B81F
        | 0x2B920..=0x2CEAF
        | 0xF900..=0xFAFF
        | 0x2F800..=0x2FA1F)
}

/// BERT's cleaning: no NULs, replacement or control characters, every
/// space " ", and spaces around CJK ideographs.
fn bert_normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\0' || c == '\u{fffd}' || bert_control(c) {
            continue;
        }
        if bert_whitespace(c) {
            out.push(' ');
        } else if cjk(c) {
            out.push(' ');
            out.push(c);
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn bert_punctuation(c: char) -> bool {
    c.is_ascii_punctuation() || c.is_punctuation()
}

/// Words split at spaces (dropped) and around punctuation (each mark a
/// word of its own).
fn bert_words(text: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut from = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() || bert_punctuation(c) {
            if let Some(f) = from.take() {
                words.push(&text[f..i]);
            }
            if bert_punctuation(c) {
                words.push(&text[i..i + c.len_utf8()]);
            }
        } else if from.is_none() {
            from = Some(i);
        }
    }
    if let Some(f) = from {
        words.push(&text[f..]);
    }
    words
}

/// Writes `tokenizer.bin` for a Unigram tokenizer.
pub fn write_unigram(
    unk: u32,
    start: u32,
    end: u32,
    map: &[u8],
    pieces: &[(String, f64)],
) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend([FORMAT, UNIGRAM]);
    for n in [unk, start, end, map.len() as u32] {
        out.extend(n.to_le_bytes());
    }
    out.extend_from_slice(map);
    out.extend((pieces.len() as u32).to_le_bytes());
    for (p, score) in pieces {
        out.extend((p.len() as u16).to_le_bytes());
        out.extend_from_slice(p.as_bytes());
        out.extend(score.to_le_bytes());
    }
    out
}

/// Writes `tokenizer.bin` for a WordPiece tokenizer: `pieces` by id.
pub fn write_wordpiece(
    unk: u32,
    start: u32,
    end: u32,
    max_chars: u32,
    pieces: &[String],
) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend([FORMAT, WORDPIECE]);
    for n in [unk, start, end, max_chars, pieces.len() as u32] {
        out.extend(n.to_le_bytes());
    }
    for p in pieces {
        out.extend((p.len() as u16).to_le_bytes());
        out.extend_from_slice(p.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unigram(pieces: &[(&str, f64)]) -> Tokenizer {
        let mut all = vec![
            ("<s>".to_string(), 0.0),
            ("<pad>".into(), 0.0),
            ("</s>".into(), 0.0),
            ("<unk>".into(), 0.0),
        ];
        all.extend(pieces.iter().map(|(p, s)| (p.to_string(), *s)));
        Tokenizer::read(&write_unigram(3, 0, 2, &[], &all)).unwrap()
    }

    #[test]
    fn unigram_takes_the_best_scoring_pieces() {
        // "▁hello" whole scores -3; "▁he" + "llo" -1 + -1.5 = -2.5 wins.
        let t = unigram(&[
            ("▁hello", -3.0),
            ("▁he", -1.0),
            ("llo", -1.5),
            ("▁", -4.0),
            ("w", -2.0),
            ("o", -2.0),
            ("r", -2.0),
            ("l", -2.0),
            ("d", -2.0),
        ]);
        assert_eq!(t.encode("hello", 100), [0, 5, 6, 2]);
        // Spaces as "▁", one before each word.
        assert_eq!(
            t.encode("hello  world", 100),
            [0, 5, 6, 7, 8, 9, 10, 11, 12, 2]
        );
        // Unknown characters, one after another, as one unknown token.
        assert_eq!(t.encode("hello ¿¿", 100), [0, 5, 6, 7, 3, 2]);
        assert_eq!(t.encode("", 100), [0, 2]);
        assert_eq!(t.encode("hello world", 4), [0, 5, 6, 2]);
    }

    #[test]
    fn wordpiece_takes_the_longest_pieces_from_the_start() {
        let pieces: Vec<String> = [
            "[PAD]", "[UNK]", "[CLS]", "[SEP]", "un", "##aff", "##able", "aff", ",", "中",
        ]
        .map(String::from)
        .to_vec();
        let t = Tokenizer::read(&write_wordpiece(1, 2, 3, 10, &pieces)).unwrap();
        assert_eq!(t.encode("unaffable", 100), [2, 4, 5, 6, 3]);
        // Punctuation apart, CJK apart, a word with no pieces unknown.
        assert_eq!(t.encode("aff,中xyz", 100), [2, 7, 8, 9, 1, 3]);
        // Too long a word is unknown.
        assert_eq!(t.encode("unaffableunaffable", 100), [2, 1, 3]);
        assert!(Tokenizer::read(b"nope").is_err());
    }
}
