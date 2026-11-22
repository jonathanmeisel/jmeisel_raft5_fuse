//! Words for keyword search, and the chunks a file's text is cut into.
//!
//! - `terms` splits text into words by the Unicode rules (UAX #29) and
//!   lowercases them. Han, Hiragana and Katakana text has no spaces, so a
//!   run of those letters becomes pairs of letters ("bigrams") instead:
//!   a query then matches inside a run without a dictionary.
//! - `chunks` cuts text into pieces of about `CHUNK_WORDS` words that
//!   overlap a little, so a phrase across a cut is still in one piece.

use std::collections::BTreeMap;

use unicode_segmentation::UnicodeSegmentation;

use crate::record::Chunk;

/// Words in a chunk, and how many of them the next chunk repeats.
pub const CHUNK_WORDS: usize = 250;
pub const CHUNK_OVERLAP: usize = 40;
/// The most chunks one file gets. A longer file is indexed up to there.
pub const MAX_CHUNKS: usize = 2000;
/// The length of a chunk's preview, in characters.
pub const PREVIEW_CHARS: usize = 160;
/// Longer words are not kept: they are hashes, base64 and the like.
const MAX_TERM_CHARS: usize = 64;

fn is_cjk(c: char) -> bool {
    matches!(c as u32,
        0x3040..=0x30FF      // Hiragana, Katakana
        | 0x3400..=0x4DBF    // Han extension A
        | 0x4E00..=0x9FFF    // Han
        | 0xF900..=0xFAFF    // Han compatibility
        | 0x20000..=0x2FFFF) // Han extensions B and on
}

/// The search terms of `text`, in order, with repeats.
pub fn terms(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // A run of CJK letters, which UAX #29 gives as many short words.
    let mut run: Vec<char> = Vec::new();
    let mut run_end = 0;
    let flush = |run: &mut Vec<char>, out: &mut Vec<String>| {
        match run.len() {
            0 => {}
            1 => out.push(run[0].to_string()),
            _ => out.extend(run.windows(2).map(|w| w.iter().collect())),
        }
        run.clear();
    };
    for (start, word) in text.unicode_word_indices() {
        if word.chars().all(is_cjk) {
            if !run.is_empty() && start != run_end {
                flush(&mut run, &mut out);
            }
            run.extend(word.chars());
            run_end = start + word.len();
            continue;
        }
        flush(&mut run, &mut out);
        if word.chars().count() <= MAX_TERM_CHARS {
            out.push(word.to_lowercase());
        }
    }
    flush(&mut run, &mut out);
    out
}

/// `terms`, counted and sorted, as a chunk keeps them.
pub fn counted(terms: &[String]) -> Vec<(String, u16)> {
    let mut counts: BTreeMap<&str, u16> = BTreeMap::new();
    for t in terms {
        let n = counts.entry(t).or_default();
        *n = n.saturating_add(1);
    }
    counts
        .into_iter()
        .map(|(t, n)| (t.to_string(), n))
        .collect()
}

/// The first `PREVIEW_CHARS` characters of `text`, with runs of white space
/// made one space.
pub fn preview(text: &str) -> String {
    let mut out = String::new();
    for (i, word) in text.split_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(word);
        if out.chars().count() >= PREVIEW_CHARS {
            break;
        }
    }
    out.chars().take(PREVIEW_CHARS).collect()
}

/// The chunks of `text`, with previews and word counts but no vectors.
/// Text with no words gives no chunks.
pub fn chunks(text: &str) -> Vec<Chunk> {
    // Cut on white space, so a preview shows the text as written. Text with
    // no spaces (CJK) is cut by characters, the same number per chunk.
    let words: Vec<&str> = text.split_whitespace().collect();
    let pieces: Vec<String> = if words.len() * 4 < text.chars().count() / 20 {
        let chars: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
        windows(chars.len(), CHUNK_WORDS * 2, CHUNK_OVERLAP * 2)
            .map(|(a, b)| chars[a..b].iter().collect())
            .collect()
    } else {
        windows(words.len(), CHUNK_WORDS, CHUNK_OVERLAP)
            .map(|(a, b)| words[a..b].join(" "))
            .collect()
    };
    pieces
        .into_iter()
        .take(MAX_CHUNKS)
        .filter_map(|piece| {
            let t = terms(&piece);
            (!t.is_empty()).then(|| Chunk {
                preview: preview(&piece),
                len: t.len() as u32,
                terms: counted(&t),
                vector: None,
            })
        })
        .collect()
}

/// Ranges of `size` over `0..len`, each starting `size - overlap` after the
/// one before; the last ends at `len`.
fn windows(len: usize, size: usize, overlap: usize) -> impl Iterator<Item = (usize, usize)> {
    let step = size - overlap;
    (0..)
        .map(move |i| i * step)
        .take_while(move |&a| a < len && (a == 0 || a + overlap < len))
        .map(move |a| (a, (a + size).min(len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_lowercased_and_split_by_unicode_rules() {
        assert_eq!(
            terms("Bike-route in VERMONT, 2024! Café"),
            ["bike", "route", "in", "vermont", "2024", "café"]
        );
        assert!(terms(&"x".repeat(65)).is_empty(), "a long word is dropped");
    }

    #[test]
    fn cjk_runs_become_bigrams() {
        assert_eq!(terms("東京都"), ["東京", "京都"]);
        assert_eq!(terms("東 京"), ["東", "京"], "a space ends a run");
        assert_eq!(terms("行く Tokyo"), ["行く", "tokyo"]);
    }

    #[test]
    fn chunks_overlap_and_cover_the_text() {
        let text: Vec<String> = (0..600).map(|i| format!("w{i}")).collect();
        let chunks = chunks(&text.join(" "));
        assert_eq!(chunks.len(), 3);
        assert!(chunks[0].preview.starts_with("w0 w1"));
        // The second chunk starts CHUNK_WORDS - CHUNK_OVERLAP words in.
        assert!(chunks[1].preview.starts_with("w210 "));
        let last = &chunks[2];
        assert!(last.terms.iter().any(|(t, _)| t == "w599"));
        assert_eq!(chunks[0].len, 250);
    }

    #[test]
    fn short_and_empty_text() {
        assert_eq!(chunks("one two").len(), 1);
        assert!(chunks("  \n ").is_empty());
        assert!(chunks("— … ·").is_empty(), "no words");
    }

    #[test]
    fn previews_are_short_and_tidy() {
        assert_eq!(preview("a\n\n  b\tc"), "a b c");
        assert_eq!(preview(&"word ".repeat(100)).chars().count(), PREVIEW_CHARS);
    }

    #[test]
    fn text_with_no_spaces_is_cut_by_characters() {
        let text = "東京".repeat(400);
        let chunks = chunks(&text);
        assert!(chunks.len() >= 2);
    }

    #[test]
    fn counts_are_sorted() {
        let t = terms("b a b");
        assert_eq!(counted(&t), [("a".to_string(), 1), ("b".to_string(), 2)]);
    }
}
