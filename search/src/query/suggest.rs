//! Type suggestions: when a query names no type the rules know, its
//! words may still mean one ("footage" for videos, "excel" for
//! spreadsheets). The text model says how close each word is to each
//! type, and a close one is offered as a chip, never applied on its own.
//!
//! - Each type has a vector: the mean of a few phrases for it, embedded as
//!   queries (data/type_vectors.bin, made by raft5fs-eval's
//!   `build_type_vectors` example for the pinned text model).
//! - e5 vectors share a large common part, so every vector is first
//!   centred: less the mean of everyday words, then made unit length
//!   again. Without that, every word is about 0.9 close to every type.
//! - A word suggests its closest type if it is at least `SUGGEST_MIN`
//!   close, and at least `SUGGEST_GAP` closer than to the next type.

use std::sync::OnceLock;

use raft5fs_wire::Reader;

use crate::Error;
use crate::filter::FileType;
use crate::vector::{SUGGEST_GAP, SUGGEST_MIN, TEXT_MODEL};

const MAGIC: &[u8; 4] = b"r5tv";

/// The types' vectors, for one text model.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeVectors {
    pub model: String,
    /// The mean of everyday words' vectors.
    pub centre: Vec<f32>,
    /// Each type's centred unit vector.
    pub types: Vec<(FileType, Vec<f32>)>,
}

/// Unit length.
pub fn unit(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        v.iter_mut().for_each(|x| *x /= n);
    }
    v
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

impl TypeVectors {
    /// `v` less the centre, at unit length.
    pub fn centred(&self, v: &[f32]) -> Vec<f32> {
        unit(v.iter().zip(&self.centre).map(|(a, c)| a - c).collect())
    }

    /// The closest type to query vector `v`, how close, and how much
    /// closer than the next.
    pub fn closest(&self, v: &[f32]) -> Option<(FileType, f32, f32)> {
        let c = self.centred(v);
        let mut scores: Vec<(FileType, f32)> =
            self.types.iter().map(|(t, p)| (*t, dot(&c, p))).collect();
        scores.sort_by(|a, b| b.1.total_cmp(&a.1));
        let best = *scores.first()?;
        let next = scores.get(1).map_or(0.0, |s| s.1);
        Some((best.0, best.1, best.1 - next))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        raft5fs_wire::put_short_bytes(&mut out, self.model.as_bytes());
        raft5fs_wire::put_varint(&mut out, self.centre.len() as u64);
        let put = |out: &mut Vec<u8>, v: &[f32]| {
            for x in v {
                raft5fs_wire::put_u32(out, x.to_bits());
            }
        };
        put(&mut out, &self.centre);
        raft5fs_wire::put_varint(&mut out, self.types.len() as u64);
        for (t, v) in &self.types {
            raft5fs_wire::put_short_bytes(&mut out, t.name().as_bytes());
            put(&mut out, v);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, "type vectors");
        if r.array::<4>()? != *MAGIC {
            return Err(r.garbled());
        }
        let model = String::from_utf8(r.short_bytes()?.to_vec()).map_err(|_| r.garbled())?;
        let dims = usize::try_from(r.varint()?).map_err(|_| r.garbled())?;
        if dims > 4096 {
            return Err(r.garbled());
        }
        let get = |r: &mut Reader| -> Result<Vec<f32>, Error> {
            (0..dims).map(|_| Ok(f32::from_bits(r.u32()?))).collect()
        };
        let centre = get(&mut r)?;
        let n = r.varint()?;
        if n > 64 {
            return Err(r.garbled());
        }
        let mut types = Vec::new();
        for _ in 0..n {
            let name = String::from_utf8(r.short_bytes()?.to_vec()).map_err(|_| r.garbled())?;
            let t = FileType::of_name(&name).ok_or_else(|| r.garbled())?;
            types.push((t, get(&mut r)?));
        }
        r.finish()?;
        Ok(Self {
            model,
            centre,
            types,
        })
    }
}

/// The pinned text model's type vectors, if data/type_vectors.bin is for
/// it.
pub fn pinned() -> Option<&'static TypeVectors> {
    static PINNED: OnceLock<Option<TypeVectors>> = OnceLock::new();
    PINNED
        .get_or_init(|| {
            TypeVectors::decode(include_bytes!("../../data/type_vectors.bin"))
                .ok()
                .filter(|t| t.model == TEXT_MODEL)
        })
        .as_ref()
}

/// At most how many of a query's words are embedded to look for a type.
pub const MOST_WORDS: usize = 3;

/// The words of `unknown` worth asking the model about: at most
/// `MOST_WORDS`, each a word or two words together.
pub fn candidates(unknown: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in unknown.windows(2) {
        out.push(format!("{} {}", w[0], w[1]));
    }
    let mut words: Vec<String> = unknown.to_vec();
    words.extend(out);
    words.truncate(MOST_WORDS);
    words
}

/// The type to suggest for words `vectors` (each a word and its query
/// vector), if one is close enough: the closest over all words.
pub fn suggest(types: &TypeVectors, vectors: &[(String, Vec<f32>)]) -> Option<FileType> {
    suggest_with(types, vectors, SUGGEST_MIN, SUGGEST_GAP)
}

pub fn suggest_with(
    types: &TypeVectors,
    vectors: &[(String, Vec<f32>)],
    min: f32,
    gap: f32,
) -> Option<FileType> {
    vectors
        .iter()
        .filter_map(|(_, v)| types.closest(v))
        .filter(|(_, score, g)| *score >= min && *g >= gap)
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(t, _, _)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toy() -> TypeVectors {
        TypeVectors {
            model: "m".into(),
            centre: vec![0.0, 0.0, 1.0],
            types: vec![
                (FileType::Video, vec![1.0, 0.0, 0.0]),
                (FileType::Photo, vec![0.0, 1.0, 0.0]),
            ],
        }
    }

    #[test]
    fn a_word_close_to_one_type_suggests_it() {
        let t = toy();
        // Mostly the common part, a little video.
        let footage = ("footage".to_string(), unit(vec![0.4, 0.05, 1.0]));
        let lake = ("lake".to_string(), unit(vec![0.05, 0.05, 1.0]));
        let both = ("clip art".to_string(), unit(vec![0.3, 0.3, 1.0]));
        assert_eq!(
            suggest_with(&t, std::slice::from_ref(&footage), 0.5, 0.1),
            Some(FileType::Video)
        );
        assert_eq!(
            suggest_with(&t, std::slice::from_ref(&lake), 0.5, 0.1),
            None,
            "after centring, near both"
        );
        assert_eq!(suggest_with(&t, &[both], 0.5, 0.1), None, "no gap");
        assert_eq!(
            suggest_with(&t, &[lake, footage], 0.5, 0.1),
            Some(FileType::Video)
        );
    }

    #[test]
    fn type_vectors_read_back() {
        let t = toy();
        assert_eq!(TypeVectors::decode(&t.encode()).unwrap(), t);
        let mut bad = t.encode();
        bad[0] = b'x';
        assert!(TypeVectors::decode(&bad).is_err());
    }

    #[test]
    fn the_pinned_vectors_are_for_the_pinned_model() {
        let t = pinned().expect("data/type_vectors.bin is for TEXT_MODEL");
        assert!(t.types.len() >= 8);
        assert_eq!(t.centre.len(), crate::vector::TEXT_DIMS);
    }

    #[test]
    fn candidates_are_few() {
        let words: Vec<String> = ["dashcam", "from", "lisbon"].map(String::from).to_vec();
        assert_eq!(candidates(&words), ["dashcam", "from", "lisbon"]);
        let two: Vec<String> = ["home", "movies"].map(String::from).to_vec();
        assert_eq!(candidates(&two), ["home", "movies", "home movies"]);
    }
}
