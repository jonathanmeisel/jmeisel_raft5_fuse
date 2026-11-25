//! A text model: tokens, their rows of the word table, the encoder, then
//! pooling and an optional projection, made unit length.
//!
//! - **Batches.** Texts of a batch are padded to the longest, and padding
//!   is masked out of attention and pooling. Q8_0 quantizes each row of
//!   activations alone, so a text gets the same vector in any batch.
//! - **What goes before a text** (a model's "query: " and "passage: ") is
//!   the caller's: `embed` takes texts as the model should read them.

use std::io::{Read, Seek};

use candle_core::{D, Device, IndexOp, Tensor};

use crate::encoder::Encoder;
use crate::gguf::Body;
use crate::q8::{Rows, add_row, row_bytes};
use crate::tokenize::Tokenizer;
use crate::{Error, Result};

/// How a text's vector is made from the encoder's last hidden states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pooling {
    /// The first token's.
    Cls,
    /// The mean over the text's real tokens.
    Mean,
}

impl Pooling {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "cls" => Ok(Pooling::Cls),
            "mean" => Ok(Pooling::Mean),
            other => Err(Error(format!("unknown pooling {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TextOptions {
    pub pooling: Pooling,
    /// The most tokens of a text the model reads; the rest are cut.
    pub max_tokens: usize,
    /// Whether to make the weights f32 when loading: native clients that
    /// embed many passages, where candle multiplies f32 batches several
    /// times faster than Q8_0 (and the vectors stay within cosine 0.9999
    /// of Q8_0's). Browsers keep Q8_0, for memory.
    pub dense: bool,
}

/// How many texts `embed_batched` runs at once.
pub const BATCH: usize = 16;

pub struct TextModel {
    encoder: Encoder,
    tokenizer: Tokenizer,
    rows: Box<dyn Rows>,
    /// The projection after pooling (out, hidden), if the model has one.
    projection: Option<Tensor>,
    pooling: Pooling,
    /// The most tokens read of a text, with the start and end ones.
    most: usize,
}

/// A very negative score: attention to padding.
const MASKED: f32 = -1e9;

impl TextModel {
    /// The model whose body `body` reads from, with its tokenizer
    /// (`tokenizer.bin`'s bytes) and word table.
    pub fn load<R: Read + Seek>(
        body: &mut R,
        tokenizer: &[u8],
        rows: Box<dyn Rows>,
        options: TextOptions,
    ) -> Result<Self> {
        let index = Body::read(body)?;
        let encoder = Encoder::load(&index, body, options.dense)?;
        let projection = if index.has("projection.weight") {
            Some(index.tensor(body, "projection.weight")?)
        } else {
            None
        };
        let tokenizer = Tokenizer::read(tokenizer)?;
        if tokenizer.vocab() > encoder.settings.vocab {
            return Err(Error::from(
                "the tokenizer has more pieces than the model's table",
            ));
        }
        let most = options
            .max_tokens
            .min(encoder.settings.positions - encoder.settings.position_offset);
        Ok(Self {
            encoder,
            tokenizer,
            rows,
            projection,
            pooling: options.pooling,
            most,
        })
    }

    /// The token ids the model reads for `text`.
    pub fn ids(&self, text: &str) -> Vec<u32> {
        self.tokenizer.encode(text, self.most)
    }

    /// The size of the vectors this model gives.
    pub fn dims(&self) -> usize {
        match &self.projection {
            Some(p) => p.dims()[0],
            None => self.encoder.hidden(),
        }
    }

    /// The vectors of `texts`, in batches of texts of about the same length
    /// (padding a short text to a long one's length costs more than the
    /// batch saves), in the order given.
    pub fn embed_batched(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        let mut order: Vec<(usize, usize)> = texts
            .iter()
            .enumerate()
            .map(|(i, t)| (self.ids(t).len(), i))
            .collect();
        order.sort();
        let mut out = vec![Vec::new(); texts.len()];
        let mut at = 0;
        while at < order.len() {
            // Texts within a quarter of the shortest one's length, at most
            // `BATCH` of them.
            let shortest = order[at].0;
            let mut end = at + 1;
            while end < order.len() && end - at < BATCH && order[end].0 * 4 <= shortest * 5 {
                end += 1;
            }
            let batch: Vec<&str> = order[at..end].iter().map(|&(_, i)| texts[i]).collect();
            for (v, &(_, i)) in self.embed(&batch)?.into_iter().zip(&order[at..end]) {
                out[i] = v;
            }
            at = end;
        }
        Ok(out)
    }

    /// The vectors of `texts`, in one batch, each unit length.
    pub fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Vec<u32>> = texts.iter().map(|t| self.ids(t)).collect();
        let b = ids.len();
        let t = ids.iter().map(Vec::len).max().unwrap_or(0).max(1);
        let h = self.encoder.hidden();
        let vocab = self.encoder.settings.vocab;
        let row = row_bytes(h);
        let mut words = vec![0f32; b * t * h];
        let mut bytes = vec![0u8; row];
        for (i, text) in ids.iter().enumerate() {
            for (j, &id) in text.iter().enumerate() {
                if id as usize >= vocab {
                    return Err(Error(format!("token {id} isn't in the model's table")));
                }
                self.rows.read(u64::from(id) * row as u64, &mut bytes)?;
                let at = (i * t + j) * h;
                add_row(&bytes, &mut words[at..at + h]);
            }
        }
        let words = Tensor::from_vec(words, (b, t, h), &Device::Cpu)?;
        let padded = ids.iter().any(|x| x.len() < t);
        let keep: Vec<f32> = ids
            .iter()
            .flat_map(|x| (0..t).map(move |j| if j < x.len() { 1.0 } else { 0.0 }))
            .collect();
        let keep = Tensor::from_vec(keep, (b, t), &Device::Cpu)?;
        let mask = if padded {
            Some(((keep.ones_like()? - &keep)? * f64::from(MASKED))?.reshape((b, 1, 1, t))?)
        } else {
            None
        };
        let hidden = self.encoder.forward(&words, mask.as_ref())?;
        let mut pooled = match self.pooling {
            Pooling::Cls => hidden.i((.., 0, ..))?.contiguous()?,
            Pooling::Mean => {
                let weights = keep.unsqueeze(D::Minus1)?;
                let sum = hidden.broadcast_mul(&weights)?.sum(1)?;
                sum.broadcast_div(&weights.sum(1)?)?
            }
        };
        if let Some(p) = &self.projection {
            pooled = pooled.matmul(&p.t()?)?;
        }
        let mut out: Vec<Vec<f32>> = pooled.to_vec2()?;
        for v in &mut out {
            let len = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if len > 0.0 {
                v.iter_mut().for_each(|x| *x /= len);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use candle_core::quantized::gguf_file::{self, Value};
    use candle_core::quantized::{GgmlDType, QTensor};
    use candle_core::{Device, Tensor};

    use super::*;
    use crate::q8::{MemoryRows, quantize_row};
    use crate::tokenize::write_wordpiece;

    const H: usize = 64;
    const VOCAB: usize = 40;

    /// A tiny random BERT, its table and a WordPiece tokenizer of `a`..`z`
    /// and a few words.
    fn tiny(dense: bool, pooling: Pooling) -> TextModel {
        let dev = Device::Cpu;
        let rand = |shape: &[usize]| Tensor::randn(0f32, 0.2, shape, &dev).unwrap();
        let mut tensors: Vec<(String, QTensor)> = Vec::new();
        let mut put = |name: &str, t: Tensor, q: bool| {
            let dtype = if q { GgmlDType::Q8_0 } else { GgmlDType::F32 };
            tensors.push((name.to_string(), QTensor::quantize(&t, dtype).unwrap()));
        };
        put("embeddings.position", rand(&[32, H]), false);
        put("embeddings.token_type", rand(&[2, H]), false);
        put(
            "embeddings.norm.weight",
            Tensor::ones(H, candle_core::DType::F32, &dev).unwrap(),
            false,
        );
        put(
            "embeddings.norm.bias",
            Tensor::zeros(H, candle_core::DType::F32, &dev).unwrap(),
            false,
        );
        for l in 0..2 {
            let at = |n: &str| format!("layers.{l}.{n}");
            put(&at("attn.qkv.weight"), rand(&[3 * H, H]), true);
            put(&at("attn.qkv.bias"), rand(&[3 * H]), false);
            put(&at("attn.out.weight"), rand(&[H, H]), true);
            put(&at("attn.out.bias"), rand(&[H]), false);
            put(&at("ffn.up.weight"), rand(&[2 * H, H]), true);
            put(&at("ffn.up.bias"), rand(&[2 * H]), false);
            put(&at("ffn.down.weight"), rand(&[H, 2 * H]), true);
            put(&at("ffn.down.bias"), rand(&[H]), false);
            for n in ["attn_norm", "ffn_norm"] {
                put(
                    &at(&format!("{n}.weight")),
                    Tensor::ones(H, candle_core::DType::F32, &dev).unwrap(),
                    false,
                );
                put(
                    &at(&format!("{n}.bias")),
                    Tensor::zeros(H, candle_core::DType::F32, &dev).unwrap(),
                    false,
                );
            }
        }
        let settings = [
            ("raft5fs.hidden", Value::U32(H as u32)),
            ("raft5fs.layers", Value::U32(2)),
            ("raft5fs.heads", Value::U32(2)),
            ("raft5fs.positions", Value::U32(32)),
            ("raft5fs.position_offset", Value::U32(0)),
            ("raft5fs.token_types", Value::U32(1)),
            ("raft5fs.eps", Value::F32(1e-12)),
            ("raft5fs.act", Value::String("gelu".into())),
            ("raft5fs.vocab", Value::U32(VOCAB as u32)),
        ];
        let meta: Vec<(&str, &Value)> = settings.iter().map(|(k, v)| (*k, v)).collect();
        let refs: Vec<(&str, &QTensor)> = tensors.iter().map(|(n, t)| (n.as_str(), t)).collect();
        let mut body = Cursor::new(Vec::new());
        gguf_file::write(&mut body, &meta, &refs).unwrap();
        body.set_position(0);
        let mut table = Vec::new();
        for _ in 0..VOCAB {
            let row: Vec<f32> = rand(&[H]).to_vec1().unwrap();
            quantize_row(&row, &mut table);
        }
        let mut pieces: Vec<String> = [
            "[PAD]", "[UNK]", "[CLS]", "[SEP]", "cat", "dog", "sat", "on", "the", "mat",
        ]
        .map(String::from)
        .to_vec();
        pieces.extend(('a'..='z').map(|c| format!("##{c}")));
        pieces.truncate(VOCAB);
        let tokenizer = write_wordpiece(1, 2, 3, 100, &pieces);
        TextModel::load(
            &mut body,
            &tokenizer,
            Box::new(MemoryRows(table)),
            TextOptions {
                pooling,
                max_tokens: 32,
                dense,
            },
        )
        .unwrap()
    }

    fn cos(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| x * y).sum()
    }

    #[test]
    fn vectors_are_unit_length_and_the_same_in_a_batch() {
        for pooling in [Pooling::Mean, Pooling::Cls] {
            let m = tiny(false, pooling);
            let texts = ["the cat sat on the mat", "dog", "the dog sat"];
            let batch = m.embed(&texts).unwrap();
            for (t, b) in texts.iter().zip(&batch) {
                let alone = m.embed(&[t]).unwrap().remove(0);
                assert!((cos(b, b) - 1.0).abs() < 1e-4);
                // Padding to the longest is masked out.
                assert!(cos(&alone, b) > 0.9999, "{t}: {}", cos(&alone, b));
            }
            assert_eq!(m.dims(), H);
        }
    }

    #[test]
    fn f32_weights_give_nearly_the_q8_vectors() {
        let (q8, f32) = (tiny(false, Pooling::Mean), tiny(true, Pooling::Mean));
        // Two random models: compare each with itself only through the
        // batched order instead.
        let texts = [
            "the cat",
            "the cat sat on the mat",
            "dog",
            "the dog sat on the mat",
        ];
        for m in [&q8, &f32] {
            let alone: Vec<Vec<f32>> = texts
                .iter()
                .map(|t| m.embed(&[t]).unwrap().remove(0))
                .collect();
            let batched = m.embed_batched(&texts).unwrap();
            for (a, b) in alone.iter().zip(&batched) {
                assert!(cos(a, b) > 0.9999);
            }
        }
    }

    #[test]
    fn token_ids_are_cut_to_the_most_read() {
        let m = tiny(false, Pooling::Mean);
        let long = "cat ".repeat(100);
        let ids = m.ids(&long);
        assert_eq!(ids.len(), 32);
        assert_eq!((ids[0], ids[31]), (2, 3));
        assert_eq!(m.embed(&[&long]).unwrap()[0].len(), H);
    }
}
