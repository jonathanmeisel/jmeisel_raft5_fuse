//! The BERT family's encoder (BERT, XLM-R, DistilBERT), with Q8_0 linear
//! layers. Its settings come from the body's metadata, and its tensors
//! have the names `convert` gives them, whatever the source called them:
//!
//! - `embeddings.position`, `embeddings.token_type` (if `token_types`),
//!   `embeddings.norm.{weight,bias}`;
//! - per layer `layers.N.`: `attn.{qkv,out}.{weight,bias}` (`qkv`: the
//!   query, key and value weights one after another, so one matmul makes
//!   all three),
//!   `attn_norm.{weight,bias}`, `ffn.{up,down}.{weight,bias}`,
//!   `ffn_norm.{weight,bias}`.
//!
//! The word embeddings are not here: the caller adds them (`text`), from
//! a table read a row at a time. Each layer normalizes after its
//! attention and after its feed-forward part, as the BERT family does.

use std::io::{Read, Seek};

use candle_core::quantized::QMatMul;
use candle_core::{Module, Tensor};
use candle_nn::LayerNorm;

use crate::gguf::Body;
use crate::{Error, Result};

/// A linear layer: quantized weights, f32 bias.
pub(crate) struct Linear {
    w: QMatMul,
    b: Option<Tensor>,
}

impl Linear {
    /// With `dense`, the weights are made f32: more memory, but on native
    /// CPUs candle multiplies batches of f32 several times faster.
    pub(crate) fn load<R: Read + Seek>(
        body: &Body,
        r: &mut R,
        name: &str,
        dense: bool,
    ) -> Result<Self> {
        let bias = format!("{name}.bias");
        Ok(Self {
            w: body.qmatmul(r, &format!("{name}.weight"), dense)?,
            b: if body.has(&bias) {
                Some(body.tensor(r, &bias)?)
            } else {
                None
            },
        })
    }

    /// `x` of shape (rows, in), as (rows, out).
    pub(crate) fn forward(&self, x: &Tensor) -> Result<Tensor> {
        let y = self.w.forward(x)?;
        Ok(match &self.b {
            Some(b) => y.broadcast_add(b)?,
            None => y,
        })
    }
}

pub(crate) fn norm<R: Read + Seek>(
    body: &Body,
    r: &mut R,
    name: &str,
    eps: f64,
) -> Result<LayerNorm> {
    Ok(LayerNorm::new(
        body.tensor(r, &format!("{name}.weight"))?,
        body.tensor(r, &format!("{name}.bias"))?,
        eps,
    ))
}

/// The activation between a feed-forward part's two layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Act {
    /// GELU, exactly (with erf): BERT's "gelu".
    Gelu,
    /// x · sigmoid(1.702 x): CLIP's "quick_gelu".
    QuickGelu,
}

impl Act {
    pub(crate) fn parse(name: &str) -> Result<Self> {
        match name {
            "gelu" => Ok(Act::Gelu),
            "quick_gelu" => Ok(Act::QuickGelu),
            other => Err(Error(format!("unknown activation {other}"))),
        }
    }

    pub(crate) fn apply(self, x: &Tensor) -> Result<Tensor> {
        Ok(match self {
            Act::Gelu => x.gelu_erf()?,
            Act::QuickGelu => (x * candle_nn::ops::sigmoid(&(x * 1.702)?)?)?,
        })
    }
}

/// Multi-head self-attention: `qkv` (the three projections as one) and
/// `out`.
pub(crate) struct Attention {
    qkv: Linear,
    out: Linear,
    heads: usize,
}

impl Attention {
    pub(crate) fn load<R: Read + Seek>(
        body: &Body,
        r: &mut R,
        at: &str,
        heads: usize,
        dense: bool,
    ) -> Result<Self> {
        Ok(Self {
            qkv: Linear::load(body, r, &format!("{at}.qkv"), dense)?,
            out: Linear::load(body, r, &format!("{at}.out"), dense)?,
            heads,
        })
    }

    /// `x` of shape (batch, tokens, hidden). `mask`, of shape (batch, 1, 1,
    /// tokens), is 0 for real tokens and very negative for padding.
    pub(crate) fn forward(&self, x: &Tensor, mask: Option<&Tensor>) -> Result<Tensor> {
        let (b, t, h) = x.dims3()?;
        let hd = h / self.heads;
        // One matmul for all three, laid out (3, batch, heads, tokens,
        // head size) by one copy.
        let qkv = self
            .qkv
            .forward(&x.reshape((b * t, h))?)?
            .reshape((b, t, 3, self.heads, hd))?
            .permute((2, 0, 3, 1, 4))?
            .contiguous()?;
        let q = (qkv.get(0)? / (hd as f64).sqrt())?;
        let (k, v) = (qkv.get(1)?, qkv.get(2)?);
        let mut scores = q.matmul(&k.t()?)?;
        if let Some(mask) = mask {
            scores = scores.broadcast_add(mask)?;
        }
        let probs = candle_nn::ops::softmax_last_dim(&scores)?;
        let ctx = probs
            .matmul(&v)?
            .transpose(1, 2)?
            .contiguous()?
            .reshape((b * t, h))?;
        Ok(self.out.forward(&ctx)?.reshape((b, t, h))?)
    }
}

/// A feed-forward part: `up`, the activation, `down`.
pub(crate) struct Ffn {
    up: Linear,
    down: Linear,
    act: Act,
}

impl Ffn {
    pub(crate) fn load<R: Read + Seek>(
        body: &Body,
        r: &mut R,
        at: &str,
        act: Act,
        dense: bool,
    ) -> Result<Self> {
        Ok(Self {
            up: Linear::load(body, r, &format!("{at}.up"), dense)?,
            down: Linear::load(body, r, &format!("{at}.down"), dense)?,
            act,
        })
    }

    pub(crate) fn forward(&self, x: &Tensor) -> Result<Tensor> {
        let (b, t, h) = x.dims3()?;
        let y = self.up.forward(&x.reshape((b * t, h))?)?;
        let y = self.down.forward(&self.act.apply(&y)?)?;
        Ok(y.reshape((b, t, h))?)
    }
}

struct Layer {
    attn: Attention,
    attn_norm: LayerNorm,
    ffn: Ffn,
    ffn_norm: LayerNorm,
}

/// What an encoder's settings say about it.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub hidden: usize,
    pub layers: usize,
    pub heads: usize,
    pub positions: usize,
    /// The position of the first token (XLM-R's tables start at 2).
    pub position_offset: usize,
    pub token_types: bool,
    pub eps: f64,
    pub act: Act,
    pub vocab: usize,
}

impl Settings {
    pub(crate) fn read(body: &Body) -> Result<Self> {
        Ok(Self {
            hidden: body.usize("hidden")?,
            layers: body.usize("layers")?,
            heads: body.usize("heads")?,
            positions: body.usize("positions")?,
            position_offset: body.usize("position_offset")?,
            token_types: body.usize("token_types")? == 1,
            eps: f64::from(body.f32("eps")?),
            act: Act::parse(&body.string("act")?)?,
            vocab: body.usize("vocab")?,
        })
    }
}

pub(crate) struct Encoder {
    pub settings: Settings,
    position: Tensor,
    token_type: Option<Tensor>,
    norm: LayerNorm,
    layers: Vec<Layer>,
}

impl Encoder {
    pub(crate) fn load<R: Read + Seek>(body: &Body, r: &mut R, dense: bool) -> Result<Self> {
        let s = Settings::read(body)?;
        let mut layers = Vec::with_capacity(s.layers);
        for i in 0..s.layers {
            let at = format!("layers.{i}");
            layers.push(Layer {
                attn: Attention::load(body, r, &format!("{at}.attn"), s.heads, dense)?,
                attn_norm: norm(body, r, &format!("{at}.attn_norm"), s.eps)?,
                ffn: Ffn::load(body, r, &format!("{at}.ffn"), s.act, dense)?,
                ffn_norm: norm(body, r, &format!("{at}.ffn_norm"), s.eps)?,
            });
        }
        Ok(Self {
            position: body.tensor(r, "embeddings.position")?,
            token_type: if s.token_types {
                Some(body.tensor(r, "embeddings.token_type")?)
            } else {
                None
            },
            norm: norm(body, r, "embeddings.norm", s.eps)?,
            layers,
            settings: s,
        })
    }

    /// The last hidden states of `words` (batch, tokens, hidden: each
    /// token's word embedding), with `mask` as for `Attention::forward`.
    pub(crate) fn forward(&self, words: &Tensor, mask: Option<&Tensor>) -> Result<Tensor> {
        let (_, t, _) = words.dims3()?;
        let s = &self.settings;
        if s.position_offset + t > s.positions {
            return Err(Error(format!("{t} tokens is more than the model reads")));
        }
        let pos = self.position.narrow(0, s.position_offset, t)?;
        let mut x = words.broadcast_add(&pos)?;
        if let Some(types) = &self.token_type {
            x = x.broadcast_add(&types.get(0)?)?;
        }
        x = self.norm.forward(&x)?;
        for layer in &self.layers {
            let a = layer.attn.forward(&x, mask)?;
            x = layer.attn_norm.forward(&(x + a)?)?;
            let f = layer.ffn.forward(&x)?;
            x = layer.ffn_norm.forward(&(x + f)?)?;
        }
        Ok(x)
    }

    /// Hidden size.
    pub(crate) fn hidden(&self) -> usize {
        self.settings.hidden
    }
}
