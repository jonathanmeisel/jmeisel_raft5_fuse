//! CLIP ViT-B/32's image side, for native clients: a photo's 224 × 224
//! pixels (see raft5fs-indexer's `clip::pixels`) as a unit vector in the
//! space the text side puts queries in.
//!
//! Tensors, as `convert` names them: `vision.patch` (the patch embedding,
//! f32), `vision.class`, `vision.position`, `vision.pre_norm`, per layer
//! `layers.N.{norm1,attn,norm2,ffn}`, `vision.post_norm` and
//! `vision.projection`. Each layer normalizes before its attention and
//! before its feed-forward part, as CLIP does.

use std::io::{Read, Seek};

use candle_core::{Device, IndexOp, Module, Tensor};
use candle_nn::LayerNorm;

use crate::encoder::{Act, Attention, Ffn, Linear, norm};
use crate::gguf::Body;
use crate::{Error, Result};

/// The side of the square image the model takes.
pub const SIDE: usize = 224;

struct Layer {
    norm1: LayerNorm,
    attn: Attention,
    norm2: LayerNorm,
    ffn: Ffn,
}

pub struct Vision {
    patch: Tensor,
    patch_size: usize,
    class: Tensor,
    position: Tensor,
    pre_norm: LayerNorm,
    layers: Vec<Layer>,
    post_norm: LayerNorm,
    projection: Linear,
    hidden: usize,
}

impl Vision {
    pub fn load<R: Read + Seek>(body: &mut R) -> Result<Self> {
        let index = Body::read(body)?;
        let hidden = index.usize("hidden")?;
        let heads = index.usize("heads")?;
        let eps = f64::from(index.f32("eps")?);
        let act = Act::parse(&index.string("act")?)?;
        let mut layers = Vec::new();
        for i in 0..index.usize("layers")? {
            let at = format!("layers.{i}");
            layers.push(Layer {
                norm1: norm(&index, body, &format!("{at}.norm1"), eps)?,
                attn: Attention::load(&index, body, &format!("{at}.attn"), heads, false)?,
                norm2: norm(&index, body, &format!("{at}.norm2"), eps)?,
                ffn: Ffn::load(&index, body, &format!("{at}.ffn"), act, false)?,
            });
        }
        Ok(Self {
            patch: index.tensor(body, "vision.patch")?,
            patch_size: index.usize("patch")?,
            class: index.tensor(body, "vision.class")?,
            position: index.tensor(body, "vision.position")?,
            pre_norm: norm(&index, body, "vision.pre_norm", eps)?,
            layers,
            post_norm: norm(&index, body, "vision.post_norm", eps)?,
            projection: Linear::load(&index, body, "vision.projection", false)?,
            hidden,
        })
    }

    /// The unit vector of an image: `pixels` normalized as CLIP's
    /// preprocessor says, channels first (3 × 224 × 224).
    pub fn embed(&self, pixels: Vec<f32>) -> Result<Vec<f32>> {
        if pixels.len() != 3 * SIDE * SIDE {
            return Err(Error::from("an image must be 3 × 224 × 224 values"));
        }
        let h = self.hidden;
        let x = Tensor::from_vec(pixels, (1, 3, SIDE, SIDE), &Device::Cpu)?;
        let patches = x.conv2d(&self.patch, 0, self.patch_size, 1, 1)?;
        let n = (SIDE / self.patch_size) * (SIDE / self.patch_size);
        let patches = patches.reshape((1, h, n))?.transpose(1, 2)?;
        let class = self.class.reshape((1, 1, h))?;
        let mut x = Tensor::cat(&[&class, &patches], 1)?.broadcast_add(&self.position)?;
        x = self.pre_norm.forward(&x)?;
        for layer in &self.layers {
            let a = layer.attn.forward(&layer.norm1.forward(&x)?, None)?;
            x = (x + a)?;
            let f = layer.ffn.forward(&layer.norm2.forward(&x)?)?;
            x = (x + f)?;
        }
        let pooled = self.post_norm.forward(&x.i((.., 0, ..))?.contiguous()?)?;
        let mut v: Vec<f32> = self.projection.forward(&pooled)?.flatten_all()?.to_vec1()?;
        let len = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if len > 0.0 {
            v.iter_mut().for_each(|x| *x /= len);
        }
        Ok(v)
    }
}
