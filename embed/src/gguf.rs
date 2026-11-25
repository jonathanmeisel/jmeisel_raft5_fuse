//! A model body: a GGUF file of tensors, with the model's settings as
//! metadata under `raft5fs.`. Linear layers' weights are Q8_0; norms,
//! biases and position tables are f32.
//!
//! Tensors are read one at a time from the file, so loading holds about
//! the model once, plus its largest tensor.

use std::io::{Read, Seek};

use candle_core::quantized::gguf_file::{Content, Value};
use candle_core::quantized::{QMatMul, QTensor};
use candle_core::{Device, Tensor};

use crate::{Error, Result};

/// The prefix of the metadata keys this crate writes and reads.
pub const KEY: &str = "raft5fs.";

/// A model body's index: its metadata and where each tensor is.
pub struct Body {
    content: Content,
}

impl Body {
    /// Reads the header of a body from `r`.
    pub fn read<R: Read + Seek>(r: &mut R) -> Result<Self> {
        Ok(Self {
            content: Content::read(r).map_err(|e| Error(format!("not a model body: {e}")))?,
        })
    }

    fn value(&self, key: &str) -> Result<&Value> {
        self.content
            .metadata
            .get(&format!("{KEY}{key}"))
            .ok_or_else(|| Error(format!("the model has no {key}")))
    }

    /// Setting `key`, a whole number.
    pub fn usize(&self, key: &str) -> Result<usize> {
        Ok(self.value(key)?.to_u32()? as usize)
    }

    pub fn f32(&self, key: &str) -> Result<f32> {
        Ok(self.value(key)?.to_f32()?)
    }

    pub fn string(&self, key: &str) -> Result<String> {
        Ok(self.value(key)?.to_string()?.clone())
    }

    pub fn has(&self, name: &str) -> bool {
        self.content.tensor_infos.contains_key(name)
    }

    fn qtensor<R: Read + Seek>(&self, r: &mut R, name: &str) -> Result<QTensor> {
        self.content
            .tensor(r, name, &Device::Cpu)
            .map_err(|e| Error(format!("cannot read {name}: {e}")))
    }

    /// Tensor `name` as f32.
    pub fn tensor<R: Read + Seek>(&self, r: &mut R, name: &str) -> Result<Tensor> {
        Ok(self.qtensor(r, name)?.dequantize(&Device::Cpu)?)
    }

    /// Linear weights `name`: kept quantized, or with `dense` as f32.
    pub fn qmatmul<R: Read + Seek>(&self, r: &mut R, name: &str, dense: bool) -> Result<QMatMul> {
        let q = self.qtensor(r, name)?;
        Ok(if dense {
            QMatMul::Tensor(q.dequantize(&Device::Cpu)?)
        } else {
            QMatMul::from_qtensor(q)?
        })
    }
}
