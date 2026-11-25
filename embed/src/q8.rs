//! Word tables: one Q8_0 row per token, read a row at a time.
//!
//! A row of `dims` values is `dims / 32` blocks, each a little-endian f16
//! scale and 32 signed bytes, as ggml's Q8_0 lays them out: value `i` of a
//! block is `qs[i] * scale`.

use half::f16;

use crate::{Error, Result};

/// The values in one Q8_0 block.
pub const BLOCK: usize = 32;
const BLOCK_BYTES: usize = 2 + BLOCK;

/// The bytes of one row of `dims` values.
pub fn row_bytes(dims: usize) -> usize {
    dims / BLOCK * BLOCK_BYTES
}

/// Where a table's rows are read from: bytes `offset..offset + out.len()`
/// of the table file.
#[cfg(not(target_arch = "wasm32"))]
pub trait Rows: Send + Sync {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()>;
}

/// Where a table's rows are read from (in a browser: OPFS, through JS).
#[cfg(target_arch = "wasm32")]
pub trait Rows {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()>;
}

/// No table: for a model whose caller gives the rows with each text
/// (`TextModel::embed_with`).
pub struct NoRows;

impl Rows for NoRows {
    fn read(&self, _: u64, _: &mut [u8]) -> Result<()> {
        Err(Error::from("this model's table rows come with each text"))
    }
}

/// Some rows of a table, by token id: what a text needs, read ahead.
pub struct GivenRows {
    /// Ids, sorted, and their rows one after another.
    pub ids: Vec<u32>,
    pub bytes: Vec<u8>,
    pub row: usize,
}

impl Rows for GivenRows {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        let id = (offset / self.row as u64) as u32;
        let at = self
            .ids
            .binary_search(&id)
            .map_err(|_| Error(format!("no row given for token {id}")))?;
        out.copy_from_slice(
            self.bytes
                .get(at * self.row..at * self.row + out.len())
                .ok_or_else(|| Error::from("a given row is short"))?,
        );
        Ok(())
    }
}

/// A table held in memory.
pub struct MemoryRows(pub Vec<u8>);

impl Rows for MemoryRows {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        read_from(&self.0, offset, out)
    }
}

/// A table file mapped into memory: the system reads in only the rows
/// used, and can drop them again.
#[cfg(not(target_arch = "wasm32"))]
pub struct MappedRows(memmap2::Mmap);

#[cfg(not(target_arch = "wasm32"))]
impl MappedRows {
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| Error(format!("cannot open {}: {e}", path.display())))?;
        // Safety: the file is the cache's, checked against its SHA-256 and
        // never written once in place.
        let map = unsafe { memmap2::Mmap::map(&file) }
            .map_err(|e| Error(format!("cannot map {}: {e}", path.display())))?;
        Ok(Self(map))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Rows for MappedRows {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        read_from(&self.0, offset, out)
    }
}

fn read_from(bytes: &[u8], offset: u64, out: &mut [u8]) -> Result<()> {
    let at = usize::try_from(offset).map_err(|_| Error::from("a row past the table"))?;
    let src = bytes
        .get(at..at + out.len())
        .ok_or_else(|| Error::from("a row past the table"))?;
    out.copy_from_slice(src);
    Ok(())
}

/// `values` (a multiple of 32 of them) as Q8_0 bytes.
pub fn quantize_row(values: &[f32], out: &mut Vec<u8>) {
    for block in values.chunks(BLOCK) {
        let amax = block.iter().fold(0f32, |m, x| m.max(x.abs()));
        let d = amax / 127.0;
        let inv = if d == 0.0 { 0.0 } else { 1.0 / d };
        out.extend_from_slice(&f16::from_f32(d).to_le_bytes());
        out.extend(block.iter().map(|x| (x * inv).round() as i8 as u8));
    }
}

/// Q8_0 bytes as values, added to `out` (its length: the row's values).
pub fn add_row(bytes: &[u8], out: &mut [f32]) {
    for (block, dst) in bytes.chunks(BLOCK_BYTES).zip(out.chunks_mut(BLOCK)) {
        let d = f16::from_le_bytes([block[0], block[1]]).to_f32();
        for (q, v) in block[2..].iter().zip(dst) {
            *v += f32::from(*q as i8) * d;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_round_trip_closely() {
        let values: Vec<f32> = (0..64).map(|i| (i as f32 - 30.0) / 17.0).collect();
        let mut bytes = Vec::new();
        quantize_row(&values, &mut bytes);
        assert_eq!(bytes.len(), row_bytes(64));
        let mut back = vec![0f32; 64];
        add_row(&bytes, &mut back);
        for (a, b) in values.iter().zip(&back) {
            assert!((a - b).abs() < 0.02, "{a} vs {b}");
        }
        let table = MemoryRows(bytes.repeat(3));
        let mut row = vec![0u8; row_bytes(64)];
        table.read(row_bytes(64) as u64 * 2, &mut row).unwrap();
        assert_eq!(row, bytes);
        assert!(table.read(row_bytes(64) as u64 * 3, &mut row).is_err());
    }
}
