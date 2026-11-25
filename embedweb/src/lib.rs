//! The search models in the browser: raft5fs-embed's `TextModel`, for the
//! embed Worker (`embedWorker.js`), as its own WebAssembly module. Builds
//! only for wasm32; elsewhere it is empty.
//!
//! - **The body** stays a JS `Uint8Array`: it is read a piece at a time,
//!   so this module's memory holds the model once, not its file as well.
//! - **The word table** stays in OPFS: for each text the Worker asks which
//!   rows it needs (`rowIds`), reads them, and passes them to `embed`. No
//!   sync access handle, so tabs don't lock each other out of the file.
//! - Built with SIMD (`+simd128`, `webapp/scripts/build-wasm.sh`):
//!   candle picks its fast WebAssembly kernels when it is compiled.

#[cfg(target_arch = "wasm32")]
mod web {
    use std::io::{Read, Seek, SeekFrom};

    use js_sys::{Float32Array, Uint8Array};
    use raft5fs_embed::{GivenRows, NoRows, Pooling, TextModel, TextOptions};
    use sha2::Digest;
    use wasm_bindgen::prelude::*;

    /// A JS `Uint8Array`, read a piece at a time.
    struct JsBytes {
        bytes: Uint8Array,
        at: u64,
    }

    impl Read for JsBytes {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let len = u64::from(self.bytes.length());
            let n = (len.saturating_sub(self.at)).min(buf.len() as u64) as usize;
            if n > 0 {
                let start = self.at as u32;
                self.bytes
                    .subarray(start, start + n as u32)
                    .copy_to(&mut buf[..n]);
                self.at += n as u64;
            }
            Ok(n)
        }
    }

    impl Seek for JsBytes {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            let len = i64::from(self.bytes.length());
            let at = match pos {
                SeekFrom::Start(n) => n as i64,
                SeekFrom::End(n) => len + n,
                SeekFrom::Current(n) => self.at as i64 + n,
            };
            if at < 0 {
                return Err(std::io::Error::other("seek before the start"));
            }
            self.at = at as u64;
            Ok(self.at)
        }
    }

    fn failure(e: raft5fs_embed::Error) -> JsError {
        JsError::new(&e.0)
    }

    /// A text model, ready to embed queries.
    #[wasm_bindgen]
    pub struct Model(TextModel);

    #[wasm_bindgen]
    impl Model {
        /// `body`: `body.gguf`'s bytes; `tokenizer`: `tokenizer.bin`'s;
        /// `pooling`: "cls" or "mean"; `max_tokens`: the most it reads
        /// (models.json).
        #[wasm_bindgen(constructor)]
        pub fn new(
            body: Uint8Array,
            tokenizer: &[u8],
            pooling: &str,
            max_tokens: usize,
        ) -> Result<Model, JsError> {
            let options = TextOptions {
                pooling: Pooling::parse(pooling).map_err(failure)?,
                max_tokens,
                dense: false,
            };
            let mut body = JsBytes { bytes: body, at: 0 };
            let model = TextModel::load(&mut body, tokenizer, Box::new(NoRows), options)
                .map_err(failure)?;
            Ok(Model(model))
        }

        /// The token ids the model reads for `text`.
        pub fn ids(&self, text: &str) -> Vec<u32> {
            self.0.ids(text)
        }

        /// The rows of the word table `text` needs, by id, sorted, each
        /// once: read `rowBytes()` bytes at `id × rowBytes()` for each.
        #[wasm_bindgen(js_name = rowIds)]
        pub fn row_ids(&self, text: &str) -> Vec<u32> {
            let mut ids = self.0.ids(text);
            ids.sort_unstable();
            ids.dedup();
            ids
        }

        #[wasm_bindgen(js_name = rowBytes)]
        pub fn row_bytes(&self) -> usize {
            self.0.row_bytes()
        }

        /// The unit vector of `text` (with what goes before it already),
        /// given `rows`: the rows `rowIds(text)` names, one after another.
        pub fn embed(
            &self,
            text: &str,
            ids: Vec<u32>,
            rows: Vec<u8>,
        ) -> Result<Float32Array, JsError> {
            let given = GivenRows {
                ids,
                bytes: rows,
                row: self.0.row_bytes(),
            };
            let v = self
                .0
                .embed_with(&[text], &given)
                .map_err(failure)?
                .remove(0);
            Ok(Float32Array::from(v.as_slice()))
        }
    }

    /// SHA-256, a piece at a time.
    #[wasm_bindgen]
    pub struct Sha256(sha2::Sha256);

    #[wasm_bindgen]
    impl Sha256 {
        #[wasm_bindgen(constructor)]
        #[allow(clippy::new_without_default)]
        pub fn new() -> Sha256 {
            Sha256(sha2::Sha256::new())
        }

        pub fn update(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }

        /// The hash, in hex.
        pub fn hex(self) -> String {
            self.0
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }
    }

    /// Bytes of WebAssembly memory this module holds, for measuring.
    #[wasm_bindgen(js_name = memoryBytes)]
    pub fn memory_bytes() -> f64 {
        let mem: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
        let buf: js_sys::ArrayBuffer = mem.buffer().unchecked_into();
        f64::from(buf.byte_length())
    }
}
