//! Embeddings on native clients: multilingual-e5-small, run with ONNX
//! Runtime.
//!
//! - **The model** is the int8 export that the web app's transformers.js
//!   also runs, at a pinned revision, so every client gives the same
//!   vectors. It downloads on first use into `cache_dir()`, and each file
//!   is checked against its SHA-256 before it is used.
//! - **e5** wants "passage: " before text that is searched and "query: "
//!   before a query. Its vector is the mean of the last hidden states over
//!   the real tokens (not padding), made unit length.
//! - **One text at a time.** The int8 export scales each run's values as a
//!   whole, so a text batched with others gets a slightly different vector
//!   (cosine about 0.997). Alone, a text gets the same vector on every
//!   client, whatever else it is indexed with.
//! - **Work** runs on a blocking thread: one inference takes tens of
//!   milliseconds of CPU, and the runtime must not stall the device's own
//!   requests.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ort::session::Session;
use ort::value::Tensor;
use raft5fs_client::indexer::Embed;
use raft5fs_search::vector::normalize;
use sha2::{Digest, Sha256};
use tokenizers::{PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

/// The name records give this model's vectors. A new revision or export
/// needs a new name: vectors from two exports must not be compared.
pub const MODEL: &str = "multilingual-e5-small-int8@761b726";

const REPO: &str = "https://huggingface.co/Xenova/multilingual-e5-small/resolve";
const REVISION: &str = "761b726dd34fb83930e26aab4e9ac3899aa1fa78";

/// Each file of the model: where it is in the repository, the name it is
/// kept under here, and its SHA-256.
const FILES: [(&str, &str, &str); 2] = [
    (
        "onnx/model_quantized.onnx",
        "model.onnx",
        "f80102d3f2a1229f387d3c81909990d8945513e347b0eab049f7de3c6f98c193",
    ),
    (
        "tokenizer.json",
        "tokenizer.json",
        "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
    ),
];

/// The most tokens the model reads of one text; the rest is cut.
const MAX_TOKENS: usize = 512;

/// Where models are kept: `$XDG_CACHE_HOME/raft5fs/models`, or
/// `~/.cache/raft5fs/models`.
pub fn cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("raft5fs").join("models").join(MODEL)
}

struct Model {
    session: Session,
    tokenizer: Tokenizer,
    /// Whether the export also takes `token_type_ids`.
    token_types: bool,
}

/// multilingual-e5-small, loaded on first use.
pub struct E5 {
    dir: PathBuf,
    model: OnceLock<Result<Arc<Mutex<Model>>, String>>,
}

impl E5 {
    /// The model kept in `dir` (downloaded there if it isn't).
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            model: OnceLock::new(),
        }
    }

    /// The model in `cache_dir()`.
    pub fn cached() -> Self {
        Self::new(cache_dir())
    }

    /// Whether the model's files are here already, so that using it
    /// downloads nothing.
    pub fn is_downloaded(&self) -> bool {
        FILES
            .iter()
            .all(|(_, name, sha)| file_matches(&self.dir.join(name), sha))
    }

    fn loaded(&self) -> Result<Arc<Mutex<Model>>, String> {
        self.model
            .get_or_init(|| load(&self.dir).map(|m| Arc::new(Mutex::new(m))))
            .clone()
    }

    /// Embeds `texts`, each after `prefix`, on this thread, one at a time.
    pub fn embed_now(&self, prefix: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let model = self.loaded()?;
        let mut model = model.lock().unwrap();
        let mut out = Vec::with_capacity(texts.len());
        for text in texts {
            out.extend(run(&mut model, prefix, std::slice::from_ref(text))?);
        }
        Ok(out)
    }
}

fn file_matches(path: &Path, sha: &str) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return false,
        }
    }
    raft5fs_wire_hex(&hasher.finalize()) == sha
}

fn raft5fs_wire_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Downloads `file` of the model to `to`, checking it as it comes. Written
/// beside it first, then renamed, so a cut download is never used.
fn download(file: &str, to: &Path, sha: &str) -> Result<(), String> {
    let url = format!("{REPO}/{REVISION}/{file}");
    eprintln!("search: downloading {file} of {MODEL} (once)");
    let mut body = ureq::get(&url)
        .call()
        .map_err(|e| format!("cannot download {url}: {e}"))?
        .into_body();
    let temp = to.with_extension("part");
    let mut out = std::fs::File::create(&temp)
        .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    let mut hasher = Sha256::new();
    let mut reader = body.as_reader();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("download of {file} cut short: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut out, &buf[..n])
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    }
    if raft5fs_wire_hex(&hasher.finalize()) != sha {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("{file} of {MODEL} isn't the file it should be"));
    }
    std::fs::rename(&temp, to).map_err(|e| format!("cannot keep {}: {e}", to.display()))
}

fn load(dir: &Path) -> Result<Model, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    for (file, name, sha) in FILES {
        let path = dir.join(name);
        if !file_matches(&path, sha) {
            download(file, &path, sha)?;
        }
    }
    let mut tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
        .map_err(|e| format!("cannot read the model's tokenizer: {e}"))?;
    let pad_id = tokenizer.token_to_id("<pad>").unwrap_or(1);
    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: MAX_TOKENS,
            ..TruncationParams::default()
        }))
        .map_err(|e| format!("cannot set up the model's tokenizer: {e}"))?;
    tokenizer.with_padding(Some(PaddingParams {
        strategy: PaddingStrategy::BatchLongest,
        pad_id,
        pad_token: "<pad>".into(),
        ..PaddingParams::default()
    }));
    let env = ort::init()
        .with_name("raft5fs")
        .build()
        .map_err(|e| format!("cannot start ONNX Runtime: {e}"))?;
    // Half the cores, at most four: indexing runs behind the device's
    // own work.
    let threads = std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).clamp(1, 4));
    let session = Session::builder(&env)
        .and_then(|b| Ok(b.with_intra_threads(threads)?))
        .and_then(|mut b| b.commit_from_file(dir.join("model.onnx")))
        .map_err(|e| format!("cannot load {MODEL}: {e}"))?;
    let token_types = session
        .inputs()
        .iter()
        .any(|i| i.name() == "token_type_ids");
    Ok(Model {
        session,
        tokenizer,
        token_types,
    })
}

fn run(model: &mut Model, prefix: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
    if texts.is_empty() {
        return Ok(Vec::new());
    }
    let inputs: Vec<String> = texts.iter().map(|t| format!("{prefix}{t}")).collect();
    let encodings = model
        .tokenizer
        .encode_batch(inputs, true)
        .map_err(|e| format!("cannot read the text into tokens: {e}"))?;
    let batch = encodings.len();
    let len = encodings[0].get_ids().len();
    let mut ids = Vec::with_capacity(batch * len);
    let mut mask = Vec::with_capacity(batch * len);
    for e in &encodings {
        ids.extend(e.get_ids().iter().map(|&i| i64::from(i)));
        mask.extend(e.get_attention_mask().iter().map(|&m| i64::from(m)));
    }
    let shape = [batch as i64, len as i64];
    let fail = |e: ort::Error| format!("{MODEL} failed: {e}");
    let ids_t = Tensor::from_array((shape, ids)).map_err(fail)?;
    let mask_t = Tensor::from_array((shape, mask.clone())).map_err(fail)?;
    let outputs = if model.token_types {
        let types = Tensor::from_array((shape, vec![0i64; batch * len])).map_err(fail)?;
        model.session.run(ort::inputs![
            "input_ids" => ids_t,
            "attention_mask" => mask_t,
            "token_type_ids" => types,
        ])
    } else {
        model.session.run(ort::inputs![
            "input_ids" => ids_t,
            "attention_mask" => mask_t,
        ])
    }
    .map_err(fail)?;
    let (out_shape, hidden) = outputs[0].try_extract_tensor::<f32>().map_err(fail)?;
    let dims = *out_shape.last().unwrap_or(&0) as usize;
    if dims == 0 || hidden.len() != batch * len * dims {
        return Err(format!("{MODEL} gave output of an unexpected shape"));
    }
    Ok(mean_pool(hidden, &mask, batch, len, dims))
}

/// The mean of each text's hidden states over its real tokens, made unit
/// length.
fn mean_pool(hidden: &[f32], mask: &[i64], batch: usize, len: usize, dims: usize) -> Vec<Vec<f32>> {
    (0..batch)
        .map(|b| {
            let mut sum = vec![0f32; dims];
            let mut count = 0f32;
            for t in 0..len {
                if mask[b * len + t] == 0 {
                    continue;
                }
                count += 1.0;
                let at = (b * len + t) * dims;
                for (s, h) in sum.iter_mut().zip(&hidden[at..at + dims]) {
                    *s += h;
                }
            }
            if count > 0.0 {
                sum.iter_mut().for_each(|s| *s /= count);
            }
            normalize(&mut sum);
            sum
        })
        .collect()
}

/// `E5` as the indexer's `Embed`: each call on a blocking thread.
pub struct Embedder(pub Arc<E5>);

impl Embedder {
    pub fn cached() -> Self {
        Self(Arc::new(E5::cached()))
    }
}

type Boxed<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

async fn blocking(
    e5: Arc<E5>,
    prefix: &'static str,
    texts: Vec<String>,
) -> Result<Vec<Vec<f32>>, String> {
    tokio::task::spawn_blocking(move || e5.embed_now(prefix, &texts))
        .await
        .map_err(|e| format!("{MODEL} stopped: {e}"))?
}

impl Embed for Embedder {
    fn model(&self) -> &str {
        MODEL
    }

    fn passages<'a>(&'a self, texts: Vec<String>) -> Boxed<'a, Result<Vec<Vec<f32>>, String>> {
        Box::pin(blocking(Arc::clone(&self.0), "passage: ", texts))
    }

    fn query<'a>(&'a self, text: &'a str) -> Boxed<'a, Result<Vec<f32>, String>> {
        let text = text.to_string();
        Box::pin(async move {
            let mut v = blocking(Arc::clone(&self.0), "query: ", vec![text]).await?;
            v.pop().ok_or_else(|| format!("{MODEL} gave no vector"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooling_skips_padding_and_makes_unit_vectors() {
        // Two texts of two tokens; the second's second token is padding.
        let hidden = [1.0, 0.0, 3.0, 0.0, 0.0, 2.0, 9.0, 9.0];
        let mask = [1, 1, 1, 0];
        let v = mean_pool(&hidden, &mask, 2, 2, 2);
        assert_eq!(v[0], [1.0, 0.0]);
        let len: f32 = v[1].iter().map(|x| x * x).sum();
        assert!((len - 1.0).abs() < 1e-6);
        assert!((v[1][1] - 1.0).abs() < 1e-6, "padding left out: {:?}", v[1]);
    }

    #[test]
    fn a_file_must_match_its_hash() {
        let dir = std::env::temp_dir().join(format!("raft5fs-embed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        std::fs::write(&path, b"abc").unwrap();
        let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(file_matches(&path, sha));
        assert!(!file_matches(&path, &"0".repeat(64)));
        assert!(!file_matches(&dir.join("none"), sha));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The real model: set RAFT5FS_MODEL_DIR to a folder with its files (or
    /// one to download them into) and run with --ignored.
    #[test]
    #[ignore = "needs the model (about 135 MB)"]
    fn the_model_puts_like_meanings_close_in_any_language() {
        let dir = std::env::var_os("RAFT5FS_MODEL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(cache_dir);
        let e5 = E5::new(dir);
        let passages: Vec<String> = [
            "We rode our bikes on gravel roads through Vermont last summer.",
            "Wir sind letzten Sommer mit dem Fahrrad durch Vermont gefahren.",
            "The tax return is due in April; keep the receipts.",
            "Recipe: whisk the eggs, then fold in the flour.",
        ]
        .map(String::from)
        .to_vec();
        let p = e5.embed_now("passage: ", &passages).unwrap();
        let q = e5
            .embed_now("query: ", &["bike routes in vermont".into()])
            .unwrap()
            .remove(0);
        let cos = |a: &[f32]| a.iter().zip(&q).map(|(x, y)| x * y).sum::<f32>();
        let scores: Vec<f32> = p.iter().map(|v| cos(v)).collect();
        eprintln!("cosines: {scores:?}");
        assert_eq!(p[0].len(), 384);
        let floor = raft5fs_search::view::MIN_SIMILARITY;
        assert!(scores[0] >= floor && scores[1] >= floor, "{scores:?}");
        assert!(scores[2] < floor && scores[3] < floor, "{scores:?}");
        // The same text gives the same vector, batched or not.
        let alone = e5.embed_now("passage: ", &passages[..1]).unwrap();
        let same: f32 = alone[0].iter().zip(&p[0]).map(|(x, y)| x * y).sum();
        assert!(same > 0.99999, "{same}");
    }
}
