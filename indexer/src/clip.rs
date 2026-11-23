//! Photos searched by what is in them: CLIP, with a text side that reads
//! many languages.
//!
//! - **Images:** OpenAI's CLIP ViT-B/32 vision model (Xenova's int8
//!   export). A photo is turned upright, its shortest side scaled to 224
//!   pixels, the middle 224 by 224 cut out, and normalized as CLIP's
//!   preprocessor says.
//! - **Text:** sentence-transformers' clip-ViT-B-32-multilingual-v1, a
//!   multilingual DistilBERT taught to put text where CLIP puts the matching
//!   image (its int8 ONNX export). Its vector is the mean of its last
//!   hidden states over the real tokens, times its `Dense` layer (768 to
//!   512, no bias), made unit length. The ONNX export leaves the layer out,
//!   so it comes as its own file.
//! - Native clients embed images and queries; the web app only queries
//!   (see the web app's `clip.js`), with the same text model.
//! - Files download on first use into `cache_dir()`, each checked against
//!   its SHA-256, as for `embed`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use image::imageops::FilterType;
use ort::session::Session;
use ort::value::Tensor;
use raft5fs_client::indexer::ImageEmbed;
use raft5fs_search::vector::{CLIP_DIMS, CLIP_MODEL, normalize};
use tokenizers::{Tokenizer, TruncationParams};

use crate::embed::{download_url, environment, file_matches};

const TEXT_REPO: &str = "https://huggingface.co/sentence-transformers/clip-ViT-B-32-multilingual-v1/resolve/58edf8cada9e398793dca955574a48cbb7f18be2";
const VISION_REPO: &str = "https://huggingface.co/Xenova/clip-vit-base-patch32/resolve/6b7c523703ae26e39be4b03774966f8571c7f523";

/// Each file: where it comes from, the name it is kept under, its SHA-256.
const FILES: [(&str, &str, &str); 4] = [
    (
        "onnx/model_quint8_avx2.onnx",
        "text.onnx",
        "fbc8fbeaa5237d96bd1bf430057c70d34de8334a463e933a5faa305f6caeed9c",
    ),
    (
        "tokenizer.json",
        "tokenizer.json",
        "5b4e1a8171c81dfd666ae40265b9530c6e0b3d53923fe8ac493dcc84229adf81",
    ),
    (
        "2_Dense/model.safetensors",
        "dense.safetensors",
        "d12568dc7300970a4d3dbb49068ad16cd89b99840b74b026f8e48071e9414f74",
    ),
    (
        "onnx/vision_model_quantized.onnx",
        "vision.onnx",
        "583fd1110a514667812fee7d684952aaf82a99b959760c8d7dca7e0ab9839299",
    ),
];

/// The most tokens the text model reads (sentence-transformers' setting
/// for it).
const MAX_TOKENS: usize = 128;
/// The image size the vision model takes, and how CLIP normalizes pixels.
const SIDE: u32 = 224;
const MEAN: [f32; 3] = [0.481_454_66, 0.457_827_5, 0.408_210_73];
const STD: [f32; 3] = [0.268_629_54, 0.261_302_6, 0.275_777_1];

/// Where these files are kept: beside `embed`'s.
pub fn cache_dir() -> PathBuf {
    crate::embed::cache_dir()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
        .join(CLIP_MODEL)
}

struct Models {
    text: Session,
    vision: Session,
    tokenizer: Tokenizer,
    /// The text side's last layer: 512 rows of 768.
    dense: Vec<f32>,
}

/// The weights of a safetensors file with one F32 tensor of `len` values.
fn read_dense(bytes: &[u8], len: usize) -> Result<Vec<f32>, String> {
    let bad = || "the text model's last layer isn't as expected".to_string();
    let head = u64::from_le_bytes(bytes.get(..8).ok_or_else(bad)?.try_into().unwrap()) as usize;
    let data = bytes.get(8 + head..).ok_or_else(bad)?;
    if data.len() != len * 4 {
        return Err(bad());
    }
    Ok(data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| f32::from_le_bytes(*b))
        .collect())
}

fn load(dir: &Path) -> Result<Models, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    for (file, name, sha) in FILES {
        let path = dir.join(name);
        if !file_matches(&path, sha) {
            let repo = if name == "vision.onnx" {
                VISION_REPO
            } else {
                TEXT_REPO
            };
            download_url(&format!("{repo}/{file}"), &path, sha, CLIP_MODEL)?;
        }
    }
    let mut tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
        .map_err(|e| format!("cannot read the CLIP tokenizer: {e}"))?;
    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: MAX_TOKENS,
            ..TruncationParams::default()
        }))
        .map_err(|e| format!("cannot set up the CLIP tokenizer: {e}"))?;
    tokenizer.with_padding(None);
    let dense = std::fs::read(dir.join("dense.safetensors"))
        .map_err(|e| format!("cannot read the CLIP text model's last layer: {e}"))
        .and_then(|b| read_dense(&b, CLIP_DIMS * 768))?;
    let env = environment()?;
    let threads = std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).clamp(1, 4));
    let session = |file: &str| {
        Session::builder(&env)
            .and_then(|b| Ok(b.with_intra_threads(threads)?))
            .and_then(|mut b| b.commit_from_file(dir.join(file)))
            .map_err(|e| format!("cannot load {CLIP_MODEL}: {e}"))
    };
    Ok(Models {
        text: session("text.onnx")?,
        vision: session("vision.onnx")?,
        tokenizer,
        dense,
    })
}

/// The text side, for `text` alone (no padding, as for `embed`).
fn text_vector(m: &mut Models, text: &str) -> Result<Vec<f32>, String> {
    let fail = |e: ort::Error| format!("{CLIP_MODEL} failed: {e}");
    let enc = m
        .tokenizer
        .encode(text, true)
        .map_err(|e| format!("cannot read the text into tokens: {e}"))?;
    let ids: Vec<i64> = enc.get_ids().iter().map(|&i| i64::from(i)).collect();
    let n = ids.len();
    let shape = [1i64, n as i64];
    let outputs = m
        .text
        .run(ort::inputs![
            "input_ids" => Tensor::from_array((shape, ids)).map_err(fail)?,
            "attention_mask" => Tensor::from_array((shape, vec![1i64; n])).map_err(fail)?,
        ])
        .map_err(fail)?;
    let (_, hidden) = outputs[0].try_extract_tensor::<f32>().map_err(fail)?;
    if hidden.len() != n * 768 {
        return Err(format!("{CLIP_MODEL} gave output of an unexpected shape"));
    }
    let mut mean = vec![0f32; 768];
    for t in 0..n {
        for (m, h) in mean.iter_mut().zip(&hidden[t * 768..(t + 1) * 768]) {
            *m += h / n as f32;
        }
    }
    Ok(project(&m.dense, &mean))
}

/// `x` (768) through the text side's last layer, made unit length.
fn project(dense: &[f32], x: &[f32]) -> Vec<f32> {
    let mut out: Vec<f32> = (0..CLIP_DIMS)
        .map(|j| {
            dense[j * 768..(j + 1) * 768]
                .iter()
                .zip(x)
                .map(|(w, v)| w * v)
                .sum()
        })
        .collect();
    normalize(&mut out);
    out
}

/// A photo as the vision model takes it: upright, its shortest side 224,
/// cut to 224 by 224 in the middle, normalized, channels first.
pub fn pixels(bytes: &[u8], orientation: u16) -> Option<Vec<f32>> {
    let img = std::panic::catch_unwind(|| image::load_from_memory(bytes))
        .ok()?
        .ok()?;
    let img = match orientation {
        2 => img.fliph(),
        3 => img.rotate180(),
        4 => img.flipv(),
        5 => img.rotate90().fliph(),
        6 => img.rotate90(),
        7 => img.rotate270().fliph(),
        8 => img.rotate270(),
        _ => img,
    };
    let (w, h) = (img.width().max(1), img.height().max(1));
    let scale = SIDE as f32 / w.min(h) as f32;
    let (nw, nh) = (
        ((w as f32 * scale).round() as u32).max(SIDE),
        ((h as f32 * scale).round() as u32).max(SIDE),
    );
    let resized = img.resize_exact(nw, nh, FilterType::CatmullRom).to_rgb8();
    let (x0, y0) = ((nw - SIDE) / 2, (nh - SIDE) / 2);
    let side = SIDE as usize;
    let mut out = vec![0f32; 3 * side * side];
    for y in 0..side {
        for x in 0..side {
            let p = resized.get_pixel(x0 + x as u32, y0 + y as u32);
            for c in 0..3 {
                out[c * side * side + y * side + x] = (f32::from(p[c]) / 255.0 - MEAN[c]) / STD[c];
            }
        }
    }
    Some(out)
}

fn image_vector(m: &mut Models, pixels: Vec<f32>) -> Result<Vec<f32>, String> {
    let fail = |e: ort::Error| format!("{CLIP_MODEL} failed: {e}");
    let shape = [1i64, 3, SIDE as i64, SIDE as i64];
    let outputs = m
        .vision
        .run(ort::inputs!["pixel_values" => Tensor::from_array((shape, pixels)).map_err(fail)?])
        .map_err(fail)?;
    let (_, v) = outputs[0].try_extract_tensor::<f32>().map_err(fail)?;
    if v.len() != CLIP_DIMS {
        return Err(format!("{CLIP_MODEL} gave output of an unexpected shape"));
    }
    let mut v = v.to_vec();
    normalize(&mut v);
    Ok(v)
}

/// CLIP, loaded on first use.
pub struct Clip {
    dir: PathBuf,
    models: OnceLock<Result<Arc<Mutex<Models>>, String>>,
}

impl Clip {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            models: OnceLock::new(),
        }
    }

    pub fn cached() -> Self {
        Self::new(cache_dir())
    }

    fn models(&self) -> Result<Arc<Mutex<Models>>, String> {
        self.models
            .get_or_init(|| load(&self.dir).map(|m| Arc::new(Mutex::new(m))))
            .clone()
    }

    /// A query's vector, on this thread.
    pub fn text_now(&self, text: &str) -> Result<Vec<f32>, String> {
        text_vector(&mut self.models()?.lock().unwrap(), text)
    }

    /// A photo's vector, on this thread; `Ok(None)` for a picture this
    /// can't decode.
    pub fn image_now(&self, bytes: &[u8], orientation: u16) -> Result<Option<Vec<f32>>, String> {
        let Some(px) = pixels(bytes, orientation) else {
            return Ok(None);
        };
        image_vector(&mut self.models()?.lock().unwrap(), px).map(Some)
    }
}

/// `Clip` as the indexer's `ImageEmbed`: each call on a blocking thread.
pub struct ImageEmbedder(pub Arc<Clip>);

impl ImageEmbedder {
    pub fn cached() -> Self {
        Self(Arc::new(Clip::cached()))
    }
}

type Boxed<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl ImageEmbed for ImageEmbedder {
    fn model(&self) -> &str {
        CLIP_MODEL
    }

    fn replaces(&self, older: &str) -> bool {
        raft5fs_search::vector::CLIP_REPLACES.contains(&older)
    }

    fn image<'a>(&'a self, bytes: Vec<u8>) -> Boxed<'a, Result<Option<Vec<f32>>, String>> {
        let clip = Arc::clone(&self.0);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let turned = raft5fs_search::extract::photo::photo_info(&bytes).orientation;
                clip.image_now(&bytes, turned)
            })
            .await
            .map_err(|e| format!("{CLIP_MODEL} stopped: {e}"))?
        })
    }

    fn query<'a>(&'a self, text: &'a str) -> Boxed<'a, Result<Vec<f32>, String>> {
        let clip = Arc::clone(&self.0);
        let text = text.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || clip.text_now(&text))
                .await
                .map_err(|e| format!("{CLIP_MODEL} stopped: {e}"))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixels_are_cut_square_and_normalized() {
        let lake = include_bytes!("../../search/src/extract/testdata/lake.jpg");
        let px = pixels(lake, 1).unwrap();
        assert_eq!(px.len(), 3 * 224 * 224);
        // Normalized values sit around zero, within a few units.
        assert!(px.iter().all(|v| v.abs() < 3.0));
        assert!(pixels(b"nope", 1).is_none());
    }

    #[test]
    fn the_last_layer_reads_and_projects() {
        // A layer that keeps the first 512 values: a 512 by 768 identity.
        let mut w = vec![0f32; CLIP_DIMS * 768];
        for j in 0..CLIP_DIMS {
            w[j * 768 + j] = 1.0;
        }
        let mut file = 8u64.to_le_bytes().to_vec();
        file.extend_from_slice(b"{}      ");
        file.extend(w.iter().flat_map(|x| x.to_le_bytes()));
        let dense = read_dense(&file, CLIP_DIMS * 768).unwrap();
        let x: Vec<f32> = (0..768).map(|i| if i == 3 { 2.0 } else { 0.0 }).collect();
        let v = project(&dense, &x);
        assert!((v[3] - 1.0).abs() < 1e-6 && v.iter().filter(|x| **x != 0.0).count() == 1);
        assert!(read_dense(&file[..100], CLIP_DIMS * 768).is_err());
    }

    /// The real models: set RAFT5FS_CLIP_DIR to a folder with their files
    /// (or one to download them into) and run with --ignored.
    #[test]
    #[ignore = "needs the CLIP models (about 225 MB)"]
    fn photos_match_what_they_show_in_any_language() {
        let dir = std::env::var_os("RAFT5FS_CLIP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(cache_dir);
        let clip = Clip::new(dir);
        let pictures: Vec<(&str, &[u8])> = vec![
            ("beach", include_bytes!("../tests/pictures/beach.jpg")),
            ("forest", include_bytes!("../tests/pictures/forest.jpg")),
            ("stop", include_bytes!("../tests/pictures/stop.jpg")),
            ("cake", include_bytes!("../tests/pictures/cake.jpg")),
        ];
        let images: Vec<Vec<f32>> = pictures
            .iter()
            .map(|(_, b)| clip.image_now(b, 1).unwrap().unwrap())
            .collect();
        let queries = [
            ("a sunny beach by the sea", "beach"),
            ("Strand am Meer", "beach"),
            ("trees in a forest", "forest"),
            ("un bosque", "forest"),
            ("a stop sign", "stop"),
            ("birthday cake", "cake"),
        ];
        for (q, want) in queries {
            let v = clip.text_now(q).unwrap();
            let scores: Vec<f32> = images
                .iter()
                .map(|i| i.iter().zip(&v).map(|(a, b)| a * b).sum())
                .collect();
            eprintln!("{q:28} {scores:.3?}");
            let best = scores
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.total_cmp(b.1))
                .unwrap()
                .0;
            assert_eq!(pictures[best].0, want, "{q}: {scores:?}");
        }
    }

    /// Writes what the native text side gives for a few queries, for the
    /// web app's parity test (webapp/tests/parity.test.js). Run again with
    /// --ignored after changing the model.
    #[test]
    #[ignore = "needs the CLIP models (about 225 MB)"]
    fn write_the_web_apps_clip_fixture() {
        let dir = std::env::var_os("RAFT5FS_CLIP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(cache_dir);
        let clip = Clip::new(dir);
        let texts = [
            "a sunny beach by the sea",
            "Strand am Meer",
            "un bosque",
            "東京の夜景",
        ];
        let mut out = format!("{{\n  \"model\": \"{CLIP_MODEL}\",\n  \"cases\": [\n");
        for (i, text) in texts.iter().enumerate() {
            let models = clip.models().unwrap();
            let ids = models
                .lock()
                .unwrap()
                .tokenizer
                .encode(*text, true)
                .unwrap()
                .get_ids()
                .to_vec();
            let v = clip.text_now(text).unwrap();
            let nums: Vec<String> = v.iter().map(|x| format!("{x:.6}")).collect();
            let ids: Vec<String> = ids.iter().map(u32::to_string).collect();
            out.push_str(&format!(
                "    {{ \"text\": {text:?}, \"ids\": [{}], \"vector\": [{}] }}{}\n",
                ids.join(", "),
                nums.join(", "),
                if i + 1 < texts.len() { "," } else { "" }
            ));
        }
        out.push_str("  ]\n}\n");
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../webapp/tests/fixtures/clip-vectors.json"
        );
        std::fs::write(path, out).unwrap();
    }
}
