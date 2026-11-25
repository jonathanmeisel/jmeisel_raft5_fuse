//! Photos searched by what is in them: CLIP ViT-B/32, with a text side
//! that reads many languages, on candle (raft5fs-embed).
//!
//! - **Images:** a photo is turned upright, its shortest side scaled to 224
//!   pixels, the middle 224 by 224 cut out, and normalized as CLIP's
//!   preprocessor says (`pixels`); raft5fs-embed's `Vision` gives its
//!   vector. Native clients only: the web app doesn't make image vectors.
//! - **Text:** the multilingual text side (DistilBERT, its `Dense` layer),
//!   as the web app runs it, kept Q8_0: here it embeds only queries.
//! - Files download on first use into `cache_dir()`, each checked against
//!   its SHA-256, as `search/data/models.json` pins them (see `manifest`).

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use image::imageops::FilterType;
use raft5fs_client::indexer::ImageEmbed;
use raft5fs_embed::{SIDE, TextModel, Vision};
use raft5fs_search::vector::CLIP_MODEL;

const SIDE_PX: u32 = SIDE as u32;
const MEAN: [f32; 3] = [0.481_454_66, 0.457_827_5, 0.408_210_73];
const STD: [f32; 3] = [0.268_629_54, 0.261_302_6, 0.275_777_1];

/// Where these files are kept: beside `embed`'s.
pub fn cache_dir() -> PathBuf {
    crate::embed::models_dir().join(CLIP_MODEL)
}

struct Models {
    text: TextModel,
    vision: Vision,
}

fn load(dir: &Path) -> Result<Models, String> {
    let text = crate::embed::load_text(dir, "clip", false)?;
    let manifest = crate::manifest::model("clip");
    let path = dir.join(&manifest.file("vision").local);
    let mut body = File::open(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let vision = Vision::load(&mut body).map_err(|e| format!("cannot load {CLIP_MODEL}: {e}"))?;
    Ok(Models { text, vision })
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
    let scale = SIDE_PX as f32 / w.min(h) as f32;
    let (nw, nh) = (
        ((w as f32 * scale).round() as u32).max(SIDE_PX),
        ((h as f32 * scale).round() as u32).max(SIDE_PX),
    );
    let resized = img.resize_exact(nw, nh, FilterType::CatmullRom).to_rgb8();
    let (x0, y0) = ((nw - SIDE_PX) / 2, (nh - SIDE_PX) / 2);
    let side = SIDE;
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

/// CLIP, loaded on first use.
pub struct Clip {
    dir: PathBuf,
    models: OnceLock<Result<Arc<Models>, String>>,
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

    fn models(&self) -> Result<Arc<Models>, String> {
        self.models
            .get_or_init(|| load(&self.dir).map(Arc::new))
            .clone()
    }

    /// A query's vector, on this thread.
    pub fn text_now(&self, text: &str) -> Result<Vec<f32>, String> {
        let m = self.models()?;
        let mut v = m
            .text
            .embed(&[text])
            .map_err(|e| format!("{CLIP_MODEL} failed: {e}"))?;
        Ok(v.remove(0))
    }

    /// The token ids the text side reads for `text`.
    pub fn text_ids(&self, text: &str) -> Result<Vec<u32>, String> {
        Ok(self.models()?.text.ids(text))
    }

    /// A photo's vector, on this thread; `Ok(None)` for a picture this
    /// can't decode.
    pub fn image_now(&self, bytes: &[u8], orientation: u16) -> Result<Option<Vec<f32>>, String> {
        let Some(px) = pixels(bytes, orientation) else {
            return Ok(None);
        };
        let m = self.models()?;
        m.vision
            .embed(px)
            .map(Some)
            .map_err(|e| format!("{CLIP_MODEL} failed: {e}"))
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

    fn clip_dir() -> PathBuf {
        std::env::var_os("RAFT5FS_CLIP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(cache_dir)
    }

    /// The real models: set RAFT5FS_CLIP_DIR to a folder with their files
    /// (or one to download them into) and run with --ignored.
    #[test]
    #[ignore = "needs the CLIP models (about 250 MB)"]
    fn photos_match_what_they_show_in_any_language() {
        let clip = Clip::new(clip_dir());
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
            ("pastel de cumpleaños", "cake"),
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

    /// Writes what the text side gives for a few queries, for the web
    /// app's parity test (webapp/tests/parity.test.js). Run again with
    /// --ignored after changing the model.
    #[test]
    #[ignore = "needs the CLIP models (about 250 MB)"]
    fn write_the_web_apps_clip_fixture() {
        let clip = Clip::new(clip_dir());
        let texts = [
            "a sunny beach by the sea",
            "Strand am Meer",
            "un bosque",
            "東京の夜景",
        ];
        let mut out = format!("{{\n  \"model\": \"{CLIP_MODEL}\",\n  \"cases\": [\n");
        for (i, text) in texts.iter().enumerate() {
            let ids = clip.text_ids(text).unwrap();
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
