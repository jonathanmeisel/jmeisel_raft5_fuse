//! Embeddings on native clients: the text model (multilingual-e5-small),
//! on candle (raft5fs-embed), as the web app runs it.
//!
//! - **The model** is the converted files `search/data/models.json` pins
//!   (see `manifest`): a body, a word table and a tokenizer. They download
//!   on first use into `cache_dir()`, and each is checked against its
//!   SHA-256 before it is used. The word table is mapped, not read: the
//!   system brings in the rows used.
//! - **Weights as f32.** The body is Q8_0, as the browser runs it; here its
//!   weights are made f32 when it loads, where candle multiplies batches
//!   of passages several times faster. The vectors stay within cosine
//!   0.9999 of the browser's.
//! - **What goes before a text** ("passage: ", "query: ") and how the
//!   vector is pooled come from models.json.
//! - **Passages run in batches** of about the same length
//!   (`TextModel::embed_batched`), on a blocking thread: the device's own
//!   requests mustn't wait for the model.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use raft5fs_client::indexer::Embed;
use raft5fs_embed::{MappedRows, Pooling, TextOptions};
use sha2::{Digest, Sha256};

/// The name records give this model's vectors (models.json's).
pub const MODEL: &str = raft5fs_search::vector::TEXT_MODEL;

/// Where models are kept: `$XDG_CACHE_HOME/raft5fs/models`, or
/// `~/.cache/raft5fs/models`; this model's files in a folder named by it.
pub fn cache_dir() -> PathBuf {
    models_dir().join(MODEL)
}

/// The folder every model's folder is in.
pub fn models_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("raft5fs").join("models")
}

/// A text model of models.json (`key`) from the files in `dir`,
/// downloaded there first if they aren't. With `dense`, its weights are
/// made f32 (see the top of this module).
pub(crate) fn load_text(
    dir: &Path,
    key: &str,
    dense: bool,
) -> Result<raft5fs_embed::TextModel, String> {
    let m = crate::manifest::model(key);
    m.fetch(dir)?;
    let at = |role: &str| dir.join(&m.file(role).local);
    let mut body = File::open(at("body")).map_err(|e| format!("cannot open {}: {e}", m.name))?;
    let tokenizer = std::fs::read(at("tokenizer"))
        .map_err(|e| format!("cannot read {}'s tokenizer: {e}", m.name))?;
    let rows = MappedRows::open(&at("table")).map_err(|e| e.0)?;
    let options = TextOptions {
        pooling: Pooling::parse(&m.pooling).map_err(|e| e.0)?,
        max_tokens: m.max_tokens,
        dense,
    };
    raft5fs_embed::TextModel::load(&mut body, &tokenizer, Box::new(rows), options)
        .map_err(|e| format!("cannot load {}: {e}", m.name))
}

/// The text model, loaded on first use.
pub struct TextModel {
    dir: PathBuf,
    model: OnceLock<Result<Arc<raft5fs_embed::TextModel>, String>>,
}

impl TextModel {
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
        crate::manifest::model("text").is_in(&self.dir)
    }

    fn loaded(&self) -> Result<Arc<raft5fs_embed::TextModel>, String> {
        self.model
            .get_or_init(|| load_text(&self.dir, "text", true).map(Arc::new))
            .clone()
    }

    /// Embeds `texts`, each after `prefix`, on this thread, in batches of
    /// about the same length.
    pub fn embed_now(&self, prefix: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let model = self.loaded()?;
        let inputs: Vec<String> = texts.iter().map(|t| format!("{prefix}{t}")).collect();
        let refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
        model
            .embed_batched(&refs)
            .map_err(|e| format!("{MODEL} failed: {e}"))
    }

    /// The token ids the model reads for `text` (with its prefix already).
    pub fn ids(&self, text: &str) -> Result<Vec<u32>, String> {
        Ok(self.loaded()?.ids(text))
    }
}

pub(crate) fn file_matches(path: &Path, sha: &str) -> bool {
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
    hex(&hasher.finalize()) == sha
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Downloads `url` to `to`, checking it as it comes against `sha`. Written
/// beside it first, then renamed, so a cut download is never used. `model`
/// names what it is part of, for messages.
pub(crate) fn download_url(url: &str, to: &Path, sha: &str, model: &str) -> Result<(), String> {
    let file = url.rsplit('/').next().unwrap_or(url);
    eprintln!("search: downloading {file} of {model} (once)");
    let mut body = ureq::get(url)
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
    if hex(&hasher.finalize()) != sha {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("{file} of {model} isn't the file it should be"));
    }
    std::fs::rename(&temp, to).map_err(|e| format!("cannot keep {}: {e}", to.display()))
}

/// What goes before a query, as models.json says.
pub fn query_prefix() -> &'static str {
    &crate::manifest::model("text").query
}

/// What goes before a passage, as models.json says.
pub fn passage_prefix() -> &'static str {
    &crate::manifest::model("text").passage
}

/// `TextModel` as the indexer's `Embed`: each call on a blocking thread.
pub struct Embedder(pub Arc<TextModel>);

impl Embedder {
    pub fn cached() -> Self {
        Self(Arc::new(TextModel::cached()))
    }
}

type Boxed<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

async fn blocking(
    model: Arc<TextModel>,
    prefix: &'static str,
    texts: Vec<String>,
) -> Result<Vec<Vec<f32>>, String> {
    tokio::task::spawn_blocking(move || model.embed_now(prefix, &texts))
        .await
        .map_err(|e| format!("{MODEL} stopped: {e}"))?
}

impl Embed for Embedder {
    fn model(&self) -> &str {
        MODEL
    }

    fn replaces(&self, older: &str) -> bool {
        raft5fs_search::vector::TEXT_REPLACES.contains(&older)
    }

    fn passages<'a>(&'a self, texts: Vec<String>) -> Boxed<'a, Result<Vec<Vec<f32>>, String>> {
        Box::pin(blocking(Arc::clone(&self.0), passage_prefix(), texts))
    }

    fn query<'a>(&'a self, text: &'a str) -> Boxed<'a, Result<Vec<f32>, String>> {
        let text = text.to_string();
        Box::pin(async move {
            let mut v = blocking(Arc::clone(&self.0), query_prefix(), vec![text]).await?;
            v.pop().ok_or_else(|| format!("{MODEL} gave no vector"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn model_dir() -> PathBuf {
        std::env::var_os("RAFT5FS_MODEL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(cache_dir)
    }

    /// Writes what the model gives for a few texts, with the browser's
    /// Q8_0 weights, for the web app's parity test
    /// (webapp/tests/parity.test.js) to check its own against. Run again
    /// with --ignored after changing the model.
    #[test]
    #[ignore = "needs the model (about 130 MB)"]
    fn write_the_web_apps_parity_fixture() {
        let model = load_text(&model_dir(), "text", false).unwrap();
        let (p, q) = (passage_prefix(), query_prefix());
        let texts = [
            format!("{p}We rode our bikes on gravel roads through Vermont last summer."),
            format!("{p}La declaración de la renta vence en abril: guarda los recibos."),
            format!("{p}Die Steuererklärung ist im April fällig; die Belege aufheben."),
            format!("{q}rutas en bicicleta por Vermont"),
        ];
        let mut out = format!("{{\n  \"model\": \"{MODEL}\",\n  \"cases\": [\n");
        for (i, text) in texts.iter().enumerate() {
            let ids = model.ids(text);
            let v = model.embed(&[text.as_str()]).unwrap().remove(0);
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
            "/../webapp/tests/fixtures/text-vectors.json"
        );
        std::fs::write(path, out).unwrap();
    }

    /// Topics, each with passages on it, and queries that should find
    /// them with few or no words in common, in English, Spanish and
    /// German.
    const TOPICS: &[(&[&str], &[&str])] = &[
        (
            &[
                "We rode our bikes on gravel roads through Vermont last summer.",
                "El tercer día: 80 km de subida en bicicleta y luego un largo descenso hasta el lago.",
            ],
            &["bike routes in vermont", "viaje en bicicleta", "Radtour"],
        ),
        (
            &[
                "The tax return is due in April; keep the receipts.",
                "La declaración de la renta vence en abril: guarda los recibos.",
            ],
            &[
                "paperwork for filing income taxes",
                "impuestos",
                "Steuerunterlagen",
            ],
        ),
        (
            &[
                "Whisk the eggs, then fold in the flour, and bake for 30 minutes.",
                "Tarta de manzana de la abuela: mantequilla, azúcar, canela y la masa del día anterior.",
            ],
            &["dessert recipe", "cómo hacer un pastel", "Kuchenrezept"],
        ),
        (
            &[
                "The car needs new brake pads and an oil change before the trip.",
                "Die Reifendruckwarnung ging wieder an; die Werkstatt hat die Ventile geprüft.",
            ],
            &["vehicle maintenance", "taller mecánico", "Autoreparatur"],
        ),
        (
            &[
                "Meeting notes: the quarterly budget is over by 12%, and hiring is paused.",
                "Acta de la reunión: terminar las diapositivas para la junta y enviar la previsión.",
            ],
            &[
                "notes from the staff meeting",
                "reunión de trabajo",
                "Besprechungsprotokoll",
            ],
        ),
        (
            &[
                "The doctor said to rest the knee for two weeks and take ibuprofen.",
                "Los análisis de sangre salieron normales; próxima revisión en seis meses.",
            ],
            &["medical appointment", "cita con el médico", "Arzttermin"],
        ),
    ];

    /// The real model: what a match and a miss score, to set models.json's
    /// `search` numbers by (see raft5fs-search's `view`). Run with --ignored
    /// --nocapture.
    #[test]
    #[ignore = "needs the model (about 130 MB)"]
    fn the_model_puts_like_meanings_close() {
        let model = TextModel::new(model_dir());
        let mut passages = Vec::new();
        let mut topic_of = Vec::new();
        for (t, (ps, _)) in TOPICS.iter().enumerate() {
            passages.extend(ps.iter().map(|p| p.to_string()));
            topic_of.extend(ps.iter().map(|_| t));
        }
        let p = model.embed_now(passage_prefix(), &passages).unwrap();
        assert_eq!(p[0].len(), raft5fs_search::vector::TEXT_DIMS);
        let (mut worst_match, mut best_miss) = (f32::MAX, f32::MIN);
        let (mut first, mut asked) = (0, 0);
        for (t, (_, queries)) in TOPICS.iter().enumerate() {
            for q in *queries {
                let qv = model
                    .embed_now(query_prefix(), &[q.to_string()])
                    .unwrap()
                    .remove(0);
                let scores: Vec<f32> = p
                    .iter()
                    .map(|v| v.iter().zip(&qv).map(|(a, b)| a * b).sum())
                    .collect();
                let n = scores.len() as f32;
                let mean = scores.iter().sum::<f32>() / n;
                let sd = (scores.iter().map(|s| (s - mean) * (s - mean)).sum::<f32>() / n).sqrt();
                let best_hit = (0..p.len())
                    .filter(|&i| topic_of[i] == t)
                    .map(|i| scores[i])
                    .fold(f32::MIN, f32::max);
                let top_miss = (0..p.len())
                    .filter(|&i| topic_of[i] != t)
                    .map(|i| scores[i])
                    .fold(f32::MIN, f32::max);
                eprintln!(
                    "{q:36} best match {best_hit:.3} (z {:.1}), best miss {top_miss:.3} (z {:.1})",
                    (best_hit - mean) / sd,
                    (top_miss - mean) / sd
                );
                worst_match = worst_match.min(best_hit);
                best_miss = best_miss.max(top_miss);
                asked += 1;
                if best_hit > top_miss {
                    first += 1;
                }
            }
        }
        eprintln!(
            "matches from {worst_match:.3}, misses up to {best_miss:.3}; {first} of {asked} queries rank a match first"
        );
        // Short queries in another language than their match can lose to
        // a miss in their own language: multilingual-e5-small leans to
        // language over subject (12 of these 18 rank a match first). This
        // is for calibrating; the meaning tests check search end to end.
        assert!(first * 3 >= asked * 2, "{first} of {asked}");
        // The same text gives about the same vector, batched or not.
        let alone = model.embed_now(passage_prefix(), &passages[..1]).unwrap();
        let same: f32 = alone[0].iter().zip(&p[0]).map(|(x, y)| x * y).sum();
        assert!(same > 0.9995, "{same}");
    }
}
