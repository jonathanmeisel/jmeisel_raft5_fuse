//! The models search uses, as `search/data/models.json` pins them: the one
//! place a model is changed (see raft5fs-search's `vector`). Built into
//! native clients; the web app reads the same file.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::embed::{download_url, file_matches};

static MODELS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../search/data/models.json"
));

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub models: HashMap<String, Model>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Model {
    /// The name records give its vectors (`vector::TEXT_MODEL`, ...).
    pub name: String,
    /// What goes before a query, and before a passage.
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub passage: String,
    /// How its vector is pooled ("cls", "mean"), and the most tokens of a
    /// text it reads (native models; the web app's ONNX exports have none).
    #[serde(default)]
    pub pooling: String,
    #[serde(default)]
    pub max_tokens: usize,
    pub files: Vec<File>,
}

#[derive(Debug, Deserialize)]
pub struct File {
    /// What the file is to the model: "model", "tokenizer", ...
    pub role: String,
    /// The name it is kept under.
    pub local: String,
    /// Where it comes from, at a pinned revision.
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// "native", "web": the clients that use it.
    pub clients: Vec<String>,
}

/// The manifest, read the first time it is asked for.
pub fn manifest() -> &'static Manifest {
    static MANIFEST: OnceLock<Manifest> = OnceLock::new();
    MANIFEST.get_or_init(|| serde_json::from_str(MODELS_JSON).expect("models.json reads"))
}

/// Model `key` ("text", "clip").
pub fn model(key: &str) -> &'static Model {
    manifest()
        .models
        .get(key)
        .unwrap_or_else(|| panic!("models.json has no model {key}"))
}

impl Model {
    /// The files native clients use.
    pub fn native(&self) -> impl Iterator<Item = &File> {
        self.files
            .iter()
            .filter(|f| f.clients.iter().any(|c| c == "native"))
    }

    /// The file native clients use for `role`.
    pub fn file(&self, role: &str) -> &File {
        self.native()
            .find(|f| f.role == role)
            .unwrap_or_else(|| panic!("{} has no {role} for native clients", self.name))
    }

    /// Whether every native file is in `dir`, checked, so loading the
    /// model downloads nothing.
    pub fn is_in(&self, dir: &Path) -> bool {
        self.native()
            .all(|f| file_matches(&dir.join(&f.local), &f.sha256))
    }

    /// Puts every native file in `dir`: downloads each one that isn't there,
    /// or isn't the file it should be.
    pub fn fetch(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
        for f in self.native() {
            let path = dir.join(&f.local);
            if !file_matches(&path, &f.sha256) {
                download_url(&f.url, &path, &f.sha256, &self.name)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raft5fs_embed::Pooling;
    use raft5fs_search::vector::{CLIP_MODEL, TEXT_MODEL};

    #[test]
    fn the_manifest_names_the_models_records_name() {
        assert_eq!(model("text").name, TEXT_MODEL);
        assert_eq!(model("clip").name, CLIP_MODEL);
    }

    #[test]
    fn every_file_is_pinned() {
        for key in ["text", "clip"] {
            let m = model(key);
            for f in &m.files {
                assert_eq!(f.sha256.len(), 64, "{key} {}", f.local);
                assert!(
                    f.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                    "{key} {}",
                    f.local
                );
                assert!(
                    f.url.contains("/releases/download/"),
                    "{key} {}: a release's file",
                    f.local
                );
                assert!(f.size > 0 && !f.clients.is_empty(), "{key} {}", f.local);
            }
            Pooling::parse(&m.pooling).unwrap();
            assert!(m.max_tokens > 0);
        }
        // What each native loader asks for is there.
        for role in ["body", "table", "tokenizer"] {
            model("text").file(role);
            model("clip").file(role);
        }
        model("clip").file("vision");
    }
}
