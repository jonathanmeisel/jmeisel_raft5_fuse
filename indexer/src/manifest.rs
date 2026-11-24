//! The models search uses, as `search/data/models.json` pins them: the one
//! place a model is changed (see raft5fs-search's `vector`). Built into
//! native clients; the web app reads the same file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
    pub runtime: Runtime,
}

/// ONNX Runtime, as native clients load it: from Microsoft's PyPI wheel
/// for their platform.
#[derive(Debug, Deserialize)]
pub struct Runtime {
    pub version: String,
    pub platforms: HashMap<String, RuntimeBuild>,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeBuild {
    /// The wheel, its SHA-256 and size.
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// The library's path in the wheel, and its own SHA-256.
    pub member: String,
    pub library_sha256: String,
}

/// This platform's name in the manifest's runtime builds.
fn platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("macos", "aarch64") => "macos-aarch64",
        _ => "",
    }
}

/// The ONNX Runtime library to load: `RAFT5FS_ONNXRUNTIME` if set (a copy
/// the system provides); else the pinned build for this platform, fetched
/// into the model cache the first time. Only the library is kept, not the
/// wheel it came in.
pub fn runtime_library() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("RAFT5FS_ONNXRUNTIME") {
        return Ok(PathBuf::from(path));
    }
    let runtime = &manifest().runtime;
    let build = runtime.platforms.get(platform()).ok_or_else(|| {
        format!(
            "no ONNX Runtime is pinned for this platform ({} {}): set RAFT5FS_ONNXRUNTIME \
             to a libonnxruntime {} to search by meaning",
            std::env::consts::OS,
            std::env::consts::ARCH,
            runtime.version
        )
    })?;
    let dir = crate::embed::cache_dir()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
        .join(format!("onnxruntime-{}", runtime.version));
    let name = build.member.rsplit('/').next().unwrap_or(&build.member);
    let library = dir.join(name);
    if file_matches(&library, &build.library_sha256) {
        return Ok(library);
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let wheel = dir.join("onnxruntime.whl");
    let what = format!("ONNX Runtime {}", runtime.version);
    download_url(&build.url, &wheel, &build.sha256, &what)?;
    let unpacked = (|| -> Result<(), String> {
        let file = std::fs::File::open(&wheel).map_err(|e| e.to_string())?;
        let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        let mut member = zip.by_name(&build.member).map_err(|e| e.to_string())?;
        let temp = library.with_extension("part");
        let mut out = std::fs::File::create(&temp).map_err(|e| e.to_string())?;
        std::io::copy(&mut member, &mut out).map_err(|e| e.to_string())?;
        if !file_matches(&temp, &build.library_sha256) {
            let _ = std::fs::remove_file(&temp);
            return Err("the library in it isn't the one models.json pins".into());
        }
        std::fs::rename(&temp, &library).map_err(|e| e.to_string())
    })();
    let _ = std::fs::remove_file(&wheel);
    unpacked.map_err(|e| format!("cannot unpack {what}: {e}"))?;
    Ok(library)
}

#[derive(Debug, Deserialize)]
pub struct Model {
    /// The name records give its vectors (`vector::E5_MODEL`, ...).
    pub name: String,
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

/// Model `key` ("e5", "clip").
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
    use raft5fs_search::vector::{CLIP_MODEL, E5_MODEL};

    #[test]
    fn the_manifest_names_the_models_records_name() {
        assert_eq!(model("e5").name, E5_MODEL);
        assert_eq!(model("clip").name, CLIP_MODEL);
    }

    #[test]
    fn every_file_is_pinned() {
        for (key, m) in &manifest().models {
            for f in &m.files {
                assert_eq!(f.sha256.len(), 64, "{key} {}", f.local);
                assert!(
                    f.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                    "{key} {}",
                    f.local
                );
                assert!(
                    f.url.contains("/resolve/") && !f.url.contains("/resolve/main/"),
                    "{key} {}: a revision, not main",
                    f.local
                );
                assert!(f.size > 0 && !f.clients.is_empty(), "{key} {}", f.local);
            }
        }
        for (name, b) in &manifest().runtime.platforms {
            assert_eq!(b.sha256.len(), 64, "{name}");
            assert_eq!(b.library_sha256.len(), 64, "{name}");
            assert!(b.url.ends_with(".whl") && b.size > 0, "{name}");
        }
        // What each native loader asks for is there.
        for role in ["model", "tokenizer"] {
            model("e5").file(role);
        }
        for role in ["model", "tokenizer", "dense", "vision"] {
            model("clip").file(role);
        }
    }
}
