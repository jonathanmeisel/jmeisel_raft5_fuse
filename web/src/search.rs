//! Search in the browser: each volume's index read into memory, searched by
//! words and meaning, and kept up to date by this tab when it holds the
//! account's index lock.
//!
//! - **The app's tools.** The Worker gives `setSearchTools` four functions:
//!   `embed(texts, query)` (the embed Worker's model), `pdf(bytes)` (the PDF
//!   module), and `cacheGet(key)` / `cachePut(key, bytes)` (IndexedDB).
//!   Indexing and search use them as raft5fs-client's `Embed`, `Extract`
//!   and `SegmentCache`.
//! - **The cache** keeps the segments this browser has read, sealed with
//!   raft5fs-crypto's `local`, so a copy of the browser's files is
//!   ciphertext without the account. Reading an index again fetches only
//!   new segments.
//! - **Scope.** A search covers the volumes the app names: the one it is
//!   in, or all it has loaded.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::{Array, Float32Array, Function, Promise, Uint8Array};
use raft5fs_client::indexer::{
    self, BuiltIn, Embed, Extract, IndexStatus, Indexer, IndexerConfig, SegmentCache, Tools,
};
use raft5fs_crypto::identity::Identity;
use raft5fs_crypto::local::{open_local, seal_local};
use raft5fs_proto::errno;
use raft5fs_proto::types::FsError;
use raft5fs_search::extract::{Extracted, Format};
use raft5fs_search::rank::fuse;
use raft5fs_search::record::DocKind;
use raft5fs_search::vector::E5_MODEL;
use raft5fs_search::view::{QueryVector, View};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::{Fs, Inner, failure, fs_failure, promise};

type Local<'a, T> = futures_util::future::LocalBoxFuture<'a, T>;

/// The most bytes of a PDF that are read.
const PDF_MAX: u64 = 64 << 20;

/// What search keeps for this session.
#[derive(Default)]
pub(crate) struct State {
    tools: RefCell<Option<Rc<JsTools>>>,
    /// Each loaded volume's view, by inode, with its path and how far
    /// indexing got.
    views: RefCell<HashMap<u64, Rc<Loaded>>>,
    indexer: RefCell<Option<Indexer>>,
}

struct Loaded {
    path: String,
    view: View,
    progress: raft5fs_search::view::Progress,
    /// Whether its owner has turned indexing off.
    off: bool,
    /// When it was read (ms).
    at: f64,
}

/// How long a volume's index, once read, is searched before it is read
/// again (only what is new is fetched).
const RELOAD_MS: f64 = 60_000.0;

/// The app's functions.
struct JsTools {
    embed: Function,
    pdf: Function,
    cache_get: Function,
    cache_put: Function,
    identity: Arc<Identity>,
}

async fn call(f: &Function, args: &[JsValue]) -> Result<JsValue, String> {
    let array: Array = args.iter().collect();
    let returned = f
        .apply(&JsValue::NULL, &array)
        .map_err(|e| js_message(&e))?;
    JsFuture::from(Promise::resolve(&returned))
        .await
        .map_err(|e| js_message(&e))
}

fn js_message(e: &JsValue) -> String {
    js_sys::Reflect::get(e, &"message".into())
        .ok()
        .and_then(|m| m.as_string())
        .or_else(|| e.as_string())
        .unwrap_or_else(|| "the app's function failed".into())
}

/// The embed Worker's model, as an `Embed`.
struct JsEmbed(Rc<JsTools>);

impl JsEmbed {
    async fn vectors(&self, texts: Vec<String>, query: bool) -> Result<Vec<Vec<f32>>, String> {
        let list: Array = texts.iter().map(|t| JsValue::from_str(t)).collect();
        let got = call(&self.0.embed, &[list.into(), query.into()]).await?;
        let got: Array = got
            .dyn_into()
            .map_err(|_| "the model gave no list".to_string())?;
        got.iter()
            .map(|v| {
                v.dyn_into::<Float32Array>()
                    .map(|a| a.to_vec())
                    .map_err(|_| "the model gave something that isn't a vector".to_string())
            })
            .collect()
    }
}

impl Embed for JsEmbed {
    fn model(&self) -> &str {
        E5_MODEL
    }

    fn passages<'a>(&'a self, texts: Vec<String>) -> Local<'a, Result<Vec<Vec<f32>>, String>> {
        Box::pin(self.vectors(texts, false))
    }

    fn query<'a>(&'a self, text: &'a str) -> Local<'a, Result<Vec<f32>, String>> {
        Box::pin(async move {
            let mut v = self.vectors(vec![text.to_string()], true).await?;
            v.pop()
                .ok_or_else(|| "the model gave no vector".to_string())
        })
    }
}

/// What raft5fs-search reads, and PDF through the PDF module.
struct JsExtract(Rc<JsTools>);

impl Extract for JsExtract {
    fn reads(&self, name: &str) -> u64 {
        match Format::of(name) {
            Format::Pdf => PDF_MAX,
            _ => BuiltIn.reads(name),
        }
    }

    fn extract<'a>(&'a self, name: &'a str, bytes: Vec<u8>) -> Local<'a, Option<Extracted>> {
        Box::pin(async move {
            if Format::of(name) != Format::Pdf {
                return BuiltIn.extract(name, bytes).await;
            }
            let bytes = Uint8Array::from(bytes.as_slice());
            let text = call(&self.0.pdf, &[bytes.into()]).await.ok()?.as_string()?;
            Some(Extracted {
                kind: DocKind::Text,
                text,
            })
        })
    }
}

/// IndexedDB, through the app, with everything sealed to the account.
struct JsCache(Rc<JsTools>);

impl SegmentCache for JsCache {
    fn get<'a>(&'a self, key: &'a str) -> Local<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let got = call(&self.0.cache_get, &[key.into()]).await.ok()?;
            let sealed = got.dyn_into::<Uint8Array>().ok()?.to_vec();
            open_local(&self.0.identity, key, &sealed).ok()
        })
    }

    fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> Local<'a, ()> {
        Box::pin(async move {
            let sealed = seal_local(&self.0.identity, key, bytes);
            let sealed = Uint8Array::from(sealed.as_slice());
            // A cache that can't keep it only costs a read next time.
            let _ = call(&self.0.cache_put, &[key.into(), sealed.into()]).await;
        })
    }
}

/// One search result, for JavaScript.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HitJs {
    /// The file's path in the app: `/<volume>/<path in it>`.
    path: String,
    preview: String,
    /// `text`, `track`, `photo`, or `file` (found by its name only).
    kind: &'static str,
}

/// A loaded volume, for JavaScript.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoadedJs {
    volume: String,
    indexed: bool,
    files: usize,
    /// When it was last indexed (ms), and by whom on what; 0 and null if
    /// never.
    updated_ms: f64,
    by: Option<String>,
    /// Whether its files have vectors, so a query is embedded too.
    meaning: bool,
    /// Whether its owner has turned indexing off.
    off: bool,
}

fn kind_name(kind: DocKind) -> &'static str {
    match kind {
        DocKind::Text => "text",
        DocKind::Track => "track",
        DocKind::Photo => "photo",
        DocKind::Opaque | DocKind::Unread => "file",
    }
}

impl Inner {
    /// Stops this tab's indexer, at logout.
    pub(crate) fn search_stop(&self) -> Option<Indexer> {
        self.search.indexer.take()
    }

    fn tools(&self) -> Result<Rc<JsTools>, FsError> {
        self.search
            .tools
            .borrow()
            .clone()
            .ok_or_else(|| FsError::new(errno::EAGAIN, "search isn't set up in this tab"))
    }

    // `Tools` holds `Arc`s, for native clients' threads. A browser runs the
    // client on one thread, where these never cross to another.
    #[allow(clippy::arc_with_non_send_sync)]
    fn index_tools(&self) -> Result<Tools, FsError> {
        let tools = self.tools()?;
        Ok(Tools {
            extract: Arc::new(JsExtract(Rc::clone(&tools))),
            embed: Some(Arc::new(JsEmbed(tools))),
        })
    }

    /// The volume that `path` is in: its inode and its path in the app.
    /// `EINVAL` for the root, a group, or a share of a folder inside a
    /// volume, which have no index of their own.
    async fn search_volume_at(&self, path: &str) -> Result<(u64, String), FsError> {
        let names: Vec<&str> = path.split('/').filter(|n| !n.is_empty()).collect();
        let Some((depth, ino)) = self.top(&names).await? else {
            return Err(FsError::new(errno::EINVAL, "choose a folder to search in"));
        };
        match self.vault().remote().get_volume(ino).await {
            Ok(_) => Ok((ino, format!("/{}", names[..depth].join("/")))),
            Err(e) if e.errno == errno::EINVAL => Err(FsError::new(
                errno::EINVAL,
                "only a whole top-level folder can be searched, not a share of a folder in one",
            )),
            Err(e) => Err(e),
        }
    }

    async fn load_view(&self, ino: u64, path: String) -> Result<Rc<Loaded>, FsError> {
        let now = js_sys::Date::now();
        if let Some(l) = self.search.views.borrow().get(&ino)
            && now - l.at < RELOAD_MS
        {
            return Ok(Rc::clone(l));
        }
        let off = self.vault().remote().get_volume(ino).await?.indexing_off;
        let tools = self.tools().ok();
        let cache = tools.map(JsCache);
        let read = indexer::read_index_cached(
            self.vault(),
            ino,
            cache.as_ref().map(|c| c as &dyn SegmentCache),
        )
        .await?;
        let (view, progress) = match read {
            Some(index) => (View::new(index.entries), index.progress),
            None => (View::default(), Default::default()),
        };
        let loaded = Rc::new(Loaded {
            path,
            view,
            progress,
            off,
            at: now,
        });
        self.search
            .views
            .borrow_mut()
            .insert(ino, Rc::clone(&loaded));
        Ok(loaded)
    }

    fn start_indexer(&self, device: String, skip: Vec<String>) -> Result<(), FsError> {
        let tools = self.index_tools()?;
        let vault = raft5fs_client::vault::Vault::new(Arc::clone(self.vault().remote()))?
            .with_known_keys(self.vault().known_keys().duplicate());
        let config = IndexerConfig {
            device,
            skip,
            ..IndexerConfig::default()
        };
        // Dropping the one before stops it.
        self.search
            .indexer
            .replace(Some(indexer::spawn(vault, config, tools)));
        Ok(())
    }
}

fn loaded_js(l: &Loaded) -> LoadedJs {
    let p = &l.progress;
    LoadedJs {
        volume: l.path.clone(),
        indexed: p.updated_ms > 0,
        files: l.view.len(),
        updated_ms: p.updated_ms as f64,
        by: p
            .updated_by
            .as_ref()
            .map(|(user, device)| format!("{user} on {device}")),
        meaning: l.view.has_model(E5_MODEL),
        off: l.off,
    }
}

#[wasm_bindgen]
impl Fs {
    /// Gives search the app's functions (see the top of `search`). Until
    /// then, search works by words only, with no cache.
    #[wasm_bindgen(js_name = setSearchTools)]
    pub fn set_search_tools(
        &self,
        embed: Function,
        pdf: Function,
        cache_get: Function,
        cache_put: Function,
    ) -> Result<(), JsValue> {
        let identity = self
            .0
            .vault()
            .remote()
            .identity()
            .ok_or_else(|| failure("EACCES", "not logged in"))?;
        self.0.search.tools.replace(Some(Rc::new(JsTools {
            embed,
            pdf,
            cache_get,
            cache_put,
            identity,
        })));
        Ok(())
    }

    /// Reads the index of the volume that `path` is in, if it wasn't read in
    /// the last minute, fetching only what this browser hasn't kept. Gives
    /// `{volume, indexed, files, updatedMs, by, meaning, off}`.
    #[wasm_bindgen(js_name = searchLoad)]
    pub fn search_load(&self, path: String) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (ino, volume) = inner.search_volume_at(&path).await?;
            let loaded = inner.load_view(ino, volume).await?;
            Ok(loaded_js(&loaded))
        })
    }

    /// Searches the loaded volumes whose paths are in `volumes` (all
    /// loaded, if empty) for `query`: by words, and with `meaning` also by
    /// meaning where their files have vectors. Gives `{hits: [{path,
    /// preview, kind}], meaning, meaningError}`, best first:
    ///
    /// - `meaning`: whether the volumes have vectors to search by meaning,
    ///   so that a search with `meaning` could add to these hits.
    /// - `meaningError`: why a search with `meaning` gave words only (the
    ///   model failed to load or run), or null.
    ///
    /// Embedding the query may first need the model downloaded, so the app
    /// searches by words first and with `meaning` after.
    pub fn search(
        &self,
        query: String,
        volumes: Vec<String>,
        limit: u32,
        meaning: bool,
    ) -> Promise {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Found {
            hits: Vec<HitJs>,
            meaning: bool,
            meaning_error: Option<String>,
        }
        let inner = Rc::clone(&self.0);
        promise(async move {
            let views: Vec<(u64, Rc<Loaded>)> = inner
                .search
                .views
                .borrow()
                .iter()
                .filter(|(_, l)| volumes.is_empty() || volumes.contains(&l.path))
                .map(|(&ino, l)| (ino, Rc::clone(l)))
                .collect();
            let limit = limit.clamp(1, 200) as usize;
            let has_vectors = views.iter().any(|(_, l)| l.view.has_model(E5_MODEL));
            let mut meaning_error = None;
            let vector = if meaning && has_vectors {
                let embedded = match inner.tools() {
                    Ok(tools) => JsEmbed(tools).query(&query).await,
                    Err(e) => Err(e.message),
                };
                embedded.map_err(|e| meaning_error = Some(e)).ok()
            } else {
                None
            };
            let mut lists = Vec::new();
            let mut hits = HashMap::new();
            for (ino, l) in &views {
                let q = vector.as_deref().map(|values| QueryVector {
                    model: E5_MODEL,
                    values,
                });
                let list: Vec<(u64, u64)> = l
                    .view
                    .search_with(&query, q, limit)
                    .into_iter()
                    .map(|h| {
                        let key = (*ino, h.ino);
                        hits.insert(
                            key,
                            HitJs {
                                path: format!("{}/{}", l.path, h.path),
                                preview: h.preview,
                                kind: kind_name(h.kind),
                            },
                        );
                        key
                    })
                    .collect();
                lists.push(list);
            }
            let hits = fuse(&lists)
                .into_iter()
                .take(limit)
                .filter_map(|(key, _)| hits.remove(&key))
                .collect();
            Ok(Found {
                hits,
                meaning: has_vectors,
                meaning_error,
            })
        })
    }

    /// Starts indexing, in the background, the volumes this account can
    /// write, less `skip` (as the root shows them). `device` names this
    /// browser in the status search shows. Needs `setSearchTools`.
    #[wasm_bindgen(js_name = startIndexing)]
    pub fn start_indexing(&self, device: String, skip: Vec<String>) -> Result<(), JsValue> {
        self.0.start_indexer(device, skip).map_err(fs_failure)
    }

    /// Stops indexing here; a pass cut short is finished by the next.
    #[wasm_bindgen(js_name = stopIndexing)]
    pub fn stop_indexing(&self) {
        drop(self.0.search.indexer.take());
    }

    /// Asks this tab's indexer to look for changes now, as after an
    /// upload. Nothing if it doesn't index.
    #[wasm_bindgen(js_name = kickIndexing)]
    pub fn kick_indexing(&self) {
        if let Some(i) = self.0.search.indexer.borrow().as_ref() {
            i.kick();
        }
    }

    /// Whether this tab indexes.
    #[wasm_bindgen(getter)]
    pub fn indexing(&self) -> bool {
        self.0.search.indexer.borrow().is_some()
    }

    /// What this tab's indexer is doing: `{current: {volume, detail} or
    /// null, last: [{volume, detail}], error}`, or null if it doesn't
    /// index.
    #[wasm_bindgen(js_name = indexStatus)]
    pub fn index_status(&self) -> Promise {
        #[derive(Serialize)]
        struct Line {
            volume: String,
            detail: String,
        }
        #[derive(Serialize)]
        struct Status {
            current: Option<Line>,
            last: Vec<Line>,
            error: Option<String>,
        }
        let inner = Rc::clone(&self.0);
        promise(async move {
            let Some(s): Option<IndexStatus> =
                inner.search.indexer.borrow().as_ref().map(Indexer::status)
            else {
                return Ok(None);
            };
            let paths = inner.volume_paths().await.unwrap_or_default();
            let name = |ino: u64| paths.get(&ino).cloned().unwrap_or_else(|| ino.to_string());
            let mut last: Vec<Line> = s
                .last
                .iter()
                .map(|(&ino, d)| Line {
                    volume: name(ino),
                    detail: d.clone(),
                })
                .collect();
            last.sort_by(|a, b| a.volume.cmp(&b.volume));
            Ok(Some(Status {
                current: s.current.map(|(ino, d)| Line {
                    volume: name(ino),
                    detail: d,
                }),
                last,
                error: s.error,
            }))
        })
    }

    /// Whether the volume `path` is in is indexed for search, and whether
    /// this account owns it (and so may turn that off): `{volume, on,
    /// owner}`.
    #[wasm_bindgen(js_name = volumeIndexing)]
    pub fn volume_indexing(&self, path: String) -> Promise {
        #[derive(Serialize)]
        struct State {
            volume: String,
            on: bool,
            owner: bool,
        }
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (ino, volume) = inner.search_volume_at(&path).await?;
            let info = inner.vault().remote().get_volume(ino).await?;
            let me = inner.vault().remote().username();
            Ok(State {
                volume,
                on: !info.indexing_off,
                owner: info.owner.as_deref() == Some(me),
            })
        })
    }

    /// Turns search indexing of the volume `path` is in on or off, as its
    /// owner. Turning it off removes its index too, to free its space.
    #[wasm_bindgen(js_name = setVolumeIndexing)]
    pub fn set_volume_indexing(&self, path: String, on: bool) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (ino, _) = inner.search_volume_at(&path).await?;
            inner.vault().remote().set_volume_indexing(ino, on).await?;
            if !on {
                indexer::delete_index(inner.vault(), ino).await?;
                inner.search.views.borrow_mut().remove(&ino);
            }
            Ok(())
        })
    }
}
