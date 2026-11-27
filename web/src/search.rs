//! Search in the browser: each volume's index downloaded, kept in the
//! cache, and searched by path, words and meaning.
//!
//! - **Downloading.** A volume's index is downloaded whole, so what the
//!   browser fetches never depends on a query. One bigger than
//!   `DOWNLOAD_LIMIT` is downloaded only if asked (the app's per-volume
//!   setting); one not downloaded isn't searched here. A big download runs
//!   in the background, and the volume is searched once it is in; a new
//!   generation downloads while the old one is still searched.
//! - **The browser doesn't index.** Native devices write the index (words,
//!   vectors and thumbnails); the models here embed queries only.
//! - **The app's tools.** The Worker gives `setSearchTools` functions:
//!   `embed(texts, query)` (the embed Worker's model), `cacheGet(key)` /
//!   `cachePut(key, bytes)` / `cacheKeep(volume, keys)` (IndexedDB), and
//!   `clip(text)` (a query's vector for searching photos by what they
//!   show). The cache is raft5fs-client's `SegmentCache`.
//! - **The cache** keeps the segments this browser has read, sealed with
//!   raft5fs-crypto's `local`, so a copy of the browser's files is
//!   ciphertext without the account. Reading an index again fetches only
//!   new segments, and adds only their entries to the volume's view.
//! - **Scope.** A search covers the volumes the app names: the one it is
//!   in, or all it has loaded.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::{Array, Float32Array, Function, Promise, Uint8Array};
use raft5fs_client::indexer::open::{self as index_open, Opened};
use raft5fs_client::indexer::{self, SegmentCache};
use raft5fs_crypto::identity::Identity;
use raft5fs_crypto::local::{open_local, seal_local};
use raft5fs_proto::errno;
use raft5fs_proto::types::FsError;
use raft5fs_search::query::{self, Vocabulary};
use raft5fs_search::record::{DocKind, Thumb};
use raft5fs_search::vector::{CLIP_MODEL, TEXT_MODEL};
use raft5fs_search::view::QueryVector;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, future_to_promise};

use super::{Fs, Inner, failure, fs_failure, promise};

type Local<'a, T> = futures_util::future::LocalBoxFuture<'a, T>;

/// What search keeps for this session.
#[derive(Default)]
pub(crate) struct State {
    tools: RefCell<Option<Rc<JsTools>>>,
    /// Each loaded volume's view, by inode, with its path and how far
    /// indexing got.
    views: RefCell<HashMap<u64, Rc<Loaded>>>,
    /// Downloads in the background, by inode: bytes done and in all, and
    /// the error that ended one.
    downloads: RefCell<HashMap<u64, Rc<RefCell<Download>>>>,
    /// The limits that tests lower (`setSearchLimits`).
    limits: RefCell<Option<(u64, u64)>>,
}

/// A download in the background.
#[derive(Default)]
struct Download {
    done: u64,
    total: u64,
    error: Option<String>,
}

/// An index bigger than this is downloaded only if asked.
pub const DOWNLOAD_LIMIT: u64 = 500 << 20;
/// One smaller than this is downloaded at once, before the search: it is
/// quick, and the search then has it.
pub const INLINE_LIMIT: u64 = 16 << 20;

struct Loaded {
    path: String,
    opened: Opened,
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
    cache_get: Function,
    cache_put: Function,
    /// Optional: without it, segments compacted away stay in the cache.
    cache_keep: Option<Function>,
    clip: Function,
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
    /// A query's vector.
    async fn query(&self, text: &str) -> Result<Vec<f32>, String> {
        let mut v = self.vectors(vec![text.to_string()], true).await?;
        v.pop()
            .ok_or_else(|| "the model gave no vector".to_string())
    }

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

    fn keep_only<'a>(&'a self, volume: u64, keys: &'a [String]) -> Local<'a, ()> {
        Box::pin(async move {
            let Some(keep) = &self.0.cache_keep else {
                return;
            };
            let keys: Array = keys.iter().map(|k| JsValue::from_str(k)).collect();
            let _ = call(keep, &[JsValue::from_f64(volume as f64), keys.into()]).await;
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
    /// For `searchThumb`, if it has a thumbnail.
    thumb: Option<String>,
}

/// A thumbnail's id for JavaScript: its volume, file, offset and length.
fn thumb_id(volume: u64, t: &Thumb) -> String {
    format!("{volume}:{}:{}:{}", t.offset, t.len, t.file)
}

fn parse_thumb_id(id: &str) -> Option<(u64, Thumb)> {
    let mut parts = id.splitn(4, ':');
    let volume = parts.next()?.parse().ok()?;
    let offset = parts.next()?.parse().ok()?;
    let len = parts.next()?.parse().ok()?;
    let file = parts.next()?.to_string();
    Some((volume, Thumb { file, offset, len }))
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
    /// Its generation's size in bytes (0 before a compaction).
    bytes: f64,
    /// Whether it is downloaded and searched here.
    downloaded: bool,
    /// A download in progress: bytes done and in all.
    downloading: Option<(f64, f64)>,
    /// Why the last download failed, if it did.
    download_error: Option<String>,
    /// Whether its owner has turned indexing off.
    off: bool,
    /// How many photos it has, and how many of them can be found by what
    /// they show (have an image vector, which only a native device makes).
    photos: usize,
    photos_seen: usize,
}

/// Whether the volume at `label` is volume or group `name`.
fn in_volume(label: &str, name: &str) -> bool {
    label.eq_ignore_ascii_case(name)
        || label
            .split_once('/')
            .is_some_and(|(group, _)| group.eq_ignore_ascii_case(name))
}

/// Now, in ms since the Unix epoch.
fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

/// This browser's offset from UTC now, in milliseconds, for the days
/// that date filters name.
fn utc_offset_ms() -> i64 {
    // `getTimezoneOffset` is UTC minus local time, in minutes.
    -(js_sys::Date::new_0().get_timezone_offset() as i64) * 60_000
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
    fn tools(&self) -> Result<Rc<JsTools>, FsError> {
        self.search
            .tools
            .borrow()
            .clone()
            .ok_or_else(|| FsError::new(errno::EAGAIN, "search isn't set up in this tab"))
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

    /// The download limits: (ask above, background above).
    fn limits(&self) -> (u64, u64) {
        self.search
            .limits
            .borrow()
            .unwrap_or((DOWNLOAD_LIMIT, INLINE_LIMIT))
    }

    /// Reads volume `ino`'s index if it wasn't read in the last minute,
    /// fetching only what this browser hasn't kept. `download` is the
    /// app's setting for it: `None` downloads it unless it is bigger than
    /// `DOWNLOAD_LIMIT`. Gives what search shows of it.
    async fn load_view(
        self: &Rc<Self>,
        ino: u64,
        path: String,
        download: Option<bool>,
    ) -> Result<LoadedJs, FsError> {
        let now = js_sys::Date::now();
        let fresh = self
            .search
            .views
            .borrow()
            .get(&ino)
            .filter(|l| now - l.at < RELOAD_MS)
            .cloned();
        if let Some(l) = fresh {
            return Ok(self.with_download(ino, loaded_js(&l)));
        }
        let off = self.vault().remote().get_volume(ino).await?.indexing_off;
        let head = index_open::head(self.vault(), ino)
            .await?
            .unwrap_or_default();
        let bytes = head.generation.map_or(0, |g| g.1);
        let (ask_above, inline_below) = self.limits();
        if !download.unwrap_or(bytes <= ask_above) {
            // Not here: forget what this browser kept of it.
            self.search.views.borrow_mut().remove(&ino);
            self.cache().keep_only(ino, &[]).await;
            return Ok(skipped_js(path, &head, bytes, off));
        }
        let old = self.search.views.borrow_mut().remove(&ino);
        let same =
            old.as_ref().map(|l| l.opened.generation()) == Some(head.generation.map(|g| g.0));
        // A new generation (or a first download) that is big: in the
        // background, while the old one, if any, is still searched.
        if !same && bytes >= inline_below {
            self.download_later(ino, path.clone(), off);
            return match old {
                Some(l) => {
                    let js = loaded_js(&l);
                    self.search.views.borrow_mut().insert(ino, l);
                    Ok(self.with_download(ino, js))
                }
                None => Ok(self.with_download(ino, skipped_js(path, &head, bytes, off))),
            };
        }
        // A search still holding the old one: read it whole again.
        let old = old.and_then(|l| Rc::try_unwrap(l).ok());
        let opened = match old {
            Some(l) => index_open::refresh(self.vault(), l.opened, &mut |_, _| {}).await?,
            None => index_open::open(self.vault(), ino, self.cache(), &mut |_, _| {}).await?,
        };
        let opened = opened.unwrap_or_else(|| Opened::empty(ino, self.cache()));
        let loaded = Rc::new(Loaded {
            path,
            opened,
            off,
            at: now,
        });
        self.search
            .views
            .borrow_mut()
            .insert(ino, Rc::clone(&loaded));
        Ok(loaded_js(&loaded))
    }

    /// `js`, with the volume's download in progress, if one is.
    fn with_download(&self, ino: u64, mut js: LoadedJs) -> LoadedJs {
        if let Some(d) = self.search.downloads.borrow().get(&ino) {
            let d = d.borrow();
            if d.error.is_none() {
                js.downloading = Some((d.done as f64, d.total as f64));
            }
            js.download_error.clone_from(&d.error);
        }
        js
    }

    /// Downloads volume `ino`'s index in the background, unless that is
    /// running already; the volume is searched once it is in. Pieces are
    /// kept as they come, so a download cut short goes on from there.
    fn download_later(self: &Rc<Self>, ino: u64, path: String, off: bool) {
        if self
            .search
            .downloads
            .borrow()
            .get(&ino)
            .is_some_and(|d| d.borrow().error.is_none())
        {
            return;
        }
        let state = Rc::new(RefCell::new(Download::default()));
        self.search
            .downloads
            .borrow_mut()
            .insert(ino, Rc::clone(&state));
        let inner = Rc::clone(self);
        wasm_bindgen_futures::spawn_local(async move {
            let shown = Rc::clone(&state);
            let mut progress = move |done: u64, total: u64| {
                let mut d = shown.borrow_mut();
                d.done = done;
                d.total = total;
            };
            match index_open::open(inner.vault(), ino, inner.cache(), &mut progress).await {
                Ok(opened) => {
                    let loaded = Rc::new(Loaded {
                        path,
                        opened: opened.unwrap_or_else(|| Opened::empty(ino, inner.cache())),
                        off,
                        at: js_sys::Date::now(),
                    });
                    inner.search.views.borrow_mut().insert(ino, loaded);
                    inner.search.downloads.borrow_mut().remove(&ino);
                }
                Err(e) => state.borrow_mut().error = Some(e.message),
            }
        });
    }

    /// Where this tab keeps index files: IndexedDB through the app, or
    /// memory before the app gives its tools.
    // A browser runs the client on one thread, where this never crosses
    // to another.
    #[allow(clippy::arc_with_non_send_sync)]
    fn cache(&self) -> Arc<dyn SegmentCache> {
        match self.tools() {
            Ok(tools) => Arc::new(JsCache(tools)),
            Err(_) => Arc::new(indexer::MemoryCache::default()),
        }
    }
}

/// A volume that isn't downloaded here, for JavaScript.
fn skipped_js(volume: String, head: &index_open::Head, bytes: u64, off: bool) -> LoadedJs {
    let p = &head.progress;
    LoadedJs {
        volume,
        indexed: p.updated_ms > 0,
        files: 0,
        updated_ms: p.updated_ms as f64,
        by: p
            .updated_by
            .as_ref()
            .map(|(user, device)| format!("{user} on {device}")),
        meaning: false,
        bytes: bytes as f64,
        downloaded: false,
        downloading: None,
        download_error: None,
        off,
        photos: 0,
        photos_seen: 0,
    }
}

fn loaded_js(l: &Loaded) -> LoadedJs {
    let p = &l.opened.progress;
    let view = &l.opened.index;
    LoadedJs {
        volume: l.path.clone(),
        indexed: p.updated_ms > 0,
        files: view.len(),
        updated_ms: p.updated_ms as f64,
        by: p
            .updated_by
            .as_ref()
            .map(|(user, device)| format!("{user} on {device}")),
        meaning: view.has_model(TEXT_MODEL),
        bytes: l.opened.bytes() as f64,
        downloaded: true,
        downloading: None,
        download_error: None,
        off: l.off,
        photos: view.photos(CLIP_MODEL).0,
        photos_seen: view.photos(CLIP_MODEL).1,
    }
}

#[wasm_bindgen]
impl Fs {
    /// Gives search the app's functions: `tools` is an object with
    /// `embed`, `cacheGet`, `cachePut`, `cacheKeep` and `clip` (see the top
    /// of `search`). Until then, search works by words only, with no cache.
    #[wasm_bindgen(js_name = setSearchTools)]
    pub fn set_search_tools(&self, tools: JsValue) -> Result<(), JsValue> {
        let get = |name: &str| -> Result<Function, JsValue> {
            js_sys::Reflect::get(&tools, &name.into())?
                .dyn_into::<Function>()
                .map_err(|_| failure("EINVAL", &format!("search tools need a function {name}")))
        };
        let identity = self
            .0
            .vault()
            .remote()
            .identity()
            .ok_or_else(|| failure("EACCES", "not logged in"))?;
        self.0.search.tools.replace(Some(Rc::new(JsTools {
            embed: get("embed")?,
            cache_get: get("cacheGet")?,
            cache_put: get("cachePut")?,
            cache_keep: get("cacheKeep").ok(),
            clip: get("clip")?,
            identity,
        })));
        Ok(())
    }

    /// Reads the index of the volume that `path` is in, if it wasn't read in
    /// the last minute, fetching only what this browser hasn't kept.
    /// `download` is this browser's setting for the volume: true, false, or
    /// null for the default (download unless it is over 500 MiB). Gives
    /// `{volume, indexed, files, updatedMs, by, meaning, bytes, downloaded,
    /// downloading: [done, total] or null, downloadError, off, photos,
    /// photosSeen}`; a volume not `downloaded` isn't searched.
    #[wasm_bindgen(js_name = searchLoad)]
    pub fn search_load(&self, path: String, download: Option<bool>) -> Promise {
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (ino, volume) = inner.search_volume_at(&path).await?;
            inner.load_view(ino, volume, download).await
        })
    }

    /// How big the index of the volume `path` is in, in bytes, and the size
    /// above which this browser asks before downloading one: `{bytes,
    /// limit}`. Reads only its manifests and header.
    #[wasm_bindgen(js_name = searchSize)]
    pub fn search_size(&self, path: String) -> Promise {
        #[derive(Serialize)]
        struct Size {
            bytes: f64,
            limit: f64,
        }
        let inner = Rc::clone(&self.0);
        promise(async move {
            let (ino, _) = inner.search_volume_at(&path).await?;
            let head = index_open::head(inner.vault(), ino)
                .await?
                .unwrap_or_default();
            Ok(Size {
                bytes: head.generation.map_or(0, |g| g.1) as f64,
                limit: inner.limits().0 as f64,
            })
        })
    }

    /// For the browser tests only: the download limits, in bytes (ask
    /// above `ask`, in the background above `background`).
    #[wasm_bindgen(js_name = setSearchLimits)]
    pub fn set_search_limits(&self, ask: f64, background: f64) {
        self.0
            .search
            .limits
            .replace(Some((ask as u64, background as u64)));
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
            /// Whether files here have text vectors, so that a search with
            /// `meaning` needs the text model.
            vectors: bool,
            /// Whether photos here have image vectors, so that a search
            /// with `meaning` also needs the CLIP text model.
            images: bool,
            meaning_error: Option<String>,
        }
        let inner = Rc::clone(&self.0);
        promise(async move {
            let chosen: Vec<(u64, Rc<Loaded>)> = inner
                .search
                .views
                .borrow()
                .iter()
                .filter(|(_, l)| volumes.is_empty() || volumes.contains(&l.path))
                .map(|(&ino, l)| (ino, Rc::clone(l)))
                .collect();
            let mut vocabulary = Vocabulary::default();
            for (_, l) in &chosen {
                vocabulary.extend(&l.opened.index.vocabulary());
                vocabulary.add_volume(l.path.trim_start_matches('/'));
            }
            let parsed = query::parse(&query, &vocabulary, now_ms(), utc_offset_ms());
            let filter = parsed.filter;
            let query = parsed.text;
            let named = filter.volumes();
            let views: Vec<(u64, Rc<Loaded>)> = chosen
                .into_iter()
                .filter(|(_, l)| {
                    let label = l.path.trim_start_matches('/');
                    named.is_empty() || named.iter().any(|n| in_volume(label, n))
                })
                .collect();
            let limit = limit.clamp(1, 200) as usize;
            let has_vectors = views
                .iter()
                .any(|(_, l)| l.opened.index.has_model(TEXT_MODEL));
            let has_images = views
                .iter()
                .any(|(_, l)| l.opened.index.has_image_model(CLIP_MODEL));
            let mut meaning_error = None;
            let words = !query.trim().is_empty();
            let vector = if meaning && has_vectors && words {
                let embedded = match inner.tools() {
                    Ok(tools) => JsEmbed(tools).query(&query).await,
                    Err(e) => Err(e.message),
                };
                embedded.map_err(|e| meaning_error = Some(e)).ok()
            } else {
                None
            };
            let image_vector = if meaning && has_images && words {
                let embedded = match inner.tools() {
                    Ok(tools) => call(&tools.clip, &[JsValue::from_str(&query)])
                        .await
                        .and_then(|v| {
                            v.dyn_into::<Float32Array>()
                                .map(|a| a.to_vec())
                                .map_err(|_| "the photo model gave no vector".to_string())
                        }),
                    Err(e) => Err(e.message),
                };
                embedded.map_err(|e| meaning_error = Some(e)).ok()
            } else {
                None
            };
            let q = vector.as_deref().map(|values| QueryVector {
                model: TEXT_MODEL,
                values,
            });
            let image = image_vector.as_deref().map(|values| QueryVector {
                model: CLIP_MODEL,
                values,
            });
            // All the volumes are ranked as one (`index::search`).
            let all: Vec<&Opened> = views.iter().map(|(_, l)| &l.opened).collect();
            let hits = index_open::search(&all, &query, q, image, limit, Some(&filter))
                .await
                .into_iter()
                .map(|(i, h)| {
                    let (ino, l) = &views[i];
                    HitJs {
                        path: format!("{}/{}", l.path, h.path),
                        preview: h.preview,
                        kind: kind_name(h.kind),
                        thumb: h.thumb.as_ref().map(|t| thumb_id(*ino, t)),
                    }
                })
                .collect();
            Ok(Found {
                hits,
                meaning: has_vectors || has_images,
                vectors: has_vectors,
                images: has_images,
                meaning_error,
            })
        })
    }

    /// A thumbnail that `search` named (a hit's `thumb`): JPEG bytes.
    #[wasm_bindgen(js_name = searchThumb)]
    pub fn search_thumb(&self, id: String) -> Promise {
        let inner = Rc::clone(&self.0);
        future_to_promise(async move {
            let (volume, thumb) =
                parse_thumb_id(&id).ok_or_else(|| failure("EINVAL", "not a thumbnail"))?;
            let bytes = indexer::read_thumb(inner.vault(), volume, &thumb)
                .await
                .map_err(fs_failure)?;
            Ok(Uint8Array::from(bytes.as_slice()).into())
        })
    }

    /// How big the loaded indexes are, for measuring memory: `{volumes,
    /// docs, live, chunks, chunkWords, vectors, words, postings}`, summed
    /// over the loaded volumes.
    #[wasm_bindgen(js_name = searchMemory)]
    pub fn search_memory(&self) -> JsValue {
        #[derive(Serialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct Sizes {
            volumes: usize,
            generation_files: usize,
            docs: usize,
            live: usize,
            chunks: usize,
            chunk_words: usize,
            vectors: usize,
            words: usize,
            postings: usize,
        }
        let mut out = Sizes::default();
        for l in self.0.search.views.borrow().values() {
            let s = l.opened.index.recent.stats();
            out.generation_files += l
                .opened
                .index
                .generation
                .as_ref()
                .map_or(0, |g| g.rows().len());
            out.volumes += 1;
            out.docs += s.docs;
            out.live += s.live;
            out.chunks += s.chunks;
            out.chunk_words += s.chunk_words;
            out.vectors += s.vectors;
            out.words += s.words;
            out.postings += s.postings;
        }
        serde_wasm_bindgen::to_value(&out).unwrap_or(JsValue::NULL)
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
