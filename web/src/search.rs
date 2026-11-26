//! Search in the browser: each volume's index read into memory and searched
//! by path, words and meaning.
//!
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
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use js_sys::{Array, Float32Array, Function, Promise, Uint8Array};
use raft5fs_client::indexer::{self, SegmentCache};
use raft5fs_crypto::identity::Identity;
use raft5fs_crypto::local::{open_local, seal_local};
use raft5fs_proto::errno;
use raft5fs_proto::types::FsError;
use raft5fs_search::record::{DocKind, Thumb};
use raft5fs_search::vector::{CLIP_MODEL, TEXT_MODEL};
use raft5fs_search::view::{QueryVector, View, search_many};
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
}

struct Loaded {
    path: String,
    view: View,
    /// The segments `view` holds, to read only new ones next time.
    keys: HashSet<String>,
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
    /// Whether its owner has turned indexing off.
    off: bool,
    /// How many photos it has, and how many of them can be found by what
    /// they show (have an image vector, which only a native device makes).
    photos: usize,
    photos_seen: usize,
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
        let cache = cache.as_ref().map(|c| c as &dyn SegmentCache);
        let known = self
            .search
            .views
            .borrow()
            .get(&ino)
            .map(|l| l.keys.clone())
            .unwrap_or_default();
        // What is new since the last read: a few segments, so collected.
        let mut delta = Vec::new();
        let head = if known.is_empty() {
            None
        } else {
            indexer::read_index_into(self.vault(), ino, cache, &known, &mut |e| delta.extend(e))
                .await?
        };
        let old = self.search.views.borrow_mut().remove(&ino);
        let old = old.and_then(|l| Rc::try_unwrap(l).ok());
        let grown = match (head, old) {
            (Some(h), Some(mut l)) if !h.reset => {
                l.view.add(delta);
                l.view.shrink();
                Some((l.view, h.keys.into_iter().collect(), h.progress))
            }
            // A first read, a segment compacted away, or a search still
            // holding the old view: the index is read whole (from the
            // cache), a segment at a time, into a new view.
            _ => None,
        };
        let (view, keys, progress) = match grown {
            Some(g) => g,
            None => {
                let mut view = View::default();
                let head =
                    indexer::read_index_into(self.vault(), ino, cache, &HashSet::new(), &mut |e| {
                        view.add(e)
                    })
                    .await?;
                view.shrink();
                match head {
                    Some(h) => (view, h.keys.into_iter().collect(), h.progress),
                    None => (View::default(), HashSet::new(), Default::default()),
                }
            }
        };
        let loaded = Rc::new(Loaded {
            path,
            view,
            keys,
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
        meaning: l.view.has_model(TEXT_MODEL),
        off: l.off,
        photos: l.view.photos(CLIP_MODEL).0,
        photos_seen: l.view.photos(CLIP_MODEL).1,
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
            let views: Vec<(u64, Rc<Loaded>)> = inner
                .search
                .views
                .borrow()
                .iter()
                .filter(|(_, l)| volumes.is_empty() || volumes.contains(&l.path))
                .map(|(&ino, l)| (ino, Rc::clone(l)))
                .collect();
            let limit = limit.clamp(1, 200) as usize;
            let has_vectors = views.iter().any(|(_, l)| l.view.has_model(TEXT_MODEL));
            let has_images = views
                .iter()
                .any(|(_, l)| l.view.has_image_model(CLIP_MODEL));
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
            let image_vector = if meaning && has_images {
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
            // All the volumes are ranked as one (`view::search_many`).
            let all: Vec<&View> = views.iter().map(|(_, l)| &l.view).collect();
            let hits = search_many(&all, &query, q, image, limit)
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
            let s = l.view.stats();
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
