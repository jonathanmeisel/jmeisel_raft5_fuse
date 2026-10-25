//! The browser's `Store`: pins and the prune queue in IndexedDB.
//!
//! IndexedDB only answers asynchronously, and `Store` is synchronous. So:
//!
//! - At login, the app reads this account's blobs and hands them over.
//!   Loads come from that copy in memory.
//! - Each save changes the copy, then goes to `persist`, the app's
//!   function that writes it to IndexedDB. Saves reach it one at a time,
//!   in order, so the last save of a blob is the one that stays.
//! - The app lets only one tab at a time log in to an account (a Web
//!   Lock), so no other tab changes the blobs under this copy.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use futures_channel::mpsc::{UnboundedSender, unbounded};
use futures_util::StreamExt;
use js_sys::{Function, Promise, Uint8Array};
use raft5fs_client::store::Store;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

pub struct BrowserStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    lock: Mutex<()>,
    saves: UnboundedSender<(String, Vec<u8>)>,
}

impl BrowserStore {
    /// A store holding `blobs`, which saves through `persist(name,
    /// bytes)`. If `persist` returns a promise, the next save waits for
    /// it. A failed save is the app's to report.
    pub fn new(blobs: HashMap<String, Vec<u8>>, persist: Function) -> Self {
        let (saves, mut queue) = unbounded::<(String, Vec<u8>)>();
        wasm_bindgen_futures::spawn_local(async move {
            while let Some((name, data)) = queue.next().await {
                let bytes = Uint8Array::from(data.as_slice());
                let Ok(answer) = persist.call2(&JsValue::NULL, &name.into(), &bytes) else {
                    continue;
                };
                if let Ok(promise) = answer.dyn_into::<Promise>() {
                    let _ = JsFuture::from(promise).await;
                }
            }
        });
        Self {
            blobs: Mutex::new(blobs),
            lock: Mutex::new(()),
            saves,
        }
    }
}

impl Store for BrowserStore {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(self.blobs.lock().unwrap().get(name).cloned())
    }

    fn save(&self, name: &str, data: &[u8]) -> io::Result<()> {
        self.blobs
            .lock()
            .unwrap()
            .insert(name.to_string(), data.to_vec());
        self.saves
            .unbounded_send((name.to_string(), data.to_vec()))
            .map_err(|_| io::Error::other("the browser store is closed"))
    }

    /// The Web Lock that the app holds covers other tabs; in this one,
    /// everything runs on one thread.
    fn exclusive(&self, _lock: &str, f: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        let _held = self.lock.lock().unwrap();
        f()
    }

    fn location(&self, name: &str) -> String {
        format!("{name} (in this browser)")
    }
}
