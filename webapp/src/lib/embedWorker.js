// The embed Worker: the search model, and the PDF reader, apart from the
// session's Worker, so that minutes of indexing never hold up its calls.
// It holds no keys: the session's Worker sends it text, or a PDF's bytes.
//
// - The model is multilingual-e5-small, the int8 export that native clients
//   also run (raft5fs-indexer's `embed`), served by this app from
//   models/<name>/ (scripts/fetch-models.mjs), as search/data/models.json
//   pins it for every client. The model comes in pieces:
//   they are joined, the whole is checked against its SHA-256, and it is
//   kept in the Cache API, so it downloads once.
// - It runs on ONNX Runtime's WebAssembly backend, on one thread, as on a
//   native client's CPU: a GPU would give slightly different vectors.
// - The model runs as e5.js says, one text at a time, as native clients
//   run it. "passage: " goes before text to search, "query: " before a
//   query.
// - PDFs are read by the PDF module (raft5fs-pdf-web). A PDF that makes it
//   trap ends that instance only; the next PDF starts a new one.
//
// - A first load fetches each piece straight into one buffer the size of
//   the whole, so a phone holds the model once, not twice, while it loads.
//
// - Photos' thumbnails are drawn here too, on an OffscreenCanvas.
//
// - CLIP's text side (clip.js) embeds queries for photos, which native
//   devices give image vectors.
//
// Messages: {id, op: "embed", texts, query} → {id, vectors}; {id, op:
// "clip", text} → {id, vector}; {id, op: "pdf", bytes} → {id, text}; {id,
// op: "thumb", bytes} → {id, thumb}; {id, op: "state"} → {id, state: {e5,
// clip: {ready, loading, cached}, loaded, total}}, at once. A failure
// answers {id, error}.
import * as ort from "onnxruntime-web/wasm";
import ortWasm from "onnxruntime-web/ort-wasm-simd-threaded.wasm?url";
import ortMjs from "onnxruntime-web/ort-wasm-simd-threaded.mjs?url";
import { loadE5 } from "./e5.js";
import { loadClip } from "./clip.js";
import initPdf, { pdfText } from "../wasm/raft5fs_pdf_web.js";
// Every model, pinned in one place for every client (see its "about").
import manifest from "../../../search/data/models.json";

/// Where the app serves a model: public/models/<name>/, under its base.
const base = (name) => new URL(`${import.meta.env.BASE_URL}models/${name}/`, self.location.origin);

/// Model `key`'s files that the web app uses, by role: their pieces (as
/// scripts/fetch-models.mjs cuts them) with the pieces' sizes, and the
/// whole's SHA-256.
function webModel(key) {
  const m = manifest.models[key];
  const files = {};
  for (const f of m.files.filter((f) => f.clients.includes("web"))) {
    const count = f.piece ? Math.ceil(f.size / f.piece) : 1;
    const parts = f.piece
      ? Array.from({ length: count }, (_, i) => [`${f.local}.${i}`, Math.min(f.piece, f.size - i * f.piece)])
      : [[f.local, f.size]];
    files[f.role] = { parts, sha256: f.sha256 };
  }
  return { name: m.name, base: base(m.name), files };
}

/// The text model, and CLIP's text side only: photos' image vectors are
/// made on native devices.
const MODELS = { e5: webModel("e5"), clip: webModel("clip") };
const CACHE = "raft5fs-models";

/// What a first load of model `name` downloads: every piece of every file.
const total = (name) =>
  Object.values(MODELS[name].files).reduce((n, f) => n + f.parts.reduce((m, [, size]) => m + size, 0), 0);

ort.env.wasm.wasmPaths = { wasm: ortWasm, mjs: ortMjs };
ort.env.wasm.numThreads = 1;

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const cacheKey = (model, name) =>
  new URL(`${name}?sha256=${MODELS[model].files[name].sha256}`, MODELS[model].base).href;

/// Whether every file of model `name` is in the Cache API, so loading it
/// downloads nothing.
async function cached(model) {
  try {
    const cache = await caches.open(CACHE);
    for (const name of Object.keys(MODELS[model].files)) {
      if (!(await cache.match(cacheKey(model, name)))) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/// How much of each model's download has come, for `state`.
const progress = { e5: 0, clip: 0 };

/// File `name` of `model`, checked: from the Cache API, or else fetched in
/// its pieces straight into one buffer (no copy of the whole), checked
/// and kept.
async function file(model, name) {
  const { parts, sha256 } = MODELS[model].files[name];
  const key = cacheKey(model, name);
  const cache = await caches.open(CACHE).catch(() => null);
  const kept = await cache?.match(key);
  if (kept) {
    const bytes = await kept.arrayBuffer();
    if (hex(await crypto.subtle.digest("SHA-256", bytes)) === sha256) {
      progress[model] += bytes.byteLength;
      return new Uint8Array(bytes);
    }
    await cache.delete(key);
  }
  const bytes = new Uint8Array(parts.reduce((n, [, size]) => n + size, 0));
  let at = 0;
  for (const [part, size] of parts) {
    const response = await fetch(new URL(part, MODELS[model].base));
    if (!response.ok) throw new Error(`the search model's ${part} isn't on this site (${response.status})`);
    const reader = response.body.getReader();
    const end = at + size;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (at + value.length > end) throw new Error(`the search model's ${part} is too long`);
      bytes.set(value, at);
      at += value.length;
      progress[model] += value.length;
    }
    if (at !== end) throw new Error(`the search model's ${part} was cut short`);
  }
  if (hex(await crypto.subtle.digest("SHA-256", bytes)) !== sha256) {
    throw new Error(`the search model's ${name} isn't the file it should be`);
  }
  await cache?.put(key, new Response(bytes)).catch(() => {});
  return bytes;
}

const json = (bytes) => JSON.parse(new TextDecoder().decode(bytes));

/// Each model as it loads (a promise), and whether it has.
const loading = { e5: null, clip: null };
const ready = { e5: false, clip: false };

const loaders = {
  e5: async () => {
    const [onnx, tokenizer, config] = await Promise.all([
      file("e5", "model"),
      file("e5", "tokenizer").then(json),
      file("e5", "tokenizerConfig").then(json),
    ]);
    return loadE5(ort, onnx, tokenizer, config);
  },
  clip: async () => {
    const [onnx, tokenizer, config, dense] = await Promise.all([
      file("clip", "model"),
      file("clip", "tokenizer").then(json),
      file("clip", "tokenizerConfig").then(json),
      file("clip", "dense"),
    ]);
    return loadClip(ort, onnx, tokenizer, config, dense);
  },
};

/// Removes from the Cache API what no model here uses any more: the files
/// of models an update replaced. Once a load has worked, so a model this
/// version can't load isn't left without its old one meanwhile.
let pruned = false;
async function pruneCache() {
  if (pruned) return;
  pruned = true;
  try {
    const cache = await caches.open(CACHE);
    const wanted = new Set(
      Object.keys(MODELS).flatMap((m) => Object.keys(MODELS[m].files).map((f) => cacheKey(m, f))),
    );
    for (const request of await cache.keys()) {
      if (!wanted.has(request.url)) await cache.delete(request);
    }
  } catch {}
}

/// Model `name`, loaded once.
async function use(name) {
  if (!loading[name]) {
    progress[name] = 0;
    loading[name] = loaders[name]();
  }
  try {
    const m = await loading[name];
    ready[name] = true;
    pruneCache();
    return m;
  } catch (e) {
    loading[name] = null;
    throw e;
  }
}

/// Each model's state: loaded, loading, kept here; and how far the
/// downloads under way have come, over all models.
async function state() {
  const out = { loaded: 0, total: 0 };
  for (const name of Object.keys(MODELS)) {
    const busy = !!loading[name] && !ready[name];
    out[name] = { ready: ready[name], loading: busy, cached: await cached(name) };
    if (busy) {
      out.loaded += progress[name];
      out.total += total(name);
    }
  }
  return out;
}

/// The longest side of a photo's thumbnail (raft5fs-search's THUMB_PX).
const THUMB_PX = 256;

/// A photo's thumbnail, as a JPEG: upright (the browser reads its EXIF
/// orientation), at most THUMB_PX on its longest side. Null for a format
/// this browser can't decode.
async function makeThumb(bytes) {
  try {
    const image = await createImageBitmap(new Blob([bytes]));
    const scale = Math.min(1, THUMB_PX / Math.max(image.width, image.height));
    const w = Math.max(1, Math.round(image.width * scale));
    const h = Math.max(1, Math.round(image.height * scale));
    const canvas = new OffscreenCanvas(w, h);
    canvas.getContext("2d").drawImage(image, 0, 0, w, h);
    image.close();
    const blob = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.75 });
    return new Uint8Array(await blob.arrayBuffer());
  } catch {
    return null;
  }
}

let pdfReady = null;

async function readPdf(bytes) {
  pdfReady ??= initPdf();
  await pdfReady;
  try {
    return pdfText(bytes) ?? null;
  } catch {
    // A trap leaves the module unusable: start a new one next time.
    pdfReady = null;
    return null;
  }
}

/// Work runs one message at a time, so a query waits at most one
/// passage.
let queue = Promise.resolve();

onmessage = ({ data: { id, op, texts, query, text, bytes } }) => {
  // How the models are: answered at once, not after queued work.
  if (op === "state") {
    state().then((s) => postMessage({ id, state: s }));
    return;
  }
  queue = queue.then(async () => {
    try {
      if (op === "pdf") {
        postMessage({ id, text: await readPdf(bytes) });
        return;
      }
      if (op === "thumb") {
        const thumb = await makeThumb(bytes);
        postMessage({ id, thumb }, thumb ? [thumb.buffer] : []);
        return;
      }
      if (op === "clip") {
        const vector = await (await use("clip")).embed(text);
        postMessage({ id, vector }, [vector.buffer]);
        return;
      }
      const m = await use("e5");
      const prefix = query ? "query: " : "passage: ";
      const vectors = [];
      for (const t of texts) vectors.push(await m.embed(prefix + t));
      postMessage({ id, vectors }, vectors.map((v) => v.buffer));
    } catch (e) {
      postMessage({ id, error: e?.message ?? String(e) });
    }
  });
};
