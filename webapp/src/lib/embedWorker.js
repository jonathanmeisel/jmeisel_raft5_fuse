// The embed Worker: the search models, and the PDF reader, apart from the
// session's Worker, so that minutes of indexing never hold up its calls.
// It holds no keys: the session's Worker sends it text, or a PDF's bytes.
//
// - The models are raft5fs-embed's, as native clients run them (the
//   raft5fs-embed-web module): multilingual-e5-small for text, and CLIP's
//   multilingual text side for photos (native devices make photos' image
//   vectors). This app serves their files from models/<name>/
//   (scripts/fetch-models.mjs), as search/data/models.json pins them.
// - A model's body and tokenizer are kept in the Cache API, checked
//   against their SHA-256s. Its word table (about 100 MB, mostly words a
//   query never has) goes to OPFS once, checked as it streams in, and each
//   query reads only its tokens' rows from there: the table is never in
//   memory. Without OPFS (some private windows), the table is held in
//   memory instead.
// - What goes before a query or a passage comes from models.json.
// - PDFs are read by the PDF module (raft5fs-pdf-web). A PDF that makes it
//   trap ends that instance only; the next PDF starts a new one.
// - Photos' thumbnails are drawn here too, on an OffscreenCanvas.
//
// Messages: {id, op: "embed", texts, query} → {id, vectors}; {id, op:
// "clip", text} → {id, vector}; {id, op: "pdf", bytes} → {id, text}; {id,
// op: "thumb", bytes} → {id, thumb}; {id, op: "state"} → {id, state: {text,
// clip: {ready, loading, cached}, loaded, total}}, and {id, op: "memory"},
// at once. A failure answers {id, error}.
import initEmbed, { Model, Sha256, memoryBytes } from "../wasm/raft5fs_embed_web.js";
import initPdf, { pdfText } from "../wasm/raft5fs_pdf_web.js";
// Every model, pinned in one place for every client (see its "about").
import manifest from "../../../search/data/models.json";

/// Where the app serves a model: public/models/<name>/, under its base.
const base = (name) => new URL(`${import.meta.env.BASE_URL}models/${name}/`, self.location.origin);

/// Model `key`'s files that the web app uses, by role: their pieces (as
/// scripts/fetch-models.mjs cuts them) with the pieces' sizes, and the
/// whole's SHA-256 and size.
function webModel(key) {
  const m = manifest.models[key];
  const files = {};
  for (const f of m.files.filter((f) => f.clients.includes("web"))) {
    const count = f.piece ? Math.ceil(f.size / f.piece) : 1;
    const parts = f.piece
      ? Array.from({ length: count }, (_, i) => [`${f.local}.${i}`, Math.min(f.piece, f.size - i * f.piece)])
      : [[f.local, f.size]];
    files[f.role] = { parts, sha256: f.sha256, size: f.size, local: f.local };
  }
  return { ...m, base: base(m.name), files };
}

/// The text model, and CLIP's text side.
const MODELS = { text: webModel("text"), clip: webModel("clip") };
const CACHE = "raft5fs-models";

/// What a first load of model `name` downloads: every piece of every file.
const total = (name) =>
  Object.values(MODELS[name].files).reduce((n, f) => n + f.parts.reduce((m, [, size]) => m + size, 0), 0);

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const cacheKey = (model, name) =>
  new URL(`${name}?sha256=${MODELS[model].files[name].sha256}`, MODELS[model].base).href;

/// How much of each model's download has come, for `state`.
const progress = { text: 0, clip: 0 };

/// The pieces of file `name` of `model`, each as its response's stream, in
/// order, counting what comes in `progress`.
async function* pieces(model, name) {
  for (const [part, size] of MODELS[model].files[name].parts) {
    const response = await fetch(new URL(part, MODELS[model].base));
    if (!response.ok) throw new Error(`the search model's ${part} isn't on this site (${response.status})`);
    const reader = response.body.getReader();
    let got = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      got += value.length;
      if (got > size) throw new Error(`the search model's ${part} is too long`);
      progress[model] += value.length;
      yield value;
    }
    if (got !== size) throw new Error(`the search model's ${part} was cut short`);
  }
}

/// File `name` of `model`, checked: from the Cache API, or else fetched in
/// its pieces straight into one buffer (no copy of the whole), checked
/// and kept.
async function file(model, name) {
  const { size, sha256 } = MODELS[model].files[name];
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
  const bytes = new Uint8Array(size);
  let at = 0;
  for await (const chunk of pieces(model, name)) {
    bytes.set(chunk, at);
    at += chunk.length;
  }
  if (hex(await crypto.subtle.digest("SHA-256", bytes)) !== sha256) {
    throw new Error(`the search model's ${name} isn't the file it should be`);
  }
  await cache?.put(key, new Response(bytes)).catch(() => {});
  return bytes;
}

/// The folder in OPFS that model `model`'s table is kept in.
async function tableDir(model, create) {
  const root = await navigator.storage.getDirectory();
  const models = await root.getDirectoryHandle("models", { create });
  return models.getDirectoryHandle(MODELS[model].name, { create });
}

/// Whether model `model`'s table is in OPFS and was checked: its marker
/// file holds its SHA-256, written once it checked out.
async function tableKept(model) {
  try {
    const dir = await tableDir(model, false);
    const { local, sha256, size } = MODELS[model].files.table;
    const marker = await (await (await dir.getFileHandle(`${local}.sha256`)).getFile()).text();
    const table = await (await dir.getFileHandle(local)).getFile();
    return marker === sha256 && table.size === size ? table : null;
  } catch {
    return null;
  }
}

/// Model `model`'s word table: a way to read rows from it. From OPFS,
/// where it is fetched into once, checked as it comes; or, without OPFS,
/// in memory.
async function table(model) {
  const kept = await tableKept(model);
  if (kept) {
    progress[model] += kept.size;
    return { read: (start, end) => kept.slice(start, end).arrayBuffer() };
  }
  const { local, sha256 } = MODELS[model].files.table;
  let dir;
  try {
    dir = await tableDir(model, true);
  } catch {
    const bytes = await file(model, "table");
    return { read: async (start, end) => bytes.slice(start, end).buffer };
  }
  // A sync handle writes it as it streams in; another tab writing it at
  // the same time holds the lock, and this one waits for its marker.
  let handle;
  try {
    handle = await (await dir.getFileHandle(local, { create: true })).createSyncAccessHandle();
  } catch {
    for (let i = 0; i < 600; i++) {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
      const done = await tableKept(model);
      if (done) return { read: (start, end) => done.slice(start, end).arrayBuffer() };
    }
    throw new Error("the search model's table is being fetched by another tab");
  }
  const sha = new Sha256();
  try {
    handle.truncate(0);
    let at = 0;
    for await (const chunk of pieces(model, "table")) {
      handle.write(chunk, { at });
      sha.update(chunk);
      at += chunk.length;
    }
    handle.flush();
  } finally {
    handle.close();
  }
  if (sha.hex() !== sha256) {
    await dir.removeEntry(local).catch(() => {});
    throw new Error("the search model's table isn't the file it should be");
  }
  const marker = await (await dir.getFileHandle(`${local}.sha256`, { create: true })).createSyncAccessHandle();
  marker.truncate(0);
  marker.write(new TextEncoder().encode(sha256), { at: 0 });
  marker.close();
  const done = await tableKept(model);
  return { read: (start, end) => done.slice(start, end).arrayBuffer() };
}

/// Whether every file of model `name` is kept here, so loading it
/// downloads nothing.
async function cached(model) {
  try {
    const cache = await caches.open(CACHE);
    for (const name of ["body", "tokenizer"]) {
      if (!(await cache.match(cacheKey(model, name)))) return false;
    }
    return !!(await tableKept(model));
  } catch {
    return false;
  }
}

let embedReady = null;
/// The embed module's exports, once loaded (for `memory`).
let embedExports = null;

/// Model `key`, ready to embed: `embed(text)` gives its vector.
async function load(key) {
  embedReady ??= initEmbed().then((e) => (embedExports = e));
  await embedReady;
  const m = MODELS[key];
  const [body, tokenizer, rows] = await Promise.all([file(key, "body"), file(key, "tokenizer"), table(key)]);
  const model = new Model(body, tokenizer, m.pooling, m.maxTokens);
  const size = model.rowBytes();
  return {
    async embed(text) {
      const ids = model.rowIds(text);
      const parts = await Promise.all(Array.from(ids, (id) => rows.read(id * size, (id + 1) * size)));
      const bytes = new Uint8Array(ids.length * size);
      parts.forEach((p, i) => bytes.set(new Uint8Array(p), i * size));
      return model.embed(text, ids, bytes);
    },
  };
}

/// Each model as it loads (a promise), and whether it has.
const loading = { text: null, clip: null };
const ready = { text: false, clip: false };

/// Removes what no model here uses any more: the files of models an update
/// replaced, from the Cache API and OPFS. Once a load has worked, so a
/// model this version can't load isn't left without its old one meanwhile.
let pruned = false;
async function pruneCache() {
  if (pruned) return;
  pruned = true;
  try {
    const cache = await caches.open(CACHE);
    const wanted = new Set(
      Object.keys(MODELS).flatMap((m) => ["body", "tokenizer"].map((f) => cacheKey(m, f))),
    );
    for (const request of await cache.keys()) {
      if (!wanted.has(request.url)) await cache.delete(request);
    }
  } catch {}
  try {
    const models = await (await navigator.storage.getDirectory()).getDirectoryHandle("models");
    const names = new Set(Object.values(MODELS).map((m) => m.name));
    for await (const name of models.keys()) {
      if (!names.has(name)) await models.removeEntry(name, { recursive: true });
    }
  } catch {}
}

/// Model `name`, loaded once.
async function use(name) {
  if (!loading[name]) {
    progress[name] = 0;
    loading[name] = load(name);
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
/// The PDF module's exports, once loaded (for `memory`).
let pdfExports = null;

async function readPdf(bytes) {
  pdfReady ??= initPdf().then((e) => (pdfExports = e));
  await pdfReady;
  try {
    return pdfText(bytes) ?? null;
  } catch {
    // A trap leaves the module unusable: start a new one next time.
    pdfReady = null;
    return null;
  }
}

/// Bytes of WebAssembly memory this Worker holds (the models' module, the
/// PDF module), and which models are loaded.
function memory() {
  return {
    pdfWasm: pdfExports?.memory?.buffer.byteLength ?? 0,
    modelWasm: embedExports ? memoryBytes() : 0,
    loaded: Object.keys(ready).filter((m) => ready[m]),
  };
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
  // What this Worker holds, for measuring memory, at once.
  if (op === "memory") {
    postMessage({ id, memory: memory() });
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
      const m = await use("text");
      const prefix = query ? MODELS.text.query : MODELS.text.passage;
      const vectors = [];
      for (const t of texts) vectors.push(await m.embed(prefix + t));
      postMessage({ id, vectors }, vectors.map((v) => v.buffer));
    } catch (e) {
      postMessage({ id, error: e?.message ?? String(e) });
    }
  });
};
