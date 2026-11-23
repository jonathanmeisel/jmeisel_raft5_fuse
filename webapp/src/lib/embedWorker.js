// The embed Worker: the search model, and the PDF reader, apart from the
// session's Worker, so that minutes of indexing never hold up its calls.
// It holds no keys: the session's Worker sends it text, or a PDF's bytes.
//
// - The model is multilingual-e5-small, the int8 export that native clients
//   also run (raft5fs-indexer's `embed`), served by this app from
//   models/<MODEL>/ (scripts/fetch-model.sh). The model comes in pieces:
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
// Messages: {id, op: "embed", texts, query} → {id, vectors}; {id, op:
// "pdf", bytes} → {id, text}; {id, op: "state"} → {id, state: {ready,
// loading, cached, loaded, total}}, at once. A failure answers {id, error}.
import * as ort from "onnxruntime-web/wasm";
import ortWasm from "onnxruntime-web/ort-wasm-simd-threaded.wasm?url";
import ortMjs from "onnxruntime-web/ort-wasm-simd-threaded.mjs?url";
import { MODEL, loadE5 } from "./e5.js";
import initPdf, { pdfText } from "../wasm/raft5fs_pdf_web.js";

/// Where the app serves the model: public/models/, under the app's base.
const BASE = new URL(`${import.meta.env.BASE_URL}models/${MODEL}/`, self.location.origin);
/// Each file: its pieces and their sizes, and the whole's SHA-256.
const FILES = {
  model: {
    parts: [
      ["model.onnx.0", 60_000_000],
      ["model.onnx.1", 58_308_185],
    ],
    sha256: "f80102d3f2a1229f387d3c81909990d8945513e347b0eab049f7de3c6f98c193",
  },
  tokenizer: {
    parts: [["tokenizer.json", 17_082_730]],
    sha256: "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
  },
  tokenizerConfig: {
    parts: [["tokenizer_config.json", 443]],
    sha256: "a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b",
  },
};
const CACHE = "raft5fs-models";
/// The bytes a first load downloads: every piece of every file.
const TOTAL = Object.values(FILES).reduce((n, f) => n + f.parts.reduce((m, [, size]) => m + size, 0), 0);

ort.env.wasm.wasmPaths = { wasm: ortWasm, mjs: ortMjs };
ort.env.wasm.numThreads = 1;

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const cacheKey = (name) => new URL(`${name}?sha256=${FILES[name].sha256}`, BASE).href;

/// Whether every file of the model is in the Cache API, so loading it
/// downloads nothing.
async function cached() {
  try {
    const cache = await caches.open(CACHE);
    for (const name of Object.keys(FILES)) {
      if (!(await cache.match(cacheKey(name)))) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/// How much of a download has come, over all files, for `state`.
const progress = { loaded: 0, total: TOTAL };

/// File `name`'s bytes, checked: from the Cache API, or else fetched in
/// its pieces straight into one buffer (no copy of the whole), checked
/// and kept.
async function file(name) {
  const { parts, sha256 } = FILES[name];
  const key = cacheKey(name);
  const cache = await caches.open(CACHE).catch(() => null);
  const kept = await cache?.match(key);
  if (kept) {
    const bytes = await kept.arrayBuffer();
    if (hex(await crypto.subtle.digest("SHA-256", bytes)) === sha256) {
      progress.loaded += bytes.byteLength;
      return bytes;
    }
    await cache.delete(key);
  }
  const bytes = new Uint8Array(parts.reduce((n, [, size]) => n + size, 0));
  let at = 0;
  for (const [part, size] of parts) {
    const response = await fetch(new URL(part, BASE));
    if (!response.ok) throw new Error(`the search model's ${part} isn't on this site (${response.status})`);
    const reader = response.body.getReader();
    const end = at + size;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (at + value.length > end) throw new Error(`the search model's ${part} is too long`);
      bytes.set(value, at);
      at += value.length;
      progress.loaded += value.length;
    }
    if (at !== end) throw new Error(`the search model's ${part} was cut short`);
  }
  if (hex(await crypto.subtle.digest("SHA-256", bytes)) !== sha256) {
    throw new Error(`the search model's ${name} isn't the file it should be`);
  }
  await cache?.put(key, new Response(bytes)).catch(() => {});
  return bytes.buffer;
}

let model = null;

async function load() {
  progress.loaded = 0;
  const text = (bytes) => JSON.parse(new TextDecoder().decode(bytes));
  const [onnx, tokenizerJson, tokenizerConfig] = await Promise.all([
    file("model"),
    file("tokenizer").then(text),
    file("tokenizerConfig").then(text),
  ]);
  return loadE5(ort, new Uint8Array(onnx), tokenizerJson, tokenizerConfig);
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

/// Whether the model is loaded, loading, or neither.
let ready = false;

onmessage = ({ data: { id, op, texts, query, bytes } }) => {
  // How the model is: answered at once, not after queued work.
  if (op === "state") {
    cached().then((isCached) =>
      postMessage({
        id,
        state: { ready, loading: !!model && !ready, cached: isCached, ...progress },
      }),
    );
    return;
  }
  queue = queue.then(async () => {
    try {
      if (op === "pdf") {
        postMessage({ id, text: await readPdf(bytes) });
        return;
      }
      model ??= load();
      let m;
      try {
        m = await model;
        ready = true;
      } catch (e) {
        model = null;
        throw e;
      }
      const prefix = query ? "query: " : "passage: ";
      const vectors = [];
      for (const text of texts) vectors.push(await m.embed(prefix + text));
      postMessage({ id, vectors }, vectors.map((v) => v.buffer));
    } catch (e) {
      postMessage({ id, error: e?.message ?? String(e) });
    }
  });
};
