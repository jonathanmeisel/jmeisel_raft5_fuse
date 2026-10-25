// Previews of files, for SVAR's cards and preview pane: images shrunk, and
// the start of text files drawn. The Worker decrypts and draws them (see
// worker.js `preview`); here they are kept as blob: URLs.
//
// - SVAR asks for a preview while it renders, so `url` answers at once:
//   the preview if it is ready, else null, and it starts the work. The map
//   of ready previews is reactive, so SVAR renders again when one arrives.
// - A preview means fetching and decrypting the file (the start of it, for
//   text), so only files up to MAX_BYTES get one, two at a time, and at
//   most MAX_KEPT stay cached.
// - SVG never gets one: it can carry scripts.
import { SvelteMap } from "svelte/reactivity";

const IMAGE = new Set(["jpg", "jpeg", "png", "gif", "webp", "bmp", "avif", "ico"]);
const TEXT = new Set([
  "txt", "md", "markdown", "log", "csv", "tsv", "json", "yaml", "yml", "toml", "ini",
  "conf", "cfg", "env", "sh", "bash", "zsh", "py", "js", "mjs", "ts", "rs", "go",
  "c", "h", "cc", "cpp", "hpp", "java", "kt", "swift", "rb", "php", "pl", "lua",
  "sql", "html", "htm", "css", "xml", "tex", "srt", "vtt",
]);
const MAX_BYTES = 20 << 20;
const MAX_KEPT = 300;
const AT_ONCE = 2;
/// The size that previews are drawn at: SVAR's preview pane's, which the
/// cards show smaller.
const WIDTH = 400;
const HEIGHT = 500;

function extension(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
}

/// "image", "text", or null: what kind of preview a file can have.
export function kindOf(name) {
  const ext = extension(name);
  if (IMAGE.has(ext)) return "image";
  if (TEXT.has(ext)) return "text";
  return null;
}

export function previews(fs) {
  /// Ready previews, by key: a blob: URL, or "" for a file that has none.
  const ready = new SvelteMap();
  const waiting = [];
  const started = new Set();
  let running = 0;

  // A file's key changes when it changes, so an edited file is drawn
  // again.
  const keyOf = (file) => `${file.id}\n${file.size}\n${file.date?.getTime?.() ?? ""}`;

  function next() {
    while (running < AT_ONCE && waiting.length) {
      const { key, file, kind } = waiting.shift();
      running++;
      fs.preview(file.id, kind, WIDTH, HEIGHT)
        .then((blob) => (blob ? URL.createObjectURL(blob) : ""))
        .catch(() => "")
        .then((url) => {
          ready.set(key, url);
          trim();
        })
        .finally(() => {
          running--;
          next();
        });
    }
  }

  // Drops the oldest previews past MAX_KEPT.
  function trim() {
    for (const [key, url] of ready) {
      if (ready.size <= MAX_KEPT) break;
      if (url) URL.revokeObjectURL(url);
      ready.delete(key);
      started.delete(key);
    }
  }

  return {
    /// The preview URL of SVAR's `file`, or null for now.
    url(file) {
      if (file.type !== "file" || !(file.size > 0) || file.size > MAX_BYTES) return null;
      const kind = kindOf(file.name ?? file.id);
      if (!kind) return null;
      const key = keyOf(file);
      if (ready.has(key)) return ready.get(key) || null;
      if (!started.has(key)) {
        started.add(key);
        waiting.push({ key, file, kind });
        // Not while SVAR renders.
        queueMicrotask(next);
      }
      return null;
    },

    /// Frees every preview, at logout.
    clear() {
      waiting.length = 0;
      for (const url of ready.values()) if (url) URL.revokeObjectURL(url);
      ready.clear();
      started.clear();
    },
  };
}
