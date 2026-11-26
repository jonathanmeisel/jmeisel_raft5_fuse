// This browser's search settings, kept for the browser, not the account.
// The browser doesn't index: native devices do.
//
// - Whether to download each folder's index, to search it here: by
//   default yes, unless it is over 500 MiB (the wasm `searchLoad` decides).
//   A folder whose index isn't downloaded isn't searched here.
// - "Keep search data on this device": the index segments it has read, so
//   a search here fetches only what is new. Off for a borrowed computer.
// - Whether to download the search models (about 130 MB for text, and 150
//   MB more where photos have image vectors, once) to search by
//   meaning: on a computer without asking; on a phone or tablet, or with
//   the browser's Data Saver or a slow connection, only once the person
//   says yes (`meaningAllowed`).
import { mobile } from "./pruneSetting.js";

const KEEP = "raft5fs:keep-search";
const DOWNLOAD = "raft5fs:index-download";
const MEANING = "raft5fs:search-meaning";

function read(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {}
}

/// Whether to download `volume`'s index (as the root shows it, like
/// "/photos"): true, false, or null for the default.
export function download(volume) {
  try {
    const all = JSON.parse(read(DOWNLOAD) ?? "{}");
    const v = all?.[volume];
    return typeof v === "boolean" ? v : null;
  } catch {
    return null;
  }
}

export function setDownload(volume, on) {
  let all = {};
  try {
    all = JSON.parse(read(DOWNLOAD) ?? "{}") ?? {};
  } catch {}
  all[volume] = !!on;
  write(DOWNLOAD, JSON.stringify(all));
}

export const keepSearch = () => read(KEEP) !== "off";
export const setKeepSearch = (on) => write(KEEP, on ? "on" : "off");

/// The search models' sizes, as the question about them says: for text,
/// and for photos (CLIP's text side).
export const MODEL_MB = 130;
export const PHOTO_MODEL_MB = 150;

/// Whether a download is worth asking about here: a phone or tablet, Data
/// Saver, or a slow connection.
export function askBeforeModel() {
  const net = navigator.connection;
  if (net?.saveData) return true;
  if (["slow-2g", "2g", "3g"].includes(net?.effectiveType)) return true;
  return mobile();
}

/// Whether search may load the model: "yes", "no", or "ask" (no answer
/// yet, where it is asked).
export function meaningAllowed() {
  const kept = read(MEANING);
  if (kept === "yes" || kept === "no") return kept;
  return askBeforeModel() ? "ask" : "yes";
}

export const setMeaningAllowed = (yes) => write(MEANING, yes ? "yes" : "no");

