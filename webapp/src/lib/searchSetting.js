// This browser's search settings, kept for the browser, not the account:
//
// - "Index for search on this device": on by default for a computer, off
//   for a phone or tablet, as for re-sealing (pruneSetting.js). Indexing
//   reads every changed file, for its words only (native devices add
//   vectors); another device that can write a volume indexes it if this
//   one doesn't.
// - Volumes this browser doesn't index (others still may).
// - "Keep search data on this device": the index segments it has read, so
//   a search here fetches only what is new. Off for a borrowed computer.
// - Whether to download the search models (about 130 MB for text, and 150
//   MB more where photos have image vectors, once) to search by
//   meaning: on a computer without asking; on a phone or tablet, or with
//   the browser's Data Saver or a slow connection, only once the person
//   says yes (`meaningAllowed`).
import { mobile } from "./pruneSetting.js";

const INDEX = "raft5fs:index-here";
const SKIP = "raft5fs:index-skip";
const KEEP = "raft5fs:keep-search";
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

export function indexHere() {
  const kept = read(INDEX);
  if (kept === "on" || kept === "off") return kept === "on";
  return !mobile();
}

export const setIndexHere = (on) => write(INDEX, on ? "on" : "off");

/// The volumes (as the root shows them, like "/photos") this browser skips.
export function indexSkip() {
  try {
    const list = JSON.parse(read(SKIP) ?? "[]");
    return Array.isArray(list) ? list.filter((v) => typeof v === "string") : [];
  } catch {
    return [];
  }
}

export const setIndexSkip = (list) => write(SKIP, JSON.stringify(list));

export const keepSearch = () => read(KEEP) !== "off";
export const setKeepSearch = (on) => write(KEEP, on ? "on" : "off");

/// What the status of an index calls this browser: "Firefox on Linux".
export function deviceName() {
  const ua = navigator.userAgent;
  const name =
    (/Edg\//.test(ua) && "Edge") ||
    (/Firefox\//.test(ua) && "Firefox") ||
    (/Chrome\//.test(ua) && "Chrome") ||
    (/Safari\//.test(ua) && "Safari") ||
    "a browser";
  const os =
    (/Android/.test(ua) && "Android") ||
    (/iPhone|iPad/.test(ua) && "iOS") ||
    (/Mac OS X/.test(ua) && "macOS") ||
    (/Windows/.test(ua) && "Windows") ||
    (/Linux/.test(ua) && "Linux") ||
    "";
  return os ? `${name} on ${os}` : name;
}

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

