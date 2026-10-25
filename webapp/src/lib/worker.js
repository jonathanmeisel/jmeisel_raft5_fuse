// The Web Worker that holds the session. Everything is sealed and opened
// here, in the wasm client, so keys never reach the page. The page calls
// it through `rpc.js`: {id, method, args} in, {id, value} or {id, error}
// out, and {id, progress} on the way for uploads and downloads.
//
// - The app may serve several filesystems (`filesystems`, from its build
//   config). Each call works on one, chosen at login, or by an invitation's
//   filesystem id at enrolment. Everything stored is filed by that id.
// - IndexedDB keeps pins and the prune queue, under `<fsId>/<user>/<name>`.
//   Each tab on an account keeps its own copy in the wasm client; every
//   save also goes to the account's other tabs (a BroadcastChannel), so
//   none of them saves over another's change.
// - One tab at a time runs the background prune: the one holding the
//   account's prune lock (a Web Lock). When it closes, the next tab takes
//   over.
// - With "stay unlocked", it also keeps the account's unlock keys (what a
//   password gives a login), for one account per filesystem and for
//   REMEMBER_MS. They are encrypted (AES-GCM) under a key that WebCrypto
//   made non-extractable: scripts on this origin can use it, but nothing
//   can read it out of the browser. Logging out deletes them.
import init, * as wasm from "../wasm/raft5fs_web.js";

const filesystems = __RAFT5FS_FILESYSTEMS__;
/// The filesystem of the session (or the enrolment) in this Worker.
let config = null;
const PIECE = 4 << 20;
const REMEMBER_MS = 7 * 24 * 60 * 60 * 1000;
let ready = null;
let fs = null;

// ---------------------------------------------------------------- storage

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("raft5fs", 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("blobs")) db.createObjectStore("blobs");
      if (!db.objectStoreNames.contains("unlock")) db.createObjectStore("unlock");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function done(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}

/// The account's blobs, by name.
async function loadBlobs(db, prefix) {
  const blobs = new Map();
  const transaction = db.transaction("blobs", "readonly");
  const range = IDBKeyRange.bound(prefix, prefix + "￿");
  await new Promise((resolve, reject) => {
    const request = transaction.objectStore("blobs").openCursor(range);
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return resolve();
      blobs.set(cursor.key.slice(prefix.length), new Uint8Array(cursor.value));
      cursor.continue();
    };
    request.onerror = () => reject(request.error);
  });
  return blobs;
}

/// Saves blobs to IndexedDB, and tells the account's other tabs.
function persister(db, prefix, channel) {
  return async (name, bytes) => {
    channel.postMessage({ name, bytes });
    try {
      const transaction = db.transaction("blobs", "readwrite");
      transaction.objectStore("blobs").put(bytes.slice().buffer, prefix + name);
      await done(transaction);
    } catch (e) {
      // The page shows it: an unsaved prune queue matters.
      postMessage({ event: "storage-error", message: String(e) });
    }
  };
}

async function getRecord(db, store, key) {
  const transaction = db.transaction(store, "readonly");
  const request = transaction.objectStore(store).get(key);
  await done(transaction);
  return request.result;
}

async function putRecord(db, store, key, value) {
  const transaction = db.transaction(store, "readwrite");
  if (value === undefined) transaction.objectStore(store).delete(key);
  else transaction.objectStore(store).put(value, key);
  await done(transaction);
}

/// What the encryption binds the keys to, so a record can't be moved to
/// another account or given a later expiry.
const aad = (user, expires) => new TextEncoder().encode(`raft5fs-unlock:1:${config.fsId}:${user}:${expires}`);

async function remember(db, user, keys) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const expires = Date.now() + REMEMBER_MS;
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(user, expires) },
    key,
    keys,
  );
  keys.fill(0);
  await putRecord(db, "unlock", config.fsId, { user, key, iv, sealed, expires });
}

/// The filesystem with id `fsId`.
function filesystem(fsId) {
  const found = filesystems.find((f) => f.fsId === fsId);
  if (!found) {
    throw Object.assign(new Error("this app isn't set up for that filesystem"), {
      code: "EINVAL",
    });
  }
  return found;
}

/// The remembered account of `config`'s filesystem and its keys, or null.
/// Drops an expired record.
async function recall(db) {
  const record = await getRecord(db, "unlock", config.fsId);
  if (!record) return null;
  if (!(record.expires > Date.now())) {
    await putRecord(db, "unlock", config.fsId, undefined);
    return null;
  }
  try {
    const keys = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: record.iv, additionalData: aad(record.user, record.expires) },
      record.key,
      record.sealed,
    );
    return { user: record.user, keys: new Uint8Array(keys), expires: record.expires };
  } catch {
    await putRecord(db, "unlock", config.fsId, undefined);
    return null;
  }
}

// ------------------------------------------------------------------ tabs

/// Whether this tab runs the account's background prune.
let prunesHere = false;

/// The account's channel to its other tabs, opened before its blobs are
/// read, so no save made meanwhile is missed: saves that arrive before
/// the session exists wait in `early`.
function openChannel(user) {
  const channel = new BroadcastChannel(`raft5fs:${config.fsId}:${user}`);
  const early = [];
  channel.onmessage = ({ data: { name, bytes } }) => {
    if (fs) fs.storeUpdated(name, bytes);
    else early.push([name, bytes]);
  };
  return { channel, early };
}

/// Once the session exists: applies the saves that arrived first, and
/// waits for the account's prune lock, to run the background prune while
/// it holds it (until the Worker ends).
function joined(user, { early }) {
  for (const [name, bytes] of early.splice(0)) fs.storeUpdated(name, bytes);
  navigator.locks.request(`raft5fs:${config.fsId}:${user}:prune`, () => {
    if (!fs) return null;
    prunesHere = true;
    fs.resumePruning();
    return new Promise(() => {});
  });
}

// ----------------------------------------------------------------- reading

/// How much of a text file its preview draws from.
const TEXT_PREVIEW_BYTES = 8 << 10;

/// Up to `max` bytes from the start of file `path`.
async function readHead(path, max) {
  const s = session();
  const { size } = await s.stat(path);
  const want = Math.min(size, max);
  const handle = await s.open(path, false, false);
  const parts = [];
  let got = 0;
  try {
    while (got < want) {
      const piece = await s.read(handle, got, Math.min(PIECE, want - got));
      if (piece.length === 0) break;
      parts.push(piece);
      got += piece.length;
    }
  } finally {
    await s.close(handle);
  }
  const bytes = new Uint8Array(got);
  let at = 0;
  for (const part of parts) {
    bytes.set(part, at);
    at += part.length;
  }
  return bytes;
}

/// `bytes` as UTF-8 text, or null if it looks like something else: a NUL,
/// or many bytes that aren't UTF-8. A character cut off at the end is fine.
function asText(bytes) {
  if (bytes.includes(0)) return null;
  const text = new TextDecoder("utf-8").decode(bytes);
  const bad = (text.match(/\uFFFD/g) || []).length;
  return bad > 4 + text.length / 100 ? null : text;
}

// ----------------------------------------------------------------- methods

function session() {
  if (!fs) throw Object.assign(new Error("not logged in"), { code: "EACCES" });
  return fs;
}

const methods = {
  /// Enrols with `invitation`, on the filesystem it is for.
  async enrol(invitation, password) {
    let fsId;
    try {
      fsId = wasm.invitationFsId(invitation);
    } catch (e) {
      throw Object.assign(new Error(e.message), { code: e.code });
    }
    config = filesystems.find((f) => f.fsId === fsId);
    if (!config) {
      throw Object.assign(
        new Error("not a valid invitation"),
        { code: "EINVAL" },
      );
    }
    return { ...(await wasm.enrol(config, invitation, password)), fsId };
  },

  /// Logs in to filesystem `fsId`. With `stay`, remembers the account on
  /// this device; without it, forgets any account remembered here for that
  /// filesystem.
  async login(fsId, user, password, stay) {
    config = filesystem(fsId);
    const tabs = openChannel(user);
    const db = await openDb();
    const prefix = `${config.fsId}/${user}/`;
    const blobs = await loadBlobs(db, prefix);
    try {
      fs = await wasm.login(config, user, password, blobs, persister(db, prefix, tabs.channel));
    } catch (e) {
      tabs.channel.close();
      throw e;
    }
    joined(user, tabs);
    if (stay) await remember(db, user, fs.unlockKeys());
    else await putRecord(db, "unlock", config.fsId, undefined);
    return { ...fs.whoami(), remembered: !!stay, fsId: config.fsId, filesystem: config.name };
  },

  /// Logs the remembered account in, if there is one (the newest, if
  /// several filesystems have one); else null. Forgets it if the servers
  /// refuse it (its password changed), but not if they can't be reached.
  async resume() {
    const db = await openDb();
    let remembered = null;
    for (const candidate of filesystems) {
      config = candidate;
      const found = await recall(db);
      if (found && (!remembered || found.expires > remembered.found.expires)) {
        remembered?.found.keys.fill(0);
        remembered = { found, config: candidate };
      } else {
        found?.keys.fill(0);
      }
    }
    if (!remembered) return null;
    config = remembered.config;
    remembered = remembered.found;
    const { user, keys } = remembered;
    const tabs = openChannel(user);
    const prefix = `${config.fsId}/${user}/`;
    const blobs = await loadBlobs(db, prefix);
    try {
      fs = await wasm.resume(config, user, keys, blobs, persister(db, prefix, tabs.channel));
    } catch (e) {
      tabs.channel.close();
      if (e.code !== "EHOSTUNREACH") await putRecord(db, "unlock", config.fsId, undefined);
      throw e;
    } finally {
      keys.fill(0);
    }
    joined(user, tabs);
    return { ...fs.whoami(), remembered: true, fsId: config.fsId, filesystem: config.name };
  },

  checkNewPassword: (password) => wasm.checkNewPassword(password),
  whoami: () => session().whoami(),
  readdir: (path) => session().readdir(path),
  stat: (path) => session().stat(path),
  mkdir: (path) => session().mkdir(path),
  remove: (path) => session().remove(path),
  rename: (from, to) => session().rename(from, to),
  copy: (from, to) => session().copy(from, to),

  /// Writes `file` (a File) to `path`, a piece at a time.
  async upload(path, file, overwrite) {
    const s = session();
    if (!overwrite) {
      const exists = await s.stat(path).then(
        () => true,
        (e) => (e.code === "ENOENT" ? false : Promise.reject(e)),
      );
      if (exists) {
        throw Object.assign(new Error(`${path} already exists`), {
          code: "EEXIST",
        });
      }
    }
    const handle = await s.open(path, true, true);
    try {
      for (let at = 0; at < file.size; at += PIECE) {
        const piece = new Uint8Array(
          await file.slice(at, at + PIECE).arrayBuffer(),
        );
        await s.write(handle, at, piece);
        this.progress(Math.min(at + PIECE, file.size), file.size);
      }
    } finally {
      await s.close(handle);
    }
  },

  /// The whole of file `path`, as a Blob.
  async download(path) {
    const s = session();
    const { size } = await s.stat(path);
    const handle = await s.open(path, false, false);
    const parts = [];
    try {
      for (let at = 0; at < size; at += PIECE) {
        const piece = await s.read(handle, at, PIECE);
        if (piece.length === 0) break;
        parts.push(piece);
        this.progress(Math.min(at + piece.length, size), size);
      }
    } finally {
      await s.close(handle);
    }
    return new Blob(parts);
  },

  /// A preview of file `path`, as a small image Blob that fits in
  /// `width` x `height`: the picture shrunk, or the start of the text
  /// drawn. `kind` is "image" or "text" (see previews.js). Null if it
  /// doesn't decode.
  async preview(path, kind, width, height) {
    const bytes = await readHead(path, kind === "text" ? TEXT_PREVIEW_BYTES : Infinity);
    const canvas = new OffscreenCanvas(width, height);
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, width, height);
    if (kind === "image") {
      let bitmap;
      try {
        bitmap = await createImageBitmap(new Blob([bytes]));
      } catch {
        return null;
      }
      const scale = Math.min(1, width / bitmap.width, height / bitmap.height);
      const w = Math.max(1, Math.round(bitmap.width * scale));
      const h = Math.max(1, Math.round(bitmap.height * scale));
      canvas.width = w;
      canvas.height = h;
      ctx.fillStyle = "#fff";
      ctx.fillRect(0, 0, w, h);
      ctx.drawImage(bitmap, 0, 0, w, h);
      bitmap.close();
    } else {
      const text = asText(bytes);
      if (text === null) return null;
      // Large enough to read on a card, which shows it at about half size.
      ctx.fillStyle = "#1d2330";
      ctx.font = "22px ui-monospace, monospace";
      const lines = text.split("\n");
      const lineHeight = 28;
      for (let i = 0; i < lines.length && (i + 1) * lineHeight < height - 16; i++) {
        ctx.fillText(lines[i].replace(/\t/g, "    ").slice(0, 100), 16, 16 + (i + 1) * lineHeight - 6);
      }
    }
    // PNG keeps drawn text sharp; JPEG is smaller for pictures.
    return canvas.convertToBlob(
      kind === "text" ? { type: "image/png" } : { type: "image/jpeg", quality: 0.85 },
    );
  },

  /// The start of text file `path`, up to `max` bytes: {text, truncated},
  /// or null if it isn't text.
  async readText(path, max) {
    const bytes = await readHead(path, max + 1);
    const truncated = bytes.length > max;
    const text = asText(truncated ? bytes.subarray(0, max) : bytes);
    return text === null ? null : { text, truncated };
  },

  isPinned: (user) => session().isPinned(user),
  share: (path, user, writable, label, fingerprint) =>
    session().share(path, user, writable, label, fingerprint || undefined),
  sharedWith: (path) => session().sharedWith(path),
  revoke: (path, user) => session().revoke(path, user),
  pending: () => session().pending(),
  trust: (user, words) => session().trust(user, words),
  forgetKey: (user) => session().forgetKey(user),
  pruneStatus: () => session().pruneStatus(),
  pruneEstimate: (path) => session().pruneEstimate(path),
  pruneAgain: (path) => session().pruneAgain(path),
  /// Pause and resume act only in the tab that runs the prune.
  pausePruning: () => prunesHere && session().pausePruning(),
  resumePruning: () => prunesHere && session().resumePruning(),
  /// "running" or "paused" here, or "elsewhere": another tab runs it.
  pruning: () => (prunesHere ? (session().pruning ? "running" : "paused") : "elsewhere"),

  /// Logs out, and forgets the account if this device remembered it.
  async logout() {
    if (fs) await fs.logout();
    fs = null;
    if (config) await putRecord(await openDb(), "unlock", config.fsId, undefined);
  },
};

onmessage = async ({ data: { id, method, args } }) => {
  try {
    ready ??= init();
    await ready;
    const call = methods[method];
    if (!call) throw new Error(`no method ${method}`);
    // Long calls report how far they got through `this.progress`.
    const progress = (done, total) => postMessage({ id, progress: { done, total } });
    const value = await call.apply({ progress }, args);
    postMessage({ id, value });
  } catch (e) {
    postMessage({
      id,
      error: { message: e?.message ?? String(e), code: e?.code ?? "EIO" },
    });
  }
};
