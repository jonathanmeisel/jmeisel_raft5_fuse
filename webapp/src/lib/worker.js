// The Web Worker that holds the session. Everything is sealed and opened
// here, in the wasm client, so keys never reach the page. The page calls
// it through `rpc.js`: {id, method, args} in, {id, value} or {id, error}
// out, and {id, progress} on the way for uploads and downloads.
//
// - One tab at a time per account: login takes a Web Lock named for the
//   filesystem and user, held until the Worker ends. The pins and the
//   prune queue in IndexedDB then have one writer.
// - IndexedDB keeps only pins and the prune queue, under
//   `<fsId>/<user>/<name>`. Nothing secret is stored.
import init, * as wasm from "../wasm/raft5fs_web.js";

const config = __RAFT5FS_CONFIG__;
const PIECE = 4 << 20;
let ready = null;
let fs = null;

// ---------------------------------------------------------------- storage

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("raft5fs", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("blobs");
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

function persister(db, prefix) {
  return async (name, bytes) => {
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

/// Holds the account's lock until the Worker ends. False if another tab
/// holds it.
function takeLock(name) {
  return new Promise((resolve) => {
    navigator.locks.request(name, { ifAvailable: true }, (lock) => {
      resolve(!!lock);
      // Held for as long as this promise is pending: until the Worker ends.
      return lock ? new Promise(() => {}) : null;
    });
  });
}

// ----------------------------------------------------------------- methods

function session() {
  if (!fs) throw Object.assign(new Error("not logged in"), { code: "EACCES" });
  return fs;
}

const methods = {
  async enrol(invitation, password) {
    return wasm.enrol(config, invitation, password);
  },

  async login(user, password) {
    if (!(await takeLock(`raft5fs:${config.fsId}:${user}`))) {
      throw Object.assign(
        new Error(`${user} is already open in another tab or window`),
        { code: "EBUSY" },
      );
    }
    const db = await openDb();
    const prefix = `${config.fsId}/${user}/`;
    const blobs = await loadBlobs(db, prefix);
    fs = await wasm.login(config, user, password, blobs, persister(db, prefix));
    return fs.whoami();
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
  pausePruning: () => session().pausePruning(),
  resumePruning: () => session().resumePruning(),
  pruning: () => session().pruning,

  async logout() {
    if (fs) await fs.logout();
    fs = null;
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
