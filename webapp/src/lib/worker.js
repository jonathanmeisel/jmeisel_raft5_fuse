// The Web Worker that holds the session. Everything is sealed and opened
// here, in the wasm client, so keys never reach the page. The page calls
// it through `rpc.js`: {id, method, args} in, {id, value} or {id, error}
// out, and {id, progress} on the way for uploads and downloads.
//
// - The app may serve several filesystems (`filesystems`, from its build
//   config). Each call works on one, chosen at login, or by an invitation's
//   filesystem id at enrolment. Everything stored is filed by that id.
// - One tab at a time per account: login takes a Web Lock named for the
//   filesystem and user, held until the Worker ends. The pins and the
//   prune queue in IndexedDB then have one writer.
// - IndexedDB keeps pins and the prune queue, under `<fsId>/<user>/<name>`.
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

async function lock(user) {
  if (!(await takeLock(`raft5fs:${config.fsId}:${user}`))) {
    throw Object.assign(new Error(`${user} is already open in another tab or window`), {
      code: "EBUSY",
    });
  }
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
        new Error("this invitation is for a filesystem this app isn't set up for"),
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
    await lock(user);
    const db = await openDb();
    const prefix = `${config.fsId}/${user}/`;
    const blobs = await loadBlobs(db, prefix);
    fs = await wasm.login(config, user, password, blobs, persister(db, prefix));
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
    await lock(user);
    const prefix = `${config.fsId}/${user}/`;
    const blobs = await loadBlobs(db, prefix);
    try {
      fs = await wasm.resume(config, user, keys, blobs, persister(db, prefix));
    } catch (e) {
      if (e.code !== "EHOSTUNREACH") await putRecord(db, "unlock", config.fsId, undefined);
      throw e;
    } finally {
      keys.fill(0);
    }
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
