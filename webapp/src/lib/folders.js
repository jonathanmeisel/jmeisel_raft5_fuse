// Folders the browser hands over, by dragging or from a picker, and uploading
// them as trees. A tree is `{files: [{path, file}], dirs: [path]}`, with paths
// relative to where it goes, and `/` between names.

/// Every entry below `dir`. A directory reader gives a batch at a time (at
/// most 100 in Chromium), and an empty batch when it is done.
async function readAll(dir) {
  const reader = dir.createReader();
  const all = [];
  for (;;) {
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if (batch.length === 0) return all;
    all.push(...batch);
  }
}

async function collect(entry, path, tree) {
  if (entry.isDirectory) {
    tree.dirs.push(path);
    for (const child of await readAll(entry)) {
      await collect(child, `${path}/${child.name}`, tree);
    }
  } else {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    tree.files.push({ path, file });
  }
}

/// The tree of what was dropped, from file system entries. A dropped item only
/// gives its entry while the drop event runs, so take these there.
export async function treeFromEntries(entries) {
  const tree = { files: [], dirs: [] };
  for (const entry of entries) await collect(entry, entry.name, tree);
  return tree;
}

/// The tree of a folder picker's files. It gives no empty folders.
export function treeFromPicker(files) {
  const tree = { files: [], dirs: [] };
  const dirs = new Set();
  for (const file of files) {
    const path = file.webkitRelativePath || file.name;
    tree.files.push({ path, file });
    const names = path.split("/");
    for (let i = 1; i < names.length; i++) dirs.add(names.slice(0, i).join("/"));
  }
  tree.dirs = [...dirs];
  return tree;
}

/// How many files upload at once. Most folders are many small files, where
/// each file's few round trips are the cost, not its bytes.
const AT_ONCE = 4;
/// Refusals that every other file would get too.
const STOPS = new Set(["EDQUOT", "EACCES", "EPERM", "EROFS", "ENOSPC"]);

/// Uploads `tree` into folder `dir`. Returns `{uploaded, skipped, failed}`, with
/// `failed` a list of `{path, message}`, and `stopped`, a reason it ended early.
///
/// - `ask()` says what to do with files that exist already: "skip", "replace"
///   or "cancel". It is asked at most once.
/// - Room is asked for up front for a folder that is new, so a folder that
///   can't fit is refused before anything is stored. For one that exists, each
///   file asks for itself, because replaced files take no more room.
/// - A file that fails doesn't stop the rest, unless they would all fail.
/// - `key` names this upload to `fs.cancelUploads`. `cancelled()` says to start
///   no more.
export async function uploadTree(fs, dir, tree, { key, ask, cancelled, progress }) {
  const join = (name) => (dir === "/" ? "" : dir) + "/" + name;
  const total = tree.files.reduce((n, { file }) => n + file.size, 0);
  const result = { uploaded: 0, skipped: 0, failed: [], stopped: null };

  const bytesUnder = new Map();
  for (const { path, file } of tree.files) {
    const top = path.split("/")[0];
    bytesUnder.set(top, (bytesUnder.get(top) ?? 0) + file.size);
  }
  const tops = new Set(tree.dirs.map((path) => path.split("/")[0]));
  const made = new Set();
  for (const top of tops) {
    const created = await fs.mkdir(join(top)).then(
      () => true,
      (e) => (e.code === "EEXIST" ? false : Promise.reject(e)),
    );
    if (!created) continue;
    made.add(top);
    try {
      await fs.checkRoom(join(top), bytesUnder.get(top) ?? 0);
    } catch (e) {
      for (const each of made) await fs.remove(join(each)).catch(() => {});
      throw e;
    }
  }
  const deeper = tree.dirs.filter((path) => path.includes("/"));
  deeper.sort((a, b) => a.split("/").length - b.split("/").length);
  for (const path of deeper) {
    if (cancelled()) break;
    await fs.mkdir(join(path)).catch((e) => {
      if (e.code !== "EEXIST") result.failed.push({ path, message: e.message });
    });
  }

  let policy = null;
  let asking = null;
  const decide = () => {
    asking ??= ask().then((answer) => (policy = answer));
    return asking;
  };

  const done = new Map();
  const report = () => {
    const bytes = [...done.values()].reduce((a, b) => a + b, 0);
    const files = result.uploaded + result.skipped + result.failed.length;
    progress(bytes, total, files, tree.files.length);
  };

  const stop = () => result.stopped || cancelled();

  async function uploadOne({ path, file }) {
    const tick = (bytes) => {
      done.set(path, bytes);
      report();
    };
    const send = (overwrite) => fs.upload(join(path), file, overwrite, tick, key);
    try {
      try {
        await send(policy === "replace");
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
        const answer = await decide();
        if (answer === "cancel") {
          result.stopped = "cancelled";
          return;
        }
        if (answer === "skip") {
          result.skipped++;
          done.set(path, file.size);
          return;
        }
        await send(true);
      }
      result.uploaded++;
      done.set(path, file.size);
    } catch (e) {
      if (e.code === "ECANCELED") return;
      result.failed.push({ path, message: e.message });
      if (STOPS.has(e.code)) result.stopped = e.message;
    } finally {
      report();
    }
  }

  const queue = [...tree.files];
  async function worker() {
    while (queue.length && !stop()) await uploadOne(queue.shift());
  }
  await Promise.all(Array.from({ length: AT_ONCE }, worker));
  if (cancelled() && !result.stopped) result.stopped = "cancelled";
  return result;
}
