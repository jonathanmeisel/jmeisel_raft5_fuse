<script>
  // The files, in SVAR's File Manager. Every action it takes is
  // intercepted and done in the Worker. SVAR's own change is cancelled,
  // and the folders involved are listed again, so what shows is what the
  // servers have. SVAR never gets a URL, so it fetches nothing itself.
  import { Filemanager, WillowDark, getMenuOptions } from "@svar-ui/svelte-filemanager";
  import Fingerprint from "./Fingerprint.svelte";
  import ErrorText from "./ErrorText.svelte";
  import Dialog from "./Dialog.svelte";
  import ShareDialog from "./ShareDialog.svelte";
  import SharedWith from "./SharedWith.svelte";
  import Pending from "./Pending.svelte";
  import PruneBar from "./PruneBar.svelte";
  import Viewer from "./Viewer.svelte";
  import UsersDialog from "./UsersDialog.svelte";
  import AccountMenu from "./AccountMenu.svelte";
  import SharingBar from "./SharingBar.svelte";
  import LinkDialog from "./LinkDialog.svelte";
  import LinksDialog from "./LinksDialog.svelte";
  import People from "./People.svelte";
  import TransferDialog from "./TransferDialog.svelte";
  import LimitDialog from "./LimitDialog.svelte";
  import Versions from "./Versions.svelte";
  import Activity from "./Activity.svelte";
  import { sizeText } from "../lib/sizes.js";
  import { onDestroy } from "svelte";
  import { kindOf, mimeOf, previews } from "../lib/previews.js";
  import { streams } from "../lib/streams.js";
  import { pathHash, readRoute } from "../lib/route.js";
  import { sharedIcon } from "../lib/sharedIcons.js";
  import { treeFromEntries, treeFromPicker, uploadTree } from "../lib/folders.js";

  let { fs, me, storageError, onlogout } = $props();
  /// A public link's visitor: read-only, one folder, nothing of an account.
  // svelte-ignore state_referenced_locally
  const visitor = !!me.visitor;


  // svelte-ignore state_referenced_locally
  const preview = previews(fs);
  /// Streams through the service worker (see streams.js).
  // svelte-ignore state_referenced_locally
  const streaming = streams(fs);
  onDestroy(() => streaming.end());
  onDestroy(() => preview.clear());
  /// The largest file of each kind that the viewer opens whole (decrypted
  /// into memory); bigger ones download, unless they can stream.
  const MAX_VIEW_BYTES = { image: 50 << 20, text: 50 << 20, video: 500 << 20, audio: 500 << 20, pdf: 500 << 20 };
  /// The kinds that can play or show from a stream (see streams.js).
  const STREAMED = new Set(["video", "audio", "pdf"]);

  let api = null;
  let initial = $state(null);
  let error = $state("");
  /// What a finished folder transfer has to say, when it isn't an error.
  let notice = $state("");
  let transfers = $state([]);
  let nextTransfer = 1;
  let dialog = $state(null);
  let pendingCount = $state(0);
  let pruneQueued = $state(0);
  /// Whether this tab is re-sealing now, and video or audio is playing.
  let pruning = false;
  let playing = false;

  /// Whether work is in progress that an idle logout would kill: a transfer,
  /// a stream the browser is reading (a download, say), playing media, or a
  /// re-seal.
  export function busy() {
    return transfers.length > 0 || streaming.reading() || playing || pruning;
  }
  /// What this account may do (see the wasm `account`).
  let account = $state({ caps: ["volumes"], kind: "person" });
  /// How much this account's top-level folders hold (see the wasm
  /// `storage`), and the folders offered to it.
  let storage = $state(null);
  let offered = $state([]);

  const parentOf = (path) => path.slice(0, path.lastIndexOf("/")) || "/";
  const nameOf = (path) => path.slice(path.lastIndexOf("/") + 1);
  const join = (dir, name) => (dir === "/" ? "" : dir) + "/" + name;

  function entries(dir, list) {
    return list.map((e) => ({
      id: join(dir, e.name),
      type: e.kind === "folder" ? "folder" : "file",
      // SVAR shows a size only if there is one: none for a folder not
      // measured yet.
      ...(e.size != null ? { size: e.size } : {}),
      date: new Date(e.modified),
      shared: e.shared ?? null,
      group: !!e.group,
      top: !!e.top,
      ...(e.kind === "folder" ? { lazy: true } : {}),
    }));
  }

  async function load() {
    try {
      const list = await fs.readdir("/");
      shown.set("/", JSON.stringify(list));
      initial = entries("/", list);
    } catch (e) {
      error = e.message;
      initial = [];
    }
    if (visitor) return;
    refreshPending();
    refreshOffers();
    refreshStorage();
    try {
      account = await fs.account();
    } catch {}
  }
  load();

  async function refreshStorage() {
    try {
      storage = await fs.storage();
    } catch {}
  }

  async function refreshOffers() {
    try {
      offered = (await fs.offers()).filter((o) => o.to === me.user && o.path);
    } catch {}
  }

  /// Accepts or declines a folder offered to this account.
  function answer(offer, accept) {
    act(async () => {
      try {
        await fs.answerOffer(offer.path, accept);
      } finally {
        await refreshOffers();
        await refreshStorage();
      }
    }, []);
  }

  const storageNote = $derived(
    storage
      ? storage.quota
        ? `${sizeText(storage.used)} of ${sizeText(storage.quota)} used`
        : `${sizeText(storage.used)} used`
      : "",
  );

  // ---------------------------------------------------------- staying current
  // Others share things and change files while this tab is open, and a reload
  // means logging in again. So the app looks every minute while the tab is in
  // view, and as soon as it comes back into view.

  const POLL_MS = 60_000;
  let polling = false;
  /// The folder last listed, to show a new listing only if it differs:
  /// showing one disturbs what is on screen.
  let shown = new Map();

  async function poll() {
    if (visitor || polling || document.hidden || !api) return;
    polling = true;
    try {
      await Promise.all([refreshPending(), refreshOffers()]);
      account = await fs.account();
      const root = await listIfChanged("/");
      // Listing a folder makes SVAR forget what was in those inside it, so a
      // change in the root lists again down to the open one.
      if (root && current !== "/") await relistDown("/", current);
      else if (current !== "/") await listIfChanged(current);
    } catch {
    } finally {
      polling = false;
    }
  }

  /// Lists `dir`, and shows it if it changed. Says if it did.
  async function listIfChanged(dir) {
    const list = await fs.readdir(dir);
    const seen = JSON.stringify(list);
    if (shown.get(dir) === seen) return false;
    shown.set(dir, seen);
    await api.exec("provide-data", { id: dir, data: entries(dir, list) });
    return true;
  }

  /// Lists again the folders below `top`, down to `open`.
  async function relistDown(top, open) {
    const inside = top === "/" ? "/" : top + "/";
    if (open === top || !open.startsWith(inside)) return;
    let folder = top;
    for (const name of open.slice(inside.length).split("/").filter(Boolean)) {
      folder = join(folder, name);
      await reload(folder);
    }
  }

  const onVisible = () => poll();
  const pollTimer = setInterval(poll, POLL_MS);
  addEventListener("focus", onVisible);
  document.addEventListener("visibilitychange", onVisible);
  onDestroy(() => {
    clearInterval(pollTimer);
    removeEventListener("focus", onVisible);
    document.removeEventListener("visibilitychange", onVisible);
  });

  async function refreshPending() {
    try {
      pendingCount = (await fs.pending()).filter((p) => p.state !== "trusted").length;
    } catch {}
  }

  /// Lists `dir` again and shows it.
  async function reload(dir) {
    try {
      const list = await fs.readdir(dir);
      shown.set(dir, JSON.stringify(list));
      await api.exec("provide-data", { id: dir, data: entries(dir, list) });
    } catch (e) {
      if (e.code !== "ENOENT") fail(e);
    }
  }

  function fail(e) {
    error = e.message;
  }

  /// Runs `work`, shows any failure, then lists `dirs` again.
  async function act(work, dirs) {
    error = "";
    try {
      await work();
    } catch (e) {
      fail(e);
    } finally {
      for (const dir of new Set(dirs)) await reload(dir);
    }
  }

  /// A name in `dir` like `name` that isn't taken: "a.txt", "a (copy).txt".
  async function freeName(dir, name) {
    const taken = new Set((await fs.readdir(dir)).map((e) => e.name));
    if (!taken.has(name)) return name;
    const dot = name.lastIndexOf(".");
    const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ""];
    for (let n = 1; ; n++) {
      const candidate = `${stem} (copy${n > 1 ? " " + n : ""})${ext}`;
      if (!taken.has(candidate)) return candidate;
    }
  }

  /// Shows a transfer while `work(progress)` runs. `progress` can also say
  /// how many of how many files, and `cancel` adds a button that stops it.
  async function transfer(kind, name, work, cancel = null) {
    const id = nextTransfer++;
    transfers = [...transfers, { id, kind, name, done: 0, total: 0, cancel }];
    const progress = (done, total, files = null, ofFiles = null) => {
      transfers = transfers.map((t) => (t.id === id ? { ...t, done, total, files, ofFiles } : t));
    };
    try {
      return await work(progress);
    } finally {
      transfers = transfers.filter((t) => t.id !== id);
    }
  }

  function upload(dir, file) {
    const path = join(dir, file.name);
    return transfer("up", file.name, async (progress) => {
      try {
        await fs.upload(path, file, false, progress);
      } catch (e) {
        if (e.code !== "EEXIST" || !confirm(`${file.name} already exists. Replace it?`)) throw e;
        await fs.upload(path, file, true, progress);
      }
    });
  }

  async function download(path) {
    const name = nameOf(path);
    // Streamed straight to disk by the browser, which shows its progress.
    // Through a hidden frame: a navigation reaches the service worker,
    // where an <a download> click wouldn't, and the stream's
    // `Content-Disposition: attachment` makes it a download.
    if (streaming.available()) {
      const { url } = await streaming.open(path, mimeOf(name), { download: true });
      const frame = document.createElement("iframe");
      frame.hidden = true;
      frame.src = url;
      document.body.append(frame);
      setTimeout(() => frame.remove(), 60_000);
      return;
    }
    const { size } = await fs.stat(path);
    if (size > 1 << 30 && !confirm(
      `${nameOf(path)} is ${(size / (1 << 30)).toFixed(1)} GB. The browser holds all of it in memory while it downloads. Do you want to continue?`,
    )) return;
    const blob = await transfer("down", nameOf(path), (progress) =>
      fs.download(path, progress, mimeOf(nameOf(path))),
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = nameOf(path);
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  // ---------------------------------------------------------- folders

  /// Whether what is made in `dir` is a new top-level folder: it is the root,
  /// or a group in it.
  const inRoot = (dir) => dir === "/" || !!api?.getFile(dir)?.group;

  /// What to do with files that exist already, from a person.
  function askExisting() {
    return new Promise((answer) => {
      dialog = {
        kind: "exists",
        answer: (choice) => {
          dialog = null;
          answer(choice);
        },
      };
    });
  }

  /// `what` a folder transfer did, for the banner: `Uploaded 3 files`.
  const counted = (n, what) => `${n} ${what}${n === 1 ? "" : "s"}`;

  /// Uploads `tree` into folder `dir`, and says what became of it.
  async function uploadFolder(dir, tree) {
    if (tree.files.length === 0 && tree.dirs.length === 0) return;
    if (inRoot(dir) && !account.caps.includes("volumes")) {
      error = "You can't create top-level folders here. Open a folder shared with you to add things to it.";
      return;
    }
    notice = "";
    const key = `upload-${nextTransfer}`;
    let cancelling = false;
    const cancelled = () => cancelling;
    const name = tree.dirs.length ? tree.dirs[0].split("/")[0] : counted(tree.files.length, "file");
    await act(async () => {
      const result = await transfer(
        "up",
        name,
        (progress) => uploadTree(fs, dir, tree, { key, ask: askExisting, cancelled, progress }),
        () => {
          cancelling = true;
          fs.cancelUploads(key);
        },
      );
      const said = [`Uploaded ${counted(result.uploaded, "file")}`];
      if (result.skipped) said.push(`skipped ${result.skipped} that already exist`);
      if (result.stopped === "cancelled") said.push("then stopped, as you asked");
      if (result.failed.length) {
        const shown = result.failed.slice(0, 5).map((f) => `${f.path}: ${f.message}`);
        const more = result.failed.length - shown.length;
        error = `${said.join(", ")}. ${counted(result.failed.length, "file")} failed:\n${shown.join("\n")}${more > 0 ? `\nand ${more} more` : ""}`;
      } else {
        notice = `${said.join(", ")}.`;
      }
    }, [dir, current]);
  }

  /// Asks for a folder, and uploads it to the open one.
  function pickFolder() {
    const input = document.createElement("input");
    input.type = "file";
    input.webkitdirectory = true;
    input.onchange = () => uploadFolder(current, treeFromPicker(input.files));
    input.click();
  }

  /// Takes a dropped folder from SVAR, which would upload all its files into
  /// the open folder, without their folders. Plain files stay with SVAR.
  function dropFolder(event) {
    if (visitor) return;
    const entries = [...(event.dataTransfer?.items ?? [])]
      .filter((i) => i.kind === "file")
      .map((i) => i.webkitGetAsEntry?.())
      .filter(Boolean);
    if (!entries.some((e) => e.isDirectory)) return;
    // SVAR's handler still has to run, to clear its drop highlight. It reads
    // the drop's items, so show it none.
    Object.defineProperty(event, "dataTransfer", { value: { items: [] } });
    const dir = current;
    treeFromEntries(entries).then((tree) => uploadFolder(dir, tree), fail);
  }

  /// How long a download's stream can go unread before it counts as abandoned.
  /// The browser doesn't always say that someone cancelled it.
  const ABANDONED_MS = 5 * 60 * 1000;

  /// Downloads `paths`, files or folders, as one ZIP. It goes straight to disk
  /// where it can, and through memory where it can't, as a file does.
  async function downloadZip(paths) {
    const name = paths.length === 1 ? nameOf(paths[0]) : nameOf(parentOf(paths[0])) || "files";
    const filename = `${name}.zip`;
    await transfer("down", filename, async (progress) => {
      const { id, bytes: total } = await fs.zipOpen(paths);
      let sent = 0;
      const read = async () => {
        const bytes = await fs.zipRead(id);
        sent += bytes.byteLength;
        progress(Math.min(sent, total), total);
        return bytes;
      };
      try {
        if (streaming.available()) {
          await new Promise((finished) => {
            let last = Date.now();
            const watching = setInterval(() => {
              if (Date.now() - last > ABANDONED_MS) streaming.close(token);
            }, 30_000);
            const url = streaming.openArchive(
              filename,
              () => {
                last = Date.now();
                return read();
              },
              () => {
                clearInterval(watching);
                finished();
              },
            );
            const token = url.split("/")[2];
            const frame = document.createElement("iframe");
            frame.hidden = true;
            frame.src = url;
            document.body.append(frame);
            setTimeout(() => frame.remove(), 60_000);
          });
        } else {
          if (total > 1 << 30 && !confirm(
            `This is ${(total / (1 << 30)).toFixed(1)} GB. The browser holds all of it in memory while it downloads. Do you want to continue?`,
          )) return;
          const parts = [];
          for (;;) {
            const bytes = await read();
            if (bytes.byteLength === 0) break;
            parts.push(bytes);
          }
          const url = URL.createObjectURL(new Blob(parts, { type: "application/zip" }));
          const a = document.createElement("a");
          a.href = url;
          a.download = filename;
          a.click();
          setTimeout(() => URL.revokeObjectURL(url), 60_000);
        }
      } finally {
        const errors = await fs.zipClose(id).catch(() => []);
        if (errors.length) {
          error = `${counted(errors.length, "item")} couldn't be read, and ${errors.length === 1 ? "is" : "are"} listed in DOWNLOAD-ERRORS.txt in the ZIP:\n${errors.slice(0, 5).join("\n")}`;
        }
      }
    });
  }

  const selectedPaths = () => {
    const { panels, activePanel } = api.getState();
    return panels[activePanel].selected;
  };

  // ---------------------------------------------------------- the URL
  // The open folder is in the URL's fragment (see route.js): browsing adds
  // a history entry, Back and Forward go back to it, and the app opens at
  // the path it was given.

  /// Whether a navigation comes from the URL, so it adds no history entry.
  let following = false;

  /// Opens `path`: a folder, or a file in its folder (then opened as a
  /// double-click would). Lists each folder on the way, which SVAR only
  /// knows once its parent is listed, and the folder itself: listing a
  /// parent again makes SVAR forget what was in it.
  async function goTo(path, { fromUrl = false } = {}) {
    let kind = "folder";
    try {
      kind = (await fs.stat(path)).kind;
    } catch {
      if (path !== "/") error = `There's nothing at ${path} that you can see.`;
      path = "/";
    }
    const folder = kind === "folder" ? path : parentOf(path);
    const names = folder.split("/").filter(Boolean);
    for (let i = 1; i <= names.length; i++) await reload("/" + names.slice(0, i).join("/"));
    following = fromUrl;
    try {
      await api.exec("set-path", { id: folder });
    } finally {
      following = false;
    }
    if (kind !== "folder") await api.exec("open-file", { id: path });
  }

  /// The open folder, and how it is shared (see SharingBar).
  let current = $state("/");
  let here = $state(null);
  /// The open folder's size and size limit, if it has a limit.
  let limited = $state(null);
  let hereAsked = 0;

  async function showSharing(path) {
    current = path;
    const asked = ++hereAsked;
    let found = null;
    let size = null;
    if (!visitor && path !== "/") {
      [found, size] = await Promise.all([
        fs.sharingHere(path).catch(() => null),
        fs.folderSize(path).catch(() => null),
      ]);
    }
    // A later move asked again meanwhile: its answer wins.
    if (asked === hereAsked) {
      here = found;
      limited = size?.limit ? size : null;
    }
  }

  /// Adds a history entry for the folder SVAR moved to.
  function moved({ id }) {
    if (id) showSharing(id);
    if (following || !id || location.hash === pathHash(id)) return;
    history.pushState(null, "", pathHash(id));
  }

  const onPopState = () => goTo(readRoute()?.path ?? "/", { fromUrl: true });
  addEventListener("popstate", onPopState);
  onDestroy(() => removeEventListener("popstate", onPopState));

  function init(fm) {
    api = fm;
    api.on("set-path", moved);
    const start = readRoute()?.path ?? (visitor ? "/" + me.folder : null);
    if (start && start !== "/") queueMicrotask(() => goTo(start, { fromUrl: true }));
    api.intercept("request-data", ({ id }) => {
      reload(id);
      return false;
    });
    api.intercept("create-file", ({ file, parent }) => {
      if (inRoot(parent) && !account.caps.includes("volumes")) {
        error = "You can't create top-level folders here. Open a folder shared with you to add things to it.";
        return false;
      }
      const work = file.file
        ? () => upload(parent, file.file)
        : file.type === "folder"
          ? () => fs.mkdir(join(parent, file.name))
          : async () => {
              const created = join(parent, file.name);
              await fs.upload(created, new Blob([]), false);
            };
      act(work, [parent]);
      return false;
    });
    api.intercept("rename-file", ({ id, name }) => {
      // A share's name is its label here, which is this account's own.
      if (api.getFile(id)?.top) {
        act(() => relabel(id, join(parentOf(id), name).slice(1)), []);
        return false;
      }
      act(() => fs.rename(id, join(parentOf(id), name)), [parentOf(id)]);
      return false;
    });
    api.intercept("delete-files", ({ ids }) => {
      act(async () => {
        for (const id of ids) await fs.remove(id);
      }, ids.map(parentOf));
      return false;
    });
    api.intercept("move-files", ({ ids, target }) => {
      act(async () => {
        for (const id of ids) {
          if (parentOf(id) !== target) await fs.rename(id, join(target, nameOf(id)));
        }
      }, [target, ...ids.map(parentOf)]);
      return false;
    });
    api.intercept("copy-files", ({ ids, target }) => {
      act(async () => {
        for (const id of ids) {
          await fs.copy(id, join(target, await freeName(target, nameOf(id))));
        }
      }, [target]);
      return false;
    });
    api.intercept("download-file", ({ id }) => {
      act(() => download(id), []);
      return false;
    });
    // Images, text, video, audio and PDFs open in the viewer; anything
    // else downloads.
    api.intercept("open-file", ({ id }) => {
      const file = api.getFile(id);
      const kind = kindOf(nameOf(id));
      const streams = STREAMED.has(kind) && streaming?.available();
      if (kind && (streams || !(file?.size > MAX_VIEW_BYTES[kind]))) {
        dialog = { kind: "view", path: id };
      } else {
        act(() => download(id), []);
      }
      return false;
    });
  }

  /// Shows the share at `path` as `label`, and lists again where it was and
  /// the root, where it may have made a group. Goes to the root only if the
  /// open folder went with it, or with a group that nothing shows in now.
  async function relabel(path, label) {
    await fs.relabelShare(path, label);
    await reload("/");
    await reload(parentOf(path));
    const open = current;
    const gone = await fs.stat(open).then(
      () => false,
      (e) => e.code === "ENOENT",
    );
    if (gone && current === open) await goTo("/");
  }

  /// SVAR's menus, with sharing for folders. Volumes and shares are the
  /// root's folders, and only folders are shared. What is used less is behind
  /// More, so the menu stays short. More opens a panel, not a submenu: SVAR's
  /// submenus open only on hover, so a phone couldn't reach one.
  function menuOptions(mode, item) {
    const options = getMenuOptions(mode);
    // A file's history is its versions, with the changes between them. A
    // folder's has its activity too, as a tab.
    const history = {
      id: "history",
      text: "History",
      icon: "wxi-sync",
      handler: () => (dialog = { kind: item.type === "folder" && item.top ? "activity" : "versions", path: item.id }),
    };
    if (mode === "file" && item && !item.id.startsWith("/.snapshot")) return [options[0], history, ...options.slice(1)];
    if (mode === "add") {
      return [
        ...options,
        { id: "upload-folder", text: "Upload folder", icon: "mdi mdi-folder-upload-outline", handler: pickFolder },
      ];
    }
    if (mode === "multiselect") {
      return [
        { id: "download-zip", text: "Download as ZIP", icon: "wxi-download", handler: () => act(() => downloadZip(selectedPaths()), []) },
        ...options,
      ];
    }
    if (mode !== "folder" || !item || item.id === "/" || item.id === "/.snapshot") return options;
    const zip = { id: "download-zip", text: "Download as ZIP", icon: "wxi-download", handler: () => act(() => downloadZip([item.id]), []) };
    if (item.id.startsWith("/.snapshot") || item.group) return [zip, ...(item.group ? [] : options)];
    const more = [
      { text: "Size limit", open: () => (dialog = { kind: "limit", path: item.id }) },
      ...(item.top
        ? [
            { text: "Show as", open: () => (dialog = { kind: "show-as", path: item.id, label: item.id.slice(1) }) },
            { text: "Transfer ownership", open: () => (dialog = { kind: "transfer", path: item.id }) },
          ]
        : []),
      {
        text: "Prune again",
        open: () => {
          dialog = null;
          pruneAgain(item.id);
        },
      },
    ];
    return [
      zip,
      history,
      ...options,
      { comp: "separator" },
      { id: "sharing", text: "Sharing", icon: "wxi-account", handler: () => (dialog = { kind: "shared-with", path: item.id }) },
      { id: "more", text: "More", icon: "wxi-dots-v", handler: () => (dialog = { kind: "more", path: item.id, more }) },
    ];
  }

  async function pruneAgain(path) {
    error = "";
    try {
      await fs.pruneAgain(path);
    } catch (e) {
      fail(e);
    }
  }

  // Closing the tab now would lose an upload, or leave a prune for later.
  function beforeUnload(event) {
    if (transfers.some((t) => t.kind === "up") || pruneQueued > 0) {
      event.preventDefault();
    }
  }

  const percent = (t) => (t.total ? Math.floor((100 * t.done) / t.total) : 0);

  /// The account menu: what the account does besides files.
  const menuItems = $derived([
    { id: "pending", text: "Shared with me", icon: "wxi-file-multiple-outline", badge: pendingCount || 0 },
    { id: "people", text: "People", icon: "wxi-account" },
    ...(account.caps.includes("admin") ? [{ id: "users", text: "Users", icon: "wxi-account" }] : []),
    ...(account.caps.includes("links") ? [{ id: "links", text: "Public links", icon: "wxi-link" }] : []),
    { id: "fingerprint", text: "My safety code", icon: "wxi-information-outline" },
    { id: "logout", text: "Log out", icon: "wxi-external", separator: true },
  ]);

  /// Closes a dialog that may have changed what is shared, and lists
  /// again the folder that shows it, so its mark is right. Listing a folder
  /// makes SVAR forget what was in the folders inside it, so the folders on
  /// the way down to the open one are listed again too.
  async function closeSharing() {
    const path = dialog?.path;
    dialog = null;
    const state = api?.getState();
    const open = state?.panels[state.activePanel]?.path ?? current;
    const top = path ? parentOf(path) : open;
    await reload(top);
    await relistDown(top, open);
    showSharing(current);
  }

  function chose(id) {
    if (id === "logout") onlogout();
    else dialog = { kind: id };
  }

  const several = __RAFT5FS_FILESYSTEMS__.length > 1;
</script>

<svelte:window onbeforeunload={beforeUnload} />

<WillowDark fonts={false}>
<div class="layout">
  <header>
    {#if visitor}
      <span class="title">
        <i class="wxi-folder logo" aria-hidden="true"></i>
        <span class="fs">Shared with you: read-only</span>
      </span>
      <button class="close" onclick={onlogout}>Close</button>
    {:else}
      <span class="title">
        <i class="wxi-folder logo" aria-hidden="true"></i>
        {#if several}<span class="fs">{me.filesystem}</span>{/if}
      </span>
      <AccountMenu user={me.user} items={menuItems} onselect={chose} note={storageNote} onopen={refreshStorage} />
    {/if}
  </header>

  {#if pendingCount && !visitor}
    <div class="banner">
      {pendingCount === 1 ? "A share needs" : `${pendingCount} shares need`} checking. You can already
      open {pendingCount === 1 ? "it" : "them"}, but check who sent {pendingCount === 1 ? "it" : "them"} to be sure.
      <button onclick={() => (dialog = { kind: "pending" })}>Review</button>
    </div>
  {/if}

  {#each offered as offer (offer.path)}
    <div class="banner">
      <span>
        <strong>{offer.from}</strong> wants to give you <strong>{offer.path.slice(1)}</strong>
        ({sizeText(offer.bytes)}). It would count against your storage.
      </span>
      <span>
        <button onclick={() => answer(offer, true)}>Accept</button>
        <button onclick={() => answer(offer, false)}>Decline</button>
      </span>
    </div>
  {/each}

  {#if storageError}
    <div class="banner" title={storageError}>Unable to persist state to browser storage</div>
  {/if}
  {#if error}
    <div class="banner error-banner">
      <ErrorText {fs} message={error} />
      <button onclick={() => (error = "")}>Dismiss</button>
    </div>
  {/if}
  {#if notice}
    <div class="banner">
      {notice}
      <button onclick={() => (notice = "")}>Dismiss</button>
    </div>
  {/if}
  {#if visitor}
    <div class="banner">
      <button onclick={() => act(() => downloadZip([current === "/" ? "/" + me.folder : current]), [])}>
        Download this folder as a ZIP
      </button>
    </div>
  {/if}

  {#if !visitor}
    <PruneBar
      {fs}
      onqueued={(n, running) => {
        pruneQueued = n;
        pruning = running;
      }}
    />
  {/if}

  {#each transfers as t}
    <div class="transfer">
      {t.kind === "up" ? "Uploading" : "Downloading"} {t.name}:
      {#if t.ofFiles != null}{t.files} of {t.ofFiles} files,{/if}
      {percent(t)}%
      <progress max="100" value={percent(t)}></progress>
      {#if t.cancel}<button onclick={t.cancel}>Cancel</button>{/if}
    </div>
  {/each}

  <SharingBar {here} {current} {limited} ondetails={(path) => (dialog = { kind: "shared-with", path })} />

  <div class="fm" role="presentation" ondropcapture={dropFolder}>
    {#if initial}
        <Filemanager
          data={initial}
          {init}
          {menuOptions}
          readonly={visitor}
          icons={sharedIcon}
          previews={(file) => preview.url(file)}
        />
    {/if}
  </div>
</div>
</WillowDark>

{#if dialog?.kind === "fingerprint"}
  <Dialog title="My safety code" onclose={() => (dialog = null)}>
    <p class="note">
      These 12 words are your safety code. The first time you share with someone, you'll each
      read yours to the other, so you know you've really reached each other. No need to save it: it's
      always under your name, in My safety code.
    </p>
    <Fingerprint fingerprint={me.fingerprint} />
  </Dialog>
{:else if dialog?.kind === "show-as"}
  <Dialog title="Show as" onclose={() => (dialog = null)}>
    <form
      onsubmit={(event) => {
        event.preventDefault();
        const { path, label } = dialog;
        dialog = null;
        act(() => relabel(path, label.trim()), []);
      }}
    >
      <label for="show-as">What this folder shows up to you as</label>
      <input id="show-as" bind:value={dialog.label} required />
      <p class="note">
        A / puts it in a group: CS101/assignments shows inside a CS101 folder. This changes it only
        for you.
      </p>
      <p>
        <button class="primary" type="submit">Save</button>
        <button type="button" onclick={() => (dialog = null)}>Cancel</button>
      </p>
    </form>
  </Dialog>
{:else if dialog?.kind === "exists"}
  <Dialog title="Some files already exist" keep onclose={() => dialog.answer("cancel")}>
    <p>Some of the files in this folder are already there. What should happen to them?</p>
    <p>
      <button class="primary" onclick={() => dialog.answer("skip")}>Skip existing</button>
      <button onclick={() => dialog.answer("replace")}>Replace all</button>
      <button onclick={() => dialog.answer("cancel")}>Cancel upload</button>
    </p>
  </Dialog>
{:else if dialog?.kind === "view"}
  <Viewer
    {fs}
    path={dialog.path}
    streams={streaming}
    onmedia={(on) => (playing = on)}
    ondownload={() => act(() => download(dialog.path), [])}
    onversions={visitor || dialog.path.startsWith("/.snapshot") ? null : () => (dialog = { kind: "versions", path: dialog.path })}
    onclose={() => (dialog = dialog.back ?? null)}
  />
{:else if dialog?.kind === "more"}
  <Dialog title={nameOf(dialog.path)} onclose={() => (dialog = null)}>
    <div class="more">
      {#each dialog.more as choice (choice.text)}
        <button onclick={choice.open}>{choice.text}</button>
      {/each}
    </div>
    <p><button onclick={() => (dialog = null)}>Close</button></p>
  </Dialog>
{:else if dialog?.kind === "activity"}
  <Activity
    {fs}
    path={dialog.path}
    onversions={(path) => (dialog = { kind: "versions", path })}
    ontab={api?.getFile(dialog.path)?.top ? null : () => (dialog = { kind: "versions", path: dialog.path })}
    onclose={() => (dialog = null)}
  />
{:else if dialog?.kind === "versions"}
  <Versions
    {fs}
    path={dialog.path}
    free={freeName}
    ontab={api?.getFile(dialog.path)?.type === "folder" ? () => (dialog = { kind: "activity", path: dialog.path }) : null}
    onopen={(version) => {
      if (version.kind === "folder") {
        dialog = null;
        goTo(version.path);
      } else {
        dialog = { kind: "view", path: version.path, back: dialog };
      }
    }}
    ondownload={(version) =>
      act(() => (version.kind === "folder" ? downloadZip([version.path]) : download(version.path)), [])}
    onrestored={(dir, text) => {
      notice = text;
      reload(dir);
    }}
    onclose={() => (dialog = null)}
  />
{:else if dialog?.kind === "share"}
  <ShareDialog {fs} path={dialog.path} mine={me.fingerprint} onclose={closeSharing} />
{:else if dialog?.kind === "shared-with"}
  <SharedWith
    {fs}
    path={dialog.path}
    me={me.user}
    links={account.caps.includes("links")}
    onshare={() => (dialog = { kind: "share", path: dialog.path })}
    onlink={() => (dialog = { kind: "link", path: dialog.path })}
    onclose={closeSharing}
  />
{:else if dialog?.kind === "transfer"}
  <TransferDialog {fs} path={dialog.path} me={me.user} onclose={() => (dialog = null)} />
{:else if dialog?.kind === "limit"}
  <LimitDialog
    {fs}
    path={dialog.path}
    me={me.user}
    admin={account.caps.includes("admin")}
    onclose={() => {
      dialog = null;
      showSharing(current);
    }}
  />
{:else if dialog?.kind === "link"}
  <LinkDialog {fs} path={dialog.path} onclose={closeSharing} />
{:else if dialog?.kind === "links"}
  <LinksDialog {fs} onclose={closeSharing} />
{:else if dialog?.kind === "users"}
  <UsersDialog {fs} me={me.user} onclose={() => (dialog = null)} />
{:else if dialog?.kind === "people"}
  <People
    {fs}
    mine={me.fingerprint}
    onclose={() => {
      dialog = null;
      refreshPending();
    }}
  />
{:else if dialog?.kind === "pending"}
  <Pending
    {fs}
    me={me.user}
    mine={me.fingerprint}
    onclose={() => {
      dialog = null;
      refreshPending();
      reload("/");
    }}
  />
{/if}

<style>
  .layout { display: flex; flex-direction: column; height: 100%; }
  /* In SVAR's colours and sizes, as one bar with its toolbar below. */
  header {
    display: flex; align-items: center; gap: 12px;
    height: 52px; padding: 0 12px 0 16px; flex: none;
    background: var(--wx-background); border-bottom: var(--wx-border-medium);
    font-size: var(--wx-font-size);
  }
  .title {
    flex: 1; min-width: 0; display: flex; align-items: center; gap: 10px;
    overflow: hidden; white-space: nowrap;
  }
  /* SVAR's folder icon, in its colour, as in the folder tree. The glyph
     sits high in its box, so it moves down to look centred. */
  .logo {
    font-size: 28px; line-height: 1; color: var(--wx-color-primary); flex: none;
    transform: translateY(2px);
  }
  .fs { color: var(--wx-color-font-alt); overflow: hidden; text-overflow: ellipsis; }
  .close {
    height: 36px; border: none; border-radius: var(--wx-radius-major, 6px);
    background: var(--wx-background-alt); color: var(--wx-color-font);
  }
  .banner {
    padding: 8px 14px; background: var(--warn-bg); border-bottom: 1px solid var(--border);
    display: flex; gap: 12px; align-items: center; justify-content: space-between;
  }
  .error-banner { color: var(--danger); white-space: pre-wrap; }
  .transfer {
    padding: 6px 14px; display: flex; gap: 10px; align-items: center;
    background: var(--panel); border-bottom: 1px solid var(--border);
  }
  .fm { flex: 1; min-height: 0; }
  .more { display: flex; flex-direction: column; align-items: stretch; gap: 8px; }
</style>
