<script>
  // The files, in SVAR's File Manager. Every action it takes is
  // intercepted and done in the Worker. SVAR's own change is cancelled,
  // and the folders involved are listed again, so what shows is what the
  // servers have. SVAR never gets a URL, so it fetches nothing itself.
  import { Filemanager, WillowDark, getMenuOptions } from "@svar-ui/svelte-filemanager";
  import Fingerprint from "./Fingerprint.svelte";
  import Dialog from "./Dialog.svelte";
  import ShareDialog from "./ShareDialog.svelte";
  import SharedWith from "./SharedWith.svelte";
  import Pending from "./Pending.svelte";
  import PruneBar from "./PruneBar.svelte";
  import Viewer from "./Viewer.svelte";
  import InviteDialog from "./InviteDialog.svelte";
  import { onDestroy } from "svelte";
  import { kindOf, mimeOf, previews } from "../lib/previews.js";
  import { streams } from "../lib/streams.js";
  import { pathHash, readRoute } from "../lib/route.js";

  let { fs, me, storageError, onlogout } = $props();


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
  let transfers = $state([]);
  let nextTransfer = 1;
  let dialog = $state(null);
  let pendingCount = $state(0);
  let pruneQueued = $state(0);
  /// What this account may do (see the wasm `account`).
  let account = $state({ caps: ["volumes"], kind: "person" });

  const parentOf = (path) => path.slice(0, path.lastIndexOf("/")) || "/";
  const nameOf = (path) => path.slice(path.lastIndexOf("/") + 1);
  const join = (dir, name) => (dir === "/" ? "" : dir) + "/" + name;

  function entries(dir, list) {
    return list.map((e) => ({
      id: join(dir, e.name),
      type: e.kind === "folder" ? "folder" : "file",
      size: e.size,
      date: new Date(e.modified),
      ...(e.kind === "folder" ? { lazy: true } : {}),
    }));
  }

  async function load() {
    try {
      initial = entries("/", await fs.readdir("/"));
    } catch (e) {
      error = e.message;
      initial = [];
    }
    refreshPending();
    try {
      account = await fs.account();
    } catch {}
  }
  load();

  async function refreshPending() {
    try {
      pendingCount = (await fs.pending()).length;
    } catch {}
  }

  /// Lists `dir` again and shows it.
  async function reload(dir) {
    try {
      const list = await fs.readdir(dir);
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

  /// Shows a transfer while `work(progress)` runs.
  async function transfer(kind, name, work) {
    const id = nextTransfer++;
    transfers = [...transfers, { id, kind, name, done: 0, total: 0 }];
    const progress = (done, total) => {
      transfers = transfers.map((t) => (t.id === id ? { ...t, done, total } : t));
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

  // ---------------------------------------------------------- the URL
  // The open folder is in the URL's fragment (see route.js): browsing adds
  // a history entry, Back and Forward go back to it, and the app opens at
  // the path it was given.

  /// Whether a navigation comes from the URL, so it adds no history entry.
  let following = false;

  /// Opens `path`: a folder, or a file in its folder (then opened as a
  /// double-click would). Loads each folder on the way, which SVAR only
  /// knows once its parent is listed.
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
    for (let i = 1; i < names.length; i++) await reload("/" + names.slice(0, i).join("/"));
    following = fromUrl;
    try {
      await api.exec("set-path", { id: folder });
    } finally {
      following = false;
    }
    if (kind !== "folder") await api.exec("open-file", { id: path });
  }

  /// Adds a history entry for the folder SVAR moved to.
  function moved({ id }) {
    if (following || !id || location.hash === pathHash(id)) return;
    history.pushState(null, "", pathHash(id));
  }

  const onPopState = () => goTo(readRoute()?.path ?? "/", { fromUrl: true });
  addEventListener("popstate", onPopState);
  onDestroy(() => removeEventListener("popstate", onPopState));

  function init(fm) {
    api = fm;
    api.on("set-path", moved);
    const start = readRoute()?.path;
    if (start && start !== "/") queueMicrotask(() => goTo(start, { fromUrl: true }));
    api.intercept("request-data", ({ id }) => {
      reload(id);
      return false;
    });
    api.intercept("create-file", ({ file, parent }) => {
      if (parent === "/" && !account.caps.includes("volumes")) {
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

  /// SVAR's menus, with sharing for folders. Volumes and shares are the
  /// root's folders, and only folders are shared.
  function menuOptions(mode, item) {
    const options = getMenuOptions(mode);
    if (mode !== "folder" || !item || item.id === "/" || item.id.startsWith("/.snapshot")) {
      return options;
    }
    return [
      ...options,
      { comp: "separator" },
      { id: "share", text: "Share…", icon: "wxi-account", handler: () => (dialog = { kind: "share", path: item.id }) },
      { id: "shared-with", text: "Shared with…", icon: "wxi-account", handler: () => (dialog = { kind: "shared-with", path: item.id }) },
      { id: "prune-again", text: "Prune again", icon: "wxi-sync", handler: () => pruneAgain(item.id) },
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
</script>

<svelte:window onbeforeunload={beforeUnload} />

<div class="layout">
  <header>
    <span class="who">{me.user}{__RAFT5FS_FILESYSTEMS__.length > 1 ? ` on ${me.filesystem}` : ""}</span>
    <span class="spacer"></span>
    <button onclick={() => (dialog = { kind: "pending" })}>
      Shared with me{pendingCount ? ` (${pendingCount} pending)` : ""}
    </button>
    {#if account.caps.includes("invite")}
      <button onclick={() => (dialog = { kind: "invite" })}>Invite someone</button>
    {/if}
    <button onclick={() => (dialog = { kind: "fingerprint" })}>My fingerprint</button>
    <button onclick={onlogout}>Log out</button>
  </header>

  {#if storageError}
    <div class="banner" title={storageError}>Unable to persist state to browser storage</div>
  {/if}
  {#if error}
    <div class="banner error-banner">
      {error}
      <button onclick={() => (error = "")}>Dismiss</button>
    </div>
  {/if}

  <PruneBar {fs} onqueued={(n) => (pruneQueued = n)} />

  {#each transfers as t}
    <div class="transfer">
      {t.kind === "up" ? "Uploading" : "Downloading"} {t.name}: {percent(t)}%
      <progress max="100" value={percent(t)}></progress>
    </div>
  {/each}

  <div class="fm">
    {#if initial}
      <WillowDark fonts={false}>
        <Filemanager
          data={initial}
          {init}
          {menuOptions}
          icons="simple"
          previews={(file) => preview.url(file)}
        />
      </WillowDark>
    {/if}
  </div>
</div>

{#if dialog?.kind === "fingerprint"}
  <Dialog title="My fingerprint" onclose={() => (dialog = null)}>
    <p>Your key's fingerprint</p>
    <Fingerprint fingerprint={me.fingerprint} />
  </Dialog>
{:else if dialog?.kind === "view"}
  <Viewer
    {fs}
    path={dialog.path}
    streams={streaming}
    ondownload={() => act(() => download(dialog.path), [])}
    onclose={() => (dialog = null)}
  />
{:else if dialog?.kind === "share"}
  <ShareDialog {fs} path={dialog.path} onclose={() => (dialog = null)} />
{:else if dialog?.kind === "shared-with"}
  <SharedWith {fs} path={dialog.path} me={me.user} onclose={() => (dialog = null)} />
{:else if dialog?.kind === "invite"}
  <InviteDialog {fs} caps={account.caps} onclose={() => (dialog = null)} />
{:else if dialog?.kind === "pending"}
  <Pending
    {fs}
    onclose={() => {
      dialog = null;
      refreshPending();
      reload("/");
    }}
  />
{/if}

<style>
  .layout { display: flex; flex-direction: column; height: 100%; }
  header {
    display: flex; flex-wrap: wrap; align-items: center; gap: 8px 10px; padding: 8px 14px;
    background: var(--panel); border-bottom: 1px solid var(--border);
  }
  .who {
    color: var(--muted);
    min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  header button { white-space: nowrap; }
  /* Phones: the name on its own line, the buttons sharing the row below. */
  @media (max-width: 600px) {
    header { padding: 8px 10px; }
    .who { flex: 1 0 100%; }
    .spacer { display: none; }
    header button { flex: 1 1 auto; padding: 6px 8px; font-size: 0.9em; }
  }
  .spacer { flex: 1; }
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
</style>
