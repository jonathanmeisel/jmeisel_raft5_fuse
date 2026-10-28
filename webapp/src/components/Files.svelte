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
  import AccountMenu from "./AccountMenu.svelte";
  import SharingBar from "./SharingBar.svelte";
  import LinkDialog from "./LinkDialog.svelte";
  import LinksDialog from "./LinksDialog.svelte";
  import { onDestroy } from "svelte";
  import { kindOf, mimeOf, previews } from "../lib/previews.js";
  import { streams } from "../lib/streams.js";
  import { pathHash, readRoute } from "../lib/route.js";
  import { sharedIcon } from "../lib/sharedIcons.js";

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
      shared: e.shared ?? null,
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
    if (visitor) return;
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
  let hereAsked = 0;

  async function showSharing(path) {
    current = path;
    const asked = ++hereAsked;
    let found = null;
    if (!visitor && path !== "/") {
      try {
        found = await fs.sharingHere(path);
      } catch {}
    }
    // A later move asked again meanwhile: its answer wins.
    if (asked === hereAsked) here = found;
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
      ...(account.caps.includes("links")
        ? [{ id: "share-link", text: "Share publicly…", icon: "wxi-link", handler: () => (dialog = { kind: "link", path: item.id }) }]
        : []),
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

  /// The account menu: what the account does besides files.
  const menuItems = $derived([
    { id: "pending", text: "Shared with me", icon: "wxi-file-multiple-outline", badge: pendingCount || 0 },
    ...(account.caps.includes("invite") ? [{ id: "invite", text: "Invite someone", icon: "wxi-plus" }] : []),
    ...(account.caps.includes("links") ? [{ id: "links", text: "Public links", icon: "wxi-link" }] : []),
    { id: "fingerprint", text: "My fingerprint", icon: "wxi-information-outline" },
    { id: "logout", text: "Log out", icon: "wxi-external", separator: true },
  ]);

  /// Closes a dialog that may have changed what is shared, and lists
  /// again the folder that shows it, so its mark is right.
  function closeSharing() {
    const path = dialog?.path;
    dialog = null;
    const state = api?.getState();
    reload(path ? parentOf(path) : (state?.panels[state.activePanel]?.path ?? "/"));
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
      <AccountMenu user={me.user} items={menuItems} onselect={chose} />
    {/if}
  </header>

  {#if pendingCount && !visitor}
    <div class="banner">
      {pendingCount === 1 ? "A share is" : `${pendingCount} shares are`} waiting for you to check who
      sent {pendingCount === 1 ? "it" : "them"}.
      <button onclick={() => (dialog = { kind: "pending" })}>Review</button>
    </div>
  {/if}

  {#if storageError}
    <div class="banner" title={storageError}>Unable to persist state to browser storage</div>
  {/if}
  {#if error}
    <div class="banner error-banner">
      {error}
      <button onclick={() => (error = "")}>Dismiss</button>
    </div>
  {/if}

  {#if !visitor}
    <PruneBar {fs} onqueued={(n) => (pruneQueued = n)} />
  {/if}

  {#each transfers as t}
    <div class="transfer">
      {t.kind === "up" ? "Uploading" : "Downloading"} {t.name}: {percent(t)}%
      <progress max="100" value={percent(t)}></progress>
    </div>
  {/each}

  <SharingBar {here} {current} ondetails={(path) => (dialog = { kind: "shared-with", path })} />

  <div class="fm">
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
  <ShareDialog {fs} path={dialog.path} onclose={closeSharing} />
{:else if dialog?.kind === "shared-with"}
  <SharedWith {fs} path={dialog.path} me={me.user} links={account.caps.includes("links")} onclose={closeSharing} />
{:else if dialog?.kind === "link"}
  <LinkDialog {fs} path={dialog.path} onclose={closeSharing} />
{:else if dialog?.kind === "links"}
  <LinksDialog {fs} onclose={closeSharing} />
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
</style>
