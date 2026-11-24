<script>
  // Search, in the header: by words and by meaning, in the open top-level
  // folder or in all of them (see the wasm `search`).
  //
  // - Each folder's index is read the first time it is searched, and again
  //   once it is a minute old (the wasm `searchLoad` decides). The Worker
  //   keeps what it has read (unless this browser's setting says not to),
  //   so reading again fetches only what is new.
  // - A share of a folder inside someone's top-level folder has no index of
  //   its own yet, so it isn't searched.
  // - Typing searches after a pause; Enter searches at once; Escape closes
  //   the results.
  // - On a narrow screen it is a button, so the header keeps room for the
  //   folder menu: the button opens the search bar across the whole header,
  //   and its own close button shuts it again.
  // - Words first, at once; then meaning, which may need the model loaded
  //   (and the first time, downloaded), so its results replace the first
  //   ones when they come. Where a download is worth asking about (a phone,
  //   Data Saver, a slow connection), it asks first (searchSetting.js).
  import * as searchSetting from "../lib/searchSetting.js";
  import { onDestroy } from "svelte";
  import { SvelteMap } from "svelte/reactivity";

  let { fs, folder, onopen } = $props();

  const PAUSE_MS = 300;

  /// On a narrow screen: whether the search bar is open over the header.
  let expanded = $state(false);
  let box = $state(null);

  function expand() {
    expanded = true;
    // Once the bar shows.
    setTimeout(() => box?.focus());
  }

  function collapse() {
    expanded = false;
    open = false;
  }

  let query = $state("");
  let everywhere = $state(false);
  let open = $state(false);
  let busy = $state(false);
  let results = $state([]);
  let status = $state([]);
  let error = $state("");
  /// The meaning search: "" (none, or done), "asking" (whether to
  /// download the model), "loading", or a note on why it gave words only.
  let meaning = $state("");
  /// How far the model's download is: {loaded, total}, while it loads.
  let download = $state(null);
  /// "Not now", for the rest of this page's life.
  let notNow = false;
  /// The models the last search needs to search by meaning: "e5" for
  /// text, "clip" for photos.
  let needed = $state([]);
  const neededMB = $derived(
    (needed.includes("e5") ? searchSetting.MODEL_MB : 0) +
      (needed.includes("clip") ? searchSetting.PHOTO_MODEL_MB : 0),
  );
  /// Photos' thumbnails, by id, as blob: URLs (null while loading or if
  /// one can't be read).
  const thumbs = new SvelteMap();
  onDestroy(() => {
    for (const url of thumbs.values()) if (url) URL.revokeObjectURL(url);
  });

  /// Fetches the thumbnails of the results that have one and aren't
  /// fetched yet. (Not from the markup: rendering mustn't change state.)
  $effect(() => {
    for (const hit of results) {
      const id = hit.thumb;
      if (!id || thumbs.has(id)) continue;
      thumbs.set(id, null);
      fs.searchThumb(id).then(
        (bytes) => thumbs.set(id, URL.createObjectURL(new Blob([bytes], { type: "image/jpeg" }))),
        () => {},
      );
    }
  });
  let asked = 0;
  let timer = null;

  /// The top-level folder of `path`, or null for the root.
  const volumeOf = (path) => {
    const first = path.split("/").filter(Boolean)[0];
    return first ? "/" + first : null;
  };

  /// The volumes to search: the open one, or every top-level one (and those
  /// in groups).
  async function scope() {
    const here = volumeOf(folder);
    if (here && !everywhere) return [here];
    const list = await fs.readdir("/");
    const out = [];
    for (const e of list) {
      if (e.kind !== "folder" || e.name === ".snapshot") continue;
      if (!e.group) {
        out.push("/" + e.name);
        continue;
      }
      for (const inner of await fs.readdir("/" + e.name).catch(() => [])) {
        if (inner.kind === "folder") out.push(`/${e.name}/${inner.name}`);
      }
    }
    return out;
  }

  async function ensureRead(volumes) {
    const loaded = [];
    for (const v of volumes) {
      try {
        loaded.push(await fs.searchLoad(v));
      } catch (e) {
        // A share of a folder inside a volume, or a group: not searched.
        if (e.code !== "EINVAL") throw e;
      }
    }
    return loaded;
  }

  async function run() {
    clearTimeout(timer);
    const q = query.trim();
    if (!q) {
      results = [];
      return;
    }
    const mine = ++asked;
    busy = true;
    error = "";
    meaning = "";
    open = true;
    let volumes;
    try {
      const loaded = await ensureRead(await scope());
      volumes = loaded.map((l) => l.volume);
      const found = await fs.search(q, volumes, 50, false);
      if (mine !== asked) return;
      status = loaded;
      results = found.hits;
      if (!found.meaning) return;
      needed = [...(found.vectors ? ["e5"] : []), ...(found.images ? ["clip"] : [])];
    } catch (e) {
      if (mine === asked) error = e.message;
      return;
    } finally {
      if (mine === asked) busy = false;
    }
    await byMeaning(mine, q, volumes);
  }

  /// Searches again by meaning too, if the model is here or may be fetched.
  async function byMeaning(mine, q, volumes) {
    const allowed = searchSetting.meaningAllowed();
    const model = await fs.modelState().catch(() => null);
    if (mine !== asked) return;
    const here = !!model && needed.every((m) => model[m]?.ready || model[m]?.cached);
    if (!here && (allowed === "no" || (allowed === "ask" && notNow))) return;
    if (!here && allowed === "ask") {
      meaning = "asking";
      return;
    }
    meaning = "loading";
    const watch = here
      ? null
      : setInterval(async () => {
          const s = await fs.modelState().catch(() => null);
          if (s && mine === asked) download = { loaded: s.loaded, total: s.total };
        }, 500);
    try {
      const found = await fs.search(q, volumes, 50, true);
      if (mine !== asked) return;
      results = found.hits;
      meaning = found.meaningError ? `Searching by words only: ${found.meaningError}` : "";
    } catch (e) {
      if (mine === asked) meaning = `Searching by words only: ${e.message}`;
    } finally {
      clearInterval(watch);
      download = null;
    }
  }

  function answer(yes, always) {
    if (always || yes) searchSetting.setMeaningAllowed(yes);
    if (!yes) notNow = true;
    meaning = "";
    if (yes) run();
  }

  const mb = (bytes) => Math.round(bytes / 1e6);

  function typed() {
    clearTimeout(timer);
    timer = setTimeout(run, PAUSE_MS);
  }

  function key(event) {
    if (event.key === "Enter") run();
    if (event.key === "Escape") {
      if (open) open = false;
      else expanded = false;
    }
  }

  function choose(hit) {
    open = false;
    expanded = false;
    onopen(hit.path);
  }

  const ago = (ms) => {
    const s = Math.round((Date.now() - ms) / 1000);
    if (s < 120) return `${s}s ago`;
    if (s < 7200) return `${Math.round(s / 60)}m ago`;
    if (s < 172800) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  };

  const notIndexed = $derived(status.filter((s) => !s.indexed && !s.off).map((s) => s.volume.slice(1)));
  const off = $derived(status.filter((s) => s.off).map((s) => s.volume.slice(1)));
  const placeholder = $derived(
    everywhere || !volumeOf(folder) ? "Search all folders" : `Search ${volumeOf(folder).slice(1)}`,
  );
</script>

<div class="search" class:expanded>
  <button class="opener" aria-label="Open search" onclick={expand}>
    <i class="wxi-search"></i>
  </button>
  <input
    type="search"
    aria-label="Search"
    {placeholder}
    bind:this={box}
    bind:value={query}
    oninput={typed}
    onkeydown={key}
    onfocus={() => query && (open = true)}
  />
  {#if volumeOf(folder)}
    <label class="scope" title="Search every top-level folder, not only this one">
      <input type="checkbox" bind:checked={everywhere} onchange={run} /> All
    </label>
  {/if}
  <button class="shut" aria-label="Close search" onclick={collapse}>
    <i class="wxi-close"></i>
  </button>
  {#if open && query.trim()}
    <div class="results" role="listbox" aria-label="Search results">
      {#if error}
        <p class="error">{error}</p>
      {:else if busy && results.length === 0}
        <p class="note">Searching…</p>
      {:else if results.length === 0 && meaning !== "loading"}
        <p class="note">Nothing found.</p>
      {/if}
      {#if meaning === "asking"}
        <div class="ask">
          <span>
            Also search by meaning, in any language{needed.includes("clip") ? ", and photos by what they show" : ""}?
            This downloads the search {needed.length > 1 ? "models" : "model"} once (about {neededMB} MB).
          </span>
          <span>
            <button onclick={() => answer(true)}>Download</button>
            <button onclick={() => answer(false)}>Not now</button>
            <button onclick={() => answer(false, true)}>Never on this device</button>
          </span>
        </div>
      {:else if meaning === "loading"}
        <p class="note">
          {download && download.loaded < download.total
            ? `Downloading the search model: ${mb(download.loaded)} of ${mb(download.total)} MB…`
            : "Searching by meaning…"}
        </p>
      {:else if meaning}
        <p class="note">{meaning}</p>
      {/if}
      {#each results as hit (hit.path)}
        <button class="hit" role="option" aria-selected="false" onclick={() => choose(hit)}>
          {#if hit.thumb}
            {@const url = thumbs.get(hit.thumb)}
            {#if url}<img class="thumb" src={url} alt="" />{:else}<span class="thumb"></span>{/if}
          {/if}
          <span class="words">
            <span class="path">{hit.path.slice(1)}</span>
            {#if hit.preview}<span class="preview">{hit.preview}</span>{/if}
          </span>
        </button>
      {/each}
      <p class="status">
        {#each status.filter((s) => s.indexed && !s.off) as s (s.volume)}
          <span>{s.volume.slice(1)}: {s.files} files, indexed {ago(s.updatedMs)}{s.by ? ` by ${s.by}` : ""}</span>
          {#if s.photos > s.photosSeen}
            <span>
              {s.photos - s.photosSeen} of its {s.photos} photos can only be found by their dates and places
              so far: a computer running raft5fs makes them searchable by what they show.
            </span>
          {/if}
        {/each}
        {#if notIndexed.length}
          <span>Not indexed yet: {notIndexed.join(", ")}</span>
        {/if}
        {#if off.length}
          <span>Indexing is off: {off.join(", ")}</span>
        {/if}
      </p>
      <button class="close" onclick={() => (open = false)}>Close</button>
    </div>
  {/if}
</div>

<style>
  .search { position: relative; display: flex; align-items: center; gap: 6px; flex: 0 1 340px; min-width: 120px; }
  input[type="search"] {
    flex: 1; min-width: 0; height: 32px; padding: 0 10px;
    border: var(--wx-border-medium); border-radius: var(--wx-radius-major, 6px);
    background: var(--wx-background-alt); color: var(--wx-color-font);
  }
  .scope { display: flex; align-items: center; gap: 4px; white-space: nowrap; font-size: 0.9em; }
  .results {
    position: absolute; top: 40px; left: 0; z-index: 20;
    width: min(560px, calc(100vw - 32px)); max-height: 70vh; overflow-y: auto;
    padding: 8px; display: flex; flex-direction: column; gap: 2px;
    background: var(--wx-background); border: var(--wx-border-medium);
    border-radius: var(--wx-radius-major, 6px); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  }
  .hit {
    display: flex; flex-direction: row; align-items: center; gap: 10px;
    padding: 6px 8px; border: none; border-radius: 4px; text-align: left;
    background: none; color: var(--wx-color-font); cursor: pointer;
  }
  .hit:hover, .hit:focus { background: var(--wx-background-alt); }
  .words { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; min-width: 0; }
  .thumb {
    flex: none; width: 64px; height: 64px; object-fit: cover; border-radius: 4px;
    background: var(--wx-background-alt);
  }
  .path { font-weight: 600; overflow-wrap: anywhere; }
  .preview { opacity: 0.75; font-size: 0.9em; overflow-wrap: anywhere; }
  .note, .error, .status { margin: 4px 8px; }
  .error { color: var(--danger); }
  .status { display: flex; flex-direction: column; gap: 2px; font-size: 0.85em; opacity: 0.7; }
  .close { align-self: flex-end; }
  .ask {
    margin: 4px 8px; display: flex; flex-direction: column; gap: 6px;
    padding: 8px; border-radius: 4px; background: var(--wx-background-alt);
  }
  .ask span:last-child { display: flex; gap: 6px; flex-wrap: wrap; }
  .opener, .shut {
    display: none; flex: none; align-items: center; justify-content: center;
    width: 36px; height: 36px; border: none; border-radius: var(--wx-radius-major, 6px);
    background: var(--wx-background-alt); color: var(--wx-color-font); font-size: 20px;
  }
  /* A phone: a button, which opens the bar across the header (Files.svelte
     makes the header the bar's container). */
  @media (max-width: 640px) {
    .search { flex: none; min-width: 0; position: static; }
    .search:not(.expanded) > :not(.opener) { display: none; }
    .search:not(.expanded) > .opener { display: inline-flex; }
    .search.expanded {
      position: absolute; inset: 0; z-index: 30;
      padding: 0 12px; background: var(--wx-background);
    }
    .search.expanded > .shut { display: inline-flex; }
    .results {
      position: fixed; top: 56px; left: 8px; right: 8px; width: auto;
      max-height: calc(100vh - 72px);
    }
  }
</style>
