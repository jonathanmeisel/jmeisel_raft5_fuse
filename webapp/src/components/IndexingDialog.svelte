<script>
  // A top-level folder's search indexing: whether its files are indexed
  // for search, for everyone who can read it. Only its owner can turn that
  // off, which also removes its index to free the space it takes.
  //
  // Also, for this browser only: whether to download the folder's index to
  // search it here (searchSetting.js). By default yes, unless it is big.
  import * as searchSetting from "../lib/searchSetting.js";
  import Dialog from "./Dialog.svelte";
  import ErrorText from "./ErrorText.svelte";

  let { fs, path, onclose } = $props();

  let state = $state(null);
  let error = $state("");
  let working = $state(false);
  let confirming = $state(false);

  // svelte-ignore state_referenced_locally
  fs.volumeIndexing(path).then(
    (s) => (state = s),
    (e) => (error = e.message),
  );

  /// The index's size, and whether this browser downloads it: as chosen
  /// here, else as this browser's setting says, else if it is small.
  let size = $state(null);
  let chosen = $state(null);
  // svelte-ignore state_referenced_locally
  fs.searchSize(path).then(
    (s) => (size = s),
    () => {},
  );
  const here = $derived(
    chosen ?? (state?.volume && size ? (searchSetting.download(state.volume) ?? size.bytes <= size.limit) : false),
  );

  function setHere(on) {
    chosen = on;
    if (state?.volume) searchSetting.setDownload(state.volume, on);
  }

  const mb = (bytes) => Math.max(1, Math.round(bytes / 1e6));

  async function set(on) {
    working = true;
    error = "";
    try {
      await fs.setVolumeIndexing(path, on);
      state = { ...state, on };
      confirming = false;
    } catch (e) {
      error = e.message;
    } finally {
      working = false;
    }
  }
</script>

<Dialog title="Search indexing" {onclose}>
  {#if error}<p class="error"><ErrorText {fs} message={error} /></p>{/if}
  {#if state}
    <!-- For everyone: whether the folder is indexed. -->
    <p>
      {state.on
        ? `The files in ${state.volume.slice(1)} are indexed for search, so anyone who can read it can search it.`
        : `Indexing for search is off for ${state.volume.slice(1)}.`}
    </p>
    {#if !state.owner}
      <p class="note">Only the folder's owner can turn this {state.on ? "off" : "on"}.</p>
    {:else if state.on && confirming}
      <p>
        Turning it off stops every device indexing it, and removes its index, which frees the space it
        takes. You can turn it on again later; it is then indexed from the start.
      </p>
      <div class="row">
        <button class="danger" disabled={working} onclick={() => set(false)}>Turn off and remove the index</button>
        <button disabled={working} onclick={() => (confirming = false)}>Cancel</button>
      </div>
    {:else if state.on}
      <div class="row"><button onclick={() => (confirming = true)}>Turn off…</button></div>
    {:else}
      <div class="row"><button class="primary" disabled={working} onclick={() => set(true)}>Turn on</button></div>
    {/if}
    <!-- For this browser only: whether to download the index. -->
    {#if state.on && size}
      <label class="here">
        <input type="checkbox" checked={here} onchange={(e) => setHere(e.currentTarget.checked)} />
        <span>
          Download its index to search it in this browser{size.bytes ? ` (${mb(size.bytes)} MB)` : ""}
          <span class="note">Only this browser. Folders not downloaded aren't searched here.</span>
        </span>
      </label>
    {/if}
  {:else if !error}
    <p class="note">Loading…</p>
  {/if}
  <div class="footer"><button onclick={onclose}>Close</button></div>
</Dialog>

<style>
  .error { color: var(--danger); }
  .row { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0 4px; }
  .here {
    display: flex; gap: 10px; align-items: flex-start;
    margin: 16px 0 0; padding-top: 14px; border-top: 1px solid var(--border);
    color: var(--text); font-size: 1em;
  }
  .here input { margin-top: 3px; flex: none; }
  .here .note { display: block; margin-top: 2px; }
  .footer {
    display: flex; justify-content: flex-end;
    margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border);
  }
</style>
