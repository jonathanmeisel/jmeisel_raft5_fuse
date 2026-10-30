<script>
  // A folder's size, and a cap on it. The owner of its top-level folder,
  // or an admin, sets the cap; it holds for everyone who writes there, the
  // owner too. Sizes are measured every few minutes, and kept up to date
  // within seconds for folders with a cap.
  import Dialog from "./Dialog.svelte";
  import { parseSize, sizeText } from "../lib/sizes.js";

  let { fs, path, me, admin = false, onclose } = $props();
  // svelte-ignore state_referenced_locally
  const name = path.replace(/^\//, "");
  // svelte-ignore state_referenced_locally
  const top = "/" + path.split("/")[1];

  let size = $state(undefined);
  let owner = $state(null);
  let typed = $state("");
  let busy = $state(false);
  let error = $state("");

  async function load() {
    try {
      const [measured, volume] = await Promise.all([fs.folderSize(path), fs.volume(top)]);
      size = measured;
      owner = volume?.owner ?? null;
      typed = measured?.limit ? sizeText(measured.limit).replace(" ", "") : "";
    } catch (e) {
      error = e.message;
      size = null;
    }
  }
  load();

  const may = $derived(admin || owner === me);

  async function set(limit) {
    busy = true;
    error = "";
    try {
      await fs.setFolderLimit(path, limit);
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function submit(event) {
    event.preventDefault();
    let limit;
    try {
      limit = parseSize(typed);
    } catch (e) {
      error = e.message;
      return;
    }
    set(limit);
  }
</script>

<Dialog title={`Size limit: ${name}`} {onclose}>
  {#if size === undefined}
    <p class="note">Loading…</p>
  {:else}
    <p>
      {#if size?.measuredAt}
        Holds {sizeText(size.bytes)} in {size.files} {size.files === 1 ? "file" : "files"}{size.limit
          ? `, of a ${sizeText(size.limit)} limit`
          : ""}.
      {:else}
        Not measured yet: sizes are measured every few minutes.
      {/if}
    </p>
    {#if may}
      <form onsubmit={submit}>
        <label for="limit-size">Limit, such as 500M or 10G (blank for none)</label>
        <input id="limit-size" bind:value={typed} autocomplete="off" />
        <p class="note">Writes that would take the folder over it are refused, whoever writes, you too.</p>
        <p>
          <button class="primary" type="submit" disabled={busy}>Set limit</button>
          {#if size?.limit}<button type="button" onclick={() => set(null)} disabled={busy}>Remove limit</button>{/if}
        </p>
      </form>
    {:else}
      <p class="note">
        {size?.limit ? `Its limit is ${sizeText(size.limit)}.` : "It has no limit."}
        Only {owner ?? "the owner of its top-level folder"} or an admin can change that.
      </p>
    {/if}
  {/if}
  {#if error}<p class="error">{error}</p>{/if}
  <p><button onclick={onclose}>Close</button></p>
</Dialog>
