<script>
  // Makes a public link to a folder: anyone with the link can read the
  // folder until it expires or someone who can write the folder revokes
  // it. The link holds its own password, so it is shown once and kept
  // nowhere: a lost link means making a new one.
  import Dialog from "./Dialog.svelte";

  let { fs, path, onclose } = $props();

  const EXPIRY = [
    { days: 0, text: "Never" },
    { days: 1, text: "After 1 day" },
    { days: 7, text: "After 7 days" },
    { days: 30, text: "After 30 days" },
  ];

  // svelte-ignore state_referenced_locally
  let label = $state(path.slice(path.lastIndexOf("/") + 1));
  let days = $state(7);
  let busy = $state(false);
  let error = $state("");
  let link = $state("");
  let copied = $state(false);

  async function submit(event) {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      const expires = days ? Math.floor(Date.now() / 1000) + days * 86400 : null;
      const made = await fs.createLink(path, label.trim(), expires);
      link = `${location.origin}${location.pathname}#link=${made.link}`;
    } catch (e) {
      error = e.code === "EROFS" ? "You can only share folders you can change." : e.message;
    } finally {
      busy = false;
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(link);
      copied = true;
    } catch {
      error = "The browser wouldn't copy. Select the link and copy it yourself.";
    }
  }
</script>

<Dialog title={`Share ${path} publicly`} {onclose}>
  {#if link}
    <label for="public-link">Public link</label>
    <div class="row">
      <input id="public-link" readonly value={link} onfocus={(e) => e.target.select()} />
      <button onclick={copy}>{copied ? "Copied" : "Copy"}</button>
    </div>
    <p class="error">
      Anyone with this link can read {path} until you revoke it{days ? " or it expires" : ""}. This is
      the only time it is shown: if it is lost, make a new one.
    </p>
    <p><button class="primary" onclick={onclose}>Done</button></p>
  {:else}
    <form onsubmit={submit}>
      <p>Anyone with the link will be able to read this folder and everything in it, without an account.</p>
      <label for="link-label">What visitors see the folder as</label>
      <input id="link-label" bind:value={label} required />
      <label for="link-expiry">The link stops working</label>
      <select id="link-expiry" bind:value={days}>
        {#each EXPIRY as e}<option value={e.days}>{e.text}</option>{/each}
      </select>
      {#if error}<p class="error">{error}</p>{/if}
      <p>
        <button class="primary" type="submit" disabled={busy}>{busy ? "Making…" : "Make link"}</button>
        <button type="button" onclick={onclose}>Cancel</button>
      </p>
    </form>
  {/if}
</Dialog>

<style>
  .row { display: flex; gap: 8px; align-items: center; }
  .row input { flex: 1; min-width: 0; }
</style>
