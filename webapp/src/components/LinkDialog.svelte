<script>
  // Makes a public link to a folder: anyone with the link can read the
  // folder until it expires or someone who can write the folder revokes
  // it. Whoever can change the folder can copy the link again from its
  // "Shared with…" list.
  import Dialog from "./Dialog.svelte";
  import LinkField from "./LinkField.svelte";

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

  async function submit(event) {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      const expires = days ? Math.floor(Date.now() / 1000) + days * 86400 : null;
      const made = await fs.createLink(path, label.trim(), expires);
      link = made.link;
    } catch (e) {
      error = e.code === "EROFS" ? "You can only share folders you can change." : e.message;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={`Share ${path} publicly`} {onclose}>
  {#if link}
    <LinkField {link} />
    <p class="error">
      Anyone with this link can read {path} until it is revoked{days ? " or it expires" : ""}.
    </p>
    <p class="note">
      You, and anyone else who can change this folder and make links, can copy it again from the
      folder's "Shared with…".
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
