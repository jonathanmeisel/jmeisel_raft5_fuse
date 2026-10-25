<script>
  // Shares a folder. The first share with someone needs their
  // fingerprint, the words they read out: the key the server gives for
  // them is trusted only if it matches, never because the server says so.
  import Dialog from "./Dialog.svelte";
  import Fingerprint from "./Fingerprint.svelte";

  let { fs, path, onclose } = $props();
  let user = $state("");
  let readOnly = $state(false);
  // svelte-ignore state_referenced_locally
  let label = $state(path.slice(path.lastIndexOf("/") + 1));
  let words = $state("");
  let needWords = $state(false);
  let busy = $state(false);
  let error = $state("");
  let sealedTo = $state(null);

  async function submit(event) {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      if (!needWords && !(await fs.isPinned(user.trim()))) {
        needWords = true;
        return;
      }
      sealedTo = await fs.share(path, user.trim(), !readOnly, label.trim(), needWords ? words.trim() : null);
    } catch (e) {
      if (e.code === "EFINGERPRINT") needWords = true;
      else error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={`Share ${path}`} {onclose}>
  {#if sealedTo}
    <p>Shared with <strong>{user}</strong> {readOnly ? "read-only" : "read-write"} as “{label}”, sealed to the key with fingerprint:</p>
    <Fingerprint fingerprint={sealedTo} />
    <p><button class="primary" onclick={onclose}>Done</button></p>
  {:else}
    <form onsubmit={submit}>
      <label for="share-user">User</label>
      <input id="share-user" bind:value={user} required disabled={needWords} />
      <label for="share-label">Shown to them as</label>
      <input id="share-label" bind:value={label} required />
      <label><input type="checkbox" bind:checked={readOnly} style="width:auto" /> Read-only</label>
      {#if needWords}
        <label for="share-words">{user}'s fingerprint</label>
        <textarea id="share-words" rows="3" bind:value={words} required></textarea>
        <p class="note">
          This is your first share with {user}. Ask them to read you the fingerprint
          that “Your fingerprint” shows them (or <code>raft5fs whoami</code>), in person
          or on a call, and type it here. The share goes through only if it matches.
        </p>
      {/if}
      {#if error}<p class="error">{error}</p>{/if}
      <p>
        <button class="primary" type="submit" disabled={busy}>{busy ? "Sharing…" : "Share"}</button>
        <button type="button" onclick={onclose}>Cancel</button>
      </p>
    </form>
  {/if}
</Dialog>
