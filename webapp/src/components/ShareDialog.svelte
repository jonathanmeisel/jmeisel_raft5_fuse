<script>
  // Shares a folder. The first share with someone needs their
  // fingerprint, the words they read out: the key the server gives for
  // them is trusted only if it matches, never because the server says so.
  // So does a share with someone whose key changed (they enrolled again):
  // their new key replaces the old one only if it matches.
  import Dialog from "./Dialog.svelte";
  import Fingerprint from "./Fingerprint.svelte";

  let { fs, path, onclose } = $props();
  let user = $state("");
  let readOnly = $state(false);
  // svelte-ignore state_referenced_locally
  let label = $state(path.slice(path.lastIndexOf("/") + 1));
  let words = $state("");
  let needWords = $state(false);
  let keyChanged = $state(false);
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
      if (keyChanged) await fs.replaceKey(user.trim(), words.trim());
      const fingerprint = needWords && !keyChanged ? words.trim() : null;
      sealedTo = await fs.share(path, user.trim(), !readOnly, label.trim(), fingerprint);
    } catch (e) {
      if (e.code === "EFINGERPRINT") needWords = true;
      else if (e.code === "EKEYCHANGED") needWords = keyChanged = true;
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
      <label for="share-label">What this folder will show up to shared user as</label>
      <input id="share-label" bind:value={label} required />
      <label><input type="checkbox" bind:checked={readOnly} style="width:auto" /> Read-only</label>
      {#if needWords}
        <label for="share-words">{user}'s fingerprint</label>
        <textarea id="share-words" rows="3" bind:value={words} required></textarea>
        {#if keyChanged}
          <p class="note">
            {user}'s key has changed since you last shared with them: they may have enrolled again.
            Ask them for their new fingerprint. Their new key is trusted only if it matches.
          </p>
        {:else}
          <p class="note">This is your first share with {user}. Ask them for their key's fingerprint.</p>
        {/if}
      {/if}
      {#if error}<p class="error">{error}</p>{/if}
      <p>
        <button class="primary" type="submit" disabled={busy}>{busy ? "Sharing…" : "Share"}</button>
        <button type="button" onclick={onclose}>Cancel</button>
      </p>
    </form>
  {/if}
</Dialog>
