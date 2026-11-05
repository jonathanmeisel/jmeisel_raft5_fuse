<script>
  // Shares a folder. The first share with someone needs their safety code,
  // the words they read out: the key the server gives for
  // them is trusted only if it matches, never because the server says so.
  // So does a share with someone whose key changed (they enrolled again):
  // their new key replaces the old one only if it matches.
  import Dialog from "./Dialog.svelte";
  import Fingerprint from "./Fingerprint.svelte";
  import CodeInput from "./CodeInput.svelte";

  // That check goes both ways: to change what is shared, the other person
  // needs this account's code too. So it shows here while the two are in
  // touch, and again at the end.
  let { fs, path, mine, onclose } = $props();
  let user = $state("");
  let readOnly = $state(false);
  // svelte-ignore state_referenced_locally
  let label = $state(path.slice(path.lastIndexOf("/") + 1));
  let words = $state("");
  let needWords = $state(false);
  let wordsComplete = $state(false);
  let keyChanged = $state(false);
  let busy = $state(false);
  let error = $state("");
  let shared = $state(false);
  /// Whether this was the first share with them, so they need this account's
  /// code next.
  let first = $state(false);

  async function submit(event) {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      if (!needWords) {
        if (!(await fs.userExists(user.trim()))) {
          error = `There's nobody called ${user.trim()} here. Check the spelling.`;
          return;
        }
        if (!(await fs.isPinned(user.trim()))) {
          needWords = true;
          return;
        }
      }
      if (keyChanged) await fs.replaceKey(user.trim(), words.trim());
      const fingerprint = needWords && !keyChanged ? words.trim() : null;
      first = needWords;
      await fs.share(path, user.trim(), !readOnly, label.trim(), fingerprint);
      shared = true;
    } catch (e) {
      if (e.code === "EFINGERPRINT") needWords = true;
      else if (e.code === "EKEYCHANGED") needWords = keyChanged = true;
      else error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={`Share ${path}`} keep={needWords && !shared} {onclose}>
  {#if shared}
    <p>Shared with <strong>{user}</strong> {readOnly ? "read-only" : "read-write"} as “{label}”.</p>
    {#if first}
      <p>{user} now needs your safety code, to know it's really from you:</p>
      <Fingerprint fingerprint={mine} />
    {/if}
    <p><button class="primary" onclick={onclose}>Done</button></p>
  {:else}
    <form onsubmit={submit}>
      <label for="share-user">User</label>
      <input id="share-user" bind:value={user} required disabled={needWords} autocapitalize="none" autocomplete="off" />
      {#if needWords}
        <button
          type="button"
          onclick={() => {
            needWords = keyChanged = false;
            words = "";
            error = "";
          }}
        >
          Change
        </button>
      {/if}
      <label for="share-label">What this folder will show up to shared user as</label>
      <input id="share-label" bind:value={label} required />
      <label><input type="checkbox" bind:checked={readOnly} style="width:auto" /> Read-only</label>
      {#if needWords}
        <CodeInput {fs} id="share-words" label={`${user}'s safety code`} bind:value={words} bind:complete={wordsComplete} />
        {#if keyChanged}
          <p class="note">
            {user}'s key has changed since you last shared with them: they may have enrolled again.
            Ask them for their new safety code. Their new key is trusted only if it matches.
          </p>
        {:else}
          <p class="note">
            This is your first share with {user}, so you need to check it's really them. Ask {user} to
            open the app, tap their name at the top, choose My safety code, and read or text you the 12
            words.
          </p>
        {/if}
        <p>They'll need yours too. Your safety code:</p>
        <Fingerprint fingerprint={mine} />
      {/if}
      {#if error}<p class="error">{error}</p>{/if}
      <p>
        <button class="primary" type="submit" disabled={busy || (needWords && !wordsComplete)}>{busy ? "Sharing…" : "Share"}</button>
        <button type="button" onclick={onclose}>Cancel</button>
      </p>
    </form>
  {/if}
</Dialog>
