<script>
  // Everything shared with this account, from whom, and what it allows.
  // Shares from people whose keys aren't pinned here can be opened, but stay
  // read-only until checked, by the safety code the sender reads out. A sender
  // whose key changed (they enrolled again) is checked the same way: their new
  // key replaces the old one only if it matches. This account's own folders
  // aren't shares, so they don't show.
  import Dialog from "./Dialog.svelte";
  import CodeInput from "./CodeInput.svelte";
  import Fingerprint from "./Fingerprint.svelte";

  let { fs, me, mine, onclose } = $props();
  let pending = $state(null);
  /// {sender, label, keyChanged} being checked.
  let trusting = $state(null);
  let words = $state("");
  let wordsComplete = $state(false);
  let error = $state("");
  let busy = $state(false);
  /// What was just checked, to say so.
  let verified = $state(null);

  async function load() {
    try {
      pending = (await fs.pending()).filter((p) => p.sender !== me);
    } catch (e) {
      error = e.message;
      pending = [];
    }
  }
  load();

  async function trust(event) {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      if (trusting.keyChanged) await fs.replaceKey(trusting.sender, words.trim());
      else await fs.trust(trusting.sender, words.trim());
      verified = trusting;
      trusting = null;
      words = "";
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title="Shared with me" keep={!!trusting} {onclose}>
  {#if pending === null}
    <p class="note">Loading…</p>
  {:else if trusting}
    <form onsubmit={trust}>
      {#if trusting.keyChanged}
        <p>
          <strong>{trusting.sender}</strong>'s key has changed: they may have enrolled again. Ask them
          to read you their new safety code, in person or on a call, and type it here. If they didn't
          reset anything, tell your admin first.
        </p>
      {:else}
        <p>Ask <strong>{trusting.sender}</strong> to read you their safety code, in person or on a call, and type it here.</p>
      {/if}
      <CodeInput {fs} id="trust-words" label="Their safety code" bind:value={words} bind:complete={wordsComplete} />
      <p>They may need yours too. Your safety code:</p>
      <Fingerprint fingerprint={mine} />
      <p>
        <button class="primary" type="submit" disabled={busy || !wordsComplete}>Trust</button>
        <button type="button" onclick={() => (trusting = null)}>Cancel</button>
      </p>
    </form>
  {:else}
    {#if verified}
      <p class="note">You and {verified.sender} are verified. {verified.label} is in My files.</p>
    {/if}
    {#if pending.length === 0}
      <p>Nothing has been shared with you yet.</p>
    {/if}
    {#each pending as p}
      <div class="item">
        <strong>{p.label}</strong>, from {p.sender}.
        {#if p.state === "trusted"}
          <span class="note">{p.writable ? "You can add, change and delete files here." : "You can open files here."}</span>
        {:else if p.state === "untrusted" && p.keyChanged}
          {p.sender}'s key has changed, so this is read-only until you check their new safety code.
          <button onclick={() => (trusting = { sender: p.sender, label: p.label, keyChanged: true })}>Check new safety code…</button>
        {:else if p.state === "untrusted"}
          {#if p.writable}
            You can already open it. To add or change files, check {p.sender}'s safety code.
          {:else}
            You can open it. Check {p.sender}'s safety code, so you know it's really from them.
          {/if}
          <button onclick={() => (trusting = { sender: p.sender, label: p.label, keyChanged: false })}>Trust…</button>
        {:else}
          <span class="error">It doesn't open: {p.message}</span>
        {/if}
      </div>
    {/each}
  {/if}
  {#if error}<p class="error">{error}</p>{/if}
  {#if !trusting}<p><button onclick={onclose}>Close</button></p>{/if}
</Dialog>

<style>
  .item { padding: 8px 0; border-bottom: 1px solid var(--border); }
</style>
