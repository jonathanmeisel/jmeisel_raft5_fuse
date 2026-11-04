<script>
  // Shares from people whose keys aren't pinned here. They're read-only
  // until trusted, by the safety code the sender reads out. A sender whose
  // key changed (they enrolled again) is trusted the same way: their new
  // key replaces the old one only if it matches.
  import Dialog from "./Dialog.svelte";
  import CodeInput from "./CodeInput.svelte";

  let { fs, onclose } = $props();
  let pending = $state(null);
  /// {sender, keyChanged} being trusted.
  let trusting = $state(null);
  let words = $state("");
  let wordsComplete = $state(false);
  let error = $state("");
  let busy = $state(false);

  async function load() {
    try {
      pending = await fs.pending();
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

<Dialog title="Shared with me" {onclose}>
  {#if pending === null}
    <p class="note">Loading…</p>
  {:else if trusting}
    <form onsubmit={trust}>
      {#if trusting.keyChanged}
        <p>
          <strong>{trusting.sender}</strong>'s key has changed: they may have enrolled again. Ask them
          to read you their new safety code, in person or on a call, and type it here.
        </p>
      {:else}
        <p>Ask <strong>{trusting.sender}</strong> to read you their safety code, in person or on a call, and type it here.</p>
      {/if}
      <CodeInput {fs} id="trust-words" label="Their safety code" bind:value={words} bind:complete={wordsComplete} />
      <p>
        <button class="primary" type="submit" disabled={busy || !wordsComplete}>Trust</button>
        <button type="button" onclick={() => (trusting = null)}>Cancel</button>
      </p>
    </form>
  {:else if pending.length === 0}
    <p>No shares from untrusted users</p>
  {:else}
    {#each pending as p}
      <div class="item">
        <strong>{p.label}</strong>, from {p.sender}:
        {#if p.state === "untrusted" && p.keyChanged}
          {p.sender}'s key has changed, so it is read-only until you check their new safety code.
          <button onclick={() => (trusting = { sender: p.sender, keyChanged: true })}>Check new safety code…</button>
        {:else if p.state === "untrusted"}
          read-only until you trust {p.sender}.
          <button onclick={() => (trusting = { sender: p.sender, keyChanged: false })}>Trust…</button>
        {:else}
          <span class="error">doesn't open: {p.message}</span>
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
