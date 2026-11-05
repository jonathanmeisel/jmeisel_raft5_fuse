<script>
  // A safety code: the 12 words that someone reads to another person, with a
  // way to copy them for a message. The hex form says the same thing, for the
  // command line's `raft5fs whoami`.
  let { fingerprint } = $props();
  let copied = $state(false);
  let showHex = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(fingerprint.words);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      // Where the browser refuses, the words can still be selected.
      copied = false;
    }
  }
</script>

<div class="fingerprint">
  <div class="words">{fingerprint.words}</div>
  {#if showHex}<div class="note">{fingerprint.hex}</div>{/if}
  <div class="actions">
    <button type="button" onclick={copy}>{copied ? "Copied" : "Copy"}</button>
    <button type="button" class="plain" onclick={() => (showHex = !showHex)}>
      {showHex ? "Hide hex" : "Show as hex"}
    </button>
  </div>
</div>

<style>
  .fingerprint {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    word-break: break-word;
  }
  .actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
  .plain { border: none; background: none; color: var(--muted); padding: 0; font-size: 0.85em; }
</style>
