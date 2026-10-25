<script>
  let { fingerprint } = $props();
</script>

<div class="fingerprint">
  <div class="words">{fingerprint.words}</div>
  <div class="note">{fingerprint.hex}</div>
</div>

<style>
  .fingerprint {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    word-break: break-word;
  }
</style>
