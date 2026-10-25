<script>
  let { title, onclose, children } = $props();
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && onclose()} />

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog" role="dialog" aria-modal="true" aria-label={title}>
    <h2>{title}</h2>
    {@render children()}
  </div>
</div>

<style>
  .backdrop {
    position: fixed; inset: 0; background: rgba(20, 24, 32, 0.35);
    display: flex; align-items: flex-start; justify-content: center; z-index: 100;
  }
  .dialog {
    margin-top: 10vh; width: min(520px, 92vw); max-height: 80vh; overflow: auto;
    background: var(--panel); border-radius: 10px; padding: 20px 24px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
  }
  h2 { margin: 0 0 10px; font-size: 1.2em; }
</style>
