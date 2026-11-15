<script>
  // `keep` holds it open against Esc and clicks outside it, while closing it
  // would lose something typed.
  let { title, wide = false, keep = false, onclose, children } = $props();
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && !keep && onclose()} />

<div class="backdrop" class:wide role="presentation" onclick={(e) => e.target === e.currentTarget && !keep && onclose()}>
  <div class="dialog" class:wide role="dialog" aria-modal="true" aria-label={title}>
    <h2>{title}</h2>
    {@render children()}
  </div>
</div>

<style>
  /* The backdrop covers what can be seen of the screen, so the dialog fits
     in it: a phone's `vh` counts the browser's bars as screen, so a height
     in `vh` can put the dialog's end, and its Close, behind them. A long
     dialog scrolls inside itself. */
  .backdrop {
    position: fixed; inset: 0; background: rgba(20, 24, 32, 0.35);
    display: flex; align-items: flex-start; justify-content: center; z-index: 100;
    box-sizing: border-box; padding: 10vh 0 16px;
  }
  .backdrop.wide { padding-top: 4vh; }
  .dialog {
    box-sizing: border-box; width: min(520px, 92vw); max-height: 100%; overflow: auto;
    overscroll-behavior: contain;
    background: var(--panel); border-radius: 10px; padding: 20px 24px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
  }
  .dialog.wide { width: min(1000px, 94vw); }
  @media (max-width: 600px) {
    .backdrop, .backdrop.wide { padding: 12px 0; }
    .dialog { padding: 16px; }
  }
  h2 { margin: 0 0 10px; font-size: 1.2em; }
</style>
