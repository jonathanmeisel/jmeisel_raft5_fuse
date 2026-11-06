<script>
  // The two views of a folder's history, Versions and Activity, as tabs at the
  // top of either dialog.
  let { current, ontab } = $props();
</script>

<div class="tabs" role="tablist">
  {#each [["versions", "Versions"], ["activity", "Activity"]] as [id, text] (id)}
    <button role="tab" aria-selected={current === id} class:on={current === id} onclick={() => ontab(id)}>
      {text}
    </button>
  {/each}
</div>

<style>
  .tabs { display: flex; gap: 4px; margin-bottom: 12px; border-bottom: 1px solid var(--border); }
  button { border: none; border-bottom: 2px solid transparent; border-radius: 0; background: none; padding: 6px 12px; }
  .on { border-bottom-color: currentColor; font-weight: 600; }
</style>
