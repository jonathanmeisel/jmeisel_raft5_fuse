<script>
  // What waits to be re-sealed after a revoke, and how it's going. The
  // Worker prunes in the background while the app is open, and carries on
  // at the next login.
  import { onDestroy } from "svelte";

  let { fs, onqueued } = $props();
  const POLL_MS = 3000;

  let queued = $state([]);
  let running = $state(true);

  async function poll() {
    try {
      queued = await fs.pruneStatus();
      running = await fs.pruning();
      onqueued(queued.length);
    } catch {}
  }
  poll();
  const timer = setInterval(poll, POLL_MS);
  onDestroy(() => clearInterval(timer));

  async function toggle() {
    if (running) await fs.pausePruning();
    else await fs.resumePruning();
    poll();
  }
</script>

{#if queued.length}
  <div class="prune">
    <div class="items">
      {#each queued as q}
        <div><strong>Re-sealing {q.note}</strong>: {running ? q.status : "paused"}</div>
      {/each}
      <div class="note">Keep this tab open until it's done; closing it pauses re-sealing until you next log in.</div>
    </div>
    <button onclick={toggle}>{running ? "Pause" : "Resume"}</button>
  </div>
{/if}

<style>
  .prune {
    display: flex; gap: 12px; align-items: center; padding: 8px 14px;
    background: var(--warn-bg); border-bottom: 1px solid var(--border);
  }
  .items { flex: 1; }
</style>
