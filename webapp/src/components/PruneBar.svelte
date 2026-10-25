<script>
  // What waits to be re-sealed after a revoke, and how it's going. One
  // tab per account prunes in the background while the app is open, and
  // carries on at the next login.
  import { onDestroy } from "svelte";

  let { fs, onqueued } = $props();
  const POLL_MS = 3000;

  let queued = $state([]);
  /// "running", "paused", or "elsewhere" (another tab prunes).
  let state = $state("running");

  async function poll() {
    try {
      queued = await fs.pruneStatus();
      state = await fs.pruning();
      onqueued(queued.length);
    } catch {}
  }
  poll();
  const timer = setInterval(poll, POLL_MS);
  onDestroy(() => clearInterval(timer));

  async function toggle() {
    if (state === "running") await fs.pausePruning();
    else await fs.resumePruning();
    poll();
  }
</script>

{#if queued.length}
  <div class="prune">
    <div class="items">
      {#each queued as q}
        <div>
          <strong>Re-sealing {q.note}</strong>:
          {state === "running" ? q.status : state === "paused" ? "paused" : "running in another tab"}
        </div>
      {/each}
      <div class="note">Keep this tab open until it's done; closing it pauses re-sealing until you next log in.</div>
    </div>
    {#if state !== "elsewhere"}
      <button onclick={toggle}>{state === "running" ? "Pause" : "Resume"}</button>
    {/if}
  </div>
{/if}

<style>
  .prune {
    display: flex; gap: 12px; align-items: center; padding: 8px 14px;
    background: var(--warn-bg); border-bottom: 1px solid var(--border);
  }
  .items { flex: 1; }
</style>
