<script>
  // What waits to be re-sealed after a revoke, and who is doing it. The
  // servers keep the list, so any device that can write a folder can
  // finish it: of each browser, one tab re-seals in the background, if
  // "Re-seal on this device" is on (account menu).
  import { onDestroy } from "svelte";

  /// `onrunning` hears whether this tab is re-sealing now.
  let { fs, me, onrunning } = $props();
  const POLL_MS = 3000;

  let waiting = $state([]);
  /// "running", "elsewhere" (another tab of this browser) or "off".
  let here = $state("running");

  async function poll() {
    try {
      [waiting, here] = await Promise.all([fs.pruneStatus(), fs.pruning()]);
      onrunning(waiting.some((w) => w.state === "pruning" && !w.by));
    } catch {}
  }
  poll();
  const timer = setInterval(poll, POLL_MS);
  onDestroy(() => clearInterval(timer));

  function line(w) {
    if (w.state === "pruning" && !w.by) return `Re-sealing ${w.path}`;
    if (w.state === "pruning" && w.by === me) return `Re-sealing ${w.path} on another device`;
    if (w.state === "pruning") return `${w.by} is re-sealing ${w.path}`;
    if (w.state === "incomplete") return `Re-sealing ${w.path} couldn't finish yet: it will try again`;
    return `${w.path} waits to be re-sealed`;
  }
</script>

{#if waiting.length}
  <div class="prune">
    {#each waiting as w}
      <div title={w.detail ?? ""}>{line(w)}</div>
    {/each}
    <div class="note">
      {here === "off"
        ? "Re-sealing is off on this device. Anyone who can write the folder can finish it, on any device."
        : "Anyone who can write the folder can finish this, on any device."}
    </div>
  </div>
{/if}

<style>
  .prune {
    padding: 8px 14px; background: var(--warn-bg); border-bottom: 1px solid var(--border);
  }
</style>
