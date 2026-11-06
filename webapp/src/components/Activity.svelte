<script>
  // What changed in a folder and below it, newest first (the wasm `activity`):
  // who created, edited, renamed, moved or deleted what. The servers keep it
  // for a few days, and vouch for who did what. A name opens its versions.
  import Dialog from "./Dialog.svelte";
  import { when } from "../lib/when.js";
  import HistoryTabs from "./HistoryTabs.svelte";

  /// `ontab` shows the tabs to the folder's Versions.
  let { fs, path, onversions, ontab = null, onclose } = $props();
  // svelte-ignore state_referenced_locally
  const name = path.slice(path.lastIndexOf("/") + 1);
  const base = (p) => p.slice(path.length + 1);

  let lines = $state([]);
  let next = $state(null);
  let loaded = $state(false);
  let error = $state("");
  let busy = $state(false);

  async function more() {
    busy = true;
    try {
      const page = await fs.activity(path, next);
      lines = [...lines, ...page.lines];
      next = page.next;
    } catch (e) {
      error = e.code === "ENOTSUP" ? "The servers are too old to keep a log of changes." : e.message;
    } finally {
      loaded = true;
      busy = false;
    }
  }
  more();
</script>

{#snippet named(p)}
  {#if p}
    <button class="link" onclick={() => onversions(p)}>{base(p)}</button>
  {:else}
    <span class="note">something in a folder deleted since</span>
  {/if}
{/snippet}

<Dialog title={`${name}: history`} wide {onclose}>
  {#if ontab}<HistoryTabs current="activity" {ontab} />{/if}
  {#if !loaded}
    <p class="note">Loading…</p>
  {:else if lines.length === 0 && !error}
    <p>Nothing has changed here lately.</p>
  {/if}
  <ul>
    {#each lines as line, i (i)}
      <li>
        <span class="when">{when(line.at)}</span>
        <strong>{line.user}</strong>
        {line.change}
        {#if (line.change === "renamed" || line.change === "moved") && line.from}
          {@render named(line.from)} to {@render named(line.path)}{line.replaced ? ", replacing what was there" : ""}
        {:else}
          {@render named(line.path)}
        {/if}
      </li>
    {/each}
  </ul>
  {#if next}
    <p><button onclick={more} disabled={busy}>Load more</button></p>
  {/if}
  <p class="note">
    The servers keep this for a few days, and say who made each change: it isn't signed by them. A name
    opens its versions.
  </p>
  {#if error}<p class="error">{error}</p>{/if}
  <p><button onclick={onclose}>Close</button></p>
</Dialog>

<style>
  ul { list-style: none; padding: 0; margin: 0; }
  li { padding: 6px 0; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
  .when { display: inline-block; min-width: 9em; color: var(--muted, inherit); }
  .link { background: none; border: none; padding: 0; color: inherit; text-decoration: underline; cursor: pointer; font: inherit; }
</style>
