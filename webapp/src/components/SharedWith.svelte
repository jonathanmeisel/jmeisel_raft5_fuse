<script>
  // Who a folder is shared with, and revoking. A revoke queues the folder
  // for pruning: until that finishes, what was written there before is
  // still sealed under keys the revoked user had.
  import Dialog from "./Dialog.svelte";

  let { fs, path, me, onclose } = $props();
  const WARN_BYTES = 1 << 30;

  let grantees = $state(null);
  let error = $state("");
  let confirming = $state(null);
  let busy = $state(false);
  let revoked = $state("");

  async function load() {
    try {
      grantees = await fs.sharedWith(path);
    } catch (e) {
      error = e.message;
      grantees = [];
    }
  }
  load();

  async function ask(user) {
    error = "";
    busy = true;
    try {
      confirming = { user, estimate: await fs.pruneEstimate(path) };
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function revoke() {
    busy = true;
    error = "";
    try {
      await fs.revoke(path, confirming.user);
      revoked = confirming.user;
      confirming = null;
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  const size = (bytes) =>
    bytes >= 1 << 30 ? `${(bytes / (1 << 30)).toFixed(1)} GB` : `${Math.ceil(bytes / (1 << 20))} MB`;
</script>

<Dialog title={`Shared with: ${path}`} {onclose}>
  {#if grantees === null}
    <p class="note">Loading…</p>
  {:else if confirming}
    <p>Revoke <strong>{confirming.user}</strong>'s share of {path}?</p>
    <p class="note">
      This app then re-seals what is there, so {confirming.user}'s old keys stop opening it:
      about {size(confirming.estimate.bytes)} to download, re-seal and upload, while this tab is open.
    </p>
    {#if confirming.estimate.bytes > WARN_BYTES}
      <p class="error">
        That's a lot for a browser. Keep this tab open until it finishes, or let a desktop
        client do it (<code>raft5fs prune</code>).
      </p>
    {/if}
    <p>
      <button class="danger" onclick={revoke} disabled={busy}>{busy ? "Revoking…" : "Revoke"}</button>
      <button onclick={() => (confirming = null)}>Cancel</button>
    </p>
  {:else}
    {#if revoked}<p class="note">Revoked {revoked}'s share; re-sealing runs in the background.</p>{/if}
    {#if grantees.length === 0}
      <p>Not shared with anyone.</p>
    {:else}
      <table>
        <tbody>
          {#each grantees as g}
            <tr>
              <td><strong>{g.user}</strong>{g.user === me ? " (you)" : ""}</td>
              <td>{g.writable ? "read-write" : "read-only"}</td>
              <td>
                {#if g.user !== me}
                  <button class="danger" onclick={() => ask(g.user)} disabled={busy}>Revoke…</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    <p><button onclick={onclose}>Close</button></p>
  {/if}
  {#if error}<p class="error">{error}</p>{/if}
</Dialog>

<style>
  table { width: 100%; border-collapse: collapse; }
  td { padding: 6px 4px; border-bottom: 1px solid var(--border); }
  td:last-child { text-align: right; }
</style>
