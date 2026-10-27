<script>
  // The public links this account made: their folder, when they expire,
  // and revoking. Revoking re-seals the folder, as for a person, and queues
  // it for pruning. A link can't be shown again: its password is kept only
  // in the link.
  import Dialog from "./Dialog.svelte";

  let { fs, onclose } = $props();

  let links = $state(null);
  let error = $state("");
  let confirming = $state(null);
  let busy = $state(false);

  async function load() {
    try {
      links = await fs.listLinks();
    } catch (e) {
      error = e.message;
      links = [];
    }
  }
  load();

  async function revoke() {
    busy = true;
    error = "";
    try {
      await fs.revokeLink(confirming.user);
      confirming = null;
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  const date = (secs) => new Date(secs * 1000).toLocaleDateString();
  const expiry = (l) => (l.expired ? "expired" : l.expires ? `until ${date(l.expires)}` : "no expiry");
</script>

<Dialog title="Public links" {onclose}>
  {#if links === null}
    <p class="note">Loading…</p>
  {:else if confirming}
    <p>Revoke the public link to <strong>{confirming.path ?? "this folder"}</strong>?</p>
    <p class="note">
      It stops working at once. The folder is re-encrypted in the background while the tab stays
      open, as when you revoke a person.
    </p>
    <p>
      <button class="danger" onclick={revoke} disabled={busy}>{busy ? "Revoking…" : "Revoke"}</button>
      <button onclick={() => (confirming = null)}>Cancel</button>
    </p>
  {:else}
    {#if links.length === 0}
      <p>You haven't made any public links. Make one from a folder's menu: Share publicly…</p>
    {:else}
      <table>
        <tbody>
          {#each links as l}
            <tr>
              <td><strong>{l.path ?? "(a folder)"}</strong></td>
              <td class="note">made {date(l.created)}, {expiry(l)}</td>
              <td><button class="danger" onclick={() => (confirming = l)}>Revoke…</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="note">A link is shown only when it is made. If one is lost, revoke it and make a new one.</p>
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
