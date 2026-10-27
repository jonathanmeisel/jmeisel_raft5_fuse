<script>
  // Who a folder is shared with, and revoking. A revoke queues the folder
  // for pruning: until that finishes, what was written there before is
  // still sealed under keys the revoked user had.
  //
  // Shares of a folder above this one reach it too. They show with the
  // folder they come from, and are revoked there, not here.
  //
  // Public links show as such, not by their account name. Anyone who can
  // change the folder can revoke one, as for a person.
  import Dialog from "./Dialog.svelte";
  import LinkField from "./LinkField.svelte";

  let { fs, path, me, links = false, onclose } = $props();
  /// This account's own links, by name, for their expiry.
  let mine = $state(new Map());
  const isLink = (user) => user.startsWith("link-");
  const WARN_BYTES = 1 << 30;

  let grantees = $state(null);
  let error = $state("");
  let confirming = $state(null);
  let busy = $state(false);
  let revoked = $state("");
  /// The public link being shown, by its account name.
  let shown = $state(null);

  async function load() {
    try {
      grantees = await fs.sharedWith(path);
      if (links && grantees.some((g) => isLink(g.user))) {
        mine = new Map((await fs.listLinks()).map((l) => [l.user, l]));
      }
    } catch (e) {
      error = e.message;
      grantees = [];
    }
  }
  load();

  // Asks at once. The size to re-encrypt takes a walk of the whole folder,
  // so it shows when it is ready; revoking needn't wait for it.
  function ask(user) {
    error = "";
    const asking = { user, estimate: null };
    confirming = asking;
    fs.pruneEstimate(path).then(
      (estimate) => {
        if (confirming?.user === asking.user) confirming = { ...confirming, estimate };
      },
      () => {},
    );
  }

  async function revoke() {
    busy = true;
    error = "";
    try {
      await fs.revoke(path, confirming.user);
      revoked = isLink(confirming.user) ? "the public link" : `${confirming.user}'s share`;
      confirming = null;
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  const own = $derived(grantees?.filter((g) => !g.via) ?? []);
  const inherited = $derived(grantees?.filter((g) => g.via) ?? []);
  /// A folder as people know it: its path without the leading slash.
  const folder = (via) => via.replace(/^\//, "");

  const size = (bytes) =>
    bytes >= 1 << 30 ? `${(bytes / (1 << 30)).toFixed(1)} GB` : `${Math.ceil(bytes / (1 << 20))} MB`;
</script>

<Dialog title={`Shared with: ${path}`} {onclose}>
  {#if grantees === null}
    <p class="note">Loading…</p>
  {:else if confirming}
    {#if isLink(confirming.user)}
      <p>Revoke the public link to {path}? It stops working at once.</p>
    {:else}
      <p>Revoke <strong>{confirming.user}</strong>'s share of {path}?</p>
    {/if}
    <p class="note">
      This will attempt to re-encrypt all files previously visible to
      {isLink(confirming.user) ? "the link" : confirming.user} while the tab stays open, around
      {confirming.estimate ? size(confirming.estimate.bytes) : "…"}
    </p>
    {#if confirming.estimate && confirming.estimate.bytes > WARN_BYTES}
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
    {#if revoked}<p class="note">Revoked {revoked}; re-sealing runs in the background.</p>{/if}
    {#if grantees.length === 0}
      <p>Not shared with anyone.</p>
    {:else}
      <table>
        <tbody>
          {#each own as g}
            <tr>
              {#if isLink(g.user)}
                <td><strong>Public link</strong>{mine.has(g.user) ? " (yours)" : ""}</td>
                <td>
                  read-only{mine.get(g.user)?.expired ? ", expired" : ""}{mine.get(g.user)?.expires && !mine.get(g.user)?.expired
                    ? `, until ${new Date(mine.get(g.user).expires * 1000).toLocaleDateString()}`
                    : ""}
                </td>
              {:else}
                <td><strong>{g.user}</strong>{g.user === me ? " (you)" : ""}</td>
                <td>{g.writable ? "read-write" : "read-only"}</td>
              {/if}
              <td>
                {#if links && g.link}
                  <button onclick={() => (shown = shown === g.user ? null : g.user)}>
                    {shown === g.user ? "Hide link" : "Show link"}
                  </button>
                {/if}
                {#if g.user !== me}
                  <button class="danger" onclick={() => ask(g.user)} disabled={busy}>Revoke…</button>
                {/if}
              </td>
            </tr>
            {#if shown === g.user}
              <tr>
                <td colspan="3"><LinkField link={g.link} id="shared-link" /></td>
              </tr>
            {/if}
          {/each}
          {#each inherited as g}
            <tr class="inherited">
              <td><strong>{isLink(g.user) ? "Public link" : g.user}</strong></td>
              <td>{g.writable ? "read-write" : "read-only"}</td>
              <td class="note">via {folder(g.via)}</td>
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
