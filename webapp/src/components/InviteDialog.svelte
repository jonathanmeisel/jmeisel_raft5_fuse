<script>
  // Invites a new user: a name that nobody has yet, and what they may do
  // (at most what this account may). The result is a link to this app that
  // opens the enroll screen filled in, and the same invitation as text for
  // the command line. Either one lets whoever has it take the name, so it
  // goes to that person alone.
  import Dialog from "./Dialog.svelte";

  let { fs, caps, onclose } = $props();

  const CAPS = [
    { id: "volumes", text: "Create their own top-level folders" },
    { id: "invite", text: "Invite others" },
    { id: "links", text: "Make public links" },
  ];
  const offered = $derived(CAPS.filter((c) => caps.includes(c.id)));

  let user = $state("");
  let chosen = $state({});
  let busy = $state(false);
  let error = $state("");
  let issued = $state(null);
  let pending = $state(null);
  let copied = $state("");

  async function load() {
    try {
      pending = await fs.listInvites();
    } catch (e) {
      error = e.message;
      pending = [];
    }
  }
  load();

  async function submit(event) {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      const name = user.trim();
      const given = offered.filter((c) => chosen[c.id]).map((c) => c.id);
      const result = await fs.issueInvite(name, given);
      issued = { ...result, user: name, link: result.invitation && linkFor(result.invitation) };
      await load();
    } catch (e) {
      error = e.code === "EEXIST" ? `The name ${user.trim()} is taken. Choose another.` : e.message;
    } finally {
      busy = false;
    }
  }

  /// This app, opening the enroll screen with `invitation` (see route.js).
  const linkFor = (invitation) =>
    `${location.origin}${location.pathname}#invite=${encodeURIComponent(invitation)}`;

  async function copy(what, text) {
    try {
      await navigator.clipboard.writeText(text);
      copied = what;
    } catch {
      error = "The browser wouldn't copy. Select the text and copy it yourself.";
    }
  }

  async function cancel(name) {
    error = "";
    try {
      await fs.cancelInvite(name);
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  const capsText = (list) =>
    list.length ? list.map((id) => CAPS.find((c) => c.id === id)?.text.toLowerCase() ?? id).join(", ") : "only what is shared with them";
</script>

<Dialog title="Invite someone" {onclose}>
  {#if issued}
    <p>Invitation for <strong>{issued.user}</strong>. Send it to {issued.user} alone: whoever has it can take the name.</p>
    {#if issued.link}
      <label for="invite-link">Link to enroll in this app</label>
      <div class="row">
        <input id="invite-link" readonly value={issued.link} onfocus={(e) => e.target.select()} />
        <button onclick={() => copy("link", issued.link)}>{copied === "link" ? "Copied" : "Copy"}</button>
      </div>
      <label for="invite-text">Or, for the command line (<code>raft5fs enrol '…'</code>)</label>
      <div class="row">
        <input id="invite-text" readonly value={issued.invitation} onfocus={(e) => e.target.select()} />
        <button onclick={() => copy("text", issued.invitation)}>{copied === "text" ? "Copied" : "Copy"}</button>
      </div>
    {:else}
      <p>The servers don't say how to reach them, so this is only the enrollment code:</p>
      <div class="row">
        <input id="invite-code" readonly value={issued.code} onfocus={(e) => e.target.select()} />
        <button onclick={() => copy("code", issued.code)}>{copied === "code" ? "Copied" : "Copy"}</button>
      </div>
    {/if}
    <p>
      <button class="primary" onclick={onclose}>Done</button>
      <button onclick={() => { issued = null; user = ""; chosen = {}; copied = ""; }}>Invite someone else</button>
    </p>
  {:else}
    <form onsubmit={submit}>
      <label for="invite-user">Their account name</label>
      <input id="invite-user" bind:value={user} required autocomplete="off" />
      <p class="note">Lower-case letters, digits, _ . and -. It can't be changed later.</p>
      {#if offered.length}
        <p>They may also:</p>
        {#each offered as c}
          <label><input type="checkbox" bind:checked={chosen[c.id]} style="width:auto" /> {c.text}</label>
        {/each}
      {/if}
      {#if error}<p class="error">{error}</p>{/if}
      <p>
        <button class="primary" type="submit" disabled={busy}>{busy ? "Inviting…" : "Invite"}</button>
        <button type="button" onclick={onclose}>Cancel</button>
      </p>
    </form>
    {#if pending?.length}
      <h3>Waiting to enroll</h3>
      <table>
        <tbody>
          {#each pending as p}
            <tr>
              <td><strong>{p.user}</strong></td>
              <td class="note">{capsText(p.caps)}</td>
              <td><button onclick={() => cancel(p.user)}>Cancel invitation</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</Dialog>

<style>
  .row { display: flex; gap: 8px; align-items: center; }
  .row input { flex: 1; min-width: 0; }
  h3 { margin: 18px 0 6px; font-size: 1em; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 6px 4px; border-bottom: 1px solid var(--border); }
  td:last-child { text-align: right; }
</style>
