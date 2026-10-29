<script>
  // User management, for admins: every account, invitation not used yet,
  // and public link; what each may do; inviting, letting someone enroll
  // again, and removing. The servers check every step: this only offers
  // them.
  import Dialog from "./Dialog.svelte";
  import Invitation from "./Invitation.svelte";

  let { fs, me, onclose } = $props();

  const CAPS = [
    { id: "volumes", text: "Folders", title: "Create their own top-level folders" },
    { id: "links", text: "Links", title: "Make public links" },
    { id: "admin", text: "Admin", title: "Manage users, as you do" },
  ];

  let users = $state(null);
  let error = $state("");
  let busy = $state(false);
  /// What the dialog shows instead of the list: an invite form, an
  /// invitation, or a question.
  let step = $state(null);

  // The invite form.
  let name = $state("");
  let chosen = $state({});

  async function load() {
    try {
      users = await fs.listUsers();
    } catch (e) {
      error = e.message;
      users = [];
    }
  }
  load();

  async function run(work) {
    busy = true;
    error = "";
    try {
      await work();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function toggle(user, cap, on) {
    run(async () => {
      try {
        user.caps = await fs.setCapabilities(user.user, on ? [cap] : [], on ? [] : [cap]);
      } finally {
        users = [...users];
      }
    });
  }

  function invite(event) {
    event.preventDefault();
    const user = name.trim();
    run(async () => {
      try {
        const caps = CAPS.filter((c) => chosen[c.id]).map((c) => c.id);
        step = { kind: "issued", user, ...(await fs.issueInvite(user, caps)) };
        name = "";
        chosen = {};
        await load();
      } catch (e) {
        throw e.code === "EEXIST" ? new Error(`The name ${user} is taken. Choose another.`) : e;
      }
    });
  }

  const reissue = (user) =>
    run(async () => {
      step = { kind: "issued", user, ...(await fs.reissueInvite(user)) };
      await load();
    });

  const remove = (user) =>
    run(async () => {
      await fs.deleteUser(user);
      step = null;
      await load();
    });

  /// Asks about `user` (step `kind`, with `extra`), and fills in what only
  /// they can reach, which removing them or re-enrolling them would leave
  /// unreachable.
  async function ask(kind, user, extra = {}) {
    step = { kind, user, ...extra, impact: null };
    try {
      const impact = await fs.removalImpact(user);
      if (step?.user === user) step = { ...step, impact };
    } catch (e) {
      error = e.message;
    }
  }

  async function showUnreachable() {
    step = { kind: "unreachable", items: null };
    try {
      const items = await fs.listUnreachable();
      if (step?.kind === "unreachable") step = { ...step, items };
    } catch (e) {
      error = e.message;
    }
  }

  const purge = (item) =>
    run(async () => {
      await fs.deleteUnreachable(item.ino);
      await showUnreachable();
    });

  const size = (bytes) =>
    bytes >= 1 << 30
      ? `${(bytes / (1 << 30)).toFixed(1)} GB`
      : bytes >= 1 << 20
        ? `${(bytes / (1 << 20)).toFixed(1)} MB`
        : `${Math.ceil(bytes / 1024)} KB`;
  const kind = (u) => (u.volume ? "Top-level folder" : u.folders ? "Folder" : "File");
  const total = (items) => ({
    files: items.reduce((n, u) => n + u.files, 0),
    bytes: items.reduce((n, u) => n + u.bytes, 0),
  });

  const what = (u) => (u.kind === "link" ? `public link made by ${u.owner}` : u.enrolled ? "" : "invited");
</script>

<Dialog title="Users" wide {onclose}>
  {#if step?.kind === "invite"}
    <form onsubmit={invite}>
      <label for="invite-user">Their account name</label>
      <input id="invite-user" bind:value={name} required autocomplete="off" />
      <p class="note">Lower-case letters, digits, _ . and -. It can't be changed later.</p>
      <p>They may also:</p>
      {#each CAPS as c}
        <label><input type="checkbox" bind:checked={chosen[c.id]} style="width:auto" /> {c.title}</label>
      {/each}
      <p>
        <button class="primary" type="submit" disabled={busy}>{busy ? "Inviting…" : "Invite"}</button>
        <button type="button" onclick={() => (step = null)}>Back</button>
      </p>
    </form>
  {:else if step?.kind === "issued"}
    <Invitation user={step.user} invitation={step.invitation} code={step.code} />
    <p><button class="primary" onclick={() => (step = null)}>Done</button></p>
  {:else if step?.kind === "reenroll"}
    <p>Let <strong>{step.user}</strong> enroll again?</p>
    <p class="note">
      They get a new invitation, which replaces any earlier one. Enrolling with it gives them a new
      key: everything shared with them, their own folders included, is unshared and has to be shared
      with them again, and the people who share with them are asked to check their new fingerprint.
    </p>
    {#if step.impact === null}
      <p class="note">Checking what only {step.user} can reach…</p>
    {:else if step.impact.length}
      <p class="error">
        Only {step.user} can reach {step.impact.length === 1 ? "one folder or file" : `${step.impact.length} folders or files`}
        now: {total(step.impact).files} files, {size(total(step.impact).bytes)}. Nobody could open them
        afterwards. You can delete them later, under Unreachable folders.
      </p>
    {/if}
    <p>
      <button class="danger" onclick={() => reissue(step.user)} disabled={busy || step.impact === null}>Make an invitation</button>
      <button onclick={() => (step = null)}>Cancel</button>
    </p>
  {:else if step?.kind === "delete"}
    <p>Remove <strong>{step.user}</strong>?</p>
    <p class="note">
      {#if step.link}
        The public link stops working at once.
      {:else if !step.enrolled}
        Their invitation stops working.
      {:else}
        They can't log in any more, and everything shared with them is unshared. Folders only they
        could reach can't be reached by anyone.
      {/if}
    </p>
    {#if step.impact === null}
      <p class="note">Checking what only {step.user} can reach…</p>
    {:else if step.impact.length}
      <p class="error">
        Only {step.user} can reach {step.impact.length === 1 ? "one folder or file" : `${step.impact.length} folders or files`}
        now: {total(step.impact).files} files, {size(total(step.impact).bytes)}. Nobody could open them
        afterwards. You can delete them later, under Unreachable folders.
      </p>
    {/if}
    <p>
      <button class="danger" onclick={() => remove(step.user)} disabled={busy || step.impact === null}>Remove</button>
      <button onclick={() => (step = null)}>Cancel</button>
    </p>
  {:else if step?.kind === "unreachable"}
    <p class="note">
      Folders and files whose last account was removed, or enrolled again. Their names are sealed under
      keys nobody has, so only their size and age show, and nobody can open them. Deleting one frees its
      space, for good.
    </p>
    {#if step.items === null}
      <p class="note">Looking…</p>
    {:else if step.items.length === 0}
      <p>Every folder and file can be reached by someone.</p>
    {:else}
      <table>
        <tbody>
          {#each step.items as u (u.ino)}
            <tr>
              <td><strong>{kind(u)}</strong> <span class="note">#{u.ino}</span></td>
              <td class="note">
                {u.files} files, {size(u.bytes)}, last changed {new Date(u.modified).toLocaleDateString()}
              </td>
              <td class="actions">
                <button class="danger" onclick={() => (step = { kind: "purge", item: u })}>Delete…</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    <p><button onclick={() => (step = null)}>Back</button></p>
  {:else if step?.kind === "purge"}
    <p>Delete this {kind(step.item).toLowerCase()} ({step.item.files} files, {size(step.item.bytes)})?</p>
    <p class="note">Nobody can open it now, and this frees its space. It can't be undone.</p>
    <p>
      <button class="danger" onclick={() => purge(step.item)} disabled={busy}>Delete</button>
      <button onclick={showUnreachable}>Cancel</button>
    </p>
  {:else if users === null}
    <p class="note">Loading…</p>
  {:else}
    <p>
      <button class="primary" onclick={() => (step = { kind: "invite" })}>Invite someone</button>
      <button onclick={showUnreachable}>Unreachable folders</button>
    </p>
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>User</th>
            {#each CAPS as c}<th title={c.title}>{c.text}</th>{/each}
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each users as u (u.user)}
            <tr>
              <td>
                <strong>{u.user}</strong>{u.user === me ? " (you)" : ""}
                {#if what(u)}<span class="note"> · {what(u)}</span>{/if}
              </td>
              {#each CAPS as c}
                <td class="cap">
                  {#if u.kind === "person"}
                    <input
                      type="checkbox"
                      aria-label={`${c.title}: ${u.user}`}
                      checked={u.caps.includes(c.id)}
                      disabled={busy || (u.user === me && c.id === "admin")}
                      onchange={(e) => toggle(u, c.id, e.target.checked)}
                    />
                  {/if}
                </td>
              {/each}
              <td class="actions">
                {#if u.kind === "person" && u.user !== me}
                  <button onclick={() => ask("reenroll", u.user)}>
                    {u.enrolled ? "Re-enroll…" : "New invitation…"}
                  </button>
                {/if}
                {#if u.user !== me}
                  <button
                    class="danger"
                    onclick={() => ask("delete", u.user, { link: u.kind === "link", enrolled: u.enrolled })}
                  >
                    Remove…
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p><button onclick={onclose}>Close</button></p>
  {/if}
  {#if error}<p class="error">{error}</p>{/if}
</Dialog>

<style>
  .scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 0.85em; padding: 6px 4px; }
  td { padding: 6px 4px; border-bottom: 1px solid var(--border); }
  .cap { text-align: center; }
  .cap input { width: auto; }
  .actions { text-align: right; white-space: nowrap; }
  .actions button { margin-left: 6px; }
  /* Phones: each user's buttons on a line of their own, under the name. */
  @media (max-width: 600px) {
    tr { display: grid; grid-template-columns: 1fr repeat(3, 52px); align-items: center; }
    tr { border-bottom: 1px solid var(--border); }
    td { border: none; }
    th:last-child { display: none; }
    .actions { grid-column: 1 / -1; text-align: left; padding-top: 0; }
    .actions button { margin: 0 6px 0 0; }
    .actions:empty { display: none; }
  }
</style>
