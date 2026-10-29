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
    <p>
      <button class="danger" onclick={() => reissue(step.user)} disabled={busy}>Make an invitation</button>
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
    <p>
      <button class="danger" onclick={() => remove(step.user)} disabled={busy}>Remove</button>
      <button onclick={() => (step = null)}>Cancel</button>
    </p>
  {:else if users === null}
    <p class="note">Loading…</p>
  {:else}
    <p><button class="primary" onclick={() => (step = { kind: "invite" })}>Invite someone</button></p>
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
                  <button onclick={() => (step = { kind: "reenroll", user: u.user })}>
                    {u.enrolled ? "Re-enroll…" : "New invitation…"}
                  </button>
                {/if}
                {#if u.user !== me}
                  <button
                    class="danger"
                    onclick={() => (step = { kind: "delete", user: u.user, link: u.kind === "link", enrolled: u.enrolled })}
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
