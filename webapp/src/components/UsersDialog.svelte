<script>
  // User management, for admins: every account, invitation not used yet,
  // and public link; what each may do and how much they store; inviting,
  // letting someone enroll again, and removing. Also orphaned folders, in
  // one list: top-level folders whose owner is gone, which an admin gives
  // to someone who can change them, and anything nobody can reach any
  // more, which an admin deletes. The servers check every step: this only
  // offers them.
  import Dialog from "./Dialog.svelte";
  import Invitation from "./Invitation.svelte";
  import { parseSize, sizeText } from "../lib/sizes.js";

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
  /// unreachable, and the top-level folders they own, which it would leave
  /// without an owner.
  async function ask(kind, user, extra = {}) {
    step = { kind, user, ...extra, impact: null, owned: null };
    try {
      const [impact, owned] = await Promise.all([
        fs.removalImpact(user),
        fs.removalOrphans(user).catch((e) => (e.code === "ENOTSUP" ? [] : Promise.reject(e))),
      ]);
      if (step?.user === user) step = { ...step, impact, owned };
    } catch (e) {
      error = e.message;
    }
  }

  /// Gives top-level folder `ino` to `user`, then asks again what step
  /// `kind` is about.
  const give = (ino, user) =>
    run(async () => {
      await fs.assignOwner(ino, user);
      if (step?.kind === "orphans") await showOrphans();
      else if (step?.user) await ask(step.kind, step.user, step);
    });

  /// Shows orphaned folders: each top-level folder without an owner who
  /// can change it, and each part nobody can reach. A top-level folder
  /// nobody can reach is both, and shows once, to delete.
  async function showOrphans() {
    step = { kind: "orphans", items: null };
    try {
      const [orphans, lost] = await Promise.all([
        fs.listOrphans().catch((e) => (e.code === "ENOTSUP" ? [] : Promise.reject(e))),
        fs.listUnreachable(),
      ]);
      const unreachable = new Map(lost.map((u) => [u.ino, u]));
      const items = [
        ...orphans.map((o) => ({ ...o, lost: unreachable.get(o.ino) ?? null })),
        ...lost
          .filter((u) => !orphans.some((o) => o.ino === u.ino))
          .map((u) => ({ ino: u.ino, path: null, owner: null, writers: [], bytes: u.bytes, lost: u })),
      ];
      if (step?.kind === "orphans") step = { ...step, items };
    } catch (e) {
      error = e.message;
    }
  }

  /// Who each orphan in a list goes to, as chosen.
  let heir = $state({});
  const folderName = (o) =>
    o.path ? o.path.slice(1) : `${o.lost ? kind(o.lost) : "Top-level folder"} #${o.ino}`;

  // The quota form.
  let quota = $state("");
  function editQuota(u) {
    quota = u.quota ? sizeText(u.quota).replace(" ", "") : "";
    step = { kind: "quota", user: u.user };
  }
  function saveQuota(event) {
    event.preventDefault();
    run(async () => {
      await fs.setQuota(step.user, parseSize(quota));
      step = null;
      await load();
    });
  }
  const measure = () =>
    run(async () => {
      await fs.measureUsage();
      await load();
    });
  const storage = (u) => (u.quota ? `${sizeText(u.used)} of ${sizeText(u.quota)}` : sizeText(u.used));

  const purge = (item) =>
    run(async () => {
      await fs.deleteUnreachable(item.ino);
      await showOrphans();
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

{#snippet heirs(o)}
  {#if o.writers.length}
    <select aria-label={`Who gets ${folderName(o)}`} bind:value={heir[o.ino]}>
      {#each o.writers as w}<option value={w}>{w}</option>{/each}
    </select>
    <button onclick={() => give(o.ino, heir[o.ino] ?? o.writers[0])} disabled={busy}>Give</button>
  {:else if o.reachable}
    <span class="note">Nobody else can change it.</span>
  {:else}
    <span class="note">Nobody else can reach it.</span>
  {/if}
{/snippet}

{#snippet owned(step)}
  {#if step.owned?.length}
    <p class="error">
      {step.user} owns {step.owned.length === 1 ? "a top-level folder" : `${step.owned.length} top-level folders`},
      which would have no owner. Give each to someone who can change it first:
    </p>
    <table>
      <tbody>
        {#each step.owned as o (o.ino)}
          <tr>
            <td><strong>{folderName(o)}</strong> <span class="note">{sizeText(o.bytes)}</span></td>
            <td class="actions">{@render heirs(o)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/snippet}

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
        afterwards. You can delete them later, under Orphaned folders.
      </p>
    {/if}
    {@render owned(step)}
    <p>
      <button class="danger" onclick={() => reissue(step.user)} disabled={busy || step.impact === null || step.owned === null}>Make an invitation</button>
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
        afterwards. You can delete them later, under Orphaned folders.
      </p>
    {/if}
    {@render owned(step)}
    <p>
      <button class="danger" onclick={() => remove(step.user)} disabled={busy || step.impact === null || step.owned === null}>Remove</button>
      <button onclick={() => (step = null)}>Cancel</button>
    </p>
  {:else if step?.kind === "orphans"}
    <p class="note">
      Folders left behind when their owner, or everyone who could open them, was removed or enrolled
      again. A top-level folder without an owner counts against nobody's storage: give it to someone
      who can change it. What nobody can reach, nobody can open (its names are sealed under keys
      nobody has, so only its size and age show): deleting it frees its space, for good.
    </p>
    {#if step.items === null}
      <p class="note">Looking…</p>
    {:else if step.items.length === 0}
      <p>Every top-level folder has an owner, and every folder and file can be reached by someone.</p>
    {:else}
      <table>
        <tbody>
          {#each step.items as o (o.ino)}
            <tr>
              <td>
                <strong>{folderName(o)}</strong>
                <span class="note">
                  {#if o.lost}
                    {o.lost.files} files, {sizeText(o.bytes)}, last changed
                    {new Date(o.lost.modified).toLocaleDateString()}{o.owner ? `, was ${o.owner}'s` : ""};
                    nobody can reach it
                  {:else}
                    {sizeText(o.bytes)}{o.owner ? `, was ${o.owner}'s` : ""}
                  {/if}
                </span>
              </td>
              <td class="actions">
                {#if o.lost}
                  <button class="danger" onclick={() => (step = { kind: "purge", item: o.lost })}>Delete…</button>
                {:else}
                  {@render heirs(o)}
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    <p><button onclick={() => (step = null)}>Back</button></p>
  {:else if step?.kind === "quota"}
    <form onsubmit={saveQuota}>
      <label for="quota-size">How much {step.user}'s top-level folders may hold, such as 10G (blank for no limit)</label>
      <input id="quota-size" bind:value={quota} autocomplete="off" />
      <p class="note">
        Everything in the folders they own counts, whoever writes it. Writes that would go over it are
        refused; deleting always works.
      </p>
      <p>
        <button class="primary" type="submit" disabled={busy}>Save</button>
        <button type="button" onclick={() => (step = null)}>Cancel</button>
      </p>
    </form>
  {:else if step?.kind === "purge"}
    <p>Delete this {kind(step.item).toLowerCase()} ({step.item.files} files, {size(step.item.bytes)})?</p>
    <p class="note">Nobody can open it now, and this frees its space. It can't be undone.</p>
    <p>
      <button class="danger" onclick={() => purge(step.item)} disabled={busy}>Delete</button>
      <button onclick={showOrphans}>Cancel</button>
    </p>
  {:else if users === null}
    <p class="note">Loading…</p>
  {:else}
    <p class="toolbar">
      <button class="primary" onclick={() => (step = { kind: "invite" })}>Invite someone</button>
      <button onclick={showOrphans}>Orphaned folders</button>
      <button onclick={measure} disabled={busy}>Measure storage now</button>
    </p>
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>User</th>
            {#each CAPS as c}<th title={c.title}>{c.text}</th>{/each}
            <th>Storage</th>
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
                    <label>
                      <input
                        type="checkbox"
                        aria-label={`${c.title}: ${u.user}`}
                        checked={u.caps.includes(c.id)}
                        disabled={busy || (u.user === me && c.id === "admin")}
                        onchange={(e) => toggle(u, c.id, e.target.checked)}
                      />
                      <span class="cap-name" aria-hidden="true">{c.text}</span>
                    </label>
                  {/if}
                </td>
              {/each}
              <td class="storage">{u.kind === "person" ? storage(u) : ""}</td>
              <td class="actions">
                {#if u.kind === "person"}
                  <button aria-label={`Quota: ${u.user}`} onclick={() => editQuota(u)}>Quota</button>
                {/if}
                {#if u.kind === "person" && u.user !== me}
                  <button onclick={() => ask("reenroll", u.user)}>
                    {u.enrolled ? "Re-enroll" : "New invitation"}
                  </button>
                {/if}
                {#if u.user !== me}
                  <button
                    class="danger"
                    onclick={() => ask("delete", u.user, { link: u.kind === "link", enrolled: u.enrolled })}
                  >
                    Remove
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
  .toolbar { display: flex; flex-wrap: wrap; gap: 8px; }
  .scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 0.85em; padding: 6px 4px; }
  td { padding: 6px 4px; border-bottom: 1px solid var(--border); }
  .cap { text-align: center; }
  .cap input { width: auto; margin: 0; }
  /* The capability's name shows next to its box on phones, where the
     table has no header. */
  .cap-name { display: none; }
  .storage { white-space: nowrap; font-size: 0.9em; color: var(--muted); }
  .actions { text-align: right; white-space: nowrap; }
  .actions button { margin-left: 6px; }
  /* Phones: a card per user. The name; the capabilities, each with its
     name, and the storage at the right; then the buttons, small, on one
     line. */
  @media (max-width: 600px) {
    .toolbar button { flex: 1 1 auto; }
    thead { display: none; }
    tr {
      display: grid; grid-template-columns: auto auto auto 1fr; column-gap: 16px;
      align-items: center; padding: 10px 0; border-bottom: 1px solid var(--border);
    }
    td { border: none; padding: 2px 0; }
    td:first-child { grid-column: 1 / -1; padding-bottom: 6px; }
    .cap label { display: flex; align-items: center; gap: 6px; margin: 0; font-size: 0.9em; }
    .cap-name { display: inline; }
    .storage { text-align: right; }
    .actions { grid-column: 1 / -1; text-align: left; padding-top: 8px; white-space: normal; }
    .actions button { margin: 0 6px 0 0; padding: 4px 10px; font-size: 0.85em; }
    .actions:empty { display: none; }
  }
</style>
