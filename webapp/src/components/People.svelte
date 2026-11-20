<script>
  // Whose key this account trusts, and how: a safety code read, an invitation,
  // or an introduction from someone it trusts to check keys (an introducer).
  // Their keys follow the account to its other devices. Someone whose key has
  // changed since (they may have enrolled again) shows here, to check again.
  import Dialog from "./Dialog.svelte";
  import CodeInput from "./CodeInput.svelte";
  import Fingerprint from "./Fingerprint.svelte";
  import ErrorText from "./ErrorText.svelte";

  let { fs, mine, onclose } = $props();
  let people = $state(null);
  let warnings = $state([]);
  /// {user, keyChanged} being checked; `user` is empty for someone new.
  let checking = $state(null);
  /// Whom to confirm forgetting, and whose code shows.
  let forgetting = $state("");
  let shown = $state("");
  let name = $state("");
  let words = $state("");
  let wordsComplete = $state(false);
  let error = $state("");
  let busy = $state(false);

  async function load() {
    try {
      people = await fs.people();
      warnings = await fs.trustWarnings();
    } catch (e) {
      error = e.message;
      people = [];
    }
  }

  // Each login merges with the account's other devices, but only logs a failure.
  // This is where someone looks at whom they trust, so it says so here.
  fs.syncPins()
    .catch((e) => (error = e.message))
    .then(load);

  async function run(work) {
    busy = true;
    error = "";
    try {
      await work();
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function check(event) {
    event.preventDefault();
    const user = checking.user || name.trim();
    run(async () => {
      if (checking.keyChanged) await fs.replaceKey(user, words.trim());
      else {
        if (!(await fs.userExists(user))) {
          throw new Error(`There's nobody called ${user} here. Check the spelling.`);
        }
        await fs.trust(user, words.trim());
      }
      checking = null;
      name = words = "";
    });
  }

  const setIntroducer = (user, on) => run(() => fs.setIntroducer(user, on));

  /// How a person's key came to be trusted, in a few words.
  function how(p) {
    if (p.how === "invited") return "through an invitation";
    if (p.how === "introduced") return `introduced by ${p.by}`;
    return "checked";
  }

  const forget = (user) =>
    run(async () => {
      await fs.forgetKey(user);
      forgetting = "";
    });
</script>

<Dialog title="People" keep={!!checking} {onclose}>
  {#if people === null}
    <p class="note">Loading…</p>
  {:else if checking}
    <form onsubmit={check}>
      {#if checking.user}
        <p>
          <strong>{checking.user}</strong>'s key has changed: they may have enrolled again. Ask them to
          read you their new safety code. If they didn't reset anything, tell your admin first.
        </p>
      {:else}
        <label for="person-name">Their account name</label>
        <input id="person-name" bind:value={name} required autocapitalize="none" autocomplete="off" />
      {/if}
      <CodeInput {fs} id="person-words" label="Their safety code" bind:value={words} bind:complete={wordsComplete} />
      <p>They may need yours too. Your safety code:</p>
      <Fingerprint fingerprint={mine} />
      <p>
        <button class="primary" type="submit" disabled={busy || !wordsComplete}>Check</button>
        <button type="button" onclick={() => (checking = null)}>Cancel</button>
      </p>
    </form>
  {:else}
    <p class="note">
      People whose key you trust: you read their safety code, one of you invited the other, or someone
      you trust to check keys introduced them. You can share with them, and change what they share
      with you, without checking again.
    </p>
    {#each warnings as w}<p class="error">{w}</p>{/each}
    {#if people.length === 0}
      <p>You haven't checked anyone yet.</p>
    {/if}
    {#each people as p (p.user)}
      <div class="person">
        <div class="line">
          <span>
            <strong>{p.user}</strong>
            {#if p.keyChanged}<span class="error">, key changed</span>{:else}<span class="note">, {how(p)}</span>{/if}
          </span>
          <span class="actions">
            {#if p.keyChanged}
              <button onclick={() => (checking = { user: p.user, keyChanged: true })}>Check new safety code…</button>
            {:else}
              <button onclick={() => (shown = shown === p.user ? "" : p.user)}>{shown === p.user ? "Hide code" : "Show code"}</button>
            {/if}
            <button class="danger" onclick={() => (forgetting = p.user)}>Forget…</button>
          </span>
        </div>
        {#if !p.keyChanged && p.how !== "introduced"}
          <label class="introducer">
            <input
              type="checkbox"
              checked={p.introducer}
              disabled={busy}
              onchange={(e) => setIntroducer(p.user, e.target.checked)}
            />
            Trust people {p.user} checks
          </label>
        {/if}
        {#if shown === p.user}<Fingerprint fingerprint={p.fingerprint} />{/if}
        {#if forgetting === p.user}
          <p class="note">
            Forget {p.user}'s key? Files aren't affected, but their shares become read-only here, and
            you'd need their safety code to share with them again.
          </p>
          <p>
            <button class="danger" onclick={() => forget(p.user)} disabled={busy}>Forget</button>
            <button onclick={() => (forgetting = "")}>Cancel</button>
          </p>
        {/if}
      </div>
    {/each}
    <p>
      <button class="primary" onclick={() => (checking = { user: "", keyChanged: false })}>Check someone's safety code</button>
      <button onclick={onclose}>Close</button>
    </p>
  {/if}
  {#if error}<div class="error"><ErrorText {fs} message={error} /></div>{/if}
</Dialog>

<style>
  .person { padding: 8px 0; border-bottom: 1px solid var(--border); }
  .line { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; }
  .introducer { display: flex; align-items: center; gap: 6px; font-size: 0.9em; margin-top: 4px; }
</style>
