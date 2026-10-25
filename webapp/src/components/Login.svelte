<script>
  let { worker, user = "", onlogin, onenrol } = $props();

  // The filesystems this app serves; the last one used is remembered (not
  // a secret) for next time.
  const filesystems = __RAFT5FS_FILESYSTEMS__;
  const LAST = "raft5fs:filesystem";
  let fsId = $state(lastUsed());

  function lastUsed() {
    try {
      const last = localStorage.getItem(LAST);
      if (filesystems.some((f) => f.fsId === last)) return last;
    } catch {}
    return filesystems[0].fsId;
  }
  // svelte-ignore state_referenced_locally
  let username = $state(user);
  let password = $state("");
  let stay = $state(false);
  let busy = $state(false);
  let error = $state("");

  async function submit(event) {
    event.preventDefault();
    busy = true;
    error = "";
    const fs = worker();
    try {
      const me = await fs.login(fsId, username.trim(), password, stay);
      try {
        localStorage.setItem(LAST, fsId);
      } catch {}
      password = "";
      onlogin(fs, me);
    } catch (e) {
      fs.kill();
      error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<form onsubmit={submit}>
  {#if filesystems.length > 1}
    <label for="filesystem">Filesystem</label>
    <select id="filesystem" bind:value={fsId}>
      {#each filesystems as f}
        <option value={f.fsId}>{f.name}</option>
      {/each}
    </select>
  {/if}
  <label for="user">User name</label>
  <input id="user" autocomplete="username" bind:value={username} required />
  <label for="password">Password</label>
  <input id="password" type="password" autocomplete="current-password" bind:value={password} required />
  <label class="stay">
    <input type="checkbox" bind:checked={stay} />
    Stay unlocked on this device for 7 days
  </label>
  {#if stay}
    <p class="note">
      Only on a device that only you use: anyone who can open this browser can open your
      files until then, or until you log out.
    </p>
  {/if}
  {#if error}<p class="error">{error}</p>{/if}
  <p><button class="primary" type="submit" disabled={busy}>{busy ? "Logging in…" : "Log in"}</button></p>
</form>
<p class="note">New here, with an invitation? <a href="#enrol" onclick={(e) => { e.preventDefault(); onenrol(); }}>Enrol</a></p>

<style>
  .stay { display: flex; gap: 8px; align-items: center; color: var(--text); }
  .stay input { width: auto; }
</style>
