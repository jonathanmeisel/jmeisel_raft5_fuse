<script>
  import Fingerprint from "./Fingerprint.svelte";

  let { worker, ondone, oncancel } = $props();
  let invitation = $state("");
  let password = $state("");
  let again = $state("");
  let busy = $state(false);
  let error = $state("");
  let enrolled = $state(null);

  async function submit(event) {
    event.preventDefault();
    error = "";
    if (password !== again) {
      error = "The passwords don't match.";
      return;
    }
    busy = true;
    const fs = worker();
    try {
      await fs.checkNewPassword(password);
      enrolled = await fs.enrol(invitation.trim(), password);
      password = again = "";
      // The login screen then offers this filesystem first.
      try {
        localStorage.setItem("raft5fs:filesystem", enrolled.fsId);
      } catch {}
    } catch (e) {
      error = e.message;
    } finally {
      fs.kill();
      busy = false;
    }
  }
</script>

{#if enrolled}
  <p>Enrolled <strong>{enrolled.user}</strong>.</p>
  <p>Your key's fingerprint</p>
  <Fingerprint fingerprint={enrolled.fingerprint} />
  <p><button class="primary" onclick={() => ondone(enrolled.user)}>Continue to log in</button></p>
{:else}
  <form onsubmit={submit}>
    <label for="invitation">Invitation</label>
    <textarea id="invitation" rows="4" bind:value={invitation} required placeholder="raft5fs-invite:1:…"></textarea>
    <label for="new-password">New password</label>
    <input id="new-password" type="password" autocomplete="new-password" bind:value={password} required />
    <label for="again">Again</label>
    <input id="again" type="password" autocomplete="new-password" bind:value={again} required />
    <p class="note">Choose a password with at least 12 characters</p>
    {#if error}<p class="error">{error}</p>{/if}
    <p>
      <button class="primary" type="submit" disabled={busy}>{busy ? "Enrolling…" : "Enroll"}</button>
      <button type="button" onclick={oncancel}>Cancel</button>
    </p>
  </form>
{/if}
