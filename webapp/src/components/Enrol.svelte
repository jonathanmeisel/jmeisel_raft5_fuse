<script>
  import Fingerprint from "./Fingerprint.svelte";

  let { worker, invitation: given = "", ondone, oncancel } = $props();
  // svelte-ignore state_referenced_locally
  let invitation = $state(given);
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
  <p class="note">
    These 12 words are your safety code. The first time you share with someone, you'll each
    read yours to the other, so you know you've really reached each other. No need to save it: it's
    always under your name, in My safety code.
  </p>
  <Fingerprint fingerprint={enrolled.fingerprint} />
  {#if enrolled.inviterTrusted}
    <p class="note">
      Your invitation came from <strong>{enrolled.inviter}</strong>, so the two of you already trust
      each other's keys. You won't need to read safety codes with {enrolled.inviter}, or with the
      people {enrolled.inviter} has checked.
    </p>
  {:else if enrolled.inviter}
    <p class="error">
      Couldn't confirm {enrolled.inviter}'s key from your invitation: {enrolled.inviterError}.
      Read safety codes with {enrolled.inviter} the first time you share.
    </p>
  {/if}
  <p><button class="primary" onclick={() => ondone(enrolled.user)}>Continue to log in</button></p>
{:else}
  <form onsubmit={submit}>
    <label for="invitation">Invitation</label>
    <textarea id="invitation" rows="4" bind:value={invitation} required placeholder="raft5fs-invite:…"></textarea>
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
