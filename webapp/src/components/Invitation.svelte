<script>
  // An invitation, as an admin gets it: a link that opens this app's enroll
  // screen filled in, and the same invitation as text for the command line.
  // Either one lets whoever has it take the name, so it goes to that person
  // alone. Without the servers' addresses, only the code.
  let { user, invitation, code } = $props();

  /// This app, opening the enroll screen with `invitation` (see route.js).
  const link = $derived(
    invitation && `${location.origin}${location.pathname}#invite=${encodeURIComponent(invitation)}`,
  );
  let copied = $state("");
  let error = $state("");

  async function copy(what, text) {
    try {
      await navigator.clipboard.writeText(text);
      copied = what;
    } catch {
      error = "The browser wouldn't copy. Select the text and copy it yourself.";
    }
  }
</script>

<p>Invitation for <strong>{user}</strong>. Send it to {user} alone: whoever has it can take the name.</p>
{#if link}
  <label for="invite-link">Link to enroll in this app</label>
  <div class="row">
    <input id="invite-link" readonly value={link} onfocus={(e) => e.target.select()} />
    <button onclick={() => copy("link", link)}>{copied === "link" ? "Copied" : "Copy"}</button>
  </div>
  <label for="invite-text">Or, for the command line (<code>raft5fs enrol '…'</code>)</label>
  <div class="row">
    <input id="invite-text" readonly value={invitation} onfocus={(e) => e.target.select()} />
    <button onclick={() => copy("text", invitation)}>{copied === "text" ? "Copied" : "Copy"}</button>
  </div>
{:else}
  <p>The servers don't say how to reach them, so this is only the enrollment code:</p>
  <div class="row">
    <input id="invite-code" readonly value={code} onfocus={(e) => e.target.select()} />
    <button onclick={() => copy("code", code)}>{copied === "code" ? "Copied" : "Copy"}</button>
  </div>
{/if}
{#if error}<p class="error">{error}</p>{/if}

<style>
  .row { display: flex; gap: 8px; align-items: center; }
  .row input { flex: 1; min-width: 0; }
</style>
