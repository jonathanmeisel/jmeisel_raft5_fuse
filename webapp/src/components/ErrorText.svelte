<script>
  // An error's text. If it may mean the filesystem was restored from a backup,
  // this also offers the reset that only a person can decide on.
  let { fs, message } = $props();
  const MARK = "restored from a backup";
  let busy = $state(false);
  let failed = $state("");

  async function reset() {
    busy = true;
    try {
      await fs.resetVersions();
      // Every handle in this tab starts again from what is now remembered.
      location.reload();
    } catch (e) {
      failed = e.message;
      busy = false;
    }
  }
</script>

{#if message.includes(MARK)}
  {message.split(" Only if")[0]}
  <p>
    <button onclick={reset} disabled={busy}>It was restored: reset this device</button>
  </p>
  <p class="note">
    Only do this if your admin says so. If the filesystem wasn't restored, someone may be tampering with
    the servers.
  </p>
  {#if failed}<p>{failed}</p>{/if}
{:else}
  {message}
{/if}
