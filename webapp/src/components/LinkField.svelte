<script>
  // A public link to read or copy: `link` is the `#link=` fragment's value.
  let { link, id = "public-link", label = "Public link" } = $props();

  const url = $derived(`${location.origin}${location.pathname}#link=${link}`);
  let copied = $state(false);
  let error = $state("");

  async function copy() {
    try {
      await navigator.clipboard.writeText(url);
      copied = true;
    } catch {
      error = "The browser wouldn't copy. Select the link and copy it yourself.";
    }
  }
</script>

<label for={id}>{label}</label>
<div class="row">
  <input {id} readonly value={url} onfocus={(e) => e.target.select()} />
  <button onclick={copy}>{copied ? "Copied" : "Copy"}</button>
</div>
{#if error}<p class="error">{error}</p>{/if}

<style>
  .row { display: flex; gap: 8px; align-items: center; }
  .row input { flex: 1; min-width: 0; }
</style>
