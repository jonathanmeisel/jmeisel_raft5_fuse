<script>
  // A file opened in the app: an image shown, or text up to MAX_TEXT
  // bytes. Shown as text, never as a page, so nothing in the file runs.
  import { onDestroy } from "svelte";
  import Dialog from "./Dialog.svelte";
  import { kindOf } from "../lib/previews.js";

  let { fs, path, ondownload, onclose } = $props();
  const MAX_TEXT = 1 << 20;
  const name = path.slice(path.lastIndexOf("/") + 1);
  // svelte-ignore state_referenced_locally
  const kind = kindOf(name);

  let image = $state("");
  let text = $state(null);
  let error = $state("");

  async function load() {
    try {
      if (kind === "image") {
        image = URL.createObjectURL(await fs.download(path));
      } else {
        text = await fs.readText(path, MAX_TEXT);
        if (text === null) error = "This file isn't text.";
      }
    } catch (e) {
      error = e.message;
    }
  }
  load();
  onDestroy(() => image && URL.revokeObjectURL(image));
</script>

<Dialog title={name} wide {onclose}>
  {#if error}
    <p class="error">{error}</p>
  {:else if image}
    <img src={image} alt={name} />
  {:else if text}
    <pre>{text.text}</pre>
    {#if text.truncated}<p class="note">Only the first megabyte is shown; download it for the rest.</p>{/if}
  {:else}
    <p class="note">Opening…</p>
  {/if}
  <p>
    <button class="primary" onclick={ondownload}>Download</button>
    <button onclick={onclose}>Close</button>
  </p>
</Dialog>

<style>
  img {
    display: block;
    max-width: 100%;
    max-height: 70vh;
    margin: 0 auto;
  }
  pre {
    max-height: 65vh;
    overflow: auto;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 0.9em;
    white-space: pre-wrap;
    word-break: break-word;
  }
</style>
