<script>
  // A file opened in the app: an image, a video, audio or a PDF shown by the
  // browser itself, or text up to MAX_TEXT bytes shown as text. A file's
  // type comes from its extension only (`mimeOf`), so nothing in it runs as
  // a page.
  //
  // - With streaming (`streams`, see streams.js), video, audio and PDFs play
  //   at once from a stream URL, with no size limit, and fall back to the
  //   whole file if the browser can't play the stream.
  // - Otherwise the whole file is decrypted into memory first (a blob: URL).
  import { onDestroy } from "svelte";
  import Dialog from "./Dialog.svelte";
  import { kindOf, mimeOf } from "../lib/previews.js";

  let { fs, path, streams = null, ondownload, onclose } = $props();
  const MAX_TEXT = 1 << 20;
  const name = path.slice(path.lastIndexOf("/") + 1);
  // svelte-ignore state_referenced_locally
  const kind = kindOf(name);
  const type = mimeOf(name);

  let url = $state("");
  let text = $state(null);
  let error = $state("");
  /// The stream's token, while the viewer shows a stream.
  let token = null;
  /// Whether the file was opened in another tab, which still needs it.
  let shared = false;

  async function wholeFile() {
    return URL.createObjectURL(await fs.download(path, undefined, type));
  }

  async function load() {
    try {
      if (kind === "text") {
        text = await fs.readText(path, MAX_TEXT);
        if (text === null) error = "This file isn't text.";
      } else if (kind !== "image" && streams?.available()) {
        ({ token, url } = await streams.open(path, type));
      } else {
        url = await wholeFile();
      }
    } catch (e) {
      error = e.message;
    }
  }
  load();

  // A browser that can't play the stream (Safari has quirks with media
  // through a service worker) gets the whole file instead, once.
  async function streamFailed() {
    if (!token) return;
    const failed = token;
    token = null;
    streams.close(failed);
    url = "";
    try {
      url = await wholeFile();
    } catch (e) {
      error = e.message;
    }
  }

  function openInTab() {
    shared = true;
    window.open(url, "_blank", "noopener");
  }

  onDestroy(() => {
    if (token) {
      // A stream open in another tab keeps working until logout.
      if (!shared) streams.close(token);
    } else if (url) {
      const blob = url;
      setTimeout(() => URL.revokeObjectURL(blob), shared ? 60_000 : 0);
    }
  });
</script>

<Dialog title={name} wide {onclose}>
  {#if error}
    <p class="error">{error}</p>
  {:else if text}
    <pre>{text.text}</pre>
    {#if text.truncated}<p class="note">Only the first megabyte is shown; download it for the rest.</p>{/if}
  {:else if url && kind === "image"}
    <img src={url} alt={name} />
  {:else if url && kind === "video"}
    <!-- svelte-ignore a11y_media_has_caption -->
    <video src={url} controls autoplay onerror={streamFailed}></video>
  {:else if url && kind === "audio"}
    <audio src={url} controls autoplay onerror={streamFailed}></audio>
  {:else if url && kind === "pdf"}
    <iframe src={url} title={name}></iframe>
  {:else}
    <p class="note">Opening…</p>
  {/if}
  <p>
    <button class="primary" onclick={ondownload}>Download</button>
    {#if url}<button onclick={openInTab}>Open in new tab</button>{/if}
    <button onclick={onclose}>Close</button>
  </p>
</Dialog>

<style>
  img, video {
    display: block;
    max-width: 100%;
    max-height: 70vh;
    margin: 0 auto;
  }
  audio {
    display: block;
    width: 100%;
  }
  iframe {
    display: block;
    width: 100%;
    height: 72vh;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: #fff;
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
