<script>
  // Where someone types the safety code that another person read out to them.
  // It says at once if a word isn't one of the code's words, so a typo is
  // never mistaken for a different key. `complete` says when it can be checked.
  import { onDestroy } from "svelte";

  let { fs, id, label, value = $bindable(""), complete = $bindable(false) } = $props();
  let progress = $state({ words: 0, unknown: [] });
  let asked = 0;

  $effect(() => {
    const text = value;
    const asking = ++asked;
    fs.checkSafetyCode(text).then(
      (answer) => {
        if (asking !== asked) return;
        progress = answer;
        complete = answer.complete;
      },
      () => {},
    );
  });
  onDestroy(() => asked++);
</script>

<label for={id}>{label}</label>
<textarea
  {id}
  rows="3"
  bind:value
  required
  autocapitalize="none"
  autocomplete="off"
  autocorrect="off"
  spellcheck="false"
></textarea>
{#if progress.unknown.length}
  <p class="error">“{progress.unknown[0]}” isn't one of the words. Check the spelling.</p>
{:else if value.trim() && !complete}
  <p class="note">{progress.words} of 12 words</p>
{/if}
