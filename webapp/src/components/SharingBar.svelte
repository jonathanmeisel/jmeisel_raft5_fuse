<script>
  // A line above the files saying whether the open folder is shared: its
  // folder icon, with the share mark when it is, and "Shared" or "Not
  // shared", which opens the folder's Sharing (who, how, and sharing it
  // further). For a folder under a share made to this account, who shared
  // it, and whether this account can change it. `here` is the Worker's
  // `sharingHere`; `shareable` says the folder is one that can be shared.
  // For a folder with a size limit (`limited`, the Worker's `folderSize`),
  // it also says how full it is. `end` is what shows at the bar's right
  // end (the Show deleted toggle).
  import { markUrl } from "../lib/sharedIcons.js";
  import { sizeText } from "../lib/sizes.js";

  let { here, limited = null, shareable = false, ondetails, end = null } = $props();

  const sources = $derived(here?.sources ?? []);
  const shared = $derived(!!(here?.from || sources.length));
  const link = $derived(sources.some((s) => s.link));
  const text = $derived(
    here?.from
      ? `Shared with you by ${here.from}${here.writable ? "" : ", read-only"}`
      : shared
        ? "Shared"
        : "Not shared",
  );
  /// A reader can't see or change who else has the folder.
  const opens = $derived(shareable && !(here?.from && !sources.length && !here.writable));
</script>

{#if shareable || shared || limited || end}
  <div class="sharing-bar">
    {#if shareable || shared}
      <img src={markUrl(shared ? (link ? "link" : "people") : "none")} alt="" width="22" height="22" />
    {/if}
    <div class="text">
      {#if shareable || shared}
        <p class="source">
          {#if opens}<button class="details" onclick={ondetails}>{text}</button>{:else}{text}{/if}
        </p>
      {/if}
      {#if limited}
        <p class="source">
          Holds {sizeText(limited.bytes)} of its {sizeText(limited.limit)} limit.
        </p>
      {/if}
    </div>
    {#if end}<div class="end">{@render end()}</div>{/if}
  </div>
{/if}

<style>
  .sharing-bar {
    display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; padding: 6px 16px;
    background: var(--wx-background); border-bottom: var(--wx-border-medium);
    color: var(--wx-color-font-alt); font-size: 13px;
  }
  .sharing-bar img { flex: none; }
  /* The text keeps room to read on a phone: below that, `end` goes to its
     own line, at the right. */
  .text { flex: 1 1 160px; min-width: 0; line-height: 1.45; }
  .end { margin-left: auto; flex: none; display: flex; align-items: center; gap: 10px; }
  .source { margin: 0; }
  .details {
    display: inline; padding: 0; border: none; background: none; text-align: left;
    font-size: inherit; color: var(--wx-color-primary); text-decoration: underline;
  }
</style>
