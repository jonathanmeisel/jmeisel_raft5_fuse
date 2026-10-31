<script>
  // A line above the files saying how the open folder is shared: with
  // whom, whether by public link, and through which folder, when the
  // sharing was set up on a folder above it. For a folder in a top-level
  // folder that this account can only read, who shared it, and whether
  // this account can still change it (a read-write share inside a
  // read-only one). `here` is the Worker's `sharingHere`. It
  // also names the top-level folder's owner, if someone else, and, for a
  // folder with a size limit (`limited`, the Worker's `folderSize`), how
  // full it is.
  import { markUrl } from "../lib/sharedIcons.js";
  import { sizeText } from "../lib/sizes.js";

  let { here, current, limited = null, ondetails } = $props();

  /// "bob", "bob and carol", "bob, carol and dave", "bob, carol and 3 others".
  function names(people) {
    if (people.length <= 3) {
      return people.length > 1 ? `${people.slice(0, -1).join(", ")} and ${people.at(-1)}` : people[0];
    }
    return `${people.slice(0, 2).join(", ")} and ${people.length - 2} others`;
  }

  function what(source) {
    const people = source.people.length ? `with ${names(source.people)}` : "";
    const link = source.link ? (people ? " and by public link" : "by public link") : "";
    return `Shared ${people}${link}`;
  }

  const folder = (path) => path.replace(/^\//, "");
  const link = $derived(here?.sources?.some((s) => s.link));
</script>

{#if here || limited}
  <div class="sharing-bar">
    {#if here}<img src={markUrl(link ? "link" : "people")} alt="" width="22" height="22" />{/if}
    <div class="text">
      {#if !here}
        <!-- Only a size limit to show. -->
      {:else if here.from}
        <p class="source">Shared with you by <strong>{here.from}</strong>{here.writable ? "" : ", read-only"}.</p>
      {:else}
        {#each here.sources as source}
          <p class="source">
            {what(source)}{#if source.path !== current}{" "}through <strong>{folder(source.path)}</strong>{/if}.
            <button class="details" onclick={() => ondetails(source.path)}>Details</button>
          </p>
        {/each}
      {/if}
      {#if here?.owner}<p class="source">Owned by <strong>{here.owner}</strong>.</p>{/if}
      {#if limited}
        <p class="source">
          Holds {sizeText(limited.bytes)} of its {sizeText(limited.limit)} limit.
        </p>
      {/if}
    </div>
  </div>
{/if}

<style>
  .sharing-bar {
    display: flex; align-items: center; gap: 10px; padding: 6px 16px;
    background: var(--wx-background); border-bottom: var(--wx-border-medium);
    color: var(--wx-color-font-alt); font-size: 13px;
  }
  .sharing-bar img { flex: none; }
  .text { min-width: 0; line-height: 1.45; }
  /* One sentence each, wrapping as text does, with Details as a link at
     its end. */
  .source { margin: 0; }
  strong { color: var(--wx-color-font); font-weight: 600; }
  .details {
    display: inline; padding: 0 0 0 4px; border: none; background: none;
    font-size: inherit; color: var(--wx-color-primary); text-decoration: underline;
  }
</style>
