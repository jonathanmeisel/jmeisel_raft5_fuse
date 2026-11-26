<script>
  // The folder button in the header: the open folder's icon, with the share
  // mark when it is shared, and a menu of what there is to know and do about
  // it. In the account menu's colours and sizes; on phones it opens as a
  // sheet across the screen.
  //
  // - Sharing: "Shared" or "Not shared", or for a folder under a share made
  //   to this account, who shared it. It opens the folder's Sharing (who
  //   has it, and sharing it further), except for a reader, who can't.
  // - How much the folder holds, as last measured, and its size limit.
  // - Show deleted: what its snapshots hold that it doesn't now.
  // - View: how the file manager shows folders (SVAR's modes), and its
  //   details pane. These replace SVAR's own toolbar, so the app has one
  //   bar. Phones get no details pane: SVAR shows details there as a page.
  //
  // `here` is the Worker's `sharingHere`, and `size` its `folderSize`.
  // `shareable` says the open folder is one inside a share: outside one
  // (the root, a group, a snapshot) the menu has only View. `view` is
  // SVAR's `{ mode, preview }`. `children` is what the header shows beside
  // the icon.
  import { markUrl } from "../lib/sharedIcons.js";
  import { sizeText } from "../lib/sizes.js";

  let {
    folder,
    here,
    size = null,
    shareable = false,
    showDeleted = false,
    goneError = "",
    view = { mode: "cards", preview: false },
    onsharing,
    ontoggledeleted,
    onview,
    onpreview,
    children,
  } = $props();

  /// SVAR's modes, as the menu names them.
  const modes = [
    { id: "table", text: "List", icon: "wxi-view-sequential" },
    { id: "cards", text: "Grid", icon: "wxi-view-grid" },
    { id: "panels", text: "Two panels", icon: "wxi-view-column" },
  ];

  let open = $state(false);
  let root = $state(null);

  const sources = $derived(here?.sources ?? []);
  const shared = $derived(!!(here?.from || sources.length));
  const link = $derived(sources.some((s) => s.link));
  const sharing = $derived(
    here?.from
      ? `Shared with you by ${here.from}${here.writable ? "" : ", read-only"}`
      : shared
        ? "Shared"
        : "Not shared",
  );
  /// A reader can't see or change who else has the folder.
  const opens = $derived(!(here?.from && !sources.length && !here.writable));
  /// With a limit, what it holds against it (nothing, until measured);
  /// without one, what it holds once measured.
  const holds = $derived(
    size?.limit
      ? `Holds ${sizeText(size.bytes)} of its ${sizeText(size.limit)} limit`
      : size?.measuredAt
        ? `Holds ${sizeText(size.bytes)}`
        : "",
  );
  const name = $derived(folder.slice(folder.lastIndexOf("/") + 1) || "My files");

  function choose(act) {
    open = false;
    act();
  }

  function outside(event) {
    if (open && root && !root.contains(event.target)) open = false;
  }

  function key(event) {
    if (open && event.key === "Escape") {
      open = false;
      root?.querySelector(".folder")?.focus();
    }
  }
</script>

<svelte:window onpointerdown={outside} onkeydown={key} />

<div class="wrap" bind:this={root}>
  <button
    class="folder"
    aria-label={`Folder (${name})`}
    aria-haspopup="menu"
    aria-expanded={open}
    onclick={() => (open = !open)}
  >
    {#if shared}
      <img src={markUrl(link ? "link" : "people")} alt="" width="28" height="28" />
    {:else}
      <i class="wxi-folder logo" aria-hidden="true"></i>
    {/if}
    {@render children?.()}
    <i class="wxi-angle-down" aria-hidden="true"></i>
  </button>
  {#if open}
    <div class="menu" role="menu">
      <div class="who"><strong>{name}</strong></div>
      {#if shareable}
        {#if opens}
          <button role="menuitem" class="option" onclick={() => choose(onsharing)}>
            <i class="wxi-account" aria-hidden="true"></i>
            <span class="text">{sharing}</span>
          </button>
        {:else}
          <div class="info"><i class="wxi-account" aria-hidden="true"></i><span class="text">{sharing}</span></div>
        {/if}
        {#if holds}
          <div class="info"><i class="wxi-folder" aria-hidden="true"></i><span class="text">{holds}</span></div>
        {/if}
        <button
          role="menuitemcheckbox"
          aria-checked={showDeleted}
          class="option"
          onclick={() => choose(() => ontoggledeleted(!showDeleted))}
        >
          <span class="box" class:on={showDeleted} aria-hidden="true">
            {#if showDeleted}<i class="wxi-check" aria-hidden="true"></i>{/if}
          </span>
          <span class="text">Show deleted</span>
        </button>
        {#if showDeleted && goneError}
          <div class="note" title={goneError}>Deleted files can't be shown here.</div>
        {/if}
      {/if}
      <div class="section" class:first={!shareable} role="presentation">View</div>
      {#each modes as m (m.id)}
        <button
          role="menuitemradio"
          aria-checked={view.mode === m.id}
          class="option"
          onclick={() => choose(() => onview(m.id))}
        >
          <i class={m.icon} aria-hidden="true"></i>
          <span class="text">{m.text}</span>
          {#if view.mode === m.id}<i class="wxi-check mark" aria-hidden="true"></i>{/if}
        </button>
      {/each}
      <button
        role="menuitemcheckbox"
        aria-checked={view.preview}
        class="option wide"
        onclick={() => choose(() => onpreview(!view.preview))}
      >
        <span class="box" class:on={view.preview} aria-hidden="true">
          {#if view.preview}<i class="wxi-check" aria-hidden="true"></i>{/if}
        </span>
        <span class="text">Show details</span>
      </button>
    </div>
  {/if}
</div>

<style>
  .wrap { position: relative; min-width: 0; }
  .folder {
    display: flex; align-items: center; gap: 10px;
    height: 36px; padding: 0 8px 0 4px; min-width: 0;
    border: none; border-radius: var(--wx-radius-major, 6px);
    background: none; color: var(--wx-color-font); font-size: var(--wx-font-size);
  }
  button.folder:hover, .folder[aria-expanded="true"] { background: var(--wx-background-alt); }
  .folder img { flex: none; }
  .folder > .wxi-angle-down { font-size: 20px; color: var(--wx-icon-color); }
  /* SVAR's folder icon, in its colour, as in the folder tree. The glyph
     sits high in its box, so it moves down to look centred. */
  .logo {
    font-size: 28px; line-height: 1; color: var(--wx-color-primary); flex: none;
    transform: translateY(2px);
  }

  .menu {
    position: absolute; left: 0; top: calc(100% + 6px); z-index: 1001;
    min-width: 260px; padding: 4px 0;
    background: var(--wx-background); border: var(--menu-border);
    border-radius: var(--wx-radius-major, 6px);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
  }
  .who {
    padding: 8px 14px 10px; color: var(--wx-color-font);
    font-size: 13px; border-bottom: var(--wx-border-medium); margin-bottom: 4px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .who strong { font-weight: 600; }
  .option, .info {
    display: flex; align-items: center; gap: 10px; width: 100%;
    min-height: 36px; padding: 0 14px; box-sizing: border-box;
    border: none; border-radius: 0; background: transparent;
    color: var(--wx-color-font); font-size: var(--wx-font-size); text-align: left;
  }
  .info { color: var(--wx-color-font-alt); }
  .option:hover, .option:focus-visible { background: var(--wx-background-alt); outline: none; }
  .option i, .info i { font-size: 20px; color: var(--wx-icon-color); width: 20px; flex: none; }
  .text { flex: 1; }
  /* A checkbox drawn in the menu's colours, in the icons' column, so it
     reads as one even when empty. */
  .box {
    width: 16px; height: 16px; margin: 0 2px; flex: none; box-sizing: border-box;
    display: flex; align-items: center; justify-content: center;
    border: 2px solid var(--wx-icon-color); border-radius: 3px;
  }
  .box.on { background: var(--wx-color-primary); border-color: var(--wx-color-primary); }
  .option .box i { width: auto; font-size: 14px; color: #fff; }
  .note { padding: 4px 14px 8px 44px; color: var(--wx-color-font-alt); font-size: 13px; }
  .section {
    padding: 10px 14px 4px; margin-top: 4px; border-top: var(--wx-border-medium);
    color: var(--wx-color-font-alt); font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase;
  }
  .section.first { border-top: none; margin-top: 0; padding-top: 4px; }
  .option .mark { color: var(--wx-color-primary); }
  /* SVAR's narrow layout (under 768 px) has no details pane. */
  @media (max-width: 767px) { .wide { display: none; } }

  /* Phones: a sheet across the screen, under the header. */
  @media (max-width: 600px) {
    .menu { position: fixed; left: 8px; right: 8px; top: 56px; min-width: 0; }
    .option, .info { min-height: 48px; font-size: 16px; }
  }
</style>
