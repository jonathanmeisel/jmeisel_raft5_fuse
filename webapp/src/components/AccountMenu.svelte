<script>
  // The account button: the user's initial in a circle and their name (on
  // phones the initial alone), and a menu of what the account does that
  // isn't a file action. In SVAR's colours and sizes, so it sits
  // with the file manager. On phones the menu opens as a sheet across the
  // screen, with bigger targets.
  //
  // `items` is a list of {id, text, icon, badge?, danger?, separator?};
  // choosing one calls `onselect(id)`. `note` shows under the name, such
  // as the storage used; opening the menu calls `onopen`, to refresh it.
  let { user, items, onselect, note = "", onopen = () => {} } = $props();

  let open = $state(false);
  let root = $state(null);
  /// The name's first character, whole even outside the BMP.
  const initial = $derived(([...user][0] ?? "?").toUpperCase());

  function choose(id) {
    open = false;
    onselect(id);
  }

  function outside(event) {
    if (open && root && !root.contains(event.target)) open = false;
  }

  function key(event) {
    if (open && event.key === "Escape") {
      open = false;
      root?.querySelector(".account")?.focus();
    }
  }
</script>

<svelte:window onpointerdown={outside} onkeydown={key} />

<div class="wrap" bind:this={root}>
  <button
    class="account"
    aria-label={`Account (${user})`}
    aria-haspopup="menu"
    aria-expanded={open}
    onclick={() => {
      open = !open;
      if (open) onopen();
    }}
  >
    <span class="avatar" aria-hidden="true">{initial}</span>
    <span class="name">{user}</span>
    {#if items.some((i) => i.badge)}<span class="dot" aria-hidden="true"></span>{/if}
    <i class="wxi-angle-down" aria-hidden="true"></i>
  </button>
  {#if open}
    <div class="menu" role="menu">
      <div class="who">
        Logged in as <strong>{user}</strong>
        {#if note}<div class="storage">{note}</div>{/if}
      </div>
      {#each items as item (item.id)}
        {#if item.separator}<div class="separator"></div>{/if}
        <button role="menuitem" class="option" class:danger={item.danger} onclick={() => choose(item.id)}>
          <i class={item.icon}></i>
          <span class="text">{item.text}</span>
          {#if item.badge}<span class="badge">{item.badge}</span>{/if}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .wrap { position: relative; }
  .account {
    position: relative;
    display: flex; align-items: center; gap: 8px;
    height: 36px; padding: 0 8px 0 6px; max-width: 220px;
    border: none; border-radius: var(--wx-radius-major, 6px);
    background: none; color: var(--wx-color-font);
    font-size: var(--wx-font-size);
  }
  .account:hover, .account[aria-expanded="true"] { background: var(--wx-background-alt); }
  .account i { font-size: 20px; color: var(--wx-icon-color); }
  .avatar {
    width: 26px; height: 26px; border-radius: 50%; flex: none;
    display: flex; align-items: center; justify-content: center;
    background: var(--wx-color-primary); color: #fff;
    font-size: 13px; font-weight: 700; line-height: 1;
  }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--wx-color-primary); flex: none; }

  .menu {
    position: absolute; right: 0; top: calc(100% + 6px); z-index: 1001;
    min-width: 230px; padding: 4px 0;
    background: var(--wx-background); border: var(--menu-border);
    border-radius: var(--wx-radius-major, 6px);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
  }
  .who {
    padding: 8px 14px 10px; color: var(--wx-color-font-alt);
    font-size: 13px; border-bottom: var(--wx-border-medium); margin-bottom: 4px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .who strong { color: var(--wx-color-font); font-weight: 600; }
  .storage { margin-top: 4px; }
  .separator { border-top: var(--wx-border-medium); margin: 4px 0; }
  .option {
    display: flex; align-items: center; gap: 10px; width: 100%;
    height: 36px; padding: 0 14px;
    border: none; border-radius: 0; background: transparent;
    color: var(--wx-color-font); font-size: var(--wx-font-size); text-align: left;
  }
  .option:hover, .option:focus-visible { background: var(--wx-background-alt); outline: none; }
  .option i { font-size: 20px; color: var(--wx-icon-color); width: 20px; }
  .option.danger, .option.danger i { color: var(--danger); }
  .text { flex: 1; white-space: nowrap; }
  .badge {
    min-width: 20px; padding: 0 6px; border-radius: 10px; line-height: 20px;
    background: var(--wx-color-primary); color: #fff; font-size: 12px; text-align: center;
  }

  /* Phones: a sheet across the screen, under the header. */
  @media (max-width: 600px) {
    .account { padding: 0 5px; }
    .account .name, .account > .wxi-angle-down { display: none; }
    /* The badge's dot sits on the avatar's corner. */
    .dot { position: absolute; top: 4px; right: 3px; border: 2px solid var(--wx-background); }
    .menu {
      position: fixed; left: 8px; right: 8px; top: 56px; min-width: 0;
    }
    .option { height: 48px; font-size: 16px; }
  }
</style>
