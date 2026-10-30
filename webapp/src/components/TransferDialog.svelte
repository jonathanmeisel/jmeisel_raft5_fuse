<script>
  // Gives a top-level folder to another user. Only its owner can, and only
  // to someone who can already change it. It is theirs once they accept:
  // then it counts against their storage, and they can remove the old
  // owner's access. Nothing is encrypted again.
  import Dialog from "./Dialog.svelte";
  import { sizeText } from "../lib/sizes.js";

  let { fs, path, me, onclose } = $props();
  // svelte-ignore state_referenced_locally
  const name = path.replace(/^\//, "");
  const isLink = (user) => user.startsWith("link-");

  let volume = $state(null);
  let writers = $state([]);
  let size = $state(null);
  let to = $state("");
  let busy = $state(false);
  let error = $state("");
  let done = $state("");

  async function load() {
    try {
      const [v, shared, measured] = await Promise.all([
        fs.volume(path),
        fs.sharedWith(path),
        fs.folderSize(path),
      ]);
      volume = v ?? { owner: null, offeredTo: null };
      writers = shared.filter((g) => g.writable && !g.via && g.user !== me && !isLink(g.user)).map((g) => g.user);
      to = writers[0] ?? "";
      size = measured?.measuredAt ? measured.bytes : null;
    } catch (e) {
      error = e.message;
      volume = { owner: null, offeredTo: null };
    }
  }
  load();

  async function run(work) {
    busy = true;
    error = "";
    try {
      await work();
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  const offer = (event) => {
    event.preventDefault();
    run(async () => {
      await fs.offerVolume(path, to);
      done = `Offered ${name} to ${to}. It's theirs once they accept it.`;
    });
  };
  const withdraw = () =>
    run(async () => {
      await fs.withdrawOffer(path);
      done = "Withdrew the offer.";
    });
</script>

<Dialog title={`Transfer ownership: ${name}`} {onclose}>
  {#if volume === null}
    <p class="note">Loading…</p>
  {:else if volume.owner !== me}
    <p>
      {#if volume.owner}Only <strong>{volume.owner}</strong>, who owns {name}, can give it away.
      {:else}Nobody owns {name}: an admin can give it to someone.{/if}
    </p>
  {:else}
    {#if done}<p class="note">{done}</p>{/if}
    {#if volume.offeredTo}
      <p>Offered to <strong>{volume.offeredTo}</strong>, who hasn't answered yet.</p>
      <p><button class="danger" onclick={withdraw} disabled={busy}>Withdraw the offer</button></p>
    {:else if writers.length === 0}
      <p>
        You can give {name} only to someone who can change it. Share it with them read-write
        first, then come back here.
      </p>
    {:else}
      <form onsubmit={offer}>
        <p class="note">
          Once they accept, {name}{size !== null ? ` (${sizeText(size)})` : ""} counts against their
          storage, not yours, and they can remove your access to it.
        </p>
        <label for="transfer-to">Give it to</label>
        <select id="transfer-to" bind:value={to}>
          {#each writers as w}<option value={w}>{w}</option>{/each}
        </select>
        <p><button class="primary" type="submit" disabled={busy}>{busy ? "Offering…" : "Offer"}</button></p>
      </form>
    {/if}
  {/if}
  {#if error}<p class="error">{error}</p>{/if}
  <p><button onclick={onclose}>Close</button></p>
</Dialog>
