<script>
  // What a file or folder was in each snapshot (the wasm `versions`): open,
  // download, or restore one. Snapshots are hourly for a day and daily for a
  // week on a cluster that keeps them, so this is only as fine as they are.
  import Dialog from "./Dialog.svelte";
  import { sizeText } from "../lib/sizes.js";

  let { fs, path, free, onopen, ondownload, onrestored, onclose } = $props();
  // svelte-ignore state_referenced_locally
  const name = path.slice(path.lastIndexOf("/") + 1);
  // svelte-ignore state_referenced_locally
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";

  let found = $state(null);
  let error = $state("");
  let busy = $state(false);
  /// The version whose restore choices show.
  let restoring = $state(null);

  async function load() {
    try {
      found = await fs.versions(path);
    } catch (e) {
      error = e.message;
    }
  }
  load();

  const isFolder = $derived((found?.now?.kind ?? found?.versions[0]?.kind) === "folder");

  /// "14:00" today, "yesterday 14:00", else "Nov 4 14:00".
  function when(ms) {
    const at = new Date(ms);
    const time = at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const day = new Date(at).setHours(0, 0, 0, 0);
    const today = new Date().setHours(0, 0, 0, 0);
    if (day === today) return time;
    if (today - day === 24 * 3600 * 1000) return `yesterday ${time}`;
    return `${at.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
  }

  /// `report (as of Nov 4 14.00).docx`, from `report.docx`. No `:`, which some
  /// systems can't have in a name.
  function restoredName(version) {
    const label = when(version.taken).replaceAll(":", ".");
    const dot = version.kind === "file" ? name.lastIndexOf(".") : -1;
    const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ""];
    return `${stem} (as of ${label})${ext}`;
  }

  const join = (name) => (dir === "/" ? "" : dir) + "/" + name;

  async function restore(version, replace) {
    busy = true;
    error = "";
    try {
      const copy = join(await free(dir, restoredName(version)));
      await fs.copy(version.path, copy);
      if (replace) {
        await fs.rename(copy, path, true);
        onrestored(dir, `Put back ${name} as it was at ${when(version.taken)}.`);
      } else {
        onrestored(dir, `Restored ${name} as it was at ${when(version.taken)}, as ${copy.slice(dir.length).replace(/^\//, "")}.`);
      }
      onclose();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={`${name}: versions`} wide {onclose}>
  {#if found === null && !error}
    <p class="note">Looking through the snapshots…</p>
  {:else if found}
    <table>
      <tbody>
        <tr class="now">
          <td>Now</td>
          {#if found.now}
            <td>{isFolder ? "" : `edited ${when(found.now.modified)}`}</td>
            <td>{found.now.size != null && !isFolder ? sizeText(found.now.size) : ""}</td>
          {:else}
            <td colspan="2">Not here any more</td>
          {/if}
          <td></td>
        </tr>
        {#each found.versions as version (version.snapshot)}
          <tr>
            <td>As of {when(version.taken)}</td>
            <td>{version.kind === "file" ? `edited ${when(version.modified)}` : ""}</td>
            <td>{version.kind === "file" && version.size != null ? sizeText(version.size) : ""}</td>
            <td class="actions">
              <button onclick={() => onopen(version)}>Open</button>
              <button onclick={() => ondownload(version)}>Download</button>
              <button onclick={() => (restoring = restoring === version ? null : version)}>Restore…</button>
            </td>
          </tr>
          {#if restoring === version}
            <tr>
              <td colspan="4" class="restore">
                <button class="primary" disabled={busy} onclick={() => restore(version, false)}>As a copy</button>
                {#if version.kind === "file" && found.now?.kind === "file"}
                  <button class="danger" disabled={busy} onclick={() => restore(version, true)}>Replace the current file</button>
                  <span class="note">Replacing loses what is there now, unless a snapshot has it.</span>
                {/if}
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
    {#if found.versions.length === 0}
      <p>No other versions in the snapshots.</p>
    {/if}
    <p class="note">
      Versions come from snapshots: on a server that keeps them, one each hour for a day, and one each
      day for a week. A {isFolder ? "folder" : "file"} renamed since isn't found in older ones.
      {#if found.unreadable}{found.unreadable} snapshots couldn't be read.{/if}
    </p>
  {/if}
  {#if error}<p class="error">{error}</p>{/if}
  <p><button onclick={onclose}>Close</button></p>
</Dialog>

<style>
  table { width: 100%; border-collapse: collapse; }
  td { padding: 6px 8px 6px 0; border-bottom: 1px solid var(--border); vertical-align: middle; }
  .now td { font-weight: 600; }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
  .restore { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
</style>
