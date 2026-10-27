<script>
  // The app's screens: log in, enrol, then the files. Logging out, or 30
  // minutes without input, ends the Worker, which drops every key. A
  // device that stays unlocked (an opt-in at login) logs back in by itself
  // when the app opens, has no idle logout, and forgets the account when
  // the user logs out. A public link opens its folder for a visitor, with
  // nothing kept in the browser.
  import { onDestroy } from "svelte";
  import { connect } from "./lib/rpc.js";
  import Login from "./components/Login.svelte";
  import Enrol from "./components/Enrol.svelte";
  import Files from "./components/Files.svelte";
  import { clearRoute, readRoute } from "./lib/route.js";

  const IDLE_MS = 30 * 60 * 1000;

  let screen = $state("starting");
  let fs = $state(null);
  let me = $state(null);
  let notice = $state("");
  let storageError = $state("");
  let lastUser = $state("");
  /// An invitation from the URL (`#invite=`), for the enroll screen.
  let invitation = $state("");

  function worker() {
    return connect({ onStorageError: (m) => (storageError = m) });
  }

  async function loggedIn(session, who) {
    fs = session;
    me = who;
    notice = "";
    screen = "files";
    // Ask the browser not to evict the pins, the prune queue, and any
    // remembered account.
    try {
      await navigator.storage?.persist?.();
    } catch {}
    resetIdle();
  }

  async function logout(why = "") {
    const ending = fs;
    const visitor = me?.visitor;
    fs = null;
    me = null;
    screen = visitor ? "closed" : "login";
    notice = why;
    clearTimeout(idleTimer);
    // A shared computer's address bar shouldn't keep showing folder names.
    clearRoute();
    if (ending) {
      if (why) ending.kill();
      else await ending.end().catch(() => ending.kill());
    }
  }

  /// Logs the remembered account back in, if this device has one. An
  /// invitation link goes straight to the enroll screen instead; its code
  /// leaves the address bar at once.
  async function start() {
    const route = readRoute();
    if (route?.invite) {
      invitation = route.invite;
      clearRoute();
      screen = "enrol";
      return;
    }
    if (route?.link) {
      // The link is a password: it leaves the address bar at once.
      clearRoute();
      const session = worker();
      try {
        return loggedIn(session, await session.visit(route.link));
      } catch (e) {
        session.kill();
        notice = e.code === "ELINK" ? e.message : `Couldn't open the link: ${e.message}`;
        screen = "closed";
        return;
      }
    }
    const session = worker();
    try {
      const who = await session.resume();
      if (who) return loggedIn(session, who);
      session.kill();
    } catch (e) {
      session.kill();
      notice =
        e.code === "EHOSTUNREACH"
          ? `Couldn't reach servers: ${e.message}`
          : `Log in again: ${e.message}`;
    }
    screen = "login";
  }
  start();

  let idleTimer = null;
  function resetIdle() {
    if (!fs || me?.remembered || me?.visitor) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(
      () => logout("Logged out after 30 minutes without use."),
      IDLE_MS,
    );
  }
  for (const event of ["pointerdown", "keydown", "wheel"]) {
    addEventListener(event, resetIdle, { passive: true });
  }
  onDestroy(() => clearTimeout(idleTimer));
</script>

{#if screen === "starting"}
  <main class="card"><p class="note">Opening…</p></main>
{:else if screen === "files" && fs}
  <Files {fs} {me} {storageError} onlogout={() => logout()} />
{:else}
  <main class="card">
    {#if notice}<p class="note">{notice}</p>{/if}
    {#if screen === "closed"}
      <p>To see the folder again, open the link you were given once more.</p>
    {:else if screen === "enrol"}
      <Enrol
        {worker}
        {invitation}
        ondone={(user) => {
          lastUser = user;
          screen = "login";
        }}
        oncancel={() => (screen = "login")}
      />
    {:else}
      <Login {worker} user={lastUser} onlogin={loggedIn} onenrol={() => (screen = "enrol")} />
    {/if}
  </main>
{/if}

<style>
  .card {
    /* A 16px gutter on phones. */
    width: min(440px, calc(100% - 32px));
    margin: 8vh auto;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px 28px;
  }
</style>
