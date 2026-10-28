// The whole app, as two people use it: enrol, log in, make a volume,
// upload and download (one file large enough for object storage), share
// with a fingerprint, trust, read as the other user, and revoke, which
// queues a prune that the app works through.
import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

const invites = () =>
  JSON.parse(readFileSync(new URL("../config/local/invites.json", import.meta.url)));
const PASSWORD = "correct horse battery staple";
const localFsId = () =>
  JSON.parse(readFileSync(new URL("../config/local/config.json", import.meta.url)))
    .filesystems.find((f) => f.name === "local").fsId;
const SLOW = { timeout: 60_000 };
/// A 1x1 PNG.
const fixture = (name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url));
const WEBM = fixture("clip.webm");
const PDF = fixture("page.pdf");

/// Uploads the video and the PDF into the folder open in `page`.
async function uploadMedia(page) {
  await page.locator("input[type=file]").setInputFiles([
    { name: "clip.webm", mimeType: "video/webm", buffer: WEBM },
    { name: "page.pdf", mimeType: "application/pdf", buffer: PDF },
  ]);
  await expect(item(page, "clip.webm")).toBeVisible(SLOW);
  await expect(item(page, "page.pdf")).toBeVisible(SLOW);
  await expect(page.getByText(/Uploading/)).toHaveCount(0, SLOW);
}

/// Opens the video in the viewer, checks it plays and seeks, and gives its
/// source URL.
async function playsVideo(page) {
  await item(page, "clip.webm").dblclick();
  const video = page.getByRole("dialog").locator("video");
  await expect(video).toBeVisible(SLOW);
  await expect.poll(() => video.evaluate((v) => v.readyState), SLOW).toBeGreaterThanOrEqual(2);
  const at = await video.evaluate(
    (v) =>
      new Promise((resolve) => {
        v.pause();
        v.addEventListener("seeked", () => resolve(v.currentTime), { once: true });
        v.currentTime = 2;
      }),
  );
  expect(at).toBeCloseTo(2, 0);
  const src = await video.getAttribute("src");
  await page.getByRole("button", { name: "Close" }).click();
  return src;
}

/// Opens the PDF in the viewer, checks it comes as a PDF, and gives its
/// frame's source URL.
async function showsPdf(page) {
  await item(page, "page.pdf").dblclick();
  const frame = page.getByRole("dialog").locator("iframe");
  await expect(frame).toBeVisible(SLOW);
  const src = await frame.getAttribute("src");
  // A stream says its type; a blob: URL can't be fetched under the CSP,
  // and the viewer typed it the same way.
  if (!src.startsWith("blob:")) {
    const type = await page.evaluate(async (url) => (await fetch(url)).headers.get("content-type"), src);
    expect(type).toBe("application/pdf");
  }
  await page.getByRole("button", { name: "Close" }).click();
  return src;
}

const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

/// Enrols `user` through the page, and gives their fingerprint's words.
async function enrol(page, user, { viaLink = false } = {}) {
  if (viaLink) {
    // An invitation link opens the enroll screen with it filled in, and
    // takes the code out of the address bar.
    await page.goto(`/#invite=${encodeURIComponent(invites()[user])}`);
    await expect(page.getByLabel("Invitation")).toHaveValue(invites()[user]);
    expect(new URL(page.url()).hash).toBe("");
  } else {
    await page.goto("/");
    await page.getByRole("link", { name: "Enroll with an invitation" }).click();
    await page.getByLabel("Invitation").fill(invites()[user]);
  }
  await page.getByLabel("New password").fill(PASSWORD);
  await page.getByLabel("Again").fill(PASSWORD);
  await page.getByRole("button", { name: "Enroll" }).click();
  await expect(page.getByText(`Enrolled ${user}`)).toBeVisible(SLOW);
  const words = (await page.locator(".words").innerText()).trim();
  await page.getByRole("button", { name: "Continue to log in" }).click();
  return words;
}

/// The account button in the header.
const accountButton = (page) => page.getByRole("button", { name: /^Account/ });

/// Chooses `item` from the account menu.
async function accountMenu(page, item) {
  await accountButton(page).click();
  await page.getByRole("menuitem", { name: item }).click();
}

async function login(page, user, stay = false) {
  // Of the two filesystems, enrolling chose "local" (by the invitation),
  // and the app offers it first from then on.
  await expect(page.getByLabel("Filesystem")).toHaveValue(localFsId());
  await page.getByLabel("User name").fill(user);
  await page.getByLabel("Password").fill(PASSWORD);
  if (stay) await page.getByLabel(/Stay logged in/).check();
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(accountButton(page)).toBeVisible(SLOW);
}

/// Opens the app afresh at `hash`: a whole new page load, not a jump
/// within the page that is already there.
async function visit(page, hash) {
  await page.goto("about:blank");
  await page.goto(`/${hash}`);
}

/// Collects CSP violations and uncaught errors in `page`.
function watch(page) {
  const problems = [];
  page.on("console", (m) => {
    if (m.type() === "error") problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(String(e)));
  return problems;
}

/// The item called `name` in the main view (not the folder tree).
const item = (page, name) =>
  page.locator(".wx-filemanager .wx-content, .wx-filemanager [class*=cards], .wx-filemanager [class*=table]")
    .getByText(name, { exact: true })
    .first();

async function addFolder(page, name) {
  await page.getByText("Add New").click();
  await page.getByText("Add new folder").click();
  await page.locator(".wx-modal input").fill(name);
  await page.locator(".wx-modal").getByRole("button", { name: "OK" }).click();
  await expect(item(page, name)).toBeVisible(SLOW);
}

async function open(page, name) {
  await item(page, name).dblclick();
  await expect(page.locator(".wx-filemanager").getByText(name).first()).toBeVisible();
}

async function download(page, name) {
  const [file] = await Promise.all([page.waitForEvent("download", SLOW), menu(page, name, "Download")]);
  return readFileSync(await file.path());
}

async function menu(page, name, option) {
  // The first match is the option; a hotkey label can repeat its text.
  const choice = page.getByText(option, { exact: true }).first();
  // A right-click while the list re-renders opens no menu: try again.
  for (let tries = 0; ; tries++) {
    await item(page, name).click({ button: "right" });
    try {
      await choice.waitFor({ timeout: 3_000 });
      break;
    } catch (e) {
      if (tries === 4) throw e;
      await page.keyboard.press("Escape");
    }
  }
  await choice.click();
}

test("two people share a folder, then one revokes", async ({ browser }) => {
  const alice = await (await browser.newContext()).newPage();
  const bob = await (await browser.newContext()).newPage();
  const problems = [...[alice, bob].map(watch)];

  const small = Buffer.from("hello from alice\n");
  const large = randomBytes(12 << 20);
  let aliceWords, bobWords;

  await test.step("both enrol and log in", async () => {
    aliceWords = await enrol(alice, "alice");
    bobWords = await enrol(bob, "bob");
    expect(aliceWords.split(/\s+/).length).toBeGreaterThanOrEqual(12);
    await login(alice, "alice");
    await login(bob, "bob");
  });

  await test.step("alice makes a volume and uploads", async () => {
    await addFolder(alice, "docs");
    await open(alice, "docs");
    await alice.locator("input[type=file]").setInputFiles([
      { name: "small.txt", mimeType: "text/plain", buffer: small },
      { name: "large.bin", mimeType: "application/octet-stream", buffer: large },
    ]);
    await expect(item(alice, "small.txt")).toBeVisible(SLOW);
    await expect(item(alice, "large.bin")).toBeVisible(SLOW);
    await expect(alice.getByText(/Uploading/)).toHaveCount(0, SLOW);
  });

  await test.step("and downloads the same bytes", async () => {
    expect((await download(alice, "small.txt")).equals(small)).toBe(true);
    expect((await download(alice, "large.bin")).equals(large)).toBe(true);
  });

  await test.step("paths in the URL open folders and files", async () => {
    // Browsing records the folder, and a fresh visit to it lands there.
    expect(new URL(alice.url()).hash).toBe("#/docs");
    await visit(alice, "#/docs");
    await login(alice, "alice");
    await expect(item(alice, "small.txt")).toBeVisible(SLOW);
    // Back returns to where the app was before.
    await alice.getByText("My files").first().click();
    await expect(item(alice, "docs")).toBeVisible(SLOW);
    await alice.goBack();
    await expect(item(alice, "small.txt")).toBeVisible(SLOW);
    // A file's path opens it.
    await visit(alice, "#/docs/small.txt");
    await login(alice, "alice");
    await expect(alice.getByRole("dialog").locator("pre")).toHaveText(small.toString().trim(), SLOW);
    await alice.getByRole("button", { name: "Close" }).click();
    // A path that isn't there says so, from the root.
    await visit(alice, "#/nowhere");
    await login(alice, "alice");
    await expect(alice.getByText(/There's nothing at \/nowhere/)).toBeVisible(SLOW);
    await expect(item(alice, "docs")).toBeVisible(SLOW);
    await open(alice, "docs");
  });

  await test.step("video and PDFs stream through the service worker", async () => {
    await uploadMedia(alice);
    const video = await playsVideo(alice);
    expect(video).toMatch(/^\/stream\//);
    // A range, as a player asks for one, is exactly those bytes. The
    // viewer closed its stream, so open one again for the check.
    await item(alice, "clip.webm").dblclick();
    const src = await alice.getByRole("dialog").locator("video").getAttribute("src");
    const got = await alice.evaluate(async (url) => {
      const r = await fetch(url, { headers: { Range: "bytes=100-199" } });
      return { status: r.status, range: r.headers.get("content-range"), bytes: [...new Uint8Array(await r.arrayBuffer())] };
    }, src);
    expect(got.status).toBe(206);
    expect(got.range).toBe(`bytes 100-199/${WEBM.length}`);
    expect(Buffer.from(got.bytes).equals(WEBM.subarray(100, 200))).toBe(true);
    await alice.getByRole("button", { name: "Close" }).click();
    // The PDF too, as a PDF.
    const pdf = await showsPdf(alice);
    expect(pdf).toMatch(/^\/stream\//);
  });

  await test.step("images and text get previews, and open in the viewer", async () => {
    await alice.locator("input[type=file]").setInputFiles([
      { name: "dot.png", mimeType: "image/png", buffer: PNG },
    ]);
    await expect(item(alice, "dot.png")).toBeVisible(SLOW);
    // Thumbnails, drawn in the Worker, for dot.png and small.txt; not for
    // large.bin.
    await expect(alice.locator('.fm img[src^="blob:"]')).toHaveCount(2, SLOW);
    await item(alice, "small.txt").dblclick();
    await expect(alice.locator("pre")).toHaveText(small.toString().trim(), SLOW);
    await alice.getByRole("button", { name: "Close" }).click();
    await item(alice, "dot.png").dblclick();
    await expect(alice.getByRole("dialog").locator('img[src^="blob:"]')).toBeVisible(SLOW);
    await alice.getByRole("button", { name: "Close" }).click();
  });

  await test.step("alice renames and deletes", async () => {
    await addFolder(alice, "scratch");
    await menu(alice, "scratch", "Rename");
    await alice.locator(".wx-modal input").fill("renamed");
    await alice.locator(".wx-modal").getByRole("button", { name: "OK" }).click();
    await expect(item(alice, "renamed")).toBeVisible(SLOW);
    await expect(item(alice, "scratch")).toHaveCount(0);
    await menu(alice, "renamed", "Delete");
    await alice.locator(".wx-modal").getByRole("button", { name: "OK" }).click();
    await expect(item(alice, "renamed")).toHaveCount(0, SLOW);
  });

  await test.step("a share needs the right fingerprint", async () => {
    await alice.getByText("My files").first().click();
    await menu(alice, "docs", "Share…");
    await alice.getByLabel("User", { exact: true }).fill("bob");
    await alice.getByRole("button", { name: "Share", exact: true }).click();
    await alice.getByLabel("bob's fingerprint").fill(aliceWords);
    await alice.getByRole("button", { name: "Share", exact: true }).click();
    await expect(alice.getByText(/not the one given/)).toBeVisible(SLOW);
    await alice.getByLabel("bob's fingerprint").fill(bobWords);
    await alice.getByRole("button", { name: "Share", exact: true }).click();
    await expect(alice.getByText(/Shared with bob/)).toBeVisible(SLOW);
    await alice.getByRole("button", { name: "Done" }).click();
  });

  await test.step("a subfolder shows the share it inherits, without revoke", async () => {
    await open(alice, "docs");
    await addFolder(alice, "sub");
    await menu(alice, "sub", "Shared with…");
    const row = alice.getByRole("row").filter({ hasText: "bob" });
    await expect(row).toContainText("via docs", SLOW);
    await expect(row.getByRole("button")).toHaveCount(0);
    await alice.getByRole("button", { name: "Close" }).click();
    await alice.getByText("My files").first().click();
  });

  await test.step("bob trusts alice and reads the share", async () => {
    await bob.reload();
    await login(bob, "bob");
    // A share from someone not trusted yet shows as a banner.
    await expect(bob.getByText("A share is waiting for you to check who sent it.")).toBeVisible(SLOW);
    await bob.getByRole("button", { name: "Review" }).click();
    await expect(bob.getByText(/docs.*from alice/)).toBeVisible(SLOW);
    await bob.getByRole("button", { name: "Trust…" }).click();
    await bob.getByLabel("fingerprint").fill(aliceWords);
    await bob.getByRole("button", { name: "Trust", exact: true }).click();
    await expect(bob.getByText(/No shares from untrusted users/)).toBeVisible(SLOW);
    await bob.getByRole("button", { name: "Close" }).click();
    await open(bob, "docs");
    expect((await download(bob, "small.txt")).equals(small)).toBe(true);
  });

  await test.step("alice revokes, and the app re-seals the folder", async () => {
    await menu(alice, "docs", "Shared with…");
    const bobRow = alice.getByRole("row").filter({ hasText: "bob" });
    await expect(bobRow).toContainText("read-write", SLOW);
    await expect(alice.getByRole("row").filter({ hasText: "alice (you)" }).getByRole("button")).toHaveCount(0);
    await bobRow.getByRole("button", { name: "Revoke…" }).click();
    await alice.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(alice.getByText(/Revoked bob's share/)).toBeVisible(SLOW);
    await alice.getByRole("button", { name: "Close" }).click();
    await expect(alice.getByText(/Re-sealing/)).toBeVisible(SLOW);
    await expect(alice.getByText(/Re-sealing/)).toHaveCount(0, { timeout: 90_000 });
  });

  await test.step("bob can no longer open it", async () => {
    await bob.reload();
    await login(bob, "bob");
    await expect(item(bob, "docs")).toHaveCount(0, SLOW);
  });

  await test.step("a reload logs out, unless alice stays unlocked", async () => {
    await alice.reload();
    await expect(alice.getByRole("button", { name: "Log in" })).toBeVisible(SLOW);
    await login(alice, "alice", true);
    await alice.reload();
    await expect(accountButton(alice)).toBeVisible(SLOW);
    await expect(item(alice, "docs")).toBeVisible(SLOW);
    // A second tab opens the same account too.
    const second = await alice.context().newPage();
    await second.goto("/");
    await expect(accountButton(second)).toBeVisible(SLOW);
    await expect(item(second, "docs")).toBeVisible(SLOW);
    await second.close();
    // Logging out forgets the device.
    await accountMenu(alice, "Log out");
    await alice.reload();
    await expect(alice.getByRole("button", { name: "Log in" })).toBeVisible(SLOW);
  });

  expect(problems.flat()).toEqual([]);
});

test("without a service worker, files open and download whole", async ({ browser }) => {
  const context = await browser.newContext({ serviceWorkers: "block" });
  const carol = await context.newPage();
  const problems = watch(carol);
  await enrol(carol, "carol", { viaLink: true });
  await login(carol, "carol");
  await addFolder(carol, "media");
  await open(carol, "media");
  await uploadMedia(carol);
  expect(await playsVideo(carol)).toMatch(/^blob:/);
  expect(await showsPdf(carol)).toMatch(/^blob:/);
  expect((await download(carol, "page.pdf")).equals(PDF)).toBe(true);
  expect(problems).toEqual([]);
});

test("a user invites someone, who enrolls from the link", async ({ browser }) => {
  const erin = await (await browser.newContext()).newPage();
  const dave = await (await browser.newContext()).newPage();
  const problems = [erin, dave].map(watch);
  let link;

  await test.step("erin invites dave from the app", async () => {
    await enrol(erin, "erin");
    await login(erin, "erin");
    await accountMenu(erin, "Invite someone");
    // A name that is taken is refused.
    await erin.getByLabel("Their account name").fill("alice");
    await erin.getByRole("button", { name: "Invite", exact: true }).click();
    await expect(erin.getByText("The name alice is taken")).toBeVisible(SLOW);
    await erin.getByLabel("Their account name").fill("dave");
    await erin.getByRole("button", { name: "Invite", exact: true }).click();
    link = await erin.getByLabel("Link to enroll in this app").inputValue();
    expect(link).toMatch(/^http:\/\/localhost:4173\/#invite=raft5fs-invite/);
    await erin.getByRole("button", { name: "Invite someone else" }).click();
    await expect(erin.getByRole("cell", { name: "dave" })).toBeVisible();
    await erin.getByRole("button", { name: "Cancel", exact: true }).click();
  });

  await test.step("dave enrolls from the link, and can't make volumes", async () => {
    await dave.goto(link);
    expect(new URL(dave.url()).hash).toBe("");
    await dave.getByLabel("New password").fill(PASSWORD);
    await dave.getByLabel("Again").fill(PASSWORD);
    await dave.getByRole("button", { name: "Enroll" }).click();
    await expect(dave.getByText("Enrolled dave")).toBeVisible(SLOW);
    await dave.getByRole("button", { name: "Continue to log in" }).click();
    await login(dave, "dave");
    await accountButton(dave).click();
    await expect(dave.getByRole("menuitem", { name: "Shared with me" })).toBeVisible();
    await expect(dave.getByRole("menuitem", { name: "Invite someone" })).toHaveCount(0);
    await dave.keyboard.press("Escape");
    await dave.getByText("Add New").click();
    await dave.getByText("Add new folder").click();
    await dave.locator(".wx-modal input").fill("mine");
    await dave.locator(".wx-modal").getByRole("button", { name: "OK" }).click();
    await expect(dave.getByText("You can't create top-level folders here")).toBeVisible();
  });

  await test.step("the invitation is used up", async () => {
    await accountMenu(erin, "Invite someone");
    await expect(erin.getByLabel("Their account name")).toBeVisible();
    await expect(erin.getByRole("cell", { name: "dave" })).toHaveCount(0);
  });

  expect(problems.flat()).toEqual([]);
});

test("a public link opens a folder for anyone, until a writer revokes it", async ({ browser }) => {
  const frank = await (await browser.newContext()).newPage();
  const gina = await (await browser.newContext()).newPage();
  const visitor = await (await browser.newContext()).newPage();
  const problems = [frank, gina, visitor].map(watch);
  const note = Buffer.from("for everyone\n");
  let link;

  await test.step("frank shares a folder with gina, who trusts him", async () => {
    const frankWords = await enrol(frank, "frank");
    const ginaWords = await enrol(gina, "gina");
    await login(frank, "frank");
    await login(gina, "gina");
    await addFolder(frank, "public");
    await open(frank, "public");
    await frank.locator("input[type=file]").setInputFiles([
      { name: "note.txt", mimeType: "text/plain", buffer: note },
    ]);
    await expect(item(frank, "note.txt")).toBeVisible(SLOW);
    await frank.getByText("My files").first().click();
    await menu(frank, "public", "Share…");
    await frank.getByLabel("User", { exact: true }).fill("gina");
    await frank.getByRole("button", { name: "Share", exact: true }).click();
    await frank.getByLabel("gina's fingerprint").fill(ginaWords);
    await frank.getByRole("button", { name: "Share", exact: true }).click();
    await frank.getByRole("button", { name: "Done" }).click();
    await gina.reload();
    await login(gina, "gina");
    await accountMenu(gina, "Shared with me");
    await gina.getByRole("button", { name: "Trust…" }).click();
    await gina.getByLabel("fingerprint").fill(frankWords);
    await gina.getByRole("button", { name: "Trust", exact: true }).click();
    await gina.getByRole("button", { name: "Close" }).click();
  });

  await test.step("frank makes a public link", async () => {
    await menu(frank, "public", "Share publicly…");
    await frank.getByRole("button", { name: "Make link" }).click();
    link = await frank.getByLabel("Public link").inputValue();
    expect(link).toMatch(/^http:\/\/localhost:4173\/#link=[\w-]+$/);
    await frank.getByRole("button", { name: "Done" }).click();
    await accountMenu(frank, "Public links");
    await expect(frank.getByRole("cell", { name: "/public" })).toBeVisible(SLOW);
    await frank.getByRole("button", { name: "Show link" }).click();
    expect(await frank.locator("#my-link").inputValue()).toBe(link);
    await frank.getByRole("button", { name: "Close" }).click();
  });

  await test.step("anyone opens it, read-only, with nothing kept", async () => {
    await visitor.goto(link);
    await expect(item(visitor, "note.txt")).toBeVisible(SLOW);
    expect(new URL(visitor.url()).hash).not.toContain("link=");
    await expect(visitor.getByRole("button", { name: "Close" })).toBeVisible();
    await expect(accountButton(visitor)).toHaveCount(0);
    await expect(visitor.getByText("Add New")).toHaveCount(0);
    expect((await download(visitor, "note.txt")).equals(note)).toBe(true);
    expect(await visitor.evaluate(async () => (await indexedDB.databases()).length)).toBe(0);
  });

  await test.step("gina, who can change the folder, copies it, then revokes it", async () => {
    await menu(gina, "public", "Shared with…");
    const row = gina.getByRole("row").filter({ hasText: "Public link" });
    await row.getByRole("button", { name: "Show link" }).click();
    expect(await gina.locator("#shared-link").inputValue()).toBe(link);
    await row.getByRole("button", { name: "Revoke…" }).click();
    await gina.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(gina.getByText(/Revoked the public link/)).toBeVisible(SLOW);
    await gina.getByRole("button", { name: "Close" }).click();
  });

  await test.step("and the link no longer works", async () => {
    const again = await (await browser.newContext()).newPage();
    await again.goto(link);
    await expect(again.getByText("This link no longer works.")).toBeVisible(SLOW);
    await accountMenu(frank, "Public links");
    await expect(frank.getByText(/haven't made any public links/)).toBeVisible(SLOW);
  });

  expect(problems.flat()).toEqual([]);
});

/// Makes the key that `page`'s browser has pinned for `user` a wrong one,
/// as if `user` had enrolled again since. Run it logged out: the Worker
/// reads the pins at login.
async function stalePin(page, me, user) {
  await page.evaluate(
    async ([me, user]) => {
      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open("raft5fs", 2);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const ask = (request) =>
        new Promise((resolve, reject) => {
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
      const blobs = db.transaction("blobs", "readwrite").objectStore("blobs");
      const name = (await ask(blobs.getAllKeys())).find((k) => k.endsWith(`/${me}/known_keys`));
      const text = new TextDecoder().decode(await ask(blobs.get(name)));
      const changed = text.replace(new RegExp(`^${user} .*$`, "m"), `${user} ${"00".repeat(32)}`);
      await ask(blobs.put(new TextEncoder().encode(changed).buffer, name));
    },
    [me, user],
  );
}

test("a changed key is trusted again only by its new fingerprint", async ({ browser }) => {
  const hank = await (await browser.newContext()).newPage();
  const iris = await (await browser.newContext()).newPage();
  const problems = [hank, iris].map(watch);
  let hankWords, irisWords;

  await test.step("hank shares with iris, who trusts him", async () => {
    hankWords = await enrol(hank, "hank");
    irisWords = await enrol(iris, "iris");
    await login(hank, "hank");
    await login(iris, "iris");
    await addFolder(hank, "team");
    await menu(hank, "team", "Share…");
    await hank.getByLabel("User", { exact: true }).fill("iris");
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await hank.getByLabel("iris's fingerprint").fill(irisWords);
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await hank.getByRole("button", { name: "Done" }).click();
    await iris.reload();
    await login(iris, "iris");
    await iris.getByRole("button", { name: "Review" }).click();
    await iris.getByRole("button", { name: "Trust…" }).click();
    await iris.getByLabel("fingerprint").fill(hankWords);
    await iris.getByRole("button", { name: "Trust", exact: true }).click();
    await expect(iris.getByText(/No shares from untrusted users/)).toBeVisible(SLOW);
    await iris.getByRole("button", { name: "Close" }).click();
  });

  await test.step("hank shares again after iris's key changed", async () => {
    await accountMenu(hank, "Log out");
    await stalePin(hank, "hank", "iris");
    await login(hank, "hank");
    await menu(hank, "team", "Share…");
    await hank.getByLabel("User", { exact: true }).fill("iris");
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await expect(hank.getByText(/iris's key has changed/)).toBeVisible(SLOW);
    // The wrong fingerprint leaves the old key in place.
    await hank.getByLabel("iris's fingerprint").fill(hankWords);
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await expect(hank.getByText(/not the one given/)).toBeVisible(SLOW);
    await hank.getByLabel("iris's fingerprint").fill(irisWords);
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await expect(hank.getByText(/Shared with iris/)).toBeVisible(SLOW);
    await hank.getByRole("button", { name: "Done" }).click();
  });

  await test.step("iris trusts hank again after his key changed", async () => {
    await accountMenu(iris, "Log out");
    await stalePin(iris, "iris", "hank");
    await login(iris, "iris");
    await iris.getByRole("button", { name: "Review" }).click();
    await expect(iris.getByText(/hank's key has changed/)).toBeVisible(SLOW);
    await iris.getByRole("button", { name: "Check new fingerprint…" }).click();
    await iris.getByLabel("fingerprint").fill(hankWords);
    await iris.getByRole("button", { name: "Trust", exact: true }).click();
    await expect(iris.getByText(/No shares from untrusted users/)).toBeVisible(SLOW);
    await iris.getByRole("button", { name: "Close" }).click();
  });

  expect(problems.flat()).toEqual([]);
});

test("the app refuses to run in a frame", async ({ page }) => {
  // A page that frames the app. Chrome won't let a page from another
  // origin frame a local one at all, so this one is on the app's origin;
  // the app refuses any frame.
  await page.route("http://localhost:4173/framer.html", (route) =>
    route.fulfill({ contentType: "text/html", body: `<iframe src="/"></iframe>` }),
  );
  await page.goto("/framer.html");
  const frame = page.frameLocator("iframe");
  await expect(frame.locator("body")).toContainText("doesn't run inside a frame");
});
