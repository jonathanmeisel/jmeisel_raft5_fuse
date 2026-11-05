// The whole app, as two people use it: enrol, log in, make a volume,
// upload and download (one file large enough for object storage), share
// with a fingerprint, trust, read as the other user, and revoke, which
// queues a prune that the app works through.
import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const invites = () =>
  JSON.parse(readFileSync(new URL("../config/local/invites.json", import.meta.url)));
const PASSWORD = "correct horse battery staple";
const localFsId = () =>
  JSON.parse(readFileSync(new URL("../config/local/config.json", import.meta.url)))
    .filesystems.find((f) => f.name === "local").fsId;
const SLOW = { timeout: 60_000 };
/// web_dev's port for new invitations: three after its native port.
const REISSUE = "http://127.0.0.1:27163";
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

/// Chooses `item` from the account menu. Some items show only once the
/// account's capabilities have loaded, just after login: open it again
/// until it's there.
async function accountMenu(page, item) {
  const choice = page.getByRole("menuitem", { name: item });
  for (let tries = 0; ; tries++) {
    await accountButton(page).click();
    try {
      await choice.waitFor({ timeout: 2_000 });
      break;
    } catch (e) {
      if (tries === 9) throw e;
      await page.keyboard.press("Escape");
    }
  }
  await choice.click();
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

/// How folder `name`'s card is marked as shared: "people", "link", or
/// null for SVAR's plain folder.
async function sharedMark(page, name) {
  const card = page.locator(".wx-item").filter({ has: page.getByText(name, { exact: true }) }).first();
  const src = await card.locator("img").first().getAttribute("src", { timeout: 2_000 }).catch(() => null);
  if (!src) return null;
  const svg = decodeURIComponent(src);
  return svg.includes("<rect") ? "link" : svg.includes("<circle") ? "people" : "?";
}

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

/// Opens folder `name`'s Sharing dialog, and chooses `action` in it, if any.
async function sharing(page, name, action) {
  await menu(page, name, "Sharing…");
  if (action) await page.getByRole("button", { name: action, exact: true }).click();
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
    expect(await sharedMark(alice, "docs")).toBe(null);
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
    await sharing(alice, "docs", "Share with someone");
    await alice.getByLabel("User", { exact: true }).fill("bob");
    await alice.getByRole("button", { name: "Share", exact: true }).click();
    await alice.getByLabel("bob's safety code").fill(aliceWords);
    await alice.getByRole("button", { name: "Share", exact: true }).click();
    await expect(alice.getByText(/don't match the key/)).toBeVisible(SLOW);
    await alice.getByLabel("bob's safety code").fill(bobWords);
    await alice.getByRole("button", { name: "Share", exact: true }).click();
    await expect(alice.getByText(/Shared with bob/)).toBeVisible(SLOW);
    await alice.getByRole("button", { name: "Done" }).click();
    await expect.poll(() => sharedMark(alice, "docs"), SLOW).toBe("people");
  });

  await test.step("a subfolder shows the share it inherits, without revoke", async () => {
    await open(alice, "docs");
    // The bar above the files says how the open folder is shared.
    const bar = alice.locator(".sharing-bar");
    await expect(bar).toHaveText(/^\s*Shared with bob\.\s*Details\s*$/, SLOW);
    await addFolder(alice, "sub");
    // Closing the details leaves the open folder as it was.
    await bar.getByRole("button", { name: "Details" }).click();
    await alice.getByRole("button", { name: "Close" }).click();
    await expect(item(alice, "sub")).toBeVisible(SLOW);
    await open(alice, "sub");
    await expect(bar).toContainText("Shared with bob through docs", SLOW);
    await bar.getByRole("button", { name: "Details" }).click();
    await expect(alice.getByRole("dialog", { name: "Shared with: /docs" })).toBeVisible();
    await alice.getByRole("button", { name: "Close" }).click();
    await alice.goBack();
    await expect(item(alice, "sub")).toBeVisible(SLOW);
    await sharing(alice, "sub");
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
    await expect(bob.getByText(/A share needs checking/)).toBeVisible(SLOW);
    await bob.getByRole("button", { name: "Review" }).click();
    await expect(bob.getByText(/docs.*from alice/)).toBeVisible(SLOW);
    await bob.getByRole("button", { name: "Trust…" }).click();
    await bob.getByLabel("Their safety code").fill(aliceWords);
    await bob.getByRole("button", { name: "Trust", exact: true }).click();
    await expect(bob.getByText(/You and alice are verified/)).toBeVisible(SLOW);
    await bob.getByRole("button", { name: "Close" }).click();
    await open(bob, "docs");
    await expect(bob.locator(".sharing-bar")).toContainText("Shared with alice", SLOW);
    expect((await download(bob, "small.txt")).equals(small)).toBe(true);
  });

  await test.step("alice revokes, and the app re-seals the folder", async () => {
    await sharing(alice, "docs");
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

test("an admin invites, changes, re-enrolls and removes a user", async ({ browser }) => {
  const erin = await (await browser.newContext()).newPage();
  const dave = await (await browser.newContext()).newPage();
  const problems = [erin, dave].map(watch);
  /// dave's row in erin's Users screen.
  const row = () => erin.getByRole("row").filter({ hasText: "dave" });
  let link;

  /// Enrolls dave in `page` from invitation link `link`.
  async function enrolFrom(page, link) {
    await page.goto("about:blank");
    await page.goto(link);
    expect(new URL(page.url()).hash).toBe("");
    await page.getByLabel("New password").fill(PASSWORD);
    await page.getByLabel("Again").fill(PASSWORD);
    await page.getByRole("button", { name: "Enroll" }).click();
    await expect(page.getByText("Enrolled dave")).toBeVisible(SLOW);
    await page.getByRole("button", { name: "Continue to log in" }).click();
  }

  await test.step("erin, an admin, invites dave", async () => {
    await enrol(erin, "erin");
    await login(erin, "erin");
    await accountMenu(erin, "Users");
    await erin.getByRole("button", { name: "Invite someone" }).click();
    // A name that is taken is refused.
    await erin.getByLabel("Their account name").fill("alice");
    await erin.getByRole("button", { name: "Invite", exact: true }).click();
    await expect(erin.getByText("The name alice is taken")).toBeVisible(SLOW);
    await erin.getByLabel("Their account name").fill("dave");
    await erin.getByRole("button", { name: "Invite", exact: true }).click();
    link = await erin.getByLabel("Link to enroll in this app").inputValue();
    expect(link).toMatch(/^http:\/\/localhost:4173\/#invite=raft5fs-invite/);
    await erin.getByRole("button", { name: "Done" }).click();
    await expect(row()).toContainText("invited", SLOW);
  });

  await test.step("dave enrolls, and may do nothing more", async () => {
    await enrolFrom(dave, link);
    await login(dave, "dave");
    await accountButton(dave).click();
    await expect(dave.getByRole("menuitem", { name: "Shared with me" })).toBeVisible();
    await expect(dave.getByRole("menuitem", { name: "Users" })).toHaveCount(0);
    await dave.keyboard.press("Escape");
    await dave.getByText("Add New").click();
    await dave.getByText("Add new folder").click();
    await dave.locator(".wx-modal input").fill("mine");
    await dave.locator(".wx-modal").getByRole("button", { name: "OK" }).click();
    await expect(dave.getByText("You can't create top-level folders here")).toBeVisible();
  });

  await test.step("erin lets dave make folders; she can't drop her own admin", async () => {
    await erin.getByRole("button", { name: "Close" }).click();
    await accountMenu(erin, "Users");
    await expect(row()).not.toContainText("invited", SLOW);
    await row().getByRole("checkbox", { name: /top-level folders: dave/ }).check();
    await expect(row().getByRole("checkbox", { name: /top-level folders: dave/ })).toBeChecked(SLOW);
    const mine = erin.getByRole("row").filter({ hasText: "erin (you)" });
    await expect(mine.getByRole("checkbox", { name: /Manage users.*: erin/ })).toBeDisabled();
    await expect(mine.getByRole("button", { name: /Re-enroll|Remove/ })).toHaveCount(0);
    // dave picks it up at his next login.
    await dave.reload();
    await login(dave, "dave");
    await addFolder(dave, "mine");
  });

  await test.step("dave enrolls again from a new invitation", async () => {
    await row().getByRole("button", { name: "Re-enroll", exact: true }).click();
    await expect(erin.getByText(/enroll again\?/)).toBeVisible();
    // His folder `mine` would be left with nobody to reach it.
    await expect(erin.getByText(/Only dave can reach one folder or file/)).toBeVisible(SLOW);
    await erin.getByRole("button", { name: "Make an invitation" }).click();
    const again = await erin.getByLabel("Link to enroll in this app").inputValue();
    await erin.getByRole("button", { name: "Done" }).click();
    await enrolFrom(dave, again);
    await login(dave, "dave");
    // His new key has none of what the old one had.
    await expect(item(dave, "mine")).toHaveCount(0, SLOW);
  });

  await test.step("erin deletes dave's old folder, which nobody can reach", async () => {
    await erin.getByRole("button", { name: "Orphaned folders" }).click();
    await expect(erin.getByText(/^Top-level folder #/)).toBeVisible(SLOW);
    await erin.getByRole("button", { name: "Delete…" }).click();
    await erin.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(erin.getByText("every folder and file can be reached by someone")).toBeVisible(SLOW);
    await erin.getByRole("button", { name: "Back" }).click();
  });

  await test.step("erin removes dave", async () => {
    await row().getByRole("button", { name: "Remove", exact: true }).click();
    await erin.getByRole("button", { name: "Remove", exact: true }).click();
    await expect(row()).toHaveCount(0, SLOW);
    await dave.reload();
    await dave.getByLabel("User name").fill("dave");
    await dave.getByLabel("Password").fill(PASSWORD);
    await dave.getByRole("button", { name: "Log in" }).click();
    await expect(dave.getByText(/login refused/)).toBeVisible(SLOW);
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
    await sharing(frank, "public", "Share with someone");
    await frank.getByLabel("User", { exact: true }).fill("gina");
    await frank.getByRole("button", { name: "Share", exact: true }).click();
    await frank.getByLabel("gina's safety code").fill(ginaWords);
    await frank.getByRole("button", { name: "Share", exact: true }).click();
    await frank.getByRole("button", { name: "Done" }).click();
    await gina.reload();
    await login(gina, "gina");
    await accountMenu(gina, "Shared with me");
    await gina.getByRole("button", { name: "Trust…" }).click();
    await gina.getByLabel("Their safety code").fill(frankWords);
    await gina.getByRole("button", { name: "Trust", exact: true }).click();
    await gina.getByRole("button", { name: "Close" }).click();
  });

  await test.step("frank makes a public link", async () => {
    await sharing(frank, "public", "Share publicly");
    await frank.getByRole("button", { name: "Make link" }).click();
    link = await frank.getByLabel("Public link").inputValue();
    expect(link).toMatch(/^http:\/\/localhost:4173\/#link=[\w-]+$/);
    await frank.getByRole("button", { name: "Done" }).click();
    await expect.poll(() => sharedMark(frank, "public"), SLOW).toBe("link");
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
    // A whole folder too, as one ZIP.
    const saving = visitor.waitForEvent("download");
    await visitor.getByRole("button", { name: "Download this folder as a ZIP" }).click();
    const zip = await saving;
    expect(zip.suggestedFilename()).toMatch(/\.zip$/);
    const zipPath = join(mkdtempSync(join(tmpdir(), "link-zip-")), "folder.zip");
    await zip.saveAs(zipPath);
    execFileSync("unzip", ["-tq", zipPath]);
    expect(execFileSync("unzip", ["-Z1", zipPath], { encoding: "utf8" })).toContain("note.txt");
    rmSync(dirname(zipPath), { recursive: true });
    expect(await visitor.evaluate(async () => (await indexedDB.databases()).length)).toBe(0);
  });

  await test.step("gina, who can change the folder, copies it, then revokes it", async () => {
    await sharing(gina, "public");
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

/// A new invitation for `user`, who enrolled before: what an administrator
/// gives someone who forgot their password (web_dev's reissue port).
async function reissue(user) {
  const reply = await fetch(`${REISSUE}/reissue/${user}`);
  expect(reply.ok).toBe(true);
  return reply.text();
}

/// Enrolls `user` again with `invitation`, from the page they are logged
/// in on, and gives their new fingerprint's words.
async function enrolAgain(page, user, invitation) {
  await accountMenu(page, "Log out");
  await visit(page, `#invite=${encodeURIComponent(invitation)}`);
  await page.getByLabel("New password").fill(PASSWORD);
  await page.getByLabel("Again").fill(PASSWORD);
  await page.getByRole("button", { name: "Enroll" }).click();
  await expect(page.getByText(`Enrolled ${user}`)).toBeVisible(SLOW);
  const words = (await page.locator(".words").innerText()).trim();
  await page.getByRole("button", { name: "Continue to log in" }).click();
  await login(page, user);
  return words;
}

test("trusted keys follow an account, and a changed key needs its new fingerprint", async ({ browser }) => {
  const hank = await (await browser.newContext()).newPage();
  const iris = await (await browser.newContext()).newPage();
  const problems = [hank, iris].map(watch);
  let hankWords, irisWords;

  async function share(page, folder, user, words) {
    await sharing(page, folder, "Share with someone");
    await page.getByLabel("User", { exact: true }).fill(user);
    await page.getByRole("button", { name: "Share", exact: true }).click();
    if (words) {
      await page.getByLabel(`${user}'s safety code`).fill(words);
      await page.getByRole("button", { name: "Share", exact: true }).click();
    }
    await expect(page.getByText(new RegExp(`Shared with ${user}`))).toBeVisible(SLOW);
    await page.getByRole("button", { name: "Done" }).click();
  }

  await test.step("hank shares with iris, who trusts him", async () => {
    hankWords = await enrol(hank, "hank");
    irisWords = await enrol(iris, "iris");
    await login(hank, "hank");
    await login(iris, "iris");
    await addFolder(hank, "team");
    await share(hank, "team", "iris", irisWords);
    await iris.reload();
    await login(iris, "iris");
    await iris.getByRole("button", { name: "Review" }).click();
    await iris.getByRole("button", { name: "Trust…" }).click();
    await iris.getByLabel("Their safety code").fill(hankWords);
    await iris.getByRole("button", { name: "Trust", exact: true }).click();
    await expect(iris.getByText(/You and hank are verified/)).toBeVisible(SLOW);
    await iris.getByRole("button", { name: "Close" }).click();
  });

  await test.step("hank's other browser already trusts iris", async () => {
    const other = await (await browser.newContext()).newPage();
    problems.push(watch(other));
    await other.goto("/");
    // A browser that never enrolled offers the first filesystem.
    await other.getByLabel("Filesystem").selectOption(localFsId());
    await login(other, "hank");
    await addFolder(other, "notes");
    // No fingerprint asked for: the servers' copy of hank's trusted keys.
    await share(other, "notes", "iris", null);
    await other.close();
  });

  await test.step("iris enrolls again; hank shares only by her new fingerprint", async () => {
    const newIris = await enrolAgain(iris, "iris", await reissue("iris"));
    await hank.reload();
    await login(hank, "hank");
    await sharing(hank, "team", "Share with someone");
    await hank.getByLabel("User", { exact: true }).fill("iris");
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await expect(hank.getByText(/iris's key has changed/)).toBeVisible(SLOW);
    // Her old fingerprint doesn't match her new key.
    await hank.getByLabel("iris's safety code").fill(irisWords);
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await expect(hank.getByText(/don't match the key/)).toBeVisible(SLOW);
    await hank.getByLabel("iris's safety code").fill(newIris);
    await hank.getByRole("button", { name: "Share", exact: true }).click();
    await expect(hank.getByText(/Shared with iris/)).toBeVisible(SLOW);
    await hank.getByRole("button", { name: "Done" }).click();
    irisWords = newIris;
  });

  await test.step("hank enrolls again; iris trusts him only by his new fingerprint", async () => {
    const newHank = await enrolAgain(hank, "hank", await reissue("hank"));
    await addFolder(hank, "fresh");
    // This browser still trusts iris's new key, and tells the servers.
    await share(hank, "fresh", "iris", null);
    await iris.reload();
    await login(iris, "iris");
    await iris.getByRole("button", { name: "Review" }).click();
    await expect(iris.getByText(/hank's key has changed/)).toBeVisible(SLOW);
    await iris.getByRole("button", { name: "Check new safety code…" }).click();
    await iris.getByLabel("Their safety code").fill(hankWords);
    await iris.getByRole("button", { name: "Trust", exact: true }).click();
    await expect(iris.getByText(/don't match the key/)).toBeVisible(SLOW);
    await iris.getByLabel("Their safety code").fill(newHank);
    await iris.getByRole("button", { name: "Trust", exact: true }).click();
    await expect(iris.getByRole("button", { name: "Check new safety code…" })).toHaveCount(0, SLOW);
    await iris.getByRole("button", { name: "Close" }).click();
    await expect(item(iris, "fresh")).toBeVisible(SLOW);
  });

  expect(problems.flat()).toEqual([]);
});

test("storage, size limits, and giving a folder away", async ({ browser }) => {
  const jack = await (await browser.newContext()).newPage();
  const kim = await (await browser.newContext()).newPage();
  const problems = [jack, kim].map(watch);
  let kimWords;

  /// The storage line in `page`'s account menu.
  async function storageLine(page) {
    await accountButton(page).click();
    const line = page.locator(".storage");
    // Opening the menu asks again; give the answer a moment.
    await line.waitFor({ timeout: 2_000 }).catch(() => {});
    await page.waitForTimeout(300);
    const text = (await line.count()) ? await line.innerText() : "";
    await page.keyboard.press("Escape");
    return text;
  }

  await test.step("jack sees what his folders hold", async () => {
    await enrol(jack, "jack");
    kimWords = await enrol(kim, "kim");
    await login(jack, "jack");
    await login(kim, "kim");
    await addFolder(jack, "proj");
    await open(jack, "proj");
    await jack.locator("input[type=file]").setInputFiles([
      { name: "notes.txt", mimeType: "text/plain", buffer: Buffer.alloc(2000, 97) },
    ]);
    await expect(item(jack, "notes.txt")).toBeVisible(SLOW);
    await expect.poll(() => storageLine(jack), SLOW).toBe("2.0 KB used");
  });

  await test.step("a size limit stops what would go over it", async () => {
    await addFolder(jack, "drop");
    await menu(jack, "drop", "Size limit…");
    await jack.getByLabel(/Limit, such as/).fill("1K");
    await jack.getByRole("button", { name: "Set limit" }).click();
    await expect(jack.getByText(/of a 1\.0 KB limit/)).toBeVisible(SLOW);
    await jack.getByRole("button", { name: "Close" }).click();
    await open(jack, "drop");
    await expect(jack.getByText(/Holds 0 bytes of its 1\.0 KB limit/)).toBeVisible(SLOW);
    await jack.locator("input[type=file]").setInputFiles([
      { name: "big.bin", mimeType: "application/octet-stream", buffer: Buffer.alloc(2048, 1) },
    ]);
    await expect(jack.getByText(/reached its size limit/)).toBeVisible(SLOW);
    await jack.getByRole("button", { name: "Dismiss" }).click();
    // Refused before anything was made: no empty file left behind.
    await expect(item(jack, "big.bin")).toHaveCount(0);
  });

  await test.step("jack offers proj to kim, who accepts it", async () => {
    await jack.getByText("My files").first().click();
    await expect(item(jack, "proj")).toBeVisible(SLOW);
    // Only to someone who can change it.
    await menu(jack, "proj", "Transfer ownership…");
    await expect(jack.getByText("Share it with them read-write first", { exact: false })).toBeVisible(SLOW);
    await jack.getByRole("button", { name: "Close" }).click();
    await sharing(jack, "proj", "Share with someone");
    await jack.getByLabel("User", { exact: true }).fill("kim");
    await jack.getByRole("button", { name: "Share", exact: true }).click();
    await jack.getByLabel("kim's safety code").fill(kimWords);
    await jack.getByRole("button", { name: "Share", exact: true }).click();
    await expect(jack.getByText(/Shared with kim/)).toBeVisible(SLOW);
    await jack.getByRole("button", { name: "Done" }).click();
    await menu(jack, "proj", "Transfer ownership…");
    await expect(jack.getByLabel("Give it to")).toHaveValue("kim", SLOW);
    await jack.getByRole("button", { name: "Offer", exact: true }).click();
    await expect(jack.getByText(/Offered to kim/)).toBeVisible(SLOW);
    await jack.getByRole("button", { name: "Close" }).click();

    await kim.reload();
    await login(kim, "kim");
    await expect(kim.getByText(/jack wants to give you proj/)).toBeVisible(SLOW);
    await kim.getByRole("button", { name: "Accept" }).click();
    await expect(kim.getByText(/wants to give you/)).toHaveCount(0, SLOW);
    await expect.poll(() => storageLine(kim), SLOW).toBe("2.0 KB used");

    // jack sees kim as the owner, whose access nobody can take away.
    await sharing(jack, "proj");
    const kimRow = jack.getByRole("row").filter({ hasText: "kim" });
    await expect(kimRow).toContainText("owner", SLOW);
    await expect(kimRow.getByRole("button", { name: "Revoke…" })).toHaveCount(0);
    await jack.getByRole("button", { name: "Close" }).click();
  });

  await test.step("jack, an admin, gets proj back before removing kim", async () => {
    await accountMenu(jack, "Users");
    await jack.getByRole("button", { name: "Measure storage now" }).click();
    const kimRow = jack.getByRole("row").filter({ hasText: "kim" });
    await expect(kimRow).toContainText("2.0 KB", SLOW);
    await kimRow.getByRole("button", { name: "Remove", exact: true }).click();
    await expect(jack.getByText(/kim owns a top-level folder/)).toBeVisible(SLOW);
    await expect(jack.getByLabel("Who gets proj")).toHaveValue("jack");
    await jack.getByRole("button", { name: "Give" }).click();
    await expect(jack.getByText(/kim owns a top-level folder/)).toHaveCount(0, SLOW);
    await jack.getByRole("button", { name: "Remove", exact: true }).click();
    await expect(kimRow).toHaveCount(0, SLOW);
    // Other tests' users enroll again, which orphans their folders; proj
    // isn't among them.
    await jack.getByRole("button", { name: "Orphaned folders" }).click();
    await expect(jack.getByText("Looking…")).toHaveCount(0, SLOW);
    await expect(jack.getByRole("dialog").getByText("proj", { exact: true })).toHaveCount(0);
  });

  expect(problems.flat()).toEqual([]);
});

test("an idle logout waits for playing media, but not for ever", async ({ browser }) => {
  const lena = await (await browser.newContext()).newPage();
  const problems = watch(lena);
  await lena.clock.install();
  const loggedOut = lena.getByText("Logged out after 30 minutes without use.");

  /// Opens the video, playing on a loop.
  async function play() {
    await item(lena, "clip.webm").dblclick();
    const video = lena.getByRole("dialog").locator("video");
    await expect(video).toBeVisible(SLOW);
    await video.evaluate((v) => {
      v.loop = true;
      v.muted = true;
      return v.play();
    });
    await expect.poll(() => video.evaluate((v) => !v.paused && v.readyState >= 2), SLOW).toBe(true);
    return video;
  }

  await test.step("a playing video keeps the tab logged in", async () => {
    await enrol(lena, "lena");
    await login(lena, "lena");
    await addFolder(lena, "films");
    await open(lena, "films");
    await uploadMedia(lena);
    const video = await play();
    await lena.clock.fastForward("31:00");
    await expect(video).toBeVisible();
    await expect(loggedOut).toHaveCount(0);
    await test.step("and once it's paused, an idle tab logs out", async () => {
      await video.evaluate(
        (v) =>
          new Promise((resolve) => {
            v.addEventListener("pause", resolve, { once: true });
            v.pause();
          }),
      );
      await lena.clock.fastForward("31:00");
      await expect(loggedOut).toBeVisible(SLOW);
    });
  });

  await test.step("nothing keeps it logged in past 12 hours", async () => {
    await login(lena, "lena");
    await open(lena, "films");
    const video = await play();
    await lena.clock.fastForward("11:00:00");
    await expect(video).toBeVisible();
    await expect(loggedOut).toHaveCount(0);
    await lena.clock.fastForward("01:01:00");
    await expect(loggedOut).toBeVisible(SLOW);
  });

  expect(problems).toEqual([]);
});

test("new shares and files show up without a reload", async ({ browser }) => {
  const mona = await (await browser.newContext()).newPage();
  const nils = await (await browser.newContext()).newPage();
  const problems = [mona, nils].map(watch);
  /// What the browser does when someone comes back to the tab.
  const comeBack = (page) => page.evaluate(() => window.dispatchEvent(new Event("focus")));

  const monaWords = await enrol(mona, "mona");
  const nilsWords = await enrol(nils, "nils");
  await login(mona, "mona");
  await login(nils, "nils");
  await addFolder(mona, "gift");
  await sharing(mona, "gift", "Share with someone");
  // A mistyped name says so at once, and can be put right.
  await mona.getByLabel("User", { exact: true }).fill("nilz");
  await mona.getByRole("button", { name: "Share", exact: true }).click();
  await expect(mona.getByText("There's nobody called nilz here")).toBeVisible(SLOW);
  await mona.getByLabel("User", { exact: true }).fill("nils");
  await mona.getByRole("button", { name: "Share", exact: true }).click();
  await mona.getByRole("button", { name: "Change" }).click();
  await expect(mona.getByLabel("User", { exact: true })).toBeEnabled();
  await mona.getByRole("button", { name: "Share", exact: true }).click();
  // A word that isn't one of the code's words says so, and can't go further.
  await mona.getByLabel("nils's safety code").fill("notaword ");
  await expect(mona.getByText(/isn't one of the words/)).toBeVisible();
  await expect(mona.getByRole("button", { name: "Share", exact: true })).toBeDisabled();
  await mona.getByLabel("nils's safety code").fill(nilsWords);
  // While the two are in touch, mona has her own code to hand, and an Esc
  // doesn't lose what she typed.
  await expect(mona.getByRole("dialog").locator(".words")).toHaveText(monaWords);
  await mona.keyboard.press("Escape");
  await expect(mona.getByLabel("nils's safety code")).toHaveValue(nilsWords);
  await mona.getByRole("button", { name: "Share", exact: true }).click();
  await expect(mona.getByText(/Shared with nils/)).toBeVisible(SLOW);
  // What nils needs next is mona's code, not his own.
  await expect(mona.getByText(/nils now needs your safety code/)).toBeVisible();
  await expect(mona.getByRole("dialog").locator(".words")).toHaveText(monaWords);
  await mona.getByRole("button", { name: "Done" }).click();

  // nils is already logged in, and hasn't reloaded.
  await comeBack(nils);
  await expect(nils.getByRole("button", { name: "Review" })).toBeVisible(SLOW);
  await expect(item(nils, "gift")).toBeVisible(SLOW);

  // "Shared with me" lists it, says what it allows, and stays useful after.
  await nils.getByRole("button", { name: "Review" }).click();
  await expect(nils.getByText(/You can already open it/)).toBeVisible(SLOW);
  await nils.getByRole("button", { name: "Trust…" }).click();
  await expect(nils.getByRole("dialog").locator(".words")).toHaveText(nilsWords);
  await nils.getByLabel("Their safety code").fill(monaWords);
  await nils.getByRole("button", { name: "Trust", exact: true }).click();
  await expect(nils.getByText(/You and mona are verified. gift is in My files/)).toBeVisible(SLOW);
  await expect(nils.getByText(/You can add, change and delete files here/)).toBeVisible();
  await nils.getByRole("button", { name: "Close" }).click();

  // People lists who has been checked, and shows their code on request.
  await accountMenu(nils, "People");
  await expect(nils.getByRole("dialog").getByText("mona", { exact: true })).toBeVisible(SLOW);
  await nils.getByRole("button", { name: "Show code" }).click();
  await expect(nils.getByRole("dialog").locator(".words")).toHaveText(monaWords);
  // Forgetting makes her shares read-only again, and checking her again undoes it.
  await nils.getByRole("button", { name: "Forget…" }).click();
  await nils.getByRole("button", { name: "Forget", exact: true }).click();
  await expect(nils.getByText("You haven't checked anyone yet.")).toBeVisible(SLOW);
  await nils.getByRole("button", { name: "Check someone's safety code" }).click();
  await nils.getByLabel("Their account name").fill("mona");
  await nils.getByLabel("Their safety code").fill(monaWords);
  await nils.getByRole("button", { name: "Check", exact: true }).click();
  await expect(nils.getByRole("dialog").getByText("mona", { exact: true })).toBeVisible(SLOW);
  await nils.getByRole("button", { name: "Close" }).click();

  // A file added while nils has the folder open appears there too, and the
  // folder stays open.
  await open(nils, "gift");
  await open(mona, "gift");
  await mona.locator("input[type=file]").setInputFiles([
    { name: "card.txt", mimeType: "text/plain", buffer: Buffer.from("hello") },
  ]);
  await expect(item(mona, "card.txt")).toBeVisible(SLOW);
  await comeBack(nils);
  await expect(item(nils, "card.txt")).toBeVisible(SLOW);
  expect(new URL(nils.url()).hash).toBe("#/gift");

  expect(problems.flat()).toEqual([]);
});

test("a device that saw newer keys says so, and a person can reset it", async ({ page }) => {
  const problems = watch(page);
  await enrol(page, "olga");
  await login(page, "olga");
  await addFolder(page, "kept");

  // Stands in for a rollback, or a restore: this browser remembers more than
  // the servers now have.
  const remember = (names) =>
    page.evaluate(
      ({ names }) =>
        new Promise((resolve, reject) => {
          const opening = indexedDB.open("raft5fs");
          opening.onerror = () => reject(opening.error);
          opening.onsuccess = () => {
            const transaction = opening.result.transaction("blobs", "readwrite");
            const blobs = transaction.objectStore("blobs");
            const keys = blobs.getAllKeys();
            keys.onsuccess = () => {
              const encode = (text) => new TextEncoder().encode(text).buffer;
              const mine = keys.result.filter((key) => key.includes("/olga/"));
              const pins = mine.find((key) => key.includes(".sync."));
              if (!pins) return reject(new Error(`no merge remembered: ${mine}`));
              blobs.put(encode(names.pins), pins);
              const versions = pins.slice(0, pins.indexOf(".sync.")) + ".versions";
              blobs.put(encode(names.versions), versions);
            };
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(transaction.error);
          };
        }),
      { names },
    );
  const inodes = Array.from({ length: 5000 }, (_, ino) => `${ino} 99\n`).join("");
  await expect(async () => remember({ pins: "counter 999\n", versions: inodes })).toPass(SLOW);

  await page.reload();
  await login(page, "olga");
  await open(page, "kept");
  const message = /older than[^]*restored from a backup/;
  await expect(page.getByText(message).first()).toBeVisible(SLOW);
  await expect(page.getByText("raft5fs reset-versions")).toHaveCount(0);

  // The sealed list is older too, and People is where that shows.
  await accountMenu(page, "People");
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText(/trusted keys is change \d+, older than change 999/)).toBeVisible(SLOW);

  await dialog.getByRole("button", { name: "It was restored: reset this device" }).click();
  await login(page, "olga");
  await expect(item(page, "kept")).toBeVisible(SLOW);
  await open(page, "kept");
  await accountMenu(page, "People");
  await expect(page.getByRole("dialog").getByText("You haven't checked anyone yet.")).toBeVisible(SLOW);
  await expect(page.getByRole("dialog").getByText(/older than/)).toHaveCount(0);

  expect(problems).toEqual([]);
});

test("a folder uploads with its folders, and downloads as a ZIP", async ({ page }) => {
  const problems = watch(page);
  await enrol(page, "pia");
  await login(page, "pia");
  await addFolder(page, "trip");
  await open(page, "trip");

  const local = mkdtempSync(join(tmpdir(), "folder-upload-"));
  mkdirSync(join(local, "photos/day one"), { recursive: true });
  writeFileSync(join(local, "photos/notes.txt"), "first notes");
  writeFileSync(join(local, "photos/day one/a.txt"), "aaa");
  writeFileSync(join(local, "photos/day one/b.txt"), "bbb");

  const upload = async () => {
    const chooser = page.waitForEvent("filechooser");
    await page.getByText("Add New").click();
    await page.getByText("Upload folder").click();
    await (await chooser).setFiles(join(local, "photos"));
  };
  await upload();
  await expect(page.getByText("Uploaded 3 files.")).toBeVisible(SLOW);
  await open(page, "photos");
  await expect(item(page, "notes.txt")).toBeVisible(SLOW);
  await open(page, "day one");
  await expect(item(page, "b.txt")).toBeVisible(SLOW);

  // Again, into the same place: one question, for all of them.
  const backToTrip = async () => {
    await page.getByText("My files").first().click();
    await open(page, "trip");
    await expect(item(page, "photos")).toBeVisible(SLOW);
  };
  await backToTrip();
  writeFileSync(join(local, "photos/notes.txt"), "second notes");
  await upload();
  await page.getByRole("button", { name: "Skip existing" }).click();
  await expect(page.getByText("Uploaded 0 files, skipped 3 that already exist.")).toBeVisible(SLOW);
  await upload();
  await page.getByRole("button", { name: "Replace all" }).click();
  await expect(page.getByText("Uploaded 3 files.")).toBeVisible(SLOW);
  await upload();
  await page.getByRole("button", { name: "Cancel upload" }).click();
  await expect(page.getByText("then stopped, as you asked")).toBeVisible(SLOW);

  // A dropped folder keeps its shape, however many it holds. The reader gives
  // batches of 100, as Chromium's does, and the empty folder stays.
  await page.evaluate(() => {
    const file = (name) => ({
      isFile: true,
      name,
      file: (done) => done(new File([name], name)),
    });
    const dir = (name, entries) => ({
      isDirectory: true,
      name,
      createReader() {
        let at = 0;
        return {
          readEntries(done) {
            done(entries.slice(at, at + 100));
            at += 100;
          },
        };
      },
    });
    const many = Array.from({ length: 150 }, (_, n) => file(`f${n}.txt`));
    const dropped = dir("dropped", [dir("inner", many), dir("hollow", [])]);
    const drop = new DragEvent("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(drop, "dataTransfer", {
      value: { items: [{ kind: "file", webkitGetAsEntry: () => dropped }] },
      configurable: true,
    });
    document.querySelector(".wx-upload-area").dispatchEvent(drop);
  });
  await expect(page.getByText("Uploaded 150 files.")).toBeVisible({ timeout: 90_000 });
  await open(page, "dropped");
  await expect(item(page, "hollow")).toBeVisible(SLOW);
  await expect(item(page, "inner")).toBeVisible(SLOW);
  await backToTrip();

  // The folder's menu gives a ZIP of everything in it, an empty folder too.
  const saved = page.waitForEvent("download");
  await menu(page, "dropped", "Download as ZIP");
  const download = await saved;
  expect(download.suggestedFilename()).toBe("dropped.zip");
  const zip = join(local, "dropped.zip");
  await download.saveAs(zip);
  execFileSync("unzip", ["-tq", zip]);
  const names = execFileSync("unzip", ["-Z1", zip], { encoding: "utf8" }).trim().split("\n");
  expect(names).toHaveLength(153);
  expect(names).toContain("dropped/hollow/");
  expect(execFileSync("unzip", ["-p", zip, "dropped/inner/f149.txt"], { encoding: "utf8" })).toBe("f149.txt");

  // Several selected go in one, with the replaced file's new contents.
  await item(page, "photos").click();
  await item(page, "dropped").click({ modifiers: ["Control"] });
  const savedBoth = page.waitForEvent("download");
  await menu(page, "dropped", "Download as ZIP");
  const both = await savedBoth;
  expect(both.suggestedFilename()).toBe("trip.zip");
  const trip = join(local, "trip.zip");
  await both.saveAs(trip);
  expect(execFileSync("unzip", ["-p", trip, "photos/notes.txt"], { encoding: "utf8" })).toBe("second notes");
  expect(execFileSync("unzip", ["-p", trip, "photos/day one/a.txt"], { encoding: "utf8" })).toBe("aaa");
  expect(execFileSync("unzip", ["-p", trip, "dropped/inner/f7.txt"], { encoding: "utf8" })).toBe("f7.txt");

  // A new folder that wouldn't fit is refused before anything stays.
  await addFolder(page, "tiny");
  await menu(page, "tiny", "Size limit…");
  await page.getByLabel(/Limit, such as/).fill("1K");
  await page.getByRole("button", { name: "Set limit" }).click();
  await expect(page.getByText(/of a 1\.0 KB limit/)).toBeVisible(SLOW);
  await page.getByRole("button", { name: "Close" }).click();
  await open(page, "tiny");
  mkdirSync(join(local, "large"));
  writeFileSync(join(local, "large/big.bin"), Buffer.alloc(4096, 1));
  const tooBig = page.waitForEvent("filechooser");
  await page.getByText("Add New").click();
  await page.getByText("Upload folder").click();
  await (await tooBig).setFiles(join(local, "large"));
  await expect(page.getByText(/reached its size limit/)).toBeVisible(SLOW);
  await expect(item(page, "large")).toHaveCount(0);

  rmSync(local, { recursive: true });
  expect(problems).toEqual([]);
});

test("shares group into one folder for each student", async ({ browser }) => {
  const rosa = await (await browser.newContext()).newPage();
  const quinn = await (await browser.newContext()).newPage();
  const problems = [rosa, quinn].map(watch);
  const rosaWords = await enrol(rosa, "rosa");
  const quinnWords = await enrol(quinn, "quinn");
  await login(rosa, "rosa");
  await login(quinn, "quinn");
  const comeBack = (page) => page.evaluate(() => window.dispatchEvent(new Event("focus")));

  // The teacher's class is one folder, and what she shares is inside it.
  await addFolder(rosa, "class");
  await open(rosa, "class");
  await addFolder(rosa, "assignments");
  await addFolder(rosa, "quinn");
  await addFolder(rosa, "someone else");
  await sharing(rosa, "assignments", "Share with someone");
  await rosa.getByLabel("User", { exact: true }).fill("quinn");
  await rosa.getByLabel("What this folder will show up to shared user as").fill("CS101/assignments");
  await rosa.getByRole("button", { name: "Share", exact: true }).click();
  await rosa.getByLabel("quinn's safety code").fill(quinnWords);
  await rosa.getByRole("button", { name: "Share", exact: true }).click();
  await expect(rosa.getByText(/Shared with quinn/)).toBeVisible(SLOW);
  await rosa.getByRole("button", { name: "Done" }).click();
  await sharing(rosa, "quinn", "Share with someone");
  await rosa.getByLabel("User", { exact: true }).fill("quinn");
  await rosa.getByLabel("What this folder will show up to shared user as").fill("CS101/quinn");
  await rosa.getByRole("button", { name: "Share", exact: true }).click();
  await expect(rosa.getByText(/Shared with quinn/)).toBeVisible(SLOW);
  await rosa.getByRole("button", { name: "Done" }).click();

  // Until quinn checks who shared them, they stay out of any group.
  await comeBack(quinn);
  await expect(item(quinn, "CS101-assignments")).toBeVisible(SLOW);
  await expect(item(quinn, "CS101-quinn")).toBeVisible(SLOW);
  await accountMenu(quinn, "People");
  await quinn.getByRole("button", { name: "Check someone's safety code" }).click();
  await quinn.getByLabel("Their account name").fill("rosa");
  await quinn.getByLabel("Their safety code").fill(rosaWords);
  await quinn.getByRole("button", { name: "Check", exact: true }).click();
  await expect(quinn.getByRole("dialog").getByText("rosa", { exact: true })).toBeVisible(SLOW);
  await quinn.getByRole("button", { name: "Close" }).click();
  await comeBack(quinn);

  // Then one folder, with those two, and nothing of the rest of the class.
  await expect(item(quinn, "CS101")).toBeVisible(SLOW);
  await expect(item(quinn, "CS101-quinn")).toHaveCount(0);
  await open(quinn, "CS101");
  await expect(item(quinn, "assignments")).toBeVisible(SLOW);
  await expect(item(quinn, "quinn")).toBeVisible(SLOW);
  await expect(item(quinn, "someone else")).toHaveCount(0);
  await expect(item(quinn, "class")).toHaveCount(0);

  // Each share works as itself, and its address names the group.
  await open(quinn, "quinn");
  await expect.poll(() => new URL(quinn.url()).hash).toBe("#/CS101/quinn");
  await quinn.locator("input[type=file]").setInputFiles([
    { name: "essay.txt", mimeType: "text/plain", buffer: Buffer.from("my essay") },
  ]);
  await expect(item(quinn, "essay.txt")).toBeVisible(SLOW);

  // The teacher sees it in the real folder, under its real name.
  await open(rosa, "quinn");
  await expect(item(rosa, "essay.txt")).toBeVisible(SLOW);

  // A group is only a place: its menu has no rename or delete, and a folder
  // made in it is a top-level folder of its own.
  await quinn.getByText("My files").first().click();
  await expect(item(quinn, "CS101")).toBeVisible(SLOW);
  await item(quinn, "CS101").click({ button: "right" });
  await expect(quinn.getByText("Download as ZIP", { exact: true }).first()).toBeVisible(SLOW);
  await expect(quinn.getByText("Delete", { exact: true })).toHaveCount(0);
  await expect(quinn.getByText("Rename", { exact: true })).toHaveCount(0);
  await quinn.keyboard.press("Escape");
  await open(quinn, "CS101");
  await addFolder(quinn, "own notes");
  await expect(item(quinn, "own notes")).toBeVisible(SLOW);

  // Someone can show a share their own way. Nobody else is affected.
  await menu(quinn, "assignments", "Show as…");
  await quinn.getByLabel("What this folder shows up to you as").fill("Reading/CS101 work");
  await quinn.getByRole("button", { name: "Save" }).click();
  await expect(item(quinn, "assignments")).toHaveCount(0);
  await quinn.getByText("My files").first().click();
  await expect(item(quinn, "Reading")).toBeVisible(SLOW);
  await open(quinn, "Reading");
  await expect(item(quinn, "CS101 work")).toBeVisible(SLOW);
  await rosa.getByText("My files").first().click();
  await open(rosa, "class");
  await expect(item(rosa, "assignments")).toBeVisible(SLOW);

  // Its ZIP holds what shows in it, under the names that show.
  await quinn.getByText("My files").first().click();
  await expect(item(quinn, "CS101")).toBeVisible(SLOW);
  const saving = quinn.waitForEvent("download");
  await menu(quinn, "CS101", "Download as ZIP");
  const zip = await saving;
  const zipPath = join(mkdtempSync(join(tmpdir(), "group-zip-")), "group.zip");
  await zip.saveAs(zipPath);
  expect(execFileSync("unzip", ["-p", zipPath, "CS101/quinn/essay.txt"], { encoding: "utf8" })).toBe("my essay");
  rmSync(dirname(zipPath), { recursive: true });

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
