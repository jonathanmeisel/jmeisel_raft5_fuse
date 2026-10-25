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
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

/// Enrols `user` through the page, and gives their fingerprint's words.
async function enrol(page, user) {
  await page.goto("/");
  await page.getByRole("link", { name: "Enroll with an invitation" }).click();
  await page.getByLabel("Invitation").fill(invites()[user]);
  await page.getByLabel("New password").fill(PASSWORD);
  await page.getByLabel("Again").fill(PASSWORD);
  await page.getByRole("button", { name: "Enroll" }).click();
  await expect(page.getByText(`Enrolled ${user}`)).toBeVisible(SLOW);
  const words = (await page.locator(".words").innerText()).trim();
  await page.getByRole("button", { name: "Continue to log in" }).click();
  return words;
}

async function login(page, user, stay = false) {
  // Of the two filesystems, enrolling chose "local" (by the invitation),
  // and the app offers it first from then on.
  await expect(page.getByLabel("Filesystem")).toHaveValue(localFsId());
  await page.getByLabel("User name").fill(user);
  await page.getByLabel("Password").fill(PASSWORD);
  if (stay) await page.getByLabel(/Stay logged in/).check();
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible(SLOW);
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
    await bob.getByRole("button", { name: /Shared with me/ }).click();
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
    await expect(alice.getByRole("button", { name: "Log out" })).toBeVisible(SLOW);
    await expect(item(alice, "docs")).toBeVisible(SLOW);
    // A second tab opens the same account too.
    const second = await alice.context().newPage();
    await second.goto("/");
    await expect(second.getByRole("button", { name: "Log out" })).toBeVisible(SLOW);
    await expect(item(second, "docs")).toBeVisible(SLOW);
    await second.close();
    // Logging out forgets the device.
    await alice.getByRole("button", { name: "Log out" }).click();
    await alice.reload();
    await expect(alice.getByRole("button", { name: "Log in" })).toBeVisible(SLOW);
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
