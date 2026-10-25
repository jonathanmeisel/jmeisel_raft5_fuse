// End-to-end tests of the built app, in headless Chromium, against a
// filesystem on this machine (see tests/global-setup.js).
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests",
  globalSetup: "./tests/global-setup.js",
  timeout: 120_000,
  workers: 1,
  use: {
    baseURL: "http://localhost:4173",
    acceptDownloads: true,
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
