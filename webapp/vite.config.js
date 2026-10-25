// Builds the app for one filesystem. The config comes from
// config/<mode>.json, or config/local/config.json for `--mode dev` and the
// dev server (what `cargo run -p raft5fs-testkit --example web_dev`
// writes):
//
//   servers    the servers' web ports (https://host:port)
//   objects    the object store's origin, where blocks are fetched from
//   fsId       the filesystem's id (its CA's), to check invitations
//   plaintext  plain HTTP, for local development only
//
// A built page gets a Content Security Policy as the first element of
// <head>, before any script: it may load code only from its own origin,
// and connect only to the servers and the object store.
import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

function loadConfig(mode) {
  const file =
    mode === "dev" ? "config/local/config.json" : `config/${mode}.json`;
  const config = JSON.parse(readFileSync(file, "utf8"));
  for (const key of ["servers", "objects", "fsId"]) {
    if (!config[key]) throw new Error(`${file}: no ${key}`);
  }
  return config;
}

function origin(url) {
  return new URL(url).origin;
}

function csp(config) {
  const connect = [...config.servers.map(origin), origin(config.objects)];
  return [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self'",
    // SVAR sets inline style attributes.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "media-src blob:",
    "font-src 'self'",
    `connect-src 'self' ${[...new Set(connect)].join(" ")}`,
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
  ].join("; ");
}

export default defineConfig(({ mode, command }) => {
  const config = loadConfig(mode === "development" ? "dev" : mode);
  return {
    plugins: [
      svelte(),
      {
        name: "raft5fs-csp",
        apply: "build",
        transformIndexHtml: {
          order: "pre",
          handler: (html) =>
            html.replace(
              "<head>",
              `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp(config)}">`,
            ),
        },
      },
    ],
    define: {
      __RAFT5FS_CONFIG__: JSON.stringify({
        servers: config.servers,
        fsId: config.fsId,
        plaintext: !!config.plaintext,
      }),
    },
    worker: { format: "es" },
    build: {
      target: "es2022",
      // No inline data: URLs for scripts or workers; the CSP refuses them.
      assetsInlineLimit: 0,
    },
    server: command === "serve" ? { port: 5173, strictPort: true } : undefined,
    preview: { port: 4173, strictPort: true },
  };
});
