// Builds the app for the filesystems in its config, which comes from
// config/<mode>.json: config/prod.json for a plain `vite build` (CI writes
// it from the WEB_CONFIG variable; deploy/webapp-config.sh prints it), and
// config/local/config.json for `--mode dev` and the dev server (what
// `cargo run -p raft5fs-testkit --example web_dev` writes). See
// config/example.json:
//
//   filesystems  a list; the login screen offers a choice if there are
//                several, and an invitation picks its own by fsId:
//     name       what the login screen calls it
//     servers    the servers' web ports (https://host:port)
//     objects    the object store's origin, where blocks are fetched
//                from, if the filesystem keeps blocks there
//     fsId       the filesystem's id (its CA's), to check invitations
//     plaintext  plain HTTP, for local development only
//
// A built page gets a Content Security Policy as the first element of
// <head>, before any script: it may load code only from its own origin,
// and connect only to the filesystems' servers and object stores.
import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

function loadConfig(mode) {
  mode = { production: "prod", development: "dev" }[mode] ?? mode;
  const file =
    mode === "dev" ? "config/local/config.json" : `config/${mode}.json`;
  const config = JSON.parse(readFileSync(file, "utf8"));
  const list = config.filesystems;
  if (!Array.isArray(list) || list.length === 0) {
    throw new Error(`${file}: no filesystems`);
  }
  const ids = new Set();
  for (const fs of list) {
    for (const key of ["name", "servers", "fsId"]) {
      if (!fs[key]) throw new Error(`${file}: a filesystem has no ${key}`);
    }
    if (ids.has(fs.fsId)) throw new Error(`${file}: fsId ${fs.fsId} twice`);
    ids.add(fs.fsId);
  }
  return list;
}

function origin(url) {
  return new URL(url).origin;
}

function csp(filesystems) {
  const connect = filesystems.flatMap((fs) => [
    ...fs.servers.map(origin),
    ...(fs.objects ? [origin(fs.objects)] : []),
  ]);
  return [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self'",
    // SVAR sets inline style attributes.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:",
    // Video and audio, streamed (public/sw.js) or whole.
    "media-src 'self' blob:",
    // The browser's own PDF viewer, in the app's viewer.
    "frame-src 'self' blob:",
    "font-src 'self'",
    `connect-src 'self' ${[...new Set(connect)].join(" ")}`,
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
  ].join("; ");
}

export default defineConfig(({ mode, command }) => {
  const filesystems = loadConfig(mode);
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
              `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp(filesystems)}">`,
            ),
        },
      },
    ],
    define: {
      __RAFT5FS_FILESYSTEMS__: JSON.stringify(
        filesystems.map((fs) => ({
          name: fs.name,
          servers: fs.servers,
          fsId: fs.fsId,
          plaintext: !!fs.plaintext,
        })),
      ),
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
