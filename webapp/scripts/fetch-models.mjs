// Fetches the search models into public/models/<name>/, for the build to
// serve from the app's own origin (the page's CSP loads nothing from
// elsewhere), and copies the places table into public/data/.
//
// - What to fetch comes from search/data/models.json, the one place every
//   client's models are pinned: each file the web app uses, at its pinned
//   URL, checked against its SHA-256.
// - A file with a `piece` size is cut into pieces under GitHub Pages' 100
//   MB a file: <local>.0, <local>.1, ...; the embed Worker joins them and
//   checks the whole again.
// - What is there already, and checks out, isn't fetched again.
//
// Not committed (see .gitignore). Usage: npm run model.
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";

const app = new URL("..", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("../search/data/models.json", app)));

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/// The names and sizes of file `f`'s pieces, as the embed Worker reads them.
function pieces(f) {
  if (!f.piece) return [[f.local, f.size]];
  return Array.from({ length: Math.ceil(f.size / f.piece) }, (_, i) => [
    `${f.local}.${i}`,
    Math.min(f.piece, f.size - i * f.piece),
  ]);
}

/// File `f` from its pieces in `dir`, if they are all there at their sizes.
function kept(dir, f) {
  const parts = [];
  for (const [name, size] of pieces(f)) {
    const path = new URL(name, dir);
    if (!existsSync(path)) return null;
    const bytes = readFileSync(path);
    if (bytes.length !== size) return null;
    parts.push(bytes);
  }
  return Buffer.concat(parts);
}

for (const [key, model] of Object.entries(manifest.models)) {
  const dir = new URL(`public/models/${model.name}/`, app);
  mkdirSync(dir, { recursive: true });
  const wanted = new Set();
  for (const f of model.files.filter((f) => f.clients.includes("web"))) {
    for (const [name] of pieces(f)) wanted.add(name);
    const have = kept(dir, f);
    if (have && sha256(have) === f.sha256) continue;
    console.log(`fetching ${key} ${f.local} (${Math.round(f.size / 1e6)} MB)`);
    const response = await fetch(f.url);
    if (!response.ok) throw new Error(`${f.url}: ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length !== f.size || sha256(bytes) !== f.sha256) {
      throw new Error(`${f.url} isn't the file models.json pins`);
    }
    let at = 0;
    for (const [name, size] of pieces(f)) {
      writeFileSync(new URL(name, dir), bytes.subarray(at, at + size));
      at += size;
    }
  }
  // What an earlier version of the manifest cut differently, or used.
  for (const name of readdirSync(dir)) {
    if (!wanted.has(name)) rmSync(new URL(name, dir));
  }
  console.log(`${model.name}: ${[...wanted].join(", ")}`);
}

// The places table that tracks and photos are named with (search/data,
// committed), served beside the models.
mkdirSync(new URL("public/data/", app), { recursive: true });
copyFileSync(new URL("../search/data/places.bin", app), new URL("public/data/places.bin", app));
console.log("public/data/places.bin");
