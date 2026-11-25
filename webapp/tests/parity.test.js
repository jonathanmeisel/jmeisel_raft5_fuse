// The web app's models give the vectors native clients give: the same token
// ids, and vectors within cosine 0.999 of those in fixtures/text-vectors.json
// and fixtures/clip-vectors.json (written by raft5fs-indexer's ignored tests
// `write_the_web_apps_parity_fixture` and `write_the_web_apps_clip_fixture`,
// with the browser's Q8_0 weights). Both run raft5fs-embed: only the
// summation order of WebAssembly's SIMD and the CPU's differs. A wrong
// tokenizer, table read or pooling gives far less. Runs in Node, on the
// files that scripts/fetch-models.mjs puts in public/models, with the
// module that scripts/build-wasm.sh builds: npm run test:parity.
import { test } from "node:test";
import assert from "node:assert/strict";
import { closeSync, openSync, readFileSync, readSync } from "node:fs";
import { initSync, Model } from "../src/wasm/raft5fs_embed_web.js";

const manifest = JSON.parse(readFileSync(new URL("../../search/data/models.json", import.meta.url)));
initSync({ module: readFileSync(new URL("../src/wasm/raft5fs_embed_web_bg.wasm", import.meta.url)) });

/// Model `key` as the embed Worker loads it, reading its table's rows from
/// the served pieces.
function load(key) {
  const m = manifest.models[key];
  const dir = new URL(`../public/models/${m.name}/`, import.meta.url);
  const role = (r) => m.files.find((f) => f.role === r);
  const whole = (f) => {
    if (!f.piece) return [{ path: new URL(f.local, dir), start: 0, size: f.size }];
    return Array.from({ length: Math.ceil(f.size / f.piece) }, (_, i) => ({
      path: new URL(`${f.local}.${i}`, dir),
      start: i * f.piece,
      size: Math.min(f.piece, f.size - i * f.piece),
    }));
  };
  const read = (parts, start, length) => {
    const out = new Uint8Array(length);
    for (const p of parts) {
      const from = Math.max(start, p.start);
      const to = Math.min(start + length, p.start + p.size);
      if (from >= to) continue;
      const fd = openSync(p.path, "r");
      readSync(fd, out, from - start, to - from, from - p.start);
      closeSync(fd);
    }
    return out;
  };
  const body = whole(role("body"));
  const model = new Model(
    read(body, 0, role("body").size),
    read(whole(role("tokenizer")), 0, role("tokenizer").size),
    m.pooling,
    m.maxTokens,
  );
  const table = whole(role("table"));
  const size = model.rowBytes();
  return {
    model,
    embed(text) {
      const ids = model.rowIds(text);
      const rows = new Uint8Array(ids.length * size);
      ids.forEach((id, i) => rows.set(read(table, id * size, size), i * size));
      return model.embed(text, ids, rows);
    },
  };
}

function check(key, fixtureFile) {
  const fixture = JSON.parse(readFileSync(new URL(`fixtures/${fixtureFile}`, import.meta.url)));
  assert.equal(fixture.model, manifest.models[key].name, "the fixture is for another model");
  const m = load(key);
  for (const c of fixture.cases) {
    assert.deepEqual(Array.from(m.model.ids(c.text)), c.ids, `token ids of ${c.text}`);
    const v = m.embed(c.text);
    const cos = c.vector.reduce((sum, x, i) => sum + x * v[i], 0);
    console.log(`${cos.toFixed(6)}  ${c.text}`);
    assert.ok(cos > 0.999, `${c.text}: cosine ${cos}`);
  }
}

test("the browser's text model gives native clients' vectors", () => check("text", "text-vectors.json"));

test("the browser's photo model gives queries native clients' vectors", () => check("clip", "clip-vectors.json"));
