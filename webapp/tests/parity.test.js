// The web app's model gives the vectors native clients give: the same
// token ids, and vectors within cosine 0.995 of those in
// fixtures/e5-vectors.json (written by raft5fs-indexer's ignored test
// `write_the_web_apps_parity_fixture`). Native ONNX Runtime's int8 kernels
// and its WebAssembly ones round a little differently (0.9998 or more for a
// passage, 0.9988 for a short query): far less than the 0.07 between a
// match and a miss (raft5fs-search's MIN_SIMILARITY). A wrong tokenizer or
// pooling gives much less. Runs in Node, on the files that
// scripts/fetch-model.sh puts in public/models: npm run test:parity.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import * as ort from "onnxruntime-web/wasm";
import { MODEL, loadE5 } from "../src/lib/e5.js";
import { CLIP_MODEL, loadClip } from "../src/lib/clip.js";

const fixture = JSON.parse(readFileSync(new URL("fixtures/e5-vectors.json", import.meta.url)));
const dir = new URL(`../public/models/${MODEL}/`, import.meta.url);

test("the browser's model matches the native one", async () => {
  assert.equal(fixture.model, MODEL, "the fixture is for another model");
  const parts = readdirSync(dir)
    .filter((n) => n.startsWith("model.onnx."))
    .sort();
  const onnx = Buffer.concat(parts.map((p) => readFileSync(new URL(p, dir))));
  const json = (name) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));
  ort.env.wasm.numThreads = 1;
  const e5 = await loadE5(ort, new Uint8Array(onnx), json("tokenizer.json"), json("tokenizer_config.json"));
  for (const c of fixture.cases) {
    assert.deepEqual(e5.ids(c.text), c.ids, `token ids of ${c.text}`);
    const v = await e5.embed(c.text);
    const cos = c.vector.reduce((sum, x, i) => sum + x * v[i], 0);
    console.log(`${cos.toFixed(5)}  ${c.text}`);
    assert.ok(cos > 0.995, `${c.text}: cosine ${cos}`);
  }
});

test("the browser's photo model gives queries native clients' vectors", async () => {
  const clipFixture = JSON.parse(readFileSync(new URL("fixtures/clip-vectors.json", import.meta.url)));
  assert.equal(clipFixture.model, CLIP_MODEL, "the fixture is for another model");
  const at = new URL(`../public/models/${CLIP_MODEL}/`, import.meta.url);
  const parts = readdirSync(at)
    .filter((n) => n.startsWith("text.onnx."))
    .sort();
  const onnx = Buffer.concat(parts.map((p) => readFileSync(new URL(p, at))));
  const json = (name) => JSON.parse(readFileSync(new URL(name, at), "utf8"));
  const dense = new Uint8Array(readFileSync(new URL("dense.safetensors", at)));
  const clip = await loadClip(ort, new Uint8Array(onnx), json("tokenizer.json"), json("tokenizer_config.json"), dense);
  for (const c of clipFixture.cases) {
    assert.deepEqual(clip.ids(c.text), c.ids, `token ids of ${c.text}`);
    const v = await clip.embed(c.text);
    const cos = c.vector.reduce((sum, x, i) => sum + x * v[i], 0);
    console.log(`${cos.toFixed(5)}  ${c.text}`);
    assert.ok(cos > 0.995, `${c.text}: cosine ${cos}`);
  }
});
