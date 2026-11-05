// The ZIP writer, checked by the tools people will unpack with. No browser.
import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zipStream } from "../src/lib/zip.js";

const encoder = new TextEncoder();
const FILES = {
  "top/a.txt": "hello",
  "top/under/b.bin": "x".repeat(300_000),
  "top/ünï çødé.txt": "names are UTF-8",
};

async function archive(entries, read, errors) {
  const parts = [];
  for await (const part of zipStream(entries, read, errors)) parts.push(part);
  return Buffer.concat(parts);
}

const entry = (name, text) => ({ name, modified: Date.UTC(2024, 5, 1), size: encoder.encode(text).length, text });
async function* pieces(e) {
  const bytes = encoder.encode(e.text);
  for (let at = 0; at < bytes.length; at += 70_000) yield bytes.subarray(at, at + 70_000);
}

/// What Python's zipfile finds in `zip`, which also checks every checksum.
function listed(zip) {
  const script = `
import json, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
assert z.testzip() is None
print(json.dumps({i.filename: z.read(i).decode() for i in z.infolist()}))
`;
  return JSON.parse(execFileSync("python3", ["-I", "-c", script, zip], { encoding: "utf8" }));
}

function inTemp(work) {
  const dir = mkdtempSync(join(tmpdir(), "zip-test-"));
  try {
    return work(join(dir, "out.zip"));
  } finally {
    rmSync(dir, { recursive: true });
  }
}

test("an archive opens in the usual tools", async () => {
  const entries = [
    { name: "top", modified: Date.UTC(2024, 5, 1), dir: true },
    { name: "top/empty", modified: 0, dir: true },
    { name: "top/under", modified: Date.UTC(2024, 5, 1), dir: true },
    ...Object.entries(FILES).map(([name, text]) => entry(name, text)),
  ];
  const zip = await archive(entries, pieces);
  inTemp((path) => {
    writeFileSync(path, zip);
    execFileSync("unzip", ["-tq", path]);
    expect(listed(path)).toEqual({ "top/": "", "top/empty/": "", "top/under/": "", ...FILES });
  });
});

test("a name can't climb out on Windows", async () => {
  const zip = await archive([entry("..\\..\\evil.txt", "x")], pieces);
  inTemp((path) => {
    writeFileSync(path, zip);
    expect(Object.keys(listed(path))).toEqual([".._.._evil.txt"]);
  });
});

test("a file that fails is reported in the archive, and the rest stay", async () => {
  const entries = [entry("good.txt", "fine"), entry("bad.txt", "never read"), entry("short.txt", "cut")];
  entries[2].size = 100;
  const errors = ["gone: the folder couldn't be listed"];
  const zip = await archive(
    entries,
    async function* (e) {
      if (e.name === "bad.txt") {
        yield encoder.encode("par");
        throw new Error("no key");
      }
      yield* pieces(e);
    },
    errors,
  );
  inTemp((path) => {
    writeFileSync(path, zip);
    execFileSync("unzip", ["-tq", path]);
    const found = listed(path);
    expect(found["good.txt"]).toBe("fine");
    expect(found["bad.txt"]).toBe("par");
    expect(found["short.txt"]).toBe("cut");
    expect(found["DOWNLOAD-ERRORS.txt"]).toContain("gone: the folder couldn't be listed");
    expect(found["DOWNLOAD-ERRORS.txt"]).toContain("bad.txt: no key");
    expect(found["DOWNLOAD-ERRORS.txt"]).toContain("short.txt: it got shorter");
  });
});
