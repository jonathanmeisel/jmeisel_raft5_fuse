// Starts a new, empty filesystem (`web_dev`), builds the app for it and
// for a second, unreachable one (so the app has a choice to make), and
// serves the build on :4173. Returns the teardown, which stops both.
// Needs the example built: cargo build -p raft5fs-testkit --example web_dev
import { spawn, execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const root = new URL("../..", import.meta.url).pathname;
const app = new URL("..", import.meta.url).pathname;

function waitFor(child, pattern, what) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what} never started`)), 90_000);
    const look = (chunk) => {
      if (pattern.test(chunk.toString())) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout.on("data", look);
    child.stderr.on("data", look);
    child.on("exit", (code) => reject(new Error(`${what} exited with ${code}`)));
  });
}

export default async function () {
  const binary = `${root}target/debug/examples/web_dev`;
  if (!existsSync(binary)) {
    throw new Error("build it first: cargo build -p raft5fs-testkit --example web_dev");
  }
  const users = ["alice", "bob", "carol", "erin", "frank", "gina", "hank", "iris"].flatMap((u) => ["--user", u]);
  const backend = spawn(binary, ["--origin", "http://localhost:4173", "--out", `${app}config/local`, ...users], {
    cwd: root,
  });
  await waitFor(backend, /^ready$/m, "the filesystem");
  const file = `${app}config/local/config.json`;
  const config = JSON.parse(readFileSync(file, "utf8"));
  config.filesystems.unshift({
    name: "elsewhere",
    servers: ["http://127.0.0.1:9"],
    fsId: "ffffffffffffffff",
    plaintext: true,
  });
  writeFileSync(file, JSON.stringify(config, null, 2));
  execFileSync("npx", ["vite", "build", "--mode", "dev", "--logLevel", "error"], { cwd: app, stdio: "inherit" });
  const preview = spawn("npx", ["vite", "preview", "--mode", "dev"], { cwd: app });
  await waitFor(preview, /4173/, "the preview server");
  return async () => {
    preview.kill();
    backend.kill();
  };
}
