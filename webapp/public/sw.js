// The app's service worker: it streams files to the browser (video, audio,
// PDFs, downloads) a byte range at a time, so playback starts at once,
// seeking fetches only what it needs, and downloads go straight to disk.
//
// - It answers only GET /stream/<token>/<name>. Every other request goes to
//   the network untouched.
// - It holds no keys and no state. The app's page owns each token (see
//   src/lib/streams.js); this asks that page for the file's size and type,
//   then for its bytes, which the page's Worker decrypts.
// - A file's type comes from the page, which takes it from the extension
//   alone, and is sent with nosniff, so a stream can never be a page.
// - It takes over at once when updated, which is safe because it keeps
//   nothing.

/// How much one read asks for: one chunk, so the Worker's chunk cache
/// serves a sequential reader.
const PIECE = 1 << 20;
/// How long a page has to say whether a token is its own. Pages that aren't
/// the app (a PDF in a frame) never answer.
const ASK_MS = 3000;
/// How long one read can take: a read can wait for a server to fail over.
const READ_MS = 120000;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (
    event.request.method !== "GET" ||
    url.origin !== self.location.origin ||
    !url.pathname.startsWith("/stream/")
  ) {
    return;
  }
  event.respondWith(stream(event, url.pathname.split("/")[2] ?? ""));
});

/// Sends `message` to `client` and gives its answer, or null after `ms`.
function ask(client, message, ms) {
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => resolve(null), ms);
    channel.port1.onmessage = ({ data }) => {
      clearTimeout(timer);
      resolve(data);
    };
    client.postMessage({ raft5fs: message.kind, ...message }, [channel.port2]);
  });
}

/// The page that owns `token`, and what it says of the file: the page that
/// made the request, or for a new tab or a download, whichever of the app's
/// windows knows it.
async function owner(event, token) {
  const clients = await self.clients.matchAll({ type: "window" });
  const own = event.clientId && (await self.clients.get(event.clientId));
  const candidates = own ? [own, ...clients.filter((c) => c.id !== own.id)] : clients;
  const answers = candidates.map(async (client) => {
    const meta = await ask(client, { kind: "meta", token }, ASK_MS);
    if (!meta) throw new Error("not this one");
    return { client, meta };
  });
  try {
    return await Promise.any(answers);
  } catch {
    return null;
  }
}

/// The byte range a request asks for, as [first, last], or null for a
/// range outside the file.
function range(header, size) {
  if (!header) return [0, size - 1];
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!match || (match[1] === "" && match[2] === "")) return null;
  let first, last;
  if (match[1] === "") {
    first = Math.max(0, size - Number(match[2]));
    last = size - 1;
  } else {
    first = Number(match[1]);
    last = match[2] === "" ? size - 1 : Math.min(Number(match[2]), size - 1);
  }
  return first <= last && first < size ? [first, last] : null;
}

async function stream(event, token) {
  const found = await owner(event, token);
  if (!found) return new Response("This stream has ended.", { status: 404 });
  const { client, meta } = found;
  const header = event.request.headers.get("range");
  const wanted = meta.size === 0 ? [0, -1] : range(header, meta.size);
  if (!wanted) {
    return new Response(null, {
      status: 416,
      headers: { "Content-Range": `bytes */${meta.size}` },
    });
  }
  const [first, last] = wanted;
  let at = first;
  const body = new ReadableStream({
    async pull(controller) {
      if (at > last) {
        controller.close();
        return;
      }
      const len = Math.min(PIECE, last + 1 - at);
      const reply = await ask(client, { kind: "read", token, offset: at, len }, READ_MS);
      if (!reply?.bytes || reply.bytes.byteLength === 0) {
        controller.error(new Error(reply?.error ?? "the file couldn't be read"));
        return;
      }
      controller.enqueue(new Uint8Array(reply.bytes));
      at += reply.bytes.byteLength;
    },
  });
  const headers = {
    "Content-Type": meta.type,
    "Content-Length": String(last + 1 - first),
    "Accept-Ranges": "bytes",
    "Content-Disposition": `${meta.disposition}; filename*=UTF-8''${encodeURIComponent(meta.name)}`,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  if (header) headers["Content-Range"] = `bytes ${first}-${last}/${meta.size}`;
  return new Response(body, { status: header ? 206 : 200, headers });
}
