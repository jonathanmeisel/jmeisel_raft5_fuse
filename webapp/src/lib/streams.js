// Streams of files through the service worker (public/sw.js): the page's
// side. Each stream is a token for one open file; the service worker asks
// this page about the token, and this page reads the bytes from the Worker,
// which decrypts them.
//
// - Tokens are random and live only here, in this tab's memory. A stream
//   ends when it is closed, at logout, or when the tab goes away.
// - `available` says whether this page is under the service worker. Where
//   it isn't (a first visit before it takes over, a private window, a
//   browser that has them off), callers decrypt the whole file instead.

/// A token: 128 random bits, in hex.
function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function streams(fs) {
  const sw = navigator.serviceWorker;
  /// The open streams, by token.
  const open = new Map();
  let controlled = !!sw?.controller;

  const onController = () => (controlled = !!sw.controller);
  const onMessage = async ({ data, ports: [port] }) => {
    if (!port || !data?.raft5fs) return;
    const s = open.get(data.token);
    if (!s) {
      port.postMessage(null);
    } else if (data.raft5fs === "meta") {
      port.postMessage({ size: s.size, type: s.type, name: s.name, disposition: s.disposition });
    } else if (data.raft5fs === "read") {
      try {
        const bytes = await fs.readFile(s.handle, data.offset, data.len);
        const buffer = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
          ? bytes.buffer
          : bytes.slice().buffer;
        port.postMessage({ bytes: buffer }, [buffer]);
      } catch (e) {
        port.postMessage({ error: e.message });
      }
    }
  };
  sw?.addEventListener("controllerchange", onController);
  sw?.addEventListener("message", onMessage);
  sw?.startMessages();

  function closeAll() {
    for (const token of [...open.keys()]) close(token);
  }

  function close(token) {
    const s = open.get(token);
    if (!s) return;
    open.delete(token);
    fs.closeFile(s.handle).catch(() => {});
  }

  addEventListener("pagehide", closeAll);

  return {
    available: () => controlled,

    /// Opens file `path` as a stream of `type`; a `download` stream tells
    /// the browser to save it. Gives the token and the stream's URL.
    async open(path, type, { download = false } = {}) {
      const name = path.slice(path.lastIndexOf("/") + 1);
      const { size } = await fs.stat(path);
      const handle = await fs.openFile(path);
      const token = newToken();
      open.set(token, {
        handle,
        size,
        type,
        name,
        disposition: download ? "attachment" : "inline",
      });
      return { token, url: `/stream/${token}/${encodeURIComponent(name)}` };
    },

    close,
    closeAll,

    /// Stops answering, at logout.
    end() {
      closeAll();
      sw?.removeEventListener("controllerchange", onController);
      sw?.removeEventListener("message", onMessage);
      removeEventListener("pagehide", closeAll);
    },
  };
}
