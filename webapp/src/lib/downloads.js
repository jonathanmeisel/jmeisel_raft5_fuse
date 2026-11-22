// The two ways the app hands a file to the browser to save.
//
// - `saveStream` is for a stream the service worker serves (see streams.js).
//   It goes through a hidden frame: a navigation reaches the service worker,
//   where an <a download> click wouldn't, and the stream's
//   `Content-Disposition: attachment` makes it a download. The browser then
//   shows the progress, and the bytes go straight to disk.
// - `saveBlob` is for bytes already in memory, where there is no service
//   worker.

/// How long a frame or a blob URL stays, so the browser has taken it over.
const KEEP_MS = 60_000;

/// Saves the stream at `url`.
export function saveStream(url) {
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.src = url;
  document.body.append(frame);
  setTimeout(() => frame.remove(), KEEP_MS);
}

/// Saves `blob` as `filename`.
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), KEEP_MS);
}
