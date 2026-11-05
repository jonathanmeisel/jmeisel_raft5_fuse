// A ZIP archive, written as a stream, so a folder of any size goes straight to
// disk (see streams.js).
//
// - Files are stored, not compressed: most large files are photos and video,
//   which are compressed already, and this needs no third-party code.
// - A file's checksum is only known after it, so it follows the file, in a data
//   descriptor. Archive tools read the sizes from the directory at the end.
// - ZIP64 records appear only where a value doesn't fit in 32 bits, so that
//   ordinary archives open in every tool.

const LOCAL = 0x04034b50;
const DESCRIPTOR = 0x08074b50;
const CENTRAL = 0x02014b50;
const END = 0x06054b50;
const END64 = 0x06064b50;
const LOCATOR64 = 0x07064b50;
const LIMIT32 = 0xffffffff;
const LIMIT16 = 0xffff;
/// Names are UTF-8, and a file's sizes follow it.
const FLAGS_DIR = 0x0800;
const FLAGS_FILE = 0x0808;

const TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});

function crc32(crc, bytes) {
  let c = ~crc;
  for (let i = 0; i < bytes.length; i++) c = TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

/// Little-endian fields, as [width in bytes, value].
function record(fields) {
  const out = new Uint8Array(fields.reduce((n, [width]) => n + width, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const [width, value] of fields) {
    if (width === 2) view.setUint16(at, value, true);
    else if (width === 4) view.setUint32(at, value, true);
    else view.setBigUint64(at, BigInt(value), true);
    at += width;
  }
  return out;
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/// `ms` as a ZIP's local time and date, which can't say before 1980.
function dosTime(ms) {
  const d = new Date(Math.max(ms || 0, new Date(1980, 0, 1).getTime()));
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

/// A name that an unpacking tool can't take for a path elsewhere. The vault
/// already leaves out `/` and `..`, but Windows tools also split on `\`.
export const safeName = (name) => name.replaceAll("\\", "_");

/// Yields the bytes of an archive of `entries`, each `{name, modified, dir}`,
/// with `size` for a file: its folders first in its name, `/` between them.
/// `name` has no leading `/`, and a folder's has no trailing one.
///
/// - `read(entry)` is an async iterable of a file's bytes. It yields no more
///   than `size`.
/// - A file that fails part way stays cut short in the archive, and its name
///   and why go in `errors`, a list of strings the caller can add to first.
/// - If `errors` isn't empty after the last entry, the list goes in the
///   archive as `DOWNLOAD-ERRORS.txt`.
export async function* zipStream(entries, read, errors = []) {
  const encoder = new TextEncoder();
  const directory = [];
  let offset = 0;

  function* header(name, modified, flags, zip64) {
    const { time, date } = dosTime(modified);
    const bytes = encoder.encode(name);
    const extra = zip64 ? record([[2, 1], [2, 16], [8, 0], [8, 0]]) : new Uint8Array();
    const sized = zip64 ? LIMIT32 : 0;
    const head = record([
      [4, LOCAL], [2, zip64 ? 45 : 20], [2, flags], [2, 0], [2, time], [2, date],
      [4, 0], [4, sized], [4, sized], [2, bytes.length], [2, extra.length],
    ]);
    const all = concat([head, bytes, extra]);
    offset += all.length;
    yield all;
    return { bytes, time, date };
  }

  for (const entry of entries) {
    const start = offset;
    if (entry.dir) {
      const name = `${safeName(entry.name)}/`;
      const made = yield* header(name, entry.modified, FLAGS_DIR, false);
      directory.push({ ...made, flags: FLAGS_DIR, dir: true, crc: 0, size: 0, start });
      continue;
    }
    // Past 4 GiB too, though the file itself is small: unzip reads a file as
    // ZIP64 if its directory row is, and then expects the longer descriptor.
    const zip64 = entry.size > LIMIT32 || start > LIMIT32;
    const made = yield* header(safeName(entry.name), entry.modified, FLAGS_FILE, zip64);
    let crc = 0;
    let size = 0;
    try {
      for await (const piece of read(entry)) {
        crc = crc32(crc, piece);
        size += piece.length;
        offset += piece.length;
        yield piece;
      }
      if (size < entry.size) errors.push(`${entry.name}: it got shorter while being read`);
    } catch (e) {
      errors.push(`${entry.name}: ${e.message}`);
    }
    const sizes = zip64 ? [[8, size], [8, size]] : [[4, size], [4, size]];
    const descriptor = record([[4, DESCRIPTOR], [4, crc], ...sizes]);
    offset += descriptor.length;
    yield descriptor;
    directory.push({ ...made, flags: FLAGS_FILE, dir: false, crc, size, start, zip64 });
  }

  if (errors.length) {
    const body = encoder.encode(`These couldn't be read:\n\n${errors.join("\n")}\n`);
    const start = offset;
    const made = yield* header("DOWNLOAD-ERRORS.txt", Date.now(), FLAGS_FILE, false);
    const crc = crc32(0, body);
    const tail = record([[4, DESCRIPTOR], [4, crc], [4, body.length], [4, body.length]]);
    offset += body.length + tail.length;
    yield concat([body, tail]);
    directory.push({ ...made, flags: FLAGS_FILE, dir: false, crc, size: body.length, start });
  }

  const directoryStart = offset;
  for (const e of directory) {
    const big = [];
    if (e.size > LIMIT32) big.push([8, e.size], [8, e.size]);
    if (e.start > LIMIT32) big.push([8, e.start]);
    const extra = big.length
      ? record([[2, 1], [2, big.reduce((n, [w]) => n + w, 0)], ...big])
      : new Uint8Array();
    const size = e.size > LIMIT32 ? LIMIT32 : e.size;
    // Unix attributes, so that unpacking gives ordinary permissions.
    const mode = e.dir ? (0o40755 * 0x10000 + 0x10) : 0o100644 * 0x10000;
    const version = big.length || e.zip64 ? 45 : 20;
    const row = concat([
      record([
        [4, CENTRAL], [2, (3 << 8) | version], [2, version], [2, e.flags], [2, 0], [2, e.time],
        [2, e.date], [4, e.crc], [4, size], [4, size], [2, e.bytes.length], [2, extra.length],
        [2, 0], [2, 0], [2, 0], [4, mode], [4, Math.min(e.start, LIMIT32)],
      ]),
      e.bytes,
      extra,
    ]);
    offset += row.length;
    yield row;
  }

  const directorySize = offset - directoryStart;
  const count = directory.length;
  const needs64 = count >= LIMIT16 || directorySize >= LIMIT32 || directoryStart >= LIMIT32;
  const tail = [];
  if (needs64) {
    tail.push(
      record([
        [4, END64], [8, 44], [2, 45], [2, 45], [4, 0], [4, 0],
        [8, count], [8, count], [8, directorySize], [8, directoryStart],
      ]),
      record([[4, LOCATOR64], [4, 0], [8, offset], [4, 1]]),
    );
  }
  tail.push(
    record([
      [4, END], [2, 0], [2, 0], [2, Math.min(count, LIMIT16)], [2, Math.min(count, LIMIT16)],
      [4, Math.min(directorySize, LIMIT32)], [4, Math.min(directoryStart, LIMIT32)], [2, 0],
    ]),
  );
  yield concat(tail);
}
