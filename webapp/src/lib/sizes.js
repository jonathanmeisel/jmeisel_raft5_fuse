// Sizes as people read and type them, in powers of 1024 as the servers'
// tools count them.

const UNITS = ["KB", "MB", "GB", "TB"];

/// `bytes` as "4.2 GB", "512 KB" or "800 bytes".
export function sizeText(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${UNITS[unit]}`;
}

/// A size as typed: a number of bytes, or a number with K, M, G or T
/// (with or without a B), such as "10G" or "1.5 GB". Null if blank. Throws
/// if it isn't a size.
export function parseSize(text) {
  const typed = text.trim();
  if (!typed) return null;
  const match = /^(\d+(?:\.\d+)?)\s*([kmgt]?)b?$/i.exec(typed);
  if (!match) throw new Error(`${typed} isn't a size: write one such as 500M or 10G`);
  const power = " kmgt".indexOf(match[2].toLowerCase() || " ");
  return Math.round(Number(match[1]) * 1024 ** power);
}
