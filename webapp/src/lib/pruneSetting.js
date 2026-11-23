// Whether this browser re-seals (prunes) in the background: the account
// menu's "Re-seal on this device". Kept for the browser, not the account.
// By default on for a computer and off for a phone or tablet, where a
// background prune would cost battery and data. Any device that can write
// a folder can finish its prune, so one left off here is done elsewhere.

const KEY = "raft5fs:prune-here";

/// Whether this looks like a phone or tablet: the browser says so, or its
/// only pointer is a finger.
export function mobile() {
  const said = navigator.userAgentData?.mobile;
  if (said != null) return said;
  return matchMedia("(pointer: coarse)").matches && !matchMedia("(any-pointer: fine)").matches;
}

/// The setting: as last chosen here, or the default for this device.
export function pruneHere() {
  try {
    const kept = localStorage.getItem(KEY);
    if (kept === "on" || kept === "off") return kept === "on";
  } catch {}
  return !mobile();
}

export function setPruneHere(on) {
  try {
    localStorage.setItem(KEY, on ? "on" : "off");
  } catch {}
}
