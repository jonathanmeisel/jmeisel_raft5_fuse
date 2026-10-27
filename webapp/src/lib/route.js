// Where the app is, in the URL's fragment, which no server ever sees:
//
// - `#/<path>`: a folder or file, as a path from the root, each name
//   encoded with encodeURIComponent. `#/` is the root.
// - `#invite=<invitation>`: open the enroll screen with this invitation.
// - `#link=<…>`: a public link (part C of the plan; not handled yet).

/// What `hash` (default: the page's) asks for: `{ path }`, `{ invite }`,
/// `{ link }`, or null.
export function readRoute(hash = location.hash) {
  if (hash.startsWith("#/")) {
    const names = hash.slice(2).split("/").filter(Boolean);
    try {
      return { path: "/" + names.map(decodeURIComponent).join("/") };
    } catch {
      return null;
    }
  }
  const action = /^#(invite|link)=(.+)$/.exec(hash);
  if (!action) return null;
  try {
    return { [action[1]]: decodeURIComponent(action[2]) };
  } catch {
    return null;
  }
}

/// The fragment for `path`.
export function pathHash(path) {
  return "#/" + path.split("/").filter(Boolean).map(encodeURIComponent).join("/");
}

/// Removes the fragment from the address bar, without a new history entry.
export function clearRoute() {
  if (location.hash) history.replaceState(history.state, "", location.pathname + location.search);
}
