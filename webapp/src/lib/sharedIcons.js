// Icons for shared folders, for SVAR's `icons` option: its pink folder,
// with a white mark on it. A person for a folder shared with people, a
// chain link for one with a public link. Images, as SVAR takes them, made
// here as `data:` URLs, so nothing is fetched.

const ACCENT = "#DF2F90";
/// SVAR's folder glyph (Material Design's "folder"), in a 24 by 24 box.
const FOLDER = "M10,4H4C2.89,4 2,4.89 2,6V18A2,2 0 0,0 4,20H20A2,2 0 0,0 22,18V8C22,6.89 21.1,6 20,6H12L10,4Z";

const MARKS = {
  people: `
    <circle cx="12" cy="11.2" r="2.1" fill="#fff"/>
    <path d="M8.2 17a3.8 3.8 0 0 1 7.6 0z" fill="#fff"/>`,
  link: `
    <g transform="rotate(-45 12 13.2)" fill="none" stroke="#fff" stroke-width="1.4">
      <rect x="7.1" y="11.6" width="5.9" height="3.2" rx="1.6"/>
      <rect x="11" y="11.6" width="5.9" height="3.2" rx="1.6"/>
    </g>`,
};

function svg(kind) {
  // A slightly tighter box than the glyph's, so it shows the size of
  // SVAR's own folder icon.
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0.55 0.55 22.9 22.9">
    <path d="${FOLDER}" fill="${ACCENT}"/>
    ${MARKS[kind]}
  </svg>`;
}

const urls = Object.fromEntries(
  Object.keys(MARKS).map((kind) => [kind, `data:image/svg+xml,${encodeURIComponent(svg(kind))}`]),
);

/// The image for a folder shared as `kind` ("people" or "link").
export const markUrl = (kind) => urls[kind];

/// SVAR's `icons(file, size)`: the image for a shared folder, or null for
/// SVAR's own icon.
export function sharedIcon(file) {
  return (file.type === "folder" && urls[file.shared]) || null;
}
