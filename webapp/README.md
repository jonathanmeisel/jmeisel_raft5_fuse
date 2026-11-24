# raft5fs web app

The filesystem in a browser. The client library is compiled to WebAssembly
(the `raft5fs-web` crate) and runs in a Web Worker, so files are sealed and
opened in the browser and the servers see only what they see from a native
client. The UI is [SVAR File Manager](https://svar.dev/svelte/filemanager/)
(MIT) in Svelte.

## Layout

- `src/lib/worker.js`: the Worker. It holds the session and IndexedDB
  (pins, the prune queue, and a remembered login; the pins are also merged
  with the account's sealed copy on the servers at each login and change,
  so every browser and device trusts the same keys), keeps the account's
  other tabs up to date with its saves, and runs the background prune
  when it holds the account's prune lock (one tab at a time).
- `src/lib/rpc.js`: the page's calls into the Worker.
- `src/lib/route.js`: where the app is, in the URL's fragment (never sent to
  a server): `#/<path>` opens a folder or a file, browsing adds history
  entries, `#invite=<invitation>` opens the enroll screen filled in, and
  `#link=<…>` opens a public link. Logging out clears it.
- `src/lib/previews.js`: thumbnails for images and text files (up to
  20 MB), which the Worker decrypts and draws. Showing a folder fetches
  its images to make them. It also says what the viewer can open, and as
  what type: always from the extension, never the file's contents. SVG is
  never shown, because it can carry scripts.
- `src/lib/sharedIcons.js`: shared folders show SVAR's folder with a
  white person (shared with someone) or chain link (a public link) on it,
  in the card and list views. The Worker learns which folders are shared
  from each volume's grants (one request per volume, kept 30 seconds), so
  only those who can change a volume see its marks; folders shared with
  this account are marked in the top folder. The folder menu in the
  header (`FolderMenu.svelte`) says how the open folder is shared: with
  whom, by public link, and through which folder above it; or, in a folder
  this account only reads, who shared it.
- `src/components/Viewer.svelte`: double-clicking an image, text, a video,
  audio or a PDF opens it here; "Open in new tab" too.
- `public/sw.js` and `src/lib/streams.js`: a service worker that streams
  video, audio, PDFs and downloads a byte range at a time (playback and
  seeking start at once; downloads go straight to disk). It holds no keys:
  it asks the page, whose Worker decrypts. Where service workers aren't
  available (Firefox's private windows, say), files are decrypted whole
  into memory instead, with size limits.
- The right-click menu keeps to what is used most. **History** opens a
  file's versions, or a folder's activity; what was deleted from a folder
  shows in the folder itself, with **Show deleted** in the folder menu. A
  folder's **More** opens a panel with Size limit, and for a top-level
  folder Show as and Transfer ownership. It is a panel, not a submenu,
  because SVAR's submenus open only on hover, which a phone doesn't have.
- `src/components/Versions.svelte`: **History** on a file lists what it
  was in each snapshot (the wasm `versions`, one row for each
  distinct version), and opens, downloads or restores one: as a copy beside
  it, or in place of the file. On a cluster, snapshots are hourly for a day
  and daily for a week (`deploy/README.md`).
- `src/components/Activity.svelte`: a folder's **History** lists who
  created, edited, renamed, moved or deleted what in it, newest first (the
  wasm `activity`). The servers keep it for 7 days. A name opens its
  versions.
- Groups: a share's label can hold a `/`, and `CS101/notes` shows inside a
  `CS101` folder that exists only in that person's view, up to 8 names deep.
  Only a share from someone checked joins a group; until then it shows as
  `CS101-notes`. **More → Show as** (or renaming) in a share's menu changes it for
  yourself. A group's menu only offers the ZIP.
- `src/lib/folders.js` and `src/lib/zip.js`: folders. **Upload folder**, or
  dropping one, keeps its shape. A new folder that wouldn't fit is refused
  before anything stays, and existing files prompt one question for the whole
  folder: skip them, replace them all, or cancel. A folder's menu, several
  selected items, and a button for a public link's visitor give one **ZIP**,
  stored uncompressed and streamed through the service worker, so its size
  isn't limited by memory where streams are available. What can't be read is
  listed in `DOWNLOAD-ERRORS.txt` in the ZIP.
- `src/components/`: the screens and dialogs. `Files.svelte` sends every
  SVAR action to the Worker and then lists the folders again. What the
  account may do (its capabilities) decides what the account menu
  (`AccountMenu.svelte`, the user's name in the header) offers:
  **Users** (`UsersDialog.svelte`: invite, change capabilities and
  quotas, re-enroll, remove (giving the folders they own to someone
  first), measure storage now, and, in one list of orphaned folders,
  give top-level folders without an owner to someone and delete what
  nobody can reach any more) needs `admin`,
  making a
  top-level folder needs `volumes`, and public links (`LinkDialog.svelte`
  from a folder's menu, `LinksDialog.svelte` from the account menu) need
  `links`.
- Storage: the account menu shows what the account's top-level folders
  hold, and its quota. Folders show their size, as last measured, in the
  size column (blank until measured). A folder's **More → Size limit**
  (`LimitDialog.svelte`) shows its size, and lets the owner of its
  top-level folder, or an admin, cap it; the bar above the files says how
  full a capped folder is. A top-level folder's **More → Transfer ownership**
  (`TransferDialog.svelte`) offers it to someone with read-write access,
  who sees a banner to accept or decline it. **Shared with…** names the
  owner, who can't be revoked.
- Safety codes: what the command line calls a fingerprint, in words people can
  read to each other. `Fingerprint.svelte` shows one and `CodeInput.svelte`
  takes one, checking each word as it's typed. A folder's **Sharing**
  (`SharedWith.svelte`) lists who has it and leads to sharing further
  (`ShareDialog.svelte`) and public links. **People** (`People.svelte`) lists
  whose key this account trusts and how: a code read, an invitation, or an
  introduction from someone marked "Trust people … checks" (an introducer).
  An invitation made in the app vouches for both keys: after enrolling, the
  worker logs in once to trust the inviter (`acceptInvitation`), and the
  inviter's next sync checks the new key's proof (`SETUP.txt` 7.3). **Shared with me**
  (`Pending.svelte`) lists what others have shared. The app looks for new
  shares every minute, and when the tab comes back into view.
- Public links: `#link=<…>` logs in as the link's own account, in a
  Worker that stores nothing (no IndexedDB, no prune), and shows its one
  folder read-only. The fragment leaves the address bar at once. Whoever
  can change a folder can show its links again (`LinkField.svelte`, in
  "Shared with…"): their secrets are in the folder's sealed grantee list.
- Search: the box in the header (`Search.svelte`) searches the open
  top-level folder, or with **All** every one, by words and by meaning (the
  wasm `search`; `SETUP.txt` section 15). A result opens the file.
  - The tab that holds the account's index lock (a Web Lock, as for
    re-sealing) indexes in the background, if the account menu's **Index
    for search on this device** is on: by default on a computer, off on a
    phone or tablet (`searchSetting.js`). An upload is indexed a few seconds
    later. A browser indexes words, dates, places and thumbnails only.
    Vectors come from native devices, which add them to records a
    browser wrote at their next pass.
  - `src/lib/embedWorker.js` is a Worker of its own, so indexing never holds
    up the session's calls. It runs the model to embed queries
    (`src/lib/e5.js`, on ONNX Runtime's WebAssembly backend, one thread),
    and reads PDFs with the PDF module (the `raft5fs-pdf-web` crate, a
    separate wasm: a PDF that crashes it only restarts it). It holds no
    keys.
  - The models are served by the app from `public/models/`, which
    `npm run model` (`scripts/fetch-models.mjs`) fetches as
    `search/data/models.json` pins them for every client (about 135 MB for
    text, 140 MB more for photos, checked against their SHA-256s, split
    into pieces under GitHub Pages' 100 MB limit). The embed Worker
    streams the pieces into one buffer, checks the whole, and keeps it in
    the Cache API.
  - A search shows what matches by words at once, then searches by meaning
    too and shows those results when the model is ready, with the
    download's progress the first time. On a phone or tablet, with Data
    Saver, or on a slow connection, it asks before that download
    (`searchSetting.js`): **Download**, **Not now** (until the page
    reloads), or **Never on this device**.
  - IndexedDB's `search` store keeps the index segments this browser has
    read, sealed to the account in the wasm client (raft5fs-crypto's
    `local`), so searching again fetches only what is new, and adds only
    that to the volume's view in memory. Segments a compaction removed
    are dropped from it (`cacheKeep`). **Keep search data on this device**
    off keeps nothing, for a borrowed computer.
  - Tracks and photos are named with the places table (`search/data/`,
    served from `public/data/places.bin`, checked against its pinned
    SHA-256), fetched by the tab that indexes. Photos get thumbnails, drawn
    on an OffscreenCanvas in the embed Worker; results show them.
  - Photos are found by what they show with CLIP (`src/lib/clip.js`, its
    multilingual text side only, served beside the text model): native
    devices give photos their image vectors, and a search of a folder whose
    photos have them embeds the query with it too. The download question
    counts it (about 140 MB more).
  - A top-level folder's **More → Search indexing** (`IndexingDialog.svelte`)
    shows whether it is indexed; its owner can turn that off, which removes
    its index.
- `src/wasm/`: generated by `npm run wasm`; not committed.
- `public/icons/`: SVAR's icon font, copied from `cdn.svar.dev/fonts/wxi/`
  so the page loads nothing from other origins.
- `config/`: which filesystems a build is for (see `vite.config.js` and
  `example.json`). The release's `prod.json` isn't kept here: CI writes it
  from the `WEB_CONFIG` variable, which `deploy/webapp-config.sh` prints
  from the cluster repo. `config/local/` comes from the dev backend.

## Developing

Needs Rust with the `wasm32-unknown-unknown` target, the `wasm-bindgen` CLI
at the version `web/Cargo.toml` pins, and Node.

```sh
npm ci
npm run wasm                       # the client and the PDF module, into src/wasm
npm run model                      # the search models, into public/models
cargo run -p raft5fs-testkit --example web_dev   # in another terminal
npm run dev                        # http://localhost:5173
```

`web_dev` runs a new, empty filesystem on this machine (servers on plain
HTTP, a fake object store) and writes `config/local/config.json` and
`config/local/invites.json`, an invitation for `alice` and `bob`. Enroll
with one in the app. Its users may also invite others and make public
links.

The dev server has no Content Security Policy; builds do. To try a build:
`npx vite build --mode dev && npx vite preview --mode dev`, with `web_dev
--origin http://localhost:4173`.

## Tests

```sh
cargo build -p raft5fs-testkit --example web_dev
cargo build -p raft5fs --no-default-features --features index
npm run wasm
npm run model
npm run test:parity                # the model gives native clients' vectors
npx playwright test
```

`test:parity` runs the app's model code in Node and checks its token ids,
and its vectors to cosine 0.995, against `tests/fixtures/e5-vectors.json`
and `tests/fixtures/clip-vectors.json`, which native clients wrote
(raft5fs-indexer's ignored tests `write_the_web_apps_parity_fixture` and
`write_the_web_apps_clip_fixture`; run them again after changing a
model). In the browser tests, indexing is off in every tab except the
search tests', which upload text, Word and PDF files, find them by their
words, run `raft5fs index` (the CLI, as a desktop would) to add vectors,
find them by meaning in another language, check that what the browser
keeps of the index is sealed, and turn indexing off as the owner.

The tests start their own `web_dev`, build the app for it, and drive it in
headless Chromium: two users enroll, upload and download (one file large
enough for object storage), share with a fingerprint, trust, revoke and
re-seal; one user invites another, who enrolls from the link; a public
link opens its folder in a fresh browser, then stops working once another
writer revokes it. They also check that the page raises no CSP violation and refuses
to run in a frame. `web_dev` issues new invitations for users who enroll
again on its fourth port (`GET /reissue/<user>`), which the tests use. Stop any other `web_dev` first: they use the same ports.
