//! Builds each volume's search index, in the background or all at once.
//! Any device of any user who can write a volume can do it, as with prunes
//! (see `pruner`).
//!
//! - **Claims.** An indexer claims a volume on the servers before it
//!   works on it, and renews the claim as it goes, so two devices do not
//!   index one volume at once. A claim someone else holds is left alone.
//! - **The index** is files in the volume's `INDEX_DIR`, sealed like any
//!   other file there (raft5fs-search's `segment` and `manifest`). Each
//!   device writes only its own files.
//! - **A pass** follows the volume's activity log from the newest cursor in
//!   any manifest, and indexes what changed. Once a day, or when the log
//!   can't say what changed (a folder moved), it walks the whole volume
//!   instead.
//! - **Meaning.** With an `Embed`, each chunk gets a vector from its model,
//!   and the record names the model. A record from another model, or from
//!   none, counts as out of date: the next pass that sees it embeds it
//!   again.
//! - **Resumable.** A pass stores what it has every `SEGMENT_ENTRIES`
//!   files. A pass cut short is finished by whoever claims the volume
//!   next: files already indexed as they are now are skipped.
//!
//! Gaps in the activity log, and how a pass covers them:
//!
//! - An edit is noted at most once each ten minutes for each user and
//!   file. So a pass checks again, until `RECHECK_MS` after a noted edit,
//!   whether the file changed.
//! - The log is best effort and kept only some days. The daily walk finds
//!   what it missed.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

// `std::time::Instant` panics in a browser; this is the same type natively.
use web_time::Instant;

use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{Activity, ActivityOp, Attr, FsError, Kind};
use raft5fs_proto::{clock, errno};
use raft5fs_search::INDEX_DIR;
use raft5fs_search::extract::{self, Extracted, Format};
use raft5fs_search::manifest::{IndexerId, Manifest, decode_manifest, encode_manifest};
use raft5fs_search::record::{Chunk, DocKind, Entry, Extra, Record, Stamp, Thumb};
use raft5fs_search::segment::{decode_segment, encode_segment};
use raft5fs_search::text;
use raft5fs_search::vector::quantize;
use raft5fs_search::view;
use raft5fs_search::view::MIN_MEANING_WORDS;
use tokio::sync::Notify;

use crate::rt::{self, AbortHandle, BoxFuture};
pub use crate::rt::{MaybeSend, MaybeSync};
use crate::vault::Vault;

/// How far back of the cursor a pass reads the log again: servers' clocks
/// differ a little, and seeing a change twice costs nothing.
pub const OVERLAP_MS: u64 = 2 * 60 * 1000;
/// How long after a noted edit a pass checks the file again.
pub const RECHECK_MS: u64 = 15 * 60 * 1000;
/// How often a pass walks the whole volume.
pub const FULL_WALK_EVERY_MS: u64 = 24 * 60 * 60 * 1000;
/// How many entries go in one segment before a pass stores it.
const SEGMENT_ENTRIES: usize = 200;
/// How much of a file is read in one request.
const READ_PIECE: u64 = 4 << 20;
/// How many log entries one page asks for.
const LOG_PAGE: u32 = 200;

/// How fast an indexer works, and what it leaves alone.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// How often a background indexer looks for volumes to index.
    pub poll: Duration,
    /// The wait after each file indexed, so the device's own work can go
    /// on.
    pub pace: Duration,
    /// The first wait before a volume whose pass failed is tried again. It
    /// doubles each time, up to `max_backoff`.
    pub backoff: Duration,
    pub max_backoff: Duration,
    /// How often a claim is renewed while a pass runs.
    pub renew: Duration,
    /// What this device is called in the status search shows.
    pub device: String,
    /// Volumes this device does not index (others still may), as this
    /// account's root shows them, such as `photos` or `CS101/notes`.
    pub skip: Vec<String>,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(60),
            pace: Duration::from_millis(20),
            backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
            renew: Duration::from_secs(180),
            device: String::new(),
            skip: Vec::new(),
        }
    }
}

/// Reads the text of files. Each client brings its own, for the formats
/// raft5fs-search can't read alone (PDF).
pub trait Extract: MaybeSend + MaybeSync {
    /// The most bytes of file `name` worth reading, or 0 if this can't read
    /// its text. A bigger file is indexed by its name only.
    fn reads(&self, name: &str) -> u64;

    /// The text of file `name`, or `None` if it has none this can read.
    fn extract<'a>(&'a self, name: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Option<Extracted>>;
}

/// Turns text into vectors whose dot product says how close two texts are
/// in meaning. Each client brings its own model runner; all must give the
/// same vectors for the same `model`.
pub trait Embed: MaybeSend + MaybeSync {
    /// The model's name and version, as records keep it.
    fn model(&self) -> &str;

    /// Whether this model supersedes `older`, a model a record names, so
    /// that the record is embedded again with this one. A model it doesn't
    /// know may be newer, from a device updated first: it is left alone,
    /// so devices on two versions don't undo each other's work.
    fn replaces(&self, older: &str) -> bool {
        let _ = older;
        false
    }

    /// One unit vector for each of `texts`, which are pieces of files.
    fn passages<'a>(&'a self, texts: Vec<String>) -> BoxFuture<'a, Result<Vec<Vec<f32>>, String>>;

    /// One unit vector for a query, to compare with passages.
    fn query<'a>(&'a self, text: &'a str) -> BoxFuture<'a, Result<Vec<f32>, String>>;
}

/// Turns photos, and queries, into vectors in one space, so that a query's
/// vector is near the photos that show what it says (CLIP).
pub trait ImageEmbed: MaybeSend + MaybeSync {
    /// The model's name and version, as records keep it.
    fn model(&self) -> &str;

    /// As `Embed::replaces`, for photos' image vectors.
    fn replaces(&self, older: &str) -> bool {
        let _ = older;
        false
    }

    /// A photo's unit vector, from its file's bytes; `Ok(None)` for a
    /// picture this can't decode.
    fn image<'a>(&'a self, bytes: Vec<u8>) -> BoxFuture<'a, Result<Option<Vec<f32>>, String>>;

    /// A query's unit vector, to compare with photos'.
    fn query<'a>(&'a self, text: &'a str) -> BoxFuture<'a, Result<Vec<f32>, String>>;
}

/// How many chunks go to the model at once.
const EMBED_BATCH: usize = 16;

/// What an indexer reads files and embeds text and photos with.
#[derive(Clone)]
pub struct Tools {
    pub extract: Arc<dyn Extract>,
    /// `None` to index words only.
    pub embed: Option<Arc<dyn Embed>>,
    /// `None` to leave photos' image vectors to another device.
    pub image: Option<Arc<dyn ImageEmbed>>,
}

impl Tools {
    /// The formats raft5fs-search reads, and no vectors.
    pub fn words_only() -> Self {
        Self {
            extract: Arc::new(BuiltIn),
            embed: None,
            image: None,
        }
    }

    /// The model records from this indexer name: empty for none.
    pub fn model(&self) -> &str {
        self.embed.as_deref().map_or("", |e| e.model())
    }
}

/// The formats raft5fs-search reads by itself.
pub struct BuiltIn;

/// The most bytes read of a plain text file, and of any other.
const PLAIN_MAX: u64 = 16 << 20;
const OTHER_MAX: u64 = 64 << 20;

impl Extract for BuiltIn {
    fn reads(&self, name: &str) -> u64 {
        match Format::of(name) {
            Format::Other | Format::Pdf => 0,
            Format::Plain | Format::Html => PLAIN_MAX,
            _ => OTHER_MAX,
        }
    }

    fn extract<'a>(&'a self, name: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Option<Extracted>> {
        Box::pin(async move { extract::extract(name, &bytes) })
    }
}

/// A new random id for an indexer, as for a pruner's claims.
pub fn new_id() -> IndexerId {
    crate::pruner::new_holder()
}

/// What one pass did.
#[derive(Debug, Clone, Default)]
pub struct PassStats {
    /// Whether it walked the whole volume.
    pub full: bool,
    pub indexed: usize,
    /// Files whose path changed and nothing else.
    pub moved: usize,
    pub gone: usize,
    /// Files it could not read, and why. They are tried again next pass.
    pub failed: Vec<(String, String)>,
    /// When the volume next needs a pass even with no new changes (ms):
    /// soon while files edited lately are checked again, else at the next
    /// walk.
    pub due_ms: u64,
}

/// One line about a pass, for people.
pub fn describe(stats: &PassStats) -> String {
    let mut line = format!(
        "{} files indexed, {} moved, {} removed{}",
        stats.indexed,
        stats.moved,
        stats.gone,
        if stats.full { " (whole volume)" } else { "" }
    );
    if let Some((path, e)) = stats.failed.first() {
        line.push_str(&format!(
            "; {} could not be read ({path}: {e})",
            stats.failed.len()
        ));
    }
    line
}

/// Whether a pass may follow the log or must walk the whole volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassKind {
    /// Follow the log, unless a walk is due.
    Auto,
    Full,
}

/// Where a volume's index is, and whose files are in it.
struct Loaded {
    dir: u64,
    manifests: Vec<Manifest>,
    /// The newest entry for each inode, from every indexer.
    entries: HashMap<u64, Entry>,
}

/// How many times `load` lists the index again when a file in it goes
/// while it reads: an indexer replaces its manifest by a rename.
const LOAD_TRIES: usize = 5;

/// The index of `volume` as its files are now. Makes `INDEX_DIR` if there
/// is none and `create` says so; otherwise `None` for no index.
async fn load(vault: &Vault, volume: u64, create: bool) -> Result<Option<Loaded>, FsError> {
    load_with(vault, volume, create, None).await
}

/// `load`, with segments taken from `cache` where it has them, and put
/// there when they are read.
async fn load_with(
    vault: &Vault,
    volume: u64,
    create: bool,
    cache: Option<&dyn SegmentCache>,
) -> Result<Option<Loaded>, FsError> {
    let mut tries = 0;
    loop {
        match load_once(vault, volume, create, cache).await {
            Err(e) if e.errno == errno::ENOENT && tries + 1 < LOAD_TRIES => tries += 1,
            other => return other,
        }
    }
}

async fn load_once(
    vault: &Vault,
    volume: u64,
    create: bool,
    cache: Option<&dyn SegmentCache>,
) -> Result<Option<Loaded>, FsError> {
    let dir = match vault.lookup(volume, OsStr::new(INDEX_DIR)).await {
        Ok(attr) => attr.ino,
        Err(e) if e.errno == errno::ENOENT && create => {
            match vault.mkdir(volume, OsStr::new(INDEX_DIR), 0o700).await {
                Ok(attr) => attr.ino,
                // Made by someone else since the lookup.
                Err(e) if e.errno == errno::EEXIST => {
                    vault.lookup(volume, OsStr::new(INDEX_DIR)).await?.ino
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) if e.errno == errno::ENOENT => return Ok(None),
        Err(e) => return Err(e),
    };
    let files: HashMap<String, u64> = vault
        .children(dir)
        .await?
        .into_iter()
        .filter(|i| i.kind == Kind::File)
        .map(|i| {
            (
                String::from_utf8_lossy(os_bytes::bytes(&i.name)).into_owned(),
                i.ino,
            )
        })
        .collect();
    let mut manifests = Vec::new();
    for (name, &ino) in &files {
        if !name.starts_with("manifest-") || name.ends_with(".new") {
            continue;
        }
        match decode_manifest(&read_all(vault, ino).await?) {
            Ok(m) => manifests.push(m),
            Err(e) => eprintln!("search index: skipped {name}: {e}"),
        }
    }
    let mut all = Vec::new();
    for m in &manifests {
        for seg in &m.segments {
            let Some(&ino) = files.get(seg) else {
                eprintln!("search index: {seg} is missing");
                continue;
            };
            // A segment never changes once a manifest lists it, so a copy
            // kept under its name and inode is the segment.
            let key = format!("{volume}/{ino}/{seg}");
            let kept = match cache {
                Some(c) => c.get(&key).await,
                None => None,
            };
            let bytes = match kept {
                Some(bytes) => bytes,
                None => {
                    let bytes = read_all(vault, ino).await?;
                    if let Some(c) = cache {
                        c.put(&key, &bytes).await;
                    }
                    bytes
                }
            };
            match decode_segment(&bytes) {
                Ok(entries) => all.extend(entries),
                Err(e) => eprintln!("search index: skipped {seg}: {e}"),
            }
        }
    }
    Ok(Some(Loaded {
        dir,
        manifests,
        entries: view::latest(all),
    }))
}

/// Every entry in `volume`'s index, for searching it. `None` if it has
/// none.
pub async fn read_index(vault: &Vault, volume: u64) -> Result<Option<IndexSnapshot>, FsError> {
    read_index_cached(vault, volume, None).await
}

/// `read_index`, reading only the segments that `cache` doesn't have.
pub async fn read_index_cached(
    vault: &Vault,
    volume: u64,
    cache: Option<&dyn SegmentCache>,
) -> Result<Option<IndexSnapshot>, FsError> {
    Ok(load_with(vault, volume, false, cache)
        .await?
        .map(|l| IndexSnapshot {
            progress: view::progress(&l.manifests),
            entries: l.entries.into_values().collect(),
        }))
}

/// The bytes of `thumb`, a thumbnail in `volume`'s index.
pub async fn read_thumb(vault: &Vault, volume: u64, thumb: &Thumb) -> Result<Vec<u8>, FsError> {
    let dir = vault.lookup(volume, OsStr::new(INDEX_DIR)).await?.ino;
    let file = vault.lookup(dir, OsStr::new(&thumb.file)).await?.ino;
    vault.read(file, thumb.offset, thumb.len as usize).await
}

/// Where a device keeps the segments it has read, so that reading an index
/// again fetches only new ones. Keys name a segment, its volume and its
/// inode. What it keeps is the account's data: seal it
/// (raft5fs-crypto's `local`).
pub trait SegmentCache: MaybeSend + MaybeSync {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Option<Vec<u8>>>;
    fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> BoxFuture<'a, ()>;
}

/// A volume's index as read: its entries, and how far indexing got.
pub struct IndexSnapshot {
    pub progress: view::Progress,
    pub entries: Vec<Entry>,
}

async fn read_all(vault: &Vault, ino: u64) -> Result<Vec<u8>, FsError> {
    let size = vault.remote().getattr(ino).await?.size;
    let mut out = Vec::with_capacity(size as usize);
    while (out.len() as u64) < size {
        let want = (size - out.len() as u64).min(READ_PIECE) as usize;
        let piece = vault.read(ino, out.len() as u64, want).await?;
        if piece.is_empty() {
            break;
        }
        out.extend_from_slice(&piece);
    }
    Ok(out)
}

/// Makes file `name` in `dir` with `bytes` in it.
async fn write_new(vault: &Vault, dir: u64, name: &str, bytes: &[u8]) -> Result<(), FsError> {
    let ino = vault.create(dir, OsStr::new(name), 0o600).await?.ino;
    vault.write(ino, 0, bytes).await.map_err(|e| e.error)?;
    Ok(())
}

/// Puts `bytes` in file `name` in `dir` in one step: written beside it,
/// then renamed over it, so a reader sees the old file or the new one.
async fn replace(vault: &Vault, dir: u64, name: &str, bytes: &[u8]) -> Result<(), FsError> {
    let temp = format!("{name}.new");
    match vault.unlink(dir, OsStr::new(&temp)).await {
        Ok(_) => {}
        Err(e) if e.errno == errno::ENOENT => {}
        Err(e) => return Err(e),
    }
    write_new(vault, dir, &temp, bytes).await?;
    vault
        .rename(dir, OsStr::new(&temp), dir, OsStr::new(name), false)
        .await?;
    Ok(())
}

fn stamp_of(attr: &Attr) -> Stamp {
    let mtime = attr.mtime.duration_since(UNIX_EPOCH).unwrap_or_default();
    Stamp {
        mtime_ns: mtime.as_nanos() as u64,
        size: attr.size,
    }
}

fn name_text(name: &OsStr) -> String {
    String::from_utf8_lossy(os_bytes::bytes(name)).into_owned()
}

/// One pass over one volume, under a claim.
struct Pass<'a> {
    vault: &'a Vault,
    volume: u64,
    tools: &'a Tools,
    config: &'a IndexerConfig,
    dir: u64,
    mine: Manifest,
    entries: HashMap<u64, Entry>,
    /// The inode of each live record's path, to drop a file replaced by
    /// another at the same path.
    by_path: HashMap<String, u64>,
    pending: Vec<Entry>,
    /// The thumbnails of `pending`'s records, one after another.
    pending_thumbs: Vec<u8>,
    /// Folder listings, by inode: names of what is in each.
    listings: HashMap<u64, Vec<(String, u64, Kind)>>,
    stats: PassStats,
    progress: &'a mut (dyn FnMut(&PassStats) + Send),
    told: Instant,
}

impl Pass<'_> {
    fn tell(&mut self) {
        if self.told.elapsed() >= Duration::from_secs(1) {
            self.told = Instant::now();
            (self.progress)(&self.stats);
        }
    }

    async fn listing(&mut self, dir: u64) -> Result<&[(String, u64, Kind)], FsError> {
        if !self.listings.contains_key(&dir) {
            let items = self
                .vault
                .children(dir)
                .await?
                .into_iter()
                .map(|i| (name_text(&i.name), i.ino, i.kind))
                .collect();
            self.listings.insert(dir, items);
        }
        Ok(&self.listings[&dir])
    }

    /// The path of `ino` in folder `parent`, with `folders` the folders
    /// from the volume down to `parent`, not counting the volume. `None` if
    /// a name is not there any more: it moved again, and a later log entry
    /// or the daily walk says where.
    async fn path_of(
        &mut self,
        folders: &[u64],
        parent: u64,
        ino: u64,
    ) -> Result<Option<String>, FsError> {
        let mut names = Vec::new();
        let mut at = self.volume;
        for &next in folders.iter().chain(std::iter::once(&ino)) {
            let found = self
                .listing(at)
                .await?
                .iter()
                .find(|(_, i, _)| *i == next)
                .map(|(n, ..)| n.clone());
            let Some(name) = found else {
                return Ok(None);
            };
            names.push(name);
            at = next;
        }
        if folders.last().copied().unwrap_or(self.volume) != parent {
            return Ok(None);
        }
        Ok(Some(names.join("/")))
    }

    async fn push(&mut self, entry: Entry) -> Result<(), FsError> {
        match &entry {
            Entry::Record(r) => {
                self.by_path.insert(r.path.clone(), r.ino);
            }
            Entry::Gone { ino, .. } => {
                if let Some(Entry::Record(old)) = self.entries.get(ino) {
                    let old_path = old.path.clone();
                    if self.by_path.get(&old_path) == Some(ino) {
                        self.by_path.remove(&old_path);
                    }
                }
            }
        }
        self.entries.insert(entry.ino(), entry.clone());
        self.pending.push(entry);
        if self.pending.len() >= SEGMENT_ENTRIES {
            self.store().await?;
        }
        Ok(())
    }

    /// Stores what is pending as a new segment, and the manifest that
    /// lists it.
    async fn store(&mut self) -> Result<(), FsError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let n = self.mine.next_segment;
        if !self.pending_thumbs.is_empty() {
            let thumbs = Manifest::thumbs_name(&self.mine.id, n);
            write_new(self.vault, self.dir, &thumbs, &self.pending_thumbs).await?;
            self.pending_thumbs.clear();
        }
        let name = Manifest::segment_name(&self.mine.id, n);
        write_new(self.vault, self.dir, &name, &encode_segment(&self.pending)).await?;
        self.pending.clear();
        self.mine.segments.push(name);
        self.mine.next_segment += 1;
        self.mine.updated_ms = clock::now_millis();
        self.save_manifest().await
    }

    async fn save_manifest(&mut self) -> Result<(), FsError> {
        let name = Manifest::file_name(&self.mine.id);
        replace(self.vault, self.dir, &name, &encode_manifest(&self.mine)).await
    }

    async fn gone(&mut self, ino: u64) -> Result<(), FsError> {
        if matches!(self.entries.get(&ino), Some(Entry::Record(_))) {
            self.stats.gone += 1;
            let at_ms = clock::now_millis();
            self.push(Entry::Gone { ino, at_ms }).await?;
        }
        Ok(())
    }

    /// Whether `old` is as this indexer would leave it: vectors from its
    /// model, from a model it doesn't supersede (`Embed::replaces`), or
    /// none for an indexer with none. A record with no chunk long enough to
    /// embed has nothing to embed, but one another device couldn't read
    /// (`Unread`) is read here if it can be, and so is one that older
    /// readers read (`extract::READER`).
    fn embedded_as_now(&self, old: &Record) -> bool {
        let name = old.path.rsplit('/').next().unwrap_or(&old.path);
        if old.kind == DocKind::Unread && self.tools.extract.reads(name) >= old.stamp.size {
            return false;
        }
        // A photo with no image vector (another device left it for one that
        // has the model), or one from a model this one supersedes.
        if let Some(image) = &self.tools.image
            && old.kind == DocKind::Photo
            && match &old.extra.image {
                None => true,
                Some((m, _)) => m != image.model() && image.replaces(m),
            }
        {
            return false;
        }
        // Read by older readers, which found less in it than these would.
        if old.extra.reader < extract::READER
            && !matches!(Format::of(name), Format::Other)
            && self.tools.extract.reads(name) > 0
        {
            return false;
        }
        let Some(embed) = &self.tools.embed else {
            return true;
        };
        // Text with no vectors yet (a failed model, or a device with none),
        // or vectors from a model this one supersedes.
        !old.chunks.iter().any(|c| c.len >= MIN_MEANING_WORDS)
            || old.model == embed.model()
            || !(old.model.is_empty() || embed.replaces(&old.model))
    }

    /// `pieces` as chunks, each with its vector if this indexer embeds, and
    /// the model that made them. If the model fails, the chunks keep no
    /// vectors and name no model, so a later pass tries again.
    async fn embed(&mut self, pieces: Vec<(Chunk, String)>, path: &str) -> (Vec<Chunk>, String) {
        let Some(embed) = self.tools.embed.clone() else {
            return (pieces.into_iter().map(|(c, _)| c).collect(), String::new());
        };
        let (mut chunks, texts): (Vec<Chunk>, Vec<String>) = pieces.into_iter().unzip();
        // Only chunks long enough to match by meaning are worth the model's
        // time (`MIN_MEANING_WORDS`): a photo's few words aren't.
        let worth: Vec<usize> = (0..chunks.len())
            .filter(|&i| chunks[i].len >= MIN_MEANING_WORDS)
            .collect();
        let texts: Vec<String> = worth.iter().map(|&i| texts[i].clone()).collect();
        let mut vectors = Vec::with_capacity(texts.len());
        for batch in texts.chunks(EMBED_BATCH) {
            match embed.passages(batch.to_vec()).await {
                Ok(v) if v.len() == batch.len() => vectors.extend(v),
                Ok(v) => {
                    let why = format!("the model gave {} vectors for {}", v.len(), batch.len());
                    self.stats.failed.push((path.to_string(), why));
                    return (chunks, String::new());
                }
                Err(e) => {
                    self.stats.failed.push((path.to_string(), e));
                    return (chunks, String::new());
                }
            }
        }
        for (&i, v) in worth.iter().zip(&vectors) {
            chunks[i].vector = Some(quantize(v));
        }
        (chunks, embed.model().to_string())
    }

    /// Indexes file `ino` at `path`, unless the index has it as it is now.
    async fn upsert(&mut self, ino: u64, attr: &Attr, path: String) -> Result<(), FsError> {
        let stamp = stamp_of(attr);
        let at_ms = clock::now_millis();
        // Another file that was at this path was replaced by this one (as
        // editors save): it is gone.
        if let Some(&other) = self.by_path.get(&path)
            && other != ino
        {
            self.gone(other).await?;
        }
        if let Some(Entry::Record(old)) = self.entries.get(&ino)
            && old.stamp == stamp
            && self.embedded_as_now(old)
        {
            if old.path != path {
                let mut moved = old.clone();
                moved.path = path;
                moved.at_ms = at_ms;
                self.stats.moved += 1;
                self.push(Entry::Record(moved)).await?;
            }
            return Ok(());
        }
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        let extract = &self.tools.extract;
        let most = extract.reads(&name);
        let mut image = None;
        let extracted = if most > 0 && attr.size <= most {
            match read_all(self.vault, ino).await {
                Ok(bytes) => {
                    // A photo's image vector, from the same bytes.
                    if let Some(embed) = self.tools.image.clone()
                        && Format::of(&name) == Format::Photo
                    {
                        match embed.image(bytes.clone()).await {
                            Ok(Some(v)) => image = Some((embed.model().to_string(), quantize(&v))),
                            Ok(None) => {}
                            Err(e) => self.stats.failed.push((path.clone(), e)),
                        }
                    }
                    extract.extract(&name, bytes).await
                }
                Err(e) if e.errno == errno::ENOENT => return self.gone(ino).await,
                Err(e) => {
                    self.stats.failed.push((path, e.to_string()));
                    return Ok(());
                }
            }
        } else {
            None
        };
        let nothing = Extra {
            reader: extract::READER,
            ..Extra::default()
        };
        let (kind, pieces, mut extra, thumb) = match extracted {
            Some(ex) => (
                ex.kind,
                text::chunks_with_text(&ex.text),
                ex.extra,
                ex.thumb,
            ),
            // A format with text, which this device can't read.
            None if most == 0 && !matches!(Format::of(&name), Format::Other) => {
                (DocKind::Unread, Vec::new(), nothing, None)
            }
            None => (DocKind::Opaque, Vec::new(), nothing, None),
        };
        if kind == DocKind::Photo {
            extra.image = image;
        }
        // Its thumbnail goes in the thumbnails file of the segment that
        // will hold this record.
        if let Some(jpeg) = thumb {
            extra.thumb = Some(Thumb {
                file: Manifest::thumbs_name(&self.mine.id, self.mine.next_segment),
                offset: self.pending_thumbs.len() as u64,
                len: jpeg.len() as u32,
            });
            self.pending_thumbs.extend_from_slice(&jpeg);
        }
        let (chunks, model) = self.embed(pieces, &path).await;
        self.stats.indexed += 1;
        self.push(Entry::Record(Record {
            ino,
            at_ms,
            stamp,
            path,
            kind,
            model,
            chunks,
            extra,
        }))
        .await?;
        self.tell();
        rt::sleep(self.config.pace).await;
        Ok(())
    }

    /// Checks file `ino` (in `parent`, below `folders`) as it is now.
    async fn check(&mut self, ino: u64, folders: &[u64], parent: u64) -> Result<(), FsError> {
        let attr = match self.vault.remote().getattr(ino).await {
            Ok(attr) => attr,
            Err(e) if e.errno == errno::ENOENT => return self.gone(ino).await,
            Err(e) => return Err(e),
        };
        if attr.kind != Kind::File {
            return Ok(());
        }
        // Listings may be from before this change.
        self.listings.remove(&parent);
        if let Some(path) = self.path_of(folders, parent, ino).await? {
            self.upsert(ino, &attr, path).await?;
        }
        Ok(())
    }

    /// Walks the whole volume: indexes what changed, and drops what the
    /// index has that is not there any more.
    async fn walk(&mut self) -> Result<(), FsError> {
        let mut seen = HashSet::new();
        let mut todo = vec![(self.volume, String::new())];
        while let Some((dir, prefix)) = todo.pop() {
            let items = match self.vault.children(dir).await {
                Ok(items) => items,
                // Removed or moved out since its parent was listed.
                Err(e) if e.errno == errno::ENOENT => continue,
                Err(e) => return Err(e),
            };
            let mut files = Vec::new();
            for item in items {
                let name = name_text(&item.name);
                if dir == self.volume && name == INDEX_DIR {
                    continue;
                }
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                match item.kind {
                    Kind::Directory => todo.push((item.ino, path)),
                    Kind::File => files.push((item.ino, path)),
                }
            }
            let remote = self.vault.remote();
            let attrs =
                futures_util::future::join_all(files.iter().map(|(ino, _)| remote.getattr(*ino)))
                    .await;
            for ((ino, path), attr) in files.into_iter().zip(attrs) {
                match attr {
                    Ok(attr) => {
                        seen.insert(ino);
                        self.upsert(ino, &attr, path).await?;
                    }
                    Err(e) if e.errno == errno::ENOENT => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let missing: Vec<u64> = self
            .entries
            .iter()
            .filter(|(ino, e)| matches!(e, Entry::Record(_)) && !seen.contains(*ino))
            .map(|(ino, _)| *ino)
            .collect();
        for ino in missing {
            self.gone(ino).await?;
        }
        Ok(())
    }
}

/// The volume's log back to `since_ms`, newest first. Its own entries in
/// `dir` (the index) are left out.
async fn read_log(
    vault: &Vault,
    volume: u64,
    dir: u64,
    since_ms: u64,
) -> Result<Vec<Activity>, FsError> {
    let mut out = Vec::new();
    let mut after = Vec::new();
    loop {
        let page = vault
            .remote()
            .list_activity(volume, &after, LOG_PAGE)
            .await?;
        let mut done = page.next.is_empty();
        for a in page.entries {
            if a.at_ms < since_ms {
                done = true;
                break;
            }
            if a.parent == dir || a.ino == dir || a.path.first() == Some(&dir) {
                continue;
            }
            out.push(a);
        }
        if done {
            return Ok(out);
        }
        after = page.next;
    }
}

/// One pass over `volume`, which the caller has claimed.
async fn run_pass(
    vault: &Vault,
    volume: u64,
    id: IndexerId,
    config: &IndexerConfig,
    tools: &Tools,
    kind: PassKind,
    progress: &mut (dyn FnMut(&PassStats) + Send),
) -> Result<PassStats, FsError> {
    let started = clock::now_millis();
    let loaded = load(vault, volume, true)
        .await?
        .expect("load makes the index folder");
    let so_far = view::progress(&loaded.manifests);
    let mine = loaded
        .manifests
        .iter()
        .find(|m| m.id == id)
        .cloned()
        .unwrap_or_else(|| Manifest {
            id,
            ..Manifest::default()
        });
    let by_path = loaded
        .entries
        .values()
        .filter_map(|e| match e {
            Entry::Record(r) => Some((r.path.clone(), r.ino)),
            Entry::Gone { .. } => None,
        })
        .collect();
    let mut pass = Pass {
        vault,
        volume,
        tools,
        config,
        dir: loaded.dir,
        mine,
        entries: loaded.entries,
        by_path,
        pending: Vec::new(),
        pending_thumbs: Vec::new(),
        listings: HashMap::new(),
        stats: PassStats::default(),
        progress,
        told: Instant::now(),
    };
    pass.mine.user = vault.remote().username().to_string();
    pass.mine.device = config.device.clone();
    pass.mine.model = tools.model().to_string();
    let mut full = kind == PassKind::Full
        || so_far.full_walk_ms == 0
        || started.saturating_sub(so_far.full_walk_ms) > FULL_WALK_EVERY_MS;
    let mut recent: HashMap<u64, u64> = so_far
        .recent
        .into_iter()
        .filter(|&(_, until)| until > started)
        .collect();
    let mut cursor = so_far.cursor_ms;
    if !full {
        let log = read_log(
            vault,
            volume,
            pass.dir,
            so_far.cursor_ms.saturating_sub(OVERLAP_MS),
        )
        .await?;
        cursor = log.first().map_or(cursor, |a| a.at_ms.max(cursor));
        // A folder that moved changes the paths of everything in it, and the
        // log does not list those: walk instead.
        full = log
            .iter()
            .any(|a| a.kind == Kind::Directory && a.op == ActivityOp::Renamed);
        if !full {
            let mut seen = HashSet::new();
            for a in &log {
                if a.op == ActivityOp::Edited {
                    let until = recent.entry(a.ino).or_default();
                    *until = (*until).max(a.at_ms + RECHECK_MS);
                }
                if a.kind != Kind::File || !seen.insert(a.ino) {
                    continue;
                }
                match a.op {
                    ActivityOp::Deleted => pass.gone(a.ino).await?,
                    ActivityOp::Renamed if a.moved_out => pass.gone(a.ino).await?,
                    _ => pass.check(a.ino, &a.path, a.parent).await?,
                }
            }
            // Files edited lately, which the log may not note again.
            for (&ino, _) in recent.iter().filter(|(ino, _)| !seen.contains(*ino)) {
                let Some(Entry::Record(r)) = pass.entries.get(&ino).cloned() else {
                    continue;
                };
                match vault.remote().getattr(ino).await {
                    Ok(attr) if stamp_of(&attr) != r.stamp => {
                        pass.upsert(ino, &attr, r.path).await?
                    }
                    Ok(_) => {}
                    Err(e) if e.errno == errno::ENOENT => pass.gone(ino).await?,
                    Err(e) => return Err(e),
                }
            }
        }
    }
    if full {
        pass.stats.full = true;
        pass.walk().await?;
        cursor = cursor.max(started);
        pass.mine.full_walk_ms = started;
    }
    pass.store().await?;
    let now = clock::now_millis();
    recent.retain(|_, until| *until > now);
    let mut recent: Vec<(u64, u64)> = recent.into_iter().collect();
    recent.sort();
    pass.stats.due_ms = if recent.is_empty() {
        pass.mine.full_walk_ms.max(so_far.full_walk_ms) + FULL_WALK_EVERY_MS
    } else {
        now
    };
    if pass.mine.cursor_ms != cursor || pass.mine.recent != recent || full {
        pass.mine.cursor_ms = cursor;
        pass.mine.recent = recent;
        pass.mine.updated_ms = now;
        pass.save_manifest().await?;
    }
    Ok(pass.stats)
}

/// Claims `volume` for `id`, runs one pass over it while renewing the
/// claim, and gives the claim up. `progress` hears how far it got, at most
/// once a second. `EBUSY` if someone else holds the claim. Servers from
/// before claims get a pass with no claim.
pub async fn index_claimed(
    vault: &Vault,
    volume: u64,
    id: IndexerId,
    config: &IndexerConfig,
    tools: &Tools,
    kind: PassKind,
    progress: &mut (dyn FnMut(&PassStats) + Send),
) -> Result<PassStats, FsError> {
    let remote = vault.remote();
    // Servers from before claims can't keep two devices apart. Each device
    // writes only its own files, so two at once is still safe: only slower.
    if remote.protocol() < raft5fs_proto::since::SEARCH_INDEX {
        return run_pass(vault, volume, id, config, tools, kind, progress).await;
    }
    let claim = remote.claim_index(volume, id, false).await?;
    if !claim.granted {
        let by = claim
            .claim
            .map_or_else(String::new, |c| format!(" by {}", c.user));
        return Err(FsError::new(
            errno::EBUSY,
            format!("this volume is being indexed elsewhere{by}"),
        ));
    }
    let pass = std::pin::pin!(run_pass(vault, volume, id, config, tools, kind, progress));
    // Renews the claim while the pass runs. A failed renewal is tried again
    // at the next: at worst, someone else indexes too, which is safe.
    let renew = std::pin::pin!(async {
        loop {
            rt::sleep(config.renew).await;
            let _ = remote.claim_index(volume, id, false).await;
        }
    });
    let stats = match futures_util::future::select(pass, renew).await {
        futures_util::future::Either::Left((stats, _)) => stats,
        futures_util::future::Either::Right((never, _)) => never,
    };
    let _ = remote.claim_index(volume, id, true).await;
    stats
}

/// The volumes this account can index: those granted to it read-write
/// whose owner has not turned indexing off.
pub async fn indexable_volumes(vault: &Vault) -> Result<Vec<u64>, FsError> {
    let (grants, _) = vault.remote().list_grants_covered().await?;
    let mut out = Vec::new();
    for g in grants.into_iter().filter(|g| g.writable) {
        match vault.remote().get_volume(g.ino).await {
            Ok(v) if !v.indexing_off => out.push(g.ino),
            Ok(_) => {}
            // A grant of a folder inside a volume: not indexed (yet).
            Err(e) if e.errno == errno::EINVAL => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// The volumes among `skip` (as the root shows them), by inode.
async fn skipped_volumes(vault: &Vault, skip: &[String]) -> HashSet<u64> {
    if skip.is_empty() {
        return HashSet::new();
    }
    let wanted: HashSet<&str> = skip.iter().map(|s| s.trim_matches('/')).collect();
    match vault.grant_paths().await {
        Ok(paths) => paths
            .into_iter()
            .filter(|(_, p)| wanted.contains(p.trim_matches('/')))
            .map(|(ino, _)| ino)
            .collect(),
        Err(e) => {
            eprintln!("search index: cannot tell which volumes to skip: {e}");
            HashSet::new()
        }
    }
}

/// Removes `volume`'s index, as its owner does after turning indexing off.
/// Returns how many bytes it held. Nothing to do for a volume with none.
pub async fn delete_index(vault: &Vault, volume: u64) -> Result<u64, FsError> {
    let dir = match vault.lookup(volume, OsStr::new(INDEX_DIR)).await {
        Ok(attr) => attr.ino,
        Err(e) if e.errno == errno::ENOENT => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut bytes = 0;
    for item in vault.children(dir).await? {
        if let Ok(attr) = vault.remote().getattr(item.ino).await {
            bytes += attr.size;
        }
        vault.unlink(dir, &item.name).await?;
    }
    vault.rmdir(volume, OsStr::new(INDEX_DIR)).await?;
    Ok(bytes)
}

/// What indexing a volume would take, from reading it all and storing
/// nothing (`raft5fs index --dry-run`).
#[derive(Debug, Clone, Default)]
pub struct Survey {
    /// Files and bytes by kind of file, as `Format` names them.
    pub by_format: std::collections::BTreeMap<String, (usize, u64)>,
    /// Words of text found, and the chunks they make.
    pub words: u64,
    pub chunks: u64,
    /// The size of the index's segments, as this would store them now
    /// (no vectors).
    pub index_bytes: u64,
}

/// Reads every file in `volume` as a pass would, and counts.
pub async fn survey(
    vault: &Vault,
    volume: u64,
    extract: &dyn Extract,
    progress: &mut (dyn FnMut(&Survey) + Send),
) -> Result<Survey, FsError> {
    let mut s = Survey::default();
    let mut told = Instant::now();
    let mut todo = vec![(volume, String::new())];
    while let Some((dir, prefix)) = todo.pop() {
        for item in vault.children(dir).await? {
            let name = name_text(&item.name);
            if dir == volume && name == INDEX_DIR {
                continue;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if item.kind == Kind::Directory {
                todo.push((item.ino, path));
                continue;
            }
            let attr = match vault.remote().getattr(item.ino).await {
                Ok(attr) => attr,
                Err(e) if e.errno == errno::ENOENT => continue,
                Err(e) => return Err(e),
            };
            let slot = s
                .by_format
                .entry(format!("{:?}", Format::of(&name)).to_lowercase())
                .or_default();
            slot.0 += 1;
            slot.1 += attr.size;
            let most = extract.reads(&name);
            let text = if most > 0 && attr.size <= most {
                match read_all(vault, item.ino).await {
                    Ok(bytes) => extract.extract(&name, bytes).await.map(|e| e.text),
                    Err(_) => None,
                }
            } else {
                None
            };
            let chunks = text.as_deref().map(text::chunks).unwrap_or_default();
            s.words += text
                .as_deref()
                .map_or(0, |t| t.split_whitespace().count() as u64);
            s.chunks += chunks.len() as u64;
            let record = Entry::Record(Record {
                ino: item.ino,
                at_ms: 0,
                stamp: stamp_of(&attr),
                path,
                kind: DocKind::Text,
                model: String::new(),
                chunks,
                extra: Extra::default(),
            });
            s.index_bytes += raft5fs_search::record::encode_entry(&record).len() as u64 + 4;
            if told.elapsed() >= Duration::from_secs(1) {
                told = Instant::now();
                progress(&s);
            }
        }
    }
    Ok(s)
}

/// What a background indexer knows, for showing.
#[derive(Debug, Clone, Default)]
pub struct IndexStatus {
    /// The volume this indexer works on now, and how far it got.
    pub current: Option<(u64, String)>,
    /// The last pass over each volume here, and how it went.
    pub last: HashMap<u64, String>,
    /// Why the servers couldn't be asked, the last time they weren't.
    pub error: Option<String>,
}

/// An indexer running in the background: dropping it stops it.
pub struct Indexer {
    handle: AbortHandle,
    kick: Arc<Notify>,
    status: Arc<Mutex<IndexStatus>>,
}

impl Indexer {
    /// Looks for work now, as after a write.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    pub fn status(&self) -> IndexStatus {
        self.status.lock().unwrap().clone()
    }
}

impl Drop for Indexer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Starts to index, with `vault`, the volumes this account can. Give it its
/// own vault, as for a pruner. Runs until the `Indexer` drops.
pub fn spawn(vault: Vault, config: IndexerConfig, tools: Tools) -> Indexer {
    let kick = Arc::new(Notify::new());
    let status = Arc::new(Mutex::new(IndexStatus::default()));
    let handle = rt::spawn(run(
        vault,
        config,
        tools,
        Arc::clone(&kick),
        Arc::clone(&status),
    ));
    Indexer {
        handle,
        kick,
        status,
    }
}

/// How many log entries `newest_change` looks at for one that is not the
/// index's own.
const NEWEST_PAGE: u32 = 50;

/// When `volume` last changed, as its log says (ms): its newest entry that
/// is not a write to the index itself, which every pass makes. `u64::MAX`
/// if the log can't say, so that a pass runs. `dirs` keeps each volume's
/// index folder, once found.
async fn newest_change(vault: &Vault, volume: u64, dirs: &mut HashMap<u64, u64>) -> u64 {
    if !dirs.contains_key(&volume)
        && let Ok(attr) = vault.lookup(volume, OsStr::new(INDEX_DIR)).await
    {
        dirs.insert(volume, attr.ino);
    }
    let dir = dirs.get(&volume).copied();
    let Ok(page) = vault.remote().list_activity(volume, &[], NEWEST_PAGE).await else {
        return u64::MAX;
    };
    let own = |a: &Activity| {
        dir.is_some_and(|d| a.parent == d || a.ino == d || a.path.first() == Some(&d))
    };
    match page.entries.iter().find(|a| !own(a)) {
        Some(a) => a.at_ms,
        None if page.entries.is_empty() => 0,
        // Only the index's own writes in sight: the page may hide others.
        None if !page.next.is_empty() => u64::MAX,
        None => 0,
    }
}

async fn rest(duration: Duration, kick: &Notify) {
    let sleep = std::pin::pin!(rt::sleep(duration));
    let kicked = std::pin::pin!(kick.notified());
    futures_util::future::select(sleep, kicked).await;
}

/// The background loop:
///
/// - Lists the volumes this account can index, less those this device
///   skips.
/// - For each, asks the log for its newest change. A volume with nothing
///   newer than this device's last pass, and no walk or recheck due, is
///   left alone without a claim.
/// - Indexes the others, each under a claim; a claim held elsewhere is left
///   alone. A failed volume waits longer each time.
async fn run(
    vault: Vault,
    config: IndexerConfig,
    tools: Tools,
    kick: Arc<Notify>,
    status: Arc<Mutex<IndexStatus>>,
) {
    // Without claims, devices would all index every volume at once.
    if vault.remote().protocol() < raft5fs_proto::since::SEARCH_INDEX {
        status.lock().unwrap().error =
            Some("the servers are too old to share indexing: update them".into());
        return;
    }
    let id = new_id();
    // What this device knows of each volume after its last pass: the
    // newest change it saw, when it is next due anyway, and any wait after
    // a failure.
    let mut known: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut retry: HashMap<u64, (Instant, Duration)> = HashMap::new();
    let mut index_dirs: HashMap<u64, u64> = HashMap::new();
    let mut list_wait = config.backoff;
    loop {
        let volumes = match indexable_volumes(&vault).await {
            Ok(v) => {
                list_wait = config.backoff;
                status.lock().unwrap().error = None;
                v
            }
            Err(e) => {
                status.lock().unwrap().error = Some(e.to_string());
                let wait = if e.errno == errno::ENOTSUP {
                    config.max_backoff
                } else {
                    list_wait
                };
                list_wait = (list_wait * 2).min(config.max_backoff);
                rest(wait, &kick).await;
                continue;
            }
        };
        let skipped = skipped_volumes(&vault, &config.skip).await;
        for volume in volumes.into_iter().filter(|v| !skipped.contains(v)) {
            if retry
                .get(&volume)
                .is_some_and(|(at, _)| *at > Instant::now())
            {
                continue;
            }
            let newest = newest_change(&vault, volume, &mut index_dirs).await;
            let now = clock::now_millis();
            if let Some(&(seen, due)) = known.get(&volume)
                && newest <= seen
                && now < due
            {
                continue;
            }
            status.lock().unwrap().current = Some((volume, "started".into()));
            let done = index_claimed(
                &vault,
                volume,
                id,
                &config,
                &tools,
                PassKind::Auto,
                &mut |so_far| {
                    status.lock().unwrap().current = Some((volume, describe(so_far)));
                },
            )
            .await;
            let mut s = status.lock().unwrap();
            s.current = None;
            match done {
                Ok(stats) => {
                    s.last.insert(volume, describe(&stats));
                    retry.remove(&volume);
                    known.insert(volume, (newest, stats.due_ms));
                }
                // Someone else indexes it now; look again later.
                Err(e) if e.errno == errno::EBUSY => {}
                Err(e) => {
                    s.last.insert(volume, e.to_string());
                    let wait = retry
                        .get(&volume)
                        .map_or(config.backoff, |(_, w)| (*w * 2).min(config.max_backoff));
                    retry.insert(volume, (Instant::now() + wait, wait));
                }
            }
        }
        rest(config.poll, &kick).await;
    }
}
