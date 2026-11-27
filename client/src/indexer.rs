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
//!   any manifest, and indexes what changed. It also indexes again what
//!   this device can do more for than whoever indexed it (vectors a browser
//!   left out, say), whether or not it changed. Once a day, or when the log
//!   can't say what changed (a folder moved), it walks the whole volume
//!   instead.
//! - **Meaning.** With an `Embed`, each chunk gets a vector from its model,
//!   and the record names the model. A record from another model, or from
//!   none, counts as out of date: the next pass that sees it embeds it
//!   again.
//! - **Resumable.** A pass stores what it has every `SEGMENT_ENTRIES`
//!   files, or sooner once they reach about `SEGMENT_BYTES`. A pass cut
//!   short is finished by whoever claims the volume
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

// `std::time::Instant` panics in a browser; this is the same type natively.
use web_time::Instant;

use raft5fs_proto::os_bytes;
use raft5fs_proto::types::{Activity, ActivityOp, Attr, FsError, Kind};
use raft5fs_proto::{clock, errno};
use raft5fs_search::INDEX_DIR;
use raft5fs_search::extract::{self, Extracted, Format};
use raft5fs_search::generation;
use raft5fs_search::manifest::{IndexerId, Manifest, decode_manifest, encode_manifest};
use raft5fs_search::record::{Chunk, DocKind, Entry, Extra, Meta, Record, Stamp, Thumb, Vector};
use raft5fs_search::segment::{decode_segment, encode_segment};
use raft5fs_search::text;
use raft5fs_search::vector::quantize;
use raft5fs_search::view;
use raft5fs_search::view::MIN_MEANING_WORDS;
use tokio::sync::Notify;

mod cache;
#[cfg(not(target_arch = "wasm32"))]
mod compaction;
pub mod open;
#[cfg(not(target_arch = "wasm32"))]
mod spill;

#[cfg(not(target_arch = "wasm32"))]
pub use cache::DiskCache;
pub use cache::MemoryCache;

use crate::remote::Remote;
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
/// How many entries go in one segment before a pass stores it...
const SEGMENT_ENTRIES: usize = 200;
/// ... or how many bytes, about, whichever comes first: a run of large
/// files would otherwise hold much memory before it is stored.
const SEGMENT_BYTES: usize = 8 << 20;
/// A pass compacts once the recent segments hold more files than this
/// share of the generation's, ...
const RECENT_SHARE: f64 = 0.075;
/// ... or this many chunks, which every reader holds in memory, ...
const RECENT_CHUNKS: usize = 25_000;
/// ... or are this many files, ...
const RECENT_SEGMENTS: usize = 64;
/// ... or when more than this share of the generation's files are dead.
const DEAD_SHARE: f64 = 0.3;
/// How long a compaction keeps the files it replaced, for readers part-way
/// through them. Snapshots keep them a while too.
pub const GRACE_MS: u64 = 24 * 60 * 60 * 1000;
/// How much of a file is read in one request.
const READ_PIECE: u64 = 4 << 20;
/// How many log entries one page asks for.
const LOG_PAGE: u32 = 200;

/// How fast an indexer works, and what it leaves alone.
#[derive(Clone)]
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
    /// How long a pass may go without progress (a file checked, a folder
    /// listed, a batch embedded) before it stops and gives up its claim.
    /// Long enough for a model's first download on a slow line: that is
    /// one step.
    pub stall: Duration,
    /// What this device is called in the status search shows.
    pub device: String,
    /// Volumes this device does not index (others still may), as this
    /// account's root shows them, such as `photos` or `CS101/notes`.
    pub skip: Vec<String>,
    /// The fewest recent files worth a compaction: a small index stays in
    /// recent segments. Tests set it low.
    pub compact_min: usize,
    /// How long a compaction keeps what it replaced (`GRACE_MS`).
    pub grace: Duration,
    /// Where the index files read are kept between passes (sealed), and
    /// where compaction keeps its work: a folder of this device's cache.
    /// `None`: kept for one pass only, and the index is never compacted.
    #[cfg(not(target_arch = "wasm32"))]
    pub cache_dir: Option<std::path::PathBuf>,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(60),
            pace: Duration::from_millis(20),
            backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
            renew: Duration::from_secs(180),
            stall: Duration::from_secs(30 * 60),
            device: String::new(),
            skip: Vec::new(),
            compact_min: 200,
            grace: Duration::from_millis(GRACE_MS),
            #[cfg(not(target_arch = "wasm32"))]
            cache_dir: None,
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
    /// Whether a model failed in this pass: the pass stopped asking it, and
    /// a background indexer waits longer before the next try.
    pub model_failed: bool,
    /// Whether the pass compacted the index (`Pass::compact`).
    pub compacted: bool,
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
    if stats.compacted {
        line.push_str("; index compacted");
    }
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
    /// The index folder's files, by name.
    files: HashMap<String, u64>,
    manifests: Vec<Manifest>,
    /// The generation, if the index was compacted.
    header: Option<generation::Header>,
    /// The newest entry for each inode, from every recent segment read.
    entries: HashMap<u64, Entry>,
    /// Every segment the manifests list, by cache key (`segment_key`).
    keys: Vec<String>,
    /// Whether a segment known to the caller is gone (compacted away), so
    /// that every segment was read.
    reset: bool,
    /// Whether a manifest or segment couldn't be read: one from a newer
    /// client, or damaged. Then nothing compacts the index, which would
    /// lose what it holds.
    unread: bool,
}

/// What names a segment in a cache: its volume, inode and name. A segment
/// never changes once a manifest lists it, so this names its bytes.
fn segment_key(volume: u64, ino: u64, name: &str) -> String {
    format!("{volume}/{ino}/{name}")
}

/// How many times `load` lists the index again when a file in it goes
/// while it reads: an indexer replaces its manifest by a rename.
const LOAD_TRIES: usize = 5;

/// Where `load_with` puts each segment's entries as it reads them.
#[cfg(not(target_arch = "wasm32"))]
pub type EntrySink<'a> = &'a mut (dyn FnMut(Vec<Entry>) + Send);
#[cfg(target_arch = "wasm32")]
pub type EntrySink<'a> = &'a mut dyn FnMut(Vec<Entry>);

/// `load`, with segments taken from `cache` where it has them, and put
/// there when they are read. Segments in `known` are not read, unless one
/// of them is gone (`Loaded::reset`).
///
/// With `sink`, each segment's entries go there as they are read, and
/// `Loaded::entries` is empty; and if a known segment is gone, nothing is
/// read, so that the caller starts again from nothing.
async fn load_with(
    vault: &Vault,
    volume: u64,
    create: bool,
    cache: Option<&dyn SegmentCache>,
    known: &HashSet<String>,
    mut sink: Option<EntrySink<'_>>,
) -> Result<Option<Loaded>, FsError> {
    let mut tries = 0;
    loop {
        match load_once(vault, volume, create, cache, known, &mut sink).await {
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
    known: &HashSet<String>,
    sink: &mut Option<EntrySink<'_>>,
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
    let mut unread = false;
    for (name, &ino) in &files {
        if !Manifest::is_manifest(name) {
            continue;
        }
        match decode_manifest(&read_all(vault, ino).await?) {
            Ok(m) => manifests.push(m),
            Err(e) => {
                eprintln!("search index: skipped {name}: {e}");
                unread = true;
            }
        }
    }
    let mut listed = Vec::new();
    for m in &manifests {
        for seg in &m.segments {
            match files.get(seg) {
                Some(&ino) => listed.push((segment_key(volume, ino, seg), ino, seg)),
                None => eprintln!("search index: {seg} is missing"),
            }
        }
    }
    let keys: Vec<String> = listed.iter().map(|(key, ..)| key.clone()).collect();
    let now: HashSet<&String> = keys.iter().collect();
    let reset = known.iter().any(|k| !now.contains(k));
    // The generation, named by the manifest that compacted last.
    let header = match manifests
        .iter()
        .filter_map(|m| Some((m.updated_ms, m.generation?)))
        .max()
    {
        None => None,
        Some((_, id)) => {
            let name = generation::head_name(&id);
            // Gone: replaced by a newer compaction meanwhile (`load_with`
            // reads again).
            let &ino = files
                .get(&name)
                .ok_or_else(|| FsError::new(errno::ENOENT, "the index's generation is gone"))?;
            match generation::decode_header(&read_all(vault, ino).await?) {
                Ok(h) => Some(h),
                Err(e) => {
                    eprintln!("search index: skipped {name}: {e}");
                    unread = true;
                    None
                }
            }
        }
    };
    let mut all = Vec::new();
    if reset && sink.is_some() {
        listed.clear();
    }
    for (key, ino, seg) in listed {
        if !reset && known.contains(&key) {
            continue;
        }
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
            Ok(entries) => match sink.as_mut() {
                Some(sink) => sink(entries),
                None => all.extend(entries),
            },
            Err(e) => {
                eprintln!("search index: skipped {seg}: {e}");
                unread = true;
            }
        }
    }
    Ok(Some(Loaded {
        dir,
        files,
        manifests,
        header,
        entries: view::latest(all),
        keys,
        reset,
        unread,
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
    /// Drops what it keeps for `volume` under keys not in `keys`: segments
    /// compacted away. Called on a first read, and when a segment is gone.
    fn keep_only<'a>(&'a self, volume: u64, keys: &'a [String]) -> BoxFuture<'a, ()> {
        let _ = (volume, keys);
        Box::pin(async {})
    }
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

/// `write_new` for a file of this indexer's that no manifest lists yet.
/// One there already is left from a pass cut short before it listed it,
/// so is replaced.
async fn write_fresh(vault: &Vault, dir: u64, name: &str, bytes: &[u8]) -> Result<(), FsError> {
    match write_new(vault, dir, name, bytes).await {
        Err(e) if e.errno == errno::EEXIST => {
            vault.unlink(dir, OsStr::new(name)).await?;
            write_new(vault, dir, name, bytes).await
        }
        other => other,
    }
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

/// About how many bytes `entry` takes in a segment, before compression:
/// its path, and each chunk's preview, words and vector.
fn entry_bytes(entry: &Entry) -> usize {
    let Entry::Record(r) = entry else { return 16 };
    let chunks: usize = r
        .chunks
        .iter()
        .map(|c| {
            let words: usize = c.terms.iter().map(|(t, _)| t.len() + 3).sum();
            c.preview.len() + words + c.vector.as_ref().map_or(0, |v| v.values.len() + 4)
        })
        .sum();
    let image = r
        .extra
        .image
        .as_ref()
        .map_or(0, |(_, v)| v.values.len() + 4);
    64 + r.path.len() + chunks + image
}

/// What a pass keeps of each live file: what tells whether the file
/// changed, or whether this device can do more for it.
#[derive(Debug, Clone)]
struct Known {
    path: String,
    stamp: Stamp,
    kind: DocKind,
    /// The model of its text vectors; empty for none.
    model: String,
    reader: u32,
    /// A photo's image vector's model, and whether it has one.
    image: Option<(String, bool)>,
    /// Whether a chunk is long enough to embed.
    embeddable: bool,
    /// Who made it and when, and who last changed it (`Meta`), carried to
    /// the file's next record.
    added_ms: u64,
    added_by: String,
    changed_by: String,
}

/// What the volume's activity log says of one file.
#[derive(Debug, Clone, Default)]
struct Author {
    /// When it was made, and by whom: 0 and empty if the log doesn't go
    /// back that far.
    added_ms: u64,
    added_by: String,
    /// Who last made or changed it.
    changed_by: String,
}

impl Known {
    fn of_record(r: &Record) -> Self {
        Self::of_row(&generation::Row::of(r, MIN_MEANING_WORDS))
    }

    fn of_row(r: &generation::Row) -> Self {
        Self {
            path: r.path.clone(),
            stamp: r.stamp,
            kind: r.kind,
            model: r.model.clone(),
            reader: r.reader,
            image: r.image.clone(),
            embeddable: r.embeddable,
            added_ms: r.meta.added_ms,
            added_by: r.meta.added_by.clone(),
            changed_by: r.meta.changed_by.clone(),
        }
    }
}

/// Each file's author, from `log` (newest first).
fn authors_of(log: &[Activity]) -> HashMap<u64, Author> {
    let mut out: HashMap<u64, Author> = HashMap::new();
    for a in log.iter().filter(|a| a.kind == Kind::File) {
        let author = out.entry(a.ino).or_default();
        match a.op {
            ActivityOp::Created => {
                author.added_ms = a.at_ms;
                author.added_by = a.user.clone();
            }
            ActivityOp::Edited => {}
            _ => continue,
        }
        if author.changed_by.is_empty() {
            author.changed_by = a.user.clone();
        }
    }
    out
}

/// One pass over one volume, under a claim.
struct Pass<'a> {
    vault: &'a Vault,
    volume: u64,
    tools: &'a Tools,
    config: &'a IndexerConfig,
    dir: u64,
    mine: Manifest,
    /// Every live file.
    files: HashMap<u64, Known>,
    /// The newest entry for each file in the recent segments, this pass's
    /// own included: what the next compaction folds in.
    recent: HashMap<u64, Entry>,
    /// The generation, if the index was compacted.
    generation: Option<Arc<raft5fs_search::index::Generation>>,
    header: Option<generation::Header>,
    /// The index folder's files when the pass began, by name.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    listing: HashMap<String, u64>,
    /// The other indexers' manifests when the pass began.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    others: Vec<Manifest>,
    /// The inode of each live file's path, to drop a file replaced by
    /// another at the same path.
    by_path: HashMap<String, u64>,
    pending: Vec<Entry>,
    /// About how many bytes `pending` takes encoded (`entry_bytes`).
    pending_bytes: usize,
    /// The thumbnails of `pending`'s records, one after another.
    pending_thumbs: Vec<u8>,
    /// Records waiting for their chunks' vectors, with the chunks' texts
    /// (`queue`).
    queued: Vec<(Record, Vec<String>)>,
    /// Folder listings, by inode: names of what is in each.
    listings: HashMap<u64, Vec<(String, u64, Kind)>>,
    /// Who made and changed files, from the activity log the pass read.
    authors: HashMap<u64, Author>,
    stats: PassStats,
    progress: &'a mut (dyn FnMut(&PassStats) + Send),
    told: Instant,
    /// When the pass last made progress (ms): see `IndexerConfig::stall`.
    alive: &'a AtomicU64,
    /// Recent segment files listed, in every manifest.
    segment_files: usize,
}

impl Pass<'_> {
    /// Notes that the pass is making progress.
    fn beat(&self) {
        self.alive.store(clock::now_millis(), Ordering::Relaxed);
    }

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
        let ino = entry.ino();
        if let Some(old) = self.files.get(&ino)
            && self.by_path.get(&old.path) == Some(&ino)
        {
            let old_path = old.path.clone();
            self.by_path.remove(&old_path);
        }
        match &entry {
            Entry::Record(r) => {
                self.by_path.insert(r.path.clone(), ino);
                self.files.insert(ino, Known::of_record(r));
            }
            Entry::Gone { .. } => {
                self.files.remove(&ino);
            }
            Entry::Moved { path, .. } => {
                self.by_path.insert(path.clone(), ino);
                if let Some(k) = self.files.get_mut(&ino) {
                    k.path.clone_from(path);
                }
            }
        }
        let merged = match self.recent.remove(&ino) {
            Some(old) => old.then(entry.clone()),
            None => entry.clone(),
        };
        self.recent.insert(ino, merged);
        self.pending_bytes += entry_bytes(&entry);
        self.pending.push(entry);
        if self.pending.len() >= SEGMENT_ENTRIES || self.pending_bytes >= SEGMENT_BYTES {
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
        self.beat();
        let n = self.mine.next_segment;
        if !self.pending_thumbs.is_empty() {
            let thumbs = Manifest::thumbs_name(&self.mine.id, n);
            write_fresh(self.vault, self.dir, &thumbs, &self.pending_thumbs).await?;
            self.pending_thumbs.clear();
        }
        let name = Manifest::segment_name(&self.mine.id, n);
        let entries = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        write_fresh(self.vault, self.dir, &name, &encode_segment(&entries)).await?;
        self.segment_files += 1;
        self.mine.segments.push(name);
        self.mine.next_segment += 1;
        self.mine.updated_ms = clock::now_millis();
        self.save_manifest().await
    }

    async fn save_manifest(&mut self) -> Result<(), FsError> {
        let name = Manifest::file_name(&self.mine.id);
        replace(self.vault, self.dir, &name, &encode_manifest(&self.mine)).await
    }

    /// Whether the recent segments hold enough to compact: a share of the
    /// generation, or so many chunks that readers' memory would suffer,
    /// or so many files; or the generation has many dead files.
    fn compaction_due(&self) -> bool {
        let generation = self.header.as_ref().map_or(0, |h| h.files) as f64;
        let chunks: usize = self
            .recent
            .values()
            .map(|e| match e {
                Entry::Record(r) => r.chunks.len(),
                _ => 0,
            })
            .sum();
        let dead = self.generation.as_ref().map_or(0, |g| {
            self.recent
                .keys()
                .filter(|ino| g.file_of(**ino).is_some())
                .count()
        });
        let recent = self.recent.len() as f64;
        recent >= self.config.compact_min as f64
            && (recent > generation * RECENT_SHARE
                || chunks >= RECENT_CHUNKS
                || self.segment_files > RECENT_SEGMENTS
                || (generation > 0.0 && dead as f64 > generation * DEAD_SHARE))
    }

    /// Deletes the retired files whose time has come.
    async fn retire_due(&mut self) -> Result<(), FsError> {
        let now = clock::now_millis();
        let (due, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.mine.retired)
            .into_iter()
            .partition(|(_, at)| *at <= now);
        self.mine.retired = kept;
        for (name, _) in &due {
            match self.vault.unlink(self.dir, OsStr::new(name)).await {
                Ok(_) => {}
                Err(e) if e.errno == errno::ENOENT => {}
                Err(e) => return Err(e),
            }
        }
        if !due.is_empty() {
            self.save_manifest().await?;
        }
        Ok(())
    }

    async fn gone(&mut self, ino: u64) -> Result<(), FsError> {
        self.beat();
        if self.files.contains_key(&ino) {
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
    fn embedded_as_now(&self, old: &Known) -> bool {
        let name = old.path.rsplit('/').next().unwrap_or(&old.path);
        if old.kind == DocKind::Unread && self.tools.extract.reads(name) >= old.stamp.size {
            return false;
        }
        // A photo with no image vector (another device left it for one that
        // has the model), or one from a model this one supersedes.
        if let Some(image) = &self.tools.image
            && old.kind == DocKind::Photo
            && match &old.image {
                None => true,
                Some((m, _)) => m != image.model() && image.replaces(m),
            }
        {
            return false;
        }
        // Read by older readers, which found less in it than these would.
        if old.reader < extract::READER
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
        !old.embeddable
            || old.model == embed.model()
            || !(old.model.is_empty() || embed.replaces(&old.model))
    }

    /// `pieces` as chunks, each with its vector if this indexer embeds, and
    /// the model that made them. If the model fails, the chunks keep no
    /// vectors and name no model, so a later pass tries again.
    /// Stores `record`, whose chunks have the texts `texts`, once its
    /// chunks have vectors: records wait until `EMBED_BATCH` passages from
    /// any files are waiting, so the model runs on a batch (much faster
    /// than one file's chunks at a time), or until the pass ends (`flush`).
    async fn queue(&mut self, record: Record, texts: Vec<String>) -> Result<(), FsError> {
        let worth = record
            .chunks
            .iter()
            .filter(|c| c.len >= MIN_MEANING_WORDS)
            .count();
        if self.tools.embed.is_none() || self.stats.model_failed || worth == 0 {
            return self.push(Entry::Record(record)).await;
        }
        self.queued.retain(|(r, _)| r.ino != record.ino);
        self.queued.push((record, texts));
        let waiting: usize = self
            .queued
            .iter()
            .map(|(r, _)| {
                r.chunks
                    .iter()
                    .filter(|c| c.len >= MIN_MEANING_WORDS)
                    .count()
            })
            .sum();
        if waiting >= EMBED_BATCH {
            self.flush().await?;
        }
        Ok(())
    }

    /// Embeds the waiting records' chunks, in one call, and stores them.
    /// Only chunks long enough to match by meaning are worth the model's
    /// time (`MIN_MEANING_WORDS`): a photo's few words aren't. If the model
    /// fails, the records keep no vectors and name no model, so a later
    /// pass tries again.
    async fn flush(&mut self) -> Result<(), FsError> {
        let mut queued = std::mem::take(&mut self.queued);
        if queued.is_empty() {
            return Ok(());
        }
        let Some(embed) = self.tools.embed.clone() else {
            return Ok(());
        };
        let mut at = Vec::new();
        let mut texts = Vec::new();
        for (r, (record, chunk_texts)) in queued.iter().enumerate() {
            for (c, chunk) in record.chunks.iter().enumerate() {
                if chunk.len >= MIN_MEANING_WORDS {
                    at.push((r, c));
                    texts.push(chunk_texts[c].clone());
                }
            }
        }
        self.beat();
        let got = if self.stats.model_failed {
            Err(String::new())
        } else {
            match embed.passages(texts).await {
                Ok(v) if v.len() == at.len() => Ok(v),
                Ok(v) => Err(format!(
                    "the model gave {} vectors for {}",
                    v.len(),
                    at.len()
                )),
                Err(e) => Err(e),
            }
        };
        match got {
            Ok(vectors) => {
                for (&(r, c), v) in at.iter().zip(&vectors) {
                    queued[r].0.chunks[c].vector = Some(quantize(v));
                }
                for (record, _) in &mut queued {
                    record.model = embed.model().to_string();
                }
            }
            Err(why) => {
                if !self.stats.model_failed {
                    self.stats.failed.push((queued[0].0.path.clone(), why));
                    self.stats.model_failed = true;
                }
            }
        }
        for (record, _) in queued {
            self.push(Entry::Record(record)).await?;
        }
        Ok(())
    }

    /// Indexes file `ino` at `path`, unless the index has it as it is now.
    async fn upsert(&mut self, ino: u64, attr: &Attr, path: String) -> Result<(), FsError> {
        self.beat();
        let stamp = stamp_of(attr);
        let at_ms = clock::now_millis();
        // Another file that was at this path was replaced by this one (as
        // editors save): it is gone, and this one was made when it was.
        let mut replaced = None;
        if let Some(&other) = self.by_path.get(&path)
            && other != ino
        {
            replaced = self.files.get(&other).cloned();
            self.gone(other).await?;
        }
        if let Some(old) = self.files.get(&ino)
            && old.stamp == stamp
            && self.embedded_as_now(old)
        {
            if old.path != path {
                self.stats.moved += 1;
                self.push(Entry::Moved { ino, at_ms, path }).await?;
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
                        && !self.stats.model_failed
                    {
                        let model = embed.model().to_string();
                        match embed.image(bytes.clone()).await {
                            Ok(Some(v)) => image = Some((model, quantize(&v))),
                            // A picture this model can't decode (HEIC): an
                            // empty vector says it tried, so it isn't
                            // tried again until the file or model changes.
                            Ok(None) => {
                                image = Some((
                                    model,
                                    Vector {
                                        scale: 0.0,
                                        values: Vec::new(),
                                    },
                                ))
                            }
                            Err(e) => {
                                self.stats.failed.push((path.clone(), e));
                                self.stats.model_failed = true;
                            }
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
        self.author(ino, replaced.as_ref(), &mut extra.meta);
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
        let (chunks, texts): (Vec<Chunk>, Vec<String>) = pieces.into_iter().unzip();
        self.stats.indexed += 1;
        let record = Record {
            ino,
            at_ms,
            stamp,
            path,
            kind,
            model: String::new(),
            chunks,
            extra,
        };
        self.queue(record, texts).await?;
        self.tell();
        rt::sleep(self.config.pace).await;
        Ok(())
    }

    /// Fills in who made file `ino` and when, and who last changed it:
    /// from the log, else from its last record, else from the file it
    /// `replaced` at its path.
    fn author(&self, ino: u64, replaced: Option<&Known>, meta: &mut Meta) {
        let log = self.authors.get(&ino);
        let known = self.files.get(&ino);
        let carried = known
            .filter(|k| k.added_ms > 0 || !k.added_by.is_empty())
            .or(replaced.filter(|k| k.added_ms > 0 || !k.added_by.is_empty()));
        match (log.filter(|a| a.added_ms > 0), carried) {
            (_, Some(k)) => {
                meta.added_ms = k.added_ms;
                meta.added_by = k.added_by.clone();
            }
            (Some(a), None) => {
                meta.added_ms = a.added_ms;
                meta.added_by = a.added_by.clone();
            }
            (None, None) => {}
        }
        meta.changed_by = log
            .map(|a| a.changed_by.clone())
            .filter(|c| !c.is_empty())
            .or_else(|| known.map(|k| k.changed_by.clone()))
            .unwrap_or_default();
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
            self.beat();
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
            .files
            .keys()
            .filter(|ino| !seen.contains(*ino))
            .copied()
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

/// Where a pass keeps the index files it reads: on disk in the config's
/// folder, for this account, or else in memory for the pass.
fn pass_cache(vault: &Vault, config: &IndexerConfig) -> Arc<dyn SegmentCache> {
    #[cfg(not(target_arch = "wasm32"))]
    if let (Some(dir), Some(identity)) = (&config.cache_dir, vault.remote().identity()) {
        return Arc::new(DiskCache::new(
            disk_dir(dir, vault.remote().username()),
            identity,
        ));
    }
    let _ = (vault, config);
    Arc::new(MemoryCache::default())
}

/// The folder in `base` where `user`'s index files are kept.
#[cfg(not(target_arch = "wasm32"))]
pub fn disk_dir(base: &std::path::Path, user: &str) -> std::path::PathBuf {
    base.join("index").join(raft5fs_wire::hex(user.as_bytes()))
}

/// This device's cache folder for the index: `$XDG_CACHE_HOME/raft5fs`, or
/// `~/.cache/raft5fs`.
#[cfg(not(target_arch = "wasm32"))]
pub fn cache_base() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))?;
    Some(base.join("raft5fs"))
}

/// `vault`'s disk cache in `base` (`cache_base`), if it is logged in.
#[cfg(not(target_arch = "wasm32"))]
pub fn disk_cache(vault: &Vault, base: &std::path::Path) -> Option<Arc<dyn SegmentCache>> {
    let identity = vault.remote().identity()?;
    Some(Arc::new(DiskCache::new(
        disk_dir(base, vault.remote().username()),
        identity,
    )))
}

/// One pass over `volume`, which the caller has claimed.
/// One pass over `volume`. With `claimed`, no one else writes its index
/// meanwhile, so the pass may compact it.
#[allow(clippy::too_many_arguments)]
async fn run_pass(
    vault: &Vault,
    volume: u64,
    id: IndexerId,
    config: &IndexerConfig,
    tools: &Tools,
    kind: PassKind,
    claimed: bool,
    alive: &AtomicU64,
    progress: &mut (dyn FnMut(&PassStats) + Send),
) -> Result<PassStats, FsError> {
    let started = clock::now_millis();
    let owned = pass_cache(vault, config);
    let cache: &dyn SegmentCache = owned.as_ref();
    let loaded = load_with(vault, volume, true, Some(cache), &HashSet::new(), None)
        .await?
        .expect("load makes the index folder");
    let so_far = view::progress(&loaded.manifests);
    let can_compact = claimed && !loaded.unread;
    let mine = loaded
        .manifests
        .iter()
        .find(|m| m.id == id)
        .cloned()
        .unwrap_or_else(|| Manifest {
            id,
            ..Manifest::default()
        });
    let others: Vec<Manifest> = loaded
        .manifests
        .iter()
        .filter(|m| m.id != id)
        .cloned()
        .collect();
    // The generation's files, then the recent segments' on top.
    let generation = match &loaded.header {
        Some(h) => {
            open::fetch_generation(vault, volume, &loaded.files, h, cache, &mut |_, _| {}).await?;
            Some(Arc::new(open::generation_of(volume, h, cache).await?))
        }
        None => None,
    };
    let mut files: HashMap<u64, Known> = HashMap::new();
    if let Some(g) = &generation {
        let index = raft5fs_search::index::Index::new(
            Some(Arc::clone(g)),
            view::View::new(loaded.entries.values().cloned()),
        );
        for row in index.rows() {
            files.insert(row.ino, Known::of_row(&row));
        }
    }
    for e in loaded.entries.values() {
        match e {
            Entry::Record(r) => {
                files.insert(r.ino, Known::of_record(r));
            }
            Entry::Gone { ino, .. } => {
                files.remove(ino);
            }
            Entry::Moved { ino, path, .. } => {
                if let Some(k) = files.get_mut(ino) {
                    k.path.clone_from(path);
                }
            }
        }
    }
    let by_path = files
        .iter()
        .map(|(&ino, k)| (k.path.clone(), ino))
        .collect();
    let mut pass = Pass {
        vault,
        volume,
        tools,
        config,
        dir: loaded.dir,
        mine,
        files,
        recent: loaded.entries,
        generation,
        header: loaded.header,
        listing: loaded.files,
        others,
        by_path,
        pending: Vec::new(),
        pending_bytes: 0,
        pending_thumbs: Vec::new(),
        queued: Vec::new(),
        listings: HashMap::new(),
        authors: HashMap::new(),
        stats: PassStats::default(),
        progress,
        told: Instant::now(),
        segment_files: loaded.keys.len(),
        alive,
    };
    pass.mine.user = vault.remote().username().to_string();
    pass.mine.device = config.device.clone();
    pass.mine.model = tools.model().to_string();
    if claimed {
        pass.retire_due().await?;
    }
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
        pass.authors = authors_of(&log);
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
                let Some(r) = pass.files.get(&ino).cloned() else {
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
            // Files the log says nothing new about, which this device can
            // do more for than whoever indexed them: vectors a browser
            // left out, a PDF it couldn't read, an older reader's record.
            let behind: Vec<(u64, String)> = pass
                .files
                .iter()
                .filter(|(ino, k)| !seen.contains(*ino) && !pass.embedded_as_now(k))
                .map(|(&ino, k)| (ino, k.path.clone()))
                .collect();
            for (ino, path) in behind {
                // A model that fails now would fail for each of them.
                if pass.stats.model_failed {
                    break;
                }
                match vault.remote().getattr(ino).await {
                    Ok(attr) => pass.upsert(ino, &attr, path).await?,
                    Err(e) if e.errno == errno::ENOENT => pass.gone(ino).await?,
                    Err(e) => return Err(e),
                }
            }
        }
    }
    if full {
        pass.stats.full = true;
        // All the log the server keeps, for who made the files it lists.
        pass.authors = authors_of(&read_log(vault, volume, pass.dir, 0).await?);
        pass.walk().await?;
        cursor = cursor.max(started);
        pass.mine.full_walk_ms = started;
    }
    pass.flush().await?;
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
    if can_compact && pass.compaction_due() {
        #[cfg(not(target_arch = "wasm32"))]
        if config.cache_dir.is_some() {
            pass.compact(so_far.full_walk_ms).await?;
        }
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
    let alive = AtomicU64::new(clock::now_millis());
    // Servers from before claims can't keep two devices apart. Each device
    // writes only its own files, so two at once is still safe: only slower.
    if remote.protocol() < raft5fs_proto::since::SEARCH_INDEX {
        return run_pass(
            vault, volume, id, config, tools, kind, false, &alive, progress,
        )
        .await;
    }
    let claim = remote.claim_index(volume, id, false).await?;
    if !claim.granted {
        return Err(FsError::new(
            errno::EBUSY,
            busy_message(claim.claim.as_ref()),
        ));
    }
    // Gives the claim up however the pass ends: done, failed, or dropped
    // (a device stopping its indexer, a session ending).
    let guard = ClaimGuard {
        remote: Some(Arc::clone(remote)),
        volume,
        id,
    };
    let pass = std::pin::pin!(run_pass(
        vault, volume, id, config, tools, kind, true, &alive, progress
    ));
    // Renews the claim while the pass makes progress. A failed renewal is
    // tried again at the next: at worst, someone else indexes too, which is
    // safe. A pass stuck for `config.stall` is ended, so it can't keep the
    // volume from everyone else.
    let renew = std::pin::pin!(async {
        loop {
            rt::sleep(config.renew).await;
            let quiet = clock::now_millis().saturating_sub(alive.load(Ordering::Relaxed));
            if quiet > config.stall.as_millis() as u64 {
                return Err(FsError::new(
                    errno::ETIMEDOUT,
                    format!(
                        "the pass made no progress for {} minutes, so it stopped",
                        quiet / 60_000
                    ),
                ));
            }
            let _ = remote.claim_index(volume, id, false).await;
        }
    });
    let stats = match futures_util::future::select(pass, renew).await {
        futures_util::future::Either::Left((stats, _)) => stats,
        futures_util::future::Either::Right((stuck, _)) => stuck,
    };
    guard.release().await;
    stats
}

/// Why a volume can't be indexed now: someone else's claim, and when it
/// runs out if its holder stops renewing it.
fn busy_message(claim: Option<&raft5fs_proto::types::PruneClaim>) -> String {
    let Some(c) = claim else {
        return "this volume is being indexed elsewhere".into();
    };
    let left = c.expires_ms.saturating_sub(clock::now_millis());
    format!(
        "this volume is being indexed elsewhere by {}; their claim runs out in {} \
         minutes unless they renew it (a pass renews it while it runs)",
        c.user,
        left.div_ceil(60_000).max(1)
    )
}

/// A claim on a volume's indexing, given up when it drops. Dropped without
/// `release` (the pass's future dropped), it gives the claim up in the
/// background, if it can.
struct ClaimGuard {
    /// `None` once given up.
    remote: Option<Arc<Remote>>,
    volume: u64,
    id: IndexerId,
}

impl ClaimGuard {
    async fn release(mut self) {
        if let Some(remote) = self.remote.take() {
            let _ = remote.claim_index(self.volume, self.id, true).await;
        }
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        let Some(remote) = self.remote.take() else {
            return;
        };
        let (volume, id) = (self.volume, self.id);
        rt::spawn_if_running(async move {
            let _ = remote.claim_index(volume, id, true).await;
        });
    }
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
    // Records are measured in segments as a pass writes them, so the size
    // counts what compression saves.
    let mut batch = Vec::new();
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
            batch.push(record);
            if batch.len() == SEGMENT_ENTRIES {
                s.index_bytes += encode_segment(&batch).len() as u64;
                batch.clear();
            }
            if told.elapsed() >= Duration::from_secs(1) {
                told = Instant::now();
                progress(&s);
            }
        }
    }
    if !batch.is_empty() {
        s.index_bytes += encode_segment(&batch).len() as u64;
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

/// An indexer running in the background: dropping it stops it, and gives
/// up its claim in the background; `stop` waits for that.
pub struct Indexer {
    handle: AbortHandle,
    kick: Arc<Notify>,
    status: Arc<Mutex<IndexStatus>>,
    remote: Arc<Remote>,
    id: IndexerId,
}

impl Indexer {
    /// Looks for work now, as after a write.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    pub fn status(&self) -> IndexStatus {
        self.status.lock().unwrap().clone()
    }

    /// Stops it, and gives up the claim of the volume it was indexing, if
    /// any: before a session ends, so another device needn't wait for the
    /// claim to run out.
    pub async fn stop(self) {
        self.handle.abort();
        let current = self.status.lock().unwrap().current.as_ref().map(|c| c.0);
        if let Some(volume) = current {
            let _ = self.remote.claim_index(volume, self.id, true).await;
        }
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
    let remote = Arc::clone(vault.remote());
    let id = new_id();
    let handle = rt::spawn(run(
        vault,
        config,
        tools,
        id,
        Arc::clone(&kick),
        Arc::clone(&status),
    ));
    Indexer {
        handle,
        kick,
        status,
        remote,
        id,
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
    id: IndexerId,
    kick: Arc<Notify>,
    status: Arc<Mutex<IndexStatus>>,
) {
    // Without claims, devices would all index every volume at once.
    if vault.remote().protocol() < raft5fs_proto::since::SEARCH_INDEX {
        status.lock().unwrap().error =
            Some("the servers are too old to share indexing: update them".into());
        return;
    }
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
                // A model that failed: try again later, not each minute.
                Ok(stats) if stats.model_failed => {
                    s.last.insert(volume, describe(&stats));
                    let wait = retry
                        .get(&volume)
                        .map_or(config.backoff, |(_, w)| (*w * 2).min(config.max_backoff));
                    retry.insert(volume, (Instant::now() + wait, wait));
                }
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
