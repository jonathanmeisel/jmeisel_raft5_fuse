//! Tests search indexing against real servers: passes over a volume, by a
//! walk and by the activity log; claims and hand-offs between devices; the
//! owner's switch; and the hidden index folder.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::indexer::open::{self, Opened};
use raft5fs_client::indexer::{
    BuiltIn, Embed, IndexerConfig, MemoryCache, PassKind, PassStats, SegmentCache, Tools,
    index_claimed, indexable_volumes, new_id,
};
use raft5fs_client::remote::Remote;
use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_client::vault::{VIRTUAL_ROOT, Vault};
use raft5fs_proto::errno;
use raft5fs_search::INDEX_DIR;
use raft5fs_search::manifest::{IndexerId, Manifest};
use raft5fs_search::view::{Hit, QueryVector};
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, credentials, fs_tls};

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

fn vault(backend: &Backend, user: &str) -> Vault {
    let remote = backend
        .runtime
        .block_on(Remote::connect(
            &backend.addresses(),
            credentials(user),
            Some(fs_tls()),
        ))
        .unwrap_or_else(|e| panic!("log in as {user}: {e}"));
    let vault = Vault::new(Arc::new(remote)).unwrap();
    if user != TESTER {
        vault
            .known_keys()
            .check(TESTER, &backend.tester_key)
            .unwrap();
    }
    vault
}

fn write(backend: &Backend, vault: &Vault, dir: u64, name: &str, body: &[u8]) -> u64 {
    let rt = &backend.runtime;
    let ino = rt
        .block_on(vault.create(dir, OsStr::new(name), 0o644))
        .unwrap()
        .ino;
    rt.block_on(vault.write(ino, 0, body)).unwrap();
    ino
}

fn pass(
    backend: &Backend,
    vault: &Vault,
    volume: u64,
    id: IndexerId,
    kind: PassKind,
) -> Result<PassStats, raft5fs_proto::types::FsError> {
    pass_with(backend, vault, volume, id, kind, &Tools::words_only())
}

fn pass_with(
    backend: &Backend,
    vault: &Vault,
    volume: u64,
    id: IndexerId,
    kind: PassKind,
    tools: &Tools,
) -> Result<PassStats, raft5fs_proto::types::FsError> {
    let config = IndexerConfig {
        pace: std::time::Duration::ZERO,
        ..IndexerConfig::default()
    };
    backend.runtime.block_on(index_claimed(
        vault,
        volume,
        id,
        &config,
        tools,
        kind,
        &mut |_| {},
    ))
}

/// A folder of this test's own, for a device's cache.
fn cache_dir() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("raft5fs-index-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A pass by a device that compacts as soon as there is anything, and
/// keeps what a compaction replaced for no time at all.
fn compacting(
    backend: &Backend,
    vault: &Vault,
    volume: u64,
    id: IndexerId,
    tools: &Tools,
    cache: &std::path::Path,
) -> Result<PassStats, raft5fs_proto::types::FsError> {
    let config = IndexerConfig {
        pace: std::time::Duration::ZERO,
        compact_min: 1,
        grace: std::time::Duration::ZERO,
        cache_dir: Some(cache.to_path_buf()),
        ..IndexerConfig::default()
    };
    backend.runtime.block_on(index_claimed(
        vault,
        volume,
        id,
        &config,
        tools,
        PassKind::Auto,
        &mut |_| {},
    ))
}

/// `volume`'s index, open, kept in `cache`.
fn opened_in(
    backend: &Backend,
    vault: &Vault,
    volume: u64,
    cache: Arc<dyn SegmentCache>,
) -> Option<Opened> {
    backend
        .runtime
        .block_on(open::open(vault, volume, cache, &mut |_, _| {}))
        .unwrap()
}

/// `volume`'s index, open, read afresh.
fn opened(backend: &Backend, vault: &Vault, volume: u64) -> Option<Opened> {
    opened_in(backend, vault, volume, Arc::new(MemoryCache::default()))
}

/// What a search of `volume` for `query` finds, best first; with `vector`
/// (model and values), by meaning too.
fn hits(
    backend: &Backend,
    vault: &Vault,
    volume: u64,
    query: &str,
    vector: Option<(&str, &[f32])>,
) -> Vec<Hit> {
    let index = opened(backend, vault, volume).expect("the volume has an index");
    let q = vector.map(|(model, values)| QueryVector { model, values });
    backend
        .runtime
        .block_on(open::search(&[&index], query, q, None, 10, None))
        .into_iter()
        .map(|h| h.1)
        .collect()
}

/// The paths that a search of `volume`'s index for `query` finds, best
/// first.
fn search(backend: &Backend, vault: &Vault, volume: u64, query: &str) -> Vec<String> {
    hits(backend, vault, volume, query, None)
        .into_iter()
        .map(|h| h.path)
        .collect()
}

const GPX: &str = r#"<gpx><trk><name>Kingdom Trails 40k</name><type>cycling</type>
  <trkseg><trkpt lat="44.5" lon="-72"/><trkpt lat="44.51" lon="-72"/></trkseg></trk></gpx>"#;

/// A volume "v" of the tester's with a few files. Returns it and the inode
/// of `notes`.
fn volume(backend: &Backend, tester: &Vault) -> (u64, u64) {
    let rt = &backend.runtime;
    let v = rt
        .block_on(tester.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let notes = rt
        .block_on(tester.mkdir(v, OsStr::new("notes"), 0o755))
        .unwrap()
        .ino;
    write(
        backend,
        tester,
        notes,
        "tax.txt",
        b"receipts for the tax return, due in April, kept in the blue folder",
    );
    write(backend, tester, v, "ride.gpx", GPX.as_bytes());
    write(backend, tester, v, "photo.jpg", b"\xFF\xD8\xFF not text");
    (v, notes)
}

#[test]
fn a_first_pass_walks_and_search_finds_text_tracks_and_names() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let stats = pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    assert!(stats.full, "a first pass walks");
    assert_eq!(stats.indexed, 3);
    assert!(stats.failed.is_empty(), "{:?}", stats.failed);

    assert_eq!(search(&backend, &tester, v, "tax"), ["notes/tax.txt"]);
    assert_eq!(search(&backend, &tester, v, "bike ride"), ["ride.gpx"]);
    // No text, but found by its name.
    assert_eq!(search(&backend, &tester, v, "photo"), ["photo.jpg"]);
    // The index's own files are never indexed, nor shown as activity.
    assert!(search(&backend, &tester, v, "manifest").is_empty());
    let lines = backend
        .runtime
        .block_on(tester.activity(v, &[], 200))
        .unwrap()
        .lines;
    assert!(!lines.is_empty());
    for line in lines {
        let name = line.name.unwrap_or_default();
        assert!(!name.contains(INDEX_DIR), "{name} shows as activity");
    }

    // A second pass at once has nothing to do.
    let stats = pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    assert!(!stats.full);
    assert_eq!((stats.indexed, stats.moved, stats.gone), (0, 0, 0));
}

#[test]
fn log_passes_find_changes_without_a_walk() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, notes) = volume(&backend, &tester);
    let other = rt
        .block_on(tester.create_volume(OsStr::new("other"), 0o755))
        .unwrap()
        .ino;
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();

    // A new file, a rename, a delete, and a move out of the volume.
    write(&backend, &tester, v, "plan.md", b"vermont gravel weekend");
    rt.block_on(tester.rename(
        notes,
        OsStr::new("tax.txt"),
        v,
        OsStr::new("taxes.txt"),
        false,
    ))
    .unwrap();
    rt.block_on(tester.unlink(v, OsStr::new("photo.jpg")))
        .unwrap();
    rt.block_on(tester.rename(
        v,
        OsStr::new("ride.gpx"),
        other,
        OsStr::new("ride.gpx"),
        false,
    ))
    .unwrap();

    let stats = pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    assert!(!stats.full, "the log said what changed");
    assert_eq!((stats.indexed, stats.moved, stats.gone), (1, 1, 2));
    assert_eq!(search(&backend, &tester, v, "vermont"), ["plan.md"]);
    assert_eq!(search(&backend, &tester, v, "tax"), ["taxes.txt"]);
    assert!(search(&backend, &tester, v, "photo").is_empty());
    assert!(search(&backend, &tester, v, "kingdom").is_empty());
}

#[test]
fn an_edit_the_log_does_not_note_again_is_still_found() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let f = write(&backend, &tester, v, "draft.txt", b"first words");
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    // The log noted the first edit; this one, minutes later at most, it
    // does not.
    rt.block_on(tester.write(f, 0, b"second thoughts")).unwrap();
    let stats = pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    assert!(!stats.full);
    assert_eq!(stats.indexed, 1);
    assert_eq!(search(&backend, &tester, v, "thoughts"), ["draft.txt"]);
}

#[test]
fn a_folder_moved_makes_a_pass_walk() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    rt.block_on(tester.rename(v, OsStr::new("notes"), v, OsStr::new("papers"), false))
        .unwrap();
    let stats = pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    assert!(stats.full);
    assert_eq!(stats.moved, 1);
    assert_eq!(search(&backend, &tester, v, "tax"), ["papers/tax.txt"]);
}

#[test]
fn a_claim_keeps_another_device_off_and_the_next_goes_on_from_the_last() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("carol");
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    rt.block_on(tester.grant(v, "carol", true, OsStr::new("v")))
        .unwrap();
    let carol = vault(&backend, "carol");

    // While the tester's device holds the claim, carol's can't index.
    let mine = new_id();
    assert!(
        rt.block_on(tester.remote().claim_index(v, mine, false))
            .unwrap()
            .granted
    );
    let busy = pass(&backend, &carol, v, new_id(), PassKind::Auto).unwrap_err();
    assert_eq!(busy.errno, errno::EBUSY);
    rt.block_on(tester.remote().claim_index(v, mine, true))
        .unwrap();

    // The tester indexes; then carol's device goes on from there, and
    // finds only what is new.
    pass(&backend, &tester, v, mine, PassKind::Auto).unwrap();
    write(&backend, &tester, v, "new.txt", b"fresh");
    let stats = pass(&backend, &carol, v, new_id(), PassKind::Auto).unwrap();
    assert!(!stats.full);
    assert_eq!(stats.indexed, 1);
    assert_eq!(search(&backend, &carol, v, "fresh"), ["new.txt"]);
}

#[test]
fn only_writers_claim_and_only_the_owner_turns_indexing_off() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("carol");
    backend.enrol("dave");
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, notes) = volume(&backend, &tester);
    rt.block_on(tester.grant(v, "carol", true, OsStr::new("v")))
        .unwrap();
    rt.block_on(tester.grant(v, "dave", false, OsStr::new("v")))
        .unwrap();
    rt.block_on(tester.grant(notes, "carol", true, OsStr::new("notes")))
        .ok();
    let carol = vault(&backend, "carol");
    let dave = vault(&backend, "dave");

    let refused = rt
        .block_on(dave.remote().claim_index(v, new_id(), false))
        .unwrap_err();
    assert_eq!(refused.errno, errno::EROFS, "{refused}");
    assert!(rt.block_on(indexable_volumes(&dave)).unwrap().is_empty());
    // A folder inside a volume isn't indexed on its own.
    let refused = rt
        .block_on(tester.remote().claim_index(notes, new_id(), false))
        .unwrap_err();
    assert_eq!(refused.errno, errno::EINVAL);

    // Carol writes it but doesn't own it.
    let refused = rt
        .block_on(carol.remote().set_volume_indexing(v, false))
        .unwrap_err();
    assert_eq!(refused.errno, errno::EPERM);

    rt.block_on(tester.remote().set_volume_indexing(v, false))
        .unwrap();
    assert!(
        rt.block_on(tester.remote().get_volume(v))
            .unwrap()
            .indexing_off
    );
    assert!(!rt.block_on(indexable_volumes(&carol)).unwrap().contains(&v));
    let refused = pass(&backend, &carol, v, new_id(), PassKind::Auto).unwrap_err();
    assert_eq!(refused.errno, errno::EPERM);

    rt.block_on(tester.remote().set_volume_indexing(v, true))
        .unwrap();
    assert!(rt.block_on(indexable_volumes(&carol)).unwrap().contains(&v));
    assert!(
        pass(&backend, &carol, v, new_id(), PassKind::Auto)
            .unwrap()
            .full
    );
}

#[test]
fn a_session_hides_the_index_and_keeps_its_name() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let mut config = SessionConfig::new(backend.addresses(), credentials(TESTER));
    config.tls = Some(fs_tls());
    let session: Arc<Session> = backend.runtime.block_on(Session::open(config)).unwrap();
    let rt = &backend.runtime;
    let v = rt
        .block_on(session.mkdir(VIRTUAL_ROOT, OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let tester = vault(&backend, TESTER);
    write(&backend, &tester, v, "a.txt", b"words");
    pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();

    let names: Vec<_> = rt
        .block_on(session.children(v))
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert_eq!(names, ["a.txt"]);
    let name = OsStr::new(INDEX_DIR);
    assert_eq!(
        rt.block_on(session.lookup(v, name)).unwrap_err().errno,
        errno::ENOENT
    );
    assert_eq!(
        rt.block_on(session.mkdir(v, name, 0o755))
            .unwrap_err()
            .errno,
        errno::EPERM
    );
    assert_eq!(
        rt.block_on(session.create(v, name, 0o644))
            .unwrap_err()
            .errno,
        errno::EPERM
    );
    assert_eq!(
        rt.block_on(session.rename(v, OsStr::new("a.txt"), v, name, false))
            .unwrap_err()
            .errno,
        errno::EPERM
    );
    assert_eq!(
        rt.block_on(session.rmdir(v, name)).unwrap_err().errno,
        errno::ENOENT
    );
}

#[test]
fn a_session_indexes_in_the_background() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let mut config = SessionConfig::new(backend.addresses(), credentials(TESTER));
    config.tls = Some(fs_tls());
    let index = IndexerConfig {
        poll: std::time::Duration::from_millis(200),
        pace: std::time::Duration::ZERO,
        device: "test".into(),
        ..IndexerConfig::default()
    };
    config.index = Some((index, Tools::words_only()));
    let session: Arc<Session> = backend.runtime.block_on(Session::open(config)).unwrap();
    let rt = &backend.runtime;
    let v = rt
        .block_on(session.mkdir(VIRTUAL_ROOT, OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let tester = vault(&backend, TESTER);
    write(&backend, &tester, v, "first.txt", b"background words");
    let found = |query: &str| {
        opened(&backend, &tester, v).is_some() && !search(&backend, &tester, v, query).is_empty()
    };
    let wait_for = |query: &str| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !found(query) {
            assert!(
                std::time::Instant::now() < deadline,
                "{query} never indexed: {:?}",
                session.index_status()
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    wait_for("background");
    // A later change is found by a pass that follows the log.
    write(&backend, &tester, v, "second.txt", b"later words");
    wait_for("later");
    let status = session.index_status().unwrap();
    assert!(status.last.contains_key(&v), "{status:?}");
    rt.block_on(session.shutdown());
}

/// An embedder for tests: each word sets one of 16 dimensions, so texts
/// that share words are close. Fails on purpose while `broken` is set.
struct Fake {
    model: &'static str,
    /// The models it supersedes.
    replaces: &'static [&'static str],
    broken: std::sync::atomic::AtomicBool,
}

impl Fake {
    fn new(model: &'static str) -> Arc<Self> {
        Self::replacing(model, &[])
    }

    fn replacing(model: &'static str, replaces: &'static [&'static str]) -> Arc<Self> {
        Arc::new(Self {
            model,
            replaces,
            broken: false.into(),
        })
    }

    fn vector(text: &str) -> Vec<f32> {
        let mut v = vec![0f32; 16];
        for word in raft5fs_search::text::terms(text) {
            let h = word
                .bytes()
                .fold(7u32, |h, b| h.wrapping_mul(31).wrapping_add(b.into()));
            v[(h % 16) as usize] += 1.0;
        }
        raft5fs_search::vector::normalize(&mut v);
        v
    }
}

type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl Embed for Fake {
    fn model(&self) -> &str {
        self.model
    }

    fn replaces(&self, older: &str) -> bool {
        self.replaces.contains(&older)
    }

    fn passages<'a>(&'a self, texts: Vec<String>) -> Boxed<'a, Result<Vec<Vec<f32>>, String>> {
        Box::pin(async move {
            if self.broken.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("the model is broken".into());
            }
            Ok(texts.iter().map(|t| Self::vector(t)).collect())
        })
    }

    fn query<'a>(&'a self, text: &'a str) -> Boxed<'a, Result<Vec<f32>, String>> {
        Box::pin(async move { Ok(Self::vector(text)) })
    }
}

fn tools(embed: &Arc<Fake>) -> Tools {
    Tools {
        extract: Arc::new(BuiltIn),
        embed: Some(Arc::clone(embed) as Arc<dyn Embed>),

        image: None,
    }
}

/// The models named by `volume`'s live records with text long enough to
/// embed.
fn models(backend: &Backend, vault: &Vault, volume: u64) -> Vec<String> {
    let index = opened(backend, vault, volume).unwrap().index;
    let mut out: Vec<String> = index
        .rows()
        .into_iter()
        .filter(|r| r.embeddable)
        .map(|r| r.model)
        .chain(
            index
                .recent
                .live_records()
                .filter(|r| {
                    r.chunks
                        .iter()
                        .any(|c| c.len >= raft5fs_search::view::MIN_MEANING_WORDS)
                })
                .map(|r| r.model.clone()),
        )
        .collect();
    out.sort();
    out
}

#[test]
fn chunks_get_vectors_and_a_new_model_embeds_again() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let first = Fake::new("fake@1");
    let id = new_id();
    pass_with(&backend, &tester, v, id, PassKind::Auto, &tools(&first)).unwrap();
    assert_eq!(models(&backend, &tester, v), ["fake@1", "fake@1"]);

    // Searched by meaning: the query's words aren't in the file, but its
    // vector (from the fake model) is the file's.
    let q = Fake::vector("receipts for the tax return, due in April, kept in the blue folder");
    let found = hits(&backend, &tester, v, "quittungen", Some(("fake@1", &q)));
    assert_eq!(found[0].path, "notes/tax.txt");

    // A new model that supersedes it: a walk embeds the two text files
    // again, not the photo.
    let second = Fake::replacing("fake@2", &["fake@1"]);
    let stats = pass_with(&backend, &tester, v, id, PassKind::Full, &tools(&second)).unwrap();
    assert_eq!(stats.indexed, 2);
    assert_eq!(models(&backend, &tester, v), ["fake@2", "fake@2"]);
    // A device still on the old model doesn't know the new one: it leaves
    // those records alone, so the two don't undo each other's work.
    let stats = pass_with(
        &backend,
        &tester,
        v,
        new_id(),
        PassKind::Full,
        &tools(&first),
    )
    .unwrap();
    assert_eq!(stats.indexed, 0);
    assert_eq!(models(&backend, &tester, v), ["fake@2", "fake@2"]);
    // Nor does another model that doesn't say it supersedes this one.
    let other = Fake::new("other@1");
    let stats = pass_with(
        &backend,
        &tester,
        v,
        new_id(),
        PassKind::Full,
        &tools(&other),
    )
    .unwrap();
    assert_eq!(stats.indexed, 0);
    // A device with no model leaves the vectors alone.
    let stats = pass(&backend, &tester, v, new_id(), PassKind::Full).unwrap();
    assert_eq!(stats.indexed, 0);
}

#[test]
fn a_model_that_fails_is_tried_again() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let fake = Fake::new("fake@1");
    fake.broken.store(true, std::sync::atomic::Ordering::SeqCst);
    let id = new_id();
    let stats = pass_with(&backend, &tester, v, id, PassKind::Auto, &tools(&fake)).unwrap();
    // Asked once: after it fails, the pass stops asking it.
    assert!(stats.model_failed);
    assert_eq!(stats.failed.len(), 1, "{:?}", stats.failed);
    // Still found by words.
    assert_eq!(search(&backend, &tester, v, "tax"), ["notes/tax.txt"]);
    assert_eq!(models(&backend, &tester, v), ["", ""]);
    fake.broken
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let stats = pass_with(&backend, &tester, v, id, PassKind::Full, &tools(&fake)).unwrap();
    assert_eq!((stats.indexed, stats.failed.len()), (2, 0));
    assert_eq!(models(&backend, &tester, v), ["fake@1", "fake@1"]);
}

/// A segment cache in memory that counts what it is asked.
#[derive(Default)]
struct Kept {
    pieces: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    hits: std::sync::atomic::AtomicUsize,
}

impl raft5fs_client::indexer::SegmentCache for Kept {
    fn get<'a>(&'a self, key: &'a str) -> Boxed<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let got = self.pieces.lock().unwrap().get(key).cloned();
            if got.is_some() {
                self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            got
        })
    }

    fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> Boxed<'a, ()> {
        Box::pin(async move {
            self.pieces
                .lock()
                .unwrap()
                .insert(key.into(), bytes.to_vec());
        })
    }

    fn keep_only<'a>(&'a self, volume: u64, keys: &'a [String]) -> Boxed<'a, ()> {
        Box::pin(async move {
            let prefix = format!("{volume}/");
            self.pieces
                .lock()
                .unwrap()
                .retain(|k, _| !k.starts_with(&prefix) || keys.contains(k));
        })
    }
}

#[test]
fn a_second_read_fetches_only_new_segments() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    let kept = Arc::new(Kept::default());
    let first = opened_in(&backend, &tester, v, kept.clone()).unwrap();
    let pieces = kept.pieces.lock().unwrap().len();
    assert!(pieces >= 1);
    assert_eq!(kept.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    write(&backend, &tester, v, "new.txt", b"fresh");
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    let again = rt
        .block_on(open::refresh(&tester, first, &mut |_, _| {}))
        .unwrap()
        .unwrap();
    let found = rt.block_on(open::search(&[&again], "fresh", None, None, 5, None));
    assert_eq!(found[0].1.path, "new.txt");
    // Only the new segment was read; the old ones weren't asked again.
    assert_eq!(kept.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(kept.pieces.lock().unwrap().len(), pieces + 1);
    assert_eq!(again.index.len(), 4);
}

/// Reads "PDFs" as plain text, to stand in for a device with a PDF reader.
struct PdfToo;

impl raft5fs_client::indexer::Extract for PdfToo {
    fn reads(&self, name: &str) -> u64 {
        if name.ends_with(".pdf") {
            1 << 20
        } else {
            BuiltIn.reads(name)
        }
    }

    fn extract<'a>(
        &'a self,
        name: &'a str,
        bytes: Vec<u8>,
    ) -> Boxed<'a, Option<raft5fs_search::extract::Extracted>> {
        Box::pin(async move {
            if !name.ends_with(".pdf") {
                return BuiltIn.extract(name, bytes).await;
            }
            Some(raft5fs_search::extract::Extracted {
                kind: raft5fs_search::record::DocKind::Text,
                text: String::from_utf8(bytes).ok()?,
                extra: raft5fs_search::record::Extra {
                    reader: raft5fs_search::extract::READER,
                    ..Default::default()
                },
                thumb: None,
            })
        })
    }
}

#[test]
fn a_file_one_device_could_not_read_is_read_by_one_that_can() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    write(
        &backend,
        &tester,
        v,
        "scan.pdf",
        b"insurance policy renewal",
    );
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    assert!(search(&backend, &tester, v, "insurance").is_empty());
    // A device that reads PDFs fills it in at its next walk; the rest
    // stays as it was.
    let reads_pdf = Tools {
        extract: Arc::new(PdfToo),
        embed: None,

        image: None,
    };
    let stats = pass_with(&backend, &tester, v, new_id(), PassKind::Full, &reads_pdf).unwrap();
    assert_eq!(stats.indexed, 1);
    assert_eq!(search(&backend, &tester, v, "insurance"), ["scan.pdf"]);
}

/// Reads as `BuiltIn` does, but says it is an older reader.
struct OldReader;

impl raft5fs_client::indexer::Extract for OldReader {
    fn reads(&self, name: &str) -> u64 {
        BuiltIn.reads(name)
    }

    fn extract<'a>(
        &'a self,
        name: &'a str,
        bytes: Vec<u8>,
    ) -> Boxed<'a, Option<raft5fs_search::extract::Extracted>> {
        Box::pin(async move {
            let mut got = BuiltIn.extract(name, bytes).await?;
            got.extra.reader = 1;
            Some(got)
        })
    }
}

#[test]
fn files_read_by_older_readers_are_read_again() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let old = Tools {
        extract: Arc::new(OldReader),
        embed: None,

        image: None,
    };
    pass_with(&backend, &tester, v, new_id(), PassKind::Auto, &old).unwrap();
    // The text file, the track and the photo are read again.
    let stats = pass(&backend, &tester, v, new_id(), PassKind::Full).unwrap();
    assert_eq!(stats.indexed, 3);
    // Once read by these readers, not again.
    let stats = pass(&backend, &tester, v, new_id(), PassKind::Full).unwrap();
    assert_eq!(stats.indexed, 0);
}

/// Gives each photo a "thumbnail" that names it.
struct Thumbs;

impl raft5fs_client::indexer::Extract for Thumbs {
    fn reads(&self, name: &str) -> u64 {
        BuiltIn.reads(name)
    }

    fn extract<'a>(
        &'a self,
        name: &'a str,
        bytes: Vec<u8>,
    ) -> Boxed<'a, Option<raft5fs_search::extract::Extracted>> {
        Box::pin(async move {
            let mut got = BuiltIn.extract(name, bytes).await?;
            if got.kind == raft5fs_search::record::DocKind::Photo {
                got.thumb = Some(format!("thumb of {name}").into_bytes());
            }
            Some(got)
        })
    }
}

#[test]
fn thumbnails_are_kept_beside_their_records_and_read_back() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    write(
        &backend,
        &tester,
        v,
        "beach.jpg",
        b"\xFF\xD8\xFF also not a picture",
    );
    let tools = Tools {
        extract: Arc::new(Thumbs),
        embed: None,

        image: None,
    };
    let id = new_id();
    pass_with(&backend, &tester, v, id, PassKind::Auto, &tools).unwrap();
    let thumb_of = |path: &str| {
        let name = path.rsplit('/').next().unwrap().split('.').next().unwrap();
        let hit = hits(&backend, &tester, v, name, None)
            .into_iter()
            .find(|h| h.path == path)
            .unwrap_or_else(|| panic!("{path} not found"));
        let thumb = hit.thumb.expect("a photo has a thumbnail");
        rt.block_on(raft5fs_client::indexer::read_thumb(&tester, v, &thumb))
            .unwrap()
    };
    assert_eq!(thumb_of("photo.jpg"), b"thumb of photo.jpg");
    assert_eq!(thumb_of("beach.jpg"), b"thumb of beach.jpg");
    // A rename keeps the thumbnail, without reading the photo again.
    rt.block_on(tester.rename(
        v,
        OsStr::new("beach.jpg"),
        v,
        OsStr::new("shore.jpg"),
        false,
    ))
    .unwrap();
    let stats = pass_with(&backend, &tester, v, id, PassKind::Auto, &tools).unwrap();
    assert_eq!((stats.indexed, stats.moved), (0, 1));
    assert_eq!(thumb_of("shore.jpg"), b"thumb of beach.jpg");
}

/// An image model for tests: every picture gets the same vector.
struct FakeImages;

impl raft5fs_client::indexer::ImageEmbed for FakeImages {
    fn model(&self) -> &str {
        "fake-clip@1"
    }

    fn image<'a>(&'a self, _: Vec<u8>) -> Boxed<'a, Result<Option<Vec<f32>>, String>> {
        Box::pin(async { Ok(Some(vec![1.0, 0.0])) })
    }

    fn query<'a>(&'a self, _: &'a str) -> Boxed<'a, Result<Vec<f32>, String>> {
        Box::pin(async { Ok(vec![1.0, 0.0]) })
    }
}

#[test]
fn a_photo_another_device_indexed_gets_its_image_vector_here() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    // A browser's pass: no image model.
    pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    let has_vector = || {
        opened(&backend, &tester, v)
            .unwrap()
            .index
            .has_image_model("fake-clip@1")
    };
    assert!(!has_vector());
    // A device with one fills it in at its next walk, and only the photo.
    let tools = Tools {
        extract: Arc::new(BuiltIn),
        embed: None,
        image: Some(Arc::new(FakeImages)),
    };
    let stats = pass_with(&backend, &tester, v, new_id(), PassKind::Full, &tools).unwrap();
    assert_eq!(stats.indexed, 1);
    assert!(has_vector());
    let stats = pass_with(&backend, &tester, v, new_id(), PassKind::Full, &tools).unwrap();
    assert_eq!(stats.indexed, 0);
}

/// An image model that can't decode anything, as with HEIC on a native
/// device; it counts how often it is asked.
#[derive(Default)]
struct BlindImages {
    asked: std::sync::atomic::AtomicUsize,
}

impl raft5fs_client::indexer::ImageEmbed for BlindImages {
    fn model(&self) -> &str {
        "fake-clip@1"
    }

    fn image<'a>(&'a self, _: Vec<u8>) -> Boxed<'a, Result<Option<Vec<f32>>, String>> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(None) })
    }

    fn query<'a>(&'a self, _: &'a str) -> Boxed<'a, Result<Vec<f32>, String>> {
        Box::pin(async { Ok(vec![1.0, 0.0]) })
    }
}

#[test]
fn a_native_pass_fills_in_what_a_browser_left_out_without_a_walk() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    // The browser's first pass walks the volume, by words only.
    let first = pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    assert!(first.full);
    // A native device's next pass: nothing changed, and no walk is due, but
    // it adds the text and image vectors the browser left out.
    let native = Tools {
        extract: Arc::new(BuiltIn),
        embed: Some(Fake::new("fake@1") as Arc<dyn Embed>),
        image: Some(Arc::new(FakeImages)),
    };
    let id = new_id();
    let stats = pass_with(&backend, &tester, v, id, PassKind::Auto, &native).unwrap();
    assert!(!stats.full, "no walk was due");
    assert_eq!(stats.indexed, 3, "the text file, the track and the photo");
    assert_eq!(models(&backend, &tester, v), ["fake@1", "fake@1"]);
    assert_eq!(
        opened(&backend, &tester, v)
            .unwrap()
            .index
            .photos("fake-clip@1"),
        (1, 1)
    );
    // Then there's nothing more to do.
    let stats = pass_with(&backend, &tester, v, id, PassKind::Auto, &native).unwrap();
    assert_eq!(stats.indexed, 0);
}

#[test]
fn a_photo_the_model_cant_decode_is_tried_once() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let blind = Arc::new(BlindImages::default());
    let tools = Tools {
        extract: Arc::new(BuiltIn),
        embed: None,
        image: Some(Arc::clone(&blind) as Arc<dyn raft5fs_client::indexer::ImageEmbed>),
    };
    let id = new_id();
    pass_with(&backend, &tester, v, id, PassKind::Auto, &tools).unwrap();
    assert_eq!(blind.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    for _ in 0..2 {
        let stats = pass_with(&backend, &tester, v, id, PassKind::Auto, &tools).unwrap();
        assert_eq!(stats.indexed, 0);
    }
    assert_eq!(blind.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    // It counts as a photo, not as one searchable by what it shows.
    assert_eq!(
        opened(&backend, &tester, v)
            .unwrap()
            .index
            .photos("fake-clip@1"),
        (1, 0)
    );
}

#[test]
fn a_model_that_fails_stops_the_pass_asking_it() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    let fake = Fake::new("fake@1");
    fake.broken.store(true, std::sync::atomic::Ordering::SeqCst);
    let stats = pass_with(
        &backend,
        &tester,
        v,
        new_id(),
        PassKind::Auto,
        &tools(&fake),
    )
    .unwrap();
    assert!(stats.model_failed);
    assert_eq!(
        stats.failed.len(),
        1,
        "asked once, then not again: {:?}",
        stats.failed
    );
}

/// The names of the files in `volume`'s index folder, sorted.
fn index_files(backend: &Backend, vault: &Vault, volume: u64) -> Vec<String> {
    let rt = &backend.runtime;
    let dir = rt
        .block_on(vault.lookup(volume, OsStr::new(INDEX_DIR)))
        .unwrap()
        .ino;
    let mut names: Vec<String> = rt
        .block_on(vault.children(dir))
        .unwrap()
        .into_iter()
        .map(|i| i.name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Puts a file in `volume`'s index folder, as another client might.
fn put_index_file(backend: &Backend, vault: &Vault, volume: u64, name: &str, body: &[u8]) {
    let dir = backend
        .runtime
        .block_on(vault.lookup(volume, OsStr::new(INDEX_DIR)))
        .unwrap()
        .ino;
    write(backend, vault, dir, name, body);
}

fn thumbs_tools() -> Tools {
    Tools {
        extract: Arc::new(Thumbs),
        embed: None,
        image: None,
    }
}

fn thumb_of(backend: &Backend, vault: &Vault, volume: u64, path: &str) -> Vec<u8> {
    let rt = &backend.runtime;
    let hit = hits(
        backend,
        vault,
        volume,
        path.split('.').next().unwrap(),
        None,
    )
    .into_iter()
    .find(|h| h.path == path)
    .unwrap_or_else(|| panic!("{path} not found"));
    let thumb = hit.thumb.expect("a photo has a thumbnail");
    rt.block_on(raft5fs_client::indexer::read_thumb(vault, volume, &thumb))
        .unwrap()
}

/// The manifest of indexer `id` in `volume`'s index.
fn manifest_of(backend: &Backend, vault: &Vault, volume: u64, id: &IndexerId) -> Manifest {
    let rt = &backend.runtime;
    let dir = rt
        .block_on(vault.lookup(volume, OsStr::new(INDEX_DIR)))
        .unwrap()
        .ino;
    let ino = rt
        .block_on(vault.lookup(dir, OsStr::new(&Manifest::file_name(id))))
        .unwrap()
        .ino;
    let size = rt.block_on(vault.remote().getattr(ino)).unwrap().size;
    let bytes = rt.block_on(vault.read(ino, 0, size as usize)).unwrap();
    raft5fs_search::manifest::decode_manifest(&bytes).unwrap()
}

#[test]
fn a_compaction_writes_one_generation_that_searches_the_same() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    for name in ["p1.jpg", "p2.jpg", "p3.jpg"] {
        write(&backend, &tester, v, name, b"\xFF\xD8\xFF not a picture");
    }
    let tools = thumbs_tools();
    let (a, b) = (new_id(), new_id());
    let stats = pass_with(&backend, &tester, v, a, PassKind::Auto, &tools).unwrap();
    assert!(!stats.compacted, "a small index stays in recent segments");
    // Another device sees three photos go and one renamed, and compacts.
    for name in ["p1.jpg", "p2.jpg", "p3.jpg"] {
        rt.block_on(tester.unlink(v, OsStr::new(name))).unwrap();
    }
    rt.block_on(tester.rename(
        v,
        OsStr::new("photo.jpg"),
        v,
        OsStr::new("shore.jpg"),
        false,
    ))
    .unwrap();
    let cache = cache_dir();
    let stats = compacting(&backend, &tester, v, b, &tools, &cache).unwrap();
    assert!(stats.compacted, "{stats:?}");
    let m = manifest_of(&backend, &tester, v, &b);
    let generation = m.generation.expect("the manifest names its generation");
    assert!(m.segments.is_empty());
    let files = index_files(&backend, &tester, v);
    assert!(files.contains(&raft5fs_search::generation::head_name(&generation)));
    assert!(!files.contains(&Manifest::file_name(&a)), "{files:?}");
    // What it replaced stays, retired, for readers part-way through it.
    assert!(
        m.retired
            .iter()
            .any(|(name, _)| name == &Manifest::segment_name(&a, 0))
    );
    assert!(files.contains(&Manifest::segment_name(&a, 0)));

    assert_eq!(search(&backend, &tester, v, "receipts"), ["notes/tax.txt"]);
    assert_eq!(search(&backend, &tester, v, "kingdom"), ["ride.gpx"]);
    assert!(search(&backend, &tester, v, "p1").is_empty());
    assert_eq!(
        thumb_of(&backend, &tester, v, "shore.jpg"),
        b"thumb of photo.jpg"
    );
    let index = opened(&backend, &tester, v).unwrap();
    assert!(
        index.progress.full_walk_ms > 0,
        "how far indexing got is kept"
    );
    assert_eq!(index.index.len(), 3);

    // The first device goes on, in recent segments over the generation.
    write(
        &backend,
        &tester,
        v,
        "later.txt",
        b"written after the compaction",
    );
    let stats = pass_with(&backend, &tester, v, a, PassKind::Auto, &tools).unwrap();
    assert_eq!(stats.indexed, 1);
    assert_eq!(search(&backend, &tester, v, "compaction"), ["later.txt"]);
    assert_eq!(search(&backend, &tester, v, "receipts"), ["notes/tax.txt"]);

    // The next compaction deletes what the first retired, and folds the
    // new file in.
    let stats = compacting(&backend, &tester, v, b, &tools, &cache).unwrap();
    assert!(stats.compacted);
    let files = index_files(&backend, &tester, v);
    assert!(!files.contains(&Manifest::segment_name(&a, 0)), "{files:?}");
    let old_head = raft5fs_search::generation::head_name(&generation);
    let m = manifest_of(&backend, &tester, v, &b);
    assert!(m.retired.iter().any(|(name, _)| *name == old_head));
    // The pass after deletes the first generation it retired.
    compacting(&backend, &tester, v, b, &tools, &cache).unwrap();
    assert!(!index_files(&backend, &tester, v).contains(&old_head));
    assert_eq!(search(&backend, &tester, v, "compaction"), ["later.txt"]);
    assert_eq!(
        thumb_of(&backend, &tester, v, "shore.jpg"),
        b"thumb of photo.jpg"
    );
    std::fs::remove_dir_all(cache).unwrap();
}

#[test]
fn a_refresh_reads_new_segments_and_a_compaction_switches_the_generation() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, notes) = volume(&backend, &tester);
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    let kept = Arc::new(Kept::default());
    let first = opened_in(&backend, &tester, v, kept.clone()).unwrap();
    assert!(first.header.is_none());
    assert_eq!(first.index.len(), 3);
    write(&backend, &tester, v, "new.txt", b"fresh");
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    let refresh = |o: Opened| {
        rt.block_on(open::refresh(&tester, o, &mut |_, _| {}))
            .unwrap()
            .unwrap()
    };
    let second = refresh(first);
    assert_eq!(second.index.len(), 4);
    // A compaction: the next refresh reads the new generation, and the
    // cache lets go of what's gone.
    rt.block_on(tester.unlink(notes, OsStr::new("tax.txt")))
        .unwrap();
    rt.block_on(tester.unlink(v, OsStr::new("ride.gpx")))
        .unwrap();
    let cache = cache_dir();
    assert!(
        compacting(&backend, &tester, v, id, &Tools::words_only(), &cache)
            .unwrap()
            .compacted
    );
    let third = refresh(second);
    assert!(third.header.is_some());
    assert_eq!(third.index.len(), 2);
    let mut cached: Vec<String> = kept.pieces.lock().unwrap().keys().cloned().collect();
    let mut keys = third.keys();
    cached.sort();
    keys.sort();
    assert_eq!(cached, keys);
    // New files after it come in recent segments, on the same generation.
    write(&backend, &tester, v, "later.txt", b"later words");
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    let fourth = refresh(third);
    assert_eq!(
        fourth.header.as_ref().map(|h| h.id),
        fourth.header.as_ref().map(|h| h.id)
    );
    assert_eq!(fourth.index.len(), 3);
    let found = rt.block_on(open::search(&[&fourth], "later", None, None, 5, None));
    assert_eq!(found[0].1.path, "later.txt");
    std::fs::remove_dir_all(cache).unwrap();
}

#[test]
fn a_segment_a_pass_left_unlisted_is_written_over() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    // A pass cut short after it wrote its next segment, before its manifest.
    put_index_file(
        &backend,
        &tester,
        v,
        &Manifest::segment_name(&id, 1),
        b"half",
    );
    write(&backend, &tester, v, "new.txt", b"fresh");
    let stats = pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    assert_eq!(stats.indexed, 1);
    assert_eq!(search(&backend, &tester, v, "fresh"), ["new.txt"]);
}

#[test]
fn an_index_with_a_file_it_cant_read_is_not_compacted() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, notes) = volume(&backend, &tester);
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    // A manifest from a newer client, say.
    let newer = Manifest::file_name(&new_id());
    put_index_file(&backend, &tester, v, &newer, b"r5mf\x09");
    rt.block_on(tester.unlink(notes, OsStr::new("tax.txt")))
        .unwrap();
    rt.block_on(tester.unlink(v, OsStr::new("ride.gpx")))
        .unwrap();
    let cache = cache_dir();
    let stats = compacting(&backend, &tester, v, id, &Tools::words_only(), &cache).unwrap();
    assert!(!stats.compacted);
    assert!(index_files(&backend, &tester, v).contains(&newer));
    std::fs::remove_dir_all(cache).unwrap();
}

/// An extractor that never finishes a text file: a pass stuck in it.
struct Hangs;

impl raft5fs_client::indexer::Extract for Hangs {
    fn reads(&self, name: &str) -> u64 {
        BuiltIn.reads(name)
    }

    fn extract<'a>(
        &'a self,
        _: &'a str,
        _: Vec<u8>,
    ) -> Boxed<'a, Option<raft5fs_search::extract::Extracted>> {
        Box::pin(std::future::pending())
    }
}

fn hanging() -> Tools {
    Tools {
        extract: Arc::new(Hangs),
        embed: None,
        image: None,
    }
}

/// Whether a device with no claim of its own can claim `volume` now (and
/// gives the claim back if so).
fn claimable(backend: &Backend, vault: &Vault, volume: u64) -> bool {
    let id = new_id();
    let rt = &backend.runtime;
    let granted = rt
        .block_on(vault.remote().claim_index(volume, id, false))
        .unwrap()
        .granted;
    rt.block_on(vault.remote().claim_index(volume, id, true))
        .unwrap();
    granted
}

#[test]
fn a_pass_dropped_midway_gives_up_its_claim() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let tools = hanging();
    let config = IndexerConfig::default();
    let mut told = |_: &PassStats| {};
    rt.block_on(async {
        let pass = index_claimed(
            &tester,
            v,
            new_id(),
            &config,
            &tools,
            PassKind::Auto,
            &mut told,
        );
        // Stuck in a file: dropped after a while, as a stopping device does.
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), pass)
                .await
                .is_err()
        );
        // The claim goes back in the background.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    });
    assert!(claimable(&backend, &tester, v));
}

#[test]
fn a_stopped_indexer_gives_up_its_claim() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let indexer = {
        let _in_runtime = rt.enter();
        let own = Vault::new(Arc::clone(tester.remote())).unwrap();
        raft5fs_client::indexer::spawn(own, IndexerConfig::default(), hanging())
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while indexer.status().current.is_none() {
        assert!(std::time::Instant::now() < deadline, "it never started");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Stuck on a file, so it holds the claim...
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(!claimable(&backend, &tester, v));
    // ...until it stops.
    rt.block_on(indexer.stop());
    assert!(claimable(&backend, &tester, v));
}

#[test]
fn a_pass_stuck_past_the_stall_limit_ends_and_gives_up_its_claim() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let config = IndexerConfig {
        renew: std::time::Duration::from_millis(200),
        stall: std::time::Duration::from_secs(1),
        ..IndexerConfig::default()
    };
    let e = rt
        .block_on(index_claimed(
            &tester,
            v,
            new_id(),
            &config,
            &hanging(),
            PassKind::Auto,
            &mut |_| {},
        ))
        .unwrap_err();
    assert_eq!(e.errno, errno::ETIMEDOUT, "{e}");
    assert!(claimable(&backend, &tester, v));
}

#[test]
fn a_busy_volume_says_when_its_claim_runs_out() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let other = new_id();
    rt.block_on(tester.remote().claim_index(v, other, false))
        .unwrap();
    let e = pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap_err();
    assert_eq!(e.errno, errno::EBUSY);
    let text = e.to_string();
    assert!(text.contains(&format!("by {TESTER}")), "{text}");
    assert!(text.contains("runs out in 10 minutes"), "{text}");
}

/// A model that notes how many passages each call gives it.
#[derive(Default)]
struct Batches(std::sync::Mutex<Vec<usize>>);

impl Embed for Batches {
    fn model(&self) -> &str {
        "batched@1"
    }

    fn passages<'a>(&'a self, texts: Vec<String>) -> Boxed<'a, Result<Vec<Vec<f32>>, String>> {
        self.0.lock().unwrap().push(texts.len());
        Box::pin(async move { Ok(texts.iter().map(|t| Fake::vector(t)).collect()) })
    }

    fn query<'a>(&'a self, text: &'a str) -> Boxed<'a, Result<Vec<f32>, String>> {
        Box::pin(async move { Ok(Fake::vector(text)) })
    }
}

#[test]
fn passages_from_several_files_are_embedded_together() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let v = rt
        .block_on(tester.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    for i in 0..20 {
        let text = format!("note {i}: we rode our bikes along the lake and then home again");
        write(&backend, &tester, v, &format!("n{i}.txt"), text.as_bytes());
    }
    let batches = Arc::new(Batches::default());
    let tools = Tools {
        extract: Arc::new(BuiltIn),
        embed: Some(Arc::clone(&batches) as Arc<dyn Embed>),
        image: None,
    };
    let stats = pass_with(&backend, &tester, v, new_id(), PassKind::Auto, &tools).unwrap();
    assert_eq!((stats.indexed, stats.failed.len()), (20, 0));
    // One call for the first 16 or more passages, and one for the rest.
    let calls = batches.0.lock().unwrap().clone();
    assert!(calls.len() <= 2 && calls[0] >= 16, "{calls:?}");
    assert_eq!(calls.iter().sum::<usize>(), 20);
    assert_eq!(models(&backend, &tester, v), vec!["batched@1"; 20]);
}

#[test]
fn a_pass_over_large_files_stores_them_in_several_segments() {
    let backend = Backend::start(TEST_CHUNK_SIZE, true, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    // Each file has about 400,000 distinct words: some MB of words in its
    // record, so four of them pass a segment's size long before its count.
    for f in 0..4 {
        let text: Vec<String> = (0..400_000).map(|w| format!("w{f}x{w}")).collect();
        write(
            &backend,
            &tester,
            v,
            &format!("big{f}.txt"),
            text.join(" ").as_bytes(),
        );
    }
    pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    let segments = index_files(&backend, &tester, v)
        .into_iter()
        .filter(|n| n.starts_with("recent-"))
        .count();
    assert!(segments >= 2, "{segments} segments");
    assert_eq!(search(&backend, &tester, v, "w3x399999"), ["big3.txt"]);
}

/// The row of the file at `path` in `volume`'s index.
fn row_of(
    backend: &Backend,
    vault: &Vault,
    volume: u64,
    path: &str,
) -> raft5fs_search::generation::Row {
    let index = opened(backend, vault, volume).expect("the volume has an index");
    index
        .index
        .all_rows()
        .into_iter()
        .find(|r| r.path == path)
        .unwrap_or_else(|| panic!("{path} in the index"))
}

#[test]
fn photos_and_tracks_keep_the_facts_filters_read() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    let lisbon = include_bytes!("../../webapp/tests/fixtures/lisbon.jpg");
    write(&backend, &tester, v, "lisbon.jpg", lisbon);
    pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    let photo = row_of(&backend, &tester, v, "lisbon.jpg");
    assert_eq!(photo.meta.camera, "Apple iPhone 13");
    assert_eq!(photo.reader, raft5fs_search::extract::READER);
    let ride = row_of(&backend, &tester, v, "ride.gpx");
    assert_eq!(ride.meta.activity, raft5fs_search::record::Activity::Ride);
}

#[test]
fn who_made_a_file_comes_from_the_log_and_outlasts_edits() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("carol");
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    rt.block_on(tester.grant(v, "carol", true, OsStr::new("v")))
        .unwrap();
    let carol = vault(&backend, "carol");
    let id = new_id();
    pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    let first = row_of(&backend, &tester, v, "ride.gpx");
    assert_eq!(first.meta.added_by, TESTER);
    assert_eq!(first.meta.changed_by, TESTER);
    assert!(first.meta.added_ms > 0);

    // Carol changes the ride; the next pass reads the log, not a walk.
    let ino = rt
        .block_on(tester.lookup(v, OsStr::new("ride.gpx")))
        .unwrap()
        .ino;
    rt.block_on(carol.write(ino, 0, GPX.replace("40k", "41k").as_bytes()))
        .unwrap();
    let stats = pass(&backend, &tester, v, id, PassKind::Auto).unwrap();
    assert!(!stats.full);
    let edited = row_of(&backend, &tester, v, "ride.gpx");
    assert_eq!(edited.meta.added_by, TESTER, "still made by the tester");
    assert_eq!(edited.meta.added_ms, first.meta.added_ms);
    assert_eq!(edited.meta.changed_by, "carol");
}

#[test]
fn a_filtered_search_returns_only_what_the_filter_keeps() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let tester = vault(&backend, TESTER);
    let (v, _) = volume(&backend, &tester);
    pass(&backend, &tester, v, new_id(), PassKind::Auto).unwrap();
    let index = opened(&backend, &tester, v).unwrap();
    let find = |query: &str, filter: &str| -> Vec<String> {
        let (filter, rest) = raft5fs_search::filter::Filter::parse_syntax(filter, 0);
        assert!(rest.is_empty());
        backend
            .runtime
            .block_on(open::search(
                &[&index],
                query,
                None,
                None,
                10,
                Some(&filter),
            ))
            .into_iter()
            .map(|h| h.1.path)
            .collect()
    };
    assert_eq!(find("", "type:track"), ["ride.gpx"]);
    assert_eq!(find("", "activity:ride"), ["ride.gpx"]);
    assert_eq!(find("tax", "in:notes"), ["notes/tax.txt"]);
    assert!(find("tax", "-in:notes").is_empty());
    let mut all = find("", "-type:track");
    all.sort();
    assert_eq!(all, ["notes/tax.txt", "photo.jpg"]);
}
