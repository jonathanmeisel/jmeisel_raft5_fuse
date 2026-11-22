//! Tests search indexing against real servers: passes over a volume, by a
//! walk and by the activity log; claims and hand-offs between devices; the
//! owner's switch; and the hidden index folder.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::indexer::{
    BuiltIn, IndexerConfig, PassKind, PassStats, index_claimed, indexable_volumes, new_id,
    read_index,
};
use raft5fs_client::remote::Remote;
use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_client::vault::{VIRTUAL_ROOT, Vault};
use raft5fs_proto::errno;
use raft5fs_search::INDEX_DIR;
use raft5fs_search::manifest::IndexerId;
use raft5fs_search::view::View;
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
    backend.runtime.block_on(index_claimed(
        vault,
        volume,
        id,
        &IndexerConfig {
            pace: std::time::Duration::ZERO,
            ..IndexerConfig::default()
        },
        &BuiltIn,
        kind,
        &mut |_| {},
    ))
}

/// The paths that a search of `volume`'s index for `query` finds, best
/// first.
fn search(backend: &Backend, vault: &Vault, volume: u64, query: &str) -> Vec<String> {
    let index = backend
        .runtime
        .block_on(read_index(vault, volume))
        .unwrap()
        .expect("the volume has an index");
    View::new(index.entries)
        .search(query, 10)
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
        b"receipts for the tax return",
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
    config.index = Some((index, Arc::new(BuiltIn)));
    let session: Arc<Session> = backend.runtime.block_on(Session::open(config)).unwrap();
    let rt = &backend.runtime;
    let v = rt
        .block_on(session.mkdir(VIRTUAL_ROOT, OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let tester = vault(&backend, TESTER);
    write(&backend, &tester, v, "first.txt", b"background words");
    let found = |query: &str| {
        let index = rt.block_on(read_index(&tester, v)).unwrap();
        index.is_some_and(|i| !View::new(i.entries).search(query, 5).is_empty())
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
