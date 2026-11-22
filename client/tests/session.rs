//! Tests the session alone, with no front end: the part that a mount and a
//! WebDAV server share. They run against a real store and servers, but no
//! kernel, so they run wherever the tests run.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_client::vault::VIRTUAL_ROOT;
use raft5fs_proto::types::Kind;
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, VOLUME, credentials, errno, fs_tls};

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

/// The backend, and a session as `TESTER` with `VOLUME` made in it. Fields
/// drop in order, so the session drops before the servers.
struct Setup {
    session: Arc<Session>,
    volume: u64,
    backend: Backend,
}

impl Setup {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(edit: impl FnOnce(&mut SessionConfig)) -> Self {
        let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
        let session = open(&backend, edit);
        let volume = backend
            .runtime
            .block_on(session.mkdir(VIRTUAL_ROOT, OsStr::new(VOLUME), 0o755))
            .expect("make the test's volume")
            .ino;
        Self {
            session,
            volume,
            backend,
        }
    }

    fn block<F: Future>(&self, fut: F) -> F::Output {
        self.backend.runtime.block_on(fut)
    }
}

fn open(backend: &Backend, edit: impl FnOnce(&mut SessionConfig)) -> Arc<Session> {
    let mut config = SessionConfig::new(backend.addresses(), credentials(TESTER));
    config.tls = Some(fs_tls());
    edit(&mut config);
    backend
        .runtime
        .block_on(Session::open(config))
        .expect("open a session")
}

#[test]
fn buffered_writes_read_back_across_batches() {
    let s = Setup::new();
    let ino = s
        .block(s.session.create(s.volume, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    // Small writes, three chunks in total. They are buffered, and committed
    // when each batch fills or when something needs to see them.
    let data: Vec<u8> = (0..3 * TEST_CHUNK_SIZE as usize)
        .map(|i| (i % 251) as u8)
        .collect();
    for (i, piece) in data.chunks(1000).enumerate() {
        let n = s
            .block(s.session.write(ino, (i * 1000) as u64, piece))
            .unwrap();
        assert_eq!(n, piece.len());
    }
    assert_eq!(
        s.block(s.session.getattr(ino)).unwrap().size,
        data.len() as u64
    );
    assert_eq!(s.block(s.session.read(ino, 0, data.len())).unwrap(), data);
    s.block(s.session.release(ino)).unwrap();
}

#[test]
fn shutdown_stores_what_is_buffered() {
    let s = Setup::new();
    let ino = s
        .block(s.session.create(s.volume, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    s.block(s.session.write(ino, 0, b"not yet stored")).unwrap();
    s.block(s.session.shutdown());

    let other = open(&s.backend, |_| {});
    let attr = s.block(other.resolve(b"/v/f")).unwrap();
    assert_eq!(
        s.block(other.read(attr.ino, 0, 100)).unwrap(),
        b"not yet stored"
    );
}

#[test]
fn paths_resolve_from_the_virtual_root() {
    let s = Setup::new();
    let dir = s
        .block(s.session.mkdir(s.volume, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;
    let file = s
        .block(s.session.create(dir, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;

    assert_eq!(s.block(s.session.resolve(b"/")).unwrap().ino, VIRTUAL_ROOT);
    assert_eq!(s.block(s.session.resolve(b"/v")).unwrap().ino, s.volume);
    assert_eq!(s.block(s.session.resolve(b"/v/d/")).unwrap().ino, dir);
    let attr = s.block(s.session.resolve(b"//v/./d/f")).unwrap();
    assert_eq!((attr.ino, attr.kind), (file, Kind::File));
    assert_eq!(
        s.block(s.session.resolve_parent(b"/v/d/new")).unwrap(),
        (dir, "new".into())
    );

    assert_eq!(
        errno(s.block(s.session.resolve(b"/v/missing"))),
        libc::ENOENT
    );
    assert_eq!(errno(s.block(s.session.resolve(b"/v/../v"))), libc::EINVAL);
    assert_eq!(
        errno(s.block(s.session.resolve_parent(b"/v/d/f/x"))),
        libc::ENOTDIR
    );
    assert_eq!(errno(s.block(s.session.resolve_parent(b"/"))), libc::EPERM);
}

#[test]
fn changes_through_the_session_show_by_path_at_once() {
    let s = Setup::new();
    let ino = s
        .block(s.session.create(s.volume, OsStr::new("a"), 0o644))
        .unwrap()
        .ino;
    // Resolved, so it is remembered.
    assert_eq!(s.block(s.session.resolve(b"/v/a")).unwrap().ino, ino);

    s.block(
        s.session
            .rename(s.volume, OsStr::new("a"), s.volume, OsStr::new("b"), false),
    )
    .unwrap();
    assert_eq!(errno(s.block(s.session.resolve(b"/v/a"))), libc::ENOENT);
    assert_eq!(s.block(s.session.resolve(b"/v/b")).unwrap().ino, ino);

    s.block(s.session.unlink(s.volume, OsStr::new("b")))
        .unwrap();
    assert_eq!(errno(s.block(s.session.resolve(b"/v/b"))), libc::ENOENT);
}

#[test]
fn another_clients_changes_show_by_path() {
    let s = Setup::new();
    let d = s
        .block(s.session.mkdir(s.volume, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;
    s.block(s.session.create(d, OsStr::new("f"), 0o644))
        .unwrap();
    s.block(s.session.resolve(b"/v/d/f")).unwrap();

    // Another client replaces `d`, under the name that this client
    // remembers.
    let other = open(&s.backend, |_| {});
    s.block(other.unlink(d, OsStr::new("f"))).unwrap();
    s.block(other.rmdir(s.volume, OsStr::new("d"))).unwrap();
    let new_d = s
        .block(other.mkdir(s.volume, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;
    let new_f = s
        .block(other.create(new_d, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;

    // The remembered `d` is gone, so the path is resolved again.
    assert_eq!(s.block(s.session.resolve(b"/v/d/f")).unwrap().ino, new_f);
}

#[test]
fn the_virtual_root_holds_only_volumes() {
    let s = Setup::new();
    let root = OsStr::new("f");
    assert_eq!(
        errno(s.block(s.session.create(VIRTUAL_ROOT, root, 0o644))),
        libc::EPERM
    );
    assert_eq!(
        errno(s.block(s.session.unlink(VIRTUAL_ROOT, OsStr::new(VOLUME)))),
        libc::EPERM
    );
    let names: Vec<_> = s
        .block(s.session.readdir(VIRTUAL_ROOT))
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert_eq!(names, [".", "..", VOLUME]);

    s.block(s.session.rmdir(VIRTUAL_ROOT, OsStr::new(VOLUME)))
        .unwrap();
    assert_eq!(errno(s.block(s.session.resolve(b"/v"))), libc::ENOENT);
}

#[test]
fn snapshots_are_read_only_and_copy_out() {
    let s = Setup::new();
    let ino = s
        .block(s.session.create(s.volume, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    s.block(s.session.write(ino, 0, b"then")).unwrap();
    s.block(s.session.release(ino)).unwrap();
    s.backend.snapshot("s1");
    s.block(s.session.write(ino, 0, b"now!")).unwrap();
    s.block(s.session.release(ino)).unwrap();

    let old = s.block(s.session.resolve(b"/.snapshot/s1/v/f")).unwrap();
    assert_eq!(s.block(s.session.read(old.ino, 0, 10)).unwrap(), b"then");
    let snap_dir = s.block(s.session.resolve(b"/.snapshot/s1/v")).unwrap().ino;
    assert_eq!(
        errno(s.block(s.session.create(snap_dir, OsStr::new("g"), 0o644))),
        libc::EROFS
    );
    assert_eq!(
        errno(s.block(s.session.write(old.ino, 0, b"x"))),
        libc::EROFS
    );
    assert_eq!(
        errno(s.block(s.session.rename(
            snap_dir,
            OsStr::new("f"),
            s.volume,
            OsStr::new("g"),
            false
        ))),
        libc::EXDEV
    );

    // To restore is to copy out of the snapshot.
    let restored = s
        .block(
            s.session
                .copy_file(old.ino, s.volume, OsStr::new("restored")),
        )
        .unwrap();
    assert_eq!(restored.size, 4);
    assert_eq!(
        s.block(s.session.read(restored.ino, 0, 10)).unwrap(),
        b"then"
    );
}

#[test]
fn copies_span_batches() {
    let s = Setup::new();
    let src = s
        .block(s.session.create(s.volume, OsStr::new("src"), 0o640))
        .unwrap()
        .ino;
    let data: Vec<u8> = (0..5 * TEST_CHUNK_SIZE as usize + 123)
        .map(|i| (i % 253) as u8)
        .collect();
    s.block(s.session.write(src, 0, &data)).unwrap();
    s.block(s.session.release(src)).unwrap();

    let copy = s
        .block(s.session.copy_file(src, s.volume, OsStr::new("dst")))
        .unwrap();
    assert_eq!((copy.size, copy.perm), (data.len() as u64, 0o640));
    assert_eq!(
        s.block(s.session.read(copy.ino, 0, data.len())).unwrap(),
        data
    );
    assert_eq!(
        errno(s.block(s.session.copy_file(src, s.volume, OsStr::new("dst")))),
        libc::EEXIST
    );
}

#[test]
fn apple_double_files_are_refused_when_asked() {
    let s = Setup::with(|config| config.hide_apple_double = true);
    for name in ["._f", ".DS_Store"] {
        assert_eq!(
            errno(s.block(s.session.create(s.volume, OsStr::new(name), 0o644))),
            libc::EACCES,
            "{name}"
        );
    }
    s.block(s.session.create(s.volume, OsStr::new(".f"), 0o644))
        .unwrap();
}

#[test]
fn remembered_keys_log_in_until_the_password_changes() {
    use raft5fs_client::remote::Remote;
    use raft5fs_crypto::password::KdfParams;

    let setup = Setup::new();
    let remote = setup.session.vault().remote();
    let keys = remote.unlock_keys().expect("keys after a login");
    let identity = remote.identity().unwrap();

    // A new login with the keys alone opens the same key pair.
    let mut remembered = credentials(TESTER);
    remembered.password = String::new();
    remembered.keys = Some(keys);
    let again = setup
        .block(Remote::connect(
            &setup.backend.addresses(),
            remembered.clone(),
            Some(fs_tls()),
        ))
        .expect("a login with the remembered keys");
    assert_eq!(
        again.identity().unwrap().public_key(),
        identity.public_key()
    );

    // A new password makes them useless.
    setup
        .block(remote.change_password("a new password, long enough", KdfParams::TESTING))
        .unwrap();
    assert!(
        setup
            .block(Remote::connect(
                &setup.backend.addresses(),
                remembered,
                Some(fs_tls()),
            ))
            .is_err()
    );
}

/// A writer that something keeps looking at (a file manager, a shell
/// prompt) still uploads each block once. Asking for the file's attributes
/// counts what is buffered; storing it instead would cut the writer's run
/// into pieces, and a block stored in pieces is uploaded again for each.
#[test]
fn looking_at_a_file_being_written_uploads_each_block_once() {
    use raft5fs_testkit::{TEST_BLOCK_CHUNKS, TEST_OBJECT_FROM_CHUNKS};

    let backend = Backend::start(TEST_CHUNK_SIZE, true, true);
    let session = open(&backend, |_| {});
    let block = (TEST_BLOCK_CHUNKS * TEST_CHUNK_SIZE) as usize;
    let inline = (TEST_OBJECT_FROM_CHUNKS * TEST_CHUNK_SIZE) as usize;
    let data: Vec<u8> = (0..inline + 4 * block).map(|i| (i % 251) as u8).collect();
    let rt = &backend.runtime;
    let volume = rt
        .block_on(session.mkdir(VIRTUAL_ROOT, OsStr::new(VOLUME), 0o755))
        .unwrap()
        .ino;
    let ino = rt
        .block_on(session.create(volume, OsStr::new("watched.bin"), 0o644))
        .unwrap()
        .ino;
    let puts = backend.store().stats().puts;
    let mut offset = 0;
    for piece in data.chunks(16 << 10) {
        let n = rt
            .block_on(session.write(ino, offset as u64, piece))
            .unwrap();
        assert_eq!(n, piece.len());
        offset += n;
        let attr = rt.block_on(session.getattr(ino)).unwrap();
        assert_eq!(attr.size, offset as u64, "the size counts buffered bytes");
    }
    rt.block_on(session.fsync(ino)).unwrap();
    assert_eq!(
        backend.store().stats().puts - puts,
        4,
        "each block uploaded once"
    );
    assert_eq!(rt.block_on(session.read(ino, 0, data.len())).unwrap(), data);
}

/// The servers' count of requests from `session`, snapshots included.
fn requests(session: &Session) -> u64 {
    session.vault().remote().requests()
}

#[test]
fn a_listed_folder_resolves_with_no_round_trip() {
    let s = Setup::with(|c| c.path_ttl = std::time::Duration::from_secs(60));
    let d = s
        .block(s.session.mkdir(s.volume, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;
    let sub = s
        .block(s.session.mkdir(d, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    // As the web app does: each folder is listed before it is opened.
    for dir in [VIRTUAL_ROOT, s.volume, d] {
        s.block(s.session.readdir(dir)).unwrap();
    }
    let before = requests(&s.session);
    assert_eq!(s.block(s.session.resolve_ino(b"/v/d/sub")).unwrap(), sub);
    assert_eq!(requests(&s.session), before);
}

#[test]
fn a_stale_inode_resolves_fresh() {
    let s = Setup::with(|c| c.path_ttl = std::time::Duration::from_secs(60));
    let d = s
        .block(s.session.mkdir(s.volume, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;
    let keep = s
        .block(s.session.mkdir(s.volume, OsStr::new("keep"), 0o755))
        .unwrap()
        .ino;
    s.block(s.session.readdir(s.volume)).unwrap();

    // Another client replaces `d`, under the name that this client
    // remembers.
    let other = open(&s.backend, |_| {});
    s.block(other.rmdir(s.volume, OsStr::new("d"))).unwrap();
    let new_d = s
        .block(other.mkdir(s.volume, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;

    // The remembered inode is the old one, and using it finds it gone.
    let stale = s.block(s.session.resolve_ino(b"/v/d")).unwrap();
    assert_eq!(stale, d);
    assert_eq!(errno(s.block(s.session.readdir(stale))), libc::ENOENT);
    assert_eq!(
        s.block(s.session.resolve_ino_fresh(b"/v/d")).unwrap(),
        new_d
    );
    // Only that path was looked up again.
    let before = requests(&s.session);
    assert_eq!(s.block(s.session.resolve_ino(b"/v/keep")).unwrap(), keep);
    assert_eq!(requests(&s.session), before);
}

/// Writes `data` over the start of file `ino` and stores it.
fn write_now(s: &Setup, ino: u64, data: &[u8]) {
    s.block(s.session.write(ino, 0, data)).unwrap();
    s.block(s.session.release(ino)).unwrap();
}

#[test]
fn versions_come_from_the_same_folder_in_each_snapshot() {
    let s = Setup::new();
    let d = s
        .block(s.session.mkdir(s.volume, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;
    let f = s
        .block(s.session.create(d, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    write_now(&s, f, b"one");
    s.backend.snapshot("s1");
    write_now(&s, f, b"two!");
    s.backend.snapshot("s2");
    write_now(&s, f, b"three");
    // The folder is renamed since: its versions are still found.
    s.block(
        s.session
            .rename(s.volume, OsStr::new("d"), s.volume, OsStr::new("e"), true),
    )
    .unwrap();

    let before = requests(&s.session);
    let found = s.block(s.session.versions(b"/v/e/f")).unwrap();
    let sent = requests(&s.session) - before;
    assert_eq!(found.now.unwrap().size, 5);
    let sizes: Vec<u64> = found.versions.iter().map(|v| v.attr.size).collect();
    let names: Vec<&str> = found.versions.iter().map(|v| v.snapshot.as_str()).collect();
    assert_eq!(names, ["s2", "s1"]);
    assert_eq!(sizes, [4, 3]);
    assert_eq!(found.unreadable, 0);
    // One for each name on the path and one for the snapshots, at once;
    // at most one for the folder's key; then one lookup in each snapshot.
    assert!(sent <= 3 + 1 + 1 + 2, "versions sent {sent} requests");

    // What a version's number names reads as it was.
    let s1 = &found.versions[1];
    assert_eq!(s.block(s.session.read(s1.attr.ino, 0, 10)).unwrap(), b"one");

    // A file made after every snapshot has no versions, and that isn't a
    // failure to read them.
    s.block(s.session.create(d, OsStr::new("new"), 0o644))
        .unwrap();
    let found = s.block(s.session.versions(b"/v/e/new")).unwrap();
    assert!(found.versions.is_empty());
    assert_eq!(found.unreadable, 0);
}

#[test]
fn a_volumes_versions_are_found_by_path() {
    let s = Setup::new();
    s.backend.snapshot("s1");
    s.backend.snapshot("s2");
    let found = s.block(s.session.versions(b"/v")).unwrap();
    assert_eq!(found.versions.len(), 2);
    assert_eq!(found.unreadable, 0);
    assert_eq!(errno(s.block(s.session.versions(b"/"))), libc::EINVAL);
}

#[test]
fn versions_open_under_a_folder_key_rotated_since() {
    let s = Setup::new();
    s.backend.enrol("bob");
    let f = s
        .block(s.session.create(s.volume, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    write_now(&s, f, b"old");
    s.block(
        s.session
            .vault()
            .grant(s.volume, "bob", true, OsStr::new("v")),
    )
    .unwrap();
    s.backend.snapshot("s1");
    // Revoking rotates the volume's key, so the snapshot's names are
    // sealed under a key older than the one this session holds.
    s.block(s.session.vault().revoke(s.volume, "bob")).unwrap();
    write_now(&s, f, b"newer");

    let found = s.block(s.session.versions(b"/v/f")).unwrap();
    assert_eq!(found.unreadable, 0);
    let names: Vec<&str> = found.versions.iter().map(|v| v.snapshot.as_str()).collect();
    assert_eq!(names, ["s1"]);
    assert_eq!(found.versions[0].attr.size, 3);
}

#[test]
fn deleted_files_come_from_the_snapshots() {
    let s = Setup::with(|c| c.path_ttl = std::time::Duration::from_secs(60));
    let mkdir = |parent, name: &str| {
        s.block(s.session.mkdir(parent, OsStr::new(name), 0o755))
            .unwrap()
            .ino
    };
    let create = |parent, name: &str, data: &[u8]| {
        let ino = s
            .block(s.session.create(parent, OsStr::new(name), 0o644))
            .unwrap()
            .ino;
        write_now(&s, ino, data);
        ino
    };
    let d = mkdir(s.volume, "d");
    let other = mkdir(s.volume, "other");
    create(d, "gone", b"gone");
    create(d, "renamed", b"r");
    let moved = create(d, "moved", b"m");
    create(d, "saved", b"old");
    let sub = mkdir(d, "sub");
    create(sub, "inner", b"i");
    s.backend.snapshot("s1");

    s.block(s.session.unlink(d, OsStr::new("gone"))).unwrap();
    let rename = |from, name: &str, to, new: &str| {
        s.block(
            s.session
                .rename(from, OsStr::new(name), to, OsStr::new(new), false),
        )
        .unwrap()
    };
    rename(d, "renamed", d, "renamed-too");
    rename(d, "moved", other, "moved");
    // An editor's save: a new file renamed over the old one.
    create(d, "saved.tmp", b"new");
    rename(d, "saved.tmp", d, "saved");
    s.block(s.session.unlink(sub, OsStr::new("inner"))).unwrap();
    s.block(s.session.rmdir(d, OsStr::new("sub"))).unwrap();
    // Made and deleted between snapshots: in none of them.
    create(d, "brief", b"b");
    s.block(s.session.unlink(d, OsStr::new("brief"))).unwrap();
    s.backend.snapshot("s2");
    // The folder is renamed since: it is still the same folder.
    rename(s.volume, "d", s.volume, "e");
    s.block(s.session.readdir(s.volume)).unwrap();

    let before = requests(&s.session);
    let found = s.block(s.session.deleted(b"/v/e")).unwrap();
    let sent = requests(&s.session) - before;
    let names: Vec<&str> = found
        .gone
        .iter()
        .map(|g| g.name.to_str().unwrap())
        .collect();
    assert_eq!(names, ["gone", "moved", "sub"]);
    assert_eq!(found.unreadable, 0);
    let by = |name: &str| found.gone.iter().find(|g| g.name == name).unwrap();
    assert_eq!(by("gone").snapshot, "s1");
    assert_eq!(by("gone").moved, None);
    assert_eq!(by("moved").moved, Some(moved));
    assert_eq!(by("sub").kind, Kind::Directory);
    // The folder now, its key and the snapshots; the folder in each of 2
    // snapshots; each of 3 found, in its snapshot and live.
    assert!(sent <= 3 + 2 + 2 * 3, "deleted sent {sent} requests");

    // A deleted file reads as it was, and copies back.
    let gone = by("gone");
    assert_eq!(
        s.block(s.session.read(gone.attr.ino, 0, 10)).unwrap(),
        b"gone"
    );
    s.block(s.session.copy_file(gone.attr.ino, d, OsStr::new("gone")))
        .unwrap();
    let found = s.block(s.session.deleted(b"/v/e")).unwrap();
    assert!(found.gone.iter().all(|g| g.name != "gone"));

    // Where the moved file is now.
    assert_eq!(
        s.block(s.session.locate(moved)).unwrap().as_deref(),
        Some("/v/other/moved")
    );
    // Also with no names remembered, so each is found by listing.
    let fresh = open(&s.backend, |_| {});
    assert_eq!(
        s.block(fresh.locate(moved)).unwrap().as_deref(),
        Some("/v/other/moved")
    );
    assert_eq!(errno(s.block(s.session.deleted(b"/"))), libc::EINVAL);
}

/// A tree with a file at the top and one in a subfolder.
fn small_tree(s: &Setup) -> u64 {
    let top = s
        .block(s.session.mkdir(s.volume, OsStr::new("tree"), 0o755))
        .unwrap()
        .ino;
    let sub = s
        .block(s.session.mkdir(top, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    for (dir, name, bytes) in [(top, "a", &b"top file"[..]), (sub, "b", &b"deeper"[..])] {
        let ino = s
            .block(s.session.create(dir, OsStr::new(name), 0o644))
            .unwrap()
            .ino;
        s.block(s.session.write(ino, 0, bytes)).unwrap();
        s.block(s.session.flush(ino)).unwrap();
    }
    top
}

fn read_path(s: &Setup, path: &str) -> Vec<u8> {
    let ino = s.block(s.session.resolve_ino(path.as_bytes())).unwrap();
    s.block(s.session.read(ino, 0, 1 << 20)).unwrap()
}

#[test]
fn a_tree_copies_whole_and_empties_whole() {
    let s = Setup::new();
    let top = small_tree(&s);
    s.block(s.session.copy_tree(top, s.volume, "copy".into()))
        .unwrap();
    assert_eq!(read_path(&s, &format!("/{VOLUME}/copy/a")), b"top file");
    assert_eq!(read_path(&s, &format!("/{VOLUME}/copy/sub/b")), b"deeper");
    // The original is untouched.
    assert_eq!(read_path(&s, &format!("/{VOLUME}/tree/sub/b")), b"deeper");

    s.block(s.session.empty_tree(top)).unwrap();
    assert!(s.block(s.session.children(top)).unwrap().is_empty());
    s.block(s.session.rmdir(s.volume, OsStr::new("tree")))
        .unwrap();
    assert_eq!(read_path(&s, &format!("/{VOLUME}/copy/a")), b"top file");
}

#[test]
fn a_path_reaches_its_grant_through_groups() {
    let s = Setup::new();
    let vault = s.session.vault();
    assert_eq!(
        s.block(vault.grant_at(&[VOLUME, "any", "deeper"])).unwrap(),
        Some((1, s.volume))
    );
    assert_eq!(s.block(vault.grant_at(&[])).unwrap(), None);
    s.block(vault.relabel(s.volume, OsStr::new("Work/notes")))
        .unwrap();
    assert_eq!(s.block(vault.grant_at(&["Work"])).unwrap(), None, "a group");
    assert_eq!(
        s.block(vault.grant_at(&["Work", "notes", "x"])).unwrap(),
        Some((2, s.volume))
    );
    assert_eq!(errno(s.block(vault.grant_at(&["nowhere"]))), libc::ENOENT);
}
