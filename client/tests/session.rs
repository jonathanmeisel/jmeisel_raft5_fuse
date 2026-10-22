//! Tests the session alone, with no front end: the part that a mount and a
//! WebDAV server share. They run against a real store and servers, but no
//! kernel, so they run wherever the tests run.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_client::vault::VIRTUAL_ROOT;
use raft5fs_proto::types::{FsError, Kind};
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, VOLUME, credentials, fs_tls};

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

fn errno<T: std::fmt::Debug>(result: Result<T, FsError>) -> i32 {
    result.expect_err("an error").errno
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
