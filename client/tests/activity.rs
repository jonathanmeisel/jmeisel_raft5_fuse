//! Tests the activity log against real servers: what each change records,
//! who may read it, and how it reads.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::remote::Remote;
use raft5fs_client::vault::{ActivityLine, Change, Vault};
use raft5fs_core::accounts;
use raft5fs_crypto::identity::fingerprint_words;
use raft5fs_proto::types::{ActivityOp, Caps, FsError};
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, credentials, credentials_with, fs_tls};

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

fn connect(backend: &Backend, user: &str, secret: Option<&str>) -> Result<Remote, String> {
    let credentials = match secret {
        Some(secret) => credentials_with(user, secret),
        None => credentials(user),
    };
    backend.runtime.block_on(Remote::connect(
        &backend.addresses(),
        credentials,
        Some(fs_tls()),
    ))
}

fn vault(backend: &Backend, user: &str) -> Vault {
    Vault::new(Arc::new(connect(backend, user, None).unwrap())).unwrap()
}

fn errno<T: std::fmt::Debug>(result: Result<T, FsError>) -> i32 {
    result.unwrap_err().errno
}

fn lines(backend: &Backend, vault: &Vault, folder: u64) -> Vec<ActivityLine> {
    backend
        .runtime
        .block_on(vault.activity(folder, &[], 0))
        .unwrap()
        .lines
}

/// `(user, change, name)` for each line, newest first.
fn said(lines: &[ActivityLine]) -> Vec<(String, &'static str, String)> {
    lines
        .iter()
        .map(|l| {
            let name = l.name.clone().unwrap_or_else(|| "?".into());
            let name = match &l.from {
                Some(from) => format!("{from} -> {name}"),
                None => name,
            };
            (l.user.clone(), l.change.as_str(), name)
        })
        .collect()
}

fn line(user: &str, change: &'static str, name: &str) -> (String, &'static str, String) {
    (user.to_string(), change, name.to_string())
}

#[test]
fn changes_are_logged_with_who_made_them() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let bob_key = backend.enrol("bob");
    let me = vault(&backend, TESTER);
    rt.block_on(me.trust("bob", &fingerprint_words(&bob_key)))
        .unwrap();
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let sub = rt
        .block_on(me.mkdir(docs, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    let a = rt
        .block_on(me.create(docs, OsStr::new("a.txt"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(me.write(a, 0, b"hello")).unwrap();
    rt.block_on(me.rename(docs, OsStr::new("a.txt"), docs, OsStr::new("b.txt"), true))
        .unwrap();
    rt.block_on(me.rename(docs, OsStr::new("b.txt"), sub, OsStr::new("b.txt"), true))
        .unwrap();
    // Someone else, who can write, edits it. Many writes are one line.
    rt.block_on(me.grant(docs, "bob", true, OsStr::new("docs")))
        .unwrap();
    let bob = vault(&backend, "bob");
    let my_key = connect(&backend, TESTER, None)
        .unwrap()
        .identity()
        .unwrap()
        .public_key();
    rt.block_on(bob.trust(TESTER, &fingerprint_words(&my_key)))
        .unwrap();
    for i in 0..3 {
        rt.block_on(bob.write(a, i * 5, b"again")).unwrap();
    }
    let raw = rt
        .block_on(me.remote().list_activity(docs, &[], 0))
        .unwrap();
    let edits = raw
        .entries
        .iter()
        .filter(|e| e.op == ActivityOp::Edited && e.user == "bob")
        .count();
    assert_eq!(edits, 1, "one edit line for many writes");
    rt.block_on(bob.unlink(sub, OsStr::new("b.txt"))).unwrap();

    assert_eq!(
        said(&lines(&backend, &me, docs)),
        [
            line("bob", "deleted", "sub/b.txt"),
            line("bob", "edited", "sub/b.txt"),
            line(TESTER, "moved", "b.txt -> sub/b.txt"),
            line(TESTER, "renamed", "a.txt -> b.txt"),
            line(TESTER, "created", "a.txt"),
            line(TESTER, "created", "sub"),
        ]
    );

    // Paging: one page at a time, with where the next starts.
    let first = rt.block_on(me.activity(docs, &[], 2)).unwrap();
    assert_eq!(first.lines.len(), 2);
    let rest = rt.block_on(me.activity(docs, &first.next, 0)).unwrap();
    assert_eq!(rest.lines.len(), 4);
    assert!(rest.next.is_empty());
}

#[test]
fn a_save_by_renaming_over_shows_as_an_edit() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let me = vault(&backend, TESTER);
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let report = rt
        .block_on(me.create(docs, OsStr::new("report.txt"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(me.write(report, 0, b"one")).unwrap();
    // An editor's save: a new file, written, then renamed over the old one.
    let tmp = rt
        .block_on(me.create(docs, OsStr::new("~report.tmp"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(me.write(tmp, 0, b"two")).unwrap();
    rt.block_on(me.rename(
        docs,
        OsStr::new("~report.tmp"),
        docs,
        OsStr::new("report.txt"),
        false,
    ))
    .unwrap();
    assert_eq!(
        said(&lines(&backend, &me, docs)),
        [
            line(TESTER, "edited", "report.txt"),
            line(TESTER, "created", "report.txt"),
        ]
    );
}

#[test]
fn only_those_who_can_read_a_folder_see_its_log() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    rt.block_on(accounts::set_caps(
        &backend.client,
        TESTER,
        Caps::ADMIN | Caps::LINKS,
        Caps::NONE,
    ))
    .unwrap();
    let carol_key = backend.enrol("carol");
    backend.enrol("eve");
    let me = vault(&backend, TESTER);
    rt.block_on(me.trust("carol", &fingerprint_words(&carol_key)))
        .unwrap();
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let sub = rt
        .block_on(me.mkdir(docs, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(me.create(docs, OsStr::new("top.txt"), 0o644))
        .unwrap();
    rt.block_on(me.create(sub, OsStr::new("inner.txt"), 0o644))
        .unwrap();

    // Someone shared only `sub` sees only what is in it, read-only or not.
    rt.block_on(me.grant(sub, "carol", false, OsStr::new("sub")))
        .unwrap();
    let carol = vault(&backend, "carol");
    assert_eq!(
        said(&lines(&backend, &carol, sub)),
        [line(TESTER, "created", "inner.txt")]
    );
    assert_eq!(
        errno(rt.block_on(carol.remote().list_activity(docs, &[], 0))),
        libc::EACCES
    );
    // Someone with no share sees nothing.
    let eve = vault(&backend, "eve");
    assert_eq!(
        errno(rt.block_on(eve.remote().list_activity(docs, &[], 0))),
        libc::EACCES
    );
    // Nor does a public link's visitor.
    let (link, secret) = rt
        .block_on(me.create_link(docs, "/docs", OsStr::new("docs"), None))
        .unwrap();
    let visitor = connect(&backend, &link, Some(&secret)).unwrap();
    assert_eq!(
        errno(rt.block_on(visitor.list_activity(docs, &[], 0))),
        libc::EACCES
    );
}

#[test]
fn old_entries_and_deleted_volumes_leave_the_log() {
    // With an object store: the measuring core here needs one.
    let backend = Backend::start(TEST_CHUNK_SIZE, true, true);
    let rt = &backend.runtime;
    let me = vault(&backend, TESTER);
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(me.create(docs, OsStr::new("new.txt"), 0o644))
        .unwrap();
    let prefix = [&[0x0F], &docs.to_be_bytes()[..]].concat();
    assert_eq!(backend.keys_with_prefix(&prefix).len(), 1);

    // An entry from 8 days ago, as the log would have written it then.
    let mut old = backend.keys_with_prefix(&prefix)[0].clone();
    let value = backend.read_key(&old).unwrap();
    let eight_days_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 8 * 86_400_000;
    old[9..17].copy_from_slice(&(u64::MAX - eight_days_ago).to_be_bytes());
    backend.write_key(&old, Some(&value));
    assert_eq!(backend.keys_with_prefix(&prefix).len(), 2);

    // The measuring server removes it, and keeps the new one.
    let core = backend.gc_core();
    rt.block_on(core.measure()).unwrap();
    assert_eq!(backend.keys_with_prefix(&prefix).len(), 1);

    // Deleting the volume takes its log.
    rt.block_on(me.unlink(docs, OsStr::new("new.txt"))).unwrap();
    rt.block_on(me.delete_volume(OsStr::new("docs"))).unwrap();
    assert!(backend.keys_with_prefix(&prefix).is_empty());
}

/// A deleted folder still shows by name. What was in it can't be named any
/// more: its name was sealed under the folder's key, which went with it.
#[test]
fn a_deleted_folder_still_shows_by_name() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let me = vault(&backend, TESTER);
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let old = rt
        .block_on(me.mkdir(docs, OsStr::new("old"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(me.create(old, OsStr::new("x.txt"), 0o644))
        .unwrap();
    rt.block_on(me.unlink(old, OsStr::new("x.txt"))).unwrap();
    rt.block_on(me.rmdir(docs, OsStr::new("old"))).unwrap();
    let shown = lines(&backend, &me, docs);
    let said = said(&shown);
    assert_eq!(said[0], line(TESTER, "deleted", "old"));
    assert_eq!(said.last(), Some(&line(TESTER, "created", "old")));
    for inner in &shown[1..shown.len() - 1] {
        assert!(inner.name.is_none(), "{inner:?}");
        assert!(matches!(inner.change, Change::Created | Change::Deleted));
    }
}
