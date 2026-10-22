//! Snapshots, end to end: taken by the store's administrator, browsed
//! read-only at `/.snapshot/<name>` in every mount, each user seeing what
//! they could see when it was taken.

mod support;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use raft5fs_client::remote::Remote;
use raft5fs_client::vault::Vault;
use raft5fs_core::{ChunkWrite, WriteBody};

/// Not really a test: the entry point that lets the harness run a
/// filesystem server as a separate process (see `support::TestServer`).
/// Returns at once in a normal run.
#[test]
fn server_process_mode() {
    support::serve_if_requested();
}

fn connect(h: &support::Harness, user: &str) -> Remote {
    let credentials = support::credentials(user);
    h.runtime
        .block_on(Remote::connect(
            &h.addresses(),
            credentials,
            Some(support::fs_tls()),
        ))
        .unwrap()
}

fn vault(h: &support::Harness, user: &str) -> Vault {
    Vault::new(Arc::new(connect(h, user)))
        .unwrap()
        .with_known_keys(h.known_keys())
}

fn ino(path: &Path) -> u64 {
    fs::metadata(path).unwrap().ino()
}

/// The names in a directory, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[track_caller]
fn assert_errno<T: std::fmt::Debug>(result: std::io::Result<T>, errno: i32) {
    match result {
        Err(e) => assert_eq!(e.raw_os_error(), Some(errno), "wrong error: {e}"),
        Ok(v) => panic!("expected errno {errno}, got Ok({v:?})"),
    }
}

#[track_caller]
fn assert_fs_errno<T: std::fmt::Debug>(result: Result<T, raft5fs_core::FsError>, errno: i32) {
    match result {
        Err(e) => assert_eq!(e.errno, errno, "wrong error: {e}"),
        Ok(v) => panic!("expected errno {errno}, got Ok({v:?})"),
    }
}

/// `root`'s view of snapshot `name`.
fn snap(root: &Path, name: &str) -> PathBuf {
    root.join(".snapshot").join(name)
}

/// Longer than the mount tells the kernel to keep a name or attributes.
fn past_kernel_cache() {
    std::thread::sleep(Duration::from_millis(1200));
}

#[test]
fn a_snapshot_keeps_what_was_there_when_it_was_taken() {
    let h = support::setup();
    let big: Vec<u8> = (0..h.chunk_size * 5 / 2).map(|i| (i % 251) as u8).collect();
    fs::create_dir(h.path().join("d")).unwrap();
    fs::write(h.path().join("d/f"), b"before").unwrap();
    fs::write(h.path().join("big"), &big).unwrap();

    h.snapshot("s1");

    fs::write(h.path().join("d/f"), b"after").unwrap();
    fs::remove_file(h.path().join("big")).unwrap();
    fs::write(h.path().join("new"), b"new").unwrap();

    let old = snap(h.root(), "s1").join(support::VOLUME);
    assert_eq!(names(&snap(h.root(), "s1")), [support::VOLUME]);
    assert_eq!(names(&old), ["big", "d"]);
    assert_eq!(fs::read(old.join("d/f")).unwrap(), b"before");
    assert_eq!(fs::read(old.join("big")).unwrap(), big);
    // Again: from the cache this time, which a snapshot never outdates.
    assert_eq!(fs::read(old.join("big")).unwrap(), big);
    assert_eq!(
        fs::metadata(old.join("big")).unwrap().len(),
        big.len() as u64
    );

    assert_eq!(fs::read(h.path().join("d/f")).unwrap(), b"after");
    assert_eq!(names(h.path()), ["d", "new"]);

    // A snapshot's inodes are its own to the kernel, not the live ones.
    assert_ne!(ino(&old.join("d/f")), ino(&h.path().join("d/f")));
    assert_eq!(
        fs::metadata(old.join("..")).unwrap().ino(),
        ino(&snap(h.root(), "s1"))
    );
}

#[test]
fn the_snapshot_directory_is_reachable_but_not_listed() {
    let h = support::setup();
    assert_errno(fs::metadata(h.root().join(".snapshot/s1")), libc::ENOENT);
    h.snapshot("s1");
    h.snapshot("s2");

    assert_eq!(names(h.root()), [support::VOLUME]);
    assert!(fs::metadata(h.root().join(".snapshot")).unwrap().is_dir());
    assert_eq!(names(&h.root().join(".snapshot")), ["s1", "s2"]);
    assert_errno(fs::metadata(snap(h.root(), "nope")), libc::ENOENT);
    // Nor can a volume take its name.
    assert_errno(fs::create_dir(h.root().join(".snapshot")), libc::EEXIST);
}

#[test]
fn nothing_in_a_snapshot_can_be_changed() {
    let h = support::setup();
    fs::create_dir(h.path().join("d")).unwrap();
    fs::write(h.path().join("f"), b"bytes").unwrap();
    h.snapshot("s1");
    let old = snap(h.root(), "s1").join(support::VOLUME);

    let mode = fs::metadata(old.join("f")).unwrap().permissions().mode();
    assert_eq!(mode & 0o222, 0, "shown without write bits");
    assert_errno(fs::write(old.join("new"), b"x"), libc::EROFS);
    assert_errno(
        fs::OpenOptions::new().write(true).open(old.join("f")),
        libc::EROFS,
    );
    assert_errno(
        fs::OpenOptions::new()
            .read(true)
            .truncate(true)
            .write(true)
            .open(old.join("f")),
        libc::EROFS,
    );
    assert_errno(fs::remove_file(old.join("f")), libc::EROFS);
    assert_errno(fs::create_dir(old.join("e")), libc::EROFS);
    assert_errno(fs::remove_dir(old.join("d")), libc::EROFS);
    assert_errno(
        fs::set_permissions(old.join("f"), fs::Permissions::from_mode(0o600)),
        libc::EROFS,
    );
    assert_errno(fs::rename(old.join("f"), old.join("g")), libc::EROFS);
    // Out of one and into the live filesystem is a move between
    // filesystems, which `mv` copies.
    assert_errno(fs::rename(old.join("f"), h.path().join("g")), libc::EXDEV);
    assert_errno(fs::remove_dir(h.root().join(".snapshot")), libc::EROFS);
    assert_errno(fs::remove_dir(snap(h.root(), "s1")), libc::EROFS);

    // And a copy out is how to get something back.
    fs::remove_file(h.path().join("f")).unwrap();
    fs::copy(old.join("f"), h.path().join("f")).unwrap();
    assert_eq!(fs::read(h.path().join("f")).unwrap(), b"bytes");
}

#[test]
fn a_snapshot_is_read_only_whoever_asks() {
    let h = support::setup();
    let f = h.path().join("f");
    fs::write(&f, b"bytes").unwrap();
    h.snapshot("s1");
    let live = connect(&h, support::TESTER);
    let at = live.at("s1");

    // Refused before it is sent...
    let write = ChunkWrite {
        index: 0,
        expected_seq: None,
        body: WriteBody::Inline(Vec::new()),
    };
    assert_fs_errno(
        h.runtime.block_on(at.write_chunks(ino(&f), &[write], 0)),
        libc::EROFS,
    );
    // ...and by the server, for the one that is sent as a read.
    assert_fs_errno(
        h.runtime.block_on(at.grants_under(ino(h.path()))),
        libc::EROFS,
    );
    // Asked of a snapshot there isn't, the answer is at once.
    assert_fs_errno(
        h.runtime.block_on(live.at("nope").getattr(ino(&f))),
        libc::ENOENT,
    );
}

#[test]
fn access_in_a_snapshot_is_as_it_was_when_it_was_taken() {
    let h = support::setup_root();
    let team = h.root().join("team");
    fs::create_dir(&team).unwrap();
    fs::write(team.join("plan"), b"secret plan").unwrap();
    h.add_user("alice");
    h.add_user("bob");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&team), "alice", false, OsStr::new("theirs")))
        .unwrap();

    h.snapshot("s1");

    h.runtime
        .block_on(mine.revoke(ino(&team), "alice"))
        .unwrap();
    h.runtime
        .block_on(mine.grant(ino(&team), "bob", false, OsStr::new("theirs")))
        .unwrap();
    fs::write(team.join("plan"), b"new plan").unwrap();

    // alice is cut off from the filesystem, but not from what she could
    // read then: she held its keys, and the snapshot is sealed under them.
    let alice = h.mount_as("alice");
    assert!(names(&alice.root).is_empty());
    assert_eq!(names(&snap(&alice.root, "s1")), ["theirs"]);
    assert_eq!(
        fs::read(snap(&alice.root, "s1").join("theirs/plan")).unwrap(),
        b"secret plan"
    );

    // bob, granted since, sees nothing in it.
    let bob = h.mount_as("bob");
    assert_eq!(fs::read(bob.root.join("theirs/plan")).unwrap(), b"new plan");
    assert!(names(&snap(&bob.root, "s1")).is_empty());
    assert_errno(
        fs::metadata(snap(&bob.root, "s1").join("theirs")),
        libc::ENOENT,
    );
}

#[test]
fn a_snapshot_still_opens_after_its_keys_are_rotated_and_pruned() {
    let h = support::setup_root();
    let v = h.root().join("v");
    fs::create_dir_all(v.join("shared/sub")).unwrap();
    fs::write(v.join("shared/sub/f"), b"before").unwrap();
    fs::write(v.join("shared/sub/g"), b"untouched").unwrap();
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();

    h.snapshot("s1");

    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();
    fs::write(v.join("shared/sub/f"), b"after").unwrap();
    let stats = h.runtime.block_on(mine.prune_tree(ino(&v), false));
    assert!(stats.skipped.is_empty(), "{:?}", stats.skipped);
    assert!(
        stats.dropped > 0,
        "the old versions are gone from the live tree"
    );

    let old = snap(h.root(), "s1").join("v/shared/sub");
    assert_eq!(names(&old), ["f", "g"]);
    assert_eq!(fs::read(old.join("f")).unwrap(), b"before");
    assert_eq!(fs::read(old.join("g")).unwrap(), b"untouched");
    assert_eq!(fs::read(v.join("shared/sub/f")).unwrap(), b"after");
}

#[test]
fn a_deleted_volume_is_still_in_an_earlier_snapshot() {
    let h = support::setup_root();
    let w = h.root().join("w");
    fs::create_dir(&w).unwrap();
    fs::write(w.join("f"), b"keep me").unwrap();
    h.snapshot("s1");
    fs::remove_file(w.join("f")).unwrap();
    fs::remove_dir(&w).unwrap();

    assert!(names(h.root()).is_empty());
    assert_eq!(
        fs::read(snap(h.root(), "s1").join("w/f")).unwrap(),
        b"keep me"
    );
}

#[test]
fn a_removed_snapshot_is_gone_from_the_mount() {
    let h = support::setup();
    fs::write(h.path().join("f"), b"bytes").unwrap();
    h.snapshot("s1");
    let old = snap(h.root(), "s1").join(support::VOLUME).join("f");
    assert_eq!(fs::read(&old).unwrap(), b"bytes");

    h.drop_snapshot("s1");
    past_kernel_cache();
    assert!(names(&h.root().join(".snapshot")).is_empty());
    assert_errno(fs::metadata(&old), libc::ENOENT);

    // Another under the same name is another snapshot.
    fs::write(h.path().join("f"), b"later").unwrap();
    h.snapshot("s1");
    past_kernel_cache();
    assert_eq!(fs::read(&old).unwrap(), b"later");
}
