//! Encryption and access by grant, end to end: enrolment, logins whose password
//! never reaches a server, password changes, and access by grant -- the
//! virtual root, volumes, and what each user can and can't reach.

mod support;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use raft5fs_core::{ENCRYPTED_KEY, NewNode, SealedMove, accounts, check_store};
use raft5fs_crypto::node::NodeKeys;
use raft5fs_crypto::password::KdfParams;
use raft5fs_fuse::remote::{Credentials, Remote};
use raft5fs_fuse::vault::Vault;

/// Not really a test: the entry point that lets the harness run a
/// filesystem server as a separate process (see `support::TestServer`).
/// Returns at once in a normal run.
#[test]
fn server_process_mode() {
    support::serve_if_requested();
}

fn connect(h: &support::Harness, user: &str, password: &str) -> Result<Remote, String> {
    let credentials = support::credentials_with(user, password);
    h.runtime.block_on(Remote::connect(
        &h.addresses(),
        credentials,
        Some(support::fs_tls()),
    ))
}

/// `user`'s vault: logged in afresh, so it knows no keys yet -- but with
/// `TESTER`'s public key pinned (see `Harness::known_keys`).
fn vault(h: &support::Harness, user: &str) -> Vault {
    let remote = connect(h, user, &support::password(user)).unwrap();
    Vault::new(Arc::new(remote))
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

fn enrol_with(
    h: &support::Harness,
    name: &str,
    code: &str,
    password: &str,
) -> Result<[u8; 32], raft5fs_core::FsError> {
    h.runtime.block_on(Remote::enrol(
        &h.addresses(),
        Some(support::fs_tls()),
        support::credentials_with(name, password),
        code,
        KdfParams::TESTING,
    ))
}

#[test]
fn an_enrolled_user_mounts_and_uses_the_filesystem() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("vol")).unwrap();
    let f = h.path().join("vol/hello");
    fs::write(&f, b"world").unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"world");
    let remote = connect(&h, support::TESTER, &support::password(support::TESTER)).unwrap();
    assert!(remote.identity().is_some(), "the login opened the key pair");
}

#[test]
fn a_wrong_password_and_an_unknown_user_are_refused_alike() {
    let h = support::setup_root();
    let wrong = connect(&h, support::TESTER, "not it").err().unwrap();
    let unknown = connect(&h, "nobody", "anything").err().unwrap();
    assert!(wrong.contains("login refused"), "{wrong}");
    assert_eq!(wrong, unknown);
}

#[test]
fn an_enrolment_code_works_once_and_only_for_its_user() {
    let h = support::setup_root();
    let code = h
        .runtime
        .block_on(accounts::issue_code(&h.client, "alice"))
        .unwrap();

    let wrong = enrol_with(&h, "alice", "00000000000000000000000000000000", "pw");
    assert_eq!(wrong.unwrap_err().errno, libc::EACCES);
    let someone_elses = enrol_with(&h, "bob", &code, "pw");
    assert_eq!(someone_elses.unwrap_err().errno, libc::EACCES);
    assert!(connect(&h, "alice", "pw").is_err(), "not enrolled yet");

    enrol_with(&h, "alice", &code, "pw").unwrap();
    connect(&h, "alice", "pw").unwrap();
    let again = enrol_with(&h, "alice", &code, "other");
    assert_eq!(
        again.unwrap_err().errno,
        libc::EACCES,
        "the code was used up"
    );
    connect(&h, "alice", "pw").unwrap();
}

#[test]
fn enrolling_again_drops_the_old_key_pairs_grants() {
    let h = support::setup_root();
    fs::create_dir(h.root().join("v")).unwrap();
    fs::write(h.root().join("v/f"), b"x").unwrap();
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&h.root().join("v")), "alice", true, OsStr::new("v")))
        .unwrap();
    let before = connect(&h, "alice", &support::password("alice")).unwrap();
    assert_eq!(h.runtime.block_on(before.list_grants()).unwrap().len(), 1);

    // Whoever enrols with a new code gets a new key pair and nothing
    // else: not the right to delete or overwrite what they can't read.
    h.enrol("alice");
    let after = connect(&h, "alice", &support::password("alice")).unwrap();
    assert!(h.runtime.block_on(after.list_grants()).unwrap().is_empty());
    let mut index = vec![0x09];
    index.extend_from_slice(b"alice\0");
    assert!(h.keys_with_prefix(&index).is_empty(), "her grants are gone");
    assert_eq!(fs::read(h.root().join("v/f")).unwrap(), b"x");
}

#[test]
fn a_login_refuses_weaker_key_stretching_than_it_accepts() {
    let h = support::setup_root();
    // Enrolled with `KdfParams::TESTING`, which is what Prelogin now hands
    // out for her -- as a server trying to cheapen her `auth` would.
    h.add_user("alice");
    let credentials = Credentials::new("alice", support::password("alice"));
    let refused = h
        .runtime
        .block_on(Remote::connect(
            &h.addresses(),
            credentials,
            Some(support::fs_tls()),
        ))
        .map(drop)
        .unwrap_err();
    assert!(refused.contains("weaker key stretching"), "{refused}");
    connect(&h, "alice", &support::password("alice")).unwrap();
}

#[test]
fn a_password_change_keeps_the_key_pair() {
    let h = support::setup_root();
    h.add_user("alice");
    let old = support::password("alice");
    let remote = connect(&h, "alice", &old).unwrap();
    let key = remote.identity().unwrap().public_key();

    h.runtime
        .block_on(remote.change_password("new password", KdfParams::TESTING))
        .unwrap();
    assert!(connect(&h, "alice", &old).is_err());
    let after = connect(&h, "alice", "new password").unwrap();
    assert_eq!(after.identity().unwrap().public_key(), key);
}

#[test]
fn no_password_reaches_the_store() {
    let h = support::setup_root();
    let password = "correct horse battery staple";
    let code = h
        .runtime
        .block_on(accounts::issue_code(&h.client, "alice"))
        .unwrap();
    enrol_with(&h, "alice", &code, password).unwrap();
    connect(&h, "alice", password).unwrap();

    for key in h.keys_with_prefix(&[]) {
        let value = h.read_key(&key).unwrap_or_default();
        for bytes in [&key, &value] {
            assert!(
                !bytes
                    .windows(password.len())
                    .any(|w| w == password.as_bytes()),
                "the password is stored under {key:?}"
            );
        }
    }
}

#[test]
fn a_mount_logs_in_again_without_its_password() {
    let mut h = support::setup_root();
    fs::create_dir(h.path().join("vol")).unwrap();
    fs::write(h.path().join("vol/before"), b"x").unwrap();
    // Every session the mount holds is now refused, so its next request
    // logs in again -- from the `auth` it kept, the password long gone.
    h.restart_servers_with_key("another key, also at least 32 bytes");
    fs::write(h.path().join("vol/after"), b"y").unwrap();
    assert_eq!(fs::read(h.path().join("vol/before")).unwrap(), b"x");
}

#[test]
fn a_store_from_an_older_raft5fs_is_refused() {
    let h = support::setup_root();
    let check = || h.runtime.block_on(check_store(&h.client));
    check().unwrap();
    // Recorded unencrypted, in the format before grants, names and
    // grantee lists were sealed as now, or from before anything was
    // recorded.
    for old in [Some(&[0u8][..]), Some(&[1u8][..]), None] {
        h.write_key(ENCRYPTED_KEY, old);
        assert!(check().unwrap_err().contains("older raft5fs"), "{old:?}");
    }
}

#[test]
fn removing_a_user_cuts_them_off_and_drops_their_grants() {
    let h = support::setup_root();
    fs::create_dir(h.root().join("v")).unwrap();
    fs::write(h.root().join("v/f"), b"x").unwrap();
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&h.root().join("v")), "alice", false, OsStr::new("v")))
        .unwrap();
    let alice = h.mount_as("alice");
    assert_eq!(fs::read(alice.path.join("v/f")).unwrap(), b"x");

    assert!(
        h.runtime
            .block_on(accounts::remove(&h.client, "alice"))
            .unwrap()
    );
    // Her mount's next request is refused, and so is logging in again.
    assert!(fs::read(alice.path.join("v/f")).is_err());
    assert!(connect(&h, "alice", &support::password("alice")).is_err());
    let mut index = vec![0x09];
    index.extend_from_slice(b"alice\0");
    assert!(h.keys_with_prefix(&index).is_empty(), "her grants are gone");
}

// ----------------------------------------------------------------- grants

#[test]
fn the_root_lists_grants_and_mkdir_there_makes_a_volume() {
    let h = support::setup_root();
    let root = h.path();
    assert!(names(root).is_empty(), "a new account has nothing granted");

    fs::create_dir(root.join("docs")).unwrap();
    fs::write(root.join("docs/a"), b"x").unwrap();
    assert_eq!(names(root), ["docs"]);
    assert_eq!(fs::read(root.join("docs/a")).unwrap(), b"x");

    // Only volumes go in the root.
    assert_errno(fs::write(root.join("loose"), b"x"), libc::EPERM);
    assert_errno(fs::rename(root.join("docs/a"), root.join("a")), libc::EPERM);
    assert_errno(fs::create_dir(root.join("docs")), libc::EEXIST);

    assert_errno(fs::remove_dir(root.join("docs")), libc::ENOTEMPTY);
    fs::remove_file(root.join("docs/a")).unwrap();
    fs::remove_dir(root.join("docs")).unwrap();
    assert!(names(root).is_empty());
}

#[test]
fn nothing_ungranted_is_reachable() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("mine")).unwrap();
    fs::write(h.path().join("mine/secret"), b"x").unwrap();
    let volume = ino(&h.path().join("mine"));
    let file = ino(&h.path().join("mine/secret"));

    h.add_user("alice");
    let alice = h.mount_as("alice");
    assert!(names(&alice.path).is_empty());

    // Straight to the servers, inode numbers in hand: still nothing.
    let remote = connect(&h, "alice", &support::password("alice")).unwrap();
    let run = |f| h.runtime.block_on(f);
    assert_fs_errno(run(remote.getattr(volume)), libc::EACCES);
    assert_fs_errno(run(remote.getattr(file)), libc::EACCES);
    assert_fs_errno(h.runtime.block_on(remote.readdir(volume)), libc::EACCES);
    assert_fs_errno(
        h.runtime
            .block_on(remote.lookup(volume, OsStr::new("secret"))),
        libc::EACCES,
    );
    assert_fs_errno(h.runtime.block_on(remote.access(file, 4)), libc::EACCES);
    assert_fs_errno(h.runtime.block_on(remote.key_path(file)), libc::EACCES);
    // The real root is no one's, not even the volumes' owners'.
    assert_fs_errno(run(remote.getattr(1)), libc::EACCES);
    assert_fs_errno(h.runtime.block_on(remote.readdir(1)), libc::EACCES);
    let tester = connect(&h, support::TESTER, &support::password(support::TESTER)).unwrap();
    assert_fs_errno(h.runtime.block_on(tester.readdir(1)), libc::EACCES);

    // Nor can alice make anything there, keys or no keys.
    let alices = Vault::new(Arc::new(remote)).unwrap();
    assert_fs_errno(
        h.runtime
            .block_on(alices.create(volume, OsStr::new("planted"), 0o644)),
        libc::EACCES,
    );
}

#[test]
fn a_read_only_grant_shows_its_directory_and_nothing_above() {
    let h = support::setup_root();
    let team = h.path().join("team");
    fs::create_dir_all(team.join("shared/deeper")).unwrap();
    fs::write(team.join("shared/notes"), b"agenda").unwrap();
    fs::write(team.join("private"), b"x").unwrap();
    h.add_user("alice");

    let mine = vault(&h, support::TESTER);
    let shared = ino(&team.join("shared"));
    h.runtime
        .block_on(mine.grant(shared, "alice", false, OsStr::new("from-tester")))
        .unwrap();

    let alice = h.mount_as("alice");
    let granted = alice.path.join("from-tester");
    assert_eq!(names(&alice.path), ["from-tester"]);
    assert_eq!(names(&granted), ["deeper", "notes"]);
    assert_eq!(fs::read(granted.join("notes")).unwrap(), b"agenda");
    assert_eq!(ino(&granted.join("..")), 1, "above the grant is the root");

    assert_errno(fs::write(granted.join("notes"), b"defaced"), libc::EROFS);
    assert_errno(fs::write(granted.join("new"), b"x"), libc::EROFS);
    assert_errno(fs::create_dir(granted.join("dir")), libc::EROFS);
    assert_errno(fs::remove_file(granted.join("notes")), libc::EROFS);

    let remote = connect(&h, "alice", &support::password("alice")).unwrap();
    assert_fs_errno(h.runtime.block_on(remote.getattr(ino(&team))), libc::EACCES);
    assert_fs_errno(
        h.runtime
            .block_on(remote.getattr(ino(&team.join("private")))),
        libc::EACCES,
    );
}

#[test]
fn a_writable_grant_shares_both_ways() {
    let h = support::setup_root();
    let team = h.path().join("team");
    fs::create_dir(&team).unwrap();
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&team), "alice", true, OsStr::new("team")))
        .unwrap();

    let alice = h.mount_as("alice");
    fs::create_dir(alice.path.join("team/from-alice")).unwrap();
    fs::write(alice.path.join("team/from-alice/hello"), b"hi").unwrap();
    assert_eq!(fs::read(team.join("from-alice/hello")).unwrap(), b"hi");

    // Keys alice made unwrap for the volume's owner, from scratch.
    let fresh = vault(&h, support::TESTER);
    let hers = ino(&team.join("from-alice/hello"));
    let theirs = vault(&h, "alice");
    let a = h.runtime.block_on(fresh.node(hers)).unwrap();
    let b = h.runtime.block_on(theirs.node(hers)).unwrap();
    assert_eq!(a.key, b.key);
}

#[test]
fn a_moved_node_gets_a_new_key_under_its_new_parent() {
    let h = support::setup_root();
    let v = h.path().join("v");
    fs::create_dir_all(v.join("a/sub")).unwrap();
    fs::create_dir(v.join("b")).unwrap();
    fs::write(v.join("a/f"), b"x").unwrap();
    let f = ino(&v.join("a/f"));
    let sub = ino(&v.join("a/sub"));
    let before = vault(&h, support::TESTER);
    let f_key = h.runtime.block_on(before.node(f)).unwrap().key.clone();
    let sub_key = h.runtime.block_on(before.node(sub)).unwrap().key.clone();

    let a_key = h
        .runtime
        .block_on(before.node(ino(&v.join("a"))))
        .unwrap()
        .key
        .clone();

    fs::rename(v.join("a/f"), v.join("b/f")).unwrap();
    fs::rename(v.join("a/sub"), v.join("b/sub")).unwrap();

    // Only b is shared, so alice reaches them only through their new
    // parent's key -- which works only if the move re-wrapped them.
    h.add_user("alice");
    h.runtime
        .block_on(before.grant(ino(&v.join("b")), "alice", false, OsStr::new("b")))
        .unwrap();
    let alices = vault(&h, "alice");
    let (f_now, sub_now) = (
        h.runtime.block_on(alices.node(f)).unwrap(),
        h.runtime.block_on(alices.node(sub)).unwrap(),
    );
    // New keys: whoever held a's -- and so f's and sub's old ones --
    // holds nothing that opens what is written to them from now on.
    assert_ne!(f_now.key, f_key);
    assert_ne!(sub_now.key, sub_key);
    assert!(record(&h, f).open(f, &a_key).is_err());
    assert!(record(&h, f).name_key(f, &f_key).is_err());
    // What was written before still reads, through the history.
    assert_eq!(f_now.record.older(f, &f_now.key, 1).unwrap(), f_key);
    let alice = h.mount_as("alice");
    assert_eq!(fs::read(alice.path.join("b/f")).unwrap(), b"x");
}

#[test]
fn a_create_must_bring_a_reserved_inode_and_a_fitting_key_record() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("v")).unwrap();
    let v = ino(&h.path().join("v"));
    let mine = vault(&h, support::TESTER);
    let remote = mine.remote();
    let parent = h.runtime.block_on(mine.node(v)).unwrap();
    // A create as an honest client would send it, but for `ino` and its
    // key record claiming `parent_version`.
    let create = |name: &str, ino: u64, parent_version: u32| {
        let (record, _) = NodeKeys::create(ino, Some((&parent.key, parent_version)));
        let tag = parent.tag(OsStr::new(name));
        let new = NewNode {
            ino,
            keys: record.encode(),
            sealed_name: parent.seal(v, ino, &tag, OsStr::new(name)),
        };
        h.runtime.block_on(remote.create(v, &tag, 0o644, &new))
    };
    let version = parent.record.version;

    // No inode reserved, no key record.
    let tag = parent.tag(OsStr::new("bare"));
    let bare = NewNode {
        ino: 0,
        keys: Vec::new(),
        sealed_name: parent.seal(v, 0, &tag, OsStr::new("bare")),
    };
    let bare = h.runtime.block_on(remote.create(v, &tag, 0o644, &bare));
    assert_fs_errno(bare, libc::EACCES);
    assert_fs_errno(create("unreserved", 1_000_000, version), libc::EACCES);

    // A reserved inode, but a record claiming the wrong parent version:
    // what a client with an out-of-date key sends, told to fetch it again.
    let reserved = h.runtime.block_on(remote.allocate_inode()).unwrap();
    assert_fs_errno(
        create("wrong-version", reserved, version + 1),
        libc::EKEYEXPIRED,
    );
    create("right", reserved, version).unwrap();

    // Someone else's reservation won't do either.
    h.add_user("alice");
    let alice = connect(&h, "alice", &support::password("alice")).unwrap();
    let hers = h.runtime.block_on(alice.allocate_inode()).unwrap();
    assert_fs_errno(create("hers", hers, version), libc::EACCES);
}

#[test]
fn removing_a_volume_removes_its_grants_and_keys() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("gone")).unwrap();
    let volume = ino(&h.path().join("gone"));
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(volume, "alice", false, OsStr::new("gone")))
        .unwrap();
    let alice = h.mount_as("alice");
    assert_eq!(names(&alice.path), ["gone"]);

    fs::remove_dir(h.path().join("gone")).unwrap();
    assert!(names(&alice.path).is_empty());
    let mut keys_of_it = vec![0x08];
    keys_of_it.extend_from_slice(&volume.to_be_bytes());
    assert_eq!(h.read_key(&keys_of_it), None);
    let mut grants_of_it = vec![0x07];
    grants_of_it.extend_from_slice(&volume.to_be_bytes());
    assert!(h.keys_with_prefix(&grants_of_it).is_empty());
}

#[test]
fn every_inode_has_a_key_record() {
    let h = support::setup_root();
    let v = h.path().join("v");
    fs::create_dir_all(v.join("d")).unwrap();
    fs::write(v.join("d/f"), b"x").unwrap();
    for path in [v.clone(), v.join("d"), v.join("d/f")] {
        let mut key = vec![0x08];
        key.extend_from_slice(&ino(&path).to_be_bytes());
        let record = h
            .read_key(&key)
            .unwrap_or_else(|| panic!("no key record for {path:?}"));
        assert_eq!(NodeKeys::decode(&record).unwrap().version, 1);
    }
}

// ------------------------------------------------------------------ names

/// Asserts `marker` appears in no key or value in the store.
#[track_caller]
fn assert_nowhere_in_store(h: &support::Harness, marker: &[u8]) {
    for key in h.keys_with_prefix(&[]) {
        let value = h.read_key(&key).unwrap_or_default();
        for bytes in [&key, &value] {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker),
                "{:?} is stored under {key:?}",
                String::from_utf8_lossy(marker)
            );
        }
    }
}

#[test]
fn no_name_reaches_the_store() {
    let h = support::setup_root();
    let v = h.path().join("volume-zebra");
    fs::create_dir_all(v.join("dir-zebra/deeper-zebra")).unwrap();
    fs::write(v.join("dir-zebra/file-zebra"), b"x").unwrap();
    fs::rename(v.join("dir-zebra/file-zebra"), v.join("moved-zebra")).unwrap();
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(
            ino(&v.join("dir-zebra")),
            "alice",
            false,
            OsStr::new("label-zebra"),
        ))
        .unwrap();
    assert_nowhere_in_store(&h, b"zebra");
}

#[test]
fn names_survive_listing_moving_and_sharing() {
    let h = support::setup_root();
    let v = h.path().join("v");
    fs::create_dir_all(v.join("a")).unwrap();
    fs::create_dir(v.join("b")).unwrap();
    for name in ["one", "two", "naïve ☃"] {
        fs::write(v.join("a").join(name), name).unwrap();
    }
    assert_eq!(names(&v.join("a")), ["naïve ☃", "one", "two"]);

    fs::rename(v.join("a/one"), v.join("a/uno")).unwrap();
    fs::rename(v.join("a/two"), v.join("b/dos")).unwrap();
    assert_eq!(names(&v.join("a")), ["naïve ☃", "uno"]);
    assert_eq!(names(&v.join("b")), ["dos"]);
    assert_eq!(fs::read(v.join("b/dos")).unwrap(), b"two");
    assert_errno(fs::read(v.join("a/one")), libc::ENOENT);

    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    let alice = h.mount_as("alice");
    assert_eq!(names(&alice.path.join("v/a")), ["naïve ☃", "uno"]);
    assert_eq!(
        fs::read(alice.path.join("v/a/naïve ☃")).unwrap(),
        "naïve ☃".as_bytes()
    );
}

#[test]
fn a_plain_name_is_refused() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("v")).unwrap();
    fs::write(h.path().join("v/f"), b"x").unwrap();
    let v = ino(&h.path().join("v"));
    let mine = vault(&h, support::TESTER);
    let remote = mine.remote();
    let parent = h.runtime.block_on(mine.node(v)).unwrap();

    // Everything right but the name, which goes as itself.
    let reserved = h.runtime.block_on(remote.allocate_inode()).unwrap();
    let (record, _) = NodeKeys::create(reserved, Some((&parent.key, parent.record.version)));
    let name = OsStr::new("in-the-clear");
    let new = NewNode {
        ino: reserved,
        keys: record.encode(),
        sealed_name: parent.seal(v, reserved, name, name),
    };
    let created = h.runtime.block_on(remote.create(v, name, 0o644, &new));
    assert_fs_errno(created, libc::EINVAL);

    // A rename to a plain name, with nothing sealed.
    let tag = parent.tag(OsStr::new("f"));
    let sealed = SealedMove {
        ino: ino(&h.path().join("v/f")),
        node_keys: Vec::new(),
        sealed_name: Vec::new(),
    };
    let renamed = h
        .runtime
        .block_on(remote.rename(v, &tag, v, name, false, &sealed));
    assert_fs_errno(renamed, libc::EINVAL);
}

#[test]
fn an_entry_filed_under_another_name_is_left_out() {
    let h = support::setup_root();
    let v = h.path().join("v");
    fs::create_dir(&v).unwrap();
    fs::write(v.join("a"), b"a").unwrap();
    fs::write(v.join("b"), b"b").unwrap();
    let mine = vault(&h, support::TESTER);
    let dir = h.runtime.block_on(mine.node(ino(&v))).unwrap();
    let dirent = |name: &str| {
        let mut key = vec![0x03];
        key.extend_from_slice(&ino(&v).to_be_bytes());
        key.extend_from_slice(dir.tag(OsStr::new(name)).as_bytes());
        key
    };
    // What a server could do: file a's entry, sealed name and all, under
    // b's tag too.
    let a = h.read_key(&dirent("a")).unwrap();
    h.write_key(&dirent("b"), Some(&a));

    let fresh = vault(&h, support::TESTER);
    let listed: Vec<String> = h
        .runtime
        .block_on(fresh.readdir(ino(&v)))
        .unwrap()
        .into_iter()
        .map(|item| item.name.into_string().unwrap())
        .collect();
    assert_eq!(listed, [".", "..", "a"]);
}

// ------------------------------------------------------------------- data

const CHUNK: usize = support::TEST_CHUNK_SIZE as usize;

/// Position-dependent bytes, as in `fuse_fs`, so data landing at the wrong
/// offset fails loudly.
fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ salt).collect()
}

#[test]
fn no_data_reaches_the_store() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("v")).unwrap();
    let f = h.path().join("v/f");
    let marker = b"zebra-stripes-";
    // Whole chunks, a partial one, and a patch in the middle of one.
    let mut data: Vec<u8> = marker
        .iter()
        .copied()
        .cycle()
        .take(2 * CHUNK + 1000)
        .collect();
    fs::write(&f, &data).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&f).unwrap();
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(CHUNK as u64 + 7)).unwrap();
    file.write_all(marker).unwrap();
    drop(file);
    data[CHUNK + 7..CHUNK + 7 + marker.len()].copy_from_slice(marker);
    assert!(fs::read(&f).unwrap() == data, "the file reads back changed");
    assert_nowhere_in_store(&h, marker);
}

#[test]
fn data_reads_back_through_overwrites_holes_and_truncation() {
    use std::io::{Seek, SeekFrom, Write};
    let h = support::setup_root();
    fs::create_dir(h.path().join("v")).unwrap();
    let f = h.path().join("v/f");
    let mut model = pattern(3 * CHUNK + 500, 0);
    fs::write(&f, &model).unwrap();

    let mut file = fs::OpenOptions::new().write(true).open(&f).unwrap();
    // A patch straddling a chunk boundary.
    let patch = pattern(300, 0x55);
    let at = CHUNK - 100;
    file.seek(SeekFrom::Start(at as u64)).unwrap();
    file.write_all(&patch).unwrap();
    model[at..at + 300].copy_from_slice(&patch);
    // A write past the end leaves a hole of zeros.
    let far = 5 * CHUNK + 3;
    file.seek(SeekFrom::Start(far as u64)).unwrap();
    file.write_all(b"tail").unwrap();
    model.resize(far, 0);
    model.extend_from_slice(b"tail");
    file.sync_all().unwrap();
    assert_eq!(fs::read(&f).unwrap(), model);

    // Cut mid-chunk, then grow again: what was cut reads as zeros.
    let cut = 2 * CHUNK + 10;
    file.set_len(cut as u64).unwrap();
    model.truncate(cut);
    assert_eq!(fs::read(&f).unwrap(), model);
    file.set_len((3 * CHUNK) as u64).unwrap();
    model.resize(3 * CHUNK, 0);
    assert_eq!(fs::read(&f).unwrap(), model);
    // And by path, with no handle: truncate(2).
    drop(file);
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&f)
        .unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"");
}

#[test]
fn concurrent_writes_to_one_chunk_lose_nothing() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("v")).unwrap();
    let f = h.path().join("v/f");
    fs::write(&f, vec![0u8; 1000]).unwrap();
    let file = ino(&f);
    let a = vault(&h, support::TESTER);
    let b = vault(&h, support::TESTER);
    // Each writes its own bytes of the same chunk, over and over; every
    // write is a read-modify-write of the whole chunk.
    h.runtime.block_on(async {
        let left = async {
            for i in 0..20u8 {
                a.write(file, 0, &[i + 1; 10]).await.unwrap();
            }
        };
        let right = async {
            for i in 0..20u8 {
                b.write(file, 500, &[i + 101; 10]).await.unwrap();
            }
        };
        tokio::join!(left, right);
    });
    let data = fs::read(&f).unwrap();
    assert_eq!(&data[0..10], &[20; 10]);
    assert_eq!(&data[500..510], &[120; 10]);
    assert!(data[10..500].iter().all(|&b| b == 0));
}

#[test]
fn the_server_takes_no_mis_sealed_or_stale_data() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("v")).unwrap();
    let f = h.path().join("v/f");
    fs::write(&f, b"sealed").unwrap();
    let file = ino(&f);
    let mine = vault(&h, support::TESTER);
    let remote = mine.remote();

    // A chunk sealed under a key version the file doesn't have.
    let node = h.runtime.block_on(mine.node(file)).unwrap();
    let blob = raft5fs_crypto::data::seal_chunk(&node.key, node.record.version + 1, file, 0, b"x");
    let wrong = raft5fs_core::ChunkWrite {
        index: 0,
        expected_seq: None,
        body: raft5fs_core::WriteBody::Inline(blob),
    };
    assert_fs_errno(
        h.runtime.block_on(remote.write_chunks(file, &[wrong], 1)),
        libc::EKEYEXPIRED,
    );
    // A stale expected seq.
    let blob = raft5fs_crypto::data::seal_chunk(&node.key, node.record.version, file, 0, b"x");
    let stale = raft5fs_core::ChunkWrite {
        index: 0,
        expected_seq: Some(1),
        body: raft5fs_core::WriteBody::Inline(blob),
    };
    assert_fs_errno(
        h.runtime.block_on(remote.write_chunks(file, &[stale], 1)),
        libc::EAGAIN,
    );
    assert_eq!(fs::read(&f).unwrap(), b"sealed");
}

// ------------------------------------------------------------- revocation

/// `ino`'s key record, as stored.
fn record(h: &support::Harness, ino: u64) -> NodeKeys {
    let mut key = vec![0x08];
    key.extend_from_slice(&ino.to_be_bytes());
    NodeKeys::decode(&h.read_key(&key).unwrap()).unwrap()
}

/// Chunk `index` of file `ino`, sealed, as stored.
fn stored_chunk(h: &support::Harness, ino: u64, index: u64) -> Vec<u8> {
    let mut key = vec![0x02];
    key.extend_from_slice(&ino.to_be_bytes());
    key.extend_from_slice(&index.to_be_bytes());
    h.read_key(&key).unwrap()
}

#[test]
fn a_block_pointer_is_never_read_as_a_hole() {
    let h = support::setup_root();
    fs::create_dir(h.path().join("v")).unwrap();
    let f = h.path().join("v/f");
    fs::write(&f, b"sealed").unwrap();
    let file = ino(&f);
    // What a hybrid file keeps under a block's first chunk key: 32 bytes,
    // starting with the key version, as a sealed chunk does. This file is
    // all inline, so it can only be corruption.
    let mut pointer = record(&h, file).version.to_be_bytes().to_vec();
    pointer.resize(32, 7);
    let mut key = vec![0x02];
    key.extend_from_slice(&file.to_be_bytes());
    key.extend_from_slice(&0u64.to_be_bytes());
    h.write_key(&key, Some(&pointer));
    let mine = vault(&h, support::TESTER);
    assert_fs_errno(
        h.runtime
            .block_on(mine.remote().read_chunks(file, 0, 1, &[])),
        libc::EIO,
    );
}

/// A volume `v` holding `shared/sub/f` and `shared/sub/g`, each with some
/// bytes in it.
fn shared_tree(h: &support::Harness) -> std::path::PathBuf {
    let v = h.path().join("v");
    fs::create_dir_all(v.join("shared/sub")).unwrap();
    fs::write(v.join("shared/sub/f"), b"before").unwrap();
    fs::write(v.join("shared/sub/g"), b"untouched").unwrap();
    v
}

#[test]
fn a_revoked_user_is_cut_off_and_new_writes_are_sealed_beyond_them() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    let (sub, f, g) = (
        ino(&v.join("shared/sub")),
        ino(&v.join("shared/sub/f")),
        ino(&v.join("shared/sub/g")),
    );
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    // Everything alice could ever learn: the keys as they are now.
    let hers = vault(&h, "alice");
    let her_sub_key = h.runtime.block_on(hers.node(sub)).unwrap().key.clone();
    let her_f_key = h.runtime.block_on(hers.node(f)).unwrap().key.clone();
    let alice = h.mount_as("alice");
    assert_eq!(
        fs::read(alice.path.join("v/shared/sub/f")).unwrap(),
        b"before"
    );

    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();

    // Cut off at once, open mount and all.
    assert!(names(&alice.path).is_empty());
    let remote = hers.remote();
    assert_fs_errno(h.runtime.block_on(remote.getattr(f)), libc::EACCES);
    assert_fs_errno(
        h.runtime.block_on(remote.read_chunks(f, 0, 1, &[])),
        libc::EACCES,
    );

    // The volume has a new key; what is under it is stale until written.
    assert_eq!(record(&h, ino(&v)).version, 2);
    assert_eq!(record(&h, sub).version, 1);
    // A write sealed under f's old key is refused, stale as it is.
    let old = h.runtime.block_on(mine.node(f)).unwrap();
    let blob = raft5fs_crypto::data::seal_chunk(&old.key, old.record.version, f, 0, b"leaky");
    let write = raft5fs_core::ChunkWrite {
        index: 0,
        expected_seq: None,
        body: raft5fs_core::WriteBody::Inline(blob),
    };
    assert_fs_errno(
        h.runtime
            .block_on(mine.remote().write_chunks(f, &[write], 5)),
        libc::EKEYEXPIRED,
    );

    // Writing through the mount rotates the stale path on the way.
    fs::write(v.join("shared/sub/f"), b"after").unwrap();
    fs::write(v.join("shared/sub/new"), b"new").unwrap();
    assert_eq!(record(&h, ino(&v.join("shared"))).version, 2);
    assert_eq!(record(&h, sub).version, 2);
    assert_eq!(record(&h, f).version, 2);
    assert_eq!(fs::read(v.join("shared/sub/f")).unwrap(), b"after");

    // None of it opens with what alice had.
    let chunk = stored_chunk(&h, f, 0);
    assert!(raft5fs_crypto::data::open_chunk(&her_f_key, f, 0, &chunk).is_err());
    let new = ino(&v.join("shared/sub/new"));
    assert!(record(&h, new).open(new, &her_sub_key).is_err());
    assert!(record(&h, sub).name_key(sub, &her_sub_key).is_err());

    // What was written before is still readable, through the history.
    let fresh = vault(&h, support::TESTER);
    assert_eq!(
        h.runtime.block_on(fresh.read(g, 0, 100)).unwrap(),
        b"untouched"
    );
}

#[test]
fn a_revocation_keeps_the_grants_below_it_usable() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    let sub = ino(&v.join("shared/sub"));
    h.add_user("alice");
    h.add_user("bob");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    h.runtime
        .block_on(mine.grant(sub, "bob", true, OsStr::new("sub")))
        .unwrap();

    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();

    // Bob's grant -- and the path down to it -- has new keys already: bob
    // can't reach above his grant to rotate anything there himself.
    assert_eq!(record(&h, sub).version, 2);
    assert_eq!(record(&h, ino(&v.join("shared"))).version, 2);
    let bobs = vault(&h, "bob");
    let grants = h.runtime.block_on(bobs.remote().list_grants()).unwrap();
    assert_eq!(grants[0].key_version, 2);
    let bob = h.mount_as("bob");
    fs::write(bob.path.join("sub/from-bob"), b"hi").unwrap();
    assert_eq!(fs::read(bob.path.join("sub/f")).unwrap(), b"before");
    assert_eq!(fs::read(v.join("shared/sub/from-bob")).unwrap(), b"hi");
}

#[test]
fn revoking_takes_the_key_above_unless_it_is_a_volume() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    let shared = ino(&v.join("shared"));
    h.add_user("alice");
    h.add_user("bob");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(shared, "alice", true, OsStr::new("shared")))
        .unwrap();
    let hers = vault(&h, "alice");
    h.runtime
        .block_on(hers.grant(shared, "bob", false, OsStr::new("shared")))
        .unwrap();

    // Alice can't reach `v`, so she can't wrap a new key for `shared`.
    assert_fs_errno(h.runtime.block_on(hers.revoke(shared, "bob")), libc::EACCES);
    assert_fs_errno(
        h.runtime.block_on(mine.revoke(shared, "carol")),
        libc::ENOENT,
    );
    h.runtime.block_on(mine.revoke(shared, "bob")).unwrap();
    let bobs = vault(&h, "bob");
    assert!(
        h.runtime
            .block_on(bobs.remote().list_grants())
            .unwrap()
            .is_empty()
    );
    // Alice's own grant came through re-sealed.
    let alice = h.mount_as("alice");
    assert_eq!(
        fs::read(alice.path.join("shared/sub/f")).unwrap(),
        b"before"
    );
}

#[test]
fn concurrent_writers_rotate_a_stale_path_once() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    let f = ino(&v.join("shared/sub/f"));
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();

    let a = vault(&h, support::TESTER);
    let b = vault(&h, support::TESTER);
    h.runtime.block_on(async {
        let (x, y) = tokio::join!(a.write(f, 0, b"aaaa"), b.write(f, 10, b"bbbb"));
        x.unwrap();
        y.unwrap();
    });
    for path in ["shared", "shared/sub", "shared/sub/f"] {
        assert_eq!(record(&h, ino(&v.join(path))).version, 2, "{path}");
    }
    let data = fs::read(v.join("shared/sub/f")).unwrap();
    assert_eq!(&data[0..4], b"aaaa");
    assert_eq!(&data[10..14], b"bbbb");
}

#[test]
fn a_changed_public_key_is_refused_until_forgotten() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    let first = h
        .runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();

    // Alice enrols again -- or the server says she did, with its own key.
    let second = h.enrol("alice");
    assert_ne!(first, second);
    let shared = ino(&v.join("shared"));
    let refused = h
        .runtime
        .block_on(mine.grant(shared, "alice", false, OsStr::new("shared")));
    assert_fs_errno(refused, libc::EPERM);
    // Nor does a rotation re-seal a grant made to the new key by someone
    // who never pinned the old one.
    h.add_user("bob");
    h.runtime
        .block_on(mine.grant(ino(&v), "bob", true, OsStr::new("v")))
        .unwrap();
    let bobs = vault(&h, "bob");
    h.runtime
        .block_on(bobs.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    assert_fs_errno(h.runtime.block_on(mine.revoke(ino(&v), "bob")), libc::EPERM);

    mine.known_keys().forget("alice").unwrap();
    assert_eq!(
        h.runtime
            .block_on(mine.grant(shared, "alice", false, OsStr::new("shared")))
            .unwrap(),
        second
    );
}

// ---------------------------------------------------------------- pruning

/// `dir` and everything under it, parents first.
fn tree(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    let mut i = 0;
    while i < out.len() {
        if out[i].is_dir() {
            let mut children: Vec<_> = fs::read_dir(&out[i])
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            children.sort();
            out.extend(children);
        }
        i += 1;
    }
    out
}

/// The stored values under `prefix`.
fn values_under(h: &support::Harness, prefix: &[u8]) -> Vec<Vec<u8>> {
    h.keys_with_prefix(prefix)
        .into_iter()
        .filter(|k| k.starts_with(prefix))
        .filter_map(|k| h.read_key(&k))
        .collect()
}

/// That nothing under `dir` is sealed under anything but its node's
/// current key, nor wrapped under anything but its parent's, and that no
/// key history is left.
#[track_caller]
fn assert_fully_pruned(h: &support::Harness, dir: &Path) {
    use raft5fs_crypto::data::sealed_version;
    for path in tree(dir) {
        let n = ino(&path);
        let rec = record(h, n);
        assert_eq!(rec.base(), rec.version, "{path:?} still has a history");
        if path.is_dir() {
            for value in values_under(h, &raft5fs_core::dirent_prefix(n)) {
                assert_eq!(sealed_version(&value[8..]).unwrap(), rec.version);
                let child = u64::from_be_bytes(value[..8].try_into().unwrap());
                assert_eq!(record(h, child).parent_version, rec.version);
            }
        } else {
            for chunk in values_under(h, &raft5fs_core::chunk_prefix(n)) {
                assert_eq!(sealed_version(&chunk).unwrap(), rec.version, "{path:?}");
            }
        }
    }
}

/// `shared_tree` with a multi-chunk file in it too, granted to alice and
/// revoked again, then partly written: some of it rotated since, some of
/// it stale. Returns the volume, and the key alice held for `g`.
fn revoked_tree(h: &support::Harness) -> (std::path::PathBuf, raft5fs_crypto::Key) {
    let v = shared_tree(h);
    let big: Vec<u8> = (0..h.chunk_size * 5 / 2).map(|i| i as u8).collect();
    fs::write(v.join("shared/sub/big"), &big).unwrap();
    h.add_user("alice");
    let mine = vault(h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    let hers = vault(h, "alice");
    let her_g_key = h
        .runtime
        .block_on(hers.node(ino(&v.join("shared/sub/g"))))
        .unwrap()
        .key
        .clone();
    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();
    // Rotates v/shared, sub and f on the way, leaving g and big stale.
    fs::write(v.join("shared/sub/f"), b"after").unwrap();
    (v, her_g_key)
}

#[test]
fn pruning_reseals_everything_and_drops_every_old_version() {
    let h = support::setup_root();
    let (v, her_g_key) = revoked_tree(&h);
    let g = ino(&v.join("shared/sub/g"));
    let big = fs::read(v.join("shared/sub/big")).unwrap();
    let g_mtime = fs::metadata(v.join("shared/sub/g")).unwrap().mtime();
    assert!(record(&h, ino(&v)).base() < record(&h, ino(&v)).version);

    let mine = vault(&h, support::TESTER);
    let dry = h.runtime.block_on(mine.prune_tree(ino(&v), true));
    assert!(dry.skipped.is_empty(), "{:?}", dry.skipped);
    assert!(dry.chunks > 0 && dry.names > 0 && dry.rotated > 0 && dry.dropped > 0);
    assert!(
        record(&h, ino(&v)).base() < record(&h, ino(&v)).version,
        "a dry run changes nothing"
    );

    let stats = h.runtime.block_on(mine.prune_tree(ino(&v), false));
    assert!(stats.skipped.is_empty(), "{:?}", stats.skipped);
    assert_eq!(stats.nodes, tree(&v).len());
    assert_eq!(
        (stats.chunks, stats.names, stats.rotated),
        (dry.chunks, dry.names, dry.rotated)
    );
    assert_fully_pruned(&h, &v);

    // Everything reads as before, through a fresh login and the mount,
    // and nothing's times moved.
    assert_eq!(fs::read(v.join("shared/sub/f")).unwrap(), b"after");
    assert_eq!(fs::read(v.join("shared/sub/g")).unwrap(), b"untouched");
    assert_eq!(fs::read(v.join("shared/sub/big")).unwrap(), big);
    assert_eq!(
        fs::metadata(v.join("shared/sub/g")).unwrap().mtime(),
        g_mtime
    );
    let fresh = vault(&h, support::TESTER);
    assert_eq!(
        h.runtime.block_on(fresh.read(g, 0, 100)).unwrap(),
        b"untouched"
    );
    // And what alice held no longer opens any of it.
    let chunk = stored_chunk(&h, g, 0);
    assert!(raft5fs_crypto::data::open_chunk(&her_g_key, g, 0, &chunk).is_err());

    // A second run finds nothing to do.
    let again = h.runtime.block_on(mine.prune_tree(ino(&v), false));
    assert!(again.skipped.is_empty(), "{:?}", again.skipped);
    assert_eq!(
        (again.chunks, again.names, again.rotated, again.dropped),
        (0, 0, 0, 0)
    );
}

#[test]
fn a_prune_is_refused_while_anything_is_under_a_version_it_drops() {
    let h = support::setup_root();
    let (v, _) = revoked_tree(&h);
    let g = ino(&v.join("shared/sub/g"));
    let sub = ino(&v.join("shared/sub"));
    let mine = vault(&h, support::TESTER);
    let remote = mine.remote();
    // A new key for g, its chunk still sealed under the old one.
    h.runtime.block_on(mine.freshen(g)).unwrap();
    let rec = record(&h, g);
    assert_eq!(rec.base(), 1);
    assert_fs_errno(
        h.runtime
            .block_on(remote.prune_keys(g, rec.version, rec.pruned(rec.version).encode())),
        libc::EBUSY,
    );
    // sub's entries' names are still under its old key.
    let rec = record(&h, sub);
    assert_fs_errno(
        h.runtime
            .block_on(remote.prune_keys(sub, rec.version, rec.pruned(rec.version).encode())),
        libc::EBUSY,
    );
    // v's child `shared` is fresh, but its name in v isn't.
    let top = ino(&v);
    let rec = record(&h, top);
    assert_fs_errno(
        h.runtime
            .block_on(remote.prune_keys(top, rec.version, rec.pruned(rec.version).encode())),
        libc::EBUSY,
    );
    // Only cutting a history short is a prune.
    let rec = record(&h, g);
    assert_fs_errno(
        h.runtime
            .block_on(remote.prune_keys(g, rec.version, record(&h, sub).encode())),
        libc::EINVAL,
    );
    assert_fs_errno(
        h.runtime
            .block_on(remote.prune_keys(g, rec.version - 1, rec.pruned(rec.version).encode())),
        libc::EAGAIN,
    );
    assert_eq!(record(&h, g).base(), 1, "nothing was cut");
}

#[test]
fn names_sealed_under_an_old_key_are_refused() {
    let h = support::setup_root();
    let (v, _) = revoked_tree(&h);
    let sub = ino(&v.join("shared/sub"));
    let mine = vault(&h, support::TESTER);
    let node = h.runtime.block_on(mine.node(sub)).unwrap();
    let old = node
        .record
        .older(sub, &node.key, node.record.version - 1)
        .unwrap();
    let tag = node.tag(OsStr::new("leaky"));
    let leaky = h.runtime.block_on(mine.remote().allocate_inode()).unwrap();
    let new = NewNode {
        ino: leaky,
        keys: NodeKeys::create(0, Some((&node.key, node.record.version)))
            .0
            .encode(),
        sealed_name: raft5fs_crypto::data::seal_name(
            &old,
            node.record.version - 1,
            sub,
            leaky,
            tag.as_bytes(),
            b"leaky",
        ),
    };
    assert_fs_errno(
        h.runtime
            .block_on(mine.remote().create(sub, &tag, 0o644, &new)),
        libc::EKEYEXPIRED,
    );
}

#[test]
fn pruning_through_a_read_only_grant_changes_nothing() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    h.add_user("alice");
    h.add_user("bob");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    h.runtime
        .block_on(mine.grant(ino(&v), "bob", false, OsStr::new("v")))
        .unwrap();
    h.runtime.block_on(mine.revoke(ino(&v), "bob")).unwrap();
    let before = record(&h, ino(&v));
    assert!(before.base() < before.version);

    let hers = vault(&h, "alice");
    let roots = h.runtime.block_on(hers.grant_roots()).unwrap();
    assert_eq!(roots.len(), 1);
    assert!(!roots[0].writable);
    let stats = h.runtime.block_on(hers.prune_tree(ino(&v), false));
    assert_eq!(stats.skipped.len(), 1);
    assert_eq!(stats.skipped[0].1.errno, libc::EROFS);
    assert_eq!(record(&h, ino(&v)), before);
}

#[test]
fn pruning_while_a_mount_writes_loses_nothing() {
    let h = support::setup_root();
    let (v, _) = revoked_tree(&h);
    let f = v.join("shared/sub/f");
    let writer = {
        let f = f.clone();
        std::thread::spawn(move || {
            for i in 0..40u32 {
                fs::write(&f, format!("write {i}")).unwrap();
            }
        })
    };
    let mine = vault(&h, support::TESTER);
    let stats = h.runtime.block_on(mine.prune_tree(ino(&v), false));
    writer.join().unwrap();
    assert!(stats.skipped.is_empty(), "{:?}", stats.skipped);
    assert_eq!(fs::read(&f).unwrap(), b"write 39");
    assert_fully_pruned(&h, &v);
}

// ------------------------------------------------------------------ cache

#[test]
fn a_small_write_into_a_cached_chunk_fetches_nothing() {
    let h = support::setup();
    let f = h.path().join("f");
    fs::write(&f, b"").unwrap();
    let file = ino(&f);
    let mine = vault(&h, support::TESTER);
    let remote = mine.remote();
    let run = |offset, data: &[u8]| h.runtime.block_on(mine.write(file, offset, data)).unwrap();

    run(0, &[1; 100]);
    let after_first = remote.chunk_reads();
    // What it wrote it cached, so changing a few bytes of it -- a
    // read-modify-write of the whole chunk -- needs nothing from the
    // server, and neither does reading it back.
    run(10, &[2; 5]);
    run(50, &[3; 5]);
    let read = h.runtime.block_on(mine.read(file, 0, 100)).unwrap();
    assert_eq!(remote.chunk_reads(), after_first);
    let mut expected = vec![1; 100];
    expected[10..15].fill(2);
    expected[50..55].fill(3);
    assert_eq!(read, expected);
}

#[test]
fn a_cached_chunk_is_never_served_stale() {
    let h = support::setup();
    let f = h.path().join("f");
    fs::write(&f, vec![1; 1000]).unwrap();
    let file = ino(&f);
    let reader = vault(&h, support::TESTER);
    let writer = vault(&h, support::TESTER);
    assert_eq!(h.runtime.block_on(reader.read(file, 0, 4)).unwrap(), [1; 4]);

    h.runtime.block_on(writer.write(file, 0, &[9; 4])).unwrap();
    assert_eq!(h.runtime.block_on(reader.read(file, 0, 4)).unwrap(), [9; 4]);

    // And a write based on a stale cached copy is refused by its seq, and
    // redone on fresh bytes: the other writer's change survives.
    h.runtime
        .block_on(writer.write(file, 100, &[8; 4]))
        .unwrap();
    h.runtime
        .block_on(reader.write(file, 200, &[7; 4]))
        .unwrap();
    let data = h.runtime.block_on(writer.read(file, 0, 1000)).unwrap();
    assert_eq!(&data[100..104], &[8; 4]);
    assert_eq!(&data[200..204], &[7; 4]);
}

// ------------------------------------------------------- a malicious store

/// Plants a grant of `ino` to `user` straight in the store, as a server
/// that wanted the next rotation to seal `ino`'s new key to `user` would.
fn plant_grant(h: &support::Harness, ino: u64, user: &str) {
    let mut row = vec![0x07];
    row.extend_from_slice(&ino.to_be_bytes());
    row.extend_from_slice(user.as_bytes());
    // Read-only, version 1, an empty sealed key and an empty label.
    let value = [0u8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    h.write_key(&row, Some(&value));
    let mut index = vec![0x09];
    index.extend_from_slice(user.as_bytes());
    index.push(0);
    index.extend_from_slice(&ino.to_be_bytes());
    h.write_key(&index, Some(&[]));
}

#[test]
fn a_rotation_seals_to_no_grantee_the_server_made_up() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    h.add_user("alice");
    h.add_user("eve");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    plant_grant(&h, ino(&v), "eve");

    let revoked = h.runtime.block_on(mine.revoke(ino(&v), "alice"));
    assert_fs_errno(revoked, libc::EPERM);
    // Whatever eve's grant holds, it isn't the volume's key.
    let eves = vault(&h, "eve");
    assert!(h.runtime.block_on(eves.node(ino(&v))).is_err());
    // Nor does sharing on seal anything to her.
    h.add_user("bob");
    assert_fs_errno(
        h.runtime
            .block_on(mine.grant(ino(&v), "bob", false, OsStr::new("v"))),
        libc::EPERM,
    );

    // Revoking her own made-up grant takes no one's say-so -- and then
    // the rest goes ahead, sealed beyond her.
    h.runtime.block_on(mine.revoke(ino(&v), "eve")).unwrap();
    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();
    assert!(h.runtime.block_on(eves.node(ino(&v))).is_err());
    let after = vault(&h, support::TESTER);
    let grantees = h.runtime.block_on(after.grantees(ino(&v))).unwrap();
    let names: Vec<_> = grantees.iter().map(|g| g.user.as_str()).collect();
    assert_eq!(names, [support::TESTER]);
}

#[test]
fn grants_made_at_once_both_stay_on_the_sealed_list() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    let users = ["alice", "bob", "carol", "dave"];
    for user in users {
        h.add_user(user);
    }
    let vaults: Vec<Vault> = users.iter().map(|_| vault(&h, support::TESTER)).collect();
    let grant = |i: usize| vaults[i].grant(ino(&v), users[i], false, OsStr::new("v"));
    h.runtime.block_on(async {
        let (a, b, c, d) = tokio::join!(grant(0), grant(1), grant(2), grant(3));
        for granted in [a, b, c, d] {
            granted.unwrap();
        }
    });
    // Every one of them is on the list a revocation checks against.
    let mine = vault(&h, support::TESTER);
    let mut names: Vec<_> = h
        .runtime
        .block_on(mine.grantees(ino(&v)))
        .unwrap()
        .into_iter()
        .map(|g| g.user)
        .collect();
    names.sort();
    assert_eq!(names, ["alice", "bob", "carol", "dave", support::TESTER]);
    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();
}

/// The store row of `user`'s grant index entry for `ino`.
fn grant_index_key(user: &str, ino: u64) -> Vec<u8> {
    let mut key = vec![0x09];
    key.extend_from_slice(user.as_bytes());
    key.push(0);
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

#[test]
fn a_share_from_someone_unpinned_is_read_only_until_trusted() {
    let h = support::setup_root();
    fs::create_dir(h.root().join("photos")).unwrap();
    let real = ino(&h.root().join("photos"));
    // Mallory -- or a server making her up -- shares a volume of her own
    // with the tester, called what the tester's own volume is called...
    let mallory_key = h.enrol("mallory");
    let hers = vault(&h, "mallory");
    let fake = h
        .runtime
        .block_on(hers.create_volume(OsStr::new("mine"), 0o755))
        .unwrap()
        .ino;
    h.runtime
        .block_on(hers.grant(fake, support::TESTER, true, OsStr::new("photos")))
        .unwrap();
    // ...and the server stops listing the real one.
    h.write_key(&grant_index_key(support::TESTER, real), None);

    // The tester's mount shows hers as "photos", and reads it, but writes
    // nothing there: it would be the server's to read.
    let mount = h.second_mount();
    assert_eq!(names(&mount.root), ["photos"]);
    assert_eq!(ino(&mount.root.join("photos")), fake);
    assert!(names(&mount.root.join("photos")).is_empty());
    assert_errno(
        fs::write(mount.root.join("photos/holiday.jpg"), b"secret"),
        libc::EACCES,
    );
    assert_errno(fs::create_dir(mount.root.join("photos/2024")), libc::EACCES);
    let mine = vault(&h, support::TESTER);
    assert_fs_errno(
        h.runtime
            .block_on(mine.grant(fake, "mallory", true, OsStr::new("x"))),
        libc::EACCES,
    );

    // Trusting her takes her key's real fingerprint.
    let wrong = raft5fs_crypto::identity::fingerprint(&h.tester_key);
    assert_fs_errno(
        h.runtime.block_on(mine.trust("mallory", &wrong)),
        libc::EPERM,
    );
    assert!(
        h.runtime
            .block_on(mine.create(fake, OsStr::new("f"), 0o644))
            .is_err()
    );
    let right = raft5fs_crypto::identity::fingerprint(&mallory_key);
    h.runtime.block_on(mine.trust("mallory", &right)).unwrap();
    h.runtime
        .block_on(mine.create(fake, OsStr::new("f"), 0o644))
        .unwrap();
}

#[test]
fn an_entry_pointed_at_another_inode_is_refused() {
    let h = support::setup_root();
    let v = h.path().join("v");
    fs::create_dir(&v).unwrap();
    fs::write(v.join("a"), b"a").unwrap();
    fs::write(v.join("b"), b"b").unwrap();
    let mine = vault(&h, support::TESTER);
    let dir = h.runtime.block_on(mine.node(ino(&v))).unwrap();
    let dirent = |name: &str| {
        let mut key = vec![0x03];
        key.extend_from_slice(&ino(&v).to_be_bytes());
        key.extend_from_slice(dir.tag(OsStr::new(name)).as_bytes());
        key
    };
    // What a server could do: keep each entry's sealed name, but point it
    // at the other's inode -- so that what is written to "a" lands in b.
    let mut a = h.read_key(&dirent("a")).unwrap();
    let mut b = h.read_key(&dirent("b")).unwrap();
    let a_ino: [u8; 8] = a[..8].try_into().unwrap();
    a[..8].copy_from_slice(&b[..8]);
    b[..8].copy_from_slice(&a_ino);
    h.write_key(&dirent("a"), Some(&a));
    h.write_key(&dirent("b"), Some(&b));

    let fresh = vault(&h, support::TESTER);
    let listed: Vec<String> = h
        .runtime
        .block_on(fresh.readdir(ino(&v)))
        .unwrap()
        .into_iter()
        .map(|item| item.name.into_string().unwrap())
        .collect();
    assert_eq!(listed, [".", ".."]);
    assert_fs_errno(
        h.runtime.block_on(fresh.lookup(ino(&v), OsStr::new("a"))),
        libc::EIO,
    );
    let mount = h.second_mount();
    assert_errno(fs::write(mount.root.join("v/a"), b"for a"), libc::EIO);
}

#[test]
fn a_key_record_rolled_back_is_refused() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    let v_ino = ino(&v);
    h.add_user("alice");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(v_ino, "alice", false, OsStr::new("v")))
        .unwrap();
    let mut record_key = vec![0x08];
    record_key.extend_from_slice(&v_ino.to_be_bytes());
    let mut grant_key = vec![0x07];
    grant_key.extend_from_slice(&v_ino.to_be_bytes());
    grant_key.extend_from_slice(support::TESTER.as_bytes());
    let (old_record, old_grant) = (
        h.read_key(&record_key).unwrap(),
        h.read_key(&grant_key).unwrap(),
    );

    h.runtime.block_on(mine.revoke(v_ino, "alice")).unwrap();
    assert_eq!(
        h.runtime.block_on(mine.node(v_ino)).unwrap().record.version,
        2
    );

    // The server hands back the record and grant from before, whose key
    // alice holds: nothing new may be sealed under that.
    h.write_key(&record_key, Some(&old_record));
    h.write_key(&grant_key, Some(&old_grant));
    assert_fs_errno(h.runtime.block_on(mine.freshen(v_ino)).map(drop), libc::EIO);
}

#[test]
fn a_login_without_tls_is_refused_unless_asked_for() {
    let h = support::setup_root();
    let credentials = support::credentials(support::TESTER);
    let plain = h.runtime.block_on(Remote::connect(
        &["http://127.0.0.1:1".to_string()],
        credentials.clone(),
        None,
    ));
    assert!(plain.err().unwrap().contains("without TLS"));
    let http = h.runtime.block_on(Remote::connect(
        &["http://127.0.0.1:1".to_string()],
        credentials.clone(),
        Some(support::fs_tls()),
    ));
    assert!(http.err().unwrap().contains("only https://"));
    // Allowed, it gets as far as the (missing) server.
    let allowed = Credentials {
        allow_plaintext: true,
        ..credentials
    };
    let tried = h.runtime.block_on(Remote::connect(
        &["http://127.0.0.1:1".to_string()],
        allowed,
        None,
    ));
    assert!(!tried.err().unwrap().contains("refusing"));
}

#[test]
fn a_name_that_could_break_a_line_is_no_account() {
    let h = support::setup_root();
    for bad in ["x\nalice 00", "Alice", "a b", ""] {
        let issued = h.runtime.block_on(accounts::issue_code(&h.client, bad));
        assert_fs_errno(issued, libc::EINVAL);
    }
    let mine = vault(&h, support::TESTER);
    fs::create_dir(h.root().join("v")).unwrap();
    let granted = h.runtime.block_on(mine.grant(
        ino(&h.root().join("v")),
        "x\nalice 00",
        false,
        OsStr::new("v"),
    ));
    assert_fs_errno(granted, libc::EINVAL);
}

// ------------------------------------------------- shares and the pruner

/// A prune queue of its own, in a fresh temporary directory.
fn temp_queue(name: &str) -> raft5fs_fuse::prune_queue::PruneQueue {
    let dir = std::env::temp_dir().join(format!(
        "raft5fs-test-queue-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    raft5fs_fuse::prune_queue::PruneQueue::at(dir)
}

#[test]
fn shares_say_whose_they_are_and_whether_trusted() {
    use raft5fs_fuse::vault::ShareTrust;
    let h = support::setup_root();
    let v = shared_tree(&h);
    h.add_user("alice");
    let mallory_key = h.enrol("mallory");
    let mine = vault(&h, support::TESTER);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("from-tester")))
        .unwrap();
    let hers = vault(&h, "mallory");
    let fake = h
        .runtime
        .block_on(hers.create_volume(OsStr::new("m"), 0o755))
        .unwrap()
        .ino;
    h.runtime
        .block_on(hers.grant(fake, "alice", true, OsStr::new("from-mallory")))
        .unwrap();

    let alices = vault(&h, "alice");
    let shares = h.runtime.block_on(alices.shares()).unwrap();
    let by_label = |label: &str| {
        shares
            .iter()
            .find(|s| s.label == label)
            .unwrap_or_else(|| panic!("no share {label}"))
    };
    let tester = by_label("from-tester");
    assert_eq!(tester.sender, support::TESTER);
    assert!(matches!(tester.trust, ShareTrust::Trusted));
    let mallory = by_label("from-mallory");
    assert_eq!((mallory.sender.as_str(), mallory.ino), ("mallory", fake));
    match &mallory.trust {
        ShareTrust::Untrusted { key } => assert_eq!(*key, mallory_key),
        other => panic!("{other:?}"),
    }
    // Trusting her, by the words she would read out, changes that.
    let words = raft5fs_crypto::identity::fingerprint_words(&mallory_key);
    h.runtime.block_on(alices.trust("mallory", &words)).unwrap();
    let shares = h.runtime.block_on(alices.shares()).unwrap();
    assert!(
        shares
            .iter()
            .all(|s| matches!(s.trust, ShareTrust::Trusted))
    );
}

#[test]
fn a_mount_prunes_what_is_queued_in_the_background() {
    let h = support::setup_root();
    let (v, _) = revoked_tree(&h);
    let f = v.join("shared/sub/f");
    let queue = temp_queue("background");
    queue.add(ino(&v), "v (revoked alice)").unwrap();
    let dir = queue.dir().to_path_buf();
    let _mount = h.pruning_mount(queue);
    // Writes through the first mount go on meanwhile.
    let writer = {
        let f = f.clone();
        std::thread::spawn(move || {
            for i in 0..40u32 {
                fs::write(&f, format!("write {i}")).unwrap();
            }
        })
    };
    let queue = raft5fs_fuse::prune_queue::PruneQueue::at(dir);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !queue.entries().unwrap().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "still queued: {:?}",
            queue.statuses()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    writer.join().unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"write 39");
    assert_fully_pruned(&h, &v);
    let _ = fs::remove_dir_all(queue.dir());
}

#[test]
fn a_prune_that_skips_anything_stays_queued() {
    let h = support::setup_root();
    let v = shared_tree(&h);
    h.add_user("alice");
    h.add_user("bob");
    let mine = vault(&h, support::TESTER);
    for user in ["alice", "bob"] {
        h.runtime
            .block_on(mine.grant(ino(&v), user, false, OsStr::new("v")))
            .unwrap();
    }
    h.runtime.block_on(mine.revoke(ino(&v), "bob")).unwrap();

    // Alice can't prune what she may only read: it stays queued, saying
    // why, for someone who can.
    let queue = temp_queue("skips");
    queue.add(ino(&v), "v").unwrap();
    let hers = vault(&h, "alice");
    let stats = h.runtime.block_on(raft5fs_fuse::pruner::prune_entry(
        &hers,
        &queue,
        ino(&v),
        std::time::Duration::ZERO,
    ));
    assert!(!stats.skipped.is_empty());
    assert_eq!(queue.entries().unwrap().len(), 1);
    let status = &queue.statuses().unwrap()[&ino(&v)];
    assert!(status.starts_with("incomplete"), "{status}");

    // The tester can, which empties it.
    let stats = h.runtime.block_on(raft5fs_fuse::pruner::prune_entry(
        &mine,
        &queue,
        ino(&v),
        std::time::Duration::ZERO,
    ));
    assert!(stats.skipped.is_empty(), "{:?}", stats.skipped);
    assert!(queue.entries().unwrap().is_empty());
    assert_fully_pruned(&h, &v);
    let _ = fs::remove_dir_all(queue.dir());
}
