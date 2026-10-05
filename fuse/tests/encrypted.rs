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
    let credentials = Credentials {
        username: user.to_string(),
        password: password.to_string(),
    };
    h.runtime.block_on(Remote::connect(
        &h.addresses(),
        credentials,
        Some(support::fs_tls()),
    ))
}

/// `user`'s vault: logged in afresh, so it knows no keys yet.
fn vault(h: &support::Harness, user: &str) -> Vault {
    let remote = connect(h, user, &support::password(user)).unwrap();
    Vault::new(Arc::new(remote)).unwrap()
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
        name,
        code,
        password,
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
fn a_store_from_an_unencrypted_raft5fs_is_refused() {
    let h = support::setup_root();
    let check = || h.runtime.block_on(check_store(&h.client));
    check().unwrap();
    // Recorded unencrypted, or from before anything was recorded.
    h.write_key(ENCRYPTED_KEY, Some(&[0]));
    assert!(check().unwrap_err().contains("older, unencrypted raft5fs"));
    h.write_key(ENCRYPTED_KEY, None);
    assert!(check().unwrap_err().contains("older, unencrypted raft5fs"));
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
fn a_moved_node_keeps_its_key_under_its_new_parent() {
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

    fs::rename(v.join("a/f"), v.join("b/f")).unwrap();
    fs::rename(v.join("a/sub"), v.join("b/sub")).unwrap();

    // Only b is shared, so alice reaches them only through their new
    // parent's key -- which works only if the move re-wrapped them.
    h.add_user("alice");
    h.runtime
        .block_on(before.grant(ino(&v.join("b")), "alice", false, OsStr::new("b")))
        .unwrap();
    let alices = vault(&h, "alice");
    assert_eq!(h.runtime.block_on(alices.node(f)).unwrap().key, f_key);
    assert_eq!(h.runtime.block_on(alices.node(sub)).unwrap().key, sub_key);
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
            sealed_name: parent.seal(v, &tag, OsStr::new(name)),
        };
        h.runtime.block_on(remote.create(v, &tag, 0o644, &new))
    };
    let version = parent.record.version;

    // No inode reserved, no key record.
    let tag = parent.tag(OsStr::new("bare"));
    let bare = NewNode {
        ino: 0,
        keys: Vec::new(),
        sealed_name: parent.seal(v, &tag, OsStr::new("bare")),
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
        sealed_name: parent.seal(v, name, name),
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
        blob,
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
        blob,
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
        blob,
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
    // Nor does a rotation re-seal her grant to the new key.
    h.add_user("bob");
    h.runtime
        .block_on(mine.grant(ino(&v), "bob", false, OsStr::new("v")))
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
