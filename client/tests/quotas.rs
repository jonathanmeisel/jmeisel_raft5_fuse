//! Tests volume ownership, quotas, folder sizes and limits, transfers and
//! orphaned volumes, against a real store and servers.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::remote::Remote;
use raft5fs_client::vault::Vault;
use raft5fs_proto::types::FsError;
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, credentials, fs_tls};

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

fn errno<T: std::fmt::Debug>(result: Result<T, FsError>) -> i32 {
    result.unwrap_err().errno
}

fn connect(backend: &Backend, user: &str) -> Remote {
    backend
        .runtime
        .block_on(Remote::connect(
            &backend.addresses(),
            credentials(user),
            Some(fs_tls()),
        ))
        .unwrap_or_else(|e| panic!("log in as {user}: {e}"))
}

fn vault(backend: &Backend, user: &str) -> Vault {
    Vault::new(Arc::new(connect(backend, user))).unwrap()
}

/// The store key of volume `ino`'s record.
fn volume_key(ino: u64) -> Vec<u8> {
    let mut key = vec![0x0C];
    key.extend_from_slice(&ino.to_be_bytes());
    key
}

fn owner(backend: &Backend, v: &Vault, ino: u64) -> Option<String> {
    backend
        .runtime
        .block_on(v.remote().get_volume(ino))
        .unwrap()
        .owner
}

#[test]
fn the_creator_owns_a_volume_and_keeps_read_write_access() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("bob");
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let v = rt
        .block_on(tester.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    assert_eq!(owner(&backend, &tester, v).as_deref(), Some(TESTER));
    rt.block_on(tester.grant(v, "bob", true, OsStr::new("v")))
        .unwrap();
    let bob = vault(&backend, "bob");
    bob.known_keys().check(TESTER, &backend.tester_key).unwrap();
    assert_eq!(owner(&backend, &bob, v).as_deref(), Some(TESTER));

    // Nobody takes the owner's read-write access away; others go as usual.
    assert_eq!(errno(rt.block_on(bob.revoke(v, TESTER))), libc::EPERM);
    assert_eq!(
        errno(rt.block_on(bob.grant(v, TESTER, false, OsStr::new("v")))),
        libc::EPERM
    );
    rt.block_on(tester.revoke(v, "bob")).unwrap();

    // Only volumes have owners; deleting one deletes its record.
    let sub = rt
        .block_on(tester.mkdir(v, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    assert_eq!(
        errno(rt.block_on(tester.remote().get_volume(sub))),
        libc::EINVAL
    );
    rt.block_on(tester.rmdir(v, OsStr::new("sub"))).unwrap();
    assert!(backend.read_key(&volume_key(v)).is_some());
    rt.block_on(tester.delete_volume(OsStr::new("v"))).unwrap();
    assert!(backend.read_key(&volume_key(v)).is_none());
}

#[test]
fn older_volumes_get_their_only_writer_as_owner() {
    let mut backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("bob");
    let (solo, pair, read_only) = {
        let rt = &backend.runtime;
        let tester = vault(&backend, TESTER);
        let make = |name: &str| {
            rt.block_on(tester.create_volume(OsStr::new(name), 0o755))
                .unwrap()
                .ino
        };
        let (solo, pair, read_only) = (make("solo"), make("pair"), make("ro"));
        rt.block_on(tester.grant(pair, "bob", true, OsStr::new("pair")))
            .unwrap();
        rt.block_on(tester.grant(read_only, "bob", false, OsStr::new("ro")))
            .unwrap();
        (solo, pair, read_only)
    };
    // As if they were made before volumes had owners.
    for v in [solo, pair, read_only] {
        backend.write_key(&volume_key(v), None);
    }
    drop(backend.replace_servers(TEST_CHUNK_SIZE));
    let tester = vault(&backend, TESTER);
    assert_eq!(owner(&backend, &tester, solo).as_deref(), Some(TESTER));
    assert_eq!(
        owner(&backend, &tester, pair),
        None,
        "two writers: no owner yet"
    );
    assert_eq!(owner(&backend, &tester, read_only).as_deref(), Some(TESTER));
}
