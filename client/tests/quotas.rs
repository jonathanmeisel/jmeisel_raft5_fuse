//! Tests volume ownership, quotas, folder sizes and limits, transfers and
//! orphaned volumes, against a real store and servers.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::remote::Remote;
use raft5fs_client::vault::Vault;
use raft5fs_core::accounts;
use raft5fs_proto::types::{Caps, FsError};
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

fn make_admin(backend: &Backend, user: &str) {
    backend
        .runtime
        .block_on(accounts::set_caps(
            &backend.client,
            user,
            Caps::ADMIN,
            Caps::NONE,
        ))
        .unwrap();
}

/// Waits up to five seconds for `check` to hold.
fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..50 {
        if check() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("never: {what}");
}

fn used(backend: &Backend, v: &Vault) -> u64 {
    backend.runtime.block_on(v.remote().storage()).unwrap().used
}

#[test]
fn usage_and_folder_sizes_are_measured_and_counted_at_once() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    make_admin(&backend, TESTER);
    backend.enrol("bob");
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let v = rt
        .block_on(tester.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let a = rt
        .block_on(tester.create(v, OsStr::new("a"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(tester.write(a, 0, &[1; 3000])).unwrap();
    let sub = rt
        .block_on(tester.mkdir(v, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    let b = rt
        .block_on(tester.create(sub, OsStr::new("b"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(tester.write(b, 0, &[2; 5000])).unwrap();

    // Measuring: every folder, and the owner.
    rt.block_on(tester.remote().measure_usage()).unwrap();
    assert_eq!(used(&backend, &tester), 8000);
    // The writes before measuring, stored after it, don't count twice.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert_eq!(used(&backend, &tester), 8000);
    let mut sizes = rt
        .block_on(tester.remote().folder_sizes(&[v, sub]))
        .unwrap();
    sizes.sort_by_key(|s| s.ino);
    let got: Vec<_> = sizes.iter().map(|s| (s.ino, s.bytes, s.files)).collect();
    assert_eq!(got, [(v, 8000, 2), (sub, 5000, 1)]);

    // Writes, truncations and deletions count within a second.
    rt.block_on(tester.write(a, 3000, &[1; 1000])).unwrap();
    eventually("a write counts", || used(&backend, &tester) == 9000);
    rt.block_on(tester.unlink(v, OsStr::new("a"))).unwrap();
    eventually("a deletion counts", || used(&backend, &tester) == 5000);

    // What bob writes into the tester's volume counts against the tester.
    rt.block_on(tester.grant(v, "bob", true, OsStr::new("v")))
        .unwrap();
    let bob = vault(&backend, "bob");
    bob.known_keys().check(TESTER, &backend.tester_key).unwrap();
    let c = rt
        .block_on(bob.create(v, OsStr::new("c"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(bob.write(c, 0, &[3; 2000])).unwrap();
    eventually("bob's write counts against the owner", || {
        used(&backend, &tester) == 7000
    });
    assert_eq!(used(&backend, &bob), 0);

    // A folder's size record goes with it, and measuring keeps no other.
    rt.block_on(tester.unlink(sub, OsStr::new("b"))).unwrap();
    rt.block_on(tester.rmdir(v, OsStr::new("sub"))).unwrap();
    rt.block_on(tester.remote().measure_usage()).unwrap();
    assert_eq!(backend.keys_with_prefix(&[0x0D]).len(), 1);
    assert_eq!(used(&backend, &tester), 2000);

    // Only admins measure.
    assert_eq!(
        errno(rt.block_on(bob.remote().measure_usage())),
        libc::EACCES
    );
}
