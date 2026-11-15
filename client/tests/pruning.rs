//! Tests pruning that any writer can finish: what the servers list as
//! waiting for a prune, claims on it, and the listing of key records from
//! before the list was kept.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::pruner::{PrunerConfig, new_holder, prune_claimed};
use raft5fs_client::remote::Remote;
use raft5fs_client::vault::Vault;
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
    // The tester made every grant here; trusting them lets others write.
    if user != TESTER {
        vault
            .known_keys()
            .check(TESTER, &backend.tester_key)
            .unwrap();
    }
    vault
}

/// What waits for a prune that `vault`'s account can write.
fn waiting(backend: &Backend, vault: &Vault) -> Vec<u64> {
    let listed = backend
        .runtime
        .block_on(vault.remote().list_unpruned())
        .unwrap();
    listed.into_iter().map(|u| u.ino).collect()
}

/// A volume with a file in a folder, granted read-write to `writer`, and
/// then granted to and revoked from `revoked`. Returns the volume.
fn revoked_volume(backend: &Backend, writer: &str, revoked: &str) -> u64 {
    let rt = &backend.runtime;
    let tester = vault(backend, TESTER);
    let v = rt
        .block_on(tester.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let d = rt
        .block_on(tester.mkdir(v, OsStr::new("d"), 0o755))
        .unwrap()
        .ino;
    let f = rt
        .block_on(tester.create(d, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(tester.write(f, 0, b"before the revoke"))
        .unwrap();
    rt.block_on(tester.grant(v, writer, true, OsStr::new("v")))
        .unwrap();
    rt.block_on(tester.grant(v, revoked, false, OsStr::new("v")))
        .unwrap();
    rt.block_on(tester.revoke(v, revoked)).unwrap();
    v
}

#[test]
fn another_writer_finishes_a_revokers_prune() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("carol");
    backend.enrol("mallory");
    let v = revoked_volume(&backend, "carol", "mallory");
    let tester = vault(&backend, TESTER);
    let carol = vault(&backend, "carol");
    let mallory = vault(&backend, "mallory");

    // Both writers see it waiting; the revoked user sees nothing.
    assert!(waiting(&backend, &tester).contains(&v));
    assert!(waiting(&backend, &carol).contains(&v));
    assert!(waiting(&backend, &mallory).is_empty());

    // Carol, not the revoker, prunes it, and then nothing waits for anyone.
    let stats = backend
        .runtime
        .block_on(prune_claimed(
            &carol,
            v,
            new_holder(),
            &PrunerConfig::default(),
            &mut |_| {},
        ))
        .unwrap();
    assert!(stats.skipped.is_empty(), "{:?}", stats.skipped);
    assert!(waiting(&backend, &tester).is_empty());
    assert!(waiting(&backend, &carol).is_empty());
}

#[test]
fn a_claim_keeps_others_off_until_released() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("carol");
    backend.enrol("mallory");
    let v = revoked_volume(&backend, "carol", "mallory");
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let carol = vault(&backend, "carol");
    let (mine, hers) = (new_holder(), new_holder());

    let first = rt
        .block_on(tester.remote().claim_prune(v, mine, false))
        .unwrap();
    assert!(first.granted);
    // Someone else is refused, and told who holds it; the listing says so.
    let other = rt
        .block_on(carol.remote().claim_prune(v, hers, false))
        .unwrap();
    assert!(!other.granted);
    assert_eq!(other.claim.unwrap().user, TESTER);
    let listed = rt.block_on(carol.remote().list_unpruned()).unwrap();
    let node = listed.iter().find(|u| u.ino == v).unwrap();
    assert_eq!(node.claim.as_ref().unwrap().user, TESTER);
    // Its holder can renew it.
    assert!(
        rt.block_on(tester.remote().claim_prune(v, mine, false))
            .unwrap()
            .granted
    );
    // Someone else can't release it; its holder can, which frees it.
    rt.block_on(carol.remote().claim_prune(v, hers, true))
        .unwrap();
    assert!(
        !rt.block_on(carol.remote().claim_prune(v, hers, false))
            .unwrap()
            .granted
    );
    rt.block_on(tester.remote().claim_prune(v, mine, true))
        .unwrap();
    assert!(
        rt.block_on(carol.remote().claim_prune(v, hers, false))
            .unwrap()
            .granted
    );
    // A pruner that finds it claimed leaves it alone.
    let busy = rt.block_on(prune_claimed(
        &tester,
        v,
        mine,
        &PrunerConfig::default(),
        &mut |_| {},
    ));
    assert_eq!(busy.unwrap_err().errno, libc::EBUSY);
}

#[test]
fn key_records_from_before_the_list_are_found() {
    // A server core of its own needs the object store.
    let backend = Backend::start(TEST_CHUNK_SIZE, true, true);
    backend.enrol("carol");
    backend.enrol("mallory");
    let v = revoked_volume(&backend, "carol", "mallory");
    let tester = vault(&backend, TESTER);
    assert!(waiting(&backend, &tester).contains(&v));

    // As a store from before the list: no rows, and not marked listed.
    for key in backend.keys_with_prefix(&[0x10]) {
        backend.write_key(&key, None);
    }
    backend.write_key(b"\x04unpruned_indexed", None);
    assert!(waiting(&backend, &tester).is_empty());

    // The server that measures usage lists them again.
    let core = backend.gc_core();
    backend.runtime.block_on(core.measure()).unwrap();
    assert!(waiting(&backend, &tester).contains(&v));
}
