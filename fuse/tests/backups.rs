//! Tests backups end to end: a snapshot's store contents and objects copied
//! to a backup space, deleted with a sweep of what no backup uses, and
//! restored into a new cluster that a mount reads the files back from.

mod support;

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::Path;

use raft5fs_core::backup::{self, BackupStore};
use raft5fs_crypto::backup::BackupKeyPair;
use raft5fs_objstore::fake::FakeStore;
use support::{
    TEST_BACKUP_BUCKET, TEST_BACKUP_PREFIX, TEST_BLOCK_CHUNKS, TEST_BUCKET, TEST_CHUNK_SIZE,
    TEST_OBJECT_FROM_CHUNKS, TEST_OBJECT_PREFIX,
};

/// Not a real test: the entry point that lets the harness run a filesystem
/// server as a separate process (see `support::TestServer`). Returns at
/// once in a normal run.
#[test]
fn server_process_mode() {
    support::serve_if_requested();
}

const C: u64 = TEST_CHUNK_SIZE;
const K: u64 = TEST_OBJECT_FROM_CHUNKS;
/// How much of a file one block holds.
const B: u64 = TEST_BLOCK_CHUNKS * C;

fn pattern(len: u64) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8 + 1).collect()
}

/// A harness with objects, and an empty backup space beside it.
fn setup() -> (support::Harness, FakeStore, BackupStore) {
    let h = support::setup_with_objects();
    let space = h
        .runtime
        .block_on(FakeStore::start(TEST_BACKUP_BUCKET))
        .expect("start the backup space");
    let backup = support::backup_store(&space);
    (h, space, backup)
}

/// The object names in the servers' store, as paths under its prefix.
fn serving_objects(h: &support::Harness) -> BTreeSet<String> {
    h.store()
        .keys()
        .iter()
        .filter_map(|k| k.strip_prefix(TEST_OBJECT_PREFIX).map(str::to_string))
        .collect()
}

/// The object names in the backup pool, as paths under its prefix.
fn pool_objects(space: &FakeStore) -> BTreeSet<String> {
    let pool = format!("{TEST_BACKUP_PREFIX}objects/");
    space
        .keys()
        .iter()
        .filter_map(|k| k.strip_prefix(&pool).map(str::to_string))
        .collect()
}

fn manifest_key(name: &str) -> String {
    format!("{TEST_BACKUP_PREFIX}backups/{name}/manifest")
}

fn create(
    h: &support::Harness,
    backup: &BackupStore,
    key: &BackupKeyPair,
    name: &str,
) -> Result<backup::CreateStats, String> {
    h.runtime.block_on(backup::create(
        &h.client,
        Some(h.serving_store()),
        backup,
        &key.public_key(),
        name,
    ))
}

/// Overwrites a few bytes inside the file's first block, so that block
/// gets a new object and the others keep theirs.
fn touch_first_block(path: &Path) {
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(&[0xee; 10], K * C + 100).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn a_backup_holds_the_snapshots_objects_and_its_sealed_store() {
    let (h, space, backup) = setup();
    let key = BackupKeyPair::generate();
    let f = h.path().join("f");
    fs::write(&f, pattern(K * C + 2 * B)).unwrap();
    fs::write(h.path().join("small"), b"inline").unwrap();
    h.snapshot("s1");
    let at_snapshot = serving_objects(&h);
    assert_eq!(at_snapshot.len(), 2);
    // Changed after the snapshot: the backup still has what it pointed to.
    touch_first_block(&f);

    let stats = create(&h, &backup, &key, "s1").unwrap();
    assert_eq!((stats.objects, stats.copied), (2, 2));
    assert_eq!(pool_objects(&space), at_snapshot);
    assert!(space.object(&manifest_key("s1")).is_some());

    // The store's own backup holds account names in clear; the parts
    // must not.
    let parts: Vec<String> = space
        .keys()
        .into_iter()
        .filter(|k| k.contains("/kv/"))
        .collect();
    assert!(!parts.is_empty());
    for part in parts {
        let sealed = space.object(&part).unwrap();
        let needle = support::SERVICE_USER.as_bytes();
        assert!(!sealed.windows(needle.len()).any(|w| w == needle));
    }

    let listed = h.runtime.block_on(backup::list(&backup)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "s1");
    assert_eq!(listed[0].objects, 2);

    // Backing up the same snapshot again is refused.
    let again = create(&h, &backup, &key, "s1").unwrap_err();
    assert!(again.contains("already has a backup"), "{again}");
}

#[test]
fn a_second_backup_copies_only_new_objects() {
    let (h, space, backup) = setup();
    let key = BackupKeyPair::generate();
    let f = h.path().join("f");
    fs::write(&f, pattern(K * C + 2 * B)).unwrap();
    h.snapshot("s1");
    let first = serving_objects(&h);
    create(&h, &backup, &key, "s1").unwrap();

    touch_first_block(&f);
    h.snapshot("s2");
    // Prompt deletion runs in the background; the snapshot holds what s2
    // needs either way.
    let second: BTreeSet<String> = serving_objects(&h);
    let puts = space.stats().puts;
    let stats = create(&h, &backup, &key, "s2").unwrap();
    let new: BTreeSet<_> = second.difference(&first).cloned().collect();
    assert!(!new.is_empty());
    assert_eq!(stats.objects, 2);
    assert_eq!(stats.copied, new.len());
    // The new objects, the store backup's parts, and the manifest.
    let kv_parts = space
        .keys()
        .iter()
        .filter(|k| k.contains("backups/s2/kv/"))
        .count() as u64;
    assert_eq!(space.stats().puts - puts, new.len() as u64 + kv_parts + 1);
}

#[test]
fn a_missing_object_fails_the_backup_and_leaves_no_manifest() {
    let (h, space, backup) = setup();
    let key = BackupKeyPair::generate();
    fs::write(h.path().join("f"), pattern(K * C + 2 * B)).unwrap();
    h.snapshot("s1");
    let gone = serving_objects(&h).into_iter().next().unwrap();
    h.store().remove(&format!("{TEST_OBJECT_PREFIX}{gone}"));

    let why = create(&h, &backup, &key, "s1").unwrap_err();
    assert!(why.contains("is gone"), "{why}");
    assert!(space.object(&manifest_key("s1")).is_none());
    assert!(
        h.runtime
            .block_on(backup::list(&backup))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_backup_needs_a_snapshot() {
    let (h, _space, backup) = setup();
    let key = BackupKeyPair::generate();
    let why = create(&h, &backup, &key, "nope").unwrap_err();
    assert!(why.contains("no snapshot"), "{why}");
}

#[test]
fn deleting_a_backup_sweeps_what_no_other_backup_uses() {
    let (h, space, backup) = setup();
    let key = BackupKeyPair::generate();
    let f = h.path().join("f");
    fs::write(&f, pattern(K * C + 2 * B)).unwrap();
    h.snapshot("s1");
    create(&h, &backup, &key, "s1").unwrap();
    touch_first_block(&f);
    h.snapshot("s2");
    create(&h, &backup, &key, "s2").unwrap();
    let s2_objects = h
        .runtime
        .block_on(backup::list(&backup))
        .unwrap()
        .into_iter()
        .find(|b| b.name == "s2")
        .unwrap()
        .objects;
    // Files from a backup that failed part way.
    space.insert(
        &format!("{TEST_BACKUP_PREFIX}backups/broken/kv/00000"),
        b"junk".to_vec(),
    );

    let stats = h
        .runtime
        .block_on(backup::delete(&h.client, &backup, "s1"))
        .unwrap();
    assert!(stats.existed);
    assert_eq!(stats.objects_deleted, 1);
    assert_eq!(stats.leftovers_deleted, 1);
    assert_eq!(pool_objects(&space).len(), s2_objects);
    assert!(!space.keys().iter().any(|k| k.contains("backups/s1/")));
    assert!(!space.keys().iter().any(|k| k.contains("backups/broken/")));
    let names: Vec<String> = h
        .runtime
        .block_on(backup::list(&backup))
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, ["s2"]);
    // The snapshots are the admin's to remove.
    h.drop_snapshot("s1");

    let stats = h
        .runtime
        .block_on(backup::delete(&h.client, &backup, "s2"))
        .unwrap();
    assert_eq!(stats.objects_deleted, s2_objects);
    assert!(space.keys().is_empty(), "{:?}", space.keys());

    let stats = h
        .runtime
        .block_on(backup::delete(&h.client, &backup, "s2"))
        .unwrap();
    assert!(!stats.existed);
}

#[test]
fn one_backup_job_runs_at_a_time() {
    let (h, _space, backup) = setup();
    let key = BackupKeyPair::generate();
    h.snapshot("s1");
    // Another job's lease, good for an hour.
    let mut lease = vec![7; 16];
    let expires = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    let expires_ms = expires
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    lease.extend_from_slice(&expires_ms.to_be_bytes());
    h.write_key(b"\x04backup_lease", Some(&lease));

    let why = create(&h, &backup, &key, "s1").unwrap_err();
    assert!(why.contains("another backup job"), "{why}");
    let why = h
        .runtime
        .block_on(backup::delete(&h.client, &backup, "s1"))
        .unwrap_err();
    assert!(why.contains("another backup job"), "{why}");

    h.write_key(b"\x04backup_lease", None);
    create(&h, &backup, &key, "s1").unwrap();
    // A finished job gives the lease back, so the next one runs at once.
    h.runtime
        .block_on(backup::delete(&h.client, &backup, "s1"))
        .unwrap();
}

#[test]
fn only_the_operator_key_opens_the_store_backup() {
    let (h, _space, backup) = setup();
    let key = BackupKeyPair::generate();
    h.snapshot("s1");
    create(&h, &backup, &key, "s1").unwrap();
    let out = support::temp_dir("restore").join("kv");
    let why = h
        .runtime
        .block_on(backup::fetch_kv(
            &backup,
            &BackupKeyPair::generate(),
            "s1",
            &out,
        ))
        .unwrap_err();
    assert!(why.contains("not sealed to this key"), "{why}");
    assert!(!out.exists());
}

#[test]
fn a_backup_restores_into_a_new_cluster() {
    let (h, space, _) = setup();
    // Small parts, so the store backup spans several.
    let backup = support::backup_store(&space).with_part_size(4096);
    let key = BackupKeyPair::generate();
    let big = pattern(K * C + 2 * B + 300);
    fs::write(h.path().join("big"), &big).unwrap();
    fs::create_dir(h.path().join("d")).unwrap();
    fs::write(h.path().join("d/small"), b"inline").unwrap();
    h.snapshot("s1");
    // After the snapshot, so not in the backup.
    fs::write(h.path().join("later"), b"later").unwrap();
    create(&h, &backup, &key, "s1").unwrap();

    let dir = support::temp_dir("restore");
    let out = dir.join("kv");
    let written = h
        .runtime
        .block_on(backup::fetch_kv(&backup, &key, "s1", &out))
        .unwrap();
    assert!(written > 4096, "only {written} bytes");
    assert_eq!(fs::metadata(&out).unwrap().len(), written);

    // A new cluster and object store, as after losing both.
    let (cluster, _client) = support::TestCluster::start_from_backup(&h.runtime, &out);
    let serving = h
        .runtime
        .block_on(FakeStore::start(TEST_BUCKET))
        .expect("start a new object store");
    let restored = h
        .runtime
        .block_on(backup::restore_objects(
            &backup,
            std::sync::Arc::new(support::store_on(&serving.config(TEST_OBJECT_PREFIX))),
            "s1",
        ))
        .unwrap();
    // Two whole blocks and the start of a third.
    assert_eq!(restored, 3);
    let objects = support::ServerObjects {
        endpoint: serving.endpoint(),
        prompt_delete: true,
    };
    let servers = support::start_servers(&cluster, h.chunk_size, Some(&objects));
    let addresses: Vec<String> = servers.iter().map(|s| s.address.clone()).collect();
    let mount = support::MountedFs::mount(&h.runtime, addresses).in_volume();

    assert_eq!(fs::read(mount.path.join("big")).unwrap(), big);
    assert_eq!(fs::read(mount.path.join("d/small")).unwrap(), b"inline");
    assert!(!mount.path.join("later").exists());
    drop(mount);
    drop(servers);
    let _ = fs::remove_dir_all(dir);
}
