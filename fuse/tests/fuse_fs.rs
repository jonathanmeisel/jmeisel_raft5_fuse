//! End-to-end tests: a real single-node raft5 cluster, a real `Raft5Fs`
//! mounted through the kernel's FUSE interface, and plain `std::fs`
//! calls against the mountpoint -- see `support` for how both are
//! wired up.

mod support;

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use raft5fs_core::{
    CHUNK_SIZE_KEY, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, batch_bytes, chunk_prefix,
    dirent_prefix, groups, resolve_chunk_size, tombstone_key, users,
};

/// Not really a test: the entry point that lets the harness run a
/// filesystem server as a separate process (see `support::TestServer`).
/// Returns at once in a normal run.
#[test]
fn server_process_mode() {
    support::serve_if_requested();
}

/// Position-dependent bytes, so a chunk landing at the wrong offset (or
/// in the wrong order) fails loudly instead of matching by luck. 251 is
/// prime, so it never divides a power-of-two chunk size and the pattern
/// never lines up with a chunk boundary.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn ino_of(path: &std::path::Path) -> u64 {
    fs::metadata(path).expect("stat").ino()
}

/// Compares buffers by reporting the first offset that differs. A plain
/// `assert_eq!` on multi-chunk buffers dumps megabytes and buries the one
/// fact worth knowing: where it went wrong.
#[track_caller]
fn assert_same_bytes(got: &[u8], want: &[u8]) {
    assert_eq!(got.len(), want.len(), "length mismatch");
    if let Some(at) = got.iter().zip(want).position(|(a, b)| a != b) {
        panic!(
            "bytes differ at offset {at}: got {:#04x}, want {:#04x}",
            got[at], want[at]
        );
    }
}

// ---------------------------------------------------------------- basics

#[test]
fn root_directory_starts_empty() {
    let h = support::setup();

    let entries: Vec<_> = fs::read_dir(h.path())
        .expect("read_dir on mountpoint")
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(entries.is_empty(), "expected no entries, got {entries:?}");
}

#[test]
fn root_directory_is_owned_by_the_calling_user() {
    let h = support::setup();

    let meta = fs::metadata(h.path()).expect("stat mountpoint");
    assert_eq!(meta.uid(), unsafe { libc::getuid() });
    assert_eq!(meta.gid(), unsafe { libc::getgid() });
}

#[test]
fn create_write_and_read_back_a_file() {
    let h = support::setup();
    let path = h.path().join("hello.txt");

    fs::write(&path, b"hello, raft5!").expect("write file");
    let contents = fs::read(&path).expect("read file back");
    assert_eq!(contents, b"hello, raft5!");

    let meta = fs::metadata(&path).expect("stat file");
    assert!(meta.is_file());
    assert_eq!(meta.len(), 13);
}

#[test]
fn a_new_file_shows_up_in_its_directory_listing() {
    let h = support::setup();
    fs::write(h.path().join("a.txt"), b"a").unwrap();
    fs::write(h.path().join("b.txt"), b"b").unwrap();

    let mut names: Vec<_> = fs::read_dir(h.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
}

#[test]
fn mkdir_creates_a_visible_subdirectory() {
    let h = support::setup();
    let dir = h.path().join("subdir");
    fs::create_dir(&dir).expect("mkdir");

    let meta = fs::metadata(&dir).expect("stat subdir");
    assert!(meta.is_dir());

    let names: Vec<_> = fs::read_dir(h.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["subdir".to_string()]);
}

#[test]
fn nested_files_and_directories_round_trip() {
    let h = support::setup();
    let dir = h.path().join("nested");
    fs::create_dir(&dir).expect("mkdir nested");

    let file = dir.join("inner.txt");
    fs::write(&file, b"deep").expect("write nested file");
    assert_eq!(fs::read(&file).unwrap(), b"deep");

    let names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["inner.txt".to_string()]);
}

#[test]
fn dot_dot_resolves_to_the_parent_directory() {
    let h = support::setup();
    let dir = h.path().join("child");
    fs::create_dir(&dir).unwrap();

    let via_dotdot = fs::canonicalize(dir.join("..")).expect("canonicalize ..");
    let root = fs::canonicalize(h.path()).expect("canonicalize mountpoint");
    assert_eq!(via_dotdot, root);
}

#[test]
fn overwriting_with_a_shorter_value_truncates() {
    let h = support::setup();
    let path = h.path().join("shrink.txt");
    fs::write(&path, b"a longer first value").unwrap();
    fs::write(&path, b"short").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"short");
    assert_eq!(fs::metadata(&path).unwrap().len(), 5);
}

#[test]
fn unlink_removes_a_file() {
    let h = support::setup();
    let path = h.path().join("gone.txt");
    fs::write(&path, b"bye").unwrap();
    fs::remove_file(&path).unwrap();

    assert!(fs::metadata(&path).is_err());
    let entries: Vec<_> = fs::read_dir(h.path()).unwrap().collect();
    assert!(entries.is_empty());
}

#[test]
fn rmdir_fails_on_a_non_empty_directory_and_succeeds_once_empty() {
    let h = support::setup();
    let dir = h.path().join("occupied");
    fs::create_dir(&dir).unwrap();
    let file = dir.join("f.txt");
    fs::write(&file, b"x").unwrap();

    let err = fs::remove_dir(&dir).expect_err("rmdir on a non-empty dir should fail");
    assert_eq!(err.raw_os_error(), Some(libc::ENOTEMPTY));

    fs::remove_file(&file).unwrap();
    fs::remove_dir(&dir).expect("rmdir once empty should succeed");
}

#[test]
fn creating_a_file_that_already_exists_fails() {
    let h = support::setup();
    let path = h.path().join("dup.txt");
    fs::write(&path, b"first").unwrap();

    let err = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect_err("create_new on an existing file should fail");
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
}

#[test]
fn setattr_can_change_permissions() {
    let h = support::setup();
    let path = h.path().join("perms.txt");
    fs::write(&path, b"x").unwrap();

    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).expect("chmod");

    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

// --------------------------------------------------------------- chunking

#[test]
fn multi_chunk_file_round_trips_byte_for_byte() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("big.bin");

    let data = pattern(c * 3 + c / 2);
    fs::write(&path, &data).expect("write multi-chunk file");

    assert_eq!(fs::metadata(&path).unwrap().len(), data.len() as u64);
    assert_same_bytes(&fs::read(&path).unwrap(), &data);
}

/// The rest of the suite runs at a small chunk size for speed. This one
/// uses the real default, so the size an actual mount gets is covered
/// too -- including the blind whole-chunk write path, which only opens
/// up when a write op lines up with a chunk exactly.
#[test]
fn the_default_chunk_size_handles_a_multi_megabyte_file() {
    let h = support::setup_with_chunk_size(DEFAULT_CHUNK_SIZE);
    let path = h.path().join("default-size.bin");

    let data = pattern(DEFAULT_CHUNK_SIZE as usize * 3 + 4096);
    fs::write(&path, &data).expect("write a multi-megabyte file");

    assert_eq!(fs::metadata(&path).unwrap().len(), data.len() as u64);
    assert_same_bytes(&fs::read(&path).unwrap(), &data);
}

/// A chunk this size only fits in a transaction because each chunk is
/// stored on its own: an overwrite straddling a boundary rewrites two
/// full chunks, which together exceed what one transaction may hold.
#[test]
fn the_max_chunk_size_survives_an_overwrite_across_a_boundary() {
    let h = support::setup_with_chunk_size(MAX_CHUNK_SIZE);
    let c = MAX_CHUNK_SIZE;
    let path = h.path().join("max-chunk.bin");

    let mut expected = pattern(c as usize * 2);
    fs::write(&path, &expected).unwrap();

    let patch = vec![0xCDu8; 4096];
    let at = c - 2048;
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(&patch).unwrap();
    drop(file);

    expected[at as usize..at as usize + patch.len()].copy_from_slice(&patch);
    assert_same_bytes(&fs::read(&path).unwrap(), &expected);
}

#[test]
fn overwrite_spanning_a_chunk_boundary() {
    let h = support::setup();
    let c = h.chunk_size;
    let path = h.path().join("spanning.bin");

    let mut expected = pattern(c as usize * 2);
    fs::write(&path, &expected).unwrap();

    let patch = vec![0xABu8; 200];
    let at = c - 100;
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(&patch).unwrap();
    drop(file);

    expected[at as usize..at as usize + patch.len()].copy_from_slice(&patch);
    assert_same_bytes(&fs::read(&path).unwrap(), &expected);
}

#[test]
fn exact_chunk_size_boundaries() {
    let h = support::setup();
    let c = h.chunk_size as usize;

    for len in [c - 1, c, c + 1, 2 * c - 1, 2 * c, 2 * c + 1] {
        let path = h.path().join(format!("len-{len}.bin"));
        let data = pattern(len);
        fs::write(&path, &data).unwrap();

        assert_eq!(fs::metadata(&path).unwrap().len(), len as u64, "len {len}");
        assert_same_bytes(&fs::read(&path).unwrap(), &data);
    }
}

#[test]
fn truncate_down_then_up_reads_zeros() {
    let h = support::setup();
    let c = h.chunk_size;
    let path = h.path().join("trunc.bin");

    fs::write(&path, vec![0xFFu8; c as usize * 2]).unwrap();

    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(c / 2).unwrap();
    // Growing back must not resurrect the bytes that were past the new
    // end -- the boundary chunk has to have been cut back, not just the
    // recorded size.
    file.set_len(c * 2).unwrap();
    drop(file);

    let got = fs::read(&path).unwrap();
    assert_eq!(got.len(), c as usize * 2);
    assert!(got[..c as usize / 2].iter().all(|&b| b == 0xFF));
    assert!(
        got[c as usize / 2..].iter().all(|&b| b == 0),
        "bytes past the truncation point came back"
    );
}

#[test]
fn truncate_to_exact_chunk_multiple_then_grow() {
    let h = support::setup();
    let c = h.chunk_size;
    let path = h.path().join("trunc-aligned.bin");

    fs::write(&path, vec![0xFFu8; c as usize * 3]).unwrap();

    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(c).unwrap();
    file.set_len(c * 3).unwrap();
    drop(file);

    let got = fs::read(&path).unwrap();
    assert_eq!(got.len(), c as usize * 3);
    assert!(got[..c as usize].iter().all(|&b| b == 0xFF));
    assert!(got[c as usize..].iter().all(|&b| b == 0));
}

#[test]
fn sparse_write_far_past_eof() {
    let h = support::setup();
    let c = h.chunk_size;
    let path = h.path().join("sparse.bin");

    let at = c * 3 + 12345;
    let mut file = fs::File::create(&path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(b"tail").unwrap();
    drop(file);

    assert_eq!(fs::metadata(&path).unwrap().len(), at + 4);

    let got = fs::read(&path).unwrap();
    assert!(
        got[..at as usize].iter().all(|&b| b == 0),
        "the hole should read as zeros"
    );
    assert_eq!(&got[at as usize..], b"tail");

    // The hole is absent, not materialized: only the chunk actually
    // written to should exist.
    let keys = h.keys_with_prefix(&chunk_prefix(ino_of(&path)));
    assert_eq!(keys.len(), 1, "a hole should not have been written out");
}

#[test]
fn unlink_leaves_no_chunk_keys() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("doomed.bin");

    fs::write(&path, pattern(c * 3)).unwrap();
    let ino = ino_of(&path);
    assert!(!h.keys_with_prefix(&chunk_prefix(ino)).is_empty());

    fs::remove_file(&path).unwrap();

    assert!(
        h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
        "unlink left chunks behind"
    );
    let mut attr_key = vec![0x01];
    attr_key.extend_from_slice(&ino.to_be_bytes());
    assert!(h.read_key(&attr_key).is_none(), "unlink left the attrs");
}

#[test]
fn truncating_overwrite_removes_tail_chunks() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("retruncated.bin");

    fs::write(&path, pattern(c * 3)).unwrap();
    let ino = ino_of(&path);

    // O_TRUNC, so this shrinks to 5 bytes and everything past chunk 0
    // should go.
    fs::write(&path, b"small").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"small");
    assert_eq!(fs::metadata(&path).unwrap().len(), 5);
    assert_eq!(h.keys_with_prefix(&chunk_prefix(ino)).len(), 1);
}

// ------------------------------------------------------------- chunk size

#[test]
fn a_fresh_store_adopts_the_requested_chunk_size() {
    let h = support::setup_with_chunk_size(32 * 1024);
    // Force the INIT handshake to have completed before reading it back.
    let _ = fs::read_dir(h.path()).unwrap().count();

    let recorded = h.read_key(CHUNK_SIZE_KEY).expect("chunk size not recorded");
    assert_eq!(u64::from_be_bytes(recorded.try_into().unwrap()), 32 * 1024);
}

#[test]
fn an_existing_store_keeps_its_chunk_size() {
    let mut h = support::setup_with_chunk_size(32 * 1024);
    let path = h.path().join("carried-over.bin");
    let data = pattern(32 * 1024 * 3);
    fs::write(&path, &data).unwrap();

    // Remounting with a different request must not reinterpret the chunk
    // boundaries the file was written with.
    h.remount(128 * 1024);

    let path = h.path().join("carried-over.bin");
    assert_same_bytes(&fs::read(&path).unwrap(), &data);
    let recorded = h.read_key(CHUNK_SIZE_KEY).unwrap();
    assert_eq!(u64::from_be_bytes(recorded.try_into().unwrap()), 32 * 1024);
}

#[test]
fn an_out_of_range_stored_chunk_size_is_refused() {
    let h = support::setup();
    let _ = fs::read_dir(h.path()).unwrap().count();

    // Bigger than a transaction can hold or the client can read back, so
    // adopting it would produce chunks nothing could store or fetch.
    h.write_key(CHUNK_SIZE_KEY, Some(&(MAX_CHUNK_SIZE * 2).to_be_bytes()));

    let err = h
        .runtime
        .block_on(resolve_chunk_size(&h.client, h.chunk_size))
        .expect_err("an unusable recorded chunk size should be refused");
    assert!(err.contains("unusable"), "unexpected message: {err}");
}

// ------------------------------------------------- write buffer / read cache

/// The inode of `name` in the mount's root, learned from `readdir` --
/// unlike `stat`, that doesn't make the filesystem store buffered writes,
/// so it can be used to look at the store while a file still has some.
fn ino_from_readdir(dir: &std::path::Path, name: &str) -> u64 {
    use std::os::unix::fs::DirEntryExt;
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .find(|e| e.file_name() == name)
        .unwrap_or_else(|| panic!("{name} not listed"))
        .ino()
}

#[test]
fn many_small_sequential_writes_round_trip() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("streamed.bin");
    let want = pattern(c * 3 + c / 2 + 123);

    let mut f = fs::File::create(&path).unwrap();
    for piece in want.chunks(4096) {
        f.write_all(piece).unwrap();
    }
    drop(f);

    assert_same_bytes(&fs::read(&path).unwrap(), &want);
}

#[test]
fn small_sequential_reads_round_trip() {
    use std::io::Read;
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("read_streamed.bin");
    let want = pattern(c * 2 + 777);
    fs::write(&path, &want).unwrap();

    let mut f = fs::File::open(&path).unwrap();
    let mut got = Vec::new();
    let mut piece = [0u8; 1000];
    loop {
        let n = f.read(&mut piece).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&piece[..n]);
    }
    assert_same_bytes(&got, &want);
}

#[test]
fn buffered_writes_reach_the_store_on_fsync_and_close() {
    let h = support::setup();
    let path = h.path().join("buffered.bin");

    let mut f = fs::File::create(&path).unwrap();
    // Before the write, not after: `ino_from_readdir` costs a round trip
    // per entry, and "still buffered" only holds for `AUTO_FLUSH_DELAY`.
    // Learning the inode first leaves one fast key scan between the write
    // and the assertion instead of a whole readdir.
    let ino = ino_from_readdir(h.path(), "buffered.bin");
    f.write_all(&pattern(4096)).unwrap();
    assert!(
        h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
        "a small write should still be buffered"
    );

    f.sync_all().unwrap();
    assert_eq!(h.keys_with_prefix(&chunk_prefix(ino)).len(), 1);

    let more = vec![9u8; 100];
    f.write_all(&more).unwrap();
    drop(f);
    let mut want = pattern(4096);
    want.extend_from_slice(&more);
    assert_same_bytes(&fs::read(&path).unwrap(), &want);
}

/// Waits for `ino` to have at least `want` chunk keys stored, giving up
/// after `within`. A deadline rather than a sleep because storing happens
/// in the background, and a short one is how a test distinguishes the
/// size trigger from the 500 ms timer.
fn await_chunk_keys(
    h: &support::Harness,
    ino: u64,
    want: usize,
    within: std::time::Duration,
    why: &str,
) {
    let deadline = std::time::Instant::now() + within;
    loop {
        let have = h.keys_with_prefix(&chunk_prefix(ino)).len();
        if have >= want {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{why}: {have} of {want} chunks stored after {within:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// A run that fills a batch is handed off as soon as the `write` that
/// completed it returns -- not left for the timer.
///
/// Run at the smallest chunk size so a batch is only 64 KiB: the deadline
/// has to stay comfortably under `AUTO_FLUSH_DELAY` for this to be
/// testing the size trigger at all, and a small batch commits well inside
/// it. Written in chunk-sized pieces so no single `write` is big enough to
/// take the bypass.
#[test]
fn a_full_batch_is_stored_without_waiting_for_close() {
    let h = support::setup_with_chunk_size(MIN_CHUNK_SIZE);
    let batch = batch_bytes(MIN_CHUNK_SIZE) as usize;
    let chunks = batch / MIN_CHUNK_SIZE as usize;
    let path = h.path().join("filling.bin");

    let mut f = fs::File::create(&path).unwrap();
    for piece in pattern(batch).chunks(MIN_CHUNK_SIZE as usize) {
        f.write_all(piece).unwrap();
    }
    let ino = ino_from_readdir(h.path(), "filling.bin");

    await_chunk_keys(
        &h,
        ino,
        chunks,
        std::time::Duration::from_millis(400),
        "a filled batch should be stored without the timer",
    );
    drop(f);
}

/// A run too short to fill a batch, which the application never closes,
/// syncs or reads, still reaches the store on its own. Without the
/// auto-flush timer it would sit in memory until one of those happened.
///
/// Run on its own this isolates the timer, and fails without it. Run
/// alongside other tests it does not, and the reason is worth recording:
/// the kernel sends a FUSE flush on *every* `close` of a descriptor,
/// including the copies a child process inherits. `fuser` fork+execs
/// `fusermount3` to mount and unmount, so any other test starting or
/// ending makes the child's close-on-exec generate a flush against every
/// open file in every mount this process holds -- which stores this
/// buffer early, by a route that has nothing to do with the timer. So
/// what this asserts under concurrency is the weaker, still useful claim
/// in the first paragraph.
#[test]
fn an_idle_partial_batch_reaches_the_store_on_its_own() {
    let h = support::setup();
    let path = h.path().join("idle.bin");

    let mut f = fs::File::create(&path).unwrap();
    let ino = ino_from_readdir(h.path(), "idle.bin");
    f.write_all(&pattern(4096)).unwrap();
    assert!(
        h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
        "a write this small should not be stored before the timer fires"
    );

    await_chunk_keys(
        &h,
        ino,
        1,
        std::time::Duration::from_secs(10),
        "the timer should have stored an idle buffer",
    );
    drop(f);
}

/// Many chunks, several batches' worth, written in small pieces --
/// exercises the batch splitting in `write_range` and that the bytes land
/// in order across it.
#[test]
fn many_small_writes_across_several_batches_round_trip_in_order() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("multi-batch-small-writes.bin");

    let data = pattern(c * 24 + 123);
    let mut f = fs::File::create(&path).unwrap();
    for piece in data.chunks(c / 4) {
        f.write_all(piece).unwrap();
    }
    drop(f);

    assert_eq!(fs::metadata(&path).unwrap().len(), data.len() as u64);
    assert_same_bytes(&fs::read(&path).unwrap(), &data);
}

/// A read must see writes that are still buffered, not yet committed.
#[test]
fn reads_wait_for_buffered_writes() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("read-while-buffered.bin");

    let data = pattern(c * 6);
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&data).unwrap();
    // Still open, nothing closed or synced.
    assert_same_bytes(&fs::read(&path).unwrap(), &data);
    drop(f);
}

/// Deleting a file with several batches' worth of writes on it must not
/// leave any chunks behind: a chunk stored after the delete's scan would
/// have nothing left to find it. Each batch commits synchronously as
/// `write_all` fills it, so by the time `remove_file` runs, only the last,
/// still-partial run is actually buffered -- the rest is already
/// committed and has to be cleaned up like any other stored data.
#[test]
fn unlinking_a_file_with_several_buffered_batches_leaves_nothing() {
    let h = support::setup();
    let path = h.path().join("doomed.bin");

    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&pattern(batch_bytes(h.chunk_size) as usize * 3))
        .unwrap();
    let ino = ino_from_readdir(h.path(), "doomed.bin");
    fs::remove_file(&path).unwrap();
    drop(f);

    assert!(
        h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
        "chunks survived the unlink"
    );
}

#[test]
fn stat_sees_buffered_writes() {
    let h = support::setup();
    let path = h.path().join("sized.bin");

    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&pattern(1000)).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), 1000);
    f.write_all(&pattern(500)).unwrap();
    assert_eq!(f.metadata().unwrap().len(), 1500);
}

#[test]
fn reading_through_the_same_handle_sees_buffered_writes() {
    use std::io::Read;
    let h = support::setup();
    let path = h.path().join("readback.bin");

    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    f.write_all(b"hello buffered world").unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    let mut got = String::new();
    f.read_to_string(&mut got).unwrap();
    assert_eq!(got, "hello buffered world");
}

#[test]
fn truncating_a_file_with_buffered_writes() {
    let h = support::setup();
    let path = h.path().join("cut.bin");

    let f = {
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(&pattern(10_000)).unwrap();
        f
    };
    f.set_len(100).unwrap();
    drop(f);

    assert_same_bytes(&fs::read(&path).unwrap(), &pattern(100));
}

#[test]
fn unlinking_a_file_with_buffered_writes_leaves_nothing() {
    let h = support::setup();
    let path = h.path().join("dropped.bin");

    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&pattern(5000)).unwrap();
    let ino = ino_from_readdir(h.path(), "dropped.bin");
    fs::remove_file(&path).unwrap();
    drop(f);

    assert!(h.keys_with_prefix(&chunk_prefix(ino)).is_empty());
    let mut attr_key = vec![0x01];
    attr_key.extend_from_slice(&ino.to_be_bytes());
    assert!(h.read_key(&attr_key).is_none());
}

#[test]
fn non_sequential_and_overlapping_writes_land_in_order() {
    let h = support::setup();
    let path = h.path().join("scattered.bin");

    let mut f = fs::File::create(&path).unwrap();
    f.write_all(b"aaaa").unwrap();
    f.seek(SeekFrom::Start(100)).unwrap();
    f.write_all(b"bbbb").unwrap();
    f.seek(SeekFrom::Start(2)).unwrap();
    f.write_all(b"cc").unwrap();
    f.seek(SeekFrom::Start(3)).unwrap();
    f.write_all(b"dd").unwrap();
    drop(f);

    let mut want = vec![0u8; 104];
    want[..4].copy_from_slice(b"aaaa");
    want[100..].copy_from_slice(b"bbbb");
    want[2..4].copy_from_slice(b"cc");
    want[3..5].copy_from_slice(b"dd");
    assert_same_bytes(&fs::read(&path).unwrap(), &want);
}

#[test]
fn a_write_straddling_a_chunk_boundary_through_the_buffer() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("straddle.bin");
    let want = pattern(c + 5000);

    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&want[..c - 100]).unwrap();
    f.write_all(&want[c - 100..c + 200]).unwrap();
    f.write_all(&want[c + 200..]).unwrap();
    drop(f);

    assert_same_bytes(&fs::read(&path).unwrap(), &want);
}

#[test]
fn reads_see_writes_made_after_the_chunk_was_cached() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("fresh.bin");
    fs::write(&path, pattern(c * 2)).unwrap();

    // Populate the cache for both chunks.
    assert_same_bytes(&fs::read(&path).unwrap(), &pattern(c * 2));

    let mut want = pattern(c * 2);
    let mut f = fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.seek(SeekFrom::Start(c as u64 - 10)).unwrap();
    f.write_all(&[0xEE; 20]).unwrap();
    drop(f);
    want[c - 10..c + 10].fill(0xEE);
    assert_same_bytes(&fs::read(&path).unwrap(), &want);

    // Truncate then grow must read zeros, not the cached old bytes.
    let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(c as u64 + 5).unwrap();
    f.set_len(c as u64 * 2).unwrap();
    drop(f);
    want[c + 5..].fill(0);
    assert_same_bytes(&fs::read(&path).unwrap(), &want);
}

#[test]
fn buffered_data_survives_a_remount() {
    let mut h = support::setup();
    let c = h.chunk_size;
    let path = h.path().join("durable.bin");
    fs::write(&path, pattern(3000)).unwrap();

    h.remount(c);

    assert_same_bytes(
        &fs::read(h.path().join("durable.bin")).unwrap(),
        &pattern(3000),
    );
}

// ------------------------------------------------------- multiple mounts

/// A read cache only one mount can see must not outlive the bytes it
/// holds: another mount's write is invisible here, so a hit has to be
/// confirmed against the store's seq before it is served.
#[test]
fn another_mount_sees_an_overwrite_after_caching_the_old_bytes() {
    let h = support::setup();
    let other = h.second_mount();
    let c = h.chunk_size as usize;

    let mine = h.path().join("shared.bin");
    let theirs = other.path.join("shared.bin");

    let first = pattern(c * 2);
    fs::write(&mine, &first).unwrap();

    // The other mount reads the whole file, which caches every chunk.
    assert_same_bytes(&fs::read(&theirs).unwrap(), &first);

    // Same length, so nothing about the *size* it cached changes -- only
    // the bytes, which is the part a stale cache would get wrong.
    let second: Vec<u8> = first.iter().map(|b| !b).collect();
    fs::write(&mine, &second).unwrap();

    assert_same_bytes(&fs::read(&theirs).unwrap(), &second);
}

/// The same, for a chunk cached as a hole. Seq 0 is the store's
/// "never written" sentinel, so this is the one version a cached chunk
/// can hold that was never assigned to anything.
#[test]
fn another_mount_sees_a_write_into_a_chunk_it_cached_as_a_hole() {
    let h = support::setup();
    let other = h.second_mount();
    let c = h.chunk_size;

    let mine = h.path().join("sparse.bin");
    let theirs = other.path.join("sparse.bin");

    // Three chunks of size, none of them stored.
    fs::File::create(&mine).unwrap().set_len(c * 3).unwrap();
    assert_same_bytes(&fs::read(&theirs).unwrap(), &vec![0u8; c as usize * 3]);

    // Filled in from the other side, inside the existing size.
    let patch = pattern(c as usize);
    let mut f = fs::OpenOptions::new().write(true).open(&mine).unwrap();
    f.seek(SeekFrom::Start(c * 2)).unwrap();
    f.write_all(&patch).unwrap();
    drop(f);

    let mut want = vec![0u8; c as usize * 3];
    want[c as usize * 2..].copy_from_slice(&patch);
    assert_same_bytes(&fs::read(&theirs).unwrap(), &want);
}

// ------------------------------------------------------- batched commits

/// A single write covering more than one batch is split across
/// transactions; the seams between them must not lose or duplicate bytes.
#[test]
fn a_write_spanning_more_than_one_batch_round_trips() {
    let h = support::setup();
    let batch = batch_bytes(h.chunk_size) as usize;
    let path = h.path().join("multibatch.bin");

    let data = pattern(batch * 2 + batch / 3);
    fs::write(&path, &data).unwrap();

    assert_eq!(fs::metadata(&path).unwrap().len(), data.len() as u64);
    assert_same_bytes(&fs::read(&path).unwrap(), &data);
}

/// The same, misaligned at both ends, so the first and last chunk of each
/// batch take the read-modify-write path inside the transaction rather
/// than the whole-chunk blind write.
#[test]
fn an_unaligned_write_spanning_batches_round_trips() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let batch = batch_bytes(h.chunk_size) as usize;
    let path = h.path().join("unaligned.bin");

    let mut expected = pattern(batch * 3);
    fs::write(&path, &expected).unwrap();

    let at = (c + c / 2) as u64;
    let patch: Vec<u8> = pattern(batch + c / 3).iter().map(|b| !b).collect();
    let mut f = fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.seek(SeekFrom::Start(at)).unwrap();
    f.write_all(&patch).unwrap();
    drop(f);

    expected[at as usize..at as usize + patch.len()].copy_from_slice(&patch);
    assert_same_bytes(&fs::read(&path).unwrap(), &expected);
}

/// At the smallest chunk size the chunk-count cap is what keeps a batch
/// inside the server's transaction budget -- the byte budget alone would
/// admit a thousand keys. A transaction over the limit is refused
/// outright, so writing several batches' worth at all is the assertion.
#[test]
fn a_batch_never_exceeds_the_transaction_budget() {
    let h = support::setup_with_chunk_size(MIN_CHUNK_SIZE);
    let path = h.path().join("tiny-chunks.bin");

    let data = pattern(batch_bytes(MIN_CHUNK_SIZE) as usize * 6);
    fs::write(&path, &data).expect("no batch should be refused for size");

    assert_same_bytes(&fs::read(&path).unwrap(), &data);
}

/// Unmounting inside `AUTO_FLUSH_DELAY` must not lose buffered bytes: the
/// timer has not fired yet, so `destroy` draining every buffer is the only
/// thing that stores them. The file is deliberately left open, since
/// closing it would flush by itself and prove nothing.
#[test]
fn unmounting_before_the_timer_fires_loses_nothing() {
    let mut h = support::setup();
    let path = h.path().join("racing-unmount.bin");

    let mut f = fs::File::create(&path).unwrap();
    // Everything slow happens before the write, so that what follows it
    // stays well inside `AUTO_FLUSH_DELAY` -- otherwise the timer could
    // store the bytes and this would pass without `destroy` doing a thing.
    let ino = ino_from_readdir(h.path(), "racing-unmount.bin");
    f.write_all(&pattern(4096)).unwrap();
    assert!(
        h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
        "the timer should not have run yet"
    );

    // Drops the old session, which unmounts and so runs `destroy`.
    h.remount(h.chunk_size);

    // Read from the store rather than through a mount: what is being
    // tested is that the bytes were stored, not that anyone can see them.
    assert!(
        !h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
        "unmounting lost a buffered write the timer had not reached yet"
    );
    drop(f);
}

/// The whole point of batching: every chunk of one batch is written by one
/// transaction, so they all land at the same sequence number, and the next
/// batch lands at a different one.
///
/// This is the assertion that would catch a regression to a transaction
/// per chunk -- which would still round-trip the bytes correctly, and so
/// slip past every other test here.
#[test]
fn the_chunks_of_one_batch_share_a_commit() {
    let h = support::setup();
    let batch = batch_bytes(h.chunk_size) as usize;
    let per_batch = batch / h.chunk_size as usize;
    assert!(
        per_batch > 1,
        "this test is meaningless unless a batch spans several chunks"
    );

    let path = h.path().join("batched.bin");
    fs::write(&path, pattern(batch * 2)).unwrap();
    let ino = ino_from_readdir(h.path(), "batched.bin");

    let seq_of = |index: u64| {
        let mut key = chunk_prefix(ino);
        key.extend_from_slice(&index.to_be_bytes());
        h.key_version(&key)
    };

    let first = seq_of(0);
    assert_ne!(first, 0, "chunk 0 should have been written");
    assert_eq!(
        seq_of(per_batch as u64 - 1),
        first,
        "the last chunk of a batch shares its commit with the first"
    );
    assert_ne!(
        seq_of(per_batch as u64),
        first,
        "the next batch is a separate commit"
    );
}

// ------------------------------------------------------------- deletion

/// One mount unlinks a file while another keeps committing writes to it.
/// Deleting the chunks takes several transactions, so without the
/// deletion mark a commit landing between them stores a chunk the
/// deletion has already scanned past -- leaked, with nothing left that
/// could find it -- and a writer that keeps landing commits can stop the
/// deletion's rescans from ever finishing. The two mounts share no process
/// state, so nothing but the store can order them.
///
/// The writer has a deadline so that a regression fails rather than hangs:
/// with the mark working, its writes are refused as soon as the unlink's
/// first step commits, long before then.
#[test]
fn unlinking_from_one_mount_while_another_writes_leaks_no_chunks() {
    let h = support::setup_with_chunk_size(MIN_CHUNK_SIZE);
    let other = h.second_mount();
    let batch = batch_bytes(MIN_CHUNK_SIZE) as usize;
    // Enough chunks that the deletion's scan spans several transactions.
    let span = batch * 32;

    for round in 0..3 {
        let name = format!("contested-{round}.bin");
        let path = h.path().join(&name);
        fs::write(&path, pattern(span)).unwrap();
        let ino = ino_from_readdir(h.path(), &name);

        let writer = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut f = fs::OpenOptions::new().write(true).open(&path).unwrap();
            // A batch-sized write commits immediately, so commits keep
            // landing until one is refused because the file is gone.
            let mut offset = 0u64;
            while std::time::Instant::now() < deadline {
                if f.seek(SeekFrom::Start(offset)).is_err() || f.write_all(&pattern(batch)).is_err()
                {
                    return true;
                }
                offset = (offset + batch as u64) % span as u64;
            }
            false
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::remove_file(other.path.join(&name)).unwrap();
        let refused = writer.join().unwrap();

        assert!(
            refused,
            "round {round}: writes kept succeeding after the file was unlinked"
        );
        assert!(
            h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
            "round {round}: chunks outlived the unlink"
        );
        assert!(h.read_key(&tombstone_key(ino)).is_none());
    }
}

/// A deletion that stops after its first step -- dirent gone, Entry
/// marked, tombstone written -- as a crash would leave it. The inode is
/// unreachable by name, so only the tombstone says it exists; the next
/// mount to start must find it and finish the job.
#[test]
fn an_interrupted_deletion_is_finished_by_the_next_mount() {
    let mut h = support::setup();
    let name = "half-deleted.bin";
    let path = h.path().join(name);
    fs::write(&path, pattern(h.chunk_size as usize * 3)).unwrap();
    let ino = ino_from_readdir(h.path(), name);

    // The first step of an unlink, by hand. The link count is bytes 19..23
    // of the Entry record (after kind, perm, uid, gid and size).
    let mut attr_key = vec![0x01];
    attr_key.extend_from_slice(&ino.to_be_bytes());
    let mut entry = h.read_key(&attr_key).unwrap();
    entry[19..23].copy_from_slice(&0u32.to_be_bytes());
    h.write_key(&attr_key, Some(&entry));
    let mut dirent = vec![0x03];
    dirent.extend_from_slice(&1u64.to_be_bytes());
    dirent.extend_from_slice(name.as_bytes());
    h.write_key(&dirent, None);
    h.write_key(&tombstone_key(ino), Some(&[1u8][..]));
    assert!(!h.keys_with_prefix(&chunk_prefix(ino)).is_empty());

    h.remount(h.chunk_size);
    // Any request waits for the mount's `init`, which is where it reaps.
    let _ = fs::read_dir(h.path()).unwrap().count();

    assert!(
        h.keys_with_prefix(&chunk_prefix(ino)).is_empty(),
        "the interrupted deletion's chunks were never removed"
    );
    assert!(h.read_key(&attr_key).is_none());
    assert!(h.read_key(&tombstone_key(ino)).is_none());
}

// ------------------------------------------------------- server failover

/// The mount's server goes away part-way through a write. Servers hold no
/// write state -- unstored bytes are in the client's buffer -- so the
/// client resends to the other server and nothing is lost. Writes are
/// safe to resend: a batch commits whole or not at all, and the same
/// bytes at the same offset store the same thing twice.
#[test]
fn a_mount_fails_over_when_its_server_goes_away() {
    let mut h = support::setup();
    let batch = batch_bytes(h.chunk_size) as usize;
    let path = h.path().join("failover.bin");
    let data = pattern(batch * 6 + 123);
    let (before, after) = data.split_at(batch * 3 + 17);

    let mut f = fs::File::create(&path).unwrap();
    f.write_all(before).unwrap();

    // The mount starts on the first server. Take it away, and make sure
    // it is really gone rather than still answering an open connection.
    let server = h.servers.remove(0);
    let gone = server.address.trim_start_matches("http://").to_string();
    drop(server);
    assert!(
        std::net::TcpStream::connect(&gone).is_err(),
        "the stopped server is still accepting connections"
    );

    f.write_all(after).unwrap();
    f.sync_all()
        .expect("fsync should succeed through the surviving server");
    drop(f);

    assert_eq!(fs::metadata(&path).unwrap().len(), data.len() as u64);
    assert_same_bytes(&fs::read(&path).unwrap(), &data);
}

/// Bytes a `write` was told are written, lost when a later commit carrying
/// them fails, must surface at `fsync` -- even though by then the buffer
/// is empty and there is nothing left to commit. The commit that failed
/// took them out of the buffer, so without the stashed error `fsync`
/// would find nothing wrong and report success over lost data.
///
/// A mount with a single server, so stopping it makes the commit fail
/// rather than fail over.
#[test]
fn a_lost_acknowledged_write_is_reported_by_fsync() {
    let mut h = support::setup();
    let batch = batch_bytes(h.chunk_size) as usize;
    let lone = support::MountedFs::mount(&h.runtime, vec![h.servers[0].address.clone()]);
    let path = lone.path.join("acknowledged.bin");
    let mut f = fs::File::create(&path).unwrap();

    // Gone before the writes, so they run back to back with nothing slow
    // between them: the auto-flush timer (500 ms) can't store the first
    // one on its own before the second makes it fail.
    drop(h.servers.remove(0));

    // Only buffered, so it is acknowledged without reaching any server.
    f.write_all(&pattern(4096)).unwrap();
    // Crosses a batch boundary, so this commits the bytes above too --
    // and fails, with nowhere to fail over to.
    assert!(
        f.write_all(&pattern(batch)).is_err(),
        "the commit should have failed with the server gone"
    );
    assert!(
        f.sync_all().is_err(),
        "fsync reported success over acknowledged bytes that were lost"
    );
    drop(f);
}

// ------------------------------------------------------------ permissions

/// The uids of the users `add_people` adds. None of them is the user
/// running the tests, who owns the root directory.
const ALICE: u32 = 50_001;
const BOB: u32 = 50_002;
const CAROL: u32 = 50_003;
/// A group Alice and Bob are in, and Carol isn't.
const STAFF: u32 = 50_100;

/// Adds users "alice", "bob" and "carol", each with a primary group of
/// their own; alice and bob are also in `STAFF`.
fn add_people(h: &support::Harness) {
    h.add_user("alice", ALICE, ALICE, &[STAFF]);
    h.add_user("bob", BOB, BOB, &[STAFF]);
    h.add_user("carol", CAROL, CAROL, &[]);
}

fn chmod(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn chgrp(path: &std::path::Path, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, None, Some(gid))
}

#[track_caller]
fn assert_errno<T: std::fmt::Debug>(result: std::io::Result<T>, errno: i32) {
    match result {
        Err(e) => assert_eq!(e.raw_os_error(), Some(errno), "wrong error: {e}"),
        Ok(v) => panic!("expected errno {errno}, got Ok({v:?})"),
    }
}

/// access(2) on `path`.
fn access(path: &std::path::Path, mask: i32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    if unsafe { libc::access(path.as_ptr(), mask) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// A directory at the root that anyone may create in, for tests whose
/// users don't own the root.
/// Also adds the users (see `add_people`), since every such test needs
/// both.
fn open_dir(h: &support::Harness, name: &str) {
    add_people(h);
    let dir = h.path().join(name);
    fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o777).unwrap();
}

#[test]
fn files_are_created_as_the_mounts_user() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");

    fs::write(alice.path.join("pub/a"), b"x").unwrap();
    fs::create_dir(alice.path.join("pub/d")).unwrap();

    for name in ["pub/a", "pub/d"] {
        let meta = fs::metadata(h.path().join(name)).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (ALICE, ALICE), "{name}");
    }
}

#[test]
fn another_user_cannot_open_a_private_file() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    let private = alice.path.join("pub/private");
    fs::write(&private, b"secret").unwrap();
    chmod(&private, 0o600).unwrap();

    assert_errno(fs::read(bob.path.join("pub/private")), libc::EACCES);
    assert_errno(
        fs::OpenOptions::new()
            .write(true)
            .open(bob.path.join("pub/private")),
        libc::EACCES,
    );
    assert_eq!(fs::read(&private).unwrap(), b"secret");
}

#[test]
fn read_permission_does_not_imply_write_permission() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    fs::write(alice.path.join("pub/f"), b"alice's").unwrap();
    chmod(&alice.path.join("pub/f"), 0o644).unwrap();

    let theirs = bob.path.join("pub/f");
    assert_eq!(fs::read(&theirs).unwrap(), b"alice's");
    assert_errno(fs::write(&theirs, b"bob's"), libc::EACCES);
    // Truncating is writing too.
    assert_errno(fs::File::create(&theirs), libc::EACCES);
    assert_eq!(fs::read(&theirs).unwrap(), b"alice's");
}

#[test]
fn access_reports_what_the_server_would_allow() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let carol = h.mount_as("carol");
    fs::write(alice.path.join("pub/f"), b"x").unwrap();
    chmod(&alice.path.join("pub/f"), 0o640).unwrap();
    chgrp(&alice.path.join("pub/f"), STAFF).unwrap();
    let bob = h.mount_as("bob");

    assert!(access(&alice.path.join("pub/f"), libc::R_OK | libc::W_OK).is_ok());
    assert!(access(&bob.path.join("pub/f"), libc::R_OK).is_ok());
    assert_errno(access(&bob.path.join("pub/f"), libc::W_OK), libc::EACCES);
    assert_errno(access(&carol.path.join("pub/f"), libc::R_OK), libc::EACCES);
    assert!(access(&carol.path.join("pub/f"), libc::F_OK).is_ok());
}

#[test]
fn a_directory_without_search_permission_hides_its_contents() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    fs::create_dir(alice.path.join("pub/private")).unwrap();
    fs::write(alice.path.join("pub/private/f"), b"x").unwrap();
    chmod(&alice.path.join("pub/private/f"), 0o666).unwrap();
    chmod(&alice.path.join("pub/private"), 0o700).unwrap();

    // Even a world-readable file is out of reach behind it.
    assert_errno(fs::read(bob.path.join("pub/private/f")), libc::EACCES);
    assert_errno(fs::read_dir(bob.path.join("pub/private")), libc::EACCES);
    assert_eq!(fs::read(alice.path.join("pub/private/f")).unwrap(), b"x");
}

#[test]
fn listing_a_directory_takes_read_permission() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    fs::create_dir(alice.path.join("pub/dropbox")).unwrap();
    fs::write(alice.path.join("pub/dropbox/known"), b"x").unwrap();
    chmod(&alice.path.join("pub/dropbox/known"), 0o644).unwrap();
    chmod(&alice.path.join("pub/dropbox"), 0o711).unwrap();

    // Bob can't list it, but can reach a name he already knows.
    assert_errno(fs::read_dir(bob.path.join("pub/dropbox")), libc::EACCES);
    assert_eq!(fs::read(bob.path.join("pub/dropbox/known")).unwrap(), b"x");
}

#[test]
fn creating_and_removing_take_write_permission_on_the_directory() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    fs::create_dir(alice.path.join("pub/mine")).unwrap();
    fs::write(alice.path.join("pub/mine/f"), b"x").unwrap();
    fs::create_dir(alice.path.join("pub/mine/d")).unwrap();
    chmod(&alice.path.join("pub/mine"), 0o755).unwrap();

    let mine = bob.path.join("pub/mine");
    assert_errno(fs::write(mine.join("new"), b"x"), libc::EACCES);
    assert_errno(fs::create_dir(mine.join("newdir")), libc::EACCES);
    assert_errno(fs::remove_file(mine.join("f")), libc::EACCES);
    assert_errno(fs::remove_dir(mine.join("d")), libc::EACCES);
    assert!(alice.path.join("pub/mine/f").exists());
    assert!(alice.path.join("pub/mine/d").exists());
    // And the root, which neither owns.
    assert_errno(fs::write(alice.path.join("top"), b"x"), libc::EACCES);
}

#[test]
fn the_sticky_bit_stops_users_removing_each_others_files() {
    let h = support::setup();
    add_people(&h);
    let tmp = h.path().join("tmp");
    fs::create_dir(&tmp).unwrap();
    chmod(&tmp, 0o1777).unwrap();
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    fs::write(alice.path.join("tmp/alices"), b"x").unwrap();
    fs::write(bob.path.join("tmp/bobs"), b"x").unwrap();

    assert_errno(fs::remove_file(bob.path.join("tmp/alices")), libc::EPERM);
    fs::remove_file(bob.path.join("tmp/bobs")).unwrap();
    // The directory's owner may still clean up.
    fs::remove_file(tmp.join("alices")).unwrap();
}

#[test]
fn only_the_owner_may_chmod_and_only_to_their_own_groups_chgrp() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    let f = alice.path.join("pub/f");
    fs::write(&f, b"x").unwrap();
    chmod(&f, 0o666).unwrap();

    assert_errno(chmod(&bob.path.join("pub/f"), 0o777), libc::EPERM);
    assert_errno(chgrp(&bob.path.join("pub/f"), STAFF), libc::EPERM);
    chgrp(&f, STAFF).unwrap();
    assert_errno(chgrp(&f, CAROL), libc::EPERM);
    assert_errno(std::os::unix::fs::chown(&f, Some(BOB), None), libc::EPERM);
    let meta = fs::metadata(&f).unwrap();
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777),
        (ALICE, STAFF, 0o666)
    );
}

#[test]
fn a_setgid_group_directory_is_shared_by_its_members() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    let carol = h.mount_as("carol");
    let shared = alice.path.join("pub/shared");
    fs::create_dir(&shared).unwrap();
    chgrp(&shared, STAFF).unwrap();
    chmod(&shared, 0o2770).unwrap();

    fs::write(bob.path.join("pub/shared/bobs"), b"from bob").unwrap();
    fs::create_dir(bob.path.join("pub/shared/sub")).unwrap();
    let file = fs::metadata(alice.path.join("pub/shared/bobs")).unwrap();
    assert_eq!((file.uid(), file.gid()), (BOB, STAFF));
    let sub = fs::metadata(alice.path.join("pub/shared/sub")).unwrap();
    assert_eq!(sub.gid(), STAFF);
    assert_eq!(sub.mode() & 0o2000, 0o2000, "subdirectories inherit setgid");

    assert_errno(fs::read_dir(carol.path.join("pub/shared")), libc::EACCES);
    assert_errno(
        fs::write(carol.path.join("pub/shared/x"), b"x"),
        libc::EACCES,
    );
}

#[test]
fn joining_or_leaving_a_group_applies_without_mounting_again() {
    let h = support::setup();
    open_dir(&h, "pub");
    let alice = h.mount_as("alice");
    let carol = h.mount_as("carol");
    let report = alice.path.join("pub/report");
    fs::write(&report, b"figures").unwrap();
    chgrp(&report, STAFF).unwrap();
    chmod(&report, 0o640).unwrap();
    let carols_view = carol.path.join("pub/report");
    assert_errno(fs::read(&carols_view), libc::EACCES);

    let joined = h
        .runtime
        .block_on(users::modify(&h.client, "carol", &[STAFF], &[]))
        .unwrap();
    assert_eq!(joined.groups, [STAFF]);
    assert_eq!(fs::read(&carols_view).unwrap(), b"figures");

    h.runtime
        .block_on(users::modify(&h.client, "carol", &[], &[STAFF]))
        .unwrap();
    assert_errno(fs::read(&carols_view), libc::EACCES);
}

#[test]
fn a_removed_account_is_cut_off_without_waiting_for_its_session() {
    let h = support::setup();
    open_dir(&h, "pub");
    let bob = h.mount_as("bob");
    fs::write(bob.path.join("pub/before"), b"x").unwrap();
    assert!(h.runtime.block_on(users::remove(&h.client, "bob")).unwrap());
    assert_errno(fs::write(bob.path.join("pub/after"), b"x"), libc::EACCES);
}

#[test]
fn groups_are_named_and_given_free_gids() {
    let h = support::setup();
    add_people(&h);
    let in_use: Vec<u32> = h
        .runtime
        .block_on(users::list(&h.client))
        .unwrap()
        .into_iter()
        .flat_map(|(_, a)| std::iter::once(a.gid).chain(a.groups))
        .collect();

    let devs = h
        .runtime
        .block_on(groups::add(&h.client, "devs", None))
        .unwrap();
    assert!(devs >= groups::FIRST_ALLOCATED_GID && !in_use.contains(&devs));
    let next = h
        .runtime
        .block_on(groups::add(&h.client, "ops", None))
        .unwrap();
    assert_ne!(next, devs);
    assert_eq!(
        h.runtime
            .block_on(groups::add(&h.client, "devs", Some(60_000)))
            .unwrap_err()
            .errno,
        libc::EEXIST
    );
    assert_eq!(
        h.runtime
            .block_on(groups::add(&h.client, "qa", Some(devs)))
            .unwrap_err()
            .errno,
        libc::EEXIST
    );
    // A gid users already have can be named on purpose.
    assert_eq!(
        h.runtime
            .block_on(groups::add(&h.client, "staff", Some(STAFF)))
            .unwrap(),
        STAFF
    );

    let resolve = |g: &str| h.runtime.block_on(groups::resolve(&h.client, g));
    assert_eq!(resolve("devs").unwrap(), devs);
    assert_eq!(resolve("123").unwrap(), 123);
    assert_eq!(resolve("nobody").unwrap_err().errno, libc::ENOENT);
    let names: Vec<String> = h
        .runtime
        .block_on(groups::list(&h.client))
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, ["devs", "ops", "staff"]);

    // Removing a group leaves its gid on the users who have it.
    assert_eq!(
        h.runtime
            .block_on(groups::remove(&h.client, "staff"))
            .unwrap(),
        Some(STAFF)
    );
    assert_eq!(
        h.runtime
            .block_on(groups::remove(&h.client, "staff"))
            .unwrap(),
        None
    );
    assert_eq!(resolve("staff").unwrap_err().errno, libc::ENOENT);
    let alice = h
        .runtime
        .block_on(users::get(&h.client, "alice"))
        .unwrap()
        .unwrap();
    assert_eq!(alice.groups, [STAFF]);

    assert_eq!(
        h.runtime
            .block_on(users::modify(&h.client, "nobody", &[devs], &[]))
            .unwrap_err()
            .errno,
        libc::ENOENT
    );
}

// ------------------------------------------------------- identity, tokens

fn connect_as(h: &support::Harness, user: &str, password: &str) -> Result<(), String> {
    let addresses: Vec<String> = h.servers.iter().map(|s| s.address.clone()).collect();
    let credentials = raft5fs_fuse::remote::Credentials {
        username: user.to_string(),
        password: password.to_string(),
    };
    h.runtime
        .block_on(raft5fs_fuse::remote::Remote::connect(
            &addresses,
            credentials,
            Some(support::fs_tls()),
        ))
        .map(drop)
}

#[test]
fn a_wrong_password_is_refused() {
    let h = support::setup();
    add_people(&h);
    let refused = connect_as(&h, "alice", "alice").unwrap_err();
    assert!(refused.contains("login refused"), "{refused}");
    connect_as(&h, "alice", &support::password("alice")).unwrap();
}

#[test]
fn a_store_account_without_a_filesystem_identity_is_refused() {
    let h = support::setup();
    h.runtime
        .block_on(
            h.cluster
                .admin
                .create_user("dave", &support::password("dave"), false),
        )
        .unwrap();
    let refused = connect_as(&h, "dave", &support::password("dave")).unwrap_err();
    assert!(refused.contains("no filesystem account"), "{refused}");
}

/// Users get at the filesystem only through the servers. The store talks
/// only to holders of a client certificate, which users don't have...
#[test]
fn users_cannot_connect_to_the_store_at_all() {
    let h = support::setup();
    add_people(&h);
    h.runtime.block_on(async {
        let alice = raft5_client::Client::with_tls(
            [&h.cluster.client_address],
            support::store_tls_without_identity(),
        )
        .unwrap();
        let refused = alice
            .login("alice", &support::password("alice"))
            .await
            .unwrap_err();
        // Refused at the handshake, before any RPC: to the client that
        // looks like a store that never answers.
        assert!(
            matches!(refused, raft5_client::Error::Unavailable(_)),
            "{refused}"
        );
    });
}

/// ...and even holding one, a user's own store account can't read the
/// filesystem's keys, let alone write them.
#[test]
fn users_cannot_reach_the_filesystems_keys_directly() {
    let h = support::setup();
    add_people(&h);
    h.runtime.block_on(async {
        let alice =
            raft5_client::Client::with_tls([&h.cluster.client_address], support::store_tls())
                .unwrap();
        alice
            .login("alice", &support::password("alice"))
            .await
            .unwrap();
        assert!(alice.read(CHUNK_SIZE_KEY).await.is_err());
        assert!(alice.write(CHUNK_SIZE_KEY, Some(b"x")).await.is_err());
    });
    // Still there and unchanged, as the service account sees it.
    assert_eq!(h.read_key(CHUNK_SIZE_KEY).unwrap().len(), 8);
}

/// A mount whose session stops being accepted -- here because the servers
/// now sign with another key, as after a rotation; an expiry looks the
/// same -- logs in again by itself and carries on.
#[test]
fn a_refused_session_is_renewed_by_logging_in_again() {
    let mut h = support::setup();
    let path = h.path().join("f");
    fs::write(&path, b"before").unwrap();

    h.restart_servers_with_key("another key, also at least 32 bytes");

    assert_eq!(fs::read(&path).unwrap(), b"before");
    fs::write(h.path().join("g"), b"after").unwrap();
    assert_eq!(fs::read(h.path().join("g")).unwrap(), b"after");
}

/// Servers keep nothing about open files, so a descriptor survives every
/// server being restarted under it.
#[test]
fn an_open_file_survives_its_servers_restarting() {
    let mut h = support::setup();
    let path = h.path().join("f");
    fs::write(&path, b"0123456789").unwrap();
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();

    h.restart_servers_with_key(support::TOKEN_KEY);

    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(b"abc").unwrap();
    f.sync_all().unwrap();
    let mut got = String::new();
    f.seek(SeekFrom::Start(0)).unwrap();
    std::io::Read::read_to_string(&mut f, &mut got).unwrap();
    assert_eq!(got, "abc3456789");
}

/// Access is decided at open, as POSIX has it: taking permissions away
/// afterwards doesn't break a descriptor already open.
#[test]
fn an_open_file_keeps_the_access_it_was_opened_with() {
    let h = support::setup();
    let path = h.path().join("f");
    fs::write(&path, b"data").unwrap();
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    chmod(&path, 0o000).unwrap();

    assert_errno(fs::read(&path), libc::EACCES);
    f.write_all(b"more").unwrap();
    f.sync_all().unwrap();
    let mut got = String::new();
    f.seek(SeekFrom::Start(0)).unwrap();
    std::io::Read::read_to_string(&mut f, &mut got).unwrap();
    assert_eq!(got, "more");
}

/// Creating a file read-only and filling it through the descriptor that
/// created it is ordinary -- `cp` does it for every read-only file.
#[test]
fn a_file_created_read_only_can_be_written_through_its_creating_descriptor() {
    use std::os::unix::fs::OpenOptionsExt;
    let h = support::setup();
    let path = h.path().join("ro");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&path)
        .unwrap();
    f.write_all(b"contents").unwrap();
    f.set_len(4).unwrap();
    drop(f);

    assert_eq!(fs::read(&path).unwrap(), b"cont");
    assert_errno(fs::OpenOptions::new().write(true).open(&path), libc::EACCES);
}

// ----------------------------------------------------------------- rename

#[test]
fn rename_within_a_directory() {
    let h = support::setup();
    let (a, b) = (h.path().join("a"), h.path().join("b"));
    fs::write(&a, b"contents").unwrap();
    let ino = ino_of(&a);

    fs::rename(&a, &b).unwrap();

    assert!(!a.exists());
    assert_eq!(fs::read(&b).unwrap(), b"contents");
    assert_eq!(ino_of(&b), ino, "a rename keeps the inode");
    let names: Vec<_> = fs::read_dir(h.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["b"]);
}

#[test]
fn rename_across_directories_moves_files_and_whole_trees() {
    let h = support::setup();
    let p = h.path();
    fs::create_dir_all(p.join("src/tree/deep")).unwrap();
    fs::write(p.join("src/tree/deep/f"), b"deep").unwrap();
    fs::write(p.join("src/file"), b"file").unwrap();
    fs::create_dir(p.join("dst")).unwrap();

    fs::rename(p.join("src/file"), p.join("dst/file")).unwrap();
    fs::rename(p.join("src/tree"), p.join("dst/tree")).unwrap();

    assert_eq!(fs::read(p.join("dst/file")).unwrap(), b"file");
    assert_eq!(fs::read(p.join("dst/tree/deep/f")).unwrap(), b"deep");
    assert_eq!(fs::read_dir(p.join("src")).unwrap().count(), 0);
    // A fresh mount resolves the new paths from the store alone.
    let other = h.second_mount();
    assert_eq!(
        fs::read(other.path.join("dst/tree/deep/f")).unwrap(),
        b"deep"
    );
    assert!(!other.path.join("src/tree").exists());
}

#[test]
fn rename_over_a_file_replaces_it_and_frees_its_data() {
    let h = support::setup();
    let (a, b) = (h.path().join("a"), h.path().join("b"));
    fs::write(&a, b"new").unwrap();
    fs::write(&b, pattern(3 * h.chunk_size as usize)).unwrap();
    let old = ino_of(&b);
    assert!(!h.keys_with_prefix(&chunk_prefix(old)).is_empty());

    fs::rename(&a, &b).unwrap();

    assert_eq!(fs::read(&b).unwrap(), b"new");
    assert!(h.keys_with_prefix(&chunk_prefix(old)).is_empty());
    assert!(h.read_key(&tombstone_key(old)).is_none());
}

/// The data stays where it is: chunks are keyed by inode, so moving a
/// large file rewrites none of them.
#[test]
fn rename_copies_no_data() {
    let h = support::setup();
    let a = h.path().join("big");
    fs::write(&a, pattern(8 * h.chunk_size as usize)).unwrap();
    let ino = ino_of(&a);
    let chunks = h.keys_with_prefix(&chunk_prefix(ino));
    let before: Vec<u64> = chunks.iter().map(|k| h.key_version(k)).collect();
    fs::create_dir(h.path().join("d")).unwrap();

    fs::rename(&a, h.path().join("d/big")).unwrap();

    let after: Vec<u64> = chunks.iter().map(|k| h.key_version(k)).collect();
    assert_eq!(before, after);
    assert_same_bytes(
        &fs::read(h.path().join("d/big")).unwrap(),
        &pattern(8 * h.chunk_size as usize),
    );
}

#[test]
fn rename_over_a_directory_needs_it_empty_and_of_the_same_kind() {
    let h = support::setup();
    let p = h.path();
    fs::create_dir(p.join("d1")).unwrap();
    fs::write(p.join("d1/f"), b"x").unwrap();
    fs::create_dir(p.join("full")).unwrap();
    fs::write(p.join("full/f"), b"x").unwrap();
    fs::create_dir(p.join("empty")).unwrap();
    fs::write(p.join("file"), b"x").unwrap();

    assert_errno(fs::rename(p.join("d1"), p.join("full")), libc::ENOTEMPTY);
    assert_errno(fs::rename(p.join("d1"), p.join("file")), libc::ENOTDIR);
    assert_errno(fs::rename(p.join("file"), p.join("empty")), libc::EISDIR);
    let empty = ino_of(&p.join("empty"));
    fs::rename(p.join("d1"), p.join("empty")).unwrap();
    assert_eq!(fs::read(p.join("empty/f")).unwrap(), b"x");
    assert!(!p.join("d1").exists());
    assert!(h.read_key(&tombstone_key(empty)).is_none());
}

#[test]
fn a_directory_cannot_be_moved_into_itself() {
    let h = support::setup();
    let p = h.path();
    fs::create_dir_all(p.join("a/b/c")).unwrap();

    assert_errno(fs::rename(p.join("a"), p.join("a/b/c/a")), libc::EINVAL);
    assert_errno(fs::rename(p.join("a"), p.join("a/a")), libc::EINVAL);
    assert!(p.join("a/b/c").is_dir());
    // Moving one level up out of itself is fine.
    fs::rename(p.join("a/b/c"), p.join("c")).unwrap();
    assert!(p.join("c").is_dir());
}

fn renameat2(from: &std::path::Path, to: &std::path::Path, flags: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes()).unwrap();
    let to = std::ffi::CString::new(to.as_os_str().as_bytes()).unwrap();
    let r = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            flags,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[test]
fn rename_noreplace_refuses_an_existing_name_and_exchange_is_unsupported() {
    let h = support::setup();
    let (a, b, c) = (h.path().join("a"), h.path().join("b"), h.path().join("c"));
    fs::write(&a, b"a").unwrap();
    fs::write(&b, b"b").unwrap();

    assert_errno(renameat2(&a, &b, libc::RENAME_NOREPLACE), libc::EEXIST);
    assert_eq!(fs::read(&b).unwrap(), b"b");
    renameat2(&a, &c, libc::RENAME_NOREPLACE).unwrap();
    assert_errno(renameat2(&b, &c, libc::RENAME_EXCHANGE), libc::EINVAL);
}

#[test]
fn renaming_takes_write_permission_on_both_directories_and_respects_sticky() {
    let h = support::setup();
    open_dir(&h, "pub");
    let tmp = h.path().join("tmp");
    fs::create_dir(&tmp).unwrap();
    chmod(&tmp, 0o1777).unwrap();
    let alice = h.mount_as("alice");
    let bob = h.mount_as("bob");
    fs::create_dir(alice.path.join("pub/mine")).unwrap();
    chmod(&alice.path.join("pub/mine"), 0o755).unwrap();
    fs::write(alice.path.join("pub/mine/f"), b"x").unwrap();
    fs::write(alice.path.join("tmp/alices"), b"x").unwrap();
    fs::create_dir(bob.path.join("pub/bobs")).unwrap();

    // Out of a directory bob can't write, and into one.
    assert_errno(
        fs::rename(bob.path.join("pub/mine/f"), bob.path.join("pub/bobs/f")),
        libc::EACCES,
    );
    fs::write(bob.path.join("pub/bobs/g"), b"x").unwrap();
    assert_errno(
        fs::rename(bob.path.join("pub/bobs/g"), bob.path.join("pub/mine/g")),
        libc::EACCES,
    );
    // Someone else's file in a sticky directory.
    assert_errno(
        fs::rename(bob.path.join("tmp/alices"), bob.path.join("tmp/bobs-now")),
        libc::EPERM,
    );
    assert!(alice.path.join("pub/mine/f").exists());
    assert!(alice.path.join("tmp/alices").exists());
}

/// rmdir's emptiness check and a create in the same directory can't both
/// win: either the directory goes and nothing was created in it, or the
/// create lands and the directory stays. A create that slipped in after
/// the check would leave an entry nothing can reach.
///
/// A smoke test, not proof: the window it probes is a single round trip
/// wide, too narrow to hit reliably. What closes it is the locking
/// argument on `is_empty_dir`.
#[test]
fn rmdir_and_a_concurrent_create_cannot_both_succeed() {
    let h = support::setup();
    let other = h.second_mount();
    for round in 0..20 {
        let dir = format!("d{round}");
        fs::create_dir(h.path().join(&dir)).unwrap();
        let ino = ino_of(&h.path().join(&dir));
        let barrier = std::sync::Barrier::new(2);
        let (removed, created) = std::thread::scope(|s| {
            let rm = s.spawn(|| {
                barrier.wait();
                fs::remove_dir(h.path().join(&dir)).is_ok()
            });
            let mk = s.spawn(|| {
                barrier.wait();
                fs::write(other.path.join(&dir).join("f"), b"x").is_ok()
            });
            (rm.join().unwrap(), mk.join().unwrap())
        });
        assert!(!(removed && created), "round {round}: both succeeded");
        if removed {
            assert!(
                h.keys_with_prefix(&dirent_prefix(ino)).is_empty(),
                "round {round}: a removed directory kept entries"
            );
        }
    }
}

/// Two renames that would each be fine alone, but together would make a
/// loop -- `a` into `b` and `b` into `a` -- that nothing could reach.
/// Exactly one must win.
#[test]
fn opposite_renames_cannot_make_a_loop() {
    let h = support::setup();
    let other = h.second_mount();
    for round in 0..20 {
        let x = format!("x{round}");
        fs::create_dir_all(h.path().join(&x).join("a")).unwrap();
        fs::create_dir(h.path().join(&x).join("b")).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let (ab, ba) = std::thread::scope(|s| {
            let ab = s.spawn(|| {
                barrier.wait();
                fs::rename(h.path().join(&x).join("a"), h.path().join(&x).join("b/a")).is_ok()
            });
            let ba = s.spawn(|| {
                barrier.wait();
                fs::rename(
                    other.path.join(&x).join("b"),
                    other.path.join(&x).join("a/b"),
                )
                .is_ok()
            });
            (ab.join().unwrap(), ba.join().unwrap())
        });
        assert!(ab != ba, "round {round}: a->b/a {ab}, b->a/b {ba}");
        // Whichever won, both are still reachable from the root.
        let fresh = h.second_mount();
        let base = fresh.path.join(&x);
        let reachable = if ab {
            base.join("b/a").is_dir()
        } else {
            base.join("a/b").is_dir()
        };
        assert!(
            reachable,
            "round {round}: the moved directory is unreachable"
        );
    }
}

#[test]
fn creating_and_removing_update_the_directorys_mtime() {
    let h = support::setup();
    let dir = h.path().join("d");
    fs::create_dir(&dir).unwrap();
    let mtime = |p: &std::path::Path| fs::metadata(p).unwrap().modified().unwrap();
    let t0 = mtime(&dir);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(dir.join("f"), b"x").unwrap();
    let t1 = mtime(&dir);
    assert!(t1 > t0);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::remove_file(dir.join("f")).unwrap();
    assert!(mtime(&dir) > t1);
}
