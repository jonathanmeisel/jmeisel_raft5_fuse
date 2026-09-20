//! End-to-end tests: a real single-node raft5 cluster, a real `Raft5Fs`
//! mounted through the kernel's FUSE interface, and plain `std::fs`
//! calls against the mountpoint -- see `support` for how both are
//! wired up.

mod support;

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use jmeisel_raft5_fuse::filesystem::{
    CHUNK_SIZE_KEY, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, chunk_prefix,
};

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

    let fs_over_same_store = h.unmounted_fs(h.chunk_size);
    let err = fs_over_same_store
        .resolve_chunk_size(h.chunk_size)
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
    f.write_all(&pattern(4096)).unwrap();
    let ino = ino_from_readdir(h.path(), "buffered.bin");
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

#[test]
fn a_filled_chunk_is_stored_without_waiting_for_close() {
    let h = support::setup();
    let c = h.chunk_size as usize;
    let path = h.path().join("filling.bin");

    let mut f = fs::File::create(&path).unwrap();
    for piece in pattern(c).chunks(4096) {
        f.write_all(piece).unwrap();
    }
    let ino = ino_from_readdir(h.path(), "filling.bin");
    assert_eq!(h.keys_with_prefix(&chunk_prefix(ino)).len(), 1);
    drop(f);
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
