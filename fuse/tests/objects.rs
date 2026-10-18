//! Object storage: hybrid files, upload URLs, block pointers and how the
//! servers check, read and trim them, and how mounts read and write
//! blocks. The servers' side is driven through `Remote`, sealing and
//! uploading blocks by hand; the mounts' through `std::fs`.

mod support;

use std::ffi::OsStr;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use raft5fs_core::{
    BlockRef, BlockUpload, ChunkBody, ChunkWrite, FsError, Layout, ObjectGrid, SetAttr, WriteBody,
};
use raft5fs_crypto::data::{CHUNK_OVERHEAD, open_chunk, seal_chunk};
use raft5fs_fuse::remote::Remote;
use raft5fs_fuse::vault::{Node, Vault};
use raft5fs_objstore::http::{self, HttpConfig};
use support::{TEST_BLOCK_CHUNKS, TEST_CHUNK_SIZE, TEST_OBJECT_FROM_CHUNKS};

const C: u64 = TEST_CHUNK_SIZE;
/// The first chunk index in blocks, and the second block's.
const K: u64 = TEST_OBJECT_FROM_CHUNKS;
const K2: u64 = K + TEST_BLOCK_CHUNKS;
/// What one sealed segment takes in an object.
const S: u64 = C + CHUNK_OVERHEAD as u64;

/// Not really a test: the entry point that lets the harness run a
/// filesystem server as a separate process (see `support::TestServer`).
/// Returns at once in a normal run.
#[test]
fn server_process_mode() {
    support::serve_if_requested();
}

fn connect(h: &support::Harness) -> Remote {
    let credentials = support::credentials(support::TESTER);
    h.runtime
        .block_on(Remote::connect(
            &h.addresses(),
            credentials,
            Some(support::fs_tls()),
        ))
        .unwrap()
}

fn vault(h: &support::Harness) -> Vault {
    Vault::new(Arc::new(connect(h)))
        .unwrap()
        .with_known_keys(h.known_keys())
}

fn ino(path: &Path) -> u64 {
    fs::metadata(path).unwrap().ino()
}

fn plaintext_http() -> http::Client {
    http::client(&HttpConfig {
        allow_plaintext: true,
        ..HttpConfig::default()
    })
    .unwrap()
}

#[track_caller]
fn assert_fs_errno<T: std::fmt::Debug>(result: Result<T, FsError>, errno: i32) {
    match result {
        Err(e) => assert_eq!(e.errno, errno, "wrong error: {e}"),
        Ok(v) => panic!("expected errno {errno}, got Ok({v:?})"),
    }
}

/// A file `v/f` in a harness with object storage, with a few inline bytes
/// in it, and its key.
fn hybrid_file(h: &support::Harness, mine: &Vault) -> (u64, Arc<Node>) {
    let f = h.path().join("f");
    fs::write(&f, b"head").unwrap();
    let file = ino(&f);
    let node = h.runtime.block_on(mine.node(file)).unwrap();
    (file, node)
}

/// Block `plains` of `ino` from chunk `first` on, as a client seals one:
/// each segment zero-padded to a whole chunk, then sealed at its index.
fn seal_block(node: &Node, ino: u64, first: u64, plains: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for (j, plain) in plains.iter().enumerate() {
        let mut padded = plain.clone();
        padded.resize(C as usize, 0);
        body.extend(seal_chunk(
            &node.key,
            node.record.version,
            ino,
            first + j as u64,
            &padded,
        ));
    }
    body
}

/// Uploads `plains` as the block at chunk `first`, through a URL the
/// servers mint, and returns the pointer that would commit it.
fn upload(
    h: &support::Harness,
    remote: &Remote,
    node: &Node,
    ino: u64,
    first: u64,
    plains: &[Vec<u8>],
) -> BlockRef {
    let nseg = plains.len() as u32;
    let mut prepared = h
        .runtime
        .block_on(remote.prepare_uploads(ino, &[BlockUpload { index: first, nseg }]))
        .unwrap();
    assert_eq!(prepared.len(), 1);
    let up = prepared.pop().unwrap();
    let body = seal_block(node, ino, first, plains);
    assert_eq!(body.len() as u64, u64::from(nseg) * S);
    h.runtime
        .block_on(http::put(&plaintext_http(), &up.url, body))
        .unwrap();
    BlockRef {
        version: node.record.version,
        minted_ms: up.minted_ms,
        random: up.random,
        nseg,
    }
}

fn block_write(index: u64, block: BlockRef) -> ChunkWrite {
    ChunkWrite {
        index,
        expected_seq: None,
        body: WriteBody::Block(block),
    }
}

/// What the store holds under chunk `index` of `ino`.
fn stored(h: &support::Harness, ino: u64, index: u64) -> Option<Vec<u8>> {
    let mut key = raft5fs_core::chunk_prefix(ino);
    key.extend_from_slice(&index.to_be_bytes());
    h.read_key(&key)
}

#[test]
fn the_servers_say_how_blocks_are_laid_out() {
    let h = support::setup_with_objects();
    assert_eq!(
        connect(&h).grid(),
        Some(ObjectGrid {
            from_index: K,
            per_block: TEST_BLOCK_CHUNKS as u32,
        })
    );
    let plain = support::setup();
    assert_eq!(connect(&plain).grid(), None);
    // Without object storage there is nothing to upload to.
    fs::write(plain.path().join("f"), b"x").unwrap();
    let file = ino(&plain.path().join("f"));
    assert_fs_errno(
        plain
            .runtime
            .block_on(connect(&plain).prepare_uploads(file, &[BlockUpload { index: K, nseg: 1 }])),
        libc::ENOTSUP,
    );
}

#[test]
fn files_made_with_object_storage_are_hybrid() {
    let h = support::setup_with_objects();
    fs::write(h.path().join("f"), b"x").unwrap();
    fs::create_dir(h.path().join("d")).unwrap();
    let remote = connect(&h);
    let attr = |p: &str| {
        h.runtime
            .block_on(remote.getattr(ino(&h.path().join(p))))
            .unwrap()
    };
    assert_eq!(attr("f").layout, Layout::Hybrid);
    assert_eq!(attr("d").layout, Layout::Inline);
    // Small files keep everything in the store.
    assert!(h.store().keys().is_empty());
}

#[test]
fn a_block_round_trips() {
    let h = support::setup_with_objects();
    let mine = vault(&h);
    let remote = mine.remote();
    let (file, node) = hybrid_file(&h, &mine);

    let plains = vec![vec![1; C as usize], vec![2; 100]];
    let block = upload(&h, remote, &node, file, K, &plains);
    let end = (K + 1) * C + 100;
    let (attr, seq) = h
        .runtime
        .block_on(remote.write_chunks(file, &[block_write(K, block)], end))
        .unwrap();
    assert_eq!(attr.size, end);

    // One 32-byte pointer, at the block's first index only; one object.
    assert_eq!(stored(&h, file, K).unwrap().len(), 32);
    assert_eq!(stored(&h, file, K + 1), None);
    let keys = h.store().keys();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].starts_with(&format!("{}{file:016x}/", support::TEST_OBJECT_PREFIX)));
    assert_eq!(h.store().object(&keys[0]).unwrap().len() as u64, 2 * S);

    let read = h
        .runtime
        .block_on(remote.read_chunks(file, K, TEST_BLOCK_CHUNKS as u32, &[]))
        .unwrap();
    let bodies: Vec<_> = read.chunks.iter().map(|c| c.body.clone()).collect();
    assert_eq!(
        bodies,
        vec![
            ChunkBody::Segment {
                block: 0,
                segment: 0
            },
            ChunkBody::Segment {
                block: 0,
                segment: 1
            },
            ChunkBody::Hole,
            ChunkBody::Hole,
        ]
    );
    assert!(read.chunks.iter().all(|c| c.seq == seq));
    assert_eq!(read.blocks.len(), 1);
    assert_eq!(read.blocks[0].block, block);

    // Each segment opens on its own, from a ranged read.
    let http = plaintext_http();
    for (j, plain) in plains.iter().enumerate() {
        let j = j as u64;
        let sealed = h
            .runtime
            .block_on(http::get_range(
                &http,
                &read.blocks[0].url,
                j * S..(j + 1) * S,
            ))
            .unwrap();
        let opened = open_chunk(&node.key, file, K + j, &sealed).unwrap();
        assert_eq!(&opened[..plain.len()], &plain[..]);
        assert!(opened[plain.len()..].iter().all(|&b| b == 0));
    }

    // What the client holds at the block's seq is confirmed, not resent.
    let again = h
        .runtime
        .block_on(remote.read_chunks(file, K, 2, &[seq, seq]))
        .unwrap();
    assert!(again.chunks.iter().all(|c| c.unchanged));
    assert!(again.blocks.is_empty());

    // The chunk before the blocks is still inline.
    let head = h
        .runtime
        .block_on(remote.read_chunks(file, 0, 1, &[]))
        .unwrap();
    assert!(matches!(head.chunks[0].body, ChunkBody::Inline(_)));

    // A snapshot reads the block too, and keeps it after a rewrite.
    h.snapshot("s");
    let later = upload(&h, remote, &node, file, K, &[vec![9; 10]]);
    h.runtime
        .block_on(remote.write_chunks(file, &[block_write(K, later)], 0))
        .unwrap();
    let at = remote.at("s");
    let then = h.runtime.block_on(at.read_chunks(file, K, 1, &[])).unwrap();
    assert_eq!(then.blocks[0].block, block);
}

#[test]
fn commits_are_checked() {
    let h = support::setup_with_objects();
    let mine = vault(&h);
    let remote = mine.remote();
    let (file, node) = hybrid_file(&h, &mine);
    let write = |w: ChunkWrite| h.runtime.block_on(remote.write_chunks(file, &[w], 0));
    let prepare = |index, nseg| {
        h.runtime
            .block_on(remote.prepare_uploads(file, &[BlockUpload { index, nseg }]))
    };

    // Names only where a block starts, for a block's worth of segments.
    for (index, nseg) in [
        (K + 1, 1),
        (K - 1, 1),
        (K, 0),
        (K, TEST_BLOCK_CHUNKS as u32 + 1),
    ] {
        assert_fs_errno(prepare(index, nseg), libc::EINVAL);
    }
    prepare(K2, TEST_BLOCK_CHUNKS as u32).unwrap();

    let block = upload(&h, remote, &node, file, K, &[vec![1; 10]]);
    // A block anywhere but at a block's start, or inline data in a block.
    assert_fs_errno(write(block_write(K + 1, block)), libc::EINVAL);
    assert_fs_errno(write(block_write(K - 1, block)), libc::EINVAL);
    let inline = seal_chunk(&node.key, node.record.version, file, K, b"x");
    assert_fs_errno(
        write(ChunkWrite {
            index: K,
            expected_seq: None,
            body: WriteBody::Inline(inline),
        }),
        libc::EINVAL,
    );
    // More segments than a block holds.
    assert_fs_errno(
        write(block_write(
            K,
            BlockRef {
                nseg: TEST_BLOCK_CHUNKS as u32 + 1,
                ..block
            },
        )),
        libc::EINVAL,
    );
    // Sealed under a version the file doesn't have.
    assert_fs_errno(
        write(block_write(
            K,
            BlockRef {
                version: block.version + 1,
                ..block
            },
        )),
        libc::EKEYEXPIRED,
    );
    // Named too long ago to commit, or not yet.
    let ms = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    for minted in [
        SystemTime::now() - Duration::from_secs(3600),
        SystemTime::now() + Duration::from_secs(3600),
    ] {
        assert_fs_errno(
            write(block_write(
                K,
                BlockRef {
                    minted_ms: ms(minted),
                    ..block
                },
            )),
            libc::EINVAL,
        );
    }
    assert_eq!(stored(&h, file, K), None, "nothing landed");
    write(block_write(K, block)).unwrap();
}

#[test]
fn a_client_that_cant_read_blocks_is_refused_not_given_zeros() {
    let h = support::setup_with_objects();
    let mine = vault(&h);
    let (file, node) = hybrid_file(&h, &mine);
    let block = upload(&h, mine.remote(), &node, file, K, &[vec![1; 10]]);
    h.runtime
        .block_on(
            mine.remote()
                .write_chunks(file, &[block_write(K, block)], K * C + 10),
        )
        .unwrap();

    let old = connect(&h).without_object_reads();
    assert_fs_errno(
        h.runtime.block_on(old.read_chunks(file, K, 1, &[])),
        libc::ENOTSUP,
    );
    // What it can read, it still can.
    let head = h
        .runtime
        .block_on(old.read_chunks(file, 0, 1, &[]))
        .unwrap();
    assert!(matches!(head.chunks[0].body, ChunkBody::Inline(_)));
}

#[test]
fn truncating_trims_the_block_the_end_falls_in() {
    let h = support::setup_with_objects();
    let mine = vault(&h);
    let remote = mine.remote();
    let (file, node) = hybrid_file(&h, &mine);
    let full: Vec<Vec<u8>> = (0..TEST_BLOCK_CHUNKS)
        .map(|j| vec![j as u8 + 1; C as usize])
        .collect();
    let block = upload(&h, remote, &node, file, K, &full);
    let second = upload(&h, remote, &node, file, K2, &[vec![7; 10]]);
    h.runtime
        .block_on(remote.write_chunks(
            file,
            &[block_write(K, block), block_write(K2, second)],
            K2 * C + 10,
        ))
        .unwrap();
    let nseg = |h: &support::Harness| {
        stored(h, file, K).map(|v| u32::from_be_bytes(v[28..32].try_into().unwrap()))
    };
    let truncate = |size| {
        h.runtime
            .block_on(remote.setattr(
                file,
                SetAttr {
                    size: Some(size),
                    ..SetAttr::default()
                },
            ))
            .unwrap()
    };
    let bodies = || -> Vec<ChunkBody> {
        h.runtime
            .block_on(remote.read_chunks(file, K, TEST_BLOCK_CHUNKS as u32, &[]))
            .unwrap()
            .chunks
            .into_iter()
            .map(|c| c.body)
            .collect()
    };

    // Into the block's second segment: two segments stay, the next block
    // goes, and no new object is made.
    let objects = h.store().keys().len();
    truncate((K + 1) * C + 10);
    assert_eq!(nseg(&h), Some(2));
    assert_eq!(stored(&h, file, K2), None);
    assert_eq!(h.store().keys().len(), objects);
    // Grown again, the segments cut off read as holes, not as they were.
    truncate(K2 * C);
    assert_eq!(nseg(&h), Some(2));
    assert!(matches!(bodies()[1], ChunkBody::Segment { .. }));
    assert_eq!(bodies()[2..], [ChunkBody::Hole, ChunkBody::Hole]);
    // To the block's start: the block goes.
    truncate(K * C);
    assert_eq!(nseg(&h), None);
    assert!(bodies().iter().all(|b| *b == ChunkBody::Hole));
}

/// Commits `plains` as the block at chunk `first` of `ino`, growing the
/// file to `end`.
fn commit(
    h: &support::Harness,
    mine: &Vault,
    node: &Node,
    ino: u64,
    first: u64,
    plains: &[Vec<u8>],
    end: u64,
) {
    let block = upload(h, mine.remote(), node, ino, first, plains);
    h.runtime
        .block_on(
            mine.remote()
                .write_chunks(ino, &[block_write(first, block)], end),
        )
        .unwrap();
}

#[test]
fn a_mount_reads_blocks() {
    let h = support::setup_with_objects();
    let mine = vault(&h);
    let (file, node) = hybrid_file(&h, &mine);
    let end = K2 * C + 50;
    commit(
        &h,
        &mine,
        &node,
        file,
        K,
        &[vec![1; C as usize], vec![2; 100]],
        end,
    );
    commit(&h, &mine, &node, file, K2, &[vec![3; 50]], end);

    let mut expected = vec![0; end as usize];
    expected[..4].copy_from_slice(b"head");
    let at = |i: u64| i as usize;
    expected[at(K * C)..at((K + 1) * C)].fill(1);
    expected[at((K + 1) * C)..at((K + 1) * C + 100)].fill(2);
    expected[at(K2 * C)..].fill(3);

    // Through a vault of its own, which has cached none of it...
    let reader = vault(&h);
    let read = h
        .runtime
        .block_on(reader.read(file, 0, end as usize + 100))
        .unwrap();
    assert_eq!(read, expected);
    // ...part-way into a block and out the other side...
    let from = (K + 1) * C + 90;
    let part = h
        .runtime
        .block_on(reader.read(file, from, (K2 * C + 10 - from) as usize))
        .unwrap();
    assert_eq!(part, expected[at(from)..at(K2 * C + 10)]);
    // ...and through the kernel, on a mount with nothing cached.
    let other = h.second_mount();
    assert_eq!(fs::read(other.path.join("f")).unwrap(), expected);
}

#[test]
fn a_read_fetches_only_the_segments_it_needs_once() {
    let h = support::setup_with_objects();
    let mine = vault(&h);
    let (file, node) = hybrid_file(&h, &mine);
    let full: Vec<Vec<u8>> = (0..TEST_BLOCK_CHUNKS)
        .map(|j| vec![j as u8 + 1; C as usize])
        .collect();
    commit(&h, &mine, &node, file, K, &full, K2 * C);
    let fetched = |since: &raft5fs_objstore::fake::Stats| {
        let now = h.store().stats();
        (now.gets - since.gets, now.bytes_read - since.bytes_read)
    };

    // A few bytes of the third segment: that segment, alone.
    let reader = vault(&h);
    let before = h.store().stats();
    let got = h
        .runtime
        .block_on(reader.read(file, (K + 2) * C + 10, 20))
        .unwrap();
    assert_eq!(got, vec![3; 20]);
    assert_eq!(fetched(&before), (1, S));

    // The whole block, from a vault with nothing cached: one ranged GET.
    let fresh = vault(&h);
    let before = h.store().stats();
    let got = h
        .runtime
        .block_on(fresh.read(file, K * C, (TEST_BLOCK_CHUNKS * C) as usize))
        .unwrap();
    assert_eq!(got.len() as u64, TEST_BLOCK_CHUNKS * C);
    assert_eq!(fetched(&before), (1, TEST_BLOCK_CHUNKS * S));

    // Again: all cached, confirmed with the server, nothing fetched.
    let before = h.store().stats();
    h.runtime
        .block_on(fresh.read(file, K * C, (TEST_BLOCK_CHUNKS * C) as usize))
        .unwrap();
    assert_eq!(fetched(&before), (0, 0));

    // Around a cached segment: the runs either side of it.
    let before = h.store().stats();
    h.runtime
        .block_on(reader.read(file, K * C, (TEST_BLOCK_CHUNKS * C) as usize))
        .unwrap();
    assert_eq!(fetched(&before), (2, (TEST_BLOCK_CHUNKS - 1) * S));
}

#[test]
fn a_snapshot_reads_the_blocks_it_was_taken_with() {
    let h = support::setup_with_objects();
    let mine = vault(&h);
    let (file, node) = hybrid_file(&h, &mine);
    let end = K * C + 10;
    commit(&h, &mine, &node, file, K, &[vec![1; 10]], end);
    h.snapshot("s");
    commit(&h, &mine, &node, file, K, &[vec![2; 10]], end);

    let then = mine.at_snapshot("s", 1);
    let read = |v: &Vault| h.runtime.block_on(v.read(file, K * C, 10)).unwrap();
    assert_eq!(read(&then), vec![1; 10]);
    assert_eq!(read(&mine), vec![2; 10]);
}

/// How much of a file one block holds.
const B: u64 = TEST_BLOCK_CHUNKS * C;

fn pattern(len: u64) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8 + 1).collect()
}

/// How many segments the block at chunk `index` of `ino` holds, if
/// there is one.
fn nseg(h: &support::Harness, ino: u64, index: u64) -> Option<u32> {
    stored(h, ino, index).map(|v| {
        assert_eq!(v.len(), 32, "a block pointer");
        u32::from_be_bytes(v[28..32].try_into().unwrap())
    })
}

/// `path` as a mount that has cached none of it reads it.
fn read_afresh(h: &support::Harness, name: &str) -> Vec<u8> {
    let other = h.second_mount();
    fs::read(other.path.join(name)).unwrap()
}

#[test]
fn a_sequential_write_uploads_each_block_once() {
    let h = support::setup_with_objects();
    let data = pattern(K * C + 2 * B + C / 2);
    let f = h.path().join("f");
    fs::write(&f, &data).unwrap();
    let file = ino(&f);

    // Two whole blocks and the start of a third, one upload each.
    assert_eq!(h.store().stats().puts, 3);
    assert_eq!(h.store().keys().len(), 3);
    assert_eq!(nseg(&h, file, K), Some(TEST_BLOCK_CHUNKS as u32));
    assert_eq!(nseg(&h, file, K2), Some(TEST_BLOCK_CHUNKS as u32));
    assert_eq!(nseg(&h, file, K2 + TEST_BLOCK_CHUNKS), Some(1));
    // Nothing but pointers past the grid's start; the start, inline.
    assert_eq!(stored(&h, file, K + 1), None);
    assert!(stored(&h, file, K - 1).unwrap().len() > 32);

    assert_eq!(fs::read(&f).unwrap(), data);
    assert_eq!(read_afresh(&h, "f"), data);
}

#[test]
fn a_small_write_into_a_block_keeps_the_rest_of_it() {
    let h = support::setup_with_objects();
    let mut data = pattern(K * C + B + 100);
    let f = h.path().join("f");
    fs::write(&f, &data).unwrap();
    let objects = h.store().keys().len();

    let at = (K + 1) * C + 100;
    let file = fs::OpenOptions::new().write(true).open(&f).unwrap();
    file.write_all_at(&[0xee; 10], at).unwrap();
    // And one spanning two segments.
    file.write_all_at(&[0xdd; 20], (K + 3) * C - 10).unwrap();
    file.sync_all().unwrap();
    drop(file);
    data[at as usize..at as usize + 10].fill(0xee);
    let from = ((K + 3) * C - 10) as usize;
    data[from..from + 20].fill(0xdd);

    assert_eq!(fs::read(&f).unwrap(), data);
    assert_eq!(read_afresh(&h, "f"), data);
    // A new object for the block; the old ones are garbage collection's.
    assert!(h.store().keys().len() > objects);
}

#[test]
fn a_sparse_write_past_the_threshold_leaves_holes() {
    let h = support::setup_with_objects();
    let f = h.path().join("f");
    let mut file = fs::File::create(&f).unwrap();
    file.seek(SeekFrom::Start(K2 * C + 5)).unwrap();
    file.write_all(b"x").unwrap();
    drop(file);
    let file_ino = ino(&f);

    assert_eq!(
        nseg(&h, file_ino, K),
        None,
        "no block where nothing was written"
    );
    assert_eq!(nseg(&h, file_ino, K2), Some(1));
    let mut expected = vec![0; (K2 * C + 6) as usize];
    expected[(K2 * C + 5) as usize] = b'x';
    assert_eq!(read_afresh(&h, "f"), expected);
}

#[test]
fn truncating_into_a_segment_then_growing_reads_zeros() {
    let h = support::setup_with_objects();
    let data = pattern(K * C + B);
    let f = h.path().join("f");
    fs::write(&f, &data).unwrap();
    let file_ino = ino(&f);

    // On a segment's boundary: the servers trim the block, no upload.
    let puts = h.store().stats().puts;
    let file = fs::OpenOptions::new().write(true).open(&f).unwrap();
    file.set_len((K + 3) * C).unwrap();
    assert_eq!(h.store().stats().puts, puts);
    assert_eq!(nseg(&h, file_ino, K), Some(3));
    // Part-way into one: the block is rewritten with that segment cut.
    let cut = (K + 1) * C + 100;
    file.set_len(cut).unwrap();
    assert_eq!(h.store().stats().puts, puts + 1);
    assert_eq!(nseg(&h, file_ino, K), Some(2));
    // Grown again, what was cut reads as zeros.
    file.set_len(K * C + B).unwrap();
    drop(file);

    let mut expected = data[..cut as usize].to_vec();
    expected.resize((K * C + B) as usize, 0);
    assert_eq!(fs::read(&f).unwrap(), expected);
    assert_eq!(read_afresh(&h, "f"), expected);
}

#[test]
fn a_block_synced_part_way_is_finished_by_later_writes() {
    let h = support::setup_with_objects();
    let data = pattern(K * C + B + C);
    let f = h.path().join("f");
    let mut file = fs::File::create(&f).unwrap();
    let mid = (K * C + C + C / 2) as usize;
    file.write_all(&data[..mid]).unwrap();
    file.sync_all().unwrap();
    assert_eq!(nseg(&h, ino(&f), K), Some(2));
    file.write_all(&data[mid..]).unwrap();
    drop(file);

    assert_eq!(nseg(&h, ino(&f), K), Some(TEST_BLOCK_CHUNKS as u32));
    assert_eq!(read_afresh(&h, "f"), data);
}

#[test]
fn pruning_reseals_blocks_into_new_objects() {
    let h = support::setup_with_objects();
    let v = h.path().to_path_buf();
    let data = pattern(K * C + B + 100);
    fs::write(v.join("big"), &data).unwrap();
    let big = ino(&v.join("big"));
    // Granted and revoked: the volume's key rotates, big's is left stale.
    h.add_user("alice");
    let mine = vault(&h);
    h.runtime
        .block_on(mine.grant(ino(&v), "alice", false, OsStr::new("v")))
        .unwrap();
    h.runtime.block_on(mine.revoke(ino(&v), "alice")).unwrap();
    let old_version = u32::from_be_bytes(stored(&h, big, K).unwrap()[..4].try_into().unwrap());

    let dry = h.runtime.block_on(mine.prune_tree(ino(&v), true));
    assert!(dry.skipped.is_empty(), "{:?}", dry.skipped);
    assert!(dry.chunks as u64 > K + TEST_BLOCK_CHUNKS, "{dry:?}");
    let objects = h.store().keys().len();
    let stats = h.runtime.block_on(mine.prune_tree(ino(&v), false));
    assert!(stats.skipped.is_empty(), "{:?}", stats.skipped);
    assert_eq!(stats.chunks, dry.chunks);

    // Each block is a new object, under the key big has now.
    assert_eq!(h.store().keys().len(), objects + 2);
    for start in [K, K2] {
        let version = u32::from_be_bytes(stored(&h, big, start).unwrap()[..4].try_into().unwrap());
        assert!(version > old_version);
    }
    let fresh = vault(&h);
    assert_eq!(
        h.runtime
            .block_on(fresh.read(big, 0, data.len() + 10))
            .unwrap(),
        data
    );
    let again = h.runtime.block_on(mine.prune_tree(ino(&v), false));
    assert_eq!(again.chunks, 0, "{again:?}");
}

/// Past the commit window (a PUT URL's life, a transaction's, and clock
/// skew), so nothing minted before a sweep then is too new to judge.
const LATER: Duration = Duration::from_secs(3600);
/// How long an object must go unreferenced between two sweeps.
const WAIT: Duration = Duration::from_secs(
    raft5fs_core::objects::DEFAULT_GET_TTL.as_secs() + raft5fs_core::gc::DELETE_MARGIN.as_secs(),
);

fn sweep(
    h: &support::Harness,
    core: &raft5fs_core::FsCore,
    gc: &mut raft5fs_core::gc::Gc,
    at: SystemTime,
) -> raft5fs_core::gc::GcStats {
    h.runtime.block_on(core.gc_once(gc, at)).unwrap()
}

/// A file `f` holding one block, rewritten in part: its first object now
/// unreferenced.
fn file_with_garbage(h: &support::Harness) -> std::path::PathBuf {
    let f = h.path().join("f");
    fs::write(&f, pattern(K * C + B)).unwrap();
    let file = fs::OpenOptions::new().write(true).open(&f).unwrap();
    file.write_all_at(b"changed", K * C + 5).unwrap();
    file.sync_all().unwrap();
    f
}

#[test]
fn garbage_goes_after_two_sweeps_and_nothing_else_does() {
    let h = support::setup_with_objects();
    let f = file_with_garbage(&h);
    let expected = fs::read(&f).unwrap();
    // An upload no commit ever named, and something not ours at all.
    let mine = vault(&h);
    let file = ino(&f);
    let node = h.runtime.block_on(mine.node(file)).unwrap();
    upload(&h, mine.remote(), &node, file, K2, &[vec![1; 10]]);
    h.store().insert("fs/not-ours", vec![1]);
    assert_eq!(h.store().keys().len(), 4);

    let core = h.gc_core();
    let mut gc = raft5fs_core::gc::Gc::default();
    let now = SystemTime::now();
    // At once, the two unreferenced objects are too new to judge.
    let s = sweep(&h, &core, &mut gc, now);
    assert!(s.swept);
    assert_eq!(
        (s.referenced, s.listed, s.foreign, s.young, s.deleted),
        (1, 4, 1, 2, 0)
    );
    // Later, they are candidates; not yet gone.
    let first = now + LATER;
    let s = sweep(&h, &core, &mut gc, first);
    assert_eq!((s.waiting, s.deleted), (2, 0));
    let s = sweep(&h, &core, &mut gc, first + WAIT - Duration::from_secs(60));
    assert_eq!((s.waiting, s.deleted), (2, 0));
    // Long enough after the first sweep to find them: gone.
    let s = sweep(&h, &core, &mut gc, first + WAIT);
    assert_eq!((s.waiting, s.deleted), (0, 2));
    assert_eq!(h.store().keys().len(), 2);
    assert!(h.store().object("fs/not-ours").is_some());
    assert_eq!(read_afresh(&h, "f"), expected);
    let s = sweep(&h, &core, &mut gc, first + WAIT * 2);
    assert_eq!(s.deleted, 0);
}

#[test]
fn what_a_snapshot_holds_stays_until_the_snapshot_goes() {
    let h = support::setup_with_objects();
    let f = h.path().join("f");
    let data = pattern(K * C + B);
    fs::write(&f, &data).unwrap();
    let file = ino(&f);
    h.snapshot("s");
    fs::remove_file(&f).unwrap();
    assert_eq!(h.store().keys().len(), 1);

    let core = h.gc_core();
    let mut gc = raft5fs_core::gc::Gc::default();
    let first = SystemTime::now() + LATER;
    for at in [first, first + WAIT, first + WAIT * 2] {
        let s = sweep(&h, &core, &mut gc, at);
        assert_eq!((s.snapshots, s.referenced, s.deleted), (1, 1, 0));
    }
    let then = vault(&h).at_snapshot("s", 1);
    assert_eq!(
        h.runtime.block_on(then.read(file, 0, data.len())).unwrap(),
        data
    );

    h.drop_snapshot("s");
    let after = first + WAIT * 3;
    assert_eq!(sweep(&h, &core, &mut gc, after).deleted, 0);
    assert_eq!(sweep(&h, &core, &mut gc, after + WAIT).deleted, 1);
    assert!(h.store().keys().is_empty());
}

#[test]
fn a_sweep_that_fails_deletes_nothing() {
    let h = support::setup_with_objects();
    file_with_garbage(&h);
    let objects = h.store().keys().len();
    // Can't list the bucket: its secret is wrong.
    let broken = h.gc_core_with(|config| config.secret_key = "wrong".into());
    let mut gc = raft5fs_core::gc::Gc::default();
    let first = SystemTime::now() + LATER;
    for at in [first, first + WAIT, first + WAIT * 2] {
        assert!(h.runtime.block_on(broken.gc_once(&mut gc, at)).is_err());
    }
    assert_eq!(h.store().keys().len(), objects);
    assert_eq!(h.store().stats().deleted, 0);

    // A working one, once the broken one's lease has run out, does.
    let core = h.gc_core();
    let mut gc = raft5fs_core::gc::Gc::default();
    let later = first + WAIT * 2 + raft5fs_core::gc::LEASE_TTL;
    assert_eq!(sweep(&h, &core, &mut gc, later).deleted, 0);
    assert_eq!(sweep(&h, &core, &mut gc, later + WAIT).deleted, 1);
}

#[test]
fn one_server_sweeps_at_a_time() {
    let h = support::setup_with_objects();
    let (a, b) = (h.gc_core(), h.gc_core());
    let (mut ga, mut gb) = (
        raft5fs_core::gc::Gc::default(),
        raft5fs_core::gc::Gc::default(),
    );
    let now = SystemTime::now();
    assert!(sweep(&h, &a, &mut ga, now).swept);
    assert!(!sweep(&h, &b, &mut gb, now).swept);
    // The holder keeps it by sweeping; the other waits it out.
    let soon = now + Duration::from_secs(60);
    assert!(sweep(&h, &a, &mut ga, soon).swept);
    assert!(!sweep(&h, &b, &mut gb, soon).swept);
    let expired = soon + raft5fs_core::gc::LEASE_TTL + Duration::from_secs(1);
    assert!(sweep(&h, &b, &mut gb, expired).swept);
    assert!(!sweep(&h, &a, &mut ga, expired).swept);
}
