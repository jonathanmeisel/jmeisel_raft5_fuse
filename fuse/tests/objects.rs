//! The servers' side of object storage: hybrid files, upload URLs, block
//! pointers and how they are checked, read and trimmed. Driven through
//! `Remote` directly -- sealing and uploading blocks by hand -- since the
//! mount's own reads and writes of blocks come later.

mod support;

use std::fs;
use std::os::unix::fs::MetadataExt;
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
