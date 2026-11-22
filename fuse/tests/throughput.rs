//! Measures how fast a large file moves through object storage when every
//! request to the store takes time (see `FakeStore::set_network`). It
//! prints numbers and checks only that the data comes back intact, so it
//! does not run by default:
//!
//! ```sh
//! cargo test --release -p raft5fs-fuse --test throughput -- --ignored --nocapture
//! ```
//!
//! The servers' RPCs stay on localhost, so the numbers show the cost of
//! the object store's round trips alone. Over a real network, each RPC
//! adds its own round trip as well.

mod support;

use support::pattern;

use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_objstore::fake::Network;

const MIB: u64 = 1 << 20;
/// The file's size: 16 blocks on the grid of 1 MiB chunks.
const SIZE: u64 = 64 * MIB;
/// The store's network: a round trip of 40 ms, and 10 MB/s for each
/// request.
const NETWORK: Network = Network {
    latency: Duration::from_millis(40),
    bytes_per_sec: 10_000_000,
};

/// Not a real test: the entry point that lets the harness run a filesystem
/// server as a separate process (see `support::TestServer`).
#[test]
fn server_process_mode() {
    support::serve_if_requested();
}

fn report(what: &str, took: Duration) {
    let rate = SIZE as f64 / MIB as f64 / took.as_secs_f64();
    println!("{what:<44} {:>7.2} s {rate:>7.1} MiB/s", took.as_secs_f64());
}

#[test]
#[ignore = "a benchmark: run it with --ignored --nocapture"]
fn throughput_on_a_slow_store() {
    let h = support::setup_with_objects_and_chunk_size(MIB);
    h.store().set_network(NETWORK);
    let data = pattern(SIZE);
    let path = h.path().join("big");
    println!(
        "{} MiB file, store round trip {:?}, {} MB/s per request",
        SIZE / MIB,
        NETWORK.latency,
        NETWORK.bytes_per_sec / 1_000_000
    );

    let started = Instant::now();
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();
    drop(file);
    report("write through a mount, then fsync", started.elapsed());
    let after_write = h.store().stats();

    let other = h.second_mount();
    let started = Instant::now();
    let read = fs::read(other.path.join("big")).unwrap();
    report("read through a fresh mount", started.elapsed());
    assert!(read == data, "the mount read back other bytes");

    // As the web app's service worker reads: 1 MiB at a time, in order,
    // through a session of its own.
    let mut config = SessionConfig::new(h.addresses(), support::credentials(support::TESTER));
    config.tls = Some(support::fs_tls());
    config.known_keys = Some(h.known_keys());
    let session = h.runtime.block_on(Session::open(config)).unwrap();
    let ino = fs::metadata(&path).unwrap().ino();
    let started = Instant::now();
    let mut offset = 0;
    while offset < SIZE {
        let piece = h
            .runtime
            .block_on(session.read(ino, offset, MIB as usize))
            .unwrap();
        assert!(
            piece[..] == data[offset as usize..(offset + piece.len() as u64) as usize],
            "the session read back other bytes at {offset}"
        );
        offset += piece.len() as u64;
    }
    report("read 1 MiB at a time through a session", started.elapsed());

    let stats = h.store().stats();
    println!(
        "store requests: {} PUTs to write, {} GETs to read it twice",
        after_write.puts,
        stats.gets - after_write.gets
    );
}
