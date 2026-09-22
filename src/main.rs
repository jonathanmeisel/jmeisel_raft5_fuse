use std::env;

use fuser::{Config, MountOption};
use jmeisel_raft5_fuse::filesystem::{
    DEFAULT_CHUNK_SIZE, DEFAULT_READ_CACHE_BYTES, Raft5Fs, validate_chunk_size,
};
use raft5_client::Client;
use tokio::runtime::Runtime;

const USAGE: &str = "\
usage: jmeisel_raft5_fuse [--chunk-size <SIZE>] [--read-cache-size <SIZE>]
                          [--no-write-buffer] <mountpoint> <kv-seed-address>...

  --chunk-size <SIZE>  size of each stored file chunk, as a byte count or
                       with a K/M suffix (default 1M). Only applies when
                       creating a new filesystem: an existing one keeps
                       the size it was created with, since chunk
                       boundaries are baked into its keys.
  --read-cache-size <SIZE>
                       memory for caching recently read chunks, same size
                       syntax (default 64M, 0 disables).
  --no-write-buffer    store every write immediately instead of buffering
                       small sequential writes until a chunk fills, the
                       file is closed, or fsync is called.";

fn usage(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(1);
}

fn parse_size(s: &str) -> Result<u64, String> {
    let (digits, unit) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1024),
        Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    digits
        .parse::<u64>()
        .map_err(|_| format!("not a size: {s}"))?
        .checked_mul(unit)
        .ok_or_else(|| format!("size too large: {s}"))
}

fn main() {
    let mut chunk_size = DEFAULT_CHUNK_SIZE;
    let mut read_cache_bytes = DEFAULT_READ_CACHE_BYTES;
    let mut write_buffering = true;
    let mut positional = Vec::new();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--chunk-size" {
            let value = args
                .next()
                .unwrap_or_else(|| usage("--chunk-size needs a value"));
            chunk_size = parse_size(&value).unwrap_or_else(|why| usage(&why));
        } else if arg == "--read-cache-size" {
            let value = args
                .next()
                .unwrap_or_else(|| usage("--read-cache-size needs a value"));
            read_cache_bytes = parse_size(&value)
                .unwrap_or_else(|why| usage(&why))
                .try_into()
                .unwrap_or_else(|_| usage("--read-cache-size is too large"));
        } else if arg == "--no-write-buffer" {
            write_buffering = false;
        } else {
            positional.push(arg);
        }
    }

    if positional.len() < 2 {
        usage("a mountpoint and at least one seed address are required");
    }
    if let Err(why) = validate_chunk_size(chunk_size) {
        usage(&why);
    }
    let mountpoint = &positional[0];
    let seeds = &positional[1..];

    let runtime = Runtime::new().expect("failed to start tokio runtime");
    let client = runtime
        .block_on(async { Client::new(seeds) })
        .expect("failed to create raft5 client");

    let fs = Raft5Fs::new(client, runtime.handle().clone(), chunk_size)
        .with_read_cache_bytes(read_cache_bytes)
        .with_write_buffering(write_buffering);

    let mut options = Config::default();
    options.mount_options = vec![
        MountOption::FSName("raft5fs".to_string()),
        MountOption::DefaultPermissions,
        MountOption::CUSTOM("allow_other".to_string()),
    ];
    // Writes now commit synchronously, so without this, one file's slow
    // commit would stall every other fuse request on the mount --
    // `fuser` dispatches from a single thread unless told otherwise.
    options.n_threads = Some(8);

    fuser::mount(fs, mountpoint, &options).expect("failed to mount filesystem");
}
