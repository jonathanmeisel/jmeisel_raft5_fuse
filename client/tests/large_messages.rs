//! Tests answers larger than gRPC's default message limit, against a real
//! store and servers.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::remote::Remote;
use raft5fs_client::vault::Vault;
use raft5fs_core::dirent_prefix;
use raft5fs_testkit::{Backend, TESTER, credentials, fs_tls};

const MIB: u64 = 1 << 20;

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

fn vault(backend: &Backend) -> Vault {
    let remote = backend
        .runtime
        .block_on(Remote::connect(
            &backend.addresses(),
            credentials(TESTER),
            Some(fs_tls()),
        ))
        .unwrap();
    Vault::new(Arc::new(remote)).unwrap()
}

/// Four full chunks of 1 MiB are just over 4 MiB with their overhead. A
/// fresh client has nothing cached, so the servers must send all of them.
#[test]
fn a_cold_read_of_a_full_batch_of_inline_chunks_works() {
    let backend = Backend::start(MIB, false, true);
    let rt = &backend.runtime;
    let writer = vault(&backend);
    let v = rt
        .block_on(writer.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let f = rt
        .block_on(writer.create(v, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    let data: Vec<u8> = (0..6 * MIB as usize).map(|i| (i % 251) as u8).collect();
    rt.block_on(writer.write(f, 0, &data)).unwrap();

    let reader = vault(&backend);
    let got = rt
        .block_on(reader.read(f, 0, data.len()))
        .expect("a cold read of a full batch");
    assert!(got == data, "the bytes read aren't the bytes written");
}

/// More entries than fit in 4 MiB. They are copies of one real entry under
/// other tags, written straight to the store, because making that many files
/// through the client takes minutes. So this lists them without opening their
/// names, which don't match the copies' tags.
#[test]
fn a_listing_larger_than_the_default_message_limit_arrives_whole() {
    const ENTRIES: usize = 15_000;

    let backend = Backend::start(MIB, false, true);
    let rt = &backend.runtime;
    let v = vault(&backend);
    let dir = rt
        .block_on(v.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let long_name = "n".repeat(250);
    rt.block_on(v.create(dir, OsStr::new(&long_name), 0o644))
        .unwrap();
    let prefix = dirent_prefix(dir);
    let original = backend.keys_with_prefix(&prefix).remove(0);
    let value = backend.read_key(&original).unwrap();
    let tag_len = original.len() - prefix.len();

    let tags: Vec<usize> = (0..ENTRIES).collect();
    rt.block_on(async {
        for batch in tags.chunks(1000) {
            let (client, prefix, value) = (&backend.client, &prefix, &value);
            client
                .run_transaction(std::time::Duration::from_secs(10), |txn| async move {
                    for tag in batch {
                        let mut key = prefix.clone();
                        key.extend_from_slice(format!("{tag:0tag_len$}").as_bytes());
                        txn.write(&key, Some(value)).await?;
                    }
                    txn.commit().await
                })
                .await
                .unwrap();
        }
    });

    let listed = rt
        .block_on(v.remote().readdir(dir))
        .expect("a listing over 4 MiB");
    // `.` and `..` may be listed too.
    assert!(listed.len() > ENTRIES, "{} entries", listed.len());
}
