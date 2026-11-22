//! Search by meaning end to end, with the real model: a volume indexed on
//! real servers, then searched in another language than its files.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

use raft5fs_client::indexer::{
    BuiltIn, Embed, IndexerConfig, PassKind, Tools, index_claimed, new_id, read_index,
};
use raft5fs_client::remote::Remote;
use raft5fs_client::vault::Vault;
use raft5fs_indexer::embed::{E5, Embedder, MODEL, cache_dir};
use raft5fs_search::view::{QueryVector, View};
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, credentials, fs_tls};

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

/// Set RAFT5FS_MODEL_DIR to a folder with the model's files (or one to
/// download them into) and run with --ignored.
#[test]
#[ignore = "needs the model (about 135 MB)"]
fn a_query_finds_a_file_by_meaning_in_another_language() {
    let dir = std::env::var_os("RAFT5FS_MODEL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(cache_dir);
    let embedder = Arc::new(Embedder(Arc::new(E5::new(dir))));
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let remote = rt
        .block_on(Remote::connect(
            &backend.addresses(),
            credentials(TESTER),
            Some(fs_tls()),
        ))
        .unwrap();
    let vault = Vault::new(Arc::new(remote)).unwrap();
    let v = rt
        .block_on(vault.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    for (name, body) in [
        (
            "urlaub.txt",
            "Letzten Sommer sind wir mit dem Fahrrad über Schotterstraßen durch Vermont gefahren.",
        ),
        (
            "steuer.txt",
            "Die Steuererklärung ist im April fällig; die Belege aufheben.",
        ),
        ("kuchen.txt", "Die Eier schlagen, dann das Mehl unterheben."),
    ] {
        let ino = rt
            .block_on(vault.create(v, OsStr::new(name), 0o644))
            .unwrap()
            .ino;
        rt.block_on(vault.write(ino, 0, body.as_bytes())).unwrap();
    }
    let tools = Tools {
        extract: Arc::new(BuiltIn),
        embed: Some(Arc::clone(&embedder) as Arc<dyn Embed>),
    };
    let stats = rt
        .block_on(index_claimed(
            &vault,
            v,
            new_id(),
            &IndexerConfig::default(),
            &tools,
            PassKind::Auto,
            &mut |_| {},
        ))
        .unwrap();
    assert!(stats.failed.is_empty(), "{:?}", stats.failed);
    let view = View::new(rt.block_on(read_index(&vault, v)).unwrap().unwrap().entries);
    let query = "bike routes in vermont";
    let q = rt.block_on(embedder.query(query)).unwrap();
    let hits = view.search_with(
        query,
        Some(QueryVector {
            model: MODEL,
            values: &q,
        }),
        5,
    );
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert_eq!(paths.first(), Some(&"urlaub.txt"), "{paths:?}");
    assert!(!paths.contains(&"kuchen.txt"), "{paths:?}");

    // No word in common at all: meaning alone.
    for (query, want) in [
        ("cycling holiday", "urlaub.txt"),
        ("tax deadline", "steuer.txt"),
    ] {
        let q = rt.block_on(embedder.query(query)).unwrap();
        let vector = QueryVector {
            model: MODEL,
            values: &q,
        };
        let hits = view.search_with(query, Some(vector), 5);
        assert_eq!(
            hits.first().map(|h| h.path.as_str()),
            Some(want),
            "{query}: {hits:?}"
        );
    }
}
