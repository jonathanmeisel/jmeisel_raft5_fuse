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
use raft5fs_indexer::embed::{Embedder, MODEL, TextModel, cache_dir};
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
    let embedder = Arc::new(Embedder(Arc::new(TextModel::new(dir))));
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
        image: None,
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
        None,
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
        let hits = view.search_with(query, Some(vector), None, 5);
        assert_eq!(
            hits.first().map(|h| h.path.as_str()),
            Some(want),
            "{query}: {hits:?}"
        );
    }
}

/// Set RAFT5FS_MODEL_DIR and RAFT5FS_CLIP_DIR as for the models' own
/// tests, and run with --ignored.
#[test]
#[ignore = "needs the models (about 360 MB)"]
fn photos_are_found_by_what_they_show_with_thumbnails() {
    use raft5fs_indexer::Native;
    use raft5fs_indexer::clip::{Clip, ImageEmbedder};
    use raft5fs_search::vector::CLIP_MODEL;
    let dir = |var: &str| std::env::var_os(var).map(PathBuf::from);
    let clip = Arc::new(ImageEmbedder(Arc::new(Clip::new(
        dir("RAFT5FS_CLIP_DIR").unwrap_or_else(raft5fs_indexer::clip::cache_dir),
    ))));
    let text = Arc::new(Embedder(Arc::new(TextModel::new(
        dir("RAFT5FS_MODEL_DIR").unwrap_or_else(cache_dir),
    ))));
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
        .block_on(vault.create_volume(OsStr::new("photos"), 0o755))
        .unwrap()
        .ino;
    let pictures: [(&str, &[u8]); 4] = [
        ("IMG_1.jpg", include_bytes!("pictures/beach.jpg")),
        ("IMG_2.jpg", include_bytes!("pictures/forest.jpg")),
        ("IMG_3.jpg", include_bytes!("pictures/stop.jpg")),
        ("IMG_4.jpg", include_bytes!("pictures/cake.jpg")),
    ];
    for (name, body) in pictures {
        let ino = rt
            .block_on(vault.create(v, OsStr::new(name), 0o644))
            .unwrap()
            .ino;
        rt.block_on(vault.write(ino, 0, body)).unwrap();
    }
    let tools = Tools {
        extract: Arc::new(Native),
        embed: Some(Arc::clone(&text) as Arc<dyn Embed>),
        image: Some(Arc::clone(&clip) as Arc<dyn raft5fs_client::indexer::ImageEmbed>),
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
    assert!(view.has_image_model(CLIP_MODEL));
    for (query, want) in [
        ("Strand am Meer", "IMG_1.jpg"),
        ("un bosque", "IMG_2.jpg"),
        ("a stop sign", "IMG_3.jpg"),
    ] {
        let q = rt
            .block_on(raft5fs_client::indexer::ImageEmbed::query(
                clip.as_ref(),
                query,
            ))
            .unwrap();
        let image = QueryVector {
            model: CLIP_MODEL,
            values: &q,
        };
        let hits = view.search_with(query, None, Some(image), 5);
        assert_eq!(
            hits.first().map(|h| h.path.as_str()),
            Some(want),
            "{query}: {hits:?}"
        );
        // Each has a thumbnail, as a JPEG.
        let thumb = hits[0].thumb.clone().expect("a thumbnail");
        let jpeg = rt
            .block_on(raft5fs_client::indexer::read_thumb(&vault, v, &thumb))
            .unwrap();
        assert_eq!(&jpeg[..2], &[0xFF, 0xD8]);
    }
}
