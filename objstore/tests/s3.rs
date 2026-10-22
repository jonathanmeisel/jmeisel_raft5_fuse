//! Tests `S3Store` and the `http` helpers against the fake store, which
//! checks signatures.

use std::time::{Duration, SystemTime};

use raft5fs_objstore::fake::FakeStore;
use raft5fs_objstore::http::{self, HttpConfig};
use raft5fs_objstore::{Error, ObjectName, S3Store};

const PREFIX: &str = "fs/";
const TTL: Duration = Duration::from_secs(600);

fn plaintext_client() -> reqwest::Client {
    http::client(&HttpConfig {
        allow_plaintext: true,
        ..HttpConfig::default()
    })
    .unwrap()
}

async fn setup() -> (FakeStore, S3Store, reqwest::Client) {
    let fake = FakeStore::start("bucket").await.unwrap();
    let client = plaintext_client();
    let store = S3Store::new(&fake.config(PREFIX), client.clone()).unwrap();
    (fake, store, client)
}

fn name(ino: u64) -> ObjectName {
    ObjectName::mint(ino, SystemTime::now())
}

#[tokio::test]
async fn upload_then_read_ranges() {
    let (fake, store, client) = setup().await;
    let n = name(7);
    let body: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    let url = store.presign_put(&n, body.len() as u64, TTL);
    http::put(&client, &url, body.clone()).await.unwrap();
    assert_eq!(fake.object(&n.key(PREFIX)).as_ref(), Some(&body));

    let get = store.presign_get(&n, TTL);
    for range in [0..1, 0..10_000, 4096..8192, 9_999..10_000] {
        let got = http::get_range(&client, &get, range.clone()).await.unwrap();
        assert_eq!(got, body[range.start as usize..range.end as usize]);
    }
    assert!(
        http::get_range(&client, &get, 5..5)
            .await
            .unwrap()
            .is_empty()
    );
    // A range past the end: the store cannot return what was asked for.
    assert!(http::get_range(&client, &get, 9_000..10_001).await.is_err());
    assert!(
        http::get_range(&client, &get, 20_000..20_001)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_object_is_written_once() {
    let (fake, store, client) = setup().await;
    let n = name(7);
    let url = store.presign_put(&n, 3, TTL);
    http::put(&client, &url, b"one".to_vec()).await.unwrap();
    assert!(matches!(
        http::put(&client, &url, b"two".to_vec()).await,
        Err(Error::AlreadyExists)
    ));
    assert_eq!(fake.object(&n.key(PREFIX)).unwrap(), b"one");
}

#[tokio::test]
async fn an_upload_must_be_the_signed_length() {
    let (fake, store, client) = setup().await;
    let n = name(7);
    let url = store.presign_put(&n, 4, TTL);
    for wrong in [b"abc".to_vec(), b"abcde".to_vec()] {
        match http::put(&client, &url, wrong).await {
            Err(Error::Status { status: 403, .. }) => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(fake.keys().is_empty());
    http::put(&client, &url, b"abcd".to_vec()).await.unwrap();
}

#[tokio::test]
async fn an_upload_without_the_signed_condition_is_refused() {
    let (fake, store, client) = setup().await;
    let n = name(7);
    let url = store.presign_put(&n, 3, TTL);
    // Do not use `http::put`, which always sends If-None-Match.
    let response = client.put(&url).body(b"abc".to_vec()).send().await.unwrap();
    assert_eq!(response.status(), 403);
    assert!(fake.keys().is_empty());
}

#[tokio::test]
async fn urls_expire() {
    let (fake, store, client) = setup().await;
    let n = name(7);
    let put = store.presign_put(&n, 3, Duration::from_secs(60));
    fake.advance(Duration::from_secs(61));
    assert!(matches!(
        http::put(&client, &put, b"abc".to_vec()).await,
        Err(Error::Status { status: 403, .. })
    ));
    // The store's clock is now 61 s ahead of ours, so a URL signed now must
    // stay valid for longer than that.
    let put = store.presign_put(&n, 3, Duration::from_secs(600));
    http::put(&client, &put, b"abc".to_vec()).await.unwrap();

    let get = store.presign_get(&n, Duration::from_secs(60));
    fake.advance(Duration::from_secs(61));
    assert!(http::get_range(&client, &get, 0..3).await.is_err());
}

#[tokio::test]
async fn a_url_is_only_good_for_its_own_object() {
    let (fake, store, client) = setup().await;
    let (a, b) = (name(7), name(7));
    let put = store.presign_put(&a, 3, TTL);
    let elsewhere = put.replace(&a.key(PREFIX), &b.key(PREFIX));
    assert!(
        http::put(&client, &elsewhere, b"abc".to_vec())
            .await
            .is_err()
    );
    assert!(fake.keys().is_empty());
    assert!(fake.stats().refused > 0);
}

#[tokio::test]
async fn other_credentials_are_refused() {
    let fake = FakeStore::start("bucket").await.unwrap();
    let mut config = fake.config(PREFIX);
    config.secret_key = "not-the-secret".into();
    let client = plaintext_client();
    let store = S3Store::new(&config, client.clone()).unwrap();
    let url = store.presign_put(&name(7), 3, TTL);
    assert!(http::put(&client, &url, b"abc".to_vec()).await.is_err());
    assert!(store.list().await.is_err());
}

#[tokio::test]
async fn listing_pages_through_the_prefix_only() {
    let (fake, store, client) = setup().await;
    fake.set_page_size(2);
    let mut names: Vec<_> = (0..5).map(|i| name(10 + i % 2)).collect();
    for n in &names {
        let url = store.presign_put(n, 1, TTL);
        http::put(&client, &url, vec![0]).await.unwrap();
    }
    fake.insert("fs/not-one-of-ours", vec![1, 2]);
    fake.insert("other/000000000000000a/x", vec![1]);

    let listed = store.list().await.unwrap();
    assert!(fake.stats().lists >= 3, "paged: {:?}", fake.stats());
    let mut keys: Vec<_> = names.iter().map(|n| n.key(PREFIX)).collect();
    keys.push("fs/not-one-of-ours".into());
    keys.sort();
    assert_eq!(
        listed.iter().map(|l| l.key.clone()).collect::<Vec<_>>(),
        keys
    );

    let mut parsed: Vec<_> = listed.iter().filter_map(|l| l.name).collect();
    parsed.sort();
    names.sort();
    assert_eq!(parsed, names);
    let foreign = listed
        .iter()
        .find(|l| l.key == "fs/not-one-of-ours")
        .unwrap();
    assert_eq!((foreign.name, foreign.size), (None, 2));
}

#[tokio::test]
async fn deleting_is_by_name_and_repeatable() {
    let (fake, store, client) = setup().await;
    let names: Vec<_> = (0..3).map(|_| name(7)).collect();
    for n in &names {
        let url = store.presign_put(n, 1, TTL);
        http::put(&client, &url, vec![0]).await.unwrap();
    }
    fake.insert("fs/not-one-of-ours", vec![1]);

    store.delete(&names[..2]).await.unwrap();
    let mut left = vec!["fs/not-one-of-ours".to_string(), names[2].key(PREFIX)];
    left.sort();
    assert_eq!(fake.keys(), left);
    // Deleting objects that are already gone still succeeds.
    store.delete(&names[..2]).await.unwrap();
    store.delete(&[]).await.unwrap();
    assert_eq!(fake.stats().deleted, 2);
}

#[tokio::test]
async fn deleting_more_than_one_batch() {
    let (fake, store, _client) = setup().await;
    let names: Vec<_> = (0..1500).map(|_| name(7)).collect();
    for n in &names {
        fake.insert(&n.key(PREFIX), vec![0]);
    }
    store.delete(&names).await.unwrap();
    assert!(fake.keys().is_empty());
}

#[tokio::test]
async fn plaintext_is_refused_unless_allowed() {
    let (_fake, store, _client) = setup().await;
    let strict = http::client(&HttpConfig::default()).unwrap();
    let url = store.presign_get(&name(7), TTL);
    assert!(matches!(
        http::get_range(&strict, &url, 0..1).await,
        Err(Error::Http(_))
    ));
}

#[test]
fn bad_settings_are_refused() {
    let client = plaintext_client();
    let good = raft5fs_objstore::S3Config {
        endpoint: "https://s3.example.com".into(),
        bucket: "b".into(),
        region: "r".into(),
        path_style: false,
        access_key: "k".into(),
        secret_key: "s".into(),
        prefix: "fs/".into(),
    };
    S3Store::new(&good, client.clone()).unwrap();
    for bad in [
        raft5fs_objstore::S3Config {
            endpoint: "not a url".into(),
            ..good.clone()
        },
        raft5fs_objstore::S3Config {
            prefix: "fs".into(),
            ..good.clone()
        },
    ] {
        assert!(matches!(
            S3Store::new(&bad, client.clone()),
            Err(Error::Config(_))
        ));
    }
    assert!(
        !format!("{good:?}").contains("\"s\""),
        "the secret isn't printed"
    );
    assert!(matches!(
        http::client(&HttpConfig {
            extra_roots_pem: Some(b"not a certificate".to_vec()),
            ..HttpConfig::default()
        }),
        Err(Error::Config(_))
    ));
}
