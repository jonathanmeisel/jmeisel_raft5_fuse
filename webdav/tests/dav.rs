//! Tests the WebDAV server end to end: real HTTP on loopback, through
//! `dav_server` and the session, into a real store and servers.

use std::sync::Arc;

use raft5fs_client::session::{Session, SessionConfig};
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, credentials, fs_tls};
use raft5fs_webdav::{Auth, serve};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

/// A WebDAV server as `TESTER`, on a new backend. Dropping it stops the
/// server (and stores what it buffered) before the backend stops.
struct Dav {
    url: String,
    auth: Auth,
    http: reqwest::Client,
    stop: Option<oneshot::Sender<()>>,
    served: Option<JoinHandle<std::io::Result<()>>>,
    backend: Backend,
}

impl Dav {
    fn start() -> Self {
        let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
        let mut config = SessionConfig::new(backend.addresses(), credentials(TESTER));
        config.tls = Some(fs_tls());
        let auth = Auth::generate(TESTER).unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let (url, served) = backend.runtime.block_on(async {
            let session: Arc<Session> = Session::open(config).await.expect("open a session");
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://localhost:{}", listener.local_addr().unwrap().port());
            let served = tokio::spawn(serve(session, listener, auth.clone(), async {
                let _ = stopped.await;
            }));
            (url, served)
        });
        Self {
            url,
            auth,
            http: reqwest::Client::new(),
            stop: Some(stop),
            served: Some(served),
            backend,
        }
    }

    fn request(&self, method: &str, path: &str) -> RequestBuilder {
        self.http
            .request(
                Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{path}", self.url),
            )
            .basic_auth(self.auth.user(), Some(self.auth.password()))
    }

    fn send(&self, request: RequestBuilder) -> Response {
        self.backend
            .runtime
            .block_on(request.send())
            .expect("send a request")
    }

    fn status(&self, request: RequestBuilder) -> StatusCode {
        self.send(request).status()
    }

    fn body(&self, request: RequestBuilder) -> (StatusCode, Vec<u8>) {
        let response = self.send(request);
        let status = response.status();
        let body = self.backend.runtime.block_on(response.bytes()).unwrap();
        (status, body.to_vec())
    }

    fn mkcol(&self, path: &str) {
        assert_eq!(
            self.status(self.request("MKCOL", path)),
            StatusCode::CREATED,
            "MKCOL {path}"
        );
    }

    fn put(&self, path: &str, body: Vec<u8>) -> StatusCode {
        self.status(self.request("PUT", path).body(body))
    }

    fn get(&self, path: &str) -> (StatusCode, Vec<u8>) {
        self.body(self.request("GET", path))
    }

    /// The names that a depth-1 PROPFIND of `path` lists, as hrefs.
    fn listing(&self, path: &str) -> String {
        let (status, body) = self.body(self.request("PROPFIND", path).header("Depth", "1"));
        assert_eq!(status, StatusCode::MULTI_STATUS, "PROPFIND {path}");
        String::from_utf8(body).unwrap()
    }
}

impl Drop for Dav {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(served) = self.served.take() {
            let _ = self.backend.runtime.block_on(served);
        }
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn only_the_password_on_a_loopback_name_gets_in() {
    let dav = Dav::start();
    let anonymous = dav.http.request(Method::GET, format!("{}/", dav.url));
    let response = dav.send(anonymous);
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("www-authenticate"));

    let wrong = dav
        .http
        .get(format!("{}/", dav.url))
        .basic_auth(TESTER, Some("guess"));
    assert_eq!(dav.status(wrong), StatusCode::UNAUTHORIZED);

    // A page that points its own name at 127.0.0.1.
    let rebound = dav.request("PROPFIND", "/").header("Host", "evil.example");
    assert_eq!(dav.status(rebound), StatusCode::FORBIDDEN);
    let cross_origin = dav
        .request("PROPFIND", "/")
        .header("Origin", "https://evil.example");
    assert_eq!(dav.status(cross_origin), StatusCode::FORBIDDEN);
}

#[test]
fn collections_in_the_root_are_volumes() {
    let dav = Dav::start();
    dav.mkcol("/v");
    assert!(dav.listing("/").contains("/v/"));
    // The root holds volumes only.
    assert_eq!(dav.put("/f", b"x".to_vec()), StatusCode::FORBIDDEN);
    assert_eq!(
        dav.status(dav.request("DELETE", "/v")),
        StatusCode::NO_CONTENT
    );
    assert!(!dav.listing("/").contains("/v/"));
}

#[test]
fn put_and_get_a_file_of_several_batches() {
    let dav = Dav::start();
    dav.mkcol("/v");
    let data = pattern(5 * TEST_CHUNK_SIZE as usize + 321);
    assert_eq!(dav.put("/v/f", data.clone()), StatusCode::CREATED);
    assert_eq!(dav.get("/v/f"), (StatusCode::OK, data.clone()));

    let (status, part) = dav.body(
        dav.request("GET", "/v/f")
            .header("Range", "bytes=70000-70099"),
    );
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part, &data[70000..70100]);

    // Replacing the file truncates it.
    assert_eq!(dav.put("/v/f", b"short".to_vec()), StatusCode::NO_CONTENT);
    assert_eq!(dav.get("/v/f"), (StatusCode::OK, b"short".to_vec()));
}

#[test]
fn propfind_lists_names_and_sizes() {
    let dav = Dav::start();
    dav.mkcol("/v");
    dav.mkcol("/v/d");
    assert_eq!(dav.put("/v/a.txt", pattern(1234)), StatusCode::CREATED);
    let listing = dav.listing("/v/");
    assert!(listing.contains("/v/a.txt"), "{listing}");
    assert!(listing.contains("/v/d/"), "{listing}");
    assert!(listing.contains(">1234<"), "{listing}");
    assert_eq!(
        dav.status(dav.request("PROPFIND", "/v/missing").header("Depth", "0")),
        StatusCode::NOT_FOUND
    );
}

#[test]
fn move_and_copy() {
    let dav = Dav::start();
    dav.mkcol("/v");
    assert_eq!(dav.put("/v/a", b"aaa".to_vec()), StatusCode::CREATED);
    assert_eq!(dav.put("/v/b", b"bbb".to_vec()), StatusCode::CREATED);
    let destination = |path: &str| format!("{}{path}", dav.url);

    let refused = dav
        .request("MOVE", "/v/a")
        .header("Destination", destination("/v/b"))
        .header("Overwrite", "F");
    assert_eq!(dav.status(refused), StatusCode::PRECONDITION_FAILED);

    let replaced = dav
        .request("MOVE", "/v/a")
        .header("Destination", destination("/v/b"))
        .header("Overwrite", "T");
    assert_eq!(dav.status(replaced), StatusCode::NO_CONTENT);
    assert_eq!(dav.get("/v/a").0, StatusCode::NOT_FOUND);
    assert_eq!(dav.get("/v/b"), (StatusCode::OK, b"aaa".to_vec()));

    let copied = dav
        .request("COPY", "/v/b")
        .header("Destination", destination("/v/c"));
    assert_eq!(dav.status(copied), StatusCode::CREATED);
    assert_eq!(dav.get("/v/c"), (StatusCode::OK, b"aaa".to_vec()));

    // A directory copy, which `dav_server` does itself.
    dav.mkcol("/v/d");
    assert_eq!(dav.put("/v/d/x", b"xx".to_vec()), StatusCode::CREATED);
    let tree = dav
        .request("COPY", "/v/d/")
        .header("Destination", destination("/v/e/"));
    assert_eq!(dav.status(tree), StatusCode::CREATED);
    assert_eq!(dav.get("/v/e/x"), (StatusCode::OK, b"xx".to_vec()));
}

#[test]
fn delete_takes_a_collection_and_all_in_it() {
    let dav = Dav::start();
    dav.mkcol("/v");
    dav.mkcol("/v/d");
    dav.mkcol("/v/d/e");
    assert_eq!(dav.put("/v/d/e/f", b"f".to_vec()), StatusCode::CREATED);
    assert_eq!(
        dav.status(dav.request("DELETE", "/v/d/")),
        StatusCode::NO_CONTENT
    );
    assert_eq!(dav.get("/v/d/e/f").0, StatusCode::NOT_FOUND);
    assert!(!dav.listing("/v/").contains("/v/d/"));
}

#[test]
fn snapshots_are_read_only() {
    let dav = Dav::start();
    dav.mkcol("/v");
    assert_eq!(dav.put("/v/f", b"then".to_vec()), StatusCode::CREATED);
    dav.backend.snapshot("s1");
    assert_eq!(dav.put("/v/f", b"now".to_vec()), StatusCode::NO_CONTENT);

    assert_eq!(
        dav.get("/.snapshot/s1/v/f"),
        (StatusCode::OK, b"then".to_vec())
    );
    assert_eq!(
        dav.put("/.snapshot/s1/v/g", b"x".to_vec()),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        dav.status(dav.request("DELETE", "/.snapshot/s1/v/f")),
        StatusCode::FORBIDDEN
    );

    // To restore is to copy out of the snapshot.
    let restore = dav
        .request("COPY", "/.snapshot/s1/v/f")
        .header("Destination", format!("{}/v/restored", dav.url));
    assert_eq!(dav.status(restore), StatusCode::CREATED);
    assert_eq!(dav.get("/v/restored"), (StatusCode::OK, b"then".to_vec()));
}

#[test]
fn locking_is_offered() {
    let dav = Dav::start();
    let response = dav.send(dav.request("OPTIONS", "/"));
    let classes = response
        .headers()
        .get("dav")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        classes.split(',').any(|c| c.trim() == "2"),
        "DAV: {classes}"
    );
}
