//! The web port: gRPC-Web for the web app's origin, refused for others.

use std::sync::Arc;
use std::time::Duration;

use hyper_util::client::legacy::Client as HttpClient;
use hyper_util::rt::TokioExecutor;
use raft5fs_client::remote::Remote;
use raft5fs_core::{FsCore, accounts};
use raft5fs_crypto::password::{KdfParams, derive};
use raft5fs_proto::convert::session_to_metadata;
use raft5fs_proto::pb::fs_client::FsClient;
use raft5fs_proto::pb::{HelloRequest, ListGrantsRequest, LoginRequest, PreloginRequest};
use raft5fs_server::auth::Signer;
use raft5fs_server::{FsService, WebPort, parse_origin, serve, serve_web};
use raft5fs_testkit::{TestCluster, credentials, fs_tls, server_tls};
use tokio::net::TcpListener;
use tonic::Code;
use tonic::body::Body;
use tonic::codegen::http::Uri;
use tonic_web::{GrpcWebCall, GrpcWebClientService};

const ORIGIN: &str = "https://app.example.test";
const OTHER: &str = "https://evil.example.test";

/// The test that is the testkit's server mode; unused here, but every test
/// binary that links the testkit needs it.
#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

/// A gRPC-Web request that says it comes from `ORIGIN`, with `session` if
/// not empty.
fn request<T>(message: T, session: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert("origin", ORIGIN.parse().unwrap());
    if !session.is_empty() {
        session_to_metadata(session, request.metadata_mut());
    }
    request
}

#[test]
fn a_browser_logs_in_over_grpc_web_from_the_apps_origin_only() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_cluster, client) = TestCluster::start(&runtime);
    runtime.block_on(async {
        let core = FsCore::connect(client.clone(), 1 << 20, None)
            .await
            .unwrap();
        let signer = Signer::new(&[9; 32], Duration::from_secs(3600));
        let fs = Arc::new(FsService::new(Arc::new(core), signer, Duration::ZERO));

        let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native_address = format!("http://{}", native.local_addr().unwrap());
        let web = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_address = format!("http://{}", web.local_addr().unwrap());
        tokio::spawn(serve(Arc::clone(&fs), native, None, std::future::pending()));
        let port = WebPort {
            listener: web,
            tls: None,
            origin: parse_origin(ORIGIN).unwrap(),
        };
        tokio::spawn(serve_web(fs, port, std::future::pending()));

        // Alice enrols from a native client, on the native port.
        let code = accounts::issue_code(&client, "alice").await.unwrap();
        let mut alice = credentials("alice");
        alice.allow_plaintext = true;
        let password = alice.password.clone();
        Remote::enrol(
            std::slice::from_ref(&native_address),
            None,
            alice,
            &code,
            KdfParams::TESTING,
        )
        .await
        .unwrap();

        // Then logs in from a browser, on the web port.
        let http = HttpClient::builder(TokioExecutor::new()).build_http::<GrpcWebCall<Body>>();
        let mut web = FsClient::with_origin(
            GrpcWebClientService::new(http),
            web_address.parse::<Uri>().unwrap(),
        );
        let hello = web.hello(request(HelloRequest {}, "")).await.unwrap();
        assert_eq!(hello.get_ref().chunk_size, 1 << 20);
        assert_eq!(hello.get_ref().protocol, raft5fs_proto::PROTOCOL);
        let settings = web
            .prelogin(request(
                PreloginRequest {
                    username: "alice".into(),
                },
                "",
            ))
            .await
            .unwrap()
            .into_inner()
            .into_result()
            .unwrap();
        let params = KdfParams::decode(&settings.params).unwrap();
        let keys = derive(password.as_bytes(), "alice", &settings.salt, params).unwrap();
        let session = web
            .login(request(
                LoginRequest {
                    username: "alice".into(),
                    auth: keys.auth.to_vec(),
                },
                "",
            ))
            .await
            .unwrap()
            .into_inner()
            .into_result()
            .unwrap();
        web.list_grants(request(ListGrantsRequest::default(), &session.token))
            .await
            .unwrap();
        let refused = web
            .list_grants(request(ListGrantsRequest::default(), ""))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::Unauthenticated);

        // CORS, as a browser checks it before and after a request.
        let http = reqwest::Client::new();
        let preflight = |origin: &'static str| {
            http.request(
                reqwest::Method::OPTIONS,
                format!("{web_address}/raft5fs.Fs/Hello"),
            )
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "content-type,x-grpc-web,authorization",
            )
            .send()
        };
        let allowed = preflight(ORIGIN).await.unwrap();
        let header = |r: &reqwest::Response, name: &str| {
            r.headers()
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(
            header(&allowed, "access-control-allow-origin").as_deref(),
            Some(ORIGIN)
        );
        let methods = header(&allowed, "access-control-allow-methods").unwrap();
        assert_eq!(methods, "POST");
        let headers = header(&allowed, "access-control-allow-headers").unwrap();
        for name in ["content-type", "x-grpc-web", "authorization"] {
            assert!(headers.contains(name), "{name} in {headers}");
        }
        assert!(header(&allowed, "vary").unwrap().contains("origin"));
        let refused = preflight(OTHER).await.unwrap();
        assert_eq!(header(&refused, "access-control-allow-origin"), None);

        // The answer itself lets the app read gRPC's status.
        let answer = http
            .post(format!("{web_address}/raft5fs.Fs/Hello"))
            .header("origin", ORIGIN)
            .header("content-type", "application/grpc-web+proto")
            .header("x-grpc-web", "1")
            .body(vec![0, 0, 0, 0, 0])
            .send()
            .await
            .unwrap();
        assert!(answer.status().is_success());
        assert_eq!(
            header(&answer, "access-control-allow-origin").as_deref(),
            Some(ORIGIN)
        );
        let exposed = header(&answer, "access-control-expose-headers").unwrap();
        assert!(exposed.contains("grpc-status"), "{exposed}");
    });
}

#[test]
fn the_web_port_serves_over_tls() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_cluster, client) = TestCluster::start(&runtime);
    runtime.block_on(async {
        let core = FsCore::connect(client.clone(), 1 << 20, None)
            .await
            .unwrap();
        let signer = Signer::new(&[9; 32], Duration::from_secs(3600));
        let fs = FsService::new(Arc::new(core), signer, Duration::ZERO);
        let web = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}", web.local_addr().unwrap());
        let port = WebPort {
            listener: web,
            tls: Some(server_tls()),
            origin: parse_origin(ORIGIN).unwrap(),
        };
        tokio::spawn(serve_web(fs, port, std::future::pending()));

        // A native client's HTTP/2 over TLS, as a browser negotiates it.
        let code = accounts::issue_code(&client, "bob").await.unwrap();
        Remote::enrol(
            &[address],
            Some(fs_tls()),
            credentials("bob"),
            &code,
            KdfParams::TESTING,
        )
        .await
        .unwrap();
    });
}

#[test]
fn the_web_origin_must_be_one_a_browser_sends() {
    for good in [
        "https://app.example.com",
        "https://app.example.com:8443",
        "http://localhost:5173",
        "http://[::1]:5173",
    ] {
        assert!(parse_origin(good).is_ok(), "{good}");
    }
    for bad in [
        "app.example.com",
        "https://app.example.com/",
        "https://app.example.com/app",
        "https://App.example.com",
        "https://",
        "https://*.example.com",
        "ftp://app.example.com",
        "https://app example.com",
    ] {
        assert!(parse_origin(bad).is_err(), "{bad}");
    }
}
