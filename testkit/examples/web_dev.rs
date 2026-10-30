//! A filesystem on this machine for developing and testing the web app: a
//! store, a fake object store, and a server whose web port is plain HTTP.
//!
//! usage: cargo run -p raft5fs-testkit --example web_dev --
//!            [--origin URL] [--port N] [--out DIR] [--user NAME]...
//!
//! - `--origin`: the app's origin (default `http://localhost:5173`, Vite's).
//! - `--port`: the native port; the web port is the next one, and the
//!   object store the one after (default 27160).
//! - `--out`: where to write `config.json`, the app's config for this
//!   filesystem, and `invites.json`, an invitation for each user (default
//!   `webapp/config/local`).
//! - `--user`: a user to invite (default `alice` and `bob`).
//!
//! The port after the object store's answers `GET /reissue/<user>` with a
//! new invitation for an existing user, as `raft5fs-server user add` would
//! give an administrator: for tests where someone enrolls again. Only on
//! this machine, and only here.
//!
//! It prints `ready` once everything serves, then serves until killed.
//! Nothing is kept: each run is a new, empty filesystem.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use raft5fs_core::{FsCore, accounts};
use raft5fs_objstore::fake::FakeStore;
use raft5fs_proto::invite::Invite;
use raft5fs_proto::types::Caps;
use raft5fs_server::auth::{DEFAULT_SESSION_TTL, Signer};
use raft5fs_server::{FsService, InviteSettings, WebPort, parse_origin, serve, serve_web};
use raft5fs_testkit::{TEST_BUCKET, TOKEN_KEY, TestCluster, fs_ca_der, object_settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The production default, so files cross into object storage at 2 MiB
/// (the test grid's two chunks).
const CHUNK_SIZE: u64 = 1 << 20;

fn main() {
    let mut origin = "http://localhost:5173".to_string();
    let mut port: u16 = 27160;
    let mut out = PathBuf::from("webapp/config/local");
    let mut users = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| panic!("{arg} needs a value"));
        match arg.as_str() {
            "--origin" => origin = value(),
            "--port" => port = value().parse().expect("--port takes a number"),
            "--out" => out = value().into(),
            "--user" => users.push(value()),
            _ => panic!("unknown option {arg}"),
        }
    }
    if users.is_empty() {
        users = vec!["alice".into(), "bob".into()];
    }

    let runtime = tokio::runtime::Runtime::new().expect("a Tokio runtime");
    let (_cluster, client) = TestCluster::start(&runtime);
    runtime.block_on(async {
        let objects = FakeStore::start_for(
            TEST_BUCKET,
            &format!("127.0.0.1:{}", port + 2),
            Some(&origin),
        )
        .await
        .expect("a fake object store");
        let settings = object_settings(objects.endpoint(), CHUNK_SIZE, true, |_| {});
        let core = FsCore::connect(client.clone(), CHUNK_SIZE, Some(settings))
            .await
            .expect("the filesystem opens");
        let signer = Signer::new(TOKEN_KEY.as_bytes(), DEFAULT_SESSION_TTL);
        let native_address = format!("http://127.0.0.1:{port}");
        let ca = fs_ca_der();
        let core = Arc::new(core);
        // Often, so folder sizes show soon while trying the app.
        tokio::spawn(Arc::clone(&core).run_tallies());
        tokio::spawn(Arc::clone(&core).run_measure(Duration::from_secs(20)));
        let fs = Arc::new(
            FsService::new(core, signer, Duration::ZERO).with_invites(Some(
                InviteSettings {
                    servers: vec![native_address.clone()],
                    tls_server_name: None,
                    ca: ca.clone(),
                },
            )),
        );

        let native = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("the native port");
        let web = TcpListener::bind(("127.0.0.1", port + 1))
            .await
            .expect("the web port");
        let web_address = format!("http://127.0.0.1:{}", port + 1);
        tokio::spawn(serve(Arc::clone(&fs), native, None, std::future::pending()));
        let web = WebPort {
            listener: web,
            tls: None,
            origin: parse_origin(&origin).expect("--origin"),
        };
        tokio::spawn(serve_web(fs, web, std::future::pending()));

        let mut invites = BTreeMap::new();
        for user in users {
            // Everything, so the app's invitations and public links can be
            // tried.
            let code = accounts::add(&client, &user, Caps::ADMIN | Caps::LINKS, Caps::NONE)
                .await
                .expect("an enrolment code");
            let invite = Invite {
                user: user.clone(),
                code,
                servers: vec![native_address.clone()],
                tls_server_name: None,
                ca: ca.clone(),
            };
            invites.insert(user, invite.encode());
        }
        std::fs::create_dir_all(&out).expect("--out");
        let config = format!(
            "{{\"filesystems\": [{{\n  \"name\": \"local\",\n  \"servers\": [\"{web_address}\"],\n  \
             \"objects\": \"{}\",\n  \"fsId\": \"{}\",\n  \"plaintext\": true\n}}]}}\n",
            objects.endpoint(),
            raft5fs_client::fs_id(&ca)
        );
        std::fs::write(out.join("config.json"), config).expect("config.json");
        let invites: Vec<String> = invites
            .iter()
            .map(|(user, line)| format!("  \"{user}\": \"{line}\""))
            .collect();
        std::fs::write(
            out.join("invites.json"),
            format!("{{\n{}\n}}\n", invites.join(",\n")),
        )
        .expect("invites.json");
        let admin = TcpListener::bind(("127.0.0.1", port + 3))
            .await
            .expect("the reissue port");
        tokio::spawn(reissue(admin, client.clone(), native_address.clone(), ca.clone()));
        println!("ready");
        std::future::pending::<()>().await;
    });
}

/// Answers `GET /reissue/<user>` with a new invitation for `user`, whose
/// code replaces any earlier one (see the top of this file).
async fn reissue(listener: TcpListener, client: raft5_client::Client, server: String, ca: Vec<u8>) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let mut request = vec![0; 1024];
        let n = socket.read(&mut request).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&request[..n]);
        let user = request
            .strip_prefix("GET /reissue/")
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("");
        let (status, body) = match accounts::issue_code(&client, user).await {
            Ok(code) => (
                "200 OK",
                Invite {
                    user: user.to_string(),
                    code,
                    servers: vec![server.clone()],
                    tls_server_name: None,
                    ca: ca.clone(),
                }
                .encode(),
            ),
            Err(e) => ("400 Bad Request", e.to_string()),
        };
        let reply = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(reply.as_bytes()).await;
    }
}
