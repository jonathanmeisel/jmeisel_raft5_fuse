//! Serves the session over HTTP, on loopback only.
//!
//! A WebDAV server is another kind of mount: everything in it is decrypted
//! and used as the account. So it is for this machine's user only. Loopback
//! keeps other machines out, but not this machine's other users, or web
//! pages that its browsers open, which can also send requests to localhost.
//! So every request must also:
//!
//! - send the password that this server was started with (HTTP Basic, which
//!   Finder, davfs2, and gio all use);
//! - name a loopback host. A page can point its own name at 127.0.0.1, but
//!   it cannot make its requests say `localhost`;
//! - come from no other origin.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use dav_server::DavHandler;
use dav_server::body::Body;
use dav_server::memls::MemLs;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::graceful::GracefulShutdown;
use raft5fs_client::session::Session;
use tokio::net::TcpListener;

use crate::fs::DavFs;

/// How much of a file a GET reads at a time: big enough that a large file
/// is not one round trip per 16 KiB (`dav_server`'s default).
const READ_SIZE: usize = 1 << 20;

/// How long a shutdown waits for requests in progress.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// The realm that a 401 names.
const REALM: &str = "raft5fs";

/// Who can use the server: the account's name, and a password made when the
/// server started.
#[derive(Clone)]
pub struct Auth {
    user: String,
    password: String,
}

impl Auth {
    /// `user`, with a new random password.
    pub fn generate(user: &str) -> io::Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(io::Error::other)?;
        Ok(Self {
            user: user.to_string(),
            password: URL_SAFE_NO_PAD.encode(secret),
        })
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    /// Whether `headers` contain these credentials.
    fn admits(&self, headers: &HeaderMap) -> bool {
        let Some(given) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|v| STANDARD.decode(v.trim()).ok())
        else {
            return false;
        };
        let expected = format!("{}:{}", self.user, self.password);
        constant_time_eq(&given, expected.as_bytes())
    }
}

/// Whether `a` and `b` are equal. The time taken does not depend on which
/// byte differs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Whether `host` (a `Host` header, or an origin's host and port) is this
/// machine's loopback, by a name that no one else can give it.
fn is_loopback_host(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        // An IPv6 address, with or without a port after it.
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.split(':').next().unwrap_or(""),
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
}

/// The refusal for a request that must not reach the handler, if any.
fn refusal(auth: &Auth, headers: &HeaderMap) -> Option<Response<Body>> {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    if !host.is_some_and(is_loopback_host) {
        return Some(status(StatusCode::FORBIDDEN));
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let local = origin
            .to_str()
            .ok()
            .and_then(|o| o.split_once("://"))
            .is_some_and(|(_, host)| is_loopback_host(host));
        if !local {
            return Some(status(StatusCode::FORBIDDEN));
        }
    }
    if !auth.admits(headers) {
        let mut response = status(StatusCode::UNAUTHORIZED);
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&format!("Basic realm=\"{REALM}\", charset=\"UTF-8\""))
                .expect("a valid header"),
        );
        return Some(response);
    }
    None
}

fn status(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = code;
    response
}

/// Whether `addr` is a loopback address, the only kind that `serve` listens
/// on.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Serves `session` on `listener`, which must be bound to loopback, to
/// requests that `auth` admits, until `shutdown` completes. Then it waits a
/// short time for requests in progress, and stores everything still
/// buffered.
pub async fn serve(
    session: Arc<Session>,
    listener: TcpListener,
    auth: Auth,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let local = listener.local_addr()?;
    if !is_loopback(&local) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{local} isn't a loopback address"),
        ));
    }
    let handler = DavHandler::builder()
        .filesystem(Box::new(DavFs::new(Arc::clone(&session))))
        .locksystem(MemLs::new())
        .read_buf_size(READ_SIZE)
        .build_handler();
    let auth = Arc::new(auth);
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    eprintln!("webdav: accepting a connection: {e}");
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let handler = handler.clone();
        let auth = Arc::clone(&auth);
        let service = service_fn(move |req: Request<Incoming>| {
            let handler = handler.clone();
            let auth = Arc::clone(&auth);
            async move {
                if let Some(refused) = refusal(&auth, req.headers()) {
                    return Ok::<_, Infallible>(refused);
                }
                Ok(handler.handle(req).await)
            }
        });
        let conn = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("webdav: serving a connection: {e}");
            }
        });
    }
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        eprintln!("webdav: requests still in flight at shutdown were abandoned");
    }
    session.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn basic(user: &str, password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
    }

    #[test]
    fn loopback_hosts() {
        for host in [
            "localhost",
            "localhost:8080",
            "127.0.0.1:1",
            "[::1]",
            "[::1]:80",
        ] {
            assert!(is_loopback_host(host), "{host}");
        }
        for host in [
            "evil.example",
            "127.0.0.1.evil.example",
            "10.0.0.1",
            "[::2]",
            "",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn admits_only_the_password() {
        let auth = Auth::generate("alice").unwrap();
        let right = basic("alice", auth.password());
        assert!(
            refusal(
                &auth,
                &headers(&[(header::HOST, "localhost"), (header::AUTHORIZATION, &right)])
            )
            .is_none()
        );
        let wrong = basic("alice", "guess");
        let refused = refusal(
            &auth,
            &headers(&[(header::HOST, "localhost"), (header::AUTHORIZATION, &wrong)]),
        )
        .unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert!(refused.headers().contains_key(header::WWW_AUTHENTICATE));
        let missing = refusal(&auth, &headers(&[(header::HOST, "localhost")])).unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn refuses_other_hosts_and_origins() {
        let auth = Auth::generate("alice").unwrap();
        let right = basic("alice", auth.password());
        let foreign_host = refusal(
            &auth,
            &headers(&[
                (header::HOST, "evil.example"),
                (header::AUTHORIZATION, &right),
            ]),
        );
        assert_eq!(foreign_host.unwrap().status(), StatusCode::FORBIDDEN);
        let foreign_origin = refusal(
            &auth,
            &headers(&[
                (header::HOST, "localhost"),
                (header::ORIGIN, "https://evil.example"),
                (header::AUTHORIZATION, &right),
            ]),
        );
        assert_eq!(foreign_origin.unwrap().status(), StatusCode::FORBIDDEN);
        let local_origin = refusal(
            &auth,
            &headers(&[
                (header::HOST, "localhost"),
                (header::ORIGIN, "http://localhost:8080"),
                (header::AUTHORIZATION, &right),
            ]),
        );
        assert!(local_origin.is_none());
    }

    #[test]
    fn passwords_differ() {
        let a = Auth::generate("alice").unwrap();
        let b = Auth::generate("alice").unwrap();
        assert_ne!(a.password(), b.password());
        assert_eq!(a.password().len(), 43);
    }
}
