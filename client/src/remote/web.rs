//! The transport in a browser: gRPC-Web through `fetch`. It gives what the
//! native `Channel` gives `Remote`'s failover: a request that takes longer
//! than `REQUEST_TIMEOUT` fails, and a server that can't be reached fails
//! with `Unavailable`.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tonic::Status;
use tonic::body::Body;
use tonic::codegen::Service;
use tonic::codegen::http::{Request, Response};
use tonic_web_wasm_client::options::FetchOptions;
use tonic_web_wasm_client::{Client, Error, ResponseBody};

/// In a browser, the browser does TLS against its own roots, so there is
/// nothing to set. Giving one only says that TLS is required.
#[derive(Debug, Clone, Default)]
pub struct ClientTlsConfig;

/// gRPC-Web to one server.
#[derive(Clone)]
pub struct WebChannel(Client);

impl WebChannel {
    /// Every request to `address` fails after `timeout`. The browser stops
    /// the fetch then, and also when the request is dropped.
    pub fn new(address: &str, timeout: Duration) -> Self {
        Self(Client::new_with_options(
            address.to_string(),
            FetchOptions::new().timeout(timeout),
        ))
    }
}

/// The status for a failure below gRPC.
///
/// - A timeout reads as the native timeout does.
/// - `fetch` reports a refused connection, a failed TLS handshake and a
///   CORS refusal alike, as a `TypeError`: the server can't be reached.
fn status(e: Error) -> Status {
    match e {
        Error::TonicStatusError(status) => status,
        Error::JsError(why) if why.contains("TimedOut") => Status::cancelled("Timeout expired"),
        Error::JsError(why) => Status::unavailable(why),
        e => Status::internal(e.to_string()),
    }
}

impl Service<Request<Body>> for WebChannel {
    type Response = Response<ResponseBody>;
    type Error = Status;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Status>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Status>> {
        self.0.poll_ready(cx).map_err(status)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let answer = self.0.call(request);
        Box::pin(async move { answer.await.map_err(status) })
    }
}
