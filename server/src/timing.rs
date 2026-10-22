//! Times every request: how long it took to handle, and how much of that
//! went to the store (see `raft5fs_core::timing`). Each request runs in an
//! `rpc` span named for its method, so all core logs during the request say
//! which request they are for. The span ends with one `info` line that says
//! where the time went. If the server is told to, it also sends this to the
//! client in `raft5fs_proto::timing::HEADER`.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use raft5fs_core::timing::measure;
use raft5fs_proto::timing::{HEADER, ServerTiming};
use tonic::codegen::Service;
use tonic::codegen::http::{HeaderValue, Request, Response};
use tonic::server::NamedService;
use tracing::Instrument;

/// Wraps `S` and times every request that it answers.
#[derive(Clone)]
pub struct Timed<S> {
    inner: S,
    /// Whether responses send the timing back to the client.
    header: bool,
}

impl<S> Timed<S> {
    pub fn new(inner: S, header: bool) -> Self {
        Self { inner, header }
    }
}

impl<S: NamedService> NamedService for Timed<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Timed<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // The span name for `/raft5fs.Fs/Lookup` is `Lookup`.
        let path = request.uri().path();
        let method = path.rsplit('/').next().unwrap_or(path).to_string();
        let span = tracing::info_span!("rpc", method);
        let answer = self.inner.call(request);
        let header = self.header;
        Box::pin(
            async move {
                let start = Instant::now();
                let (answer, store) = measure(answer).await;
                let timing = ServerTiming {
                    handled: start.elapsed(),
                    store,
                };
                tracing::info!("{timing}");
                answer.map(|mut response| {
                    if header {
                        let value = HeaderValue::from_str(&timing.encode())
                            .expect("an encoded timing is a valid header value");
                        response.headers_mut().insert(HEADER, value);
                    }
                    response
                })
            }
            .instrument(span),
        )
    }
}
