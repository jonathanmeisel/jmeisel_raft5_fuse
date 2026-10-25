//! With `RAFT5FS_TIMING=1`, times every request to the servers and prints
//! one line on stderr for each. The line says:
//!
//! - how long the request took, from send to the last byte of the answer;
//! - if the server reports it (see `raft5fs_proto::timing`), how much of
//!   that time the server spent on the request, and how much of that went
//!   to the store.
//!
//! The rest is the network: the round trip, the bytes each way, and
//! anything queued in front of the request on either side. Each attempt
//! gets its own line, so a request that fails over shows one line for each
//! server it tried.

use std::env;
use std::fmt::Display;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;

// `std::time::Instant` panics in a browser; this is the same type natively.
use web_time::Instant;

use http_body::{Body, Frame, SizeHint};
use raft5fs_proto::timing::{HEADER, ServerTiming, ms};
use tonic::codegen::http::{Request, Response};
use tonic::codegen::{Bytes, Service};

use crate::rt::{BoxFuture, MaybeSend};

static ENABLED: LazyLock<bool> =
    LazyLock::new(|| env::var("RAFT5FS_TIMING").is_ok_and(|v| v == "1"));

/// Wraps `S`, a connection to `server`, and times every request through it.
#[derive(Clone)]
pub struct Timed<S> {
    inner: S,
    server: Arc<str>,
}

impl<S> Timed<S> {
    pub fn new(inner: S, server: &str) -> Self {
        Self {
            inner,
            server: server.into(),
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Timed<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: MaybeSend + 'static,
    S::Error: Display,
{
    type Response = Response<TimedBody<ResBody>>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // The name for `/raft5fs.Fs/Lookup` is `Lookup`.
        let path = request.uri().path();
        let method = path.rsplit('/').next().unwrap_or(path).to_string();
        let server = Arc::clone(&self.server);
        let start = Instant::now();
        let answer = self.inner.call(request);
        Box::pin(async move {
            let response = match answer.await {
                Ok(response) => response,
                Err(e) => {
                    if *ENABLED {
                        eprintln!(
                            "timing: {method} via {server}: failed after {}: {e}",
                            ms(start.elapsed())
                        );
                    }
                    return Err(e);
                }
            };
            let report = ENABLED.then(|| Report {
                method,
                server,
                start,
                first_byte: start.elapsed(),
                server_timing: response
                    .headers()
                    .get(HEADER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(ServerTiming::decode),
                bytes: 0,
            });
            Ok(response.map(|body| TimedBody {
                inner: Box::pin(body),
                report,
            }))
        })
    }
}

/// An answer's body. It reports how long the answer took after all of it
/// arrives.
pub struct TimedBody<B> {
    inner: Pin<Box<B>>,
    /// The report to print, until it is printed. `None` when timing is off.
    report: Option<Report>,
}

struct Report {
    method: String,
    server: Arc<str>,
    start: Instant,
    /// When the answer's headers arrived. The server is done by then, and
    /// the rest is the body crossing the network.
    first_byte: Duration,
    server_timing: Option<ServerTiming>,
    bytes: u64,
}

impl Report {
    fn say(self, how: &str) {
        let total = self.start.elapsed();
        let mut line = format!(
            "timing: {} via {}: {}{how} (first byte at {}, {} back)",
            self.method,
            self.server,
            ms(total),
            ms(self.first_byte),
            size(self.bytes),
        );
        match self.server_timing {
            Some(timing) => line.push_str(&format!(
                "; server {timing}; network and queueing {}",
                ms(total.saturating_sub(timing.handled))
            )),
            None => line.push_str("; the server sent no timing (RAFT5FS_TIMING=1 on it?)"),
        }
        eprintln!("{line}");
    }
}

fn size(bytes: u64) -> String {
    match bytes {
        b if b < 1 << 10 => format!("{b} B"),
        b if b < 1 << 20 => format!("{:.1} KiB", b as f64 / 1024.0),
        b => format!("{:.1} MiB", b as f64 / (1024.0 * 1024.0)),
    }
}

/// An empty body that times nothing. tonic uses this when there is no
/// answer from the server.
impl<B: Default> Default for TimedBody<B> {
    fn default() -> Self {
        Self {
            inner: Box::pin(B::default()),
            report: None,
        }
    }
}

impl<B> TimedBody<B> {
    fn finish(&mut self, how: &str) {
        if let Some(report) = self.report.take() {
            report.say(how);
        }
    }
}

impl<B: Body<Data = Bytes>> Body for TimedBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        let poll = this.inner.as_mut().poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(report), Some(data)) = (&mut this.report, frame.data_ref()) {
                    report.bytes += data.len() as u64;
                }
                // gRPC's status comes last, in the trailers. The whole
                // answer is here, whether or not anything polls for its
                // end.
                if frame.is_trailers() {
                    this.finish("");
                }
            }
            Poll::Ready(Some(Err(_))) => this.finish(", then broke off"),
            Poll::Ready(None) => this.finish(""),
            Poll::Pending => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for TimedBody<B> {
    fn drop(&mut self) {
        self.finish(", answer dropped before its end");
    }
}
