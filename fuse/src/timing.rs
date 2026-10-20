//! Timing every request to the servers, with `RAFT5FS_TIMING=1`: a line
//! on stderr for each, saying how long it took from being sent to the
//! last byte of its answer, and -- from a server that says (see
//! `raft5fs_proto::timing`) -- how much of that the server spent
//! handling it, and how much of that went on the store. What neither
//! accounts for is the network: the round trip, the bytes each way, and
//! anything queued in front of the request at either end.
//!
//! Each attempt gets its own line, so a request that fails over shows
//! as one line per server it tried.

use std::env;
use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http_body::{Body, Frame, SizeHint};
use raft5fs_proto::timing::{HEADER, ServerTiming, ms};
use tonic::codegen::http::{Request, Response};
use tonic::codegen::{Bytes, Service};

static ENABLED: LazyLock<bool> =
    LazyLock::new(|| env::var("RAFT5FS_TIMING").is_ok_and(|v| v == "1"));

/// `S`, a connection to `server`, with every request through it timed.
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
    S::Future: Send + 'static,
    S::Error: Display,
{
    type Response = Response<TimedBody<ResBody>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // `/raft5fs.Fs/Lookup` is `Lookup`.
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

/// An answer's body, which says how long the answer took once it has all
/// arrived.
pub struct TimedBody<B> {
    inner: Pin<Box<B>>,
    /// What to say, until it has been said. `None` when timing is off.
    report: Option<Report>,
}

struct Report {
    method: String,
    server: Arc<str>,
    start: Instant,
    /// When the answer's headers came: the server is done by then, and
    /// what follows is the body crossing the network.
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

/// An empty body, timing nothing: what tonic answers with itself when
/// there is no answer from the server to give.
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
                // gRPC's status comes last, in the trailers: the answer is
                // all here, whether or not anything polls for its end.
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
