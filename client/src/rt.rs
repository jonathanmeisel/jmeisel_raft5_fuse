//! Background work, timers and slow computation: on Tokio natively, and on
//! the browser's event loop in WebAssembly, which has no threads and no
//! Tokio runtime. Everything in the client that would call Tokio for these
//! calls here instead.

use std::future::Future;
use std::time::Duration;

pub use futures_util::future::AbortHandle;
use futures_util::future::abortable;

/// `Send` natively. A browser runs everything on one thread, and futures
/// that wait on JavaScript aren't `Send`, so there it asks nothing.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// A boxed future, `Send` natively (see `MaybeSend`).
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = futures_util::future::BoxFuture<'a, T>;
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = futures_util::future::LocalBoxFuture<'a, T>;

/// Runs `task` in the background until it ends or its handle is aborted.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F>(task: F) -> AbortHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    let (task, handle) = abortable(task);
    tokio::spawn(async move {
        let _ = task.await;
    });
    handle
}

/// Runs `task` in the background until it ends or its handle is aborted.
#[cfg(target_arch = "wasm32")]
pub fn spawn<F>(task: F) -> AbortHandle
where
    F: Future<Output = ()> + 'static,
{
    let (task, handle) = abortable(task);
    wasm_bindgen_futures::spawn_local(async move {
        let _ = task.await;
    });
    handle
}

/// Waits for `duration`.
pub async fn sleep(duration: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(duration).await;
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::sleep(duration).await;
}

/// Runs `work`, which is slow on purpose (password stretching), away from
/// the threads that serve requests. In a browser the client already runs
/// in its own Web Worker, so it simply runs.
#[cfg(not(target_arch = "wasm32"))]
pub async fn blocking<T, F>(work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .expect("blocking work panicked")
}

/// Runs `work`, which is slow on purpose (password stretching), away from
/// the threads that serve requests. In a browser the client already runs
/// in its own Web Worker, so it simply runs.
#[cfg(target_arch = "wasm32")]
pub async fn blocking<T, F>(work: F) -> T
where
    F: FnOnce() -> T,
{
    work()
}
