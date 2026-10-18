//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::future::Future;
use std::sync::Arc;

use tokio::sync::{watch, OwnedRwLockReadGuard, RwLock};
use tokio::task::JoinHandle;

tokio::task_local! {
    static CURRENT: ConnectionShutdown;
}

pub struct ShutdownTrigger {
    tx: watch::Sender<bool>,
    work: Arc<RwLock<()>>,
}

#[derive(Clone)]
pub struct ConnectionShutdown {
    rx: watch::Receiver<bool>,
    work: Arc<RwLock<()>>,
}

pub struct WorkGuard {
    _guard: OwnedRwLockReadGuard<()>,
}

pub fn channel() -> (ShutdownTrigger, ConnectionShutdown) {
    let (tx, rx) = watch::channel(false);
    let work = Arc::new(RwLock::new(()));
    (
        ShutdownTrigger { tx, work: work.clone() },
        ConnectionShutdown { rx, work },
    )
}

impl ShutdownTrigger {
    pub fn close_connections(&self) {
        self.tx.send_replace(true);
    }

    pub async fn close_and_wait(&self) {
        self.close_connections();
        drop(self.work.write().await);
    }

    pub fn is_idle(&self) -> bool {
        self.work.try_write().is_ok()
    }
}

impl ConnectionShutdown {
    pub fn never() -> Self {
        let (_, rx) = watch::channel(false);
        Self { rx, work: Arc::new(RwLock::new(())) }
    }

    pub fn hold(&self) -> Option<WorkGuard> {
        let guard = self.work.clone().try_read_owned().ok()?;
        (!self.is_closed()).then_some(WorkGuard { _guard: guard })
    }

    pub fn spawn<F>(&self, fut: F) -> JoinHandle<Option<F::Output>>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let shutdown = self.clone();
        let held = self.hold();
        tokio::spawn(async move {
            let _held = held?;
            shutdown.clone().scope(until_closed(shutdown, fut)).await
        })
    }

    pub fn is_closed(&self) -> bool {
        *self.rx.borrow()
    }

    pub async fn closed(mut self) {
        if self.rx.wait_for(|closed| *closed).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    pub async fn scope<F: Future>(self, fut: F) -> F::Output {
        CURRENT.scope(self, fut).await
    }
}

pub fn current() -> ConnectionShutdown {
    CURRENT
        .try_with(|shutdown| shutdown.clone())
        .unwrap_or_else(|_| ConnectionShutdown::never())
}

const HTTP_CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

pub fn closing_handle(shutdown: ConnectionShutdown) -> axum_server::Handle {
    let handle = axum_server::Handle::new();
    let closer = handle.clone();
    tokio::spawn(async move {
        shutdown.closed().await;
        closer.graceful_shutdown(Some(HTTP_CLOSE_GRACE));
    });
    handle
}

pub async fn spawn_blocking_held<T, F>(f: F) -> Option<Result<T, tokio::task::JoinError>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let held = current().hold()?;
    Some(
        tokio::task::spawn_blocking(move || {
            let _held = held;
            f()
        })
        .await,
    )
}

pub async fn hold_request(
    axum::extract::State(shutdown): axum::extract::State<ConnectionShutdown>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let Some(_held) = shutdown.hold() else {
        return shutting_down();
    };
    match shutdown.clone().scope(until_closed(shutdown, next.run(req))).await {
        Some(response) => response,
        None => shutting_down(),
    }
}

fn shutting_down() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::CONNECTION, "close")],
        "Aster Bridge is stopping. Try again after it restarts.",
    )
        .into_response()
}

pub async fn until_closed<F: Future>(shutdown: ConnectionShutdown, fut: F) -> Option<F::Output> {
    tokio::select! {
        biased;
        _ = shutdown.closed() => None,
        out = fut => Some(out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_connection_task_ends_when_connections_are_closed() {
        let (trigger, shutdown) = channel();
        let task = tokio::spawn(until_closed(shutdown, std::future::pending::<()>()));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        trigger.close_connections();
        let out = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn a_task_started_after_the_close_ends_at_once() {
        let (trigger, shutdown) = channel();
        trigger.close_connections();
        assert!(shutdown.is_closed());
        let out = until_closed(shutdown, std::future::pending::<()>()).await;
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn work_that_finishes_first_returns_its_output() {
        let (_trigger, shutdown) = channel();
        assert_eq!(until_closed(shutdown, async { 7 }).await, Some(7));
    }

    #[tokio::test]
    async fn a_listener_scope_hands_its_shutdown_to_the_accept_loop() {
        let (trigger, shutdown) = channel();
        let seen = shutdown.scope(async { current() }).await;
        assert!(!seen.is_closed());
        trigger.close_connections();
        assert!(seen.is_closed());
    }

    #[tokio::test]
    async fn outside_a_listener_scope_connections_never_close() {
        let shutdown = current();
        let out = tokio::time::timeout(Duration::from_millis(50), shutdown.closed()).await;
        assert!(out.is_err());
    }

    #[tokio::test]
    async fn spawned_work_is_cancelled_and_awaited_before_close_and_wait_returns() {
        let (trigger, shutdown) = channel();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = finished.clone();
        let task = shutdown.spawn(async move {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tokio::time::timeout(Duration::from_secs(5), trigger.close_and_wait()).await.unwrap();
        assert!(task.is_finished());
        assert_eq!(task.await.unwrap(), None);
        assert!(!finished.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn close_and_wait_waits_for_a_held_write_to_finish() {
        let (trigger, shutdown) = channel();
        let guard = shutdown.hold().unwrap();
        let wrote = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = wrote.clone();
        let write = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(200));
            writer.store(true, std::sync::atomic::Ordering::SeqCst);
            drop(guard);
        });
        trigger.close_and_wait().await;
        assert!(wrote.load(std::sync::atomic::Ordering::SeqCst));
        write.await.unwrap();
    }

    #[tokio::test]
    async fn blocking_work_outlives_its_caller_until_close_and_wait_returns() {
        let (trigger, shutdown) = channel();
        let wrote = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = wrote.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let caller = shutdown.spawn(spawn_blocking_held(move || {
            let _ = started_tx.send(());
            std::thread::sleep(Duration::from_millis(200));
            writer.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        started_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), trigger.close_and_wait()).await.unwrap();
        assert!(wrote.load(std::sync::atomic::Ordering::SeqCst));
        assert!(caller.await.unwrap().is_none());
    }

    #[tokio::test]
    async fn blocking_work_does_not_start_once_connections_are_closed() {
        let (trigger, shutdown) = channel();
        trigger.close_and_wait().await;
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runner = ran.clone();
        let out = shutdown
            .scope(spawn_blocking_held(move || runner.store(true, std::sync::atomic::Ordering::SeqCst)))
            .await;
        assert!(out.is_none());
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn no_work_starts_once_connections_are_closed() {
        let (trigger, shutdown) = channel();
        trigger.close_and_wait().await;
        assert!(shutdown.hold().is_none());
        let task = shutdown.spawn(async { 7 });
        assert_eq!(task.await.unwrap(), None);
    }

    #[tokio::test]
    async fn spawned_work_sees_its_shutdown_as_current() {
        let (trigger, shutdown) = channel();
        let inner = shutdown.spawn(async { current() }).await.unwrap().unwrap();
        assert!(inner.hold().is_some());
        trigger.close_connections();
        assert!(inner.is_closed());
        assert!(inner.hold().is_none());
    }

    #[tokio::test]
    async fn work_outside_a_listener_scope_can_always_hold() {
        assert!(current().hold().is_some());
    }

    #[tokio::test]
    async fn dropping_the_trigger_without_closing_keeps_connections_open() {
        let (trigger, shutdown) = channel();
        drop(trigger);
        let out = tokio::time::timeout(Duration::from_millis(50), shutdown.closed()).await;
        assert!(out.is_err());
    }

    async fn serve_router(shutdown: ConnectionShutdown, app: axum::Router) -> String {
        let app = app.layer(axum::middleware::from_fn_with_state(shutdown, hold_request));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn close_and_wait_waits_for_a_request_that_is_writing() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (trigger, shutdown) = channel();
        let wrote = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let writer = wrote.clone();
        let app = axum::Router::new().route(
            "/write",
            axum::routing::post(move || {
                let writer = writer.clone();
                let started_tx = started_tx.clone();
                async move {
                    spawn_blocking_held(move || {
                        if let Some(tx) = started_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                        std::thread::sleep(Duration::from_millis(300));
                        writer.store(true, Ordering::SeqCst);
                    })
                    .await;
                    "done"
                }
            }),
        );
        let base = serve_router(shutdown, app).await;
        let request = tokio::spawn(async move { reqwest::Client::new().post(format!("{}/write", base)).send().await });
        started_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), trigger.close_and_wait()).await.unwrap();
        assert!(wrote.load(Ordering::SeqCst));
        let _ = request.await;
    }

    #[tokio::test]
    async fn a_request_that_is_waiting_is_cancelled_by_close_and_wait() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (trigger, shutdown) = channel();
        let reached = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let seen = reached.clone();
        let app = axum::Router::new().route(
            "/wait",
            axum::routing::get(move || {
                let seen = seen.clone();
                let started_tx = started_tx.clone();
                async move {
                    if let Some(tx) = started_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    seen.store(true, Ordering::SeqCst);
                    "late"
                }
            }),
        );
        let base = serve_router(shutdown, app).await;
        let request = tokio::spawn(async move { reqwest::get(format!("{}/wait", base)).await });
        started_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), trigger.close_and_wait()).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), request).await.unwrap().unwrap().unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(!reached.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_request_after_the_close_is_refused_without_running() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (trigger, shutdown) = channel();
        let ran = Arc::new(AtomicBool::new(false));
        let seen = ran.clone();
        let app = axum::Router::new().route(
            "/write",
            axum::routing::post(move || {
                let seen = seen.clone();
                async move {
                    seen.store(true, Ordering::SeqCst);
                    "ran"
                }
            }),
        );
        let base = serve_router(shutdown, app).await;
        trigger.close_and_wait().await;
        let response = reqwest::Client::new().post(format!("{}/write", base)).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_trigger_is_idle_only_when_no_work_is_held() {
        let (trigger, shutdown) = channel();
        assert!(trigger.is_idle());
        let guard = shutdown.hold().unwrap();
        assert!(!trigger.is_idle());
        drop(guard);
        assert!(trigger.is_idle());
    }
}
