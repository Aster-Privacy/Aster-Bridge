//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::future::Future;

use tokio::sync::watch;

tokio::task_local! {
    static CURRENT: ConnectionShutdown;
}

pub struct ShutdownTrigger {
    tx: watch::Sender<bool>,
}

#[derive(Clone)]
pub struct ConnectionShutdown {
    rx: watch::Receiver<bool>,
}

pub fn channel() -> (ShutdownTrigger, ConnectionShutdown) {
    let (tx, rx) = watch::channel(false);
    (ShutdownTrigger { tx }, ConnectionShutdown { rx })
}

impl ShutdownTrigger {
    pub fn close_connections(&self) {
        self.tx.send_replace(true);
    }
}

impl ConnectionShutdown {
    pub fn never() -> Self {
        let (_, rx) = watch::channel(false);
        Self { rx }
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
    async fn dropping_the_trigger_without_closing_keeps_connections_open() {
        let (trigger, shutdown) = channel();
        drop(trigger);
        let out = tokio::time::timeout(Duration::from_millis(50), shutdown.closed()).await;
        assert!(out.is_err());
    }
}
