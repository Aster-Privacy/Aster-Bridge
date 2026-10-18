//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

const MAX_CONNECTIONS_PER_PROTOCOL: usize = 256;
pub const PRE_AUTH_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const PRE_AUTH_DEADLINE: Duration = Duration::from_secs(300);
pub const PRE_AUTH_GRACE: Duration = Duration::from_secs(10);
pub const PRE_AUTH_FAREWELL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct PreAuthClock {
    deadline: Instant,
    signed_in: Arc<AtomicBool>,
}

impl PreAuthClock {
    pub fn start() -> Self {
        Self {
            deadline: Instant::now() + PRE_AUTH_DEADLINE,
            signed_in: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn mark_signed_in(&self) {
        self.signed_in.store(true, Ordering::SeqCst);
    }

    pub fn is_signed_in(&self) -> bool {
        self.signed_in.load(Ordering::SeqCst)
    }

    pub async fn guard<F: Future>(&self, future: F) -> Option<F::Output> {
        let expiry = async {
            tokio::time::sleep_until(self.deadline + PRE_AUTH_GRACE).await;
            if self.is_signed_in() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            biased;
            output = future => Some(output),
            _ = expiry => None,
        }
    }

    pub fn farewell_window(&self) -> Option<Duration> {
        (!self.is_signed_in()).then_some(PRE_AUTH_FAREWELL_TIMEOUT)
    }

    pub async fn bound<F: Future>(&self, future: F) -> Option<F::Output> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        tokio::time::timeout(remaining.min(PRE_AUTH_IDLE_TIMEOUT), future)
            .await
            .ok()
    }

    pub async fn bound_until_auth<F: Future>(
        &self,
        authenticated: bool,
        future: F,
    ) -> Option<F::Output> {
        if authenticated {
            Some(future.await)
        } else {
            self.bound(future).await
        }
    }
}

/// A local mail listener family. Each protocol gets its own connection pool so a
/// flood (or long-lived IMAP IDLE sessions) on one cannot starve the others.
#[derive(Clone, Copy)]
pub enum Protocol {
    Imap,
    Smtp,
    Pop3,
    Jmap,
    Dav,
}

fn semaphore_for(protocol: Protocol) -> &'static Arc<Semaphore> {
    static IMAP: OnceLock<Arc<Semaphore>> = OnceLock::new();
    static SMTP: OnceLock<Arc<Semaphore>> = OnceLock::new();
    static POP3: OnceLock<Arc<Semaphore>> = OnceLock::new();
    static JMAP: OnceLock<Arc<Semaphore>> = OnceLock::new();
    static DAV: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let cell = match protocol {
        Protocol::Imap => &IMAP,
        Protocol::Smtp => &SMTP,
        Protocol::Pop3 => &POP3,
        Protocol::Jmap => &JMAP,
        Protocol::Dav => &DAV,
    };
    cell.get_or_init(|| Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_PROTOCOL)))
}

/// Acquire a permit for one inbound connection on the given protocol.
///
/// The permit is held for the lifetime of the connection task and released on
/// drop. Returns `None` when that protocol's connection cap is reached, in which
/// case the caller should drop the connection rather than spawn a handler.
pub fn try_acquire_connection(protocol: Protocol) -> Option<OwnedSemaphorePermit> {
    semaphore_for(protocol).clone().try_acquire_owned().ok()
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::future::Future;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, DuplexStream, ReadHalf, WriteHalf};

    pub(crate) fn connect<F, Fut, T>(serve: F) -> (ReadHalf<DuplexStream>, WriteHalf<DuplexStream>)
    where
        F: FnOnce(DuplexStream) -> Fut,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (client_side, server_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(serve(server_side));
        tokio::io::split(client_side)
    }

    pub(crate) async fn read_until_closed(
        reader: &mut ReadHalf<DuplexStream>,
        limit: Duration,
    ) -> (String, bool) {
        let mut out = Vec::new();
        let closed = tokio::time::timeout(limit, reader.read_to_end(&mut out))
            .await
            .is_ok();
        (String::from_utf8_lossy(&out).into_owned(), closed)
    }

    pub(crate) async fn flood_without_reading<F, Fut, T>(
        serve: F,
        command: &'static [u8],
        limit: Duration,
    ) -> (bool, ReadHalf<DuplexStream>)
    where
        F: FnOnce(DuplexStream) -> Fut,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        use tokio::io::AsyncWriteExt;
        let (client_side, server_side) = tokio::io::duplex(1024);
        let server = tokio::spawn(serve(server_side));
        let (reader, mut writer) = tokio::io::split(client_side);
        let flood = tokio::spawn(async move {
            while writer.write_all(command).await.is_ok() {}
        });
        let finished = tokio::time::timeout(limit, server).await.is_ok();
        flood.abort();
        (finished, reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SERIALIZE: Mutex<()> = Mutex::new(());

    fn drain_all(protocol: Protocol) -> Vec<OwnedSemaphorePermit> {
        let mut held = Vec::new();
        while let Some(permit) = try_acquire_connection(protocol) {
            held.push(permit);
        }
        held
    }

    #[test]
    fn acquire_releases_capacity_on_drop() {
        let _guard = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
        let held = drain_all(Protocol::Smtp);
        assert_eq!(held.len(), MAX_CONNECTIONS_PER_PROTOCOL);
        assert!(try_acquire_connection(Protocol::Smtp).is_none());
        drop(held);
        let permit = try_acquire_connection(Protocol::Smtp);
        assert!(permit.is_some(), "capacity must return after the permit drops");
    }

    #[test]
    fn cap_is_enforced_and_recovers_after_release() {
        let held = drain_all(Protocol::Imap);
        assert_eq!(held.len(), MAX_CONNECTIONS_PER_PROTOCOL);
        assert!(
            try_acquire_connection(Protocol::Imap).is_none(),
            "acquiring beyond the cap must be rejected"
        );
        drop(held);
        assert!(
            try_acquire_connection(Protocol::Imap).is_some(),
            "permits must be reusable after release"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pre_auth_read_times_out_when_idle() {
        let clock = PreAuthClock::start();
        let started = Instant::now();
        let result = clock.bound(std::future::pending::<()>()).await;
        assert!(result.is_none());
        assert_eq!(started.elapsed(), PRE_AUTH_IDLE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn pre_auth_deadline_caps_a_slow_trickle() {
        let clock = PreAuthClock::start();
        let started = Instant::now();
        let step = PRE_AUTH_IDLE_TIMEOUT - Duration::from_secs(1);
        let mut completed = 0u32;
        while clock.bound(tokio::time::sleep(step)).await.is_some() {
            completed += 1;
        }
        assert!(completed > 0);
        assert!(started.elapsed() <= PRE_AUTH_DEADLINE);
        assert!(started.elapsed() >= PRE_AUTH_DEADLINE - step);
    }

    #[tokio::test(start_paused = true)]
    async fn authenticated_reads_are_not_bounded() {
        let clock = PreAuthClock::start();
        let wait = PRE_AUTH_DEADLINE * 4;
        let result = clock
            .bound_until_auth(true, async {
                tokio::time::sleep(wait).await;
                7u32
            })
            .await;
        assert_eq!(result, Some(7));
    }

    #[tokio::test(start_paused = true)]
    async fn guard_ends_a_stalled_session_before_sign_in() {
        let clock = PreAuthClock::start();
        let started = Instant::now();
        let result = clock.guard(std::future::pending::<()>()).await;
        assert!(result.is_none());
        assert_eq!(started.elapsed(), PRE_AUTH_DEADLINE + PRE_AUTH_GRACE);
    }

    #[tokio::test(start_paused = true)]
    async fn guard_leaves_a_signed_in_session_alone() {
        let clock = PreAuthClock::start();
        let inner = clock.clone();
        let wait = PRE_AUTH_DEADLINE * 4;
        let result = clock
            .guard(async move {
                inner.mark_signed_in();
                tokio::time::sleep(wait).await;
                9u32
            })
            .await;
        assert_eq!(result, Some(9));
    }

    #[test]
    fn farewell_is_short_before_sign_in_only() {
        let clock = PreAuthClock::start();
        assert_eq!(clock.farewell_window(), Some(PRE_AUTH_FAREWELL_TIMEOUT));
        clock.clone().mark_signed_in();
        assert_eq!(clock.farewell_window(), None);
    }

    #[test]
    fn protocols_have_independent_pools() {
        let _guard = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
        let held = drain_all(Protocol::Pop3);
        assert!(try_acquire_connection(Protocol::Pop3).is_none());
        assert!(
            try_acquire_connection(Protocol::Smtp).is_some(),
            "draining one protocol must not starve another"
        );
        drop(held);
    }
}
