//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_CONNECTIONS_PER_PROTOCOL: usize = 256;

/// A local mail listener family. Each protocol gets its own connection pool so a
/// flood (or long-lived IMAP IDLE sessions) on one cannot starve the others.
#[derive(Clone, Copy)]
pub enum Protocol {
    Imap,
    Smtp,
    Pop3,
}

fn semaphore_for(protocol: Protocol) -> &'static Arc<Semaphore> {
    static IMAP: OnceLock<Arc<Semaphore>> = OnceLock::new();
    static SMTP: OnceLock<Arc<Semaphore>> = OnceLock::new();
    static POP3: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let cell = match protocol {
        Protocol::Imap => &IMAP,
        Protocol::Smtp => &SMTP,
        Protocol::Pop3 => &POP3,
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
