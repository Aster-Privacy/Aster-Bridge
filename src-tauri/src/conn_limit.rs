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
