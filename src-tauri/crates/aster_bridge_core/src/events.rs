//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::sync::{Arc, Mutex, OnceLock};

use crate::imap::append::ImportProgress;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncProgress {
    pub folder: String,
    pub done: usize,
    pub total: usize,
    pub folder_done: usize,
    pub folder_total: usize,
}

pub trait BridgeEvents: Send + Sync {
    fn sync_progress(&self, _progress: &SyncProgress) {}
    fn sync_done(&self, _failed: bool) {}
    fn import_progress(&self, _progress: &ImportProgress) {}
    fn send_failed(&self) {}
    fn access_revoked(&self) {}
    fn session_expired(&self) {}
    fn state_changed(&self) {}
    fn account_state_changed(&self, _state: crate::account_state::AccountState) {}
}

static EVENT_SINK: OnceLock<Mutex<Option<Arc<dyn BridgeEvents>>>> = OnceLock::new();

pub fn set_event_sink(sink: Option<Arc<dyn BridgeEvents>>) {
    let cell = EVENT_SINK.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = cell.lock() {
        *guard = sink;
    }
}

pub fn emit(f: impl FnOnce(&dyn BridgeEvents)) {
    let Some(cell) = EVENT_SINK.get() else {
        return;
    };
    let sink = cell.lock().ok().and_then(|g| g.clone());
    if let Some(sink) = sink {
        f(sink.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSink {
        count: AtomicUsize,
    }

    impl BridgeEvents for CountingSink {
        fn send_failed(&self) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn emit_reaches_installed_sink_and_stops_after_removal() {
        let sink = Arc::new(CountingSink {
            count: AtomicUsize::new(0),
        });
        set_event_sink(Some(sink.clone()));
        emit(|s| s.send_failed());
        set_event_sink(None);
        emit(|s| s.send_failed());
        assert_eq!(sink.count.load(Ordering::SeqCst), 1);
    }
}
