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
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aster_bridge_core::account_state::AccountState;
use aster_bridge_core::events::{BridgeEvents, SyncProgress};
use serde_json::{json, Map, Value};

use crate::state::{self, SyncInfo};

const PROGRESS_INTERVAL: Duration = Duration::from_millis(500);

pub fn emit_line(event: &str, fields: Value) {
    let mut map = Map::new();
    map.insert("event".to_string(), Value::from(event));
    map.insert("at".to_string(), Value::from(state::now()));
    if let Value::Object(object) = fields {
        for (key, value) in object {
            map.insert(key, value);
        }
    }
    let line = crate::output::envelope(Value::Object(map));
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{}", line);
    let _ = handle.flush();
}

pub struct CliEvents {
    data_dir: PathBuf,
    ndjson: bool,
    last_progress: Mutex<Option<Instant>>,
}

impl CliEvents {
    pub fn new(data_dir: PathBuf, ndjson: bool) -> Arc<Self> {
        Arc::new(Self {
            data_dir,
            ndjson,
            last_progress: Mutex::new(None),
        })
    }

    fn emit(&self, event: &str, fields: Value) {
        if self.ndjson {
            emit_line(event, fields);
        }
    }

    fn persist(&self, f: impl FnOnce(&mut state::CliState)) {
        if let Err(e) = state::update(&self.data_dir, f) {
            tracing::warn!("couldn't save state: {}", e);
        }
    }
}

impl BridgeEvents for CliEvents {
    fn sync_progress(&self, progress: &SyncProgress) {
        if !self.ndjson {
            return;
        }
        let finished = progress.total > 0 && progress.done >= progress.total;
        {
            let Ok(mut last) = self.last_progress.lock() else {
                return;
            };
            if !finished && last.is_some_and(|t| t.elapsed() < PROGRESS_INTERVAL) {
                return;
            }
            *last = Some(Instant::now());
        }
        self.emit(
            "sync_progress",
            json!({
                "folder": progress.folder,
                "done": progress.done,
                "total": progress.total,
                "folder_done": progress.folder_done,
                "folder_total": progress.folder_total,
            }),
        );
    }

    fn sync_done(&self, failed: bool) {
        self.persist(|s| {
            s.last_sync = Some(SyncInfo {
                at: state::now(),
                failed,
            })
        });
        if failed {
            tracing::warn!("sync finished with errors");
        }
        self.emit("sync_done", json!({ "failed": failed }));
    }

    fn send_failed(&self) {
        tracing::warn!("a queued message failed to send");
        self.emit("send_failed", json!({}));
    }

    fn access_revoked(&self) {
        self.persist(|s| {
            let code = s.plan.as_ref().and_then(|p| p.code.clone());
            s.plan = Some(state::PlanInfo {
                code,
                has_bridge_access: false,
                checked_at: state::now(),
            });
        });
        self.emit("access_revoked", json!({}));
    }

    fn session_expired(&self) {
        tracing::warn!("the Aster Mail session expired");
        self.emit("session_expired", json!({}));
    }

    fn account_state_changed(&self, account_state: AccountState) {
        self.persist(|s| s.account_state = account_state);
        self.emit(
            "account_state_changed",
            json!({ "account_state": account_state.as_str() }),
        );
    }
}

pub struct SinkGuard;

impl SinkGuard {
    pub fn install(events: Arc<CliEvents>) -> Self {
        aster_bridge_core::events::set_event_sink(Some(events));
        SinkGuard
    }
}

impl Drop for SinkGuard {
    fn drop(&mut self) {
        aster_bridge_core::events::set_event_sink(None);
    }
}
