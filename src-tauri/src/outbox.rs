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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::api_client::ApiClient;
use crate::auth::session::Session;
use crate::db::{Database, OutboxRow};
use crate::error::BridgeError;
use crate::smtp::server::{build_send_payload, is_transient_send_error};

const TICK_SECS: u64 = 30;
const MAX_ATTEMPTS: i64 = 7;

const BACKOFF_SECS: [i64; 7] = [30, 60, 120, 300, 900, 1800, 3600];

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn ready_to_retry(row: &OutboxRow) -> bool {
    if row.attempts <= 0 {
        return true;
    }
    let idx = (row.attempts - 1).min((BACKOFF_SECS.len() as i64) - 1) as usize;
    let wait = BACKOFF_SECS[idx];
    let last = row.last_attempt_at.unwrap_or(row.queued_at);
    now_secs() >= last + wait
}

pub async fn try_send_row(
    row: &OutboxRow,
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
) -> Result<(), BridgeError> {
    let session_email = {
        let s = session.read().await;
        s.email.clone()
    };
    let from_opt = if row.envelope_from.is_empty() {
        None
    } else {
        Some(row.envelope_from.as_str())
    };
    let recipients: Vec<String> = row
        .envelope_to
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    let payload = build_send_payload(&row.raw_mime, from_opt, &recipients, &session_email)?;
    let access_token = {
        let s = session.read().await;
        s.access_token.clone()
    };
    client.send_mail(&access_token, &payload).await
}

async fn process_one(
    row: &OutboxRow,
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
    db: &Arc<Database>,
) {
    match db.outbox_mark_sending(row.id) {
        Ok(0) => {
            tracing::debug!("outbox id={} already claimed, skipping", row.id);
            return;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("outbox mark_sending failed for {}: {}", row.id, e);
            return;
        }
    }
    match try_send_row(row, session, client).await {
        Ok(()) => {
            if let Err(e) = db.outbox_mark_sent(row.id) {
                tracing::warn!("outbox mark_sent failed for {}: {}", row.id, e);
            } else {
                tracing::info!("outbox id={} sent after {} attempts", row.id, row.attempts + 1);
            }
        }
        Err(e) => {
            let err_msg = format!("{}", e);
            if !is_transient_send_error(&e) {
                tracing::warn!("outbox id={} permanent failure: {}", row.id, err_msg);
                let _ = db.outbox_mark_failed(row.id, &err_msg);
                return;
            }
            let next_attempts = row.attempts + 1;
            if next_attempts >= MAX_ATTEMPTS {
                tracing::warn!("outbox id={} exhausted retries: {}", row.id, err_msg);
                let _ = db.outbox_mark_failed(row.id, &err_msg);
            } else {
                let _ = db.outbox_bump_attempt(row.id, &err_msg);
            }
        }
    }
}

pub async fn run_outbox_loop(
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    db: Arc<Database>,
    mut trigger_rx: tokio::sync::mpsc::Receiver<i64>,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(TICK_SECS));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let rows = match db.outbox_list_pending() {
                    Ok(r) => r,
                    Err(e) => { tracing::warn!("outbox list failed: {}", e); continue; }
                };
                for row in rows {
                    if row.attempts >= MAX_ATTEMPTS {
                        continue;
                    }
                    if !ready_to_retry(&row) {
                        continue;
                    }
                    process_one(&row, &session, &client, &db).await;
                }
            }
            maybe_id = trigger_rx.recv() => {
                let Some(id) = maybe_id else { return; };
                match db.outbox_get(id) {
                    Ok(Some(row)) => {
                        if row.status == "sent" {
                            continue;
                        }
                        process_one(&row, &session, &client, &db).await;
                    }
                    Ok(None) => {
                        tracing::debug!("outbox retry_now: id {} not found", id);
                    }
                    Err(e) => {
                        tracing::warn!("outbox get failed for {}: {}", id, e);
                    }
                }
                tick.reset();
            }
        }
    }
}

pub fn outbox_trigger_channel() -> (tokio::sync::mpsc::Sender<i64>, tokio::sync::mpsc::Receiver<i64>) {
    tokio::sync::mpsc::channel(16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    fn test_db() -> (tempfile::TempDir, Arc<Database>) {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let db = Database::open_with_key(dir.path(), &key).unwrap();
        (dir, Arc::new(db))
    }

    fn row_with(attempts: i64, last_attempt_at: Option<i64>, queued_at: i64) -> OutboxRow {
        OutboxRow {
            id: 1,
            raw_mime: b"raw".to_vec(),
            envelope_from: "a@b.test".to_string(),
            envelope_to: "c@d.test".to_string(),
            queued_at,
            attempts,
            last_attempt_at,
            last_error: None,
            status: "pending".to_string(),
        }
    }

    #[test]
    fn now_secs_is_positive() {
        assert!(now_secs() > 0);
    }

    #[test]
    fn backoff_table_matches_max_attempts() {
        assert_eq!(BACKOFF_SECS.len() as i64, MAX_ATTEMPTS);
    }

    #[test]
    fn backoff_table_is_monotonic() {
        for w in BACKOFF_SECS.windows(2) {
            assert!(w[1] > w[0]);
        }
    }

    #[test]
    fn ready_to_retry_first_attempt_is_immediate() {
        let row = row_with(0, None, now_secs());
        assert!(ready_to_retry(&row));
    }

    #[test]
    fn ready_to_retry_false_within_backoff_window() {
        let row = row_with(1, Some(now_secs()), now_secs());
        assert!(!ready_to_retry(&row));
    }

    #[test]
    fn ready_to_retry_true_after_backoff_elapsed() {
        let long_ago = now_secs() - BACKOFF_SECS[0] - 5;
        let row = row_with(1, Some(long_ago), long_ago);
        assert!(ready_to_retry(&row));
    }

    #[test]
    fn ready_to_retry_uses_queued_at_when_no_last_attempt() {
        let long_ago = now_secs() - BACKOFF_SECS[0] - 5;
        let row = row_with(1, None, long_ago);
        assert!(ready_to_retry(&row));
    }

    #[test]
    fn ready_to_retry_clamps_index_for_high_attempts() {
        let last = now_secs() - BACKOFF_SECS[BACKOFF_SECS.len() - 1] - 1;
        let row = row_with(50, Some(last), last);
        assert!(ready_to_retry(&row));
        let recent = row_with(50, Some(now_secs()), now_secs());
        assert!(!ready_to_retry(&recent));
    }

    #[test]
    fn enqueue_then_get_round_trip() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"hello mime", "from@x.test", "to@x.test").unwrap();
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_eq!(row.raw_mime, b"hello mime");
        assert_eq!(row.envelope_from, "from@x.test");
        assert_eq!(row.envelope_to, "to@x.test");
        assert_eq!(row.attempts, 0);
        assert_eq!(row.status, "pending");
    }

    #[test]
    fn list_pending_orders_by_queued_at() {
        let (_dir, db) = test_db();
        let id1 = db.outbox_insert(b"first", "a@x", "b@x").unwrap();
        let id2 = db.outbox_insert(b"second", "a@x", "b@x").unwrap();
        let rows = db.outbox_list_pending().unwrap();
        assert!(rows.len() >= 2);
        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        let p1 = ids.iter().position(|&i| i == id1).unwrap();
        let p2 = ids.iter().position(|&i| i == id2).unwrap();
        assert!(p1 < p2);
    }

    #[test]
    fn mark_sending_claims_once() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"m", "a@x", "b@x").unwrap();
        let first = db.outbox_mark_sending(id).unwrap();
        assert_eq!(first, 1);
        let second = db.outbox_mark_sending(id).unwrap();
        assert_eq!(second, 0);
    }

    #[test]
    fn mark_sent_removes_from_pending() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"m", "a@x", "b@x").unwrap();
        db.outbox_mark_sending(id).unwrap();
        db.outbox_mark_sent(id).unwrap();
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_eq!(row.status, "sent");
        let pending = db.outbox_list_pending().unwrap();
        assert!(!pending.iter().any(|r| r.id == id));
    }

    #[test]
    fn bump_attempt_increments_and_records_error() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"m", "a@x", "b@x").unwrap();
        db.outbox_bump_attempt(id, "transient 503").unwrap();
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_eq!(row.attempts, 1);
        assert_eq!(row.last_error.as_deref(), Some("transient 503"));
        assert!(row.last_attempt_at.is_some());
    }

    #[test]
    fn mark_failed_records_terminal_state() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"m", "a@x", "b@x").unwrap();
        db.outbox_mark_failed(id, "permanent 401").unwrap();
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_eq!(row.last_error.as_deref(), Some("permanent 401"));
    }

    #[test]
    fn failed_row_is_reclaimable_for_retry() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"m", "a@x", "b@x").unwrap();
        db.outbox_bump_attempt(id, "503").unwrap();
        let claimed = db.outbox_mark_sending(id).unwrap();
        assert_eq!(claimed, 1);
    }

    #[test]
    fn get_missing_id_returns_none() {
        let (_dir, db) = test_db();
        assert!(db.outbox_get(99999).unwrap().is_none());
    }

    #[tokio::test]
    async fn trigger_channel_delivers_ids() {
        let (tx, mut rx) = outbox_trigger_channel();
        tx.send(42).await.unwrap();
        assert_eq!(rx.recv().await, Some(42));
    }

    #[tokio::test]
    async fn trigger_channel_closes_on_sender_drop() {
        let (tx, mut rx) = outbox_trigger_channel();
        drop(tx);
        assert_eq!(rx.recv().await, None);
    }
}
