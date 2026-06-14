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
