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
use crate::smtp::server::{build_threaded_send_payload, is_transient_send_error, log_send_failure};

const TICK_SECS: u64 = 30;
const MAX_ATTEMPTS: i64 = 7;
const STALE_SENDING_SECS: i64 = 600;

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

fn due_for_automatic_send(row: &OutboxRow) -> bool {
    row.status != "failed" && row.attempts < MAX_ATTEMPTS && ready_to_retry(row)
}

pub async fn try_send_row(
    row: &OutboxRow,
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
    db: &Database,
) -> Result<(), BridgeError> {
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
    let (payload, access_token) = build_threaded_send_payload(
        &row.raw_mime,
        from_opt.map(|s| s.to_string()),
        recipients,
        session,
        client,
        db,
    )
    .await?;
    client.send_mail(&access_token, &payload).await
}

const NOTICE_REASON_MAX_CHARS: usize = 300;

fn failure_reason(err: &BridgeError) -> String {
    let reason = match err {
        BridgeError::PlanUpgradeRequired(msg)
        | BridgeError::MessageTooLarge(msg)
        | BridgeError::RecipientKey(msg) => msg.clone(),
        BridgeError::Network(_) | BridgeError::Io(_) => {
            "Aster Bridge couldn't reach the Aster server.".to_string()
        }
        BridgeError::Api(msg) => {
            let (status, body) = msg.split_once(": ").unwrap_or((msg.as_str(), ""));
            serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| {
                    v.get("error")
                        .or_else(|| v.get("message"))
                        .and_then(|m| m.as_str())
                        .map(|m| format!("{} ({})", m, status))
                })
                .unwrap_or_else(|| status.to_string())
        }
        other => other.to_string(),
    };
    let reason = crate::protocol_text::response_text(&reason);
    reason.trim().chars().take(NOTICE_REASON_MAX_CHARS).collect()
}

fn header_text(value: &str) -> String {
    crate::protocol_text::response_text(value).trim().to_string()
}

fn encoded_header_text(value: &str) -> String {
    use base64::Engine;
    if value.is_ascii() {
        value.to_string()
    } else {
        format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        )
    }
}

fn failed_send_notice(row: &OutboxRow, reason: &str, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    use mail_parser::MessageParser;
    let parsed = MessageParser::default().parse(&row.raw_mime);
    let subject = parsed
        .as_ref()
        .and_then(|p| p.subject())
        .map(header_text)
        .filter(|s| !s.is_empty());
    let original_id = parsed
        .as_ref()
        .and_then(|p| p.message_id())
        .map(header_text)
        .filter(|s| !s.is_empty());
    let recipients: Vec<String> = row
        .envelope_to
        .split(',')
        .map(header_text)
        .filter(|s| !s.is_empty())
        .collect();
    let mut out = String::new();
    out.push_str(&format!("Date: {}\r\n", now.to_rfc2822()));
    out.push_str("From: Aster Bridge <mailer-daemon@localhost>\r\n");
    let owner = header_text(&row.envelope_from);
    if !owner.is_empty() {
        out.push_str(&format!("To: <{}>\r\n", owner));
    }
    let notice_subject = match &subject {
        Some(s) => format!("Undelivered: {}", s),
        None => "Undelivered message".to_string(),
    };
    out.push_str(&format!("Subject: {}\r\n", encoded_header_text(&notice_subject)));
    out.push_str(&format!(
        "Message-ID: <failed-send-{}-{}@localhost>\r\n",
        row.id,
        now.timestamp_millis()
    ));
    if let Some(id) = &original_id {
        out.push_str(&format!("In-Reply-To: <{}>\r\nReferences: <{}>\r\n", id, id));
    }
    out.push_str("Auto-Submitted: auto-generated\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    out.push_str("Aster Bridge couldn't send this message.\r\n\r\n");
    if let Some(s) = &subject {
        out.push_str(&format!("Subject: {}\r\n", s));
    }
    if !recipients.is_empty() {
        out.push_str(&format!("To: {}\r\n", recipients.join(", ")));
    }
    out.push_str(&format!("Reason: {}\r\n\r\n", reason));
    out.push_str("To try again, send the message again from your mail app.\r\n");
    out.into_bytes()
}

async fn report_failed_send(
    row: &OutboxRow,
    err: &BridgeError,
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
    db: &Arc<Database>,
) {
    log_send_failure(&format!("Queued SMTP send {} failed: {}", row.id, err));
    let notice = failed_send_notice(row, &failure_reason(err), chrono::Utc::now());
    if let Err(e) = crate::imap::append::append_imported_message(
        db,
        client,
        session,
        "inbox",
        &notice,
        &crate::imap::append::AppendFlags::default(),
        None,
    )
    .await
    {
        tracing::warn!("outbox id={} failure notice not delivered: {}", row.id, e);
    }
}

pub fn sent_copy_exists(db: &Database, row: &OutboxRow) -> bool {
    use mail_parser::MessageParser;
    let Some(parsed) = MessageParser::default().parse(&row.raw_mime) else {
        return false;
    };
    let Some(subject) = parsed.subject().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    else {
        return false;
    };
    let envelope_addrs: Vec<String> = row
        .envelope_to
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let Ok(sent) = db.list_cached_message_meta("sent") else {
        return false;
    };
    let message_id = parsed
        .message_id()
        .map(crate::imap::server::normalize_message_id)
        .filter(|s| !s.is_empty());
    if let Some(message_id) = message_id {
        return sent.iter().any(|m| {
            crate::imap::server::stored_message_id(m)
                .is_some_and(|stored| stored.eq_ignore_ascii_case(&message_id))
        });
    }
    if row.attempts == 0 || envelope_addrs.is_empty() {
        return false;
    }
    sent.iter().any(|m| {
        let subject_matches = m.subject.as_deref().map(|s| s.trim()) == Some(subject.as_str());
        if !subject_matches {
            return false;
        }
        let recent_enough = m
            .date
            .as_deref()
            .and_then(crate::imap::server::parse_datetime_lenient)
            .map(|d| d.timestamp() >= row.queued_at - 60)
            .unwrap_or(false);
        if !recent_enough {
            return false;
        }
        match m.recipients.as_deref() {
            Some(r) => {
                let r_lower = r.to_lowercase();
                envelope_addrs.iter().any(|a| r_lower.contains(a.as_str()))
            }
            None => false,
        }
    })
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
    if sent_copy_exists(db, row) {
        tracing::info!(
            "outbox id={} already delivered (sent copy found), skipping resend",
            row.id
        );
        if let Err(e) = db.outbox_mark_sent(row.id) {
            tracing::warn!("outbox mark_sent failed for {}: {}", row.id, e);
        }
        return;
    }
    match try_send_row(row, session, client, db).await {
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
                crate::sync::poller::notify_send_failed();
                report_failed_send(row, &e, session, client, db).await;
                return;
            }
            let next_attempts = row.attempts + 1;
            if next_attempts >= MAX_ATTEMPTS {
                tracing::warn!("outbox id={} exhausted retries: {}", row.id, err_msg);
                let _ = db.outbox_mark_failed(row.id, &err_msg);
                crate::sync::poller::notify_send_failed();
                report_failed_send(row, &e, session, client, db).await;
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
    match db.outbox_reset_stale_sending(0) {
        Ok(n) if n > 0 => tracing::info!("outbox: reclaimed {} interrupted send(s) from previous run", n),
        Ok(_) => {}
        Err(e) => tracing::warn!("outbox: stale reclaim failed: {}", e),
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(TICK_SECS));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Ok(n) = db.outbox_reset_stale_sending(STALE_SENDING_SECS) {
                    if n > 0 {
                        tracing::warn!("outbox: reset {} stuck sending row(s)", n);
                    }
                }
                let rows = match db.outbox_list_pending() {
                    Ok(r) => r,
                    Err(e) => { tracing::warn!("outbox list failed: {}", e); continue; }
                };
                for row in rows {
                    if !due_for_automatic_send(&row) {
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
    fn failed_rows_are_not_sent_automatically() {
        let mut row = row_with(0, None, now_secs() - 3600);
        assert!(due_for_automatic_send(&row));
        row.status = "failed".to_string();
        assert!(!due_for_automatic_send(&row));
        row.attempts = MAX_ATTEMPTS - 1;
        assert!(!due_for_automatic_send(&row));
    }

    #[test]
    fn exhausted_rows_are_not_sent_automatically() {
        let row = row_with(MAX_ATTEMPTS, None, now_secs() - 86400);
        assert!(!due_for_automatic_send(&row));
    }

    #[test]
    fn failed_row_can_still_be_claimed_for_manual_retry() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"m", "a@x", "b@x").unwrap();
        db.outbox_mark_failed(id, "permanent 400").unwrap();
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_eq!(row.status, "failed");
        assert!(!due_for_automatic_send(&row));
        assert_eq!(db.outbox_mark_sending(id).unwrap(), 1);
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

    #[test]
    fn stale_sending_rows_are_reclaimable() {
        let (_dir, db) = test_db();
        let id = db.outbox_insert(b"m", "a@x", "b@x").unwrap();
        assert_eq!(db.outbox_mark_sending(id).unwrap(), 1);
        assert_eq!(db.outbox_mark_sending(id).unwrap(), 0, "sending row unclaimable");

        assert_eq!(db.outbox_reset_stale_sending(600).unwrap(), 0, "fresh row must not reset");
        assert_eq!(db.outbox_reset_stale_sending(0).unwrap(), 1, "age 0 reclaims");
        assert_eq!(db.outbox_mark_sending(id).unwrap(), 1, "claimable after reclaim");
    }

    fn seed_sent(db: &Database, id: &str, subject: &str, recipients: &str, date: &str) {
        db.upsert_cached_message(
            id,
            "sent",
            Some(subject),
            Some("me@aster.test"),
            Some(recipients),
            Some(date),
            10,
            Some("body"),
            Some("{}"),
        )
        .unwrap();
        let _ = db.assign_uid_if_missing("sent", id);
    }

    fn outbox_row_for(subject: &str, to: &str, queued_at: i64) -> OutboxRow {
        let mime = format!("From: me@aster.test\r\nTo: {}\r\nSubject: {}\r\n\r\nbody", to, subject);
        OutboxRow {
            id: 1,
            raw_mime: mime.into_bytes(),
            envelope_from: "me@aster.test".to_string(),
            envelope_to: to.to_string(),
            queued_at,
            attempts: 1,
            last_attempt_at: None,
            last_error: None,
            status: "pending".to_string(),
        }
    }

    #[test]
    fn sent_copy_exists_matches_subject_recipient_and_time() {
        let (_dir, db) = test_db();
        let queued = chrono::DateTime::parse_from_rfc3339("2026-08-01T10:00:00+00:00")
            .unwrap()
            .timestamp();
        seed_sent(&db, "sc-1", "quarterly numbers", "bob@example.com", "2026-08-01T10:00:30+00:00");
        let row = outbox_row_for("quarterly numbers", "bob@example.com", queued);
        assert!(sent_copy_exists(&db, &row));
    }

    #[test]
    fn sent_copy_exists_rejects_older_copy_and_wrong_subject() {
        let (_dir, db) = test_db();
        let queued = chrono::DateTime::parse_from_rfc3339("2026-08-01T10:00:00+00:00")
            .unwrap()
            .timestamp();
        seed_sent(&db, "sc-2", "quarterly numbers", "bob@example.com", "2026-07-01T10:00:00+00:00");
        let row = outbox_row_for("quarterly numbers", "bob@example.com", queued);
        assert!(!sent_copy_exists(&db, &row), "old copy must not dedupe");
        let row2 = outbox_row_for("different subject", "bob@example.com", queued);
        assert!(!sent_copy_exists(&db, &row2));
    }

    #[test]
    fn sent_copy_exists_rejects_wrong_recipient() {
        let (_dir, db) = test_db();
        let queued = chrono::DateTime::parse_from_rfc3339("2026-08-01T10:00:00+00:00")
            .unwrap()
            .timestamp();
        seed_sent(&db, "sc-3", "hello", "carol@example.com", "2026-08-01T10:00:30+00:00");
        let row = outbox_row_for("hello", "bob@example.com", queued);
        assert!(!sent_copy_exists(&db, &row));
    }

    #[test]
    fn sent_copy_exists_needs_the_same_message_id_when_the_message_has_one() {
        let (_dir, db) = test_db();
        let queued = chrono::DateTime::parse_from_rfc3339("2026-08-01T10:00:00+00:00")
            .unwrap()
            .timestamp();
        seed_sent(&db, "sc-4", "weekly summary", "bob@example.com", "2026-08-01T10:00:30+00:00");
        let mut row = outbox_row_for("weekly summary", "bob@example.com", queued);
        row.raw_mime = b"Message-ID: <queued@client.example>\r\nFrom: me@aster.test\r\nTo: bob@example.com\r\nSubject: weekly summary\r\n\r\nbody".to_vec();
        assert!(
            !sent_copy_exists(&db, &row),
            "another message with the same subject must not cancel the retry"
        );
        db.upsert_cached_message(
            "sc-5",
            "sent",
            Some("weekly summary"),
            Some("me@aster.test"),
            Some("bob@example.com"),
            Some("2026-08-01T10:00:40+00:00"),
            10,
            Some("body"),
            Some(r#"{"message_id":"<queued@client.example>"}"#),
        )
        .unwrap();
        assert!(sent_copy_exists(&db, &row));
    }

    #[test]
    fn sent_copy_without_recipients_never_matches() {
        let (_dir, db) = test_db();
        let queued = chrono::DateTime::parse_from_rfc3339("2026-08-01T10:00:00+00:00")
            .unwrap()
            .timestamp();
        db.upsert_cached_message(
            "sc-7",
            "sent",
            Some("status report"),
            Some("me@aster.test"),
            None,
            Some("2026-08-01T10:00:30+00:00"),
            10,
            Some("body"),
            Some("{}"),
        )
        .unwrap();
        let row = outbox_row_for("status report", "bob@example.com", queued);
        assert!(!sent_copy_exists(&db, &row));
    }

    fn stub_session() -> Arc<RwLock<Session>> {
        Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "me@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: b"pass".to_vec(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            ratchet_recovery: Default::default(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
        }))
    }

    #[test]
    fn first_attempt_without_message_id_is_never_matched_by_subject() {
        let (_dir, db) = test_db();
        let queued = chrono::DateTime::parse_from_rfc3339("2026-08-01T10:00:00+00:00")
            .unwrap()
            .timestamp();
        seed_sent(&db, "sc-6", "Backup failed", "ops@example.com", "2026-08-01T10:00:30+00:00");
        let mut row = outbox_row_for("Backup failed", "ops@example.com", queued);
        row.attempts = 0;
        assert!(!sent_copy_exists(&db, &row));
        row.attempts = 1;
        assert!(sent_copy_exists(&db, &row));
    }

    #[tokio::test]
    async fn first_outbox_attempt_without_message_id_still_sends() {
        let (_dir, db) = test_db();
        let raw = b"From: me@aster.test\r\nTo: bob@example.com\r\nSubject: invoice\r\n\r\nbody";
        let id = db.outbox_insert(raw, "me@aster.test", "bob@example.com").unwrap();
        seed_sent(&db, "sc-earlier", "invoice", "bob@example.com", &chrono::Utc::now().to_rfc3339());
        let row = db.outbox_get(id).unwrap().unwrap();
        let client = Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:1"));
        process_one(&row, &stub_session(), &client, &db).await;
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_ne!(row.status, "sent");
        assert!(row.last_error.is_some());
    }

    #[tokio::test]
    async fn first_outbox_attempt_skips_resend_when_sent_copy_exists() {
        let (_dir, db) = test_db();
        let raw = b"Message-ID: <first@client.example>\r\nFrom: me@aster.test\r\nTo: bob@example.com\r\nSubject: invoice\r\n\r\nbody";
        let id = db.outbox_insert(raw, "me@aster.test", "bob@example.com").unwrap();
        db.upsert_cached_message(
            "sc-first",
            "sent",
            Some("invoice"),
            Some("me@aster.test"),
            Some("bob@example.com"),
            Some(&chrono::Utc::now().to_rfc3339()),
            10,
            Some("body"),
            Some(r#"{"message_id":"<first@client.example>"}"#),
        )
        .unwrap();
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_eq!(row.attempts, 0);
        let client = Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:1"));
        process_one(&row, &stub_session(), &client, &db).await;
        let row = db.outbox_get(id).unwrap().unwrap();
        assert_eq!(row.status, "sent");
        assert_eq!(row.attempts, 0);
    }

    fn notice_envelope(row: &OutboxRow, reason: &str) -> serde_json::Value {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-29T12:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let notice = failed_send_notice(row, reason, now);
        let message = crate::imap::append::build_imported_message(&notice, "inbox", None, now)
            .expect("the failure notice did not parse");
        assert!(message.message_id.starts_with("failed-send-1-"));
        assert_eq!(message.item_type, "received");
        serde_json::from_str(&message.envelope_json).unwrap()
    }

    #[test]
    fn failure_notice_names_the_message_recipients_and_reason() {
        let mut row = outbox_row_for("status report", "bob@example.com, carol@example.com", 0);
        row.raw_mime = b"Message-ID: <orig@client.example>\r\nFrom: me@aster.test\r\nTo: bob@example.com\r\nSubject: status report\r\n\r\nbody".to_vec();
        let envelope = notice_envelope(&row, "Recipient not found (422 Unprocessable Entity)");
        assert_eq!(envelope["subject"], "Undelivered: status report");
        assert_eq!(envelope["to"][0], "me@aster.test");
        let body = envelope["body_text"].as_str().unwrap();
        assert!(body.contains("couldn't send this message"));
        assert!(body.contains("To: bob@example.com, carol@example.com"));
        assert!(body.contains("Reason: Recipient not found (422 Unprocessable Entity)"));
        assert!(!body.contains("body"));
        let headers = envelope["raw_headers"].as_array().unwrap();
        assert!(headers.iter().any(|h| h["name"] == "In-Reply-To"
            && h["value"].as_str().unwrap().contains("orig@client.example")));
    }

    #[test]
    fn failure_notice_encodes_a_non_ascii_subject() {
        let row = outbox_row_for("Résumé für Anna", "bob@example.com", 0);
        let notice = failed_send_notice(&row, "refused", chrono::Utc::now());
        let text = String::from_utf8(notice).unwrap();
        let header = text.lines().find(|l| l.starts_with("Subject: ")).unwrap();
        assert!(header.is_ascii());
        assert!(header.contains("=?UTF-8?B?"));
        let envelope = notice_envelope(&row, "refused");
        assert_eq!(envelope["subject"], "Undelivered: Résumé für Anna");
    }

    #[test]
    fn failure_notice_without_a_subject_still_has_one() {
        let mut row = outbox_row_for("", "bob@example.com", 0);
        row.raw_mime = b"From: me@aster.test\r\nTo: bob@example.com\r\n\r\nbody".to_vec();
        let envelope = notice_envelope(&row, "refused");
        assert_eq!(envelope["subject"], "Undelivered message");
    }

    #[test]
    fn failure_notice_cannot_be_given_extra_headers() {
        let mut row = outbox_row_for("hi", "bob@example.com\r\nBcc: eve@example.com", 0);
        row.envelope_from = "me@aster.test\r\nX-Injected: yes".to_string();
        let notice = failed_send_notice(&row, "bad\r\nX-Reason: injected", chrono::Utc::now());
        let text = String::from_utf8(notice).unwrap();
        let (headers, _) = text.split_once("\r\n\r\n").unwrap();
        assert!(!headers.lines().any(|l| l.starts_with("Bcc:") || l.starts_with("X-")));
    }

    #[test]
    fn failure_reason_reads_the_server_message() {
        let err = BridgeError::Api(
            r#"422 Unprocessable Entity: {"error":"Recipient not found"}"#.to_string(),
        );
        assert_eq!(failure_reason(&err), "Recipient not found (422 Unprocessable Entity)");
        let err = BridgeError::Api(r#"500 Internal Server Error: {"error":"#.to_string());
        assert_eq!(failure_reason(&err), "500 Internal Server Error");
        let err = BridgeError::RecipientKey("bob@example.com changed keys".to_string());
        assert_eq!(failure_reason(&err), "bob@example.com changed keys");
    }

    #[test]
    fn failure_reason_is_one_bounded_line() {
        let err = BridgeError::Smtp(format!("line one\nline two {}", "x".repeat(1000)));
        let reason = failure_reason(&err);
        assert!(!reason.contains('\n'));
        assert_eq!(reason.chars().count(), NOTICE_REASON_MAX_CHARS);
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
