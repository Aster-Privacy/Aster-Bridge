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
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::sync::Mutex as StdMutex;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tauri::Emitter;
use zeroize::Zeroizing;

use crate::api_client::{ApiClient, MailItem, MailListQuery};
use crate::auth::session::Session;
use crate::crypto::envelope::decrypt_envelope;
use crate::db::Database;
use crate::error::BridgeError;
use crate::jmap::state::StateChange;

const POLL_INTERVAL_SECS: u64 = 30;

pub struct SyncTrigger {
    pub done: oneshot::Sender<Result<(), String>>,
}

pub type SyncTriggerTx = mpsc::Sender<SyncTrigger>;
pub type SyncTriggerRx = mpsc::Receiver<SyncTrigger>;

pub fn sync_trigger_channel() -> (SyncTriggerTx, SyncTriggerRx) {
    mpsc::channel(8)
}

static GLOBAL_SYNC_TRIGGER: OnceLock<StdMutex<Option<SyncTriggerTx>>> = OnceLock::new();
static GLOBAL_APP_HANDLE: OnceLock<StdMutex<Option<tauri::AppHandle>>> = OnceLock::new();

pub fn set_global_app_handle(handle: Option<tauri::AppHandle>) {
    let cell = GLOBAL_APP_HANDLE.get_or_init(|| StdMutex::new(None));
    if let Ok(mut guard) = cell.lock() {
        *guard = handle;
    }
}

fn emit_sync_progress(folder: &str, done: usize, total: usize) {
    let Some(cell) = GLOBAL_APP_HANDLE.get() else { return; };
    let handle_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(handle) = handle_opt else { return; };
    let _ = handle.emit("sync_progress", serde_json::json!({
        "folder": folder,
        "done": done,
        "total": total,
    }));
}

fn emit_sync_done(failed: bool) {
    let Some(cell) = GLOBAL_APP_HANDLE.get() else { return; };
    let handle_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(handle) = handle_opt else { return; };
    let _ = handle.emit("sync_done", serde_json::json!({ "failed": failed }));
}

fn emit_bridge_access_revoked() {
    let Some(cell) = GLOBAL_APP_HANDLE.get() else { return; };
    let handle_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(handle) = handle_opt else { return; };
    let _ = handle.emit("bridge_access_revoked", serde_json::Value::Null);
}

pub fn emit_session_expired() {
    let Some(cell) = GLOBAL_APP_HANDLE.get() else { return; };
    let handle_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(handle) = handle_opt else { return; };
    let _ = handle.emit("session_expired", serde_json::Value::Null);
}

async fn check_plan_access(session: &Arc<RwLock<Session>>, client: &Arc<ApiClient>) -> bool {
    let token = {
        let s = session.read().await;
        (*s.access_token).clone()
    };
    match client.get_plan_info(&token).await {
        Ok(info) => info.has_bridge_access,
        Err(BridgeError::PlanUpgradeRequired(_)) => false,
        Err(_) => true,
    }
}

pub fn set_global_sync_trigger(tx: Option<SyncTriggerTx>) {
    let cell = GLOBAL_SYNC_TRIGGER.get_or_init(|| StdMutex::new(None));
    if let Ok(mut guard) = cell.lock() {
        *guard = tx;
    }
}

pub fn try_kick_sync() {
    let Some(cell) = GLOBAL_SYNC_TRIGGER.get() else { return; };
    let tx_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(tx) = tx_opt else { return; };
    tokio::spawn(async move {
        let (done_tx, _done_rx) = oneshot::channel();
        let _ = tx.try_send(SyncTrigger { done: done_tx });
    });
}

struct FolderQuery {
    label: &'static str,
    query: MailListQuery,
}

fn build_folder_queries() -> Vec<FolderQuery> {
    vec![
        FolderQuery {
            label: "inbox",
            query: MailListQuery {
                item_type: Some("received".to_string()),
                is_trashed: None,
                is_archived: None,
                is_spam: None,
                limit: Some(100),
                cursor: None,
            },
        },
        FolderQuery {
            label: "sent",
            query: MailListQuery {
                item_type: Some("sent".to_string()),
                is_trashed: None,
                is_archived: None,
                is_spam: None,
                limit: Some(100),
                cursor: None,
            },
        },
        FolderQuery {
            label: "drafts",
            query: MailListQuery {
                item_type: Some("draft".to_string()),
                is_trashed: None,
                is_archived: None,
                is_spam: None,
                limit: Some(100),
                cursor: None,
            },
        },
        FolderQuery {
            label: "trash",
            query: MailListQuery {
                item_type: None,
                is_trashed: Some(true),
                is_archived: None,
                is_spam: None,
                limit: Some(100),
                cursor: None,
            },
        },
        FolderQuery {
            label: "spam",
            query: MailListQuery {
                item_type: None,
                is_trashed: None,
                is_archived: None,
                is_spam: Some(true),
                limit: Some(100),
                cursor: None,
            },
        },
        FolderQuery {
            label: "archive",
            query: MailListQuery {
                item_type: None,
                is_trashed: None,
                is_archived: Some(true),
                is_spam: None,
                limit: Some(100),
                cursor: None,
            },
        },
    ]
}

fn is_valid_item_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn json_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn extract_from_field(v: &serde_json::Value) -> Option<String> {
    let from = v.get("from")?;
    if let Some(s) = from.as_str() {
        return Some(s.to_string());
    }
    let email = from.get("email").and_then(|x| x.as_str()).unwrap_or("");
    let name = from.get("name").and_then(|x| x.as_str()).unwrap_or("");
    if email.is_empty() && name.is_empty() {
        None
    } else if name.is_empty() {
        Some(email.to_string())
    } else {
        Some(format!("{} <{}>", name, email))
    }
}

fn extract_recipients(v: &serde_json::Value, key: &str) -> Option<String> {
    let arr = v.get(key)?.as_array()?;
    let mut parts = Vec::new();
    for r in arr {
        if let Some(s) = r.as_str() {
            parts.push(s.to_string());
        } else {
            let email = r.get("email").and_then(|x| x.as_str()).unwrap_or("");
            let name = r.get("name").and_then(|x| x.as_str()).unwrap_or("");
            if !email.is_empty() {
                if name.is_empty() {
                    parts.push(email.to_string());
                } else {
                    parts.push(format!("{} <{}>", name, email));
                }
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn cache_mail_item(
    db: &Database,
    folder: &str,
    item: &MailItem,
    passphrase: &[u8],
    identity_key: Option<&str>,
) -> bool {
    if !is_valid_item_id(&item.id) {
        tracing::warn!("rejecting message with invalid id format");
        return false;
    }

    if db.body_cached(&item.id) {
        let _ = db.set_folder_if_changed(&item.id, folder);
        let _ = db.assign_uid_if_missing(folder, &item.id);
        return false;
    }

    if !item.envelope_nonce.is_empty() {
        match db.replay_check_and_record(&item.id, &item.envelope_nonce) {
            Ok(false) => {
                tracing::warn!("rejecting envelope nonce mismatch (replay/rollback)");
                return false;
            }
            _ => {}
        }
    }

    let plaintext_result = decrypt_envelope(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        passphrase,
        identity_key,
    );

    let plaintext = match plaintext_result {
        Ok(p) => p,
        Err(_) => {
            tracing::debug!("envelope decrypt skipped");
            return false;
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&plaintext) {
        Ok(v) => v,
        Err(_) => serde_json::Value::Null,
    };

    let is_ratchet_envelope = parsed
        .get("type")
        .and_then(|v| v.as_str())
        .map(|t| t.starts_with("double_ratchet"))
        .unwrap_or(false);

    let subject = json_str(&parsed, "subject");
    let sender = extract_from_field(&parsed);
    let recipients = extract_recipients(&parsed, "to");
    let date = json_str(&parsed, "date").or_else(|| Some(item.created_at.clone()));
    let body_html = json_str(&parsed, "body_html")
        .or_else(|| json_str(&parsed, "html_body"))
        .or_else(|| json_str(&parsed, "html"));
    let body_plain = json_str(&parsed, "body_text")
        .or_else(|| json_str(&parsed, "text_body"))
        .or_else(|| json_str(&parsed, "body"))
        .or_else(|| json_str(&parsed, "text"));
    let mut is_html = body_html.is_some();
    let mut body_text = body_html.or(body_plain);
    if is_ratchet_envelope {
        body_text = Some(
            "[This message is end-to-end encrypted with Aster's double-ratchet protocol. \
             Open it in the Aster web or mobile app to decrypt.]"
                .to_string(),
        );
        is_html = false;
    }
    const MAX_CACHED_BODY_BYTES: usize = 5 * 1024 * 1024;
    if let Some(b) = body_text.as_mut() {
        if b.len() > MAX_CACHED_BODY_BYTES {
            let mut end = MAX_CACHED_BODY_BYTES;
            while end > 0 && !b.is_char_boundary(end) {
                end -= 1;
            }
            b.truncate(end);
            b.push_str("\n[truncated]");
        }
    }
    let size = body_text.as_ref().map(|b| b.len() as i64).unwrap_or(0);
    let message_id = json_str(&parsed, "message_id").or_else(|| json_str(&parsed, "messageId"));
    let raw_headers_meta = serde_json::json!({
        "is_html": is_html,
        "message_id": message_id,
    })
    .to_string();

    let was_new = match db.upsert_cached_message(
        &item.id,
        folder,
        subject.as_deref(),
        sender.as_deref(),
        recipients.as_deref(),
        date.as_deref(),
        size,
        body_text.as_deref(),
        Some(&raw_headers_meta),
    ) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("cache upsert failed for {}: {}", item.id, e);
            return false;
        }
    };
    if let Err(e) = db.assign_uid_if_missing(folder, &item.id) {
        tracing::warn!("uid assign failed for {}: {}", item.id, e);
    }
    was_new
}

async fn run_sync_pass(
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
    db: &Arc<Database>,
    jmap_broadcaster: Option<&broadcast::Sender<StateChange>>,
) -> Result<(), String> {
    let mut any_inserted = false;
    let mut last_err: Option<String> = None;

    let (access_token, passphrase, identity_key) = {
        let s = session.read().await;
        (
            s.access_token.clone(),
            Zeroizing::new(s.vault_passphrase.clone()),
            s.identity_key.clone(),
        )
    };

    let queries = build_folder_queries();
    let total_folders = queries.len();
    for (folder_idx, folder_query) in queries.iter().enumerate() {
        emit_sync_progress(folder_query.label, folder_idx, total_folders);
        let mut cursor: Option<String> = None;
        let mut total_fetched = 0usize;
        let max_per_folder = 2000usize;
        loop {
            let mut q = folder_query.query.clone();
            q.cursor = cursor.clone();
            match client.list_mail(&access_token, &q).await {
                Ok(resp) => {
                    tracing::debug!(
                        "Synced {} page - {} items (total: {}, has_more: {})",
                        folder_query.label,
                        resp.items.len(),
                        resp.total,
                        resp.has_more
                    );
                    let mut new_ids: Vec<String> = Vec::new();
                    for item in &resp.items {
                        let was_new = cache_mail_item(
                            db,
                            folder_query.label,
                            item,
                            &passphrase,
                            identity_key.as_deref(),
                        );
                        if was_new {
                            new_ids.push(item.id.clone());
                        }
                    }
                    if !new_ids.is_empty() {
                        any_inserted = true;
                        let id_refs: Vec<&str> = new_ids.iter().map(|s| s.as_str()).collect();
                        let _ = db.jmap_record_sync_batch("Email", &id_refs);
                    }
                    total_fetched += resp.items.len();
                    let page_all_cached = !resp.items.is_empty() && new_ids.is_empty();
                    if !resp.has_more
                        || resp.next_cursor.is_none()
                        || total_fetched >= max_per_folder
                        || page_all_cached
                    {
                        break;
                    }
                    cursor = resp.next_cursor;
                }
                Err(e) => {
                    let msg = format!("failed to sync {}: {}", folder_query.label, e);
                    tracing::warn!("{}", msg);
                    last_err = Some(msg);
                    break;
                }
            }
        }
    }

    if any_inserted {
        let email_state = db.jmap_state_get("Email").unwrap_or(0);
        let mailbox_state = db.jmap_state_bump("Mailbox").unwrap_or(0);
        let thread_state = db.jmap_state_bump("Thread").unwrap_or(0);
        if let Some(tx) = jmap_broadcaster {
            let mut changed = HashMap::new();
            changed.insert("Email".to_string(), email_state.to_string());
            changed.insert("Mailbox".to_string(), mailbox_state.to_string());
            changed.insert("Thread".to_string(), thread_state.to_string());
            let _ = tx.send(StateChange { changed });
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = db.set_sync_state("last_sync_ts", &now.to_string());

    emit_sync_done(last_err.is_some());

    match last_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

const PLAN_CHECK_INTERVAL: u32 = 20;

pub async fn run_poll_loop(
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    db: Arc<Database>,
    jmap_broadcaster: Option<broadcast::Sender<StateChange>>,
    mut trigger_rx: SyncTriggerRx,
    poll_interval_secs: Option<u64>,
) {
    let interval_secs = poll_interval_secs.filter(|&v| v >= 5).unwrap_or(POLL_INTERVAL_SECS);
    let interval_dur = std::time::Duration::from_secs(interval_secs);
    let mut interval = tokio::time::interval(interval_dur);
    let mut last_tick = tokio::time::Instant::now();
    let mut sync_count: u32 = 0;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = tokio::time::Instant::now();
                let elapsed = now.duration_since(last_tick);
                last_tick = now;
                if elapsed > interval_dur * 3 {
                    tracing::info!("sync: detected sleep/wake gap ({:.0}s); running immediate sync pass", elapsed.as_secs_f64());
                }
                sync_count += 1;
                if sync_count % PLAN_CHECK_INTERVAL == 0 {
                    if !check_plan_access(&session, &client).await {
                        tracing::warn!("sync: bridge access revoked - stopping poll loop");
                        emit_bridge_access_revoked();
                        return;
                    }
                }
                let result = run_sync_pass(&session, &client, &db, jmap_broadcaster.as_ref()).await;
                if let Err(ref e) = result {
                    if e.contains("plan_upgrade_required") {
                        tracing::warn!("sync: plan_upgrade_required from server - stopping poll loop");
                        emit_bridge_access_revoked();
                        return;
                    }
                }
            }
            maybe_trigger = trigger_rx.recv() => {
                let Some(trigger) = maybe_trigger else { return; };
                last_tick = tokio::time::Instant::now();
                let result = run_sync_pass(&session, &client, &db, jmap_broadcaster.as_ref()).await;
                if let Err(ref e) = result {
                    if e.contains("plan_upgrade_required") {
                        tracing::warn!("sync: plan_upgrade_required from server - stopping poll loop");
                        emit_bridge_access_revoked();
                        let _ = trigger.done.send(Err(e.clone()));
                        return;
                    }
                }
                interval.reset();
                let _ = trigger.done.send(result);
            }
        }
    }
}
