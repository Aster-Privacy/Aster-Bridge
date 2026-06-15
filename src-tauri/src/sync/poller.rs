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

    let is_ratchet_envelope = crate::crypto::ratchet::find_ratchet_object(&parsed).is_some();

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

fn looks_like_html(s: &str) -> bool {
    let trimmed = s.trim_start();
    trimmed.starts_with('<') || (s.contains('<') && s.contains("</"))
}

async fn try_decrypt_internal_mail(
    item: &MailItem,
    our_email: &str,
    passphrase: &[u8],
    identity_key: Option<&str>,
    ratchet_keys: &[crate::crypto::ratchet::RatchetReceiverKeys],
    sync_key: Option<&[u8; 32]>,
    client: &ApiClient,
    access_token: &str,
) -> Option<String> {
    if ratchet_keys.is_empty() {
        return None;
    }

    let plaintext_env = decrypt_envelope(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        passphrase,
        identity_key,
    )
    .ok()?;

    let parsed: serde_json::Value = serde_json::from_str(&plaintext_env).ok()?;
    let ratchet_obj = crate::crypto::ratchet::find_ratchet_object(&parsed)?;
    let mut msg = crate::crypto::ratchet::parse_recipient_message(&ratchet_obj, our_email)?;

    if let Some(key_id) = msg.pq_key_id {
        let sk = sync_key?;
        let resp = client.get_pq_secret(access_token, key_id).await.ok()?;
        let secret =
            crate::crypto::ratchet::decrypt_pq_secret(sk, &resp.encrypted_secret, &resp.secret_nonce)
                .ok()?;
        msg.pq_secret = Some(secret);
    }

    crate::crypto::ratchet::decrypt_with_key_sets(ratchet_keys, &msg)
}

async fn run_sync_pass(
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
    db: &Arc<Database>,
    jmap_broadcaster: Option<&broadcast::Sender<StateChange>>,
) -> Result<(), String> {
    let mut any_inserted = false;
    let mut last_err: Option<String> = None;

    let (access_token, passphrase, identity_key, our_email, ratchet_keys) = {
        let s = session.read().await;
        (
            s.access_token.clone(),
            Zeroizing::new(s.vault_passphrase.clone()),
            s.identity_key.clone(),
            s.email.clone(),
            s.ratchet_keys.clone(),
        )
    };
    let sync_key = crate::crypto::ratchet::derive_sync_key(&passphrase).ok();

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
                            if let Some(plaintext) = try_decrypt_internal_mail(
                                item,
                                &our_email,
                                &passphrase,
                                identity_key.as_deref(),
                                &ratchet_keys,
                                sync_key.as_ref(),
                                client,
                                &access_token,
                            )
                            .await
                            {
                                let meta = serde_json::json!({
                                    "is_html": looks_like_html(&plaintext),
                                    "message_id": serde_json::Value::Null,
                                })
                                .to_string();
                                let _ = db.update_cached_body(&item.id, &plaintext, Some(&meta));
                            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    fn temp_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        (dir, db)
    }

    fn envelope_b64(json: &serde_json::Value) -> String {
        STANDARD.encode(json.to_string().as_bytes())
    }

    fn item_with_envelope(id: &str, json: &serde_json::Value) -> MailItem {
        MailItem {
            id: id.to_string(),
            item_type: "received".to_string(),
            encrypted_envelope: envelope_b64(json),
            envelope_nonce: String::new(),
            ephemeral_key: None,
            ephemeral_pq_key: None,
            sender_sealed: None,
            folder_token: "tok".to_string(),
            is_external: false,
            thread_token: None,
            thread_message_count: None,
            created_at: "2026-06-14T00:00:00Z".to_string(),
            encrypted_metadata: None,
            metadata_nonce: None,
            metadata_version: None,
            scheduled_at: None,
            send_status: None,
            message_ts: None,
            snoozed_until: None,
            expires_at: None,
            expiry_type: None,
            is_spam: None,
        }
    }

    #[test]
    fn is_valid_item_id_accepts_safe_ids() {
        assert!(is_valid_item_id("abc-123_DEF"));
        assert!(is_valid_item_id("a"));
        assert!(is_valid_item_id(&"x".repeat(128)));
    }

    #[test]
    fn is_valid_item_id_rejects_bad_ids() {
        assert!(!is_valid_item_id(""));
        assert!(!is_valid_item_id(&"x".repeat(129)));
        assert!(!is_valid_item_id("has space"));
        assert!(!is_valid_item_id("has/slash"));
        assert!(!is_valid_item_id("semi;colon"));
        assert!(!is_valid_item_id("dot.dot"));
    }

    #[test]
    fn json_str_extracts_string_fields_only() {
        let v = serde_json::json!({"a": "hello", "b": 5, "c": null});
        assert_eq!(json_str(&v, "a"), Some("hello".to_string()));
        assert_eq!(json_str(&v, "b"), None);
        assert_eq!(json_str(&v, "c"), None);
        assert_eq!(json_str(&v, "missing"), None);
    }

    #[test]
    fn extract_from_field_handles_string_form() {
        let v = serde_json::json!({"from": "alice@example.com"});
        assert_eq!(extract_from_field(&v), Some("alice@example.com".to_string()));
    }

    #[test]
    fn extract_from_field_handles_name_and_email_object() {
        let v = serde_json::json!({"from": {"name": "Alice", "email": "alice@example.com"}});
        assert_eq!(
            extract_from_field(&v),
            Some("Alice <alice@example.com>".to_string())
        );
    }

    #[test]
    fn extract_from_field_email_only_object() {
        let v = serde_json::json!({"from": {"email": "bob@example.com"}});
        assert_eq!(extract_from_field(&v), Some("bob@example.com".to_string()));
    }

    #[test]
    fn extract_from_field_none_when_absent_or_empty() {
        assert_eq!(extract_from_field(&serde_json::json!({})), None);
        assert_eq!(
            extract_from_field(&serde_json::json!({"from": {"name": "", "email": ""}})),
            None
        );
    }

    #[test]
    fn extract_recipients_joins_mixed_forms() {
        let v = serde_json::json!({
            "to": [
                "raw@example.com",
                {"name": "Carol", "email": "carol@example.com"},
                {"email": "dave@example.com"}
            ]
        });
        assert_eq!(
            extract_recipients(&v, "to"),
            Some("raw@example.com, Carol <carol@example.com>, dave@example.com".to_string())
        );
    }

    #[test]
    fn extract_recipients_none_for_empty_or_missing() {
        assert_eq!(extract_recipients(&serde_json::json!({"to": []}), "to"), None);
        assert_eq!(extract_recipients(&serde_json::json!({}), "to"), None);
    }

    #[test]
    fn build_folder_queries_covers_all_six_folders() {
        let queries = build_folder_queries();
        let labels: Vec<&str> = queries.iter().map(|q| q.label).collect();
        assert_eq!(labels, vec!["inbox", "sent", "drafts", "trash", "spam", "archive"]);

        let inbox = &queries[0].query;
        assert_eq!(inbox.item_type.as_deref(), Some("received"));
        assert_eq!(inbox.is_trashed, None);

        let trash = &queries[3].query;
        assert_eq!(trash.is_trashed, Some(true));
        assert_eq!(trash.item_type, None);

        let spam = &queries[4].query;
        assert_eq!(spam.is_spam, Some(true));

        let archive = &queries[5].query;
        assert_eq!(archive.is_archived, Some(true));
    }

    #[test]
    fn cache_mail_item_rejects_invalid_id() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "x", "body_text": "y"});
        let mut item = item_with_envelope("good", &json);
        item.id = "bad id".to_string();
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None));
        assert!(db.get_cached_message("bad id").unwrap().is_none());
    }

    #[test]
    fn cache_mail_item_inserts_new_message_and_maps_fields() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({
            "subject": "Hello",
            "from": {"name": "Alice", "email": "alice@example.com"},
            "to": ["bob@example.com"],
            "date": "Wed, 21 May 2026 10:00:00 +0000",
            "body_html": "<p>hi</p>",
            "message_id": "mid-1@test"
        });
        let item = item_with_envelope("msg-new", &json);
        let was_new = cache_mail_item(&db, "inbox", &item, b"pass", None);
        assert!(was_new);

        let cached = db.get_cached_message("msg-new").unwrap().unwrap();
        assert_eq!(cached.folder, "inbox");
        assert_eq!(cached.subject.as_deref(), Some("Hello"));
        assert_eq!(cached.sender.as_deref(), Some("Alice <alice@example.com>"));
        assert_eq!(cached.recipients.as_deref(), Some("bob@example.com"));
        assert_eq!(cached.date.as_deref(), Some("Wed, 21 May 2026 10:00:00 +0000"));
        assert_eq!(cached.body_text.as_deref(), Some("<p>hi</p>"));
        assert!(cached.imap_uid >= 1);
        let raw = cached.raw_headers.unwrap();
        assert!(raw.contains("\"is_html\":true"));
        assert!(raw.contains("mid-1@test"));
    }

    #[test]
    fn cache_mail_item_prefers_plain_body_when_no_html() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "plain words"});
        let item = item_with_envelope("msg-plain", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None));
        let cached = db.get_cached_message("msg-plain").unwrap().unwrap();
        assert_eq!(cached.body_text.as_deref(), Some("plain words"));
        let raw = cached.raw_headers.unwrap();
        assert!(raw.contains("\"is_html\":false"));
    }

    #[test]
    fn cache_mail_item_replaces_ratchet_body_with_placeholder() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({
            "type": "double_ratchet_v2",
            "subject": "secret",
            "body_text": "ciphertext-blob"
        });
        let item = item_with_envelope("msg-ratchet", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None));
        let cached = db.get_cached_message("msg-ratchet").unwrap().unwrap();
        let body = cached.body_text.unwrap();
        assert!(body.contains("end-to-end encrypted"));
        assert!(!body.contains("ciphertext-blob"));
    }

    #[test]
    fn cache_mail_item_skips_already_body_cached_and_reconciles_folder() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let item = item_with_envelope("msg-move", &json);

        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None));
        let first = db.get_cached_message("msg-move").unwrap().unwrap();
        assert_eq!(first.folder, "inbox");
        let inbox_uid = first.imap_uid;

        let was_new = cache_mail_item(&db, "archive", &item, b"pass", None);
        assert!(!was_new, "already-body-cached item must not count as new");

        let moved = db.get_cached_message("msg-move").unwrap().unwrap();
        assert_eq!(moved.folder, "archive", "folder must be reconciled on early return");
        assert!(moved.imap_uid >= 1);
        let _ = inbox_uid;
        assert_eq!(db.count_cached_messages("inbox").unwrap(), 0);
        assert_eq!(db.count_cached_messages("archive").unwrap(), 1);
    }

    #[test]
    fn cache_mail_item_same_folder_reentry_is_noop_skip() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let item = item_with_envelope("msg-dedup", &json);

        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None));
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None));
        assert_eq!(db.count_cached_messages("inbox").unwrap(), 1);
    }

    #[test]
    fn cache_mail_item_skips_on_undecryptable_envelope() {
        let (_dir, db) = temp_db();
        let mut item = item_with_envelope("msg-bad-env", &serde_json::json!({"subject": "x"}));
        item.encrypted_envelope = "!!!not-base64!!!".to_string();
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None));
        assert!(db.get_cached_message("msg-bad-env").unwrap().is_none());
    }

    #[test]
    fn cache_mail_item_truncates_oversized_body() {
        let (_dir, db) = temp_db();
        let big = "a".repeat(6 * 1024 * 1024);
        let json = serde_json::json!({"subject": "s", "body_text": big});
        let item = item_with_envelope("msg-big", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None));
        let cached = db.get_cached_message("msg-big").unwrap().unwrap();
        let body = cached.body_text.unwrap();
        assert!(body.len() < 6 * 1024 * 1024);
        assert!(body.ends_with("[truncated]"));
    }

    #[test]
    fn cache_mail_item_records_envelope_nonce_replay() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let nonce_pbkdf2 = STANDARD.encode([0x01u8]);

        let mut first = item_with_envelope("msg-replay", &json);
        first.envelope_nonce = nonce_pbkdf2.clone();
        let _ = cache_mail_item(&db, "inbox", &first, b"pass", None);
        assert_eq!(
            db.replay_check_and_record("msg-replay", &nonce_pbkdf2).unwrap(),
            true,
            "same nonce must be accepted"
        );
        assert_eq!(
            db.replay_check_and_record("msg-replay", &STANDARD.encode([0x02u8])).unwrap(),
            false,
            "different nonce for same id is a replay/rollback"
        );
    }
}
