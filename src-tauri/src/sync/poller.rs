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
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::sync::Mutex as StdMutex;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tauri::Emitter;
use zeroize::Zeroizing;

use crate::api_client::{ApiClient, MailItem, MailListQuery};
use crate::auth::session::Session;
use crate::crypto::envelope::decrypt_envelope;
use crate::crypto::attachment::{decrypt_attachment, AttachmentKeyEntry};
use crate::db::{
    CachedAttachment, Database, ATTACHMENTS_FAILED, ATTACHMENTS_NONE, ATTACHMENTS_PENDING,
    ATTACHMENTS_STORED,
};
use crate::error::BridgeError;
use crate::jmap::state::StateChange;

const POLL_INTERVAL_SECS: u64 = 30;
const DEEP_SYNC_INTERVAL_SECS: u64 = 300;
const TRIGGER_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(5);

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

fn emit_sync_progress(
    folder: &str,
    done: usize,
    total: usize,
    folder_done: usize,
    folder_total: usize,
) {
    let Some(cell) = GLOBAL_APP_HANDLE.get() else { return; };
    let handle_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(handle) = handle_opt else { return; };
    let _ = handle.emit("sync_progress", serde_json::json!({
        "folder": folder,
        "done": done,
        "total": total,
        "folder_done": folder_done,
        "folder_total": folder_total,
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

pub fn emit_import_progress(progress: &crate::imap::append::ImportProgress) {
    let Some(cell) = GLOBAL_APP_HANDLE.get() else { return; };
    let handle_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(handle) = handle_opt else { return; };
    let _ = handle.emit("import_progress", progress.clone());
}

pub fn notify_send_failed() {
    let Some(cell) = GLOBAL_APP_HANDLE.get() else { return; };
    let handle_opt = cell.lock().ok().and_then(|g| g.clone());
    let Some(handle) = handle_opt else { return; };
    use tauri_plugin_notification::NotificationExt;
    let _ = handle
        .notification()
        .builder()
        .title("Message not sent")
        .body("Aster Bridge couldn't send a message. Open Aster Bridge to retry it.")
        .show();
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

const DEFAULT_ATTACHMENT_CONTENT_TYPE: &str = "application/octet-stream";
const ATTACHMENT_PLACEHOLDER_NAME: &str = "Attachment";

#[derive(Debug, Clone, PartialEq)]
struct EnvelopeAttachment {
    seq: Option<i64>,
    filename: Option<String>,
    content_type: String,
    content_id: Option<String>,
    size: Option<i64>,
    key: Option<String>,
}

fn json_trimmed_string(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn normalize_content_type(raw: Option<String>) -> String {
    match raw {
        Some(s) if s.contains('/') => s.to_ascii_lowercase(),
        _ => DEFAULT_ATTACHMENT_CONTENT_TYPE.to_string(),
    }
}

fn parse_envelope_attachments(v: &serde_json::Value) -> Vec<EnvelopeAttachment> {
    let Some(entries) = v.get("attachment_keys").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    let mut seen_seq: Vec<i64> = Vec::new();
    let mut keyed: Vec<EnvelopeAttachment> = Vec::new();
    let mut unkeyed: Vec<EnvelopeAttachment> = Vec::new();
    for entry in entries {
        if !entry.is_object() {
            continue;
        }
        let seq = entry.get("seq").and_then(|x| x.as_i64());
        let parsed = EnvelopeAttachment {
            seq,
            filename: json_trimmed_string(entry, "filename"),
            content_type: normalize_content_type(json_trimmed_string(entry, "content_type")),
            content_id: json_trimmed_string(entry, "content_id"),
            size: entry.get("size").and_then(|x| x.as_i64()).filter(|n| *n >= 0),
            key: json_trimmed_string(entry, "key"),
        };
        match seq {
            Some(s) => {
                if seen_seq.contains(&s) {
                    continue;
                }
                seen_seq.push(s);
                keyed.push(parsed);
            }
            None => unkeyed.push(parsed),
        }
    }
    keyed.sort_by_key(|a| a.seq.unwrap_or(0));
    keyed.extend(unkeyed);
    keyed
}

fn attachment_display_name(a: &EnvelopeAttachment) -> String {
    a.filename
        .clone()
        .unwrap_or_else(|| ATTACHMENT_PLACEHOLDER_NAME.to_string())
}

const ATTACHMENT_INLINE_DOWNLOADS_PER_PASS: usize = 25;
const ATTACHMENT_BACKLOG_PER_PASS: i64 = 25;
const ATTACHMENT_MAX_ATTEMPTS: i64 = 50;

enum AttachmentFetchError {
    Transport(String),
    Content(String),
}

fn classify_api_error(e: BridgeError) -> AttachmentFetchError {
    match e {
        BridgeError::Network(_) | BridgeError::Auth(_) => {
            AttachmentFetchError::Transport(e.to_string())
        }
        other => AttachmentFetchError::Content(other.to_string()),
    }
}

fn key_entry(a: &EnvelopeAttachment) -> AttachmentKeyEntry {
    AttachmentKeyEntry {
        key: a.key.clone(),
        filename: a.filename.clone(),
        content_type: Some(a.content_type.clone()),
        content_id: a.content_id.clone(),
        size: a.size,
    }
}

fn cached_attachment_entries(raw_headers: Option<&str>) -> Vec<EnvelopeAttachment> {
    let Some(raw) = raw_headers else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(list) = parsed.get("attachments").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    list.iter()
        .filter(|e| e.is_object())
        .map(|e| EnvelopeAttachment {
            seq: e.get("seq").and_then(|x| x.as_i64()),
            filename: json_trimmed_string(e, "name").filter(|n| n != ATTACHMENT_PLACEHOLDER_NAME),
            content_type: normalize_content_type(json_trimmed_string(e, "type")),
            content_id: json_trimmed_string(e, "cid"),
            size: e.get("size").and_then(|x| x.as_i64()).filter(|n| *n >= 0),
            key: json_trimmed_string(e, "key"),
        })
        .collect()
}

fn entry_for_row(
    entries: &[EnvelopeAttachment],
    seq: i64,
    position: usize,
) -> Option<&EnvelopeAttachment> {
    entries.iter().find(|e| e.seq == Some(seq)).or_else(|| {
        if entries.iter().all(|e| e.seq.is_none()) {
            entries.get(position)
        } else {
            None
        }
    })
}

fn expected_attachment_count(item: &MailItem, entries: &[EnvelopeAttachment]) -> usize {
    let declared = item.attachment_count.map(|n| n.max(0) as usize).unwrap_or(0);
    let flagged = usize::from(item.has_attachments == Some(true));
    entries.len().max(declared).max(flagged)
}

fn merge_attachment_meta(raw_headers: Option<&str>, entries: &[EnvelopeAttachment]) -> String {
    let mut map = raw_headers
        .and_then(|r| serde_json::from_str::<serde_json::Value>(r).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    map.insert(
        "attachment_count".to_string(),
        serde_json::json!(entries.len()),
    );
    map.insert("attachments".to_string(), attachment_meta_json(entries));
    serde_json::Value::Object(map).to_string()
}

fn carry_attachment_meta(
    db: &Database,
    aster_id: &str,
    meta: &mut serde_json::Map<String, serde_json::Value>,
) {
    let Ok(Some(existing)) = db.get_cached_message(aster_id) else {
        return;
    };
    let Some(raw) = existing.raw_headers.as_deref() else {
        return;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) else {
        return;
    };
    for key in ["attachment_count", "attachments"] {
        if let Some(v) = parsed.get(key) {
            meta.insert(key.to_string(), v.clone());
        }
    }
}

async fn fetch_and_decrypt_attachments(
    client: &ApiClient,
    access_token: &str,
    mail_id: &str,
    entries: &[EnvelopeAttachment],
    passphrase: &[u8],
    identity_key: Option<&str>,
) -> std::result::Result<Vec<CachedAttachment>, AttachmentFetchError> {
    let resp = client
        .list_attachments_for_mail(access_token, mail_id)
        .await
        .map_err(classify_api_error)?;
    if resp.attachments.is_empty() {
        return Err(AttachmentFetchError::Content(
            "server returned no attachment rows".to_string(),
        ));
    }
    let rows = resp.attachments;
    let entries: Vec<EnvelopeAttachment> = entries.to_vec();
    let passphrase = Zeroizing::new(passphrase.to_vec());
    let identity_key = identity_key.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        let mut out: Vec<CachedAttachment> = Vec::with_capacity(rows.len());
        for (position, row) in rows.iter().enumerate() {
            let seq = row.seq_num as i64;
            if out.iter().any(|a| a.seq == seq) {
                continue;
            }
            let entry = entry_for_row(&entries, seq, position).map(key_entry);
            let att = decrypt_attachment(row, entry.as_ref(), &passphrase, identity_key.as_deref())
                .map_err(|e| e.to_string())?;
            out.push(CachedAttachment {
                seq: att.seq,
                name: att.filename,
                is_inline: att.is_inline || att.content_id.is_some(),
                content_type: att.content_type,
                content_id: att.content_id,
                size: att.data.len() as i64,
                data: att.data,
            });
        }
        out.sort_by_key(|a| a.seq);
        Ok::<Vec<CachedAttachment>, String>(out)
    })
    .await
    .map_err(|e| AttachmentFetchError::Content(format!("attachment decrypt task: {}", e)))?
    .map_err(AttachmentFetchError::Content)
}

async fn refresh_attachment_keys(
    client: &ApiClient,
    access_token: &str,
    aster_id: &str,
    passphrase: &[u8],
    identity_key: Option<&str>,
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> std::result::Result<Vec<EnvelopeAttachment>, AttachmentFetchError> {
    let item = client
        .fetch_mail_item(access_token, aster_id)
        .await
        .map_err(classify_api_error)?;
    let plaintext = decrypt_envelope(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        passphrase,
        identity_key,
        inbound_keys,
    )
    .map_err(|_| AttachmentFetchError::Content("envelope decrypt failed".to_string()))?;
    let parsed: serde_json::Value = serde_json::from_str(&plaintext)
        .map_err(|e| AttachmentFetchError::Content(format!("envelope parse: {}", e)))?;
    Ok(parse_envelope_attachments(&parsed))
}

async fn backfill_pending_attachments(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    passphrase: &[u8],
    identity_key: Option<&str>,
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
    skip: &HashSet<String>,
) -> Vec<String> {
    let mut updated: Vec<String> = Vec::new();
    let backlog = match db.list_attachment_backlog(ATTACHMENT_BACKLOG_PER_PASS) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("attachment backlog query failed: {}", e);
            return updated;
        }
    };
    for (aster_id, folder) in backlog {
        if skip.contains(&aster_id) {
            continue;
        }
        let Ok(Some(msg)) = db.get_cached_message(&aster_id) else {
            continue;
        };
        let mut entries = cached_attachment_entries(msg.raw_headers.as_deref());
        let mut meta_json = msg.raw_headers.clone();
        if entries.iter().all(|e| e.key.is_none()) {
            match refresh_attachment_keys(
                client,
                access_token,
                &aster_id,
                passphrase,
                identity_key,
                inbound_keys,
            )
            .await
            {
                Ok(fresh) if !fresh.is_empty() => {
                    meta_json = Some(merge_attachment_meta(msg.raw_headers.as_deref(), &fresh));
                    entries = fresh;
                }
                Ok(_) => {}
                Err(AttachmentFetchError::Transport(e)) => {
                    tracing::warn!("attachment key refresh for {} deferred: {}", aster_id, e);
                    break;
                }
                Err(AttachmentFetchError::Content(e)) => {
                    tracing::debug!("attachment key refresh for {} skipped: {}", aster_id, e);
                }
            }
        }
        match fetch_and_decrypt_attachments(
            client,
            access_token,
            &aster_id,
            &entries,
            passphrase,
            identity_key,
        )
        .await
        {
            Ok(list) => {
                if let Err(e) = db.replace_message_attachments(&aster_id, &list) {
                    tracing::warn!("attachment store for {} failed: {}", aster_id, e);
                    continue;
                }
                let body = msg.body_text.clone().unwrap_or_default();
                let cleaned = crate::message_render::strip_legacy_note(&body);
                if cleaned.is_some() || meta_json != msg.raw_headers {
                    let new_body = cleaned.unwrap_or(body);
                    let _ = db.update_cached_body(&aster_id, &new_body, meta_json.as_deref());
                }
                if msg.imap_uid > 0 {
                    let _ = db.remove_uid_mapping(msg.imap_uid as i64, &folder);
                }
                let _ = db.assign_uid_if_missing(&folder, &aster_id);
                tracing::info!(
                    "attachments for {} stored ({} part(s))",
                    aster_id,
                    list.len()
                );
                updated.push(aster_id);
            }
            Err(AttachmentFetchError::Transport(e)) => {
                tracing::warn!("attachment download for {} deferred: {}", aster_id, e);
                break;
            }
            Err(AttachmentFetchError::Content(e)) => {
                let attempts = db.bump_attachment_attempts(&aster_id).unwrap_or(0);
                tracing::warn!(
                    "attachment download for {} failed (attempt {}): {}",
                    aster_id,
                    attempts,
                    e
                );
                if attempts >= ATTACHMENT_MAX_ATTEMPTS {
                    let _ = db.set_attachments_state(&aster_id, ATTACHMENTS_FAILED);
                    updated.push(aster_id);
                }
            }
        }
    }
    updated
}

fn attachment_meta_json(attachments: &[EnvelopeAttachment]) -> serde_json::Value {
    serde_json::Value::Array(
        attachments
            .iter()
            .map(|a| {
                let mut map = serde_json::Map::new();
                if let Some(seq) = a.seq {
                    map.insert("seq".to_string(), serde_json::json!(seq));
                }
                map.insert("name".to_string(), serde_json::json!(attachment_display_name(a)));
                map.insert("type".to_string(), serde_json::json!(a.content_type));
                if let Some(size) = a.size {
                    map.insert("size".to_string(), serde_json::json!(size));
                }
                if let Some(cid) = &a.content_id {
                    map.insert("cid".to_string(), serde_json::json!(cid));
                }
                if let Some(key) = &a.key {
                    map.insert("key".to_string(), serde_json::json!(key));
                }
                serde_json::Value::Object(map)
            })
            .collect(),
    )
}

fn normalize_date_rfc3339(s: &str) -> String {
    let trimmed = s.trim();
    if chrono::DateTime::parse_from_rfc3339(trimmed).is_ok() {
        return trimmed.to_string();
    }
    match crate::imap::server::parse_datetime_lenient(trimmed) {
        Some(d) => d.to_rfc3339(),
        None => trimmed.to_string(),
    }
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

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CacheOutcome {
    was_new: bool,
    flags_changed: bool,
    inbound_decrypt_failed: bool,
}

fn reconcile_server_flags(db: &Database, item: &MailItem) -> bool {
    if item.is_read.is_none() && item.is_starred.is_none() {
        return false;
    }
    let current = match db.get_message_flags_by_id(&item.id) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut new_flags = current;
    if let Some(read) = item.is_read {
        if read {
            new_flags |= 1;
        } else {
            new_flags &= !1;
        }
    }
    if let Some(starred) = item.is_starred {
        if starred {
            new_flags |= 4;
        } else {
            new_flags &= !4;
        }
    }
    if new_flags == current {
        return false;
    }
    db.set_message_flags_by_id(&item.id, new_flags).is_ok()
}

struct PreparedMessage {
    subject: Option<String>,
    sender: Option<String>,
    recipients: Option<String>,
    date: Option<String>,
    body_text: Option<String>,
    is_html: bool,
    message_id: Option<String>,
    attachments: Vec<EnvelopeAttachment>,
    expected_attachments: usize,
}

enum Prepared {
    Done(CacheOutcome),
    Ready(PreparedMessage),
}

fn prepare_mail_item(
    db: &Database,
    folder: &str,
    item: &MailItem,
    passphrase: &[u8],
    identity_key: Option<&str>,
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> Prepared {
    if !is_valid_item_id(&item.id) {
        tracing::warn!("rejecting message with invalid id format");
        return Prepared::Done(CacheOutcome::default());
    }

    if db.body_cached(&item.id) {
        let _ = db.set_folder_if_changed(&item.id, folder);
        let _ = db.assign_uid_if_missing(folder, &item.id);
        return Prepared::Done(CacheOutcome {
            was_new: false,
            flags_changed: reconcile_server_flags(db, item),
            inbound_decrypt_failed: false,
        });
    }

    if !item.envelope_nonce.is_empty() {
        if let Ok(false) = db.replay_check_and_record(&item.id, &item.envelope_nonce) {
            tracing::warn!("rejecting envelope nonce mismatch (replay/rollback)");
            return Prepared::Done(CacheOutcome::default());
        }
    }

    let plaintext_result = decrypt_envelope(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        passphrase,
        identity_key,
        inbound_keys,
    );

    let plaintext = match plaintext_result {
        Ok(p) => p,
        Err(_) => {
            let inbound = crate::crypto::inbound::is_inbound_payload(
                &item.encrypted_envelope,
                &item.envelope_nonce,
            );
            if inbound {
                if inbound_keys.is_empty() {
                    tracing::error!(
                        "encrypted mail received but no inbound keys are loaded; sign in again to restore them"
                    );
                } else {
                    tracing::warn!("inbound envelope decrypt failed; item left uncached for retry");
                }
            } else {
                tracing::debug!("envelope decrypt skipped");
            }
            return Prepared::Done(CacheOutcome {
                inbound_decrypt_failed: inbound,
                ..CacheOutcome::default()
            });
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
    let date = json_str(&parsed, "date")
        .map(|d| normalize_date_rfc3339(&d))
        .or_else(|| Some(normalize_date_rfc3339(&item.created_at)));
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
    let attachments = parse_envelope_attachments(&parsed);
    let expected_attachments = expected_attachment_count(item, &attachments);
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
    let message_id = json_str(&parsed, "message_id").or_else(|| json_str(&parsed, "messageId"));
    Prepared::Ready(PreparedMessage {
        subject,
        sender,
        recipients,
        date,
        body_text,
        is_html,
        message_id,
        attachments,
        expected_attachments,
    })
}

fn commit_mail_item(
    db: &Database,
    folder: &str,
    item: &MailItem,
    prepared: PreparedMessage,
    downloaded: Option<Vec<CachedAttachment>>,
) -> CacheOutcome {
    let attachment_count = prepared.expected_attachments;
    let size = prepared
        .body_text
        .as_ref()
        .map(|b| b.len() as i64)
        .unwrap_or(0);
    let mut raw_headers_map = serde_json::Map::new();
    raw_headers_map.insert("is_html".to_string(), serde_json::json!(prepared.is_html));
    raw_headers_map.insert(
        "message_id".to_string(),
        serde_json::json!(prepared.message_id),
    );
    raw_headers_map.insert(
        "attachment_count".to_string(),
        serde_json::json!(attachment_count),
    );
    if !prepared.attachments.is_empty() {
        raw_headers_map.insert(
            "attachments".to_string(),
            attachment_meta_json(&prepared.attachments),
        );
    }
    let raw_headers_meta = serde_json::Value::Object(raw_headers_map).to_string();

    let was_new = match db.upsert_cached_message(
        &item.id,
        folder,
        prepared.subject.as_deref(),
        prepared.sender.as_deref(),
        prepared.recipients.as_deref(),
        prepared.date.as_deref(),
        size,
        prepared.body_text.as_deref(),
        Some(&raw_headers_meta),
    ) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("cache upsert failed for {}: {}", item.id, e);
            return CacheOutcome::default();
        }
    };
    let stored = match downloaded {
        Some(list) if !list.is_empty() => match db.replace_message_attachments(&item.id, &list) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("attachment store for {} failed: {}", item.id, e);
                false
            }
        },
        _ => false,
    };
    if !stored
        && attachment_count > 0
        && db.attachments_state(&item.id).unwrap_or(ATTACHMENTS_NONE) != ATTACHMENTS_STORED
    {
        let _ = db.set_attachments_state(&item.id, ATTACHMENTS_PENDING);
    }
    if let Err(e) = db.assign_uid_if_missing(folder, &item.id) {
        tracing::warn!("uid assign failed for {}: {}", item.id, e);
    }
    let flags_changed = reconcile_server_flags(db, item);
    CacheOutcome {
        was_new,
        flags_changed: flags_changed && !was_new,
        inbound_decrypt_failed: false,
    }
}

pub(crate) fn cache_mail_item(
    db: &Database,
    folder: &str,
    item: &MailItem,
    passphrase: &[u8],
    identity_key: Option<&str>,
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> CacheOutcome {
    match prepare_mail_item(db, folder, item, passphrase, identity_key, inbound_keys) {
        Prepared::Done(outcome) => outcome,
        Prepared::Ready(prepared) => commit_mail_item(db, folder, item, prepared, None),
    }
}

pub fn cache_web_draft(
    db: &Database,
    draft_id: &str,
    content: &crate::crypto::draft::DraftContent,
    our_email: &str,
    date: &str,
    version: i64,
) -> bool {
    let recipients = if content.to_recipients.is_empty() {
        None
    } else {
        Some(content.to_recipients.join(", "))
    };
    let cc = content.cc_recipients.join(", ");
    let bcc = content.bcc_recipients.join(", ");
    let attachments = draft_cached_attachments(content);
    let meta = serde_json::json!({
        "is_html": true,
        "message_id": serde_json::Value::Null,
        "draft_api": true,
        "draft_version": version,
        "cc": cc,
        "bcc": bcc,
        "attachment_count": attachments.len(),
    })
    .to_string();
    let subject = if content.subject.is_empty() {
        None
    } else {
        Some(content.subject.as_str())
    };
    let body = content.message.as_str();
    let was_new = db
        .upsert_cached_message(
            draft_id,
            "drafts",
            subject,
            Some(our_email),
            recipients.as_deref(),
            Some(date),
            body.len() as i64,
            Some(body),
            Some(&meta),
        )
        .unwrap_or(false);
    match db.replace_message_attachments(draft_id, &attachments) {
        Ok(()) => {
            let state = if attachments.is_empty() {
                ATTACHMENTS_NONE
            } else {
                ATTACHMENTS_STORED
            };
            if let Err(e) = db.set_attachments_state(draft_id, state) {
                tracing::warn!("draft attachment state failed for {}: {}", draft_id, e);
            }
        }
        Err(e) => tracing::warn!("draft attachment store failed for {}: {}", draft_id, e),
    }
    if let Err(e) = db.assign_uid_if_missing("drafts", draft_id) {
        tracing::warn!("draft uid assign failed for {}: {}", draft_id, e);
    }
    match db.get_message_flags_by_id(draft_id) {
        Ok(f) if f & 16 == 0 => {
            let _ = db.set_message_flags_by_id(draft_id, f | 1 | 16);
        }
        Err(_) => {
            let _ = db.set_message_flags_by_id(draft_id, 1 | 16);
        }
        _ => {}
    }
    was_new
}

fn draft_cached_attachments(content: &crate::crypto::draft::DraftContent) -> Vec<CachedAttachment> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    content
        .attachments
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|a| {
            let data = STANDARD.decode(a.data_base64.trim()).ok()?;
            if data.is_empty() {
                return None;
            }
            let content_id = a.content_id.clone().filter(|c| !c.is_empty());
            Some((a, content_id, data))
        })
        .enumerate()
        .map(|(seq, (a, content_id, data))| CachedAttachment {
            seq: seq as i64,
            name: if a.name.is_empty() {
                format!("attachment-{}", seq + 1)
            } else {
                a.name.clone()
            },
            content_type: crate::crypto::attachment::normalize_content_type(Some(&a.mime_type)),
            is_inline: content_id.is_some(),
            content_id,
            size: data.len() as i64,
            data,
        })
        .collect()
}

fn cached_draft_versions(db: &Database) -> std::collections::HashMap<String, i64> {
    db.list_cached_message_meta("drafts")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| {
            let meta: serde_json::Value = serde_json::from_str(m.raw_headers.as_deref()?).ok()?;
            if meta.get("draft_api").and_then(|v| v.as_bool()) != Some(true) {
                return None;
            }
            let version = meta.get("draft_version").and_then(|v| v.as_i64()).unwrap_or(-1);
            Some((m.aster_id, version))
        })
        .collect()
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
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
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
        inbound_keys,
    )
    .ok()?;

    let parsed: serde_json::Value = serde_json::from_str(&plaintext_env).ok()?;
    let ratchet_obj = crate::crypto::ratchet::find_ratchet_object(&parsed)?;
    let mut msg = crate::crypto::ratchet::parse_recipient_message(&ratchet_obj, our_email)?;

    if let Some(key_id) = msg.pq_key_id {
        if key_id == crate::crypto::ratchet::PQ_IDENTITY_KEY_ID {
            for candidate in inbound_keys {
                let Some(pq_identity_secret) = candidate.pq_decap_key.as_ref() else {
                    continue;
                };
                msg.pq_secret = Some(pq_identity_secret.clone());
                if let Some(plaintext) =
                    crate::crypto::ratchet::decrypt_with_key_sets(ratchet_keys, &msg)
                {
                    return Some(plaintext);
                }
            }
            return None;
        }
        let sk = sync_key?;
        let resp = client
            .get_pq_secret(access_token, u32::try_from(key_id).ok()?)
            .await
            .ok()?;
        let secret =
            crate::crypto::ratchet::decrypt_pq_secret(sk, &resp.encrypted_secret, &resp.secret_nonce)
                .ok()?;
        msg.pq_secret = Some(secret);
    }

    crate::crypto::ratchet::decrypt_with_key_sets(ratchet_keys, &msg)
}

const INBOUND_HEAL_COOLDOWN_SECS: u64 = 300;
const INBOUND_HEAL_RETRY_CAP: usize = 500;

static INBOUND_HEAL_LAST: OnceLock<StdMutex<Option<std::time::Instant>>> = OnceLock::new();

fn take_heal_permit(
    state: &StdMutex<Option<std::time::Instant>>,
    now: std::time::Instant,
) -> bool {
    let Ok(mut guard) = state.lock() else {
        return false;
    };
    let allowed = guard.map_or(true, |t| {
        now.duration_since(t) >= std::time::Duration::from_secs(INBOUND_HEAL_COOLDOWN_SECS)
    });
    if allowed {
        *guard = Some(now);
    }
    allowed
}

async fn heal_inbound_keys(session: &Arc<RwLock<Session>>, client: &Arc<ApiClient>) -> bool {
    let state = INBOUND_HEAL_LAST.get_or_init(|| StdMutex::new(None));
    if !take_heal_permit(state, std::time::Instant::now()) {
        return false;
    }
    let old_keys = { session.read().await.inbound_keys.clone() };
    let Ok(data_dir) = crate::config::data_dir() else {
        return false;
    };
    let identity = match crate::auth::device_identity::get_or_create_identity(&data_dir) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!("inbound key heal skipped, no device identity: {}", e);
            return false;
        }
    };
    let Some(device_id) = identity.device_id else {
        return false;
    };
    if let Err(e) = crate::auth::session::refresh_access_token(
        session,
        device_id,
        &identity.ed25519_signing_key,
        client,
    )
    .await
    {
        tracing::warn!("inbound key heal refresh failed: {}", e);
        return false;
    }
    let changed = {
        let s = session.read().await;
        !crate::auth::session::inbound_keys_equal(&old_keys, &s.inbound_keys)
    };
    if changed {
        tracing::info!("inbound key heal: vault delivered updated keys");
    } else {
        tracing::info!("inbound key heal: vault keys unchanged");
    }
    changed
}

fn retry_failed_inbound_items(
    db: &Database,
    failed: &[(&'static str, MailItem)],
    passphrase: &[u8],
    identity_key: Option<&str>,
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> (Vec<String>, Vec<String>) {
    let mut new_ids = Vec::new();
    let mut updated_ids = Vec::new();
    for (folder, item) in failed {
        let outcome = cache_mail_item(db, folder, item, passphrase, identity_key, inbound_keys);
        if outcome.was_new {
            new_ids.push(item.id.clone());
        } else if outcome.flags_changed {
            updated_ids.push(item.id.clone());
        }
    }
    (new_ids, updated_ids)
}

async fn run_sync_pass(
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
    db: &Arc<Database>,
    jmap_broadcaster: Option<&broadcast::Sender<StateChange>>,
    deep: bool,
) -> Result<(), String> {
    let mut any_inserted = false;
    let mut last_err: Option<String> = None;
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut updated_ids: Vec<String> = Vec::new();
    let mut all_folders_complete = true;
    let mut failed_inbound: Vec<(&'static str, MailItem)> = Vec::new();
    let mut inline_downloads = 0usize;
    let mut attachments_handled: HashSet<String> = HashSet::new();

    let (access_token, passphrase, identity_key, our_email, ratchet_keys, inbound_keys) = {
        let s = session.read().await;
        (
            s.access_token.clone(),
            Zeroizing::new(s.vault_passphrase.clone()),
            s.identity_key.clone(),
            s.email.clone(),
            s.ratchet_keys.clone(),
            s.inbound_keys.clone(),
        )
    };
    let sync_key = crate::crypto::ratchet::derive_sync_key(&passphrase).ok();

    let queries = build_folder_queries();
    let total_folders = queries.len();
    for (folder_idx, folder_query) in queries.iter().enumerate() {
        emit_sync_progress(folder_query.label, folder_idx, total_folders, 0, 0);
        let mut cursor: Option<String> = None;
        let mut total_fetched = 0usize;
        let max_per_folder = 2000usize;
        loop {
            let mut q = folder_query.query.clone();
            q.cursor = cursor.clone();
            match client.list_mail(&access_token, &q).await {
                Ok(resp) => {
                    let folder_total = (resp.total as usize).min(max_per_folder);
                    tracing::debug!(
                        "Synced {} page - {} items (total: {}, has_more: {})",
                        folder_query.label,
                        resp.items.len(),
                        resp.total,
                        resp.has_more
                    );
                    let mut new_ids: Vec<String> = Vec::new();
                    for item in &resp.items {
                        seen_ids.insert(item.id.clone());
                        let outcome = match prepare_mail_item(
                            db,
                            folder_query.label,
                            item,
                            &passphrase,
                            identity_key.as_deref(),
                            &inbound_keys,
                        ) {
                            Prepared::Done(outcome) => outcome,
                            Prepared::Ready(prepared) => {
                                let mut downloaded: Option<Vec<CachedAttachment>> = None;
                                let mut content_failed = false;
                                if prepared.expected_attachments > 0
                                    && inline_downloads < ATTACHMENT_INLINE_DOWNLOADS_PER_PASS
                                {
                                    inline_downloads += 1;
                                    attachments_handled.insert(item.id.clone());
                                    match fetch_and_decrypt_attachments(
                                        client,
                                        &access_token,
                                        &item.id,
                                        &prepared.attachments,
                                        &passphrase,
                                        identity_key.as_deref(),
                                    )
                                    .await
                                    {
                                        Ok(list) => downloaded = Some(list),
                                        Err(AttachmentFetchError::Transport(e)) => {
                                            tracing::warn!(
                                                "attachment download for {} deferred: {}",
                                                item.id,
                                                e
                                            );
                                        }
                                        Err(AttachmentFetchError::Content(e)) => {
                                            tracing::warn!(
                                                "attachment download for {} failed: {}",
                                                item.id,
                                                e
                                            );
                                            content_failed = true;
                                        }
                                    }
                                }
                                let outcome = commit_mail_item(
                                    db,
                                    folder_query.label,
                                    item,
                                    prepared,
                                    downloaded,
                                );
                                if content_failed {
                                    let _ = db.bump_attachment_attempts(&item.id);
                                }
                                outcome
                            }
                        };
                        if outcome.flags_changed {
                            updated_ids.push(item.id.clone());
                        }
                        if outcome.inbound_decrypt_failed
                            && failed_inbound.len() < INBOUND_HEAL_RETRY_CAP
                        {
                            failed_inbound.push((folder_query.label, item.clone()));
                        }
                        if outcome.was_new {
                            new_ids.push(item.id.clone());
                            if let Some(plaintext) = try_decrypt_internal_mail(
                                item,
                                &our_email,
                                &passphrase,
                                identity_key.as_deref(),
                                &ratchet_keys,
                                &inbound_keys,
                                sync_key.as_ref(),
                                client,
                                &access_token,
                            )
                            .await
                            {
                                let mut meta_map = serde_json::Map::new();
                                meta_map.insert(
                                    "is_html".to_string(),
                                    serde_json::json!(looks_like_html(&plaintext)),
                                );
                                meta_map
                                    .insert("message_id".to_string(), serde_json::Value::Null);
                                carry_attachment_meta(db, &item.id, &mut meta_map);
                                let meta = serde_json::Value::Object(meta_map).to_string();
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
                    emit_sync_progress(
                        folder_query.label,
                        folder_idx,
                        total_folders,
                        total_fetched.min(folder_total),
                        folder_total,
                    );
                    let page_all_cached = !resp.items.is_empty() && new_ids.is_empty();
                    let reached_end = !resp.has_more || resp.next_cursor.is_none();
                    let capped = total_fetched >= max_per_folder;
                    let done_with_folder =
                        reached_end || capped || (!deep && page_all_cached);
                    if done_with_folder {
                        if !reached_end {
                            all_folders_complete = false;
                        }
                        break;
                    }
                    cursor = resp.next_cursor;
                }
                Err(e) => {
                    let msg = format!("failed to sync {}: {}", folder_query.label, e);
                    tracing::warn!("{}", msg);
                    last_err = Some(msg);
                    all_folders_complete = false;
                    break;
                }
            }
        }
    }

    if !failed_inbound.is_empty() {
        tracing::warn!(
            "sync: {} inbound item(s) failed to decrypt; attempting key heal",
            failed_inbound.len()
        );
        if heal_inbound_keys(session, client).await {
            let (fresh_identity_key, fresh_inbound_keys) = {
                let s = session.read().await;
                (s.identity_key.clone(), s.inbound_keys.clone())
            };
            let (healed_new, healed_updated) = retry_failed_inbound_items(
                db,
                &failed_inbound,
                &passphrase,
                fresh_identity_key.as_deref(),
                &fresh_inbound_keys,
            );
            if !healed_new.is_empty() {
                tracing::info!(
                    "sync: inbound key heal recovered {} item(s)",
                    healed_new.len()
                );
                any_inserted = true;
                let id_refs: Vec<&str> = healed_new.iter().map(|s| s.as_str()).collect();
                let _ = db.jmap_record_sync_batch("Email", &id_refs);
            }
            updated_ids.extend(healed_updated);
        }
    }

    let backfilled = backfill_pending_attachments(
        db,
        client,
        &access_token,
        &passphrase,
        identity_key.as_deref(),
        &inbound_keys,
        &attachments_handled,
    )
    .await;
    updated_ids.extend(backfilled);

    match identity_key.as_deref() {
        Some(ik) => {
            let existing_versions = cached_draft_versions(db);
            let mut cursor: Option<String> = None;
            let mut fetched = 0usize;
            let mut new_ids: Vec<String> = Vec::new();
            loop {
                match client.list_drafts(&access_token, 100, cursor.as_deref()).await {
                    Ok(resp) => {
                        for d in &resp.items {
                            if !is_valid_item_id(&d.id) {
                                continue;
                            }
                            seen_ids.insert(d.id.clone());
                            if existing_versions.get(&d.id) == Some(&d.version) {
                                continue;
                            }
                            let content = match crate::crypto::draft::decrypt_draft_content(
                                &d.encrypted_content,
                                &d.content_nonce,
                                ik,
                            ) {
                                Ok(c) => c,
                                Err(_) => {
                                    tracing::debug!("web draft decrypt skipped");
                                    continue;
                                }
                            };
                            let date = normalize_date_rfc3339(&d.updated_at);
                            let was_new =
                                cache_web_draft(db, &d.id, &content, &our_email, &date, d.version);
                            if was_new {
                                new_ids.push(d.id.clone());
                            } else {
                                updated_ids.push(d.id.clone());
                            }
                        }
                        fetched += resp.items.len();
                        let reached_end = !resp.has_more || resp.next_cursor.is_none();
                        if reached_end || fetched >= 1000 {
                            if !reached_end {
                                all_folders_complete = false;
                            }
                            break;
                        }
                        cursor = resp.next_cursor;
                    }
                    Err(e) => {
                        let msg = format!("failed to sync web drafts: {}", e);
                        tracing::warn!("{}", msg);
                        last_err = Some(msg);
                        all_folders_complete = false;
                        break;
                    }
                }
            }
            if !new_ids.is_empty() {
                any_inserted = true;
                let id_refs: Vec<&str> = new_ids.iter().map(|s| s.as_str()).collect();
                let _ = db.jmap_record_sync_batch("Email", &id_refs);
            }
        }
        None => {
            for id in cached_draft_versions(db).keys() {
                seen_ids.insert(id.clone());
            }
        }
    }

    let mut destroyed_ids: Vec<String> = Vec::new();
    if deep && all_folders_complete && last_err.is_none() {
        if let Ok(local) = db.list_all_cached_id_folders() {
            for (id, folder) in local {
                if !seen_ids.contains(&id) {
                    if db.delete_message_by_aster_id(&id).is_ok() {
                        tracing::info!("sync: pruned {} from {} (gone on server)", id, folder);
                        destroyed_ids.push(id);
                    }
                }
            }
        }
    }
    if !destroyed_ids.is_empty() {
        let refs: Vec<&str> = destroyed_ids.iter().map(|s| s.as_str()).collect();
        let _ = db.jmap_record_destroyed_batch("Email", &refs);
    }
    if !updated_ids.is_empty() {
        let refs: Vec<&str> = updated_ids.iter().map(|s| s.as_str()).collect();
        let _ = db.jmap_record_updated_batch("Email", &refs);
    }

    if any_inserted || !destroyed_ids.is_empty() || !updated_ids.is_empty() {
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

fn migrate_legacy_dates(db: &Arc<Database>) {
    let rows = match db.list_non_rfc3339_dates() {
        Ok(r) if !r.is_empty() => r,
        _ => return,
    };
    let mut fixed = 0usize;
    for (id, date) in rows {
        let normalized = normalize_date_rfc3339(&date);
        if normalized != date && db.set_message_date(&id, &normalized).is_ok() {
            fixed += 1;
        }
    }
    if fixed > 0 {
        tracing::info!("sync: normalized {} legacy cached date(s)", fixed);
    }
}

async fn report_envelope_capability(session: &Arc<RwLock<Session>>, client: &Arc<ApiClient>) {
    let Ok(data_dir) = crate::config::data_dir() else {
        return;
    };
    let (access_token, user_id, identity_public) = {
        let guard = session.read().await;
        (
            guard.access_token.to_string(),
            guard.user_id.to_string(),
            guard.ratchet_identity_public.clone(),
        )
    };
    crate::crypto::envelope_capability::report_if_due(
        client,
        &access_token,
        &user_id,
        identity_public.as_deref(),
        &data_dir,
    )
    .await;
}

pub async fn run_poll_loop(
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    db: Arc<Database>,
    jmap_broadcaster: Option<broadcast::Sender<StateChange>>,
    mut trigger_rx: SyncTriggerRx,
    poll_interval_secs: Option<u64>,
) {
    migrate_legacy_dates(&db);
    report_envelope_capability(&session, &client).await;
    let interval_secs = poll_interval_secs.filter(|&v| v >= 5).unwrap_or(POLL_INTERVAL_SECS);
    let interval_dur = std::time::Duration::from_secs(interval_secs);
    let mut interval = tokio::time::interval(interval_dur);
    let mut last_tick = tokio::time::Instant::now();
    let mut sync_count: u32 = 0;
    let mut last_deep_at: Option<tokio::time::Instant> = None;
    let mut last_triggered_at: Option<tokio::time::Instant> = None;
    let mut last_triggered_result: Result<(), String> = Ok(());
    let deep_due = |last: &Option<tokio::time::Instant>| {
        last.map_or(true, |t| {
            t.elapsed() >= std::time::Duration::from_secs(DEEP_SYNC_INTERVAL_SECS)
        })
    };

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
                let deep = deep_due(&last_deep_at);
                let result = run_sync_pass(&session, &client, &db, jmap_broadcaster.as_ref(), deep).await;
                if deep && result.is_ok() {
                    last_deep_at = Some(tokio::time::Instant::now());
                    report_envelope_capability(&session, &client).await;
                }
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
                let mut waiting = vec![trigger.done];
                while let Ok(queued) = trigger_rx.try_recv() {
                    waiting.push(queued.done);
                }
                let cooling = last_triggered_at
                    .map_or(false, |at| at.elapsed() < TRIGGER_COOLDOWN);
                if cooling {
                    let replay = last_triggered_result.clone();
                    for done in waiting {
                        let _ = done.send(replay.clone());
                    }
                    continue;
                }
                last_triggered_at = Some(tokio::time::Instant::now());
                last_tick = tokio::time::Instant::now();
                let deep = deep_due(&last_deep_at);
                let result = run_sync_pass(&session, &client, &db, jmap_broadcaster.as_ref(), deep).await;
                if deep && result.is_ok() {
                    last_deep_at = Some(tokio::time::Instant::now());
                }
                if let Err(ref e) = result {
                    if e.contains("plan_upgrade_required") {
                        tracing::warn!("sync: plan_upgrade_required from server - stopping poll loop");
                        emit_bridge_access_revoked();
                        for done in waiting {
                            let _ = done.send(Err(e.clone()));
                        }
                        return;
                    }
                }
                last_triggered_result = result.clone();
                interval.reset();
                for done in waiting {
                    let _ = done.send(result.clone());
                }
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
            is_read: None,
            is_starred: None,
            has_attachments: None,
            attachment_count: None,
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
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
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
        let was_new = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new;
        assert!(was_new);

        let cached = db.get_cached_message("msg-new").unwrap().unwrap();
        assert_eq!(cached.folder, "inbox");
        assert_eq!(cached.subject.as_deref(), Some("Hello"));
        assert_eq!(cached.sender.as_deref(), Some("Alice <alice@example.com>"));
        assert_eq!(cached.recipients.as_deref(), Some("bob@example.com"));
        assert_eq!(cached.date.as_deref(), Some("2026-05-21T10:00:00+00:00"));
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
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

        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let first = db.get_cached_message("msg-move").unwrap().unwrap();
        assert_eq!(first.folder, "inbox");
        let inbox_uid = first.imap_uid;

        let was_new = cache_mail_item(&db, "archive", &item, b"pass", None, &[]).was_new;
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

        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        assert_eq!(db.count_cached_messages("inbox").unwrap(), 1);
    }

    #[test]
    fn cache_mail_item_skips_on_undecryptable_envelope() {
        let (_dir, db) = temp_db();
        let mut item = item_with_envelope("msg-bad-env", &serde_json::json!({"subject": "x"}));
        item.encrypted_envelope = "!!!not-base64!!!".to_string();
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        assert!(db.get_cached_message("msg-bad-env").unwrap().is_none());
    }

    #[test]
    fn cache_mail_item_truncates_oversized_body() {
        let (_dir, db) = temp_db();
        let big = "a".repeat(6 * 1024 * 1024);
        let json = serde_json::json!({"subject": "s", "body_text": big});
        let item = item_with_envelope("msg-big", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let cached = db.get_cached_message("msg-big").unwrap().unwrap();
        let body = cached.body_text.unwrap();
        assert!(body.len() < 6 * 1024 * 1024);
        assert!(body.ends_with("[truncated]"));
    }

    #[test]
    fn cache_mail_item_records_envelope_nonce_and_survives_re_encryption() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let nonce_pbkdf2 = STANDARD.encode([0x01u8]);

        let mut first = item_with_envelope("msg-replay", &json);
        first.envelope_nonce = nonce_pbkdf2.clone();
        let _ = cache_mail_item(&db, "inbox", &first, b"pass", None, &[]);
        assert_eq!(
            db.replay_check_and_record("msg-replay", &nonce_pbkdf2).unwrap(),
            true,
            "same nonce must be accepted"
        );
        assert_eq!(
            db.replay_check_and_record("msg-replay", &STANDARD.encode([0x02u8])).unwrap(),
            true,
            "a server-side re-encryption rotates the nonce and must not lock the item out"
        );
    }

    #[test]
    fn cache_mail_item_still_caches_an_item_whose_nonce_rotated_before_first_decrypt() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "rotated", "body_text": "b"});

        let mut undecryptable = item_with_envelope("msg-rotate", &json);
        undecryptable.envelope_nonce = STANDARD.encode([0x09u8]);
        undecryptable.encrypted_envelope = STANDARD.encode(b"not decryptable");
        let first = cache_mail_item(&db, "inbox", &undecryptable, b"pass", None, &[]);
        assert!(!first.was_new, "an undecryptable item must not be cached");
        assert!(!db.body_cached("msg-rotate"));

        let re_encrypted = item_with_envelope("msg-rotate", &json);
        assert!(
            cache_mail_item(&db, "inbox", &re_encrypted, b"pass", None, &[]).was_new,
            "the re-encrypted copy must still be accepted after the nonce changed"
        );
        assert!(db.body_cached("msg-rotate"));
    }

    #[test]
    fn cache_mail_item_leaves_inbound_mail_uncached_when_no_inbound_keys_are_loaded() {
        let (_dir, db) = temp_db();
        let mut item = item_with_envelope("msg-no-keys", &serde_json::json!({"subject": "s"}));
        let mut envelope = vec![crate::crypto::inbound::INBOUND_ECDH_MARKER];
        envelope.extend_from_slice(&[0x04u8; 96]);
        item.encrypted_envelope = STANDARD.encode(&envelope);
        item.envelope_nonce = STANDARD.encode([0x01u8; 12]);

        assert!(
            crate::crypto::inbound::is_inbound_payload(
                &item.encrypted_envelope,
                &item.envelope_nonce
            ),
            "the fixture must be recognized as inbound so the no-keys branch is reached"
        );

        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]);

        assert!(!outcome.was_new, "inbound mail must not be cached without keys");
        assert!(
            !db.body_cached("msg-no-keys"),
            "no blank body may be written when the inbound keys are missing"
        );
    }

    fn inbound_candidate(sk: &p256::SecretKey) -> crate::crypto::inbound::InboundKeyCandidate {
        crate::crypto::inbound::InboundKeyCandidate {
            ecdh_secret_d: sk.to_bytes().to_vec(),
            pq_decap_key: None,
        }
    }

    fn encrypt_inbound_ecdh(
        plaintext: &[u8],
        recipient: &p256::SecretKey,
        nonce_bytes: &[u8; 12],
    ) -> Vec<u8> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use hkdf::Hkdf;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use sha2::Sha256;
        let recipient_pub = recipient.public_key().to_encoded_point(false);
        let ephemeral = p256::SecretKey::random(&mut rand_core::OsRng);
        let eph_pub = ephemeral.public_key().to_encoded_point(false);
        let shared_x = crate::crypto::ratchet::ecdh_p256(
            ephemeral.to_bytes().as_slice(),
            recipient_pub.as_bytes(),
        )
        .unwrap();
        let hk = Hkdf::<Sha256>::new(None, &shared_x);
        let mut key = [0u8; 32];
        hk.expand(b"aster-inbound-v1", &mut key).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(plaintext, 6);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce_bytes), compressed.as_slice())
            .unwrap();
        let mut out = vec![crate::crypto::inbound::INBOUND_ECDH_MARKER];
        out.extend_from_slice(eph_pub.as_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    fn inbound_item(id: &str, json: &serde_json::Value, recipient: &p256::SecretKey) -> MailItem {
        let nonce = [7u8; 12];
        let payload = encrypt_inbound_ecdh(json.to_string().as_bytes(), recipient, &nonce);
        let mut item = item_with_envelope(id, json);
        item.encrypted_envelope = STANDARD.encode(&payload);
        item.envelope_nonce = STANDARD.encode(nonce);
        item
    }

    #[test]
    fn heal_cooldown_prevents_repeated_refreshes() {
        let state = StdMutex::new(None);
        let start = std::time::Instant::now();
        let secs = std::time::Duration::from_secs;
        assert!(take_heal_permit(&state, start));
        assert!(!take_heal_permit(&state, start + secs(1)));
        assert!(!take_heal_permit(&state, start + secs(299)));
        assert!(take_heal_permit(&state, start + secs(300)));
        assert!(!take_heal_permit(&state, start + secs(301)));
    }

    #[test]
    fn failed_inbound_item_is_flagged_and_recovers_after_key_refresh() {
        let (_dir, db) = temp_db();
        let recipient = p256::SecretKey::random(&mut rand_core::OsRng);
        let wrong = p256::SecretKey::random(&mut rand_core::OsRng);
        let json = serde_json::json!({"subject": "sealed", "body_text": "inbound body"});
        let item = inbound_item("msg-heal", &json, &recipient);

        let stale_keys = [inbound_candidate(&wrong)];
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &stale_keys);
        assert!(!outcome.was_new);
        assert!(outcome.inbound_decrypt_failed);
        assert!(!db.body_cached("msg-heal"));

        let fresh_keys = [inbound_candidate(&recipient)];
        let failed = vec![("inbox", item.clone())];
        let (new_ids, updated_ids) =
            retry_failed_inbound_items(&db, &failed, b"pass", None, &fresh_keys);
        assert_eq!(new_ids, vec!["msg-heal".to_string()]);
        assert!(updated_ids.is_empty());
        let cached = db.get_cached_message("msg-heal").unwrap().unwrap();
        assert_eq!(cached.subject.as_deref(), Some("sealed"));
        assert_eq!(cached.body_text.as_deref(), Some("inbound body"));
    }

    #[test]
    fn unrecoverable_inbound_item_stays_uncached_after_retry() {
        let (_dir, db) = temp_db();
        let recipient = p256::SecretKey::random(&mut rand_core::OsRng);
        let wrong = p256::SecretKey::random(&mut rand_core::OsRng);
        let json = serde_json::json!({"subject": "sealed"});
        let item = inbound_item("msg-unhealable", &json, &recipient);

        let stale_keys = [inbound_candidate(&wrong)];
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &stale_keys);
        assert!(outcome.inbound_decrypt_failed);

        let failed = vec![("inbox", item)];
        let (new_ids, updated_ids) =
            retry_failed_inbound_items(&db, &failed, b"pass", None, &stale_keys);
        assert!(new_ids.is_empty());
        assert!(updated_ids.is_empty());
        assert!(!db.body_cached("msg-unhealable"));
    }

    #[test]
    fn successful_decrypt_does_not_flag_inbound_failure() {
        let (_dir, db) = temp_db();
        let recipient = p256::SecretKey::random(&mut rand_core::OsRng);
        let json = serde_json::json!({"subject": "ok", "body_text": "b"});
        let item = inbound_item("msg-inbound-ok", &json, &recipient);
        let keys = [inbound_candidate(&recipient)];
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &keys);
        assert!(outcome.was_new);
        assert!(!outcome.inbound_decrypt_failed);
    }

    #[test]
    fn normalize_date_converts_rfc2822_to_rfc3339() {
        let out = normalize_date_rfc3339("Wed, 21 May 2026 10:00:00 +0000");
        assert!(chrono::DateTime::parse_from_rfc3339(&out).is_ok(), "got {}", out);
        assert_eq!(normalize_date_rfc3339("2026-05-21T10:00:00Z"), "2026-05-21T10:00:00Z");
        assert_eq!(normalize_date_rfc3339("not a date"), "not a date");
    }

    #[test]
    fn cache_mail_item_normalizes_rfc2822_dates() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({
            "subject": "s",
            "body_text": "b",
            "date": "Wed, 21 May 2026 10:00:00 +0000"
        });
        let item = item_with_envelope("msg-date-norm", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let cached = db.get_cached_message("msg-date-norm").unwrap().unwrap();
        let stored = cached.date.unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(&stored).is_ok(),
            "stored date not rfc3339: {}",
            stored
        );
    }

    #[test]
    fn migrate_legacy_dates_normalizes_rfc2822_rows() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        db.upsert_cached_message(
            "legacy-1",
            "inbox",
            Some("s"),
            Some("a@b.com"),
            Some("c@d.com"),
            Some("Thu, 21 May 2026 10:00:00 +0000"),
            10,
            Some("body"),
            Some("{}"),
        )
        .unwrap();
        db.upsert_cached_message(
            "modern-1",
            "inbox",
            Some("s"),
            Some("a@b.com"),
            Some("c@d.com"),
            Some("2026-05-22T09:00:00+00:00"),
            10,
            Some("body"),
            Some("{}"),
        )
        .unwrap();

        migrate_legacy_dates(&db);

        let legacy = db.get_cached_message("legacy-1").unwrap().unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(legacy.date.as_deref().unwrap()).is_ok(),
            "legacy date not migrated: {:?}",
            legacy.date
        );
        let modern = db.get_cached_message("modern-1").unwrap().unwrap();
        assert_eq!(modern.date.as_deref(), Some("2026-05-22T09:00:00+00:00"));
    }

    #[test]
    fn new_message_applies_server_read_state() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let mut item = item_with_envelope("msg-read-new", &json);
        item.is_read = Some(true);
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]);
        assert!(outcome.was_new);
        assert!(!outcome.flags_changed);
        let cached = db.get_cached_message("msg-read-new").unwrap().unwrap();
        assert_eq!(cached.flags & 1, 1);
    }

    #[test]
    fn cached_message_read_on_server_updates_local_seen_flag() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let mut item = item_with_envelope("msg-read-sync", &json);
        item.is_read = Some(false);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        assert_eq!(
            db.get_cached_message("msg-read-sync").unwrap().unwrap().flags & 1,
            0
        );

        item.is_read = Some(true);
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]);
        assert!(!outcome.was_new);
        assert!(outcome.flags_changed);
        assert_eq!(
            db.get_cached_message("msg-read-sync").unwrap().unwrap().flags & 1,
            1
        );

        let repeat = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]);
        assert!(!repeat.flags_changed, "no-op flag sync must not report change");
    }

    #[test]
    fn cached_message_starred_on_server_updates_local_flagged_bit() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let mut item = item_with_envelope("msg-star-sync", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);

        item.is_starred = Some(true);
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]);
        assert!(outcome.flags_changed);
        assert_eq!(
            db.get_cached_message("msg-star-sync").unwrap().unwrap().flags & 4,
            4
        );

        item.is_starred = Some(false);
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]);
        assert!(outcome.flags_changed);
        assert_eq!(
            db.get_cached_message("msg-star-sync").unwrap().unwrap().flags & 4,
            0
        );
    }

    #[test]
    fn server_flags_absent_leaves_local_flags_untouched() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let item = item_with_envelope("msg-noflags", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let uid = db.get_cached_message("msg-noflags").unwrap().unwrap().imap_uid;
        db.update_message_flags(uid as i64, "inbox", 5).unwrap();

        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[]);
        assert!(!outcome.flags_changed);
        assert_eq!(db.get_cached_message("msg-noflags").unwrap().unwrap().flags, 5);
    }

    fn mock_session() -> Arc<RwLock<crate::auth::session::Session>> {
        Arc::new(RwLock::new(crate::auth::session::Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: b"pass".to_vec(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
        }))
    }

    async fn spawn_mock_list_server(items: Vec<serde_json::Value>) -> String {
        use axum::{routing::get, Json, Router};
        let total = items.len();
        let body = serde_json::json!({
            "items": items,
            "total": total,
            "has_more": false,
            "next_cursor": serde_json::Value::Null
        });
        let app = Router::new().route(
            "/bridge/v1/messages",
            get(move || {
                let body = body.clone();
                async move { Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn server_item_json(id: &str, subject: &str) -> serde_json::Value {
        let env = envelope_b64(&serde_json::json!({"subject": subject, "body_text": "b"}));
        serde_json::json!({
            "id": id,
            "item_type": "received",
            "encrypted_envelope": env,
            "envelope_nonce": "",
            "folder_token": "tok",
            "is_external": false,
            "created_at": "2026-06-14T00:00:00Z"
        })
    }

    async fn spawn_mock_server_with_drafts(
        items: Vec<serde_json::Value>,
        drafts: Vec<serde_json::Value>,
    ) -> String {
        use axum::{routing::get, Json, Router};
        let total = items.len();
        let body = serde_json::json!({
            "items": items,
            "total": total,
            "has_more": false,
            "next_cursor": serde_json::Value::Null
        });
        let drafts_body = serde_json::json!({
            "items": drafts,
            "has_more": false,
            "next_cursor": serde_json::Value::Null
        });
        let app = Router::new()
            .route(
                "/bridge/v1/messages",
                get(move || {
                    let body = body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/mail/v1/drafts",
                get(move || {
                    let drafts_body = drafts_body.clone();
                    async move { Json(drafts_body) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn mock_session_with_identity_key(ik: &str) -> Arc<RwLock<crate::auth::session::Session>> {
        Arc::new(RwLock::new(crate::auth::session::Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: b"pass".to_vec(),
            identity_key: Some(ik.to_string()),
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
        }))
    }

    #[tokio::test]
    async fn web_drafts_sync_into_drafts_folder() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);

        let content = crate::crypto::draft::DraftContent {
            to_recipients: vec!["bruno@example.com".to_string()],
            cc_recipients: vec!["copy@example.com".to_string()],
            bcc_recipients: vec![],
            subject: "web draft".to_string(),
            message: "<p>bozza</p>".to_string(),
            attachments: None,
        };
        let (enc, nonce) =
            crate::crypto::draft::encrypt_draft_content(&content, "test-ik").unwrap();
        let draft_json = serde_json::json!({
            "id": "web-draft-1",
            "draft_type": "new",
            "encrypted_content": enc,
            "content_nonce": nonce,
            "version": 3,
            "has_attachments": false,
            "attachment_count": 0,
            "created_at": "2026-08-01T00:00:00Z",
            "updated_at": "2026-08-01T12:00:00Z"
        });
        let base = spawn_mock_server_with_drafts(vec![], vec![draft_json]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session_with_identity_key("test-ik");

        run_sync_pass(&session, &client, &db, None, true)
            .await
            .unwrap();

        let cached = db.get_cached_message("web-draft-1").unwrap().unwrap();
        assert_eq!(cached.folder, "drafts");
        assert_eq!(cached.subject.as_deref(), Some("web draft"));
        assert_eq!(cached.recipients.as_deref(), Some("bruno@example.com"));
        assert!(cached.body_text.unwrap_or_default().contains("bozza"));
        assert!(cached.flags & 16 != 0, "draft flag missing: {}", cached.flags);
        assert!(cached.imap_uid > 0);

        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta.get("draft_api"), Some(&serde_json::json!(true)));
        assert_eq!(meta.get("draft_version"), Some(&serde_json::json!(3)));
        assert_eq!(meta.get("cc"), Some(&serde_json::json!("copy@example.com")));

        run_sync_pass(&session, &client, &db, None, true)
            .await
            .unwrap();
        assert_eq!(db.count_cached_messages("drafts").unwrap(), 1);
        assert!(db.get_cached_message("web-draft-1").unwrap().is_some());
    }

    #[test]
    fn web_draft_attachments_are_cached_for_the_drafts_folder() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let (_dir, db) = temp_db();
        let content = crate::crypto::draft::DraftContent {
            to_recipients: vec!["bruno@example.com".to_string()],
            subject: "with files".to_string(),
            message: "<p>see attached</p>".to_string(),
            attachments: Some(vec![
                crate::crypto::draft::DraftAttachment {
                    id: "a1".to_string(),
                    name: "report.pdf".to_string(),
                    size: "9 B".to_string(),
                    size_bytes: 9,
                    mime_type: "application/pdf".to_string(),
                    data_base64: STANDARD.encode(b"hello pdf"),
                    content_id: None,
                },
                crate::crypto::draft::DraftAttachment {
                    id: "a2".to_string(),
                    name: "".to_string(),
                    size: "4 B".to_string(),
                    size_bytes: 4,
                    mime_type: "image/png".to_string(),
                    data_base64: STANDARD.encode(b"\x89PNG"),
                    content_id: Some("pic@aster".to_string()),
                },
                crate::crypto::draft::DraftAttachment {
                    id: "a3".to_string(),
                    name: "broken.bin".to_string(),
                    size: "0 B".to_string(),
                    size_bytes: 0,
                    mime_type: "application/octet-stream".to_string(),
                    data_base64: "not base64!!".to_string(),
                    content_id: None,
                },
            ]),
            ..Default::default()
        };
        cache_web_draft(&db, "web-draft-att", &content, "tester@aster.test", "2026-08-01T00:00:00Z", 2);

        let cached = db.get_cached_message("web-draft-att").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_STORED);
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta.get("attachment_count"), Some(&serde_json::json!(2)));

        let rows = db.get_message_attachments("web-draft-att").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].seq, 0);
        assert_eq!(rows[0].name, "report.pdf");
        assert_eq!(rows[0].content_type, "application/pdf");
        assert_eq!(rows[0].data, b"hello pdf");
        assert!(!rows[0].is_inline);
        assert_eq!(rows[1].seq, 1);
        assert_eq!(rows[1].name, "attachment-2");
        assert_eq!(rows[1].content_id.as_deref(), Some("pic@aster"));
        assert!(rows[1].is_inline);
        assert_eq!(rows[1].size, 4);

        let without = crate::crypto::draft::DraftContent {
            subject: "with files".to_string(),
            message: "<p>removed</p>".to_string(),
            ..Default::default()
        };
        cache_web_draft(&db, "web-draft-att", &without, "tester@aster.test", "2026-08-02T00:00:00Z", 3);
        let cached = db.get_cached_message("web-draft-att").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_NONE);
        assert!(db.get_message_attachments("web-draft-att").unwrap().is_empty());
    }

    #[tokio::test]
    async fn deep_sync_prunes_web_draft_deleted_on_server() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);

        let content = crate::crypto::draft::DraftContent {
            subject: "stale".to_string(),
            message: "x".to_string(),
            ..Default::default()
        };
        cache_web_draft(&db, "web-draft-gone", &content, "tester@aster.test", "2026-08-01T00:00:00Z", 1);
        assert!(db.get_cached_message("web-draft-gone").unwrap().is_some());

        let base = spawn_mock_server_with_drafts(vec![], vec![]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session_with_identity_key("test-ik");

        run_sync_pass(&session, &client, &db, None, true)
            .await
            .unwrap();

        assert!(db.get_cached_message("web-draft-gone").unwrap().is_none());
    }

    #[tokio::test]
    async fn deep_sync_prunes_messages_deleted_on_server() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let stale = item_with_envelope(
            "stale-1",
            &serde_json::json!({"subject": "old", "body_text": "b"}),
        );
        assert!(cache_mail_item(&db, "inbox", &stale, b"pass", None, &[]).was_new);

        let base = spawn_mock_list_server(vec![server_item_json("keep-1", "kept")]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();
        let (tx, mut rx) = broadcast::channel(8);

        run_sync_pass(&session, &client, &db, Some(&tx), true)
            .await
            .unwrap();

        assert!(
            db.get_cached_message("stale-1").unwrap().is_none(),
            "server-deleted message must be pruned locally"
        );
        assert!(db.get_cached_message("keep-1").unwrap().is_some());

        let destroyed: i64 = db
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM jmap_change_log WHERE op = 'destroyed' AND object_id = 'stale-1'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(destroyed, 1);

        let change = rx.try_recv().expect("state change must be broadcast");
        assert!(change.changed.contains_key("Email"));
    }

    #[tokio::test]
    async fn shallow_sync_does_not_prune() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let stale = item_with_envelope(
            "stale-2",
            &serde_json::json!({"subject": "old", "body_text": "b"}),
        );
        assert!(cache_mail_item(&db, "inbox", &stale, b"pass", None, &[]).was_new);

        let base = spawn_mock_list_server(vec![server_item_json("keep-2", "kept")]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();

        run_sync_pass(&session, &client, &db, None, false)
            .await
            .unwrap();

        assert!(
            db.get_cached_message("stale-2").unwrap().is_some(),
            "shallow sync must never prune"
        );
    }

    #[tokio::test]
    async fn deep_sync_does_not_prune_when_a_folder_fails() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let stale = item_with_envelope(
            "stale-3",
            &serde_json::json!({"subject": "old", "body_text": "b"}),
        );
        assert!(cache_mail_item(&db, "inbox", &stale, b"pass", None, &[]).was_new);

        use axum::{routing::get, Router};
        let app = Router::new().route(
            "/bridge/v1/messages",
            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = Arc::new(ApiClient::new_with_base_url(&format!(
            "http://127.0.0.1:{}",
            port
        )));
        let session = mock_session();

        let result = run_sync_pass(&session, &client, &db, None, true).await;
        assert!(result.is_err());
        assert!(
            db.get_cached_message("stale-3").unwrap().is_some(),
            "failed sync must never prune"
        );
    }

    #[tokio::test]
    async fn deep_sync_marks_web_read_message_seen() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let unread = item_with_envelope(
            "read-on-web",
            &serde_json::json!({"subject": "s", "body_text": "b"}),
        );
        assert!(cache_mail_item(&db, "inbox", &unread, b"pass", None, &[]).was_new);

        let mut item = server_item_json("read-on-web", "s");
        item["is_read"] = serde_json::json!(true);
        let base = spawn_mock_list_server(vec![item]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();
        let (tx, mut rx) = broadcast::channel(8);

        run_sync_pass(&session, &client, &db, Some(&tx), false)
            .await
            .unwrap();

        assert_eq!(
            db.get_cached_message("read-on-web").unwrap().unwrap().flags & 1,
            1,
            "web-read message must become \\Seen on the bridge"
        );
        let change = rx.try_recv().expect("flag change must broadcast state");
        assert!(change.changed.contains_key("Email"));
    }

    #[test]
    fn envelope_attachment_count_reads_the_key_list() {
        let v = serde_json::json!({"attachment_keys": [{"seq": 0, "key": "k0"}, {"seq": 1, "key": "k1"}]});
        assert_eq!(parse_envelope_attachments(&v).len(), 2);
    }

    #[test]
    fn envelope_attachment_count_is_zero_when_absent_or_wrong_type() {
        assert_eq!(parse_envelope_attachments(&serde_json::json!({})).len(), 0);
        assert_eq!(
            parse_envelope_attachments(&serde_json::json!({"attachment_keys": null})).len(),
            0
        );
        assert_eq!(
            parse_envelope_attachments(&serde_json::json!({"attachment_keys": "two"})).len(),
            0
        );
        assert_eq!(
            parse_envelope_attachments(&serde_json::json!({"attachment_keys": ["k0", 3]})).len(),
            0
        );
    }

    #[test]
    fn attachment_entries_are_matched_by_seq_not_by_position() {
        let v = serde_json::json!({"attachment_keys": [
            {"seq": 2, "key": "k2", "filename": "third.txt", "content_type": "text/plain", "size": 3},
            {"seq": 0, "key": "k0", "filename": "first.pdf", "content_type": "application/pdf", "size": 1},
            {"seq": 1, "key": "k1", "filename": "second.png", "content_type": "image/png", "size": 2}
        ]});
        let parsed = parse_envelope_attachments(&v);
        let names: Vec<String> = parsed.iter().map(attachment_display_name).collect();
        assert_eq!(names, vec!["first.pdf", "second.png", "third.txt"]);
        assert_eq!(
            parsed.iter().map(|a| a.seq).collect::<Vec<_>>(),
            vec![Some(0), Some(1), Some(2)]
        );
    }

    #[test]
    fn a_repeated_seq_is_counted_once() {
        let v = serde_json::json!({"attachment_keys": [
            {"seq": 0, "key": "k0", "filename": "keep.txt"},
            {"seq": 0, "key": "k0b", "filename": "drop.txt"}
        ]});
        let parsed = parse_envelope_attachments(&v);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].filename.as_deref(), Some("keep.txt"));
    }

    #[test]
    fn a_missing_filename_falls_back_to_the_placeholder() {
        let v = serde_json::json!({"attachment_keys": [{"seq": 0, "key": "k0"}]});
        let parsed = parse_envelope_attachments(&v);
        assert_eq!(parsed[0].filename, None);
        assert_eq!(attachment_display_name(&parsed[0]), "Attachment");
    }

    #[test]
    fn a_missing_or_malformed_content_type_falls_back_to_octet_stream() {
        let v = serde_json::json!({"attachment_keys": [
            {"seq": 0, "key": "k0"},
            {"seq": 1, "key": "k1", "content_type": "   "},
            {"seq": 2, "key": "k2", "content_type": "notamimetype"},
            {"seq": 3, "key": "k3", "content_type": "Application/PDF"}
        ]});
        let parsed = parse_envelope_attachments(&v);
        assert_eq!(parsed[0].content_type, "application/octet-stream");
        assert_eq!(parsed[1].content_type, "application/octet-stream");
        assert_eq!(parsed[2].content_type, "application/octet-stream");
        assert_eq!(parsed[3].content_type, "application/pdf");
    }

    #[test]
    fn a_missing_content_id_is_never_synthesized() {
        let v = serde_json::json!({"attachment_keys": [
            {"seq": 0, "key": "k0", "filename": "a.pdf"},
            {"seq": 1, "key": "k1", "filename": "b.png", "content_id": "cid-42"}
        ]});
        let parsed = parse_envelope_attachments(&v);
        assert_eq!(parsed[0].content_id, None);
        assert_eq!(parsed[1].content_id.as_deref(), Some("cid-42"));
    }

    #[test]
    fn cached_attachment_metadata_is_persisted_for_jmap() {
        let (_dir, db) = temp_db();
        let item = item_with_envelope(
            "described-attachments",
            &serde_json::json!({
                "subject": "invoice",
                "body_text": "see attached",
                "attachment_keys": [
                    {"seq": 1, "key": "k1", "filename": "b.png", "content_type": "image/png", "size": 2, "content_id": "cid-9"},
                    {"seq": 0, "key": "k0", "filename": "a.pdf", "content_type": "application/pdf", "size": 11}
                ]
            }),
        );
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);

        let cached = db.get_cached_message("described-attachments").unwrap().unwrap();
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta.get("attachment_count").and_then(|v| v.as_u64()), Some(2));
        let list = meta.get("attachments").and_then(|v| v.as_array()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].get("name").and_then(|v| v.as_str()), Some("a.pdf"));
        assert_eq!(list[0].get("seq").and_then(|v| v.as_i64()), Some(0));
        assert!(list[0].get("cid").is_none());
        assert_eq!(list[1].get("cid").and_then(|v| v.as_str()), Some("cid-9"));
        assert_eq!(list[1].get("size").and_then(|v| v.as_i64()), Some(2));
    }

    #[test]
    fn a_message_without_attachments_stores_no_attachment_list() {
        let (_dir, db) = temp_db();
        let item = item_with_envelope(
            "no-attachment-list",
            &serde_json::json!({"subject": "hi", "body_text": "plain"}),
        );
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let cached = db.get_cached_message("no-attachment-list").unwrap().unwrap();
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert!(meta.get("attachments").is_none());
    }

    #[test]
    fn a_message_without_attachments_keeps_its_body_untouched() {
        let (_dir, db) = temp_db();
        let item = item_with_envelope(
            "no-attachments",
            &serde_json::json!({"subject": "hi", "body_text": "plain body"}),
        );
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);

        let cached = db.get_cached_message("no-attachments").unwrap().unwrap();
        assert_eq!(cached.body_text.as_deref(), Some("plain body"));
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta.get("attachment_count").and_then(|v| v.as_u64()), Some(0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_storm_of_sync_triggers_cannot_hammer_the_backend() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        drop(stream);
                    }
                    Err(_) => break,
                }
            }
        });

        let (dir, db) = temp_db();
        let session = mock_session();
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let (tx, rx) = sync_trigger_channel();
        let loop_handle = tokio::spawn(run_poll_loop(
            session,
            client,
            Arc::new(db),
            None,
            rx,
            Some(3600),
        ));

        let storm_started = tokio::time::Instant::now();
        while storm_started.elapsed() < std::time::Duration::from_secs(2) {
            let (done, _rx) = oneshot::channel();
            let _ = tx.try_send(SyncTrigger { done });
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let seen = attempts.load(std::sync::atomic::Ordering::SeqCst);
        loop_handle.abort();
        drop(dir);

        assert!(
            seen < 40,
            "a two second trigger storm produced {} backend connections, which is the runaway that pins the processor when the network is down",
            seen
        );
    }


    #[test]
    fn a_missing_or_negative_size_is_dropped() {
        let v = serde_json::json!({"attachment_keys": [
            {"seq": 0, "key": "k0", "filename": "a.pdf", "content_type": "application/pdf"},
            {"seq": 1, "key": "k1", "filename": "b.png", "content_type": "image/png", "size": -4},
            {"seq": 2, "key": "k2", "filename": "c.bin", "content_type": "text/plain", "size": 2048}
        ]});
        let parsed = parse_envelope_attachments(&v);
        assert_eq!(parsed[0].size, None);
        assert_eq!(parsed[1].size, None);
        assert_eq!(parsed[2].size, Some(2048));
        assert_eq!(parsed[2].key.as_deref(), Some("k2"));
    }

    #[test]
    fn a_message_with_attachments_is_marked_pending_and_keeps_its_body() {
        let (_dir, db) = temp_db();
        let item = item_with_envelope(
            "with-attachments",
            &serde_json::json!({
                "subject": "invoice",
                "body_text": "see attached",
                "attachment_keys": [
                    {"seq": 0, "key": "k0", "filename": "a.pdf", "content_type": "application/pdf", "size": 11},
                    {"seq": 1, "key": "k1"}
                ]
            }),
        );
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);

        let cached = db.get_cached_message("with-attachments").unwrap().unwrap();
        assert_eq!(cached.body_text.as_deref(), Some("see attached"));
        assert_eq!(cached.attachments_state, ATTACHMENTS_PENDING);
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta.get("attachment_count").and_then(|v| v.as_u64()), Some(2));
        let list = meta.get("attachments").and_then(|v| v.as_array()).unwrap();
        assert_eq!(list[0].get("key").and_then(|v| v.as_str()), Some("k0"));
        assert_eq!(list[1].get("key").and_then(|v| v.as_str()), Some("k1"));
        assert_eq!(list[1].get("name").and_then(|v| v.as_str()), Some("Attachment"));
    }

    #[test]
    fn an_attacker_named_file_never_reaches_the_body() {
        let (_dir, db) = temp_db();
        let item = item_with_envelope(
            "html-injection",
            &serde_json::json!({
                "subject": "report",
                "body_html": "<p>hello</p>",
                "attachment_keys": [{
                    "seq": 0,
                    "key": "k0",
                    "filename": "<img src=x onerror=alert(1)>.png",
                    "content_type": "image/png",
                    "size": 4
                }]
            }),
        );
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let cached = db.get_cached_message("html-injection").unwrap().unwrap();
        assert_eq!(cached.body_text.as_deref(), Some("<p>hello</p>"));
        assert_eq!(cached.attachments_state, ATTACHMENTS_PENDING);
    }

    #[test]
    fn a_body_less_message_with_attachments_is_pending() {
        let (_dir, db) = temp_db();
        let item = item_with_envelope(
            "only-attachments",
            &serde_json::json!({
                "subject": "scan",
                "attachment_keys": [{"seq": 0, "key": "k0"}]
            }),
        );
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let cached = db.get_cached_message("only-attachments").unwrap().unwrap();
        assert!(cached.body_text.as_deref().unwrap_or("").is_empty());
        assert_eq!(cached.attachments_state, ATTACHMENTS_PENDING);
        assert_eq!(db.list_attachment_backlog(10).unwrap().len(), 1);
    }

    #[test]
    fn a_message_without_attachments_is_never_pending() {
        let (_dir, db) = temp_db();
        let item = item_with_envelope(
            "no-attachments-state",
            &serde_json::json!({"subject": "hi", "body_text": "plain body"}),
        );
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let cached = db.get_cached_message("no-attachments-state").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_NONE);
        assert!(db.list_attachment_backlog(10).unwrap().is_empty());
    }

    #[test]
    fn the_server_count_marks_a_message_pending_even_without_keys() {
        let (_dir, db) = temp_db();
        let mut item = item_with_envelope(
            "count-only",
            &serde_json::json!({"subject": "hi", "body_text": "plain body"}),
        );
        item.attachment_count = Some(1);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[]).was_new);
        let cached = db.get_cached_message("count-only").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_PENDING);
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta.get("attachment_count").and_then(|v| v.as_u64()), Some(1));
    }

    #[test]
    fn cached_meta_entries_round_trip_into_download_entries() {
        let raw = serde_json::json!({
            "is_html": false,
            "attachment_count": 2,
            "attachments": [
                {"seq": 0, "name": "a.pdf", "type": "application/pdf", "size": 11, "key": "k0"},
                {"seq": 1, "name": "Attachment", "type": "application/octet-stream"}
            ]
        })
        .to_string();
        let entries = cached_attachment_entries(Some(&raw));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename.as_deref(), Some("a.pdf"));
        assert_eq!(entries[0].key.as_deref(), Some("k0"));
        assert_eq!(entries[1].filename, None);
        assert_eq!(entries[1].key, None);
        assert!(cached_attachment_entries(None).is_empty());
        assert!(cached_attachment_entries(Some("From: x\r\n")).is_empty());
    }

    #[test]
    fn merged_meta_keeps_other_fields_and_adds_keys() {
        let raw = serde_json::json!({"is_html": true, "message_id": "<m@x>", "attachment_count": 1, "attachments": [{"seq": 0, "name": "a.pdf", "type": "application/pdf"}]}).to_string();
        let fresh = parse_envelope_attachments(&serde_json::json!({"attachment_keys": [
            {"seq": 0, "key": "k0", "filename": "a.pdf", "content_type": "application/pdf", "size": 3}
        ]}));
        let merged: serde_json::Value =
            serde_json::from_str(&merge_attachment_meta(Some(&raw), &fresh)).unwrap();
        assert_eq!(merged.get("is_html"), Some(&serde_json::json!(true)));
        assert_eq!(merged.get("message_id"), Some(&serde_json::json!("<m@x>")));
        let list = merged.get("attachments").and_then(|v| v.as_array()).unwrap();
        assert_eq!(list[0].get("key").and_then(|v| v.as_str()), Some("k0"));
        assert_eq!(list[0].get("size").and_then(|v| v.as_i64()), Some(3));
    }

    fn sealed_attachment_row(
        seq: i16,
        key: &[u8; 32],
        plain: &[u8],
        filename: &str,
        content_type: &str,
    ) -> serde_json::Value {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let data_nonce = [7u8; 12];
        let aad = crate::crypto::attachment::attachment_data_aad(seq as i64);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&data_nonce),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .unwrap();
        let meta_nonce = [9u8; 12];
        let meta = serde_json::json!({"filename": filename, "content_type": content_type})
            .to_string();
        let sealed_meta = cipher
            .encrypt(Nonce::from_slice(&meta_nonce), meta.as_bytes())
            .unwrap();
        serde_json::json!({
            "id": format!("att-{}", seq),
            "mail_item_id": "mail-1",
            "encrypted_data": STANDARD.encode(ct),
            "data_nonce": STANDARD.encode(data_nonce),
            "encrypted_meta": STANDARD.encode(sealed_meta),
            "meta_nonce": STANDARD.encode(meta_nonce),
            "size_bytes": plain.len(),
            "seq_num": seq,
            "created_at": null
        })
    }

    fn server_item_with_envelope(id: &str, envelope: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "item_type": "received",
            "encrypted_envelope": envelope_b64(envelope),
            "envelope_nonce": "",
            "folder_token": "tok",
            "is_external": false,
            "created_at": "2026-06-14T00:00:00Z",
            "has_attachments": true,
            "attachment_count": 1
        })
    }

    async fn spawn_mock_attachment_server(
        listed: Vec<serde_json::Value>,
        single: serde_json::Value,
        attachments: Vec<serde_json::Value>,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use axum::{routing::get, Json, Router};
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        let total = listed.len();
        let list_body = serde_json::json!({
            "items": listed,
            "total": total,
            "has_more": false,
            "next_cursor": serde_json::Value::Null
        });
        let att_total = attachments.len();
        let att_body = serde_json::json!({"attachments": attachments, "total": att_total});
        let app = Router::new()
            .route(
                "/bridge/v1/messages",
                get(move || {
                    let body = list_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/bridge/v1/messages/:id",
                get(move || {
                    let body = single.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/mail/v1/attachments/by-mail/:id",
                get(move || {
                    let body = att_body.clone();
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Json(body) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{}", port), hits)
    }

    #[tokio::test]
    async fn a_new_message_downloads_and_stores_its_attachments_during_sync() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let key = [42u8; 32];
        let plain = b"%PDF-1.7 attachment payload".to_vec();
        let envelope = serde_json::json!({
            "subject": "invoice",
            "body_text": "see attached",
            "attachment_keys": [{
                "seq": 0,
                "key": STANDARD.encode(key),
                "filename": "report.pdf",
                "content_type": "application/pdf",
                "size": plain.len()
            }]
        });
        let item = server_item_with_envelope("mail-1", &envelope);
        let row = sealed_attachment_row(0, &key, &plain, "report.pdf", "application/pdf");
        let (base, hits) =
            spawn_mock_attachment_server(vec![item.clone()], item, vec![row]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();

        run_sync_pass(&session, &client, &db, None, false)
            .await
            .unwrap();

        let cached = db.get_cached_message("mail-1").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_STORED);
        assert_eq!(cached.body_text.as_deref(), Some("see attached"));
        assert!(cached.imap_uid > 0);
        let stored = db.get_message_attachments("mail-1").unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "report.pdf");
        assert_eq!(stored[0].content_type, "application/pdf");
        assert_eq!(stored[0].data, plain);
        assert_eq!(stored[0].size, plain.len() as i64);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(db.list_attachment_backlog(10).unwrap().is_empty());

        let rendered = crate::message_render::render_text(&cached, &stored);
        assert!(rendered.contains("Content-Type: multipart/mixed"));
        assert!(rendered.contains("filename=\"report.pdf\""));
        assert!(!rendered.contains("Aster Bridge cannot download"));
        assert!(!rendered.contains("still downloading"));

        run_sync_pass(&session, &client, &db, None, false)
            .await
            .unwrap();
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_legacy_cached_message_has_its_attachments_backfilled() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let key = [5u8; 32];
        let plain = b"PNG payload".to_vec();
        let legacy_body = "see attached\n\n[This message has 1 attachment that Aster Bridge cannot download yet: pic.png (image/png, 11 B). To get it, open the message in the Aster web or mobile app.]";
        let legacy_meta = serde_json::json!({
            "is_html": false,
            "message_id": null,
            "attachment_count": 1,
            "attachments": [{"seq": 0, "name": "pic.png", "type": "image/png", "size": 11}]
        })
        .to_string();
        db.upsert_cached_message(
            "mail-legacy",
            "inbox",
            Some("old"),
            Some("a@b.c"),
            Some("d@e.f"),
            Some("2026-06-14T00:00:00Z"),
            legacy_body.len() as i64,
            Some(legacy_body),
            Some(&legacy_meta),
        )
        .unwrap();
        db.set_attachments_state("mail-legacy", ATTACHMENTS_PENDING).unwrap();
        let first_uid = db.assign_uid_if_missing("inbox", "mail-legacy").unwrap();

        let envelope = serde_json::json!({
            "subject": "old",
            "body_text": "see attached",
            "attachment_keys": [{
                "seq": 0,
                "key": STANDARD.encode(key),
                "filename": "pic.png",
                "content_type": "image/png",
                "size": plain.len()
            }]
        });
        let single = server_item_with_envelope("mail-legacy", &envelope);
        let row = sealed_attachment_row(0, &key, &plain, "pic.png", "image/png");
        let (base, hits) = spawn_mock_attachment_server(vec![], single, vec![row]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();
        let (tx, mut rx) = broadcast::channel(4);

        run_sync_pass(&session, &client, &db, Some(&tx), false)
            .await
            .unwrap();

        let cached = db.get_cached_message("mail-legacy").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_STORED);
        assert_eq!(cached.body_text.as_deref(), Some("see attached"));
        assert!(cached.imap_uid > first_uid, "clients must refetch the rebuilt message");
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        let list = meta.get("attachments").and_then(|v| v.as_array()).unwrap();
        assert_eq!(list[0].get("key").and_then(|v| v.as_str()), Some(STANDARD.encode(key).as_str()));
        let stored = db.get_message_attachments("mail-legacy").unwrap();
        assert_eq!(stored[0].data, plain);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        let change = rx.try_recv().expect("backfill must broadcast a state change");
        assert!(change.changed.contains_key("Email"));
    }

    #[tokio::test]
    async fn an_undecryptable_attachment_counts_an_attempt_and_stays_pending() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let envelope = serde_json::json!({
            "subject": "broken",
            "body_text": "see attached",
            "attachment_keys": [{"seq": 0, "key": STANDARD.encode([1u8; 32]), "filename": "x.bin"}]
        });
        let item = server_item_with_envelope("mail-broken", &envelope);
        let row = sealed_attachment_row(0, &[2u8; 32], b"payload", "x.bin", "application/octet-stream");
        let (base, hits) =
            spawn_mock_attachment_server(vec![item.clone()], item, vec![row]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();

        run_sync_pass(&session, &client, &db, None, false)
            .await
            .unwrap();

        let cached = db.get_cached_message("mail-broken").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_PENDING);
        assert_eq!(cached.body_text.as_deref(), Some("see attached"));
        assert!(cached.imap_uid > 0);
        assert!(db.get_message_attachments("mail-broken").unwrap().is_empty());
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(db.bump_attachment_attempts("mail-broken").unwrap(), 2);

        run_sync_pass(&session, &client, &db, None, false)
            .await
            .unwrap();
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(db.attachments_state("mail-broken").unwrap(), ATTACHMENTS_PENDING);
    }

    #[tokio::test]
    async fn an_unreachable_attachment_endpoint_leaves_the_message_pending_without_an_attempt() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let envelope = serde_json::json!({
            "subject": "offline",
            "body_text": "see attached",
            "attachment_keys": [{"seq": 0, "key": STANDARD.encode([1u8; 32])}]
        });
        let item = server_item_with_envelope("mail-offline", &envelope);
        let base = spawn_mock_list_server(vec![item]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();

        run_sync_pass(&session, &client, &db, None, false)
            .await
            .unwrap();

        let cached = db.get_cached_message("mail-offline").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_PENDING);
        assert_eq!(cached.body_text.as_deref(), Some("see attached"));
        assert_eq!(db.bump_attachment_attempts("mail-offline").unwrap(), 2);
    }

}
