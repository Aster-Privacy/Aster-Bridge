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
use zeroize::{Zeroize, Zeroizing};

use crate::api_client::{ApiClient, MailItem, MailListQuery};
use crate::auth::session::Session;
use crate::crypto::envelope::decrypt_envelope_with_previous_keys;
use crate::crypto::attachment::{decrypt_attachment, AttachmentKeyEntry};
use crate::db::{
    CachedAttachment, CachedMessage, CachedSyncState, Database, ATTACHMENTS_FAILED, ATTACHMENTS_NONE, ATTACHMENTS_PENDING,
    ATTACHMENTS_STORED,
};
use crate::error::BridgeError;
use crate::jmap::state::StateChange;

const POLL_INTERVAL_SECS: u64 = 30;
const DEEP_SYNC_INTERVAL_SECS: u64 = 300;
const TRIGGER_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(5);
const RATE_LIMIT_PAUSE: std::time::Duration = std::time::Duration::from_secs(60);
const RATE_LIMIT_MESSAGE: &str = "sync paused: the server asked Aster Bridge to slow down";

fn is_rate_limit_message(message: &str) -> bool {
    message.contains("API error: 429")
}

fn sync_is_paused(paused_until: Option<tokio::time::Instant>, now: tokio::time::Instant) -> bool {
    paused_until.is_some_and(|until| now < until)
}

fn pause_after(result: &Result<(), String>, now: tokio::time::Instant) -> Option<tokio::time::Instant> {
    match result {
        Err(e) if e == RATE_LIMIT_MESSAGE => Some(now + RATE_LIMIT_PAUSE),
        _ => None,
    }
}

pub struct SyncTrigger {
    pub done: oneshot::Sender<Result<(), String>>,
}

pub type SyncTriggerTx = mpsc::Sender<SyncTrigger>;
pub type SyncTriggerRx = mpsc::Receiver<SyncTrigger>;

pub fn sync_trigger_channel() -> (SyncTriggerTx, SyncTriggerRx) {
    mpsc::channel(8)
}

static GLOBAL_SYNC_TRIGGER: OnceLock<StdMutex<Option<SyncTriggerTx>>> = OnceLock::new();

fn emit_sync_progress(
    folder: &str,
    done: usize,
    total: usize,
    folder_done: usize,
    folder_total: usize,
) {
    let progress = crate::events::SyncProgress {
        folder: folder.to_string(),
        done,
        total,
        folder_done,
        folder_total,
    };
    crate::events::emit(|sink| sink.sync_progress(&progress));
}

fn emit_sync_done(failed: bool) {
    crate::events::emit(|sink| sink.sync_done(failed));
}

fn emit_bridge_access_revoked() {
    crate::events::emit(|sink| sink.access_revoked());
}

pub fn emit_import_progress(progress: &crate::imap::append::ImportProgress) {
    crate::events::emit(|sink| sink.import_progress(progress));
}

pub fn notify_send_failed() {
    crate::events::emit(|sink| sink.send_failed());
}

pub fn emit_session_expired() {
    crate::events::emit(|sink| sink.session_expired());
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

pub fn clear_global_sync_trigger_if(tx: &SyncTriggerTx) {
    let Some(cell) = GLOBAL_SYNC_TRIGGER.get() else { return; };
    if let Ok(mut guard) = cell.lock() {
        if guard.as_ref().is_some_and(|current| current.same_channel(tx)) {
            *guard = None;
        }
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

pub fn envelope_header(v: &serde_json::Value, name: &str) -> Option<String> {
    let headers = v.get("raw_headers")?.as_array()?;
    headers
        .iter()
        .find(|h| {
            h.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
        })
        .and_then(|h| h.get("value").and_then(|x| x.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
const ATTACHMENT_BACKLOG_BATCH: usize = 25;
const ATTACHMENT_BACKLOG_PER_PASS: usize = 100;
const ATTACHMENT_BACKLOG_CONCURRENCY: usize = 4;
const ATTACHMENT_BACKLOG_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
const ATTACHMENT_MAX_ATTEMPTS: i64 = 5;

enum AttachmentFetchError {
    Transport(String),
    Permanent(String),
    Content(String),
}

fn api_status_code(message: &str) -> Option<u16> {
    message
        .split_whitespace()
        .next()
        .map(|token| token.trim_end_matches(':'))
        .and_then(|token| token.parse::<u16>().ok())
}

fn is_transient_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429) || (500..600).contains(&status)
}

fn is_permanent_status(status: u16) -> bool {
    matches!(status, 404 | 410)
}

fn classify_api_error(e: BridgeError) -> AttachmentFetchError {
    match e {
        BridgeError::Network(_) | BridgeError::Auth(_) => {
            AttachmentFetchError::Transport(e.to_string())
        }
        BridgeError::Crypto(_) => AttachmentFetchError::Permanent(e.to_string()),
        BridgeError::Api(ref message) => match api_status_code(message) {
            Some(status) if is_transient_status(status) => {
                AttachmentFetchError::Transport(e.to_string())
            }
            Some(status) if is_permanent_status(status) => {
                AttachmentFetchError::Permanent(e.to_string())
            }
            _ => AttachmentFetchError::Content(e.to_string()),
        },
        other => AttachmentFetchError::Content(other.to_string()),
    }
}

fn classify_decrypt_error(e: BridgeError) -> AttachmentFetchError {
    match e {
        BridgeError::Crypto(_) => AttachmentFetchError::Permanent(e.to_string()),
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
    let declared = item.attachment_count.map(|n| n.max(0) as usize);
    if entries.is_empty() && declared == Some(0) {
        return 0;
    }
    let flagged = usize::from(item.has_attachments == Some(true));
    entries.len().max(declared.unwrap_or(0)).max(flagged)
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

const ADDRESS_META_VERSION_KEY: &str = "addresses_v";

#[derive(Debug, Clone, Default, PartialEq)]
struct EnvelopeAddresses {
    cc: Option<String>,
    bcc: Option<String>,
    reply_to: Option<String>,
}

impl EnvelopeAddresses {
    fn from_envelope(envelope: &serde_json::Value) -> Self {
        Self {
            cc: crate::address::envelope_cc(envelope),
            bcc: crate::address::envelope_bcc(envelope),
            reply_to: crate::address::envelope_reply_to(envelope),
        }
    }

    fn is_empty(&self) -> bool {
        self.cc.is_none() && self.bcc.is_none() && self.reply_to.is_none()
    }

    fn write_to(&self, meta: &mut serde_json::Map<String, serde_json::Value>) {
        for (key, value) in [("cc", &self.cc), ("bcc", &self.bcc), ("reply_to", &self.reply_to)] {
            if let Some(v) = value {
                meta.insert(key.to_string(), serde_json::json!(v));
            }
        }
        meta.insert(ADDRESS_META_VERSION_KEY.to_string(), serde_json::json!(1));
    }
}

fn cached_meta_map(db: &Database, aster_id: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let existing = db.get_cached_message(aster_id).ok()??;
    meta_map_of(&existing)
}

fn meta_map_of(msg: &CachedMessage) -> Option<serde_json::Map<String, serde_json::Value>> {
    match serde_json::from_str::<serde_json::Value>(msg.raw_headers.as_deref()?).ok()? {
        serde_json::Value::Object(map) => Some(map),
        _ => None,
    }
}

fn backfill_cached_addresses(
    db: &Database,
    folder: &str,
    item: &MailItem,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> bool {
    let Ok(Some(cached)) = db.get_cached_message(&item.id) else {
        return false;
    };
    let Some(mut meta) = meta_map_of(&cached) else {
        return false;
    };
    if meta.contains_key(ADDRESS_META_VERSION_KEY) || meta.contains_key("draft_api") {
        return false;
    }
    let Ok(plaintext) = decrypt_envelope_with_previous_keys(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        passphrase,
        identity_key,
        previous_keys,
        inbound_keys,
    ) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&plaintext) else {
        return false;
    };
    let addresses = EnvelopeAddresses::from_envelope(&parsed);
    addresses.write_to(&mut meta);
    let raw = serde_json::Value::Object(meta).to_string();
    if let Err(e) = db.set_cached_raw_headers(&item.id, &raw) {
        tracing::warn!("address backfill failed for {}: {}", item.id, e);
        return false;
    }
    if addresses.is_empty() {
        return false;
    }
    if cached.imap_uid > 0 {
        let _ = db.remove_uid_mapping(cached.imap_uid as i64, folder);
    }
    let _ = db.assign_uid_if_missing(folder, &item.id);
    true
}



#[allow(clippy::too_many_arguments)]
async fn fetch_and_decrypt_attachments(
    client: &ApiClient,
    access_token: &str,
    mail_id: &str,
    entries: &[EnvelopeAttachment],
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    timeout: Option<std::time::Duration>,
) -> std::result::Result<Vec<CachedAttachment>, AttachmentFetchError> {
    let resp = client
        .list_attachments_for_mail(access_token, mail_id, timeout)
        .await
        .map_err(classify_api_error)?;
    if resp.attachments.is_empty() {
        return Err(AttachmentFetchError::Permanent(
            "server returned no attachment rows".to_string(),
        ));
    }
    let rows = resp.attachments;
    let entries: Vec<EnvelopeAttachment> = entries.to_vec();
    let passphrase = Zeroizing::new(passphrase.to_vec());
    let identity_key = identity_key.map(str::to_string);
    let previous_keys = Zeroizing::new(previous_keys.to_vec());
    tokio::task::spawn_blocking(move || {
        let mut out: Vec<CachedAttachment> = Vec::with_capacity(rows.len());
        for (position, row) in rows.iter().enumerate() {
            let seq = row.seq_num as i64;
            if out.iter().any(|a| a.seq == seq) {
                continue;
            }
            let entry = entry_for_row(&entries, seq, position).map(key_entry);
            let att = decrypt_attachment(
                row,
                entry.as_ref(),
                &passphrase,
                identity_key.as_deref(),
                &previous_keys,
            )
                .map_err(classify_decrypt_error)?;
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
        Ok::<Vec<CachedAttachment>, AttachmentFetchError>(out)
    })
    .await
    .map_err(|e| AttachmentFetchError::Content(format!("attachment decrypt task: {}", e)))?
}

async fn refresh_attachment_keys(
    client: &ApiClient,
    access_token: &str,
    aster_id: &str,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> std::result::Result<Vec<EnvelopeAttachment>, AttachmentFetchError> {
    let item = client
        .fetch_mail_item(access_token, aster_id)
        .await
        .map_err(classify_api_error)?;
    let plaintext = decrypt_envelope_with_previous_keys(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        passphrase,
        identity_key,
        previous_keys,
        inbound_keys,
    )
    .map_err(|_| AttachmentFetchError::Content("envelope decrypt failed".to_string()))?;
    let parsed: serde_json::Value = serde_json::from_str(&plaintext)
        .map_err(|e| AttachmentFetchError::Content(format!("envelope parse: {}", e)))?;
    Ok(parse_envelope_attachments(&parsed))
}

struct BacklogDownload {
    aster_id: String,
    folder: String,
    msg: CachedMessage,
    meta_json: Option<String>,
    result: std::result::Result<Vec<CachedAttachment>, AttachmentFetchError>,
}

#[allow(clippy::too_many_arguments)]
async fn download_backlog_item(
    client: &ApiClient,
    access_token: &str,
    aster_id: String,
    folder: String,
    msg: CachedMessage,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> BacklogDownload {
    let mut entries = cached_attachment_entries(msg.raw_headers.as_deref());
    let mut meta_json = msg.raw_headers.clone();
    if entries.iter().all(|e| e.key.is_none()) {
        match refresh_attachment_keys(
            client,
            access_token,
            &aster_id,
            passphrase,
            identity_key,
            previous_keys,
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
                tracing::debug!("attachment key refresh for {} deferred: {}", aster_id, e);
                return BacklogDownload {
                    aster_id,
                    folder,
                    msg,
                    meta_json,
                    result: Err(AttachmentFetchError::Transport(e)),
                };
            }
            Err(AttachmentFetchError::Permanent(e)) | Err(AttachmentFetchError::Content(e)) => {
                tracing::debug!("attachment key refresh for {} skipped: {}", aster_id, e);
            }
        }
    }
    let result = fetch_and_decrypt_attachments(
        client,
        access_token,
        &aster_id,
        &entries,
        passphrase,
        identity_key,
        previous_keys,
        Some(crate::api_client::ATTACHMENT_TRANSFER_TIMEOUT),
    )
    .await;
    BacklogDownload {
        aster_id,
        folder,
        msg,
        meta_json,
        result,
    }
}

#[allow(clippy::too_many_arguments)]
async fn backfill_pending_attachments(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
    skip: &HashSet<String>,
) -> Vec<String> {
    use futures_util::StreamExt;

    let mut updated: Vec<String> = Vec::new();
    let mut unavailable: usize = 0;
    let deadline = std::time::Instant::now() + ATTACHMENT_BACKLOG_BUDGET;
    let mut tried: HashSet<String> = HashSet::new();
    let mut stop = false;

    while !stop && tried.len() < ATTACHMENT_BACKLOG_PER_PASS && std::time::Instant::now() < deadline
    {
        let limit = (skip.len() + tried.len() + ATTACHMENT_BACKLOG_BATCH) as i64;
        let backlog = match db.list_attachment_backlog(limit) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("attachment backlog query failed: {}", e);
                break;
            }
        };
        let mut batch: Vec<(String, String, CachedMessage)> = Vec::new();
        for (aster_id, folder) in backlog {
            if batch.len() >= ATTACHMENT_BACKLOG_BATCH {
                break;
            }
            if skip.contains(&aster_id) || !tried.insert(aster_id.clone()) {
                continue;
            }
            let Ok(Some(msg)) = db.get_cached_message(&aster_id) else {
                continue;
            };
            batch.push((aster_id, folder, msg));
        }
        if batch.is_empty() {
            break;
        }

        let halted = std::sync::atomic::AtomicBool::new(false);
        let mut downloads = futures_util::stream::iter(batch)
            .take_while(|_| {
                let go_on = !halted.load(std::sync::atomic::Ordering::Relaxed)
                    && std::time::Instant::now() < deadline;
                std::future::ready(go_on)
            })
            .enumerate()
            .map(|(position, (aster_id, folder, msg))| async move {
                let download = download_backlog_item(
                    client,
                    access_token,
                    aster_id,
                    folder,
                    msg,
                    passphrase,
                    identity_key,
                    previous_keys,
                    inbound_keys,
                )
                .await;
                (position, download)
            })
            .buffer_unordered(ATTACHMENT_BACKLOG_CONCURRENCY);

        let mut deferred: Option<(usize, String)> = None;
        while let Some((position, download)) = downloads.next().await {
            let BacklogDownload {
                aster_id,
                folder,
                msg,
                meta_json,
                result,
            } = download;
            match result {
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
                    tracing::debug!("attachment download for {} deferred: {}", aster_id, e);
                    if !matches!(&deferred, Some((first, _)) if *first <= position) {
                        deferred = Some((position, aster_id));
                    }
                    halted.store(true, std::sync::atomic::Ordering::Relaxed);
                    stop = true;
                }
                Err(AttachmentFetchError::Permanent(e)) => {
                    let _ = db.set_attachments_state(&aster_id, ATTACHMENTS_FAILED);
                    tracing::debug!("attachment download for {} unavailable: {}", aster_id, e);
                    unavailable += 1;
                    updated.push(aster_id);
                }
                Err(AttachmentFetchError::Content(e)) => {
                    let attempts = db.bump_attachment_attempts(&aster_id).unwrap_or(0);
                    tracing::debug!(
                        "attachment download for {} failed (attempt {}): {}",
                        aster_id,
                        attempts,
                        e
                    );
                    if attempts >= ATTACHMENT_MAX_ATTEMPTS {
                        let _ = db.set_attachments_state(&aster_id, ATTACHMENTS_FAILED);
                        unavailable += 1;
                        updated.push(aster_id);
                    }
                }
            }
        }
        if let Some((_, aster_id)) = deferred {
            let _ = db.bump_attachment_attempts(&aster_id);
        }
    }
    if unavailable > 0 {
        tracing::info!(
            "{} message(s) have attachments this device cannot read; they will not be retried",
            unavailable
        );
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
    let mailbox = crate::address::format_mailbox(name, email);
    if mailbox.is_empty() {
        None
    } else {
        Some(mailbox)
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
            let mailbox = crate::address::format_mailbox(name, email);
            if !mailbox.is_empty() {
                parts.push(mailbox);
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
    let new_flags = server_flags(current, item);
    if new_flags == current {
        return false;
    }
    db.set_message_flags_by_id(&item.id, new_flags).is_ok()
}

fn server_flags(current: i64, item: &MailItem) -> i64 {
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
    new_flags
}

enum CachedShortcut {
    Unchanged,
    FlagsOnly(i64),
}

fn cached_shortcut(
    state: Option<&CachedSyncState>,
    folder: &str,
    item: &MailItem,
) -> Option<CachedShortcut> {
    if !is_valid_item_id(&item.id) {
        return None;
    }
    let state = state?;
    if !state.body_cached
        || state.folder != folder
        || !state.uid_folders.iter().any(|f| f == folder)
    {
        return None;
    }
    let meta = state
        .raw_headers
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
    if let Some(serde_json::Value::Object(meta)) = meta {
        if !meta.contains_key(ADDRESS_META_VERSION_KEY) && !meta.contains_key("draft_api") {
            return None;
        }
    }
    let new_flags = server_flags(state.flags, item);
    if new_flags == state.flags {
        Some(CachedShortcut::Unchanged)
    } else {
        Some(CachedShortcut::FlagsOnly(new_flags))
    }
}

struct PreparedMessage {
    subject: Option<String>,
    sender: Option<String>,
    recipients: Option<String>,
    date: Option<String>,
    body_text: Option<String>,
    is_html: bool,
    message_id: Option<String>,
    in_reply_to: Option<String>,
    references: Option<String>,
    addresses: EnvelopeAddresses,
    attachments: Vec<EnvelopeAttachment>,
    expected_attachments: usize,
}

enum Prepared {
    Done(CacheOutcome),
    Ready(PreparedMessage),
}

const RATCHET_PLACEHOLDER: &str = "[This message is end-to-end encrypted with Aster's double-ratchet protocol. \
     Open it in the Aster web or mobile app to decrypt.]";

fn prepare_mail_item(
    db: &Database,
    folder: &str,
    item: &MailItem,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> Prepared {
    if !is_valid_item_id(&item.id) {
        tracing::warn!("rejecting message with invalid id format");
        return Prepared::Done(CacheOutcome::default());
    }

    if db.body_cached(&item.id) {
        let _ = db.set_folder_if_changed(&item.id, folder);
        let _ = db.assign_uid_if_missing(folder, &item.id);
        let addresses_added = backfill_cached_addresses(
            db,
            folder,
            item,
            passphrase,
            identity_key,
            previous_keys,
            inbound_keys,
        );
        let flags_changed = reconcile_server_flags(db, item);
        return Prepared::Done(CacheOutcome {
            was_new: false,
            flags_changed: flags_changed || addresses_added,
            inbound_decrypt_failed: false,
        });
    }

    if !item.envelope_nonce.is_empty() {
        if let Ok(false) = db.replay_check_and_record(&item.id, &item.envelope_nonce) {
            tracing::warn!("rejecting envelope nonce mismatch (replay/rollback)");
            return Prepared::Done(CacheOutcome::default());
        }
    }

    let plaintext_result = decrypt_envelope_with_previous_keys(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        passphrase,
        identity_key,
        previous_keys,
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
        body_text = Some(RATCHET_PLACEHOLDER.to_string());
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
    let message_id = json_str(&parsed, "message_id")
        .or_else(|| json_str(&parsed, "messageId"))
        .or_else(|| envelope_header(&parsed, "message-id"));
    let in_reply_to = json_str(&parsed, "in_reply_to")
        .or_else(|| envelope_header(&parsed, "in-reply-to"));
    let references = json_str(&parsed, "references")
        .or_else(|| envelope_header(&parsed, "references"));
    let addresses = EnvelopeAddresses::from_envelope(&parsed);
    Prepared::Ready(PreparedMessage {
        subject,
        sender,
        recipients,
        date,
        body_text,
        is_html,
        message_id,
        in_reply_to,
        references,
        addresses,
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
    if let Some(ref value) = prepared.in_reply_to {
        raw_headers_map.insert("in_reply_to".to_string(), serde_json::json!(value));
    }
    if let Some(ref value) = prepared.references {
        raw_headers_map.insert("references".to_string(), serde_json::json!(value));
    }
    prepared.addresses.write_to(&mut raw_headers_map);
    if !prepared.attachments.is_empty() {
        raw_headers_map.insert(
            "attachments".to_string(),
            attachment_meta_json(&prepared.attachments),
        );
    }
    let raw_headers_meta = serde_json::Value::Object(raw_headers_map).to_string();
    let bare_message_id = prepared
        .message_id
        .as_deref()
        .and_then(|m| crate::smtp::reply_thread::message_ids(m).into_iter().next());

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
    if bare_message_id.is_some() {
        if let Err(e) = db.update_message_thread_and_msgid(&item.id, None, bare_message_id.as_deref()) {
            tracing::warn!("message id index failed for {}: {}", item.id, e);
        }
    }
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
    previous_keys: &[String],
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> CacheOutcome {
    match prepare_mail_item(db, folder, item, passphrase, identity_key, previous_keys, inbound_keys) {
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
    reply_to_id: Option<&str>,
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
        "reply_to_id": reply_to_id,
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

struct InternalDecryptContext<'a> {
    our_email: &'a str,
    passphrase: &'a [u8],
    identity_key: Option<&'a str>,
    previous_keys: &'a [String],
    ratchet_keys: &'a [crate::crypto::ratchet::RatchetReceiverKeys],
    inbound_keys: &'a [crate::crypto::inbound::InboundKeyCandidate],
    recovery: &'a crate::crypto::ratchet_recovery::RecoveryMaterial,
    sync_keys: &'a [Zeroizing<[u8; 32]>],
    escrow_keys: &'a [Zeroizing<[u8; 32]>],
    client: &'a ApiClient,
    access_token: &'a str,
}

fn envelope_sender_address(parsed: &serde_json::Value) -> String {
    let from = parsed.get("from");
    let raw = match from {
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(v) => v.get("email").and_then(|e| e.as_str()).unwrap_or(""),
        None => "",
    };
    match (raw.rfind('<'), raw.rfind('>')) {
        (Some(open), Some(close)) if open < close => raw[open + 1..close].trim().to_string(),
        _ => raw.trim().to_string(),
    }
}

async fn fetch_pq_secrets(
    ctx: &InternalDecryptContext<'_>,
    key_id: i32,
) -> Vec<Zeroizing<Vec<u8>>> {
    if key_id == crate::crypto::ratchet::PQ_IDENTITY_KEY_ID {
        let mut secrets: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let inbound = ctx.inbound_keys.iter().filter_map(|c| c.pq_decap_key.as_ref());
        let lane = ctx.recovery.lane_candidates.iter().filter_map(|c| c.pq_decap_key.as_ref());
        for secret in inbound.chain(lane) {
            if !secrets.iter().any(|s| s.as_slice() == secret.as_slice()) {
                secrets.push(Zeroizing::new(secret.clone()));
            }
        }
        return secrets;
    }
    let Ok(key_id) = u32::try_from(key_id) else {
        return Vec::new();
    };
    if ctx.sync_keys.is_empty() {
        return Vec::new();
    }
    let resp = match ctx.client.get_pq_secret(ctx.access_token, key_id).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::debug!("ratchet pq secret {} unavailable: {}", key_id, e);
            return Vec::new();
        }
    };
    for sync_key in ctx.sync_keys {
        if let Ok(secret) = crate::crypto::ratchet::decrypt_pq_secret(
            sync_key.as_slice(),
            &resp.encrypted_secret,
            &resp.secret_nonce,
        ) {
            return vec![Zeroizing::new(secret)];
        }
    }
    tracing::debug!("ratchet pq secret {} did not open with any storage key", key_id);
    Vec::new()
}

async fn try_bootstrap(
    ctx: &InternalDecryptContext<'_>,
    ratchet_obj: &serde_json::Value,
    address: &str,
) -> Option<String> {
    if ctx.ratchet_keys.is_empty() {
        return None;
    }
    let mut msg = crate::crypto::ratchet::parse_recipient_message(ratchet_obj, address)?;
    let Some(key_id) = msg.pq_key_id else {
        return crate::crypto::ratchet::decrypt_with_key_sets(ctx.ratchet_keys, &msg);
    };
    for secret in fetch_pq_secrets(ctx, key_id).await {
        msg.pq_secret = Some(secret.to_vec());
        let opened = crate::crypto::ratchet::decrypt_with_key_sets(ctx.ratchet_keys, &msg);
        if let Some(mut s) = msg.pq_secret.take() {
            s.zeroize();
        }
        if opened.is_some() {
            return opened;
        }
    }
    None
}

async fn try_escrow(ctx: &InternalDecryptContext<'_>, dedupe_key: &str) -> Option<String> {
    if ctx.escrow_keys.is_empty() {
        return None;
    }
    let entry = match ctx.client.get_escrow_plaintext(ctx.access_token, dedupe_key).await {
        Ok(Some(entry)) => entry,
        Ok(None) => return None,
        Err(e) => {
            tracing::debug!("ratchet escrow lookup failed: {}", e);
            return None;
        }
    };
    if entry.message_id != dedupe_key {
        tracing::warn!("ratchet escrow returned an entry for a different message; ignored");
        return None;
    }
    crate::crypto::ratchet_recovery::decrypt_escrow_entry(
        ctx.escrow_keys,
        dedupe_key,
        &entry.encrypted_plaintext,
        &entry.plaintext_nonce,
    )
}

async fn try_decrypt_internal_mail(
    item: &MailItem,
    ctx: &InternalDecryptContext<'_>,
) -> Option<crate::crypto::ratchet_recovery::SubjectBundle> {
    let plaintext_env = decrypt_envelope_with_previous_keys(
        &item.encrypted_envelope,
        Some(&item.envelope_nonce),
        ctx.passphrase,
        ctx.identity_key,
        ctx.previous_keys,
        ctx.inbound_keys,
    )
    .ok()?;

    let parsed: serde_json::Value = serde_json::from_str(&plaintext_env).ok()?;
    let ratchet_obj = crate::crypto::ratchet::find_ratchet_object(&parsed)?;
    let sender_email = envelope_sender_address(&parsed);
    let sender_identity = ratchet_obj
        .get("sender_identity_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let attempts =
        crate::crypto::ratchet_recovery::recipient_attempts(&ratchet_obj, ctx.our_email, &sender_email);
    let mut opened: Option<String> = None;
    let mut via_recovery_lane = false;
    let mut failed_steps: Vec<&str> = Vec::new();
    for attempt in &attempts {
        if attempt.data.get("ephemeral_key").and_then(|v| v.as_str()).is_some() {
            opened = try_bootstrap(ctx, &ratchet_obj, &attempt.address).await;
            if opened.is_some() {
                break;
            }
            failed_steps.push("bootstrap");
        }
        if !sender_identity.is_empty() && attempt.data.get("recovery").is_some() {
            let conversation =
                crate::crypto::ratchet_recovery::conversation_id(&attempt.address, &sender_email);
            opened = crate::crypto::ratchet_recovery::decrypt_via_recovery_lane(
                attempt.data,
                &conversation,
                sender_identity,
                &ctx.recovery.lane_candidates,
            );
            if opened.is_some() {
                via_recovery_lane = true;
                break;
            }
            failed_steps.push("recovery_lane");
        }
        if let Some(dedupe_key) = crate::crypto::ratchet_recovery::escrow_dedupe_key(&item.id, attempt.data) {
            opened = try_escrow(ctx, &dedupe_key).await;
            if opened.is_some() {
                break;
            }
            failed_steps.push("escrow");
        }
    }
    if opened.is_none() && attempts.is_empty() {
        opened = try_escrow(ctx, &item.id).await;
        failed_steps.push("no_recipient_entry");
    }
    match opened {
        Some(plaintext) => {
            let mut bundle = crate::crypto::ratchet_recovery::extract_subject_bundle(&plaintext);
            bundle.sender_unverified = via_recovery_lane;
            Some(bundle)
        }
        None => {
            tracing::debug!(
                "ratchet message {} still sealed after: {}",
                item.id,
                failed_steps.join(", ")
            );
            None
        }
    }
}

const SEALED_RETRY_BATCH: usize = 40;
const SEALED_RETRY_SCAN_LIMIT: usize = 2000;
const SEALED_RETRY_BASE_SECS: u64 = 300;
const SEALED_RETRY_MAX_SECS: u64 = 6 * 60 * 60;
const SEALED_RETRY_TRACKED_CAP: usize = 10_000;

static SEALED_RETRY: OnceLock<StdMutex<HashMap<String, (u32, std::time::Instant)>>> = OnceLock::new();

fn sealed_retry_state() -> &'static StdMutex<HashMap<String, (u32, std::time::Instant)>> {
    SEALED_RETRY.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn sealed_retry_delay(attempts: u32) -> std::time::Duration {
    let factor = 1u64.checked_shl(attempts.saturating_sub(1).min(16)).unwrap_or(u64::MAX);
    std::time::Duration::from_secs(SEALED_RETRY_BASE_SECS.saturating_mul(factor).min(SEALED_RETRY_MAX_SECS))
}

fn sealed_retry_due(aster_id: &str, now: std::time::Instant) -> bool {
    let Ok(state) = sealed_retry_state().lock() else {
        return false;
    };
    state.get(aster_id).is_none_or(|(_, next)| now >= *next)
}

fn note_sealed_retry(aster_id: &str, now: std::time::Instant) {
    let Ok(mut state) = sealed_retry_state().lock() else {
        return;
    };
    if state.len() >= SEALED_RETRY_TRACKED_CAP && !state.contains_key(aster_id) {
        state.retain(|_, (_, next)| *next > now);
        if state.len() >= SEALED_RETRY_TRACKED_CAP {
            return;
        }
    }
    let entry = state.entry(aster_id.to_string()).or_insert((0, now));
    entry.0 = entry.0.saturating_add(1);
    entry.1 = now + sealed_retry_delay(entry.0);
}

fn clear_sealed_retry(aster_id: &str) {
    if let Ok(mut state) = sealed_retry_state().lock() {
        state.remove(aster_id);
    }
}

fn db_body_is_placeholder(db: &Database, aster_id: &str) -> bool {
    matches!(
        db.get_cached_message(aster_id),
        Ok(Some(ref m)) if m.body_text.as_deref() == Some(RATCHET_PLACEHOLDER)
    )
}

fn store_unsealed_message(
    db: &Database,
    aster_id: &str,
    bundle: &crate::crypto::ratchet_recovery::SubjectBundle,
) -> bool {
    let mut meta_map = cached_meta_map(db, aster_id).unwrap_or_default();
    meta_map.insert(
        "is_html".to_string(),
        serde_json::json!(looks_like_html(&bundle.body)),
    );
    meta_map
        .entry("message_id".to_string())
        .or_insert(serde_json::Value::Null);
    if bundle.sender_unverified {
        meta_map.insert("sender_unverified".to_string(), serde_json::json!(true));
    }
    let meta = serde_json::Value::Object(meta_map).to_string();
    if let Err(e) = db.update_cached_body(aster_id, &bundle.body, Some(&meta)) {
        tracing::warn!("storing decrypted ratchet body for {} failed: {}", aster_id, e);
        return false;
    }
    if let Some(subject) = bundle.subject.as_deref().filter(|s| !s.trim().is_empty()) {
        if let Err(e) = db.update_cached_subject(aster_id, subject) {
            tracing::warn!("storing decrypted ratchet subject for {} failed: {}", aster_id, e);
        }
    }
    clear_sealed_retry(aster_id);
    true
}

const BUNDLE_REPAIR_BATCH: usize = 200;

static BUNDLE_REPAIR_SKIPPED: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();

fn repair_cached_bundles(db: &Database) -> Vec<String> {
    let marker = crate::crypto::ratchet_recovery::SUBJECT_BUNDLE_MARKER;
    let skipped = BUNDLE_REPAIR_SKIPPED.get_or_init(|| StdMutex::new(HashSet::new()));
    let skip_count = skipped.lock().map(|s| s.len()).unwrap_or(0);
    let rows = match db.list_bodies_starting_with(marker, BUNDLE_REPAIR_BATCH + skip_count) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("listing cached subject bundles failed: {}", e);
            return Vec::new();
        }
    };
    let mut repaired = Vec::new();
    for (aster_id, body) in rows {
        if skipped.lock().map(|s| s.contains(&aster_id)).unwrap_or(true) {
            continue;
        }
        let Ok(Some(cached)) = db.get_cached_message(&aster_id) else {
            continue;
        };
        let bundle = crate::crypto::ratchet_recovery::extract_subject_bundle(&body);
        let sealed_subject = cached.subject.as_deref().is_none_or(|s| s.trim().is_empty());
        if bundle.subject.is_none() || !sealed_subject {
            if let Ok(mut s) = skipped.lock() {
                s.insert(aster_id);
            }
            continue;
        }
        if !store_unsealed_message(db, &aster_id, &bundle) {
            continue;
        }
        if cached.imap_uid > 0 {
            let _ = db.remove_uid_mapping(cached.imap_uid as i64, &cached.folder);
        }
        let _ = db.assign_uid_if_missing(&cached.folder, &aster_id);
        repaired.push(aster_id);
        if repaired.len() >= BUNDLE_REPAIR_BATCH {
            break;
        }
    }
    if !repaired.is_empty() {
        tracing::info!("unwrapped {} cached message(s) stored by an older version", repaired.len());
    }
    repaired
}

async fn retry_sealed_messages(
    db: &Database,
    ctx: &InternalDecryptContext<'_>,
) -> Vec<String> {
    let mut unsealed = repair_cached_bundles(db);
    let now = std::time::Instant::now();
    let ids = match db.list_ids_with_body(RATCHET_PLACEHOLDER, SEALED_RETRY_SCAN_LIMIT) {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!("listing sealed ratchet messages failed: {}", e);
            return Vec::new();
        }
    };
    let due: Vec<String> = ids
        .into_iter()
        .filter(|id| is_valid_item_id(id) && sealed_retry_due(id, now))
        .take(SEALED_RETRY_BATCH)
        .collect();
    for aster_id in due {
        let item = match ctx.client.fetch_mail_item(ctx.access_token, &aster_id).await {
            Ok(item) => item,
            Err(e) => {
                tracing::debug!("sealed message {} refetch failed: {}", aster_id, e);
                note_sealed_retry(&aster_id, now);
                continue;
            }
        };
        if item.id != aster_id {
            note_sealed_retry(&aster_id, now);
            continue;
        }
        let Some(bundle) = try_decrypt_internal_mail(&item, ctx).await else {
            note_sealed_retry(&aster_id, now);
            continue;
        };
        let Ok(Some(cached)) = db.get_cached_message(&aster_id) else {
            continue;
        };
        if !store_unsealed_message(db, &aster_id, &bundle) {
            continue;
        }
        if cached.imap_uid > 0 {
            let _ = db.remove_uid_mapping(cached.imap_uid as i64, &cached.folder);
        }
        let _ = db.assign_uid_if_missing(&cached.folder, &aster_id);
        unsealed.push(aster_id);
    }
    if !unsealed.is_empty() {
        tracing::info!("decrypted {} previously sealed message(s)", unsealed.len());
    }
    unsealed
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
    let allowed = guard.is_none_or(|t| {
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
    if let Err(e) = crate::auth::session::reload_vault_keys(
        session,
        device_id,
        &identity.ed25519_signing_key,
        client,
    )
    .await
    {
        tracing::warn!("inbound key heal vault reload failed: {}", e);
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
    failed: &[(String, MailItem)],
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[crate::crypto::inbound::InboundKeyCandidate],
) -> (Vec<String>, Vec<String>) {
    let mut new_ids = Vec::new();
    let mut updated_ids = Vec::new();
    for (folder, item) in failed {
        let outcome = cache_mail_item(db, folder, item, passphrase, identity_key, previous_keys, inbound_keys);
        if outcome.was_new {
            new_ids.push(item.id.clone());
        } else if outcome.flags_changed {
            updated_ids.push(item.id.clone());
        }
    }
    (new_ids, updated_ids)
}

const CUSTOM_FOLDER_PAGE: i64 = 100;
const CUSTOM_FOLDER_MAX_ITEMS: usize = 2000;
const SYSTEM_FOLDER_MAX_ITEMS: usize = 2000;
const CAPPED_PRUNE_CHECKS_PER_PASS: usize = 50;

fn parse_cached_date(date: Option<&str>) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(date?).ok()
}

fn capped_prune_candidates(
    local: &[(String, String, Option<String>)],
    seen: &HashSet<String>,
    capped_listings: &[Vec<String>],
) -> Vec<String> {
    let dates: HashMap<&str, chrono::DateTime<chrono::FixedOffset>> = local
        .iter()
        .filter_map(|(id, _, date)| Some((id.as_str(), parse_cached_date(date.as_deref())?)))
        .collect();
    let mut floor = None;
    for listing in capped_listings {
        let Some(oldest) = listing.iter().filter_map(|id| dates.get(id.as_str())).min() else {
            return Vec::new();
        };
        floor = floor.max(Some(*oldest));
    }
    let Some(floor) = floor else {
        return Vec::new();
    };
    local
        .iter()
        .filter(|(id, folder, _)| folder != "drafts" && !seen.contains(id))
        .filter(|(id, _, _)| dates.get(id.as_str()).is_some_and(|d| *d >= floor))
        .map(|(id, _, _)| id.clone())
        .collect()
}

async fn confirm_gone_on_server(
    client: &ApiClient,
    access_token: &str,
    candidates: &[String],
) -> Vec<String> {
    let mut gone = Vec::new();
    for id in candidates.iter().take(CAPPED_PRUNE_CHECKS_PER_PASS) {
        match client.fetch_mail_item(access_token, id).await {
            Ok(_) => {}
            Err(BridgeError::Api(ref msg))
                if api_status_code(msg).is_some_and(is_permanent_status) =>
            {
                gone.push(id.clone())
            }
            Err(e) => {
                tracing::debug!("sync: stopped checking for deleted messages: {}", e);
                break;
            }
        }
    }
    gone
}

fn is_custom_folder_definition(def: &crate::api_client::FolderDefinition) -> bool {
    !def.is_system
        && !def.is_password_protected
        && matches!(def.folder_type.as_deref(), None | Some("custom") | Some("folder"))
}

pub(crate) fn folders_from_definitions(
    defs: &[crate::api_client::FolderDefinition],
    identity_key: &str,
    previous_keys: &[String],
) -> Vec<crate::db::CustomFolder> {
    defs.iter()
        .filter(|d| is_custom_folder_definition(d) && !d.label_token.is_empty())
        .filter_map(|d| {
            let name = crate::crypto::folder::decrypt_folder_name(
                &d.encrypted_name,
                &d.name_nonce,
                identity_key,
                previous_keys,
            )?;
            Some(crate::db::CustomFolder {
                label_token: d.label_token.clone(),
                server_id: d.id.clone(),
                name,
                parent_token: d.parent_token.clone().filter(|p| !p.is_empty()),
                sort_order: d.sort_order as i64,
                created_at: d.created_at.clone(),
            })
        })
        .collect()
}

pub(crate) fn record_mailbox_diff(
    db: &Database,
    before: &[crate::db::CustomFolder],
    after: &[crate::db::CustomFolder],
) -> bool {
    let rows = |folders: &[crate::db::CustomFolder]| -> HashMap<String, (String, Option<String>, i32)> {
        crate::folders::jmap_rows(&crate::folders::build_tree(folders))
            .into_iter()
            .map(|r| (r.id, (r.name, r.parent_id, r.sort_order)))
            .collect()
    };
    let old = rows(before);
    let new = rows(after);
    let created: Vec<&str> = new.keys().filter(|k| !old.contains_key(*k)).map(|k| k.as_str()).collect();
    let destroyed: Vec<&str> = old.keys().filter(|k| !new.contains_key(*k)).map(|k| k.as_str()).collect();
    let updated: Vec<&str> = new
        .iter()
        .filter(|(k, v)| old.get(*k).is_some_and(|o| o != *v))
        .map(|(k, _)| k.as_str())
        .collect();
    if !created.is_empty() {
        let _ = db.jmap_record_sync_batch("Mailbox", &created);
    }
    if !updated.is_empty() {
        let _ = db.jmap_record_updated_batch("Mailbox", &updated);
    }
    if !destroyed.is_empty() {
        let _ = db.jmap_record_destroyed_batch("Mailbox", &destroyed);
    }
    !(created.is_empty() && updated.is_empty() && destroyed.is_empty())
}

async fn sync_custom_folders(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
    previous_keys: &[String],
) -> Result<bool, String> {
    let Some(identity_key) = identity_key else {
        return Ok(false);
    };
    let defs = client
        .list_folders(access_token)
        .await
        .map_err(|e| format!("failed to sync folders: {}", e))?;
    let folders = folders_from_definitions(&defs, identity_key, previous_keys);
    let before = db.list_custom_folders()?;
    if !db.replace_custom_folders(&folders)? {
        return Ok(false);
    }
    let after = db.list_custom_folders()?;
    Ok(record_mailbox_diff(db, &before, &after))
}

const TAG_LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

async fn sync_custom_tags(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
    previous_keys: &[String],
) -> Result<Vec<String>, String> {
    let Some(identity_key) = identity_key else {
        return Ok(Vec::new());
    };
    let _guard = db.tag_lock.lock().await;
    let defs = tokio::time::timeout(TAG_LIST_TIMEOUT, client.list_tags(access_token))
        .await
        .map_err(|_| "failed to sync labels: timed out".to_string())?
        .map_err(|e| format!("failed to sync labels: {}", e))?;
    let tags = crate::tags::tags_from_definitions(&defs, identity_key, previous_keys);
    let before = db.list_custom_tags()?;
    let mut affected: Vec<String> = Vec::new();
    for old in &before {
        let keyword_now = tags
            .iter()
            .find(|tag| tag.tag_token == old.tag_token)
            .map(|tag| &tag.keyword);
        if keyword_now != Some(&old.keyword) {
            affected.extend(db.messages_with_tag(&old.tag_token)?);
        }
    }
    db.replace_custom_tags(&tags)?;
    Ok(affected)
}

fn server_tags_differ(
    item: &MailItem,
    known: &HashSet<String>,
    cached: &HashMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    let mut wanted: Vec<String> = item
        .tag_tokens
        .as_ref()?
        .iter()
        .filter(|token| known.contains(*token))
        .cloned()
        .collect();
    wanted.sort();
    wanted.dedup();
    let current = cached.get(&item.id).map(|tokens| tokens.as_slice()).unwrap_or(&[]);
    (current != wanted.as_slice()).then_some(wanted)
}

fn custom_folder_of(item: &MailItem, known: &HashSet<String>) -> Option<String> {
    item.labels
        .as_ref()?
        .iter()
        .find(|l| known.contains(&l.token))
        .map(|l| crate::folders::folder_label(&l.token))
}

fn target_folder(system_label: &str, item: &MailItem, known: &HashSet<String>) -> String {
    if matches!(system_label, "sent" | "archive") {
        if let Some(label) = custom_folder_of(item, known) {
            return label;
        }
    }
    system_label.to_string()
}

struct FolderPage {
    label: String,
    items: Vec<MailItem>,
    total: usize,
    has_more: bool,
    next_cursor: Option<String>,
}

const MESSAGE_ID_BACKFILL_KEY: &str = "message_id_backfill_v1";

fn backfill_missing_message_ids(db: &Database) {
    if matches!(db.get_sync_state(MESSAGE_ID_BACKFILL_KEY), Ok(Some(_))) {
        return;
    }
    match db.recache_messages_without_message_id() {
        Ok(count) => {
            if count > 0 {
                tracing::info!("sync: re-caching {} messages to recover message ids", count);
            }
            let _ = db.set_sync_state(MESSAGE_ID_BACKFILL_KEY, "done");
        }
        Err(e) => tracing::warn!("message id backfill failed: {}", e),
    }
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
    let mut capped_listings: Vec<Vec<String>> = Vec::new();
    let mut capped_only = true;
    let mut failed_inbound: Vec<(String, MailItem)> = Vec::new();
    let mut mailboxes_changed = false;
    let mut inline_downloads = 0usize;
    let mut attachments_handled: HashSet<String> = HashSet::new();
    let mut rate_limited = false;

    let (access_token, passphrase, identity_key, previous_keys, our_email, ratchet_keys, inbound_keys, recovery) = {
        let s = session.read().await;
        (
            s.access_token.clone(),
            Zeroizing::new(s.vault_passphrase.clone()),
            s.identity_key.clone(),
            s.previous_keys.clone(),
            s.email.clone(),
            s.ratchet_keys.clone(),
            s.inbound_keys.clone(),
            s.ratchet_recovery.clone(),
        )
    };
    let sync_keys = recovery.sync_keys();
    let escrow_keys = recovery.escrow_keys();
    let ratchet_ctx = InternalDecryptContext {
        our_email: &our_email,
        passphrase: &passphrase,
        identity_key: identity_key.as_deref(),
        previous_keys: &previous_keys,
        ratchet_keys: &ratchet_keys,
        inbound_keys: &inbound_keys,
        recovery: &recovery,
        sync_keys: &sync_keys,
        escrow_keys: &escrow_keys,
        client,
        access_token: &access_token,
    };

    backfill_missing_message_ids(db);

    updated_ids.extend(retry_sealed_messages(db, &ratchet_ctx).await);

    match sync_custom_folders(db, client, &access_token, identity_key.as_deref(), &previous_keys).await {
        Ok(changed) => mailboxes_changed = changed,
        Err(msg) => {
            rate_limited = is_rate_limit_message(&msg);
            if !rate_limited {
                tracing::warn!("{}", msg);
            }
            last_err = Some(msg);
            all_folders_complete = false;
        }
    }
    let custom_folders = db.list_custom_folders().unwrap_or_default();
    let known_tokens: HashSet<String> = custom_folders.iter().map(|f| f.label_token.clone()).collect();

    let tag_writes_at_start = db.tag_writes.load(std::sync::atomic::Ordering::SeqCst);
    if !rate_limited {
        match sync_custom_tags(db, client, &access_token, identity_key.as_deref(), &previous_keys).await {
            Ok(affected) => {
                updated_ids.extend(affected);
                updated_ids.extend(
                    crate::tag_ops::migrate_local_keywords(db, client, &access_token, identity_key.as_deref())
                        .await,
                );
            }
            Err(msg) if is_rate_limit_message(&msg) => rate_limited = true,
            Err(msg) => tracing::warn!("{}", msg),
        }
    }
    let known_tags: HashSet<String> = db
        .list_custom_tags()
        .unwrap_or_default()
        .into_iter()
        .map(|tag| tag.tag_token)
        .collect();

    let queries = build_folder_queries();
    let total_folders = queries.len() + custom_folders.len();
    for folder_idx in 0..total_folders {
        if rate_limited {
            all_folders_complete = false;
            break;
        }
        let system_query = queries.get(folder_idx);
        let custom_folder = folder_idx
            .checked_sub(queries.len())
            .and_then(|i| custom_folders.get(i));
        let progress_label = match (system_query, custom_folder) {
            (Some(q), _) => q.label,
            _ => "folders",
        };
        emit_sync_progress(progress_label, folder_idx, total_folders, 0, 0);
        let mut cursor: Option<String> = None;
        let mut offset: i64 = 0;
        let mut total_fetched = 0usize;
        let mut listed_ids: Vec<String> = Vec::new();
        let max_per_folder = if custom_folder.is_some() {
            CUSTOM_FOLDER_MAX_ITEMS
        } else {
            SYSTEM_FOLDER_MAX_ITEMS
        };
        loop {
            let page: Result<FolderPage, BridgeError> = match (system_query, custom_folder) {
                (Some(folder_query), _) => {
                    let mut q = folder_query.query.clone();
                    q.cursor = cursor.clone();
                    client.list_mail(&access_token, &q).await.map(|resp| FolderPage {
                        label: folder_query.label.to_string(),
                        total: resp.total.max(0) as usize,
                        has_more: resp.has_more,
                        next_cursor: resp.next_cursor,
                        items: resp.items,
                    })
                }
                (None, Some(folder)) => client
                    .list_folder_mail(&access_token, &folder.label_token, CUSTOM_FOLDER_PAGE, offset)
                    .await
                    .map(|resp| {
                        let fetched = resp.items.len();
                        FolderPage {
                            label: crate::folders::folder_label(&folder.label_token),
                            total: resp.total.max(0) as usize,
                            has_more: resp.has_more && fetched > 0,
                            next_cursor: (resp.has_more && fetched > 0).then(String::new),
                            items: resp
                                .items
                                .into_iter()
                                .filter(|i| i.is_spam != Some(true) && !seen_ids.contains(&i.id))
                                .collect(),
                        }
                    }),
                (None, None) => break,
            };
            match page {
                Ok(resp) => {
                    let folder_total = resp.total.min(max_per_folder);
                    tracing::debug!(
                        "Synced {} page - {} items (total: {}, has_more: {})",
                        progress_label,
                        resp.items.len(),
                        resp.total,
                        resp.has_more
                    );
                    let mut new_ids: Vec<String> = Vec::new();
                    let page_ids: Vec<&str> = resp.items.iter().map(|i| i.id.as_str()).collect();
                    let mut id_counts: HashMap<&str, usize> = HashMap::new();
                    for id in &page_ids {
                        *id_counts.entry(id).or_default() += 1;
                    }
                    let snapshot = db.cached_sync_states(&page_ids).unwrap_or_default();
                    let owned_ids: Vec<String> = page_ids.iter().map(|id| id.to_string()).collect();
                    let tag_snapshot = db.message_tags(&owned_ids).unwrap_or_default();
                    let mut flag_updates: Vec<(&MailItem, i64, i64)> = Vec::new();
                    for item in &resp.items {
                        seen_ids.insert(item.id.clone());
                        listed_ids.push(item.id.clone());
                        if is_valid_item_id(&item.id)
                            && db.tag_writes.load(std::sync::atomic::Ordering::SeqCst) == tag_writes_at_start
                        {
                            if let Some(wanted) = server_tags_differ(item, &known_tags, &tag_snapshot) {
                                if db.set_message_tags(&item.id, &wanted).unwrap_or(false)
                                    && snapshot.contains_key(&item.id)
                                {
                                    updated_ids.push(item.id.clone());
                                }
                            }
                        }
                        let item_folder = if custom_folder.is_some() {
                            resp.label.clone()
                        } else {
                            target_folder(&resp.label, item, &known_tokens)
                        };
                        if id_counts.get(item.id.as_str()) == Some(&1) {
                            let state = snapshot.get(&item.id);
                            match cached_shortcut(state, &item_folder, item) {
                                Some(CachedShortcut::Unchanged) => continue,
                                Some(CachedShortcut::FlagsOnly(flags)) => {
                                    flag_updates.push((item, state.map_or(0, |s| s.flags), flags));
                                    continue;
                                }
                                None => {}
                            }
                        }
                        let outcome = match prepare_mail_item(
                            db,
                            &item_folder,
                            item,
                            &passphrase,
                            identity_key.as_deref(),
                            &previous_keys,
                            &inbound_keys,
                        ) {
                            Prepared::Done(outcome) => outcome,
                            Prepared::Ready(prepared) => {
                                let mut downloaded: Option<Vec<CachedAttachment>> = None;
                                let mut content_failed = false;
                                let mut permanently_unavailable = false;
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
                                        &previous_keys,
                                        None,
                                    )
                                    .await
                                    {
                                        Ok(list) => downloaded = Some(list),
                                        Err(AttachmentFetchError::Transport(e)) => {
                                            tracing::debug!(
                                                "attachment download for {} deferred: {}",
                                                item.id,
                                                e
                                            );
                                        }
                                        Err(AttachmentFetchError::Permanent(e)) => {
                                            tracing::debug!(
                                                "attachment download for {} unavailable: {}",
                                                item.id,
                                                e
                                            );
                                            permanently_unavailable = true;
                                        }
                                        Err(AttachmentFetchError::Content(e)) => {
                                            tracing::debug!(
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
                                    &item_folder,
                                    item,
                                    prepared,
                                    downloaded,
                                );
                                if permanently_unavailable {
                                    let _ =
                                        db.set_attachments_state(&item.id, ATTACHMENTS_FAILED);
                                } else if content_failed {
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
                            failed_inbound.push((item_folder.clone(), item.clone()));
                        }
                        if outcome.was_new {
                            new_ids.push(item.id.clone());
                            if db_body_is_placeholder(db, &item.id) {
                                if let Some(bundle) =
                                    try_decrypt_internal_mail(item, &ratchet_ctx).await
                                {
                                    store_unsealed_message(db, &item.id, &bundle);
                                } else {
                                    note_sealed_retry(&item.id, std::time::Instant::now());
                                }
                            }
                        }
                    }
                    let writes: Vec<(String, i64, i64)> = flag_updates
                        .iter()
                        .map(|(item, expected, flags)| (item.id.clone(), *expected, *flags))
                        .collect();
                    let stale: HashSet<String> = match db.set_message_flags_if_unchanged(&writes) {
                        Ok(stale) => stale.into_iter().collect(),
                        Err(_) => writes.into_iter().map(|(id, _, _)| id).collect(),
                    };
                    for (item, _, _) in &flag_updates {
                        if !stale.contains(&item.id) || reconcile_server_flags(db, item) {
                            updated_ids.push(item.id.clone());
                        }
                    }
                    if !new_ids.is_empty() {
                        any_inserted = true;
                        let id_refs: Vec<&str> = new_ids.iter().map(|s| s.as_str()).collect();
                        let _ = db.jmap_record_sync_batch("Email", &id_refs);
                    }
                    total_fetched += resp.items.len();
                    emit_sync_progress(
                        progress_label,
                        folder_idx,
                        total_folders,
                        total_fetched.min(folder_total),
                        folder_total,
                    );
                    let page_all_cached = !resp.items.is_empty() && new_ids.is_empty();
                    let reached_end = !resp.has_more || resp.next_cursor.is_none();
                    let capped = total_fetched >= max_per_folder
                        || (custom_folder.is_some() && offset + CUSTOM_FOLDER_PAGE >= CUSTOM_FOLDER_MAX_ITEMS as i64);
                    let done_with_folder =
                        reached_end || capped || (!deep && page_all_cached);
                    if done_with_folder {
                        if !reached_end {
                            all_folders_complete = false;
                            if capped {
                                capped_listings.push(std::mem::take(&mut listed_ids));
                            } else {
                                capped_only = false;
                            }
                        }
                        break;
                    }
                    cursor = resp.next_cursor;
                    offset += CUSTOM_FOLDER_PAGE;
                }
                Err(e) => {
                    let msg = format!("failed to sync {}: {}", progress_label, e);
                    rate_limited = is_rate_limit_message(&msg);
                    if !rate_limited {
                        tracing::warn!("{}", msg);
                    }
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
            let (fresh_identity_key, fresh_previous_keys, fresh_inbound_keys) = {
                let s = session.read().await;
                (s.identity_key.clone(), s.previous_keys.clone(), s.inbound_keys.clone())
            };
            let (healed_new, healed_updated) = retry_failed_inbound_items(
                db,
                &failed_inbound,
                &passphrase,
                fresh_identity_key.as_deref(),
                &fresh_previous_keys,
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

    if !rate_limited {
        let backfilled = backfill_pending_attachments(
            db,
            client,
            &access_token,
            &passphrase,
            identity_key.as_deref(),
            &previous_keys,
            &inbound_keys,
            &attachments_handled,
        )
        .await;
        updated_ids.extend(backfilled);

        let unsealed = retry_sealed_messages(db, &ratchet_ctx).await;
        updated_ids.extend(unsealed);
    }

    let account_keys = session.read().await.account_keys.clone();
    match identity_key.as_deref().filter(|_| !rate_limited) {
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
                            let draft_keys = crate::crypto::draft::DraftKeys {
                                identity_key: ik,
                                previous_keys: &previous_keys,
                                account_keys: &account_keys,
                                passphrase: &passphrase,
                            };
                            let content = match crate::crypto::draft::decrypt_draft_content_with_keys(
                                &d.encrypted_content,
                                &d.content_nonce,
                                &draft_keys,
                            ) {
                                Ok(c) => c,
                                Err(_) => {
                                    tracing::debug!("web draft decrypt skipped");
                                    continue;
                                }
                            };
                            let date = normalize_date_rfc3339(&d.updated_at);
                            let was_new =
                                cache_web_draft(db, &d.id, &content, &our_email, &date, d.version, d.reply_to_id.as_deref());
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
                                capped_only = false;
                            }
                            break;
                        }
                        cursor = resp.next_cursor;
                    }
                    Err(e) => {
                        let msg = format!("failed to sync web drafts: {}", e);
                        rate_limited = is_rate_limit_message(&msg);
                        if !rate_limited {
                            tracing::warn!("{}", msg);
                        }
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
        if let Ok(local) = db.list_all_cached_id_folder_dates() {
            for (id, folder, _) in local {
                if !seen_ids.contains(&id)
                    && db.delete_message_by_aster_id(&id).is_ok() {
                        tracing::info!("sync: pruned {} from {} (gone on server)", id, folder);
                        destroyed_ids.push(id);
                    }
            }
        }
    } else if deep && last_err.is_none() && capped_only && !capped_listings.is_empty() {
        if let Ok(local) = db.list_all_cached_id_folder_dates() {
            let candidates = capped_prune_candidates(&local, &seen_ids, &capped_listings);
            for id in confirm_gone_on_server(client, &access_token, &candidates).await {
                if db.delete_message_by_aster_id(&id).is_ok() {
                    tracing::info!("sync: pruned {} (gone on server)", id);
                    destroyed_ids.push(id);
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

    if any_inserted || mailboxes_changed || !destroyed_ids.is_empty() || !updated_ids.is_empty() {
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

    if rate_limited {
        tracing::warn!(
            "sync: the server is limiting requests for this account, so sync pauses for {} seconds",
            RATE_LIMIT_PAUSE.as_secs()
        );
        last_err = Some(RATE_LIMIT_MESSAGE.to_string());
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollExit {
    AccessRevoked,
    TriggerClosed,
}

#[derive(Debug, Clone, Copy)]
pub struct PollTuning {
    pub interval: std::time::Duration,
    pub plan_check_every: u32,
}

impl PollTuning {
    pub fn from_interval_secs(poll_interval_secs: Option<u64>) -> Self {
        let secs = poll_interval_secs.filter(|&v| v >= 5).unwrap_or(POLL_INTERVAL_SECS);
        Self {
            interval: std::time::Duration::from_secs(secs),
            plan_check_every: PLAN_CHECK_INTERVAL,
        }
    }
}

pub async fn run_poll_loop(
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    db: Arc<Database>,
    jmap_broadcaster: Option<broadcast::Sender<StateChange>>,
    trigger_rx: SyncTriggerRx,
    poll_interval_secs: Option<u64>,
) -> PollExit {
    run_poll_loop_tuned(
        session,
        client,
        db,
        jmap_broadcaster,
        trigger_rx,
        PollTuning::from_interval_secs(poll_interval_secs),
    )
    .await
}

pub async fn run_poll_loop_tuned(
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    db: Arc<Database>,
    jmap_broadcaster: Option<broadcast::Sender<StateChange>>,
    mut trigger_rx: SyncTriggerRx,
    tuning: PollTuning,
) -> PollExit {
    migrate_legacy_dates(&db);
    report_envelope_capability(&session, &client).await;
    let interval_dur = tuning.interval;
    let plan_check_every = tuning.plan_check_every.max(1);
    let mut interval = tokio::time::interval(interval_dur);
    let mut last_tick = tokio::time::Instant::now();
    let mut sync_count: u32 = 0;
    let mut last_deep_at: Option<tokio::time::Instant> = None;
    let mut last_triggered_at: Option<tokio::time::Instant> = None;
    let mut last_triggered_result: Result<(), String> = Ok(());
    let mut paused_until: Option<tokio::time::Instant> = None;
    let deep_due = |last: &Option<tokio::time::Instant>| {
        last.is_none_or(|t| {
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
                    crate::auth::session::request_token_refresh();
                }
                if crate::auth::session::session_rejected() {
                    tracing::debug!("sync: skipping the scheduled pass until sign-in succeeds");
                    continue;
                }
                if sync_is_paused(paused_until, now) {
                    tracing::debug!("sync: skipping the scheduled pass while the server limits requests");
                    continue;
                }
                sync_count += 1;
                if sync_count.is_multiple_of(plan_check_every)
                    && !check_plan_access(&session, &client).await {
                        tracing::warn!("sync: bridge access revoked - stopping poll loop");
                        emit_bridge_access_revoked();
                        return PollExit::AccessRevoked;
                    }
                let deep = deep_due(&last_deep_at);
                let result = run_sync_pass(&session, &client, &db, jmap_broadcaster.as_ref(), deep).await;
                crate::account_state::observe(&result);
                paused_until = pause_after(&result, tokio::time::Instant::now());
                if deep && result.is_ok() {
                    last_deep_at = Some(tokio::time::Instant::now());
                    report_envelope_capability(&session, &client).await;
                }
                if let Err(ref e) = result {
                    if e.contains("plan_upgrade_required") {
                        tracing::warn!("sync: plan_upgrade_required from server - stopping poll loop");
                        emit_bridge_access_revoked();
                        return PollExit::AccessRevoked;
                    }
                }
            }
            maybe_trigger = trigger_rx.recv() => {
                let Some(trigger) = maybe_trigger else { return PollExit::TriggerClosed; };
                let mut waiting = vec![trigger.done];
                while let Ok(queued) = trigger_rx.try_recv() {
                    waiting.push(queued.done);
                }
                let cooling = last_triggered_at
                    .is_some_and(|at| at.elapsed() < TRIGGER_COOLDOWN);
                if cooling || sync_is_paused(paused_until, tokio::time::Instant::now()) {
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
                crate::account_state::observe(&result);
                paused_until = pause_after(&result, tokio::time::Instant::now());
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
                        return PollExit::AccessRevoked;
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

    #[test]
    fn idle_http_connections_outlive_the_poll_interval() {
        assert!(crate::tls_pinning::POOL_IDLE_TIMEOUT.as_secs() > POLL_INTERVAL_SECS);
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
            labels: None,
            tag_tokens: None,
        }
    }

    fn matches_transport(e: &AttachmentFetchError) -> bool {
        matches!(e, AttachmentFetchError::Transport(_))
    }

    fn matches_permanent(e: &AttachmentFetchError) -> bool {
        matches!(e, AttachmentFetchError::Permanent(_))
    }

    fn matches_content(e: &AttachmentFetchError) -> bool {
        matches!(e, AttachmentFetchError::Content(_))
    }

    #[test]
    fn api_status_code_reads_the_leading_status() {
        assert_eq!(api_status_code("503 Service Unavailable: busy"), Some(503));
        assert_eq!(api_status_code("404:"), Some(404));
        assert_eq!(api_status_code("no status here"), None);
    }

    #[test]
    fn server_failures_are_transient_not_permanent() {
        for message in ["500 Internal Server Error: x", "429 Too Many Requests: x", "408:"] {
            let classified = classify_api_error(BridgeError::Api(message.to_string()));
            assert!(matches_transport(&classified), "{} should defer", message);
        }
    }

    #[test]
    fn missing_rows_and_bad_requests_are_classified_apart() {
        assert!(matches_permanent(&classify_api_error(BridgeError::Api(
            "404 Not Found: gone".to_string()
        ))));
        assert!(matches_content(&classify_api_error(BridgeError::Api(
            "400 Bad Request: nope".to_string()
        ))));
    }

    #[test]
    fn crypto_failures_are_permanent() {
        assert!(matches_permanent(&classify_decrypt_error(
            BridgeError::Crypto("attachment key unavailable".to_string())
        )));
        assert!(matches_permanent(&classify_api_error(BridgeError::Crypto(
            "attachment key unavailable".to_string()
        ))));
        assert!(matches_content(&classify_decrypt_error(
            BridgeError::Database("locked".to_string())
        )));
    }

    #[test]
    fn an_explicit_zero_count_skips_the_attachment_request() {
        let json = serde_json::json!({"subject": "hi"});
        let mut item = item_with_envelope("mail-flagged", &json);
        item.has_attachments = Some(true);
        item.attachment_count = Some(0);
        assert_eq!(expected_attachment_count(&item, &[]), 0);
        item.attachment_count = None;
        assert_eq!(expected_attachment_count(&item, &[]), 1);
        item.attachment_count = Some(3);
        assert_eq!(expected_attachment_count(&item, &[]), 3);
    }

    #[test]
    fn a_permanent_failure_leaves_the_backlog_at_once() {
        let (_dir, db) = temp_db();
        db.upsert_cached_message(
            "mail-permanent",
            "inbox",
            Some("subject"),
            None,
            None,
            None,
            4,
            Some("body"),
            None,
        )
        .unwrap();
        db.set_attachments_state("mail-permanent", ATTACHMENTS_PENDING)
            .unwrap();
        assert_eq!(db.list_attachment_backlog(10).unwrap().len(), 1);
        db.set_attachments_state("mail-permanent", ATTACHMENTS_FAILED)
            .unwrap();
        assert!(db.list_attachment_backlog(10).unwrap().is_empty());
    }

    #[test]
    fn a_retryable_failure_gives_up_after_the_attempt_cap() {
        let (_dir, db) = temp_db();
        db.upsert_cached_message(
            "mail-retry",
            "inbox",
            Some("subject"),
            None,
            None,
            None,
            4,
            Some("body"),
            None,
        )
        .unwrap();
        db.set_attachments_state("mail-retry", ATTACHMENTS_PENDING)
            .unwrap();
        let mut attempts = 0;
        while attempts < ATTACHMENT_MAX_ATTEMPTS {
            attempts = db.bump_attachment_attempts("mail-retry").unwrap();
            assert!(attempts <= ATTACHMENT_MAX_ATTEMPTS);
        }
        assert_eq!(attempts, ATTACHMENT_MAX_ATTEMPTS);
        db.set_attachments_state("mail-retry", ATTACHMENTS_FAILED)
            .unwrap();
        assert!(db.list_attachment_backlog(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_failing_download_moves_behind_the_rest_of_the_backlog() {
        let (_dir, db) = temp_db();
        for id in ["mail-a", "mail-b"] {
            db.upsert_cached_message(
                id,
                "inbox",
                Some("subject"),
                None,
                None,
                None,
                4,
                Some("body"),
                None,
            )
            .unwrap();
            db.set_attachments_state(id, ATTACHMENTS_PENDING).unwrap();
        }
        let base = spawn_mock_list_server(Vec::new()).await;
        let client = ApiClient::new_with_base_url(&base);

        let first = db.list_attachment_backlog(10).unwrap()[0].0.clone();
        let updated = backfill_pending_attachments(
            &db,
            &client,
            "tok",
            b"pass",
            None,
            &[],
            &[],
            &HashSet::new(),
        )
        .await;

        assert!(updated.is_empty());
        let backlog = db.list_attachment_backlog(10).unwrap();
        assert_eq!(backlog.len(), 2);
        assert_ne!(backlog[0].0, first, "the failing message must not stay at the head");
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
    fn display_names_with_commas_stay_a_single_address() {
        let v = serde_json::json!({
            "from": {"name": "Doe, John", "email": "john@example.com"},
            "to": [
                {"name": "Roe, Jane", "email": "jane@example.com"},
                {"name": "Carol", "email": "carol@example.com"}
            ]
        });
        let from = extract_from_field(&v).unwrap();
        assert_eq!(from, "\"Doe, John\" <john@example.com>");
        assert_eq!(crate::address::split_address_list(&from).len(), 1);
        assert_eq!(
            crate::address::parse_mailbox(&from),
            ("Doe, John".to_string(), "john@example.com".to_string())
        );
        let to = extract_recipients(&v, "to").unwrap();
        assert_eq!(to, "\"Roe, Jane\" <jane@example.com>, Carol <carol@example.com>");
        assert_eq!(crate::address::split_address_list(&to).len(), 2);
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
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        let was_new = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new;
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
    fn cache_mail_item_keeps_cc_bcc_and_reply_to() {
        let (_dir, db) = temp_db();
        // The web app's envelope: recipients as {name, email} objects.
        let json = serde_json::json!({
            "subject": "Plans",
            "from": {"name": "Alice", "email": "alice@example.com"},
            "to": [{"name": "Bob", "email": "bob@example.com"}],
            "cc": [{"name": "Carol", "email": "carol@example.com"}, {"name": "", "email": "dan@example.com"}],
            "bcc": [{"name": "", "email": "erin@example.com"}],
            "date": "Wed, 21 May 2026 10:00:00 +0000",
            "body_text": "hi",
            "raw_headers": [{"name": "Reply-To", "value": "Team <team@example.com>"}]
        });
        let item = item_with_envelope("msg-cc", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        let meta: serde_json::Value =
            serde_json::from_str(&db.get_cached_message("msg-cc").unwrap().unwrap().raw_headers.unwrap()).unwrap();
        assert_eq!(meta["cc"], "Carol <carol@example.com>, dan@example.com");
        assert_eq!(meta["bcc"], "erin@example.com");
        assert_eq!(meta["reply_to"], "Team <team@example.com>");
    }

    #[test]
    fn cache_mail_item_reads_imported_string_recipients() {
        let (_dir, db) = temp_db();
        // Imported mail: recipients as plain strings, reply_to as a string.
        let json = serde_json::json!({
            "subject": "Invoice",
            "from": "shop@example.com",
            "to": ["me@example.com"],
            "cc": ["accounts@example.com"],
            "reply_to": "billing@example.com",
            "body_text": "attached"
        });
        let item = item_with_envelope("msg-imported", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        let meta: serde_json::Value = serde_json::from_str(
            &db.get_cached_message("msg-imported").unwrap().unwrap().raw_headers.unwrap(),
        )
        .unwrap();
        assert_eq!(meta["cc"], "accounts@example.com");
        assert_eq!(meta["reply_to"], "billing@example.com");
        assert!(meta.get("bcc").is_none());
    }

    #[test]
    fn cache_mail_item_prefers_plain_body_when_no_html() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "plain words"});
        let item = item_with_envelope("msg-plain", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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

        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        let first = db.get_cached_message("msg-move").unwrap().unwrap();
        assert_eq!(first.folder, "inbox");
        let inbox_uid = first.imap_uid;

        let was_new = cache_mail_item(&db, "archive", &item, b"pass", None, &[], &[]).was_new;
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

        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        assert_eq!(db.count_cached_messages("inbox").unwrap(), 1);
    }

    #[test]
    fn cache_mail_item_skips_on_undecryptable_envelope() {
        let (_dir, db) = temp_db();
        let mut item = item_with_envelope("msg-bad-env", &serde_json::json!({"subject": "x"}));
        item.encrypted_envelope = "!!!not-base64!!!".to_string();
        assert!(!cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        assert!(db.get_cached_message("msg-bad-env").unwrap().is_none());
    }

    #[test]
    fn cache_mail_item_truncates_oversized_body() {
        let (_dir, db) = temp_db();
        let big = "a".repeat(6 * 1024 * 1024);
        let json = serde_json::json!({"subject": "s", "body_text": big});
        let item = item_with_envelope("msg-big", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        let _ = cache_mail_item(&db, "inbox", &first, b"pass", None, &[], &[]);
        assert!(
            db.replay_check_and_record("msg-replay", &nonce_pbkdf2).unwrap(),
            "same nonce must be accepted"
        );
        assert!(
            db.replay_check_and_record("msg-replay", &STANDARD.encode([0x02u8])).unwrap(),
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
        let first = cache_mail_item(&db, "inbox", &undecryptable, b"pass", None, &[], &[]);
        assert!(!first.was_new, "an undecryptable item must not be cached");
        assert!(!db.body_cached("msg-rotate"));

        let re_encrypted = item_with_envelope("msg-rotate", &json);
        assert!(
            cache_mail_item(&db, "inbox", &re_encrypted, b"pass", None, &[], &[]).was_new,
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

        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);

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
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &stale_keys);
        assert!(!outcome.was_new);
        assert!(outcome.inbound_decrypt_failed);
        assert!(!db.body_cached("msg-heal"));

        let fresh_keys = [inbound_candidate(&recipient)];
        let failed = vec![("inbox".to_string(), item.clone())];
        let (new_ids, updated_ids) =
            retry_failed_inbound_items(&db, &failed, b"pass", None, &[], &fresh_keys);
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
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &stale_keys);
        assert!(outcome.inbound_decrypt_failed);

        let failed = vec![("inbox".to_string(), item)];
        let (new_ids, updated_ids) =
            retry_failed_inbound_items(&db, &failed, b"pass", None, &[], &stale_keys);
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
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &keys);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        assert_eq!(
            db.get_cached_message("msg-read-sync").unwrap().unwrap().flags & 1,
            0
        );

        item.is_read = Some(true);
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        assert!(!outcome.was_new);
        assert!(outcome.flags_changed);
        assert_eq!(
            db.get_cached_message("msg-read-sync").unwrap().unwrap().flags & 1,
            1
        );

        let repeat = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        assert!(!repeat.flags_changed, "no-op flag sync must not report change");
    }

    #[test]
    fn cached_message_starred_on_server_updates_local_flagged_bit() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let mut item = item_with_envelope("msg-star-sync", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);

        item.is_starred = Some(true);
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        assert!(outcome.flags_changed);
        assert_eq!(
            db.get_cached_message("msg-star-sync").unwrap().unwrap().flags & 4,
            4
        );

        item.is_starred = Some(false);
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        let uid = db.get_cached_message("msg-noflags").unwrap().unwrap().imap_uid;
        db.update_message_flags(uid as i64, "inbox", 5).unwrap();

        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        assert!(!outcome.flags_changed);
        assert_eq!(db.get_cached_message("msg-noflags").unwrap().unwrap().flags, 5);
    }

    #[test]
    fn received_mail_keeps_cc_bcc_and_reply_to_from_the_envelope() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({
            "subject": "team",
            "body_text": "b",
            "from": {"name": "Ann", "email": "ann@x.test"},
            "to": [{"name": "", "email": "me@aster.test"}],
            "cc": [{"name": "Carol", "email": "carol@x.test"}, {"name": "Doe, John", "email": "john@x.test"}],
            "bcc": [],
            "raw_headers": [{"name": "Reply-To", "value": "Help Desk <desk@x.test>"}]
        });
        let item = item_with_envelope("msg-cc", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        let cached = db.get_cached_message("msg-cc").unwrap().unwrap();
        let meta: serde_json::Value = serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta["cc"], "Carol <carol@x.test>, \"Doe, John\" <john@x.test>");
        assert!(meta.get("bcc").is_none());
        assert_eq!(meta["reply_to"], "Help Desk <desk@x.test>");

        let rendered = crate::message_render::render_text(&cached, &[]);
        assert!(rendered.contains("Cc: Carol <carol@x.test>, \"Doe, John\" <john@x.test>\r\n"));
        assert!(rendered.contains("Reply-To: Help Desk <desk@x.test>\r\n"));
        assert!(!rendered.contains("Bcc:"));
    }

    #[test]
    fn bridge_sent_and_appended_mail_keeps_string_array_cc() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({
            "subject": "s",
            "body_text": "b",
            "cc": ["bob@old.example", "eve@old.example"],
            "bcc": ["hidden@old.example"],
            "reply_to": "list@old.example"
        });
        let item = item_with_envelope("msg-append-cc", &json);
        assert!(cache_mail_item(&db, "sent", &item, b"pass", None, &[], &[]).was_new);
        let cached = db.get_cached_message("msg-append-cc").unwrap().unwrap();
        let rendered = crate::message_render::render_text(&cached, &[]);
        assert!(rendered.contains("Cc: bob@old.example, eve@old.example\r\n"));
        assert!(rendered.contains("Bcc: hidden@old.example\r\n"));
        assert!(rendered.contains("Reply-To: list@old.example\r\n"));
    }

    #[test]
    fn a_cached_message_without_addresses_is_backfilled_once() {
        let (_dir, db) = temp_db();
        let legacy_meta = serde_json::json!({"is_html": false, "message_id": "<m@x.test>"}).to_string();
        db.upsert_cached_message(
            "msg-legacy-cc",
            "inbox",
            Some("old"),
            Some("ann@x.test"),
            Some("me@aster.test"),
            Some("2026-06-14T00:00:00Z"),
            1,
            Some("b"),
            Some(&legacy_meta),
        )
        .unwrap();
        let first_uid = db.assign_uid_if_missing("inbox", "msg-legacy-cc").unwrap();
        let json = serde_json::json!({
            "subject": "old",
            "body_text": "fresh body must not replace the cached one",
            "cc": [{"name": "", "email": "carol@x.test"}]
        });
        let item = item_with_envelope("msg-legacy-cc", &json);

        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        assert!(!outcome.was_new);
        assert!(outcome.flags_changed, "backfill must be reported so JMAP clients refetch");
        let cached = db.get_cached_message("msg-legacy-cc").unwrap().unwrap();
        assert_eq!(cached.body_text.as_deref(), Some("b"));
        assert!(cached.imap_uid > first_uid, "IMAP clients must refetch the message");
        let meta: serde_json::Value = serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta["cc"], "carol@x.test");
        assert_eq!(meta["message_id"], "<m@x.test>");
        assert_eq!(meta[ADDRESS_META_VERSION_KEY], 1);

        let again = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        assert!(!again.flags_changed);
        assert_eq!(db.get_cached_message("msg-legacy-cc").unwrap().unwrap().imap_uid, cached.imap_uid);
    }

    #[test]
    fn a_cached_message_with_no_addresses_keeps_its_uid() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b"});
        let item = item_with_envelope("msg-no-cc", &json);
        db.upsert_cached_message("msg-no-cc", "inbox", Some("s"), None, None, None, 1, Some("b"), Some("{\"is_html\":false}"))
            .unwrap();
        let uid = db.assign_uid_if_missing("inbox", "msg-no-cc").unwrap();
        let outcome = cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        assert!(!outcome.flags_changed);
        let cached = db.get_cached_message("msg-no-cc").unwrap().unwrap();
        assert_eq!(cached.imap_uid, uid);
        let meta: serde_json::Value = serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta[ADDRESS_META_VERSION_KEY], 1);
    }

    fn mock_session() -> Arc<RwLock<crate::auth::session::Session>> {
        Arc::new(RwLock::new(crate::auth::session::Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: b"pass".to_vec(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
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
        let app = Router::new()
            .route(
                "/bridge/v1/messages",
                get(move || {
                    let body = body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/mail/v1/attachments/by-mail/:id",
                get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
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
            )
            .route(
                "/mail/v1/labels",
                get(|| async { Json(serde_json::json!({"labels": [], "has_more": false})) }),
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
            refresh_token: None,
            vault_passphrase: b"pass".to_vec(),
            identity_key: Some(ik.to_string()),
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }))
    }

    async fn spawn_mock_server_with_folders(
        labels: Vec<serde_json::Value>,
        folder_items: Vec<(&'static str, serde_json::Value)>,
    ) -> String {
        use axum::extract::Query;
        use axum::{routing::get, Json, Router};
        let labels_body = serde_json::json!({"labels": labels, "has_more": false});
        let app = Router::new()
            .route(
                "/bridge/v1/messages",
                get(move |Query(q): Query<HashMap<String, String>>| {
                    let items: Vec<serde_json::Value> = match q.get("label_token") {
                        Some(token) => folder_items
                            .iter()
                            .filter(|(t, _)| t == token)
                            .map(|(_, item)| item.clone())
                            .collect(),
                        None => Vec::new(),
                    };
                    async move {
                        let total = items.len();
                        Json(serde_json::json!({
                            "items": items,
                            "total": total,
                            "has_more": false,
                            "next_cursor": serde_json::Value::Null
                        }))
                    }
                }),
            )
            .route(
                "/mail/v1/drafts",
                get(|| async {
                    Json(serde_json::json!({"items": [], "has_more": false, "next_cursor": null}))
                }),
            )
            .route(
                "/mail/v1/labels",
                get(move || {
                    let labels_body = labels_body.clone();
                    async move { Json(labels_body) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn label_json(id: &str, token: &str, name: &str, parent: Option<&str>) -> serde_json::Value {
        let (encrypted_name, name_nonce) =
            crate::crypto::folder::encrypt_folder_name(name, "test-ik").unwrap();
        serde_json::json!({
            "id": id,
            "label_token": token,
            "encrypted_name": encrypted_name,
            "name_nonce": name_nonce,
            "is_system": false,
            "is_password_protected": false,
            "sort_order": 0,
            "parent_token": parent,
            "folder_type": "custom"
        })
    }

    #[tokio::test]
    async fn sync_pass_pulls_custom_folders_and_their_mail() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let labels = vec![
            label_json("srv-w", "tok_w", "Work", None),
            label_json("srv-r", "tok_r", "Reports", Some("tok_w")),
            label_json("srv-locked", "tok_locked", "Hidden", None),
            serde_json::json!({
                "id": "srv-sys",
                "label_token": "tok_sys",
                "encrypted_name": "x",
                "name_nonce": "y",
                "is_system": true
            }),
        ];
        let mut labels = labels;
        labels[2]["is_password_protected"] = serde_json::json!(true);
        let base = spawn_mock_server_with_folders(
            labels,
            vec![
                ("tok_w", server_item_json("in-work", "work mail")),
                ("tok_r", server_item_json("in-reports", "quarterly report")),
            ],
        )
        .await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session_with_identity_key("test-ik");

        run_sync_pass(&session, &client, &db, None, true).await.unwrap();

        let mut folders = db.list_custom_folders().unwrap();
        folders.sort_by(|a, b| a.label_token.cmp(&b.label_token));
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].label_token, "tok_r");
        assert_eq!(folders[0].name, "Reports");
        assert_eq!(folders[0].parent_token.as_deref(), Some("tok_w"));
        assert_eq!(folders[0].server_id, "srv-r");
        assert_eq!(folders[1].name, "Work");
        assert_eq!(folders[1].parent_token, None);

        assert_eq!(db.get_cached_message("in-work").unwrap().unwrap().folder, "folder:tok_w");
        assert_eq!(
            db.get_cached_message("in-reports").unwrap().unwrap().folder,
            "folder:tok_r"
        );

        let mailboxes = db.list_jmap_mailboxes().unwrap();
        let reports = mailboxes
            .iter()
            .find(|m| m.name == "Reports")
            .expect("Reports mailbox");
        let work = mailboxes.iter().find(|m| m.name == "Work").expect("Work mailbox");
        assert_eq!(reports.parent_id.as_deref(), Some(work.id.as_str()));
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
        cache_web_draft(&db, "web-draft-att", &content, "tester@aster.test", "2026-08-01T00:00:00Z", 2, None);

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
        cache_web_draft(&db, "web-draft-att", &without, "tester@aster.test", "2026-08-02T00:00:00Z", 3, None);
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
        cache_web_draft(&db, "web-draft-gone", &content, "tester@aster.test", "2026-08-01T00:00:00Z", 1, None);
        assert!(db.get_cached_message("web-draft-gone").unwrap().is_some());

        let base = spawn_mock_server_with_drafts(vec![], vec![]).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session_with_identity_key("test-ik");

        run_sync_pass(&session, &client, &db, None, true)
            .await
            .unwrap();

        assert!(db.get_cached_message("web-draft-gone").unwrap().is_none());
    }

    fn local_row(id: &str, folder: &str, date: Option<&str>) -> (String, String, Option<String>) {
        (id.to_string(), folder.to_string(), date.map(str::to_string))
    }

    #[test]
    fn capped_prune_candidates_stay_within_the_listed_range() {
        let local = vec![
            local_row("listed-new", "inbox", Some("2026-06-10T00:00:00Z")),
            local_row("listed-old", "inbox", Some("2026-06-01T00:00:00Z")),
            local_row("gone-in-range", "inbox", Some("2026-06-05T00:00:00Z")),
            local_row("older-than-listing", "inbox", Some("2026-05-01T00:00:00Z")),
            local_row("undated", "inbox", None),
            local_row("draft-in-range", "drafts", Some("2026-06-05T00:00:00Z")),
        ];
        let seen: HashSet<String> = ["listed-new", "listed-old"].iter().map(|s| s.to_string()).collect();
        let listing = vec!["listed-new".to_string(), "listed-old".to_string()];

        let candidates = capped_prune_candidates(&local, &seen, std::slice::from_ref(&listing));
        assert_eq!(candidates, vec!["gone-in-range".to_string()]);

        let narrower = vec!["listed-new".to_string()];
        assert!(
            capped_prune_candidates(&local, &seen, &[listing, narrower]).is_empty(),
            "the most recent capped listing sets the floor"
        );
        assert!(capped_prune_candidates(&local, &seen, &[vec!["unknown".to_string()]]).is_empty());
    }

    #[tokio::test]
    async fn only_messages_the_server_reports_missing_are_confirmed_gone() {
        use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
        let app = Router::new().route(
            "/bridge/v1/messages/:id",
            get(|Path(id): Path<String>| async move {
                match id.as_str() {
                    "alive" => Json(server_item_json("alive", "here")).into_response(),
                    "flaky" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = ApiClient::new_with_base_url(&format!("http://127.0.0.1:{}", port));
        let ids: Vec<String> = ["alive", "gone", "flaky", "gone-later"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let gone = confirm_gone_on_server(&client, "tok", &ids).await;

        assert_eq!(gone, vec!["gone".to_string()]);
    }

    async fn spawn_capped_mock_server(fail_listing: bool) -> String {
        use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
        let items: Vec<serde_json::Value> = (0..SYSTEM_FOLDER_MAX_ITEMS)
            .map(|i| {
                let mut item = server_item_json(&format!("listed-{}", i), "listed");
                item["created_at"] = serde_json::json!("2026-06-14T00:00:00Z");
                item
            })
            .collect();
        let body = serde_json::json!({
            "items": items,
            "total": SYSTEM_FOLDER_MAX_ITEMS + 500,
            "has_more": true,
            "next_cursor": "more"
        });
        let app = Router::new()
            .route(
                "/bridge/v1/messages",
                get(move || {
                    let body = body.clone();
                    async move {
                        if fail_listing {
                            StatusCode::BAD_GATEWAY.into_response()
                        } else {
                            Json(body).into_response()
                        }
                    }
                }),
            )
            .route(
                "/bridge/v1/messages/:id",
                get(|Path(id): Path<String>| async move {
                    if id == "beyond-cap" {
                        Json(server_item_json("beyond-cap", "old")).into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn cache_dated(db: &Database, id: &str, date: &str) {
        let item = item_with_envelope(id, &serde_json::json!({"subject": id, "body_text": "b", "date": date}));
        assert!(cache_mail_item(db, "inbox", &item, b"pass", None, &[], &[]).was_new);
    }

    #[tokio::test]
    async fn deep_sync_of_a_capped_folder_prunes_only_in_range_deletions() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        cache_dated(&db, "gone-in-range", "2026-07-01T00:00:00Z");
        cache_dated(&db, "beyond-cap", "2020-01-01T00:00:00Z");

        let base = spawn_capped_mock_server(false).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();

        run_sync_pass(&session, &client, &db, None, true).await.unwrap();

        assert!(db.get_cached_message("gone-in-range").unwrap().is_none());
        assert!(
            db.get_cached_message("beyond-cap").unwrap().is_some(),
            "a message older than the listed range must be kept"
        );
        assert!(db.get_cached_message("listed-0").unwrap().is_some());
    }

    #[tokio::test]
    async fn a_failed_listing_prunes_nothing() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        cache_dated(&db, "gone-in-range", "2026-07-01T00:00:00Z");

        let base = spawn_capped_mock_server(true).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();

        assert!(run_sync_pass(&session, &client, &db, None, true).await.is_err());

        assert!(db.get_cached_message("gone-in-range").unwrap().is_some());
    }

    #[tokio::test]
    async fn deep_sync_prunes_messages_deleted_on_server() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        let stale = item_with_envelope(
            "stale-1",
            &serde_json::json!({"subject": "old", "body_text": "b"}),
        );
        assert!(cache_mail_item(&db, "inbox", &stale, b"pass", None, &[], &[]).was_new);

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
        assert!(cache_mail_item(&db, "inbox", &stale, b"pass", None, &[], &[]).was_new);

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
        assert!(cache_mail_item(&db, "inbox", &stale, b"pass", None, &[], &[]).was_new);

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
        assert!(cache_mail_item(&db, "inbox", &unread, b"pass", None, &[], &[]).was_new);

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
    fn cached_shortcut_only_skips_items_that_need_no_other_change() {
        let (_dir, db) = temp_db();
        let json = serde_json::json!({"subject": "s", "body_text": "b", "from": "a@b.c"});
        let item = item_with_envelope("shortcut-1", &json);
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        let states = db.cached_sync_states(&["shortcut-1", "missing"]).unwrap();
        assert_eq!(states.len(), 1);
        let state = states.get("shortcut-1").unwrap();
        assert!(state.body_cached);
        assert_eq!(state.folder, "inbox");
        assert_eq!(state.uid_folders, vec!["inbox".to_string()]);

        assert!(matches!(
            cached_shortcut(Some(state), "inbox", &item),
            Some(CachedShortcut::Unchanged)
        ));
        let mut read = item.clone();
        read.is_read = Some(true);
        assert!(matches!(
            cached_shortcut(Some(state), "inbox", &read),
            Some(CachedShortcut::FlagsOnly(f)) if f == state.flags | 1
        ));
        assert!(cached_shortcut(Some(state), "archive", &item).is_none());
        assert!(cached_shortcut(None, "inbox", &item).is_none());

        let mut unmapped = state.clone();
        unmapped.uid_folders.clear();
        assert!(cached_shortcut(Some(&unmapped), "inbox", &item).is_none());
        let mut not_backfilled = state.clone();
        not_backfilled.raw_headers = Some(r#"{"is_html":false}"#.to_string());
        assert!(cached_shortcut(Some(&not_backfilled), "inbox", &item).is_none());
        let mut no_body = state.clone();
        no_body.body_cached = false;
        assert!(cached_shortcut(Some(&no_body), "inbox", &item).is_none());
    }

    #[test]
    fn flag_batch_skips_rows_changed_since_the_snapshot() {
        let (_dir, db) = temp_db();
        for id in ["batch-a", "batch-b"] {
            let item = item_with_envelope(id, &serde_json::json!({"subject": "s", "body_text": "b"}));
            cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]);
        }
        let a = db.get_message_flags_by_id("batch-a").unwrap();
        let b = db.get_message_flags_by_id("batch-b").unwrap();
        db.set_message_flags_by_id("batch-b", b | 8).unwrap();
        let stale = db
            .set_message_flags_if_unchanged(&[
                ("batch-a".to_string(), a, a | 1),
                ("batch-b".to_string(), b, b | 4),
            ])
            .unwrap();
        assert_eq!(stale, vec!["batch-b".to_string()]);
        assert_eq!(db.get_message_flags_by_id("batch-a").unwrap(), a | 1);
        assert_eq!(db.get_message_flags_by_id("batch-b").unwrap(), b | 8);
        assert!(db.set_message_flags_if_unchanged(&[]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn resync_of_cached_mail_updates_only_what_the_server_changed() {
        let (_dir, db) = temp_db();
        let db = Arc::new(db);
        for id in ["same-1", "same-2", "starred-3"] {
            let item = item_with_envelope(id, &serde_json::json!({"subject": "s", "body_text": "b"}));
            assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        }
        let before: Vec<_> = ["same-1", "same-2"]
            .iter()
            .map(|id| db.get_cached_message(id).unwrap().unwrap())
            .collect();

        let mut starred = server_item_json("starred-3", "s");
        starred["is_starred"] = serde_json::json!(true);
        let items = vec![
            server_item_json("same-1", "s"),
            server_item_json("same-2", "s"),
            starred,
        ];
        let base = spawn_mock_list_server(items).await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let session = mock_session();
        let (tx, mut rx) = broadcast::channel(8);

        run_sync_pass(&session, &client, &db, Some(&tx), false)
            .await
            .unwrap();

        assert_eq!(db.get_message_flags_by_id("starred-3").unwrap() & 4, 4);
        for old in &before {
            let now = db.get_cached_message(&old.aster_id).unwrap().unwrap();
            assert_eq!(now.flags, old.flags);
            assert_eq!(now.raw_headers, old.raw_headers);
            assert_eq!(now.body_text, old.body_text);
        }
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);

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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rate_limited_pass_stops_at_the_first_refusal() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let body = "rate limit exceeded";
                    let reply = format!(
                        "HTTP/1.1 429 Too Many Requests\r\nretry-after: 60\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        let (_dir, db) = temp_db();
        let session = mock_session();
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let result = run_sync_pass(&session, &client, &Arc::new(db), None, true).await;

        assert_eq!(result, Err(RATE_LIMIT_MESSAGE.to_string()));
        let seen = attempts.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            seen <= 2,
            "a refused pass made {} requests, so it kept asking after the server said to slow down",
            seen
        );
    }

    #[test]
    fn only_a_rate_limited_pass_pauses_sync() {
        let now = tokio::time::Instant::now();
        assert_eq!(pause_after(&Ok(()), now), None);
        assert_eq!(pause_after(&Err("failed to sync trash: network error".to_string()), now), None);
        let until = pause_after(&Err(RATE_LIMIT_MESSAGE.to_string()), now);
        assert_eq!(until, Some(now + RATE_LIMIT_PAUSE));
        assert!(sync_is_paused(until, now));
        assert!(sync_is_paused(until, now + RATE_LIMIT_PAUSE / 2));
        assert!(!sync_is_paused(until, now + RATE_LIMIT_PAUSE));
        assert!(!sync_is_paused(None, now));
    }

    #[test]
    fn rate_limit_refusals_are_told_apart_from_other_failures() {
        assert!(is_rate_limit_message(
            "failed to sync trash: API error: 429 Too Many Requests: rate limit exceeded"
        ));
        assert!(!is_rate_limit_message("failed to sync trash: API error: 500 Internal Server Error: "));
        assert!(!is_rate_limit_message("failed to sync labels: timed out"));
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);

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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
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
        assert!(cache_mail_item(&db, "inbox", &item, b"pass", None, &[], &[]).was_new);
        let cached = db.get_cached_message("count-only").unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_PENDING);
        let meta: serde_json::Value =
            serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta.get("attachment_count").and_then(|v| v.as_u64()), Some(1));
    }

    #[test]
    fn envelope_header_reads_raw_headers_case_insensitively() {
        let envelope = serde_json::json!({
            "raw_headers": [
                {"name": "Message-ID", "value": "<abc@example.com>"},
                {"name": "in-reply-to", "value": "<parent@example.com>"},
                {"name": "References", "value": " <root@example.com> <parent@example.com> "}
            ]
        });
        assert_eq!(
            envelope_header(&envelope, "message-id").as_deref(),
            Some("<abc@example.com>")
        );
        assert_eq!(
            envelope_header(&envelope, "IN-REPLY-TO").as_deref(),
            Some("<parent@example.com>")
        );
        assert_eq!(
            envelope_header(&envelope, "references").as_deref(),
            Some("<root@example.com> <parent@example.com>")
        );
        assert_eq!(envelope_header(&envelope, "subject"), None);
        assert_eq!(envelope_header(&serde_json::json!({}), "message-id"), None);
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

    fn seed_backlog_with_keys(db: &Database, count: usize, key: &[u8; 32]) -> Vec<String> {
        let meta = serde_json::json!({
            "attachment_count": 1,
            "attachments": [{
                "seq": 0,
                "name": "a.txt",
                "type": "text/plain",
                "size": 7,
                "key": STANDARD.encode(key)
            }]
        })
        .to_string();
        (0..count)
            .map(|i| {
                let id = format!("mail-backlog-{:03}", i);
                db.upsert_cached_message(
                    &id,
                    "inbox",
                    Some("subject"),
                    None,
                    None,
                    None,
                    4,
                    Some("body"),
                    Some(&meta),
                )
                .unwrap();
                db.set_attachments_state(&id, ATTACHMENTS_PENDING).unwrap();
                id
            })
            .collect()
    }

    #[tokio::test]
    async fn a_backlog_pass_keeps_going_past_one_batch_while_downloads_are_quick() {
        let (_dir, db) = temp_db();
        let key = [11u8; 32];
        let ids = seed_backlog_with_keys(&db, 60, &key);
        let row = sealed_attachment_row(0, &key, b"payload", "a.txt", "text/plain");
        let (base, hits) =
            spawn_mock_attachment_server(vec![], serde_json::json!({}), vec![row]).await;
        let client = ApiClient::new_with_base_url(&base);

        let updated = backfill_pending_attachments(
            &db,
            &client,
            "tok",
            b"pass",
            None,
            &[],
            &[],
            &HashSet::new(),
        )
        .await;

        assert_eq!(updated.len(), ids.len());
        assert!(updated.len() > ATTACHMENT_BACKLOG_BATCH);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), ids.len());
        assert!(db.list_attachment_backlog(100).unwrap().is_empty());
        for id in &ids {
            let cached = db.get_cached_message(id).unwrap().unwrap();
            assert_eq!(cached.attachments_state, ATTACHMENTS_STORED);
            assert!(cached.imap_uid > 0);
            let stored = db.get_message_attachments(id).unwrap();
            assert_eq!(stored.len(), 1);
            assert_eq!(stored[0].data, b"payload".to_vec());
        }
    }

    #[tokio::test]
    async fn a_backlog_pass_stops_at_the_per_pass_cap() {
        let (_dir, db) = temp_db();
        let key = [13u8; 32];
        let ids = seed_backlog_with_keys(&db, ATTACHMENT_BACKLOG_PER_PASS + 30, &key);
        let row = sealed_attachment_row(0, &key, b"payload", "a.txt", "text/plain");
        let (base, hits) =
            spawn_mock_attachment_server(vec![], serde_json::json!({}), vec![row]).await;
        let client = ApiClient::new_with_base_url(&base);

        let updated = backfill_pending_attachments(
            &db,
            &client,
            "tok",
            b"pass",
            None,
            &[],
            &[],
            &HashSet::new(),
        )
        .await;

        assert_eq!(updated.len(), ATTACHMENT_BACKLOG_PER_PASS);
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            ATTACHMENT_BACKLOG_PER_PASS
        );
        assert_eq!(
            db.list_attachment_backlog(1000).unwrap().len(),
            ids.len() - ATTACHMENT_BACKLOG_PER_PASS
        );
    }

    #[tokio::test]
    async fn a_backlog_pass_stops_at_the_first_transport_error() {
        let (_dir, db) = temp_db();
        let key = [12u8; 32];
        let ids = seed_backlog_with_keys(&db, 40, &key);

        use axum::{routing::get, Router};
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        let app = Router::new().route(
            "/mail/v1/attachments/by-mail/:id",
            get(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { axum::http::StatusCode::SERVICE_UNAVAILABLE }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = ApiClient::new_with_base_url(&format!("http://127.0.0.1:{}", port));
        let head = db.list_attachment_backlog(1).unwrap()[0].0.clone();

        let updated = backfill_pending_attachments(
            &db,
            &client,
            "tok",
            b"pass",
            None,
            &[],
            &[],
            &HashSet::new(),
        )
        .await;

        assert!(updated.is_empty());
        let requests = hits.load(std::sync::atomic::Ordering::SeqCst);
        assert!(requests >= 1);
        assert!(
            requests <= ATTACHMENT_BACKLOG_CONCURRENCY,
            "no new download may start after a transport error, saw {}",
            requests
        );
        let backlog = db.list_attachment_backlog(100).unwrap();
        assert_eq!(backlog.len(), ids.len());
        let bumped: i64 = db
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM message_cache WHERE attachment_attempts > 0",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(bumped, 1, "only the first transport failure bumps its attempts");
        assert_ne!(
            db.list_attachment_backlog(1).unwrap()[0].0,
            head,
            "the deferred item moved behind the rest of the backlog"
        );
    }

    #[tokio::test]
    async fn an_undecryptable_attachment_is_marked_failed_and_never_refetched() {
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
        assert_eq!(cached.attachments_state, ATTACHMENTS_FAILED);
        assert_eq!(cached.body_text.as_deref(), Some("see attached"));
        assert!(cached.imap_uid > 0);
        assert!(db.get_message_attachments("mail-broken").unwrap().is_empty());
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(db.list_attachment_backlog(10).unwrap().is_empty());

        run_sync_pass(&session, &client, &db, None, false)
            .await
            .unwrap();
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a key we do not hold must not be retried every poll"
        );
        assert_eq!(db.attachments_state("mail-broken").unwrap(), ATTACHMENTS_FAILED);
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
        assert_eq!(
            db.bump_attachment_attempts("mail-offline").unwrap(),
            1,
            "a server that is temporarily down must not burn an attempt"
        );
        assert_eq!(db.list_attachment_backlog(10).unwrap().len(), 1);
    }

}

#[cfg(test)]
mod sealed_retry_tests {
    use super::*;
    use crate::crypto::ratchet_recovery::SubjectBundle;
    use std::time::{Duration, Instant};

    fn temp_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        (dir, db)
    }

    fn cache_sealed(db: &Database, id: &str) {
        db.upsert_cached_message(
            id,
            "INBOX",
            Some(""),
            Some("alice@astermail.org"),
            Some("hello@astermail.org"),
            None,
            1,
            Some(RATCHET_PLACEHOLDER),
            Some("{\"is_html\":false,\"message_id\":\"<m@x>\"}"),
        )
        .unwrap();
    }

    #[test]
    fn envelope_sender_address_handles_every_shape() {
        let cases = [
            (serde_json::json!({ "from": "alice@astermail.org" }), "alice@astermail.org"),
            (serde_json::json!({ "from": "Alice <Alice@AsterMail.org>" }), "Alice@AsterMail.org"),
            (serde_json::json!({ "from": { "email": " bob@astermail.org ", "name": "Bob" } }), "bob@astermail.org"),
            (serde_json::json!({ "from": { "name": "No address" } }), ""),
            (serde_json::json!({ "from": "broken > <order" }), "broken > <order"),
            (serde_json::json!({}), ""),
        ];
        for (parsed, expected) in cases {
            assert_eq!(envelope_sender_address(&parsed), expected, "{}", parsed);
        }
    }

    #[test]
    fn sealed_retry_backoff_doubles_and_caps() {
        assert_eq!(sealed_retry_delay(1), Duration::from_secs(SEALED_RETRY_BASE_SECS));
        assert_eq!(sealed_retry_delay(2), Duration::from_secs(SEALED_RETRY_BASE_SECS * 2));
        assert_eq!(sealed_retry_delay(3), Duration::from_secs(SEALED_RETRY_BASE_SECS * 4));
        assert_eq!(sealed_retry_delay(50), Duration::from_secs(SEALED_RETRY_MAX_SECS));
        assert_eq!(sealed_retry_delay(u32::MAX), Duration::from_secs(SEALED_RETRY_MAX_SECS));
    }

    #[test]
    fn sealed_retry_schedule_tracks_each_message() {
        let id = "sealed-retry-schedule-test";
        let now = Instant::now();
        clear_sealed_retry(id);
        assert!(sealed_retry_due(id, now));
        note_sealed_retry(id, now);
        assert!(!sealed_retry_due(id, now));
        assert!(!sealed_retry_due(id, now + Duration::from_secs(SEALED_RETRY_BASE_SECS - 1)));
        assert!(sealed_retry_due(id, now + Duration::from_secs(SEALED_RETRY_BASE_SECS)));
        note_sealed_retry(id, now);
        assert!(!sealed_retry_due(id, now + Duration::from_secs(SEALED_RETRY_BASE_SECS)));
        assert!(sealed_retry_due(id, now + Duration::from_secs(SEALED_RETRY_BASE_SECS * 2)));
        clear_sealed_retry(id);
        assert!(sealed_retry_due(id, now));
    }

    fn cache_body(db: &Database, id: &str, subject: &str, body: &str) {
        db.upsert_cached_message(
            id,
            "INBOX",
            Some(subject),
            Some("alice@astermail.org"),
            Some("hello@astermail.org"),
            None,
            1,
            Some(body),
            Some("{\"is_html\":false,\"message_id\":\"<m@x>\"}"),
        )
        .unwrap();
    }

    #[test]
    fn repair_unwraps_bundles_cached_by_older_versions() {
        let (_dir, db) = temp_db();
        cache_body(
            &db,
            "old-ratchet",
            "",
            "\u{1}ASTER_BUNDLE_V2\u{1}{\"s\":\"Aliases \",\"b\":\"<div><p>Hello</p></div>\"}",
        );
        cache_body(&db, "old-no-subject", "", "ASTER_BUNDLE_V2{\"b\":\"Hallo\nTeam\"}");
        cache_body(
            &db,
            "planted",
            "Real subject",
            "ASTER_BUNDLE_V2{\"s\":\"Your bank\",\"b\":\"pay here\"}",
        );
        cache_body(&db, "quoted", "", "Hi, see ASTER_BUNDLE_V2{\"s\":\"x\",\"b\":\"y\"}");
        cache_body(&db, "plain", "", "nothing to see");
        for id in ["old-ratchet", "old-no-subject", "planted", "quoted", "plain"] {
            db.assign_uid_if_missing("INBOX", id).unwrap();
        }
        let before_uid = db.get_cached_message("old-ratchet").unwrap().unwrap().imap_uid;

        let mut repaired = repair_cached_bundles(&db);
        repaired.sort();
        assert_eq!(repaired, vec!["old-no-subject".to_string(), "old-ratchet".to_string()]);

        let fixed = db.get_cached_message("old-ratchet").unwrap().unwrap();
        assert_eq!(fixed.subject.as_deref(), Some("Aliases"));
        assert_eq!(fixed.body_text.as_deref(), Some("<div><p>Hello</p></div>"));
        assert!(fixed.imap_uid > before_uid);
        let meta: serde_json::Value = serde_json::from_str(fixed.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta["is_html"], true);
        assert_eq!(meta["message_id"], "<m@x>");

        let no_subject = db.get_cached_message("old-no-subject").unwrap().unwrap();
        assert_eq!(no_subject.body_text.as_deref(), Some("Hallo\nTeam"));

        let planted = db.get_cached_message("planted").unwrap().unwrap();
        assert_eq!(planted.subject.as_deref(), Some("Real subject"));
        assert!(planted.body_text.unwrap().starts_with("ASTER_BUNDLE_V2"));

        let quoted = db.get_cached_message("quoted").unwrap().unwrap();
        assert!(quoted.body_text.unwrap().starts_with("Hi, see"));

        assert!(repair_cached_bundles(&db).is_empty());
    }

    #[test]
    fn unsealing_replaces_body_subject_and_keeps_meta() {
        let (_dir, db) = temp_db();
        cache_sealed(&db, "sealed-1");
        cache_sealed(&db, "sealed-2");
        db.upsert_cached_message("plain-1", "INBOX", Some("s"), None, None, None, 1, Some("hello"), None)
            .unwrap();
        assert!(db_body_is_placeholder(&db, "sealed-1"));
        assert!(!db_body_is_placeholder(&db, "plain-1"));
        assert!(!db_body_is_placeholder(&db, "missing"));
        let mut listed = db.list_ids_with_body(RATCHET_PLACEHOLDER, 10).unwrap();
        listed.sort();
        assert_eq!(listed, vec!["sealed-1".to_string(), "sealed-2".to_string()]);
        assert_eq!(db.list_ids_with_body(RATCHET_PLACEHOLDER, 1).unwrap().len(), 1);

        let bundle = SubjectBundle {
            subject: Some("Refund\r\nBcc: injected\tplease".to_string()),
            body: "<p>Hi there</p>".to_string(),
            sender_unverified: false,
        };
        assert!(store_unsealed_message(&db, "sealed-1", &bundle));
        let cached = db.get_cached_message("sealed-1").unwrap().unwrap();
        assert_eq!(cached.body_text.as_deref(), Some("<p>Hi there</p>"));
        assert_eq!(cached.subject.as_deref(), Some("Refund  Bcc: injected please"));
        let meta: serde_json::Value = serde_json::from_str(cached.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(meta["is_html"], true);
        assert_eq!(meta["message_id"], "<m@x>");
        assert!(meta.get("sender_unverified").is_none());
        assert!(!db_body_is_placeholder(&db, "sealed-1"));
        assert_eq!(db.list_ids_with_body(RATCHET_PLACEHOLDER, 10).unwrap(), vec!["sealed-2".to_string()]);

        let no_subject = SubjectBundle {
            subject: Some("   ".to_string()),
            body: "text".to_string(),
            sender_unverified: true,
        };
        assert!(store_unsealed_message(&db, "sealed-2", &no_subject));
        let kept = db.get_cached_message("sealed-2").unwrap().unwrap();
        assert_eq!(kept.subject.as_deref(), Some(""));
        assert_eq!(kept.body_text.as_deref(), Some("text"));
        let kept_meta: serde_json::Value = serde_json::from_str(kept.raw_headers.as_deref().unwrap()).unwrap();
        assert_eq!(kept_meta["sender_unverified"], true);
    }
}
