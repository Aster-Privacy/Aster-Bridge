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

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::api_client::{
    ApiClient, CreateAttachmentBody, CreateImportJobBody, ImportedEmail, StoreImportedEmailsBody,
    UpdateImportJobBody,
};
use crate::auth::session::Session;
use crate::db::Database;

pub const IMPORT_SOURCE: &str = "eml";
const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;
const MAX_ENVELOPE_CHARS: usize = 10 * 1024 * 1024;
const SYNC_LOOKUP_LIMIT: i64 = 200;
const SCOPED_LOOKUP_LIMIT: i64 = 25;
const SCOPED_LOOKUP_SKEW_SECS: i64 = 120;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AppendFlags {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub deleted: bool,
}

impl AppendFlags {
    fn from_list(list: &str) -> Self {
        let mut flags = Self::default();
        for token in list.split_whitespace() {
            let token = token.trim();
            if token.eq_ignore_ascii_case("\\Seen") {
                flags.seen = true;
            } else if token.eq_ignore_ascii_case("\\Flagged") {
                flags.flagged = true;
            } else if token.eq_ignore_ascii_case("\\Answered") {
                flags.answered = true;
            } else if token.eq_ignore_ascii_case("\\Draft") {
                flags.draft = true;
            } else if token.eq_ignore_ascii_case("\\Deleted") {
                flags.deleted = true;
            }
        }
        flags
    }

    pub fn local_bits(&self) -> i64 {
        let mut bits = 0i64;
        if self.seen {
            bits |= 1;
        }
        if self.answered {
            bits |= 2;
        }
        if self.flagged {
            bits |= 4;
        }
        if self.deleted {
            bits |= 8;
        }
        if self.draft {
            bits |= 16;
        }
        bits
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendCommand {
    pub mailbox: String,
    pub flags: AppendFlags,
    pub internal_date: Option<DateTime<Utc>>,
    pub literal_len: usize,
    pub non_sync: bool,
}

pub fn parse_append_command(args: &str) -> Option<AppendCommand> {
    let (mailbox, rest) = super::server::parse_imap_atom_or_quoted(args);
    if mailbox.is_empty() {
        return None;
    }

    let literal_start = rest.rfind('{')?;
    let literal_inner = {
        let after = &rest[literal_start + 1..];
        let end = after.find('}')?;
        &after[..end]
    };
    let non_sync = literal_inner.ends_with('+');
    let literal_len = literal_inner.trim_end_matches('+').trim().parse::<usize>().ok()?;

    let head = &rest[..literal_start];
    let flags = match (head.find('('), head.rfind(')')) {
        (Some(open), Some(close)) if close > open => AppendFlags::from_list(&head[open + 1..close]),
        _ => AppendFlags::default(),
    };

    let internal_date = head
        .rfind(')')
        .map(|close| &head[close + 1..])
        .unwrap_or(head)
        .find('"')
        .and_then(|open_rel| {
            let after_flags = head
                .rfind(')')
                .map(|close| &head[close + 1..])
                .unwrap_or(head);
            let after = &after_flags[open_rel + 1..];
            let close = after.find('"')?;
            parse_imap_internal_date(&after[..close])
        });

    Some(AppendCommand {
        mailbox,
        flags,
        internal_date,
        literal_len,
        non_sync,
    })
}

pub fn parse_imap_internal_date(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    for format in ["%d-%b-%Y %H:%M:%S %z", "%e-%b-%Y %H:%M:%S %z"] {
        if let Ok(dt) = DateTime::parse_from_str(trimmed, format) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    None
}

pub type ParsedAttachment = crate::crypto::attachment::OutgoingAttachment;

#[derive(Debug, Clone)]
pub struct ImportedMessage {
    pub message_id: String,
    pub message_id_hash: String,
    pub content_hash: String,
    pub envelope_json: String,
    pub received_at: DateTime<Utc>,
    pub item_type: &'static str,
    pub attachments: Vec<ParsedAttachment>,
}

fn iso_millis(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn base64_sha256(input: &str) -> String {
    STANDARD.encode(Sha256::digest(input.as_bytes()))
}

pub fn compute_message_id_hash(message_id: &str) -> String {
    base64_sha256(message_id)
}

pub fn compute_content_hash(
    from: &str,
    to: &[String],
    subject: &str,
    date_iso: Option<&str>,
    text_body: &str,
    html_body: &str,
) -> String {
    let canonical = [
        from.trim().to_lowercase(),
        to.join(",").trim().to_lowercase(),
        subject.trim().to_string(),
        date_iso.unwrap_or("").to_string(),
        text_body.trim().to_string(),
        html_body.trim().to_string(),
    ]
    .join("\n");

    base64_sha256(&canonical)
}

const RATE_LIMIT_ATTEMPTS: u32 = 3;

pub fn is_rate_limited(error: &crate::error::BridgeError) -> bool {
    let text = error.to_string();
    text.contains("429") || text.to_lowercase().contains("rate limit")
}

const TRANSIENT_PHRASES: [&str; 5] = [
    "bad gateway",
    "service unavailable",
    "gateway timeout",
    "gateway time-out",
    "network error",
];

pub fn is_transient(error: &crate::error::BridgeError) -> bool {
    if matches!(error, crate::error::BridgeError::Network(_)) {
        return true;
    }
    let text = error.to_string().to_lowercase();
    TRANSIENT_PHRASES.iter().any(|phrase| text.contains(phrase))
}

pub fn is_retryable(error: &crate::error::BridgeError) -> bool {
    is_rate_limited(error) || is_transient(error)
}

pub fn no_response_code(message: &str) -> &'static str {
    let text = message.to_lowercase();
    let transient = TRANSIENT_PHRASES
        .iter()
        .chain(["too many requests", "rate limit"].iter())
        .any(|phrase| text.contains(phrase));
    if transient {
        "UNAVAILABLE"
    } else {
        "SERVERBUG"
    }
}

pub fn rate_limit_backoff(attempt: u32) -> u64 {
    match attempt {
        0 => 5,
        1 => 10,
        2 => 20,
        3 => 30,
        _ => 60,
    }
}

pub fn item_type_for_folder(folder: &str) -> &'static str {
    if folder == "sent" {
        "sent"
    } else {
        "received"
    }
}

pub fn build_imported_message(
    raw_message: &[u8],
    folder: &str,
    internal_date: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<ImportedMessage> {
    use mail_parser::MessageParser;

    fn addr_list(a: Option<&mail_parser::Address<'_>>) -> Vec<String> {
        a.map(|l| {
            l.iter()
                .filter_map(|x| x.address().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
    }

    fn header_text(parsed: &mail_parser::Message<'_>, name: &str) -> Option<String> {
        let header = parsed.header(name)?;
        let value = match header.as_text() {
            Some(text) => text.trim().to_string(),
            None => header
                .as_text_list()
                .map(|list| list.join(", "))
                .unwrap_or_default(),
        };

        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    let parsed = MessageParser::default().parse(raw_message)?;

    let from = parsed
        .from()
        .and_then(|list| list.first().cloned())
        .map(|addr| match (addr.name(), addr.address()) {
            (Some(name), Some(email)) => format!("{} <{}>", name, email),
            (None, Some(email)) => email.to_string(),
            (Some(name), None) => name.to_string(),
            (None, None) => String::new(),
        })
        .unwrap_or_default();

    let to = addr_list(parsed.to());
    let cc = addr_list(parsed.cc());
    let bcc = addr_list(parsed.bcc());
    let subject = parsed.subject().unwrap_or("").to_string();

    let header_date = parsed
        .date()
        .and_then(|d| DateTime::parse_from_rfc3339(&d.to_rfc3339()).ok())
        .map(|d| d.with_timezone(&Utc));
    let (received_at, date_known) = match (header_date, internal_date) {
        (Some(d), _) => (d, true),
        (None, Some(d)) => (d, false),
        (None, None) => (now, false),
    };

    let html_body = parsed.body_html(0).map(|s| s.to_string());
    let text_body = parsed.body_text(0).map(|s| s.to_string());

    let attachments = crate::crypto::attachment::mime_attachments(&parsed, MAX_ATTACHMENT_BYTES);

    let message_id = parsed
        .message_id()
        .map(|s| s.trim_matches(&['<', '>'][..]).to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{}@append.bridge.aster", uuid::Uuid::new_v4()));

    let date_iso = iso_millis(&received_at);
    let content_hash = compute_content_hash(
        &from,
        &to,
        &subject,
        if date_known { Some(&date_iso) } else { None },
        text_body.as_deref().unwrap_or(""),
        html_body.as_deref().unwrap_or(""),
    );

    let mut preserved_headers: Vec<serde_json::Value> = Vec::new();
    for name in [
        "Reply-To",
        "List-Unsubscribe",
        "List-Unsubscribe-Post",
        "In-Reply-To",
        "References",
        "X-Mailer",
        "Message-ID",
    ] {
        if let Some(value) = header_text(&parsed, name) {
            preserved_headers.push(serde_json::json!({"name": name, "value": value}));
        }
    }

    let mut envelope = serde_json::Map::new();
    envelope.insert("message_id".to_string(), serde_json::json!(message_id));
    envelope.insert("from".to_string(), serde_json::json!(from));
    envelope.insert("to".to_string(), serde_json::json!(to));
    envelope.insert("cc".to_string(), serde_json::json!(cc));
    envelope.insert("bcc".to_string(), serde_json::json!(bcc));
    envelope.insert("subject".to_string(), serde_json::json!(subject));
    envelope.insert("sent_at".to_string(), serde_json::json!(date_iso));
    envelope.insert("date".to_string(), serde_json::json!(date_iso));
    envelope.insert("body_html".to_string(), serde_json::json!(html_body));
    envelope.insert("body_text".to_string(), serde_json::json!(text_body));
    envelope.insert("html_body".to_string(), serde_json::json!(html_body));
    envelope.insert("text_body".to_string(), serde_json::json!(text_body));
    envelope.insert(
        "attachment_count".to_string(),
        serde_json::json!(attachments.len()),
    );
    envelope.insert("source".to_string(), serde_json::json!(IMPORT_SOURCE));
    envelope.insert("imported_at".to_string(), serde_json::json!(iso_millis(&now)));
    if let Some(reply_to) = header_text(&parsed, "Reply-To") {
        envelope.insert("reply_to".to_string(), serde_json::json!(reply_to));
    }
    if let Some(unsub) = header_text(&parsed, "List-Unsubscribe") {
        envelope.insert("list_unsubscribe".to_string(), serde_json::json!(unsub));
    }
    if let Some(unsub_post) = header_text(&parsed, "List-Unsubscribe-Post") {
        envelope.insert(
            "list_unsubscribe_post".to_string(),
            serde_json::json!(unsub_post),
        );
    }
    if !preserved_headers.is_empty() {
        envelope.insert("raw_headers".to_string(), serde_json::json!(preserved_headers));
    }

    Some(ImportedMessage {
        message_id_hash: compute_message_id_hash(&message_id),
        message_id,
        content_hash,
        envelope_json: serde_json::Value::Object(envelope).to_string(),
        received_at,
        item_type: item_type_for_folder(folder),
        attachments,
    })
}

static RECENT_SENDS: OnceLock<std::sync::Mutex<Vec<(String, std::time::Instant)>>> = OnceLock::new();

const RECENT_SEND_TTL_SECS: u64 = 3600;
const RECENT_SEND_CAP: usize = 500;

fn recent_sends() -> &'static std::sync::Mutex<Vec<(String, std::time::Instant)>> {
    RECENT_SENDS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn recent_send_keys(raw_message: &[u8]) -> Vec<String> {
    use mail_parser::MessageParser;

    let Some(parsed) = MessageParser::default().parse(raw_message) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    if let Some(id) = parsed
        .message_id()
        .map(|s| s.trim_matches(&['<', '>'][..]).to_string())
        .filter(|s| !s.is_empty())
    {
        keys.push(format!("mid:{}", id));
    }
    if let Some(subject) = parsed.subject().map(|s| s.trim().to_lowercase()) {
        if !subject.is_empty() {
            keys.push(format!("subj:{}", subject));
        }
    }
    keys
}

pub fn note_outgoing_message(raw_message: &[u8]) {
    let keys = recent_send_keys(raw_message);
    if keys.is_empty() {
        return;
    }
    let Ok(mut guard) = recent_sends().lock() else {
        return;
    };
    let now = std::time::Instant::now();
    guard.retain(|(_, at)| now.duration_since(*at).as_secs() < RECENT_SEND_TTL_SECS);
    for key in keys {
        guard.push((key, now));
    }
    let overflow = guard.len().saturating_sub(RECENT_SEND_CAP);
    if overflow > 0 {
        guard.drain(..overflow);
    }
}

pub fn was_recently_sent(raw_message: &[u8]) -> bool {
    let keys = recent_send_keys(raw_message);
    if keys.is_empty() {
        return false;
    }
    let Ok(guard) = recent_sends().lock() else {
        return false;
    };
    let now = std::time::Instant::now();
    guard.iter().any(|(key, at)| {
        now.duration_since(*at).as_secs() < RECENT_SEND_TTL_SECS && keys.iter().any(|k| k == key)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    Stored { uid: u32, aster_id: String },
    Duplicate { uid: Option<u32> },
}

static IMPORT_JOB: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static IMPORT_JOB_ACTIVITY: OnceLock<std::sync::Mutex<Option<std::time::Instant>>> = OnceLock::new();
static IMPORT_JOB_CLOSER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
const IMPORT_JOB_IDLE_SECS: u64 = 120;
const IMPORT_JOB_POLL_SECS: u64 = 20;
const IMPORT_PROGRESS_EMIT_MS: u128 = 1000;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportProgress {
    pub active: bool,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub imported: u64,
    pub duplicates: u64,
}

static IMPORT_PROGRESS: OnceLock<std::sync::Mutex<Option<ImportProgress>>> = OnceLock::new();
static IMPORT_PROGRESS_EMIT: OnceLock<std::sync::Mutex<Option<std::time::Instant>>> = OnceLock::new();

fn import_progress_slot() -> &'static std::sync::Mutex<Option<ImportProgress>> {
    IMPORT_PROGRESS.get_or_init(|| std::sync::Mutex::new(None))
}

fn import_progress_emit_slot() -> &'static std::sync::Mutex<Option<std::time::Instant>> {
    IMPORT_PROGRESS_EMIT.get_or_init(|| std::sync::Mutex::new(None))
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn current_import_progress() -> Option<ImportProgress> {
    import_progress_slot().lock().ok()?.clone()
}

fn apply_import_outcome(slot: &mut Option<ImportProgress>, stored: bool, now: u64) -> ImportProgress {
    if !slot.as_ref().map_or(false, |p| p.active) {
        *slot = Some(ImportProgress {
            active: true,
            started_at_ms: now,
            updated_at_ms: now,
            imported: 0,
            duplicates: 0,
        });
    }
    let progress = slot.as_mut().expect("import progress slot was reset above");
    if stored {
        progress.imported += 1;
    } else {
        progress.duplicates += 1;
    }
    progress.updated_at_ms = now;
    progress.clone()
}

fn apply_import_finish(slot: &mut Option<ImportProgress>, now: u64) -> Option<ImportProgress> {
    let progress = slot.as_mut().filter(|p| p.active)?;
    progress.active = false;
    progress.updated_at_ms = now;
    Some(progress.clone())
}

fn record_import_outcome(stored: bool) {
    let snapshot = {
        let Ok(mut guard) = import_progress_slot().lock() else {
            return;
        };
        apply_import_outcome(&mut guard, stored, epoch_ms())
    };
    emit_import_progress_throttled(&snapshot, false);
}

fn finish_import_progress() {
    let snapshot = {
        let Ok(mut guard) = import_progress_slot().lock() else {
            return;
        };
        apply_import_finish(&mut guard, epoch_ms())
    };
    if let Some(snapshot) = snapshot {
        emit_import_progress_throttled(&snapshot, true);
    }
}

fn emit_import_progress_throttled(progress: &ImportProgress, force: bool) {
    if !force {
        let Ok(mut guard) = import_progress_emit_slot().lock() else {
            return;
        };
        if let Some(last) = *guard {
            if last.elapsed().as_millis() < IMPORT_PROGRESS_EMIT_MS {
                return;
            }
        }
        *guard = Some(std::time::Instant::now());
    }
    crate::sync::poller::emit_import_progress(progress);
}

fn import_job_slot() -> &'static Mutex<HashMap<String, String>> {
    IMPORT_JOB.get_or_init(|| Mutex::new(HashMap::new()))
}

fn import_job_activity() -> &'static std::sync::Mutex<Option<std::time::Instant>> {
    IMPORT_JOB_ACTIVITY.get_or_init(|| std::sync::Mutex::new(None))
}

fn note_import_activity() {
    if let Ok(mut guard) = import_job_activity().lock() {
        *guard = Some(std::time::Instant::now());
    }
}

fn import_job_idle_for() -> Option<u64> {
    let guard = import_job_activity().lock().ok()?;
    guard.map(|at| at.elapsed().as_secs())
}

fn spawn_import_job_closer(client: Arc<ApiClient>, session: Arc<RwLock<Session>>) {
    use std::sync::atomic::Ordering;
    if IMPORT_JOB_CLOSER
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(IMPORT_JOB_POLL_SECS)).await;
            let idle = import_job_idle_for().unwrap_or(0);
            if idle < IMPORT_JOB_IDLE_SECS {
                continue;
            }
            let job_id = {
                let mut guard = import_job_slot().lock().await;
                guard.remove(client.base_url())
            };
            if let Some(job_id) = job_id {
                let token = session.read().await.access_token.to_string();
                if let Err(e) = client
                    .update_import_job(
                        &token,
                        &job_id,
                        &UpdateImportJobBody {
                            status: "completed",
                        },
                    )
                    .await
                {
                    tracing::warn!(error = %e, "could not close the append import job");
                }
            }
            finish_import_progress();
            IMPORT_JOB_CLOSER.store(false, Ordering::SeqCst);
            return;
        }
    });
}

async fn adoptable_import_job(client: &ApiClient, token: &str, same_source_only: bool) -> Option<String> {
    let listed = client.list_import_jobs(token).await.ok()?;
    let mut fallback = None;
    for job in listed.jobs {
        if job.status != "pending" && job.status != "processing" {
            continue;
        }
        if job.source == IMPORT_SOURCE {
            return Some(job.id);
        }
        if fallback.is_none() {
            fallback = Some(job.id);
        }
    }
    if same_source_only {
        None
    } else {
        fallback
    }
}

async fn start_import_job(client: &ApiClient, token: &str, job_id: &str) -> std::result::Result<(), String> {
    let mut attempt = 0u32;
    loop {
        match client
            .update_import_job(
                token,
                job_id,
                &UpdateImportJobBody {
                    status: "processing",
                },
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(e) if is_retryable(&e) && attempt < RATE_LIMIT_ATTEMPTS => {
                let wait = rate_limit_backoff(attempt);
                attempt += 1;
                tracing::warn!(
                    error = %e,
                    seconds = wait,
                    "the server is temporarily unavailable, retrying the import job start"
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                note_import_activity();
            }
            Err(e) => return Err(format!("could not start the import job: {}", e)),
        }
    }
}

async fn processing_import_job(client: &ApiClient, token: &str) -> std::result::Result<String, String> {
    let mut guard = import_job_slot().lock().await;
    let key = client.base_url().to_string();
    if let Some(existing) = guard.get(&key) {
        return Ok(existing.clone());
    }

    if let Some(adopted) = adoptable_import_job(client, token, true).await {
        start_import_job(client, token, &adopted).await?;
        guard.insert(key, adopted.clone());
        return Ok(adopted);
    }

    let mut attempt = 0u32;
    let job_id = loop {
        match client
            .create_import_job(
                token,
                &CreateImportJobBody {
                    source: IMPORT_SOURCE,
                    total_emails: 0,
                },
            )
            .await
        {
            Ok(created) => break created.id,
            Err(e) if is_retryable(&e) && attempt < RATE_LIMIT_ATTEMPTS => {
                let wait = rate_limit_backoff(attempt);
                attempt += 1;
                tracing::warn!(
                    error = %e,
                    seconds = wait,
                    "the server is temporarily unavailable, retrying the import job creation"
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                note_import_activity();
                if let Some(adopted) = adoptable_import_job(client, token, true).await {
                    break adopted;
                }
            }
            Err(e) => match adoptable_import_job(client, token, false).await {
                Some(adopted) => break adopted,
                None => return Err(format!("could not create the import job: {}", e)),
            },
        }
    };

    start_import_job(client, token, &job_id).await?;
    guard.insert(key, job_id.clone());
    Ok(job_id)
}

async fn forget_import_job(client: &ApiClient) {
    let mut guard = import_job_slot().lock().await;
    guard.remove(client.base_url());
}

async fn upload_attachments(
    client: &ApiClient,
    token: &str,
    passphrase: &[u8],
    mail_id: &str,
    attachments: &[ParsedAttachment],
) {
    for (seq, attachment) in attachments.iter().enumerate() {
        let sealed = {
            let attachment = attachment.clone();
            let passphrase = passphrase.to_vec();
            tokio::task::spawn_blocking(move || {
                crate::crypto::attachment::seal_attachment(&attachment, &passphrase)
            })
            .await
        };

        let sealed = match sealed {
            Ok(Ok(parts)) => parts,
            Ok(Err(e)) => {
                tracing::warn!("attachment sealing failed for {}: {}", attachment.name, e);
                continue;
            }
            Err(e) => {
                tracing::warn!("attachment sealing did not finish: {}", e);
                continue;
            }
        };

        let body = CreateAttachmentBody {
            encrypted_data: &STANDARD.encode(&sealed.encrypted_data),
            data_nonce: &STANDARD.encode(sealed.data_nonce),
            encrypted_meta: &sealed.sender_meta,
            meta_nonce: &STANDARD.encode(sealed.sender_meta_nonce),
            seq_num: seq as i16,
        };

        if let Err(e) = client.create_attachment(token, mail_id, &body).await {
            tracing::warn!("attachment upload failed for {}: {}", attachment.name, e);
        }
    }
}

pub async fn append_imported_message(
    db: &Arc<Database>,
    client: &Arc<ApiClient>,
    session: &Arc<RwLock<Session>>,
    folder: &str,
    raw_message: &[u8],
    flags: &AppendFlags,
    internal_date: Option<DateTime<Utc>>,
) -> std::result::Result<AppendOutcome, String> {
    let (token, identity_key, passphrase, inbound_keys) = {
        let s = session.read().await;
        (
            s.access_token.to_string(),
            s.identity_key.clone(),
            s.vault_passphrase.clone(),
            s.inbound_keys.clone(),
        )
    };
    let identity_key = identity_key
        .ok_or_else(|| "session has no identity key for envelope encryption".to_string())?;

    let (message, encrypted_envelope, envelope_nonce) = {
        let raw = raw_message.to_vec();
        let build_folder = folder.to_string();
        let build_key = identity_key.clone();
        let now = Utc::now();
        tokio::task::spawn_blocking(move || {
            let message = build_imported_message(&raw, &build_folder, internal_date, now)
                .ok_or_else(|| "could not parse the appended message".to_string())?;
            let (encrypted_envelope, envelope_nonce) =
                crate::crypto::envelope::encrypt_identity_key_envelope_with_version(
                    &message.envelope_json,
                    &build_key,
                    crate::crypto::envelope::ENVELOPE_VERSION_IMPORT,
                )
                .map_err(|e| format!("envelope encrypt failed: {}", e))?;
            Ok::<_, String>((message, encrypted_envelope, envelope_nonce))
        })
        .await
        .map_err(|e| format!("could not prepare the message: {}", e))??
    };

    if encrypted_envelope.len() > MAX_ENVELOPE_CHARS {
        return Err("the message body is too large to import".to_string());
    }

    let received_at = message.received_at.to_rfc3339();
    let attachment_count = message.attachments.len();

    note_import_activity();
    let stored_after = Utc::now();
    let mut job_id = processing_import_job(client, &token).await?;
    spawn_import_job_closer(client.clone(), session.clone());

    let mut rate_limit_waits = 0u32;
    let mut job_retried = false;
    let response = loop {
        let response = client
            .store_imported_emails(
                &token,
                &job_id,
                &StoreImportedEmailsBody {
                    emails: vec![ImportedEmail {
                        message_id_hash: &message.message_id_hash,
                        encrypted_envelope: &encrypted_envelope,
                        envelope_nonce: &envelope_nonce,
                        content_hash: &message.content_hash,
                        item_type: message.item_type,
                        received_at: &received_at,
                        has_attachments: attachment_count > 0,
                        attachment_count: attachment_count.min(i16::MAX as usize) as i16,
                        thread_token: None,
                    }],
                },
            )
            .await;

        let Err(e) = &response else { break response };

        if is_retryable(e) && rate_limit_waits < RATE_LIMIT_ATTEMPTS {
            let wait = rate_limit_backoff(rate_limit_waits);
            rate_limit_waits += 1;
            tracing::warn!(
                error = %e,
                seconds = wait,
                "the server is temporarily unavailable, waiting before retrying the import"
            );
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            note_import_activity();
            continue;
        }

        if job_retried {
            break response;
        }
        job_retried = true;
        forget_import_job(client).await;
        job_id = processing_import_job(client, &token).await?;
    };

    note_import_activity();
    let response = response.map_err(|e| format!("could not store the message: {}", e))?;

    if response.quota_exceeded || response.skipped_quota_count > 0 {
        return Err("your Aster storage is full".to_string());
    }

    if response.stored_count == 0 {
        if response.duplicate_count > 0 {
            record_import_outcome(false);
            crate::sync::poller::try_kick_sync();
            return Ok(AppendOutcome::Duplicate { uid: None });
        }
        return Err("the server rejected the message".to_string());
    }

    let aster_id = locate_stored_item(client, &token, &encrypted_envelope, stored_after).await?;

    if attachment_count > 0 {
        upload_attachments(client, &token, &passphrase, &aster_id, &message.attachments).await;
    }

    apply_placement(client, &token, &aster_id, folder, flags).await;

    let item = crate::api_client::MailItem {
        id: aster_id.clone(),
        item_type: message.item_type.to_string(),
        encrypted_envelope: encrypted_envelope.clone(),
        envelope_nonce: envelope_nonce.clone(),
        ephemeral_key: None,
        ephemeral_pq_key: None,
        sender_sealed: None,
        folder_token: String::new(),
        is_external: true,
        thread_token: None,
        thread_message_count: None,
        created_at: received_at.clone(),
        encrypted_metadata: None,
        metadata_nonce: None,
        metadata_version: None,
        scheduled_at: None,
        send_status: None,
        message_ts: Some(received_at.clone()),
        snoozed_until: None,
        expires_at: None,
        expiry_type: None,
        is_spam: Some(folder == "spam"),
        is_read: Some(flags.seen),
        is_starred: Some(flags.flagged),
        has_attachments: Some(attachment_count > 0),
        attachment_count: Some(attachment_count.min(i16::MAX as usize) as i16),
    };

    let local_attachments: Vec<crate::db::CachedAttachment> = message
        .attachments
        .iter()
        .enumerate()
        .map(|(seq, a)| crate::db::CachedAttachment {
            seq: seq as i64,
            name: a.name.clone(),
            content_type: a.mime_type.clone(),
            content_id: a.content_id.clone(),
            is_inline: a.is_inline,
            size: a.data.len() as i64,
            data: a.data.clone(),
        })
        .collect();

    let uid = {
        let cache_db = db.clone();
        let cache_folder = folder.to_string();
        let cache_id = aster_id.clone();
        let cache_bits = flags.local_bits() & !16;
        tokio::task::spawn_blocking(move || {
            crate::sync::poller::cache_mail_item(
                &cache_db,
                &cache_folder,
                &item,
                &passphrase,
                Some(&identity_key),
                &inbound_keys,
            );

            if !local_attachments.is_empty() {
                cache_db
                    .replace_message_attachments(&cache_id, &local_attachments)
                    .map_err(|e| format!("could not store attachments locally: {}", e))?;
            }

            let uid = cache_db
                .assign_uid_if_missing(&cache_folder, &cache_id)
                .map_err(|e| format!("could not assign a UID: {}", e))?;

            if cache_bits != 0 {
                let _ = cache_db.set_message_flags_by_id(&cache_id, cache_bits);
            }

            Ok::<_, String>(uid)
        })
        .await
        .map_err(|e| format!("could not store the message locally: {}", e))??
    };

    record_import_outcome(true);
    crate::sync::poller::try_kick_sync();

    Ok(AppendOutcome::Stored { uid, aster_id })
}

async fn lookup_stored_item(
    client: &ApiClient,
    token: &str,
    encrypted_envelope: &str,
    limit: i64,
    since: Option<&str>,
) -> std::result::Result<Option<String>, String> {
    let mut attempt = 0u32;
    let synced = loop {
        match client.sync_recent_items(token, limit, since).await {
            Ok(synced) => break synced,
            Err(e) if is_retryable(&e) && attempt < RATE_LIMIT_ATTEMPTS => {
                let wait = rate_limit_backoff(attempt);
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                note_import_activity();
            }
            Err(e) => {
                return Err(format!("could not confirm the stored message: {}", e));
            }
        }
    };

    Ok(synced
        .items
        .into_iter()
        .find(|item| item.encrypted_envelope == encrypted_envelope)
        .map(|item| item.id))
}

pub fn scoped_lookup_since(stored_after: DateTime<Utc>) -> String {
    iso_millis(&(stored_after - chrono::Duration::seconds(SCOPED_LOOKUP_SKEW_SECS)))
}

async fn locate_stored_item(
    client: &ApiClient,
    token: &str,
    encrypted_envelope: &str,
    stored_after: DateTime<Utc>,
) -> std::result::Result<String, String> {
    let since = scoped_lookup_since(stored_after);
    if let Some(id) = lookup_stored_item(
        client,
        token,
        encrypted_envelope,
        SCOPED_LOOKUP_LIMIT,
        Some(&since),
    )
    .await?
    {
        return Ok(id);
    }

    note_import_activity();
    lookup_stored_item(client, token, encrypted_envelope, SYNC_LOOKUP_LIMIT, None)
        .await?
        .ok_or_else(|| "the stored message was not found on the server".to_string())
}

async fn apply_placement(
    client: &ApiClient,
    token: &str,
    aster_id: &str,
    folder: &str,
    flags: &AppendFlags,
) {
    let mut patch = serde_json::Map::new();
    match folder {
        "archive" => {
            patch.insert("is_archived".to_string(), serde_json::json!(true));
            patch.insert("is_trashed".to_string(), serde_json::json!(false));
            patch.insert("is_spam".to_string(), serde_json::json!(false));
        }
        "trash" => {
            patch.insert("is_trashed".to_string(), serde_json::json!(true));
            patch.insert("is_archived".to_string(), serde_json::json!(false));
        }
        "spam" => {
            patch.insert("is_spam".to_string(), serde_json::json!(true));
            patch.insert("is_archived".to_string(), serde_json::json!(false));
            patch.insert("is_trashed".to_string(), serde_json::json!(false));
        }
        _ => {}
    }

    if !flags.seen {
        patch.insert("is_read".to_string(), serde_json::json!(false));
    }
    if flags.flagged {
        patch.insert("is_starred".to_string(), serde_json::json!(true));
    }

    if patch.is_empty() {
        return;
    }

    if let Err(e) = client
        .set_mailbox_flags(token, aster_id, serde_json::Value::Object(patch))
        .await
    {
        tracing::warn!("append placement update failed for {}: {}", aster_id, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn plain_append_parses_mailbox_and_literal() {
        let cmd = parse_append_command("\"INBOX\" {42}").unwrap();
        assert_eq!(cmd.mailbox, "INBOX");
        assert_eq!(cmd.literal_len, 42);
        assert!(!cmd.non_sync);
        assert_eq!(cmd.flags, AppendFlags::default());
        assert!(cmd.internal_date.is_none());
    }

    #[test]
    fn append_parses_flags_and_internal_date() {
        let cmd =
            parse_append_command("Archive (\\Seen \\Flagged) \"12-Jul-2024 13:04:05 +0200\" {17+}")
                .unwrap();
        assert_eq!(cmd.mailbox, "Archive");
        assert!(cmd.flags.seen);
        assert!(cmd.flags.flagged);
        assert!(!cmd.flags.draft);
        assert!(cmd.non_sync);
        assert_eq!(cmd.literal_len, 17);
        assert_eq!(cmd.internal_date, Some(ts("2024-07-12T11:04:05Z")));
    }

    #[test]
    fn append_parses_empty_flag_list() {
        let cmd = parse_append_command("INBOX () {5}").unwrap();
        assert_eq!(cmd.flags, AppendFlags::default());
        assert_eq!(cmd.literal_len, 5);
    }

    #[test]
    fn append_parses_date_without_flags() {
        let cmd = parse_append_command("INBOX \"01-Jan-2020 00:00:00 +0000\" {3}").unwrap();
        assert_eq!(cmd.internal_date, Some(ts("2020-01-01T00:00:00Z")));
        assert_eq!(cmd.literal_len, 3);
    }

    #[test]
    fn append_without_literal_is_rejected() {
        assert!(parse_append_command("INBOX (\\Seen)").is_none());
        assert!(parse_append_command("").is_none());
    }

    #[test]
    fn append_with_quoted_mailbox_containing_space_parses() {
        let cmd = parse_append_command("\"Junk\" (\\Seen) {9}").unwrap();
        assert_eq!(cmd.mailbox, "Junk");
        assert!(cmd.flags.seen);
    }

    #[test]
    fn internal_date_accepts_space_padded_day() {
        assert_eq!(
            parse_imap_internal_date(" 2-Feb-2021 08:09:10 -0500"),
            Some(ts("2021-02-02T13:09:10Z"))
        );
    }

    #[test]
    fn internal_date_rejects_garbage() {
        assert!(parse_imap_internal_date("not a date").is_none());
    }

    fn sample_eml() -> &'static [u8] {
        concat!(
            "Message-ID: <abc123@old.example>\r\n",
            "From: Alice Example <alice@old.example>\r\n",
            "To: mark@astermail.org\r\n",
            "Cc: bob@old.example\r\n",
            "Subject: Quarterly report\r\n",
            "Date: Fri, 12 Jul 2024 13:04:05 +0000\r\n",
            "In-Reply-To: <prev@old.example>\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Here is the report.\r\n"
        )
        .as_bytes()
    }

    #[test]
    fn imported_message_preserves_headers_and_date() {
        let msg =
            build_imported_message(sample_eml(), "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        assert_eq!(msg.message_id, "abc123@old.example");
        assert_eq!(msg.item_type, "received");
        assert_eq!(msg.received_at, ts("2024-07-12T13:04:05Z"));

        let envelope: serde_json::Value = serde_json::from_str(&msg.envelope_json).unwrap();
        assert_eq!(envelope["subject"], "Quarterly report");
        assert_eq!(envelope["from"], "Alice Example <alice@old.example>");
        assert_eq!(envelope["to"][0], "mark@astermail.org");
        assert_eq!(envelope["cc"][0], "bob@old.example");
        assert_eq!(envelope["date"], "2024-07-12T13:04:05.000Z");
        assert_eq!(envelope["sent_at"], "2024-07-12T13:04:05.000Z");
        assert_eq!(envelope["body_text"], "Here is the report.\r\n");
        assert_eq!(envelope["attachment_count"], 0);
        assert_eq!(envelope["source"], "eml");
        let headers = envelope["raw_headers"].as_array().unwrap();
        assert!(headers.iter().any(|h| h["name"] == "In-Reply-To"
            && h["value"]
                .as_str()
                .unwrap()
                .contains("prev@old.example")));
    }

    #[test]
    fn imported_message_hash_is_stable_across_runs() {
        let a = build_imported_message(sample_eml(), "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        let b = build_imported_message(sample_eml(), "inbox", None, ts("2026-09-01T10:00:00Z")).unwrap();
        assert_eq!(a.content_hash, b.content_hash);
        assert_eq!(a.message_id_hash, b.message_id_hash);
    }

    #[test]
    fn imported_message_hash_differs_for_different_content() {
        let a = build_imported_message(sample_eml(), "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        let other = sample_eml()
            .to_vec()
            .into_iter()
            .collect::<Vec<u8>>()
            .split(|b| *b == b'\n')
            .map(|line| String::from_utf8_lossy(line).to_string())
            .collect::<Vec<String>>()
            .join("\n")
            .replace("Quarterly report", "Annual report");
        let b =
            build_imported_message(other.as_bytes(), "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        assert_ne!(a.content_hash, b.content_hash);
    }

    #[test]
    fn message_id_hash_matches_the_web_scheme() {
        assert_eq!(
            compute_message_id_hash("abc123@old.example"),
            STANDARD.encode(Sha256::digest(b"abc123@old.example"))
        );
    }

    #[test]
    fn content_hash_matches_the_web_canonical_string() {
        let expected = STANDARD.encode(Sha256::digest(
            "alice@old.example\nmark@astermail.org\nSubject\n2024-07-12T13:04:05.000Z\ntext\n<p>html</p>"
                .as_bytes(),
        ));
        assert_eq!(
            compute_content_hash(
                "  Alice@Old.Example  ",
                &["Mark@astermail.org".to_string()],
                " Subject ",
                Some("2024-07-12T13:04:05.000Z"),
                " text ",
                " <p>html</p> ",
            ),
            expected
        );
    }

    #[test]
    fn missing_date_header_falls_back_to_internal_date() {
        let raw = concat!(
            "From: alice@old.example\r\n",
            "To: mark@astermail.org\r\n",
            "Subject: No date\r\n",
            "\r\n",
            "body\r\n"
        )
        .as_bytes();
        let msg = build_imported_message(
            raw,
            "inbox",
            Some(ts("2019-03-04T05:06:07Z")),
            ts("2026-08-11T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(msg.received_at, ts("2019-03-04T05:06:07Z"));

        let other_internal_date = build_imported_message(
            raw,
            "inbox",
            Some(ts("2021-06-07T08:09:10Z")),
            ts("2026-08-11T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(
            msg.content_hash, other_internal_date.content_hash,
            "the web importer leaves the date out of the hash when the source has no Date header, so the internal date must not enter it either"
        );
    }

    #[test]
    fn missing_date_everywhere_uses_now_and_omits_date_from_the_hash() {
        let raw = b"From: alice@old.example\r\nSubject: s\r\n\r\nbody\r\n";
        let now = ts("2026-08-11T00:00:00Z");
        let msg = build_imported_message(raw, "inbox", None, now).unwrap();
        assert_eq!(msg.received_at, now);
        let later = build_imported_message(raw, "inbox", None, ts("2027-01-01T00:00:00Z")).unwrap();
        assert_eq!(msg.content_hash, later.content_hash);
    }

    #[test]
    fn sent_folder_marks_the_item_as_sent() {
        let msg = build_imported_message(sample_eml(), "sent", None, ts("2026-08-11T00:00:00Z")).unwrap();
        assert_eq!(msg.item_type, "sent");
        let inbox =
            build_imported_message(sample_eml(), "archive", None, ts("2026-08-11T00:00:00Z")).unwrap();
        assert_eq!(inbox.item_type, "received");
    }

    #[test]
    fn missing_message_id_is_synthesized_uniquely() {
        let raw = b"From: a@b.c\r\nSubject: s\r\n\r\nbody\r\n";
        let a = build_imported_message(raw, "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        let b = build_imported_message(raw, "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        assert_ne!(a.message_id, b.message_id);
        assert!(a.message_id.ends_with("@append.bridge.aster"));
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn attachments_are_extracted_with_names_and_bytes() {
        let raw = concat!(
            "From: a@b.c\r\n",
            "To: mark@astermail.org\r\n",
            "Subject: with attachment\r\n",
            "Date: Fri, 12 Jul 2024 13:04:05 +0000\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n",
            "\r\n",
            "--BOUND\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "see attached\r\n",
            "--BOUND\r\n",
            "Content-Type: application/pdf; name=\"report.pdf\"\r\n",
            "Content-Disposition: attachment; filename=\"report.pdf\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "aGVsbG8gcGRm\r\n",
            "--BOUND--\r\n"
        )
        .as_bytes();
        let msg = build_imported_message(raw, "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].name, "report.pdf");
        assert_eq!(msg.attachments[0].mime_type, "application/pdf");
        assert_eq!(msg.attachments[0].data, b"hello pdf");
        let envelope: serde_json::Value = serde_json::from_str(&msg.envelope_json).unwrap();
        assert_eq!(envelope["attachment_count"], 1);
    }

    #[test]
    fn html_only_message_keeps_the_html_body() {
        let raw = concat!(
            "From: a@b.c\r\n",
            "Subject: html\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p>hello</p>\r\n"
        )
        .as_bytes();
        let msg = build_imported_message(raw, "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&msg.envelope_json).unwrap();
        assert_eq!(envelope["body_html"], "<p>hello</p>\r\n");
        assert_eq!(envelope["html_body"], "<p>hello</p>\r\n");
    }

    #[test]
    fn flag_bits_map_to_the_local_cache_layout() {
        let flags = AppendFlags {
            seen: true,
            flagged: true,
            answered: true,
            draft: false,
            deleted: false,
        };
        assert_eq!(flags.local_bits(), 1 | 2 | 4);
        assert_eq!(AppendFlags::default().local_bits(), 0);
    }

    #[test]
    fn rate_limited_errors_are_recognized() {
        use crate::error::BridgeError;

        assert!(is_rate_limited(&BridgeError::Api(
            "429 Too Many Requests: rate limit exceeded".to_string()
        )));
        assert!(is_rate_limited(&BridgeError::Api(
            "Rate Limit hit".to_string()
        )));
        assert!(!is_rate_limited(&BridgeError::Api(
            "409 Conflict: too many active import jobs".to_string()
        )));
        assert!(!is_rate_limited(&BridgeError::Api(
            "500 Internal Server Error".to_string()
        )));
    }

    #[test]
    fn transient_gateway_errors_are_recognized() {
        use crate::error::BridgeError;

        assert!(is_transient(&BridgeError::Api(
            "502 Bad Gateway: error code: 502".to_string()
        )));
        assert!(is_transient(&BridgeError::Api(
            "503 Service Unavailable: upstream connect error".to_string()
        )));
        assert!(is_transient(&BridgeError::Api(
            "504 Gateway Timeout: upstream timed out".to_string()
        )));
        assert!(!is_transient(&BridgeError::Api(
            "409 Conflict: too many active import jobs".to_string()
        )));
        assert!(!is_transient(&BridgeError::Api(
            "500 Internal Server Error: unexpected".to_string()
        )));
        assert!(!is_transient(&BridgeError::Api(
            "400 Bad Request: invalid payload".to_string()
        )));
    }

    #[test]
    fn retryable_covers_rate_limits_and_gateway_blips() {
        use crate::error::BridgeError;

        assert!(is_retryable(&BridgeError::Api(
            "429 Too Many Requests: rate limit exceeded".to_string()
        )));
        assert!(is_retryable(&BridgeError::Api(
            "502 Bad Gateway: error code: 502".to_string()
        )));
        assert!(!is_retryable(&BridgeError::Api(
            "422 Unprocessable Entity: bad envelope".to_string()
        )));
    }

    #[test]
    fn no_response_code_marks_transient_failures_unavailable() {
        assert_eq!(
            no_response_code(
                "could not create the import job: API error: 502 Bad Gateway: error code: 502"
            ),
            "UNAVAILABLE"
        );
        assert_eq!(
            no_response_code("could not store the message: network error: connection reset"),
            "UNAVAILABLE"
        );
        assert_eq!(
            no_response_code("could not store the message: API error: 429 Too Many Requests: slow down"),
            "UNAVAILABLE"
        );
        assert_eq!(
            no_response_code("could not parse the appended message"),
            "SERVERBUG"
        );
        assert_eq!(
            no_response_code("the server rejected the message"),
            "SERVERBUG"
        );
    }

    #[test]
    fn import_progress_counts_and_finishes_across_sessions() {
        let mut slot: Option<ImportProgress> = None;

        apply_import_outcome(&mut slot, true, 1000);
        apply_import_outcome(&mut slot, true, 2000);
        let live = apply_import_outcome(&mut slot, false, 3000);
        assert!(live.active);
        assert_eq!(live.imported, 2);
        assert_eq!(live.duplicates, 1);
        assert_eq!(live.started_at_ms, 1000);
        assert_eq!(live.updated_at_ms, 3000);

        let done = apply_import_finish(&mut slot, 4000).unwrap();
        assert!(!done.active);
        assert_eq!(done.imported, 2);
        assert_eq!(done.duplicates, 1);
        assert_eq!(done.updated_at_ms, 4000);

        assert!(apply_import_finish(&mut slot, 5000).is_none());
        assert!(!slot.as_ref().unwrap().active);

        let fresh = apply_import_outcome(&mut slot, true, 6000);
        assert!(fresh.active);
        assert_eq!(fresh.imported, 1);
        assert_eq!(fresh.duplicates, 0);
        assert_eq!(fresh.started_at_ms, 6000);
    }

    #[test]
    fn rate_limit_backoff_grows_and_stays_under_a_client_timeout() {
        let total: u64 = (0..RATE_LIMIT_ATTEMPTS).map(rate_limit_backoff).sum();
        assert!(total < 60, "cumulative backoff {} is too long", total);
        assert!(rate_limit_backoff(0) < rate_limit_backoff(1));
        assert!(rate_limit_backoff(1) < rate_limit_backoff(2));
    }

    async fn spawn_mock(app: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    #[test]
    fn scoped_lookup_since_reaches_back_before_the_store() {
        let stored_after = ts("2026-08-20T12:00:00Z");
        assert_eq!(
            scoped_lookup_since(stored_after),
            iso_millis(&ts("2026-08-20T11:58:00Z"))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stored_item_lookup_asks_for_a_narrow_window_first() {
        use axum::extract::Query;
        use axum::routing::get;
        use std::collections::HashMap;

        let queries: Arc<tokio::sync::Mutex<Vec<HashMap<String, String>>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let seen = queries.clone();
        let app = axum::Router::new().route(
            "/bridge/v1/messages/sync",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let seen = seen.clone();
                async move {
                    seen.lock().await.push(q);
                    axum::Json(serde_json::json!({"items": [{
                        "id": "mail-1",
                        "item_type": "received",
                        "encrypted_envelope": "sealed",
                        "envelope_nonce": "n",
                        "folder_token": "",
                        "is_external": true,
                        "created_at": "2026-08-20T12:00:00.000Z",
                    }]}))
                }
            }),
        );

        let base = spawn_mock(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let id = locate_stored_item(&client, "tok", "sealed", ts("2026-08-20T12:00:00Z"))
            .await
            .unwrap();

        assert_eq!(id, "mail-1");
        let asked = queries.lock().await.clone();
        assert_eq!(asked.len(), 1, "a narrow hit must not trigger a wide sweep");
        assert_eq!(
            asked[0].get("limit").map(String::as_str),
            Some(SCOPED_LOOKUP_LIMIT.to_string().as_str())
        );
        assert!(asked[0].contains_key("since"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stored_item_lookup_falls_back_to_a_wide_sweep() {
        use axum::extract::Query;
        use axum::routing::get;
        use std::collections::HashMap;

        let queries: Arc<tokio::sync::Mutex<Vec<HashMap<String, String>>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let seen = queries.clone();
        let app = axum::Router::new().route(
            "/bridge/v1/messages/sync",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let seen = seen.clone();
                async move {
                    let scoped = q.contains_key("since");
                    seen.lock().await.push(q);
                    if scoped {
                        return axum::Json(serde_json::json!({"items": []}));
                    }
                    axum::Json(serde_json::json!({"items": [{
                        "id": "mail-9",
                        "item_type": "received",
                        "encrypted_envelope": "sealed",
                        "envelope_nonce": "n",
                        "folder_token": "",
                        "is_external": true,
                        "created_at": "2026-08-20T12:00:00.000Z",
                    }]}))
                }
            }),
        );

        let base = spawn_mock(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let id = locate_stored_item(&client, "tok", "sealed", ts("2026-08-20T12:00:00Z"))
            .await
            .unwrap();

        assert_eq!(id, "mail-9");
        let asked = queries.lock().await.clone();
        assert_eq!(asked.len(), 2);
        assert!(!asked[1].contains_key("since"));
        assert_eq!(
            asked[1].get("limit").map(String::as_str),
            Some(SYNC_LOOKUP_LIMIT.to_string().as_str())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn import_job_creation_survives_a_gateway_blip() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::{get, put};
        use std::sync::atomic::{AtomicU32, Ordering};

        let create_calls = Arc::new(AtomicU32::new(0));
        let create_counter = create_calls.clone();
        let app = axum::Router::new()
            .route(
                "/mail/v1/email_import/jobs",
                get(|| async { axum::Json(serde_json::json!({"jobs": []})) }).post(move || {
                    let calls = create_counter.clone();
                    async move {
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            (StatusCode::BAD_GATEWAY, "error code: 502").into_response()
                        } else {
                            axum::Json(serde_json::json!({"id": "job-created"})).into_response()
                        }
                    }
                }),
            )
            .route(
                "/mail/v1/email_import/jobs/:id",
                put(|| async { StatusCode::OK }),
            );

        let base = spawn_mock(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let job_id = processing_import_job(&client, "tok").await.unwrap();
        assert_eq!(job_id, "job-created");
        assert_eq!(create_calls.load(Ordering::SeqCst), 2);
        forget_import_job(&client).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn import_job_adopts_an_existing_job_when_creation_keeps_failing() {
        use axum::http::StatusCode;
        use axum::routing::{get, put};
        use std::sync::atomic::{AtomicU32, Ordering};

        let list_calls = Arc::new(AtomicU32::new(0));
        let list_counter = list_calls.clone();
        let app = axum::Router::new()
            .route(
                "/mail/v1/email_import/jobs",
                get(move || {
                    let calls = list_counter.clone();
                    async move {
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            axum::Json(serde_json::json!({"jobs": []}))
                        } else {
                            axum::Json(serde_json::json!({
                                "jobs": [{"id": "job-live", "source": "eml", "status": "pending"}]
                            }))
                        }
                    }
                })
                .post(|| async { (StatusCode::BAD_GATEWAY, "error code: 502") }),
            )
            .route(
                "/mail/v1/email_import/jobs/:id",
                put(|| async { StatusCode::OK }),
            );

        let base = spawn_mock(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let job_id = processing_import_job(&client, "tok").await.unwrap();
        assert_eq!(job_id, "job-live");
        assert!(list_calls.load(Ordering::SeqCst) >= 2);
        forget_import_job(&client).await;
    }

    #[test]
    fn envelope_encrypts_with_the_import_version() {
        let msg = build_imported_message(sample_eml(), "inbox", None, ts("2026-08-11T00:00:00Z")).unwrap();
        let ik = "identity-key-for-append";
        let (data, nonce) = crate::crypto::envelope::encrypt_identity_key_envelope_with_version(
            &msg.envelope_json,
            ik,
            crate::crypto::envelope::ENVELOPE_VERSION_IMPORT,
        )
        .unwrap();
        let out = crate::crypto::envelope::decrypt_envelope(&data, Some(&nonce), b"", Some(ik), &[])
            .unwrap();
        assert_eq!(out, msg.envelope_json);
    }
}
