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
use chrono::{Datelike, Timelike};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use tokio::sync::{broadcast, RwLock};

use crate::api_client::ApiClient;
use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;
use crate::db::{CachedMessage, Database};
use crate::error::Result;
use crate::jmap::state::StateChange;

const IDLE_KEEPALIVE_SECS: u64 = 5 * 60;
const GMAIL_ALL_MAIL: &str = "\\Allmail";

fn gmail_label_for_folder(folder: &str) -> Option<&'static str> {
    match folder {
        "inbox" => Some("\\Inbox"),
        "sent" => Some("\\Sent"),
        "drafts" => Some("\\Drafts"),
        "trash" => Some("\\Trash"),
        "spam" => Some("\\Junk"),
        "archive" => Some(GMAIL_ALL_MAIL),
        _ => None,
    }
}

fn gmail_msgid_from_aster(s: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b) | 1
}

fn gmail_thrid_from_aster(thread_token: &str) -> u64 {
    gmail_msgid_from_aster(thread_token)
}

fn utf7_encode_modified(s: &str) -> String {
    let mut out = String::new();
    let mut buf16: Vec<u16> = Vec::new();
    let flush = |buf16: &mut Vec<u16>, out: &mut String| {
        if buf16.is_empty() {
            return;
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(buf16.len() * 2);
        for u in buf16.iter() {
            bytes.extend_from_slice(&u.to_be_bytes());
        }
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &bytes);
        let b64 = b64.replace('/', ",");
        out.push('&');
        out.push_str(&b64);
        out.push('-');
        buf16.clear();
    };
    for c in s.chars() {
        let code = c as u32;
        if c == '&' {
            flush(&mut buf16, &mut out);
            out.push_str("&-");
        } else if (0x20..=0x7e).contains(&code) {
            flush(&mut buf16, &mut out);
            out.push(c);
        } else {
            let mut tmp = [0u16; 2];
            let units = c.encode_utf16(&mut tmp);
            buf16.extend_from_slice(units);
        }
    }
    flush(&mut buf16, &mut out);
    out
}

fn quote_or_atom_label(label: &str) -> String {
    if label.starts_with('\\')
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '\\')
    {
        label.to_string()
    } else if label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        && !label.is_empty()
    {
        label.to_string()
    } else {
        let encoded = utf7_encode_modified(label);
        let escaped = encoded.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{}\"", escaped)
    }
}

fn gmail_labels_for_message(msg: &CachedMessage) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    if let Some(sys) = gmail_label_for_folder(&msg.folder) {
        labels.push(sys.to_string());
    }
    labels
}

const MAX_LINE_LENGTH: usize = 8192;
const MAX_FAILED_AUTH: u32 = 5;

async fn read_line_bounded<R>(
    reader: &mut R,
    out: &mut String,
    cap: usize,
) -> std::io::Result<usize>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    out.clear();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let avail = reader.fill_buf().await?;
        if avail.is_empty() {
            break;
        }
        let (slice_end, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        let take_n = slice_end.min(cap.saturating_sub(buf.len()) + 1);
        buf.extend_from_slice(&avail[..take_n]);
        let consumed = take_n;
        tokio::io::AsyncBufReadExt::consume(reader, consumed);
        if buf.len() > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
        if done {
            break;
        }
    }
    *out = String::from_utf8_lossy(&buf).into_owned();
    Ok(buf.len())
}

fn parse_imap_search_date(s: &str) -> Option<(i32, u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 { return None; }
    let day: u32 = parts[0].parse().ok()?;
    let month = match parts[1].to_ascii_uppercase().as_str() {
        "JAN" => 1u32, "FEB" => 2, "MAR" => 3, "APR" => 4,
        "MAY" => 5, "JUN" => 6, "JUL" => 7, "AUG" => 8,
        "SEP" => 9, "OCT" => 10, "NOV" => 11, "DEC" => 12,
        _ => return None,
    };
    let year: i32 = parts[2].parse().ok()?;
    Some((year, month, day))
}

pub fn parse_datetime_lenient(s: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let t = s.trim();
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(t) {
        return Some(d);
    }
    if let Ok(d) = chrono::DateTime::parse_from_rfc2822(t) {
        return Some(d);
    }
    let no_weekday = t.split_once(',').map(|(_, rest)| rest.trim()).unwrap_or(t);
    for fmt in ["%d %b %Y %H:%M:%S %z", "%d %b %Y %H:%M %z"] {
        if let Ok(d) = chrono::DateTime::parse_from_str(no_weekday, fmt) {
            return Some(d);
        }
    }
    None
}

fn parse_message_date_ymd(date_str: &str) -> Option<(i32, u32, u32)> {
    let b = date_str.as_bytes();
    if b.len() >= 10
        && b[..10]
            .iter()
            .enumerate()
            .all(|(i, c)| if i == 4 || i == 7 { true } else { c.is_ascii_digit() })
    {
        let year: i32 = std::str::from_utf8(&b[0..4]).ok()?.parse().ok()?;
        let month: u32 = std::str::from_utf8(&b[5..7]).ok()?.parse().ok()?;
        let day: u32 = std::str::from_utf8(&b[8..10]).ok()?.parse().ok()?;
        return Some((year, month, day));
    }
    let d = parse_datetime_lenient(date_str)?;
    let nd = d.date_naive();
    Some((nd.year(), nd.month(), nd.day()))
}

fn uid_set_contains(set: &str, uid: u32) -> bool {
    for part in set.split(',') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once(':') {
            let lo: u32 = if a == "*" { u32::MAX } else { a.parse().unwrap_or(0) };
            let hi: u32 = if b == "*" { u32::MAX } else { b.parse().unwrap_or(0) };
            let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
            if uid >= lo && uid <= hi {
                return true;
            }
        } else if part == "*" {
            return true;
        } else if let Ok(n) = part.parse::<u32>() {
            if n == uid {
                return true;
            }
        }
    }
    false
}

fn tokenize_search_criteria(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes {
                    out.push(cur.clone());
                    cur.clear();
                    in_quotes = false;
                } else {
                    in_quotes = true;
                }
            }
            '\\' if in_quotes => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(cur.clone());
                    cur.clear();
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn cached_header_value(msg: &CachedMessage, field: &str) -> Option<String> {
    let meta = || -> serde_json::Value {
        msg.raw_headers
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null)
    };
    let meta_string = |key: &str| {
        meta()
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };

    match field {
        "subject" => msg.subject.clone(),
        "from" | "sender" => msg.sender.clone(),
        "to" => msg.recipients.clone(),
        "date" => msg.date.clone(),
        "cc" => meta_string("cc"),
        "bcc" => meta_string("bcc"),
        "message-id" => meta_string("message_id"),
        _ => None,
    }
}

fn header_search_matches(msg: &CachedMessage, field: &str, pattern: &str) -> bool {
    let wanted = pattern.trim().trim_matches('"');
    match cached_header_value(msg, field) {
        Some(value) => {
            wanted.is_empty() || value.to_uppercase().contains(&wanted.to_uppercase())
        }
        None => false,
    }
}

fn search_matches(msg: &CachedMessage, criteria_upper: &str) -> bool {
    let parts: Vec<String> = tokenize_search_criteria(criteria_upper);
    let mut idx = 0;
    while idx < parts.len() {
        if !search_eval(msg, &parts, &mut idx) {
            return false;
        }
    }
    true
}

fn search_eval(msg: &CachedMessage, parts: &[String], idx: &mut usize) -> bool {
    if *idx >= parts.len() { return true; }
    match parts[*idx].as_str() {
        "ALL" => { *idx += 1; true }
        "UNSEEN" => { *idx += 1; (msg.flags & 1) == 0 }
        "SEEN" => { *idx += 1; (msg.flags & 1) != 0 }
        "ANSWERED" => { *idx += 1; (msg.flags & 2) != 0 }
        "UNANSWERED" => { *idx += 1; (msg.flags & 2) == 0 }
        "FLAGGED" => { *idx += 1; (msg.flags & 4) != 0 }
        "UNFLAGGED" => { *idx += 1; (msg.flags & 4) == 0 }
        "DELETED" => { *idx += 1; (msg.flags & 8) != 0 }
        "UNDELETED" => { *idx += 1; (msg.flags & 8) == 0 }
        "DRAFT" => { *idx += 1; (msg.flags & 16) != 0 }
        "UNDRAFT" => { *idx += 1; (msg.flags & 16) == 0 }
        "NOT" => {
            *idx += 1;
            let v = search_eval(msg, parts, idx);
            !v
        }
        "OR" => {
            *idx += 1;
            let a = search_eval(msg, parts, idx);
            let b = search_eval(msg, parts, idx);
            a || b
        }
        "FROM" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            msg.sender.as_deref().unwrap_or("").to_uppercase().contains(&pat.to_uppercase())
        }
        "TO" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            msg.recipients.as_deref().unwrap_or("").to_uppercase().contains(&pat.to_uppercase())
        }
        "SUBJECT" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            msg.subject.as_deref().unwrap_or("").to_uppercase().contains(&pat.trim_matches('"').to_uppercase())
        }
        "LARGER" => {
            *idx += 1;
            let n: i64 = if *idx < parts.len() { let p = parts[*idx].parse().unwrap_or(0); *idx += 1; p } else { 0 };
            msg.size > n
        }
        "SMALLER" => {
            *idx += 1;
            let n: i64 = if *idx < parts.len() { let p = parts[*idx].parse().unwrap_or(i64::MAX); *idx += 1; p } else { i64::MAX };
            msg.size < n
        }
        "BEFORE" | "SENTBEFORE" => {
            *idx += 1;
            let date_arg = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            match (parse_imap_search_date(date_arg), msg.date.as_deref().and_then(parse_message_date_ymd)) {
                (Some(search), Some(msg_d)) => msg_d < search,
                _ => false,
            }
        }
        "SINCE" | "SENTSINCE" => {
            *idx += 1;
            let date_arg = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            match (parse_imap_search_date(date_arg), msg.date.as_deref().and_then(parse_message_date_ymd)) {
                (Some(search), Some(msg_d)) => msg_d >= search,
                _ => false,
            }
        }
        "ON" | "SENTON" => {
            *idx += 1;
            let date_arg = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            match (parse_imap_search_date(date_arg), msg.date.as_deref().and_then(parse_message_date_ymd)) {
                (Some(search), Some(msg_d)) => msg_d == search,
                _ => false,
            }
        }
        "BODY" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            let pat_lower = pat.trim_matches('"').to_lowercase();
            if pat_lower.is_empty() { return true; }
            msg.body_text.as_deref().unwrap_or("").to_lowercase().contains(&pat_lower)
        }
        "TEXT" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            let pat_lower = pat.trim_matches('"').to_lowercase();
            if pat_lower.is_empty() { return true; }
            let body_lower = msg.body_text.as_deref().unwrap_or("").to_lowercase();
            let subj_lower = msg.subject.as_deref().unwrap_or("").to_lowercase();
            body_lower.contains(&pat_lower) || subj_lower.contains(&pat_lower)
        }
        field_token @ ("CC" | "BCC") => {
            let field = field_token.to_ascii_lowercase();
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            header_search_matches(msg, &field, pat)
        }
        "KEYWORD" => {
            *idx += 1;
            if *idx < parts.len() { *idx += 1; }
            false
        }
        "UNKEYWORD" => {
            *idx += 1;
            if *idx < parts.len() { *idx += 1; }
            true
        }
        "HEADER" => {
            *idx += 1;
            let field = if *idx < parts.len() { let p = parts[*idx].trim_matches('"').to_ascii_lowercase(); *idx += 1; p } else { String::new() };
            let pat = if *idx < parts.len() { let p = parts[*idx].as_str(); *idx += 1; p } else { "" };
            header_search_matches(msg, &field, pat)
        }
        "UID" => {
            *idx += 1;
            if *idx < parts.len() {
                let uid_set = &parts[*idx];
                *idx += 1;
                uid_set_contains(uid_set, msg.imap_uid)
            } else {
                false
            }
        }
        "RECENT" | "NEW" => { *idx += 1; false }
        "OLD" => { *idx += 1; true }
        unknown => {
            tracing::warn!("unsupported SEARCH criterion {}", unknown);
            *idx += 1;
            false
        }
    }
}

fn uid_validity(db: &Database) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    if let Ok(Some(v)) = db.get_sync_state("uid_validity") {
        if let Ok(n) = v.parse::<u64>() {
            return n;
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);
    let _ = db.set_sync_state("uid_validity", &now.to_string());
    now
}

fn parse_store_flags(op_and_flags: &str) -> (i8, u32, bool) {
    let upper = op_and_flags.to_ascii_uppercase();
    let silent = upper.contains(".SILENT");
    let op: i8 = if upper.contains("+FLAGS") {
        1
    } else if upper.contains("-FLAGS") {
        -1
    } else {
        0
    };
    let flag_start = op_and_flags.find('(').map(|p| p + 1).unwrap_or(0);
    let flag_end = op_and_flags.rfind(')').unwrap_or(op_and_flags.len());
    let flag_str = if flag_start <= flag_end { &op_and_flags[flag_start..flag_end] } else { "" };
    let mut mask: u32 = 0;
    for token in flag_str.split_whitespace() {
        mask |= match token.to_ascii_uppercase().trim_start_matches('\\') {
            "SEEN" => 1,
            "ANSWERED" => 2,
            "FLAGGED" => 4,
            "DELETED" => 8,
            "DRAFT" => 16,
            _ => 0,
        };
    }
    (op, mask, silent)
}

fn apply_flags(current: u32, op: i8, mask: u32) -> u32 {
    match op {
        1 => current | mask,
        -1 => current & !mask,
        _ => mask,
    }
}

fn flags_to_str(flags: u32) -> String {
    let mut list: Vec<&str> = Vec::new();
    if flags & 1 != 0 { list.push("\\Seen"); }
    if flags & 2 != 0 { list.push("\\Answered"); }
    if flags & 4 != 0 { list.push("\\Flagged"); }
    if flags & 8 != 0 { list.push("\\Deleted"); }
    if flags & 16 != 0 { list.push("\\Draft"); }
    list.join(" ")
}

const IMAP_FOLDERS: &[(&str, &str, &str)] = &[
    ("INBOX", "inbox", ""),
    ("Sent", "sent", "\\Sent"),
    ("Drafts", "drafts", "\\Drafts"),
    ("Trash", "trash", "\\Trash"),
    ("Junk", "spam", "\\Junk"),
    ("Archive", "archive", "\\Archive"),
];

const MAX_APPEND_BYTES: usize = 40 * 1024 * 1024;
const MAX_DRAINABLE_APPEND_BYTES: usize = 256 * 1024 * 1024;

fn existing_mailbox(name: &str) -> Option<&'static str> {
    let cleaned = name.trim().trim_matches('"').trim_end_matches(['/', '.']);
    IMAP_FOLDERS
        .iter()
        .find(|(display, _, _)| display.eq_ignore_ascii_case(cleaned))
        .map(|(_, internal, _)| *internal)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ImapState {
    NotAuthenticated,
    Authenticated,
    Selected,
}

struct ImapConnection {
    state: ImapState,
    selected_mailbox: Option<String>,
    selected_folder: Option<String>,
    message_count: u32,
    read_only: bool,
}

pub async fn run(
    addr: &str,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    broadcaster: broadcast::Sender<StateChange>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener = crate::port_picker::bind_loopback_listener(addr).await?;
    tracing::info!("IMAP server listening on {} (STARTTLS={})", addr, tls_config.is_some());
    serve(listener, session, db, client, passwords, broadcaster, tls_config).await
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    broadcaster: broadcast::Sender<StateChange>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!("IMAP rejected non-loopback peer {}", peer);
            drop(stream);
            continue;
        }
        let permit = match crate::conn_limit::try_acquire_connection(crate::conn_limit::Protocol::Imap) {
            Some(p) => p,
            None => {
                tracing::warn!("IMAP connection limit reached, dropping {}", peer);
                drop(stream);
                continue;
            }
        };
        tracing::debug!("IMAP connection from {}", peer);

        let session = session.clone();
        let client = client.clone();
        let db = db.clone();
        let passwords = passwords.clone();
        let broadcaster = broadcaster.clone();
        let tls_config = tls_config.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = run_session(
                stream, session, db, client, passwords, broadcaster, tls_config,
            )
            .await
            {
                tracing::error!("IMAP connection error: {}", e);
            }
        });
    }
}

pub async fn run_implicit_tls(
    addr: &str,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    broadcaster: broadcast::Sender<StateChange>,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let listener = crate::port_picker::bind_loopback_listener(addr).await?;
    tracing::info!("IMAPS (implicit TLS) listening on {}", addr);

    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!("IMAPS rejected non-loopback peer {}", peer);
            drop(stream);
            continue;
        }
        let permit = match crate::conn_limit::try_acquire_connection(crate::conn_limit::Protocol::Imap) {
            Some(p) => p,
            None => {
                tracing::warn!("IMAPS connection limit reached, dropping {}", peer);
                drop(stream);
                continue;
            }
        };
        let session = session.clone();
        let client = client.clone();
        let db = db.clone();
        let passwords = passwords.clone();
        let broadcaster = broadcaster.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let tls_stream = match crate::tls::accept_with_timeout(&acceptor, stream, "IMAPS").await {
                Some(s) => s,
                None => return,
            };
            if let Err(e) = run_session(
                tls_stream, session, db, client, passwords, broadcaster, None,
            )
            .await
            {
                tracing::error!("IMAPS connection error: {}", e);
            }
        });
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

async fn run_session_erased(
    stream: Box<dyn AsyncReadWrite + Send + Unpin>,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    broadcaster: broadcast::Sender<StateChange>,
) -> Result<()> {
    run_session(stream, session, db, client, passwords, broadcaster, None).await
}

async fn run_session<S>(
    stream: S,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    broadcaster: broadcast::Sender<StateChange>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut writer = crate::imap::heartbeat::HeartbeatWriter::new(
        write_half,
        crate::imap::heartbeat::heartbeat_interval(),
    );
    let mut reader = BufReader::new(read_half);
    let _ = client;
    let starttls_capable = tls_config.is_some();
    let greeting_cap = if starttls_capable {
        format!("* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN IDLE UIDPLUS MOVE UNSELECT CHILDREN NAMESPACE X-GM-EXT-1] Aster Bridge {} ready\r\n", env!("CARGO_PKG_VERSION"))
    } else {
        format!("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS MOVE UNSELECT CHILDREN NAMESPACE X-GM-EXT-1] Aster Bridge {} ready\r\n", env!("CARGO_PKG_VERSION"))
    };
    writer.write_all(greeting_cap.as_bytes()).await?;

    let mut conn = ImapConnection {
        state: ImapState::NotAuthenticated,
        selected_mailbox: None,
        selected_folder: None,
        message_count: 0,
        read_only: false,
    };

    let mut line = String::new();
    let mut failed_auth: u32 = 0;

    loop {
        writer.disarm();
        writer.flush().await?;
        line.clear();
        let n = match read_line_bounded(&mut reader, &mut line, MAX_LINE_LENGTH).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                writer.write_all(b"* BAD Line too long\r\n").await?;
                break;
            }
            Err(e) => return Err(crate::error::BridgeError::Io(e)),
        };
        if n == 0 {
            break;
        }

        if line.len() > MAX_LINE_LENGTH {
            writer.write_all(b"* BAD Line too long\r\n").await?;
            continue;
        }

        let trimmed = line.trim_end().to_string();
        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
        if parts.len() < 2 {
            writer.write_all(b"* BAD Invalid command\r\n").await?;
            continue;
        }

        let tag = parts[0].to_string();
        let command = parts[1].to_uppercase();
        if command.starts_with("LOGIN") || command.starts_with("AUTH") {
            tracing::debug!("IMAP <- {} {} <redacted>", tag, command);
        } else {
            tracing::debug!("IMAP <- {}", trimmed);
        }
        writer.arm();
        let args = if parts.len() > 2 {
            parts[2].to_string()
        } else {
            String::new()
        };

        match command.as_str() {
            "CAPABILITY" => {
                let cap_line: &[u8] = if starttls_capable && conn.state == ImapState::NotAuthenticated {
                    b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN IDLE UIDPLUS MOVE UNSELECT CHILDREN NAMESPACE X-GM-EXT-1\r\n"
                } else {
                    b"* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN IDLE UIDPLUS MOVE UNSELECT CHILDREN NAMESPACE X-GM-EXT-1\r\n"
                };
                writer.write_all(cap_line).await?;
                write_ok(&mut writer, &tag, "CAPABILITY completed").await?;
            }
            "STARTTLS" => {
                let cfg = match tls_config.as_ref() {
                    Some(c) if conn.state == ImapState::NotAuthenticated => c.clone(),
                    Some(_) => {
                        write_bad(&mut writer, &tag, "STARTTLS not allowed after authentication").await?;
                        continue;
                    }
                    None => {
                        write_bad(&mut writer, &tag, "STARTTLS not available").await?;
                        continue;
                    }
                };
                write_ok(&mut writer, &tag, "Begin TLS negotiation now").await?;
                writer.flush().await?;
                let upgraded_session = session.clone();
                let upgraded_db = db.clone();
                let upgraded_client = client.clone();
                let upgraded_passwords = passwords.clone();
                let upgraded_broadcaster = broadcaster.clone();
                let reclaimed = writer.reclaim().await?;
                let rejoined = tokio::io::join(reader.into_inner(), reclaimed);
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                let tls_stream = acceptor
                    .accept(rejoined)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let erased: Box<dyn AsyncReadWrite + Send + Unpin> = Box::new(tls_stream);
                return Box::pin(run_session_erased(
                    erased,
                    upgraded_session,
                    upgraded_db,
                    upgraded_client,
                    upgraded_passwords,
                    upgraded_broadcaster,
                ))
                .await;
            }
            "NOOP" => {
                write_ok(&mut writer, &tag, "NOOP completed").await?;
            }
            "ID" => {
                writer
                    .write_all(b"* ID (\"name\" \"Aster Bridge\")\r\n")
                    .await?;
                write_ok(&mut writer, &tag, "ID completed").await?;
            }
            "CHECK" => {
                require_selected!(conn, writer, tag);
                write_ok(&mut writer, &tag, "CHECK completed").await?;
            }
            "LOGOUT" => {
                writer.write_all(b"* BYE Aster Bridge closing\r\n").await?;
                write_ok(&mut writer, &tag, "LOGOUT completed").await?;
                break;
            }
            "LOGIN" => {
                if starttls_capable {
                    write_no(&mut writer, &tag, "[PRIVACYREQUIRED] STARTTLS required before LOGIN").await?;
                    continue;
                }
                let ok = handle_login(&mut writer, &session, &passwords, &mut conn, &tag, &args).await?;
                if !ok {
                    failed_auth = failed_auth.saturating_add(1);
                    let backoff_ms = 200u64.saturating_mul(1u64 << failed_auth.min(5));
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    if failed_auth >= MAX_FAILED_AUTH {
                        writer
                            .write_all(b"* BYE Too many failed attempts\r\n")
                            .await?;
                        break;
                    }
                }
            }
            "AUTHENTICATE" => {
                if starttls_capable {
                    write_no(&mut writer, &tag, "[PRIVACYREQUIRED] STARTTLS required before AUTHENTICATE").await?;
                    continue;
                }
                let upper_args = args.to_ascii_uppercase();
                let is_plain = upper_args == "PLAIN" || upper_args.starts_with("PLAIN ");
                if is_plain {
                    let inline_creds = args
                        .splitn(2, ' ')
                        .nth(1)
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    let creds = match inline_creds {
                        Some(s) => s,
                        None => {
                            writer.write_all(b"+ \r\n").await?;
                            line.clear();
                            let nb = read_line_bounded(&mut reader, &mut line, MAX_LINE_LENGTH)
                                .await
                                .unwrap_or(0);
                            if nb == 0 {
                                break;
                            }
                            if line.trim_end() == "*" {
                                write_bad(&mut writer, &tag, "AUTHENTICATE aborted").await?;
                                continue;
                            }
                            line.trim_end().to_string()
                        }
                    };

                    let mut ok = false;
                    if let Ok(decoded) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &creds,
                    ) {
                        let null_parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
                        if null_parts.len() >= 3 {
                            let authcid = String::from_utf8_lossy(null_parts[1]);
                            let password = String::from_utf8_lossy(null_parts[2]);
                            let expected_email = session.read().await.email.clone();
                            let username_ok = !expected_email.is_empty()
                                && (authcid.is_empty()
                                    || authcid.eq_ignore_ascii_case(&expected_email));
                            if username_ok {
                                if let Some(pw_id) = passwords.verify_and_id_async(&password).await {
                                    conn.state = ImapState::Authenticated;
                                    passwords.record_use(&pw_id, Some("imap"));
                                    crate::sync::poller::try_kick_sync();
                                    write_ok(&mut writer, &tag, "AUTHENTICATE completed").await?;
                                    ok = true;
                                }
                            }
                        }
                    }
                    if !ok {
                        failed_auth = failed_auth.saturating_add(1);
                        let backoff_ms = 200u64.saturating_mul(1u64 << failed_auth.min(5));
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        write_no(&mut writer, &tag, "[AUTHENTICATIONFAILED] Invalid credentials")
                            .await?;
                        if failed_auth >= MAX_FAILED_AUTH {
                            writer
                                .write_all(b"* BYE Too many failed attempts\r\n")
                                .await?;
                            break;
                        }
                    }
                } else {
                    write_bad(&mut writer, &tag, "Unsupported auth mechanism").await?;
                }
            }
            "NAMESPACE" => {
                require_auth!(conn, writer, tag);
                writer
                    .write_all(b"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n")
                    .await?;
                write_ok(&mut writer, &tag, "NAMESPACE completed").await?;
            }
            "LIST" => {
                require_auth!(conn, writer, tag);
                handle_list(&mut writer, &tag, &args).await?;
            }
            "LSUB" => {
                require_auth!(conn, writer, tag);
                handle_lsub(&mut writer, &tag, &args).await?;
            }
            "SUBSCRIBE" | "UNSUBSCRIBE" => {
                require_auth!(conn, writer, tag);
                write_ok(&mut writer, &tag, "completed").await?;
            }
            "CREATE" => {
                require_auth!(conn, writer, tag);
                let requested = parse_imap_atom_or_quoted(args.trim()).0;
                if existing_mailbox(&requested).is_some() {
                    write_ok(&mut writer, &tag, "CREATE completed").await?;
                } else {
                    write_no(
                        &mut writer,
                        &tag,
                        "[CANNOT] folder management is not supported; folders mirror your Aster account",
                    )
                    .await?;
                }
            }
            "DELETE" | "RENAME" => {
                require_auth!(conn, writer, tag);
                write_no(
                    &mut writer,
                    &tag,
                    "[CANNOT] folder management is not supported; folders mirror your Aster account",
                )
                .await?;
            }
            "SORT" | "THREAD" => {
                require_auth!(conn, writer, tag);
                write_no(&mut writer, &tag, "[CANNOT] server-side SORT/THREAD not supported").await?;
            }
            "SELECT" | "EXAMINE" => {
                require_auth!(conn, writer, tag);
                handle_select(
                    &mut writer, &db, &mut conn, &tag, &args, &command,
                )
                .await?;
            }
            "FETCH" => {
                require_selected!(conn, writer, tag);
                handle_fetch(&mut writer, &db, &client, &session, &conn, &tag, &args, false).await?;
            }
            "UID" => {
                require_auth!(conn, writer, tag);
                let uid_parts: Vec<&str> = args.splitn(2, ' ').collect();
                if uid_parts.is_empty() {
                    write_bad(&mut writer, &tag, "UID requires a subcommand").await?;
                    continue;
                }
                let subcmd = uid_parts[0].to_uppercase();
                let subargs = if uid_parts.len() > 1 {
                    uid_parts[1]
                } else {
                    ""
                };

                match subcmd.as_str() {
                    "FETCH" => {
                        if conn.state != ImapState::Selected {
                            write_no(&mut writer, &tag, "No mailbox selected").await?;
                            continue;
                        }
                        handle_fetch(&mut writer, &db, &client, &session, &conn, &tag, subargs, true).await?;
                    }
                    "SEARCH" => {
                        if conn.state != ImapState::Selected {
                            write_no(&mut writer, &tag, "No mailbox selected").await?;
                            continue;
                        }
                        let folder = conn.selected_folder.as_deref().unwrap_or("inbox");
                        let messages = db.list_cached_messages(folder).unwrap_or_default();
                        let criteria_upper = subargs.trim().to_ascii_uppercase();
                        let uids: Vec<String> = messages.iter()
                            .filter(|m| search_matches(m, &criteria_upper))
                            .map(|m| m.imap_uid.to_string())
                            .collect();
                        writer
                            .write_all(format!("* SEARCH {}\r\n", uids.join(" ")).as_bytes())
                            .await?;
                        write_ok(&mut writer, &tag, "UID SEARCH completed").await?;
                    }
                    "STORE" => {
                        if conn.state != ImapState::Selected {
                            write_no(&mut writer, &tag, "No mailbox selected").await?;
                            continue;
                        }
                        if conn.read_only {
                            write_no(&mut writer, &tag, "[READ-ONLY] Mailbox is read-only").await?;
                            continue;
                        }
                        let set_end = subargs.find(' ').unwrap_or(subargs.len());
                        let uid_set_spec = &subargs[..set_end];
                        let op_and_flags = subargs[set_end..].trim();
                        let folder = conn.selected_folder.as_deref().unwrap_or("inbox").to_string();
                        let messages = db.list_cached_messages(&folder).unwrap_or_default();
                        let max_uid = messages.iter().map(|m| m.imap_uid).max().unwrap_or(0);
                        let uids = parse_set(uid_set_spec, max_uid);
                        let (op, flag_mask, silent) = parse_store_flags(op_and_flags);
                        let mut seen_changes: Vec<(String, bool)> = Vec::new();
                        for uid in &uids {
                            if let Some((seq_idx, m)) = messages.iter().enumerate().find(|(_, m)| m.imap_uid == *uid) {
                                let seq = seq_idx + 1;
                                let old_flags = m.flags as u32;
                                let new_flags = apply_flags(old_flags, op, flag_mask);
                                let _ = db.update_message_flags(m.imap_uid as i64, &folder, new_flags as i64);
                                if (old_flags & 1) != (new_flags & 1) {
                                    seen_changes.push((m.aster_id.clone(), (new_flags & 1) != 0));
                                }
                                if !silent {
                                    writer
                                        .write_all(
                                            format!("* {} FETCH (UID {} FLAGS ({}))\r\n", seq, uid, flags_to_str(new_flags))
                                            .as_bytes(),
                                        )
                                        .await?;
                                }
                            }
                        }
                        if !seen_changes.is_empty() {
                            let client = client.clone();
                            let session = session.clone();
                            tokio::spawn(async move {
                                let token = session.read().await.access_token.to_string();
                                for (aster_id, is_read) in seen_changes {
                                    if let Err(e) =
                                        client.set_read_status(&token, &aster_id, is_read).await
                                    {
                                        tracing::warn!(
                                            "read-status sync failed for {}: {}",
                                            aster_id,
                                            e
                                        );
                                    }
                                }
                            });
                        }
                        write_ok(&mut writer, &tag, "UID STORE completed").await?;
                    }
                    "EXPUNGE" => {
                        if conn.state != ImapState::Selected {
                            write_no(&mut writer, &tag, "No mailbox selected").await?;
                            continue;
                        }
                        if conn.read_only {
                            write_no(&mut writer, &tag, "[READ-ONLY] Mailbox is read-only").await?;
                            continue;
                        }
                        let folder = conn.selected_folder.clone().unwrap_or_else(|| "inbox".to_string());
                        let uid_set_spec = subargs.trim();
                        let messages = db.list_cached_messages(&folder).unwrap_or_default();
                        let targets: Vec<(usize, u32, String)> = messages.iter().enumerate()
                            .filter(|(_, m)| m.flags & 8 != 0)
                            .filter(|(_, m)| uid_set_spec.is_empty() || uid_set_contains(uid_set_spec, m.imap_uid))
                            .map(|(i, m)| (i + 1, m.imap_uid, m.aster_id.clone()))
                            .collect();
                        expunge_targets(&mut writer, &db, &client, &session, &mut conn, &folder, targets).await?;
                        write_ok(&mut writer, &tag, "UID EXPUNGE completed").await?;
                    }
                    "COPY" | "MOVE" => {
                        if conn.state != ImapState::Selected {
                            write_no(&mut writer, &tag, "No mailbox selected").await?;
                            continue;
                        }
                        handle_copy_move(
                            &mut writer,
                            &db,
                            &client,
                            &session,
                            &mut conn,
                            &tag,
                            subargs,
                            true,
                            subcmd == "MOVE",
                        )
                        .await?;
                    }
                    _ => {
                        write_bad(&mut writer, &tag, "Unknown UID subcommand").await?;
                    }
                }
            }
            "SEARCH" => {
                require_selected!(conn, writer, tag);
                let folder = conn.selected_folder.as_deref().unwrap_or("inbox");
                let messages = db.list_cached_messages(folder).unwrap_or_default();
                let criteria_upper = args.trim().to_ascii_uppercase();
                let matched: Vec<String> = messages.iter().enumerate()
                    .filter(|(_, m)| search_matches(m, &criteria_upper))
                    .map(|(i, _)| (i + 1).to_string())
                    .collect();
                writer
                    .write_all(format!("* SEARCH {}\r\n", matched.join(" ")).as_bytes())
                    .await?;
                write_ok(&mut writer, &tag, "SEARCH completed").await?;
            }
            "STORE" => {
                require_selected!(conn, writer, tag);
                if conn.read_only {
                    write_no(&mut writer, &tag, "[READ-ONLY] Mailbox is read-only").await?;
                    continue;
                }
                let store_args = parts.get(2).copied().unwrap_or("");
                let set_end = store_args.find(' ').unwrap_or(store_args.len());
                let set_part = &store_args[..set_end];
                let op_and_flags = store_args[set_end..].trim();
                let seqs = parse_set(set_part, conn.message_count);
                let upper_store = op_and_flags.to_ascii_uppercase();
                let is_gm_labels = upper_store.contains("X-GM-LABELS");
                let folder = conn.selected_folder.clone().unwrap_or_default();
                let messages = db.list_cached_messages(&folder).unwrap_or_default();
                if is_gm_labels {
                    let silent = upper_store.contains(".SILENT");
                    for s in &seqs {
                        if let Some(m) = messages.get((*s as usize).saturating_sub(1)) {
                            tracing::info!(
                                target: "imap::gm_labels",
                                "gm-labels store not propagated to backend: aster_id={} op={} args={}",
                                m.aster_id,
                                if upper_store.contains("+X-GM-LABELS") { "add" }
                                else if upper_store.contains("-X-GM-LABELS") { "remove" }
                                else { "replace" },
                                store_args
                            );
                            if !silent {
                                let labels = gmail_labels_for_message(m);
                                let rendered: Vec<String> =
                                    labels.iter().map(|l| quote_or_atom_label(l)).collect();
                                writer
                                    .write_all(
                                        format!("* {} FETCH (X-GM-LABELS ({}))\r\n", s, rendered.join(" "))
                                        .as_bytes(),
                                    )
                                    .await?;
                            }
                        }
                    }
                } else {
                    let (op, flag_mask, silent) = parse_store_flags(op_and_flags);
                    let mut seen_changes: Vec<(String, bool)> = Vec::new();
                    for s in &seqs {
                        if let Some(m) = messages.get((*s as usize).saturating_sub(1)) {
                            let old_flags = m.flags as u32;
                            let new_flags = apply_flags(old_flags, op, flag_mask);
                            let _ = db.update_message_flags(m.imap_uid as i64, &folder, new_flags as i64);
                            if (old_flags & 1) != (new_flags & 1) {
                                seen_changes.push((m.aster_id.clone(), (new_flags & 1) != 0));
                            }
                            if !silent {
                                writer
                                    .write_all(
                                        format!("* {} FETCH (FLAGS ({}))\r\n", s, flags_to_str(new_flags))
                                        .as_bytes(),
                                    )
                                    .await?;
                            }
                        }
                    }
                    if !seen_changes.is_empty() {
                        let client = client.clone();
                        let session = session.clone();
                        tokio::spawn(async move {
                            let token = session.read().await.access_token.to_string();
                            for (aster_id, is_read) in seen_changes {
                                if let Err(e) =
                                    client.set_read_status(&token, &aster_id, is_read).await
                                {
                                    tracing::warn!(
                                        "read-status sync failed for {}: {}",
                                        aster_id,
                                        e
                                    );
                                }
                            }
                        });
                    }
                }
                write_ok(&mut writer, &tag, "STORE completed").await?;
            }
            "EXPUNGE" => {
                require_selected!(conn, writer, tag);
                if conn.read_only {
                    write_no(&mut writer, &tag, "[READ-ONLY] Mailbox is read-only").await?;
                    continue;
                }
                let folder = conn.selected_folder.clone().unwrap_or_else(|| "inbox".to_string());
                let messages = db.list_cached_messages(&folder).unwrap_or_default();
                let targets: Vec<(usize, u32, String)> = messages.iter().enumerate()
                    .filter(|(_, m)| m.flags & 8 != 0)
                    .map(|(i, m)| (i + 1, m.imap_uid, m.aster_id.clone()))
                    .collect();
                expunge_targets(&mut writer, &db, &client, &session, &mut conn, &folder, targets).await?;
                write_ok(&mut writer, &tag, "EXPUNGE completed").await?;
            }
            "COPY" | "MOVE" => {
                require_selected!(conn, writer, tag);
                handle_copy_move(
                    &mut writer,
                    &db,
                    &client,
                    &session,
                    &mut conn,
                    &tag,
                    &args,
                    false,
                    command.eq_ignore_ascii_case("MOVE"),
                )
                .await?;
            }
            "IDLE" => {
                require_auth!(conn, writer, tag);
                writer.write_all(b"+ idling\r\n").await?;

                let mut idle_msgs: Vec<(u32, i64)> = conn
                    .selected_folder
                    .as_deref()
                    .and_then(|f| db.list_cached_message_meta(f).ok())
                    .map(|v| v.iter().map(|m| (m.imap_uid, m.flags)).collect())
                    .unwrap_or_default();
                if conn.state == ImapState::Selected
                    && idle_msgs.len() as u32 != conn.message_count
                {
                    writer
                        .write_all(format!("* {} EXISTS\r\n", idle_msgs.len()).as_bytes())
                        .await?;
                    conn.message_count = idle_msgs.len() as u32;
                }

                let mut rx = broadcaster.subscribe();
                let mut keepalive = tokio::time::interval(
                    std::time::Duration::from_secs(IDLE_KEEPALIVE_SECS),
                );
                keepalive.tick().await;

                let mut buf: Vec<u8> = Vec::with_capacity(64);
                let mut terminated = false;
                let mut disconnected = false;

                loop {
                    tokio::select! {
                        biased;
                        read_res = reader.read_until(b'\n', &mut buf) => {
                            match read_res {
                                Ok(0) => {
                                    disconnected = true;
                                    break;
                                }
                                Ok(_) => {
                                    if buf.len() > 128 {
                                        disconnected = true;
                                        break;
                                    }
                                    let s = String::from_utf8_lossy(&buf);
                                    let t = s.trim_end_matches(|c| c == '\r' || c == '\n');
                                    if t.eq_ignore_ascii_case("DONE") {
                                        terminated = true;
                                        buf.clear();
                                        break;
                                    }
                                    buf.clear();
                                }
                                Err(_) => {
                                    disconnected = true;
                                    break;
                                }
                            }
                        }
                        change = rx.recv() => {
                            match change {
                                Ok(state_change) => {
                                    if !state_change.changed.contains_key("Email") {
                                        continue;
                                    }
                                    let folder = match conn.selected_folder.as_deref() {
                                        Some(f) => f.to_string(),
                                        None => continue,
                                    };
                                    let current: Vec<(u32, i64)> = db
                                        .list_cached_message_meta(&folder)
                                        .map(|v| v.iter().map(|m| (m.imap_uid, m.flags)).collect())
                                        .unwrap_or_else(|_| idle_msgs.clone());
                                    let current_set: std::collections::HashSet<u32> =
                                        current.iter().map(|(u, _)| *u).collect();
                                    let old_flags: std::collections::HashMap<u32, i64> =
                                        idle_msgs.iter().copied().collect();
                                    let mut adjustment: usize = 0;
                                    for (i, (uid, _)) in idle_msgs.iter().enumerate() {
                                        if !current_set.contains(uid) {
                                            let seq = i + 1 - adjustment;
                                            writer
                                                .write_all(format!("* {} EXPUNGE\r\n", seq).as_bytes())
                                                .await?;
                                            conn.message_count = conn.message_count.saturating_sub(1);
                                            adjustment += 1;
                                        }
                                    }
                                    if current.len() as u32 != conn.message_count {
                                        writer
                                            .write_all(format!("* {} EXISTS\r\n", current.len()).as_bytes())
                                            .await?;
                                    }
                                    for (i, (uid, flags)) in current.iter().enumerate() {
                                        if let Some(old) = old_flags.get(uid) {
                                            if old != flags {
                                                writer
                                                    .write_all(
                                                        format!(
                                                            "* {} FETCH (UID {} FLAGS ({}))\r\n",
                                                            i + 1,
                                                            uid,
                                                            flags_to_str(*flags as u32)
                                                        )
                                                        .as_bytes(),
                                                    )
                                                    .await?;
                                            }
                                        }
                                    }
                                    conn.message_count = current.len() as u32;
                                    idle_msgs = current;
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    if let Some(folder) = conn.selected_folder.as_deref() {
                                        let current: Vec<(u32, i64)> = db
                                            .list_cached_message_meta(folder)
                                            .map(|v| v.iter().map(|m| (m.imap_uid, m.flags)).collect())
                                            .unwrap_or_else(|_| idle_msgs.clone());
                                        writer
                                            .write_all(format!("* {} EXISTS\r\n", current.len()).as_bytes())
                                            .await?;
                                        conn.message_count = current.len() as u32;
                                        idle_msgs = current;
                                    }
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    rx = broadcaster.subscribe();
                                }
                            }
                        }
                        _ = keepalive.tick() => {
                            writer.write_all(b"* OK Still here\r\n").await?;
                        }
                    }
                }

                if disconnected {
                    break;
                }
                if terminated {
                    write_ok(&mut writer, &tag, "IDLE terminated").await?;
                } else {
                    write_bad(&mut writer, &tag, "IDLE aborted").await?;
                }
            }
            "CLOSE" => {
                require_selected!(conn, writer, tag);
                let folder = conn.selected_folder.clone().unwrap_or_default();
                if !conn.read_only {
                    let messages = db.list_cached_messages(&folder).unwrap_or_default();
                    let targets: Vec<(usize, u32, String)> = messages.iter().enumerate()
                        .filter(|(_, m)| m.flags & 8 != 0)
                        .map(|(i, m)| (i + 1, m.imap_uid, m.aster_id.clone()))
                        .collect();
                    expunge_targets_silent(&db, &client, &session, &folder, targets).await;
                }
                conn.state = ImapState::Authenticated;
                conn.selected_mailbox = None;
                conn.selected_folder = None;
                conn.message_count = 0;
                conn.read_only = false;
                write_ok(&mut writer, &tag, "CLOSE completed").await?;
            }
            "UNSELECT" => {
                require_selected!(conn, writer, tag);
                conn.state = ImapState::Authenticated;
                conn.selected_mailbox = None;
                conn.selected_folder = None;
                conn.message_count = 0;
                write_ok(&mut writer, &tag, "UNSELECT completed").await?;
            }
            "STATUS" => {
                require_auth!(conn, writer, tag);
                let mailbox = args.split(' ').next().unwrap_or("").trim_matches('"');
                let aster_folder = match IMAP_FOLDERS
                    .iter()
                    .find(|(imap, _, _)| imap.eq_ignore_ascii_case(mailbox))
                    .map(|(_, f, _)| *f)
                {
                    Some(f) => f,
                    None => {
                        write_no(&mut writer, &tag, "[NONEXISTENT] No such mailbox").await?;
                        continue;
                    }
                };
                let count = db.count_cached_messages(aster_folder).unwrap_or(0);
                let max_uid = db.max_uid(aster_folder).unwrap_or(0);
                let unseen = db.count_unread_messages(aster_folder).unwrap_or(0);
                writer
                    .write_all(
                        format!(
                            "* STATUS \"{}\" (MESSAGES {} RECENT 0 UNSEEN {} UIDVALIDITY {} UIDNEXT {})\r\n",
                            mailbox,
                            count,
                            unseen,
                            uid_validity(&db),
                            max_uid + 1
                        )
                        .as_bytes(),
                    )
                    .await?;
                write_ok(&mut writer, &tag, "STATUS completed").await?;
            }
            "APPEND" => {
                require_auth!(conn, writer, tag);
                let command = crate::imap::append::parse_append_command(&args);
                let target_folder = command.as_ref().and_then(|cmd| {
                    IMAP_FOLDERS
                        .iter()
                        .find(|(imap, _, _)| imap.eq_ignore_ascii_case(&cmd.mailbox))
                        .map(|(_, f, _)| *f)
                });
                match command {
                    Some(cmd) if cmd.literal_len > MAX_APPEND_BYTES => {
                        if cmd.non_sync {
                            if cmd.literal_len > MAX_DRAINABLE_APPEND_BYTES {
                                write_no(&mut writer, &tag, "[TOOBIG] APPEND literal too large")
                                    .await?;
                                break;
                            }
                            let mut sink = tokio::io::sink();
                            let mut limited =
                                tokio::io::AsyncReadExt::take(&mut reader, cmd.literal_len as u64);
                            if tokio::io::copy(&mut limited, &mut sink).await.is_err() {
                                break;
                            }
                            let mut trailer = [0u8; 2];
                            let _ = tokio::io::AsyncReadExt::read_exact(&mut reader, &mut trailer)
                                .await;
                        }
                        write_no(&mut writer, &tag, "[TOOBIG] APPEND literal too large").await?;
                    }
                    Some(cmd) => {
                        use tokio::io::AsyncReadExt;
                        if !cmd.non_sync {
                            writer.write_all(b"+ Ready for literal data\r\n").await?;
                            writer.flush().await?;
                        }
                        let mut buf = vec![0u8; cmd.literal_len];
                        if let Err(e) = reader.read_exact(&mut buf).await {
                            tracing::warn!("APPEND read failed: {}", e);
                            write_bad(&mut writer, &tag, "APPEND read failed").await?;
                            continue;
                        }
                        let mut trailer = [0u8; 2];
                        let _ = reader.read_exact(&mut trailer).await;
                        match target_folder {
                            None => {
                                write_no(&mut writer, &tag, "[TRYCREATE] No such mailbox").await?;
                            }
                            Some("drafts") => {
                                let draft_db = db.clone();
                                let draft_client = client.clone();
                                let draft_session = session.clone();
                                let draft_body = std::mem::take(&mut buf);
                                let draft_outcome = run_with_keepalive(&mut writer, async move {
                                    append_draft(
                                        &draft_db,
                                        &draft_client,
                                        &draft_session,
                                        &draft_body,
                                    )
                                    .await
                                })
                                .await;
                                match draft_outcome {
                                    Some(Ok((uid, draft_id))) => {
                                        let _ = db.jmap_record_sync_batch("Email", &[draft_id.as_str()]);
                                        let email_state = db.jmap_state_get("Email").unwrap_or(0);
                                        let mailbox_state = db.jmap_state_bump("Mailbox").unwrap_or(0);
                                        let thread_state = db.jmap_state_bump("Thread").unwrap_or(0);
                                        let mut changed = std::collections::HashMap::new();
                                        changed.insert("Email".to_string(), email_state.to_string());
                                        changed.insert("Mailbox".to_string(), mailbox_state.to_string());
                                        changed.insert("Thread".to_string(), thread_state.to_string());
                                        let _ = broadcaster.send(StateChange { changed });
                                        if conn.state == ImapState::Selected
                                            && conn.selected_folder.as_deref() == Some("drafts")
                                        {
                                            let count =
                                                db.count_cached_messages("drafts").unwrap_or(0);
                                            writer
                                                .write_all(
                                                    format!("* {} EXISTS\r\n", count).as_bytes(),
                                                )
                                                .await?;
                                            conn.message_count = count;
                                        }
                                        write_ok(
                                            &mut writer,
                                            &tag,
                                            &format!(
                                                "[APPENDUID {} {}] APPEND completed",
                                                uid_validity(&db),
                                                uid
                                            ),
                                        )
                                        .await?;
                                    }
                                    Some(Err(e)) => {
                                        tracing::warn!("APPEND to Drafts failed: {}", e);
                                        write_no(
                                            &mut writer,
                                            &tag,
                                            "[SERVERBUG] could not save the draft to your Aster account",
                                        )
                                        .await?;
                                    }
                                    None => {
                                        write_no(
                                            &mut writer,
                                            &tag,
                                            "[UNAVAILABLE] saving the draft is taking too long, try again",
                                        )
                                        .await?;
                                    }
                                }
                            }
                            Some(folder) => {
                                let sent_through_bridge = folder == "sent"
                                    && crate::imap::append::was_recently_sent(&buf);
                                let existing = if folder == "sent" {
                                    find_appended_sent_copy(&db, &buf)
                                } else {
                                    None
                                };
                                if sent_through_bridge && existing.is_none() {
                                    crate::sync::poller::try_kick_sync();
                                    write_ok(&mut writer, &tag, "APPEND completed").await?;
                                    continue;
                                }
                                if let Some(uid) = existing {
                                    write_ok(
                                        &mut writer,
                                        &tag,
                                        &format!(
                                            "[APPENDUID {} {}] APPEND completed",
                                            uid_validity(&db),
                                            uid
                                        ),
                                    )
                                    .await?;
                                    continue;
                                }
                                let import_db = db.clone();
                                let import_client = client.clone();
                                let import_session = session.clone();
                                let import_folder = folder.to_string();
                                let import_flags = cmd.flags.clone();
                                let import_date = cmd.internal_date;
                                let import_body = std::mem::take(&mut buf);
                                let outcome = run_with_keepalive(&mut writer, async move {
                                    crate::imap::append::append_imported_message(
                                        &import_db,
                                        &import_client,
                                        &import_session,
                                        &import_folder,
                                        &import_body,
                                        &import_flags,
                                        import_date,
                                    )
                                    .await
                                })
                                .await;
                                match outcome {
                                    Some(Ok(crate::imap::append::AppendOutcome::Stored {
                                        uid,
                                        aster_id,
                                    })) => {
                                        let _ = db
                                            .jmap_record_sync_batch("Email", &[aster_id.as_str()]);
                                        let email_state = db.jmap_state_get("Email").unwrap_or(0);
                                        let mailbox_state = db.jmap_state_bump("Mailbox").unwrap_or(0);
                                        let thread_state = db.jmap_state_bump("Thread").unwrap_or(0);
                                        let mut changed = std::collections::HashMap::new();
                                        changed.insert("Email".to_string(), email_state.to_string());
                                        changed.insert("Mailbox".to_string(), mailbox_state.to_string());
                                        changed.insert("Thread".to_string(), thread_state.to_string());
                                        let _ = broadcaster.send(StateChange { changed });
                                        if conn.state == ImapState::Selected
                                            && conn.selected_folder.as_deref() == Some(folder)
                                        {
                                            let count =
                                                db.count_cached_messages(folder).unwrap_or(0);
                                            writer
                                                .write_all(
                                                    format!("* {} EXISTS\r\n", count).as_bytes(),
                                                )
                                                .await?;
                                            conn.message_count = count;
                                        }
                                        write_ok(
                                            &mut writer,
                                            &tag,
                                            &format!(
                                                "[APPENDUID {} {}] APPEND completed",
                                                uid_validity(&db),
                                                uid
                                            ),
                                        )
                                        .await?;
                                    }
                                    Some(Ok(crate::imap::append::AppendOutcome::Duplicate {
                                        uid,
                                    })) => {
                                        crate::sync::poller::try_kick_sync();
                                        match uid {
                                            Some(uid) => {
                                                write_ok(
                                                    &mut writer,
                                                    &tag,
                                                    &format!(
                                                        "[APPENDUID {} {}] APPEND completed",
                                                        uid_validity(&db),
                                                        uid
                                                    ),
                                                )
                                                .await?
                                            }
                                            None => {
                                                write_ok(&mut writer, &tag, "APPEND completed")
                                                    .await?
                                            }
                                        }
                                    }
                                    Some(Err(e)) => {
                                        tracing::warn!("APPEND to {} failed: {}", folder, e);
                                        write_no(
                                            &mut writer,
                                            &tag,
                                            &format!(
                                                "[{}] {}",
                                                crate::imap::append::no_response_code(&e),
                                                e
                                            ),
                                        )
                                        .await?;
                                    }
                                    None => {
                                        write_no(
                                            &mut writer,
                                            &tag,
                                            "[UNAVAILABLE] the import is taking too long, try again",
                                        )
                                        .await?;
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        write_bad(&mut writer, &tag, "APPEND missing literal").await?;
                    }
                }
            }
            _ => {
                write_bad(&mut writer, &tag, "Unknown command").await?;
            }
        }
    }

    let _ = writer.flush().await;
    let _ = writer.shutdown().await;

    Ok(())
}

macro_rules! require_auth {
    ($conn:expr, $writer:expr, $tag:expr) => {
        if $conn.state == ImapState::NotAuthenticated {
            write_no(&mut $writer, &$tag, "Not authenticated").await?;
            continue;
        }
    };
}
use require_auth;

macro_rules! require_selected {
    ($conn:expr, $writer:expr, $tag:expr) => {
        if $conn.state != ImapState::Selected {
            write_no(&mut $writer, &$tag, "No mailbox selected").await?;
            continue;
        }
    };
}
use require_selected;

async fn delete_on_server(
    db: &Arc<Database>,
    client: &Arc<ApiClient>,
    session: &Arc<RwLock<Session>>,
    folder: &str,
    aster_id: &str,
) -> bool {
    let token = session.read().await.access_token.to_string();
    if folder == "drafts" {
        match client.delete_draft(&token, aster_id).await {
            Ok(()) => return true,
            Err(crate::error::BridgeError::Api(ref msg)) if msg.starts_with("404") => {}
            Err(e) => {
                tracing::warn!("server draft delete failed for {}: {}", aster_id, e);
                return false;
            }
        }
    }
    match client.delete_mail_item_permanent(&token, aster_id).await {
        Ok(()) => true,
        Err(crate::error::BridgeError::Api(ref msg)) if msg.starts_with("404") => true,
        Err(e) => {
            tracing::warn!("server delete failed for {}: {}", aster_id, e);
            let _ = db;
            false
        }
    }
}

async fn expunge_targets(
    writer: &mut (impl AsyncWrite + Unpin),
    db: &Arc<Database>,
    client: &Arc<ApiClient>,
    session: &Arc<RwLock<Session>>,
    conn: &mut ImapConnection,
    folder: &str,
    targets: Vec<(usize, u32, String)>,
) -> std::io::Result<()> {
    let mut adjustment: usize = 0;
    for (seq, uid, aster_id) in &targets {
        if !delete_on_server(db, client, session, folder, aster_id).await {
            continue;
        }
        let _ = db.delete_message_by_uid(*uid as i64, folder);
        let adjusted_seq = seq - adjustment;
        writer
            .write_all(format!("* {} EXPUNGE\r\n", adjusted_seq).as_bytes())
            .await?;
        conn.message_count = conn.message_count.saturating_sub(1);
        adjustment += 1;
    }
    Ok(())
}

async fn expunge_targets_silent(
    db: &Arc<Database>,
    client: &Arc<ApiClient>,
    session: &Arc<RwLock<Session>>,
    folder: &str,
    targets: Vec<(usize, u32, String)>,
) {
    for (_, uid, aster_id) in &targets {
        if !delete_on_server(db, client, session, folder, aster_id).await {
            continue;
        }
        let _ = db.delete_message_by_aster_id(aster_id);
        let _ = uid;
    }
}

fn format_attachment_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn draft_content_from_mime(raw_message: &[u8]) -> Option<crate::crypto::draft::DraftContent> {
    use mail_parser::{MessageParser, MimeHeaders};

    fn addr_list(a: Option<&mail_parser::Address<'_>>) -> Vec<String> {
        a.map(|l| {
            l.iter()
                .filter_map(|x| x.address().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
    }

    let parsed = MessageParser::default().parse(raw_message)?;
    let to_recipients = addr_list(parsed.to());
    let cc_recipients = addr_list(parsed.cc());
    let bcc_recipients = addr_list(parsed.bcc());
    let subject = parsed.subject().unwrap_or("").to_string();
    let message = parsed
        .body_html(0)
        .map(|s| s.to_string())
        .or_else(|| parsed.body_text(0).map(|s| s.to_string()))
        .unwrap_or_default();

    let mut attachments: Vec<crate::crypto::draft::DraftAttachment> = Vec::new();
    for part in parsed.attachments() {
        let data = part.contents();
        if data.is_empty() {
            continue;
        }
        let name = part
            .attachment_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("attachment-{}", attachments.len() + 1));
        let mime_type = part
            .content_type()
            .map(|ct| match ct.subtype() {
                Some(sub) => format!("{}/{}", ct.ctype(), sub),
                None => ct.ctype().to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let content_id = part
            .content_id()
            .map(|s| s.trim_matches(&['<', '>'][..]).to_string())
            .filter(|s| !s.is_empty());
        attachments.push(crate::crypto::draft::DraftAttachment {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            size: format_attachment_size(data.len()),
            size_bytes: data.len() as i64,
            mime_type,
            data_base64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data),
            content_id,
        });
    }

    Some(crate::crypto::draft::DraftContent {
        to_recipients,
        cc_recipients,
        bcc_recipients,
        subject,
        message,
        attachments: if attachments.is_empty() {
            None
        } else {
            Some(attachments)
        },
    })
}

pub(crate) async fn append_draft(
    db: &Arc<Database>,
    client: &Arc<ApiClient>,
    session: &Arc<RwLock<Session>>,
    raw_message: &[u8],
) -> std::result::Result<(u32, String), String> {
    let (token, identity_key, our_email) = {
        let s = session.read().await;
        (
            s.access_token.to_string(),
            s.identity_key.clone(),
            s.email.clone(),
        )
    };
    let identity_key =
        identity_key.ok_or_else(|| "session has no identity key for draft encryption".to_string())?;

    let content = draft_content_from_mime(raw_message)
        .ok_or_else(|| "failed to parse draft message".to_string())?;

    let (encrypted_content, content_nonce) =
        crate::crypto::draft::encrypt_draft_content(&content, &identity_key)
            .map_err(|e| e.to_string())?;
    let content_hash = crate::crypto::draft::draft_content_hash(&encrypted_content);
    let attachment_count = content
        .attachments
        .as_ref()
        .map(|a| a.len() as i64)
        .unwrap_or(0);
    let body = crate::api_client::CreateDraftBody {
        draft_type: "new",
        encrypted_content: &encrypted_content,
        content_nonce: &content_nonce,
        content_hash: &content_hash,
        size_bytes: encrypted_content.len() as i64,
        has_attachments: attachment_count > 0,
        attachment_count,
    };
    let created = client
        .create_draft(&token, &body)
        .await
        .map_err(|e| e.to_string())?;

    let now = chrono::Utc::now().to_rfc3339();
    crate::sync::poller::cache_web_draft(db, &created.id, &content, &our_email, &now, created.version);
    let uid = db.assign_uid_if_missing("drafts", &created.id)?;
    Ok((uid, created.id))
}

fn find_appended_sent_copy(db: &Database, raw_message: &[u8]) -> Option<u32> {
    use mail_parser::MessageParser;
    let parsed = MessageParser::default().parse(raw_message)?;
    let message_id = parsed
        .message_id()
        .map(|s| s.trim_matches(&['<', '>'][..]).to_string())
        .filter(|s| !s.is_empty());
    let subject = parsed.subject().map(|s| s.to_string());
    let messages = db.list_cached_message_meta("sent").ok()?;
    if let Some(mid) = message_id {
        if let Some(m) = messages.iter().rev().find(|m| {
            m.raw_headers
                .as_deref()
                .map_or(false, |rh| rh.contains(mid.as_str()))
        }) {
            return Some(m.imap_uid);
        }
    }
    if let Some(subj) = subject {
        if let Some(m) = messages
            .iter()
            .rev()
            .take(20)
            .find(|m| m.subject.as_deref() == Some(subj.as_str()))
        {
            return Some(m.imap_uid);
        }
    }
    None
}

const APPEND_KEEPALIVE_SECS: u64 = 20;
const APPEND_DEADLINE_SECS: u64 = 15 * 60;

async fn run_with_keepalive<T>(
    writer: &mut (impl AsyncWrite + Unpin),
    fut: impl std::future::Future<Output = T> + Send + 'static,
) -> Option<T>
where
    T: Send + 'static,
{
    run_with_keepalive_every(
        writer,
        std::time::Duration::from_secs(APPEND_KEEPALIVE_SECS),
        std::time::Duration::from_secs(APPEND_DEADLINE_SECS),
        fut,
    )
    .await
}

async fn run_with_keepalive_every<T>(
    writer: &mut (impl AsyncWrite + Unpin),
    every: std::time::Duration,
    deadline: std::time::Duration,
    fut: impl std::future::Future<Output = T> + Send + 'static,
) -> Option<T>
where
    T: Send + 'static,
{
    let mut handle = tokio::spawn(fut);
    let expires_at = tokio::time::Instant::now() + deadline;
    let mut alive = true;
    loop {
        tokio::select! {
            joined = &mut handle => {
                return match joined {
                    Ok(out) => Some(out),
                    Err(e) => {
                        tracing::error!("APPEND worker ended without a result: {}", e);
                        None
                    }
                };
            }
            _ = tokio::time::sleep_until(expires_at) => {
                tracing::warn!(
                    seconds = deadline.as_secs(),
                    "APPEND is still running past its deadline, asking the client to retry"
                );
                return None;
            }
            _ = tokio::time::sleep(every), if alive => {
                let sent = writer.write_all(b"* OK APPEND in progress\r\n").await.is_ok()
                    && writer.flush().await.is_ok();
                if !sent {
                    alive = false;
                }
            }
        }
    }
}

async fn write_ok(
    writer: &mut (impl AsyncWrite + Unpin),
    tag: &str,
    msg: &str,
) -> std::io::Result<()> {
    writer
        .write_all(format!("{} OK {}\r\n", tag, msg).as_bytes())
        .await
}

async fn write_no(
    writer: &mut (impl AsyncWrite + Unpin),
    tag: &str,
    msg: &str,
) -> std::io::Result<()> {
    writer
        .write_all(format!("{} NO {}\r\n", tag, msg).as_bytes())
        .await
}

async fn write_bad(
    writer: &mut (impl AsyncWrite + Unpin),
    tag: &str,
    msg: &str,
) -> std::io::Result<()> {
    writer
        .write_all(format!("{} BAD {}\r\n", tag, msg).as_bytes())
        .await
}

async fn handle_login(
    writer: &mut (impl AsyncWrite + Unpin),
    session: &Arc<RwLock<Session>>,
    passwords: &AppPasswords,
    conn: &mut ImapConnection,
    tag: &str,
    args: &str,
) -> std::io::Result<bool> {
    if conn.state != ImapState::NotAuthenticated {
        write_bad(writer, tag, "already authenticated").await?;
        return Ok(false);
    }

    let login_parts: Vec<&str> = args.splitn(2, ' ').collect();
    if login_parts.len() < 2 {
        write_bad(writer, tag, "LOGIN requires user and password").await?;
        return Ok(false);
    }

    let username = login_parts[0].trim_matches('"');
    let password = login_parts[1].trim_matches('"');

    let expected_email = session.read().await.email.clone();
    if expected_email.is_empty() || !username.eq_ignore_ascii_case(&expected_email) {
        write_no(writer, tag, "[AUTHENTICATIONFAILED] Invalid credentials").await?;
        return Ok(false);
    }

    if let Some(pw_id) = passwords.verify_and_id_async(password).await {
        conn.state = ImapState::Authenticated;
        passwords.record_use(&pw_id, Some("imap"));
        crate::sync::poller::try_kick_sync();
        write_ok(writer, tag, "LOGIN completed").await?;
        Ok(true)
    } else {
        write_no(writer, tag, "[AUTHENTICATIONFAILED] Invalid credentials").await?;
        Ok(false)
    }
}

pub(crate) fn parse_imap_atom_or_quoted(s: &str) -> (String, &str) {
    let s = s.trim_start();
    if s.starts_with('"') {
        let rest = &s[1..];
        let mut val = String::new();
        let mut chars = rest.char_indices();
        let mut end = rest.len();
        while let Some((i, c)) = chars.next() {
            if c == '\\' {
                if let Some((_, nc)) = chars.next() {
                    val.push(nc);
                }
            } else if c == '"' {
                end = i;
                break;
            } else {
                val.push(c);
            }
        }
        let remainder = if end + 1 <= rest.len() { &rest[end + 1..] } else { "" };
        (val, remainder)
    } else {
        let end = s.find(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n')
            .unwrap_or(s.len());
        (s[..end].to_string(), &s[end..])
    }
}

fn imap_glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" { return true; }
    let p = pattern.to_ascii_uppercase();
    let n = name.to_ascii_uppercase();
    if p.contains('*') {
        let parts: Vec<&str> = p.split('*').collect();
        let mut pos = 0usize;
        for part in &parts {
            if part.is_empty() { continue; }
            if let Some(idx) = n[pos..].find(part.as_ref() as &str) {
                pos += idx + part.len();
            } else {
                return false;
            }
        }
        return true;
    }
    if p.contains('%') {
        let parts: Vec<&str> = p.split('%').collect();
        let mut pos = 0usize;
        for part in &parts {
            if part.is_empty() { continue; }
            if let Some(idx) = n[pos..].find(part.as_ref() as &str) {
                if n[pos..pos + idx].contains('/') { return false; }
                pos += idx + part.len();
            } else {
                return false;
            }
        }
        return !n[pos..].contains('/');
    }
    p == n
}

async fn handle_list(
    writer: &mut (impl AsyncWrite + Unpin),
    tag: &str,
    args: &str,
) -> std::io::Result<()> {
    let (_, rest) = parse_imap_atom_or_quoted(args);
    let rest = rest.trim();
    let (pattern, _) = parse_imap_atom_or_quoted(rest);

    if pattern.is_empty() {
        writer.write_all(b"* LIST (\\Noselect) \"/\" \"\"\r\n").await?;
        return write_ok(writer, tag, "LIST completed").await;
    }

    for (imap_name, _, flags) in IMAP_FOLDERS {
        if imap_glob_match(&pattern, imap_name) {
            let attrs = if flags.is_empty() {
                "\\HasNoChildren".to_string()
            } else {
                format!("\\HasNoChildren {}", flags)
            };
            writer
                .write_all(format!("* LIST ({}) \"/\" \"{}\"\r\n", attrs, imap_name).as_bytes())
                .await?;
        }
    }
    write_ok(writer, tag, "LIST completed").await
}

async fn handle_lsub(
    writer: &mut (impl AsyncWrite + Unpin),
    tag: &str,
    args: &str,
) -> std::io::Result<()> {
    let (_, rest) = parse_imap_atom_or_quoted(args);
    let rest = rest.trim();
    let (pattern, _) = parse_imap_atom_or_quoted(rest);

    if pattern.is_empty() {
        writer.write_all(b"* LSUB (\\Noselect) \"/\" \"\"\r\n").await?;
        return write_ok(writer, tag, "LSUB completed").await;
    }

    for (imap_name, _, flags) in IMAP_FOLDERS {
        if imap_glob_match(&pattern, imap_name) {
            let attrs = if flags.is_empty() {
                "\\HasNoChildren".to_string()
            } else {
                format!("\\HasNoChildren {}", flags)
            };
            writer
                .write_all(format!("* LSUB ({}) \"/\" \"{}\"\r\n", attrs, imap_name).as_bytes())
                .await?;
        }
    }
    write_ok(writer, tag, "LSUB completed").await
}

fn move_flags_for(internal: &str) -> Option<serde_json::Value> {
    match internal {
        "archive" => Some(serde_json::json!({"is_archived": true, "is_trashed": false, "is_spam": false})),
        "trash" => Some(serde_json::json!({"is_trashed": true, "is_archived": false})),
        "spam" => Some(serde_json::json!({"is_spam": true, "is_archived": false, "is_trashed": false})),
        "inbox" => Some(serde_json::json!({"is_archived": false, "is_trashed": false, "is_spam": false})),
        _ => None,
    }
}

async fn bulk_move_chunk(
    client: &Arc<ApiClient>,
    token: &str,
    ids: &[String],
    flags: &serde_json::Value,
) -> bool {
    let mut attempt = 0u32;
    loop {
        match client.bulk_set_mailbox_flags(token, ids, flags).await {
            Ok(updated) => return updated as usize == ids.len(),
            Err(e) => {
                if crate::imap::append::is_rate_limited(&e) && attempt < 3 {
                    let wait = crate::imap::append::rate_limit_backoff(attempt);
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    continue;
                }
                return false;
            }
        }
    }
}

async fn set_flags_with_backoff(
    client: &Arc<ApiClient>,
    token: &str,
    id: &str,
    flags: &serde_json::Value,
) -> crate::error::Result<()> {
    let mut attempt = 0u32;
    loop {
        match client.set_mailbox_flags(token, id, flags.clone()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if crate::imap::append::is_rate_limited(&e) && attempt < 3 {
                    let wait = crate::imap::append::rate_limit_backoff(attempt);
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_copy_move(
    writer: &mut (impl AsyncWrite + Unpin),
    db: &Arc<Database>,
    client: &Arc<ApiClient>,
    session: &Arc<RwLock<Session>>,
    conn: &mut ImapConnection,
    tag: &str,
    args: &str,
    is_uid: bool,
    is_move: bool,
) -> std::io::Result<()> {
    let verb = if is_move { "MOVE" } else { "COPY" };
    if is_move && conn.read_only {
        return write_no(writer, tag, "[READ-ONLY] Mailbox is read-only").await;
    }
    let source_folder = conn.selected_folder.clone().unwrap_or_else(|| "inbox".to_string());
    let trimmed = args.trim();
    let (set_str, mailbox_raw) = match trimmed.split_once(char::is_whitespace) {
        Some((s, m)) => (s.trim(), m.trim()),
        None => return write_bad(writer, tag, "command requires a message set and mailbox").await,
    };
    let mailbox = mailbox_raw.trim().trim_matches('"');
    let target_internal = match IMAP_FOLDERS
        .iter()
        .find(|(disp, _, _)| disp.eq_ignore_ascii_case(mailbox))
        .map(|(_, internal, _)| *internal)
    {
        Some(f) => f,
        None => return write_no(writer, tag, "[TRYCREATE] mailbox does not exist").await,
    };
    let flags = match move_flags_for(target_internal) {
        Some(f) => f,
        None => return write_no(writer, tag, "[CANNOT] cannot move messages into that mailbox").await,
    };
    if target_internal == source_folder.as_str() {
        return write_ok(writer, tag, &format!("{} completed", verb)).await;
    }

    let messages = {
        let db = Arc::clone(db);
        let folder = source_folder.clone();
        tokio::task::spawn_blocking(move || db.list_cached_messages(&folder).unwrap_or_default())
            .await
            .unwrap_or_default()
    };
    let mut selected: Vec<(usize, CachedMessage)> = Vec::new();
    for (i, m) in messages.iter().enumerate() {
        let seq = (i + 1) as u32;
        let hit = if is_uid {
            uid_set_contains(set_str, m.imap_uid)
        } else {
            uid_set_contains(set_str, seq)
        };
        if hit {
            selected.push((i + 1, m.clone()));
        }
    }
    if selected.is_empty() {
        return write_ok(writer, tag, &format!("{} completed", verb)).await;
    }

    let token = session.read().await.access_token.to_string();
    let validity = {
        let db = Arc::clone(db);
        tokio::task::spawn_blocking(move || uid_validity(&db))
            .await
            .unwrap_or(1)
    };
    let mut src_uids: Vec<u32> = Vec::new();
    let mut tgt_uids: Vec<u32> = Vec::new();
    let mut moved_seqs: Vec<usize> = Vec::new();
    for chunk in selected.chunks(ApiClient::MAX_BULK_METADATA_ITEMS) {
        let ids: Vec<String> = chunk.iter().map(|(_, m)| m.aster_id.clone()).collect();
        if bulk_move_chunk(client, &token, &ids, &flags).await {
            continue;
        }
        for (_, m) in chunk {
            if let Err(e) = set_flags_with_backoff(client, &token, &m.aster_id, &flags).await {
                let is_missing_item = matches!(
                    &e,
                    crate::error::BridgeError::Api(msg) if msg.starts_with("404")
                );
                let draft_removed = is_missing_item
                    && source_folder == "drafts"
                    && is_move
                    && client.delete_draft(&token, &m.aster_id).await.is_ok();
                if !draft_removed {
                    tracing::warn!("{} backend update failed for {}: {}", verb, m.aster_id, e);
                    return write_no(writer, tag, "[SERVERBUG] could not move message on the server")
                        .await;
                }
            }
        }
    }
    {
        let db = Arc::clone(db);
        let folder = source_folder.clone();
        let entries = selected.clone();
        let recorded = tokio::task::spawn_blocking(move || {
            let mut src: Vec<u32> = Vec::new();
            let mut tgt: Vec<u32> = Vec::new();
            let mut seqs: Vec<usize> = Vec::new();
            for (seq, m) in &entries {
                let _ = db.upsert_cached_message(
                    &m.aster_id,
                    target_internal,
                    m.subject.as_deref(),
                    m.sender.as_deref(),
                    m.recipients.as_deref(),
                    m.date.as_deref(),
                    m.size,
                    m.body_text.as_deref(),
                    m.raw_headers.as_deref(),
                );
                let _ = db.remove_uid_mapping(m.imap_uid as i64, &folder);
                src.push(m.imap_uid);
                tgt.push(db.assign_uid_if_missing(target_internal, &m.aster_id).unwrap_or(0));
                seqs.push(*seq);
            }
            (src, tgt, seqs)
        })
        .await
        .unwrap_or_default();
        src_uids = recorded.0;
        tgt_uids = recorded.1;
        moved_seqs = recorded.2;
    }
    let src_set = src_uids.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
    let tgt_set = tgt_uids.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");

    if is_move {
        writer
            .write_all(format!("* OK [COPYUID {} {} {}]\r\n", validity, src_set, tgt_set).as_bytes())
            .await?;
    }
    moved_seqs.sort_unstable();
    let mut adjustment = 0usize;
    for seq in &moved_seqs {
        let adjusted = seq.saturating_sub(adjustment);
        writer
            .write_all(format!("* {} EXPUNGE\r\n", adjusted).as_bytes())
            .await?;
        conn.message_count = conn.message_count.saturating_sub(1);
        adjustment += 1;
    }
    if is_move {
        write_ok(writer, tag, "MOVE completed").await
    } else {
        writer
            .write_all(
                format!(
                    "{} OK [COPYUID {} {} {}] COPY completed\r\n",
                    tag, validity, src_set, tgt_set
                )
                .as_bytes(),
            )
            .await
    }
}

async fn handle_select(
    writer: &mut (impl AsyncWrite + Unpin),
    db: &Arc<Database>,
    conn: &mut ImapConnection,
    tag: &str,
    args: &str,
    command: &str,
) -> std::io::Result<()> {
    let mailbox = {
        let s = args.trim();
        if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 { &s[1..s.len()-1] } else { s }
    };

    let folder_entry = IMAP_FOLDERS
        .iter()
        .find(|(imap, _, _)| imap.eq_ignore_ascii_case(mailbox));

    let aster_folder = match folder_entry {
        Some((_, f, _)) => *f,
        None => {
            return write_no(writer, tag, "[NONEXISTENT] No such mailbox").await;
        }
    };

    let count = db.count_cached_messages(aster_folder).unwrap_or(0);
    if count == 0 {
        crate::sync::poller::try_kick_sync();
    }

    conn.selected_mailbox = Some(mailbox.to_string());
    conn.selected_folder = Some(aster_folder.to_string());
    conn.state = ImapState::Selected;
    conn.message_count = count;
    conn.read_only = command == "EXAMINE";

    let messages = db.list_cached_messages(aster_folder).unwrap_or_default();

    writer
        .write_all(format!("* {} EXISTS\r\n", count).as_bytes())
        .await?;
    writer.write_all(b"* 0 RECENT\r\n").await?;

    if let Some(first_unseen) = messages.iter().position(|m| (m.flags & 1) == 0) {
        let seq = first_unseen + 1;
        writer
            .write_all(format!("* OK [UNSEEN {}] Message {} is first unseen\r\n", seq, seq).as_bytes())
            .await?;
    }

    writer
        .write_all(format!("* OK [UIDVALIDITY {}]\r\n", uid_validity(db)).as_bytes())
        .await?;
    let max_uid = db.max_uid(aster_folder).unwrap_or(0);
    writer
        .write_all(format!("* OK [UIDNEXT {}]\r\n", max_uid + 1).as_bytes())
        .await?;
    writer
        .write_all(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
        .await?;
    writer
        .write_all(
            b"* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)]\r\n",
        )
        .await?;

    let rw = if conn.read_only { "READ-ONLY" } else { "READ-WRITE" };
    write_ok(writer, tag, &format!("[{}] {} completed", rw, command)).await
}

fn sanitize_header(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .collect()
}

fn imap_quote(s: &str) -> String {
    let cleaned = sanitize_header(s);
    let escaped = cleaned.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

fn parse_address(addr: &str) -> (String, String, String) {
    let trimmed = addr.trim();
    let (name, email) = match (trimmed.find('<'), trimmed.rfind('>')) {
        (Some(open), Some(close)) if close > open => {
            let name_part = trimmed[..open].trim().trim_matches('"').to_string();
            let email_part = trimmed[open + 1..close].trim().to_string();
            (name_part, email_part)
        }
        _ => (String::new(), trimmed.to_string()),
    };
    let (mailbox, host) = if let Some(at) = email.find('@') {
        (email[..at].to_string(), email[at + 1..].to_string())
    } else {
        (email.clone(), String::new())
    };
    (name, mailbox, host)
}

fn imap_address_list(addr_str: Option<&str>) -> String {
    let s = match addr_str {
        Some(s) if !s.is_empty() => s,
        _ => return "NIL".to_string(),
    };
    let mut parts = Vec::new();
    for addr in s.split(',') {
        let (name, mailbox, host) = parse_address(addr);
        let name_field = if name.is_empty() { "NIL".to_string() } else { imap_quote(&name) };
        let host_field = if host.is_empty() { "NIL".to_string() } else { imap_quote(&host) };
        let mailbox_field = if mailbox.is_empty() { "NIL".to_string() } else { imap_quote(&mailbox) };
        parts.push(format!("({} NIL {} {})", name_field, mailbox_field, host_field));
    }
    if parts.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", parts.join(""))
    }
}

pub fn date_header_rfc2822(s: &str) -> String {
    match parse_datetime_lenient(s) {
        Some(d) => d.format("%a, %d %b %Y %H:%M:%S %z").to_string(),
        None => s.to_string(),
    }
}

pub fn build_rfc822(msg: &CachedMessage) -> String {
    let mut out = String::new();
    let date = sanitize_header(&date_header_rfc2822(msg.date.as_deref().unwrap_or("")));
    let from = sanitize_header(msg.sender.as_deref().unwrap_or("unknown@astermail.org"));
    let to = sanitize_header(msg.recipients.as_deref().unwrap_or(""));
    let subject = sanitize_header(msg.subject.as_deref().unwrap_or(""));
    let aster_id = sanitize_header(&msg.aster_id);
    let meta: serde_json::Value = msg
        .raw_headers
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let real_message_id = meta
        .get("message_id")
        .and_then(|v| v.as_str())
        .map(|s| sanitize_header(s))
        .filter(|s| !s.is_empty());
    let is_html_flag = meta.get("is_html").and_then(|v| v.as_bool());
    let cc = meta
        .get("cc")
        .and_then(|v| v.as_str())
        .map(sanitize_header)
        .filter(|s| !s.is_empty());
    let bcc = meta
        .get("bcc")
        .and_then(|v| v.as_str())
        .map(sanitize_header)
        .filter(|s| !s.is_empty());
    out.push_str(&format!("Date: {}\r\n", date));
    out.push_str(&format!("From: {}\r\n", from));
    if !to.is_empty() {
        out.push_str(&format!("To: {}\r\n", to));
    }
    if let Some(cc) = cc {
        out.push_str(&format!("Cc: {}\r\n", cc));
    }
    if let Some(bcc) = bcc {
        out.push_str(&format!("Bcc: {}\r\n", bcc));
    }
    out.push_str(&format!("Subject: {}\r\n", subject));
    match real_message_id {
        Some(mid) => {
            if mid.starts_with('<') {
                out.push_str(&format!("Message-ID: {}\r\n", mid));
            } else {
                out.push_str(&format!("Message-ID: <{}>\r\n", mid));
            }
        }
        None => {
            out.push_str(&format!("Message-ID: <{}@aster-bridge>\r\n", aster_id));
        }
    }
    let body = msg.body_text.as_deref().unwrap_or("");
    let is_html = is_html_flag.unwrap_or_else(|| {
        body.contains("</")
            || body.contains("<html")
            || body.contains("<body")
            || body.contains("<div")
            || body.contains("<p ")
            || body.contains("<!DOCTYPE")
    });
    out.push_str("MIME-Version: 1.0\r\n");
    if is_html {
        out.push_str("Content-Type: text/html; charset=utf-8\r\n");
    } else {
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    }
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    out.push_str(body);
    out
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        let before_ok = abs == 0
            || !haystack.as_bytes()[abs - 1].is_ascii_alphanumeric();
        let after_idx = abs + needle.len();
        let after_ok = after_idx >= haystack.len()
            || {
                let c = haystack.as_bytes()[after_idx];
                !(c.is_ascii_alphanumeric() || c == b'.')
            };
        if before_ok && after_ok {
            return true;
        }
        start = abs + needle.len();
    }
    false
}

fn parse_header_fields_request(fetch_parts: &str) -> Option<(String, Vec<String>)> {
    let upper = fetch_parts.to_ascii_uppercase();
    let key = "BODY.PEEK[HEADER.FIELDS (";
    let alt = "BODY[HEADER.FIELDS (";
    let (start, _) = if let Some(p) = upper.find(key) {
        (p + key.len(), key.len())
    } else if let Some(p) = upper.find(alt) {
        (p + alt.len(), alt.len())
    } else {
        return None;
    };
    let rest = &fetch_parts[start..];
    let end = rest.find(')')?;
    let inner = &rest[..end];
    let fields: Vec<String> = inner
        .split_ascii_whitespace()
        .map(|s| s.to_string())
        .collect();
    if fields.is_empty() {
        return None;
    }
    Some((fields.join(" "), fields))
}

fn parse_body_partial(upper_parts: &str) -> Option<(usize, Option<usize>)> {
    let idx = upper_parts
        .find("BODY[]<")
        .map(|i| i + "BODY[]<".len())
        .or_else(|| upper_parts.find("BODY.PEEK[]<").map(|i| i + "BODY.PEEK[]<".len()))?;
    let rest = &upper_parts[idx..];
    let end = rest.find('>')?;
    let spec = &rest[..end];
    let mut it = spec.split('.');
    let off: usize = it.next()?.parse().ok()?;
    let len = it.next().and_then(|s| s.parse::<usize>().ok());
    Some((off, len))
}

fn filter_header_fields(header: &str, fields: &[String]) -> String {
    let wanted: Vec<String> = fields.iter().map(|f| f.to_ascii_lowercase()).collect();
    let mut out = String::new();
    let mut include_current = false;
    for line in header.split_inclusive("\r\n") {
        let is_continuation = line.starts_with(' ') || line.starts_with('\t');
        if is_continuation {
            if include_current {
                out.push_str(line);
            }
            continue;
        }
        if line == "\r\n" {
            continue;
        }
        let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        include_current = wanted.iter().any(|w| w == &name);
        if include_current {
            out.push_str(line);
        }
    }
    out.push_str("\r\n\r\n");
    out
}

fn iso_to_imap_date(s: &str) -> String {
    const MONTHS: &[&str] = &["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    if let Some(dt) = parse_datetime_lenient(s) {
        let m = MONTHS.get(dt.date_naive().month0() as usize).unwrap_or(&"Jan");
        return format!("{:02}-{}-{} {:02}:{:02}:{:02} +0000",
            dt.date_naive().day(), m, dt.date_naive().year(),
            dt.time().hour(), dt.time().minute(), dt.time().second());
    }
    "01-Jan-1970 00:00:00 +0000".to_string()
}

fn parse_set(spec: &str, max: u32) -> Vec<u32> {
    if max == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once(':') {
            let lo: u32 = if a == "*" {
                max
            } else if let Ok(v) = a.parse() {
                v
            } else {
                continue;
            };
            let hi: u32 = if b == "*" {
                max
            } else if let Ok(v) = b.parse() {
                v
            } else {
                continue;
            };
            let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
            for i in lo..=hi.min(max) {
                if i >= 1 {
                    out.push(i);
                }
            }
        } else if part == "*" {
            out.push(max);
        } else if let Ok(n) = part.parse::<u32>() {
            if n >= 1 && n <= max {
                out.push(n);
            }
        }
    }
    out
}

async fn handle_fetch(
    writer: &mut (impl AsyncWrite + Unpin),
    db: &Arc<Database>,
    client: &Arc<ApiClient>,
    session: &Arc<RwLock<Session>>,
    conn: &ImapConnection,
    tag: &str,
    args: &str,
    uid_command: bool,
) -> std::io::Result<()> {
    let folder = conn.selected_folder.as_deref().unwrap_or("inbox");
    let mut fetch_seen_pushes: Vec<String> = Vec::new();

    let (range_spec, fetch_parts) = args
        .split_once(' ')
        .map(|(r, rest)| (r, rest))
        .unwrap_or((args, "(FLAGS)"));

    let upper_parts = fetch_parts.to_ascii_uppercase();
    let is_all  = contains_word(&upper_parts, "ALL");
    let is_fast = contains_word(&upper_parts, "FAST");
    let is_full = contains_word(&upper_parts, "FULL");
    let wants_envelope = upper_parts.contains("ENVELOPE") || is_all || is_full;
    let wants_flags = upper_parts.contains("FLAGS") || is_all || is_fast || is_full;
    let wants_size = upper_parts.contains("RFC822.SIZE") || is_all || is_fast || is_full;
    let wants_uid = uid_command || upper_parts.contains("UID");
    let wants_rfc822_text = contains_word(&upper_parts, "RFC822.TEXT");
    let wants_body = upper_parts.contains("BODY[]")
        || upper_parts.contains("BODY.PEEK[]")
        || (contains_word(&upper_parts, "RFC822") && !wants_rfc822_text && !upper_parts.contains("RFC822.HEADER") && !upper_parts.contains("RFC822.SIZE"));
    let wants_body_header = upper_parts.contains("BODY[HEADER]")
        || upper_parts.contains("BODY.PEEK[HEADER]")
        || upper_parts.contains("RFC822.HEADER");
    let wants_body_text = upper_parts.contains("BODY[TEXT]") || upper_parts.contains("BODY.PEEK[TEXT]");
    let header_fields = parse_header_fields_request(fetch_parts);
    let wants_gm_labels = contains_word(&upper_parts, "X-GM-LABELS");
    let wants_gm_thrid = contains_word(&upper_parts, "X-GM-THRID");
    let wants_gm_msgid = contains_word(&upper_parts, "X-GM-MSGID");
    let wants_bodystructure = contains_word(&upper_parts, "BODYSTRUCTURE");
    let wants_body_1 = (upper_parts.contains("BODY[1]") || upper_parts.contains("BODY.PEEK[1]"))
        && !wants_body_text;
    let wants_internaldate = upper_parts.contains("INTERNALDATE")
        || is_all || is_fast || is_full;
    let body_is_peek = upper_parts.contains("BODY.PEEK[]")
        || upper_parts.contains("BODY.PEEK[TEXT]")
        || upper_parts.contains("BODY.PEEK[1]")
        || upper_parts.contains("RFC822.HEADER");

    let needs_body = wants_body
        || wants_body_header
        || wants_body_text
        || wants_body_1
        || wants_rfc822_text
        || wants_bodystructure
        || header_fields.is_some();
    let messages = if needs_body {
        db.list_cached_messages(folder)
    } else {
        db.list_cached_message_meta(folder)
    }
    .unwrap_or_default();
    let total = messages.len() as u32;
    let max_uid_val = messages.iter().map(|m| m.imap_uid).max().unwrap_or(0);
    let range_cap = if uid_command { max_uid_val } else { total };
    let selected = parse_set(range_spec, range_cap);

    let mut out: Vec<u8> = Vec::new();
    for n in &selected {
        let (seq_num, msg) = if uid_command {
            match messages.iter().enumerate().find(|(_, m)| m.imap_uid == *n) {
                Some((idx, m)) => (idx + 1, m),
                None => continue,
            }
        } else {
            match messages.get((*n as usize).saturating_sub(1)) {
                Some(m) => (*n as usize, m),
                None => continue,
            }
        };
        let uid = msg.imap_uid;
        let rfc = build_rfc822(msg);
        let mut items: Vec<String> = Vec::new();

        if wants_flags {
            let mut flag_list: Vec<&str> = Vec::new();
            if msg.flags & 1 != 0 { flag_list.push("\\Seen"); }
            if msg.flags & 2 != 0 { flag_list.push("\\Answered"); }
            if msg.flags & 4 != 0 { flag_list.push("\\Flagged"); }
            if msg.flags & 8 != 0 { flag_list.push("\\Deleted"); }
            if msg.flags & 16 != 0 { flag_list.push("\\Draft"); }
            items.push(format!("FLAGS ({})", flag_list.join(" ")));
        }

        if wants_uid {
            items.push(format!("UID {}", uid));
        }

        if wants_size {
            let sz = rfc.len() + if needs_body { 0 } else { msg.size.max(0) as usize };
            items.push(format!("RFC822.SIZE {}", sz));
        }

        if wants_envelope {
            let date = date_header_rfc2822(&msg.date.clone().unwrap_or_default());
            let subject = msg.subject.clone().unwrap_or_default();
            let from_list = imap_address_list(msg.sender.as_deref());
            let to_list = imap_address_list(msg.recipients.as_deref());
            let env_meta: serde_json::Value = msg.raw_headers.as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::Value::Null);
            let msg_id_raw = env_meta.get("message_id").and_then(|v| v.as_str())
                .map(|s| sanitize_header(s))
                .filter(|s| !s.is_empty());
            let msg_id = match msg_id_raw {
                Some(ref mid) if mid.starts_with('<') => mid.clone(),
                Some(ref mid) => format!("<{}>", mid),
                None => format!("<{}@aster-bridge>", msg.aster_id),
            };
            items.push(format!(
                "ENVELOPE ({} {} {} {} NIL {} NIL NIL NIL {})",
                imap_quote(&date),
                imap_quote(&subject),
                from_list,
                from_list,
                to_list,
                imap_quote(&msg_id)
            ));
        }

        if wants_gm_labels {
            let labels = gmail_labels_for_message(msg);
            let rendered: Vec<String> = labels.iter().map(|l| quote_or_atom_label(l)).collect();
            items.push(format!("X-GM-LABELS ({})", rendered.join(" ")));
        }

        if wants_gm_thrid {
            items.push(format!("X-GM-THRID {}", gmail_thrid_from_aster(&msg.aster_id)));
        }

        if wants_gm_msgid {
            items.push(format!("X-GM-MSGID {}", gmail_msgid_from_aster(&msg.aster_id)));
        }

        if wants_internaldate {
            let date_val = msg.date.as_deref()
                .map(iso_to_imap_date)
                .unwrap_or_else(|| "01-Jan-1970 00:00:00 +0000".to_string());
            items.push(format!("INTERNALDATE {}", imap_quote(&date_val)));
        }

        if wants_bodystructure {
            let bs_meta: serde_json::Value = msg.raw_headers.as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::Value::Null);
            let is_html_bs = bs_meta.get("is_html").and_then(|v| v.as_bool()).unwrap_or_else(|| {
                let b = msg.body_text.as_deref().unwrap_or("");
                b.trim_start().starts_with('<') || b.contains("</")
            });
            let body_start = rfc.find("\r\n\r\n").map(|p| p + 4).unwrap_or(rfc.len());
            let body = &rfc[body_start..];
            let body_size = body.len();
            let line_count = body.chars().filter(|c| *c == '\n').count();
            let subtype = if is_html_bs { "HTML" } else { "PLAIN" };
            items.push(format!(
                "BODYSTRUCTURE (\"TEXT\" \"{}\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" {} {})",
                subtype, body_size, line_count
            ));
        }

        if wants_body_text || wants_body_1 {
            let this_is_peek = (wants_body_text && upper_parts.contains("BODY.PEEK[TEXT]"))
                || (wants_body_1 && upper_parts.contains("BODY.PEEK[1]"));
            let body_start = rfc.find("\r\n\r\n").map(|p| p + 4).unwrap_or(rfc.len());
            let body = &rfc[body_start..];
            let key = if wants_body_text { "BODY[TEXT]" } else { "BODY[1]" };
            if !this_is_peek {
                let current_flags = msg.flags as u32;
                if current_flags & 1 == 0 {
                    let new_flags = current_flags | 1;
                    let _ = db.update_message_flags(msg.imap_uid as i64, folder, new_flags as i64);
                    fetch_seen_pushes.push(msg.aster_id.clone());
                    out.extend_from_slice(
                        format!("* {} FETCH (FLAGS ({}))\r\n", seq_num, flags_to_str(new_flags)).as_bytes()
                    );
                }
            }
            items.push(format!("{} {{{}}}\r\n{}", key, body.len(), body));
        }

        if let Some((field_list_token, fields)) = &header_fields {
            let header_end = rfc.find("\r\n\r\n").map(|p| p + 4).unwrap_or(rfc.len());
            let header = &rfc[..header_end];
            let filtered = filter_header_fields(header, fields);
            items.push(format!(
                "BODY[HEADER.FIELDS ({})] {{{}}}\r\n{}",
                field_list_token,
                filtered.len(),
                filtered
            ));
        }

        if wants_body_header {
            let header_end = rfc.find("\r\n\r\n").map(|p| p + 4).unwrap_or(rfc.len());
            let header = &rfc[..header_end];
            items.push(format!(
                "BODY[HEADER] {{{}}}\r\n{}",
                header.len(),
                header
            ));
        }

        if wants_body {
            if !body_is_peek {
                let current_flags = msg.flags as u32;
                if current_flags & 1 == 0 {
                    let new_flags = current_flags | 1;
                    let _ = db.update_message_flags(msg.imap_uid as i64, folder, new_flags as i64);
                    fetch_seen_pushes.push(msg.aster_id.clone());
                    out.extend_from_slice(
                        format!("* {} FETCH (FLAGS ({}))\r\n", seq_num, flags_to_str(new_flags)).as_bytes()
                    );
                }
            }
            if let Some((off, len_opt)) = parse_body_partial(&upper_parts) {
                let bytes = rfc.as_bytes();
                let start = off.min(bytes.len());
                let end = match len_opt {
                    Some(l) => start.saturating_add(l).min(bytes.len()),
                    None => bytes.len(),
                };
                let slice = String::from_utf8_lossy(&bytes[start..end]).into_owned();
                items.push(format!("BODY[]<{}> {{{}}}\r\n{}", off, slice.len(), slice));
            } else {
                items.push(format!("BODY[] {{{}}}\r\n{}", rfc.len(), rfc));
            }
        }

        if wants_rfc822_text {
            let body_start = rfc.find("\r\n\r\n").map(|p| p + 4).unwrap_or(rfc.len());
            let body = &rfc[body_start..];
            if !body_is_peek {
                let current_flags = msg.flags as u32;
                if current_flags & 1 == 0 {
                    let new_flags = current_flags | 1;
                    let _ = db.update_message_flags(msg.imap_uid as i64, folder, new_flags as i64);
                    fetch_seen_pushes.push(msg.aster_id.clone());
                    out.extend_from_slice(
                        format!("* {} FETCH (FLAGS ({}))\r\n", seq_num, flags_to_str(new_flags)).as_bytes()
                    );
                }
            }
            items.push(format!("RFC822.TEXT {{{}}}\r\n{}", body.len(), body));
        }

        out.extend_from_slice(format!("* {} FETCH ({})\r\n", seq_num, items.join(" ")).as_bytes());
        if out.len() >= 256 * 1024 {
            writer.write_all(&out).await?;
            out.clear();
        }
    }

    if !out.is_empty() {
        writer.write_all(&out).await?;
    }
    if !fetch_seen_pushes.is_empty() {
        let client = client.clone();
        let session = session.clone();
        tokio::spawn(async move {
            let token = session.read().await.access_token.to_string();
            for aster_id in fetch_seen_pushes {
                if let Err(e) = client.set_read_status(&token, &aster_id, true).await {
                    tracing::warn!("read-status sync failed for {}: {}", aster_id, e);
                }
            }
        });
    }
    write_ok(writer, tag, "FETCH completed").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use uuid::Uuid;

    type BackendCalls = Arc<tokio::sync::Mutex<Vec<(String, String)>>>;

    #[derive(Debug, Default, Clone, Copy)]
    struct MockOpts {
        fail: bool,
        job_conflict: bool,
        rate_limit_first_store: bool,
        bulk_metadata: bool,
        gateway_blip_job_create: bool,
        slow_metadata_ms: u64,
    }

    async fn spawn_mock_backend_full(opts: MockOpts) -> (String, BackendCalls) {
        let MockOpts {
            fail,
            job_conflict,
            rate_limit_first_store,
            bulk_metadata,
            gateway_blip_job_create,
            slow_metadata_ms,
        } = opts;
        let create_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let store_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        use axum::extract::Path as AxumPath;
        use axum::response::IntoResponse;
        use axum::{routing::delete, routing::get, routing::patch, routing::post, routing::put, Json, Router};
        let calls: BackendCalls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let c1 = calls.clone();
        let c2 = calls.clone();
        let c3 = calls.clone();
        let c4 = calls.clone();
        let c5 = calls.clone();
        let c6 = calls.clone();
        let c7 = calls.clone();
        let c_blip = calls.clone();
        let stored: Arc<tokio::sync::Mutex<Vec<serde_json::Value>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let stored_writer = stored.clone();
        let stored_reader = stored.clone();
        let hashes: Arc<tokio::sync::Mutex<std::collections::HashSet<String>>> =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
        let app = Router::new()
            .route(
                "/mail/v1/messages/:id",
                delete(move |AxumPath(id): AxumPath<String>| {
                    let calls = c1.clone();
                    async move {
                        calls.lock().await.push(("DELETE".to_string(), id));
                        if fail {
                            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                        } else {
                            Json(serde_json::json!({"success": true})).into_response()
                        }
                    }
                }),
            )
            .route(
                "/bridge/v1/messages/bulk/metadata",
                patch(move |Json(body): Json<serde_json::Value>| {
                    let calls = c7.clone();
                    async move {
                        if slow_metadata_ms > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(slow_metadata_ms)).await;
                        }
                        let count = body
                            .get("items")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        calls
                            .lock()
                            .await
                            .push(("BULK_PATCH".to_string(), count.to_string()));
                        if fail || !bulk_metadata {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        } else {
                            Json(serde_json::json!({"success": true, "updated_count": count}))
                                .into_response()
                        }
                    }
                }),
            )
            .route(
                "/bridge/v1/messages/:id/metadata",
                patch(move |AxumPath(id): AxumPath<String>| {
                    let calls = c2.clone();
                    async move {
                        if slow_metadata_ms > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(slow_metadata_ms)).await;
                        }
                        calls.lock().await.push(("PATCH".to_string(), id.clone()));
                        if id.starts_with("draft-") {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        } else {
                            Json(serde_json::json!({"success": true})).into_response()
                        }
                    }
                }),
            )
            .route(
                "/mail/v1/drafts",
                post(move |Json(body): Json<serde_json::Value>| {
                    let calls = c3.clone();
                    async move {
                        let nonce = body
                            .get("content_nonce")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        calls.lock().await.push(("POST_DRAFT".to_string(), nonce));
                        if fail {
                            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                        } else {
                            Json(serde_json::json!({"id": "draft-created-1", "version": 1, "success": true}))
                                .into_response()
                        }
                    }
                }),
            )
            .route(
                "/mail/v1/drafts/:id",
                delete(move |AxumPath(id): AxumPath<String>| {
                    let calls = c4.clone();
                    async move {
                        calls.lock().await.push(("DELETE_DRAFT".to_string(), id.clone()));
                        if fail {
                            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                        } else if id.starts_with("draft-") {
                            Json(serde_json::json!({"success": true, "deleted_count": 1}))
                                .into_response()
                        } else {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        }
                    }
                }),
            )
            .route(
                "/mail/v1/email_import/jobs",
                post(move || {
                    let calls = c_blip.clone();
                    let create_hits = create_hits.clone();
                    async move {
                    let hit = create_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if gateway_blip_job_create && hit == 0 {
                        calls
                            .lock()
                            .await
                            .push(("GATEWAY_BLIP".to_string(), String::new()));
                        return (axum::http::StatusCode::BAD_GATEWAY, "error code: 502")
                            .into_response();
                    }
                    if fail {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                    } else if job_conflict {
                        (
                            axum::http::StatusCode::CONFLICT,
                            Json(serde_json::json!({"error": "Invalid request", "code": "CONFLICT"})),
                        )
                            .into_response()
                    } else {
                        Json(serde_json::json!({"id": "job-1"})).into_response()
                    }
                }})
                .get(move || async move {
                    let jobs = if job_conflict {
                        serde_json::json!([
                            {"id": "job-old", "source": "gmail", "status": "completed"},
                            {"id": "job-adopted", "source": "eml", "status": "processing"}
                        ])
                    } else {
                        serde_json::json!([])
                    };
                    Json(serde_json::json!({"jobs": jobs})).into_response()
                }),
            )
            .route(
                "/mail/v1/email_import/jobs/:id",
                put(move || async move {
                    if fail {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                    } else {
                        Json(serde_json::json!({"success": true})).into_response()
                    }
                }),
            )
            .route(
                "/mail/v1/email_import/jobs/:id/emails",
                post(move |AxumPath(job_id): AxumPath<String>, Json(body): Json<serde_json::Value>| {
                    let calls = c5.clone();
                    let stored = stored_writer.clone();
                    let hashes = hashes.clone();
                    let store_hits = store_hits.clone();
                    async move {
                        let hit = store_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if rate_limit_first_store && hit == 0 {
                            calls
                                .lock()
                                .await
                                .push(("RATE_LIMITED".to_string(), job_id.clone()));
                            return (
                                axum::http::StatusCode::TOO_MANY_REQUESTS,
                                "rate limit exceeded",
                            )
                                .into_response();
                        }
                        calls
                            .lock()
                            .await
                            .push(("IMPORT_JOB_USED".to_string(), job_id));
                        let email = body
                            .get("emails")
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let hash = email
                            .get("message_id_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        calls
                            .lock()
                            .await
                            .push(("POST_IMPORT_EMAILS".to_string(), hash.clone()));
                        if fail {
                            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom")
                                .into_response();
                        }
                        let is_new = hashes.lock().await.insert(hash);
                        if !is_new {
                            return Json(serde_json::json!({
                                "stored_count": 0,
                                "duplicate_count": 1,
                                "skipped_quota_count": 0,
                                "quota_exceeded": false
                            }))
                            .into_response();
                        }
                        let mut guard = stored.lock().await;
                        let id = format!("imported-{}", guard.len() + 1);
                        guard.push(serde_json::json!({
                            "id": id,
                            "item_type": email.get("item_type").cloned().unwrap_or(serde_json::json!("received")),
                            "encrypted_envelope": email.get("encrypted_envelope").cloned().unwrap_or(serde_json::json!("")),
                            "envelope_nonce": email.get("envelope_nonce").cloned().unwrap_or(serde_json::json!("")),
                            "folder_token": "",
                            "is_external": true,
                            "created_at": email.get("received_at").cloned().unwrap_or(serde_json::json!("")),
                            "message_ts": email.get("received_at").cloned().unwrap_or(serde_json::json!("")),
                        }));
                        Json(serde_json::json!({
                            "stored_count": 1,
                            "duplicate_count": 0,
                            "skipped_quota_count": 0,
                            "quota_exceeded": false
                        }))
                        .into_response()
                    }
                }),
            )
            .route(
                "/bridge/v1/messages/sync",
                get(move || {
                    let stored = stored_reader.clone();
                    async move {
                        let items = stored.lock().await.clone();
                        Json(serde_json::json!({"items": items})).into_response()
                    }
                }),
            )
            .route(
                "/mail/v1/attachments/by-mail/:mail_id",
                post(move |AxumPath(mail_id): AxumPath<String>| {
                    let calls = c6.clone();
                    async move {
                        calls
                            .lock()
                            .await
                            .push(("POST_ATTACHMENT".to_string(), mail_id));
                        Json(serde_json::json!({"id": "att-1", "success": true})).into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{}", port), calls)
    }

    async fn start_test_server_with_backend(
        fail: bool,
    ) -> (
        std::net::SocketAddr,
        Arc<Database>,
        broadcast::Sender<StateChange>,
        BackendCalls,
        tempfile::TempDir,
    ) {
        start_test_server_with_backend_opts(fail, None).await
    }

    async fn start_test_server_with_backend_opts(
        fail: bool,
        identity_key: Option<&str>,
    ) -> (
        std::net::SocketAddr,
        Arc<Database>,
        broadcast::Sender<StateChange>,
        BackendCalls,
        tempfile::TempDir,
    ) {
        start_test_server_full(fail, identity_key, false).await
    }

    async fn start_test_server_full(
        fail: bool,
        identity_key: Option<&str>,
        job_conflict: bool,
    ) -> (
        std::net::SocketAddr,
        Arc<Database>,
        broadcast::Sender<StateChange>,
        BackendCalls,
        tempfile::TempDir,
    ) {
        start_test_server_mock(
            MockOpts {
                fail,
                job_conflict,
                ..Default::default()
            },
            identity_key,
        )
        .await
    }

    async fn start_test_server_mock(
        opts: MockOpts,
        identity_key: Option<&str>,
    ) -> (
        std::net::SocketAddr,
        Arc<Database>,
        broadcast::Sender<StateChange>,
        BackendCalls,
        tempfile::TempDir,
    ) {
        let (base, calls) = spawn_mock_backend_full(opts).await;
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
        let _ = db.seed_jmap_mailboxes();

        let passwords = Arc::new(AppPasswords::new(db.clone()));
        let _ = passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();

        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: identity_key.map(|s| s.to_string()),
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
        }));
        let client = Arc::new(ApiClient::new_with_base_url(&base));
        let (tx, _rx) = broadcast::channel(16);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let db_clone = db.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let _ = serve(listener, session, db_clone, client, passwords, tx_clone, None).await;
        });

        for _ in 0..80 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        (addr, db, tx, calls, dir)
    }

    async fn start_test_server() -> (
        std::net::SocketAddr,
        Arc<Database>,
        broadcast::Sender<StateChange>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
        let _ = db.seed_jmap_mailboxes();

        let passwords = Arc::new(AppPasswords::new(db.clone()));
        let _ = passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();

        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
        }));
        let client = Arc::new(ApiClient::new());
        let (tx, _rx) = broadcast::channel(16);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let db_clone = db.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let _ = serve(listener, session, db_clone, client, passwords, tx_clone, None).await;
        });

        for _ in 0..80 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        (addr, db, tx, dir)
    }

    async fn read_until_tag(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        tag: &str,
    ) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await.unwrap();
            if n == 0 {
                break;
            }
            let t = line.trim_end_matches(|c| c == '\r' || c == '\n').to_string();
            let is_tag_line = t.starts_with(&format!("{} ", tag));
            out.push(t);
            if is_tag_line {
                break;
            }
        }
        out
    }

    fn seed(db: &Database, id: &str, folder: &str, subject: &str) {
        db.upsert_cached_message(
            id,
            folder,
            Some(subject),
            Some("alice@example.com"),
            Some("tester@aster.test"),
            Some("Wed, 21 May 2026 10:00:00 +0000"),
            64,
            Some("hello body"),
            Some(
                &serde_json::json!({"is_html": false, "message_id": format!("{}@test", id)})
                    .to_string(),
            ),
        )
        .unwrap();
        let _ = db.assign_uid_if_missing(folder, id);
    }

    #[test]
    fn gmail_msgid_is_stable_and_nonzero() {
        let a = gmail_msgid_from_aster("abc-123");
        let b = gmail_msgid_from_aster("abc-123");
        let c = gmail_msgid_from_aster("def-456");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, 0);
    }

    #[test]
    fn quote_label_system_atom_passthrough() {
        assert_eq!(quote_or_atom_label("\\Inbox"), "\\Inbox");
        assert_eq!(quote_or_atom_label("\\Important"), "\\Important");
    }

    #[test]
    fn quote_label_custom_simple() {
        assert_eq!(quote_or_atom_label("Work"), "Work");
        assert_eq!(quote_or_atom_label("project-x"), "project-x");
    }

    #[test]
    fn quote_label_custom_quoted() {
        let q = quote_or_atom_label("hello world");
        assert!(q.starts_with('"') && q.ends_with('"'));
    }

    #[test]
    fn utf7_ascii_unchanged() {
        assert_eq!(utf7_encode_modified("hello"), "hello");
    }

    #[test]
    fn utf7_non_ascii_encoded() {
        let s = utf7_encode_modified("\u{00e9}");
        assert!(s.starts_with('&') && s.ends_with('-'));
    }

    #[test]
    fn parse_message_date_ymd_valid() {
        assert_eq!(parse_message_date_ymd("2026-06-13T10:00:00Z"), Some((2026, 6, 13)));
    }

    #[test]
    fn parse_message_date_ymd_multibyte_does_not_panic() {
        assert_eq!(parse_message_date_ymd("\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}xx"), None);
        assert_eq!(parse_message_date_ymd("\u{1f600}-06-13"), None);
        assert_eq!(parse_message_date_ymd("short"), None);
        assert_eq!(parse_message_date_ymd(""), None);
    }

    #[tokio::test]
    async fn capability_advertises_idle_and_gmail() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut writer = w;

        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.contains("Aster Bridge"));
        assert!(greeting.contains(env!("CARGO_PKG_VERSION")), "the greeting must name the running build so a stale copy is obvious: {}", greeting);
        assert!(greeting.contains("ready"));

        writer.write_all(b"a1 CAPABILITY\r\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut cap_line = String::new();
        reader.read_line(&mut cap_line).await.unwrap();
        let mut ok_line = String::new();
        reader.read_line(&mut ok_line).await.unwrap();
        assert!(cap_line.contains("IDLE"), "cap missing IDLE: {}", cap_line);
        assert!(
            cap_line.contains("X-GM-EXT-1"),
            "cap missing X-GM-EXT-1: {}",
            cap_line
        );
        assert!(ok_line.starts_with("a1 OK"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_slow_move_never_leaves_the_client_without_a_response() {
        let (addr, db, _tx, _calls, _dir) = start_test_server_mock(
            MockOpts {
                slow_metadata_ms: 900,
                ..Default::default()
            },
            None,
        )
        .await;
        seed(&db, "msg-move-1", "inbox", "moving");

        let (mut reader, mut writer) = login_and_select(addr).await;
        writer
            .write_all(b"a3 UID MOVE 1 Archive\r\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();

        let mut heartbeats = 0usize;
        let mut widest_gap = Duration::from_millis(0);
        let mut last = tokio::time::Instant::now();
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
                .await
                .expect("the connection went silent for 20 seconds during a slow MOVE")
                .unwrap();
            assert!(read > 0, "the server closed the connection during MOVE");
            let now = tokio::time::Instant::now();
            let gap = now.duration_since(last);
            if gap > widest_gap {
                widest_gap = gap;
            }
            last = now;
            if line.starts_with("* OK still working") {
                heartbeats += 1;
                continue;
            }
            if line.starts_with("a3 ") {
                assert!(line.contains("OK"), "MOVE failed: {}", line);
                break;
            }
        }

        assert!(
            heartbeats > 0,
            "a MOVE that took most of a second produced no keepalive at all"
        );
        assert!(
            widest_gap < Duration::from_secs(5),
            "the client waited {:?} with no bytes, which is how a mail client decides the server stopped answering",
            widest_gap
        );
    }

    #[tokio::test]
    async fn a_quiet_connection_between_commands_is_not_flooded_with_keepalives() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let (mut reader, mut _writer) = login_and_select(addr).await;

        tokio::time::sleep(Duration::from_millis(700)).await;

        let idle = tokio::time::timeout(Duration::from_millis(300), async {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            line
        })
        .await;
        assert!(
            idle.is_err(),
            "an idle connection sent unsolicited traffic: {:?}",
            idle
        );
    }

    async fn login_and_select(
        addr: std::net::SocketAddr,
    ) -> (
        BufReader<tokio::net::tcp::OwnedReadHalf>,
        tokio::net::tcp::OwnedWriteHalf,
    ) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut writer = w;

        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();

        writer
            .write_all(b"a1 LOGIN \"tester@aster.test\" \"abcd-efgh-ijkl-mnop\"\r\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let _ = read_until_tag(&mut reader, "a1").await;

        writer.write_all(b"a2 SELECT INBOX\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let _ = read_until_tag(&mut reader, "a2").await;

        (reader, writer)
    }

    #[tokio::test]
    async fn idle_receives_exists_on_state_change() {
        let (addr, db, tx, _dir) = start_test_server().await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        writer.write_all(b"a3 IDLE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut plus = String::new();
        reader.read_line(&mut plus).await.unwrap();
        assert!(plus.starts_with("+ "), "expected continuation, got {}", plus);

        seed(&db, "msg-001", "inbox", "hello");

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut changed = HashMap::new();
        changed.insert("Email".to_string(), "1".to_string());
        let _ = tx.send(StateChange { changed });

        let read_fut = async {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            line
        };
        let line = tokio::time::timeout(Duration::from_secs(10), read_fut)
            .await
            .expect("EXISTS not delivered");
        assert!(line.contains("EXISTS"), "expected * N EXISTS, got: {}", line);

        writer.write_all(b"DONE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut term = String::new();
        reader.read_line(&mut term).await.unwrap();
        assert!(term.starts_with("a3 OK"), "expected tagged OK, got: {}", term);
    }

    #[tokio::test]
    async fn idle_done_terminates_cleanly() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        writer.write_all(b"a3 IDLE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut plus = String::new();
        reader.read_line(&mut plus).await.unwrap();
        assert!(plus.starts_with("+ "));

        writer.write_all(b"DONE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut term = String::new();
        reader.read_line(&mut term).await.unwrap();
        assert!(term.starts_with("a3 OK"), "got: {}", term);
    }

    #[tokio::test]
    async fn fetch_gmail_extensions_present() {
        let (addr, db, _tx, _dir) = start_test_server().await;
        seed(&db, "msg-fetch-1", "inbox", "subject one");
        let (mut reader, mut writer) = login_and_select(addr).await;

        writer
            .write_all(b"a3 FETCH 1 (X-GM-LABELS X-GM-THRID X-GM-MSGID UID)\r\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();

        let lines = read_until_tag(&mut reader, "a3").await;
        let combined = lines.join("\n");
        assert!(
            combined.contains("X-GM-LABELS"),
            "missing labels: {}",
            combined
        );
        assert!(
            combined.contains("\\Inbox"),
            "missing system label: {}",
            combined
        );
        assert!(
            combined.contains("X-GM-THRID "),
            "missing thrid: {}",
            combined
        );
        assert!(
            combined.contains("X-GM-MSGID "),
            "missing msgid: {}",
            combined
        );
        assert!(combined.contains("a3 OK"));
    }

    #[test]
    fn find_appended_sent_copy_matches_by_message_id() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        seed(&db, "sent-1", "sent", "totally different subject");
        let raw = b"Message-ID: <sent-1@test>\r\nSubject: whatever\r\n\r\nbody";
        let uid = find_appended_sent_copy(&db, raw);
        assert!(uid.is_some());
    }

    #[test]
    fn find_appended_sent_copy_falls_back_to_subject() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        seed(&db, "sent-2", "sent", "quarterly report");
        let raw = b"Message-ID: <unknown@apple-mail>\r\nSubject: quarterly report\r\n\r\nbody";
        let uid = find_appended_sent_copy(&db, raw);
        assert!(uid.is_some());
    }

    #[test]
    fn find_appended_sent_copy_none_when_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        seed(&db, "sent-3", "sent", "subject a");
        let raw = b"Message-ID: <unknown@apple-mail>\r\nSubject: subject b\r\n\r\nbody";
        assert!(find_appended_sent_copy(&db, raw).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_emits_untagged_ok_while_a_slow_append_runs() {
        let mut out: Vec<u8> = Vec::new();
        let result = run_with_keepalive(&mut out, async {
            tokio::time::sleep(std::time::Duration::from_secs(65)).await;
            42u32
        })
        .await;
        assert_eq!(result, Some(42));
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text.matches("* OK APPEND in progress\r\n").count(),
            3,
            "expected a keepalive every {}s across 65s, got: {:?}",
            APPEND_KEEPALIVE_SECS,
            text
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_stays_silent_for_a_fast_append() {
        let mut out: Vec<u8> = Vec::new();
        let result = run_with_keepalive(&mut out, async { "done" }).await;
        assert_eq!(result, Some("done"));
        assert!(out.is_empty());
    }

    struct DeadWriter;

    impl tokio::io::AsyncWrite for DeadWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_write_failure_still_finishes_the_append() {
        let mut out = DeadWriter;
        let result = run_with_keepalive(&mut out, async {
            tokio::time::sleep(std::time::Duration::from_secs(90)).await;
            "stored"
        })
        .await;
        assert_eq!(result, Some("stored"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn keepalive_keeps_writing_while_the_append_blocks_its_thread() {
        let mut out: Vec<u8> = Vec::new();
        let result = run_with_keepalive_every(
            &mut out,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(60),
            async {
                std::thread::sleep(std::time::Duration::from_millis(400));
                7u32
            },
        )
        .await;
        assert_eq!(result, Some(7));
        let text = String::from_utf8(out).unwrap();
        let beats = text.matches("* OK APPEND in progress\r\n").count();
        assert!(
            beats >= 3,
            "a blocking append must not silence the keepalive, got {} beats: {:?}",
            beats,
            text
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_gives_up_on_an_append_that_never_finishes() {
        let mut out: Vec<u8> = Vec::new();
        let result = run_with_keepalive_every(
            &mut out,
            std::time::Duration::from_secs(20),
            std::time::Duration::from_secs(130),
            async {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                "never"
            },
        )
        .await;
        assert_eq!(result, None);
        let beats = String::from_utf8(out)
            .unwrap()
            .matches("* OK APPEND in progress\r\n")
            .count();
        assert_eq!(beats, 6, "expected keepalives right up to the deadline");
    }

    async fn append_literal(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        tag: &str,
        mailbox: &str,
        literal: &[u8],
    ) -> String {
        writer
            .write_all(format!("{} APPEND {} {{{}}}\r\n", tag, mailbox, literal.len()).as_bytes())
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let mut cont = String::new();
        reader.read_line(&mut cont).await.unwrap();
        assert!(cont.starts_with("+ "), "expected continuation, got {}", cont);
        writer.write_all(literal).await.unwrap();
        writer.write_all(b"\r\n").await.unwrap();
        writer.flush().await.unwrap();
        read_until_tag(reader, tag).await.join("\n")
    }

    #[tokio::test]
    async fn append_to_sent_dedupes_against_server_copy() {
        let (addr, db, _tx, _dir) = start_test_server().await;
        seed(&db, "sent-e2e", "sent", "hello from apple mail");
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Message-ID: <sent-e2e@test>\r\nSubject: hello from apple mail\r\n\r\nbody";
        let resp = append_literal(&mut reader, &mut writer, "ap1", "Sent", raw).await;
        assert!(resp.contains("ap1 OK"), "append not accepted: {}", resp);
        assert!(resp.contains("APPENDUID"), "missing APPENDUID: {}", resp);
    }

    #[tokio::test]
    async fn append_to_sent_after_smtp_send_does_not_duplicate() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Message-ID: <fresh@apple-mail>\r\nSubject: brand new\r\n\r\nbody";
        crate::imap::append::note_outgoing_message(raw);
        let resp = append_literal(&mut reader, &mut writer, "ap2", "Sent", raw).await;
        assert!(resp.contains("ap2 OK"), "append not accepted: {}", resp);
        assert!(
            !resp.contains("APPENDUID"),
            "a bridge-sent copy must not be stored again: {}",
            resp
        );
    }

    #[tokio::test]
    async fn append_to_inbox_is_accepted_and_stored() {
        let (addr, db, _tx, _calls, _dir) =
            start_test_server_with_backend_opts(false, Some("test-ik")).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Message-ID: <migrated-1@old.example>\r\nFrom: alice@old.example\r\nTo: tester@aster.test\r\nSubject: migrated mail\r\nDate: Fri, 12 Jul 2024 13:04:05 +0000\r\n\r\nold body";
        let resp = append_literal(&mut reader, &mut writer, "ap3", "INBOX", raw).await;
        assert!(resp.contains("ap3 OK"), "append rejected: {}", resp);
        assert!(resp.contains("APPENDUID"), "missing APPENDUID: {}", resp);

        let cached = db.get_cached_message("imported-1").unwrap().unwrap();
        assert_eq!(cached.folder, "inbox");
        assert_eq!(cached.subject.as_deref(), Some("migrated mail"));
        assert!(cached.imap_uid > 0);
        assert!(
            cached.date.as_deref().unwrap_or("").starts_with("2024-07-12"),
            "original date not preserved: {:?}",
            cached.date
        );
    }

    #[tokio::test]
    async fn append_to_archive_and_junk_are_accepted() {
        let (addr, _db, _tx, _calls, _dir) =
            start_test_server_with_backend_opts(false, Some("test-ik")).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        for (tag, mailbox, subject) in [
            ("aa1", "Archive", "archived mail"),
            ("aa2", "Junk", "junk mail"),
            ("aa3", "Trash", "trashed mail"),
        ] {
            let raw = format!(
                "Message-ID: <{}@old.example>\r\nFrom: alice@old.example\r\nSubject: {}\r\nDate: Fri, 12 Jul 2024 13:04:05 +0000\r\n\r\nbody",
                tag, subject
            );
            let resp =
                append_literal(&mut reader, &mut writer, tag, mailbox, raw.as_bytes()).await;
            assert!(resp.contains(&format!("{} OK", tag)), "{} rejected: {}", mailbox, resp);
            assert!(resp.contains("APPENDUID"), "{} missing APPENDUID: {}", mailbox, resp);
        }
    }

    #[tokio::test]
    async fn append_waits_out_a_rate_limit_instead_of_losing_the_message() {
        let (addr, db, _tx, calls, _dir) = start_test_server_mock(
            MockOpts {
                rate_limit_first_store: true,
                ..Default::default()
            },
            Some("test-ik"),
        )
        .await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Message-ID: <throttled-1@old.example>\r\nFrom: alice@old.example\r\nSubject: throttled\r\nDate: Fri, 12 Jul 2024 13:04:05 +0000\r\n\r\nbody";
        let resp = append_literal(&mut reader, &mut writer, "rl1", "INBOX", raw).await;
        assert!(resp.contains("rl1 OK"), "throttled append lost: {}", resp);
        assert!(resp.contains("APPENDUID"), "missing APPENDUID: {}", resp);

        let log = calls.lock().await.clone();
        assert!(
            log.iter().any(|(m, _)| m == "RATE_LIMITED"),
            "the mock never rate limited: {:?}",
            log
        );
        assert_eq!(
            log.iter().filter(|(m, _)| m == "POST_IMPORT_EMAILS").count(),
            1,
            "expected exactly one successful store after the retry: {:?}",
            log
        );
        assert!(db.get_cached_message("imported-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn append_rides_out_a_gateway_blip_when_creating_the_import_job() {
        let (addr, db, _tx, calls, _dir) = start_test_server_mock(
            MockOpts {
                gateway_blip_job_create: true,
                ..Default::default()
            },
            Some("test-ik"),
        )
        .await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Message-ID: <blipped-1@old.example>\r\nFrom: alice@old.example\r\nSubject: blipped\r\nDate: Fri, 12 Jul 2024 13:04:05 +0000\r\n\r\nbody";
        let resp = append_literal(&mut reader, &mut writer, "gb1", "INBOX", raw).await;
        assert!(resp.contains("gb1 OK"), "append lost to the blip: {}", resp);
        assert!(resp.contains("APPENDUID"), "missing APPENDUID: {}", resp);

        let log = calls.lock().await.clone();
        assert!(
            log.iter().any(|(m, _)| m == "GATEWAY_BLIP"),
            "the mock never returned 502: {:?}",
            log
        );
        assert_eq!(
            log.iter().filter(|(m, _)| m == "POST_IMPORT_EMAILS").count(),
            1,
            "expected exactly one store after the retry: {:?}",
            log
        );
        assert!(db.get_cached_message("imported-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn append_adopts_an_existing_job_when_the_server_caps_new_ones() {
        let (addr, db, _tx, calls, _dir) =
            start_test_server_full(false, Some("test-ik"), true).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Message-ID: <capped-1@old.example>\r\nFrom: alice@old.example\r\nSubject: capped\r\nDate: Fri, 12 Jul 2024 13:04:05 +0000\r\n\r\nbody";
        let resp = append_literal(&mut reader, &mut writer, "cj1", "INBOX", raw).await;
        assert!(resp.contains("cj1 OK"), "append rejected: {}", resp);
        assert!(resp.contains("APPENDUID"), "missing APPENDUID: {}", resp);

        let used: Vec<String> = calls
            .lock()
            .await
            .iter()
            .filter(|(m, _)| m == "IMPORT_JOB_USED")
            .map(|(_, id)| id.clone())
            .collect();
        assert_eq!(used, vec!["job-adopted".to_string()]);
        assert!(db.get_cached_message("imported-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn append_duplicate_is_accepted_without_a_second_store() {
        let (addr, _db, _tx, calls, _dir) =
            start_test_server_with_backend_opts(false, Some("test-ik")).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Message-ID: <dupe-1@old.example>\r\nFrom: alice@old.example\r\nSubject: dupe\r\nDate: Fri, 12 Jul 2024 13:04:05 +0000\r\n\r\nbody";
        let first = append_literal(&mut reader, &mut writer, "dp1", "INBOX", raw).await;
        assert!(first.contains("dp1 OK"), "first append failed: {}", first);

        let second = append_literal(&mut reader, &mut writer, "dp2", "INBOX", raw).await;
        assert!(second.contains("dp2 OK"), "retry must not fail: {}", second);

        let stores = calls
            .lock()
            .await
            .iter()
            .filter(|(m, _)| m == "POST_IMPORT_EMAILS")
            .count();
        assert_eq!(stores, 2, "both appends should reach the import endpoint");
    }

    #[tokio::test]
    async fn append_without_identity_key_fails_cleanly() {
        let (addr, _db, _tx, _calls, _dir) = start_test_server_with_backend(false).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Subject: no key\r\n\r\nbody";
        let resp = append_literal(&mut reader, &mut writer, "nk1", "INBOX", raw).await;
        assert!(resp.contains("nk1 NO"), "expected NO: {}", resp);
    }

    #[tokio::test]
    async fn append_to_drafts_creates_server_draft_and_returns_appenduid() {
        let (addr, db, _tx, calls, _dir) =
            start_test_server_with_backend_opts(false, Some("test-ik")).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"To: bruno@example.com\r\nCc: copy@example.com\r\nSubject: bozza di prova\r\nContent-Type: text/plain\r\n\r\nciao";
        let resp = append_literal(&mut reader, &mut writer, "ad1", "Drafts", raw).await;
        assert!(resp.contains("ad1 OK"), "append not accepted: {}", resp);
        assert!(resp.contains("APPENDUID"), "missing APPENDUID: {}", resp);

        let cached = db.get_cached_message("draft-created-1").unwrap().unwrap();
        assert_eq!(cached.folder, "drafts");
        assert_eq!(cached.subject.as_deref(), Some("bozza di prova"));
        assert!(cached.flags & 16 != 0, "draft flag missing: {}", cached.flags);
        assert!(cached.imap_uid > 0);

        let captured = calls.lock().await.clone();
        let nonce = captured
            .iter()
            .find(|(m, _)| m == "POST_DRAFT")
            .map(|(_, n)| n.clone())
            .expect("draft not created on server");
        assert!(!nonce.is_empty());
    }

    #[tokio::test]
    async fn append_to_drafts_round_trips_web_compatible_encryption() {
        let (addr, db, _tx, calls, _dir) =
            start_test_server_with_backend_opts(false, Some("test-ik")).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"To: a@x.com\r\nSubject: verify crypto\r\n\r\nplain body";
        let resp = append_literal(&mut reader, &mut writer, "ad2", "Drafts", raw).await;
        assert!(resp.contains("ad2 OK"), "append not accepted: {}", resp);

        let cached = db.get_cached_message("draft-created-1").unwrap().unwrap();
        assert_eq!(cached.recipients.as_deref(), Some("a@x.com"));
        assert!(cached.body_text.unwrap_or_default().contains("plain body"));
        assert!(!calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn append_to_drafts_without_identity_key_fails_cleanly() {
        let (addr, _db, _tx, _calls, _dir) = start_test_server_with_backend(false).await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Subject: no key\r\n\r\nbody";
        let resp = append_literal(&mut reader, &mut writer, "ad3", "Drafts", raw).await;
        assert!(resp.contains("ad3 NO"), "expected NO: {}", resp);
    }

    #[tokio::test]
    async fn expunge_in_drafts_deletes_via_drafts_api() {
        let (addr, db, _tx, calls, _dir) =
            start_test_server_with_backend_opts(false, Some("test-ik")).await;
        seed(&db, "draft-ex1", "drafts", "old draft");
        let (mut reader, mut writer) = login_and_select(addr).await;

        let resp = imap_cmd_lines(&mut reader, &mut writer, "d1", "SELECT Drafts").await;
        assert!(resp.contains("d1 OK"));
        imap_cmd_lines(&mut reader, &mut writer, "d2", "STORE 1 +FLAGS (\\Deleted)").await;
        let resp = imap_cmd_lines(&mut reader, &mut writer, "d3", "EXPUNGE").await;
        assert!(resp.contains("* 1 EXPUNGE"), "missing expunge: {}", resp);

        assert!(db.get_cached_message("draft-ex1").unwrap().is_none());
        let captured = calls.lock().await.clone();
        assert!(
            captured
                .iter()
                .any(|(m, id)| m == "DELETE_DRAFT" && id == "draft-ex1"),
            "draft api delete missing: {:?}",
            captured
        );
        assert!(
            !captured.iter().any(|(m, _)| m == "DELETE"),
            "must not fall through to message delete: {:?}",
            captured
        );
    }

    #[tokio::test]
    async fn move_draft_to_trash_deletes_draft_on_server() {
        let (addr, db, _tx, calls, _dir) =
            start_test_server_with_backend_opts(false, Some("test-ik")).await;
        seed(&db, "draft-mv1", "drafts", "moving draft");
        let (mut reader, mut writer) = login_and_select(addr).await;

        let resp = imap_cmd_lines(&mut reader, &mut writer, "m1", "SELECT Drafts").await;
        assert!(resp.contains("m1 OK"));
        let resp = imap_cmd_lines(&mut reader, &mut writer, "m2", "MOVE 1 Trash").await;
        assert!(resp.contains("m2 OK"), "move failed: {}", resp);

        let captured = calls.lock().await.clone();
        assert!(
            captured
                .iter()
                .any(|(m, id)| m == "DELETE_DRAFT" && id == "draft-mv1"),
            "draft delete missing on move: {:?}",
            captured
        );
    }

    #[tokio::test]
    async fn move_many_messages_uses_chunked_bulk_requests() {
        let (addr, db, _tx, calls, _dir) = start_test_server_mock(
            MockOpts {
                bulk_metadata: true,
                ..Default::default()
            },
            Some("test-ik"),
        )
        .await;
        for n in 1..=250 {
            seed(&db, &format!("bulk-{}", n), "inbox", &format!("m{}", n));
        }
        let (mut reader, mut writer) = login_and_select(addr).await;

        let resp = imap_cmd_lines(&mut reader, &mut writer, "b1", "MOVE 1:250 Archive").await;
        assert!(resp.contains("b1 OK"), "bulk move rejected: {}", resp);

        let captured = calls.lock().await.clone();
        let chunks: Vec<usize> = captured
            .iter()
            .filter(|(m, _)| m == "BULK_PATCH")
            .map(|(_, n)| n.parse::<usize>().unwrap())
            .collect();
        assert_eq!(chunks, vec![100, 100, 50], "unexpected chunking: {:?}", chunks);
        assert!(
            !captured.iter().any(|(m, _)| m == "PATCH"),
            "fell back to per-message updates: {:?}",
            captured
        );
        assert_eq!(db.list_cached_messages("inbox").unwrap().len(), 0);
        assert_eq!(db.list_cached_messages("archive").unwrap().len(), 250);
    }

    #[tokio::test]
    async fn create_accepts_an_existing_folder_and_refuses_new_ones() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let resp = imap_cmd_lines(&mut reader, &mut writer, "c1", "CREATE \"Archive\"").await;
        assert!(resp.contains("c1 OK"), "existing folder refused: {}", resp);
        let resp = imap_cmd_lines(&mut reader, &mut writer, "c2", "CREATE INBOX").await;
        assert!(resp.contains("c2 OK"), "inbox refused: {}", resp);
        let resp = imap_cmd_lines(&mut reader, &mut writer, "c3", "CREATE \"Old Mail\"").await;
        assert!(resp.contains("c3 NO"), "expected NO: {}", resp);
        assert!(resp.contains("CANNOT"), "expected CANNOT: {}", resp);
    }

    #[tokio::test]
    async fn append_too_big_keeps_the_connection_usable() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let oversized = MAX_APPEND_BYTES + 1;
        let resp = imap_cmd_lines(
            &mut reader,
            &mut writer,
            "t1",
            &format!("APPEND \"INBOX\" {{{}}}", oversized),
        )
        .await;
        assert!(resp.contains("t1 NO"), "expected NO: {}", resp);
        assert!(resp.contains("TOOBIG"), "expected TOOBIG: {}", resp);

        let resp = imap_cmd_lines(&mut reader, &mut writer, "t2", "NOOP").await;
        assert!(resp.contains("t2 OK"), "connection unusable after TOOBIG: {}", resp);
    }

    #[tokio::test]
    async fn append_too_big_non_sync_literal_is_drained() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let oversized = MAX_APPEND_BYTES + 1;
        writer
            .write_all(format!("t1 APPEND \"INBOX\" {{{}+}}\r\n", oversized).as_bytes())
            .await
            .unwrap();
        let chunk = vec![b'x'; 1024 * 1024];
        let mut written = 0usize;
        while written < oversized {
            let take = (oversized - written).min(chunk.len());
            writer.write_all(&chunk[..take]).await.unwrap();
            written += take;
        }
        writer.write_all(b"\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let resp = read_until_tag(&mut reader, "t1").await.join("\n");
        assert!(resp.contains("t1 NO"), "expected NO: {}", resp);
        assert!(resp.contains("TOOBIG"), "expected TOOBIG: {}", resp);

        let resp = imap_cmd_lines(&mut reader, &mut writer, "t2", "NOOP").await;
        assert!(
            resp.contains("t2 OK"),
            "oversized literal was not drained, the session desynchronized: {}",
            resp
        );
        assert!(
            !resp.contains("BAD"),
            "literal bytes were parsed as commands: {}",
            resp
        );
    }

    #[tokio::test]
    async fn append_to_unknown_mailbox_gets_trycreate() {
        let (addr, _db, _tx, _dir) = start_test_server().await;
        let (mut reader, mut writer) = login_and_select(addr).await;

        let raw = b"Subject: x\r\n\r\nbody";
        let resp = append_literal(&mut reader, &mut writer, "ap4", "Nonexistent", raw).await;
        assert!(resp.contains("ap4 NO"), "expected NO: {}", resp);
        assert!(resp.contains("TRYCREATE"), "expected TRYCREATE: {}", resp);
    }

    async fn imap_cmd_lines(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        tag: &str,
        cmd: &str,
    ) -> String {
        writer
            .write_all(format!("{} {}\r\n", tag, cmd).as_bytes())
            .await
            .unwrap();
        writer.flush().await.unwrap();
        read_until_tag(reader, tag).await.join("\n")
    }

    #[test]
    fn tokenize_search_handles_quoted_phrases() {
        assert_eq!(
            tokenize_search_criteria("SUBJECT \"hello world\" UNSEEN"),
            vec!["SUBJECT", "hello world", "UNSEEN"]
        );
        assert_eq!(
            tokenize_search_criteria("FROM \"Alice B\" TO bob@x.com"),
            vec!["FROM", "Alice B", "TO", "bob@x.com"]
        );
        assert_eq!(tokenize_search_criteria("ALL"), vec!["ALL"]);
    }

    #[test]
    fn search_matches_quoted_multiword_subject() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        seed(&db, "sq-1", "inbox", "project alpha status");
        let msgs = db.list_cached_messages("inbox").unwrap();
        let m = &msgs[0];
        assert!(search_matches(m, "SUBJECT \"ALPHA STATUS\""));
        assert!(!search_matches(m, "SUBJECT \"ALPHA OMEGA\""));
        assert!(search_matches(m, "FROM \"ALICE@EXAMPLE.COM\" SUBJECT \"PROJECT ALPHA\""));
    }

    #[test]
    fn search_header_message_id_matches_only_that_message() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        seed(&db, "hdr-1", "inbox", "first");
        seed(&db, "hdr-2", "inbox", "second");
        let msgs = db.list_cached_messages("inbox").unwrap();
        let one = msgs.iter().find(|m| m.aster_id == "hdr-1").unwrap();
        let two = msgs.iter().find(|m| m.aster_id == "hdr-2").unwrap();

        assert!(search_matches(one, "HEADER MESSAGE-ID \"HDR-1@TEST\""));
        assert!(!search_matches(two, "HEADER MESSAGE-ID \"HDR-1@TEST\""));
        assert!(!search_matches(one, "HEADER MESSAGE-ID \"NOT-PRESENT@TEST\""));
        assert!(!search_matches(one, "HEADER X-CUSTOM-THING \"ANYTHING\""));
        assert!(!search_matches(one, "CC \"SOMEONE@EXAMPLE.COM\""));
        assert!(search_matches(one, "HEADER SUBJECT \"FIRST\""));
    }

    #[test]
    fn search_unknown_criterion_matches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        seed(&db, "unk-1", "inbox", "one");
        let msgs = db.list_cached_messages("inbox").unwrap();
        let m = &msgs[0];
        assert!(!search_matches(m, "OLDER 3600"));
        assert!(!search_matches(m, "X-SOMETHING-ELSE"));
        assert!(!search_matches(m, "RECENT"));
        assert!(search_matches(m, "OLD"));
        assert!(search_matches(m, "ALL"));
    }

    #[test]
    fn search_keyword_does_not_match_everything() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        seed(&db, "kw-1", "inbox", "one");
        let msgs = db.list_cached_messages("inbox").unwrap();
        let m = &msgs[0];
        assert!(!search_matches(m, "KEYWORD $LABEL1"));
        assert!(search_matches(m, "UNKEYWORD $LABEL1"));
    }

    #[test]
    fn existing_mailbox_resolves_display_names() {
        assert_eq!(existing_mailbox("INBOX"), Some("inbox"));
        assert_eq!(existing_mailbox("\"Archive\""), Some("archive"));
        assert_eq!(existing_mailbox("junk"), Some("spam"));
        assert_eq!(existing_mailbox("Archive/"), Some("archive"));
        assert_eq!(existing_mailbox("Old Mail"), None);
    }

    #[test]
    fn parse_message_date_ymd_accepts_rfc2822() {
        assert_eq!(
            parse_message_date_ymd("Wed, 21 May 2026 10:00:00 +0000"),
            Some((2026, 5, 21))
        );
        assert_eq!(parse_message_date_ymd("2026-05-21T10:00:00Z"), Some((2026, 5, 21)));
        assert_eq!(parse_message_date_ymd("garbage"), None);
    }

    #[test]
    fn iso_to_imap_date_accepts_rfc2822() {
        let s = iso_to_imap_date("Wed, 21 May 2026 10:30:00 +0000");
        assert!(s.starts_with("21-May-2026"), "got {}", s);
        assert!(!iso_to_imap_date("2026-05-21T10:30:00Z").contains("1970"));
    }

    #[tokio::test]
    async fn expunge_deletes_on_server_and_locally() {
        let (addr, db, _tx, calls, _dir) = start_test_server_with_backend(false).await;
        seed(&db, "ex-1", "inbox", "one");
        seed(&db, "ex-2", "inbox", "two");
        let (mut reader, mut writer) = login_and_select(addr).await;

        let resp = imap_cmd_lines(&mut reader, &mut writer, "e1", "STORE 1 +FLAGS (\\Deleted)").await;
        assert!(resp.contains("e1 OK"));
        let resp = imap_cmd_lines(&mut reader, &mut writer, "e2", "EXPUNGE").await;
        assert!(resp.contains("* 1 EXPUNGE"), "missing expunge: {}", resp);
        assert!(resp.contains("e2 OK"));

        assert!(db.get_cached_message("ex-1").unwrap().is_none());
        assert!(db.get_cached_message("ex-2").unwrap().is_some());
        let captured = calls.lock().await.clone();
        assert!(
            captured.iter().any(|(m, id)| m == "DELETE" && id == "ex-1"),
            "server delete missing: {:?}",
            captured
        );
    }

    #[tokio::test]
    async fn expunge_backend_failure_keeps_message() {
        let (addr, db, _tx, _calls, _dir) = start_test_server_with_backend(true).await;
        seed(&db, "ex-keep", "inbox", "one");
        let (mut reader, mut writer) = login_and_select(addr).await;

        imap_cmd_lines(&mut reader, &mut writer, "e1", "STORE 1 +FLAGS (\\Deleted)").await;
        let resp = imap_cmd_lines(&mut reader, &mut writer, "e2", "EXPUNGE").await;
        assert!(!resp.contains("* 1 EXPUNGE"), "must not expunge on server failure: {}", resp);
        assert!(db.get_cached_message("ex-keep").unwrap().is_some());
    }

    #[tokio::test]
    async fn uid_expunge_honors_uid_set() {
        let (addr, db, _tx, calls, _dir) = start_test_server_with_backend(false).await;
        seed(&db, "ux-1", "inbox", "one");
        seed(&db, "ux-2", "inbox", "two");
        let (mut reader, mut writer) = login_and_select(addr).await;

        imap_cmd_lines(&mut reader, &mut writer, "u1", "STORE 1:2 +FLAGS (\\Deleted)").await;
        let uid2 = db.get_cached_message("ux-2").unwrap().unwrap().imap_uid;
        let resp =
            imap_cmd_lines(&mut reader, &mut writer, "u2", &format!("UID EXPUNGE {}", uid2)).await;
        assert!(resp.contains("u2 OK"));

        assert!(
            db.get_cached_message("ux-1").unwrap().is_some(),
            "uid outside set must survive"
        );
        assert!(db.get_cached_message("ux-2").unwrap().is_none());
        let captured = calls.lock().await.clone();
        assert!(!captured.iter().any(|(_, id)| id == "ux-1"));
        assert!(captured.iter().any(|(m, id)| m == "DELETE" && id == "ux-2"));
    }

    #[tokio::test]
    async fn examine_blocks_store_expunge_and_move() {
        let (addr, db, _tx, calls, _dir) = start_test_server_with_backend(false).await;
        seed(&db, "ro-1", "inbox", "one");
        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut writer = w;
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        writer
            .write_all(b"a1 LOGIN \"tester@aster.test\" \"abcd-efgh-ijkl-mnop\"\r\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let _ = read_until_tag(&mut reader, "a1").await;
        let sel = imap_cmd_lines(&mut reader, &mut writer, "a2", "EXAMINE INBOX").await;
        assert!(sel.contains("READ-ONLY"));

        let resp = imap_cmd_lines(&mut reader, &mut writer, "r1", "STORE 1 +FLAGS (\\Seen)").await;
        assert!(resp.contains("r1 NO"), "STORE must fail read-only: {}", resp);
        let resp = imap_cmd_lines(&mut reader, &mut writer, "r2", "UID STORE 1 +FLAGS (\\Seen)").await;
        assert!(resp.contains("r2 NO"), "UID STORE must fail read-only: {}", resp);
        let resp = imap_cmd_lines(&mut reader, &mut writer, "r3", "EXPUNGE").await;
        assert!(resp.contains("r3 NO"), "EXPUNGE must fail read-only: {}", resp);
        let resp = imap_cmd_lines(&mut reader, &mut writer, "r4", "UID EXPUNGE 1").await;
        assert!(resp.contains("r4 NO"), "UID EXPUNGE must fail read-only: {}", resp);
        let resp = imap_cmd_lines(&mut reader, &mut writer, "r5", "UID MOVE 1 Trash").await;
        assert!(resp.contains("r5 NO"), "MOVE must fail read-only: {}", resp);
        assert!(db.get_cached_message("ro-1").unwrap().is_some());
        assert!(calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn uid_store_pushes_read_status_to_backend() {
        let (addr, db, _tx, calls, _dir) = start_test_server_with_backend(false).await;
        seed(&db, "rs-1", "inbox", "one");
        let (mut reader, mut writer) = login_and_select(addr).await;

        let uid = db.get_cached_message("rs-1").unwrap().unwrap().imap_uid;
        let resp = imap_cmd_lines(
            &mut reader,
            &mut writer,
            "s1",
            &format!("UID STORE {} +FLAGS (\\Seen)", uid),
        )
        .await;
        assert!(resp.contains("s1 OK"));

        let mut pushed = false;
        for _ in 0..40 {
            if calls
                .lock()
                .await
                .iter()
                .any(|(m, id)| m == "PATCH" && id == "rs-1")
            {
                pushed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(pushed, "UID STORE \\Seen must reach the backend");
    }

    #[test]
    fn date_header_rfc2822_from_rfc3339() {
        let d = date_header_rfc2822("2026-05-21T10:30:00+00:00");
        assert!(d.contains("21 May 2026"), "got {}", d);
        assert!(d.contains("10:30:00"), "got {}", d);
        assert!(!d.contains("T10:30"), "must not be rfc3339: {}", d);
        assert_eq!(date_header_rfc2822("garbage"), "garbage");
    }

    #[test]
    fn build_rfc822_emits_rfc2822_date_header() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        db.upsert_cached_message(
            "d-1",
            "inbox",
            Some("s"),
            Some("a@b.com"),
            Some("c@d.com"),
            Some("2026-05-21T10:30:00+00:00"),
            10,
            Some("body"),
            Some("{}"),
        )
        .unwrap();
        let _ = db.assign_uid_if_missing("inbox", "d-1");
        let m = db.get_cached_message("d-1").unwrap().unwrap();
        let rfc = build_rfc822(&m);
        let date_line = rfc.lines().find(|l| l.starts_with("Date:")).unwrap();
        assert!(date_line.contains("21 May 2026"), "got {}", date_line);
        assert!(!date_line.contains("2026-05-21T"), "rfc3339 leaked: {}", date_line);
    }

    #[tokio::test]
    async fn nonpeek_body_fetch_pushes_read_status() {
        let (addr, db, _tx, calls, _dir) = start_test_server_with_backend(false).await;
        seed(&db, "fs-1", "inbox", "one");
        let (mut reader, mut writer) = login_and_select(addr).await;

        let resp = imap_cmd_lines(&mut reader, &mut writer, "f1", "FETCH 1 (BODY[])").await;
        assert!(resp.contains("f1 OK"));
        assert!(resp.contains("\\Seen"), "untagged FLAGS expected: {}", resp);

        let mut pushed = false;
        for _ in 0..40 {
            if calls
                .lock()
                .await
                .iter()
                .any(|(m, id)| m == "PATCH" && id == "fs-1")
            {
                pushed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(pushed, "non-peek fetch must push read status to backend");
    }

    #[tokio::test]
    async fn peek_fetch_does_not_push_read_status() {
        let (addr, db, _tx, calls, _dir) = start_test_server_with_backend(false).await;
        seed(&db, "fs-2", "inbox", "one");
        let (mut reader, mut writer) = login_and_select(addr).await;

        let resp = imap_cmd_lines(&mut reader, &mut writer, "f1", "FETCH 1 (BODY.PEEK[])").await;
        assert!(resp.contains("f1 OK"));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            calls.lock().await.is_empty(),
            "peek fetch must not mark read"
        );
        let m = db.get_cached_message("fs-2").unwrap().unwrap();
        assert_eq!(m.flags & 1, 0);
    }

    #[tokio::test]
    async fn idle_reports_flag_changes() {
        let (addr, db, tx, _dir) = start_test_server().await;
        seed(&db, "fl-1", "inbox", "one");
        let (mut reader, mut writer) = login_and_select(addr).await;

        writer.write_all(b"i1 IDLE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut plus = String::new();
        reader.read_line(&mut plus).await.unwrap();
        assert!(plus.starts_with("+ "));

        db.set_message_flags_by_id("fl-1", 1).unwrap();
        let mut changed = HashMap::new();
        changed.insert("Email".to_string(), "5".to_string());
        let _ = tx.send(StateChange { changed });

        let read_fut = async {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            line
        };
        let line = tokio::time::timeout(Duration::from_secs(10), read_fut)
            .await
            .expect("flag change not delivered");
        assert!(
            line.contains("FETCH") && line.contains("\\Seen"),
            "expected untagged FETCH FLAGS, got: {}",
            line
        );

        writer.write_all(b"DONE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let _ = read_until_tag(&mut reader, "i1").await;
    }

    #[tokio::test]
    async fn idle_emits_correct_expunge_sequence() {
        let (addr, db, tx, _dir) = start_test_server().await;
        seed(&db, "id-1", "inbox", "one");
        seed(&db, "id-2", "inbox", "two");
        seed(&db, "id-3", "inbox", "three");
        let (mut reader, mut writer) = login_and_select(addr).await;

        writer.write_all(b"i1 IDLE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut plus = String::new();
        reader.read_line(&mut plus).await.unwrap();
        assert!(plus.starts_with("+ "));

        db.delete_message_by_aster_id("id-2").unwrap();
        let mut changed = HashMap::new();
        changed.insert("Email".to_string(), "9".to_string());
        let _ = tx.send(StateChange { changed });

        let read_fut = async {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            line
        };
        let line = tokio::time::timeout(Duration::from_secs(10), read_fut)
            .await
            .expect("EXPUNGE not delivered");
        assert!(
            line.contains("* 2 EXPUNGE"),
            "middle message must expunge as seq 2, got: {}",
            line
        );

        writer.write_all(b"DONE\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let _ = read_until_tag(&mut reader, "i1").await;
    }

    #[tokio::test]
    async fn store_gm_labels_acknowledged() {
        let (addr, db, _tx, _dir) = start_test_server().await;
        seed(&db, "msg-store-1", "inbox", "subject one");
        let (mut reader, mut writer) = login_and_select(addr).await;

        writer
            .write_all(b"a3 STORE 1 +X-GM-LABELS (\\Important Work)\r\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let lines = read_until_tag(&mut reader, "a3").await;
        let combined = lines.join("\n");
        assert!(combined.contains("a3 OK"), "store failed: {}", combined);
    }
}
