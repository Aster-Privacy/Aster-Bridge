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

fn parse_message_date_ymd(date_str: &str) -> Option<(i32, u32, u32)> {
    let b = date_str.as_bytes();
    if b.len() < 10 {
        return None;
    }
    if !b[..10]
        .iter()
        .enumerate()
        .all(|(i, c)| if i == 4 || i == 7 { true } else { c.is_ascii_digit() })
    {
        return None;
    }
    let year: i32 = std::str::from_utf8(&b[0..4]).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&b[5..7]).ok()?.parse().ok()?;
    let day: u32 = std::str::from_utf8(&b[8..10]).ok()?.parse().ok()?;
    Some((year, month, day))
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

fn search_matches(msg: &CachedMessage, criteria_upper: &str) -> bool {
    let parts: Vec<&str> = criteria_upper.split_whitespace().collect();
    let mut idx = 0;
    while idx < parts.len() {
        if !search_eval(msg, &parts, &mut idx) {
            return false;
        }
    }
    true
}

fn search_eval(msg: &CachedMessage, parts: &[&str], idx: &mut usize) -> bool {
    if *idx >= parts.len() { return true; }
    match parts[*idx] {
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
            let pat = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
            msg.sender.as_deref().unwrap_or("").to_uppercase().contains(&pat.to_uppercase())
        }
        "TO" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
            msg.recipients.as_deref().unwrap_or("").to_uppercase().contains(&pat.to_uppercase())
        }
        "SUBJECT" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
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
            let date_arg = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
            match (parse_imap_search_date(date_arg), msg.date.as_deref().and_then(parse_message_date_ymd)) {
                (Some(search), Some(msg_d)) => msg_d < search,
                _ => false,
            }
        }
        "SINCE" | "SENTSINCE" => {
            *idx += 1;
            let date_arg = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
            match (parse_imap_search_date(date_arg), msg.date.as_deref().and_then(parse_message_date_ymd)) {
                (Some(search), Some(msg_d)) => msg_d >= search,
                _ => false,
            }
        }
        "ON" | "SENTON" => {
            *idx += 1;
            let date_arg = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
            match (parse_imap_search_date(date_arg), msg.date.as_deref().and_then(parse_message_date_ymd)) {
                (Some(search), Some(msg_d)) => msg_d == search,
                _ => false,
            }
        }
        "BODY" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
            let pat_lower = pat.trim_matches('"').to_lowercase();
            if pat_lower.is_empty() { return true; }
            msg.body_text.as_deref().unwrap_or("").to_lowercase().contains(&pat_lower)
        }
        "TEXT" => {
            *idx += 1;
            let pat = if *idx < parts.len() { let p = parts[*idx]; *idx += 1; p } else { "" };
            let pat_lower = pat.trim_matches('"').to_lowercase();
            if pat_lower.is_empty() { return true; }
            let body_lower = msg.body_text.as_deref().unwrap_or("").to_lowercase();
            let subj_lower = msg.subject.as_deref().unwrap_or("").to_lowercase();
            body_lower.contains(&pat_lower) || subj_lower.contains(&pat_lower)
        }
        "CC" | "BCC" | "KEYWORD" | "UNKEYWORD" => {
            *idx += 1;
            if *idx < parts.len() { *idx += 1; }
            true
        }
        "HEADER" => {
            *idx += 1;
            if *idx < parts.len() { *idx += 1; }
            if *idx < parts.len() { *idx += 1; }
            true
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
        _ => { *idx += 1; true }
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
    let sock_addr: std::net::SocketAddr = addr.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true).ok();
    socket.bind(sock_addr)?;
    let listener = socket.listen(1024)?;
    tracing::info!("IMAP server listening on {} (STARTTLS={})", addr, tls_config.is_some());

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
    let sock_addr: std::net::SocketAddr = addr.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true).ok();
    socket.bind(sock_addr)?;
    let listener = socket.listen(1024)?;
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
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("IMAPS TLS handshake failed: {}", e);
                    return;
                }
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
    let (read_half, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let _ = client;
    let starttls_capable = tls_config.is_some();
    let greeting_cap = if starttls_capable {
        b"* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN IDLE UIDPLUS UNSELECT CHILDREN NAMESPACE X-GM-EXT-1] Aster Bridge ready\r\n" as &[u8]
    } else {
        b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS UNSELECT CHILDREN NAMESPACE X-GM-EXT-1] Aster Bridge ready\r\n"
    };
    writer.write_all(greeting_cap).await?;

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
        let args = if parts.len() > 2 {
            parts[2].to_string()
        } else {
            String::new()
        };

        match command.as_str() {
            "CAPABILITY" => {
                let cap_line: &[u8] = if starttls_capable && conn.state == ImapState::NotAuthenticated {
                    b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN IDLE UIDPLUS UNSELECT CHILDREN NAMESPACE X-GM-EXT-1\r\n"
                } else {
                    b"* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN IDLE UIDPLUS UNSELECT CHILDREN NAMESPACE X-GM-EXT-1\r\n"
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
                let rejoined = tokio::io::join(reader.into_inner(), writer);
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
            "CREATE" | "DELETE" | "RENAME" => {
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
                handle_fetch(&mut writer, &db, &conn, &tag, &args, false).await?;
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
                        handle_fetch(&mut writer, &db, &conn, &tag, subargs, true).await?;
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
                        let set_end = subargs.find(' ').unwrap_or(subargs.len());
                        let uid_set_spec = &subargs[..set_end];
                        let op_and_flags = subargs[set_end..].trim();
                        let folder = conn.selected_folder.as_deref().unwrap_or("inbox").to_string();
                        let messages = db.list_cached_messages(&folder).unwrap_or_default();
                        let max_uid = messages.iter().map(|m| m.imap_uid).max().unwrap_or(0);
                        let uids = parse_set(uid_set_spec, max_uid);
                        let (op, flag_mask, silent) = parse_store_flags(op_and_flags);
                        for uid in &uids {
                            if let Some((seq_idx, m)) = messages.iter().enumerate().find(|(_, m)| m.imap_uid == *uid) {
                                let seq = seq_idx + 1;
                                let new_flags = apply_flags(m.flags as u32, op, flag_mask);
                                let _ = db.update_message_flags(m.imap_uid as i64, &folder, new_flags as i64);
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
                        write_ok(&mut writer, &tag, "UID STORE completed").await?;
                    }
                    "EXPUNGE" => {
                        if conn.state != ImapState::Selected {
                            write_no(&mut writer, &tag, "No mailbox selected").await?;
                            continue;
                        }
                        let folder = conn.selected_folder.as_deref().unwrap_or("inbox");
                        let messages = db.list_cached_messages(folder).unwrap_or_default();
                        let deleted_seqs: Vec<(usize, i64)> = messages.iter().enumerate()
                            .filter(|(_, m)| m.flags & 8 != 0)
                            .map(|(i, m)| (i + 1, m.imap_uid as i64))
                            .collect();
                        let mut adjustment: usize = 0;
                        for (seq, uid) in &deleted_seqs {
                            let _ = db.delete_message_by_uid(*uid, folder);
                            let adjusted_seq = seq - adjustment;
                            writer.write_all(format!("* {} EXPUNGE\r\n", adjusted_seq).as_bytes()).await?;
                            conn.message_count = conn.message_count.saturating_sub(1);
                            adjustment += 1;
                        }
                        write_ok(&mut writer, &tag, "UID EXPUNGE completed").await?;
                    }
                    "COPY" | "MOVE" => {
                        write_no(&mut writer, &tag, &format!("[CANNOT] UID {} not supported", subcmd))
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
                let folder = conn.selected_folder.as_deref().unwrap_or("inbox");
                let messages = db.list_cached_messages(folder).unwrap_or_default();
                let deleted_seqs: Vec<(usize, i64)> = messages.iter().enumerate()
                    .filter(|(_, m)| m.flags & 8 != 0)
                    .map(|(i, m)| (i + 1, m.imap_uid as i64))
                    .collect();
                let mut adjustment: usize = 0;
                for (seq, uid) in &deleted_seqs {
                    let _ = db.delete_message_by_uid(*uid, folder);
                    let adjusted_seq = seq - adjustment;
                    writer.write_all(format!("* {} EXPUNGE\r\n", adjusted_seq).as_bytes()).await?;
                    conn.message_count = conn.message_count.saturating_sub(1);
                    adjustment += 1;
                }
                write_ok(&mut writer, &tag, "EXPUNGE completed").await?;
            }
            "COPY" | "MOVE" => {
                require_selected!(conn, writer, tag);
                write_no(&mut writer, &tag, "[CANNOT] COPY not supported").await?;
            }
            "IDLE" => {
                require_auth!(conn, writer, tag);
                writer.write_all(b"+ idling\r\n").await?;

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
                                    let new_count = db.count_cached_messages(&folder).unwrap_or(conn.message_count);
                                    if new_count > conn.message_count {
                                        writer
                                            .write_all(format!("* {} EXISTS\r\n", new_count).as_bytes())
                                            .await?;
                                        conn.message_count = new_count;
                                    } else if new_count < conn.message_count {
                                        let mut cur = conn.message_count;
                                        while cur > new_count {
                                            writer.write_all(format!("* {} EXPUNGE\r\n", cur).as_bytes()).await?;
                                            cur -= 1;
                                        }
                                        conn.message_count = new_count;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    if let Some(folder) = conn.selected_folder.as_deref() {
                                        let new_count = db.count_cached_messages(folder).unwrap_or(conn.message_count);
                                        writer
                                            .write_all(format!("* {} EXISTS\r\n", new_count).as_bytes())
                                            .await?;
                                        conn.message_count = new_count;
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
                let messages = db.list_cached_messages(&folder).unwrap_or_default();
                for msg in messages.iter().filter(|m| m.flags & 8 != 0) {
                    let _ = db.delete_message_by_uid(msg.imap_uid as i64, &folder);
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
                let literal_info = args.rfind('{').and_then(|s| {
                    let rest = &args[s + 1..];
                    rest.find('}').and_then(|e| {
                        let inner = &rest[..e];
                        let non_sync = inner.ends_with('+');
                        let n = inner.trim_end_matches('+').parse::<usize>().ok()?;
                        Some((n, non_sync))
                    })
                });
                match literal_info {
                    Some((n, _)) if n > 5 * 1024 * 1024 => {
                        write_no(&mut writer, &tag, "[TOOBIG] APPEND literal too large").await?;
                    }
                    Some((n, non_sync)) => {
                        use tokio::io::AsyncReadExt;
                        if !non_sync {
                            writer.write_all(b"+ Ready for literal data\r\n").await?;
                            writer.flush().await?;
                        }
                        let mut buf = vec![0u8; n];
                        if let Err(e) = reader.read_exact(&mut buf).await {
                            tracing::warn!("APPEND read failed: {}", e);
                            write_bad(&mut writer, &tag, "APPEND read failed").await?;
                            continue;
                        }
                        let mut trailer = [0u8; 2];
                        let _ = reader.read_exact(&mut trailer).await;
                        write_no(
                            &mut writer,
                            &tag,
                            "[CANNOT] APPEND not supported - use SMTP submission",
                        )
                        .await?;
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

fn parse_imap_atom_or_quoted(s: &str) -> (String, &str) {
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

pub fn build_rfc822(msg: &CachedMessage) -> String {
    let mut out = String::new();
    let date = sanitize_header(msg.date.as_deref().unwrap_or(""));
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
    out.push_str(&format!("Date: {}\r\n", date));
    out.push_str(&format!("From: {}\r\n", from));
    if !to.is_empty() {
        out.push_str(&format!("To: {}\r\n", to));
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
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
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
    conn: &ImapConnection,
    tag: &str,
    args: &str,
    uid_command: bool,
) -> std::io::Result<()> {
    let folder = conn.selected_folder.as_deref().unwrap_or("inbox");

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
            let date = msg.date.clone().unwrap_or_default();
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
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
        }));
        let client = Arc::new(ApiClient::new());
        let (tx, _rx) = broadcast::channel(16);

        let _g = crate::port_picker::TEST_SERVER_START.lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let addr_str = format!("127.0.0.1:{}", addr.port());
        let db_clone = db.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let _ = run(&addr_str, session, db_clone, client, passwords, tx_clone, None).await;
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
        assert!(greeting.contains("Aster Bridge ready"));

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
        let line = tokio::time::timeout(Duration::from_secs(2), read_fut)
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
