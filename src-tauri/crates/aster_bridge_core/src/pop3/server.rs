//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use crate::api_client::ApiClient;
use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;
use crate::db::{CachedAttachment, Database, ATTACHMENTS_ON_DEMAND};
use crate::error::Result;
use crate::message_render;

const MAX_LINE_LENGTH: usize = 512;
const MAX_FAILED_AUTH: u32 = 5;

fn pop3_size(m: &crate::db::CachedMessage, attachments: &[CachedAttachment]) -> usize {
    message_render::rendered_size(m, attachments)
}

fn uidl_line(n: usize, aster_id: &str) -> String {
    let id: String = aster_id.chars().filter(|c| matches!(c, '\x21'..='\x7e')).collect();
    format!("{} {}\r\n", n, id)
}

fn attachments_of<'a>(
    meta: &'a std::collections::HashMap<String, Vec<CachedAttachment>>,
    m: &crate::db::CachedMessage,
) -> &'a [CachedAttachment] {
    meta.get(&m.aster_id).map(|v| v.as_slice()).unwrap_or(&[])
}

fn full_message_text(db: &Database, m: &crate::db::CachedMessage) -> String {
    let attachments = if crate::db::attachment_parts_known(m.attachments_state) {
        db.get_message_attachments(&m.aster_id).unwrap_or_default()
    } else {
        Vec::new()
    };
    message_render::render_text(m, &attachments)
}

async fn with_attachments(
    db: &Database,
    client: &ApiClient,
    session: &Arc<RwLock<Session>>,
    m: crate::db::CachedMessage,
) -> Option<crate::db::CachedMessage> {
    if m.attachments_state != ATTACHMENTS_ON_DEMAND {
        return Some(m);
    }
    use crate::sync::poller::on_demand::{ensure_attachments, AttachmentFill};
    if ensure_attachments(db, client, session, &m.aster_id, None).await == AttachmentFill::Unavailable {
        return None;
    }
    db.get_cached_message(&m.aster_id)
        .ok()
        .flatten()
        .filter(|filled| filled.attachments_state != ATTACHMENTS_ON_DEMAND)
}

const ATTACHMENTS_UNAVAILABLE: &[u8] =
    b"-ERR [SYS/TEMP] the attachments of this message could not be downloaded; try again later\r\n";

fn wire_lines(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                lines.push(&text[start..i]);
                i += if bytes.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            b'\n' => {
                lines.push(&text[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

fn push_wire_line(out: &mut String, line: &str) {
    if line.starts_with('.') {
        out.push('.');
    }
    out.push_str(line);
    out.push_str("\r\n");
}

fn retr_response(text: &str) -> String {
    let lines = wire_lines(text);
    let octets: usize = lines.iter().map(|l| l.len() + 2).sum();
    let mut out = String::with_capacity(octets + 64);
    out.push_str(&format!("+OK {} octets\r\n", octets));
    for line in &lines {
        push_wire_line(&mut out, line);
    }
    out.push_str(".\r\n");
    out
}

fn top_response(text: &str, line_count: usize) -> String {
    let lines = wire_lines(text);
    let header_end = lines.iter().position(|l| l.is_empty()).unwrap_or(lines.len());
    let mut out = String::from("+OK\r\n");
    for line in &lines[..header_end] {
        push_wire_line(&mut out, line);
    }
    out.push_str("\r\n");
    for line in lines.iter().skip(header_end + 1).take(line_count) {
        push_wire_line(&mut out, line);
    }
    out.push_str(".\r\n");
    out
}

static POP3_SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

struct Pop3SessionLock;
impl Drop for Pop3SessionLock {
    fn drop(&mut self) {
        POP3_SESSION_ACTIVE.store(false, Ordering::Release);
    }
}

async fn read_pop3_line<R>(reader: &mut R, out: &mut String) -> std::io::Result<usize>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
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
        let take = slice_end.min(MAX_LINE_LENGTH.saturating_sub(buf.len()) + 1);
        buf.extend_from_slice(&avail[..take]);
        tokio::io::AsyncBufReadExt::consume(reader, take);
        if buf.len() > MAX_LINE_LENGTH {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
        }
        if done {
            break;
        }
    }
    *out = String::from_utf8_lossy(&buf).into_owned();
    Ok(buf.len())
}

pub async fn run(
    addr: &str,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    _tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener = crate::port_picker::bind_loopback_listener(addr).await?;
    tracing::info!("POP3 server listening on {}", addr);
    serve_with_tls(listener, session, db, client, passwords, _tls_config).await
}

pub async fn serve_with_tls(
    listener: tokio::net::TcpListener,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let mut acceptor = crate::accept::ResilientAcceptor::new("POP3");
    let shutdown = crate::shutdown::current();
    loop {
        let (stream, peer) = acceptor.accept(&listener).await;
        if !peer.ip().is_loopback() {
            tracing::warn!("POP3 rejected non-loopback peer {}", peer);
            drop(stream);
            continue;
        }
        let permit = match crate::conn_limit::try_acquire_connection(crate::conn_limit::Protocol::Pop3) {
            Some(p) => p,
            None => {
                tracing::warn!("POP3 connection limit reached, dropping {}", peer);
                drop(stream);
                continue;
            }
        };
        let db = db.clone();
        let passwords = passwords.clone();
        let session = session.clone();
        let client = client.clone();
        let tls_config = tls_config.clone();

        shutdown.spawn(async move {
            let _permit = permit;
            if let Err(e) = run_session(stream, session, db, client, passwords, tls_config).await {
                tracing::error!("POP3 connection error: {}", e);
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
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let listener = crate::port_picker::bind_loopback_listener(addr).await?;
    tracing::info!("POP3S (implicit TLS) listening on {}", addr);

    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let mut conn_acceptor = crate::accept::ResilientAcceptor::new("POP3S");
    let shutdown = crate::shutdown::current();
    loop {
        let (stream, peer) = conn_acceptor.accept(&listener).await;
        if !peer.ip().is_loopback() {
            tracing::warn!("POP3S rejected non-loopback peer {}", peer);
            drop(stream);
            continue;
        }
        let permit = match crate::conn_limit::try_acquire_connection(crate::conn_limit::Protocol::Pop3) {
            Some(p) => p,
            None => {
                tracing::warn!("POP3S connection limit reached, dropping {}", peer);
                drop(stream);
                continue;
            }
        };
        let db = db.clone();
        let passwords = passwords.clone();
        let session = session.clone();
        let client = client.clone();
        let acceptor = acceptor.clone();

        shutdown.spawn(async move {
            let _permit = permit;
            let tls_stream = match crate::tls::accept_with_timeout(&acceptor, stream, "POP3S").await {
                Some(s) => s,
                None => return,
            };
            if let Err(e) = run_session(tls_stream, session, db, client, passwords, None).await {
                tracing::error!("POP3S connection error: {}", e);
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
    pre_auth: crate::conn_limit::PreAuthClock,
) -> Result<()> {
    run_session_inner(stream, session, db, client, passwords, None, false, pre_auth).await
}

async fn run_session<S>(
    stream: S,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pre_auth = crate::conn_limit::PreAuthClock::start();
    let inner = run_session_inner(
        stream,
        session,
        db,
        client,
        passwords,
        tls_config,
        true,
        pre_auth.clone(),
    );
    match pre_auth.guard(inner).await {
        Some(result) => result,
        None => {
            tracing::debug!("POP3 connection closed: no sign-in before the deadline");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session_inner<S>(
    stream: S,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    greet: bool,
    pre_auth: crate::conn_limit::PreAuthClock,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stls_capable = tls_config.is_some();
    let (read_half, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    if greet {
        writer.write_all(b"+OK Aster Bridge POP3 ready\r\n").await?;
    }

    let mut authenticated = false;
    let mut user_received = false;
    let mut messages: Vec<crate::db::CachedMessage> = Vec::new();
    let mut attachment_meta: std::collections::HashMap<String, Vec<CachedAttachment>> =
        std::collections::HashMap::new();
    let mut deleted: Vec<bool> = Vec::new();
    let mut line = String::new();
    let mut failed_auth: u32 = 0;
    let mut _session_lock: Option<Pop3SessionLock> = None;

    loop {
        writer.flush().await?;
        line.clear();
        let read = pre_auth
            .bound_until_auth(authenticated, read_pop3_line(&mut reader, &mut line))
            .await;
        let Some(read) = read else {
            let _ = tokio::time::timeout(crate::conn_limit::PRE_AUTH_FAREWELL_TIMEOUT, writer.write_all(b"-ERR idle timeout\r\n")).await;
            break;
        };
        let n = match read {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }

        let trimmed = line.trim_end().to_string();
        let (cmd, args) = if let Some(pos) = trimmed.find(' ') {
            (trimmed[..pos].to_uppercase(), trimmed[pos + 1..].trim().to_string())
        } else {
            (trimmed.to_uppercase(), String::new())
        };

        if !authenticated {
            match cmd.as_str() {
                "USER" => {
                    if stls_capable {
                        crate::sign_in_notice::record_insecure("pop3");
                        writer.write_all(format!("-ERR [PRIVACYREQUIRED] {}\r\n", crate::sign_in_notice::TLS_REQUIRED_TEXT).as_bytes()).await?;
                        continue;
                    }
                    user_received = true;
                    writer.write_all(b"+OK user accepted\r\n").await?;
                }
                "APOP" => {
                    writer.write_all(b"-ERR APOP not supported\r\n").await?;
                }
                "STLS" => {
                    let cfg = match tls_config.as_ref() {
                        Some(c) => c.clone(),
                        None => {
                            writer.write_all(b"-ERR STLS not available\r\n").await?;
                            continue;
                        }
                    };
                    writer.write_all(b"+OK Begin TLS negotiation\r\n").await?;
                    writer.flush().await?;
                    let rejoined = tokio::io::join(reader.into_inner(), writer);
                    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                    let Some(accepted) = pre_auth.bound(acceptor.accept(rejoined)).await else {
                        return Ok(());
                    };
                    let tls_stream = accepted.map_err(std::io::Error::other)?;
                    let erased: Box<dyn AsyncReadWrite + Send + Unpin> = Box::new(tls_stream);
                    return Box::pin(run_session_erased(
                        erased,
                        session,
                        db,
                        client,
                        passwords,
                        pre_auth.clone(),
                    ))
                    .await;
                }
                "PASS" => {
                    if stls_capable {
                        crate::sign_in_notice::record_insecure("pop3");
                        writer.write_all(format!("-ERR [PRIVACYREQUIRED] {}\r\n", crate::sign_in_notice::TLS_REQUIRED_TEXT).as_bytes()).await?;
                        continue;
                    }
                    if !user_received {
                        writer.write_all(b"-ERR USER required first\r\n").await?;
                        continue;
                    }
                    if let Some(pw_id) = passwords.verify_and_id_async(&args).await {
                        if POP3_SESSION_ACTIVE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                            writer.write_all(b"-ERR [IN-USE] Maildrop already locked by another session\r\n").await?;
                            break;
                        }
                        _session_lock = Some(Pop3SessionLock);
                        passwords.record_use(&pw_id, Some("pop3"));
                        crate::sign_in_notice::record_signed_in("pop3");
                        messages = db.list_cached_message_meta("inbox").unwrap_or_default();
                        attachment_meta = db.list_attachment_meta_for_folder("inbox").unwrap_or_default();
                        deleted = vec![false; messages.len()];
                        authenticated = true;
                        pre_auth.mark_signed_in();
                        writer.write_all(b"+OK maildrop ready\r\n").await?;
                    } else {
                        failed_auth += 1;
                        if failed_auth >= MAX_FAILED_AUTH {
                            writer.write_all(b"-ERR too many failed attempts\r\n").await?;
                            break;
                        }
                        writer.write_all(format!("-ERR {}\r\n", crate::sign_in_notice::BAD_CREDENTIALS_TEXT).as_bytes()).await?;
                    }
                }
                "CAPA" => {
                    let capabilities: &[u8] = if stls_capable {
                        b"+OK Capability list follows\r\nSTLS\r\nUSER\r\nUIDL\r\nTOP\r\nRESP-CODES\r\nEXPIRE NEVER\r\nIMPLEMENTATION Aster Bridge\r\n.\r\n"
                    } else {
                        b"+OK Capability list follows\r\nUSER\r\nUIDL\r\nTOP\r\nRESP-CODES\r\nEXPIRE NEVER\r\nIMPLEMENTATION Aster Bridge\r\n.\r\n"
                    };
                    writer.write_all(capabilities).await?;
                }
                "QUIT" => {
                    writer.write_all(b"+OK bye\r\n").await?;
                    break;
                }
                _ => {
                    writer.write_all(b"-ERR please authenticate first\r\n").await?;
                }
            }
            continue;
        }

        match cmd.as_str() {
            "STAT" => {
                let count = deleted.iter().filter(|d| !**d).count();
                let total_octets: usize = messages.iter().zip(deleted.iter())
                    .filter(|(_, d)| !*d)
                    .map(|(m, _)| pop3_size(m, attachments_of(&attachment_meta, m)))
                    .sum();
                writer.write_all(format!("+OK {} {}\r\n", count, total_octets).as_bytes()).await?;
            }
            "LIST" => {
                if args.is_empty() {
                    let count = deleted.iter().filter(|d| !**d).count();
                    let total: usize = messages.iter().zip(deleted.iter())
                        .filter(|(_, d)| !*d)
                        .map(|(m, _)| pop3_size(m, attachments_of(&attachment_meta, m)))
                        .sum();
                    let mut resp = format!("+OK {} messages ({} octets)\r\n", count, total);
                    for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
                        if !del {
                            resp.push_str(&format!("{} {}\r\n", i + 1, pop3_size(msg, attachments_of(&attachment_meta, msg))));
                        }
                    }
                    resp.push_str(".\r\n");
                    writer.write_all(resp.as_bytes()).await?;
                } else if let Ok(n) = args.parse::<usize>() {
                    if n == 0 || n > messages.len() || deleted[n - 1] {
                        writer.write_all(b"-ERR no such message\r\n").await?;
                    } else {
                        writer.write_all(format!("+OK {} {}\r\n", n, pop3_size(&messages[n - 1], attachments_of(&attachment_meta, &messages[n - 1]))).as_bytes()).await?;
                    }
                } else {
                    writer.write_all(b"-ERR syntax error\r\n").await?;
                }
            }
            "UIDL" => {
                if args.is_empty() {
                    let mut resp = String::from("+OK\r\n");
                    for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
                        if !del {
                            resp.push_str(&uidl_line(i + 1, &msg.aster_id));
                        }
                    }
                    resp.push_str(".\r\n");
                    writer.write_all(resp.as_bytes()).await?;
                } else if let Ok(n) = args.parse::<usize>() {
                    if n == 0 || n > messages.len() || deleted[n - 1] {
                        writer.write_all(b"-ERR no such message\r\n").await?;
                    } else {
                        writer.write_all(format!("+OK {}", uidl_line(n, &messages[n - 1].aster_id)).as_bytes()).await?;
                    }
                } else {
                    writer.write_all(b"-ERR syntax error\r\n").await?;
                }
            }
            "RETR" => {
                if let Ok(n) = args.parse::<usize>() {
                    if n == 0 || n > messages.len() || deleted[n - 1] {
                        writer.write_all(b"-ERR no such message\r\n").await?;
                    } else if let Some(stored) =
                        db.get_cached_message(&messages[n - 1].aster_id).ok().flatten()
                    {
                        let Some(full) = with_attachments(&db, &client, &session, stored).await else {
                            writer.write_all(ATTACHMENTS_UNAVAILABLE).await?;
                            continue;
                        };
                        let rfc = full_message_text(&db, &full);
                        writer.write_all(retr_response(&rfc).as_bytes()).await?;
                    } else {
                        writer.write_all(b"-ERR message body unavailable\r\n").await?;
                    }
                } else {
                    writer.write_all(b"-ERR syntax error\r\n").await?;
                }
            }
            "TOP" => {
                let mut parts = args.splitn(2, ' ');
                let msg_num = parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                let line_count = parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                let full_top = if msg_num == 0 || msg_num > messages.len() || deleted[msg_num - 1] {
                    None
                } else {
                    db.get_cached_message(&messages[msg_num - 1].aster_id).ok().flatten()
                };
                let full_top = match full_top {
                    Some(stored) if line_count > 0 => match with_attachments(&db, &client, &session, stored).await {
                        Some(full) => Some(full),
                        None => {
                            writer.write_all(ATTACHMENTS_UNAVAILABLE).await?;
                            continue;
                        }
                    },
                    other => other,
                };
                if let Some(full) = full_top {
                    let rfc = full_message_text(&db, &full);
                    writer.write_all(top_response(&rfc, line_count).as_bytes()).await?;
                } else {
                    writer.write_all(b"-ERR no such message\r\n").await?;
                }
            }
            "DELE" => {
                if let Ok(n) = args.parse::<usize>() {
                    if n == 0 || n > messages.len() || deleted[n - 1] {
                        writer.write_all(b"-ERR no such message\r\n").await?;
                    } else {
                        deleted[n - 1] = true;
                        writer.write_all(format!("+OK message {} deleted\r\n", n).as_bytes()).await?;
                    }
                } else {
                    writer.write_all(b"-ERR syntax error\r\n").await?;
                }
            }
            "RSET" => {
                for d in deleted.iter_mut() {
                    *d = false;
                }
                writer.write_all(format!("+OK {} messages\r\n", messages.len()).as_bytes()).await?;
            }
            "NOOP" => {
                writer.write_all(b"+OK\r\n").await?;
            }
            "CAPA" => {
                writer.write_all(b"+OK Capability list follows\r\nUSER\r\nUIDL\r\nTOP\r\nRESP-CODES\r\nEXPIRE NEVER\r\nIMPLEMENTATION Aster Bridge\r\n.\r\n").await?;
            }
            "QUIT" => {
                let token = session.read().await.access_token.to_string();
                for (i, del) in deleted.iter().enumerate() {
                    if *del {
                        if let Some(msg) = messages.get(i) {
                            let server_gone = match client
                                .delete_mail_item_permanent(&token, &msg.aster_id)
                                .await
                            {
                                Ok(()) => true,
                                Err(crate::error::BridgeError::Api(ref m)) if m.starts_with("404") => true,
                                Err(e) => {
                                    tracing::warn!("POP3 server delete failed for {}: {}", msg.aster_id, e);
                                    false
                                }
                            };
                            if server_gone {
                                let _ = db.delete_message_by_aster_id(&msg.aster_id);
                            }
                        }
                    }
                }
                writer.write_all(b"+OK Aster Bridge POP3 server signing off\r\n").await?;
                break;
            }
            _ => {
                writer.write_all(b"-ERR unknown command\r\n").await?;
            }
        }
    }

    let closing = async {
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    };
    match pre_auth.farewell_window() {
        Some(window) => {
            let _ = tokio::time::timeout(window, closing).await;
        }
        None => closing.await,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap::server::build_rfc822;
    use crate::db::CachedMessage;

    fn sample_message(aster_id: &str) -> CachedMessage {
        CachedMessage {
            aster_id: aster_id.to_string(),
            folder: "inbox".to_string(),
            subject: Some("Test Subject".to_string()),
            sender: Some("sender@aster.test".to_string()),
            recipients: Some("rcpt@aster.test".to_string()),
            date: Some("Mon, 01 Jan 2026 00:00:00 +0000".to_string()),
            size: 999999,
            flags: 0,
            body_text: Some("line one\nline two\nline three".to_string()),
            raw_headers: None,
            imap_uid: 1,
            thread_id: None,
            attachments_state: 0,
        }
    }

    #[test]
    fn pop3_size_equals_build_rfc822_len() {
        let m = sample_message("id-1");
        let expected = build_rfc822(&m).len();
        assert_eq!(pop3_size(&m, &[]), expected);
    }

    async fn pop3_transcript(script: &str, with_tls: bool) -> String {
        let crate::sign_in_notice::test_support::Fixture { session, db, client, passwords, tls, dir } =
            crate::sign_in_notice::test_support::fixture();
        let tls = with_tls.then_some(tls);
        let out = crate::sign_in_notice::test_support::transcript(script, move |stream| {
            run_session(stream, session, db, client, passwords, tls)
        })
        .await;
        drop(dir);
        out
    }

    #[tokio::test]
    async fn sign_in_without_tls_explains_the_fix_and_is_recorded() {
        let _guard = crate::sign_in_notice::test_support::test_lock();
        crate::sign_in_notice::dismiss_insecure(u64::MAX);
        let out = pop3_transcript("USER tester@aster.test\r\nPASS x\r\nQUIT\r\n", true).await;
        let expected = "-ERR [PRIVACYREQUIRED] Turn on SSL/TLS for this account in your mail app, then try again\r\n";
        assert_eq!(out.matches(expected).count(), 2, "{:?}", out);
        assert_eq!(
            crate::sign_in_notice::last_insecure().map(|l| l.protocol),
            Some("pop3")
        );
    }

    #[tokio::test]
    async fn a_wrong_password_points_at_the_app_password_in_bridge() {
        let out = pop3_transcript("USER tester@aster.test\r\nPASS wrong-password\r\nQUIT\r\n", false).await;
        assert!(
            out.contains("-ERR Sign-in failed. Use the username and app password shown in Aster Bridge\r\n"),
            "{:?}",
            out
        );
    }

    #[test]
    fn pop3_size_ignores_stored_size_field() {
        let mut m = sample_message("id-2");
        let baseline = pop3_size(&m, &[]);
        m.size = 123456789;
        assert_eq!(pop3_size(&m, &[]), baseline);
        assert_ne!(pop3_size(&m, &[]), m.size as usize);
    }

    #[test]
    fn pop3_size_is_nonzero_for_real_message() {
        let m = sample_message("id-3");
        assert!(pop3_size(&m, &[]) > 0);
    }

    #[test]
    fn rfc822_contains_expected_headers() {
        let m = sample_message("id-4");
        let rfc = build_rfc822(&m);
        assert!(rfc.contains("Subject: Test Subject"));
        assert!(rfc.contains("From: sender@aster.test"));
        assert!(rfc.contains("\r\n\r\n"));
    }

    static AUTHENTICATED_SESSION_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn wait_for_maildrop_release() {
        for _ in 0..200 {
            if !POP3_SESSION_ACTIVE.load(Ordering::Acquire) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("the maildrop lock was never released");
    }

    fn decode_multiline(wire: &str) -> (String, Vec<String>, Vec<String>) {
        let lines = wire_lines(wire);
        let status = lines[0].to_string();
        let end = lines
            .iter()
            .skip(1)
            .position(|l| *l == ".")
            .map(|p| p + 1)
            .expect("a multi-line response always carries a terminator");
        let content = lines[1..end]
            .iter()
            .map(|l| l.strip_prefix('.').unwrap_or(l).to_string())
            .collect();
        let leftover = lines[end + 1..].iter().map(|l| l.to_string()).collect();
        (status, content, leftover)
    }

    fn assert_strict_crlf(wire: &str) {
        let stripped = wire.replace("\r\n", "");
        assert!(
            !stripped.contains('\r') && !stripped.contains('\n'),
            "response carries a bare CR or LF: {:?}",
            wire
        );
        assert!(wire.ends_with("\r\n.\r\n"));
    }

    #[test]
    fn wire_lines_splits_on_every_line_ending() {
        assert_eq!(wire_lines("a\r\nb\nc\rd"), vec!["a", "b", "c", "d"]);
        assert_eq!(wire_lines("a\r\n"), vec!["a"]);
        assert_eq!(wire_lines("a\n\nb"), vec!["a", "", "b"]);
        assert_eq!(wire_lines("\r\r\n"), vec!["", ""]);
        assert_eq!(wire_lines("\n"), vec![""]);
        assert!(wire_lines("").is_empty());
        assert_eq!(
            wire_lines("h\u{e9}llo\n\u{4e16}\u{754c}"),
            vec!["h\u{e9}llo", "\u{4e16}\u{754c}"]
        );
    }

    #[test]
    fn retr_keeps_crlf_messages_byte_for_byte() {
        let rfc = "From: a@aster.test\r\nSubject: hi\r\n\r\nline one\r\n\r\nline three\r\n";
        assert_eq!(
            retr_response(rfc),
            format!("+OK {} octets\r\n{}.\r\n", rfc.len(), rfc)
        );
    }

    #[test]
    fn retr_stuffs_leading_dots_after_crlf() {
        let wire = retr_response(".secret\r\nnormal\r\n..double\r\n");
        assert_eq!(wire, "+OK 27 octets\r\n..secret\r\nnormal\r\n...double\r\n.\r\n");
    }

    #[test]
    fn retr_leaves_normal_lines_untouched() {
        let wire = retr_response("plain line\r\nanother\r\n");
        assert_eq!(wire, "+OK 21 octets\r\nplain line\r\nanother\r\n.\r\n");
    }

    #[test]
    fn retr_stuffs_a_lone_dot_after_a_bare_line_feed() {
        let wire = retr_response("Subject: x\r\n\r\nHi\n.\n+OK fake\nBye");
        assert_eq!(
            wire,
            "+OK 36 octets\r\nSubject: x\r\n\r\nHi\r\n..\r\n+OK fake\r\nBye\r\n.\r\n"
        );
        assert_strict_crlf(&wire);
        let (status, content, leftover) = decode_multiline(&wire);
        assert_eq!(status, "+OK 36 octets");
        assert_eq!(content, vec!["Subject: x", "", "Hi", ".", "+OK fake", "Bye"]);
        assert!(leftover.is_empty(), "message text leaked past the terminator: {:?}", leftover);
    }

    #[test]
    fn retr_stuffs_a_lone_dot_after_a_bare_carriage_return() {
        let wire = retr_response("Subject: x\r\n\r\nHi\r.\r-ERR fake\rBye");
        assert_strict_crlf(&wire);
        let (_, content, leftover) = decode_multiline(&wire);
        assert_eq!(content, vec!["Subject: x", "", "Hi", ".", "-ERR fake", "Bye"]);
        assert!(leftover.is_empty());
    }

    #[test]
    fn retr_of_a_rendered_message_with_a_hostile_body_stays_framed() {
        let mut m = sample_message("id-hostile");
        m.body_text = Some("Hi\n.\n+OK fake\n.\r\n-ERR spoof\r.\rBye".to_string());
        let rfc = message_render::render_text(&m, &[]);
        let wire = retr_response(&rfc);
        assert_strict_crlf(&wire);
        let (status, content, leftover) = decode_multiline(&wire);
        assert!(leftover.is_empty(), "message text leaked past the terminator: {:?}", leftover);
        let octets: usize = content.iter().map(|l| l.len() + 2).sum();
        assert_eq!(status, format!("+OK {} octets", octets));
        let tail: Vec<&str> = content.iter().rev().take(7).rev().map(|s| s.as_str()).collect();
        assert_eq!(tail, vec!["Hi", ".", "+OK fake", ".", "-ERR spoof", ".", "Bye"]);
    }

    #[test]
    fn top_returns_headers_one_blank_line_and_the_requested_lines() {
        let rfc = "A: 1\r\nB: 2\r\n\r\none\r\ntwo\r\nthree\r\n";
        assert_eq!(top_response(rfc, 2), "+OK\r\nA: 1\r\nB: 2\r\n\r\none\r\ntwo\r\n.\r\n");
        assert_eq!(top_response(rfc, 0), "+OK\r\nA: 1\r\nB: 2\r\n\r\n.\r\n");
        assert_eq!(
            top_response(rfc, 99),
            "+OK\r\nA: 1\r\nB: 2\r\n\r\none\r\ntwo\r\nthree\r\n.\r\n"
        );
    }

    #[test]
    fn top_counts_lines_of_a_body_that_uses_bare_line_feeds() {
        let wire = top_response("A: 1\r\n\r\none\n.\ntwo\nthree", 2);
        assert_eq!(wire, "+OK\r\nA: 1\r\n\r\none\r\n..\r\n.\r\n");
        assert_strict_crlf(&wire);
        let (_, content, leftover) = decode_multiline(&wire);
        assert_eq!(content, vec!["A: 1", "", "one", "."]);
        assert!(leftover.is_empty());
    }

    #[test]
    fn top_keeps_blank_lines_inside_the_body() {
        let wire = top_response("A: 1\r\n\r\none\r\n\r\nthree\r\n", 3);
        assert_eq!(wire, "+OK\r\nA: 1\r\n\r\none\r\n\r\nthree\r\n.\r\n");
    }

    #[test]
    fn top_of_a_rendered_message_splits_headers_from_body() {
        let m = sample_message("id-5");
        let wire = top_response(&build_rfc822(&m), 1);
        let (_, content, leftover) = decode_multiline(&wire);
        assert!(leftover.is_empty());
        let blank = content.iter().position(|l| l.is_empty()).unwrap();
        assert!(content[..blank].iter().any(|l| l.starts_with("From:")));
        assert_eq!(content[blank + 1..].to_vec(), vec!["line one".to_string()]);
    }

    #[test]
    fn top_without_a_separator_treats_everything_as_headers() {
        let wire = top_response("Header-Only: yes\r\nNo-Body-Here: true", 5);
        assert_eq!(wire, "+OK\r\nHeader-Only: yes\r\nNo-Body-Here: true\r\n\r\n.\r\n");
    }

    #[test]
    fn empty_text_does_not_panic() {
        assert_eq!(retr_response(""), "+OK 0 octets\r\n.\r\n");
        assert_eq!(top_response("", 3), "+OK\r\n\r\n.\r\n");
    }

    #[test]
    fn no_short_text_can_end_a_response_early() {
        const ALPHABET: [char; 5] = ['.', '\r', '\n', 'a', '+'];
        const MAX_LEN: usize = 7;
        let mut checked = 0usize;
        for len in 0..=MAX_LEN {
            let total = ALPHABET.len().pow(len as u32);
            for index in 0..total {
                let mut n = index;
                let mut body = String::with_capacity(len);
                for _ in 0..len {
                    body.push(ALPHABET[n % ALPHABET.len()]);
                    n /= ALPHABET.len();
                }
                let text = format!("H: v\r\n\r\n{}", body);
                let expected: Vec<String> =
                    wire_lines(&text).iter().map(|l| l.to_string()).collect();

                let wire = retr_response(&text);
                assert_strict_crlf(&wire);
                let (status, content, leftover) = decode_multiline(&wire);
                assert!(leftover.is_empty(), "RETR leaked for {:?}: {:?}", body, wire);
                assert_eq!(content, expected, "RETR changed the content of {:?}", body);
                let octets: usize = expected.iter().map(|l| l.len() + 2).sum();
                assert_eq!(status, format!("+OK {} octets", octets));

                for limit in [0usize, 1, 2, 100] {
                    let wire = top_response(&text, limit);
                    assert_strict_crlf(&wire);
                    let (status, content, leftover) = decode_multiline(&wire);
                    assert_eq!(status, "+OK");
                    assert!(leftover.is_empty(), "TOP leaked for {:?}: {:?}", body, wire);
                    let keep = (2 + limit).min(expected.len());
                    assert_eq!(content, expected[..keep].to_vec(), "TOP {} of {:?}", limit, body);
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 97656);
    }

    #[tokio::test]
    async fn retr_and_top_keep_a_hostile_body_inside_the_response() {
        let _serial = AUTHENTICATED_SESSION_TESTS.lock().await;
        wait_for_maildrop_release().await;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[5u8; 32]).unwrap());
        db.upsert_cached_message(
            "pop-hostile",
            "inbox",
            Some("s"),
            Some("a@b.com"),
            Some("c@d.com"),
            Some("2026-01-01T00:00:00Z"),
            10,
            Some("Hi\n.\n+OK fake\n-ERR spoofed\r.\rBye"),
            Some("{\"is_html\":false}"),
        )
        .unwrap();
        let _ = db.assign_uid_if_missing("inbox", "pop-hostile");

        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        let _ = passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }));
        let client = Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:1"));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_with_tls(listener, session, db, client, passwords, None).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("+OK"));

        for cmd in ["USER tester@aster.test", "PASS abcd-efgh-ijkl-mnop"] {
            w.write_all(format!("{}\r\n", cmd).as_bytes()).await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("+OK"), "{} failed: {}", cmd, line);
        }

        for (cmd, expected_tail) in [
            ("RETR 1", vec!["Hi", ".", "+OK fake", "-ERR spoofed", ".", "Bye"]),
            ("TOP 1 2", vec!["Hi", "."]),
        ] {
            w.write_all(format!("{}\r\n", cmd).as_bytes()).await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("+OK"), "{} failed: {}", cmd, line);
            let mut content: Vec<String> = Vec::new();
            loop {
                line.clear();
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read_line(&mut line),
                )
                .await
                .expect("the response never ended")
                .unwrap();
                assert!(read > 0);
                assert!(line.ends_with("\r\n"), "{} sent a bare line feed: {:?}", cmd, line);
                let text = line.trim_end_matches("\r\n");
                assert!(!text.contains('\r'), "{} sent a bare carriage return: {:?}", cmd, line);
                if text == "." {
                    break;
                }
                content.push(text.strip_prefix('.').unwrap_or(text).to_string());
            }
            let blank = content.iter().position(|l| l.is_empty()).unwrap();
            assert_eq!(content[blank + 1..].to_vec(), expected_tail, "{}", cmd);

            w.write_all(b"NOOP\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "+OK\r\n", "the reply after {} came from the message body", cmd);
        }

        w.write_all(b"QUIT\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("+OK"));
        wait_for_maildrop_release().await;
        drop(dir);
    }

    #[test]
    fn uidl_line_format() {
        let messages = [sample_message("uid-a"), sample_message("uid-b")];
        let deleted = [false, false];
        let mut resp = String::from("+OK\r\n");
        for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
            if !del {
                resp.push_str(&uidl_line(i + 1, &msg.aster_id));
            }
        }
        resp.push_str(".\r\n");
        assert_eq!(resp, "+OK\r\n1 uid-a\r\n2 uid-b\r\n.\r\n");
    }

    #[test]
    fn uidl_skips_deleted() {
        let messages = [sample_message("uid-a"), sample_message("uid-b")];
        let deleted = [true, false];
        let mut resp = String::from("+OK\r\n");
        for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
            if !del {
                resp.push_str(&uidl_line(i + 1, &msg.aster_id));
            }
        }
        resp.push_str(".\r\n");
        assert_eq!(resp, "+OK\r\n2 uid-b\r\n.\r\n");
    }

    #[test]
    fn uidl_line_keeps_a_hostile_id_on_one_line() {
        assert_eq!(uidl_line(3, "id\r\n+OK forged\0"), "3 id+OKforged\r\n");
        assert_eq!(uidl_line(4, "r\u{e9}sum\u{e9} \t1"), "4 rsum1\r\n");
    }

    #[test]
    fn list_line_format() {
        let messages = [sample_message("l-a")];
        let deleted = [false];
        let count = deleted.iter().filter(|d| !**d).count();
        let total: usize = messages.iter().zip(deleted.iter())
            .filter(|(_, d)| !*d)
            .map(|(m, _)| pop3_size(m, &[]))
            .sum();
        let mut resp = format!("+OK {} messages ({} octets)\r\n", count, total);
        for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
            if !del {
                resp.push_str(&format!("{} {}\r\n", i + 1, pop3_size(msg, &[])));
            }
        }
        resp.push_str(".\r\n");
        let expected_size = pop3_size(&messages[0], &[]);
        assert!(resp.starts_with(&format!("+OK 1 messages ({} octets)\r\n", expected_size)));
        assert!(resp.contains(&format!("1 {}\r\n", expected_size)));
    }

    #[test]
    fn stat_totals_exclude_deleted() {
        let messages = [sample_message("s-a"), sample_message("s-b")];
        let deleted = [false, true];
        let count = deleted.iter().filter(|d| !**d).count();
        let total_octets: usize = messages.iter().zip(deleted.iter())
            .filter(|(_, d)| !*d)
            .map(|(m, _)| pop3_size(m, &[]))
            .sum();
        assert_eq!(count, 1);
        assert_eq!(total_octets, pop3_size(&messages[0], &[]));
    }

    type BackendCalls = Arc<tokio::sync::Mutex<Vec<String>>>;

    async fn spawn_mock_backend() -> (String, BackendCalls) {
        use axum::extract::Path as AxumPath;
        use axum::{routing::delete, Json, Router};
        let calls: BackendCalls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let cap = calls.clone();
        let app = Router::new().route(
            "/mail/v1/messages/:id",
            delete(move |AxumPath(id): AxumPath<String>| {
                let cap = cap.clone();
                async move {
                    cap.lock().await.push(id);
                    Json(serde_json::json!({"success": true}))
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

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_is_closed_before_sign_in() {
        use crate::conn_limit::{test_support, PRE_AUTH_DEADLINE, PRE_AUTH_IDLE_TIMEOUT};
        let crate::sign_in_notice::test_support::Fixture { session, db, client, passwords, dir, .. } =
            crate::sign_in_notice::test_support::fixture();
        let started = tokio::time::Instant::now();
        let (mut reader, _writer) = test_support::connect(move |stream| {
            run_session(stream, session, db, client, passwords, None)
        });
        let (out, closed) = test_support::read_until_closed(&mut reader, PRE_AUTH_DEADLINE * 2).await;
        assert!(closed, "an idle connection held its slot: {:?}", out);
        assert!(out.ends_with("-ERR idle timeout\r\n"), "{:?}", out);
        assert!(started.elapsed() <= PRE_AUTH_IDLE_TIMEOUT + std::time::Duration::from_secs(1));
        drop(dir);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_reads_cannot_hold_a_slot_before_sign_in() {
        use crate::conn_limit::{test_support, PRE_AUTH_DEADLINE, PRE_AUTH_GRACE};
        let crate::sign_in_notice::test_support::Fixture { session, db, client, passwords, dir, .. } =
            crate::sign_in_notice::test_support::fixture();
        let started = tokio::time::Instant::now();
        let (finished, mut reader) = test_support::flood_without_reading(
            move |stream| run_session(stream, session, db, client, passwords, None),
            b"CAPA\r\n",
            PRE_AUTH_DEADLINE * 3,
        )
        .await;
        assert!(finished, "a client that never reads held its slot");
        assert!(
            started.elapsed()
                <= PRE_AUTH_DEADLINE + PRE_AUTH_GRACE + std::time::Duration::from_secs(1)
        );
        let (_, closed) =
            test_support::read_until_closed(&mut reader, std::time::Duration::from_secs(2)).await;
        assert!(closed);
        drop(dir);
    }

    #[tokio::test(start_paused = true)]
    async fn a_trickle_of_commands_cannot_outlast_the_pre_auth_deadline() {
        use crate::conn_limit::{test_support, PRE_AUTH_DEADLINE, PRE_AUTH_IDLE_TIMEOUT};
        use tokio::io::AsyncWriteExt;
        let crate::sign_in_notice::test_support::Fixture { session, db, client, passwords, dir, .. } =
            crate::sign_in_notice::test_support::fixture();
        let started = tokio::time::Instant::now();
        let (mut reader, mut writer) = test_support::connect(move |stream| {
            run_session(stream, session, db, client, passwords, None)
        });
        let step = PRE_AUTH_IDLE_TIMEOUT - std::time::Duration::from_secs(10);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(step).await;
                if writer.write_all(b"CAPA\r\n").await.is_err() {
                    break;
                }
            }
        });
        let (out, closed) = test_support::read_until_closed(&mut reader, PRE_AUTH_DEADLINE * 2).await;
        assert!(closed, "a trickling client held its slot: {:?}", out);
        assert!(out.contains("+OK Capability list follows"), "{:?}", out);
        assert!(out.ends_with("-ERR idle timeout\r\n"), "{:?}", out);
        assert!(started.elapsed() <= PRE_AUTH_DEADLINE + std::time::Duration::from_secs(1));
        drop(dir);
    }

    #[tokio::test]
    async fn a_resumed_session_after_stls_does_not_repeat_the_greeting() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[9u8; 32]).unwrap());
        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }));
        let client = Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:1"));

        let (client_side, server_side) = tokio::io::duplex(4096);
        let erased: Box<dyn AsyncReadWrite + Send + Unpin> = Box::new(server_side);
        let handle = tokio::spawn(run_session_erased(
            erased,
            session,
            db,
            client,
            passwords,
            crate::conn_limit::PreAuthClock::start(),
        ));

        let (client_read, mut client_write) = tokio::io::split(client_side);
        let mut reader = BufReader::new(client_read);
        let mut line = String::new();

        client_write.write_all(b"CAPA\r\n").await.unwrap();
        client_write.flush().await.unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(
            line.starts_with("+OK Capability list follows"),
            "a session resumed after STLS answered {:?} first, so every later reply is off by one",
            line
        );
        loop {
            let mut next = String::new();
            reader.read_line(&mut next).await.unwrap();
            line.push_str(&next);
            if next == ".\r\n" || next.is_empty() {
                break;
            }
        }
        assert_eq!(
            line,
            "+OK Capability list follows\r\nUSER\r\nUIDL\r\nTOP\r\nRESP-CODES\r\nEXPIRE NEVER\r\nIMPLEMENTATION Aster Bridge\r\n.\r\n",
            "a session resumed after STLS must list its capabilities once, without STLS"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn a_quit_reply_reaches_a_client_whose_writes_are_buffered() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[9u8; 32]).unwrap());
        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }));
        let client = Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:1"));

        let (client_side, server_side) = tokio::io::duplex(4096);
        let (server_read, server_write) = tokio::io::split(server_side);
        let buffered = tokio::io::join(server_read, tokio::io::BufWriter::new(server_write));
        let handle = tokio::spawn(run_session(buffered, session, db, client, passwords, None));

        let (client_read, mut client_write) = tokio::io::split(client_side);
        let mut reader = BufReader::new(client_read);
        let mut line = String::new();

        client_write.write_all(b"QUIT
").await.unwrap();
        client_write.flush().await.unwrap();

        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("+OK"), "greeting was {:?}", line);

        line.clear();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_line(&mut line),
        )
        .await
        .expect("the server never answered QUIT")
        .unwrap();
        assert!(
            read > 0 && line.starts_with("+OK"),
            "a client behind a buffering transport got {:?} instead of a goodbye, so it sees an unexplained disconnect",
            line
        );

        let _ = handle.await;
        drop(dir);
    }

    #[tokio::test]
    async fn closing_connections_drops_an_open_session() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
        use tokio::net::TcpStream;

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }));
        let client = Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:1"));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (trigger, shutdown) = crate::shutdown::channel();
        let listener_task = tokio::spawn(shutdown.scope(async move {
            let _ = serve_with_tls(listener, session, db, client, passwords, None).await;
        }));

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("+OK"), "greeting was {:?}", line);

        let mut rest = Vec::new();
        let still_open = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            reader.read_to_end(&mut rest),
        )
        .await;
        assert!(still_open.is_err(), "the session ended before connections were closed");

        trigger.close_connections();
        listener_task.abort();

        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_to_end(&mut rest),
        )
        .await;
        assert!(
            matches!(closed, Ok(Ok(_)) | Ok(Err(_))),
            "the session stayed open after connections were closed"
        );
        drop(dir);
    }

    #[tokio::test]
    async fn dele_quit_deletes_on_server_and_locally() {
        let _serial = AUTHENTICATED_SESSION_TESTS.lock().await;
        wait_for_maildrop_release().await;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
        db.upsert_cached_message(
            "pop-1",
            "inbox",
            Some("s"),
            Some("a@b.com"),
            Some("c@d.com"),
            Some("2026-01-01T00:00:00Z"),
            10,
            Some("body"),
            Some("{}"),
        )
        .unwrap();
        let _ = db.assign_uid_if_missing("inbox", "pop-1");

        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        let _ = passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }));
        let (base, calls) = spawn_mock_backend().await;
        let client = Arc::new(ApiClient::new_with_base_url(&base));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let db_clone = db.clone();
        tokio::spawn(async move {
            let _ = serve_with_tls(listener, session, db_clone, client, passwords, None).await;
        });
        for _ in 0..80 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("+OK"));

        for cmd in [
            "USER tester@aster.test",
            "PASS abcd-efgh-ijkl-mnop",
            "DELE 1",
        ] {
            w.write_all(format!("{}\r\n", cmd).as_bytes()).await.unwrap();
            w.flush().await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("+OK"), "{} failed: {}", cmd, line);
        }
        w.write_all(b"QUIT\r\n").await.unwrap();
        w.flush().await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("+OK"));

        for _ in 0..40 {
            if db.get_cached_message("pop-1").unwrap().is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(db.get_cached_message("pop-1").unwrap().is_none());
        assert_eq!(calls.lock().await.clone(), vec!["pop-1".to_string()]);
        wait_for_maildrop_release().await;
    }
}
