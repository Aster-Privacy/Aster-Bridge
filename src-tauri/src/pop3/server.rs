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
use crate::db::Database;
use crate::error::Result;
use crate::imap::server::build_rfc822;

const MAX_LINE_LENGTH: usize = 512;
const MAX_FAILED_AUTH: u32 = 5;

fn pop3_size(m: &crate::db::CachedMessage) -> usize {
    build_rfc822(m).len()
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
    loop {
        let (stream, peer) = listener.accept().await?;
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

        tokio::spawn(async move {
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

    loop {
        let (stream, peer) = listener.accept().await?;
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

        tokio::spawn(async move {
            let _permit = permit;
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("POP3S TLS handshake failed: {}", e);
                    return;
                }
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
) -> Result<()> {
    run_session(stream, session, db, client, passwords, None).await
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
    let stls_capable = tls_config.is_some();
    let (read_half, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    writer.write_all(b"+OK Aster Bridge POP3 ready\r\n").await?;

    let mut authenticated = false;
    let mut user_received = false;
    let mut messages: Vec<crate::db::CachedMessage> = Vec::new();
    let mut deleted: Vec<bool> = Vec::new();
    let mut line = String::new();
    let mut failed_auth: u32 = 0;
    let mut _session_lock: Option<Pop3SessionLock> = None;

    loop {
        writer.flush().await?;
        line.clear();
        let n = match read_pop3_line(&mut reader, &mut line).await {
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
                        writer.write_all(b"-ERR [PRIVACYREQUIRED] STLS required before USER\r\n").await?;
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
                    let tls_stream = acceptor
                        .accept(rejoined)
                        .await
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                    let erased: Box<dyn AsyncReadWrite + Send + Unpin> = Box::new(tls_stream);
                    return Box::pin(run_session_erased(erased, session, db, client, passwords)).await;
                }
                "PASS" => {
                    if stls_capable {
                        writer.write_all(b"-ERR [PRIVACYREQUIRED] STLS required before PASS\r\n").await?;
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
                        messages = db.list_cached_message_meta("inbox").unwrap_or_default();
                        deleted = vec![false; messages.len()];
                        authenticated = true;
                        writer.write_all(b"+OK maildrop ready\r\n").await?;
                    } else {
                        failed_auth += 1;
                        if failed_auth >= MAX_FAILED_AUTH {
                            writer.write_all(b"-ERR too many failed attempts\r\n").await?;
                            break;
                        }
                        writer.write_all(b"-ERR invalid credentials\r\n").await?;
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
                    .map(|(m, _)| pop3_size(m))
                    .sum();
                writer.write_all(format!("+OK {} {}\r\n", count, total_octets).as_bytes()).await?;
            }
            "LIST" => {
                if args.is_empty() {
                    let count = deleted.iter().filter(|d| !**d).count();
                    let total: usize = messages.iter().zip(deleted.iter())
                        .filter(|(_, d)| !*d)
                        .map(|(m, _)| pop3_size(m))
                        .sum();
                    let mut resp = format!("+OK {} messages ({} octets)\r\n", count, total);
                    for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
                        if !del {
                            resp.push_str(&format!("{} {}\r\n", i + 1, pop3_size(msg)));
                        }
                    }
                    resp.push_str(".\r\n");
                    writer.write_all(resp.as_bytes()).await?;
                } else if let Ok(n) = args.parse::<usize>() {
                    if n == 0 || n > messages.len() || deleted[n - 1] {
                        writer.write_all(b"-ERR no such message\r\n").await?;
                    } else {
                        writer.write_all(format!("+OK {} {}\r\n", n, pop3_size(&messages[n - 1])).as_bytes()).await?;
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
                            resp.push_str(&format!("{} {}\r\n", i + 1, msg.aster_id));
                        }
                    }
                    resp.push_str(".\r\n");
                    writer.write_all(resp.as_bytes()).await?;
                } else if let Ok(n) = args.parse::<usize>() {
                    if n == 0 || n > messages.len() || deleted[n - 1] {
                        writer.write_all(b"-ERR no such message\r\n").await?;
                    } else {
                        writer.write_all(format!("+OK {} {}\r\n", n, messages[n - 1].aster_id).as_bytes()).await?;
                    }
                } else {
                    writer.write_all(b"-ERR syntax error\r\n").await?;
                }
            }
            "RETR" => {
                if let Ok(n) = args.parse::<usize>() {
                    if n == 0 || n > messages.len() || deleted[n - 1] {
                        writer.write_all(b"-ERR no such message\r\n").await?;
                    } else if let Some(full) =
                        db.get_cached_message(&messages[n - 1].aster_id).ok().flatten()
                    {
                        let rfc = build_rfc822(&full);
                        let mut dot_stuffed = String::with_capacity(rfc.len() + 64);
                        let lines: Vec<&str> = rfc.split("\r\n").collect();
                        let content_lines = if lines.last().map(|l| l.is_empty()).unwrap_or(false) {
                            &lines[..lines.len() - 1]
                        } else {
                            &lines[..]
                        };
                        for rline in content_lines {
                            if rline.starts_with('.') {
                                dot_stuffed.push('.');
                            }
                            dot_stuffed.push_str(rline);
                            dot_stuffed.push_str("\r\n");
                        }
                        writer.write_all(format!("+OK {} octets\r\n", rfc.len()).as_bytes()).await?;
                        writer.write_all(dot_stuffed.as_bytes()).await?;
                        writer.write_all(b".\r\n").await?;
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
                if let Some(full) = full_top {
                    let rfc = build_rfc822(&full);
                    let sep = rfc.find("\r\n\r\n").map(|p| p + 2).unwrap_or(rfc.len());
                    let header_str = &rfc[..sep];
                    let body = rfc.get(sep + 2..).unwrap_or("");
                    writer.write_all(b"+OK\r\n").await?;
                    for hline in header_str.split("\r\n") {
                        if hline.starts_with('.') {
                            writer.write_all(b".").await?;
                        }
                        writer.write_all(hline.as_bytes()).await?;
                        writer.write_all(b"\r\n").await?;
                    }
                    writer.write_all(b"\r\n").await?;
                    let body_lines: Vec<&str> = body.split("\r\n").collect();
                    let body_content = if body_lines.last().map(|l| l.is_empty()).unwrap_or(false) {
                        &body_lines[..body_lines.len() - 1]
                    } else {
                        &body_lines[..]
                    };
                    for (i, bline) in body_content.iter().enumerate() {
                        if i >= line_count {
                            break;
                        }
                        if bline.starts_with('.') {
                            writer.write_all(b".").await?;
                        }
                        writer.write_all(bline.as_bytes()).await?;
                        writer.write_all(b"\r\n").await?;
                    }
                    writer.write_all(b".\r\n").await?;
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
    }

    #[test]
    fn pop3_size_equals_build_rfc822_len() {
        let m = sample_message("id-1");
        let expected = build_rfc822(&m).len();
        assert_eq!(pop3_size(&m), expected);
    }

    #[test]
    fn pop3_size_ignores_stored_size_field() {
        let mut m = sample_message("id-2");
        let baseline = pop3_size(&m);
        m.size = 123456789;
        assert_eq!(pop3_size(&m), baseline);
        assert_ne!(pop3_size(&m), m.size as usize);
    }

    #[test]
    fn pop3_size_is_nonzero_for_real_message() {
        let m = sample_message("id-3");
        assert!(pop3_size(&m) > 0);
    }

    #[test]
    fn rfc822_contains_expected_headers() {
        let m = sample_message("id-4");
        let rfc = build_rfc822(&m);
        assert!(rfc.contains("Subject: Test Subject"));
        assert!(rfc.contains("From: sender@aster.test"));
        assert!(rfc.contains("\r\n\r\n"));
    }

    #[test]
    fn top_split_with_separator() {
        let m = sample_message("id-5");
        let rfc = build_rfc822(&m);
        let sep = rfc.find("\r\n\r\n").map(|p| p + 2).unwrap_or(rfc.len());
        let header_str = &rfc[..sep];
        let body = rfc.get(sep + 2..).unwrap_or("");
        assert!(header_str.contains("From:"));
        assert!(body.contains("line one"));
    }

    #[test]
    fn top_split_no_separator_does_not_panic() {
        let rfc = "Header-Only: yes\r\nNo-Body-Here: true";
        let sep = rfc.find("\r\n\r\n").map(|p| p + 2).unwrap_or(rfc.len());
        let header_str = &rfc[..sep];
        let body = rfc.get(sep + 2..).unwrap_or("");
        assert_eq!(header_str, rfc);
        assert_eq!(body, "");
    }

    #[test]
    fn top_split_empty_string_does_not_panic() {
        let rfc = "";
        let sep = rfc.find("\r\n\r\n").map(|p| p + 2).unwrap_or(rfc.len());
        let header_str = &rfc[..sep];
        let body = rfc.get(sep + 2..).unwrap_or("");
        assert_eq!(header_str, "");
        assert_eq!(body, "");
    }

    #[test]
    fn dot_stuffing_prefixes_leading_dot_lines() {
        let rfc = ".secret\r\nnormal\r\n..double\r\n";
        let mut dot_stuffed = String::new();
        let lines: Vec<&str> = rfc.split("\r\n").collect();
        let content_lines = if lines.last().map(|l| l.is_empty()).unwrap_or(false) {
            &lines[..lines.len() - 1]
        } else {
            &lines[..]
        };
        for rline in content_lines {
            if rline.starts_with('.') {
                dot_stuffed.push('.');
            }
            dot_stuffed.push_str(rline);
            dot_stuffed.push_str("\r\n");
        }
        assert!(dot_stuffed.starts_with("..secret\r\n"));
        assert!(dot_stuffed.contains("normal\r\n"));
        assert!(dot_stuffed.contains("...double\r\n"));
    }

    #[test]
    fn dot_stuffing_leaves_normal_lines_untouched() {
        let rfc = "plain line\r\nanother\r\n";
        let mut dot_stuffed = String::new();
        let lines: Vec<&str> = rfc.split("\r\n").collect();
        let content_lines = if lines.last().map(|l| l.is_empty()).unwrap_or(false) {
            &lines[..lines.len() - 1]
        } else {
            &lines[..]
        };
        for rline in content_lines {
            if rline.starts_with('.') {
                dot_stuffed.push('.');
            }
            dot_stuffed.push_str(rline);
            dot_stuffed.push_str("\r\n");
        }
        assert_eq!(dot_stuffed, "plain line\r\nanother\r\n");
    }

    #[test]
    fn uidl_line_format() {
        let messages = vec![sample_message("uid-a"), sample_message("uid-b")];
        let deleted = vec![false, false];
        let mut resp = String::from("+OK\r\n");
        for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
            if !del {
                resp.push_str(&format!("{} {}\r\n", i + 1, msg.aster_id));
            }
        }
        resp.push_str(".\r\n");
        assert_eq!(resp, "+OK\r\n1 uid-a\r\n2 uid-b\r\n.\r\n");
    }

    #[test]
    fn uidl_skips_deleted() {
        let messages = vec![sample_message("uid-a"), sample_message("uid-b")];
        let deleted = vec![true, false];
        let mut resp = String::from("+OK\r\n");
        for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
            if !del {
                resp.push_str(&format!("{} {}\r\n", i + 1, msg.aster_id));
            }
        }
        resp.push_str(".\r\n");
        assert_eq!(resp, "+OK\r\n2 uid-b\r\n.\r\n");
    }

    #[test]
    fn list_line_format() {
        let messages = vec![sample_message("l-a")];
        let deleted = vec![false];
        let count = deleted.iter().filter(|d| !**d).count();
        let total: usize = messages.iter().zip(deleted.iter())
            .filter(|(_, d)| !*d)
            .map(|(m, _)| pop3_size(m))
            .sum();
        let mut resp = format!("+OK {} messages ({} octets)\r\n", count, total);
        for (i, (msg, del)) in messages.iter().zip(deleted.iter()).enumerate() {
            if !del {
                resp.push_str(&format!("{} {}\r\n", i + 1, pop3_size(msg)));
            }
        }
        resp.push_str(".\r\n");
        let expected_size = pop3_size(&messages[0]);
        assert!(resp.starts_with(&format!("+OK 1 messages ({} octets)\r\n", expected_size)));
        assert!(resp.contains(&format!("1 {}\r\n", expected_size)));
    }

    #[test]
    fn stat_totals_exclude_deleted() {
        let messages = vec![sample_message("s-a"), sample_message("s-b")];
        let deleted = vec![false, true];
        let count = deleted.iter().filter(|d| !**d).count();
        let total_octets: usize = messages.iter().zip(deleted.iter())
            .filter(|(_, d)| !*d)
            .map(|(m, _)| pop3_size(m))
            .sum();
        assert_eq!(count, 1);
        assert_eq!(total_octets, pop3_size(&messages[0]));
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

    #[tokio::test]
    async fn dele_quit_deletes_on_server_and_locally() {
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
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
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
    }
}
