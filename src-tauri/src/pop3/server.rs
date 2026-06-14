//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

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
    _session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    passwords: Arc<AppPasswords>,
    _tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let sock_addr: std::net::SocketAddr = addr.parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true).ok();
    socket.bind(sock_addr)?;
    let listener = socket.listen(1024)?;
    tracing::info!("POP3 server listening on {}", addr);

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

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = run_session(stream, db, passwords).await {
                tracing::error!("POP3 connection error: {}", e);
            }
        });
    }
}

pub async fn run_implicit_tls(
    addr: &str,
    _session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    passwords: Arc<AppPasswords>,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let sock_addr: std::net::SocketAddr = addr.parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true).ok();
    socket.bind(sock_addr)?;
    let listener = socket.listen(1024)?;
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
            if let Err(e) = run_session(tls_stream, db, passwords).await {
                tracing::error!("POP3S connection error: {}", e);
            }
        });
    }
}

async fn run_session<S>(
    stream: S,
    db: Arc<Database>,
    passwords: Arc<AppPasswords>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
                    user_received = true;
                    writer.write_all(b"+OK user accepted\r\n").await?;
                }
                "PASS" => {
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
                    writer.write_all(b"+OK Capability list follows\r\nUSER\r\nUIDL\r\nTOP\r\nRESP-CODES\r\nEXPIRE NEVER\r\nIMPLEMENTATION Aster Bridge\r\n.\r\n").await?;
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
                for (i, del) in deleted.iter().enumerate() {
                    if *del {
                        if let Some(msg) = messages.get(i) {
                            let _ = db.delete_message_by_aster_id(&msg.aster_id);
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
