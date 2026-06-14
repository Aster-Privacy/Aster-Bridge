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
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use tokio::sync::RwLock;

use crate::api_client::ApiClient;
use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;
use crate::db::Database;
use crate::error::{BridgeError, Result};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

pub fn is_transient_send_error(err: &BridgeError) -> bool {
    match err {
        BridgeError::Network(_) | BridgeError::Io(_) => true,
        BridgeError::Api(msg) => {
            for code in ["408", "429", "500", "502", "503", "504"] {
                if msg.starts_with(code) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

const MAX_LINE_LENGTH: usize = 998;
const MAX_DATA_LINE_LENGTH: usize = 1_000_000;
const MAX_DATA_SIZE: usize = 25 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 100;
const MAX_FAILED_AUTH: u32 = 5;

async fn read_line_bytes<R>(reader: &mut R, out: &mut Vec<u8>, cap: usize) -> std::io::Result<usize>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    out.clear();
    loop {
        let avail = reader.fill_buf().await?;
        if avail.is_empty() {
            return Ok(out.len());
        }
        let (slice_end, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        let take_n = slice_end.min(cap.saturating_sub(out.len()) + 1);
        out.extend_from_slice(&avail[..take_n]);
        tokio::io::AsyncBufReadExt::consume(reader, take_n);
        if out.len() > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
        if done {
            return Ok(out.len());
        }
    }
}

fn find_ci_prefix(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    for i in 0..=(h.len() - n.len()) {
        if h[i..i + n.len()]
            .iter()
            .zip(n.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
    }
    None
}

fn extract_addr(s: &str) -> String {
    let trimmed = s.trim();
    if let (Some(lt), Some(gt)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if gt > lt {
            return trimmed[lt + 1..gt].trim().to_string();
        }
    }
    trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(&['<', '>'][..])
        .to_string()
}

#[derive(Debug, PartialEq)]
enum SmtpState {
    Connected,
    Greeted,
    Authenticated,
    MailFrom,
    RcptTo,
    Data,
}

struct SmtpSession {
    state: SmtpState,
    authenticated: bool,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_buffer: Vec<u8>,
}

pub async fn run(
    addr: &str,
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    db: Arc<Database>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let sock_addr: std::net::SocketAddr = addr.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true).ok();
    socket.bind(sock_addr)?;
    let listener = socket.listen(1024)?;
    tracing::info!("SMTP server listening on {} (STARTTLS={})", addr, tls_config.is_some());

    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!("SMTP rejected non-loopback peer {}", peer);
            drop(stream);
            continue;
        }
        let permit = match crate::conn_limit::try_acquire_connection(crate::conn_limit::Protocol::Smtp) {
            Some(p) => p,
            None => {
                tracing::warn!("SMTP connection limit reached, dropping {}", peer);
                drop(stream);
                continue;
            }
        };
        tracing::debug!("SMTP connection from {}", peer);

        let session = session.clone();
        let client = client.clone();
        let passwords = passwords.clone();
        let db = db.clone();
        let tls_config = tls_config.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_session(stream, session, client, passwords, db, tls_config, true).await {
                tracing::error!("SMTP connection error: {}", e);
            }
        });
    }
}

pub async fn run_implicit_tls(
    addr: &str,
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    db: Arc<Database>,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let sock_addr: std::net::SocketAddr = addr.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true).ok();
    socket.bind(sock_addr)?;
    let listener = socket.listen(1024)?;
    tracing::info!("SMTPS (implicit TLS) listening on {}", addr);

    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!("SMTPS rejected non-loopback peer {}", peer);
            drop(stream);
            continue;
        }
        let permit = match crate::conn_limit::try_acquire_connection(crate::conn_limit::Protocol::Smtp) {
            Some(p) => p,
            None => {
                tracing::warn!("SMTPS connection limit reached, dropping {}", peer);
                drop(stream);
                continue;
            }
        };
        let session = session.clone();
        let client = client.clone();
        let passwords = passwords.clone();
        let db = db.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("SMTPS TLS handshake failed: {}", e);
                    return;
                }
            };
            if let Err(e) = handle_session(tls_stream, session, client, passwords, db, None, true).await {
                tracing::error!("SMTPS connection error: {}", e);
            }
        });
    }
}

async fn handle_session_erased(
    stream: Box<dyn AsyncReadWrite + Send + Unpin>,
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    db: Arc<Database>,
) -> Result<()> {
    handle_session(stream, session, client, passwords, db, None, false).await
}

async fn handle_session<S>(
    stream: S,
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    db: Arc<Database>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    greet: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let starttls_capable = tls_config.is_some();

    if greet {
        writer
            .write_all(b"220 Aster Bridge SMTP ready\r\n")
            .await?;
    }

    let mut smtp = SmtpSession {
        state: SmtpState::Connected,
        authenticated: false,
        mail_from: None,
        rcpt_to: Vec::new(),
        data_buffer: Vec::new(),
    };
    let mut failed_auth: u32 = 0;

    let mut line_bytes: Vec<u8> = Vec::new();

    loop {
        let in_data = smtp.state == SmtpState::Data;
        let cap = if in_data { MAX_DATA_LINE_LENGTH } else { MAX_LINE_LENGTH };
        let n = match read_line_bytes(&mut reader, &mut line_bytes, cap).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                writer.write_all(b"500 Line too long\r\n").await?;
                break;
            }
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }

        if smtp.state == SmtpState::Data {
            let mut bytes = &line_bytes[..];
            while bytes.last() == Some(&b'\r') || bytes.last() == Some(&b'\n') {
                bytes = &bytes[..bytes.len() - 1];
            }
            if bytes == b"." {
                let raw_message = std::mem::take(&mut smtp.data_buffer);

                let header_section = {
                    let end = raw_message
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .unwrap_or(raw_message.len());
                    std::str::from_utf8(&raw_message[..end]).unwrap_or("").to_ascii_lowercase()
                };
                let is_pgp_mime = header_section.contains("content-type: multipart/encrypted")
                    && header_section.contains("application/pgp-encrypted");
                if is_pgp_mime {
                    smtp.state = SmtpState::Authenticated;
                    smtp.mail_from = None;
                    smtp.rcpt_to.clear();
                    writer.write_all(b"550 5.7.0 OpenPGP/MIME messages are not supported; Aster uses built-in end-to-end encryption\r\n").await?;
                    continue;
                }

                match send_via_api(&session, &client, &smtp.mail_from, &smtp.rcpt_to, &raw_message)
                    .await
                {
                    Ok(()) => {
                        writer
                            .write_all(b"250 OK Message accepted\r\n")
                            .await?;
                    }
                    Err(e) => {
                        if is_transient_send_error(&e) {
                            let envelope_from = smtp
                                .mail_from
                                .clone()
                                .unwrap_or_else(|| String::new());
                            let envelope_to = smtp.rcpt_to.join(",");
                            match db.outbox_insert(&raw_message, &envelope_from, &envelope_to) {
                                Ok(id) => {
                                    tracing::warn!(
                                        "SMTP send transient failure, queued to outbox id={}: {}",
                                        id,
                                        e
                                    );
                                    writer
                                        .write_all(b"250 OK queued\r\n")
                                        .await?;
                                }
                                Err(qe) => {
                                    tracing::error!("Failed to enqueue outbox: {}", qe);
                                    writer
                                        .write_all(b"451 Temporary failure, please retry\r\n")
                                        .await?;
                                }
                            }
                        } else {
                            let smtp_reply = match &e {
                                BridgeError::PlanUpgradeRequired(_) => {
                                    b"550 5.7.1 Plan upgrade required to send via Aster Bridge\r\n"
                                        as &[u8]
                                }
                                _ => b"550 Send rejected\r\n",
                            };
                            tracing::error!("Failed to send mail via API: {}", e);
                            let log_line = format!(
                                "[{}] {}\n",
                                chrono::Utc::now().to_rfc3339(),
                                crate::diagnostics::redact_line(&format!("SMTP send failed: {}", e))
                            );
                            if let Some(dir) = dirs::data_local_dir() {
                                let path = dir.join("com.astermail.bridge").join("smtp_errors.log");
                                let _ = std::fs::create_dir_all(path.parent().unwrap());
                                const MAX_LOG_BYTES: u64 = 1_048_576;
                                if let Ok(meta) = std::fs::metadata(&path) {
                                    if meta.len() > MAX_LOG_BYTES {
                                        let rotated = dir
                                            .join("com.astermail.bridge")
                                            .join("smtp_errors.log.1");
                                        let _ = std::fs::rename(&path, &rotated);
                                    }
                                }
                                let _ = std::fs::OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(&path)
                                    .and_then(|mut f| std::io::Write::write_all(&mut f, log_line.as_bytes()));
                            }
                            writer.write_all(smtp_reply).await?;
                        }
                    }
                }
                smtp.state = SmtpState::Authenticated;
                smtp.mail_from = None;
                smtp.rcpt_to.clear();
            } else {
                let data_line: &[u8] = if let Some(stripped) = bytes.strip_prefix(b".") {
                    stripped
                } else {
                    bytes
                };
                let addition = data_line.len() + 2;
                if smtp.data_buffer.len() + addition > MAX_DATA_SIZE {
                    smtp.data_buffer.clear();
                    loop {
                        let dn = read_line_bytes(&mut reader, &mut line_bytes, MAX_DATA_LINE_LENGTH).await.unwrap_or(0);
                        if dn == 0 { break; }
                        let dl: &[u8] = &line_bytes[..];
                        let dl = if dl.last() == Some(&b'\n') { &dl[..dl.len()-1] } else { dl };
                        let dl = if dl.last() == Some(&b'\r') { &dl[..dl.len()-1] } else { dl };
                        if dl == b"." { break; }
                    }
                    smtp.state = SmtpState::Authenticated;
                    writer.write_all(b"552 Message exceeds maximum size\r\n").await?;
                    continue;
                }
                smtp.data_buffer.extend_from_slice(data_line);
                smtp.data_buffer.extend_from_slice(b"\r\n");
            }
            continue;
        }

        let line = String::from_utf8_lossy(&line_bytes).into_owned();
        let trimmed = line.trim_end().to_string();

        let (cmd, args) = if let Some(pos) = trimmed.find(' ') {
            (&trimmed[..pos], trimmed[pos + 1..].to_string())
        } else {
            (trimmed.as_str(), String::new())
        };

        match cmd.to_uppercase().as_str() {
            "EHLO" | "HELO" => {
                smtp.state = SmtpState::Greeted;
                smtp.mail_from = None;
                smtp.rcpt_to.clear();
                smtp.data_buffer.clear();
                if cmd.to_uppercase() == "HELO" {
                    writer.write_all(b"250 Aster Bridge\r\n").await?;
                } else {
                    writer.write_all(b"250-Aster Bridge\r\n").await?;
                    writer.write_all(b"250-AUTH PLAIN LOGIN\r\n").await?;
                    if starttls_capable {
                        writer.write_all(b"250-STARTTLS\r\n").await?;
                    }
                    writer.write_all(b"250-8BITMIME\r\n").await?;
                    writer
                        .write_all(format!("250 SIZE {}\r\n", MAX_DATA_SIZE).as_bytes())
                        .await?;
                }
            }
            "STARTTLS" => {
                if smtp.authenticated {
                    writer.write_all(b"503 Bad sequence of commands\r\n").await?;
                    continue;
                }
                let cfg = match tls_config.as_ref() {
                    Some(c) => c.clone(),
                    None => {
                        writer.write_all(b"454 STARTTLS not available\r\n").await?;
                        continue;
                    }
                };
                writer.write_all(b"220 Ready to start TLS\r\n").await?;
                writer.flush().await?;
                let upgraded_session = session.clone();
                let upgraded_client = client.clone();
                let upgraded_passwords = passwords.clone();
                let upgraded_db = db.clone();
                let rejoined = tokio::io::join(reader.into_inner(), writer);
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                let tls_stream = acceptor
                    .accept(rejoined)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let erased: Box<dyn AsyncReadWrite + Send + Unpin> = Box::new(tls_stream);
                return Box::pin(handle_session_erased(
                    erased,
                    upgraded_session,
                    upgraded_client,
                    upgraded_passwords,
                    upgraded_db,
                ))
                .await;
            }
            "AUTH" => {
                if smtp.state != SmtpState::Greeted {
                    writer.write_all(b"503 Bad sequence\r\n").await?;
                    continue;
                }
                if starttls_capable {
                    writer.write_all(b"538 5.7.11 Encryption required for requested authentication mechanism\r\n").await?;
                    continue;
                }

                let auth_parts: Vec<&str> = args.splitn(2, ' ').collect();
                let auth_type = auth_parts.first().copied().unwrap_or("");

                let password_str: Option<String> = if auth_type.eq_ignore_ascii_case("PLAIN") {
                    let credentials = if auth_parts.len() > 1 {
                        auth_parts[1].to_string()
                    } else {
                        writer.write_all(b"334 \r\n").await?;
                        let mut cont = Vec::new();
                        if read_line_bytes(&mut reader, &mut cont, MAX_LINE_LENGTH).await.unwrap_or(0) == 0 {
                            break;
                        }
                        std::str::from_utf8(&cont).unwrap_or("").trim_end().to_string()
                    };
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &credentials)
                        .ok()
                        .and_then(|decoded| {
                            let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
                            let pw_bytes = if parts.len() >= 3 { parts[2] } else if parts.len() == 2 { parts[1] } else { return None; };
                            Some(String::from_utf8_lossy(pw_bytes).into_owned())
                        })
                } else if auth_type.eq_ignore_ascii_case("LOGIN") {
                    writer.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
                    let mut line = Vec::new();
                    if read_line_bytes(&mut reader, &mut line, MAX_LINE_LENGTH).await.unwrap_or(0) == 0 { break; }
                    writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
                    let mut pw_line = Vec::new();
                    if read_line_bytes(&mut reader, &mut pw_line, MAX_LINE_LENGTH).await.unwrap_or(0) == 0 { break; }
                    let pw_b64 = std::str::from_utf8(&pw_line).unwrap_or("").trim_end();
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pw_b64)
                        .ok()
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                } else {
                    writer.write_all(b"504 Unrecognized auth type\r\n").await?;
                    continue;
                };

                let mut ok = false;
                if let Some(password) = password_str {
                    if let Some(pw_id) = passwords.verify_and_id_async(&password).await {
                        smtp.authenticated = true;
                        smtp.state = SmtpState::Authenticated;
                        passwords.record_use(&pw_id, Some("smtp"));
                        writer.write_all(b"235 Authentication successful\r\n").await?;
                        ok = true;
                    }
                }

                if !ok {
                    failed_auth = failed_auth.saturating_add(1);
                    let backoff_ms = 200u64.saturating_mul(1u64 << failed_auth.min(5));
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    writer
                        .write_all(b"535 Authentication failed\r\n")
                        .await?;
                    if failed_auth >= MAX_FAILED_AUTH {
                        writer
                            .write_all(b"421 Too many failed attempts\r\n")
                            .await?;
                        break;
                    }
                }
            }
            "MAIL" => {
                if !smtp.authenticated {
                    writer
                        .write_all(b"530 Authentication required\r\n")
                        .await?;
                    continue;
                }

                if let Some(start) = find_ci_prefix(&args, "FROM:") {
                    let from_addr = extract_addr(&args[start + 5..]);
                    let session_email = {
                        let s = session.read().await;
                        s.email.clone()
                    };
                    let resolved = if from_addr.is_empty() {
                        session_email.clone()
                    } else {
                        from_addr.clone()
                    };
                    if !resolved.eq_ignore_ascii_case(&session_email) {
                        writer.write_all(b"553 5.1.8 Sender address rejected: not authenticated identity\r\n").await?;
                        continue;
                    }
                    smtp.mail_from = Some(resolved);
                    smtp.state = SmtpState::MailFrom;
                    writer.write_all(b"250 OK\r\n").await?;
                } else {
                    writer.write_all(b"501 Syntax error\r\n").await?;
                }
            }
            "RCPT" => {
                if smtp.state != SmtpState::MailFrom && smtp.state != SmtpState::RcptTo {
                    writer.write_all(b"503 Bad sequence\r\n").await?;
                    continue;
                }

                if smtp.rcpt_to.len() >= MAX_RECIPIENTS {
                    writer
                        .write_all(b"452 Too many recipients\r\n")
                        .await?;
                    continue;
                }

                if let Some(start) = find_ci_prefix(&args, "TO:") {
                    let to_addr = extract_addr(&args[start + 3..]);
                    if to_addr.is_empty() {
                        writer.write_all(b"501 Empty recipient\r\n").await?;
                        continue;
                    }
                    smtp.rcpt_to.push(to_addr);
                    smtp.state = SmtpState::RcptTo;
                    writer.write_all(b"250 OK\r\n").await?;
                } else {
                    writer.write_all(b"501 Syntax error\r\n").await?;
                }
            }
            "DATA" => {
                if smtp.state != SmtpState::RcptTo {
                    writer.write_all(b"503 Bad sequence\r\n").await?;
                    continue;
                }

                smtp.state = SmtpState::Data;
                smtp.data_buffer.clear();
                writer
                    .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    .await?;
            }
            "RSET" => {
                smtp.mail_from = None;
                smtp.rcpt_to.clear();
                smtp.data_buffer.clear();
                if smtp.authenticated {
                    smtp.state = SmtpState::Authenticated;
                } else {
                    smtp.state = SmtpState::Greeted;
                }
                writer.write_all(b"250 OK\r\n").await?;
            }
            "QUIT" => {
                writer.write_all(b"221 Bye\r\n").await?;
                break;
            }
            _ => {
                writer
                    .write_all(b"502 Command not implemented\r\n")
                    .await?;
            }
        }
    }

    Ok(())
}

pub fn build_send_payload(
    raw_message: &[u8],
    from: Option<&str>,
    recipients: &[String],
    session_email: &str,
) -> std::result::Result<serde_json::Value, crate::error::BridgeError> {
    use mail_parser::MessageParser;

    let parsed = MessageParser::default()
        .parse(raw_message)
        .ok_or_else(|| crate::error::BridgeError::Smtp("failed to parse outbound message".to_string()))?;

    let envelope_from = from.unwrap_or(session_email);
    if let Some(from_addrs) = parsed.from() {
        for a in from_addrs.iter() {
            if let Some(addr) = a.address() {
                let matches_session = addr.eq_ignore_ascii_case(session_email);
                let matches_envelope = addr.eq_ignore_ascii_case(envelope_from);
                if !matches_session && !matches_envelope {
                    tracing::debug!("from-header mismatch with session/envelope");
                }
            }
        }
    }

    let subject = parsed.subject().unwrap_or("").to_string();

    let header_to: Vec<String> = parsed
        .to()
        .map(|a| a.iter().filter_map(|x| x.address().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let header_cc: Vec<String> = parsed
        .cc()
        .map(|a| a.iter().filter_map(|x| x.address().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let header_bcc: Vec<String> = parsed
        .bcc()
        .map(|a| a.iter().filter_map(|x| x.address().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let to_list = header_to.clone();
    let cc_list = header_cc.clone();
    let mut bcc_list = header_bcc.clone();

    let known: std::collections::HashSet<String> = to_list
        .iter()
        .chain(cc_list.iter())
        .chain(bcc_list.iter())
        .map(|s| s.to_lowercase())
        .collect();

    for envelope_rcpt in recipients {
        if !known.contains(&envelope_rcpt.to_lowercase()) {
            bcc_list.push(envelope_rcpt.clone());
        }
    }

    if to_list.is_empty() && cc_list.is_empty() && bcc_list.is_empty() {
        for envelope_rcpt in recipients {
            bcc_list.push(envelope_rcpt.clone());
        }
    }

    let effective_to = if to_list.is_empty() {
        recipients.to_vec()
    } else {
        to_list
    };

    let body_html = parsed.body_html(0).map(|s| s.to_string());
    let body_plain = parsed.body_text(0).map(|s| s.to_string());
    let is_html = body_html.is_some();
    let body = body_html.as_deref()
        .or(body_plain.as_deref())
        .unwrap_or(" ")
        .to_string();

    let final_body = if body.trim().is_empty() {
        " ".to_string()
    } else {
        body
    };

    let sender_email = from.filter(|s| !s.is_empty()).map(|s| s.to_string());

    let mut payload = serde_json::json!({
        "to": effective_to,
        "cc": if cc_list.is_empty() { serde_json::Value::Null } else { serde_json::json!(cc_list) },
        "bcc": if bcc_list.is_empty() { serde_json::Value::Null } else { serde_json::json!(bcc_list) },
        "subject": subject,
        "body": final_body,
        "is_html": is_html,
        "is_e2e_encrypted": false,
        "sender_email": sender_email,
        "client_source": "bridge",
    });

    if let Some(html) = body_html {
        payload["body_html"] = serde_json::json!(html);
    }

    Ok(payload)
}

async fn send_via_api(
    session: &Arc<RwLock<Session>>,
    client: &Arc<ApiClient>,
    from: &Option<String>,
    recipients: &[String],
    raw_message: &[u8],
) -> std::result::Result<(), crate::error::BridgeError> {
    let session_email = {
        let s = session.read().await;
        s.email.clone()
    };
    let payload = build_send_payload(raw_message, from.as_deref(), recipients, &session_email)?;
    let access_token = {
        let s = session.read().await;
        s.access_token.clone()
    };
    client.send_mail(&access_token, &payload).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_err() -> BridgeError {
        BridgeError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset"))
    }

    #[test]
    fn io_errors_are_transient() {
        assert!(is_transient_send_error(&io_err()));
    }

    #[test]
    fn server_5xx_codes_are_transient() {
        for code in ["500", "502", "503", "504"] {
            let e = BridgeError::Api(format!("{} upstream broke", code));
            assert!(is_transient_send_error(&e), "{} should be transient", code);
        }
    }

    #[test]
    fn timeout_and_rate_limit_are_transient() {
        assert!(is_transient_send_error(&BridgeError::Api("408 request timeout".into())));
        assert!(is_transient_send_error(&BridgeError::Api("429 too many requests".into())));
    }

    #[test]
    fn unauthorized_401_is_permanent() {
        let e = BridgeError::Api("401 unauthorized".into());
        assert!(!is_transient_send_error(&e));
    }

    #[test]
    fn other_4xx_codes_are_permanent() {
        for code in ["400", "403", "404", "422"] {
            let e = BridgeError::Api(format!("{} client error", code));
            assert!(!is_transient_send_error(&e), "{} should be permanent", code);
        }
    }

    #[test]
    fn non_api_non_io_errors_are_permanent() {
        assert!(!is_transient_send_error(&BridgeError::Auth("nope".into())));
        assert!(!is_transient_send_error(&BridgeError::Smtp("bad".into())));
        assert!(!is_transient_send_error(&BridgeError::PlanUpgradeRequired("upgrade".into())));
        assert!(!is_transient_send_error(&BridgeError::PlanLimit("limit".into())));
        assert!(!is_transient_send_error(&BridgeError::Crypto("x".into())));
        assert!(!is_transient_send_error(&BridgeError::Database("x".into())));
        assert!(!is_transient_send_error(&BridgeError::Config("x".into())));
    }

    #[test]
    fn api_code_must_be_a_prefix_not_substring() {
        let e = BridgeError::Api("error 500 happened".into());
        assert!(!is_transient_send_error(&e));
    }

    #[test]
    fn empty_api_message_is_permanent() {
        assert!(!is_transient_send_error(&BridgeError::Api(String::new())));
    }

    #[test]
    fn extract_addr_angle_brackets() {
        assert_eq!(extract_addr("<alice@example.com>"), "alice@example.com");
        assert_eq!(extract_addr("  <bob@x.org> "), "bob@x.org");
    }

    #[test]
    fn extract_addr_display_name_and_angle() {
        assert_eq!(extract_addr("Alice <alice@example.com>"), "alice@example.com");
    }

    #[test]
    fn extract_addr_bare_address() {
        assert_eq!(extract_addr("carol@example.com"), "carol@example.com");
        assert_eq!(extract_addr("  dave@x.org  extra"), "dave@x.org");
    }

    #[test]
    fn extract_addr_empty_angle_pair() {
        assert_eq!(extract_addr("<>"), "");
    }

    #[test]
    fn extract_addr_empty_input() {
        assert_eq!(extract_addr(""), "");
        assert_eq!(extract_addr("   "), "");
    }

    #[test]
    fn extract_addr_inner_trimmed() {
        assert_eq!(extract_addr("<  spaced@x.org  >"), "spaced@x.org");
    }

    #[test]
    fn find_ci_prefix_basic() {
        assert_eq!(find_ci_prefix("FROM:<a@b>", "FROM:"), Some(0));
        assert_eq!(find_ci_prefix("from:<a@b>", "FROM:"), Some(0));
        assert_eq!(find_ci_prefix("  TO:<a@b>", "TO:"), Some(2));
    }

    #[test]
    fn find_ci_prefix_not_found() {
        assert_eq!(find_ci_prefix("RCPT", "TO:"), None);
        assert_eq!(find_ci_prefix("", "TO:"), None);
    }

    #[test]
    fn find_ci_prefix_empty_needle() {
        assert_eq!(find_ci_prefix("anything", ""), None);
    }

    #[test]
    fn find_ci_prefix_needle_longer_than_haystack() {
        assert_eq!(find_ci_prefix("ab", "abcdef"), None);
    }

    #[test]
    fn mail_from_argument_parsing() {
        let args = "FROM:<sender@aster.test> SIZE=100";
        let start = find_ci_prefix(args, "FROM:").unwrap();
        let addr = extract_addr(&args[start + 5..]);
        assert_eq!(addr, "sender@aster.test");
    }

    #[test]
    fn rcpt_to_argument_parsing() {
        let args = "TO:<rcpt@aster.test>";
        let start = find_ci_prefix(args, "TO:").unwrap();
        let addr = extract_addr(&args[start + 3..]);
        assert_eq!(addr, "rcpt@aster.test");
    }

    #[test]
    fn mail_from_empty_address_is_extractable_as_empty() {
        let args = "FROM:<>";
        let start = find_ci_prefix(args, "FROM:").unwrap();
        let addr = extract_addr(&args[start + 5..]);
        assert_eq!(addr, "");
    }

    #[test]
    fn line_length_limits_are_distinct() {
        assert!(MAX_DATA_LINE_LENGTH > MAX_LINE_LENGTH);
        assert_eq!(MAX_LINE_LENGTH, 998);
    }

    #[tokio::test]
    async fn read_line_bytes_reads_single_line() {
        let data = b"hello world\r\n".to_vec();
        let mut reader = BufReader::new(&data[..]);
        let mut out = Vec::new();
        let n = read_line_bytes(&mut reader, &mut out, MAX_LINE_LENGTH).await.unwrap();
        assert_eq!(n, data.len());
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn read_line_bytes_rejects_overlong_line() {
        let mut data = vec![b'a'; MAX_LINE_LENGTH + 5];
        data.push(b'\n');
        let mut reader = BufReader::new(&data[..]);
        let mut out = Vec::new();
        let err = read_line_bytes(&mut reader, &mut out, MAX_LINE_LENGTH).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_line_bytes_empty_input_returns_zero() {
        let data: Vec<u8> = Vec::new();
        let mut reader = BufReader::new(&data[..]);
        let mut out = Vec::new();
        let n = read_line_bytes(&mut reader, &mut out, MAX_LINE_LENGTH).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn build_send_payload_uses_envelope_recipients_as_bcc_when_no_headers() {
        let raw = b"From: sender@aster.test\r\nSubject: hi\r\n\r\nbody here\r\n";
        let recipients = vec!["rcpt@example.com".to_string()];
        let payload = build_send_payload(raw, Some("sender@aster.test"), &recipients, "sender@aster.test").unwrap();
        assert_eq!(payload["subject"], "hi");
        assert_eq!(payload["to"][0], "rcpt@example.com");
        assert_eq!(payload["client_source"], "bridge");
        assert_eq!(payload["is_e2e_encrypted"], false);
    }

    #[test]
    fn build_send_payload_prefers_header_to() {
        let raw = b"From: sender@aster.test\r\nTo: named@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let recipients = vec!["named@example.com".to_string()];
        let payload = build_send_payload(raw, Some("sender@aster.test"), &recipients, "sender@aster.test").unwrap();
        assert_eq!(payload["to"][0], "named@example.com");
        assert!(payload["bcc"].is_null());
    }

    #[test]
    fn build_send_payload_envelope_only_recipient_added_as_bcc() {
        let raw = b"From: sender@aster.test\r\nTo: visible@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let recipients = vec!["visible@example.com".to_string(), "hidden@example.com".to_string()];
        let payload = build_send_payload(raw, Some("sender@aster.test"), &recipients, "sender@aster.test").unwrap();
        assert_eq!(payload["bcc"][0], "hidden@example.com");
    }

    #[test]
    fn build_send_payload_body_is_never_empty() {
        let raw = b"From: sender@aster.test\r\nSubject: hi\r\n\r\n";
        let recipients = vec!["rcpt@example.com".to_string()];
        let payload = build_send_payload(raw, Some("sender@aster.test"), &recipients, "sender@aster.test").unwrap();
        let body = payload["body"].as_str().unwrap();
        assert!(!body.is_empty());
    }

    #[test]
    fn build_send_payload_invalid_message_errors() {
        let raw: &[u8] = b"";
        let recipients = vec!["rcpt@example.com".to_string()];
        let result = build_send_payload(raw, None, &recipients, "sender@aster.test");
        assert!(result.is_err());
    }
}
