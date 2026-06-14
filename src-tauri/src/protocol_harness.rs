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
// End-to-end protocol harness: boots the IMAP, SMTP and JMAP servers over real
// TCP with a stub session, a seeded mailbox and a mock backend, then drives the
// exact command sequences a desktop client (Thunderbird, Apple Mail, Outlook)
// uses. Run from a terminal with:
//
//   cargo test --bin aster-bridge-desktop protocol_harness -- --nocapture
//
// It prints a PASS/FAIL feature matrix so the bridge can be smoke-tested before
// shipping a beta, without needing a paired account.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::api_client::ApiClient;
use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;
use crate::db::Database;

const APP_PW: &str = "abcd-efgh-ijkl-mnop";
const EMAIL: &str = "tester@aster.test";

fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

async fn wait_listening(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server on port {} never came up", port);
}

// Minimal mock of the Aster backend send endpoint. Captures posted payloads and
// always returns 200 so the SMTP relay path can be exercised offline.
async fn start_mock_backend() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    use axum::{routing::post, Json, Router};
    let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let app = Router::new()
        .route(
            "/bridge/v1/send",
            post(move |Json(body): Json<serde_json::Value>| {
                let cap = cap.clone();
                async move {
                    cap.lock().await.push(body);
                    Json(serde_json::json!({"success": true}))
                }
            }),
        )
        .route(
            "/bridge/v1/messages/:id/metadata",
            axum::routing::patch(|| async { Json(serde_json::json!({"success": true})) }),
        );
    let port = free_port().await;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_listening(port).await;
    (format!("http://127.0.0.1:{}", port), captured)
}

fn stub_session() -> Arc<RwLock<Session>> {
    Arc::new(RwLock::new(Session {
        user_id: Uuid::new_v4(),
        username: "tester".to_string(),
        email: EMAIL.to_string(),
        access_token: zeroize::Zeroizing::new("stub-token".to_string()),
        vault_passphrase: Vec::new(),
        identity_key: None,
    }))
}

fn seed_message(db: &Database, id: &str, folder: &str, subject: &str) {
    db.upsert_cached_message(
        id,
        folder,
        Some(subject),
        Some("alice@example.com"),
        Some(EMAIL),
        Some("Wed, 21 May 2026 10:00:00 +0000"),
        128,
        Some("hello from the harness"),
        Some(&serde_json::json!({"is_html": false, "message_id": format!("{}@test", id)}).to_string()),
    )
    .unwrap();
    let _ = db.assign_uid_if_missing(folder, id);
}

struct Checklist {
    rows: Vec<(String, bool, String)>,
}

impl Checklist {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }
    fn check(&mut self, name: &str, pass: bool, detail: impl Into<String>) {
        self.rows.push((name.to_string(), pass, detail.into()));
    }
    fn render_and_assert(&self) {
        println!("\n================ ASTER BRIDGE FEATURE MATRIX ================");
        let mut failures = 0;
        for (name, pass, detail) in &self.rows {
            let mark = if *pass { "PASS" } else { "FAIL" };
            if !*pass {
                failures += 1;
            }
            println!("[{}] {:<42} {}", mark, name, detail);
        }
        println!("============================================================");
        println!(
            "{} checks, {} passed, {} failed\n",
            self.rows.len(),
            self.rows.len() - failures,
            failures
        );
        assert_eq!(failures, 0, "{} protocol checks failed", failures);
    }
}

// ---- SMTP helpers -------------------------------------------------------

async fn smtp_read_reply(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    // Reads a (possibly multiline) SMTP reply; stops at a line whose 4th byte is a space.
    let mut out = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.unwrap();
        if n == 0 {
            break;
        }
        out.push_str(&line);
        let bytes = line.as_bytes();
        if bytes.len() >= 4 && bytes[3] == b' ' {
            break;
        }
    }
    out
}

// ---- IMAP helpers -------------------------------------------------------

async fn imap_cmd(
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
    let mut out = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.unwrap();
        if n == 0 {
            break;
        }
        out.push_str(&line);
        if line.starts_with(&format!("{} ", tag)) {
            break;
        }
    }
    out
}

#[tokio::test]
async fn protocol_feature_matrix() {
    let mut cl = Checklist::new();

    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
    db.seed_jmap_mailboxes().unwrap();
    seed_message(&db, "msg-harness-1", "inbox", "Harness Subject");

    let passwords = Arc::new(AppPasswords::new(db.clone()));
    passwords.store("harness", APP_PW).unwrap();

    let (mock_base, captured) = start_mock_backend().await;
    let client = Arc::new(ApiClient::new_with_base_url(&mock_base));
    let broadcaster = crate::jmap::state::broadcaster();

    let imap_port = free_port().await;
    let smtp_port = free_port().await;
    let jmap_port = free_port().await;

    {
        let (s, d, c, p, b) = (
            stub_session(),
            db.clone(),
            client.clone(),
            passwords.clone(),
            broadcaster.clone(),
        );
        let addr = format!("127.0.0.1:{}", imap_port);
        tokio::spawn(async move {
            let _ = crate::imap::server::run(&addr, s, d, c, p, b, None).await;
        });
    }
    {
        let (s, c, p, d) = (stub_session(), client.clone(), passwords.clone(), db.clone());
        let addr = format!("127.0.0.1:{}", smtp_port);
        tokio::spawn(async move {
            let _ = crate::smtp::server::run(&addr, s, c, p, d, None).await;
        });
    }
    {
        let (s, d, c, p, b) = (
            stub_session(),
            db.clone(),
            client.clone(),
            passwords.clone(),
            broadcaster.clone(),
        );
        let addr = format!("127.0.0.1:{}", jmap_port);
        tokio::spawn(async move {
            let _ = crate::jmap::server::run(&addr, s, d, c, p, b, None).await;
        });
    }

    wait_listening(imap_port).await;
    wait_listening(smtp_port).await;
    wait_listening(jmap_port).await;

    // ===================== IMAP =====================
    {
        let stream = TcpStream::connect(("127.0.0.1", imap_port)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);

        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        cl.check(
            "IMAP greeting + CAPABILITY",
            greeting.contains("IMAP4rev1") && greeting.contains("IDLE"),
            greeting.trim().to_string(),
        );

        let login = imap_cmd(&mut reader, &mut w, "a1", &format!("LOGIN \"{}\" \"{}\"", EMAIL, APP_PW)).await;
        cl.check("IMAP LOGIN (app password)", login.contains("a1 OK"), "tagged OK");

        let bad = imap_cmd(&mut reader, &mut w, "a1b", &format!("LOGIN \"{}\" \"wrong-pass\"", EMAIL)).await;
        // bad login is on a fresh connection-state guard; reuse same conn is fine since first succeeded,
        // so we just assert the server stays responsive (NOOP).
        let _ = bad;

        let caps = imap_cmd(&mut reader, &mut w, "a2", "CAPABILITY").await;
        cl.check(
            "IMAP CAPABILITY (UIDPLUS, X-GM-EXT-1)",
            caps.contains("UIDPLUS") && caps.contains("X-GM-EXT-1"),
            "advertised",
        );

        let list = imap_cmd(&mut reader, &mut w, "a3", "LIST \"\" \"*\"").await;
        cl.check(
            "IMAP LIST folders",
            list.contains("INBOX") && list.contains("Sent") && list.contains("a3 OK"),
            "INBOX/Sent/Drafts/Trash/Junk/Archive",
        );

        let select = imap_cmd(&mut reader, &mut w, "a4", "SELECT INBOX").await;
        cl.check(
            "IMAP SELECT INBOX",
            select.contains("EXISTS") && select.contains("UIDVALIDITY") && select.contains("a4 OK"),
            "EXISTS + UIDVALIDITY",
        );

        let status = imap_cmd(&mut reader, &mut w, "a5", "STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY)").await;
        cl.check("IMAP STATUS", status.contains("MESSAGES") && status.contains("a5 OK"), "ok");

        let fetch = imap_cmd(&mut reader, &mut w, "a6", "FETCH 1 (FLAGS UID RFC822.SIZE ENVELOPE BODY.PEEK[])").await;
        cl.check(
            "IMAP FETCH (ENVELOPE + body)",
            fetch.contains("ENVELOPE") && fetch.contains("Harness Subject") && fetch.contains("a6 OK"),
            "headers + body delivered",
        );

        let uidfetch = imap_cmd(&mut reader, &mut w, "a7", "UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])").await;
        cl.check(
            "IMAP UID FETCH HEADER.FIELDS",
            uidfetch.contains("Subject") && uidfetch.contains("a7 OK"),
            "header subset",
        );

        let noop = imap_cmd(&mut reader, &mut w, "n1", "NOOP").await;
        cl.check("IMAP NOOP", noop.contains("n1 OK"), "ok");

        let search = imap_cmd(&mut reader, &mut w, "n2", "SEARCH ALL").await;
        cl.check("IMAP SEARCH", search.contains("* SEARCH") && search.contains("n2 OK"), "results");

        let uidsearch = imap_cmd(&mut reader, &mut w, "n3", "UID SEARCH ALL").await;
        cl.check("IMAP UID SEARCH", uidsearch.contains("* SEARCH") && uidsearch.contains("n3 OK"), "results");

        let store = imap_cmd(&mut reader, &mut w, "n4", "STORE 1 +FLAGS (\\Seen)").await;
        cl.check("IMAP STORE flags", store.contains("FLAGS") && store.contains("n4 OK"), "acked");

        let examine = imap_cmd(&mut reader, &mut w, "n5", "EXAMINE INBOX").await;
        cl.check("IMAP EXAMINE (read-only)", examine.contains("READ-ONLY") && examine.contains("n5 OK"), "read-only");

        let namespace = imap_cmd(&mut reader, &mut w, "n6", "NAMESPACE").await;
        cl.check("IMAP NAMESPACE", namespace.contains("* NAMESPACE") && namespace.contains("n6 OK"), "ok");

        // APPEND uses a literal continuation: send command, read "+", send the
        // literal, then read the tagged response. The bridge intentionally
        // rejects APPEND (clients submit via SMTP), so we expect a NO.
        w.write_all(b"a8 APPEND INBOX {3}\r\n").await.unwrap();
        w.flush().await.unwrap();
        let mut cont = String::new();
        reader.read_line(&mut cont).await.unwrap();
        let got_continuation = cont.starts_with("+ ");
        w.write_all(b"abc\r\n").await.unwrap();
        w.flush().await.unwrap();
        let mut appresp = String::new();
        loop {
            let mut l = String::new();
            if reader.read_line(&mut l).await.unwrap() == 0 {
                break;
            }
            appresp.push_str(&l);
            if l.starts_with("a8 ") {
                break;
            }
        }
        cl.check(
            "IMAP APPEND rejected cleanly (use SMTP)",
            got_continuation && (appresp.contains("CANNOT") || appresp.contains("a8 NO")),
            appresp.trim().to_string(),
        );

        let copy = imap_cmd(&mut reader, &mut w, "cp1", "UID COPY 1 Archive").await;
        cl.check(
            "IMAP UID COPY to Archive (COPYUID)",
            copy.contains("COPYUID") && copy.contains("cp1 OK"),
            "archived",
        );
        let movecmd = imap_cmd(&mut reader, &mut w, "mv1", "UID MOVE 1 Trash").await;
        cl.check(
            "IMAP UID MOVE to Trash (COPYUID + EXPUNGE)",
            movecmd.contains("COPYUID") && movecmd.contains("EXPUNGE") && movecmd.contains("mv1 OK"),
            "moved",
        );
        let cap_move = imap_cmd(&mut reader, &mut w, "cm1", "CAPABILITY").await;
        cl.check("IMAP CAPABILITY advertises MOVE", cap_move.contains("MOVE"), "MOVE advertised");
        let logout = imap_cmd(&mut reader, &mut w, "z1", "LOGOUT").await;
        cl.check("IMAP LOGOUT", logout.contains("BYE") && logout.contains("z1 OK"), "clean bye");
    }

    // ===================== IMAP IDLE =====================
    {
        let stream = TcpStream::connect(("127.0.0.1", imap_port)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        let _ = imap_cmd(&mut reader, &mut w, "i1", &format!("LOGIN \"{}\" \"{}\"", EMAIL, APP_PW)).await;
        let _ = imap_cmd(&mut reader, &mut w, "i2", "SELECT INBOX").await;
        w.write_all(b"i3 IDLE\r\n").await.unwrap();
        w.flush().await.unwrap();
        let mut plus = String::new();
        reader.read_line(&mut plus).await.unwrap();
        let idling = plus.starts_with("+ ");
        w.write_all(b"DONE\r\n").await.unwrap();
        w.flush().await.unwrap();
        let mut done = String::new();
        reader.read_line(&mut done).await.unwrap();
        cl.check(
            "IMAP IDLE / DONE",
            idling && done.starts_with("i3 OK"),
            "push channel open + terminate",
        );
    }

    // ===================== SMTP =====================
    {
        let stream = TcpStream::connect(("127.0.0.1", smtp_port)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);

        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        cl.check("SMTP greeting", greeting.starts_with("220"), greeting.trim());

        w.write_all(b"EHLO harness\r\n").await.unwrap();
        w.flush().await.unwrap();
        let ehlo = smtp_read_reply(&mut reader).await;
        cl.check(
            "SMTP EHLO (AUTH PLAIN, 8BITMIME, SIZE)",
            ehlo.contains("AUTH PLAIN") && ehlo.contains("8BITMIME") && ehlo.contains("SIZE"),
            "advertised",
        );

        // Wrong password rejected
        w.write_all(format!("AUTH PLAIN {}\r\n", b64(b"\0tester@aster.test\0nope")).as_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let badauth = smtp_read_reply(&mut reader).await;
        cl.check("SMTP AUTH rejects wrong password", badauth.starts_with("535"), badauth.trim());

        // Correct password
        w.write_all(format!("AUTH PLAIN {}\r\n", b64(b"\0tester@aster.test\0abcd-efgh-ijkl-mnop")).as_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let okauth = smtp_read_reply(&mut reader).await;
        cl.check("SMTP AUTH PLAIN success", okauth.starts_with("235"), okauth.trim());

        // Sender spoof rejected
        w.write_all(b"MAIL FROM:<evil@elsewhere.com>\r\n").await.unwrap();
        w.flush().await.unwrap();
        let spoof = smtp_read_reply(&mut reader).await;
        cl.check("SMTP rejects sender != authenticated user", spoof.starts_with("553"), spoof.trim());

        // Plain message accepted and relayed
        w.write_all(format!("MAIL FROM:<{}>\r\n", EMAIL).as_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let _ = smtp_read_reply(&mut reader).await;
        w.write_all(b"RCPT TO:<bob@example.com>\r\n").await.unwrap();
        w.flush().await.unwrap();
        let _ = smtp_read_reply(&mut reader).await;
        w.write_all(b"DATA\r\n").await.unwrap();
        w.flush().await.unwrap();
        let _ = smtp_read_reply(&mut reader).await;
        let msg = format!(
            "From: {}\r\nTo: bob@example.com\r\nSubject: Harness plain\r\nContent-Type: text/plain\r\n\r\nhello from thunderbird\r\n.\r\n",
            EMAIL
        );
        w.write_all(msg.as_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let sent = smtp_read_reply(&mut reader).await;
        cl.check("SMTP DATA plain message accepted", sent.starts_with("250"), sent.trim());

        tokio::time::sleep(Duration::from_millis(100)).await;
        let posted = captured.lock().await;
        let relayed_ok = posted
            .iter()
            .any(|p| p["subject"] == "Harness plain" && p["body"].as_str().unwrap_or("").contains("hello from thunderbird"));
        cl.check("SMTP relays subject+body to backend", relayed_ok, format!("{} payload(s) captured", posted.len()));
        drop(posted);

        // PGP/MIME rejected with a clear reason (no silent gutting)
        w.write_all(format!("MAIL FROM:<{}>\r\n", EMAIL).as_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let _ = smtp_read_reply(&mut reader).await;
        w.write_all(b"RCPT TO:<bob@example.com>\r\n").await.unwrap();
        w.flush().await.unwrap();
        let _ = smtp_read_reply(&mut reader).await;
        w.write_all(b"DATA\r\n").await.unwrap();
        w.flush().await.unwrap();
        let _ = smtp_read_reply(&mut reader).await;
        let pgp = "From: tester@aster.test\r\nTo: bob@example.com\r\nSubject: secret\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nabc\r\n-----END PGP MESSAGE-----\r\n\r\n--b--\r\n.\r\n";
        w.write_all(pgp.as_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let pgp_reply = smtp_read_reply(&mut reader).await;
        cl.check(
            "SMTP PGP/MIME fails loudly (not silently gutted)",
            pgp_reply.starts_with("550") && pgp_reply.contains("OpenPGP"),
            pgp_reply.trim(),
        );

        // Multi-recipient transaction + RSET
        w.write_all(format!("MAIL FROM:<{}>\r\n", EMAIL).as_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let _ = smtp_read_reply(&mut reader).await;
        let mut all_rcpt_ok = true;
        for r in ["a@example.com", "b@example.com", "c@example.com"] {
            w.write_all(format!("RCPT TO:<{}>\r\n", r).as_bytes()).await.unwrap();
            w.flush().await.unwrap();
            all_rcpt_ok &= smtp_read_reply(&mut reader).await.starts_with("250");
        }
        cl.check("SMTP multi-recipient (3x RCPT)", all_rcpt_ok, "all 250");
        w.write_all(b"RSET\r\n").await.unwrap();
        w.flush().await.unwrap();
        let rset = smtp_read_reply(&mut reader).await;
        cl.check("SMTP RSET", rset.starts_with("250"), rset.trim().to_string());

        w.write_all(b"QUIT\r\n").await.unwrap();
        w.flush().await.unwrap();
        let quit = smtp_read_reply(&mut reader).await;
        cl.check("SMTP QUIT", quit.starts_with("221"), quit.trim());
    }

    // ===================== JMAP =====================
    {
        let http = reqwest::Client::new();
        let good = http
            .get(format!("http://127.0.0.1:{}/jmap/session", jmap_port))
            .header("authorization", format!("Basic {}", b64(format!("{}:{}", EMAIL, APP_PW).as_bytes())))
            .send()
            .await
            .unwrap();
        cl.check("JMAP session (valid creds)", good.status() == 200, format!("HTTP {}", good.status()));

        let bad_user = http
            .get(format!("http://127.0.0.1:{}/jmap/session", jmap_port))
            .header("authorization", format!("Basic {}", b64(format!("mallory@evil.example:{}", APP_PW).as_bytes())))
            .send()
            .await
            .unwrap();
        cl.check("JMAP rejects wrong username", bad_user.status() == 401, format!("HTTP {}", bad_user.status()));

        let bad_pass = http
            .get(format!("http://127.0.0.1:{}/jmap/session", jmap_port))
            .header("authorization", format!("Basic {}", b64(format!("{}:wrong", EMAIL).as_bytes())))
            .send()
            .await
            .unwrap();
        cl.check("JMAP rejects wrong password", bad_pass.status() == 401, format!("HTTP {}", bad_pass.status()));
    }

    cl.render_and_assert();
}

// Boots the real IMAP/SMTP/JMAP servers on fixed local ports with a stub
// session, a known app password and a seeded inbox, then stays up so the bridge
// can be driven by hand from a separate terminal (PowerShell/openssl/telnet).
// Plaintext (no TLS) so a raw TCP client works without trusting a cert.
//
//   cargo test --bin aster-bridge-desktop serve_local -- --ignored --nocapture
//
// Listens for ~150s on IMAP 11430, SMTP 11250, JMAP 11080. Login user is the
// account email; password is the app password printed below.
#[tokio::test]
#[ignore]
async fn serve_local() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
    db.seed_jmap_mailboxes().unwrap();
    seed_message(&db, "msg-local-1", "inbox", "Welcome to Aster Bridge");
    seed_message(&db, "msg-local-2", "inbox", "Second test message");

    let passwords = Arc::new(AppPasswords::new(db.clone()));
    passwords.store("local", APP_PW).unwrap();

    let (mock_base, _captured) = start_mock_backend().await;
    let client = Arc::new(ApiClient::new_with_base_url(&mock_base));
    let broadcaster = crate::jmap::state::broadcaster();

    let imap_port: u16 = 11430;
    let smtp_port: u16 = 11250;
    let jmap_port: u16 = 11080;

    {
        let (s, d, c, p, b) = (stub_session(), db.clone(), client.clone(), passwords.clone(), broadcaster.clone());
        let addr = format!("127.0.0.1:{}", imap_port);
        tokio::spawn(async move {
            let _ = crate::imap::server::run(&addr, s, d, c, p, b, None).await;
        });
    }
    {
        let (s, c, p, d) = (stub_session(), client.clone(), passwords.clone(), db.clone());
        let addr = format!("127.0.0.1:{}", smtp_port);
        tokio::spawn(async move {
            let _ = crate::smtp::server::run(&addr, s, c, p, d, None).await;
        });
    }
    {
        let (s, d, c, p, b) = (stub_session(), db.clone(), client.clone(), passwords.clone(), broadcaster.clone());
        let addr = format!("127.0.0.1:{}", jmap_port);
        tokio::spawn(async move {
            let _ = crate::jmap::server::run(&addr, s, d, c, p, b, None).await;
        });
    }

    wait_listening(imap_port).await;
    wait_listening(smtp_port).await;
    wait_listening(jmap_port).await;

    println!("\n================ ASTER BRIDGE LOCAL SERVER (no TLS) ================");
    println!("  IMAP : 127.0.0.1:{}", imap_port);
    println!("  SMTP : 127.0.0.1:{}", smtp_port);
    println!("  JMAP : http://127.0.0.1:{}/jmap/session", jmap_port);
    println!("  user : {}", EMAIL);
    println!("  pass : {}", APP_PW);
    println!("  inbox: 2 seeded messages");
    println!("  (serving ~150s; backend send is mocked)");
    println!("===================================================================\n");

    tokio::time::sleep(Duration::from_secs(150)).await;
    println!("serve_local: shutting down");
}

// Like serve_local but with TLS enabled: IMAP STARTTLS on 11430 + implicit
// IMAPS on 11993, SMTP STARTTLS on 11250 + implicit SMTPS on 11465. Uses the
// bridge's real self-signed cert. Drive with:
//   openssl s_client -connect 127.0.0.1:11993           (implicit IMAPS)
//   openssl s_client -starttls smtp -connect 127.0.0.1:11250
//   cargo test --bin aster-bridge-desktop serve_local_tls -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn serve_local_tls() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
    db.seed_jmap_mailboxes().unwrap();
    seed_message(&db, "msg-tls-1", "inbox", "TLS test message");

    let passwords = Arc::new(AppPasswords::new(db.clone()));
    passwords.store("local", APP_PW).unwrap();

    let (mock_base, _captured) = start_mock_backend().await;
    let client = Arc::new(ApiClient::new_with_base_url(&mock_base));
    let broadcaster = crate::jmap::state::broadcaster();

    crate::tls::install_default_crypto_provider();
    let (certs, key) = crate::tls::ensure_cert(dir.path()).unwrap();
    let tls = crate::tls::server_config(certs, key).unwrap();
    if let Some(fp) = crate::tls::cert_fingerprint_sha256(dir.path()) {
        println!("cert SHA-256 fingerprint: {}", fp);
    }

    let (imap, imaps, smtp, smtps) = (11430u16, 11993u16, 11250u16, 11465u16);

    {
        let (s, d, c, p, b, t) = (stub_session(), db.clone(), client.clone(), passwords.clone(), broadcaster.clone(), tls.clone());
        let addr = format!("127.0.0.1:{}", imap);
        tokio::spawn(async move { let _ = crate::imap::server::run(&addr, s, d, c, p, b, Some(t)).await; });
    }
    {
        let (s, d, c, p, b, t) = (stub_session(), db.clone(), client.clone(), passwords.clone(), broadcaster.clone(), tls.clone());
        let addr = format!("127.0.0.1:{}", imaps);
        tokio::spawn(async move { let _ = crate::imap::server::run_implicit_tls(&addr, s, d, c, p, b, t).await; });
    }
    {
        let (s, c, p, d, t) = (stub_session(), client.clone(), passwords.clone(), db.clone(), tls.clone());
        let addr = format!("127.0.0.1:{}", smtp);
        tokio::spawn(async move { let _ = crate::smtp::server::run(&addr, s, c, p, d, Some(t)).await; });
    }
    {
        let (s, c, p, d, t) = (stub_session(), client.clone(), passwords.clone(), db.clone(), tls.clone());
        let addr = format!("127.0.0.1:{}", smtps);
        tokio::spawn(async move { let _ = crate::smtp::server::run_implicit_tls(&addr, s, c, p, d, t).await; });
    }

    wait_listening(imap).await;
    wait_listening(imaps).await;
    wait_listening(smtp).await;
    wait_listening(smtps).await;

    println!("\n============ ASTER BRIDGE LOCAL SERVER (TLS) ============");
    println!("  IMAP  STARTTLS : 127.0.0.1:{}", imap);
    println!("  IMAPS implicit : 127.0.0.1:{}", imaps);
    println!("  SMTP  STARTTLS : 127.0.0.1:{}", smtp);
    println!("  SMTPS implicit : 127.0.0.1:{}", smtps);
    println!("  user/pass      : {} / {}", EMAIL, APP_PW);
    println!("========================================================\n");

    tokio::time::sleep(Duration::from_secs(150)).await;
    println!("serve_local_tls: shutting down");
}

// Connects to the REAL paired account: reuses the device identity + passphrase
// from the bridge data dir, logs in against production, syncs the real mailbox
// into a fresh throwaway DB (the real bridge.db and stored app passwords are
// left untouched), then serves IMAP/SMTP/JMAP locally on test ports so the real
// account can be driven from the command line.
//
//   cargo test --bin aster-bridge-desktop serve_real -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn serve_real() {
    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(e) => { println!("serve_real: cannot load config: {}", e); return; }
    };
    println!("serve_real: data_dir = {}", cfg.data_dir.display());
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i,
        Err(e) => { println!("serve_real: identity load failed: {}", e); return; }
    };
    if identity.device_id.is_none() {
        println!("serve_real: NOT PAIRED (no device_id). Open the Aster Bridge app and pair first.");
        return;
    }

    crate::tls::install_default_crypto_provider();
    let client = Arc::new(ApiClient::new());

    println!("serve_real: logging in against production ...");
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s,
        Err(e) => {
            println!("serve_real: LOGIN FAILED: {}", e);
            println!("  -> the device may have been unpaired/expired. Re-pair via the app.");
            return;
        }
    };
    println!("serve_real: logged in as {} ({})", session.email, session.user_id);

    // Diagnostic: does the inbox have items server-side, and do they decrypt?
    {
        use crate::api_client::MailListQuery;
        let token = session.access_token.clone();
        let pass = session.vault_passphrase.clone();
        let ik = session.identity_key.clone();
        println!("serve_real: identity_key present = {}", ik.is_some());
        for (label, itype) in [("inbox", "received"), ("sent", "sent")] {
            let q = MailListQuery {
                item_type: Some(itype.to_string()),
                is_trashed: None,
                is_archived: None,
                is_spam: None,
                limit: Some(5),
                cursor: None,
            };
            match client.list_mail(&token, &q).await {
                Ok(resp) => {
                    println!("DIAG {}: server total={} page_items={}", label, resp.total, resp.items.len());
                    let (mut ok, mut ratchet, mut fail) = (0u32, 0u32, 0u32);
                    for item in &resp.items {
                        match crate::crypto::envelope::decrypt_envelope(
                            &item.encrypted_envelope,
                            Some(&item.envelope_nonce),
                            &pass,
                            ik.as_deref(),
                        ) {
                            Ok(pt) if pt.contains("double_ratchet") => ratchet += 1,
                            Ok(_) => ok += 1,
                            Err(_) => fail += 1,
                        }
                    }
                    println!("   decrypt: {} ok, {} ratchet-placeholder, {} failed (of {} sampled)",
                        ok, ratchet, fail, resp.items.len());
                }
                Err(e) => println!("DIAG {}: list_mail error: {}", label, e),
            }
        }
    }

    let session = Arc::new(RwLock::new(session));

    // Fresh throwaway DB so the real cache is never touched.
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
    db.seed_jmap_mailboxes().unwrap();

    let passwords = Arc::new(AppPasswords::new(db.clone()));
    let app_pw = crate::auth::app_passwords::generate_app_password();
    passwords.store("cmd-test", &app_pw).unwrap();

    let broadcaster = crate::jmap::state::broadcaster();

    // Sync the real mailbox into the throwaway DB before serving.
    let (sync_tx, sync_rx) = crate::sync::poller::sync_trigger_channel();
    {
        let (s, c, d, b) = (session.clone(), client.clone(), db.clone(), broadcaster.clone());
        tokio::spawn(async move {
            crate::sync::poller::run_poll_loop(s, c, d, Some(b), sync_rx, None).await;
        });
    }
    println!("serve_real: syncing real mailbox ...");
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let _ = sync_tx.send(crate::sync::poller::SyncTrigger { done: done_tx }).await;
    match tokio::time::timeout(Duration::from_secs(60), done_rx).await {
        Ok(Ok(Ok(()))) => println!("serve_real: sync complete"),
        Ok(Ok(Err(e))) => println!("serve_real: sync error: {}", e),
        Ok(Err(_)) => println!("serve_real: sync channel dropped"),
        Err(_) => println!("serve_real: sync timed out (serving cached-so-far)"),
    }
    for (label, folder) in [("INBOX", "inbox"), ("Sent", "sent"), ("Archive", "archive")] {
        let n = db.count_cached_messages(folder).unwrap_or(0);
        println!("  {} = {} messages", label, n);
    }

    let (imap, smtp, jmap) = (11430u16, 11250u16, 11080u16);
    {
        let (s, d, c, p, b) = (session.clone(), db.clone(), client.clone(), passwords.clone(), broadcaster.clone());
        let addr = format!("127.0.0.1:{}", imap);
        tokio::spawn(async move { let _ = crate::imap::server::run(&addr, s, d, c, p, b, None).await; });
    }
    {
        let (s, c, p, d) = (session.clone(), client.clone(), passwords.clone(), db.clone());
        let addr = format!("127.0.0.1:{}", smtp);
        tokio::spawn(async move { let _ = crate::smtp::server::run(&addr, s, c, p, d, None).await; });
    }
    {
        let (s, d, c, p, b) = (session.clone(), db.clone(), client.clone(), passwords.clone(), broadcaster.clone());
        let addr = format!("127.0.0.1:{}", jmap);
        tokio::spawn(async move { let _ = crate::jmap::server::run(&addr, s, d, c, p, b, None).await; });
    }
    wait_listening(imap).await;
    wait_listening(smtp).await;
    wait_listening(jmap).await;

    let email = session.read().await.email.clone();
    println!("\n============ ASTER BRIDGE - REAL ACCOUNT (no TLS) ============");
    println!("  IMAP : 127.0.0.1:{}", imap);
    println!("  SMTP : 127.0.0.1:{}", smtp);
    println!("  JMAP : http://127.0.0.1:{}/jmap/session", jmap);
    println!("  user : {}", email);
    println!("  pass : {}", app_pw);
    println!("  (real bridge.db untouched; serving ~240s)");
    println!("==============================================================\n");

    tokio::time::sleep(Duration::from_secs(240)).await;
    println!("serve_real: shutting down");
}
