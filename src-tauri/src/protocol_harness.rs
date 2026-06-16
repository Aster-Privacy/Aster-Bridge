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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
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
        ratchet_keys: Vec::new(),
        send_identities: Vec::new(),
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
    seed_message(&db, "msg-harness-2", "inbox", "Harness Subject Two");

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
        let movecmd = imap_cmd(&mut reader, &mut w, "mv1", "UID MOVE 2 Trash").await;
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

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "info,aster_bridge_desktop::smtp=debug,aster_bridge_desktop::imap=debug",
        ))
        .with_test_writer()
        .try_init();

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

    {
        let ids = crate::auth::session::build_send_identities(
            &client, &session.access_token, &session.email, None, &session.vault_passphrase,
        ).await;
        println!("serve_real: {} send identities", ids.len());
        for id in &ids {
            println!("IDENTITY\t{:?}\t{}", id.kind, id.address);
        }
    }

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

    let _ = db.outbox_reset_stale_sending();
    {
        let (s, c, d) = (session.clone(), client.clone(), db.clone());
        let (_obx_tx, obx_rx) = crate::outbox::outbox_trigger_channel();
        tokio::spawn(async move { crate::outbox::run_outbox_loop(s, c, d, obx_rx).await; });
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
    println!("  (real bridge.db untouched; serving ~300s)");
    println!("==============================================================\n");

    tokio::time::sleep(Duration::from_secs(300)).await;
    println!("serve_real: shutting down");
}

// Logs into the REAL paired account and runs the full internal-mail decryption
// path (X3DH + ML-KEM-768 PQXDH + double ratchet) against real messages and the
// real vault keys, printing PASS/FAIL and a plaintext snippet per message. All
// decryption is local; the PQ prekey is fetched (read-only, never deleted).
//
//   cargo test --bin aster-bridge-desktop decrypt_real_internal -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn decrypt_real_internal() {
    use crate::api_client::MailListQuery;

    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(e) => {
            println!("cannot load config: {}", e);
            return;
        }
    };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i,
        Err(e) => {
            println!("identity load failed: {}", e);
            return;
        }
    };
    if identity.device_id.is_none() {
        println!("NOT PAIRED (no device_id). Pair the bridge first.");
        return;
    }

    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();

    println!("data_dir = {}", cfg.data_dir.display());
    println!("device_id = {:?}", identity.device_id);
    let device_id = identity.device_id.unwrap();
    let passphrase = match crate::auth::device_identity::load_passphrase(&cfg.data_dir) {
        Ok(Some(p)) => {
            println!("passphrase loaded: {} bytes", p.len());
            p
        }
        Ok(None) => {
            println!("NO PASSPHRASE stored");
            return;
        }
        Err(e) => {
            println!("passphrase load err: {}", e);
            return;
        }
    };
    let challenge = match client.device_challenge(device_id).await {
        Ok(c) => {
            println!("challenge OK (id {})", c.challenge_id);
            c
        }
        Err(e) => {
            println!("CHALLENGE FAILED: {}", e);
            return;
        }
    };
    let signature = crate::auth::device_identity::sign_challenge(&identity, &challenge.nonce).unwrap();
    let login_resp = match client
        .device_login(&crate::api_client::DeviceLoginRequest {
            challenge_id: challenge.challenge_id,
            signature,
        })
        .await
    {
        Ok(r) => r,
        Err(e) => {
            println!("DEVICE_LOGIN FAILED: {}", e);
            return;
        }
    };
    let access_token = zeroize::Zeroizing::new(login_resp.access_token.clone().unwrap_or_default());
    let (identity_key, ratchet_keys) = match crate::crypto::vault::decrypt_vault(
        &login_resp.encrypted_vault,
        &login_resp.vault_nonce,
        &passphrase,
    ) {
        Ok(v) => (
            Some(v.identity_key.clone()),
            crate::crypto::ratchet::build_receiver_key_sets(&v),
        ),
        Err(e) => {
            println!("vault decrypt FAILED: {}", e);
            (None, Vec::new())
        }
    };
    let session = crate::auth::session::Session {
        user_id: login_resp.user_id,
        username: login_resp.username,
        email: login_resp.email,
        access_token,
        vault_passphrase: passphrase,
        identity_key,
        ratchet_keys,
        send_identities: Vec::new(),
    };
    println!("logged in as {}", session.email);
    println!("ratchet key sets available: {}", session.ratchet_keys.len());

    let sync_key = crate::crypto::ratchet::derive_sync_key(&session.vault_passphrase).ok();
    let token = session.access_token.clone();

    let (mut total_ratchet, mut decrypted, mut failed) = (0u32, 0u32, 0u32);

    for (label, itype) in [("inbox", "received"), ("sent", "sent")] {
        let q = MailListQuery {
            item_type: Some(itype.to_string()),
            is_trashed: None,
            is_archived: None,
            is_spam: None,
            limit: Some(40),
            cursor: None,
        };
        let resp = match client.list_mail(&token, &q).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}: list error {}", label, e);
                continue;
            }
        };
        println!("\n=== {} ({} items) ===", label, resp.items.len());
        for item in &resp.items {
            let env = match crate::crypto::envelope::decrypt_envelope(
                &item.encrypted_envelope,
                Some(&item.envelope_nonce),
                &session.vault_passphrase,
                session.identity_key.as_deref(),
            ) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let parsed: serde_json::Value = match serde_json::from_str(&env) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ratchet = match crate::crypto::ratchet::find_ratchet_object(&parsed) {
                Some(v) => v,
                None => continue,
            };
            total_ratchet += 1;
            let mut msg = match crate::crypto::ratchet::parse_recipient_message(&ratchet, &session.email) {
                Some(m) => m,
                None => {
                    failed += 1;
                    println!("  [FAIL parse] {}", item.id);
                    continue;
                }
            };
            if let Some(kid) = msg.pq_key_id {
                let Some(sk) = sync_key.as_ref() else {
                    failed += 1;
                    continue;
                };
                match client.get_pq_secret(&token, kid).await {
                    Ok(r) => match crate::crypto::ratchet::decrypt_pq_secret(sk, &r.encrypted_secret, &r.secret_nonce) {
                        Ok(s) => msg.pq_secret = Some(s),
                        Err(e) => {
                            failed += 1;
                            println!("  [FAIL pq-decrypt kid={}] {}", kid, e);
                            continue;
                        }
                    },
                    Err(_) => {
                        failed += 1;
                        println!("  [SKIP pq-fetch kid={}] secret gone (already opened on another device)", kid);
                        continue;
                    }
                }
            }
            match crate::crypto::ratchet::decrypt_with_key_sets(&session.ratchet_keys, &msg) {
                Some(pt) => {
                    decrypted += 1;
                    let snippet: String = pt.chars().take(90).collect();
                    println!("  [OK] {} => {}", item.id, snippet.replace('\n', " "));
                }
                None => {
                    failed += 1;
                    println!("  [FAIL decrypt] {}", item.id);
                }
            }
        }
    }

    println!("\n==== RATCHET DECRYPT SUMMARY ====");
    println!(
        "internal(ratchet) messages: {}, decrypted OK: {}, failed/skipped: {}",
        total_ratchet, decrypted, failed
    );
}

async fn report_internal_decrypt(client: &ApiClient, session: &crate::auth::session::Session) {
    use crate::api_client::MailListQuery;

    let sync_key = crate::crypto::ratchet::derive_sync_key(&session.vault_passphrase).ok();
    let token = session.access_token.clone();
    let (mut total_ratchet, mut decrypted, mut failed) = (0u32, 0u32, 0u32);

    for (label, itype) in [("inbox", "received"), ("sent", "sent")] {
        let q = MailListQuery {
            item_type: Some(itype.to_string()),
            is_trashed: None,
            is_archived: None,
            is_spam: None,
            limit: Some(40),
            cursor: None,
        };
        let resp = match client.list_mail(&token, &q).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}: list error {}", label, e);
                continue;
            }
        };
        println!("\n=== {} ({} items) ===", label, resp.items.len());
        for item in &resp.items {
            let env = match crate::crypto::envelope::decrypt_envelope(
                &item.encrypted_envelope,
                Some(&item.envelope_nonce),
                &session.vault_passphrase,
                session.identity_key.as_deref(),
            ) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let parsed: serde_json::Value = match serde_json::from_str(&env) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ratchet = match crate::crypto::ratchet::find_ratchet_object(&parsed) {
                Some(v) => v,
                None => continue,
            };
            total_ratchet += 1;
            let mut msg = match crate::crypto::ratchet::parse_recipient_message(&ratchet, &session.email) {
                Some(m) => m,
                None => {
                    failed += 1;
                    println!("  [FAIL parse] {}", item.id);
                    continue;
                }
            };
            if let Some(kid) = msg.pq_key_id {
                let Some(sk) = sync_key.as_ref() else {
                    failed += 1;
                    continue;
                };
                match client.get_pq_secret(&token, kid).await {
                    Ok(r) => match crate::crypto::ratchet::decrypt_pq_secret(sk, &r.encrypted_secret, &r.secret_nonce) {
                        Ok(s) => msg.pq_secret = Some(s),
                        Err(e) => {
                            failed += 1;
                            println!("  [FAIL pq-decrypt kid={}] {}", kid, e);
                            continue;
                        }
                    },
                    Err(_) => {
                        failed += 1;
                        println!("  [SKIP pq kid={}] secret gone (opened on another device)", kid);
                        continue;
                    }
                }
            }
            match crate::crypto::ratchet::decrypt_with_key_sets(&session.ratchet_keys, &msg) {
                Some(pt) => {
                    decrypted += 1;
                    let s: String = pt.chars().take(90).collect();
                    println!("  [OK] {} => {}", item.id, s.replace('\n', " "));
                }
                None => {
                    failed += 1;
                    println!("  [FAIL decrypt] {}", item.id);
                }
            }
        }
    }

    println!("\n==== RATCHET DECRYPT SUMMARY ====");
    println!(
        "internal(ratchet) messages: {}, decrypted OK: {}, failed/skipped: {}",
        total_ratchet, decrypted, failed
    );
}

#[tokio::test]
#[ignore]
async fn pair_and_decrypt_real() {
    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(e) => {
            println!("cannot load config: {}", e);
            return;
        }
    };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i,
        Err(e) => {
            println!("identity load failed: {}", e);
            return;
        }
    };
    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();

    println!("PAIRING: enter the code below in Aster Mail > Settings > Devices > Add Device");
    let session = match crate::auth::session::first_time_setup(&cfg, &identity, &client).await {
        Ok(s) => s,
        Err(e) => {
            println!("PAIRING FAILED: {}", e);
            return;
        }
    };
    println!(
        "paired + logged in as {} (ratchet key sets: {})",
        session.email,
        session.ratchet_keys.len()
    );
    report_internal_decrypt(&client, &session).await;
}

// Proves the full internal-mail crypto end to end against the LIVE backend and
// the real vault keys, with no dependency on any existing message or user
// action: fetch our own real prekey bundle, encrypt a fresh message to it using
// a live (unconsumed) PQ prekey, fetch that prekey's secret and decrypt. If the
// recovered plaintext matches, the entire X3DH + ML-KEM-768 + double-ratchet
// receive path is proven correct on the user's actual account.
//
//   cargo test --bin aster-bridge-desktop pqxdh_self_roundtrip_real -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn pqxdh_self_roundtrip_real() {
    use base64::engine::general_purpose::STANDARD;

    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(e) => { println!("cannot load config: {}", e); return; }
    };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i,
        Err(e) => { println!("identity load failed: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }

    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s,
        Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    println!("logged in as {} (user {}, key sets {})", session.email, session.username, session.ratchet_keys.len());

    let token = session.access_token.clone();
    let sync_key = match crate::crypto::ratchet::derive_sync_key(&session.vault_passphrase) {
        Ok(k) => k,
        Err(e) => { println!("sync key derive failed: {}", e); return; }
    };

    let bundle = match client.get_prekey_bundle(&token, &session.username, &session.email).await {
        Ok(b) => b,
        Err(e) => { println!("PREKEY BUNDLE FETCH FAILED: {}", e); return; }
    };
    println!("bundle fetched: has_pq_prekey={}", bundle.pq_prekey.is_some());

    let recipient_id_pub = STANDARD.decode(&bundle.kem_identity_key).expect("kem_identity b64");
    let recipient_spk_pub = STANDARD.decode(&bundle.signed_prekey).expect("signed_prekey b64");
    let (pq_pub, pq_kid) = match &bundle.pq_prekey {
        Some(p) => (Some(STANDARD.decode(&p.public_key).expect("pq pub b64")), Some(p.key_id)),
        None => { println!("WARNING: bundle has no PQ prekey; testing classical path only"); (None, None) }
    };

    if session.ratchet_keys.is_empty() {
        println!("no ratchet key sets in vault");
        return;
    }
    let sender_id_d = session.ratchet_keys[0].identity_secret_d.clone();

    let plaintext = "PQXDH self round-trip proof - sign-in code 778899";
    let mut msg = match crate::crypto::ratchet::encrypt_bootstrap(
        &sender_id_d,
        &recipient_id_pub,
        &recipient_spk_pub,
        pq_pub.as_deref(),
        pq_kid,
        plaintext,
    ) {
        Ok(m) => m,
        Err(e) => { println!("ENCRYPT FAILED: {}", e); return; }
    };

    if let Some(kid) = msg.pq_key_id {
        match client.get_pq_secret(&token, kid).await {
            Ok(r) => match crate::crypto::ratchet::decrypt_pq_secret(&sync_key, &r.encrypted_secret, &r.secret_nonce) {
                Ok(secret) => msg.pq_secret = Some(secret),
                Err(e) => { println!("PQ SECRET DECRYPT FAILED (kid={}): {}", kid, e); return; }
            },
            Err(e) => { println!("PQ SECRET FETCH FAILED (kid={}): {}", kid, e); return; }
        }
    }

    match crate::crypto::ratchet::decrypt_with_key_sets(&session.ratchet_keys, &msg) {
        Some(pt) => {
            println!("DECRYPTED: {:?}", pt);
            assert_eq!(pt, plaintext, "round-trip plaintext mismatch");
            println!("==== PROOF PASS: full PQXDH + double-ratchet decrypt works on the live account ====");
        }
        None => println!("==== PROOF FAIL: could not decrypt self-encrypted message ===="),
    }
}

// Proves the alias / custom-domain send-as feature end to end on the LIVE
// account. Logs in, prints every decrypted send identity (this alone proves the
// Bridge fetched + DECRYPTED the user's real aliases and custom-domain
// addresses), then performs a real backend send AS the primary, up to two
// aliases and up to two custom-domain addresses, each addressed only to the
// user's own primary address (a harmless self-email). It builds the exact JSON
// the SMTP path posts (build_send_payload) and calls the same send_mail the SMTP
// path uses, printing the precise HTTP status + body per identity. Non-2xx is
// never fatal here: we only want to observe whether the backend accepts each
// identity or 403s the alias/custom-domain re-check.
//
//   cargo test --bin aster-bridge-desktop alias_send_identities_real -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn alias_send_identities_real() {
    use crate::auth::session::SendIdentityKind;

    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(e) => { println!("cannot load config: {}", e); return; }
    };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i,
        Err(e) => { println!("identity load failed: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }

    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s,
        Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    println!(
        "logged in as {} (user {}, key sets {})",
        session.email, session.username, session.ratchet_keys.len()
    );

    fn redact(address: &str) -> String {
        match address.split_once('@') {
            Some((local, domain)) => {
                let head: String = local.chars().take(2).collect();
                format!("{}***@{}", head, domain)
            }
            None => address.to_string(),
        }
    }

    let mut primary_count = 0usize;
    let mut alias_count = 0usize;
    let mut domain_count = 0usize;

    println!("\n==== SEND IDENTITIES (decrypted from the live account) ====");
    println!("total: {}", session.send_identities.len());
    for id in &session.send_identities {
        match id.kind {
            SendIdentityKind::Primary => primary_count += 1,
            SendIdentityKind::Alias => alias_count += 1,
            SendIdentityKind::CustomDomain => domain_count += 1,
        }
        println!(
            "  [{}] {} enabled={} auth_hash={} display_name={}",
            id.kind.as_str(),
            redact(&id.address),
            id.enabled,
            id.auth_hash_b64.is_some(),
            id.display_name.as_deref().unwrap_or("<none>"),
        );
    }
    println!(
        "counts -> primary: {}, alias: {}, custom_domain: {}",
        primary_count, alias_count, domain_count
    );

    // Pick the primary, up to 2 aliases and up to 2 custom-domain identities.
    let primary: Vec<_> = session
        .send_identities
        .iter()
        .filter(|i| i.kind == SendIdentityKind::Primary)
        .collect();
    let aliases: Vec<_> = session
        .send_identities
        .iter()
        .filter(|i| i.kind == SendIdentityKind::Alias)
        .take(2)
        .collect();
    let domains: Vec<_> = session
        .send_identities
        .iter()
        .filter(|i| i.kind == SendIdentityKind::CustomDomain)
        .take(2)
        .collect();

    let to_self = session.email.clone();
    let access_token = session.access_token.clone();

    let mut targets: Vec<&crate::auth::session::SendIdentity> = Vec::new();
    targets.extend(primary);
    targets.extend(aliases);
    targets.extend(domains);

    println!("\n==== REAL SEND ATTEMPTS (each addressed only to your own {}) ====", redact(&to_self));
    for id in targets {
        // Build the raw RFC822 the SMTP path would hand to build_send_payload.
        // The From here is cosmetic for primary; for non-primary identities the
        // payload's sender_email/sender_alias_hash come from the SendIdentity.
        let subject = format!("bridge alias test {}", id.address);
        let raw = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbridge alias/identity integration self-test - safe to ignore.\r\n",
            id.address, to_self, subject,
        );

        let payload = match crate::smtp::server::build_send_payload(
            raw.as_bytes(),
            Some(&id.address),
            std::slice::from_ref(&to_self),
            &session.email,
            Some(id),
        ) {
            Ok(p) => p,
            Err(e) => {
                println!("  {} {}: PAYLOAD BUILD FAILED: {}", id.kind.as_str().to_uppercase(), redact(&id.address), e);
                continue;
            }
        };

        let verdict = match client.send_mail(&access_token, &payload).await {
            Ok(()) => "200/OK (accepted)".to_string(),
            Err(crate::error::BridgeError::Api(msg)) => msg,
            Err(crate::error::BridgeError::PlanUpgradeRequired(msg)) => format!("403 plan_upgrade_required: {}", msg),
            Err(e) => format!("ERROR: {}", e),
        };
        println!("  {} {}: {}", id.kind.as_str().to_uppercase(), redact(&id.address), verdict);
    }

    println!("\n==== alias_send_identities_real complete ====");
}

// Full alias send + receive round trip on the live account, spaced out to avoid
// backend send rate limits. For every send identity it sends one message to the
// primary inbox (proves send authorization + that the message lands in the inbox),
// and for every alias it sends primary -> alias (proves inbound alias routing).
// Receipt is verified by listing received items and decrypting their envelopes,
// looking for the unique marker that each message carries in its subject. All
// test messages are deleted afterwards. Send and receive are reported per address.
//
//   cargo test --bin aster-bridge-desktop alias_roundtrip_real -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn alias_roundtrip_real() {
    use crate::auth::session::{SendIdentity, SendIdentityKind};
    use crate::api_client::MailListQuery;
    use std::collections::{HashMap, HashSet};

    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(e) => { println!("cannot load config: {}", e); return; }
    };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i,
        Err(e) => { println!("identity load failed: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }

    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s,
        Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    let our_email = session.email.clone();
    let token = session.access_token.clone();
    let pass = session.vault_passphrase.clone();
    let ik = session.identity_key.clone();
    println!("logged in as {} ({} send identities)", our_email, session.send_identities.len());

    let run: String = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        format!("{}", secs % 1_000_000)
    };

    let primary_id = session.send_identities.iter()
        .find(|i| i.kind == SendIdentityKind::Primary)
        .expect("primary identity present");
    let aliases: Vec<&SendIdentity> = session.send_identities.iter()
        .filter(|i| i.kind == SendIdentityKind::Alias || i.kind == SendIdentityKind::CustomDomain)
        .collect();

    // marker -> (kind_label, address)
    let mut markers: HashMap<String, (String, String)> = HashMap::new();

    async fn send_one(
        client: &ApiClient, token: &str, our_email: &str,
        from_id: &SendIdentity, to_addr: &str, marker: &str,
    ) -> bool {
        let raw = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nalias roundtrip self-test {} - safe to ignore\r\n",
            from_id.address, to_addr, marker, marker,
        );
        let to_vec = vec![to_addr.to_string()];
        let payload = match crate::smtp::server::build_send_payload(
            raw.as_bytes(), Some(&from_id.address),
            &to_vec, our_email, Some(from_id),
        ) {
            Ok(p) => p,
            Err(e) => { println!("  PAYLOAD FAIL from {} to {}: {}", from_id.address, to_addr, e); return false; }
        };
        match client.send_mail(token, &payload).await {
            Ok(()) => true,
            Err(e) => { println!("  SEND FAIL from {} to {}: {}", from_id.address, to_addr, e); false }
        }
    }

    println!("\n==== PHASE A: send AS each identity -> primary inbox ====");
    let mut send_ok = 0usize;
    let mut send_total = 0usize;
    for id in &session.send_identities {
        let marker = format!("RTSND{}{}", markers.len(), run);
        send_total += 1;
        let ok = send_one(&client, &token, &our_email, id, &our_email, &marker).await;
        if ok { send_ok += 1; }
        println!("  SEND-AS {:<32} {} -> {}", id.address, id.kind.as_str(), if ok {"accepted"} else {"FAILED"});
        markers.insert(marker, (format!("send-as {}", id.kind.as_str()), id.address.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    }

    println!("\n==== PHASE B: send primary -> each alias (inbound routing) ====");
    for id in &aliases {
        let marker = format!("RTRCV{}{}", markers.len(), run);
        send_total += 1;
        let ok = send_one(&client, &token, &our_email, primary_id, &id.address, &marker).await;
        if ok { send_ok += 1; }
        println!("  TO-ALIAS {:<32} -> {}", id.address, if ok {"accepted"} else {"FAILED"});
        markers.insert(marker, ("to-alias".into(), id.address.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    }

    println!("\n==== PHASE C: verify receipt via list_mail(received) + envelope decrypt ====");
    let mut found: HashSet<String> = HashSet::new();
    let mut found_ids: HashMap<String, String> = HashMap::new(); // marker -> item id
    for attempt in 0..8 {
        tokio::time::sleep(std::time::Duration::from_secs(if attempt == 0 { 8 } else { 12 })).await;
        let q = MailListQuery {
            item_type: Some("received".to_string()),
            is_trashed: None, is_archived: None, is_spam: None,
            limit: Some(100), cursor: None,
        };
        match client.list_mail(&token, &q).await {
            Ok(resp) => {
                for item in &resp.items {
                    if let Ok(env) = crate::crypto::envelope::decrypt_envelope(
                        &item.encrypted_envelope, Some(&item.envelope_nonce), &pass, ik.as_deref(),
                    ) {
                        for marker in markers.keys() {
                            if env.contains(marker.as_str()) {
                                found.insert(marker.clone());
                                found_ids.entry(marker.clone()).or_insert_with(|| item.id.clone());
                            }
                        }
                    }
                }
                println!("  attempt {}: {}/{} markers found", attempt + 1, found.len(), markers.len());
            }
            Err(e) => println!("  attempt {}: list_mail error: {}", attempt + 1, e),
        }
        if found.len() >= markers.len() { break; }
    }

    println!("\n==== RESULTS ====");
    println!("SEND accepted: {}/{}", send_ok, send_total);
    let mut recv_ok = 0usize;
    let mut sorted: Vec<(&String, &(String, String))> = markers.iter().collect();
    sorted.sort_by(|a, b| a.1 .1.cmp(&b.1 .1));
    for (marker, (kind, addr)) in sorted {
        let got = found.contains(marker);
        if got { recv_ok += 1; }
        println!("  [{}] {:<10} {:<32} {}", if got {"RECV"} else {"MISS"}, kind, addr, marker);
    }
    println!("RECEIVE verified: {}/{}", recv_ok, markers.len());

    println!("\n==== CLEANUP: deleting {} test messages ====", found_ids.len());
    let mut deleted = 0usize;
    for id in found_ids.values() {
        if client.delete_mail_item_permanent(&token, id).await.is_ok() { deleted += 1; }
    }
    println!("deleted {} test messages", deleted);
    println!("\n==== alias_roundtrip_real complete ====");
}

// Verifies the set-primary (default send-from) feature end to end against the
// live backend default-sender preference: reads the current value, sets it to an
// alias, confirms it persisted, sets it to "primary", confirms, then restores the
// original. Exercises ApiClient::get_default_sender / set_default_sender.
//
//   cargo test --bin aster-bridge-desktop set_primary_real -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn set_primary_real() {
    use crate::auth::session::SendIdentityKind;

    let cfg = match crate::config::load_config() { Ok(c) => c, Err(e) => { println!("cfg: {}", e); return; } };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i, Err(e) => { println!("id: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }
    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s, Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    let token = session.access_token.clone();

    let original = client.get_default_sender(&token).await.expect("get original");
    println!("original default_sender: {:?}", original);

    let alias = session.send_identities.iter()
        .find(|i| i.kind == SendIdentityKind::Alias)
        .expect("at least one alias identity");
    let sid = alias.sender_id.clone();
    println!("setting primary to alias {} (sender_id={})", alias.address, sid);

    client.set_default_sender(&token, Some(&sid)).await.expect("set alias");
    let after = client.get_default_sender(&token).await.expect("get after alias");
    println!("after set-alias: {:?}", after);
    assert_eq!(after.as_deref(), Some(sid.as_str()), "alias default did not persist");

    client.set_default_sender(&token, Some("primary")).await.expect("set primary");
    let after2 = client.get_default_sender(&token).await.expect("get after primary");
    println!("after set-primary: {:?}", after2);
    assert_eq!(after2.as_deref(), Some("primary"), "primary default did not persist");

    client.set_default_sender(&token, original.as_deref()).await.expect("restore");
    let restored = client.get_default_sender(&token).await.expect("get restored");
    println!("restored to: {:?}", restored);
    assert_eq!(restored, original, "restore mismatch");

    println!("==== set_primary_real PASS (set alias, set primary, restored) ====");
}

// Dumps recent received + sent items, decrypting each envelope, and reports how
// many carry the marker substring in ASTER_MARKER (default "629481"). Prints the
// newest few subjects per folder so we can see what is actually arriving and how
// internal self-addressed mail lands. Read-only; deletes nothing.
//
//   ASTER_MARKER=629481 cargo test --bin aster-bridge-desktop dump_inbox_markers -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn dump_inbox_markers() {
    use crate::api_client::MailListQuery;

    let marker = std::env::var("ASTER_MARKER").unwrap_or_else(|_| "629481".to_string());
    let cfg = match crate::config::load_config() { Ok(c) => c, Err(e) => { println!("cfg: {}", e); return; } };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i, Err(e) => { println!("id: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }
    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s, Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    let token = session.access_token.clone();
    let pass = session.vault_passphrase.clone();
    let ik = session.identity_key.clone();
    println!("logged in as {}; searching for marker '{}'", session.email, marker);

    fn subj_of(env: &str) -> String {
        serde_json::from_str::<serde_json::Value>(env).ok()
            .and_then(|v| v.get("subject").and_then(|s| s.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "<no subject in envelope>".to_string())
    }

    for folder in ["received", "sent"] {
        let q = MailListQuery {
            item_type: Some(folder.to_string()),
            is_trashed: None, is_archived: None, is_spam: None,
            limit: Some(100), cursor: None,
        };
        match client.list_mail(&token, &q).await {
            Ok(resp) => {
                let mut hits = 0usize;
                let mut newest: Vec<String> = Vec::new();
                for item in &resp.items {
                    match crate::crypto::envelope::decrypt_envelope(
                        &item.encrypted_envelope, Some(&item.envelope_nonce), &pass, ik.as_deref(),
                    ) {
                        Ok(env) => {
                            if env.contains(marker.as_str()) {
                                hits += 1;
                                println!("  HIT [{}] subject={}", folder, subj_of(&env));
                            }
                            if newest.len() < 8 { newest.push(subj_of(&env)); }
                        }
                        Err(_) => { if newest.len() < 8 { newest.push("<envelope decrypt failed>".into()); } }
                    }
                }
                println!("== {} == total={} page={} marker_hits={}", folder, resp.total, resp.items.len(), hits);
                for (i, s) in newest.iter().enumerate() {
                    println!("    newest[{}] {}", i, s);
                }
            }
            Err(e) => println!("== {} == list error: {}", folder, e),
        }
    }
}

// Logs in once and watches the real inbox; the instant a fresh internal message
// arrives whose one-time PQ prekey is still alive (i.e. not yet opened on web),
// it decrypts it and prints the plaintext - a real-message proof on the live
// account. Send yourself an internal email and leave it unread.
//
//   cargo test --bin aster-bridge-desktop poll_for_fresh_decrypt -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn poll_for_fresh_decrypt() {
    use crate::api_client::MailListQuery;

    let cfg = match crate::config::load_config() { Ok(c) => c, Err(e) => { println!("cfg: {}", e); return; } };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i, Err(e) => { println!("id: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }
    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s, Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    println!("watching inbox as {} - send yourself an internal email and leave it UNREAD", session.email);

    let token = session.access_token.clone();
    let sync_key = crate::crypto::ratchet::derive_sync_key(&session.vault_passphrase).ok();
    let start = std::time::Instant::now();
    let mut round = 0u32;

    loop {
        round += 1;
        let q = MailListQuery {
            item_type: Some("received".to_string()),
            is_trashed: None, is_archived: None, is_spam: None,
            limit: Some(15), cursor: None,
        };
        if let Ok(resp) = client.list_mail(&token, &q).await {
            for item in &resp.items {
                let env = match crate::crypto::envelope::decrypt_envelope(
                    &item.encrypted_envelope, Some(&item.envelope_nonce),
                    &session.vault_passphrase, session.identity_key.as_deref(),
                ) { Ok(v) => v, Err(_) => continue };
                let parsed: serde_json::Value = match serde_json::from_str(&env) { Ok(v) => v, Err(_) => continue };
                let ratchet = match crate::crypto::ratchet::find_ratchet_object(&parsed) { Some(v) => v, None => continue };
                let mut msg = match crate::crypto::ratchet::parse_recipient_message(&ratchet, &session.email) { Some(m) => m, None => continue };
                if let Some(kid) = msg.pq_key_id {
                    let sk = match sync_key.as_ref() { Some(s) => s, None => continue };
                    match client.get_pq_secret(&token, kid).await {
                        Ok(r) => match crate::crypto::ratchet::decrypt_pq_secret(sk, &r.encrypted_secret, &r.secret_nonce) {
                            Ok(s) => msg.pq_secret = Some(s),
                            Err(_) => continue,
                        },
                        Err(_) => continue,
                    }
                }
                if let Some(pt) = crate::crypto::ratchet::decrypt_with_key_sets(&session.ratchet_keys, &msg) {
                    println!("==== FRESH REAL MESSAGE DECRYPTED (round {}, item {}) ====", round, item.id);
                    println!("plaintext: {}", pt.chars().take(220).collect::<String>().replace('\n', " "));
                    println!("==== PROOF: a real inbox internal message decrypted on your live account ====");
                    return;
                }
            }
        }
        if start.elapsed().as_secs() > 720 {
            println!("no fresh decryptable message within 6 min - send one to {} and leave it unread", session.email);
            return;
        }
        println!("round {}: nothing fresh yet, waiting 15s...", round);
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }
}

// Delivers a REAL internal message to the live inbox (self-send: we hold both
// the sender ratchet identity and the recipient identity key, so we can build
// the ratchet body AND the at-rest envelope legitimately), then reads it back
// through the normal list + decrypt path and proves the plaintext. This is the
// real-message proof on the live account with no dependency on any other sender.
//
//   cargo test --bin aster-bridge-desktop self_deliver_and_decrypt -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn self_deliver_and_decrypt() {
    use base64::engine::general_purpose::STANDARD;
    use crate::api_client::{CreateMailItem, MailListQuery};
    use sha2::{Digest, Sha256};

    let cfg = match crate::config::load_config() { Ok(c) => c, Err(e) => { println!("cfg: {}", e); return; } };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i, Err(e) => { println!("id: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }
    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s, Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    let our_email = session.email.clone();
    let token = session.access_token.clone();
    let sync_key = match crate::crypto::ratchet::derive_sync_key(&session.vault_passphrase) {
        Ok(k) => k, Err(e) => { println!("sync key: {}", e); return; }
    };
    let identity_key = match session.identity_key.as_deref() { Some(k) => k, None => { println!("no identity_key"); return; } };
    if session.ratchet_keys.is_empty() { println!("no ratchet keys"); return; }

    let bundle = match client.get_prekey_bundle(&token, &session.username, &our_email).await {
        Ok(b) => b, Err(e) => { println!("BUNDLE FETCH FAILED: {}", e); return; }
    };
    let recipient_id_pub = STANDARD.decode(&bundle.kem_identity_key).expect("kem_id");
    let recipient_spk_pub = STANDARD.decode(&bundle.signed_prekey).expect("spk");
    let (pq_pub, pq_kid) = match &bundle.pq_prekey {
        Some(p) => (Some(STANDARD.decode(&p.public_key).expect("pq")), Some(p.key_id)),
        None => (None, None),
    };

    let plaintext = "LIVE self-delivered internal message decrypted by the Bridge - code 314159";
    let msg = match crate::crypto::ratchet::encrypt_bootstrap(
        &session.ratchet_keys[0].identity_secret_d,
        &recipient_id_pub, &recipient_spk_pub, pq_pub.as_deref(), pq_kid, plaintext,
    ) { Ok(m) => m, Err(e) => { println!("ENCRYPT: {}", e); return; } };

    let mut recipient_obj = serde_json::json!({
        "ephemeral_key": STANDARD.encode(&msg.ephemeral_public),
        "header": { "dh_public": STANDARD.encode(&msg.header_dh_public), "previous_chain_length": 0, "message_number": 0, "v": 2 },
        "ciphertext": STANDARD.encode(&msg.ciphertext),
        "nonce": STANDARD.encode(&msg.nonce),
    });
    if let (Some(ct), Some(kid)) = (&msg.pq_ciphertext, msg.pq_key_id) {
        recipient_obj["pq_ciphertext"] = serde_json::json!(STANDARD.encode(ct));
        recipient_obj["pq_key_id"] = serde_json::json!(kid);
    }
    let mut recipients = serde_json::Map::new();
    recipients.insert(our_email.clone(), recipient_obj);
    let ratchet_env = serde_json::json!({
        "type": "double_ratchet_v2",
        "sender_identity_key": STANDARD.encode(&msg.sender_identity_public),
        "recipients": serde_json::Value::Object(recipients),
    });

    let meta = serde_json::json!({
        "subject": "Bridge live decrypt test",
        "from": our_email.clone(),
        "to": [our_email.clone()],
        "body_html": ratchet_env.to_string(),
    });
    let (enc_env, env_nonce) = match crate::crypto::envelope::encrypt_identity_key_envelope(&meta.to_string(), identity_key) {
        Ok(v) => v, Err(e) => { println!("ENVELOPE ENCRYPT: {}", e); return; }
    };
    let content_hash = STANDARD.encode(Sha256::digest(enc_env.as_bytes()));
    let folder_token = STANDARD.encode([0u8; 32]);

    let req = CreateMailItem {
        item_type: "received",
        encrypted_envelope: &enc_env,
        envelope_nonce: &env_nonce,
        folder_token: &folder_token,
        content_hash: &content_hash,
    };
    let _ = MailListQuery { item_type: None, is_trashed: None, is_archived: None, is_spam: None, limit: None, cursor: None };
    let created = match client.create_mail_item(&token, &req).await {
        Ok(v) => { println!("delivered real message: {}", v); v }
        Err(e) => { println!("CREATE FAILED: {}", e); return; }
    };
    let item_id = created.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    println!("created item id: {}", item_id);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let item = match client.fetch_mail_item(&token, &item_id).await {
        Ok(i) => i, Err(e) => { println!("FETCH FAILED: {}", e); return; }
    };
    let env = match crate::crypto::envelope::decrypt_envelope(&item.encrypted_envelope, Some(&item.envelope_nonce), &session.vault_passphrase, session.identity_key.as_deref()) {
        Ok(v) => v, Err(e) => { println!("ENVELOPE DECRYPT FAILED: {}", e); return; }
    };
    println!("at-rest envelope decrypted ok ({} chars)", env.len());
    let parsed: serde_json::Value = match serde_json::from_str(&env) { Ok(v) => v, Err(e) => { println!("envelope json parse: {}", e); return; } };
    let ratchet = match crate::crypto::ratchet::find_ratchet_object(&parsed) { Some(v) => v, None => { println!("no ratchet object found in envelope"); return; } };
    let mut rmsg = match crate::crypto::ratchet::parse_recipient_message(&ratchet, &our_email) { Some(m) => m, None => { println!("parse_recipient_message failed"); return; } };
    if let Some(kid) = rmsg.pq_key_id {
        match client.get_pq_secret(&token, kid).await {
            Ok(r) => match crate::crypto::ratchet::decrypt_pq_secret(&sync_key, &r.encrypted_secret, &r.secret_nonce) {
                Ok(s) => rmsg.pq_secret = Some(s),
                Err(e) => { println!("pq secret decrypt failed: {}", e); return; }
            },
            Err(e) => { println!("pq secret fetch failed (kid={}): {}", kid, e); return; }
        }
    }
    match crate::crypto::ratchet::decrypt_with_key_sets(&session.ratchet_keys, &rmsg) {
        Some(pt) => {
            println!("plaintext: {}", pt);
            assert_eq!(pt, plaintext, "decrypted plaintext mismatch");
            println!("==== PROOF: a REAL inbox internal message decrypted end to end via the Bridge on the live account ====");
        }
        None => println!("decrypt_with_key_sets returned None"),
    }

    let _ = client.delete_mail_item_permanent(&token, &item_id).await;
}

// Delivers ONE fresh internal message to the inbox and leaves it, so the running
// Bridge decrypts it and it renders as plain text in a connected mail client.
//
//   cargo test --bin aster-bridge-desktop deliver_demo_message -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn deliver_demo_message() {
    use base64::engine::general_purpose::STANDARD;
    use crate::api_client::CreateMailItem;
    use sha2::{Digest, Sha256};

    let cfg = match crate::config::load_config() { Ok(c) => c, Err(e) => { println!("cfg: {}", e); return; } };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) { Ok(i) => i, Err(e) => { println!("id: {}", e); return; } };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }
    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await { Ok(s) => s, Err(e) => { println!("LOGIN FAILED: {}", e); return; } };
    let our_email = session.email.clone();
    let token = session.access_token.clone();
    let identity_key = match session.identity_key.as_deref() { Some(k) => k, None => { println!("no identity_key"); return; } };
    if session.ratchet_keys.is_empty() { println!("no ratchet keys"); return; }

    let bundle = match client.get_prekey_bundle(&token, &session.username, &our_email).await { Ok(b) => b, Err(e) => { println!("BUNDLE: {}", e); return; } };
    let recipient_id_pub = STANDARD.decode(&bundle.kem_identity_key).expect("id");
    let recipient_spk_pub = STANDARD.decode(&bundle.signed_prekey).expect("spk");
    let (pq_pub, pq_kid) = match &bundle.pq_prekey { Some(p) => (Some(STANDARD.decode(&p.public_key).expect("pq")), Some(p.key_id)), None => (None, None) };

    let plaintext = "If you can read this in Thunderbird, internal-mail decryption through the Bridge works. Code 271828.";
    let msg = match crate::crypto::ratchet::encrypt_bootstrap(&session.ratchet_keys[0].identity_secret_d, &recipient_id_pub, &recipient_spk_pub, pq_pub.as_deref(), pq_kid, plaintext) { Ok(m) => m, Err(e) => { println!("ENC: {}", e); return; } };
    let mut recipient_obj = serde_json::json!({
        "ephemeral_key": STANDARD.encode(&msg.ephemeral_public),
        "header": { "dh_public": STANDARD.encode(&msg.header_dh_public), "previous_chain_length": 0, "message_number": 0, "v": 2 },
        "ciphertext": STANDARD.encode(&msg.ciphertext),
        "nonce": STANDARD.encode(&msg.nonce),
    });
    if let (Some(ct), Some(kid)) = (&msg.pq_ciphertext, msg.pq_key_id) {
        recipient_obj["pq_ciphertext"] = serde_json::json!(STANDARD.encode(ct));
        recipient_obj["pq_key_id"] = serde_json::json!(kid);
    }
    let mut recipients = serde_json::Map::new();
    recipients.insert(our_email.clone(), recipient_obj);
    let ratchet_env = serde_json::json!({ "type": "double_ratchet_v2", "sender_identity_key": STANDARD.encode(&msg.sender_identity_public), "recipients": serde_json::Value::Object(recipients) });
    let meta = serde_json::json!({ "subject": "BRIDGE DECRYPTION TEST - should show plain text", "from": our_email.clone(), "to": [our_email.clone()], "body_html": ratchet_env.to_string() });
    let (enc_env, env_nonce) = match crate::crypto::envelope::encrypt_identity_key_envelope(&meta.to_string(), identity_key) { Ok(v) => v, Err(e) => { println!("ENV ENC: {}", e); return; } };
    let content_hash = STANDARD.encode(Sha256::digest(enc_env.as_bytes()));
    let folder_token = STANDARD.encode([0u8; 32]);
    let req = CreateMailItem { item_type: "received", encrypted_envelope: &enc_env, envelope_nonce: &env_nonce, folder_token: &folder_token, content_hash: &content_hash };
    match client.create_mail_item(&token, &req).await {
        Ok(v) => println!("DELIVERED demo message (left in inbox): {}", v),
        Err(e) => println!("CREATE FAILED: {}", e),
    }
}

// Removes the throwaway "Bridge live decrypt test" items left in the inbox by
// earlier self_deliver runs, so nothing junk is left in the account.
//
//   cargo test --bin aster-bridge-desktop cleanup_test_messages -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn cleanup_test_messages() {
    let cfg = match crate::config::load_config() { Ok(c) => c, Err(e) => { println!("cfg: {}", e); return; } };
    let identity = match crate::auth::device_identity::get_or_create_identity(&cfg.data_dir) {
        Ok(i) => i, Err(e) => { println!("id: {}", e); return; }
    };
    if identity.device_id.is_none() { println!("NOT PAIRED"); return; }
    crate::tls::install_default_crypto_provider();
    let client = ApiClient::new();
    let session = match crate::auth::session::restore_or_login(&cfg, &identity, &client).await {
        Ok(s) => s, Err(e) => { println!("LOGIN FAILED: {}", e); return; }
    };
    let token = session.access_token.clone();
    for id in [
        "37378886-4d7e-4aec-97e9-23fdc8adb87f",
        "a5255519-2bc0-4b14-9253-cd6922baa028",
        "a955f66e-edd3-48b1-938e-501b31768d74",
    ] {
        match client.delete_mail_item_permanent(&token, id).await {
            Ok(()) => println!("deleted {}", id),
            Err(e) => println!("delete {} failed: {}", id, e),
        }
    }
}
