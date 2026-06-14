//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{extract::Request, Router};
use tokio::sync::{broadcast, RwLock};

use crate::api_client::ApiClient;
use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;
use crate::db::Database;

use super::auth::JmapAuth;
use super::state::{JmapContext, StateChange};

#[derive(Clone)]
pub struct AppState {
    pub ctx: Arc<JmapContext>,
    pub auth: Arc<JmapAuth>,
    pub bind_port: u16,
    pub use_https: bool,
}

impl FromRef<AppState> for Arc<JmapAuth> {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

impl FromRef<AppState> for Arc<JmapContext> {
    fn from_ref(s: &AppState) -> Self {
        s.ctx.clone()
    }
}

pub async fn run(
    addr: &str,
    session: Arc<RwLock<Session>>,
    db: Arc<Database>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    broadcaster: broadcast::Sender<StateChange>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), String> {
    let _ = db.seed_jmap_mailboxes();

    let auth = Arc::new(JmapAuth {
        passwords,
        session: session.clone(),
    });

    let use_https = tls_config.is_some();
    let ctx = JmapContext::new(session, db, client, broadcaster);

    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;

    let state = AppState {
        ctx,
        auth,
        bind_port: sock_addr.port(),
        use_https,
    };

    let bind_port = sock_addr.port();
    let app = Router::new()
        .route("/.well-known/jmap", get(super::session::well_known))
        .route("/jmap/session", get(super::session::session_resource))
        .route(
            "/jmap/api",
            post(super::dispatcher::handle).layer(DefaultBodyLimit::max(10_000_000)),
        )
        .route(
            "/jmap/upload/:account_id",
            post(super::blob::upload).layer(DefaultBodyLimit::max(50_000_000)),
        )
        .route(
            "/jmap/download/:account_id/:blob_id/:name",
            get(super::blob::download),
        )
        .route("/jmap/eventsource", get(super::sse::eventsource))
        .route("/jmap/ws", get(super::ws::ws_upgrade))
        .layer(middleware::from_fn(move |req, next| host_guard(req, next, bind_port, use_https)))
        .layer(middleware::from_fn(loopback_only))
        .with_state(state);

    if let Some(cfg) = tls_config {
        tracing::info!("JMAP server listening on https://{}", sock_addr);
        let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(cfg);
        axum_server::bind_rustls(sock_addr, rustls_cfg)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| e.to_string())
    } else {
        let listener = tokio::net::TcpListener::bind(sock_addr)
            .await
            .map_err(|e| format!("bind {} failed: {}", sock_addr, e))?;

        tracing::info!("JMAP server listening on http://{}", sock_addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| e.to_string())
    }
}

async fn loopback_only(req: Request, next: Next) -> Response {
    match req.extensions().get::<ConnectInfo<SocketAddr>>().cloned() {
        Some(ConnectInfo(addr)) if addr.ip().is_loopback() => next.run(req).await,
        _ => (StatusCode::FORBIDDEN, "loopback only").into_response(),
    }
}

async fn host_guard(req: Request, next: Next, port: u16, use_https: bool) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allowed = [
        format!("127.0.0.1:{}", port),
        format!("localhost:{}", port),
        format!("[::1]:{}", port),
    ];
    if !allowed.iter().any(|a| a.eq_ignore_ascii_case(host)) {
        return (StatusCode::FORBIDDEN, "bad host").into_response();
    }

    let path = req.uri().path();
    let method = req.method().clone();
    let is_public = path == "/.well-known/jmap";
    let is_sensitive = matches!(
        path,
        "/jmap/session" | "/jmap/api" | "/jmap/eventsource" | "/jmap/ws"
    ) || path.starts_with("/jmap/upload")
        || path.starts_with("/jmap/download");

    if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let scheme = if use_https { "https" } else { "http" };
        let ok_origins = [
            format!("{}://127.0.0.1:{}", scheme, port),
            format!("{}://localhost:{}", scheme, port),
            format!("{}://[::1]:{}", scheme, port),
        ];
        if !ok_origins.iter().any(|a| a.eq_ignore_ascii_case(origin)) {
            return (StatusCode::FORBIDDEN, "bad origin").into_response();
        }
    }
    if is_sensitive && !is_public {
        if let Some(sfs) = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
        {
            if !sfs.eq_ignore_ascii_case("same-origin") && !sfs.eq_ignore_ascii_case("none") {
                return (StatusCode::FORBIDDEN, "cross-site request blocked").into_response();
            }
        }
    }

    if path == "/jmap/api" && method == axum::http::Method::POST {
        let ct = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let base = ct.split(';').next().unwrap_or("").trim();
        if !base.eq_ignore_ascii_case("application/json") {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "content-type must be application/json",
            )
                .into_response();
        }
    }

    next.run(req).await
}

use axum::response::IntoResponse;

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use crate::auth::session::Session;
    use base64::Engine;
    use serde_json::json;
    use std::time::Duration;
    use uuid::Uuid;

    async fn start_server() -> (String, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
        let _ = db.seed_jmap_mailboxes();

        let passwords = Arc::new(AppPasswords::new(db.clone()));
        let _id = passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();

        let session = Arc::new(RwLock::new(Session {
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
        }));

        let client = Arc::new(ApiClient::new());
        let basic = base64::engine::general_purpose::STANDARD
            .encode(b"tester@aster.test:abcd-efgh-ijkl-mnop");
        let auth = format!("Basic {}", basic);
        for _ in 0..20 {
            let _g = crate::port_picker::TEST_SERVER_START.lock().await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
            drop(listener);
            let url_base = format!("http://{}", addr);
            let (tx, _rx) = broadcast::channel(8);
            let (s, d, c, p) = (session.clone(), db.clone(), client.clone(), passwords.clone());
            tokio::spawn(async move {
                let _ = run(&addr, s, d, c, p, tx, None).await;
            });
            let mut ready = false;
            for _ in 0..200 {
                if reqwest::get(format!("{}/.well-known/jmap", url_base)).await.is_ok() {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            if ready {
                return (url_base, auth, dir);
            }
        }
        panic!("jmap test server did not become ready");
    }

    #[tokio::test]
    async fn well_known_open() {
        let (base, _auth, _dir) = start_server().await;
        let r = reqwest::get(format!("{}/.well-known/jmap", base))
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let v: serde_json::Value = r.json().await.unwrap();
        assert_eq!(v["@type"], "Session");
        assert!(v["redirectUrl"].as_str().unwrap().contains("/jmap/session"));
    }

    #[tokio::test]
    async fn session_requires_auth() {
        let (base, _auth, _dir) = start_server().await;
        let r = reqwest::get(format!("{}/jmap/session", base))
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
        assert!(r.headers().contains_key("www-authenticate"));
    }

    #[tokio::test]
    async fn session_with_auth_returns_capabilities() {
        let (base, auth, _dir) = start_server().await;
        let r = reqwest::Client::new()
            .get(format!("{}/jmap/session", base))
            .header("authorization", auth)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let v: serde_json::Value = r.json().await.unwrap();
        assert_eq!(v["username"], "tester@aster.test");
        assert!(v["capabilities"]["urn:ietf:params:jmap:core"].is_object());
        assert!(v["capabilities"]["urn:ietf:params:jmap:mail"].is_object());
        assert!(v["apiUrl"].as_str().unwrap().ends_with("/jmap/api"));
    }

    #[tokio::test]
    async fn mailbox_get_returns_seeded_folders() {
        let (base, auth, _dir) = start_server().await;
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [["Mailbox/get", {}, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let v: serde_json::Value = r.json().await.unwrap();
        let resp = &v["methodResponses"][0];
        assert_eq!(resp[0], "Mailbox/get");
        assert_eq!(resp[2], "c0");
        let list = resp[1]["list"].as_array().unwrap();
        assert!(!list.is_empty(), "expected seeded mailboxes");
        let names: Vec<String> = list
            .iter()
            .map(|m| m["name"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(names.iter().any(|n| n == "Inbox"));
    }

    #[tokio::test]
    async fn unknown_capability_rejected() {
        let (base, auth, _dir) = start_server().await;
        let body = json!({
            "using": ["urn:ietf:params:jmap:bogus"],
            "methodCalls": [["Mailbox/get", {}, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        assert_eq!(v["type"], "urn:ietf:params:jmap:error:unknownCapability");
    }

    #[tokio::test]
    async fn back_reference_resolves() {
        let (base, auth, _dir) = start_server().await;
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Mailbox/query", {}, "c0"],
                ["Mailbox/get", {
                    "#ids": {"resultOf": "c0", "name": "Mailbox/query", "path": "/ids"}
                }, "c1"]
            ]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        let second = &v["methodResponses"][1];
        assert_eq!(second[0], "Mailbox/get");
        assert!(second[1]["list"].as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn identity_get_returns_email() {
        let (base, auth, _dir) = start_server().await;
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"],
            "methodCalls": [["Identity/get", {}, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        let list = v["methodResponses"][0][1]["list"].as_array().unwrap();
        assert_eq!(list[0]["email"], "tester@aster.test");
    }

    async fn start_server_with_db() -> (String, String, Arc<Database>, tempfile::TempDir) {
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
        let basic = base64::engine::general_purpose::STANDARD
            .encode(b"tester@aster.test:abcd-efgh-ijkl-mnop");
        let auth = format!("Basic {}", basic);
        for _ in 0..20 {
            let _g = crate::port_picker::TEST_SERVER_START.lock().await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
            drop(listener);
            let url_base = format!("http://{}", addr);
            let (tx, _rx) = broadcast::channel(8);
            let (s, d, c, p) = (session.clone(), db.clone(), client.clone(), passwords.clone());
            tokio::spawn(async move {
                let _ = run(&addr, s, d, c, p, tx, None).await;
            });
            let mut ready = false;
            for _ in 0..200 {
                if reqwest::get(format!("{}/.well-known/jmap", url_base)).await.is_ok() {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            if ready {
                return (url_base, auth, db, dir);
            }
        }
        panic!("jmap test server did not become ready");
    }

    fn seed_message(db: &Database, id: &str, folder: &str, subject: &str, body: &str) {
        db.upsert_cached_message(
            id,
            folder,
            Some(subject),
            Some("alice@example.com"),
            Some("tester@aster.test"),
            Some("2026-05-21T10:00:00Z"),
            (subject.len() + body.len()) as i64,
            Some(body),
            Some(&format!(
                "From: alice@example.com\r\nTo: tester@aster.test\r\nSubject: {}\r\nDate: Wed, 21 May 2026 10:00:00 +0000\r\nMessage-ID: <{}@test>\r\n",
                subject, id
            )),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let (base, _good, _dir) = start_server().await;
        let bad = base64::engine::general_purpose::STANDARD
            .encode(b"tester@aster.test:wrong-pass-here");
        let r = reqwest::Client::new()
            .get(format!("{}/jmap/session", base))
            .header("authorization", format!("Basic {}", bad))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn wrong_username_rejected() {
        let (base, _good, _dir) = start_server().await;
        let bad = base64::engine::general_purpose::STANDARD
            .encode(b"mallory@evil.example:abcd-efgh-ijkl-mnop");
        let r = reqwest::Client::new()
            .get(format!("{}/jmap/session", base))
            .header("authorization", format!("Basic {}", bad))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn malformed_basic_rejected() {
        let (base, _auth, _dir) = start_server().await;
        for header_val in [
            "Bearer abcdef",
            "Basic ###not-base64###",
            "Basic dGVzdGVy",
            "",
        ] {
            let mut req = reqwest::Client::new().get(format!("{}/jmap/session", base));
            if !header_val.is_empty() {
                req = req.header("authorization", header_val);
            }
            let r = req.send().await.unwrap();
            assert_eq!(r.status(), 401, "header={}", header_val);
        }
    }

    #[tokio::test]
    async fn api_text_plain_rejected() {
        let (base, auth, _dir) = start_server().await;
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .header("content-type", "text/plain")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 415);
    }

    #[tokio::test]
    async fn api_cross_site_blocked() {
        let (base, auth, _dir) = start_server().await;
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .header("content-type", "application/json")
            .header("sec-fetch-site", "cross-site")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
    }

    #[tokio::test]
    async fn email_get_and_query_against_seeded() {
        let (base, auth, db, _dir) = start_server_with_db().await;
        seed_message(&db, "m1", "Inbox", "Welcome to Aster", "Hello world body text");
        seed_message(&db, "m2", "Inbox", "Receipt #1234", "Thanks for your purchase");
        seed_message(&db, "m3", "Sent", "Re: hello", "thread reply body");

        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Email/query", {"sort": [{"property":"receivedAt","isAscending":false}]}, "c0"],
                ["Email/get", {
                    "#ids": {"resultOf":"c0","name":"Email/query","path":"/ids"},
                    "properties": ["id","subject","from","receivedAt","size","threadId"]
                }, "c1"]
            ]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let v: serde_json::Value = r.json().await.unwrap();
        let ids = v["methodResponses"][0][1]["ids"].as_array().unwrap();
        assert!(ids.len() >= 3, "expected at least 3 seeded ids, got {}", ids.len());
        let list = v["methodResponses"][1][1]["list"].as_array().unwrap();
        assert_eq!(list.len(), ids.len());
        let subjects: Vec<&str> = list
            .iter()
            .map(|m| m["subject"].as_str().unwrap_or(""))
            .collect();
        assert!(subjects.contains(&"Welcome to Aster"));
        assert!(subjects.contains(&"Receipt #1234"));
    }

    #[tokio::test]
    async fn search_snippet_marks_term() {
        let (base, auth, db, _dir) = start_server_with_db().await;
        seed_message(&db, "s1", "Inbox", "Quarterly report", "The numbers look great this quarter");

        let body = json!({
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [["SearchSnippet/get", {
                "emailIds": ["s1"],
                "filter": {"text": "numbers"}
            }, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        let list = v["methodResponses"][0][1]["list"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        let preview = list[0]["preview"].as_str().unwrap_or("");
        assert!(preview.contains("<mark>numbers</mark>"), "preview={}", preview);
    }

    #[tokio::test]
    async fn blob_upload_download_roundtrip_and_dedup() {
        let (base, auth, _db, _dir) = start_server_with_db().await;
        let client = reqwest::Client::new();
        let payload = b"hello blob world";

        let sess: serde_json::Value = client
            .get(format!("{}/jmap/session", base))
            .header("authorization", auth.clone())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let acct = sess["primaryAccounts"]["urn:ietf:params:jmap:mail"]
            .as_str()
            .unwrap()
            .to_string();
        let r1 = client
            .post(format!("{}/jmap/upload/{}", base, acct))
            .header("authorization", auth.clone())
            .header("content-type", "application/octet-stream")
            .body(payload.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), 200);
        let v1: serde_json::Value = r1.json().await.unwrap();
        let blob_id = v1["blobId"].as_str().unwrap().to_string();
        assert!(!blob_id.is_empty());
        assert_eq!(v1["size"].as_u64().unwrap(), payload.len() as u64);

        let r_dup = client
            .post(format!("{}/jmap/upload/{}", base, acct))
            .header("authorization", auth.clone())
            .header("content-type", "text/different")
            .body(payload.to_vec())
            .send()
            .await
            .unwrap();
        let vd: serde_json::Value = r_dup.json().await.unwrap();
        assert_eq!(vd["blobId"].as_str().unwrap(), blob_id);
        assert_eq!(
            vd["type"].as_str().unwrap(),
            "application/octet-stream",
            "dedup must NOT overwrite content-type"
        );

        let r_dl = client
            .get(format!(
                "{}/jmap/download/{}/{}/anything.bin",
                base, acct, blob_id
            ))
            .header("authorization", auth)
            .send()
            .await
            .unwrap();
        assert_eq!(r_dl.status(), 200);
        let bytes = r_dl.bytes().await.unwrap();
        assert_eq!(&bytes[..], payload);
    }

    #[tokio::test]
    async fn mailbox_get_too_many_ids() {
        let (base, auth, _dir) = start_server().await;
        let many: Vec<String> = (0..600).map(|i| format!("id{}", i)).collect();
        let body = json!({
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [["Mailbox/get", {"ids": many}, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        assert_eq!(v["methodResponses"][0][0], "error");
        assert_eq!(v["methodResponses"][0][1]["type"], "requestTooLarge");
    }

    #[tokio::test]
    async fn back_ref_with_wrong_name_rejected() {
        let (base, auth, _dir) = start_server().await;
        let body = json!({
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Mailbox/query", {}, "c0"],
                ["Email/get", {
                    "#ids": {"resultOf":"c0","name":"Email/query","path":"/ids"}
                }, "c1"]
            ]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        assert_eq!(v["methodResponses"][1][0], "error");
    }

    #[tokio::test]
    async fn malformed_json_rejected_gracefully() {
        let (base, auth, _dir) = start_server().await;
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .header("content-type", "application/json")
            .body("{not json")
            .send()
            .await
            .unwrap();
        assert!(r.status().is_client_error());
    }

    #[tokio::test]
    async fn evil_host_header_rejected() {
        let (base, auth, _dir) = start_server().await;
        let r = reqwest::Client::new()
            .get(format!("{}/jmap/session", base))
            .header("authorization", auth)
            .header("host", "attacker.example")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
    }

    #[tokio::test]
    async fn fts_text_filter_returns_only_matches() {
        let (base, auth, db, _dir) = start_server_with_db().await;
        seed_message(&db, "f1", "Inbox", "Quarterly report Q1", "Revenue numbers look good");
        seed_message(&db, "f2", "Inbox", "Lunch tomorrow?", "Want to grab tacos?");
        seed_message(&db, "f3", "Inbox", "Invoice 9001", "Payment due for revenue services");

        let body = json!({
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [["Email/query", {"filter": {"text": "revenue"}}, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        let ids: Vec<String> = v["methodResponses"][0][1]["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&"f1".to_string()));
        assert!(ids.contains(&"f3".to_string()));
        assert!(!ids.contains(&"f2".to_string()), "tacos should not match revenue");
    }

    #[tokio::test]
    async fn fts_subject_field_scoped() {
        let (base, auth, db, _dir) = start_server_with_db().await;
        seed_message(&db, "s1", "Inbox", "kangaroo notice", "nothing here");
        seed_message(&db, "s2", "Inbox", "boring header", "but the body says kangaroo");

        let body = json!({
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [["Email/query", {"filter": {"subject": "kangaroo"}}, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        let ids: Vec<String> = v["methodResponses"][0][1]["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&"s1".to_string()));
        assert!(!ids.contains(&"s2".to_string()), "subject filter must not match body");
    }

    #[tokio::test]
    async fn fts_injection_safe() {
        let (base, auth, db, _dir) = start_server_with_db().await;
        seed_message(&db, "i1", "Inbox", "harmless", "harmless body");

        for evil in ["\"; DROP TABLE message_cache; --", "(((((", "subject:OR body:", ""] {
            let body = json!({
                "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
                "methodCalls": [["Email/query", {"filter": {"text": evil}}, "c0"]]
            });
            let r = reqwest::Client::new()
                .post(format!("{}/jmap/api", base))
                .header("authorization", auth.clone())
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "evil={}", evil);
            let v: serde_json::Value = r.json().await.unwrap();
            assert_eq!(v["methodResponses"][0][0], "Email/query", "evil={}", evil);
        }
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&json!({
                "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
                "methodCalls": [["Mailbox/get", {}, "c0"]]
            }))
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        assert!(
            v["methodResponses"][0][1]["list"].as_array().unwrap().len() > 0,
            "mailbox table must still exist after evil queries"
        );
    }

    #[tokio::test]
    async fn fts_snippet_uses_real_highlighting() {
        let (base, auth, db, _dir) = start_server_with_db().await;
        seed_message(
            &db,
            "snip1",
            "Inbox",
            "Project update",
            "The deployment is scheduled for tomorrow morning at nine.",
        );
        let body = json!({
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [["SearchSnippet/get", {
                "emailIds": ["snip1"],
                "filter": {"text": "deployment"}
            }, "c0"]]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        let item = &v["methodResponses"][0][1]["list"][0];
        let preview = item["preview"].as_str().unwrap_or("");
        assert!(
            preview.contains("<mark>deployment</mark>") || preview.contains("<mark>Deployment</mark>"),
            "preview={}",
            preview
        );
    }

    #[tokio::test]
    async fn fts_updates_when_message_updates() {
        let (base, auth, db, _dir) = start_server_with_db().await;
        seed_message(&db, "u1", "Inbox", "old subject", "old body");
        seed_message(&db, "u1", "Inbox", "new shiny subject", "completely different body now");

        let body = json!({
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Email/query", {"filter": {"text": "shiny"}}, "c0"],
                ["Email/query", {"filter": {"text": "old"}}, "c1"]
            ]
        });
        let r = reqwest::Client::new()
            .post(format!("{}/jmap/api", base))
            .header("authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = r.json().await.unwrap();
        let shiny_ids = v["methodResponses"][0][1]["ids"].as_array().unwrap();
        let old_ids = v["methodResponses"][1][1]["ids"].as_array().unwrap();
        assert_eq!(shiny_ids.len(), 1);
        assert_eq!(old_ids.len(), 0, "trigger should have purged the stale row");
    }

    #[tokio::test]
    async fn ws_requires_subprotocol() {
        let (base, auth, _dir) = start_server().await;
        let url = format!("{}/jmap/ws", base);
        let r = reqwest::Client::new()
            .get(url)
            .header("authorization", auth)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }

    #[tokio::test]
    async fn ws_request_response_with_id() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let (base, auth, _dir) = start_server().await;
        let ws_url = base.replacen("http://", "ws://", 1) + "/jmap/ws";
        let mut req = ws_url.into_client_request().unwrap();
        req.headers_mut()
            .insert("authorization", auth.parse().unwrap());
        req.headers_mut()
            .insert("sec-websocket-protocol", "jmap".parse().unwrap());

        let (mut ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok()),
            Some("jmap")
        );

        let msg = json!({
            "@type": "Request",
            "id": "req-7",
            "using": ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
            "methodCalls": [["Mailbox/get", {}, "c0"]]
        });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(msg.to_string()))
            .await
            .unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        let text = reply.into_text().unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["@type"], "Response");
        assert_eq!(v["requestId"], "req-7");
        assert_eq!(v["methodResponses"][0][0], "Mailbox/get");
    }

    #[tokio::test]
    async fn ws_push_enable_emits_initial_state() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let (base, auth, _dir) = start_server().await;
        let ws_url = base.replacen("http://", "ws://", 1) + "/jmap/ws";
        let mut req = ws_url.into_client_request().unwrap();
        req.headers_mut()
            .insert("authorization", auth.parse().unwrap());
        req.headers_mut()
            .insert("sec-websocket-protocol", "jmap".parse().unwrap());
        let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();

        let enable = json!({
            "@type": "WebSocketPushEnable",
            "dataTypes": ["Email","Mailbox"]
        });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(enable.to_string()))
            .await
            .unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        let text = reply.into_text().unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["@type"], "StateChange");
        assert!(v["changed"].is_object());
    }

    #[tokio::test]
    async fn well_known_no_auth_required() {
        let (base, _auth, _dir) = start_server().await;
        let r = reqwest::get(format!("{}/.well-known/jmap", base))
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
}
