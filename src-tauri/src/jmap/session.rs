//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::auth::AuthedAccount;
use super::server::AppState;
use super::state::{compose_session_state, snapshot_all_states, JmapContext};

pub async fn well_known(State(state): State<AppState>) -> Response {
    let scheme = if state.use_https { "https" } else { "http" };
    let body = json!({
        "@type": "Session",
        "redirectUrl": format!("{}://127.0.0.1:{}/jmap/session", scheme, state.bind_port)
    });
    (axum::http::StatusCode::OK, Json(body)).into_response()
}

pub async fn session_resource(
    _auth: AuthedAccount,
    State(state): State<AppState>,
) -> Response {
    Json(build_session(&state.ctx, state.bind_port, state.use_https).await).into_response()
}

pub async fn build_session(ctx: &Arc<JmapContext>, port: u16, use_https: bool) -> serde_json::Value {
    let scheme = if use_https { "https" } else { "http" };
    let ws_scheme = if use_https { "wss" } else { "ws" };
    let account_id = ctx.account_id().await;
    let email = ctx.email().await;
    let states = snapshot_all_states(&ctx.db);
    let session_state = compose_session_state(&states);

    json!({
        "@type": "Session",
        "capabilities": {
            "urn:ietf:params:jmap:core": {
                "maxSizeUpload": 50_000_000u64,
                "maxConcurrentUpload": 4,
                "maxSizeRequest": 10_000_000u64,
                "maxConcurrentRequests": 4,
                "maxCallsInRequest": 32,
                "maxObjectsInGet": 500,
                "maxObjectsInSet": 100,
                "collationAlgorithms": ["i;ascii-casemap"]
            },
            "urn:ietf:params:jmap:mail": {
                "maxMailboxesPerEmail": null,
                "maxMailboxDepth": null,
                "maxSizeMailboxName": 200,
                "maxSizeAttachmentsPerEmail": 50_000_000u64,
                "emailQuerySortOptions": ["receivedAt", "from", "subject", "size"],
                "mayCreateTopLevelMailbox": false
            },
            "urn:ietf:params:jmap:submission": {
                "maxDelayedSend": 0,
                "submissionExtensions": {}
            },
            "urn:ietf:params:jmap:websocket": {
                "url": format!("{}://127.0.0.1:{}/jmap/ws", ws_scheme, port),
                "supportsPush": true
            }
        },
        "accounts": {
            &account_id: {
                "name": email,
                "isPersonal": true,
                "isReadOnly": false,
                "accountCapabilities": {
                    "urn:ietf:params:jmap:mail": {},
                    "urn:ietf:params:jmap:submission": {}
                }
            }
        },
        "primaryAccounts": {
            "urn:ietf:params:jmap:mail": &account_id,
            "urn:ietf:params:jmap:submission": &account_id
        },
        "username": email,
        "apiUrl": format!("{}://127.0.0.1:{}/jmap/api", scheme, port),
        "downloadUrl": format!("{}://127.0.0.1:{}/jmap/download/{{accountId}}/{{blobId}}/{{name}}", scheme, port),
        "uploadUrl": format!("{}://127.0.0.1:{}/jmap/upload/{{accountId}}", scheme, port),
        "eventSourceUrl": format!("{}://127.0.0.1:{}/jmap/eventsource?types={{types}}&closeafter={{closeafter}}&ping={{ping}}", scheme, port),
        "state": session_state
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;
    use crate::db::Database;
    use tokio::sync::{broadcast, RwLock};
    use uuid::Uuid;

    fn test_ctx(email: &str) -> (Arc<JmapContext>, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[10u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let account = Uuid::new_v4();
        let session = Arc::new(RwLock::new(Session {
            user_id: account,
            username: "tester".to_string(),
            email: email.to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
        }));
        let client = Arc::new(crate::api_client::ApiClient::new());
        let (tx, _rx) = broadcast::channel(8);
        (JmapContext::new(session, db, client, tx), account.to_string(), dir)
    }

    #[tokio::test]
    async fn build_session_advertises_capabilities() {
        let (ctx, _a, _d) = test_ctx("user@aster.test");
        let s = build_session(&ctx, 9000, false).await;
        let caps = s["capabilities"].as_object().unwrap();
        assert!(caps.contains_key("urn:ietf:params:jmap:core"));
        assert!(caps.contains_key("urn:ietf:params:jmap:mail"));
        assert!(caps.contains_key("urn:ietf:params:jmap:submission"));
        assert_eq!(s["@type"], json!("Session"));
    }

    #[tokio::test]
    async fn build_session_account_keyed_by_id() {
        let (ctx, account, _d) = test_ctx("user@aster.test");
        let s = build_session(&ctx, 9000, false).await;
        assert!(s["accounts"].get(&account).is_some());
        assert_eq!(s["accounts"][&account]["name"], json!("user@aster.test"));
        assert_eq!(s["primaryAccounts"]["urn:ietf:params:jmap:mail"], json!(account));
        assert_eq!(s["username"], json!("user@aster.test"));
    }

    #[tokio::test]
    async fn build_session_http_urls_when_no_tls() {
        let (ctx, _a, _d) = test_ctx("user@aster.test");
        let s = build_session(&ctx, 12345, false).await;
        assert_eq!(s["apiUrl"], json!("http://127.0.0.1:12345/jmap/api"));
        let ws = s["capabilities"]["urn:ietf:params:jmap:websocket"]["url"]
            .as_str()
            .unwrap();
        assert!(ws.starts_with("ws://127.0.0.1:12345/jmap/ws"));
    }

    #[tokio::test]
    async fn build_session_https_urls_when_tls() {
        let (ctx, _a, _d) = test_ctx("user@aster.test");
        let s = build_session(&ctx, 443, true).await;
        assert!(s["apiUrl"].as_str().unwrap().starts_with("https://"));
        assert!(s["downloadUrl"].as_str().unwrap().starts_with("https://"));
        let ws = s["capabilities"]["urn:ietf:params:jmap:websocket"]["url"]
            .as_str()
            .unwrap();
        assert!(ws.starts_with("wss://"));
    }

    #[tokio::test]
    async fn build_session_state_starts_at_zeros() {
        let (ctx, _a, _d) = test_ctx("user@aster.test");
        let s = build_session(&ctx, 80, false).await;
        assert_eq!(s["state"], json!("0-0-0"));
    }

    #[tokio::test]
    async fn build_session_state_reflects_bumps() {
        let (ctx, _a, _d) = test_ctx("user@aster.test");
        ctx.db.jmap_state_bump("Email").unwrap();
        ctx.db.jmap_state_bump("Thread").unwrap();
        let s = build_session(&ctx, 80, false).await;
        assert_eq!(s["state"], json!("1-0-1"));
    }

    #[tokio::test]
    async fn build_session_download_url_has_placeholders() {
        let (ctx, _a, _d) = test_ctx("user@aster.test");
        let s = build_session(&ctx, 80, false).await;
        let url = s["downloadUrl"].as_str().unwrap();
        assert!(url.contains("{accountId}"));
        assert!(url.contains("{blobId}"));
        assert!(url.contains("{name}"));
    }
}
