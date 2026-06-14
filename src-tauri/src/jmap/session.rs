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
