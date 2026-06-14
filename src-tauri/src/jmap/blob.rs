//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::auth::AuthedAccount;
use super::mime;
use super::server::AppState;

pub async fn upload(
    _auth: AuthedAccount,
    Path(account_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let expected = state.ctx.account_id().await;
    if account_id != expected {
        return (StatusCode::NOT_FOUND, "unknown account").into_response();
    }
    let requested_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let size = body.len() as i64;
    let blob_id = format!("blob-{}", sha256_hex(&body));

    let effective_type = match state.ctx.db.jmap_blob_get(&blob_id) {
        Ok(Some((_, Some(existing)))) => existing,
        _ => {
            if let Err(e) = state
                .ctx
                .db
                .jmap_blob_put(&blob_id, &body, Some(requested_type.as_str()))
            {
                return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
            }
            requested_type
        }
    };

    Json(json!({
        "accountId": account_id,
        "blobId": blob_id,
        "type": effective_type,
        "size": size,
    }))
    .into_response()
}

pub async fn download(
    _auth: AuthedAccount,
    Path((account_id, blob_id, name)): Path<(String, String, String)>,
    State(state): State<AppState>,
) -> Response {
    let expected = state.ctx.account_id().await;
    if account_id != expected {
        return (StatusCode::NOT_FOUND, "unknown account").into_response();
    }
    if let Ok(Some((data, ctype))) = state.ctx.db.jmap_blob_get(&blob_id) {
        let ct = ctype.as_deref().unwrap_or("application/octet-stream");
        return build_blob_response(data, ct, &name);
    }

    if let Ok(Some(m)) = state.ctx.db.get_cached_message(&blob_id) {
        let body = mime::build_rfc5322(&m);
        return build_blob_response(body, "message/rfc822", &name);
    }

    (StatusCode::NOT_FOUND, "blob not found").into_response()
}

fn build_blob_response(data: Vec<u8>, content_type: &str, name: &str) -> Response {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    let disp = format!("attachment; filename=\"{}\"", sanitize(name));
    if let Ok(v) = HeaderValue::from_str(&disp) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    (StatusCode::OK, h, data).into_response()
}

fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "download".to_string()
    } else {
        cleaned.chars().take(128).collect()
    }
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for byte in out.iter() {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
