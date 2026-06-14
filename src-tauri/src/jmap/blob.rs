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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_hex_is_64_hex_chars() {
        let h = sha256_hex(b"some payload");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn blob_id_format_matches_upload() {
        let blob_id = format!("blob-{}", sha256_hex(b"data"));
        assert!(blob_id.starts_with("blob-"));
        assert_eq!(blob_id.len(), 5 + 64);
    }

    #[test]
    fn sanitize_keeps_safe_chars() {
        assert_eq!(sanitize("file-name_1.txt"), "file-name_1.txt");
    }

    #[test]
    fn sanitize_replaces_unsafe_with_underscore() {
        assert_eq!(sanitize("a/b\\c d"), "a_b_c_d");
        assert_eq!(sanitize("../../etc/passwd"), ".._.._etc_passwd");
    }

    #[test]
    fn sanitize_empty_yields_download() {
        assert_eq!(sanitize(""), "download");
    }

    #[test]
    fn sanitize_truncates_to_128() {
        let long = "a".repeat(500);
        assert_eq!(sanitize(&long).chars().count(), 128);
    }

    #[test]
    fn sanitize_strips_quotes_preventing_header_injection() {
        let out = sanitize("evil\"; rm -rf /");
        assert!(!out.contains('"'));
        assert!(!out.contains(' '));
    }

    #[test]
    fn build_blob_response_sets_headers() {
        let resp = build_blob_response(b"hello".to_vec(), "text/plain", "note.txt");
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert_eq!(ct.to_str().unwrap(), "text/plain");
        let disp = resp.headers().get(header::CONTENT_DISPOSITION).unwrap();
        assert_eq!(disp.to_str().unwrap(), "attachment; filename=\"note.txt\"");
    }

    #[test]
    fn build_blob_response_invalid_content_type_falls_back() {
        let resp = build_blob_response(vec![1, 2, 3], "bad\nvalue", "f");
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert_eq!(ct.to_str().unwrap(), "application/octet-stream");
    }
}
