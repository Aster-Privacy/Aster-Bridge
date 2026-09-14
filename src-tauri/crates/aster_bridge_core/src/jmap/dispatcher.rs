//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::auth::AuthedAccount;
use super::methods;
use super::server::AppState;
use super::state::{snapshot_all_states, JmapContext};

const ADVERTISED_CAPS: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission",
];

pub async fn handle(
    _auth: AuthedAccount,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    match dispatch_request(&state.ctx, body).await {
        Ok(v) => Json(v).into_response(),
        Err(DispatchError::BadRequest(msg)) => error_response(StatusCode::BAD_REQUEST, &msg),
        Err(DispatchError::TooLarge(msg)) => error_response(StatusCode::PAYLOAD_TOO_LARGE, &msg),
        Err(DispatchError::UnknownCapability(cap)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "type": "urn:ietf:params:jmap:error:unknownCapability",
                "status": 400,
                "detail": format!("unknown capability: {}", cap),
            })),
        )
        .into_response(),
    }
}

pub enum DispatchError {
    BadRequest(String),
    TooLarge(String),
    UnknownCapability(String),
}

pub async fn dispatch_request(
    ctx: &Arc<JmapContext>,
    body: Value,
) -> Result<Value, DispatchError> {
    let using = match body.get("using").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_str()).collect::<HashSet<_>>(),
        None => return Err(DispatchError::BadRequest("missing using".into())),
    };
    let advertised: HashSet<&str> = ADVERTISED_CAPS.iter().copied().collect();
    for cap in &using {
        if !advertised.contains(*cap) {
            return Err(DispatchError::UnknownCapability((*cap).to_string()));
        }
    }

    let calls = match body.get("methodCalls").and_then(|v| v.as_array()) {
        Some(arr) => arr.clone(),
        None => return Err(DispatchError::BadRequest("missing methodCalls".into())),
    };
    if calls.len() > 32 {
        return Err(DispatchError::TooLarge("too many calls".into()));
    }

    let mut method_responses: Vec<Value> = Vec::with_capacity(calls.len());
    let mut by_call_id: HashMap<String, Value> = HashMap::new();
    let mut by_call_name: HashMap<String, String> = HashMap::new();
    let created_ids_in: HashMap<String, String> = body
        .get("createdIds")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let mut created_ids_out: HashMap<String, String> = created_ids_in.clone();

    for raw in calls {
        let arr = match raw.as_array() {
            Some(a) if a.len() == 3 => a,
            _ => {
                method_responses.push(json!(["error", {"type": "unknownMethod"}, ""]));
                continue;
            }
        };
        let method = match arr[0].as_str() {
            Some(s) => s.to_string(),
            None => {
                method_responses.push(json!(["error", {"type": "unknownMethod"}, ""]));
                continue;
            }
        };
        let mut args = arr[1].clone();
        let call_id = arr[2].as_str().unwrap_or("").to_string();

        if let Err(e) = resolve_back_refs_with_names(&mut args, &by_call_id, &by_call_name) {
            method_responses.push(json!([
                "error",
                {"type": "invalidResultReference", "description": e},
                call_id
            ]));
            continue;
        }

        if let Some(required) = required_capability(&method) {
            if !using.contains(required) {
                method_responses.push(json!([
                    "error",
                    {"type": "unknownMethod", "description": format!("capability {} not in 'using'", required)},
                    call_id
                ]));
                continue;
            }
        }

        let result = dispatch_one(ctx, &method, args, &mut created_ids_out).await;
        let (name, value) = match result {
            Ok(v) => (method.clone(), v),
            Err(MethodError { kind, message }) => (
                "error".to_string(),
                json!({"type": kind, "description": message}),
            ),
        };
        let entry = json!([name.clone(), value.clone(), call_id.clone()]);
        if !call_id.is_empty() {
            by_call_id.insert(call_id.clone(), value);
            by_call_name.insert(call_id.clone(), name);
        }
        method_responses.push(entry);
    }

    let states = snapshot_all_states(&ctx.db);
    let session_state = crate::jmap::state::compose_session_state(&states);

    let mut out = json!({
        "methodResponses": method_responses,
        "sessionState": session_state,
    });
    if !created_ids_out.is_empty() {
        out["createdIds"] = json!(created_ids_out);
    }
    Ok(out)
}

pub struct MethodError {
    pub kind: String,
    pub message: String,
}

impl MethodError {
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
        }
    }
    pub fn invalid_args(msg: impl Into<String>) -> Self {
        Self::new("invalidArguments", msg)
    }
    pub fn not_supported() -> Self {
        Self::new("notSupported", "method not supported")
    }
}

fn required_capability(method: &str) -> Option<&'static str> {
    let prefix = method.split('/').next().unwrap_or("");
    match prefix {
        "Mailbox" | "Email" | "Thread" | "SearchSnippet" => Some("urn:ietf:params:jmap:mail"),
        "EmailSubmission" | "Identity" => Some("urn:ietf:params:jmap:submission"),
        _ => None,
    }
}

async fn dispatch_one(
    ctx: &Arc<JmapContext>,
    method: &str,
    args: Value,
    created_ids_out: &mut HashMap<String, String>,
) -> Result<Value, MethodError> {
    match method {
        "Mailbox/get" => methods::mailbox::get(ctx, args).await,
        "Mailbox/query" => methods::mailbox::query(ctx, args).await,
        "Mailbox/changes" => methods::mailbox::changes(ctx, args).await,
        "Mailbox/set" => methods::mailbox::set(ctx, args).await,
        "Email/get" => methods::email::get(ctx, args).await,
        "Email/query" => methods::email::query(ctx, args).await,
        "Email/queryChanges" => methods::email::query_changes(ctx, args).await,
        "Email/changes" => methods::email::changes(ctx, args).await,
        "Email/set" => methods::email::set(ctx, args, created_ids_out).await,
        "Thread/get" => methods::thread::get(ctx, args).await,
        "Thread/changes" => methods::thread::changes(ctx, args).await,
        "EmailSubmission/get" => methods::submission::get(ctx, args).await,
        "EmailSubmission/set" => methods::submission::set(ctx, args, created_ids_out).await,
        "Identity/get" => methods::identity::get(ctx, args).await,
        "SearchSnippet/get" => methods::snippet::get(ctx, args).await,
        other => Err(MethodError::new(
            "unknownMethod",
            format!("unknown method: {}", other),
        )),
    }
}

fn resolve_back_refs(
    args: &mut Value,
    by_call_id: &HashMap<String, Value>,
    _created_ids: &HashMap<String, String>,
) -> Result<(), String> {
    resolve_back_refs_with_names(args, by_call_id, &HashMap::new())
}

fn resolve_back_refs_with_names(
    args: &mut Value,
    by_call_id: &HashMap<String, Value>,
    by_call_name: &HashMap<String, String>,
) -> Result<(), String> {
    let Some(obj) = args.as_object_mut() else {
        return Ok(());
    };
    let keys: Vec<String> = obj
        .keys()
        .filter(|k| k.starts_with('#'))
        .cloned()
        .collect();
    for hash_key in keys {
        let ref_val = obj.remove(&hash_key).unwrap();
        let result_of = ref_val
            .get("resultOf")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{}: missing resultOf", hash_key))?
            .to_string();
        let name = ref_val
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{}: missing name", hash_key))?
            .to_string();
        let path = ref_val
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{}: missing path", hash_key))?
            .to_string();
        if let Some(expected) = by_call_name.get(&result_of) {
            if expected != &name {
                return Err(format!(
                    "{}: name {} does not match referenced call {}",
                    hash_key, name, expected
                ));
            }
        }
        let prior = by_call_id
            .get(&result_of)
            .ok_or_else(|| format!("{}: no prior call {}", hash_key, result_of))?;
        let resolved = json_pointer_with_wildcard(prior, &path)
            .ok_or_else(|| format!("{}: pointer {} did not resolve", hash_key, path))?;
        let real_key = hash_key.trim_start_matches('#').to_string();
        obj.insert(real_key, resolved);
    }
    Ok(())
}

const MAX_POINTER_SEGMENTS: usize = 256;

fn json_pointer_with_wildcard(root: &Value, path: &str) -> Option<Value> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(root.clone());
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() > MAX_POINTER_SEGMENTS {
        return None;
    }
    if parts.iter().filter(|p| **p == "*").count() > 1 {
        return None;
    }
    eval(root, &parts)
}

fn eval(node: &Value, parts: &[&str]) -> Option<Value> {
    if parts.is_empty() {
        return Some(node.clone());
    }
    let (head, rest) = (parts[0], &parts[1..]);
    let decoded = head.replace("~1", "/").replace("~0", "~");

    if decoded == "*" {
        let arr = node.as_array()?;
        let mut collected = Vec::new();
        for item in arr {
            if let Some(v) = eval(item, rest) {
                match v {
                    Value::Array(inner) => collected.extend(inner),
                    other => collected.push(other),
                }
            }
        }
        return Some(Value::Array(collected));
    }

    if let Some(arr) = node.as_array() {
        let idx: usize = decoded.parse().ok()?;
        return eval(arr.get(idx)?, rest);
    }
    if let Some(obj) = node.as_object() {
        return eval(obj.get(&decoded)?, rest);
    }
    None
}

fn error_response(code: StatusCode, msg: &str) -> Response {
    (
        code,
        Json(json!({
            "type": "urn:ietf:params:jmap:error:notRequest",
            "status": code.as_u16(),
            "detail": msg
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pointer_index() {
        let v = json!({"list":[{"id":"a"},{"id":"b"}]});
        assert_eq!(json_pointer_with_wildcard(&v, "/list/0/id"), Some(json!("a")));
    }

    #[test]
    fn pointer_wildcard() {
        let v = json!({"list":[{"id":"a"},{"id":"b"}]});
        assert_eq!(
            json_pointer_with_wildcard(&v, "/list/*/id"),
            Some(json!(["a", "b"]))
        );
    }

    #[test]
    fn pointer_rejects_multiple_wildcards() {
        let v = json!({"a":[{"b":[{"c":"x"}]}]});
        assert_eq!(json_pointer_with_wildcard(&v, "/a/*/b/*/c"), None);
    }

    #[test]
    fn pointer_rejects_overlong_path() {
        let v = json!({"x": 1});
        let long_path = format!("/{}", vec!["0"; MAX_POINTER_SEGMENTS + 1].join("/"));
        assert_eq!(json_pointer_with_wildcard(&v, &long_path), None);
    }

    #[test]
    fn resolves_hash_ref() {
        let mut args = json!({"#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"}});
        let mut prior = HashMap::new();
        prior.insert("0".to_string(), json!({"ids": ["x","y","z"]}));
        resolve_back_refs(&mut args, &prior, &HashMap::new()).unwrap();
        assert_eq!(args.get("ids"), Some(&json!(["x","y","z"])));
    }
}
