//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::db::CachedMessage;
use crate::jmap::dispatcher::MethodError;
use crate::jmap::state::JmapContext;
use crate::jmap::store;

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let ids_field = args.get("ids");
    let want: Vec<String> = if ids_field.map(|v| v.is_null()).unwrap_or(false) {
        ctx.db.list_all_message_ids().unwrap_or_default()
    } else {
        ids_field
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    if want.len() > 500 {
        return Err(MethodError::new(
            "requestTooLarge",
            "ids exceeds maxObjectsInGet (500)",
        ));
    }
    let properties = args
        .get("properties")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        });
    let fetch_text = args
        .get("fetchTextBodyValues")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || properties
            .as_ref()
            .map(|p| p.iter().any(|s| s == "bodyValues" || s == "textBody" || s == "htmlBody"))
            .unwrap_or(false);

    let label_to_id = store::label_to_mailbox_id_map(&ctx.db);
    let mut list = Vec::new();
    let mut not_found = Vec::new();

    for id in &want {
        match ctx.db.get_cached_message(id) {
            Ok(Some(m)) => list.push(serialize_email(&m, &label_to_id, &properties, fetch_text)),
            _ => not_found.push(id.clone()),
        }
    }

    let state = ctx.db.jmap_state_get("Email").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "state": state.to_string(),
        "list": list,
        "notFound": not_found,
    }))
}

fn serialize_email(
    m: &CachedMessage,
    label_to_id: &HashMap<String, String>,
    properties: &Option<Vec<String>>,
    fetch_text: bool,
) -> Value {
    let mailbox_id = label_to_id.get(&m.folder).cloned().unwrap_or_default();
    let mut mailbox_ids = serde_json::Map::new();
    mailbox_ids.insert(mailbox_id, json!(true));

    let mut keywords = serde_json::Map::new();
    if m.flags & 1 != 0 { keywords.insert("$seen".to_string(), json!(true)); }
    if m.flags & 2 != 0 { keywords.insert("$answered".to_string(), json!(true)); }
    if m.flags & 4 != 0 { keywords.insert("$flagged".to_string(), json!(true)); }
    if m.flags & 8 != 0 { keywords.insert("$deleted".to_string(), json!(true)); }
    if m.flags & 16 != 0 { keywords.insert("$draft".to_string(), json!(true)); }

    let meta: Value = m
        .raw_headers
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(json!({}));
    let is_html = meta.get("is_html").and_then(|v| v.as_bool()).unwrap_or(false);
    let message_id = meta.get("message_id").and_then(|v| v.as_str()).map(|s| s.to_string());

    let received_at = m
        .date
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let from = parse_from(&m.sender);
    let to = parse_address_list(&m.recipients);
    let subject = m.subject.clone().unwrap_or_default();

    let body_part_id = "1";
    let body_part = json!({
        "partId": body_part_id,
        "blobId": m.aster_id,
        "size": m.size,
        "type": if is_html { "text/html" } else { "text/plain" },
        "charset": "utf-8"
    });

    let mut body_values = serde_json::Map::new();
    if fetch_text {
        if let Some(body) = &m.body_text {
            body_values.insert(
                body_part_id.to_string(),
                json!({
                    "value": body,
                    "isEncodingProblem": false,
                    "isTruncated": false,
                }),
            );
        }
    }

    let html_body = if is_html { vec![body_part.clone()] } else { vec![] };
    let text_body = if !is_html { vec![body_part.clone()] } else { vec![] };

    let include_body_values = fetch_text
        || properties
            .as_ref()
            .map(|p| p.iter().any(|s| s == "bodyValues"))
            .unwrap_or(false);

    let mut full_map = serde_json::Map::new();
    full_map.insert("id".to_string(), json!(m.aster_id));
    full_map.insert("blobId".to_string(), json!(m.aster_id));
    full_map.insert("threadId".to_string(), json!(m.thread_id.as_deref().unwrap_or(&m.aster_id)));
    full_map.insert("mailboxIds".to_string(), Value::Object(mailbox_ids));
    full_map.insert("keywords".to_string(), Value::Object(keywords));
    full_map.insert("size".to_string(), json!(m.size));
    full_map.insert("receivedAt".to_string(), json!(received_at));
    full_map.insert("messageId".to_string(), json!(message_id.map(|m| vec![m])));
    full_map.insert("inReplyTo".to_string(), Value::Null);
    full_map.insert("references".to_string(), Value::Null);
    full_map.insert("sender".to_string(), from.clone());
    full_map.insert("from".to_string(), from);
    full_map.insert("to".to_string(), to);
    full_map.insert("cc".to_string(), Value::Null);
    full_map.insert("bcc".to_string(), Value::Null);
    full_map.insert("replyTo".to_string(), Value::Null);
    full_map.insert("subject".to_string(), json!(subject));
    full_map.insert("sentAt".to_string(), json!(received_at));
    full_map.insert("hasAttachment".to_string(), json!(false));
    full_map.insert("preview".to_string(), json!(preview_of(m.body_text.as_deref())));
    if include_body_values {
        full_map.insert("bodyValues".to_string(), Value::Object(body_values));
    }
    full_map.insert("textBody".to_string(), json!(text_body));
    full_map.insert("htmlBody".to_string(), json!(html_body));
    full_map.insert("attachments".to_string(), Value::Array(vec![]));
    full_map.insert("bodyStructure".to_string(), body_part);
    let full = Value::Object(full_map);

    if let Some(props) = properties {
        if let Value::Object(map) = &full {
            let mut filtered = serde_json::Map::new();
            filtered.insert("id".to_string(), map.get("id").cloned().unwrap_or(Value::Null));
            for p in props {
                if let Some(v) = map.get(p) {
                    filtered.insert(p.clone(), v.clone());
                }
            }
            return Value::Object(filtered);
        }
    }
    full
}

fn parse_from(s: &Option<String>) -> Value {
    let Some(s) = s else { return Value::Null };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Value::Null;
    }
    if let (Some(open), Some(close)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if close > open {
            let name = trimmed[..open].trim().trim_matches('"').to_string();
            let email = trimmed[open + 1..close].trim().to_string();
            return json!([{ "name": if name.is_empty() { Value::Null } else { Value::String(name) }, "email": email }]);
        }
    }
    json!([{ "name": Value::Null, "email": trimmed }])
}

fn parse_address_list(s: &Option<String>) -> Value {
    let Some(s) = s else { return Value::Null };
    let mut out = Vec::new();
    for chunk in s.split(',') {
        let trimmed = chunk.trim();
        if trimmed.is_empty() {
            continue;
        }
        match (trimmed.find('<'), trimmed.rfind('>')) {
            (Some(open), Some(close)) if close > open => {
                let name = trimmed[..open].trim().trim_matches('"').to_string();
                let email = trimmed[open + 1..close].trim().to_string();
                out.push(json!({ "name": if name.is_empty() { Value::Null } else { Value::String(name) }, "email": email }));
            }
            _ => {
                out.push(json!({ "name": Value::Null, "email": trimmed }));
            }
        }
    }
    if out.is_empty() {
        Value::Null
    } else {
        Value::Array(out)
    }
}

fn preview_of(body: Option<&str>) -> String {
    let Some(b) = body else { return String::new() };
    let stripped: String = b
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    stripped.chars().take(256).collect()
}

pub async fn query(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let id_to_label = store::mailbox_id_to_label_map(&ctx.db);

    let position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0).max(0);
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(50)
        .clamp(0, 500);

    if let Some(filter) = args.get("filter") {
        if let Some(bad) = unsupported_filter_field(filter) {
            return Err(MethodError::new(
                "unsupportedFilter",
                format!("unknown filter property: {}", bad),
            ));
        }
    }

    let (where_sql, params) = build_filter(args.get("filter"), &id_to_label);
    let sort_sql = build_sort(args.get("sort"));

    let sql = format!(
        "SELECT m.aster_id FROM message_cache m WHERE 1=1 {} {} LIMIT ?{} OFFSET ?{}",
        where_sql,
        sort_sql,
        params.len() + 1,
        params.len() + 2
    );

    let ids: Vec<String> = ctx
        .db
        .with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let mut bound: Vec<rusqlite::types::Value> = params.clone();
            bound.push(rusqlite::types::Value::Integer(limit));
            bound.push(rusqlite::types::Value::Integer(position));
            let rows = stmt
                .query_map(rusqlite::params_from_iter(bound.iter()), |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .map_err(|e| MethodError::new("serverError", e))?;

    let count_sql = format!("SELECT COUNT(*) FROM message_cache m WHERE 1=1 {}", where_sql);
    let total: i64 = ctx
        .db
        .with_conn(|conn| {
            conn.query_row(
                &count_sql,
                rusqlite::params_from_iter(params.iter()),
                |r| r.get(0),
            )
        })
        .unwrap_or(0);

    let state = ctx.db.jmap_state_get("Email").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "queryState": state.to_string(),
        "canCalculateChanges": false,
        "position": position,
        "total": total,
        "limit": limit,
        "ids": ids,
    }))
}

const KNOWN_FILTER_FIELDS: &[&str] = &[
    "inMailbox", "inMailboxOtherThan", "subject", "from", "to", "body", "text",
    "minSize", "maxSize", "before", "after",
];

fn unsupported_filter_field(f: &Value) -> Option<String> {
    let Some(obj) = f.as_object() else { return None };
    if obj.contains_key("operator") {
        let Some(arr) = obj.get("conditions").and_then(|v| v.as_array()) else {
            return None;
        };
        for c in arr {
            if let Some(bad) = unsupported_filter_field(c) {
                return Some(bad);
            }
        }
        return None;
    }
    for k in obj.keys() {
        if !KNOWN_FILTER_FIELDS.contains(&k.as_str()) {
            return Some(k.clone());
        }
    }
    None
}

fn build_filter(
    filter: Option<&Value>,
    id_to_label: &HashMap<String, String>,
) -> (String, Vec<rusqlite::types::Value>) {
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    let Some(f) = filter else { return (String::new(), params) };
    let body = build_filter_expr(f, id_to_label, &mut params, 0);
    if body.is_empty() {
        (String::new(), params)
    } else {
        (format!(" AND ({})", body), params)
    }
}

const MAX_FILTER_DEPTH: usize = 32;

fn build_filter_expr(
    f: &Value,
    id_to_label: &HashMap<String, String>,
    params: &mut Vec<rusqlite::types::Value>,
    depth: usize,
) -> String {
    if depth > MAX_FILTER_DEPTH {
        return String::new();
    }
    let Some(obj) = f.as_object() else { return String::new() };

    if let Some(op) = obj.get("operator").and_then(|v| v.as_str()) {
        let Some(conds) = obj.get("conditions").and_then(|v| v.as_array()) else {
            return String::new();
        };
        let parts: Vec<String> = conds
            .iter()
            .map(|c| build_filter_expr(c, id_to_label, params, depth + 1))
            .filter(|s| !s.is_empty())
            .map(|s| format!("({})", s))
            .collect();
        return match op {
            "AND" => if parts.is_empty() { "1=1".into() } else { parts.join(" AND ") },
            "OR" => if parts.is_empty() { "1=0".into() } else { parts.join(" OR ") },
            "NOT" => if parts.is_empty() { "1=1".into() } else { format!("NOT ({})", parts.join(" OR ")) },
            _ => String::new(),
        };
    }

    build_condition(obj, id_to_label, params)
}

fn build_condition(
    obj: &serde_json::Map<String, Value>,
    id_to_label: &HashMap<String, String>,
    params: &mut Vec<rusqlite::types::Value>,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(mb_id) = obj.get("inMailbox").and_then(|v| v.as_str()) {
        if let Some(label) = id_to_label.get(mb_id) {
            parts.push(format!("m.folder = ?{}", params.len() + 1));
            params.push(rusqlite::types::Value::Text(label.clone()));
        } else {
            parts.push("1=0".to_string());
        }
    }
    if let Some(arr) = obj.get("inMailboxOtherThan").and_then(|v| v.as_array()) {
        let labels: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|s| id_to_label.get(s).cloned())
            .collect();
        for lbl in labels {
            parts.push(format!("m.folder != ?{}", params.len() + 1));
            params.push(rusqlite::types::Value::Text(lbl));
        }
    }
    if let Some(s) = obj.get("subject").and_then(|v| v.as_str()) {
        push_fts_clause(&mut parts, params, "subject", s);
    }
    if let Some(s) = obj.get("from").and_then(|v| v.as_str()) {
        push_fts_clause(&mut parts, params, "sender", s);
    }
    if let Some(s) = obj.get("to").and_then(|v| v.as_str()) {
        push_fts_clause(&mut parts, params, "recipients", s);
    }
    if let Some(s) = obj.get("body").and_then(|v| v.as_str()) {
        push_fts_clause(&mut parts, params, "body_text", s);
    }
    if let Some(s) = obj.get("text").and_then(|v| v.as_str()) {
        push_fts_clause(&mut parts, params, "", s);
    }
    if let Some(min) = obj.get("minSize").and_then(|v| v.as_i64()) {
        parts.push(format!("m.size >= ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Integer(min));
    }
    if let Some(max) = obj.get("maxSize").and_then(|v| v.as_i64()) {
        parts.push(format!("m.size <= ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Integer(max));
    }
    if let Some(before) = obj.get("before").and_then(|v| v.as_str()) {
        parts.push(format!("m.date < ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Text(before.to_string()));
    }
    if let Some(after) = obj.get("after").and_then(|v| v.as_str()) {
        parts.push(format!("m.date >= ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Text(after.to_string()));
    }

    parts.join(" AND ")
}

fn push_fts_clause(
    parts: &mut Vec<String>,
    params: &mut Vec<rusqlite::types::Value>,
    column: &str,
    raw: &str,
) {
    let q = sanitize_fts_term(raw);
    if q.is_empty() {
        return;
    }
    let match_expr = if column.is_empty() {
        q
    } else {
        format!("{}: {}", column, q)
    };
    parts.push(format!(
        "m.aster_id IN (SELECT aster_id FROM message_fts WHERE message_fts MATCH ?{})",
        params.len() + 1
    ));
    params.push(rusqlite::types::Value::Text(match_expr));
}

fn sanitize_fts_term(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tokens: Vec<String> = trimmed
        .split_whitespace()
        .filter_map(|tok| {
            let cleaned: String = tok
                .chars()
                .filter(|c| {
                    c.is_alphanumeric()
                        || *c == '\''
                        || *c == '-'
                        || *c == '_'
                        || *c == '@'
                        || *c == '.'
                })
                .collect();
            if cleaned.is_empty() {
                None
            } else {
                Some(format!("\"{}\"", cleaned.replace('"', "\"\"")))
            }
        })
        .collect();
    tokens.join(" ")
}

fn build_sort(sort: Option<&Value>) -> String {
    let default = " ORDER BY m.date DESC".to_string();
    let Some(arr) = sort.and_then(|v| v.as_array()) else {
        return default;
    };
    if arr.is_empty() {
        return default;
    }
    let mut parts = Vec::new();
    for item in arr {
        let prop = item.get("property").and_then(|v| v.as_str()).unwrap_or("");
        let ascending = item.get("isAscending").and_then(|v| v.as_bool()).unwrap_or(true);
        let col = match prop {
            "receivedAt" | "sentAt" => "m.date",
            "from" => "m.sender",
            "subject" => "m.subject",
            "size" => "m.size",
            _ => continue,
        };
        parts.push(format!("{} {}", col, if ascending { "ASC" } else { "DESC" }));
    }
    if parts.is_empty() {
        default
    } else {
        format!(" ORDER BY {}", parts.join(", "))
    }
}

pub async fn query_changes(_ctx: &Arc<JmapContext>, _args: Value) -> Result<Value, MethodError> {
    Err(MethodError::new(
        "cannotCalculateChanges",
        "queryChanges not supported; re-query",
    ))
}

pub async fn changes(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let since = args
        .get("sinceState")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| MethodError::invalid_args("sinceState required"))?;
    let (entries, _partial_state, too_old, has_more) = ctx
        .db
        .jmap_changes_since("Email", since)
        .map_err(|e| MethodError::new("serverError", e))?;
    if too_old {
        return Err(MethodError::new(
            "cannotCalculateChanges",
            "sinceState too old",
        ));
    }
    let new_state = if has_more { _partial_state } else { ctx.db.jmap_state_get("Email").unwrap_or(since) };
    let (created, updated, destroyed) =
        crate::jmap::methods::mailbox::partition_ops(entries);
    Ok(json!({
        "accountId": account_id,
        "oldState": since.to_string(),
        "newState": new_state.to_string(),
        "hasMoreChanges": has_more,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
    }))
}

pub async fn set(
    ctx: &Arc<JmapContext>,
    args: Value,
    _created_ids_out: &mut HashMap<String, String>,
) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let old_state = ctx.db.jmap_state_get("Email").unwrap_or(0);

    let updates = args.get("update").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let destroys: Vec<String> = args
        .get("destroy")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    let mut destroyed: Vec<String> = Vec::new();
    let mut not_destroyed = serde_json::Map::new();

    for (id, patch) in &updates {
        let kw_obj_opt = patch.get("keywords")
            .or_else(|| patch.pointer("/keywords"))
            .and_then(|v| v.as_object());

        let has_per_kw_patch = patch.as_object()
            .map(|o| o.keys().any(|k| k.starts_with("/keywords/")))
            .unwrap_or(false);

        if let Some(kw_obj) = kw_obj_opt {
            let mut flags: u32 = 0;
            for (k, v) in kw_obj {
                if v.as_bool().unwrap_or(false) {
                    match k.as_str() {
                        "$seen"      => flags |= 1,
                        "$answered"  => flags |= 2,
                        "$flagged"   => flags |= 4,
                        "$deleted"   => flags |= 8,
                        "$draft"     => flags |= 16,
                        "$forwarded" => flags |= 32,
                        _ => {}
                    }
                }
            }
            match ctx.db.set_message_flags_by_id(id, flags as i64) {
                Ok(_) => { updated.insert(id.clone(), Value::Null); }
                Err(e) => { not_updated.insert(id.clone(), json!({"type": "serverFail", "description": e})); }
            }
        } else if has_per_kw_patch {
            let current = ctx.db.get_message_flags_by_id(id).unwrap_or(0) as u32;
            let mut flags = current;
            if let Some(obj) = patch.as_object() {
                for (k, v) in obj {
                    if let Some(kw) = k.strip_prefix("/keywords/") {
                        let bit = match kw {
                            "$seen"      => 1u32,
                            "$answered"  => 2,
                            "$flagged"   => 4,
                            "$deleted"   => 8,
                            "$draft"     => 16,
                            "$forwarded" => 32,
                            _ => 0,
                        };
                        if bit != 0 {
                            if v.as_bool().unwrap_or(false) { flags |= bit; } else { flags &= !bit; }
                        }
                    }
                }
            }
            match ctx.db.set_message_flags_by_id(id, flags as i64) {
                Ok(_) => { updated.insert(id.clone(), Value::Null); }
                Err(e) => { not_updated.insert(id.clone(), json!({"type": "serverFail", "description": e})); }
            }
        } else {
            not_updated.insert(id.clone(), json!({"type": "invalidProperties", "description": "only keywords updates are supported"}));
        }
    }

    for id in &destroys {
        match ctx.db.delete_message_by_aster_id(id) {
            Ok(_) => { destroyed.push(id.clone()); }
            Err(e) => { not_destroyed.insert(id.clone(), json!({"type": "serverFail", "description": e})); }
        }
    }

    if !updated.is_empty() || !destroyed.is_empty() {
        let _ = ctx.db.jmap_state_bump("Email");
    }

    let new_state = ctx.db.jmap_state_get("Email").unwrap_or(old_state);
    Ok(json!({
        "accountId": account_id,
        "oldState": old_state.to_string(),
        "newState": new_state.to_string(),
        "created": null,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": null,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;
    use crate::db::Database;
    use tokio::sync::{broadcast, RwLock};
    use uuid::Uuid;

    fn cached(aster_id: &str, folder: &str) -> CachedMessage {
        CachedMessage {
            aster_id: aster_id.to_string(),
            folder: folder.to_string(),
            subject: Some("Hello World".to_string()),
            sender: Some("Alice <alice@example.com>".to_string()),
            recipients: Some("Bob <bob@example.com>, carol@example.com".to_string()),
            date: Some("2026-05-21T10:00:00Z".to_string()),
            size: 128,
            flags: 1,
            body_text: Some("this is the body text here".to_string()),
            raw_headers: Some(json!({"is_html": false, "message_id": "mid-1@test"}).to_string()),
            imap_uid: 1,
            thread_id: Some("thread-1".to_string()),
        }
    }

    fn test_ctx() -> (Arc<JmapContext>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[9u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let account = Uuid::new_v4();
        let session = Arc::new(RwLock::new(Session {
            user_id: account,
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
        }));
        let client = Arc::new(crate::api_client::ApiClient::new());
        let (tx, _rx) = broadcast::channel(8);
        let ctx = JmapContext::new(session, db, client, tx);
        (ctx, dir)
    }

    fn ok(r: Result<Value, MethodError>) -> Value {
        match r {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got error: {} {}", e.kind, e.message),
        }
    }

    fn err_kind(r: Result<Value, MethodError>) -> String {
        match r {
            Ok(_) => panic!("expected error, got ok"),
            Err(e) => e.kind,
        }
    }

    fn insert_msg(ctx: &Arc<JmapContext>, m: &CachedMessage) {
        ctx.db
            .upsert_cached_message(
                &m.aster_id,
                &m.folder,
                m.subject.as_deref(),
                m.sender.as_deref(),
                m.recipients.as_deref(),
                m.date.as_deref(),
                m.size,
                m.body_text.as_deref(),
                m.raw_headers.as_deref(),
            )
            .unwrap();
        ctx.db
            .set_message_flags_by_id(&m.aster_id, m.flags)
            .unwrap();
    }

    #[test]
    fn parse_from_none_and_empty() {
        assert_eq!(parse_from(&None), Value::Null);
        assert_eq!(parse_from(&Some("   ".to_string())), Value::Null);
    }

    #[test]
    fn parse_from_named_and_bare() {
        let named = parse_from(&Some("Alice <a@b.com>".to_string()));
        assert_eq!(named, json!([{"name": "Alice", "email": "a@b.com"}]));
        let bare = parse_from(&Some("a@b.com".to_string()));
        assert_eq!(bare, json!([{"name": Value::Null, "email": "a@b.com"}]));
    }

    #[test]
    fn parse_from_quoted_name_stripped() {
        let v = parse_from(&Some("\"Alice B\" <a@b.com>".to_string()));
        assert_eq!(v, json!([{"name": "Alice B", "email": "a@b.com"}]));
    }

    #[test]
    fn parse_address_list_multiple_and_mixed() {
        let v = parse_address_list(&Some("A <a@x.com>, b@y.com".to_string()));
        assert_eq!(
            v,
            json!([
                {"name": "A", "email": "a@x.com"},
                {"name": Value::Null, "email": "b@y.com"}
            ])
        );
    }

    #[test]
    fn parse_address_list_empty_yields_null() {
        assert_eq!(parse_address_list(&None), Value::Null);
        assert_eq!(parse_address_list(&Some(" , , ".to_string())), Value::Null);
    }

    #[test]
    fn preview_collapses_whitespace_and_controls() {
        let p = preview_of(Some("  hello   world  foo  "));
        assert_eq!(p, "hello world foo");
        let stripped = preview_of(Some("a\tb\nc"));
        assert_eq!(stripped, "abc");
        assert_eq!(preview_of(None), "");
    }

    #[test]
    fn preview_truncates_to_256() {
        let long = "a ".repeat(400);
        let p = preview_of(Some(&long));
        assert!(p.chars().count() <= 256);
    }

    #[test]
    fn serialize_email_full_shape() {
        let m = cached("e1", "inbox");
        let mut label_to_id = HashMap::new();
        label_to_id.insert("inbox".to_string(), "mbx_inbox".to_string());
        let v = serialize_email(&m, &label_to_id, &None, false);
        assert_eq!(v.get("id"), Some(&json!("e1")));
        assert_eq!(v.get("blobId"), Some(&json!("e1")));
        assert_eq!(v.get("threadId"), Some(&json!("thread-1")));
        assert_eq!(v.get("subject"), Some(&json!("Hello World")));
        assert_eq!(
            v.pointer("/mailboxIds/mbx_inbox"),
            Some(&json!(true))
        );
        assert_eq!(v.pointer("/keywords/$seen"), Some(&json!(true)));
    }

    #[test]
    fn serialize_email_threadid_falls_back_to_id() {
        let mut m = cached("e2", "inbox");
        m.thread_id = None;
        let v = serialize_email(&m, &HashMap::new(), &None, false);
        assert_eq!(v.get("threadId"), Some(&json!("e2")));
    }

    #[test]
    fn serialize_email_property_selection() {
        let m = cached("e3", "inbox");
        let props = Some(vec!["subject".to_string()]);
        let v = serialize_email(&m, &HashMap::new(), &props, false);
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("subject"));
        assert!(!obj.contains_key("preview"));
        assert!(!obj.contains_key("from"));
    }

    #[test]
    fn serialize_email_keywords_from_flags() {
        let mut m = cached("e4", "inbox");
        m.flags = 1 | 4 | 16;
        let v = serialize_email(&m, &HashMap::new(), &None, false);
        assert_eq!(v.pointer("/keywords/$seen"), Some(&json!(true)));
        assert_eq!(v.pointer("/keywords/$flagged"), Some(&json!(true)));
        assert_eq!(v.pointer("/keywords/$draft"), Some(&json!(true)));
        assert_eq!(v.pointer("/keywords/$answered"), None);
    }

    #[test]
    fn serialize_email_html_body_when_html() {
        let mut m = cached("e5", "inbox");
        m.raw_headers = Some(json!({"is_html": true}).to_string());
        let v = serialize_email(&m, &HashMap::new(), &None, false);
        assert!(v.get("htmlBody").unwrap().as_array().unwrap().len() == 1);
        assert!(v.get("textBody").unwrap().as_array().unwrap().is_empty());
    }

    #[test]
    fn serialize_email_fetch_text_populates_body_values() {
        let m = cached("e6", "inbox");
        let v = serialize_email(&m, &HashMap::new(), &None, true);
        assert_eq!(
            v.pointer("/bodyValues/1/value"),
            Some(&json!("this is the body text here"))
        );
    }

    #[tokio::test]
    async fn get_returns_found_and_not_found() {
        let (ctx, _d) = test_ctx();
        insert_msg(&ctx, &cached("g1", "inbox"));
        let args = json!({"ids": ["g1", "missing"]});
        let res = ok(get(&ctx, args).await);
        assert_eq!(res["list"].as_array().unwrap().len(), 1);
        assert_eq!(res["notFound"], json!(["missing"]));
        assert_eq!(res["list"][0]["id"], json!("g1"));
    }

    #[tokio::test]
    async fn get_null_ids_lists_all() {
        let (ctx, _d) = test_ctx();
        insert_msg(&ctx, &cached("g2", "inbox"));
        insert_msg(&ctx, &cached("g3", "sent"));
        let res = ok(get(&ctx, json!({"ids": Value::Null})).await);
        assert_eq!(res["list"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn get_rejects_too_many_ids() {
        let (ctx, _d) = test_ctx();
        let ids: Vec<String> = (0..501).map(|i| format!("id-{}", i)).collect();
        let err = err_kind(get(&ctx, json!({"ids": ids})).await);
        assert_eq!(err, "requestTooLarge");
    }

    #[tokio::test]
    async fn get_wrong_account_rejected() {
        let (ctx, _d) = test_ctx();
        let err = err_kind(get(&ctx, json!({"accountId": "nope", "ids": []})).await);
        assert_eq!(err, "accountNotFound");
    }

    #[tokio::test]
    async fn query_filters_by_mailbox() {
        let (ctx, _d) = test_ctx();
        insert_msg(&ctx, &cached("q1", "inbox"));
        insert_msg(&ctx, &cached("q2", "sent"));
        let res = ok(query(&ctx, json!({"filter": {"inMailbox": "mbx_inbox"}})).await);
        assert_eq!(res["ids"], json!(["q1"]));
        assert_eq!(res["total"], json!(1));
    }

    #[tokio::test]
    async fn query_unknown_filter_field_rejected() {
        let (ctx, _d) = test_ctx();
        let err = err_kind(query(&ctx, json!({"filter": {"bogus": "x"}})).await);
        assert_eq!(err, "unsupportedFilter");
    }

    #[tokio::test]
    async fn query_empty_when_no_messages() {
        let (ctx, _d) = test_ctx();
        let res = ok(query(&ctx, json!({})).await);
        assert_eq!(res["ids"], json!([]));
        assert_eq!(res["total"], json!(0));
    }

    #[tokio::test]
    async fn query_size_filter() {
        let (ctx, _d) = test_ctx();
        let mut small = cached("small", "inbox");
        small.size = 10;
        let mut big = cached("big", "inbox");
        big.size = 1000;
        insert_msg(&ctx, &small);
        insert_msg(&ctx, &big);
        let res = ok(query(&ctx, json!({"filter": {"minSize": 500}})).await);
        assert_eq!(res["ids"], json!(["big"]));
    }

    #[test]
    fn unsupported_filter_field_walks_conditions() {
        let f = json!({"operator": "AND", "conditions": [{"subject": "x"}, {"weird": 1}]});
        assert_eq!(unsupported_filter_field(&f), Some("weird".to_string()));
        let ok = json!({"operator": "AND", "conditions": [{"subject": "x"}]});
        assert_eq!(unsupported_filter_field(&ok), None);
    }

    #[test]
    fn sanitize_fts_term_quotes_tokens() {
        assert_eq!(sanitize_fts_term("hello world"), "\"hello\" \"world\"");
        assert_eq!(sanitize_fts_term("  "), "");
        assert_eq!(sanitize_fts_term("a@b.com"), "\"a@b.com\"");
    }

    #[test]
    fn sanitize_fts_term_drops_punctuation_only() {
        assert_eq!(sanitize_fts_term("!!! ???"), "");
    }

    #[test]
    fn build_sort_default_and_custom() {
        assert_eq!(build_sort(None), " ORDER BY m.date DESC");
        let asc = build_sort(Some(&json!([{"property": "subject", "isAscending": true}])));
        assert_eq!(asc, " ORDER BY m.subject ASC");
        let unknown = build_sort(Some(&json!([{"property": "bogus"}])));
        assert_eq!(unknown, " ORDER BY m.date DESC");
    }

    #[test]
    fn build_filter_or_and_not() {
        let id_to_label = HashMap::new();
        let f = json!({"operator": "OR", "conditions": []});
        let (sql, _p) = build_filter(Some(&f), &id_to_label);
        assert!(sql.contains("1=0"));
        let f2 = json!({"operator": "NOT", "conditions": []});
        let (sql2, _p2) = build_filter(Some(&f2), &id_to_label);
        assert!(sql2.contains("1=1"));
    }

    #[test]
    fn build_filter_unknown_mailbox_is_false() {
        let id_to_label = HashMap::new();
        let f = json!({"inMailbox": "does-not-exist"});
        let (sql, params) = build_filter(Some(&f), &id_to_label);
        assert!(sql.contains("1=0"));
        assert!(params.is_empty());
    }

    #[tokio::test]
    async fn query_changes_unsupported() {
        let (ctx, _d) = test_ctx();
        let err = err_kind(query_changes(&ctx, json!({})).await);
        assert_eq!(err, "cannotCalculateChanges");
    }

    #[tokio::test]
    async fn changes_requires_since_state() {
        let (ctx, _d) = test_ctx();
        let err = err_kind(changes(&ctx, json!({})).await);
        assert_eq!(err, "invalidArguments");
    }

    #[tokio::test]
    async fn changes_returns_partitioned_ops() {
        let (ctx, _d) = test_ctx();
        ctx.db.jmap_change_log_append("Email", 1, "a", "created").unwrap();
        ctx.db.jmap_change_log_append("Email", 2, "a", "updated").unwrap();
        ctx.db.jmap_change_log_append("Email", 3, "b", "created").unwrap();
        let res = ok(changes(&ctx, json!({"sinceState": "0"})).await);
        let created = res["created"].as_array().unwrap();
        assert!(created.contains(&json!("a")));
        assert!(created.contains(&json!("b")));
        assert!(res["updated"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn set_updates_keywords_via_full_object() {
        let (ctx, _d) = test_ctx();
        let mut m = cached("s1", "inbox");
        m.flags = 0;
        insert_msg(&ctx, &m);
        let args = json!({"update": {"s1": {"keywords": {"$seen": true, "$flagged": true}}}});
        let res = ok(set(&ctx, args, &mut HashMap::new()).await);
        assert!(res["updated"].as_object().unwrap().contains_key("s1"));
        let flags = ctx.db.get_message_flags_by_id("s1").unwrap();
        assert_eq!(flags, 1 | 4);
    }

    #[tokio::test]
    async fn set_patch_per_keyword_toggle() {
        let (ctx, _d) = test_ctx();
        let mut m = cached("s2", "inbox");
        m.flags = 1;
        insert_msg(&ctx, &m);
        let args = json!({"update": {"s2": {"/keywords/$seen": false}}});
        ok(set(&ctx, args, &mut HashMap::new()).await);
        assert_eq!(ctx.db.get_message_flags_by_id("s2").unwrap(), 0);
    }

    #[tokio::test]
    async fn set_rejects_non_keyword_patch() {
        let (ctx, _d) = test_ctx();
        insert_msg(&ctx, &cached("s3", "inbox"));
        let args = json!({"update": {"s3": {"subject": "x"}}});
        let res = ok(set(&ctx, args, &mut HashMap::new()).await);
        assert!(res["notUpdated"].as_object().unwrap().contains_key("s3"));
    }

    #[tokio::test]
    async fn set_destroys_message() {
        let (ctx, _d) = test_ctx();
        insert_msg(&ctx, &cached("s4", "inbox"));
        let args = json!({"destroy": ["s4"]});
        let res = ok(set(&ctx, args, &mut HashMap::new()).await);
        assert_eq!(res["destroyed"], json!(["s4"]));
        assert!(ctx.db.get_cached_message("s4").unwrap().is_none());
    }
}
