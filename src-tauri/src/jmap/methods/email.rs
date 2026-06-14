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
