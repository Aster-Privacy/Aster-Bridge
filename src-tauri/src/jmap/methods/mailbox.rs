//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::sync::Arc;

use serde_json::{json, Value};

use crate::jmap::dispatcher::MethodError;
use crate::jmap::state::JmapContext;
use crate::jmap::store;

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let requested = args.get("ids").and_then(|v| v.as_array()).cloned();
    let rows = store::all_mailboxes(&ctx.db);
    let mut out = Vec::new();
    let mut not_found = Vec::new();

    if let Some(ids) = requested {
        if ids.len() > 500 {
            return Err(MethodError::new("requestTooLarge", "too many ids"));
        }
        let want: Vec<String> = ids
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        for id in &want {
            if let Some(r) = rows.iter().find(|r| &r.id == id) {
                out.push(serialize(r, &ctx.db));
            } else {
                not_found.push(id.clone());
            }
        }
    } else {
        for r in &rows {
            out.push(serialize(r, &ctx.db));
        }
    }

    let state = ctx.db.jmap_state_get("Mailbox").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "state": state.to_string(),
        "list": out,
        "notFound": not_found,
    }))
}

fn serialize(r: &crate::db::JmapMailboxRow, db: &crate::db::Database) -> Value {
    let (total, unread) = store::folder_counts(db, &r.folder_label);
    json!({
        "id": r.id,
        "name": r.name,
        "parentId": r.parent_id,
        "role": r.role,
        "sortOrder": r.sort_order,
        "totalEmails": total,
        "unreadEmails": unread,
        "totalThreads": total,
        "unreadThreads": unread,
        "myRights": {
            "mayReadItems": true,
            "mayAddItems": true,
            "mayRemoveItems": true,
            "maySetSeen": true,
            "maySetKeywords": true,
            "mayCreateChild": false,
            "mayRename": false,
            "mayDelete": false,
            "maySubmit": true
        },
        "isSubscribed": true
    })
}

pub async fn query(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let rows = store::all_mailboxes(&ctx.db);
    let ids: Vec<String> = rows.into_iter().map(|r| r.id).collect();
    let state = ctx.db.jmap_state_get("Mailbox").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "queryState": state.to_string(),
        "canCalculateChanges": false,
        "position": 0,
        "total": ids.len(),
        "ids": ids,
    }))
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
        .jmap_changes_since("Mailbox", since)
        .map_err(|e| MethodError::new("serverError", e))?;
    if too_old {
        return Err(MethodError::new(
            "cannotCalculateChanges",
            "sinceState too old",
        ));
    }
    let new_state = if has_more { _partial_state } else { ctx.db.jmap_state_get("Mailbox").unwrap_or(since) };
    let (created, updated, destroyed) = partition_ops(entries);
    Ok(json!({
        "accountId": account_id,
        "oldState": since.to_string(),
        "newState": new_state.to_string(),
        "hasMoreChanges": has_more,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "updatedProperties": null
    }))
}

pub fn partition_ops(entries: Vec<(String, String)>) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut effective: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (id, op) in entries {
        let current = effective.get(&id).map(|s| s.as_str());
        match (current, op.as_str()) {
            (_, "destroyed") => { effective.insert(id, "destroyed".to_string()); }
            (Some("destroyed"), _) => {}
            (Some("created"), "updated") => {}
            _ => { effective.insert(id, op); }
        }
    }
    let mut created = Vec::new();
    let mut updated = Vec::new();
    let mut destroyed = Vec::new();
    for (id, op) in effective {
        match op.as_str() {
            "created" => created.push(id),
            "updated" => updated.push(id),
            "destroyed" => destroyed.push(id),
            _ => {}
        }
    }
    (created, updated, destroyed)
}

pub async fn set(_ctx: &Arc<JmapContext>, _args: Value) -> Result<Value, MethodError> {
    Err(MethodError::not_supported())
}
