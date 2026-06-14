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
use crate::jmap::methods::mailbox::partition_ops;
use crate::jmap::state::JmapContext;

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let want: Vec<String> = args
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if want.len() > 500 {
        return Err(MethodError::new("requestTooLarge", "too many ids"));
    }

    let mut list = Vec::new();
    let mut not_found = Vec::new();

    for tid in &want {
        let email_ids = ctx
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT aster_id FROM message_cache \
                     WHERE thread_id = ?1 OR (thread_id IS NULL AND aster_id = ?1) \
                     ORDER BY date ASC",
                )?;
                let rows = stmt.query_map([tid], |r| r.get::<_, String>(0))?;
                rows.collect::<std::result::Result<Vec<String>, _>>()
            })
            .unwrap_or_default();
        if email_ids.is_empty() {
            not_found.push(tid.clone());
        } else {
            list.push(json!({"id": tid, "emailIds": email_ids}));
        }
    }

    let state = ctx.db.jmap_state_get("Thread").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "state": state.to_string(),
        "list": list,
        "notFound": not_found,
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
        .jmap_changes_since("Thread", since)
        .map_err(|e| MethodError::new("serverError", e))?;
    if too_old {
        return Err(MethodError::new(
            "cannotCalculateChanges",
            "sinceState too old",
        ));
    }
    let new_state = if has_more { _partial_state } else { ctx.db.jmap_state_get("Thread").unwrap_or(since) };
    let (created, updated, destroyed) = partition_ops(entries);
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
