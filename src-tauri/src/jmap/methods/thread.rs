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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;
    use crate::db::Database;
    use tokio::sync::{broadcast, RwLock};
    use uuid::Uuid;

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

    fn test_ctx() -> (Arc<JmapContext>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[4u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let session = Arc::new(RwLock::new(Session {
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_keys: Vec::new(),
            send_identities: Vec::new(),
        }));
        let client = Arc::new(crate::api_client::ApiClient::new());
        let (tx, _rx) = broadcast::channel(8);
        (JmapContext::new(session, db, client, tx), dir)
    }

    fn add_msg(ctx: &Arc<JmapContext>, id: &str, thread: Option<&str>, date: &str) {
        ctx.db
            .upsert_cached_message(id, "inbox", Some("s"), Some("a@b.com"), Some("c@d.com"), Some(date), 10, Some("body"), Some("{}"))
            .unwrap();
        ctx.db.update_message_thread_and_msgid(id, thread, None).unwrap();
    }

    #[tokio::test]
    async fn get_groups_messages_in_thread_ordered_by_date() {
        let (ctx, _d) = test_ctx();
        add_msg(&ctx, "m1", Some("t1"), "2026-01-02T00:00:00Z");
        add_msg(&ctx, "m2", Some("t1"), "2026-01-01T00:00:00Z");
        let res = ok(get(&ctx, json!({"ids": ["t1"]})).await);
        assert_eq!(res["list"][0]["id"], json!("t1"));
        assert_eq!(res["list"][0]["emailIds"], json!(["m2", "m1"]));
    }

    #[tokio::test]
    async fn get_singleton_thread_via_aster_id() {
        let (ctx, _d) = test_ctx();
        add_msg(&ctx, "solo", None, "2026-01-01T00:00:00Z");
        let res = ok(get(&ctx, json!({"ids": ["solo"]})).await);
        assert_eq!(res["list"][0]["emailIds"], json!(["solo"]));
    }

    #[tokio::test]
    async fn get_unknown_thread_is_not_found() {
        let (ctx, _d) = test_ctx();
        let res = ok(get(&ctx, json!({"ids": ["nope"]})).await);
        assert!(res["list"].as_array().unwrap().is_empty());
        assert_eq!(res["notFound"], json!(["nope"]));
    }

    #[tokio::test]
    async fn get_empty_ids() {
        let (ctx, _d) = test_ctx();
        let res = ok(get(&ctx, json!({})).await);
        assert!(res["list"].as_array().unwrap().is_empty());
        assert!(res["notFound"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_rejects_too_many_ids() {
        let (ctx, _d) = test_ctx();
        let ids: Vec<String> = (0..501).map(|i| i.to_string()).collect();
        assert_eq!(err_kind(get(&ctx, json!({"ids": ids})).await), "requestTooLarge");
    }

    #[tokio::test]
    async fn changes_requires_since_state() {
        let (ctx, _d) = test_ctx();
        assert_eq!(err_kind(changes(&ctx, json!({})).await), "invalidArguments");
    }

    #[tokio::test]
    async fn changes_partitions_ops() {
        let (ctx, _d) = test_ctx();
        ctx.db.jmap_change_log_append("Thread", 1, "t1", "created").unwrap();
        let res = ok(changes(&ctx, json!({"sinceState": "0"})).await);
        assert_eq!(res["created"], json!(["t1"]));
        assert_eq!(res["oldState"], json!("0"));
    }

    #[tokio::test]
    async fn changes_too_old_rejected() {
        let (ctx, _d) = test_ctx();
        ctx.db.jmap_change_log_append("Thread", 50, "t1", "created").unwrap();
        assert_eq!(
            err_kind(changes(&ctx, json!({"sinceState": "1"})).await),
            "cannotCalculateChanges"
        );
    }
}
