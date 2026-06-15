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
        let db = Arc::new(Database::open_with_key(dir.path(), &[5u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let session = Arc::new(RwLock::new(Session {
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_keys: Vec::new(),
        }));
        let client = Arc::new(crate::api_client::ApiClient::new());
        let (tx, _rx) = broadcast::channel(8);
        (JmapContext::new(session, db, client, tx), dir)
    }

    fn add_msg(ctx: &Arc<JmapContext>, id: &str, folder: &str, seen: bool) {
        ctx.db
            .upsert_cached_message(id, folder, Some("s"), Some("a@b.com"), Some("c@d.com"), Some("2026-01-01T00:00:00Z"), 10, Some("body"), Some("{}"))
            .unwrap();
        if seen {
            ctx.db.set_message_flags_by_id(id, 1).unwrap();
        }
    }

    #[tokio::test]
    async fn get_returns_all_six_fixed_mailboxes() {
        let (ctx, _d) = test_ctx();
        let res = ok(get(&ctx, json!({})).await);
        let list = res["list"].as_array().unwrap();
        assert_eq!(list.len(), 6);
        let names: Vec<&str> = list.iter().map(|m| m["name"].as_str().unwrap()).collect();
        for expected in ["Inbox", "Sent", "Drafts", "Trash", "Junk", "Archive"] {
            assert!(names.contains(&expected), "missing {}", expected);
        }
    }

    #[tokio::test]
    async fn get_by_ids_filters_and_reports_not_found() {
        let (ctx, _d) = test_ctx();
        let res = ok(get(&ctx, json!({"ids": ["mbx_inbox", "ghost"]})).await);
        assert_eq!(res["list"].as_array().unwrap().len(), 1);
        assert_eq!(res["list"][0]["id"], json!("mbx_inbox"));
        assert_eq!(res["notFound"], json!(["ghost"]));
    }

    #[tokio::test]
    async fn get_counts_reflect_messages_and_unread() {
        let (ctx, _d) = test_ctx();
        add_msg(&ctx, "m1", "inbox", false);
        add_msg(&ctx, "m2", "inbox", true);
        let res = ok(get(&ctx, json!({"ids": ["mbx_inbox"]})).await);
        let mbx = &res["list"][0];
        assert_eq!(mbx["totalEmails"], json!(2));
        assert_eq!(mbx["unreadEmails"], json!(1));
    }

    #[tokio::test]
    async fn get_rejects_too_many_ids() {
        let (ctx, _d) = test_ctx();
        let ids: Vec<String> = (0..501).map(|i| i.to_string()).collect();
        assert_eq!(err_kind(get(&ctx, json!({"ids": ids})).await), "requestTooLarge");
    }

    #[tokio::test]
    async fn get_my_rights_shape() {
        let (ctx, _d) = test_ctx();
        let res = ok(get(&ctx, json!({"ids": ["mbx_inbox"]})).await);
        let rights = &res["list"][0]["myRights"];
        assert_eq!(rights["mayReadItems"], json!(true));
        assert_eq!(rights["mayCreateChild"], json!(false));
        assert_eq!(rights["mayDelete"], json!(false));
    }

    #[tokio::test]
    async fn query_returns_all_ids() {
        let (ctx, _d) = test_ctx();
        let res = ok(query(&ctx, json!({})).await);
        assert_eq!(res["total"], json!(6));
        assert_eq!(res["ids"].as_array().unwrap().len(), 6);
        assert_eq!(res["canCalculateChanges"], json!(false));
    }

    #[tokio::test]
    async fn changes_requires_since_state() {
        let (ctx, _d) = test_ctx();
        assert_eq!(err_kind(changes(&ctx, json!({})).await), "invalidArguments");
    }

    #[tokio::test]
    async fn changes_reports_created_updated_destroyed() {
        let (ctx, _d) = test_ctx();
        ctx.db.jmap_change_log_append("Mailbox", 1, "x", "created").unwrap();
        ctx.db.jmap_change_log_append("Mailbox", 2, "y", "updated").unwrap();
        ctx.db.jmap_change_log_append("Mailbox", 3, "z", "destroyed").unwrap();
        let res = ok(changes(&ctx, json!({"sinceState": "0"})).await);
        assert_eq!(res["created"], json!(["x"]));
        assert_eq!(res["updated"], json!(["y"]));
        assert_eq!(res["destroyed"], json!(["z"]));
    }

    #[tokio::test]
    async fn set_is_not_supported() {
        let (ctx, _d) = test_ctx();
        assert_eq!(err_kind(set(&ctx, json!({})).await), "notSupported");
    }

    #[test]
    fn partition_ops_create_then_update_stays_created() {
        let entries = vec![
            ("a".to_string(), "created".to_string()),
            ("a".to_string(), "updated".to_string()),
        ];
        let (created, updated, destroyed) = partition_ops(entries);
        assert_eq!(created, vec!["a".to_string()]);
        assert!(updated.is_empty());
        assert!(destroyed.is_empty());
    }

    #[test]
    fn partition_ops_destroy_wins() {
        let entries = vec![
            ("b".to_string(), "created".to_string()),
            ("b".to_string(), "destroyed".to_string()),
        ];
        let (created, updated, destroyed) = partition_ops(entries);
        assert!(created.is_empty());
        assert!(updated.is_empty());
        assert_eq!(destroyed, vec!["b".to_string()]);
    }

    #[test]
    fn partition_ops_destroyed_then_recreated_ignores_later() {
        let entries = vec![
            ("c".to_string(), "destroyed".to_string()),
            ("c".to_string(), "created".to_string()),
        ];
        let (created, _updated, destroyed) = partition_ops(entries);
        assert!(created.is_empty());
        assert_eq!(destroyed, vec!["c".to_string()]);
    }

    #[test]
    fn partition_ops_empty() {
        let (created, updated, destroyed) = partition_ops(Vec::new());
        assert!(created.is_empty() && updated.is_empty() && destroyed.is_empty());
    }
}
