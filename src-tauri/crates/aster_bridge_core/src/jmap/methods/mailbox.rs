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

use crate::folder_ops::FolderOpError;
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
    let custom = crate::folders::is_custom_label(&r.folder_label);
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
            "mayCreateChild": custom,
            "mayRename": custom,
            "mayDelete": custom,
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

const IGNORED_MAILBOX_PROPERTIES: [&str; 2] = ["sortOrder", "isSubscribed"];

enum MailboxRef {
    System,
    Custom(String),
    Unknown,
}

fn resolve_mailbox_ref(
    ctx: &JmapContext,
    id: &str,
    created_ids: &HashMap<String, String>,
) -> MailboxRef {
    let id = match id.strip_prefix('#') {
        Some(creation_id) => match created_ids.get(creation_id) {
            Some(real) => real.as_str(),
            None => return MailboxRef::Unknown,
        },
        None => id,
    };
    match store::mailbox_id_to_label_map(&ctx.db).get(id) {
        Some(label) => match crate::folders::token_of_label(label) {
            Some(token) => MailboxRef::Custom(token.to_string()),
            None => MailboxRef::System,
        },
        None => MailboxRef::Unknown,
    }
}

fn invalid_property(property: &str, description: &str) -> Value {
    json!({
        "type": "invalidProperties",
        "properties": [property],
        "description": description
    })
}

fn parse_parent(
    ctx: &JmapContext,
    value: &Value,
    created_ids: &HashMap<String, String>,
) -> Result<Option<String>, Value> {
    if value.is_null() {
        return Ok(None);
    }
    let Some(id) = value.as_str() else {
        return Err(invalid_property("parentId", "parentId must be a mailbox id or null"));
    };
    match resolve_mailbox_ref(ctx, id, created_ids) {
        MailboxRef::Custom(token) => Ok(Some(token)),
        MailboxRef::System => Err(invalid_property(
            "parentId",
            "system mailboxes cannot contain other mailboxes",
        )),
        MailboxRef::Unknown => Err(FolderOpError::ParentNotFound.jmap_set_error()),
    }
}

fn check_name(name: &str) -> Result<(), Value> {
    crate::folders::validate_name(name.trim()).map_err(|msg| invalid_property("name", msg))
}

fn check_properties(props: &serde_json::Map<String, Value>) -> Result<(), Value> {
    for (key, value) in props {
        let allowed = key == "name"
            || key == "parentId"
            || IGNORED_MAILBOX_PROPERTIES.contains(&key.as_str())
            || (key == "role" && value.is_null());
        if !allowed {
            return Err(invalid_property(key, "this property cannot be set"));
        }
    }
    Ok(())
}

async fn create_mailbox(
    ctx: &JmapContext,
    access_token: &str,
    identity_key: Option<&str>,
    props: &Value,
    created_ids: &HashMap<String, String>,
) -> Result<String, Value> {
    let Some(props) = props.as_object() else {
        return Err(invalid_property("name", "mailbox must be an object"));
    };
    check_properties(props)?;
    let Some(name) = props.get("name").and_then(|v| v.as_str()) else {
        return Err(invalid_property("name", "name is required"));
    };
    check_name(name)?;
    let parent = parse_parent(ctx, props.get("parentId").unwrap_or(&Value::Null), created_ids)?;
    let identity_key = identity_key.ok_or_else(|| FolderOpError::Locked.jmap_set_error())?;
    crate::folder_ops::create(
        &ctx.db,
        &ctx.client,
        access_token,
        identity_key,
        name,
        parent.as_deref(),
    )
    .await
    .map_err(|e| e.jmap_set_error())
}

async fn update_mailbox(
    ctx: &JmapContext,
    access_token: &str,
    identity_key: Option<&str>,
    id: &str,
    patch: &Value,
    created_ids: &HashMap<String, String>,
) -> Result<(), Value> {
    let Some(patch) = patch.as_object() else {
        return Err(json!({"type": "invalidPatch", "description": "patch must be an object"}));
    };
    check_properties(patch)?;
    let target = resolve_mailbox_ref(ctx, id, created_ids);
    let changes_folder = patch.contains_key("name") || patch.contains_key("parentId");
    let token = match target {
        MailboxRef::Unknown => return Err(FolderOpError::NotFound.jmap_set_error()),
        _ if !changes_folder => return Ok(()),
        MailboxRef::System => return Err(FolderOpError::SystemMailbox.jmap_set_error()),
        MailboxRef::Custom(token) => token,
    };
    let name = match patch.get("name") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| invalid_property("name", "name must be a string"))
                .and_then(|n| check_name(n).map(|_| n))?,
        ),
    };
    let parent = match patch.get("parentId") {
        None => None,
        Some(v) => Some(parse_parent(ctx, v, created_ids)?),
    };
    let identity_key = identity_key.ok_or_else(|| FolderOpError::Locked.jmap_set_error())?;
    crate::folder_ops::update(
        &ctx.db,
        &ctx.client,
        access_token,
        identity_key,
        &token,
        name,
        parent.as_ref().map(|p| p.as_deref()),
    )
    .await
    .map_err(|e| e.jmap_set_error())
}

async fn destroy_mailbox(
    ctx: &JmapContext,
    access_token: &str,
    id: &str,
    remove_emails: bool,
    created_ids: &HashMap<String, String>,
) -> Result<bool, Value> {
    let token = match resolve_mailbox_ref(ctx, id, created_ids) {
        MailboxRef::Unknown => return Err(FolderOpError::NotFound.jmap_set_error()),
        MailboxRef::System => return Err(FolderOpError::SystemMailbox.jmap_set_error()),
        MailboxRef::Custom(token) => token,
    };
    let folders = ctx
        .db
        .list_custom_folders()
        .map_err(|e| FolderOpError::Server(e).jmap_set_error())?;
    if crate::folder_ops::has_children(&folders, &token) {
        return Err(FolderOpError::HasChildren.jmap_set_error());
    }
    let label = crate::folders::folder_label(&token);
    if !remove_emails && ctx.db.count_cached_messages(&label).unwrap_or(0) > 0 {
        return Err(json!({
            "type": "mailboxHasEmail",
            "description": "move or delete the messages in this mailbox first"
        }));
    }
    let moved = crate::folder_ops::delete(&ctx.db, &ctx.client, access_token, &token)
        .await
        .map_err(|e| e.jmap_set_error())?;
    Ok(!moved.is_empty())
}

fn created_mailbox(id: &str) -> Value {
    json!({
        "id": id,
        "role": null,
        "totalEmails": 0,
        "unreadEmails": 0,
        "totalThreads": 0,
        "unreadThreads": 0,
        "myRights": {
            "mayReadItems": true,
            "mayAddItems": true,
            "mayRemoveItems": true,
            "maySetSeen": true,
            "maySetKeywords": true,
            "mayCreateChild": true,
            "mayRename": true,
            "mayDelete": true,
            "maySubmit": true
        },
        "isSubscribed": true
    })
}

fn string_ids(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

fn optional_map(map: serde_json::Map<String, Value>) -> Value {
    if map.is_empty() {
        Value::Null
    } else {
        Value::Object(map)
    }
}

pub async fn set(
    ctx: &Arc<JmapContext>,
    args: Value,
    created_ids_out: &mut HashMap<String, String>,
) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let old_state = ctx.db.jmap_state_get("Mailbox").unwrap_or(0);
    if let Some(expected) = args.get("ifInState").and_then(|v| v.as_str()) {
        if expected != old_state.to_string() {
            return Err(MethodError::new("stateMismatch", "mailbox state has changed"));
        }
    }

    let creates = args.get("create").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let updates = args.get("update").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let destroys = string_ids(args.get("destroy"));
    if creates.len() + updates.len() + destroys.len() > 500 {
        return Err(MethodError::new("requestTooLarge", "exceeds maxObjectsInSet (500)"));
    }
    let remove_emails = args
        .get("onDestroyRemoveEmails")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let (access_token, identity_key) = {
        let s = ctx.session.read().await;
        (s.access_token.to_string(), s.identity_key.clone())
    };
    let before = ctx
        .db
        .list_custom_folders()
        .map_err(|e| MethodError::new("serverFail", e))?;

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();
    for (creation_id, props) in &creates {
        match create_mailbox(ctx, &access_token, identity_key.as_deref(), props, created_ids_out)
            .await
        {
            Ok(token) => {
                let id = crate::folders::jmap_mailbox_id(&token);
                created_ids_out.insert(creation_id.clone(), id.clone());
                created.insert(creation_id.clone(), created_mailbox(&id));
            }
            Err(err) => {
                not_created.insert(creation_id.clone(), err);
            }
        }
    }

    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    for (id, patch) in &updates {
        match update_mailbox(ctx, &access_token, identity_key.as_deref(), id, patch, created_ids_out)
            .await
        {
            Ok(()) => {
                updated.insert(id.clone(), Value::Null);
            }
            Err(err) => {
                not_updated.insert(id.clone(), err);
            }
        }
    }

    let mut destroyed: Vec<String> = Vec::new();
    let mut not_destroyed = serde_json::Map::new();
    let mut emails_moved = false;
    for id in &destroys {
        match destroy_mailbox(ctx, &access_token, id, remove_emails, created_ids_out).await {
            Ok(moved) => {
                emails_moved |= moved;
                destroyed.push(id.clone());
            }
            Err(err) => {
                not_destroyed.insert(id.clone(), err);
            }
        }
    }

    let after = ctx
        .db
        .list_custom_folders()
        .map_err(|e| MethodError::new("serverFail", e))?;
    let mailboxes_changed = crate::sync::poller::record_mailbox_diff(&ctx.db, &before, &after);
    let new_state = ctx.db.jmap_state_get("Mailbox").unwrap_or(old_state);
    if mailboxes_changed || emails_moved {
        let mut changed = HashMap::new();
        changed.insert("Mailbox".to_string(), new_state.to_string());
        if emails_moved {
            let email_state = ctx.db.jmap_state_get("Email").unwrap_or(0);
            changed.insert("Email".to_string(), email_state.to_string());
        }
        let _ = ctx
            .broadcaster
            .send(crate::jmap::state::StateChange { changed });
        crate::sync::poller::try_kick_sync();
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": old_state.to_string(),
        "newState": new_state.to_string(),
        "created": optional_map(created),
        "updated": optional_map(updated),
        "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
        "notCreated": optional_map(not_created),
        "notUpdated": optional_map(not_updated),
        "notDestroyed": optional_map(not_destroyed),
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
        let db = Arc::new(Database::open_with_key(dir.path(), &[5u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
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
    async fn set_rejects_system_mailbox_changes_without_calling_the_server() {
        let (ctx, _d) = test_ctx();
        let mut created_ids = HashMap::new();
        let res = ok(set(
            &ctx,
            json!({
                "update": {"mbx_inbox": {"name": "Renamed"}},
                "destroy": ["mbx_trash", "ghost"]
            }),
            &mut created_ids,
        )
        .await);
        assert_eq!(res["notUpdated"]["mbx_inbox"]["type"], json!("forbidden"));
        assert_eq!(res["notDestroyed"]["mbx_trash"]["type"], json!("forbidden"));
        assert_eq!(res["notDestroyed"]["ghost"]["type"], json!("notFound"));
        assert_eq!(res["created"], Value::Null);
    }

    #[tokio::test]
    async fn set_accepts_subscription_changes_on_system_mailboxes() {
        let (ctx, _d) = test_ctx();
        let mut created_ids = HashMap::new();
        let res = ok(set(
            &ctx,
            json!({"update": {"mbx_inbox": {"isSubscribed": true}}}),
            &mut created_ids,
        )
        .await);
        assert!(res["updated"].as_object().unwrap().contains_key("mbx_inbox"));
    }

    #[tokio::test]
    async fn set_create_validates_before_needing_keys() {
        let (ctx, _d) = test_ctx();
        let mut created_ids = HashMap::new();
        let res = ok(set(
            &ctx,
            json!({"create": {
                "a": {"name": "Projects"},
                "b": {"name": ""},
                "c": {"name": "Child", "parentId": "mbx_inbox"},
                "d": {"name": "Bad", "totalEmails": 3},
                "e": {"name": "Lost", "parentId": "#missing"}
            }}),
            &mut created_ids,
        )
        .await);
        assert_eq!(res["notCreated"]["a"]["type"], json!("forbidden"));
        assert_eq!(res["notCreated"]["b"]["type"], json!("invalidProperties"));
        assert_eq!(res["notCreated"]["c"]["properties"], json!(["parentId"]));
        assert_eq!(res["notCreated"]["d"]["properties"], json!(["totalEmails"]));
        assert_eq!(res["notCreated"]["e"]["properties"], json!(["parentId"]));
        assert!(created_ids.is_empty());
    }

    #[tokio::test]
    async fn set_destroy_refuses_folders_with_children_or_mail() {
        let (ctx, _d) = test_ctx();
        for (token, parent) in [("tok_p", None), ("tok_c", Some("tok_p")), ("tok_m", None)] {
            ctx.db
                .upsert_custom_folder(&crate::db::CustomFolder {
                    label_token: token.to_string(),
                    server_id: format!("srv-{}", token),
                    name: token.to_string(),
                    parent_token: parent.map(str::to_string),
                    sort_order: 0,
                    created_at: None,
                })
                .unwrap();
        }
        add_msg(&ctx, "m1", "folder:tok_m", false);
        let parent_id = crate::folders::jmap_mailbox_id("tok_p");
        let mail_id = crate::folders::jmap_mailbox_id("tok_m");
        let mut created_ids = HashMap::new();
        let res = ok(set(
            &ctx,
            json!({"destroy": [parent_id.clone(), mail_id.clone()]}),
            &mut created_ids,
        )
        .await);
        assert_eq!(res["notDestroyed"][&parent_id]["type"], json!("mailboxHasChild"));
        assert_eq!(res["notDestroyed"][&mail_id]["type"], json!("mailboxHasEmail"));
    }

    #[tokio::test]
    async fn set_rejects_stale_if_in_state() {
        let (ctx, _d) = test_ctx();
        let mut created_ids = HashMap::new();
        assert_eq!(
            err_kind(set(&ctx, json!({"ifInState": "999"}), &mut created_ids).await),
            "stateMismatch"
        );
    }

    #[tokio::test]
    async fn get_lists_custom_folders_with_parent_ids_and_rights() {
        let (ctx, _d) = test_ctx();
        for (token, name, parent) in [("tok_p", "Projects", None), ("tok_c", "Q3", Some("tok_p"))] {
            ctx.db
                .upsert_custom_folder(&crate::db::CustomFolder {
                    label_token: token.to_string(),
                    server_id: format!("srv-{}", token),
                    name: name.to_string(),
                    parent_token: parent.map(str::to_string),
                    sort_order: 0,
                    created_at: None,
                })
                .unwrap();
        }
        let res = ok(get(&ctx, json!({})).await);
        let list = res["list"].as_array().unwrap();
        assert_eq!(list.len(), 8);
        let child = list.iter().find(|m| m["name"] == json!("Q3")).unwrap();
        assert_eq!(child["parentId"], json!(crate::folders::jmap_mailbox_id("tok_p")));
        assert_eq!(child["role"], Value::Null);
        assert_eq!(child["myRights"]["mayRename"], json!(true));
        let parent = list.iter().find(|m| m["name"] == json!("Projects")).unwrap();
        assert_eq!(parent["parentId"], Value::Null);
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
