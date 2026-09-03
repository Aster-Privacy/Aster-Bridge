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

use crate::jmap::dispatcher::MethodError;
use crate::jmap::state::JmapContext;

fn strip_header_chars(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .collect()
}

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let want = args
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let state = ctx.db.jmap_state_get("EmailSubmission").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "state": state.to_string(),
        "list": [],
        "notFound": want,
    }))
}

async fn submission_body(
    ctx: &Arc<JmapContext>,
    msg: &crate::db::CachedMessage,
    resolved_id: &str,
    sender_email: String,
    sender_alias_hash: Option<String>,
    sender_display_name: Option<String>,
) -> Result<Value, String> {
    let recipients_str = msg.recipients.clone().unwrap_or_default();
    let to_list: Vec<String> = recipients_str
        .split(',')
        .map(|s| strip_header_chars(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();
    let body_content = msg.body_text.clone().unwrap_or_default();
    let meta: Value = msg
        .raw_headers
        .as_deref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or(Value::Null);
    let is_html = meta.get("is_html").and_then(|v| v.as_bool()).unwrap_or(false);
    let cc_list = meta_address_list(&meta, "cc");
    let bcc_list = meta_address_list(&meta, "bcc");
    let final_body = if body_content.is_empty() {
        " ".to_string()
    } else {
        body_content
    };
    let mut body = json!({
        "to": to_list,
        "subject": strip_header_chars(&msg.subject.clone().unwrap_or_default()),
        "body": final_body,
        "is_html": is_html,
        "sender_email": sender_email,
        "is_e2e_encrypted": false,
        "client_source": "bridge",
    });
    if is_html {
        body["body_html"] = body["body"].clone();
    }
    if !cc_list.is_empty() {
        body["cc"] = json!(cc_list);
    }
    if !bcc_list.is_empty() {
        body["bcc"] = json!(bcc_list);
    }
    if let Some(hash) = sender_alias_hash {
        body["sender_alias_hash"] = json!(hash);
    }
    if let Some(dn) = sender_display_name {
        body["sender_display_name"] = json!(dn);
    }
    if msg.attachments_state != crate::db::ATTACHMENTS_STORED {
        return Ok(body);
    }
    let stored = ctx.db.get_message_attachments(resolved_id).unwrap_or_default();
    if stored.is_empty() {
        return Ok(body);
    }
    let outgoing: Vec<crate::crypto::attachment::OutgoingAttachment> = stored
        .into_iter()
        .map(|a| crate::crypto::attachment::OutgoingAttachment {
            name: a.name,
            mime_type: a.content_type,
            content_id: a.content_id,
            is_inline: a.is_inline,
            data: a.data,
        })
        .collect();
    let passphrase = zeroize::Zeroizing::new(ctx.session.read().await.vault_passphrase.clone());
    let sealed = tokio::task::spawn_blocking(move || {
        crate::crypto::attachment::seal_send_attachments(&outgoing, &passphrase)
    })
    .await;
    match sealed {
        Ok(Ok(list)) => {
            body["attachments"] = Value::Array(list);
            Ok(body)
        }
        Ok(Err(e)) => Err(format!("attachment sealing failed: {}", e)),
        Err(e) => Err(format!("attachment sealing did not finish: {}", e)),
    }
}

fn meta_address_list(meta: &Value, key: &str) -> Vec<String> {
    meta.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .split(',')
        .map(|s| strip_header_chars(s.trim()))
        .filter(|s| !s.is_empty())
        .collect()
}

pub async fn set(
    ctx: &Arc<JmapContext>,
    args: Value,
    created_ids_out: &mut HashMap<String, String>,
) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let creates = args
        .get("create")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();

    let old_state = ctx.db.jmap_state_get("EmailSubmission").unwrap_or(0);
    let access_token = ctx.session.read().await.access_token.clone();

    for (creation_id, sub) in creates {
        let email_id = match sub
            .get("emailId")
            .and_then(|v| v.as_str())
            .or_else(|| {
                sub.get("#emailId")
                    .and_then(|v| v.get("resultOf"))
                    .and_then(|v| v.as_str())
            }) {
            Some(s) => s.to_string(),
            None => {
                not_created.insert(
                    creation_id.clone(),
                    json!({"type": "invalidProperties", "properties": ["emailId"]}),
                );
                continue;
            }
        };

        let resolved_id = created_ids_out
            .get(email_id.trim_start_matches('#'))
            .cloned()
            .unwrap_or(email_id);

        let msg = match ctx.db.get_cached_message(&resolved_id) {
            Ok(Some(m)) => m,
            _ => {
                not_created.insert(
                    creation_id.clone(),
                    json!({"type": "invalidProperties", "properties": ["emailId"], "description": "email not found"}),
                );
                continue;
            }
        };

        // Resolve identityId to a cached send identity. The default
        // "identity-{account}" form (and an absent identityId) maps to primary.
        // Non-primary ids resolve to an enabled alias / custom-domain identity.
        let expected_primary = format!("identity-{}", account_id);
        let requested_identity_id = sub
            .get("identityId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let resolved_sender: Option<(String, Option<String>, Option<String>)> = {
            let s = ctx.session.read().await;
            match requested_identity_id.as_deref() {
                None | Some("") => Some((s.email.clone(), None, None)),
                Some(id) if id == expected_primary => Some((s.email.clone(), None, None)),
                Some(id) => s
                    .send_identities
                    .iter()
                    .filter(|i| {
                        i.enabled && i.kind != crate::auth::session::SendIdentityKind::Primary
                    })
                    .find(|i| {
                        crate::jmap::methods::identity::identity_id(&account_id, i) == id
                    })
                    .map(|i| {
                        (
                            i.address.clone(),
                            i.auth_hash_b64.clone(),
                            i.display_name.clone(),
                        )
                    }),
            }
        };

        let (sender_email, sender_alias_hash, sender_display_name) = match resolved_sender {
            Some(t) => t,
            None => {
                not_created.insert(
                    creation_id.clone(),
                    json!({"type": "invalidProperties", "properties": ["identityId"], "description": "unknown identityId"}),
                );
                continue;
            }
        };

        let body = match submission_body(
            ctx,
            &msg,
            &resolved_id,
            sender_email,
            sender_alias_hash,
            sender_display_name,
        )
        .await
        {
            Ok(b) => b,
            Err(description) => {
                not_created.insert(
                    creation_id,
                    json!({"type": "forbiddenToSend", "description": description}),
                );
                continue;
            }
        };

        match ctx.client.send_mail(&access_token, &body).await {
            Ok(_) => {
                let sub_id = format!("submission-{}", resolved_id);
                created.insert(
                    creation_id.clone(),
                    json!({
                        "id": sub_id.clone(),
                        "sendAt": chrono::Utc::now().to_rfc3339(),
                        "undoStatus": "final",
                        "deliveryStatus": null,
                    }),
                );
                created_ids_out.insert(creation_id, sub_id);
                let _ = ctx.db.jmap_state_bump("EmailSubmission");
            }
            Err(e) => {
                not_created.insert(
                    creation_id,
                    json!({"type": "forbiddenToSend", "description": e.to_string()}),
                );
            }
        }
    }

    let new_state = ctx.db.jmap_state_get("EmailSubmission").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "oldState": old_state.to_string(),
        "newState": new_state.to_string(),
        "created": created,
        "notCreated": not_created,
        "updated": null,
        "notUpdated": null,
        "destroyed": [],
        "notDestroyed": null,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;
    use crate::db::Database;
    use serde_json::Value;
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

    fn test_ctx() -> (Arc<JmapContext>, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[3u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let account = Uuid::new_v4();
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: account,
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
        }));
        let client = Arc::new(crate::api_client::ApiClient::new());
        let (tx, _rx) = broadcast::channel(8);
        (JmapContext::new(session, db, client, tx), account.to_string(), dir)
    }

    fn add_msg(ctx: &Arc<JmapContext>, id: &str) {
        ctx.db
            .upsert_cached_message(id, "drafts", Some("Subj"), Some("a@b.com"), Some("to@x.com, two@y.com"), Some("2026-01-01T00:00:00Z"), 10, Some("body"), Some("{}"))
            .unwrap();
    }

    fn open_sealed(value: &Value) -> (Vec<u8>, Value) {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let meta_bytes = STANDARD
            .decode(value["recipient_encrypted_meta"].as_str().unwrap())
            .unwrap();
        let meta: Value = serde_json::from_slice(&meta_bytes).unwrap();
        let key = STANDARD.decode(meta["session_key"].as_str().unwrap()).unwrap();
        let nonce = STANDARD.decode(value["data_nonce"].as_str().unwrap()).unwrap();
        let ct = STANDARD.decode(value["encrypted_data"].as_str().unwrap()).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        (cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).unwrap(), meta)
    }

    #[tokio::test]
    async fn submission_body_carries_html_cc_bcc_and_attachments() {
        let (ctx, _a, _d) = test_ctx();
        let meta = json!({
            "is_html": true,
            "cc": "cc1@x.com, cc2@y.com",
            "bcc": "hidden@z.com",
            "attachment_count": 1
        })
        .to_string();
        ctx.db
            .upsert_cached_message(
                "d1",
                "drafts",
                Some("Files"),
                Some("tester@aster.test"),
                Some("to@x.com"),
                Some("2026-01-01T00:00:00Z"),
                10,
                Some("<p>hello</p>"),
                Some(&meta),
            )
            .unwrap();
        ctx.db
            .replace_message_attachments(
                "d1",
                &[crate::db::CachedAttachment {
                    seq: 0,
                    name: "notes.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    content_id: None,
                    is_inline: false,
                    size: 5,
                    data: b"notes".to_vec(),
                }],
            )
            .unwrap();
        ctx.db
            .set_attachments_state("d1", crate::db::ATTACHMENTS_STORED)
            .unwrap();
        let msg = ctx.db.get_cached_message("d1").unwrap().unwrap();
        let body = submission_body(&ctx, &msg, "d1", "tester@aster.test".to_string(), None, None)
            .await
            .unwrap();
        assert_eq!(body["to"], json!(["to@x.com"]));
        assert_eq!(body["cc"], json!(["cc1@x.com", "cc2@y.com"]));
        assert_eq!(body["bcc"], json!(["hidden@z.com"]));
        assert_eq!(body["is_html"], json!(true));
        assert_eq!(body["body_html"], json!("<p>hello</p>"));
        let list = body["attachments"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        let (plain, meta) = open_sealed(&list[0]);
        assert_eq!(plain, b"notes");
        assert_eq!(meta["filename"], "notes.txt");
        assert_eq!(meta["content_type"], "text/plain");
    }

    #[tokio::test]
    async fn submission_body_plain_message_has_no_extras() {
        let (ctx, _a, _d) = test_ctx();
        add_msg(&ctx, "p1");
        let msg = ctx.db.get_cached_message("p1").unwrap().unwrap();
        let body = submission_body(&ctx, &msg, "p1", "tester@aster.test".to_string(), None, None)
            .await
            .unwrap();
        assert_eq!(body["is_html"], json!(false));
        assert!(body.get("body_html").is_none());
        assert!(body.get("cc").is_none());
        assert!(body.get("bcc").is_none());
        assert!(body.get("attachments").is_none());
        assert_eq!(body["to"], json!(["to@x.com", "two@y.com"]));
    }

    #[tokio::test]
    async fn submission_body_skips_attachments_that_are_not_stored() {
        let (ctx, _a, _d) = test_ctx();
        add_msg(&ctx, "p2");
        ctx.db
            .set_attachments_state("p2", crate::db::ATTACHMENTS_PENDING)
            .unwrap();
        let msg = ctx.db.get_cached_message("p2").unwrap().unwrap();
        let body = submission_body(&ctx, &msg, "p2", "tester@aster.test".to_string(), None, None)
            .await
            .unwrap();
        assert!(body.get("attachments").is_none());
    }

    #[test]
    fn strip_header_chars_removes_crlf_nul() {
        assert_eq!(strip_header_chars("a\r\nb\0c"), "abc");
        assert_eq!(strip_header_chars("clean"), "clean");
    }

    #[tokio::test]
    async fn get_always_not_found() {
        let (ctx, _a, _d) = test_ctx();
        let res = ok(get(&ctx, json!({"ids": ["s1", "s2"]})).await);
        assert!(res["list"].as_array().unwrap().is_empty());
        assert_eq!(res["notFound"], json!(["s1", "s2"]));
    }

    #[tokio::test]
    async fn get_wrong_account_rejected() {
        let (ctx, _a, _d) = test_ctx();
        assert_eq!(
            err_kind(get(&ctx, json!({"accountId": "nope"})).await),
            "accountNotFound"
        );
    }

    #[tokio::test]
    async fn set_missing_email_id_invalid_properties() {
        let (ctx, _a, _d) = test_ctx();
        let args = json!({"create": {"c1": {"identityId": "x"}}});
        let res = ok(set(&ctx, args, &mut HashMap::new()).await);
        let entry = &res["notCreated"]["c1"];
        assert_eq!(entry["type"], json!("invalidProperties"));
        assert_eq!(entry["properties"], json!(["emailId"]));
    }

    #[tokio::test]
    async fn set_email_not_found() {
        let (ctx, _a, _d) = test_ctx();
        let args = json!({"create": {"c1": {"emailId": "ghost"}}});
        let res = ok(set(&ctx, args, &mut HashMap::new()).await);
        assert_eq!(res["notCreated"]["c1"]["type"], json!("invalidProperties"));
        assert_eq!(res["notCreated"]["c1"]["description"], json!("email not found"));
    }

    #[tokio::test]
    async fn set_unknown_identity_rejected() {
        let (ctx, _a, _d) = test_ctx();
        add_msg(&ctx, "e1");
        let args = json!({"create": {"c1": {"emailId": "e1", "identityId": "identity-bogus"}}});
        let res = ok(set(&ctx, args, &mut HashMap::new()).await);
        assert_eq!(res["notCreated"]["c1"]["type"], json!("invalidProperties"));
        assert_eq!(res["notCreated"]["c1"]["properties"], json!(["identityId"]));
    }

    #[tokio::test]
    async fn set_empty_create_is_noop() {
        let (ctx, _a, _d) = test_ctx();
        let res = ok(set(&ctx, json!({}), &mut HashMap::new()).await);
        assert!(res["created"].as_object().unwrap().is_empty());
        assert!(res["notCreated"].as_object().unwrap().is_empty());
        assert_eq!(res["destroyed"], json!([]));
    }

    #[tokio::test]
    async fn set_send_failure_maps_to_forbidden() {
        let (ctx, account, _d) = test_ctx();
        add_msg(&ctx, "e2");
        let identity = format!("identity-{}", account);
        let args = json!({"create": {"c1": {"emailId": "e2", "identityId": identity}}});
        let res = ok(set(&ctx, args, &mut HashMap::new()).await);
        assert_eq!(res["notCreated"]["c1"]["type"], json!("forbiddenToSend"));
    }
}
