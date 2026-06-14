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

        let expected_identity = format!("identity-{}", account_id);
        if let Some(identity_id) = sub.get("identityId").and_then(|v| v.as_str()) {
            if identity_id != expected_identity {
                not_created.insert(
                    creation_id.clone(),
                    json!({"type": "invalidProperties", "properties": ["identityId"], "description": "unknown identityId"}),
                );
                continue;
            }
        }

        let recipients_str = msg.recipients.clone().unwrap_or_default();
        let to_list: Vec<String> = recipients_str
            .split(',')
            .map(|s| strip_header_chars(s.trim()))
            .filter(|s| !s.is_empty())
            .collect();
        let sender_email = {
            let s = ctx.session.read().await;
            s.email.clone()
        };
        let body_content = msg.body_text.clone().unwrap_or_default();
        let body = json!({
            "to": to_list,
            "subject": strip_header_chars(&msg.subject.clone().unwrap_or_default()),
            "body": if body_content.is_empty() { " ".to_string() } else { body_content },
            "sender_email": sender_email,
            "is_e2e_encrypted": false,
            "client_source": "bridge",
        });

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
