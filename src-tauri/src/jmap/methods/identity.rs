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

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let email = ctx.email().await;
    let name = email.split('@').next().unwrap_or(&email).to_string();
    let id = format!("identity-{}", account_id);
    let identity = json!({
        "id": id,
        "name": name,
        "email": email,
        "replyTo": null,
        "bcc": null,
        "textSignature": "",
        "htmlSignature": "",
        "mayDelete": false
    });
    let state = ctx.db.jmap_state_get("Identity").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "state": state.to_string(),
        "list": [identity],
        "notFound": []
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

    fn test_ctx(email: &str) -> (Arc<JmapContext>, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[6u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let account = Uuid::new_v4();
        let session = Arc::new(RwLock::new(Session {
            user_id: account,
            username: "tester".to_string(),
            email: email.to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
        }));
        let client = Arc::new(crate::api_client::ApiClient::new());
        let (tx, _rx) = broadcast::channel(8);
        (JmapContext::new(session, db, client, tx), account.to_string(), dir)
    }

    #[tokio::test]
    async fn get_builds_identity_from_email() {
        let (ctx, account, _d) = test_ctx("alice@aster.test");
        let res = ok(get(&ctx, json!({})).await);
        let id = &res["list"][0];
        assert_eq!(id["email"], json!("alice@aster.test"));
        assert_eq!(id["name"], json!("alice"));
        assert_eq!(id["id"], json!(format!("identity-{}", account)));
        assert_eq!(id["mayDelete"], json!(false));
        assert_eq!(res["notFound"], json!([]));
    }

    #[tokio::test]
    async fn get_name_falls_back_to_full_when_no_at() {
        let (ctx, _account, _d) = test_ctx("plainuser");
        let res = ok(get(&ctx, json!({})).await);
        assert_eq!(res["list"][0]["name"], json!("plainuser"));
    }

    #[tokio::test]
    async fn get_rejects_wrong_account() {
        let (ctx, _account, _d) = test_ctx("alice@aster.test");
        assert_eq!(
            err_kind(get(&ctx, json!({"accountId": "wrong"})).await),
            "accountNotFound"
        );
    }

    #[tokio::test]
    async fn get_signatures_empty() {
        let (ctx, _account, _d) = test_ctx("alice@aster.test");
        let res = ok(get(&ctx, json!({})).await);
        assert_eq!(res["list"][0]["textSignature"], json!(""));
        assert_eq!(res["list"][0]["htmlSignature"], json!(""));
    }
}
