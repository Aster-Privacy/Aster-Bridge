//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::auth::session::{SendIdentity, SendIdentityKind};
use crate::jmap::dispatcher::MethodError;
use crate::jmap::state::JmapContext;

// Stable, derivable JMAP identity id. Primary keeps the historical
// "identity-{account}" form so existing clients are unaffected; non-primary
// identities encode their address so submission.rs can resolve them back
// without extra state.
pub fn identity_id(account_id: &str, identity: &SendIdentity) -> String {
    match identity.kind {
        SendIdentityKind::Primary => format!("identity-{}", account_id),
        _ => format!(
            "identity-{}-{}",
            account_id,
            URL_SAFE_NO_PAD.encode(identity.address.as_bytes())
        ),
    }
}

fn identity_json(account_id: &str, identity: &SendIdentity) -> Value {
    let name = identity.display_name.clone().unwrap_or_else(|| {
        identity
            .address
            .split('@')
            .next()
            .unwrap_or(&identity.address)
            .to_string()
    });
    json!({
        "id": identity_id(account_id, identity),
        "name": name,
        "email": identity.address,
        "replyTo": null,
        "bcc": null,
        "textSignature": "",
        "htmlSignature": "",
        "mayDelete": false
    })
}

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let list: Vec<Value> = {
        let s = ctx.session.read().await;
        if s.send_identities.is_empty() {
            // No cached identities (e.g. vault not decryptable): fall back to a
            // single primary identity derived from the session email.
            let email = s.email.clone();
            let name = email.split('@').next().unwrap_or(&email).to_string();
            vec![json!({
                "id": format!("identity-{}", account_id),
                "name": name,
                "email": email,
                "replyTo": null,
                "bcc": null,
                "textSignature": "",
                "htmlSignature": "",
                "mayDelete": false
            })]
        } else {
            s.send_identities
                .iter()
                .filter(|i| i.enabled)
                .map(|i| identity_json(&account_id, i))
                .collect()
        }
    };
    let state = ctx.db.jmap_state_get("Identity").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "state": state.to_string(),
        "list": list,
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
            ratchet_keys: Vec::new(),
            send_identities: Vec::new(),
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

    #[test]
    fn primary_identity_id_is_stable_form() {
        let id = SendIdentity {
            address: "alice@aster.test".to_string(),
            auth_hash_b64: None,
            display_name: None,
            kind: SendIdentityKind::Primary,
            enabled: true,
            sender_id: "primary".to_string(),
        };
        assert_eq!(identity_id("acct", &id), "identity-acct");
    }

    #[test]
    fn non_primary_identity_id_encodes_address_and_is_unique() {
        let alias = SendIdentity {
            address: "sales@example.com".to_string(),
            auth_hash_b64: Some("h".to_string()),
            display_name: None,
            kind: SendIdentityKind::Alias,
            enabled: true,
            sender_id: "alias-1".to_string(),
        };
        let other = SendIdentity {
            address: "support@example.com".to_string(),
            auth_hash_b64: Some("h".to_string()),
            display_name: None,
            kind: SendIdentityKind::CustomDomain,
            enabled: true,
            sender_id: "domain-1".to_string(),
        };
        let a = identity_id("acct", &alias);
        let b = identity_id("acct", &other);
        assert!(a.starts_with("identity-acct-"));
        assert_ne!(a, b);
        assert_ne!(a, "identity-acct");
    }

    #[tokio::test]
    async fn get_lists_one_identity_per_enabled_send_identity() {
        let (ctx, account, _d) = test_ctx("alice@aster.test");
        {
            let mut s = ctx.session.write().await;
            s.send_identities = vec![
                SendIdentity {
                    address: "alice@aster.test".to_string(),
                    auth_hash_b64: None,
                    display_name: None,
                    kind: SendIdentityKind::Primary,
                    enabled: true,
                    sender_id: "primary".to_string(),
                },
                SendIdentity {
                    address: "sales@example.com".to_string(),
                    auth_hash_b64: Some("hash".to_string()),
                    display_name: Some("Sales".to_string()),
                    kind: SendIdentityKind::CustomDomain,
                    enabled: true,
                    sender_id: "domain-2".to_string(),
                },
                SendIdentity {
                    address: "off@example.com".to_string(),
                    auth_hash_b64: Some("hash2".to_string()),
                    display_name: None,
                    kind: SendIdentityKind::Alias,
                    enabled: false,
                    sender_id: "alias-2".to_string(),
                },
            ];
        }
        let res = ok(get(&ctx, json!({})).await);
        let list = res["list"].as_array().unwrap();
        // primary + sales (disabled one filtered out)
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["id"], json!(format!("identity-{}", account)));
        assert_eq!(list[1]["email"], json!("sales@example.com"));
        assert_eq!(list[1]["name"], json!("Sales"));
    }
}
