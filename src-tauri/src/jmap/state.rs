//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::auth::session::Session;
use crate::db::Database;

#[derive(Debug, Clone)]
pub struct StateChange {
    pub changed: HashMap<String, String>,
}

pub struct JmapContext {
    pub session: Arc<RwLock<Session>>,
    pub db: Arc<Database>,
    pub client: Arc<crate::api_client::ApiClient>,
    pub broadcaster: broadcast::Sender<StateChange>,
}

impl JmapContext {
    pub fn new(
        session: Arc<RwLock<Session>>,
        db: Arc<Database>,
        client: Arc<crate::api_client::ApiClient>,
        broadcaster: broadcast::Sender<StateChange>,
    ) -> Arc<Self> {
        Arc::new(Self {
            session,
            db,
            client,
            broadcaster,
        })
    }

    pub async fn account_id(&self) -> String {
        self.session.read().await.user_id.to_string()
    }

    pub async fn email(&self) -> String {
        self.session.read().await.email.clone()
    }

    pub async fn require_account(
        &self,
        args: &serde_json::Value,
    ) -> Result<String, crate::jmap::dispatcher::MethodError> {
        let actual = self.account_id().await;
        if let Some(supplied) = args.get("accountId").and_then(|v| v.as_str()) {
            if supplied != actual {
                return Err(crate::jmap::dispatcher::MethodError::new(
                    "accountNotFound",
                    format!("unknown accountId: {}", supplied),
                ));
            }
        }
        Ok(actual)
    }
}

pub fn broadcaster() -> broadcast::Sender<StateChange> {
    let (tx, _rx) = broadcast::channel(64);
    tx
}

pub fn snapshot_all_states(db: &Database) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for ty in &["Email", "Mailbox", "Thread", "EmailSubmission", "Identity"] {
        let s = db.jmap_state_get(ty).unwrap_or(0);
        out.insert((*ty).to_string(), s.to_string());
    }
    out
}

pub fn compose_session_state(states: &HashMap<String, String>) -> String {
    let get = |k: &str| states.get(k).map(|s| s.as_str()).unwrap_or("0");
    format!("{}-{}-{}", get("Email"), get("Mailbox"), get("Thread"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;
    use uuid::Uuid;

    fn test_db() -> (Arc<Database>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[2u8; 32]).unwrap());
        (db, dir)
    }

    fn ctx_with_account(account: Uuid, email: &str) -> (Arc<JmapContext>, tempfile::TempDir) {
        let (db, dir) = test_db();
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
        (JmapContext::new(session, db, client, tx), dir)
    }

    #[test]
    fn compose_session_state_default_zeros() {
        let states = HashMap::new();
        assert_eq!(compose_session_state(&states), "0-0-0");
    }

    #[test]
    fn compose_session_state_uses_email_mailbox_thread() {
        let mut states = HashMap::new();
        states.insert("Email".to_string(), "3".to_string());
        states.insert("Mailbox".to_string(), "1".to_string());
        states.insert("Thread".to_string(), "7".to_string());
        states.insert("Identity".to_string(), "9".to_string());
        assert_eq!(compose_session_state(&states), "3-1-7");
    }

    #[test]
    fn snapshot_all_states_covers_all_types_default_zero() {
        let (db, _dir) = test_db();
        let snap = snapshot_all_states(&db);
        for ty in ["Email", "Mailbox", "Thread", "EmailSubmission", "Identity"] {
            assert_eq!(snap.get(ty).map(|s| s.as_str()), Some("0"));
        }
    }

    #[test]
    fn snapshot_all_states_reflects_bumps() {
        let (db, _dir) = test_db();
        db.jmap_state_bump("Email").unwrap();
        db.jmap_state_bump("Email").unwrap();
        let snap = snapshot_all_states(&db);
        assert_eq!(snap.get("Email").map(|s| s.as_str()), Some("2"));
    }

    #[test]
    fn session_state_monotonic_after_bump() {
        let (db, _dir) = test_db();
        let before = compose_session_state(&snapshot_all_states(&db));
        db.jmap_state_bump("Mailbox").unwrap();
        let after = compose_session_state(&snapshot_all_states(&db));
        assert_ne!(before, after);
        assert_eq!(before, "0-0-0");
        assert_eq!(after, "0-1-0");
    }

    #[test]
    fn broadcaster_channel_is_usable() {
        let tx = broadcaster();
        let mut rx = tx.subscribe();
        let mut changed = HashMap::new();
        changed.insert("Email".to_string(), "1".to_string());
        tx.send(StateChange { changed }).unwrap();
        let got = rx.try_recv().unwrap();
        assert_eq!(got.changed.get("Email").map(|s| s.as_str()), Some("1"));
    }

    #[tokio::test]
    async fn account_id_and_email_from_session() {
        let account = Uuid::new_v4();
        let (ctx, _dir) = ctx_with_account(account, "user@aster.test");
        assert_eq!(ctx.account_id().await, account.to_string());
        assert_eq!(ctx.email().await, "user@aster.test");
    }

    #[tokio::test]
    async fn require_account_accepts_matching_or_absent() {
        let account = Uuid::new_v4();
        let (ctx, _dir) = ctx_with_account(account, "user@aster.test");
        assert!(ctx.require_account(&serde_json::json!({})).await.is_ok());
        let matching = serde_json::json!({"accountId": account.to_string()});
        assert_eq!(ctx.require_account(&matching).await.ok(), Some(account.to_string()));
    }

    #[tokio::test]
    async fn require_account_rejects_mismatch() {
        let account = Uuid::new_v4();
        let (ctx, _dir) = ctx_with_account(account, "user@aster.test");
        let bad = serde_json::json!({"accountId": "different"});
        let err = ctx.require_account(&bad).await;
        assert!(err.is_err());
        assert_eq!(err.err().unwrap().kind, "accountNotFound");
    }
}
