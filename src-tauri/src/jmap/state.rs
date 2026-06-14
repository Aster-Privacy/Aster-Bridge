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
