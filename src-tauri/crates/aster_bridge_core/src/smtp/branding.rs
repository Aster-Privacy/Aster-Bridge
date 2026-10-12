//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{json, Value};
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api_client::ApiClient;
use crate::auth::session::Session;
use crate::crypto::preferences::decrypt_preferences_with_account_keys;

const BRANDING_SHOWN_BY_DEFAULT: bool = true;

fn last_known_choices() -> &'static Mutex<HashMap<Uuid, bool>> {
    static CHOICES: OnceLock<Mutex<HashMap<Uuid, bool>>> = OnceLock::new();
    CHOICES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_choice(user_id: Uuid, shows_branding: bool) {
    if let Ok(mut choices) = last_known_choices().lock() {
        choices.insert(user_id, shows_branding);
    }
}

fn recall_choice(user_id: Uuid) -> Option<bool> {
    last_known_choices()
        .lock()
        .ok()
        .and_then(|choices| choices.get(&user_id).copied())
}

async fn read_branding_choice(
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    access_token: &str,
) -> Option<bool> {
    let (identity_key, account_keys) = {
        let s = session.read().await;
        (
            Zeroizing::new(s.identity_key.clone()?),
            s.account_keys.clone(),
        )
    };
    let response = match client.get_preferences(access_token).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!("could not read the watermark setting: {}", e);
            return None;
        }
    };
    let (Some(encrypted), Some(nonce)) =
        (response.encrypted_preferences, response.preferences_nonce)
    else {
        return Some(BRANDING_SHOWN_BY_DEFAULT);
    };
    match decrypt_preferences_with_account_keys(&identity_key, &account_keys, &encrypted, &nonce) {
        Ok(preferences) => Some(
            preferences
                .show_aster_branding
                .unwrap_or(BRANDING_SHOWN_BY_DEFAULT),
        ),
        Err(e) => {
            tracing::warn!("could not decrypt the watermark setting: {}", e);
            None
        }
    }
}

pub async fn apply_branding_preference(
    payload: &mut Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    access_token: &str,
) {
    let user_id = session.read().await.user_id;
    let shows_branding = match read_branding_choice(session, client, access_token).await {
        Some(choice) => {
            remember_choice(user_id, choice);
            choice
        }
        None => recall_choice(user_id).unwrap_or(BRANDING_SHOWN_BY_DEFAULT),
    };
    if !shows_branding {
        payload["suppress_branding"] = json!(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, Ordering};

    const IDENTITY_KEY: &str = "identity-key";
    const WATERMARK_OFF: &str = r#"{"show_aster_branding":false}"#;
    const WATERMARK_ON: &str = r#"{"show_aster_branding":true}"#;

    fn seal_preferences(identity_key: &str, plaintext: &str) -> Value {
        let mut hasher = Sha256::new();
        hasher.update(identity_key.as_bytes());
        hasher.update(b"astermail-preferences-v1");
        let key = hasher.finalize();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [9u8; 12];
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .unwrap();
        json!({
            "encrypted_preferences": STANDARD.encode(sealed),
            "preferences_nonce": STANDARD.encode(nonce),
        })
    }

    fn session_with(identity_key: Option<&str>) -> Arc<RwLock<Session>> {
        Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: identity_key.map(|k| k.to_string()),
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }))
    }

    async fn client_for(app: Router) -> ApiClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        ApiClient::new_with_base_url(&format!("http://127.0.0.1:{}", port))
    }

    async fn serve_preferences(body: Value) -> ApiClient {
        let app = Router::new().route(
            "/settings/v1/preferences",
            get(move || {
                let body = body.clone();
                async move { Json(body) }
            }),
        );
        client_for(app).await
    }

    fn outgoing() -> Value {
        json!({ "to": ["someone@example.test"], "client_source": "bridge" })
    }

    #[tokio::test]
    async fn a_turned_off_watermark_suppresses_the_footer() {
        let client = serve_preferences(seal_preferences(IDENTITY_KEY, WATERMARK_OFF)).await;
        let session = session_with(Some(IDENTITY_KEY));
        let mut payload = outgoing();
        apply_branding_preference(&mut payload, &session, &client, "tok").await;
        assert_eq!(payload["suppress_branding"], true);
    }

    #[tokio::test]
    async fn a_turned_on_watermark_keeps_the_footer() {
        let client = serve_preferences(seal_preferences(IDENTITY_KEY, WATERMARK_ON)).await;
        let session = session_with(Some(IDENTITY_KEY));
        let mut payload = outgoing();
        apply_branding_preference(&mut payload, &session, &client, "tok").await;
        assert!(payload.get("suppress_branding").is_none());
    }

    #[tokio::test]
    async fn an_unset_watermark_keeps_the_footer() {
        let client =
            serve_preferences(seal_preferences(IDENTITY_KEY, r#"{"theme":"dark"}"#)).await;
        let session = session_with(Some(IDENTITY_KEY));
        let mut payload = outgoing();
        apply_branding_preference(&mut payload, &session, &client, "tok").await;
        assert!(payload.get("suppress_branding").is_none());

        let client = serve_preferences(
            json!({ "encrypted_preferences": null, "preferences_nonce": null }),
        )
        .await;
        let mut payload = outgoing();
        apply_branding_preference(&mut payload, &session, &client, "tok").await;
        assert!(payload.get("suppress_branding").is_none());
    }

    #[tokio::test]
    async fn the_setting_is_read_again_for_every_message() {
        let turned_off = Arc::new(AtomicBool::new(true));
        let flag = turned_off.clone();
        let app = Router::new().route(
            "/settings/v1/preferences",
            get(move || {
                let flag = flag.clone();
                async move {
                    let plaintext = if flag.load(Ordering::SeqCst) {
                        WATERMARK_OFF
                    } else {
                        WATERMARK_ON
                    };
                    Json(seal_preferences(IDENTITY_KEY, plaintext))
                }
            }),
        );
        let client = client_for(app).await;
        let session = session_with(Some(IDENTITY_KEY));

        let mut first = outgoing();
        apply_branding_preference(&mut first, &session, &client, "tok").await;
        assert_eq!(first["suppress_branding"], true);

        turned_off.store(false, Ordering::SeqCst);
        let mut second = outgoing();
        apply_branding_preference(&mut second, &session, &client, "tok").await;
        assert!(second.get("suppress_branding").is_none());
    }

    #[tokio::test]
    async fn a_failed_read_keeps_the_last_known_choice() {
        let failing = Arc::new(AtomicBool::new(false));
        let flag = failing.clone();
        let app = Router::new().route(
            "/settings/v1/preferences",
            get(move || {
                let flag = flag.clone();
                async move {
                    if flag.load(Ordering::SeqCst) {
                        (StatusCode::SERVICE_UNAVAILABLE, "down").into_response()
                    } else {
                        Json(seal_preferences(IDENTITY_KEY, WATERMARK_OFF)).into_response()
                    }
                }
            }),
        );
        let client = client_for(app).await;
        let session = session_with(Some(IDENTITY_KEY));

        let mut first = outgoing();
        apply_branding_preference(&mut first, &session, &client, "tok").await;
        assert_eq!(first["suppress_branding"], true);

        failing.store(true, Ordering::SeqCst);
        let mut second = outgoing();
        apply_branding_preference(&mut second, &session, &client, "tok").await;
        assert_eq!(second["suppress_branding"], true);
    }

    #[tokio::test]
    async fn an_unreadable_setting_with_no_history_keeps_the_footer() {
        let client = serve_preferences(seal_preferences("another-key", WATERMARK_OFF)).await;
        let session = session_with(Some(IDENTITY_KEY));
        let mut payload = outgoing();
        apply_branding_preference(&mut payload, &session, &client, "tok").await;
        assert!(payload.get("suppress_branding").is_none());

        let keyless = session_with(None);
        let mut payload = outgoing();
        apply_branding_preference(&mut payload, &keyless, &client, "tok").await;
        assert!(payload.get("suppress_branding").is_none());
    }
}
