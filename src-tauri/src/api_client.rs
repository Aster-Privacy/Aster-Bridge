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
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{BridgeError, Result};

const USER_AGENT: &str = "AsterBridge/0.2.2";
const API_BASE_URL: &str = "https://app.astermail.org/api";
const ERR_BODY_MAX: usize = 256;

#[allow(dead_code)]
async fn err_body(resp: reqwest::Response) -> String {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let truncated: String = body.chars().take(ERR_BODY_MAX).collect();
    format!("{}: {}", status, truncated)
}

async fn map_response_error(resp: reqwest::Response) -> BridgeError {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status == reqwest::StatusCode::FORBIDDEN {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
            if parsed.get("error").and_then(|v| v.as_str()) == Some("plan_upgrade_required") {
                let msg = parsed
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Aster Bridge requires a Star plan or higher.")
                    .to_string();
                return BridgeError::PlanUpgradeRequired(msg);
            }
        }
    }
    let truncated: String = body.chars().take(ERR_BODY_MAX).collect();
    BridgeError::Api(format!("{}: {}", status, truncated))
}

pub struct ApiClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Deserialize)]
pub struct PqSecretResponse {
    pub key_id: i32,
    pub encrypted_secret: String,
    pub secret_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct BundlePqPrekey {
    pub key_id: u32,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct PrekeyBundle {
    pub kem_identity_key: String,
    pub signed_prekey: String,
    #[serde(default)]
    pub pq_prekey: Option<BundlePqPrekey>,
}

#[derive(Debug, Serialize)]
pub struct CreateMailItem<'a> {
    pub item_type: &'a str,
    pub encrypted_envelope: &'a str,
    pub envelope_nonce: &'a str,
    pub folder_token: &'a str,
    pub content_hash: &'a str,
}

#[derive(Debug, Serialize)]
pub struct DeviceCodeRequest {
    pub ed25519_pk: String,
    pub mlkem_pk: String,
    pub x25519_pk: String,
    pub machine_name: String,
    pub device_type: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceCodeResponse {
    pub code: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct DeviceChallengeRequest {
    pub device_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DeviceChallengeResponse {
    pub challenge_id: Uuid,
    pub nonce: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct DeviceLoginRequest {
    pub challenge_id: Uuid,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DeviceLoginResponse {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub access_token: Option<String>,
    pub encrypted_vault: String,
    pub vault_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceCodeStatusResponse {
    pub status: String,
    pub device_id: Option<Uuid>,
    pub sealed_envelope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UserProfileResponse {
    pub user_id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub profile_color: Option<String>,
    pub profile_picture: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PlanInfoResponse {
    pub plan_code: String,
    pub has_bridge_access: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MailListResponse {
    pub items: Vec<MailItem>,
    pub total: i64,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct MailItem {
    pub id: String,
    pub item_type: String,
    pub encrypted_envelope: String,
    pub envelope_nonce: String,
    pub ephemeral_key: Option<String>,
    pub ephemeral_pq_key: Option<String>,
    pub sender_sealed: Option<String>,
    pub folder_token: String,
    pub is_external: bool,
    pub thread_token: Option<String>,
    pub thread_message_count: Option<i16>,
    pub created_at: String,
    pub encrypted_metadata: Option<String>,
    pub metadata_nonce: Option<String>,
    pub metadata_version: Option<i16>,
    pub scheduled_at: Option<String>,
    pub send_status: Option<String>,
    pub message_ts: Option<String>,
    pub snoozed_until: Option<String>,
    pub expires_at: Option<String>,
    pub expiry_type: Option<String>,
    pub is_spam: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct MailListQuery {
    pub item_type: Option<String>,
    pub is_trashed: Option<bool>,
    pub is_archived: Option<bool>,
    pub is_spam: Option<bool>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[allow(dead_code)]
impl ApiClient {
    pub fn new() -> Self {
        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert("x-aster-client", reqwest::header::HeaderValue::from_static("aster-bridge"));
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(default_headers)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(std::time::Duration::from_secs(20))
            .tcp_keepalive(std::time::Duration::from_secs(20))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            base_url: API_BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    pub fn new_with_base_url(base_url: &str) -> Self {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            base_url: base_url.to_string(),
        }
    }

    pub async fn generate_device_code(&self, req: &DeviceCodeRequest) -> Result<DeviceCodeResponse> {
        let resp = self.client
            .post(format!("{}/core/v1/auth/device/code", self.base_url))
            .json(req)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn poll_device_code_status(&self, code: &str) -> Result<DeviceCodeStatusResponse> {
        let resp = self.client
            .get(format!("{}/core/v1/auth/device/code/status", self.base_url))
            .query(&[("code", code)])
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn device_challenge(&self, device_id: Uuid) -> Result<DeviceChallengeResponse> {
        let resp = self.client
            .post(format!("{}/core/v1/auth/device/challenge", self.base_url))
            .json(&DeviceChallengeRequest { device_id })
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn device_login(&self, req: &DeviceLoginRequest) -> Result<DeviceLoginResponse> {
        let resp = self.client
            .post(format!("{}/core/v1/auth/device/login", self.base_url))
            .json(req)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn get_user_profile(&self, access_token: &str) -> Result<UserProfileResponse> {
        let resp = self.client
            .get(format!("{}/core/v1/auth/me", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn get_plan_info(&self, access_token: &str) -> Result<PlanInfoResponse> {
        let resp = self.client
            .get(format!("{}/core/v1/billing/plan", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn get_prekey_bundle(
        &self,
        access_token: &str,
        username: &str,
        email: &str,
    ) -> Result<PrekeyBundle> {
        let resp = self.client
            .get(format!("{}/crypto/v1/ratchet/prekey-bundle/{}", self.base_url, username))
            .query(&[("email", email)])
            .bearer_auth(access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn delete_mail_item_permanent(&self, access_token: &str, item_id: &str) -> Result<()> {
        let resp = self.client
            .delete(format!("{}/mail/v1/messages/{}", self.base_url, item_id))
            .bearer_auth(access_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }
        Ok(())
    }

    pub async fn create_mail_item(
        &self,
        access_token: &str,
        req: &CreateMailItem<'_>,
    ) -> Result<serde_json::Value> {
        let resp = self.client
            .post(format!("{}/mail/v1/messages", self.base_url))
            .bearer_auth(access_token)
            .json(req)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn get_pq_secret(&self, access_token: &str, key_id: u32) -> Result<PqSecretResponse> {
        let resp = self.client
            .get(format!("{}/crypto/v1/ratchet/pq-secret/{}", self.base_url, key_id))
            .bearer_auth(access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn list_mail(
        &self,
        access_token: &str,
        query: &MailListQuery,
    ) -> Result<MailListResponse> {
        let mut params: Vec<(&str, String)> = Vec::new();

        if let Some(ref item_type) = query.item_type {
            params.push(("item_type", item_type.clone()));
        }
        if let Some(is_trashed) = query.is_trashed {
            params.push(("is_trashed", is_trashed.to_string()));
        }
        if let Some(is_archived) = query.is_archived {
            params.push(("is_archived", is_archived.to_string()));
        }
        if let Some(is_spam) = query.is_spam {
            params.push(("is_spam", is_spam.to_string()));
        }
        if let Some(limit) = query.limit {
            params.push(("limit", limit.to_string()));
        }
        if let Some(ref cursor) = query.cursor {
            params.push(("cursor", cursor.clone()));
        }
        params.push(("group_by_thread", "false".to_string()));

        let resp = self.client
            .get(format!("{}/bridge/v1/messages", self.base_url))
            .bearer_auth(access_token)
            .query(&params)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn fetch_mail_item(&self, access_token: &str, item_id: &str) -> Result<MailItem> {
        let resp = self.client
            .get(format!("{}/bridge/v1/messages/{}", self.base_url, item_id))
            .bearer_auth(access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }

    pub async fn update_metadata(
        &self,
        access_token: &str,
        item_id: &str,
        encrypted_metadata: &str,
        metadata_nonce: &str,
    ) -> Result<()> {
        let resp = self.client
            .patch(format!("{}/bridge/v1/messages/{}/metadata", self.base_url, item_id))
            .bearer_auth(access_token)
            .json(&serde_json::json!({
                "encrypted_metadata": encrypted_metadata,
                "metadata_nonce": metadata_nonce
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        Ok(())
    }

    pub async fn set_read_status(
        &self,
        access_token: &str,
        item_id: &str,
        is_read: bool,
    ) -> Result<()> {
        let resp = self.client
            .patch(format!("{}/bridge/v1/messages/{}/metadata", self.base_url, item_id))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "is_read": is_read }))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        Ok(())
    }

    pub async fn set_mailbox_flags(
        &self,
        access_token: &str,
        item_id: &str,
        flags: serde_json::Value,
    ) -> Result<()> {
        let resp = self.client
            .patch(format!("{}/bridge/v1/messages/{}/metadata", self.base_url, item_id))
            .bearer_auth(access_token)
            .json(&flags)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        Ok(())
    }

    pub async fn send_mail(
        &self,
        access_token: &str,
        body: &serde_json::Value,
    ) -> Result<()> {
        let resp = self.client
            .post(format!("{}/bridge/v1/send", self.base_url))
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        Ok(())
    }

    pub async fn get_mail_stats(&self, access_token: &str) -> Result<serde_json::Value> {
        let resp = self.client
            .get(format!("{}/bridge/v1/messages/stats", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(map_response_error(resp).await);
        }

        resp.json().await.map_err(BridgeError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path as AxumPath;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::{routing::get, routing::patch, routing::post, Json, Router};
    use std::sync::Arc;
    use tokio::sync::Mutex as TokioMutex;

    async fn spawn(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn sample_item_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "item_type": "received",
            "encrypted_envelope": "ZW52",
            "envelope_nonce": "",
            "folder_token": "tok",
            "is_external": false,
            "created_at": "2026-06-14T00:00:00Z"
        })
    }

    #[tokio::test]
    async fn list_mail_parses_200_json_list() {
        let body = serde_json::json!({
            "items": [sample_item_json("msg-a"), sample_item_json("msg-b")],
            "total": 2,
            "has_more": false,
            "next_cursor": serde_json::Value::Null
        });
        let app = Router::new().route(
            "/bridge/v1/messages",
            get(move || {
                let body = body.clone();
                async move { Json(body) }
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let q = MailListQuery {
            item_type: Some("received".to_string()),
            is_trashed: None,
            is_archived: None,
            is_spam: None,
            limit: Some(100),
            cursor: None,
        };
        let resp = client.list_mail("tok", &q).await.unwrap();
        assert_eq!(resp.total, 2);
        assert!(!resp.has_more);
        assert_eq!(resp.items.len(), 2);
        assert_eq!(resp.items[0].id, "msg-a");
        assert_eq!(resp.items[1].id, "msg-b");
    }

    #[tokio::test]
    async fn list_mail_forwards_query_params() {
        let seen: Arc<TokioMutex<Vec<(String, String)>>> = Arc::new(TokioMutex::new(Vec::new()));
        let cap = seen.clone();
        let app = Router::new().route(
            "/bridge/v1/messages",
            get(move |axum::extract::RawQuery(raw): axum::extract::RawQuery| {
                let cap = cap.clone();
                async move {
                    let raw = raw.unwrap_or_default();
                    let mut pairs = Vec::new();
                    for kv in raw.split('&') {
                        if let Some((k, v)) = kv.split_once('=') {
                            pairs.push((k.to_string(), v.to_string()));
                        }
                    }
                    *cap.lock().await = pairs;
                    Json(serde_json::json!({
                        "items": [],
                        "total": 0,
                        "has_more": false,
                        "next_cursor": null
                    }))
                }
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let q = MailListQuery {
            item_type: None,
            is_trashed: Some(true),
            is_archived: None,
            is_spam: None,
            limit: Some(50),
            cursor: Some("cur1".to_string()),
        };
        let _ = client.list_mail("tok", &q).await.unwrap();
        let pairs = seen.lock().await.clone();
        assert!(pairs.iter().any(|(k, v)| k == "is_trashed" && v == "true"));
        assert!(pairs.iter().any(|(k, v)| k == "limit" && v == "50"));
        assert!(pairs.iter().any(|(k, v)| k == "cursor" && v == "cur1"));
        assert!(pairs.iter().any(|(k, v)| k == "group_by_thread" && v == "false"));
        assert!(!pairs.iter().any(|(k, _)| k == "item_type"));
    }

    #[tokio::test]
    async fn list_mail_sends_bearer_token() {
        let seen: Arc<TokioMutex<Option<String>>> = Arc::new(TokioMutex::new(None));
        let cap = seen.clone();
        let app = Router::new().route(
            "/bridge/v1/messages",
            get(move |headers: axum::http::HeaderMap| {
                let cap = cap.clone();
                async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    *cap.lock().await = auth;
                    Json(serde_json::json!({
                        "items": [],
                        "total": 0,
                        "has_more": false,
                        "next_cursor": null
                    }))
                }
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let q = MailListQuery {
            item_type: None,
            is_trashed: None,
            is_archived: None,
            is_spam: None,
            limit: None,
            cursor: None,
        };
        let _ = client.list_mail("secret-token", &q).await.unwrap();
        let auth = seen.lock().await.clone();
        assert_eq!(auth.as_deref(), Some("Bearer secret-token"));
    }

    #[tokio::test]
    async fn fetch_mail_item_parses_single_item() {
        let app = Router::new().route(
            "/bridge/v1/messages/:id",
            get(|AxumPath(id): AxumPath<String>| async move { Json(sample_item_json(&id)) }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let item = client.fetch_mail_item("tok", "msg-xyz").await.unwrap();
        assert_eq!(item.id, "msg-xyz");
        assert_eq!(item.item_type, "received");
    }

    #[tokio::test]
    async fn unauthorized_maps_to_api_error() {
        let app = Router::new().route(
            "/bridge/v1/messages/:id",
            get(|| async { (StatusCode::UNAUTHORIZED, "no token").into_response() }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let err = client.fetch_mail_item("tok", "msg-1").await.unwrap_err();
        match err {
            BridgeError::Api(msg) => assert!(msg.contains("401")),
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn forbidden_plain_maps_to_api_error() {
        let app = Router::new().route(
            "/bridge/v1/messages/:id",
            get(|| async { (StatusCode::FORBIDDEN, "denied").into_response() }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let err = client.fetch_mail_item("tok", "msg-1").await.unwrap_err();
        match err {
            BridgeError::Api(msg) => assert!(msg.contains("403")),
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn forbidden_plan_upgrade_maps_to_plan_upgrade_required() {
        let app = Router::new().route(
            "/core/v1/billing/plan",
            get(|| async {
                (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "plan_upgrade_required",
                        "message": "Star plan needed"
                    })),
                )
                    .into_response()
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let err = client.get_plan_info("tok").await.unwrap_err();
        match err {
            BridgeError::PlanUpgradeRequired(msg) => assert_eq!(msg, "Star plan needed"),
            other => panic!("expected PlanUpgradeRequired, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn server_error_maps_to_api_error() {
        let app = Router::new().route(
            "/bridge/v1/messages/:id",
            get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response() }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let err = client.fetch_mail_item("tok", "msg-1").await.unwrap_err();
        match err {
            BridgeError::Api(msg) => assert!(msg.contains("500")),
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn update_metadata_patch_body_has_expected_fields() {
        let seen: Arc<TokioMutex<Option<serde_json::Value>>> = Arc::new(TokioMutex::new(None));
        let cap = seen.clone();
        let app = Router::new().route(
            "/bridge/v1/messages/:id/metadata",
            patch(move |Json(body): Json<serde_json::Value>| {
                let cap = cap.clone();
                async move {
                    *cap.lock().await = Some(body);
                    Json(serde_json::json!({"success": true}))
                }
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        client
            .update_metadata("tok", "msg-1", "ENC", "NON")
            .await
            .unwrap();
        let body = seen.lock().await.clone().unwrap();
        assert_eq!(body["encrypted_metadata"], "ENC");
        assert_eq!(body["metadata_nonce"], "NON");
    }

    #[tokio::test]
    async fn set_read_status_patch_body_has_is_read() {
        let seen: Arc<TokioMutex<Option<serde_json::Value>>> = Arc::new(TokioMutex::new(None));
        let cap = seen.clone();
        let app = Router::new().route(
            "/bridge/v1/messages/:id/metadata",
            patch(move |Json(body): Json<serde_json::Value>| {
                let cap = cap.clone();
                async move {
                    *cap.lock().await = Some(body);
                    Json(serde_json::json!({"success": true}))
                }
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        client.set_read_status("tok", "msg-1", true).await.unwrap();
        let body = seen.lock().await.clone().unwrap();
        assert_eq!(body["is_read"], true);
    }

    #[tokio::test]
    async fn set_mailbox_flags_forwards_raw_flags() {
        let seen: Arc<TokioMutex<Option<serde_json::Value>>> = Arc::new(TokioMutex::new(None));
        let cap = seen.clone();
        let app = Router::new().route(
            "/bridge/v1/messages/:id/metadata",
            patch(move |Json(body): Json<serde_json::Value>| {
                let cap = cap.clone();
                async move {
                    *cap.lock().await = Some(body);
                    Json(serde_json::json!({"success": true}))
                }
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let flags = serde_json::json!({"is_archived": true, "is_trashed": false});
        client.set_mailbox_flags("tok", "msg-1", flags).await.unwrap();
        let body = seen.lock().await.clone().unwrap();
        assert_eq!(body["is_archived"], true);
        assert_eq!(body["is_trashed"], false);
    }

    #[tokio::test]
    async fn send_mail_posts_body_and_returns_ok() {
        let seen: Arc<TokioMutex<Vec<serde_json::Value>>> = Arc::new(TokioMutex::new(Vec::new()));
        let cap = seen.clone();
        let app = Router::new().route(
            "/bridge/v1/send",
            post(move |Json(body): Json<serde_json::Value>| {
                let cap = cap.clone();
                async move {
                    cap.lock().await.push(body);
                    Json(serde_json::json!({"success": true}))
                }
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let payload = serde_json::json!({"subject": "hi", "body": "there"});
        client.send_mail("tok", &payload).await.unwrap();
        let captured = seen.lock().await.clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0]["subject"], "hi");
        assert_eq!(captured[0]["body"], "there");
    }

    #[tokio::test]
    async fn send_mail_non_2xx_maps_to_api_error() {
        let app = Router::new().route(
            "/bridge/v1/send",
            post(|| async { (StatusCode::BAD_REQUEST, "bad").into_response() }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let err = client
            .send_mail("tok", &serde_json::json!({}))
            .await
            .unwrap_err();
        match err {
            BridgeError::Api(msg) => assert!(msg.contains("400")),
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn get_plan_info_parses_bridge_access() {
        let app = Router::new().route(
            "/core/v1/billing/plan",
            get(|| async {
                Json(serde_json::json!({"plan_code": "star", "has_bridge_access": true}))
            }),
        );
        let base = spawn(app).await;
        let client = ApiClient::new_with_base_url(&base);
        let info = client.get_plan_info("tok").await.unwrap();
        assert_eq!(info.plan_code, "star");
        assert!(info.has_bridge_access);
    }

    #[test]
    fn mail_item_deserializes_with_optional_fields_absent() {
        let item: MailItem = serde_json::from_value(sample_item_json("only-required")).unwrap();
        assert_eq!(item.id, "only-required");
        assert!(item.ephemeral_key.is_none());
        assert!(item.thread_token.is_none());
        assert!(item.is_spam.is_none());
    }
}
