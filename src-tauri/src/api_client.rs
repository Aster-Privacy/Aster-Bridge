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
