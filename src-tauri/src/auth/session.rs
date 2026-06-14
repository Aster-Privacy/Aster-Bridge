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
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::api_client::ApiClient;
use crate::auth::device_identity::{self, DeviceIdentity};
use crate::config::BridgeConfig;
use crate::error::{BridgeError, Result};

#[allow(dead_code)]
pub struct Session {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub access_token: Zeroizing<String>,
    pub vault_passphrase: Vec<u8>,
    pub identity_key: Option<String>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.vault_passphrase.zeroize();
        if let Some(ref mut k) = self.identity_key {
            k.zeroize();
        }
    }
}

pub async fn restore_or_login(
    config: &BridgeConfig,
    identity: &DeviceIdentity,
    client: &ApiClient,
) -> Result<Session> {
    let device_id = identity
        .device_id
        .ok_or_else(|| BridgeError::Auth("no device_id stored - first-time setup required".to_string()))?;

    let passphrase = device_identity::load_passphrase(&config.data_dir)
        .map_err(|e| BridgeError::Auth(e))?
        .ok_or_else(|| BridgeError::Auth("no stored passphrase - first-time setup required".to_string()))?;

    let challenge = client.device_challenge(device_id).await?;

    let signature = device_identity::sign_challenge(identity, &challenge.nonce)
        .map_err(|e| BridgeError::Crypto(e))?;

    let login_resp = client
        .device_login(&crate::api_client::DeviceLoginRequest {
            challenge_id: challenge.challenge_id,
            signature,
        })
        .await?;

    let access_token = Zeroizing::new(login_resp
        .access_token
        .ok_or_else(|| BridgeError::Auth("no access token in login response".to_string()))?);

    let identity_key = match crate::crypto::vault::decrypt_vault(
        &login_resp.encrypted_vault,
        &login_resp.vault_nonce,
        &passphrase,
    ) {
        Ok(v) => Some(v.identity_key.clone()),
        Err(e) => {
            tracing::warn!("vault decrypt failed during restore: {}", e);
            None
        }
    };

    Ok(Session {
        user_id: login_resp.user_id,
        username: login_resp.username,
        email: login_resp.email,
        access_token,
        vault_passphrase: passphrase,
        identity_key,
    })
}

pub async fn refresh_access_token(
    session: &std::sync::Arc<tokio::sync::RwLock<Session>>,
    device_id: uuid::Uuid,
    signing_key: &ed25519_dalek::SigningKey,
    client: &ApiClient,
) -> Result<()> {
    let challenge = client.device_challenge(device_id).await?;
    let signature = device_identity::sign_with_key(signing_key, &challenge.nonce)
        .map_err(|e| BridgeError::Crypto(e))?;
    let login_resp = client
        .device_login(&crate::api_client::DeviceLoginRequest {
            challenge_id: challenge.challenge_id,
            signature,
        })
        .await?;
    let access_token = Zeroizing::new(login_resp
        .access_token
        .ok_or_else(|| BridgeError::Auth("no access token".to_string()))?);
    let mut s = session.write().await;
    s.access_token = access_token;
    Ok(())
}

pub async fn first_time_setup(
    config: &BridgeConfig,
    identity: &DeviceIdentity,
    client: &ApiClient,
) -> Result<Session> {
    let (ed25519_pk, mlkem_pk, x25519_pk) = device_identity::get_pubkeys(identity);
    let machine_name = whoami::devicename();

    let code_resp = client
        .generate_device_code(&crate::api_client::DeviceCodeRequest {
            ed25519_pk,
            mlkem_pk,
            x25519_pk,
            machine_name,
            device_type: "bridge".to_string(),
        })
        .await?;

    println!("\n========================================");
    println!("   Aster Bridge - Device Setup");
    println!("========================================\n");
    println!("   Enter this code in Aster Mail:");
    println!("   Settings > Devices > Add Device\n");
    println!("   Code: {}\n", code_resp.code);
    println!("   Expires in {} seconds", code_resp.expires_in);
    println!("========================================\n");

    let code_normalized = code_resp.code.replace('-', "");
    let mut attempts = 0u32;
    let max_attempts = code_resp.expires_in / 3;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        attempts += 1;

        if attempts > max_attempts as u32 {
            return Err(BridgeError::Auth("device code expired".to_string()));
        }

        let status = client.poll_device_code_status(&code_normalized).await?;

        match status.status.as_str() {
            "confirmed" => {
                let device_id = status
                    .device_id
                    .ok_or_else(|| BridgeError::Auth("no device_id in confirmation".to_string()))?;

                let sealed_envelope = status
                    .sealed_envelope
                    .ok_or_else(|| BridgeError::Auth("no sealed envelope".to_string()))?;

                let passphrase = device_identity::unseal_vault_envelope(identity, &sealed_envelope)
                    .map_err(|e| BridgeError::Crypto(e))?;

                device_identity::set_device_id(&config.data_dir, device_id)
                    .map_err(|e| BridgeError::Auth(e))?;

                device_identity::store_passphrase(&config.data_dir, &passphrase)
                    .map_err(|e| BridgeError::Auth(e))?;

                tracing::info!("Device enrolled successfully!");

                let challenge = client.device_challenge(device_id).await?;
                let signature = device_identity::sign_challenge(identity, &challenge.nonce)
                    .map_err(|e| BridgeError::Crypto(e))?;

                let login_resp = client
                    .device_login(&crate::api_client::DeviceLoginRequest {
                        challenge_id: challenge.challenge_id,
                        signature,
                    })
                    .await?;

                let access_token = Zeroizing::new(login_resp
                    .access_token
                    .ok_or_else(|| BridgeError::Auth("no access token".to_string()))?);

                let identity_key = match crate::crypto::vault::decrypt_vault(
                    &login_resp.encrypted_vault,
                    &login_resp.vault_nonce,
                    &passphrase,
                ) {
                    Ok(v) => Some(v.identity_key.clone()),
                    Err(e) => {
                        tracing::warn!("vault decrypt failed during setup: {}", e);
                        None
                    }
                };

                return Ok(Session {
                    user_id: login_resp.user_id,
                    username: login_resp.username,
                    email: login_resp.email,
                    access_token,
                    vault_passphrase: passphrase,
                    identity_key,
                });
            }
            "expired" => {
                return Err(BridgeError::Auth("device code expired".to_string()));
            }
            _ => {}
        }
    }
}
