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
use crate::crypto::alias;
use crate::error::{BridgeError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendIdentityKind {
    Primary,
    Alias,
    CustomDomain,
}

impl SendIdentityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SendIdentityKind::Primary => "primary",
            SendIdentityKind::Alias => "alias",
            SendIdentityKind::CustomDomain => "custom_domain",
        }
    }
}

// One send-as identity surfaced to mail clients. auth_hash_b64 is the value the
// send path attaches as `sender_alias_hash` (None for the primary address,
// which omits the hash). For aliases this is the HMAC alias_address_hash; for
// custom-domain addresses it is the HMAC local_part_hash. Both mirror the web
// client's `selected_sender.address_hash`.
#[derive(Debug, Clone)]
pub struct SendIdentity {
    pub address: String,
    pub auth_hash_b64: Option<String>,
    pub display_name: Option<String>,
    pub kind: SendIdentityKind,
    pub enabled: bool,
    // Stable id used by the backend default-sender preference: "primary" for the
    // account address, the raw alias uuid for aliases, "domain-<uuid>" for
    // custom-domain addresses. Mirrors use_sender_aliases.ts.
    pub sender_id: String,
}

#[allow(dead_code)]
pub struct Session {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub access_token: Zeroizing<String>,
    pub vault_passphrase: Vec<u8>,
    pub identity_key: Option<String>,
    pub ratchet_keys: Vec<crate::crypto::ratchet::RatchetReceiverKeys>,
    pub send_identities: Vec<SendIdentity>,
}

impl Session {
    // Returns the identity whose address matches `address` (case-insensitive),
    // if any. Primary is included.
    pub fn find_send_identity(&self, address: &str) -> Option<&SendIdentity> {
        self.send_identities
            .iter()
            .find(|i| i.address.eq_ignore_ascii_case(address))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.vault_passphrase.zeroize();
        if let Some(ref mut k) = self.identity_key {
            k.zeroize();
        }
        for keys in self.ratchet_keys.iter_mut() {
            keys.zeroize();
        }
    }
}

// Decrypts the user's aliases and custom-domain addresses and builds the send
// identity cache, mirroring use_sender_aliases.ts. The primary address is always
// the first entry with no auth hash. Failures to list/decrypt are non-fatal:
// they just yield fewer identities (internal mail send via primary keeps working).
pub async fn build_send_identities(
    client: &ApiClient,
    access_token: &str,
    primary_email: &str,
    primary_display_name: Option<String>,
    passphrase: &[u8],
) -> Vec<SendIdentity> {
    let mut identities = vec![SendIdentity {
        address: primary_email.to_string(),
        auth_hash_b64: None,
        display_name: primary_display_name,
        kind: SendIdentityKind::Primary,
        enabled: true,
        sender_id: "primary".to_string(),
    }];

    let mut derived_key = alias::derive_storage_key(passphrase);

    match client.list_all_aliases(access_token).await {
        Ok(aliases) => {
            for a in aliases {
                if !a.is_enabled {
                    continue;
                }
                let local_part = match alias::decrypt_alias_local_part(
                    &derived_key,
                    &a.encrypted_local_part,
                    &a.local_part_nonce,
                    a.is_random,
                ) {
                    Ok(lp) if !lp.is_empty() => lp,
                    _ => continue,
                };
                let display_name = match (&a.encrypted_display_name, &a.display_name_nonce) {
                    (Some(enc), Some(nonce)) => {
                        alias::decrypt_display_name(&derived_key, enc, nonce).ok()
                    }
                    _ => None,
                };
                // Use the server's stored alias_address_hash verbatim - it is the
                // exact value the send-authorization lookup keys on. Recomputing it
                // diverges for aliases whose stored hash predates the current
                // normalization, so the authoritative stored value is what works.
                identities.push(SendIdentity {
                    address: format!("{}@{}", local_part, a.domain),
                    auth_hash_b64: Some(a.alias_address_hash.clone()),
                    display_name,
                    kind: SendIdentityKind::Alias,
                    enabled: true,
                    sender_id: a.id.clone(),
                });
            }
        }
        Err(e) => tracing::warn!("failed to list aliases for send identities: {}", e),
    }

    match client.list_domains(access_token).await {
        Ok(domains) => {
            for domain in domains.domains {
                if domain.status != "active" {
                    continue;
                }
                let addrs = match client.list_domain_addresses(access_token, &domain.id).await {
                    Ok(a) => a.addresses,
                    Err(e) => {
                        tracing::warn!("failed to list domain addresses for {}: {}", domain.domain_name, e);
                        continue;
                    }
                };
                for addr in addrs {
                    if !addr.is_enabled {
                        continue;
                    }
                    let local_part = match alias::decrypt_domain_local_part(
                        &derived_key,
                        &addr.encrypted_local_part,
                        &addr.local_part_nonce,
                    ) {
                        Ok(lp) if !lp.is_empty() => lp,
                        _ => continue,
                    };
                    let display_name = match (&addr.encrypted_display_name, &addr.display_name_nonce)
                    {
                        (Some(enc), Some(nonce)) => {
                            alias::decrypt_display_name(&derived_key, enc, nonce).ok()
                        }
                        _ => None,
                    };
                    identities.push(SendIdentity {
                        address: format!("{}@{}", local_part, domain.domain_name),
                        auth_hash_b64: Some(addr.local_part_hash.clone()),
                        display_name,
                        kind: SendIdentityKind::CustomDomain,
                        enabled: true,
                        sender_id: format!("domain-{}", addr.id),
                    });
                }
            }
        }
        Err(e) => tracing::warn!("failed to list domains for send identities: {}", e),
    }

    derived_key.zeroize();
    identities
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

    let (identity_key, ratchet_keys) = match crate::crypto::vault::decrypt_vault(
        &login_resp.encrypted_vault,
        &login_resp.vault_nonce,
        &passphrase,
    ) {
        Ok(v) => (
            Some(v.identity_key.clone()),
            crate::crypto::ratchet::build_receiver_key_sets(&v),
        ),
        Err(e) => {
            tracing::warn!("vault decrypt failed during restore: {}", e);
            (None, Vec::new())
        }
    };

    let send_identities = build_send_identities(
        client,
        &access_token,
        &login_resp.email,
        None,
        &passphrase,
    )
    .await;

    Ok(Session {
        user_id: login_resp.user_id,
        username: login_resp.username,
        email: login_resp.email,
        access_token,
        vault_passphrase: passphrase,
        identity_key,
        ratchet_keys,
        send_identities,
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

                let (identity_key, ratchet_keys) = match crate::crypto::vault::decrypt_vault(
                    &login_resp.encrypted_vault,
                    &login_resp.vault_nonce,
                    &passphrase,
                ) {
                    Ok(v) => (
                        Some(v.identity_key.clone()),
                        crate::crypto::ratchet::build_receiver_key_sets(&v),
                    ),
                    Err(e) => {
                        tracing::warn!("vault decrypt failed during setup: {}", e);
                        (None, Vec::new())
                    }
                };

                let send_identities = build_send_identities(
                    client,
                    &access_token,
                    &login_resp.email,
                    None,
                    &passphrase,
                )
                .await;

                return Ok(Session {
                    user_id: login_resp.user_id,
                    username: login_resp.username,
                    email: login_resp.email,
                    access_token,
                    vault_passphrase: passphrase,
                    identity_key,
                    ratchet_keys,
                    send_identities,
                });
            }
            "expired" => {
                return Err(BridgeError::Auth("device code expired".to_string()));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session() -> Session {
        Session {
            user_id: Uuid::new_v4(),
            username: "alice".to_string(),
            email: "alice@astermail.org".to_string(),
            access_token: Zeroizing::new("token-abc".to_string()),
            vault_passphrase: b"passphrase-bytes".to_vec(),
            identity_key: Some("identity-key".to_string()),
            ratchet_keys: Vec::new(),
            send_identities: Vec::new(),
        }
    }

    #[test]
    fn session_fields_are_accessible() {
        let s = sample_session();
        assert_eq!(s.username, "alice");
        assert_eq!(s.email, "alice@astermail.org");
        assert_eq!(s.access_token.as_str(), "token-abc");
        assert_eq!(s.vault_passphrase, b"passphrase-bytes");
        assert_eq!(s.identity_key.as_deref(), Some("identity-key"));
    }

    #[test]
    fn dropping_session_does_not_panic() {
        let s = sample_session();
        drop(s);
    }

    #[test]
    fn dropping_session_without_identity_key_does_not_panic() {
        let s = Session {
            user_id: Uuid::new_v4(),
            username: "bob".to_string(),
            email: "bob@astermail.org".to_string(),
            access_token: Zeroizing::new(String::new()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_keys: Vec::new(),
            send_identities: Vec::new(),
        };
        drop(s);
    }
}
