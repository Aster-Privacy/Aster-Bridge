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
    pub data_kek: Option<Zeroizing<String>>,
    pub ratchet_identity_public: Option<String>,
    pub ratchet_keys: Vec<crate::crypto::ratchet::RatchetReceiverKeys>,
    pub inbound_keys: Vec<crate::crypto::inbound::InboundKeyCandidate>,
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
        for keys in self.inbound_keys.iter_mut() {
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

pub struct VaultKeyMaterial {
    pub identity_key: String,
    pub data_kek: Option<Zeroizing<String>>,
    pub ratchet_identity_public: Option<String>,
    pub ratchet_keys: Vec<crate::crypto::ratchet::RatchetReceiverKeys>,
    pub inbound_keys: Vec<crate::crypto::inbound::InboundKeyCandidate>,
}

pub fn decrypt_vault_key_material(
    encrypted_vault: &str,
    vault_nonce: &str,
    passphrase: &[u8],
) -> Result<VaultKeyMaterial> {
    let v = crate::crypto::vault::decrypt_vault(encrypted_vault, vault_nonce, passphrase)?;
    Ok(VaultKeyMaterial {
        identity_key: v.identity_key.clone(),
        data_kek: v.data_kek.clone().map(Zeroizing::new),
        ratchet_identity_public: v.ratchet_identity_public.clone(),
        ratchet_keys: crate::crypto::ratchet::build_receiver_key_sets(&v),
        inbound_keys: crate::crypto::inbound::build_inbound_key_candidates(&v),
    })
}

pub fn inbound_keys_equal(
    a: &[crate::crypto::inbound::InboundKeyCandidate],
    b: &[crate::crypto::inbound::InboundKeyCandidate],
) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.ecdh_secret_d == y.ecdh_secret_d && x.pq_decap_key == y.pq_decap_key)
}

fn apply_vault_key_material(session: &mut Session, material: VaultKeyMaterial) {
    if let Some(ref mut k) = session.identity_key {
        k.zeroize();
    }
    for keys in session.ratchet_keys.iter_mut() {
        keys.zeroize();
    }
    for keys in session.inbound_keys.iter_mut() {
        keys.zeroize();
    }
    session.identity_key = Some(material.identity_key);
    session.data_kek = material.data_kek;
    session.ratchet_identity_public = material.ratchet_identity_public;
    session.ratchet_keys = material.ratchet_keys;
    session.inbound_keys = material.inbound_keys;
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

    let (identity_key, data_kek, ratchet_identity_public, ratchet_keys, inbound_keys) =
        match decrypt_vault_key_material(
            &login_resp.encrypted_vault,
            &login_resp.vault_nonce,
            &passphrase,
        ) {
            Ok(m) => (
                Some(m.identity_key),
                m.data_kek,
                m.ratchet_identity_public,
                m.ratchet_keys,
                m.inbound_keys,
            ),
            Err(e) => {
                tracing::error!(
                    "vault decrypt failed during restore: {}; encrypted mail cannot be decrypted until you sign in again",
                    e
                );
                (None, None, None, Vec::new(), Vec::new())
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
        data_kek,
        ratchet_identity_public,
        ratchet_keys,
        inbound_keys,
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
    let passphrase = Zeroizing::new(session.read().await.vault_passphrase.clone());
    let material = decrypt_vault_key_material(
        &login_resp.encrypted_vault,
        &login_resp.vault_nonce,
        &passphrase,
    );
    let mut s = session.write().await;
    s.access_token = access_token;
    match material {
        Ok(m) => apply_vault_key_material(&mut s, m),
        Err(e) => tracing::warn!(
            "vault refresh failed during token refresh; keeping existing keys: {}",
            e
        ),
    }
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

                let (identity_key, data_kek, ratchet_identity_public, ratchet_keys, inbound_keys) =
                    match decrypt_vault_key_material(
                        &login_resp.encrypted_vault,
                        &login_resp.vault_nonce,
                        &passphrase,
                    ) {
                        Ok(m) => (
                            Some(m.identity_key),
                            m.data_kek,
                            m.ratchet_identity_public,
                            m.ratchet_keys,
                            m.inbound_keys,
                        ),
                        Err(e) => {
                            tracing::error!(
                                "vault decrypt failed during setup: {}; encrypted mail cannot be decrypted until you sign in again",
                                e
                            );
                            (None, None, None, Vec::new(), Vec::new())
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
                    data_kek,
                    ratchet_identity_public,
                    ratchet_keys,
                    inbound_keys,
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
            data_kek: None,
            user_id: Uuid::new_v4(),
            username: "alice".to_string(),
            email: "alice@astermail.org".to_string(),
            access_token: Zeroizing::new("token-abc".to_string()),
            vault_passphrase: b"passphrase-bytes".to_vec(),
            identity_key: Some("identity-key".to_string()),
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
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
            data_kek: None,
            user_id: Uuid::new_v4(),
            username: "bob".to_string(),
            email: "bob@astermail.org".to_string(),
            access_token: Zeroizing::new(String::new()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
        };
        drop(s);
    }

    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;

    fn encrypt_vault_for_test(plaintext: &[u8], passphrase: &[u8]) -> (String, String) {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use sha2::Sha256;
        let salt = [13u8; 16];
        let nonce_bytes = [21u8; 12];
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, 310_000, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .unwrap();
        let mut combined = salt.to_vec();
        combined.extend_from_slice(&ciphertext);
        (STANDARD.encode(&combined), STANDARD.encode(nonce_bytes))
    }

    async fn spawn_device_login_server(encrypted_vault: String, vault_nonce: String) -> String {
        use axum::{routing::post, Json, Router};
        let challenge = serde_json::json!({
            "challenge_id": Uuid::new_v4(),
            "nonce": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "expires_in": 60
        });
        let login = serde_json::json!({
            "user_id": Uuid::new_v4(),
            "username": "alice",
            "email": "alice@astermail.org",
            "access_token": "fresh-token",
            "encrypted_vault": encrypted_vault,
            "vault_nonce": vault_nonce
        });
        let app = Router::new()
            .route(
                "/core/v1/auth/device/challenge",
                post(move || {
                    let challenge = challenge.clone();
                    async move { Json(challenge) }
                }),
            )
            .route(
                "/core/v1/auth/device/login",
                post(move || {
                    let login = login.clone();
                    async move { Json(login) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn p256_jwk(sk: &p256::SecretKey) -> String {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "d": URL_SAFE_NO_PAD.encode(sk.to_bytes().as_slice()),
        })
        .to_string()
    }

    #[tokio::test]
    async fn refresh_updates_inbound_keys_when_vault_carries_new_identity() {
        let sk = p256::SecretKey::random(&mut rand_core::OsRng);
        let vault_json = serde_json::json!({
            "identity_key": "new-ik",
            "ratchet_identity_public": "pub-b64",
            "ratchet_identity_key": p256_jwk(&sk),
        })
        .to_string();
        let (ev, vn) = encrypt_vault_for_test(vault_json.as_bytes(), b"passphrase-bytes");
        let base = spawn_device_login_server(ev, vn).await;
        let client = ApiClient::new_with_base_url(&base);
        let session = std::sync::Arc::new(tokio::sync::RwLock::new(sample_session()));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

        refresh_access_token(&session, Uuid::new_v4(), &signing_key, &client)
            .await
            .unwrap();

        let s = session.read().await;
        assert_eq!(s.access_token.as_str(), "fresh-token");
        assert_eq!(s.identity_key.as_deref(), Some("new-ik"));
        assert_eq!(s.ratchet_identity_public.as_deref(), Some("pub-b64"));
        assert_eq!(s.inbound_keys.len(), 1);
        assert_eq!(s.inbound_keys[0].ecdh_secret_d, sk.to_bytes().to_vec());
    }

    #[tokio::test]
    async fn refresh_keeps_old_keys_when_fresh_vault_does_not_decrypt() {
        let (ev, vn) = encrypt_vault_for_test(
            br#"{"identity_key":"unreachable"}"#,
            b"a-different-passphrase",
        );
        let base = spawn_device_login_server(ev, vn).await;
        let client = ApiClient::new_with_base_url(&base);
        let mut initial = sample_session();
        initial.inbound_keys = vec![crate::crypto::inbound::InboundKeyCandidate {
            ecdh_secret_d: vec![9u8; 32],
            pq_decap_key: None,
        }];
        let session = std::sync::Arc::new(tokio::sync::RwLock::new(initial));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);

        refresh_access_token(&session, Uuid::new_v4(), &signing_key, &client)
            .await
            .unwrap();

        let s = session.read().await;
        assert_eq!(s.access_token.as_str(), "fresh-token");
        assert_eq!(s.identity_key.as_deref(), Some("identity-key"));
        assert_eq!(s.inbound_keys.len(), 1);
        assert_eq!(s.inbound_keys[0].ecdh_secret_d, vec![9u8; 32]);
    }

    #[test]
    fn inbound_keys_equal_detects_changes() {
        let a = vec![crate::crypto::inbound::InboundKeyCandidate {
            ecdh_secret_d: vec![1u8; 32],
            pq_decap_key: None,
        }];
        let b = vec![crate::crypto::inbound::InboundKeyCandidate {
            ecdh_secret_d: vec![2u8; 32],
            pq_decap_key: None,
        }];
        assert!(inbound_keys_equal(&a, &a.clone()));
        assert!(!inbound_keys_equal(&a, &b));
        assert!(!inbound_keys_equal(&a, &[]));
    }
}
