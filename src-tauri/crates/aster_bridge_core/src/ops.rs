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
use std::path::Path;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api_client::{ApiClient, DeviceCodeRequest};
use crate::auth::device_identity::{self, DeviceIdentity};
use crate::auth::session::{self, Session};
use crate::error::{BridgeError, Result};
use crate::guard::pending::{self, PendingActivation};
use crate::runtime::ClientProfile;

pub const DEVICE_TYPE: &str = "bridge";
pub const RESERVED_SERVICE_PORTS: [u16; 4] = [3306, 5432, 6379, 27017];

pub fn machine_name(profile: ClientProfile) -> String {
    let name = whoami::devicename();
    let name = name.trim();
    let name = if name.is_empty() { "Aster Bridge" } else { name };
    match profile {
        ClientProfile::Desktop => name.to_string(),
        ClientProfile::Cli => format!("{} (CLI)", name),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCode {
    pub code: String,
    pub normalized: String,
    pub expires_in: u64,
    pub device_fingerprint: String,
}

pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

pub async fn request_device_code(
    client: &ApiClient,
    identity: &DeviceIdentity,
    profile: ClientProfile,
) -> Result<DeviceCode> {
    let (ed25519_pk, mlkem_pk, x25519_pk) = device_identity::get_pubkeys(identity);
    let response = client
        .generate_device_code(&DeviceCodeRequest {
            ed25519_pk,
            mlkem_pk,
            x25519_pk,
            machine_name: machine_name(profile),
            device_type: DEVICE_TYPE.to_string(),
            envelope_versions: device_identity::ENVELOPE_VERSIONS.to_vec(),
        })
        .await?;
    Ok(DeviceCode {
        normalized: normalize_code(&response.code),
        code: response.code,
        expires_in: response.expires_in,
        device_fingerprint: device_identity::device_fingerprint(identity),
    })
}

pub enum SignInPoll {
    Pending(String),
    Expired,
    Denied,
    Confirmed(Box<Session>),
    ActivationPending {
        device_id: Uuid,
        activates_at: DateTime<Utc>,
    },
}

const MAX_PASSPHRASE_BYTES: usize = 4096;

pub(crate) fn check_unsealed_passphrase(passphrase: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(passphrase)
        .map_err(|_| BridgeError::Auth("the sign-in did not unlock this account".to_string()))?;
    if text.trim().is_empty() || passphrase.len() > MAX_PASSPHRASE_BYTES || text.contains(char::from(0)) {
        return Err(BridgeError::Auth(
            "the sign-in did not unlock this account".to_string(),
        ));
    }
    Ok(())
}

fn hold_for_activation(
    identity: &mut DeviceIdentity,
    data_dir: &Path,
    device_id: Uuid,
    passphrase: &[u8],
    activates_at: DateTime<Utc>,
    change_id: Option<Uuid>,
) -> Result<SignInPoll> {
    device_identity::set_device_id(data_dir, device_id).map_err(BridgeError::Auth)?;
    device_identity::store_passphrase(data_dir, passphrase).map_err(BridgeError::Auth)?;
    identity.device_id = Some(device_id);
    pending::save(
        data_dir,
        &PendingActivation {
            device_id,
            activates_at,
            change_id,
            code: None,
            replaced_device_id: None,
        },
    )
    .map_err(BridgeError::Auth)?;
    Ok(SignInPoll::ActivationPending {
        device_id,
        activates_at,
    })
}

fn hold_code(
    identity: &mut DeviceIdentity,
    data_dir: &Path,
    device_id: Uuid,
    normalized_code: &str,
    activates_at: DateTime<Utc>,
) -> Result<SignInPoll> {
    let replaced_device_id = match pending::load(data_dir) {
        Some(held) if held.code.as_deref() == Some(normalized_code) => held.replaced_device_id,
        _ => identity.device_id.filter(|current| *current != device_id),
    };
    pending::save(
        data_dir,
        &PendingActivation {
            device_id,
            activates_at,
            change_id: None,
            code: Some(normalized_code.to_string()),
            replaced_device_id,
        },
    )
    .map_err(BridgeError::Auth)?;
    if let Err(e) = device_identity::set_device_id(data_dir, device_id) {
        pending::clear(data_dir);
        return Err(BridgeError::Auth(e));
    }
    identity.device_id = Some(device_id);
    Ok(SignInPoll::ActivationPending {
        device_id,
        activates_at,
    })
}

fn end_held_attempt(identity: &mut DeviceIdentity, data_dir: &Path, normalized_code: &str) {
    let Some(held) = pending::load(data_dir) else {
        return;
    };
    if held.code.as_deref() != Some(normalized_code) {
        return;
    }
    pending::clear(data_dir);
    let _ = match held.replaced_device_id {
        Some(previous) => device_identity::set_device_id(data_dir, previous),
        None => device_identity::clear_device_id(data_dir),
    };
    if identity.device_id == Some(held.device_id) {
        identity.device_id = held.replaced_device_id;
    }
}

pub fn held_code(data_dir: &Path, device_id: Uuid) -> Option<String> {
    pending::load(data_dir)
        .filter(|held| held.device_id == device_id)
        .and_then(|held| held.code)
}

pub async fn finish_held_sign_in(
    client: &ApiClient,
    identity: &DeviceIdentity,
    data_dir: &Path,
    normalized_code: &str,
) -> Result<Session> {
    let mut working = identity.clone();
    let polled = poll_device_sign_in(client, &mut working, data_dir, normalized_code).await;
    match polled {
        Ok(SignInPoll::Confirmed(session)) => Ok(*session),
        Ok(SignInPoll::ActivationPending {
            device_id,
            activates_at,
        }) => Err(BridgeError::GuardPending {
            device_id,
            activates_at,
            change_id: None,
        }),
        Ok(SignInPoll::Pending(_)) => match pending::load(data_dir) {
            Some(held) => Err(BridgeError::GuardPending {
                device_id: held.device_id,
                activates_at: held.activates_at,
                change_id: held.change_id,
            }),
            None => Err(BridgeError::SignInExpired),
        },
        Ok(SignInPoll::Denied) => Err(BridgeError::SignInDenied),
        Ok(SignInPoll::Expired) => Err(BridgeError::SignInExpired),
        Err(BridgeError::Api(message)) if message.starts_with("404") || message.starts_with("410") => {
            end_held_attempt(&mut working, data_dir, normalized_code);
            Err(BridgeError::SignInExpired)
        }
        Err(e) => Err(e),
    }
}

pub async fn poll_device_sign_in(
    client: &ApiClient,
    identity: &mut DeviceIdentity,
    data_dir: &Path,
    normalized_code: &str,
) -> Result<SignInPoll> {
    let status = client.poll_device_code_status(normalized_code).await?;
    match status.status.as_str() {
        "activation_pending" => {
            let device_id = status
                .device_id
                .ok_or_else(|| BridgeError::Auth("no device_id in confirmation".to_string()))?;
            let activates_at = status.activates_at.unwrap_or_else(Utc::now);
            hold_code(identity, data_dir, device_id, normalized_code, activates_at)
        }
        "confirmed" => {
            let device_id = status
                .device_id
                .ok_or_else(|| BridgeError::Auth("no device_id in confirmation".to_string()))?;
            let sealed_envelope = status
                .sealed_envelope
                .ok_or_else(|| BridgeError::Auth("no sealed envelope in confirmation".to_string()))?;
            let passphrase = Zeroizing::new(
                device_identity::unseal_vault_envelope(identity, &sealed_envelope)
                    .map_err(BridgeError::Crypto)?,
            );
            check_unsealed_passphrase(&passphrase)?;
            let session = match session::login_with_passphrase(
                identity,
                device_id,
                passphrase.to_vec(),
                client,
            )
            .await
            {
                Ok(session) => session,
                Err(BridgeError::GuardPending {
                    device_id: held_device_id,
                    activates_at,
                    change_id,
                }) if held_device_id == device_id => {
                    return hold_for_activation(
                        identity,
                        data_dir,
                        device_id,
                        &passphrase,
                        activates_at,
                        change_id,
                    );
                }
                Err(e) => return Err(e),
            };
            if session.identity_key.is_none() {
                return Err(BridgeError::Auth(
                    "the sign-in did not unlock this account".to_string(),
                ));
            }
            device_identity::set_device_id(data_dir, device_id).map_err(BridgeError::Auth)?;
            device_identity::store_passphrase(data_dir, &session.vault_passphrase)
                .map_err(BridgeError::Auth)?;
            identity.device_id = Some(device_id);
            pending::clear(data_dir);
            Ok(SignInPoll::Confirmed(Box::new(session)))
        }
        "expired" => {
            end_held_attempt(identity, data_dir, normalized_code);
            Ok(SignInPoll::Expired)
        }
        "denied" => {
            end_held_attempt(identity, data_dir, normalized_code);
            Ok(SignInPoll::Denied)
        }
        other => Ok(SignInPoll::Pending(other.to_string())),
    }
}

pub fn validate_port(port: u16) -> std::result::Result<(), &'static str> {
    if port < 1024 {
        return Err("port must be >= 1024");
    }
    if RESERVED_SERVICE_PORTS.contains(&port) {
        return Err("well-known service port not allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_machine_name_is_suffixed() {
        let desktop = machine_name(ClientProfile::Desktop);
        let cli = machine_name(ClientProfile::Cli);
        assert!(!desktop.is_empty());
        assert_eq!(cli, format!("{} (CLI)", desktop));
    }

    #[test]
    fn normalize_code_strips_dashes_and_spaces() {
        assert_eq!(normalize_code("AB12-CD34"), "AB12CD34");
        assert_eq!(normalize_code(" AB12 - CD34 "), "AB12CD34");
    }

    #[test]
    fn validate_port_rejects_privileged_and_reserved() {
        assert!(validate_port(80).is_err());
        assert!(validate_port(1023).is_err());
        assert!(validate_port(5432).is_err());
        assert!(validate_port(27017).is_err());
        assert!(validate_port(1024).is_ok());
        assert!(validate_port(1143).is_ok());
    }

    mod guard_flow {
        use super::*;
        use crate::config::BridgeConfig;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        const CHANGE_ID: &str = "11111111-2222-4333-8444-555555555555";
        const ACTIVATES_AT: &str = "2026-11-15T11:00:00Z";
        const PASSPHRASE: &[u8] = b"correct horse battery staple";

        struct Mock {
            status: std::sync::Mutex<serde_json::Value>,
            login_pending: AtomicBool,
            challenges: AtomicUsize,
        }

        async fn spawn(mock: Arc<Mock>) -> String {
            let status_mock = mock.clone();
            let challenge_mock = mock.clone();
            let login_mock = mock.clone();
            let app = Router::new()
                .route(
                    "/core/v1/auth/device/code/status",
                    get(move || {
                        let mock = status_mock.clone();
                        async move { Json(mock.status.lock().unwrap().clone()) }
                    }),
                )
                .route(
                    "/core/v1/auth/device/challenge",
                    post(move || {
                        let mock = challenge_mock.clone();
                        async move {
                            mock.challenges.fetch_add(1, Ordering::SeqCst);
                            Json(serde_json::json!({
                                "challenge_id": Uuid::new_v4(),
                                "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                "expires_in": 60,
                            }))
                        }
                    }),
                )
                .route(
                    "/core/v1/auth/device/login",
                    post(move || {
                        let mock = login_mock.clone();
                        async move {
                            let device_id = mock.status.lock().unwrap()["device_id"].clone();
                            if mock.login_pending.load(Ordering::SeqCst) {
                                (
                                    StatusCode::FORBIDDEN,
                                    Json(serde_json::json!({
                                        "error": "This device is waiting for activation.",
                                        "code": "GUARD_DEVICE_PENDING",
                                        "details": {"device_id": device_id, "activates_at": ACTIVATES_AT, "change_id": CHANGE_ID},
                                    })),
                                )
                                    .into_response()
                            } else {
                                let (encrypted_vault, vault_nonce) =
                                    crate::crypto::vault::encrypt_vault_for_test(
                                        br#"{"identity_key":"sample-identity-key"}"#,
                                        PASSPHRASE,
                                    );
                                Json(serde_json::json!({
                                    "user_id": Uuid::new_v4(),
                                    "username": "sample",
                                    "email": "sample@example.invalid",
                                    "access_token": "access-sample",
                                    "refresh_token": "refresh-sample",
                                    "encrypted_vault": encrypted_vault,
                                    "vault_nonce": vault_nonce,
                                }))
                                .into_response()
                            }
                        }
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            format!("http://127.0.0.1:{}", port)
        }

        fn sealed_for(identity: &DeviceIdentity) -> String {
            let (ed, mlkem, x) = device_identity::get_pubkeys(identity);
            device_identity::seal_vault_envelope(&ed, &mlkem, &x, PASSPHRASE, 2).unwrap()
        }

        fn activates_at() -> DateTime<Utc> {
            DateTime::parse_from_rfc3339(ACTIVATES_AT).unwrap().with_timezone(&Utc)
        }

        fn mock_with(status: serde_json::Value) -> Arc<Mock> {
            Arc::new(Mock {
                status: std::sync::Mutex::new(status),
                login_pending: AtomicBool::new(true),
                challenges: AtomicUsize::new(0),
            })
        }

        fn config_for(dir: &Path) -> BridgeConfig {
            BridgeConfig {
                data_dir: dir.to_path_buf(),
                ..BridgeConfig::default()
            }
        }

        async fn hold(identity: &mut DeviceIdentity, dir: &Path) -> (Arc<Mock>, ApiClient, Uuid) {
            let device_id = Uuid::new_v4();
            let mock = mock_with(serde_json::json!({
                "status": "activation_pending",
                "device_id": device_id,
                "sealed_envelope": null,
                "code_secret_sealed": null,
                "activates_at": ACTIVATES_AT,
            }));
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let result = poll_device_sign_in(&client, identity, dir, "ABCD1234")
                .await
                .unwrap();
            assert!(matches!(
                result,
                SignInPoll::ActivationPending { device_id: id, activates_at: at } if id == device_id && at == activates_at()
            ));
            (mock, client, device_id)
        }

        #[tokio::test]
        async fn activation_pending_status_holds_the_code_without_any_secret() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let (mock, _client, device_id) = hold(&mut identity, dir.path()).await;
            assert_eq!(mock.challenges.load(Ordering::SeqCst), 0);
            assert_eq!(identity.device_id, Some(device_id));
            assert_eq!(device_identity::load_passphrase(dir.path()).unwrap(), None);
            let reloaded = device_identity::get_or_create_identity(dir.path()).unwrap();
            assert_eq!(reloaded.device_id, Some(device_id));
            let record = pending::load(dir.path()).unwrap();
            assert_eq!(record.device_id, device_id);
            assert_eq!(record.activates_at, activates_at());
            assert_eq!(record.change_id, None);
            assert_eq!(record.code.as_deref(), Some("ABCD1234"));
            assert_eq!(held_code(dir.path(), device_id).as_deref(), Some("ABCD1234"));
            assert_eq!(held_code(dir.path(), Uuid::new_v4()), None);
        }

        #[tokio::test]
        async fn an_envelope_sent_during_the_hold_is_never_opened() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let device_id = Uuid::new_v4();
            let mock = mock_with(serde_json::json!({
                "status": "activation_pending",
                "device_id": device_id,
                "sealed_envelope": sealed_for(&identity),
                "activates_at": ACTIVATES_AT,
            }));
            mock.login_pending.store(false, Ordering::SeqCst);
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let result = poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234")
                .await
                .unwrap();
            assert!(matches!(result, SignInPoll::ActivationPending { .. }));
            assert_eq!(mock.challenges.load(Ordering::SeqCst), 0);
            assert_eq!(device_identity::load_passphrase(dir.path()).unwrap(), None);
            assert_eq!(pending::load(dir.path()).unwrap().code.as_deref(), Some("ABCD1234"));
        }

        #[tokio::test]
        async fn a_held_code_signs_in_once_confirmed_and_clears_the_record() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let (mock, client, device_id) = hold(&mut identity, dir.path()).await;
            mock.login_pending.store(false, Ordering::SeqCst);
            let config = config_for(dir.path());
            let still_held = session::restore_or_login(&config, &identity, &client)
                .await
                .err()
                .expect("the hold is still running");
            assert!(matches!(
                still_held,
                BridgeError::GuardPending { device_id: id, change_id: None, .. } if id == device_id
            ));
            assert_eq!(mock.challenges.load(Ordering::SeqCst), 0);
            assert!(pending::load(dir.path()).unwrap().code.is_some());

            *mock.status.lock().unwrap() = serde_json::json!({
                "status": "confirmed",
                "device_id": device_id,
                "sealed_envelope": sealed_for(&identity),
                "activates_at": null,
            });
            let session = session::restore_or_login(&config, &identity, &client)
                .await
                .expect("the hold ended");
            assert!(session.identity_key.is_some());
            assert_eq!(mock.challenges.load(Ordering::SeqCst), 1);
            assert_eq!(pending::load(dir.path()), None);
            assert_eq!(
                device_identity::load_passphrase(dir.path()).unwrap().as_deref(),
                Some(PASSPHRASE)
            );
            assert_eq!(
                device_identity::get_or_create_identity(dir.path()).unwrap().device_id,
                Some(device_id)
            );
        }

        #[tokio::test]
        async fn a_held_code_that_ends_forgets_the_attempt() {
            let _secrets = crate::secrets::test_backend_lock().await;
            for ending in ["denied", "expired"] {
                let dir = tempfile::tempdir().unwrap();
                let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
                let (mock, client, _device_id) = hold(&mut identity, dir.path()).await;
                *mock.status.lock().unwrap() = serde_json::json!({"status": ending});
                let err = session::restore_or_login(&config_for(dir.path()), &identity, &client)
                    .await
                    .err()
                    .expect("the sign-in ended");
                if ending == "denied" {
                    assert!(matches!(err, BridgeError::SignInDenied));
                } else {
                    assert!(matches!(err, BridgeError::SignInExpired));
                }
                assert_eq!(pending::load(dir.path()), None);
                assert_eq!(device_identity::load_passphrase(dir.path()).unwrap(), None);
                assert_eq!(
                    device_identity::get_or_create_identity(dir.path()).unwrap().device_id,
                    None
                );
                assert_eq!(mock.challenges.load(Ordering::SeqCst), 0);
            }
        }

        #[tokio::test]
        async fn a_denied_poll_clears_the_held_record_and_device_id() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let (mock, client, _device_id) = hold(&mut identity, dir.path()).await;
            *mock.status.lock().unwrap() = serde_json::json!({"status": "denied"});
            let result = poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234")
                .await
                .unwrap();
            assert!(matches!(result, SignInPoll::Denied));
            assert_eq!(identity.device_id, None);
            assert_eq!(pending::load(dir.path()), None);
            assert_eq!(device_identity::load_passphrase(dir.path()).unwrap(), None);
            assert_eq!(
                device_identity::get_or_create_identity(dir.path()).unwrap().device_id,
                None
            );
        }

        #[tokio::test]
        async fn a_hold_keeps_the_earlier_sign_in_and_gives_it_back_when_it_ends() {
            let _secrets = crate::secrets::test_backend_lock().await;
            for ending in ["denied", "expired"] {
                let dir = tempfile::tempdir().unwrap();
                let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
                let earlier = Uuid::new_v4();
                device_identity::set_device_id(dir.path(), earlier).unwrap();
                device_identity::store_passphrase(dir.path(), PASSPHRASE).unwrap();
                identity.device_id = Some(earlier);
                let (mock, client, device_id) = hold(&mut identity, dir.path()).await;
                assert_eq!(identity.device_id, Some(device_id));
                assert_eq!(
                    device_identity::load_passphrase(dir.path()).unwrap().as_deref(),
                    Some(PASSPHRASE)
                );
                assert_eq!(pending::load(dir.path()).unwrap().replaced_device_id, Some(earlier));
                let again = poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234")
                    .await
                    .unwrap();
                assert!(matches!(again, SignInPoll::ActivationPending { .. }));
                assert_eq!(pending::load(dir.path()).unwrap().replaced_device_id, Some(earlier));
                *mock.status.lock().unwrap() = serde_json::json!({"status": ending});
                let err = session::restore_or_login(&config_for(dir.path()), &identity, &client)
                    .await
                    .err()
                    .expect("the sign-in ended");
                assert!(matches!(err, BridgeError::SignInDenied | BridgeError::SignInExpired));
                assert_eq!(pending::load(dir.path()), None);
                assert_eq!(
                    device_identity::get_or_create_identity(dir.path()).unwrap().device_id,
                    Some(earlier)
                );
                assert_eq!(
                    device_identity::load_passphrase(dir.path()).unwrap().as_deref(),
                    Some(PASSPHRASE)
                );
            }
        }

        #[tokio::test]
        async fn a_denied_code_leaves_another_sign_in_alone() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let device_id = Uuid::new_v4();
            device_identity::set_device_id(dir.path(), device_id).unwrap();
            device_identity::store_passphrase(dir.path(), PASSPHRASE).unwrap();
            identity.device_id = Some(device_id);
            let mock = mock_with(serde_json::json!({"status": "denied"}));
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let result = poll_device_sign_in(&client, &mut identity, dir.path(), "OTHER999")
                .await
                .unwrap();
            assert!(matches!(result, SignInPoll::Denied));
            assert_eq!(identity.device_id, Some(device_id));
            assert_eq!(
                device_identity::load_passphrase(dir.path()).unwrap().as_deref(),
                Some(PASSPHRASE)
            );
        }

        #[tokio::test]
        async fn confirmed_sign_in_held_by_the_server_waits_for_activation() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let device_id = Uuid::new_v4();
            let mock = mock_with(serde_json::json!({
                "status": "confirmed",
                "device_id": device_id,
                "sealed_envelope": sealed_for(&identity),
            }));
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let result = poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234")
                .await
                .unwrap();
            assert!(matches!(result, SignInPoll::ActivationPending { .. }));
            assert_eq!(mock.challenges.load(Ordering::SeqCst), 1);
            let record = pending::load(dir.path()).unwrap();
            assert_eq!(record.change_id.map(|id| id.to_string()).as_deref(), Some(CHANGE_ID));
            assert_eq!(
                device_identity::load_passphrase(dir.path()).unwrap().as_deref(),
                Some(PASSPHRASE)
            );
        }

        #[tokio::test]
        async fn activation_pending_without_a_time_still_waits() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let device_id = Uuid::new_v4();
            let mock = mock_with(serde_json::json!({
                "status": "activation_pending",
                "device_id": device_id,
            }));
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let before = Utc::now();
            let result = poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234")
                .await
                .unwrap();
            assert!(matches!(result, SignInPoll::ActivationPending { activates_at, .. } if activates_at >= before));
            assert_eq!(mock.challenges.load(Ordering::SeqCst), 0);
            assert_eq!(device_identity::load_passphrase(dir.path()).unwrap(), None);
        }

        #[tokio::test]
        async fn restore_records_the_hold_and_clears_it_once_active() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let device_id = Uuid::new_v4();
            device_identity::set_device_id(dir.path(), device_id).unwrap();
            device_identity::store_passphrase(dir.path(), PASSPHRASE).unwrap();
            identity.device_id = Some(device_id);
            let mock = mock_with(serde_json::json!({"device_id": device_id}));
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let config = config_for(dir.path());
            let err = session::restore_or_login(&config, &identity, &client)
                .await
                .err()
                .expect("the server holds the device");
            assert!(matches!(err, BridgeError::GuardPending { .. }));
            assert_eq!(pending::load(dir.path()).unwrap().device_id, device_id);
            assert_eq!(
                device_identity::load_passphrase(dir.path()).unwrap().as_deref(),
                Some(PASSPHRASE)
            );
            mock.login_pending.store(false, Ordering::SeqCst);
            session::restore_or_login(&config, &identity, &client)
                .await
                .expect("the device is active");
            assert_eq!(pending::load(dir.path()), None);
        }

        #[tokio::test]
        async fn denied_status_ends_the_sign_in_without_storing_anything() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let mock = mock_with(serde_json::json!({"status": "denied"}));
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let result = poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234")
                .await
                .unwrap();
            assert!(matches!(result, SignInPoll::Denied));
            assert_eq!(identity.device_id, None);
            assert_eq!(pending::load(dir.path()), None);
            assert_eq!(mock.challenges.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn unknown_status_keeps_waiting() {
            let _secrets = crate::secrets::test_backend_lock().await;
            let dir = tempfile::tempdir().unwrap();
            let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
            let mock = mock_with(serde_json::json!({"status": "rejected"}));
            let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
            let result = poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234")
                .await
                .unwrap();
            assert!(matches!(result, SignInPoll::Pending(status) if status == "rejected"));
        }

        #[tokio::test]
        async fn confirmed_sign_in_with_an_unusable_passphrase_stores_nothing() {
            let _secrets = crate::secrets::test_backend_lock().await;
            for payload in [b"   ".to_vec(), vec![0xff, 0xfe, 0x41], vec![b'a'; MAX_PASSPHRASE_BYTES + 1]] {
                let dir = tempfile::tempdir().unwrap();
                let mut identity = device_identity::get_or_create_identity(dir.path()).unwrap();
                let (ed, mlkem, x) = device_identity::get_pubkeys(&identity);
                let sealed =
                    device_identity::seal_vault_envelope(&ed, &mlkem, &x, &payload, 2).unwrap();
                let mock = mock_with(serde_json::json!({
                    "status": "confirmed",
                    "device_id": Uuid::new_v4(),
                    "sealed_envelope": sealed,
                }));
                let client = ApiClient::new_with_base_url(&spawn(mock.clone()).await);
                let result =
                    poll_device_sign_in(&client, &mut identity, dir.path(), "ABCD1234").await;
                assert!(matches!(result, Err(BridgeError::Auth(_))));
                assert_eq!(identity.device_id, None);
                assert_eq!(pending::load(dir.path()), None);
                assert_eq!(device_identity::load_passphrase(dir.path()).unwrap(), None);
            }
        }
    }

    #[test]
    fn unsealed_passphrase_check_accepts_a_normal_passphrase() {
        assert!(check_unsealed_passphrase(b"correct horse battery staple").is_ok());
        assert!(check_unsealed_passphrase(b"").is_err());
        assert!(check_unsealed_passphrase(b"bad\0byte").is_err());
    }
}
