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
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pgp::composed::{Deserializable, Message};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

use crate::api_client::{ApiClient, StorageKeyWrap};
use crate::auth::session::{decrypt_vault_key_material, Session};
use crate::error::{BridgeError, Result};

pub const VAULT_RECHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);
const MAX_WRAP_BYTES: usize = 4096;
const KEY_ID_BYTES: usize = 16;

#[derive(Default)]
struct FreshnessState {
    vault_sha: Option<[u8; 32]>,
    checked_at: Option<Instant>,
    stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessOutcome {
    NotDue,
    Unchanged,
    Updated,
    Failed,
}

pub struct VaultFreshness {
    interval: Duration,
    state: Mutex<FreshnessState>,
}

impl Default for VaultFreshness {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultFreshness {
    pub fn new() -> Self {
        Self::with_interval(VAULT_RECHECK_INTERVAL)
    }

    pub fn with_interval(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(FreshnessState::default()),
        }
    }

    pub async fn mark_stale(&self) {
        self.state.lock().await.stale = true;
    }

    pub async fn ensure_fresh(
        &self,
        client: &ApiClient,
        session: &RwLock<Session>,
    ) -> FreshnessOutcome {
        let mut state = self.state.lock().await;
        let due = state.stale
            || match state.checked_at {
                Some(at) => at.elapsed() >= self.interval,
                None => true,
            };
        if !due {
            return FreshnessOutcome::NotDue;
        }
        state.checked_at = Some(Instant::now());
        state.stale = false;
        match refresh(client, session, &mut state).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::warn!("vault check failed, keeping the current contacts key: {}", e);
                FreshnessOutcome::Failed
            }
        }
    }
}

fn vault_sha(encrypted_vault: &str) -> [u8; 32] {
    match STANDARD.decode(encrypted_vault.trim()) {
        Ok(bytes) => Sha256::digest(&bytes).into(),
        Err(_) => Sha256::digest(encrypted_vault.as_bytes()).into(),
    }
}

fn raw_key(b64: &str) -> Option<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(STANDARD.decode(b64.trim()).ok()?);
    let array: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(Zeroizing::new(array))
}

pub fn storage_key_id(key: &[u8; 32]) -> String {
    Sha256::digest(key)[..KEY_ID_BYTES]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

async fn refresh(
    client: &ApiClient,
    session: &RwLock<Session>,
    state: &mut FreshnessState,
) -> Result<FreshnessOutcome> {
    let (token, passphrase, session_identity, session_previous) = {
        let s = session.read().await;
        (
            Zeroizing::new(s.access_token.to_string()),
            Zeroizing::new(s.vault_passphrase.clone()),
            s.identity_key.clone().map(Zeroizing::new),
            s.previous_keys.clone(),
        )
    };

    let Some(vault) = client.get_vault(&token).await? else {
        return Ok(FreshnessOutcome::Unchanged);
    };
    let sha = vault_sha(&vault.encrypted_vault);
    if state.vault_sha == Some(sha) {
        return Ok(FreshnessOutcome::Unchanged);
    }

    let decrypt_passphrase = passphrase.clone();
    let material = tokio::task::spawn_blocking(move || {
        decrypt_vault_key_material(&vault.encrypted_vault, &vault.vault_nonce, &decrypt_passphrase)
    })
    .await
    .map_err(|e| BridgeError::Crypto(format!("vault decrypt task: {}", e)))??;

    let vault_kek = material.data_kek.as_deref().and_then(|k| raw_key(k));

    let mut identity_keys: Vec<String> = Vec::new();
    for key in std::iter::once(material.identity_key.as_str())
        .chain(material.previous_keys.iter().map(String::as_str))
        .chain(session_identity.as_deref().map(String::as_str))
        .chain(session_previous.iter().map(String::as_str))
    {
        if !key.is_empty() && !identity_keys.iter().any(|k| k == key) {
            identity_keys.push(key.to_string());
        }
    }
    let identity_keys = Zeroizing::new(identity_keys);

    let wrap_kek = match client.list_storage_key_wraps(&token).await {
        Ok(Some(wraps)) => open_newest_wrap(&wraps, &identity_keys, &passphrase),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("storage key side copies unavailable: {}", e);
            None
        }
    };

    state.vault_sha = Some(sha);

    let mut s = session.write().await;
    let updated = apply_storage_keys(
        &mut s,
        vault_kek,
        wrap_kek,
        &material.ratchet_recovery.storage_keys,
    );
    Ok(if updated {
        FreshnessOutcome::Updated
    } else {
        FreshnessOutcome::Unchanged
    })
}

pub fn open_newest_wrap(
    wraps: &[StorageKeyWrap],
    identity_keys: &[String],
    passphrase: &[u8],
) -> Option<Zeroizing<[u8; 32]>> {
    let key_pairs: Vec<aster_crypto::KeyPair> = identity_keys
        .iter()
        .filter_map(|armored| aster_crypto::import_secret_key(armored).ok())
        .collect();
    if key_pairs.is_empty() {
        return None;
    }
    let passphrase_text =
        Zeroizing::new(std::str::from_utf8(passphrase).unwrap_or("").to_string());

    for wrap in wraps {
        if wrap.nonce.as_deref().is_some_and(|n| !n.trim().is_empty()) {
            continue;
        }
        let Ok(bytes) = STANDARD.decode(wrap.wrap.trim()) else {
            continue;
        };
        if bytes.is_empty() || bytes.len() > MAX_WRAP_BYTES {
            continue;
        }
        let expected_id = wrap.key_id.trim().to_ascii_lowercase();
        for key_pair in &key_pairs {
            for candidate in [passphrase_text.as_str(), ""] {
                if let Some(key) = open_wrap(&bytes, key_pair, candidate) {
                    if storage_key_id(&key) == expected_id {
                        return Some(key);
                    }
                }
            }
        }
    }
    None
}

fn open_wrap(
    bytes: &[u8],
    key_pair: &aster_crypto::KeyPair,
    passphrase: &str,
) -> Option<Zeroizing<[u8; 32]>> {
    let msg = Message::from_bytes(bytes).ok()?;
    let (decrypted, _) = msg
        .decrypt(|| passphrase.to_string(), &[key_pair.secret_key()])
        .ok()?;
    let data = match decrypted.get_literal() {
        Some(literal) => Zeroizing::new(literal.data().to_vec()),
        None => match &decrypted {
            Message::Literal(literal) => Zeroizing::new(literal.data().to_vec()),
            _ => return None,
        },
    };
    let array: [u8; 32] = data.as_slice().try_into().ok()?;
    Some(Zeroizing::new(array))
}

fn apply_storage_keys(
    session: &mut Session,
    vault_kek: Option<Zeroizing<[u8; 32]>>,
    wrap_kek: Option<Zeroizing<[u8; 32]>>,
    vault_storage_keys: &[Zeroizing<[u8; 32]>],
) -> bool {
    let current = session.data_kek.as_deref().and_then(|k| raw_key(k));
    let known = session.ratchet_recovery.storage_keys.clone();

    let target = match (wrap_kek, vault_kek.clone()) {
        (Some(wrapped), _) => Some(wrapped),
        (None, Some(from_vault)) => {
            let is_former_key = current.as_ref().is_some_and(|c| **c != *from_vault)
                && known.iter().any(|k| **k == *from_vault);
            if is_former_key {
                tracing::warn!("server vault holds an earlier contacts key, keeping the newer one");
                None
            } else {
                Some(from_vault)
            }
        }
        (None, None) => None,
    };

    let changed = match (&target, &current) {
        (Some(t), Some(c)) => **t != **c,
        (Some(_), None) => true,
        _ => false,
    };

    let mut merged: Vec<Zeroizing<[u8; 32]>> = Vec::new();
    {
        let mut push = |key: &Zeroizing<[u8; 32]>| {
            if !merged.iter().any(|k| **k == **key) {
                merged.push(key.clone());
            }
        };
        if changed {
            if let Some(t) = target.as_ref() {
                push(t);
            }
        }
        if let Some(c) = current.as_ref() {
            push(c);
        }
        if let Some(v) = vault_kek.as_ref() {
            push(v);
        }
        for key in vault_storage_keys.iter().chain(known.iter()) {
            push(key);
        }
    }
    session.ratchet_recovery.storage_keys = merged;

    if changed {
        if let Some(t) = target {
            session.data_kek = Some(Zeroizing::new(STANDARD.encode(*t)));
            tracing::info!("contacts key updated from the server vault");
        }
    }
    changed
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use pgp::ser::Serialize as PgpSerialize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    pub(crate) const PASSPHRASE: &[u8] = b"vault-pass";

    pub(crate) fn seal_vault(vault_json: &serde_json::Value) -> (String, String) {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        let salt: [u8; 16] = rand::random();
        let nonce_bytes: [u8; 12] = rand::random();
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(PASSPHRASE, &salt, 310_000, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                vault_json.to_string().as_bytes(),
            )
            .unwrap();
        let mut combined = salt.to_vec();
        combined.extend_from_slice(&ciphertext);
        (STANDARD.encode(&combined), STANDARD.encode(nonce_bytes))
    }

    pub(crate) fn session_with(data_kek: Option<[u8; 32]>, identity_key: Option<String>) -> Session {
        Session {
            data_kek: data_kek.map(|k| Zeroizing::new(STANDARD.encode(k))),
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: PASSPHRASE.to_vec(),
            identity_key,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: crate::crypto::ratchet_recovery::RecoveryMaterial {
                storage_keys: data_kek.into_iter().map(Zeroizing::new).collect(),
                lane_candidates: Vec::new(),
            },
        }
    }

    pub(crate) fn vault_json(identity_key: &str, data_kek: [u8; 32], legacy: &[[u8; 32]]) -> serde_json::Value {
        serde_json::json!({
            "identity_key": identity_key,
            "data_kek": STANDARD.encode(data_kek),
            "vault_format": 2,
            "legacy_keks": legacy.iter().map(|k| serde_json::json!({ "k": STANDARD.encode(k) })).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn wrap_for(key_pair: &aster_crypto::KeyPair, data_kek: &[u8; 32]) -> String {
        let armored = aster_crypto::encrypt_message(data_kek, &[&key_pair.public_key()]).unwrap();
        let (msg, _) = Message::from_armor_single(&armored[..]).unwrap();
        STANDARD.encode(msg.to_bytes().unwrap())
    }

    #[derive(Clone)]
    pub(crate) struct FakeServer {
        pub vault: Arc<std::sync::Mutex<(String, String)>>,
        pub wraps: Arc<std::sync::Mutex<Option<serde_json::Value>>>,
        pub vault_reads: Arc<AtomicUsize>,
        pub other_requests: Arc<AtomicUsize>,
    }

    impl FakeServer {
        pub(crate) fn new(vault: (String, String), wraps: Option<serde_json::Value>) -> Self {
            Self {
                vault: Arc::new(std::sync::Mutex::new(vault)),
                wraps: Arc::new(std::sync::Mutex::new(wraps)),
                vault_reads: Arc::new(AtomicUsize::new(0)),
                other_requests: Arc::new(AtomicUsize::new(0)),
            }
        }

        pub(crate) fn router(&self) -> Router {
            let vault = self.vault.clone();
            let reads = self.vault_reads.clone();
            let wraps = self.wraps.clone();
            let others = self.other_requests.clone();
            Router::new()
                .route(
                    "/crypto/v1/keys/vault",
                    get(move || {
                        let vault = vault.clone();
                        let reads = reads.clone();
                        async move {
                            reads.fetch_add(1, Ordering::SeqCst);
                            let (ev, vn) = vault.lock().unwrap().clone();
                            Json(serde_json::json!({
                                "encrypted_vault": ev,
                                "vault_nonce": vn,
                                "vault_format": 2,
                            }))
                        }
                    }),
                )
                .route(
                    "/core/v1/auth/me/storage-key-wraps",
                    get(move || {
                        let wraps = wraps.clone();
                        async move {
                            match wraps.lock().unwrap().clone() {
                                Some(body) => Json(body).into_response(),
                                None => (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response(),
                            }
                        }
                    }),
                )
                .fallback(move || {
                    let others = others.clone();
                    async move {
                        others.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NOT_FOUND
                    }
                })
        }
    }

    pub(crate) async fn spawn(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn data_kek_of(session: &Session) -> [u8; 32] {
        *raw_key(session.data_kek.as_deref().unwrap()).unwrap()
    }

    fn holds(session: &Session, key: [u8; 32]) -> bool {
        session.ratchet_recovery.storage_keys.iter().any(|k| **k == key)
    }

    #[test]
    fn recheck_interval_is_bounded() {
        assert!(VAULT_RECHECK_INTERVAL >= Duration::from_secs(60));
        assert!(VAULT_RECHECK_INTERVAL <= Duration::from_secs(15 * 60));
    }

    #[test]
    fn storage_key_id_is_the_first_sixteen_bytes_of_the_digest() {
        let key = [5u8; 32];
        let id = storage_key_id(&key);
        assert_eq!(id.len(), 32);
        let digest = Sha256::digest(key);
        let expected: String = digest[..16].iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(id, expected);
    }

    #[tokio::test]
    async fn vault_is_checked_once_per_interval_unless_marked_stale() {
        let a = [3u8; 32];
        let server = FakeServer::new(
            seal_vault(&vault_json("", a, &[])),
            Some(serde_json::json!({ "wraps": [] })),
        );
        let client = ApiClient::new_with_base_url(&spawn(server.router()).await);
        let session = RwLock::new(session_with(Some(a), None));
        let freshness = VaultFreshness::new();

        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::Unchanged);
        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::NotDue);
        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::NotDue);
        assert_eq!(server.vault_reads.load(Ordering::SeqCst), 1);

        freshness.mark_stale().await;
        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::Unchanged);
        assert_eq!(server.vault_reads.load(Ordering::SeqCst), 2);
        assert_eq!(data_kek_of(&*session.read().await), a);
    }

    #[tokio::test]
    async fn rotated_vault_moves_writes_to_the_new_key_and_keeps_the_old_one_readable() {
        let a = [3u8; 32];
        let b = [4u8; 32];
        let server = FakeServer::new(seal_vault(&vault_json("", b, &[a])), None);
        let client = ApiClient::new_with_base_url(&spawn(server.router()).await);
        let session = RwLock::new(session_with(Some(a), None));
        let freshness = VaultFreshness::with_interval(Duration::from_secs(3600));

        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::Updated);
        {
            let s = session.read().await;
            assert_eq!(data_kek_of(&s), b);
            assert!(holds(&s, a));
            assert!(holds(&s, b));
        }

        *server.vault.lock().unwrap() = seal_vault(&vault_json("", a, &[]));
        freshness.mark_stale().await;
        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::Unchanged);
        let s = session.read().await;
        assert_eq!(data_kek_of(&s), b);
        assert!(holds(&s, a));
        assert_eq!(server.other_requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn newest_side_copy_wins_over_a_stale_vault_and_the_vault_is_never_written() {
        let identity = aster_crypto::generate_keypair("tester", "tester@aster.test").unwrap();
        let armored = identity.to_armored().unwrap();
        let a = [3u8; 32];
        let b = [4u8; 32];
        let unrelated = [6u8; 32];
        let wraps = serde_json::json!({
            "wraps": [
                {
                    "key_id": storage_key_id(&b),
                    "wrap": wrap_for(&identity, &unrelated),
                    "nonce": null,
                    "identity_fingerprint": "ZnA=",
                    "created_at": "2026-11-06T12:00:01Z"
                },
                {
                    "key_id": storage_key_id(&b),
                    "wrap": wrap_for(&identity, &b),
                    "nonce": null,
                    "identity_fingerprint": "ZnA=",
                    "created_at": "2026-11-06T12:00:00Z"
                }
            ]
        });
        let server = FakeServer::new(seal_vault(&vault_json(&armored, a, &[])), Some(wraps));
        let client = ApiClient::new_with_base_url(&spawn(server.router()).await);
        let session = RwLock::new(session_with(Some(a), Some(armored.clone())));
        let freshness = VaultFreshness::new();

        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::Updated);
        let s = session.read().await;
        assert_eq!(data_kek_of(&s), b);
        assert!(holds(&s, a));
        assert!(!holds(&s, unrelated));
        assert_eq!(server.other_requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn side_copies_with_a_nonce_or_a_foreign_key_are_ignored() {
        let identity = aster_crypto::generate_keypair("tester", "tester@aster.test").unwrap();
        let stranger = aster_crypto::generate_keypair("other", "other@aster.test").unwrap();
        let b = [4u8; 32];
        let wraps = vec![
            StorageKeyWrap {
                key_id: storage_key_id(&b),
                wrap: wrap_for(&identity, &b),
                nonce: Some(STANDARD.encode([1u8; 24])),
            },
            StorageKeyWrap {
                key_id: storage_key_id(&b),
                wrap: wrap_for(&stranger, &b),
                nonce: None,
            },
        ];
        let keys = vec![identity.to_armored().unwrap()];
        assert!(open_newest_wrap(&wraps, &keys, PASSPHRASE).is_none());

        let good = vec![StorageKeyWrap {
            key_id: storage_key_id(&b).to_ascii_uppercase(),
            wrap: wrap_for(&identity, &b),
            nonce: Some(String::new()),
        }];
        assert_eq!(*open_newest_wrap(&good, &keys, PASSPHRASE).unwrap(), b);
    }

    #[tokio::test]
    async fn unreachable_server_keeps_the_current_key_and_waits_for_the_interval() {
        let a = [3u8; 32];
        let client = ApiClient::new_with_base_url("http://127.0.0.1:9");
        let session = RwLock::new(session_with(Some(a), None));
        let freshness = VaultFreshness::new();

        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::Failed);
        assert_eq!(freshness.ensure_fresh(&client, &session).await, FreshnessOutcome::NotDue);
        assert_eq!(data_kek_of(&*session.read().await), a);
    }

    #[test]
    fn a_vault_without_a_data_kek_never_drops_the_session_key() {
        let a = [3u8; 32];
        let mut session = session_with(Some(a), None);
        assert!(!apply_storage_keys(&mut session, None, None, &[]));
        assert_eq!(data_kek_of(&session), a);

        let mut empty = session_with(None, None);
        assert!(apply_storage_keys(&mut empty, Some(Zeroizing::new(a)), None, &[]));
        assert_eq!(data_kek_of(&empty), a);
    }
}
