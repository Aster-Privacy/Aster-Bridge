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
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BridgeError, Result};

const PBKDF2_ITERATIONS: u32 = 310_000;
const PBKDF2_ITERATIONS_STRONG: u32 = 600_000;
const VAULT_AAD: &[u8] = b"aster-vault-v1";
const SALT_LEN: usize = 16;

#[derive(Deserialize, Zeroize, Clone)]
pub struct RatchetKeySet {
    pub ratchet_identity_key: Option<String>,
    pub ratchet_identity_public: Option<String>,
    pub ratchet_signed_prekey: Option<String>,
    pub ratchet_signed_prekey_public: Option<String>,
    pub ratchet_pq_identity_key: Option<String>,
    pub ratchet_pq_identity_seed: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    pub ratchet_pq_identity_public: Option<String>,
}

fn lenient_string<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| match v {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    }))
}

#[derive(Zeroize, Clone)]
pub struct LegacyKek {
    pub k: String,
}

fn lenient_u32<'de, D>(deserializer: D) -> std::result::Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value
        .and_then(|v| v.as_f64())
        .filter(|n| n.is_finite() && *n >= 0.0 && *n <= u32::MAX as f64)
        .map(|n| n as u32))
}

fn lenient_string_list<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| match v {
        serde_json::Value::Array(items) => Some(
            items
                .into_iter()
                .filter_map(|item| match item {
                    serde_json::Value::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }))
}

fn lenient_legacy_keks<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<LegacyKek>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| match v {
        serde_json::Value::Array(items) => Some(
            items
                .into_iter()
                .filter_map(|item| {
                    item.get("k")
                        .and_then(|k| k.as_str())
                        .map(|k| LegacyKek { k: k.to_string() })
                })
                .collect(),
        ),
        _ => None,
    }))
}

#[derive(Deserialize, ZeroizeOnDrop)]
pub struct VaultContents {
    pub identity_key: String,
    pub data_kek: Option<String>,
    pub signed_prekey_private: Option<String>,
    pub signed_prekey: Option<String>,
    pub recovery_codes: Option<Vec<String>>,
    pub vault_id: Option<String>,
    pub ratchet_identity_key: Option<String>,
    pub ratchet_identity_public: Option<String>,
    pub ratchet_signed_prekey: Option<String>,
    pub ratchet_signed_prekey_public: Option<String>,
    pub ratchet_pq_identity_key: Option<String>,
    pub ratchet_pq_identity_seed: Option<String>,
    pub ratchet_previous_keys: Option<Vec<RatchetKeySet>>,
    pub previous_keys: Option<Vec<String>>,
    #[serde(default, deserialize_with = "lenient_string")]
    pub ratchet_pq_identity_public: Option<String>,
    #[serde(default, deserialize_with = "lenient_u32")]
    pub vault_format: Option<u32>,
    #[serde(default, deserialize_with = "lenient_u32")]
    pub kdf_version: Option<u32>,
    #[serde(default, deserialize_with = "lenient_legacy_keks")]
    pub legacy_keks: Option<Vec<LegacyKek>>,
    #[serde(default, deserialize_with = "lenient_string_list")]
    pub legacy_identity_keys: Option<Vec<String>>,
}

pub fn vault_kdf_iterations(stored: Option<u32>) -> Result<u32> {
    match stored {
        None => Ok(PBKDF2_ITERATIONS),
        Some(PBKDF2_ITERATIONS) => Ok(PBKDF2_ITERATIONS),
        Some(PBKDF2_ITERATIONS_STRONG) => Ok(PBKDF2_ITERATIONS_STRONG),
        Some(other) => Err(BridgeError::Crypto(format!(
            "unsupported vault kdf iterations: {}",
            other
        ))),
    }
}

fn vault_cipher(passphrase: &[u8], salt: &[u8], iterations: u32) -> Result<Aes256Gcm> {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut key);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)));
    key.zeroize();
    cipher
}

#[cfg(any(test, feature = "test-support"))]
pub fn encrypt_vault_for_test(plaintext: &[u8], passphrase: &[u8]) -> (String, String) {
    let salt: [u8; SALT_LEN] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();
    let cipher = vault_cipher(passphrase, &salt, PBKDF2_ITERATIONS).expect("vault cipher");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .expect("vault encrypt");
    let mut combined = salt.to_vec();
    combined.extend_from_slice(&ciphertext);
    (STANDARD.encode(&combined), STANDARD.encode(nonce_bytes))
}

pub fn decrypt_vault(
    encrypted_vault_b64: &str,
    vault_nonce_b64: &str,
    passphrase: &[u8],
) -> Result<VaultContents> {
    decrypt_vault_with_iterations(encrypted_vault_b64, vault_nonce_b64, passphrase, None)
}

pub fn decrypt_vault_with_iterations(
    encrypted_vault_b64: &str,
    vault_nonce_b64: &str,
    passphrase: &[u8],
    stored_iterations: Option<u32>,
) -> Result<VaultContents> {
    let iterations = vault_kdf_iterations(stored_iterations)?;

    let combined = STANDARD
        .decode(encrypted_vault_b64)
        .map_err(|e| BridgeError::Crypto(format!("vault data decode: {}", e)))?;

    let nonce_bytes = STANDARD
        .decode(vault_nonce_b64)
        .map_err(|e| BridgeError::Crypto(format!("vault nonce decode: {}", e)))?;

    if combined.len() < SALT_LEN + 16 {
        return Err(BridgeError::Crypto("vault data too short".to_string()));
    }

    if nonce_bytes.len() != 12 {
        return Err(BridgeError::Crypto("vault nonce must be 12 bytes".to_string()));
    }

    let salt = &combined[..SALT_LEN];
    let ciphertext = &combined[SALT_LEN..];

    let cipher = vault_cipher(passphrase, salt, iterations)?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .or_else(|_| {
            cipher.decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: VAULT_AAD,
                },
            )
        })
        .map_err(|_| BridgeError::Crypto("vault decrypt failed".to_string()))?;

    let mut vault_json = String::from_utf8(plaintext)
        .map_err(|e| BridgeError::Crypto(format!("vault utf8 decode: {}", e)))?;

    let parsed = serde_json::from_str(&vault_json)
        .map_err(|e| BridgeError::Crypto(format!("vault json parse: {}", e)));
    vault_json.zeroize();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_vault(plaintext: &[u8], passphrase: &[u8], nonce_bytes: &[u8; 12]) -> (String, String) {
        let salt = [13u8; SALT_LEN];
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, PBKDF2_ITERATIONS, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
        let mut combined = Vec::new();
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&ciphertext);
        (STANDARD.encode(&combined), STANDARD.encode(nonce_bytes))
    }

    fn sample_vault_json() -> String {
        r#"{"identity_key":"ik-abc","signed_prekey_private":"spk-priv","signed_prekey":"spk-pub","recovery_codes":["one","two"],"vault_id":"vid-1"}"#.to_string()
    }

    #[test]
    fn decrypt_vault_round_trips_and_parses_fields() {
        let pass = b"vault-passphrase";
        let nonce = [21u8; 12];
        let (data, nonce_b64) = build_vault(sample_vault_json().as_bytes(), pass, &nonce);
        let vault = decrypt_vault(&data, &nonce_b64, pass).unwrap();
        assert_eq!(vault.identity_key, "ik-abc");
        assert_eq!(vault.signed_prekey_private.as_deref(), Some("spk-priv"));
        assert_eq!(vault.vault_id.as_deref(), Some("vid-1"));
        assert_eq!(vault.recovery_codes.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn decrypt_vault_minimal_json_round_trips() {
        let pass = b"p";
        let nonce = [1u8; 12];
        let json = r#"{"identity_key":"only-ik"}"#;
        let (data, nonce_b64) = build_vault(json.as_bytes(), pass, &nonce);
        let vault = decrypt_vault(&data, &nonce_b64, pass).unwrap();
        assert_eq!(vault.identity_key, "only-ik");
        assert!(vault.signed_prekey.is_none());
    }

    #[test]
    fn decrypt_vault_wrong_passphrase_fails_without_panic() {
        let nonce = [2u8; 12];
        let (data, nonce_b64) = build_vault(sample_vault_json().as_bytes(), b"right", &nonce);
        let err = decrypt_vault(&data, &nonce_b64, b"wrong");
        assert!(err.is_err());
    }

    #[test]
    fn decrypt_vault_tampered_ciphertext_fails_authentication() {
        let pass = b"p";
        let nonce = [3u8; 12];
        let (data, nonce_b64) = build_vault(sample_vault_json().as_bytes(), pass, &nonce);
        let mut raw = STANDARD.decode(&data).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        let tampered = STANDARD.encode(&raw);
        let err = decrypt_vault(&tampered, &nonce_b64, pass);
        assert!(err.is_err());
    }

    #[test]
    fn decrypt_vault_wrong_nonce_fails_authentication() {
        let pass = b"p";
        let nonce = [4u8; 12];
        let (data, _) = build_vault(sample_vault_json().as_bytes(), pass, &nonce);
        let other_nonce = STANDARD.encode([0u8; 12]);
        let err = decrypt_vault(&data, &other_nonce, pass);
        assert!(err.is_err());
    }

    #[test]
    fn decrypt_vault_short_data_is_rejected() {
        let short = STANDARD.encode([0u8; 8]);
        let nonce_b64 = STANDARD.encode([0u8; 12]);
        let err = decrypt_vault(&short, &nonce_b64, b"p");
        assert!(err.is_err());
    }

    #[test]
    fn decrypt_vault_non_twelve_byte_nonce_is_rejected() {
        let pass = b"p";
        let nonce = [5u8; 12];
        let (data, _) = build_vault(sample_vault_json().as_bytes(), pass, &nonce);
        let bad_nonce = STANDARD.encode([0u8; 8]);
        let err = decrypt_vault(&data, &bad_nonce, pass);
        assert!(err.is_err());
    }

    #[test]
    fn decrypt_vault_invalid_base64_errors_not_panic() {
        let nonce_b64 = STANDARD.encode([0u8; 12]);
        assert!(decrypt_vault("!!!not-base64", &nonce_b64, b"p").is_err());
    }

    const VECTOR_PASSWORD: &[u8] = b"correct horse battery staple";
    const VECTOR_NONCE: &str = "MDEyMzQ1Njc4OTo7";
    const VECTOR_DATA_KEK: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const VECTOR_600K_NO_AAD: &str = "EBESExQVFhcYGRobHB0eHzSa66nA+rHMINpdiOTpkjSCLhwwf3wsJL83mK7tmNaM7vJPzgxj+NUyvRlcWDdrwRNULF7InqurSUTICamu5KacrQS2IjGLyOnx9LZ0MC2EoKMAMr5335JJHdmKF1VwBXA=";
    const VECTOR_600K_AAD: &str = "EBESExQVFhcYGRobHB0eHzSa66nA+rHMINpdiOTpkjSCLhwwf3wsJL83mK7tmNaM7vJPzgxj+NUyvRlcWDdrwRNULF7InqurSUTICamu5KacrQS2IjGLyOnx9LZ0MC2EoHqqTrmesmoHLQ6kNpv6xHU=";
    const VECTOR_310K_NO_AAD: &str = "EBESExQVFhcYGRobHB0eH50xxkcJB5SCtgtwRihOGlJpA8baPelSa7kLsGCC/XD/WniEAFD+wtkjtM9nC5jHqjiir62dXVYDU2og79rnDzdr682La1IW1eHEi6OMTTtMkITkVo8ts1yICXjRFG6sx9o=";

    fn assert_vector_contents(vault: &VaultContents) {
        assert_eq!(vault.identity_key, "test");
        assert_eq!(vault.data_kek.as_deref(), Some(VECTOR_DATA_KEK));
    }

    #[test]
    fn vault_vector_600k_without_aad_decrypts() {
        let vault = decrypt_vault_with_iterations(
            VECTOR_600K_NO_AAD,
            VECTOR_NONCE,
            VECTOR_PASSWORD,
            Some(600_000),
        )
        .unwrap();
        assert_vector_contents(&vault);
    }

    #[test]
    fn vault_vector_600k_with_aad_decrypts() {
        let vault = decrypt_vault_with_iterations(
            VECTOR_600K_AAD,
            VECTOR_NONCE,
            VECTOR_PASSWORD,
            Some(600_000),
        )
        .unwrap();
        assert_vector_contents(&vault);
    }

    #[test]
    fn vault_vector_310k_decrypts_with_null_and_explicit_count() {
        let from_null =
            decrypt_vault_with_iterations(VECTOR_310K_NO_AAD, VECTOR_NONCE, VECTOR_PASSWORD, None)
                .unwrap();
        assert_vector_contents(&from_null);
        let explicit = decrypt_vault_with_iterations(
            VECTOR_310K_NO_AAD,
            VECTOR_NONCE,
            VECTOR_PASSWORD,
            Some(310_000),
        )
        .unwrap();
        assert_vector_contents(&explicit);
        assert_vector_contents(&decrypt_vault(VECTOR_310K_NO_AAD, VECTOR_NONCE, VECTOR_PASSWORD).unwrap());
    }

    #[test]
    fn vault_vector_600k_fails_at_default_count() {
        assert!(decrypt_vault_with_iterations(VECTOR_600K_NO_AAD, VECTOR_NONCE, VECTOR_PASSWORD, None).is_err());
    }

    #[test]
    fn vault_unknown_iteration_count_is_rejected() {
        assert!(vault_kdf_iterations(Some(12_345)).is_err());
        assert!(decrypt_vault_with_iterations(
            VECTOR_310K_NO_AAD,
            VECTOR_NONCE,
            VECTOR_PASSWORD,
            Some(12_345)
        )
        .is_err());
        assert_eq!(vault_kdf_iterations(None).unwrap(), 310_000);
        assert_eq!(vault_kdf_iterations(Some(600_000)).unwrap(), 600_000);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn seal_vault_with_iterations(
        plaintext: &[u8],
        passphrase: &[u8],
        iterations: u32,
    ) -> (String, String) {
        let salt: [u8; SALT_LEN] = rand::random();
        let nonce_bytes: [u8; 12] = rand::random();
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, iterations, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        key.zeroize();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .unwrap();
        let mut combined = salt.to_vec();
        combined.extend_from_slice(&ciphertext);
        (STANDARD.encode(&combined), STANDARD.encode(nonce_bytes))
    }
}
