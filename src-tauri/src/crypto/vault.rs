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
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BridgeError, Result};

const PBKDF2_ITERATIONS: u32 = 310_000;
const SALT_LEN: usize = 16;

#[derive(Deserialize, ZeroizeOnDrop)]
pub struct VaultContents {
    pub identity_key: String,
    pub signed_prekey_private: Option<String>,
    pub signed_prekey: Option<String>,
    pub recovery_codes: Option<Vec<String>>,
    pub vault_id: Option<String>,
}

pub fn decrypt_vault(
    encrypted_vault_b64: &str,
    vault_nonce_b64: &str,
    passphrase: &[u8],
) -> Result<VaultContents> {
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

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ITERATIONS, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
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
}
