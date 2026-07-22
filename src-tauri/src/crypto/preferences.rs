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

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{BridgeError, Result};

const PREFERENCES_KEY_SUFFIX: &str = "astermail-preferences-v1";

#[derive(Deserialize, Default, Clone)]
pub struct UserPreferences {
    pub theme: Option<String>,
    pub color_theme: Option<String>,
    pub accent_color: Option<String>,
    pub accent_color_hover: Option<String>,
    pub custom_theme_seed: Option<String>,
    #[serde(default)]
    pub custom_theme_overrides: HashMap<String, String>,
    pub font_choice: Option<String>,
    pub font_size_scale: Option<serde_json::Value>,
    pub reduce_motion: Option<bool>,
    pub compact_mode: Option<bool>,
    pub high_contrast: Option<bool>,
    pub reduce_transparency: Option<bool>,
    pub link_underlines: Option<bool>,
    pub dyslexia_font: Option<bool>,
    pub text_spacing: Option<bool>,
    pub color_vision_mode: Option<String>,
    pub toast_position: Option<String>,
}

fn derive_preferences_key(identity_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(identity_key.as_bytes());
    hasher.update(PREFERENCES_KEY_SUFFIX.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

pub fn decrypt_preferences(
    identity_key: &str,
    encrypted_b64: &str,
    nonce_b64: &str,
) -> Result<UserPreferences> {
    let ciphertext = STANDARD
        .decode(encrypted_b64)
        .map_err(|e| BridgeError::Crypto(format!("preferences data decode: {}", e)))?;

    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| BridgeError::Crypto(format!("preferences nonce decode: {}", e)))?;

    if nonce_bytes.len() != 12 {
        return Err(BridgeError::Crypto(
            "preferences nonce must be 12 bytes".to_string(),
        ));
    }

    let mut key = derive_preferences_key(identity_key);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| BridgeError::Crypto("preferences decrypt failed".to_string()))?;

    let mut prefs_json = String::from_utf8(plaintext)
        .map_err(|e| BridgeError::Crypto(format!("preferences utf8 decode: {}", e)))?;

    let parsed = serde_json::from_str(&prefs_json)
        .map_err(|e| BridgeError::Crypto(format!("preferences json parse: {}", e)));
    prefs_json.zeroize();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_for_test(identity_key: &str, plaintext: &[u8], nonce_bytes: &[u8; 12]) -> (String, String) {
        let key = derive_preferences_key(identity_key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
        (STANDARD.encode(&ciphertext), STANDARD.encode(nonce_bytes))
    }

    #[test]
    fn derive_key_matches_webcrypto_reference_vector() {
        let key = derive_preferences_key("identity-key-abc");
        assert_eq!(
            STANDARD.encode(key),
            "I9pIAqwb7ZiOm1W2BjFFZ+I08eCf7U3ebtocJ+bAgHU="
        );
    }

    #[test]
    fn decrypt_preferences_round_trips_theme_fields() {
        let json = r##"{"theme":"dark","color_theme":"emerald","accent_color":"#31d926","accent_color_hover":"#5ee050","custom_theme_seed":"#3b82f6","custom_theme_overrides":{"--bg-primary":"#010203"},"unrelated":42}"##;
        let (enc, nonce) = encrypt_for_test("ik-1", json.as_bytes(), &[7u8; 12]);
        let prefs = decrypt_preferences("ik-1", &enc, &nonce).unwrap();
        assert_eq!(prefs.theme.as_deref(), Some("dark"));
        assert_eq!(prefs.color_theme.as_deref(), Some("emerald"));
        assert_eq!(prefs.accent_color.as_deref(), Some("#31d926"));
        assert_eq!(prefs.custom_theme_overrides.get("--bg-primary").map(String::as_str), Some("#010203"));
    }

    #[test]
    fn decrypt_preferences_matches_real_webcrypto_ciphertext() {
        let identity_key = "test-identity-key-xyz";
        let enc = "YYPh5PxAWsh+DuDY8n7Fitk6rtzG1HAQWwhebe7gJx768wVeJMdmiremCVIebBCFhY/WXuSNnBAiNgocmQUTF1uSIieuWr/5huuchtgqQVJQf1WqjBeGQYNfOxzIN3qg2BEcIi2SptyNueNvjrYRy7G7KklNxmSuPPi0eCy/LJPcgV1A8Yq/j8B7nxa5BX8phFLaBUEBsiktVmiV+Tc6CyFi2rmup+zaKrgIV5aTNbEykyRfOzTD+nJ5qAsfNC/ooQ==";
        let nonce = "AAcOFRwjKjE4P0ZN";
        let prefs = decrypt_preferences(identity_key, enc, nonce).unwrap();
        assert_eq!(prefs.theme.as_deref(), Some("dark"));
        assert_eq!(prefs.color_theme.as_deref(), Some("custom"));
        assert_eq!(prefs.accent_color.as_deref(), Some("#a855f7"));
        assert_eq!(prefs.accent_color_hover.as_deref(), Some("#c084fc"));
        assert_eq!(prefs.custom_theme_seed.as_deref(), Some("#a855f7"));
        assert_eq!(
            prefs.custom_theme_overrides.get("--bg-primary").map(String::as_str),
            Some("#101014")
        );
    }

    #[test]
    fn decrypt_preferences_wrong_identity_key_fails() {
        let (enc, nonce) = encrypt_for_test("right", br#"{"theme":"dark"}"#, &[1u8; 12]);
        assert!(decrypt_preferences("wrong", &enc, &nonce).is_err());
    }

    #[test]
    fn decrypt_preferences_tampered_ciphertext_fails_authentication() {
        let (enc, nonce) = encrypt_for_test("ik", br#"{"theme":"light"}"#, &[2u8; 12]);
        let mut raw = STANDARD.decode(&enc).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        let tampered = STANDARD.encode(&raw);
        assert!(decrypt_preferences("ik", &tampered, &nonce).is_err());
    }

    #[test]
    fn decrypt_preferences_non_twelve_byte_nonce_rejected() {
        let (enc, _) = encrypt_for_test("ik", br#"{"theme":"dark"}"#, &[3u8; 12]);
        let bad_nonce = STANDARD.encode([0u8; 8]);
        assert!(decrypt_preferences("ik", &enc, &bad_nonce).is_err());
    }

    #[test]
    fn decrypt_preferences_invalid_base64_errors_not_panic() {
        let nonce = STANDARD.encode([0u8; 12]);
        assert!(decrypt_preferences("ik", "!!!not-base64", &nonce).is_err());
    }

    #[test]
    fn decrypt_preferences_missing_fields_default_to_none() {
        let (enc, nonce) = encrypt_for_test("ik", br#"{}"#, &[4u8; 12]);
        let prefs = decrypt_preferences("ik", &enc, &nonce).unwrap();
        assert!(prefs.theme.is_none());
        assert!(prefs.color_theme.is_none());
        assert!(prefs.custom_theme_overrides.is_empty());
    }
}
