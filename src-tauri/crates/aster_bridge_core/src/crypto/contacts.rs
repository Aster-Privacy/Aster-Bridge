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
use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BridgeError, Result};

pub const CONTACT_DATA_VERSION: u32 = 2;

const HMAC_INFO: &[u8] = b"contacts-hmac-v2";
const SEARCH_INFO: &[u8] = b"contacts-search-v2";
const MAX_CIPHERTEXT_LEN: usize = 1_048_576;

type HmacSha256 = Hmac<Sha256>;

pub struct EncryptedContact {
    pub encrypted_data: String,
    pub data_nonce: String,
    pub integrity_hash: String,
}

#[derive(ZeroizeOnDrop)]
pub struct ContactsKeys {
    data_kek: [u8; 32],
    hmac_key: [u8; 32],
    search_key: [u8; 32],
}

fn derive_sub_key(data_kek: &[u8], info: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data_kek);
    hasher.update(info);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hmac_base64(key: &[u8; 32], message: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    STANDARD.encode(mac.finalize().into_bytes())
}

impl ContactsKeys {
    pub fn from_data_kek_b64(data_kek_b64: &str) -> Result<Self> {
        let mut raw = STANDARD
            .decode(data_kek_b64)
            .map_err(|e| BridgeError::Crypto(format!("data_kek decode: {}", e)))?;

        if raw.len() != 32 {
            raw.zeroize();
            return Err(BridgeError::Crypto("data_kek must be 32 bytes".to_string()));
        }

        let mut data_kek = [0u8; 32];
        data_kek.copy_from_slice(&raw);
        raw.zeroize();

        let hmac_key = derive_sub_key(&data_kek, HMAC_INFO);
        let search_key = derive_sub_key(&data_kek, SEARCH_INFO);

        Ok(Self {
            data_kek,
            hmac_key,
            search_key,
        })
    }

    pub fn integrity_hash(&self, encrypted_data: &str, data_nonce: &str, version: u32) -> String {
        let message = format!("{}:{}:{}", encrypted_data, data_nonce, version);
        hmac_base64(&self.hmac_key, message.as_bytes())
    }

    pub fn verify_integrity_hash(
        &self,
        encrypted_data: &str,
        data_nonce: &str,
        version: u32,
        expected: &str,
    ) -> bool {
        let computed = self.integrity_hash(encrypted_data, data_nonce, version);
        computed.as_bytes().ct_eq(expected.as_bytes()).into()
    }

    pub fn search_token(&self, value: &str) -> String {
        let normalized = value.to_lowercase();
        hmac_base64(&self.search_key, normalized.trim().as_bytes())
    }

    pub fn contact_token(&self, first_name: &str, last_name: &str, emails: &[String]) -> String {
        let searchable =
            format!("{} {} {}", first_name, last_name, emails.join(" ")).to_lowercase();
        hmac_base64(&self.hmac_key, searchable.as_bytes())
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        Aes256Gcm::new_from_slice(&self.data_kek)
            .map_err(|e| BridgeError::Crypto(format!("contacts cipher init: {}", e)))
    }

    pub fn decrypt_data(&self, encrypted_data_b64: &str, data_nonce_b64: &str) -> Result<Value> {
        let ciphertext = STANDARD
            .decode(encrypted_data_b64)
            .map_err(|e| BridgeError::Crypto(format!("contact data decode: {}", e)))?;

        if ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(BridgeError::Crypto("contact data too large".to_string()));
        }

        let nonce_bytes = STANDARD
            .decode(data_nonce_b64)
            .map_err(|e| BridgeError::Crypto(format!("contact nonce decode: {}", e)))?;

        if nonce_bytes.len() != 12 {
            return Err(BridgeError::Crypto(
                "contact nonce must be 12 bytes".to_string(),
            ));
        }

        let plaintext = self
            .cipher()?
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .map_err(|_| BridgeError::Crypto("contact decrypt failed".to_string()))?;

        let mut json = String::from_utf8(plaintext)
            .map_err(|e| BridgeError::Crypto(format!("contact utf8 decode: {}", e)))?;

        let parsed: std::result::Result<Value, _> = serde_json::from_str(&json);
        json.zeroize();

        let mut value =
            parsed.map_err(|e| BridgeError::Crypto(format!("contact json parse: {}", e)))?;

        if let Some(object) = value.as_object_mut() {
            object.remove("_version");
            object.remove("_encrypted_at");
        }

        Ok(value)
    }

    pub fn encrypt_data(&self, data: &Value) -> Result<EncryptedContact> {
        let mut object: Map<String, Value> = match data {
            Value::Object(map) => map.clone(),
            _ => {
                return Err(BridgeError::Crypto(
                    "contact payload must be an object".to_string(),
                ))
            }
        };

        object.insert("_version".to_string(), Value::from(CONTACT_DATA_VERSION));
        object.insert(
            "_encrypted_at".to_string(),
            Value::from(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
        );

        let mut plaintext = serde_json::to_vec(&Value::Object(object))
            .map_err(|e| BridgeError::Crypto(format!("contact json encode: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let ciphertext = self
            .cipher()?
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
            .map_err(|_| BridgeError::Crypto("contact encrypt failed".to_string()))?;
        plaintext.zeroize();

        let encrypted_data = STANDARD.encode(&ciphertext);
        let data_nonce = STANDARD.encode(nonce_bytes);
        let integrity_hash = self.integrity_hash(&encrypted_data, &data_nonce, CONTACT_DATA_VERSION);

        Ok(EncryptedContact {
            encrypted_data,
            data_nonce,
            integrity_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> ContactsKeys {
        ContactsKeys::from_data_kek_b64(&STANDARD.encode([7u8; 32])).unwrap()
    }

    #[test]
    fn rejects_data_kek_of_wrong_length() {
        let err = ContactsKeys::from_data_kek_b64(&STANDARD.encode([1u8; 16]))
            .err()
            .unwrap();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn round_trips_contact_payload_without_internal_fields() {
        let keys = test_keys();
        let payload = serde_json::json!({
            "first_name": "Ada",
            "last_name": "Lovelace",
            "emails": ["ada@example.com"],
        });

        let sealed = keys.encrypt_data(&payload).unwrap();
        let opened = keys
            .decrypt_data(&sealed.encrypted_data, &sealed.data_nonce)
            .unwrap();

        assert_eq!(opened, payload);
        assert!(opened.get("_version").is_none());
        assert!(opened.get("_encrypted_at").is_none());
    }

    #[test]
    fn integrity_hash_binds_ciphertext_nonce_and_version() {
        let keys = test_keys();
        let sealed = keys
            .encrypt_data(&serde_json::json!({ "first_name": "Ada" }))
            .unwrap();

        assert!(keys.verify_integrity_hash(
            &sealed.encrypted_data,
            &sealed.data_nonce,
            CONTACT_DATA_VERSION,
            &sealed.integrity_hash,
        ));
        assert!(!keys.verify_integrity_hash(
            &sealed.encrypted_data,
            &sealed.data_nonce,
            CONTACT_DATA_VERSION + 1,
            &sealed.integrity_hash,
        ));
        assert!(!keys.verify_integrity_hash(
            "tampered",
            &sealed.data_nonce,
            CONTACT_DATA_VERSION,
            &sealed.integrity_hash,
        ));
    }

    #[test]
    fn rejects_nonce_that_is_not_twelve_bytes() {
        let keys = test_keys();
        let sealed = keys
            .encrypt_data(&serde_json::json!({ "first_name": "Ada" }))
            .unwrap();
        let err = keys
            .decrypt_data(&sealed.encrypted_data, &STANDARD.encode([0u8; 16]))
            .unwrap_err();

        assert!(err.to_string().contains("12 bytes"));
    }

    #[test]
    fn search_tokens_normalize_case_and_whitespace() {
        let keys = test_keys();

        assert_eq!(
            keys.search_token("  Ada@Example.COM "),
            keys.search_token("ada@example.com")
        );
        assert_ne!(
            keys.search_token("ada@example.com"),
            keys.search_token("bob@example.com")
        );
    }

    #[test]
    fn contact_token_matches_the_web_client_shape() {
        let keys = test_keys();
        let emails = vec!["Ada@example.com".to_string()];
        let expected = hmac_base64(
            &derive_sub_key(&[7u8; 32], HMAC_INFO),
            b"ada lovelace ada@example.com",
        );

        assert_eq!(keys.contact_token("Ada", "Lovelace", &emails), expected);
    }

    #[test]
    fn sub_keys_are_domain_separated() {
        assert_ne!(
            derive_sub_key(&[7u8; 32], HMAC_INFO),
            derive_sub_key(&[7u8; 32], SEARCH_INFO)
        );
    }
}
