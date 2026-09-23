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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::account_key::{context_keys, AccountKey, DRAFT_CONTEXT};
use crate::error::{BridgeError, Result};

const DRAFT_KEY_VERSION: &str = "astermail-draft-v2";
const LEGACY_DRAFT_KEY_VERSION: &str = "astermail-draft-v1";
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftAttachment {
    pub id: String,
    pub name: String,
    pub size: String,
    pub size_bytes: i64,
    pub mime_type: String,
    pub data_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DraftContent {
    #[serde(default)]
    pub to_recipients: Vec<String>,
    #[serde(default)]
    pub cc_recipients: Vec<String>,
    #[serde(default)]
    pub bcc_recipients: Vec<String>,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<DraftAttachment>>,
}

pub struct DraftKeys<'a> {
    pub identity_key: &'a str,
    pub previous_keys: &'a [String],
    pub account_keys: &'a [AccountKey],
    pub passphrase: &'a [u8],
}

fn derive_draft_key(identity_key: &str) -> [u8; 32] {
    derive_versioned_draft_key(identity_key, DRAFT_KEY_VERSION)
}

fn derive_versioned_draft_key(identity_key: &str, version: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(identity_key.len() + version.len());
    material.extend_from_slice(identity_key.as_bytes());
    material.extend_from_slice(version.as_bytes());
    let digest = Sha256::digest(&material);
    material.zeroize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

pub fn encrypt_draft_content(content: &DraftContent, identity_key: &str) -> Result<(String, String)> {
    use rand_core::{OsRng, RngCore};

    let plaintext = serde_json::to_string(content)
        .map_err(|e| BridgeError::Crypto(format!("draft serialize: {}", e)))?;

    let mut key = derive_draft_key(identity_key);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| BridgeError::Crypto("draft encrypt failed".to_string()))?;

    Ok((STANDARD.encode(&ciphertext), STANDARD.encode(nonce_bytes)))
}

pub fn decrypt_draft_content(
    encrypted_b64: &str,
    nonce_b64: &str,
    identity_key: &str,
) -> Result<DraftContent> {
    let mut key = derive_draft_key(identity_key);
    let result = decrypt_draft_content_with_key(encrypted_b64, nonce_b64, &key);
    key.zeroize();
    result
}

pub fn decrypt_draft_content_with_keys(
    encrypted_b64: &str,
    nonce_b64: &str,
    keys: &DraftKeys<'_>,
) -> Result<DraftContent> {
    let first = decrypt_draft_content(encrypted_b64, nonce_b64, keys.identity_key);
    if first.is_ok() {
        return first;
    }
    for previous_key in keys.previous_keys.iter() {
        for version in [DRAFT_KEY_VERSION, LEGACY_DRAFT_KEY_VERSION] {
            let mut key = derive_versioned_draft_key(previous_key, version);
            let result = decrypt_draft_content_with_key(encrypted_b64, nonce_b64, &key);
            key.zeroize();
            if result.is_ok() {
                return result;
            }
        }
    }
    for key in context_keys(keys.account_keys, DRAFT_CONTEXT) {
        if let Ok(content) = decrypt_draft_content_with_key(encrypted_b64, nonce_b64, &key) {
            return Ok(content);
        }
    }
    if let Ok(content) = decrypt_draft_envelope(encrypted_b64, nonce_b64, keys) {
        return Ok(content);
    }
    first
}

fn decrypt_draft_envelope(
    encrypted_b64: &str,
    nonce_b64: &str,
    keys: &DraftKeys<'_>,
) -> Result<DraftContent> {
    if nonce_b64.is_empty() && !is_armored_pgp_b64(encrypted_b64) {
        return Err(BridgeError::Crypto("draft envelope is not encrypted".to_string()));
    }
    let plaintext = Zeroizing::new(crate::crypto::envelope::decrypt_envelope_with_previous_keys(
        encrypted_b64,
        Some(nonce_b64),
        keys.passphrase,
        Some(keys.identity_key),
        keys.previous_keys,
        &[],
    )?);
    let value: serde_json::Value = serde_json::from_str(&plaintext)
        .map_err(|e| BridgeError::Crypto(format!("draft json parse: {}", e)))?;
    if !value.is_object() {
        return Err(BridgeError::Crypto("draft envelope is not an object".to_string()));
    }
    Ok(draft_content_from_value(&value))
}

fn is_armored_pgp_b64(encrypted_b64: &str) -> bool {
    STANDARD
        .decode(encrypted_b64)
        .map(|bytes| bytes.starts_with(b"-----BEGIN PGP MESSAGE-----"))
        .unwrap_or(false)
}

fn address_list(value: Option<&serde_json::Value>) -> Vec<String> {
    let Some(entries) = value.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| match entry {
            serde_json::Value::String(s) => Some(s.trim().to_string()),
            serde_json::Value::Object(o) => o
                .get("email")
                .and_then(|e| e.as_str())
                .map(|e| e.trim().to_string()),
            _ => None,
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn first_string(value: &serde_json::Value, keys: &[&str]) -> String {
    keys.iter()
        .filter_map(|key| value.get(*key).and_then(|v| v.as_str()))
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn draft_content_from_value(value: &serde_json::Value) -> DraftContent {
    let pick = |primary: &str, alias: &str| value.get(primary).or_else(|| value.get(alias));
    DraftContent {
        to_recipients: address_list(pick("to_recipients", "to")),
        cc_recipients: address_list(pick("cc_recipients", "cc")),
        bcc_recipients: address_list(pick("bcc_recipients", "bcc")),
        subject: first_string(value, &["subject"]),
        message: first_string(
            value,
            &["message", "body_html", "html_body", "body_text", "text_body"],
        ),
        attachments: value
            .get("attachments")
            .and_then(|a| serde_json::from_value(a.clone()).ok()),
    }
}

fn decrypt_draft_content_with_key(
    encrypted_b64: &str,
    nonce_b64: &str,
    key: &[u8; 32],
) -> Result<DraftContent> {
    let ciphertext = STANDARD
        .decode(encrypted_b64)
        .map_err(|e| BridgeError::Crypto(format!("draft data decode: {}", e)))?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| BridgeError::Crypto(format!("draft nonce decode: {}", e)))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(BridgeError::Crypto("invalid draft nonce length".to_string()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| BridgeError::Crypto("draft decrypt failed".to_string()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| BridgeError::Crypto(format!("draft json parse: {}", e)))
}

pub fn draft_content_hash(encrypted_b64: &str) -> String {
    STANDARD.encode(Sha256::digest(encrypted_b64.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_content() -> DraftContent {
        DraftContent {
            to_recipients: vec!["a@example.com".to_string()],
            cc_recipients: vec!["b@example.com".to_string()],
            bcc_recipients: vec![],
            subject: "Hello".to_string(),
            message: "<p>Body</p>".to_string(),
            attachments: None,
        }
    }

    #[test]
    fn draft_content_round_trips() {
        let content = sample_content();
        let (enc, nonce) = encrypt_draft_content(&content, "test-identity-key").unwrap();
        let out = decrypt_draft_content(&enc, &nonce, "test-identity-key").unwrap();
        assert_eq!(out.subject, "Hello");
        assert_eq!(out.to_recipients, vec!["a@example.com"]);
        assert_eq!(out.cc_recipients, vec!["b@example.com"]);
        assert_eq!(out.message, "<p>Body</p>");
    }

    #[test]
    fn draft_decrypt_wrong_key_fails() {
        let content = sample_content();
        let (enc, nonce) = encrypt_draft_content(&content, "key-one").unwrap();
        assert!(decrypt_draft_content(&enc, &nonce, "key-two").is_err());
    }

    #[test]
    fn draft_key_matches_web_derivation() {
        let key = derive_draft_key("ik");
        let expected = Sha256::digest("ikastermail-draft-v2".as_bytes());
        assert_eq!(key.as_slice(), expected.as_slice());
    }

    #[test]
    fn draft_json_field_names_match_web() {
        let content = sample_content();
        let json = serde_json::to_value(&content).unwrap();
        assert!(json.get("to_recipients").is_some());
        assert!(json.get("cc_recipients").is_some());
        assert!(json.get("bcc_recipients").is_some());
        assert!(json.get("subject").is_some());
        assert!(json.get("message").is_some());
        assert!(json.get("attachments").is_none());
    }

    const PASS: &str = "vault passphrase 7";

    fn keys<'a>(identity_key: &'a str, previous_keys: &'a [String]) -> DraftKeys<'a> {
        DraftKeys {
            identity_key,
            previous_keys,
            account_keys: &[],
            passphrase: PASS.as_bytes(),
        }
    }

    fn encrypt_with(key: &[u8; 32], plaintext: &[u8]) -> (String, String) {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = [9u8; NONCE_LEN];
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).unwrap();
        (STANDARD.encode(ct), STANDARD.encode(nonce))
    }

    #[test]
    fn drafts_open_with_previous_identity_keys_in_both_versions() {
        let previous = vec!["old-ik".to_string()];
        let (enc, nonce) = encrypt_draft_content(&sample_content(), "old-ik").unwrap();
        assert!(decrypt_draft_content(&enc, &nonce, "new-ik").is_err());
        let out = decrypt_draft_content_with_keys(&enc, &nonce, &keys("new-ik", &previous)).unwrap();
        assert_eq!(out.subject, "Hello");

        let v1_key = derive_versioned_draft_key("old-ik", LEGACY_DRAFT_KEY_VERSION);
        let (enc, nonce) = encrypt_with(&v1_key, br#"{"subject":"v1 draft"}"#);
        let out = decrypt_draft_content_with_keys(&enc, &nonce, &keys("new-ik", &previous)).unwrap();
        assert_eq!(out.subject, "v1 draft");
        assert!(decrypt_draft_content_with_keys(&enc, &nonce, &keys("new-ik", &[])).is_err());
    }

    #[test]
    fn current_identity_key_wins_over_previous_keys() {
        let previous = vec!["old-ik".to_string()];
        let (enc, nonce) = encrypt_draft_content(&sample_content(), "new-ik").unwrap();
        let out = decrypt_draft_content_with_keys(&enc, &nonce, &keys("new-ik", &previous)).unwrap();
        assert_eq!(out.message, "<p>Body</p>");
    }

    #[test]
    fn pgp_sealed_draft_opens_with_a_protected_key() {
        let owner = crate::crypto::account_key::tests::protected_keypair(PASS);
        let owner_armored = owner.to_armored().unwrap();
        let payload = serde_json::json!({
            "to": [{"email": " a@example.com ", "name": "A"}, "b@example.com", 5],
            "cc_recipients": ["c@example.com"],
            "subject": "sealed",
            "body_html": "<p>hi</p>",
        })
        .to_string();
        let armored =
            aster_crypto::encrypt_message(payload.as_bytes(), &[&owner.public_key()]).unwrap();
        let enc = STANDARD.encode(armored);

        let out = decrypt_draft_content_with_keys(&enc, "", &keys(&owner_armored, &[])).unwrap();
        assert_eq!(out.to_recipients, vec!["a@example.com", "b@example.com"]);
        assert_eq!(out.cc_recipients, vec!["c@example.com"]);
        assert_eq!(out.subject, "sealed");
        assert_eq!(out.message, "<p>hi</p>");

        let wrong = DraftKeys {
            passphrase: b"wrong",
            ..keys(&owner_armored, &[])
        };
        assert!(decrypt_draft_content_with_keys(&enc, "", &wrong).is_err());
    }

    #[test]
    fn unencrypted_draft_payload_is_rejected() {
        let enc = STANDARD.encode(br#"{"subject":"planted"}"#);
        assert!(decrypt_draft_content_with_keys(&enc, "", &keys("ik", &[])).is_err());
        let enc = STANDARD.encode(br#""just a string""#);
        assert!(decrypt_draft_content_with_keys(&enc, "", &keys("ik", &[])).is_err());
    }

    #[test]
    fn password_sealed_draft_opens_through_the_envelope_path() {
        let sealed = crate::crypto::envelope::encrypt_pbkdf2_envelope(
            r#"{"subject":"sealed with pass"}"#,
            PASS.as_bytes(),
        )
        .unwrap();
        let marker = crate::crypto::envelope::pbkdf2_envelope_nonce_marker();
        let out = decrypt_draft_content_with_keys(&sealed, &marker, &keys("ik", &[])).unwrap();
        assert_eq!(out.subject, "sealed with pass");
        let wrong = DraftKeys {
            passphrase: b"wrong",
            ..keys("ik", &[])
        };
        assert!(decrypt_draft_content_with_keys(&sealed, &marker, &wrong).is_err());
    }

    #[test]
    fn draft_content_missing_fields_default() {
        let parsed: DraftContent = serde_json::from_str(r#"{"subject":"x"}"#).unwrap();
        assert_eq!(parsed.subject, "x");
        assert!(parsed.to_recipients.is_empty());
        assert!(parsed.attachments.is_none());
    }
}
