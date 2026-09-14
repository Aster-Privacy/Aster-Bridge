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
use zeroize::Zeroize;

use crate::error::{BridgeError, Result};

const DRAFT_KEY_VERSION: &str = "astermail-draft-v2";
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

fn derive_draft_key(identity_key: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(identity_key.len() + DRAFT_KEY_VERSION.len());
    material.extend_from_slice(identity_key.as_bytes());
    material.extend_from_slice(DRAFT_KEY_VERSION.as_bytes());
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
    let ciphertext = STANDARD
        .decode(encrypted_b64)
        .map_err(|e| BridgeError::Crypto(format!("draft data decode: {}", e)))?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| BridgeError::Crypto(format!("draft nonce decode: {}", e)))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(BridgeError::Crypto("invalid draft nonce length".to_string()));
    }

    let mut key = derive_draft_key(identity_key);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

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

    #[test]
    fn draft_content_missing_fields_default() {
        let parsed: DraftContent = serde_json::from_str(r#"{"subject":"x"}"#).unwrap();
        assert_eq!(parsed.subject, "x");
        assert!(parsed.to_recipients.is_empty());
        assert!(parsed.attachments.is_none());
    }
}
