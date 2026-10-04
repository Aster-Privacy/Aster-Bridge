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
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{BridgeError, Result};

const TAG_KEY_CONTEXT: &str = "astermail-tags-v1";
const NONCE_LEN: usize = 12;
const TOKEN_LEN: usize = 16;

fn derive_tag_key(identity_key: &str) -> Zeroizing<[u8; 32]> {
    let mut material = Vec::with_capacity(identity_key.len() + TAG_KEY_CONTEXT.len());
    material.extend_from_slice(identity_key.as_bytes());
    material.extend_from_slice(TAG_KEY_CONTEXT.as_bytes());
    let digest = Sha256::digest(&material);
    material.zeroize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    key
}

pub fn generate_tag_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; TOKEN_LEN];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

pub fn encrypt_tag_name(name: &str, identity_key: &str) -> Result<(String, String)> {
    use rand_core::{OsRng, RngCore};
    let key = derive_tag_key(identity_key);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), name.as_bytes())
        .map_err(|_| BridgeError::Crypto("tag name encrypt failed".to_string()))?;
    Ok((STANDARD.encode(ciphertext), STANDARD.encode(nonce_bytes)))
}

fn decrypt_with_key(ciphertext: &[u8], nonce: &[u8], identity_key: &str) -> Option<String> {
    let key = derive_tag_key(identity_key);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).ok()?;
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

pub fn decrypt_tag_name(
    encrypted_b64: &str,
    nonce_b64: &str,
    identity_key: &str,
    previous_keys: &[String],
) -> Option<String> {
    let ciphertext = STANDARD.decode(encrypted_b64.trim()).ok()?;
    let nonce = STANDARD.decode(nonce_b64.trim()).ok()?;
    if nonce.len() != NONCE_LEN {
        return None;
    }
    std::iter::once(identity_key)
        .chain(previous_keys.iter().map(|k| k.as_str()))
        .find_map(|k| decrypt_with_key(&ciphertext, &nonce, k))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB_IDENTITY_KEY: &str = "fixed-identity-key-for-tests";
    const WEB_CIPHERTEXT: &str = "yXbXWL1snjjvI6eMKespVJOgAhINnWcz1i1goP5mjfEX";
    const WEB_NONCE: &str = "AAECAwQFBgcICQoL";

    #[test]
    fn tag_names_round_trip() {
        let (enc, nonce) = encrypt_tag_name("Receipts ✓", "identity").unwrap();
        assert_eq!(decrypt_tag_name(&enc, &nonce, "identity", &[]).as_deref(), Some("Receipts ✓"));
        assert_eq!(decrypt_tag_name(&enc, &nonce, "other", &[]), None);
    }

    #[test]
    fn previous_keys_decrypt_names_from_before_a_rotation() {
        let (enc, nonce) = encrypt_tag_name("Travel", "old-key").unwrap();
        let previous = vec!["older".to_string(), "old-key".to_string()];
        assert_eq!(decrypt_tag_name(&enc, &nonce, "new-key", &previous).as_deref(), Some("Travel"));
    }

    #[test]
    fn decrypts_a_tag_name_encrypted_by_the_web_client() {
        let key = derive_tag_key(WEB_IDENTITY_KEY);
        let expected = Sha256::digest(b"fixed-identity-key-for-testsastermail-tags-v1");
        assert_eq!(key.as_slice(), expected.as_slice());
        assert_eq!(
            decrypt_tag_name(WEB_CIPHERTEXT, WEB_NONCE, WEB_IDENTITY_KEY, &[]).as_deref(),
            Some("Receipts ✓ 2025")
        );
    }

    #[test]
    fn folder_keys_do_not_decrypt_tag_names() {
        let (enc, nonce) = encrypt_tag_name("Work", "identity").unwrap();
        assert_eq!(crate::crypto::folder::decrypt_folder_name(&enc, &nonce, "identity", &[]), None);
    }

    #[test]
    fn tokens_are_sixteen_random_bytes() {
        let a = generate_tag_token();
        let b = generate_tag_token();
        assert_ne!(a, b);
        assert_eq!(STANDARD.decode(&a).unwrap().len(), 16);
    }
}
