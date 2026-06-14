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
