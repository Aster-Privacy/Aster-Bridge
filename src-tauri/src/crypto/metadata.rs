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
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{BridgeError, Result};

const METADATA_INFO_PREFIX: &[u8] = b"aster-metadata-encryption-v1:";
const METADATA_SALT: &[u8] = b"aster-metadata-salt-v1";

fn derive_metadata_key(master_key: &[u8], context: &str) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(METADATA_INFO_PREFIX.len() + context.len());
    info.extend_from_slice(METADATA_INFO_PREFIX);
    info.extend_from_slice(context.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(METADATA_SALT), master_key);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| BridgeError::Crypto(format!("HKDF expand: {}", e)))?;

    Ok(okm)
}

pub fn decrypt_metadata(
    encrypted_data_b64: &str,
    nonce_b64: &str,
    master_key: &[u8],
    context: &str,
) -> Result<String> {
    let ciphertext = STANDARD
        .decode(encrypted_data_b64)
        .map_err(|e| BridgeError::Crypto(format!("data decode: {}", e)))?;

    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| BridgeError::Crypto(format!("nonce decode: {}", e)))?;

    if nonce_bytes.len() != 12 {
        return Err(BridgeError::Crypto("metadata nonce must be 12 bytes".to_string()));
    }

    let mut key = derive_metadata_key(master_key, context)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| BridgeError::Crypto("metadata decrypt failed".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| BridgeError::Crypto(format!("utf8 decode: {}", e)))
}

pub fn encrypt_metadata(
    plaintext: &str,
    master_key: &[u8],
    context: &str,
) -> Result<(String, String)> {
    use rand_core::OsRng;
    use rand_core::RngCore;

    let mut key = derive_metadata_key(master_key, context)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| BridgeError::Crypto("metadata encrypt failed".to_string()))?;

    let encrypted_b64 = STANDARD.encode(&ciphertext);
    let nonce_b64 = STANDARD.encode(&nonce_bytes);

    Ok((encrypted_b64, nonce_b64))
}
