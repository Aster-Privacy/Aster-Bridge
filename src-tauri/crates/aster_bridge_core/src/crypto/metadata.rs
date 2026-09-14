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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let master_key = [11u8; 32];
        let plaintext = r#"{"from":"a@b.com","subject":"hi"}"#;
        let (ct, nonce) = encrypt_metadata(plaintext, &master_key, "envelope").unwrap();
        let out = decrypt_metadata(&ct, &nonce, &master_key, "envelope").unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let master_key = [1u8; 32];
        let (ct, nonce) = encrypt_metadata("", &master_key, "ctx").unwrap();
        let out = decrypt_metadata(&ct, &nonce, &master_key, "ctx").unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn nonce_is_twelve_bytes_and_random_per_call() {
        let master_key = [2u8; 32];
        let (_, nonce_a) = encrypt_metadata("same", &master_key, "ctx").unwrap();
        let (_, nonce_b) = encrypt_metadata("same", &master_key, "ctx").unwrap();
        assert_eq!(STANDARD.decode(&nonce_a).unwrap().len(), 12);
        assert_ne!(nonce_a, nonce_b);
    }

    #[test]
    fn wrong_master_key_fails_without_panic() {
        let (ct, nonce) = encrypt_metadata("secret", &[3u8; 32], "ctx").unwrap();
        let err = decrypt_metadata(&ct, &nonce, &[4u8; 32], "ctx");
        assert!(err.is_err());
    }

    #[test]
    fn wrong_context_fails_authentication() {
        let master_key = [5u8; 32];
        let (ct, nonce) = encrypt_metadata("secret", &master_key, "subject").unwrap();
        let err = decrypt_metadata(&ct, &nonce, &master_key, "sender");
        assert!(err.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let master_key = [6u8; 32];
        let (ct, nonce) = encrypt_metadata("authentic", &master_key, "ctx").unwrap();
        let mut raw = STANDARD.decode(&ct).unwrap();
        raw[0] ^= 0xff;
        let tampered = STANDARD.encode(&raw);
        let err = decrypt_metadata(&tampered, &nonce, &master_key, "ctx");
        assert!(err.is_err());
    }

    #[test]
    fn wrong_nonce_fails_authentication() {
        let master_key = [7u8; 32];
        let (ct, _) = encrypt_metadata("payload", &master_key, "ctx").unwrap();
        let other_nonce = STANDARD.encode([0u8; 12]);
        let err = decrypt_metadata(&ct, &other_nonce, &master_key, "ctx");
        assert!(err.is_err());
    }

    #[test]
    fn non_twelve_byte_nonce_is_rejected() {
        let master_key = [8u8; 32];
        let (ct, _) = encrypt_metadata("payload", &master_key, "ctx").unwrap();
        let short_nonce = STANDARD.encode([0u8; 8]);
        let err = decrypt_metadata(&ct, &short_nonce, &master_key, "ctx");
        assert!(err.is_err());
    }

    #[test]
    fn invalid_base64_inputs_error_not_panic() {
        let master_key = [9u8; 32];
        assert!(decrypt_metadata("!!!notb64", "AAAA", &master_key, "ctx").is_err());
    }

    #[test]
    fn derive_metadata_key_deterministic_and_context_separated() {
        let mk = [10u8; 32];
        let a = derive_metadata_key(&mk, "subject").unwrap();
        let a_again = derive_metadata_key(&mk, "subject").unwrap();
        let b = derive_metadata_key(&mk, "body").unwrap();
        assert_eq!(a, a_again);
        assert_ne!(a, b);
    }
}
