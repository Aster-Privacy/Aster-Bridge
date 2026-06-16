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
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{BridgeError, Result};

const DERIVED_KEY_INFO: &[u8] = b"aster-storage-encryption-key-v1";
const SALT_DERIVATION_PREFIX: &[u8] = b"aster-hkdf-salt-v1:";
const ALIAS_HMAC_INFO: &[u8] = b"astermail-alias-hmac-v1";
const DOMAIN_HMAC_INFO: &[u8] = b"astermail-domain-address-hmac-v1";

type HmacSha256 = Hmac<Sha256>;

// Mirrors the web client's derive_encryption_key_from_passphrase
// (Aster-Mail/src/services/crypto/memory_key_store.ts):
//   salt = SHA-256("aster-hkdf-salt-v1:" || passphrase)
//   key  = HKDF-SHA256(ikm = passphrase, salt, info = "aster-storage-encryption-key-v1", len = 32)
pub fn derive_storage_key(passphrase: &[u8]) -> [u8; 32] {
    let mut salt_input = Vec::with_capacity(SALT_DERIVATION_PREFIX.len() + passphrase.len());
    salt_input.extend_from_slice(SALT_DERIVATION_PREFIX);
    salt_input.extend_from_slice(passphrase);
    let salt = Sha256::digest(&salt_input);
    salt_input.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(&salt), passphrase);
    let mut okm = [0u8; 32];
    hk.expand(DERIVED_KEY_INFO, &mut okm)
        .expect("hkdf expand to 32 bytes never fails");
    okm
}

// Mirrors get_alias_hmac_key / get_domain_hmac_key:
//   hmac_key = SHA-256(derived_key || info)
fn hmac_key_from(derived_key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(derived_key.len() + info.len());
    buf.extend_from_slice(derived_key);
    buf.extend_from_slice(info);
    let out = Sha256::digest(&buf);
    buf.zeroize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

// Alias normalization (normalize_local_part): lowercase + strip ALL dots.
// Domain is NOT lowercased in the alias path (matches compute_alias_hash).
fn normalize_local_part(local_part: &str) -> String {
    local_part.to_lowercase().replace('.', "")
}

// AES-256-GCM decrypt of a base64 ciphertext + base64 nonce using the derived key.
fn aes_gcm_decrypt(derived_key: &[u8; 32], encrypted_b64: &str, nonce_b64: &str) -> Result<String> {
    let ciphertext = STANDARD
        .decode(encrypted_b64)
        .map_err(|e| BridgeError::Crypto(format!("alias ciphertext decode: {}", e)))?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| BridgeError::Crypto(format!("alias nonce decode: {}", e)))?;
    if nonce_bytes.len() != 12 {
        return Err(BridgeError::Crypto("alias nonce must be 12 bytes".to_string()));
    }

    let cipher = Aes256Gcm::new_from_slice(derived_key)
        .map_err(|e| BridgeError::Crypto(format!("alias cipher init: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| BridgeError::Crypto("alias field decrypt failed".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| BridgeError::Crypto(format!("alias field utf8 decode: {}", e)))
}

// Mirrors decrypt_alias (aliases.ts): random aliases store the local part as
// plain base64; non-random aliases store AES-GCM(derived_key, nonce, local_part).
pub fn decrypt_alias_local_part(
    derived_key: &[u8; 32],
    encrypted_local_part: &str,
    local_part_nonce: &str,
    is_random: bool,
) -> Result<String> {
    if is_random {
        let raw = STANDARD
            .decode(encrypted_local_part)
            .map_err(|e| BridgeError::Crypto(format!("random alias decode: {}", e)))?;
        return String::from_utf8(raw)
            .map_err(|e| BridgeError::Crypto(format!("random alias utf8 decode: {}", e)));
    }
    aes_gcm_decrypt(derived_key, encrypted_local_part, local_part_nonce)
}

// Mirrors decrypt_address_field (domains.ts) for the custom-domain local part.
pub fn decrypt_domain_local_part(
    derived_key: &[u8; 32],
    encrypted_local_part: &str,
    local_part_nonce: &str,
) -> Result<String> {
    aes_gcm_decrypt(derived_key, encrypted_local_part, local_part_nonce)
}

// Optional display name field (AES-GCM with the derived key), used by both
// aliases and custom-domain addresses.
pub fn decrypt_display_name(
    derived_key: &[u8; 32],
    encrypted_display_name: &str,
    display_name_nonce: &str,
) -> Result<String> {
    aes_gcm_decrypt(derived_key, encrypted_display_name, display_name_nonce)
}

// Mirrors compute_alias_hash (aliases.ts):
//   HMAC-SHA256(key = SHA-256(derived_key || "astermail-alias-hmac-v1"),
//               data = normalize(local) + "@" + domain)
// Result is base64. Note: domain is NOT lowercased here (matches the web client).
pub fn compute_alias_hash(derived_key: &[u8; 32], local_part: &str, domain: &str) -> String {
    let key = hmac_key_from(derived_key, ALIAS_HMAC_INFO);
    let full = format!("{}@{}", normalize_local_part(local_part), domain);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("hmac key any length");
    mac.update(full.as_bytes());
    let sig = mac.finalize().into_bytes();
    STANDARD.encode(sig)
}

// Mirrors compute_address_hash (domains.ts):
//   HMAC-SHA256(key = SHA-256(derived_key || "astermail-domain-address-hmac-v1"),
//               data = normalize(local) + "@" + lower(domain))
// Result is base64. The domain IS lowercased here (differs from the alias path).
pub fn compute_address_hash(derived_key: &[u8; 32], local_part: &str, domain: &str) -> String {
    let key = hmac_key_from(derived_key, DOMAIN_HMAC_INFO);
    let full = format!("{}@{}", normalize_local_part(local_part), domain.to_lowercase());
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("hmac key any length");
    mac.update(full.as_bytes());
    let sig = mac.finalize().into_bytes();
    STANDARD.encode(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors reproduced from the web crypto primitives so the Rust
    // derivations stay byte-compatible with Aster-Mail. They were computed with
    // an independent implementation of the same primitives (hashlib + HKDF):
    //   passphrase = "test-passphrase"
    //   salt = SHA-256("aster-hkdf-salt-v1:test-passphrase")
    //   derived_key = HKDF-SHA256(ikm=passphrase, salt, info="aster-storage-encryption-key-v1", 32)
    const DERIVED_HEX: &str =
        "9a673e49ba2cc1c95f2456187621d2a25b9e8eb5f73d08bd170008f059d2b87e";
    // compute_alias_hash(derived, "sales", "example.com")
    const ALIAS_HASH_B64: &str = "srW342dPE8iQJE7+d7YE5SQafrZ0dIAGqyA1Kr73uG4=";
    // compute_address_hash(derived, "sales", "example.com")
    const DOMAIN_HASH_B64: &str = "9DdpThKJKsXdVFOScGxeo9YG1CLVI1pEDoJXwmeJ8A4=";

    fn derived() -> [u8; 32] {
        derive_storage_key(b"test-passphrase")
    }

    #[test]
    fn derive_storage_key_is_deterministic() {
        let a = derive_storage_key(b"hello");
        let b = derive_storage_key(b"hello");
        assert_eq!(a, b);
        let c = derive_storage_key(b"world");
        assert_ne!(a, c);
    }

    #[test]
    fn derive_storage_key_matches_known_vector() {
        let key = derive_storage_key(b"test-passphrase");
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, DERIVED_HEX);
    }

    #[test]
    fn alias_hash_matches_known_vector() {
        let key = derived();
        let h = compute_alias_hash(&key, "sales", "example.com");
        assert_eq!(h, ALIAS_HASH_B64);
    }

    #[test]
    fn domain_hash_matches_known_vector() {
        let key = derived();
        let h = compute_address_hash(&key, "sales", "example.com");
        assert_eq!(h, DOMAIN_HASH_B64);
    }

    #[test]
    fn alias_hash_is_base64_and_stable() {
        let key = derived();
        let h1 = compute_alias_hash(&key, "Hello.World", "astermail.org");
        let h2 = compute_alias_hash(&key, "helloworld", "astermail.org");
        // normalize strips dots + lowercases, so these must be equal.
        assert_eq!(h1, h2);
        assert!(STANDARD.decode(&h1).is_ok());
        assert_eq!(STANDARD.decode(&h1).unwrap().len(), 32);
    }

    #[test]
    fn domain_hash_lowercases_domain() {
        let key = derived();
        let h1 = compute_address_hash(&key, "sales", "Example.COM");
        let h2 = compute_address_hash(&key, "sales", "example.com");
        assert_eq!(h1, h2);
    }

    #[test]
    fn alias_and_domain_hash_differ_for_same_input() {
        let key = derived();
        let a = compute_alias_hash(&key, "sales", "example.com");
        let d = compute_address_hash(&key, "sales", "example.com");
        // Different HMAC info strings -> different keys -> different output.
        assert_ne!(a, d);
    }

    #[test]
    fn aes_gcm_round_trip() {
        let key = derived();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [7u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, b"my-alias".as_ref()).unwrap();
        let enc_b64 = STANDARD.encode(&ct);
        let nonce_b64 = STANDARD.encode(nonce_bytes);
        let out = decrypt_alias_local_part(&key, &enc_b64, &nonce_b64, false).unwrap();
        assert_eq!(out, "my-alias");
    }

    #[test]
    fn random_alias_is_plain_base64() {
        let key = derived();
        let enc = STANDARD.encode(b"rand123");
        let out = decrypt_alias_local_part(&key, &enc, "", true).unwrap();
        assert_eq!(out, "rand123");
    }

    #[test]
    fn aes_gcm_wrong_nonce_fails() {
        let key = derived();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&[1u8; 12]);
        let ct = cipher.encrypt(nonce, b"x".as_ref()).unwrap();
        let enc_b64 = STANDARD.encode(&ct);
        let bad_nonce = STANDARD.encode([9u8; 12]);
        assert!(decrypt_alias_local_part(&key, &enc_b64, &bad_nonce, false).is_err());
    }
}
