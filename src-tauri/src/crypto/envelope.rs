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

const PBKDF2_ITERATIONS: u32 = 310_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

const ENVELOPE_VERSIONS: &[&str] = &["astermail-envelope-v1", "astermail-import-v1"];

pub fn decrypt_envelope(
    encrypted_data_b64: &str,
    nonce_b64: Option<&str>,
    passphrase: &[u8],
    identity_key: Option<&str>,
) -> Result<String> {
    let nonce_bytes = match nonce_b64 {
        Some(n) if !n.is_empty() => STANDARD
            .decode(n)
            .map_err(|e| BridgeError::Crypto(format!("nonce decode: {}", e)))?,
        _ => Vec::new(),
    };

    if nonce_bytes.is_empty() {
        return decrypt_pgp_or_plaintext(encrypted_data_b64, identity_key, passphrase);
    }

    if nonce_bytes.len() == 1 && nonce_bytes[0] == 0x01 {
        return decrypt_pbkdf2_envelope(encrypted_data_b64, passphrase);
    }

    if let Some(ik) = identity_key {
        if let Ok(result) = decrypt_identity_key_envelope(encrypted_data_b64, &nonce_bytes, ik) {
            return Ok(result);
        }
    }

    decrypt_pbkdf2_envelope(encrypted_data_b64, passphrase)
}

fn decrypt_pbkdf2_envelope(encrypted_data_b64: &str, passphrase: &[u8]) -> Result<String> {
    let data = STANDARD
        .decode(encrypted_data_b64)
        .map_err(|e| BridgeError::Crypto(format!("data decode: {}", e)))?;

    if data.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(BridgeError::Crypto("envelope too short".to_string()));
    }

    let salt = &data[..SALT_LEN];
    let nonce = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ITERATIONS, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BridgeError::Crypto("PBKDF2 envelope decrypt failed".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| BridgeError::Crypto(format!("utf8 decode: {}", e)))
}

fn decrypt_identity_key_envelope(
    encrypted_data_b64: &str,
    nonce_bytes: &[u8],
    identity_key: &str,
) -> Result<String> {
    let encrypted_bytes = STANDARD
        .decode(encrypted_data_b64)
        .map_err(|e| BridgeError::Crypto(format!("data decode: {}", e)))?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(BridgeError::Crypto("invalid nonce length".to_string()));
    }

    for version in ENVELOPE_VERSIONS {
        let mut key = derive_envelope_key(identity_key.as_bytes(), version.as_bytes())?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
        key.zeroize();

        let nonce = Nonce::from_slice(nonce_bytes);
        if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_bytes.as_ref()) {
            return String::from_utf8(plaintext)
                .map_err(|e| BridgeError::Crypto(format!("utf8 decode: {}", e)));
        }
    }

    Err(BridgeError::Crypto(
        "identity key envelope decrypt failed for all versions".to_string(),
    ))
}

fn decrypt_pgp_or_plaintext(
    encrypted_data_b64: &str,
    identity_key: Option<&str>,
    _passphrase: &[u8],
) -> Result<String> {
    let data = STANDARD
        .decode(encrypted_data_b64)
        .map_err(|e| BridgeError::Crypto(format!("data decode: {}", e)))?;

    if let Ok(text) = String::from_utf8(data.clone()) {
        if text.starts_with("-----BEGIN PGP") {
            let ik = identity_key
                .ok_or_else(|| BridgeError::Crypto("PGP decrypt requires identity key".to_string()))?;

            let key_pair = aster_crypto::import_secret_key(ik)
                .map_err(|e| BridgeError::Crypto(format!("PGP key parse: {}", e)))?;

            let decrypted = aster_crypto::decrypt_message(text.as_bytes(), &[&key_pair])
                .map_err(|e| BridgeError::Crypto(format!("PGP decrypt: {}", e)))?;

            return String::from_utf8(decrypted)
                .map_err(|e| BridgeError::Crypto(format!("PGP utf8: {}", e)));
        }

        return Ok(text);
    }

    Err(BridgeError::Crypto("cannot decrypt envelope".to_string()))
}

fn derive_envelope_key(identity_key: &[u8], version: &[u8]) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(8 + identity_key.len() + version.len());
    info.extend_from_slice(&(identity_key.len() as u32).to_be_bytes());
    info.extend_from_slice(identity_key);
    info.extend_from_slice(&(version.len() as u32).to_be_bytes());
    info.extend_from_slice(version);
    let hk = Hkdf::<Sha256>::new(Some(b"aster-envelope-kdf-v1"), &info);
    let mut okm = [0u8; 32];
    hk.expand(b"aes-256-gcm-key", &mut okm)
        .map_err(|e| BridgeError::Crypto(format!("HKDF expand: {}", e)))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_nonce_plaintext_json_envelope_returns_as_is() {
        let json = r#"{"subject":"hello","body_text":"world"}"#;
        let b64 = STANDARD.encode(json.as_bytes());
        let out = decrypt_envelope(&b64, Some(""), b"unused-pass", None).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn empty_nonce_non_pgp_with_identity_key_still_returns_plaintext() {
        let json = r#"{"subject":"x"}"#;
        let b64 = STANDARD.encode(json.as_bytes());
        let out = decrypt_envelope(&b64, None, b"p", Some("ignored-ik")).unwrap();
        assert_eq!(out, json);
    }

    fn build_pbkdf2_envelope(plaintext: &[u8], passphrase: &[u8]) -> String {
        let salt = [7u8; SALT_LEN];
        let nonce_bytes = [9u8; NONCE_LEN];
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, PBKDF2_ITERATIONS, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
        let mut combined = Vec::new();
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        STANDARD.encode(&combined)
    }

    fn pbkdf2_nonce_marker() -> String {
        STANDARD.encode([0x01u8])
    }

    fn build_identity_envelope(plaintext: &[u8], identity_key: &str, version: &[u8]) -> (String, String) {
        let key = derive_envelope_key(identity_key.as_bytes(), version).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [4u8; NONCE_LEN];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
        (STANDARD.encode(&ciphertext), STANDARD.encode(&nonce_bytes))
    }

    #[test]
    fn pbkdf2_envelope_round_trips() {
        let plaintext = r#"{"subject":"secret","body":"hello"}"#;
        let pass = b"correct horse battery staple";
        let data = build_pbkdf2_envelope(plaintext.as_bytes(), pass);
        let out = decrypt_envelope(&data, Some(&pbkdf2_nonce_marker()), pass, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn pbkdf2_envelope_wrong_passphrase_fails_without_panic() {
        let data = build_pbkdf2_envelope(b"top secret", b"right-pass");
        let err = decrypt_envelope(&data, Some(&pbkdf2_nonce_marker()), b"wrong-pass", None);
        assert!(err.is_err());
    }

    #[test]
    fn pbkdf2_envelope_empty_plaintext_round_trips() {
        let pass = b"p";
        let data = build_pbkdf2_envelope(b"", pass);
        let out = decrypt_envelope(&data, Some(&pbkdf2_nonce_marker()), pass, None).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn pbkdf2_envelope_tampered_ciphertext_fails_authentication() {
        let pass = b"p";
        let data = build_pbkdf2_envelope(b"untampered", pass);
        let mut raw = STANDARD.decode(&data).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        let tampered = STANDARD.encode(&raw);
        let err = decrypt_envelope(&tampered, Some(&pbkdf2_nonce_marker()), pass, None);
        assert!(err.is_err());
    }

    #[test]
    fn pbkdf2_envelope_too_short_is_rejected() {
        let short = STANDARD.encode([0u8; 8]);
        let err = decrypt_envelope(&short, Some(&pbkdf2_nonce_marker()), b"p", None);
        assert!(err.is_err());
    }

    #[test]
    fn nonce_decode_failure_is_error_not_panic() {
        let data = STANDARD.encode(b"whatever");
        let err = decrypt_envelope(&data, Some("not valid base64 !!!"), b"p", None);
        assert!(err.is_err());
    }

    #[test]
    fn identity_key_envelope_round_trips() {
        let plaintext = r#"{"subject":"ik"}"#;
        let ik = "my-identity-key-material";
        let (data, nonce) = build_identity_envelope(plaintext.as_bytes(), ik, ENVELOPE_VERSIONS[0].as_bytes());
        let out = decrypt_envelope(&data, Some(&nonce), b"unused", Some(ik)).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn identity_key_envelope_second_version_round_trips() {
        let plaintext = "import payload";
        let ik = "another-identity-key";
        let (data, nonce) = build_identity_envelope(plaintext.as_bytes(), ik, ENVELOPE_VERSIONS[1].as_bytes());
        let out = decrypt_envelope(&data, Some(&nonce), b"unused", Some(ik)).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn identity_key_envelope_wrong_key_falls_back_and_errors() {
        let ik = "right-identity-key";
        let (data, nonce) = build_identity_envelope(b"hidden", ik, ENVELOPE_VERSIONS[0].as_bytes());
        let err = decrypt_envelope(&data, Some(&nonce), b"wrong-pass", Some("wrong-identity-key"));
        assert!(err.is_err());
    }

    #[test]
    fn identity_key_envelope_bad_nonce_length_falls_through_to_pbkdf2() {
        let bad_nonce = STANDARD.encode([0u8; 8]);
        let data = STANDARD.encode(b"junk");
        let err = decrypt_envelope(&data, Some(&bad_nonce), b"pass", Some("ik"));
        assert!(err.is_err());
    }

    #[test]
    fn derive_envelope_key_is_deterministic_and_version_separated() {
        let a = derive_envelope_key(b"ik", b"v1").unwrap();
        let a_again = derive_envelope_key(b"ik", b"v1").unwrap();
        let b = derive_envelope_key(b"ik", b"v2").unwrap();
        assert_eq!(a, a_again);
        assert_ne!(a, b);
    }
}
