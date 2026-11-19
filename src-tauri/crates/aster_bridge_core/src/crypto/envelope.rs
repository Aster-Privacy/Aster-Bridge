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
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::external_pgp_key::ExternalPgpKey;
use crate::crypto::inbound::{
    decrypt_inbound_envelope, is_inbound_marker, InboundKeyCandidate,
};
use crate::error::{BridgeError, Result};

const PBKDF2_ITERATIONS: u32 = 310_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

const ENVELOPE_VERSIONS: &[&str] = &["astermail-envelope-v1", "astermail-import-v1"];
const STORAGE_KEY_ENVELOPE_MARKER: u8 = 0x02;
const STORAGE_KEY_ENVELOPE_INFO: &[u8] = b"aster-envelope-v2";

static STORAGE_ENVELOPE_KEYS: std::sync::RwLock<Vec<Zeroizing<[u8; 32]>>> =
    std::sync::RwLock::new(Vec::new());
static STORAGE_ENVELOPE_KEYS_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
static CURRENT_STORAGE_KEYS: std::sync::RwLock<Vec<Zeroizing<[u8; 32]>>> =
    std::sync::RwLock::new(Vec::new());

fn decode_storage_key(key_b64: &str) -> Option<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(STANDARD.decode(key_b64.trim()).ok()?);
    if raw.len() != 32 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw);
    Some(key)
}

pub fn remember_storage_envelope_keys(
    data_kek_b64: Option<&str>,
    storage_keys: &[Zeroizing<[u8; 32]>],
) {
    let current = data_kek_b64.and_then(decode_storage_key);
    if let Some(key) = current.as_ref() {
        remember_current_storage_key(key);
    }
    let mut ring = STORAGE_ENVELOPE_KEYS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut merged: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(ring.len() + storage_keys.len() + 1);
    for key in current
        .into_iter()
        .chain(storage_keys.iter().cloned())
        .chain(ring.iter().cloned())
    {
        if !merged.iter().any(|known| **known == *key) {
            merged.push(key);
        }
    }
    let changed = merged.len() != ring.len()
        || merged.iter().zip(ring.iter()).any(|(a, b)| **a != **b);
    if changed {
        *ring = merged;
        STORAGE_ENVELOPE_KEYS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub fn remember_current_storage_key(key: &[u8; 32]) {
    if crate::crypto::mail_legacy_retirement::is_public_mail_key(key) {
        return;
    }
    let mut current = CURRENT_STORAGE_KEYS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !current.iter().any(|known| **known == *key) {
        current.push(Zeroizing::new(*key));
    }
}

pub(crate) fn mail_storage_envelope_keys() -> Vec<Zeroizing<[u8; 32]>> {
    if !crate::crypto::mail_legacy_retirement::is_mail_legacy_retired() {
        return remembered_storage_envelope_keys();
    }
    CURRENT_STORAGE_KEYS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|key| !crate::crypto::mail_legacy_retirement::is_public_mail_key(key))
        .cloned()
        .collect()
}

pub fn forget_storage_envelope_keys() {
    crate::crypto::envelope_v2::forget_envelope_v2_state();
    crate::crypto::mail_legacy_retirement::reset_mail_legacy_retirement();
    CURRENT_STORAGE_KEYS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
    let mut ring = STORAGE_ENVELOPE_KEYS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !ring.is_empty() {
        ring.clear();
        STORAGE_ENVELOPE_KEYS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub fn is_storage_key_envelope_nonce(nonce_b64: &str) -> bool {
    STANDARD
        .decode(nonce_b64)
        .map(|bytes| bytes.as_slice() == [STORAGE_KEY_ENVELOPE_MARKER])
        .unwrap_or(false)
}

pub fn storage_envelope_keys_generation() -> u64 {
    STORAGE_ENVELOPE_KEYS_GENERATION.load(std::sync::atomic::Ordering::SeqCst)
}

pub(crate) fn remembered_storage_envelope_keys() -> Vec<Zeroizing<[u8; 32]>> {
    STORAGE_ENVELOPE_KEYS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

pub fn decrypt_storage_key_envelope(
    encrypted_data_b64: &str,
    keys: &[Zeroizing<[u8; 32]>],
) -> Result<String> {
    let data = STANDARD
        .decode(encrypted_data_b64)
        .map_err(|e| BridgeError::Crypto(format!("data decode: {}", e)))?;

    if data.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(BridgeError::Crypto("envelope too short".to_string()));
    }

    let salt = &data[..SALT_LEN];
    let nonce = Nonce::from_slice(&data[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    for key in keys {
        let hk = Hkdf::<Sha256>::new(Some(salt), key.as_slice());
        let mut okm = Zeroizing::new([0u8; 32]);
        if hk.expand(STORAGE_KEY_ENVELOPE_INFO, okm.as_mut_slice()).is_err() {
            continue;
        }
        let Ok(cipher) = Aes256Gcm::new_from_slice(okm.as_slice()) else {
            continue;
        };
        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
            return String::from_utf8(plaintext)
                .map_err(|e| BridgeError::Crypto(format!("utf8 decode: {}", e)));
        }
    }

    Err(BridgeError::Crypto("storage key envelope decrypt failed".to_string()))
}

pub fn storage_key_envelope_nonce_marker() -> String {
    STANDARD.encode([STORAGE_KEY_ENVELOPE_MARKER])
}

pub fn encrypt_storage_key_envelope(plaintext: &str, key: &[u8; 32]) -> Result<String> {
    use rand_core::{OsRng, RngCore};

    if crate::crypto::mail_legacy_retirement::is_public_mail_key(key) {
        return Err(BridgeError::Crypto(
            "refusing to seal with a well-known storage key".to_string(),
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut iv);
    seal_storage_key_envelope(plaintext, key, &salt, &iv)
}

pub(crate) fn seal_storage_key_envelope(
    plaintext: &str,
    key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    iv: &[u8; NONCE_LEN],
) -> Result<String> {
    let hk = Hkdf::<Sha256>::new(Some(salt), key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(STORAGE_KEY_ENVELOPE_INFO, okm.as_mut_slice())
        .map_err(|_| BridgeError::Crypto("storage key derivation failed".to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(okm.as_slice())
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(iv), plaintext.as_bytes())
        .map_err(|_| BridgeError::Crypto("storage key envelope encrypt failed".to_string()))?;

    let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(salt);
    combined.extend_from_slice(iv);
    combined.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(&combined))
}

pub const ENVELOPE_VERSION_DEFAULT: &str = "astermail-envelope-v1";
pub const ENVELOPE_VERSION_IMPORT: &str = "astermail-import-v1";

pub fn decrypt_envelope(
    encrypted_data_b64: &str,
    nonce_b64: Option<&str>,
    passphrase: &[u8],
    identity_key: Option<&str>,
    inbound_keys: &[InboundKeyCandidate],
) -> Result<String> {
    decrypt_envelope_with_previous_keys(
        encrypted_data_b64,
        nonce_b64,
        passphrase,
        identity_key,
        &[],
        inbound_keys,
    )
}

pub fn decrypt_envelope_with_previous_keys(
    encrypted_data_b64: &str,
    nonce_b64: Option<&str>,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[InboundKeyCandidate],
) -> Result<String> {
    decrypt_envelope_with_external_key(
        encrypted_data_b64,
        nonce_b64,
        passphrase,
        identity_key,
        previous_keys,
        inbound_keys,
        None,
    )
}

pub fn decrypt_envelope_with_external_key(
    encrypted_data_b64: &str,
    nonce_b64: Option<&str>,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[InboundKeyCandidate],
    external_key: Option<&ExternalPgpKey>,
) -> Result<String> {
    decrypt_envelope_noting_origin_with_external_key(
        encrypted_data_b64,
        nonce_b64,
        passphrase,
        identity_key,
        previous_keys,
        inbound_keys,
        external_key,
    )
    .map(|(plaintext, _)| plaintext)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeOrigin {
    SelfAuthored,
    Inbound,
    UnsignedPgp,
    UnprotectedKey,
}

impl EnvelopeOrigin {
    pub fn authenticated(self) -> bool {
        self == EnvelopeOrigin::SelfAuthored
    }
}

pub fn decrypt_envelope_noting_origin(
    encrypted_data_b64: &str,
    nonce_b64: Option<&str>,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[InboundKeyCandidate],
) -> Result<(String, EnvelopeOrigin)> {
    decrypt_envelope_noting_origin_with_external_key(
        encrypted_data_b64,
        nonce_b64,
        passphrase,
        identity_key,
        previous_keys,
        inbound_keys,
        None,
    )
}

pub fn decrypt_envelope_noting_origin_with_external_key(
    encrypted_data_b64: &str,
    nonce_b64: Option<&str>,
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    inbound_keys: &[InboundKeyCandidate],
    external_key: Option<&ExternalPgpKey>,
) -> Result<(String, EnvelopeOrigin)> {
    let nonce_bytes = match nonce_b64 {
        Some(n) if !n.is_empty() => STANDARD
            .decode(n)
            .map_err(|e| BridgeError::Crypto(format!("nonce decode: {}", e)))?,
        _ => Vec::new(),
    };

    if nonce_bytes.is_empty() {
        return decrypt_pgp_envelope(encrypted_data_b64, identity_key, previous_keys, passphrase, external_key);
    }

    if nonce_bytes.len() == 1 && nonce_bytes[0] == 0x01 {
        return decrypt_pbkdf2_envelope(encrypted_data_b64, passphrase)
            .map(|plaintext| (plaintext, passphrase_origin(passphrase)));
    }

    if nonce_bytes.len() == 1 && nonce_bytes[0] == STORAGE_KEY_ENVELOPE_MARKER {
        let keys = mail_storage_envelope_keys();
        return open_storage_key_envelope_noting_origin(encrypted_data_b64, &keys);
    }

    if nonce_bytes.len() == NONCE_LEN && !inbound_keys.is_empty() {
        if let Ok(data) = STANDARD.decode(encrypted_data_b64) {
            if data.first().copied().is_some_and(is_inbound_marker) {
                if let Ok(result) = decrypt_inbound_envelope(&data, &nonce_bytes, inbound_keys) {
                    return Ok((result, EnvelopeOrigin::Inbound));
                }
            }
        }
    }

    let retired = crate::crypto::mail_legacy_retirement::is_mail_legacy_retired();
    open_identity_or_passphrase_envelope(
        encrypted_data_b64,
        &nonce_bytes,
        passphrase,
        identity_key,
        previous_keys,
        retired,
    )
}

fn passphrase_origin(passphrase: &[u8]) -> EnvelopeOrigin {
    if passphrase.is_empty() {
        EnvelopeOrigin::UnprotectedKey
    } else {
        EnvelopeOrigin::SelfAuthored
    }
}

pub(crate) fn open_storage_key_envelope_noting_origin(
    encrypted_data_b64: &str,
    keys: &[Zeroizing<[u8; 32]>],
) -> Result<(String, EnvelopeOrigin)> {
    let (public_keys, private_keys): (Vec<Zeroizing<[u8; 32]>>, Vec<Zeroizing<[u8; 32]>>) = keys
        .iter()
        .cloned()
        .partition(|key| crate::crypto::ratchet_recovery::is_public_storage_key(key));
    if let Ok(plaintext) = decrypt_storage_key_envelope(encrypted_data_b64, &private_keys) {
        return Ok((plaintext, EnvelopeOrigin::SelfAuthored));
    }
    decrypt_storage_key_envelope(encrypted_data_b64, &public_keys)
        .map(|plaintext| (plaintext, EnvelopeOrigin::UnprotectedKey))
}

fn open_identity_or_passphrase_envelope(
    encrypted_data_b64: &str,
    nonce_bytes: &[u8],
    passphrase: &[u8],
    identity_key: Option<&str>,
    previous_keys: &[String],
    retired: bool,
) -> Result<(String, EnvelopeOrigin)> {
    let (public_keys, private_keys): (Vec<&str>, Vec<&str>) = identity_key
        .into_iter()
        .chain(previous_keys.iter().map(String::as_str))
        .partition(|ik| crate::crypto::mail_legacy_retirement::is_public_identity_material(ik));
    for ik in private_keys {
        if let Ok(result) = decrypt_identity_key_envelope(encrypted_data_b64, nonce_bytes, ik) {
            return Ok((result, EnvelopeOrigin::SelfAuthored));
        }
    }
    if !retired {
        for ik in public_keys {
            if let Ok(result) = decrypt_identity_key_envelope(encrypted_data_b64, nonce_bytes, ik) {
                return Ok((result, EnvelopeOrigin::UnprotectedKey));
            }
        }
    }
    decrypt_pbkdf2_envelope(encrypted_data_b64, passphrase)
        .map(|plaintext| (plaintext, passphrase_origin(passphrase)))
}

pub(crate) fn decrypt_pbkdf2_envelope(encrypted_data_b64: &str, passphrase: &[u8]) -> Result<String> {
    let data = STANDARD
        .decode(encrypted_data_b64)
        .map_err(|e| BridgeError::Crypto(format!("data decode: {}", e)))?;

    if data.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(BridgeError::Crypto("envelope too short".to_string()));
    }

    let salt = &data[..SALT_LEN];
    if crate::crypto::login_salt_guard::is_known_login_salt(salt) {
        return Err(BridgeError::Crypto("PBKDF2 envelope decrypt failed".to_string()));
    }
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

pub fn encrypt_pbkdf2_envelope(plaintext: &str, passphrase: &[u8]) -> Result<String> {
    use rand_core::{OsRng, RngCore};

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, PBKDF2_ITERATIONS, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|_| BridgeError::Crypto("PBKDF2 envelope encrypt failed".to_string()))?;

    let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(STANDARD.encode(&combined))
}

pub fn pbkdf2_envelope_nonce_marker() -> String {
    STANDARD.encode([0x01u8])
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
        let candidates = [
            derive_envelope_key(identity_key.as_bytes(), version.as_bytes())?,
            derive_legacy_envelope_key(identity_key.as_bytes(), version.as_bytes())?,
        ];

        for mut key in candidates {
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
            key.zeroize();

            let nonce = Nonce::from_slice(nonce_bytes);
            if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_bytes.as_ref()) {
                return String::from_utf8(plaintext)
                    .map_err(|e| BridgeError::Crypto(format!("utf8 decode: {}", e)));
            }
        }
    }

    Err(BridgeError::Crypto(
        "identity key envelope decrypt failed for all versions".to_string(),
    ))
}

fn decrypt_pgp_envelope(
    encrypted_data_b64: &str,
    identity_key: Option<&str>,
    previous_keys: &[String],
    passphrase: &[u8],
    external_key: Option<&ExternalPgpKey>,
) -> Result<(String, EnvelopeOrigin)> {
    let data = STANDARD
        .decode(encrypted_data_b64)
        .map_err(|e| BridgeError::Crypto(format!("data decode: {}", e)))?;

    if let Ok(text) = String::from_utf8(data) {
        if text.starts_with("-----BEGIN PGP") {
            let (decrypted, origin) = open_own_pgp(&text, identity_key, previous_keys, passphrase, external_key)?;
            let plaintext = String::from_utf8(decrypted.to_vec())
                .map_err(|e| BridgeError::Crypto(format!("PGP utf8: {}", e)))?;
            return Ok((plaintext, origin));
        }
    }

    Err(BridgeError::Crypto("envelope is not encrypted".to_string()))
}

pub fn unencrypted_envelope_json(encrypted_data_b64: &str, nonce_b64: &str) -> Option<String> {
    if !nonce_b64.trim().is_empty() {
        return None;
    }
    let data = STANDARD.decode(encrypted_data_b64.trim()).ok()?;
    let text = String::from_utf8(data).ok()?;
    if text.trim_start().starts_with("-----BEGIN PGP") {
        return None;
    }
    matches!(
        serde_json::from_str::<serde_json::Value>(&text),
        Ok(serde_json::Value::Object(_))
    )
    .then_some(text)
}

#[cfg(test)]
pub(crate) const FIXTURE_IDENTITY_KEY: &str = "test-ik";

#[cfg(test)]
pub(crate) fn sealed_fixture(plaintext: &str) -> (String, String) {
    use sha2::Digest;

    let key = derive_envelope_key(FIXTURE_IDENTITY_KEY.as_bytes(), ENVELOPE_VERSION_DEFAULT.as_bytes()).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let digest = Sha256::digest(plaintext.as_bytes());
    let nonce_bytes = &digest[..NONCE_LEN];
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce_bytes), plaintext.as_bytes())
        .unwrap();
    (STANDARD.encode(ciphertext), STANDARD.encode(nonce_bytes))
}

fn own_pgp_keys(identity_key: Option<&str>, previous_keys: &[String]) -> Result<Vec<aster_crypto::KeyPair>> {
    let ik = identity_key
        .ok_or_else(|| BridgeError::Crypto("PGP decrypt requires identity key".to_string()))?;
    let own_keys: Vec<aster_crypto::KeyPair> = std::iter::once(ik)
        .chain(previous_keys.iter().map(String::as_str))
        .filter_map(|armored_key| aster_crypto::import_secret_key(armored_key).ok())
        .collect();
    if own_keys.is_empty() {
        return Err(BridgeError::Crypto("PGP key parse failed".to_string()));
    }
    Ok(own_keys)
}

fn open_own_pgp(
    armored: &str,
    identity_key: Option<&str>,
    previous_keys: &[String],
    passphrase: &[u8],
    external_key: Option<&ExternalPgpKey>,
) -> Result<(Zeroizing<Vec<u8>>, EnvelopeOrigin)> {
    if let Ok(own_keys) = own_pgp_keys(identity_key, previous_keys) {
        let key_refs: Vec<&aster_crypto::KeyPair> = own_keys.iter().collect();
        let own_public: Vec<aster_crypto::PublicKey> = own_keys.iter().map(|k| k.public_key()).collect();
        let public_refs: Vec<&aster_crypto::PublicKey> = own_public.iter().collect();
        let passphrase_text = Zeroizing::new(std::str::from_utf8(passphrase).unwrap_or("").to_string());
        for candidate in [passphrase_text.as_str(), ""] {
            if let Ok(plain) = aster_crypto::decrypt_and_verify_with_passphrase(
                armored.as_bytes(),
                &key_refs,
                &public_refs,
                candidate,
            ) {
                return Ok((Zeroizing::new(plain), EnvelopeOrigin::SelfAuthored));
            }
        }
    }
    decrypt_own_or_external_pgp(armored, identity_key, previous_keys, passphrase, external_key)
        .map(|plain| (plain, EnvelopeOrigin::UnsignedPgp))
}

pub(crate) fn decrypt_own_or_external_pgp(
    armored: &str,
    identity_key: Option<&str>,
    previous_keys: &[String],
    passphrase: &[u8],
    external_key: Option<&ExternalPgpKey>,
) -> Result<Zeroizing<Vec<u8>>> {
    let own = decrypt_own_pgp(armored, identity_key, previous_keys, passphrase);
    if own.is_ok() {
        return own;
    }
    match external_key.and_then(|key| key.decrypt_armored(armored)) {
        Some(plain) => Ok(plain),
        None => own,
    }
}

pub(crate) fn decrypt_own_pgp(
    armored: &str,
    identity_key: Option<&str>,
    previous_keys: &[String],
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let own_keys = own_pgp_keys(identity_key, previous_keys)?;
    let key_refs: Vec<&aster_crypto::KeyPair> = own_keys.iter().collect();
    let passphrase = Zeroizing::new(std::str::from_utf8(passphrase).unwrap_or("").to_string());
    for candidate in [passphrase.as_str(), ""] {
        if let Ok(plain) =
            aster_crypto::decrypt_message_with_passphrase(armored.as_bytes(), &key_refs, candidate)
        {
            return Ok(Zeroizing::new(plain));
        }
    }
    Err(BridgeError::Crypto("PGP decrypt failed".to_string()))
}

pub(crate) fn derive_envelope_key(identity_key: &[u8], version: &[u8]) -> Result<[u8; 32]> {
    use sha2::Digest;

    let mut hasher = Sha256::new();
    hasher.update(identity_key);
    hasher.update(version);
    Ok(hasher.finalize().into())
}

fn derive_legacy_envelope_key(identity_key: &[u8], version: &[u8]) -> Result<[u8; 32]> {
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

#[allow(dead_code)]
pub fn encrypt_identity_key_envelope(plaintext: &str, identity_key: &str) -> Result<(String, String)> {
    encrypt_identity_key_envelope_with_version(plaintext, identity_key, ENVELOPE_VERSION_DEFAULT)
}

pub fn encrypt_identity_key_envelope_with_version(
    plaintext: &str,
    identity_key: &str,
    version: &str,
) -> Result<(String, String)> {
    use rand_core::{OsRng, RngCore};

    if crate::crypto::mail_legacy_retirement::is_public_identity_material(identity_key) {
        return Err(BridgeError::Crypto(
            "refusing to seal without a private identity key".to_string(),
        ));
    }
    let mut key = derive_envelope_key(identity_key.as_bytes(), version.as_bytes())?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BridgeError::Crypto(format!("cipher init: {}", e)))?;
    key.zeroize();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| BridgeError::Crypto("envelope encrypt failed".to_string()))?;

    Ok((STANDARD.encode(&ciphertext), STANDARD.encode(nonce_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unencrypted_envelope_is_refused() {
        let json = r#"{"subject":"hello","body_text":"world","attachment_keys":[{"seq":0,"key":"AAAA"}]}"#;
        let b64 = STANDARD.encode(json.as_bytes());
        assert!(decrypt_envelope(&b64, Some(""), b"unused-pass", None, &[]).is_err());
        assert!(decrypt_envelope(&b64, None, b"p", Some("ignored-ik"), &[]).is_err());
    }

    #[test]
    fn only_a_bare_json_object_counts_as_an_unencrypted_envelope() {
        let json = r#"{"subject":"hello","body_text":"world"}"#;
        let b64 = STANDARD.encode(json.as_bytes());
        assert_eq!(unencrypted_envelope_json(&b64, "").as_deref(), Some(json));
        assert_eq!(unencrypted_envelope_json(&b64, "AAAAAAAAAAAAAAAA"), None);
        assert_eq!(unencrypted_envelope_json(&STANDARD.encode(b"[1,2]"), ""), None);
        assert_eq!(unencrypted_envelope_json(&STANDARD.encode(b"plain words"), ""), None);
        assert_eq!(
            unencrypted_envelope_json(&STANDARD.encode(b"-----BEGIN PGP MESSAGE-----\n{}"), ""),
            None
        );
        let (sealed, nonce) = sealed_fixture(json);
        assert_eq!(unencrypted_envelope_json(&sealed, &nonce), None);
        assert_eq!(unencrypted_envelope_json(&sealed, ""), None);
    }

    #[test]
    fn a_sealed_fixture_opens_with_its_identity_key() {
        let json = r#"{"subject":"x"}"#;
        let (data, nonce) = sealed_fixture(json);
        let out = decrypt_envelope(&data, Some(&nonce), b"p", Some(FIXTURE_IDENTITY_KEY), &[]).unwrap();
        assert_eq!(out, json);
        assert!(decrypt_envelope(&data, Some(&nonce), b"p", Some("another-key"), &[]).is_err());
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
        (STANDARD.encode(&ciphertext), STANDARD.encode(nonce_bytes))
    }

    #[test]
    fn pbkdf2_envelope_round_trips() {
        let plaintext = r#"{"subject":"secret","body":"hello"}"#;
        let pass = b"correct horse battery staple";
        let data = build_pbkdf2_envelope(plaintext.as_bytes(), pass);
        let out = decrypt_envelope(&data, Some(&pbkdf2_nonce_marker()), pass, None, &[]).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn pbkdf2_envelope_wrong_passphrase_fails_without_panic() {
        let data = build_pbkdf2_envelope(b"top secret", b"right-pass");
        let err = decrypt_envelope(&data, Some(&pbkdf2_nonce_marker()), b"wrong-pass", None, &[]);
        assert!(err.is_err());
    }

    #[test]
    fn pbkdf2_envelope_empty_plaintext_round_trips() {
        let pass = b"p";
        let data = build_pbkdf2_envelope(b"", pass);
        let out = decrypt_envelope(&data, Some(&pbkdf2_nonce_marker()), pass, None, &[]).unwrap();
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
        let err = decrypt_envelope(&tampered, Some(&pbkdf2_nonce_marker()), pass, None, &[]);
        assert!(err.is_err());
    }

    #[test]
    fn pbkdf2_envelope_too_short_is_rejected() {
        let short = STANDARD.encode([0u8; 8]);
        let err = decrypt_envelope(&short, Some(&pbkdf2_nonce_marker()), b"p", None, &[]);
        assert!(err.is_err());
    }

    #[test]
    fn nonce_decode_failure_is_error_not_panic() {
        let data = STANDARD.encode(b"whatever");
        let err = decrypt_envelope(&data, Some("not valid base64 !!!"), b"p", None, &[]);
        assert!(err.is_err());
    }

    #[test]
    fn identity_key_envelope_round_trips() {
        let plaintext = r#"{"subject":"ik"}"#;
        let ik = "my-identity-key-material";
        let (data, nonce) = build_identity_envelope(plaintext.as_bytes(), ik, ENVELOPE_VERSIONS[0].as_bytes());
        let out = decrypt_envelope(&data, Some(&nonce), b"unused", Some(ik), &[]).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn identity_key_envelope_second_version_round_trips() {
        let plaintext = "import payload";
        let ik = "another-identity-key";
        let (data, nonce) = build_identity_envelope(plaintext.as_bytes(), ik, ENVELOPE_VERSIONS[1].as_bytes());
        let out = decrypt_envelope(&data, Some(&nonce), b"unused", Some(ik), &[]).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn identity_key_envelope_wrong_key_falls_back_and_errors() {
        let ik = "right-identity-key";
        let (data, nonce) = build_identity_envelope(b"hidden", ik, ENVELOPE_VERSIONS[0].as_bytes());
        let err = decrypt_envelope(&data, Some(&nonce), b"wrong-pass", Some("wrong-identity-key"), &[]);
        assert!(err.is_err());
    }

    #[test]
    fn identity_key_envelope_bad_nonce_length_falls_through_to_pbkdf2() {
        let bad_nonce = STANDARD.encode([0u8; 8]);
        let data = STANDARD.encode(b"junk");
        let err = decrypt_envelope(&data, Some(&bad_nonce), b"pass", Some("ik"), &[]);
        assert!(err.is_err());
    }

    fn sample_inbound_candidates() -> Vec<InboundKeyCandidate> {
        let sk = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        vec![InboundKeyCandidate {
            ecdh_secret_d: sk.to_bytes().to_vec(),
            pq_decap_key: None,
            owner: None,
        }]
    }

    #[test]
    fn pbkdf2_envelope_starting_with_inbound_marker_falls_through_to_legacy_path() {
        let plaintext = r#"{"subject":"legacy"}"#;
        let pass = b"legacy-pass";
        let salt = {
            let mut s = [7u8; SALT_LEN];
            s[0] = 0x03;
            s
        };
        let nonce_bytes = [9u8; NONCE_LEN];
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(pass, &salt, PBKDF2_ITERATIONS, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .unwrap();
        let mut combined = Vec::new();
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        let data = STANDARD.encode(&combined);
        let envelope_nonce = STANDARD.encode([2u8; NONCE_LEN]);
        let candidates = sample_inbound_candidates();
        let out = decrypt_envelope(&data, Some(&envelope_nonce), pass, None, &candidates).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn identity_envelope_starting_with_inbound_marker_falls_through_to_legacy_path() {
        let ik = "identity-key-material";
        let candidates = sample_inbound_candidates();
        let plaintext = r#"{"subject":"marker probe"}"#;
        let key = derive_envelope_key(ik.as_bytes(), ENVELOPE_VERSIONS[0].as_bytes()).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        for i in 0u32..4096 {
            let mut nonce_bytes = [0u8; NONCE_LEN];
            nonce_bytes[..4].copy_from_slice(&i.to_be_bytes());
            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
                .unwrap();
            if ciphertext[0] != 0x03 && ciphertext[0] != 0x04 {
                continue;
            }
            let data = STANDARD.encode(&ciphertext);
            let nonce = STANDARD.encode(nonce_bytes);
            let out = decrypt_envelope(&data, Some(&nonce), b"unused", Some(ik), &candidates).unwrap();
            assert_eq!(out, plaintext);
            return;
        }
        panic!("no probe produced an inbound marker first byte");
    }

    fn pbkdf2_envelope_with_salt(plaintext: &str, pass: &[u8], salt: &[u8; SALT_LEN]) -> String {
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(pass, salt, PBKDF2_ITERATIONS, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .unwrap();
        let mut combined = Vec::new();
        combined.extend_from_slice(salt);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        STANDARD.encode(&combined)
    }

    #[test]
    fn pbkdf2_envelope_keyed_by_a_login_salt_is_refused() {
        let pass = b"account-password";
        let login_salt: [u8; SALT_LEN] = rand::random();
        let other_salt: [u8; SALT_LEN] = rand::random();
        let planted = pbkdf2_envelope_with_salt(r#"{"subject":"planted"}"#, pass, &login_salt);
        let genuine = pbkdf2_envelope_with_salt(r#"{"subject":"genuine"}"#, pass, &other_salt);
        let marker = pbkdf2_envelope_nonce_marker();

        crate::crypto::login_salt_guard::remember_login_salts(
            None,
            &uuid::Uuid::new_v4(),
            &[login_salt.to_vec()],
        );

        assert!(decrypt_envelope(&planted, Some(&marker), pass, None, &[]).is_err());
        assert!(decrypt_envelope(&planted, Some(&STANDARD.encode([5u8; NONCE_LEN])), pass, None, &[]).is_err());
        assert!(decrypt_pbkdf2_envelope(&planted, pass).is_err());
        assert_eq!(
            decrypt_envelope(&genuine, Some(&marker), pass, None, &[]).unwrap(),
            r#"{"subject":"genuine"}"#
        );
    }

    #[test]
    fn pbkdf2_envelope_encrypt_round_trips_through_the_reader() {
        let plaintext = r#"{"filename":"a.pdf","session_key":"AAAA"}"#;
        let pass = b"vault-passphrase-bytes";
        let data = encrypt_pbkdf2_envelope(plaintext, pass).unwrap();
        let out = decrypt_envelope(&data, Some(&pbkdf2_envelope_nonce_marker()), pass, None, &[]).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn pbkdf2_envelope_encrypt_layout_is_salt_nonce_ciphertext() {
        let data = encrypt_pbkdf2_envelope("x", b"p").unwrap();
        let raw = STANDARD.decode(&data).unwrap();
        assert!(raw.len() > SALT_LEN + NONCE_LEN);
        let second = encrypt_pbkdf2_envelope("x", b"p").unwrap();
        assert_ne!(data, second);
    }

    #[test]
    fn derive_envelope_key_matches_canonical_web_scheme() {
        use sha2::Digest;

        let ik = "identity-key-material";
        let version = ENVELOPE_VERSION_IMPORT;
        let expected: [u8; 32] = Sha256::digest(format!("{}{}", ik, version).as_bytes()).into();
        let actual = derive_envelope_key(ik.as_bytes(), version.as_bytes()).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn identity_envelope_written_by_bridge_decrypts_with_canonical_key() {
        use sha2::Digest;

        let plaintext = r#"{"subject":"migrated"}"#;
        let ik = "vault-identity-key";
        let (data, nonce) =
            encrypt_identity_key_envelope_with_version(plaintext, ik, ENVELOPE_VERSION_IMPORT)
                .unwrap();

        let key: [u8; 32] =
            Sha256::digest(format!("{}{}", ik, ENVELOPE_VERSION_IMPORT).as_bytes()).into();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = STANDARD.decode(&nonce).unwrap();
        let decrypted = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                STANDARD.decode(&data).unwrap().as_ref(),
            )
            .unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), plaintext);
        let out = decrypt_envelope(&data, Some(&nonce), b"unused", Some(ik), &[]).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn legacy_hkdf_identity_envelope_still_decrypts() {
        let plaintext = r#"{"subject":"legacy hkdf"}"#;
        let ik = "old-bridge-identity-key";
        let key = derive_legacy_envelope_key(ik.as_bytes(), ENVELOPE_VERSION_IMPORT.as_bytes()).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [5u8; NONCE_LEN];
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .unwrap();
        let out = decrypt_envelope(
            &STANDARD.encode(&ciphertext),
            Some(&STANDARD.encode(nonce_bytes)),
            b"unused",
            Some(ik),
            &[],
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn derive_envelope_key_is_deterministic_and_version_separated() {
        let a = derive_envelope_key(b"ik", b"v1").unwrap();
        let a_again = derive_envelope_key(b"ik", b"v1").unwrap();
        let b = derive_envelope_key(b"ik", b"v2").unwrap();
        assert_eq!(a, a_again);
        assert_ne!(a, b);
    }

    const VAULT_PASSPHRASE: &str = "vault passphrase 42";

    fn pgp_envelope_for(key: &aster_crypto::KeyPair, plaintext: &str) -> String {
        let public = key.public_key();
        let armored = aster_crypto::encrypt_message(plaintext.as_bytes(), &[&public]).unwrap();
        STANDARD.encode(armored)
    }

    #[test]
    fn pgp_envelope_opens_with_a_protected_identity_key() {
        let owner = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let owner_armored = owner.to_armored().unwrap();
        let envelope = pgp_envelope_for(&owner, "{\"subject\":\"hi\"}");

        let opened = decrypt_envelope(
            &envelope,
            None,
            VAULT_PASSPHRASE.as_bytes(),
            Some(&owner_armored),
            &[],
        )
        .unwrap();
        assert_eq!(opened, "{\"subject\":\"hi\"}");
        assert!(decrypt_envelope(&envelope, None, b"wrong passphrase", Some(&owner_armored), &[]).is_err());
        assert!(decrypt_envelope(&envelope, None, VAULT_PASSPHRASE.as_bytes(), None, &[]).is_err());
    }

    #[test]
    fn identity_key_envelope_opens_with_a_previous_key() {
        let plaintext = r#"{"subject":"imported"}"#;
        for version in ENVELOPE_VERSIONS {
            let (data, nonce) =
                build_identity_envelope(plaintext.as_bytes(), "old-identity-key", version.as_bytes());

            assert!(decrypt_envelope(&data, Some(&nonce), b"p", Some("new-identity-key"), &[]).is_err());
            let opened = decrypt_envelope_with_previous_keys(
                &data,
                Some(&nonce),
                b"p",
                Some("new-identity-key"),
                &["unrelated-key".to_string(), "old-identity-key".to_string()],
                &[],
            )
            .unwrap();
            assert_eq!(opened, plaintext);
        }
    }

    #[test]
    fn pgp_envelope_opens_with_a_previous_key() {
        let old_key = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let new_key = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let envelope = pgp_envelope_for(&old_key, "old mail");
        let new_armored = new_key.to_armored().unwrap();

        assert!(decrypt_envelope(&envelope, Some(""), VAULT_PASSPHRASE.as_bytes(), Some(&new_armored), &[]).is_err());
        let opened = decrypt_envelope_with_previous_keys(
            &envelope,
            Some(""),
            VAULT_PASSPHRASE.as_bytes(),
            Some(&new_armored),
            &[old_key.to_armored().unwrap()],
            &[],
        )
        .unwrap();
        assert_eq!(opened, "old mail");
    }

    #[test]
    fn pgp_envelope_still_opens_with_an_unprotected_key() {
        let owner = aster_crypto::generate_keypair("Owner", "owner@astermail.org").unwrap();
        let envelope = pgp_envelope_for(&owner, "legacy");
        let opened = decrypt_envelope(
            &envelope,
            None,
            VAULT_PASSPHRASE.as_bytes(),
            Some(&owner.to_armored().unwrap()),
            &[],
        )
        .unwrap();
        assert_eq!(opened, "legacy");
    }

    fn origin_of(envelope: &str, nonce: Option<&str>, owner: &aster_crypto::KeyPair) -> EnvelopeOrigin {
        decrypt_envelope_noting_origin(
            envelope,
            nonce,
            VAULT_PASSPHRASE.as_bytes(),
            Some(&owner.to_armored().unwrap()),
            &[],
            &[],
        )
        .unwrap()
        .1
    }

    #[test]
    fn a_pgp_envelope_signed_by_the_owner_is_self_authored() {
        let owner = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let sealed = crate::crypto::sent_copy::seal_sent_envelope(
            "{\"subject\":\"sent\"}",
            &owner.to_armored().unwrap(),
            VAULT_PASSPHRASE.as_bytes(),
        )
        .unwrap();
        assert_eq!(origin_of(&sealed, None, &owner), EnvelopeOrigin::SelfAuthored);
    }

    #[test]
    fn a_pgp_envelope_signed_by_a_previous_owner_key_is_self_authored() {
        let old_key = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let new_key = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let sealed = crate::crypto::sent_copy::seal_sent_envelope(
            "old sent",
            &old_key.to_armored().unwrap(),
            VAULT_PASSPHRASE.as_bytes(),
        )
        .unwrap();
        let (plaintext, origin) = decrypt_envelope_noting_origin(
            &sealed,
            Some(""),
            VAULT_PASSPHRASE.as_bytes(),
            Some(&new_key.to_armored().unwrap()),
            &[old_key.to_armored().unwrap()],
            &[],
        )
        .unwrap();
        assert_eq!(plaintext, "old sent");
        assert_eq!(origin, EnvelopeOrigin::SelfAuthored);
    }

    #[test]
    fn an_unsigned_pgp_envelope_is_not_authenticated() {
        let owner = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let envelope = pgp_envelope_for(&owner, "{\"subject\":\"forged\"}");
        let origin = origin_of(&envelope, None, &owner);
        assert_eq!(origin, EnvelopeOrigin::UnsignedPgp);
        assert!(!origin.authenticated());
    }

    #[test]
    fn a_pgp_envelope_signed_by_someone_else_is_not_authenticated() {
        let owner = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let stranger = aster_crypto::generate_keypair("Bob", "bob@astermail.org").unwrap();
        let armored = aster_crypto::encrypt_and_sign_with_passphrase(
            b"{\"subject\":\"signed by bob\"}",
            &[&owner.public_key()],
            &stranger,
            "",
        )
        .unwrap();
        let envelope = STANDARD.encode(armored);
        assert_eq!(origin_of(&envelope, None, &owner), EnvelopeOrigin::UnsignedPgp);
    }

    #[test]
    fn passphrase_and_identity_key_envelopes_are_self_authored() {
        let owner = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let pbkdf2 = encrypt_pbkdf2_envelope("{}", VAULT_PASSPHRASE.as_bytes()).unwrap();
        assert_eq!(
            origin_of(&pbkdf2, Some(&pbkdf2_envelope_nonce_marker()), &owner),
            EnvelopeOrigin::SelfAuthored
        );
        let (data, nonce) = sealed_fixture("{}");
        let (_, origin) =
            decrypt_envelope_noting_origin(&data, Some(&nonce), b"p", Some(FIXTURE_IDENTITY_KEY), &[], &[]).unwrap();
        assert_eq!(origin, EnvelopeOrigin::SelfAuthored);
    }

    #[test]
    fn unparseable_own_keys_fail_without_panic() {
        let owner = aster_crypto::generate_keypair("Owner", "owner@astermail.org").unwrap();
        let envelope = pgp_envelope_for(&owner, "x");
        assert!(decrypt_envelope_with_previous_keys(
            &envelope,
            None,
            VAULT_PASSPHRASE.as_bytes(),
            Some("not a key"),
            &["also not a key".to_string()],
            &[],
        )
        .is_err());
    }

    const V2_DATA_KEK: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const V2_LEGACY_KEK: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    const V2_PLAINTEXT: &str = r#"{"subject":"Vector test","n":7}"#;
    const V2_CURRENT: &str = "oKGio6SlpqeoqaqrrK2ur8DBwsPExcbHyMnKyxmUrphDVc4W9hq0u8Q/kCWAkTj6oNg/L8FnTtfoYrei0cSkxxjeICkSF8UMMji/";
    const V2_LEGACY_ONLY: &str = "oKGio6SlpqeoqaqrrK2ur8DBwsPExcbHyMnKywLFIOOJnavHPVGWAESVDuvrt2eV3125NPGXHdSgj9M13jpUGS2PQGNB/A8W43oA";

    fn v2_key(b64: &str) -> Zeroizing<[u8; 32]> {
        decode_storage_key(b64).unwrap()
    }

    #[test]
    fn v2_vector_opens_with_data_kek() {
        let plain = decrypt_storage_key_envelope(V2_CURRENT, &[v2_key(V2_DATA_KEK)]).unwrap();
        assert_eq!(plain, V2_PLAINTEXT);
    }

    #[test]
    fn v2_legacy_vector_needs_the_legacy_kek() {
        assert!(decrypt_storage_key_envelope(V2_LEGACY_ONLY, &[v2_key(V2_DATA_KEK)]).is_err());
        let plain = decrypt_storage_key_envelope(
            V2_LEGACY_ONLY,
            &[v2_key(V2_DATA_KEK), v2_key(V2_LEGACY_KEK)],
        )
        .unwrap();
        assert_eq!(plain, V2_PLAINTEXT);
    }

    #[test]
    fn v2_vector_fails_without_keys_and_on_tampering() {
        assert!(decrypt_storage_key_envelope(V2_CURRENT, &[]).is_err());
        let mut raw = STANDARD.decode(V2_CURRENT).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = STANDARD.encode(&raw);
        assert!(decrypt_storage_key_envelope(&tampered, &[v2_key(V2_DATA_KEK)]).is_err());
        assert!(decrypt_storage_key_envelope("AAAA", &[v2_key(V2_DATA_KEK)]).is_err());
    }

    #[test]
    fn v2_nonce_marker_is_recognized() {
        assert!(is_storage_key_envelope_nonce("Ag=="));
        assert!(!is_storage_key_envelope_nonce("AQ=="));
        assert!(!is_storage_key_envelope_nonce(""));
        assert!(!is_storage_key_envelope_nonce("not base64"));
    }

    #[test]
    fn v2_nonce_marker_uses_the_remembered_keys() {
        remember_storage_envelope_keys(Some(V2_DATA_KEK), &[v2_key(V2_LEGACY_KEK)]);
        for blob in [V2_CURRENT, V2_LEGACY_ONLY] {
            let (plain, origin) =
                decrypt_envelope_noting_origin(blob, Some("Ag=="), b"unused", None, &[], &[]).unwrap();
            assert_eq!(plain, V2_PLAINTEXT);
            assert_eq!(origin, EnvelopeOrigin::SelfAuthored);
        }
    }

    #[test]
    fn v2_write_reproduces_the_vector_and_round_trips() {
        let raw = STANDARD.decode(V2_CURRENT).unwrap();
        let salt: [u8; SALT_LEN] = raw[..SALT_LEN].try_into().unwrap();
        let iv: [u8; NONCE_LEN] = raw[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().unwrap();
        let key = v2_key(V2_DATA_KEK);
        let sealed = seal_storage_key_envelope(V2_PLAINTEXT, &key, &salt, &iv).unwrap();
        assert_eq!(sealed, V2_CURRENT);
        assert_eq!(
            decrypt_storage_key_envelope(&sealed, &[key.clone()]).unwrap(),
            V2_PLAINTEXT
        );
    }

    #[test]
    fn v2_write_uses_fresh_salt_and_iv_and_opens_only_with_its_key() {
        let key = v2_key(V2_DATA_KEK);
        let first = encrypt_storage_key_envelope(V2_PLAINTEXT, &key).unwrap();
        let second = encrypt_storage_key_envelope(V2_PLAINTEXT, &key).unwrap();
        assert_ne!(first, second);
        let raw = STANDARD.decode(&first).unwrap();
        assert_eq!(raw.len(), SALT_LEN + NONCE_LEN + V2_PLAINTEXT.len() + 16);
        assert_eq!(decrypt_storage_key_envelope(&first, &[key.clone()]).unwrap(), V2_PLAINTEXT);
        assert!(decrypt_storage_key_envelope(&first, &[v2_key(V2_LEGACY_KEK)]).is_err());
        assert_eq!(storage_key_envelope_nonce_marker(), "Ag==");
        assert!(is_storage_key_envelope_nonce(&storage_key_envelope_nonce_marker()));
    }

    const RETIRED_PASSPHRASE: &[u8] = b"retired-vault-pass";
    const RETIRED_IDENTITY: &str = "retired-account-identity-key";

    fn retired_vault_material(marker: serde_json::Value) -> crate::auth::session::VaultKeyMaterial {
        let mut vault = serde_json::json!({
            "identity_key": RETIRED_IDENTITY,
            "data_kek": V2_DATA_KEK,
            "vault_format": 2,
            "legacy_keks": [{ "k": V2_LEGACY_KEK }],
            "legacy_identity_keys": ["undefined"],
        });
        vault["mail_legacy_retired"] = marker;
        let (sealed, nonce) = crate::crypto::vault::test_support::seal_vault_with_iterations(
            vault.to_string().as_bytes(),
            RETIRED_PASSPHRASE,
            310_000,
        );
        crate::auth::session::decrypt_vault_key_material(&sealed, &nonce, Some(310_000), RETIRED_PASSPHRASE)
            .unwrap()
    }

    fn public_identity_envelope() -> (String, String) {
        build_identity_envelope(V2_PLAINTEXT.as_bytes(), "undefined", b"astermail-envelope-v1")
    }

    #[test]
    fn a_retired_vault_opens_stored_mail_only_with_the_current_key() {
        let material = retired_vault_material(serde_json::json!({ "v": 1, "at": "2026-11-17T00:00:00Z" }));
        let previous: Vec<String> = material.previous_keys.to_vec();
        let opened = decrypt_envelope_noting_origin(V2_CURRENT, Some("Ag=="), RETIRED_PASSPHRASE, None, &[], &[]);
        assert_eq!(opened.unwrap().0, V2_PLAINTEXT);
        assert!(
            decrypt_envelope_noting_origin(V2_LEGACY_ONLY, Some("Ag=="), RETIRED_PASSPHRASE, None, &[], &[])
                .is_err(),
            "a retired vault must not open mail sealed under a legacy key"
        );
        let (public_ct, public_nonce) = public_identity_envelope();
        assert!(
            decrypt_envelope_noting_origin(
                &public_ct,
                Some(&public_nonce),
                RETIRED_PASSPHRASE,
                Some(RETIRED_IDENTITY),
                &previous,
                &[],
            )
            .is_err(),
            "a retired vault must not open mail sealed under a well-known key"
        );
        let (own_ct, own_nonce) =
            build_identity_envelope(V2_PLAINTEXT.as_bytes(), RETIRED_IDENTITY, b"astermail-envelope-v1");
        let own = decrypt_envelope_noting_origin(
            &own_ct,
            Some(&own_nonce),
            RETIRED_PASSPHRASE,
            Some(RETIRED_IDENTITY),
            &previous,
            &[],
        );
        assert_eq!(own.unwrap().0, V2_PLAINTEXT);
        crate::crypto::mail_legacy_retirement::reset_mail_legacy_retirement();
    }

    #[test]
    fn an_unretired_vault_still_opens_legacy_mail() {
        let material = retired_vault_material(serde_json::Value::Null);
        assert!(!material.mail_legacy_retired);
        crate::crypto::mail_legacy_retirement::reset_mail_legacy_retirement();
        let previous: Vec<String> = material.previous_keys.to_vec();
        for blob in [V2_CURRENT, V2_LEGACY_ONLY] {
            let opened = decrypt_envelope_noting_origin(blob, Some("Ag=="), RETIRED_PASSPHRASE, None, &[], &[]);
            assert_eq!(opened.unwrap().0, V2_PLAINTEXT);
        }
        let (public_ct, public_nonce) = public_identity_envelope();
        let opened = decrypt_envelope_noting_origin(
            &public_ct,
            Some(&public_nonce),
            RETIRED_PASSPHRASE,
            Some(RETIRED_IDENTITY),
            &previous,
            &[],
        );
        assert_eq!(opened.unwrap().0, V2_PLAINTEXT);
    }

    #[test]
    fn a_pinned_account_stays_retired_when_the_vault_drops_the_marker() {
        let user = uuid::Uuid::new_v4();
        let dir = tempfile::tempdir().unwrap();
        crate::crypto::mail_legacy_retirement::sync_mail_legacy_retirement_in(Some(dir.path()), true, &user).unwrap();
        let material = retired_vault_material(serde_json::Value::Null);
        crate::crypto::mail_legacy_retirement::sync_mail_legacy_retirement_in(
            Some(dir.path()),
            material.mail_legacy_retired,
            &user,
        )
        .unwrap();
        assert!(
            decrypt_envelope_noting_origin(V2_LEGACY_ONLY, Some("Ag=="), RETIRED_PASSPHRASE, None, &[], &[])
                .is_err()
        );
        crate::crypto::mail_legacy_retirement::reset_mail_legacy_retirement();
    }

    #[test]
    fn storage_key_envelopes_opened_by_a_public_key_are_not_authenticated() {
        let public: Zeroizing<[u8; 32]> = Zeroizing::new({
            use sha2::Digest;
            Sha256::digest(b"undefinedastermail-envelope-v1").into()
        });
        let private = v2_key(V2_DATA_KEK);
        let salt = [7u8; SALT_LEN];
        let iv = [9u8; NONCE_LEN];
        let forged = seal_storage_key_envelope(V2_PLAINTEXT, &public, &salt, &iv).unwrap();
        let genuine = seal_storage_key_envelope(V2_PLAINTEXT, &private, &salt, &iv).unwrap();
        let ring = [public.clone(), private.clone()];

        let (plain, origin) = open_storage_key_envelope_noting_origin(&forged, &ring).unwrap();
        assert_eq!(plain, V2_PLAINTEXT);
        assert!(!origin.authenticated(), "a public storage key opened a row as own mail");

        let (plain, origin) = open_storage_key_envelope_noting_origin(&genuine, &ring).unwrap();
        assert_eq!(plain, V2_PLAINTEXT);
        assert_eq!(origin, EnvelopeOrigin::SelfAuthored);

        let (_, origin) = open_storage_key_envelope_noting_origin(V2_CURRENT, &[v2_key(V2_DATA_KEK)]).unwrap();
        assert_eq!(origin, EnvelopeOrigin::SelfAuthored);

        for (material, context) in [("undefined", "astermail-tags-v1"), ("null", "astermail-envelope-v1"), ("", "astermail-draft-v2")] {
            let derived: Zeroizing<[u8; 32]> = Zeroizing::new({
                use sha2::Digest;
                let mut hasher = Sha256::new();
                hasher.update(material.as_bytes());
                hasher.update(context.as_bytes());
                hasher.finalize().into()
            });
            let forged = seal_storage_key_envelope(V2_PLAINTEXT, &derived, &salt, &iv).unwrap();
            let (_, origin) = open_storage_key_envelope_noting_origin(&forged, &[derived.clone(), private.clone()]).unwrap();
            assert!(!origin.authenticated(), "a key derived from public identity material opened a row as own mail");
        }
    }

    #[test]
    fn identity_envelopes_opened_by_public_material_are_not_authenticated() {
        let (public_ct, public_nonce) = public_identity_envelope();
        let nonce = STANDARD.decode(&public_nonce).unwrap();
        let (plain, origin) = open_identity_or_passphrase_envelope(
            &public_ct,
            &nonce,
            VAULT_PASSPHRASE.as_bytes(),
            Some(RETIRED_IDENTITY),
            &["undefined".to_string()],
            false,
        )
        .unwrap();
        assert_eq!(plain, V2_PLAINTEXT);
        assert!(!origin.authenticated(), "a previous public key opened a row as own mail");

        let (plain, origin) = open_identity_or_passphrase_envelope(
            &public_ct,
            &nonce,
            VAULT_PASSPHRASE.as_bytes(),
            Some("undefined"),
            &[],
            false,
        )
        .unwrap();
        assert_eq!(plain, V2_PLAINTEXT);
        assert!(!origin.authenticated(), "a public identity key opened a row as own mail");

        assert!(open_identity_or_passphrase_envelope(
            &public_ct,
            &nonce,
            VAULT_PASSPHRASE.as_bytes(),
            Some("undefined"),
            &[],
            true,
        )
        .is_err());

        let (sealed, sealed_nonce) = encrypt_identity_key_envelope("own", RETIRED_IDENTITY).unwrap();
        let sealed_nonce = STANDARD.decode(&sealed_nonce).unwrap();
        let (plain, origin) = open_identity_or_passphrase_envelope(
            &sealed,
            &sealed_nonce,
            VAULT_PASSPHRASE.as_bytes(),
            Some(RETIRED_IDENTITY),
            &["undefined".to_string()],
            false,
        )
        .unwrap();
        assert_eq!(plain, "own");
        assert_eq!(origin, EnvelopeOrigin::SelfAuthored);
    }

    #[test]
    fn passphrase_envelopes_need_a_private_passphrase_to_count_as_own() {
        let nonce = [0u8; NONCE_LEN];
        let sealed = encrypt_pbkdf2_envelope("own", VAULT_PASSPHRASE.as_bytes()).unwrap();
        let (_, origin) =
            open_identity_or_passphrase_envelope(&sealed, &nonce, VAULT_PASSPHRASE.as_bytes(), None, &[], false)
                .unwrap();
        assert_eq!(origin, EnvelopeOrigin::SelfAuthored);

        let forged = encrypt_pbkdf2_envelope("forged", b"").unwrap();
        let (plain, origin) = open_identity_or_passphrase_envelope(&forged, &nonce, b"", None, &[], false).unwrap();
        assert_eq!(plain, "forged");
        assert!(!origin.authenticated(), "an empty passphrase opened a row as own mail");
    }

    #[test]
    fn mail_is_never_sealed_under_a_well_known_key() {
        assert!(encrypt_identity_key_envelope("x", "undefined").is_err());
        assert!(encrypt_identity_key_envelope("x", "").is_err());
        assert!(encrypt_identity_key_envelope_with_version("x", "undefined", "astermail-import-v1").is_err());
        let public: [u8; 32] = {
            use sha2::Digest;
            Sha256::digest(b"undefinedastermail-envelope-v1").into()
        };
        assert!(encrypt_storage_key_envelope("x", &public).is_err());
        assert!(encrypt_identity_key_envelope("x", RETIRED_IDENTITY).is_ok());
    }

    fn open_with_external(
        envelope: &str,
        nonce: Option<&str>,
        identity_key: Option<&str>,
        external: Option<&ExternalPgpKey>,
    ) -> Result<(String, EnvelopeOrigin)> {
        decrypt_envelope_noting_origin_with_external_key(
            envelope,
            nonce,
            VAULT_PASSPHRASE.as_bytes(),
            identity_key,
            &[],
            &[],
            external,
        )
    }

    #[test]
    fn a_pgp_envelope_to_the_external_key_opens_after_own_keys_fail() {
        let owner = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let owner_armored = owner.to_armored().unwrap();
        for bytes in [
            crate::crypto::external_pgp_key::test_keys::curve25519_legacy_secret_key(),
            crate::crypto::external_pgp_key::test_keys::rsa_3072_secret_key(),
        ] {
            let external = crate::crypto::external_pgp_key::external_key_for_tests(&bytes);
            let pair = aster_crypto::import_secret_key_bytes(&bytes).unwrap();
            let envelope = pgp_envelope_for(&pair, r#"{"body":"outside"}"#);

            assert!(open_with_external(&envelope, None, Some(&owner_armored), None).is_err());
            let (plaintext, origin) =
                open_with_external(&envelope, None, Some(&owner_armored), Some(&external)).unwrap();
            assert_eq!(plaintext, r#"{"body":"outside"}"#);
            assert_eq!(origin, EnvelopeOrigin::UnsignedPgp);
            assert!(!origin.authenticated());

            let (without_identity, _) = open_with_external(&envelope, Some(""), None, Some(&external)).unwrap();
            assert_eq!(without_identity, r#"{"body":"outside"}"#);
        }
    }

    #[test]
    fn own_keys_still_win_when_an_external_key_is_loaded() {
        let owner = crate::crypto::account_key::tests::protected_keypair(VAULT_PASSPHRASE);
        let owner_armored = owner.to_armored().unwrap();
        let external = crate::crypto::external_pgp_key::external_key_for_tests(
            &crate::crypto::external_pgp_key::test_keys::curve25519_legacy_secret_key(),
        );
        let sealed =
            crate::crypto::sent_copy::seal_sent_envelope("{}", &owner_armored, VAULT_PASSPHRASE.as_bytes()).unwrap();

        let (_, origin) = open_with_external(&sealed, None, Some(&owner_armored), Some(&external)).unwrap();

        assert_eq!(origin, EnvelopeOrigin::SelfAuthored);
    }

    #[test]
    fn the_external_key_never_opens_an_identity_key_envelope() {
        let external = crate::crypto::external_pgp_key::external_key_for_tests(
            &crate::crypto::external_pgp_key::test_keys::curve25519_legacy_secret_key(),
        );
        let (data, nonce) = build_identity_envelope(b"{}", FIXTURE_IDENTITY_KEY, ENVELOPE_VERSION_DEFAULT.as_bytes());

        assert!(open_with_external(&data, Some(&nonce), None, Some(&external)).is_err());
        assert!(open_with_external(&data, Some(&nonce), Some(FIXTURE_IDENTITY_KEY), Some(&external)).is_ok());
    }
}
