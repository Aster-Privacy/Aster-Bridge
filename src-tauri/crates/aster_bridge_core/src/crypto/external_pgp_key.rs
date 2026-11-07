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
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api_client::ApiClient;
use crate::error::{BridgeError, Result};

pub const EXTERNAL_KEY_CONTEXT: &str = "aster-external-pgp-v1";
const WRAP_FORMAT_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const DATA_KEK_LEN: usize = 32;
const FINGERPRINT_HEX_LEN: usize = 40;

#[derive(Clone)]
pub struct ExternalPgpKey {
    fingerprint: String,
    key: std::sync::Arc<aster_crypto::KeyPair>,
}

impl std::fmt::Debug for ExternalPgpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalPgpKey")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl ExternalPgpKey {
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn decrypt_armored(&self, armored: &str) -> Option<Zeroizing<Vec<u8>>> {
        aster_crypto::decrypt_message(armored.as_bytes(), &[self.key.as_ref()])
            .ok()
            .map(Zeroizing::new)
    }
}

const OWN_MAIL_FOLDERS: [&str; 4] = ["sent", "drafts", "draft", "scheduled"];
const OWN_MAIL_ITEM_TYPES: [&str; 4] = ["sent", "draft", "drafts", "scheduled"];

pub(crate) fn external_key_allowed(folder: &str, item_type: Option<&str>) -> bool {
    let folder = folder.trim();
    let own_folder = OWN_MAIL_FOLDERS.iter().any(|own| own.eq_ignore_ascii_case(folder));
    let own_item = item_type
        .map(str::trim)
        .is_some_and(|kind| OWN_MAIL_ITEM_TYPES.iter().any(|own| own.eq_ignore_ascii_case(kind)));
    !own_folder && !own_item
}

pub(crate) fn external_key_for<'a>(
    external_key: Option<&'a ExternalPgpKey>,
    folder: &str,
    item_type: Option<&str>,
) -> Option<&'a ExternalPgpKey> {
    external_key.filter(|_| external_key_allowed(folder, item_type))
}

fn every_secret_is_unprotected(key: &aster_crypto::KeyPair) -> bool {
    let secret = key.secret_key();
    secret.primary_key.secret_params().string_to_key_id() == 0
        && secret
            .secret_subkeys
            .iter()
            .all(|subkey| subkey.key.secret_params().string_to_key_id() == 0)
}

fn normalized_fingerprint(fingerprint: &str) -> Result<String> {
    let fingerprint = fingerprint.trim().to_ascii_lowercase();
    if fingerprint.len() != FINGERPRINT_HEX_LEN || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BridgeError::Crypto("external key fingerprint is malformed".to_string()));
    }
    Ok(fingerprint)
}

fn wrap_user_id(user_id: &Uuid) -> String {
    user_id.to_string().to_ascii_lowercase()
}

fn wrap_aad(user_id: &str, fingerprint: &str) -> String {
    format!("{}|{}|{}", EXTERNAL_KEY_CONTEXT, user_id, fingerprint)
}

fn derive_wrap_key(data_kek_b64: &str, user_id: &str) -> Result<Zeroizing<[u8; 32]>> {
    let data_kek = Zeroizing::new(
        STANDARD
            .decode(data_kek_b64.trim())
            .map_err(|_| BridgeError::Crypto("data_kek is not valid base64".to_string()))?,
    );
    if data_kek.len() != DATA_KEK_LEN {
        return Err(BridgeError::Crypto("data_kek must be 32 bytes".to_string()));
    }
    let hk = Hkdf::<Sha256>::new(Some(EXTERNAL_KEY_CONTEXT.as_bytes()), &data_kek);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(user_id.as_bytes(), okm.as_mut())
        .map_err(|_| BridgeError::Crypto("external key derivation failed".to_string()))?;
    Ok(okm)
}

pub fn unwrap_external_key(
    data_kek_b64: &str,
    user_id: &Uuid,
    fingerprint: &str,
    wrapped_private_key_b64: &str,
) -> Result<ExternalPgpKey> {
    let fingerprint = normalized_fingerprint(fingerprint)?;
    let user_id = wrap_user_id(user_id);
    let wrap_key = derive_wrap_key(data_kek_b64, &user_id)?;
    let blob = STANDARD
        .decode(wrapped_private_key_b64.trim())
        .map_err(|_| BridgeError::Crypto("wrapped external key is not valid base64".to_string()))?;
    if blob.len() <= 1 + NONCE_LEN + TAG_LEN || blob[0] != WRAP_FORMAT_VERSION {
        return Err(BridgeError::Crypto("wrapped external key has an unknown format".to_string()));
    }
    let cipher = Aes256Gcm::new_from_slice(wrap_key.as_slice())
        .map_err(|_| BridgeError::Crypto("external key cipher init failed".to_string()))?;
    let aad = wrap_aad(&user_id, &fingerprint);
    let secret_key_bytes = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&blob[1..1 + NONCE_LEN]),
                Payload {
                    msg: &blob[1 + NONCE_LEN..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| BridgeError::Crypto("wrapped external key failed to open".to_string()))?,
    );
    let key = aster_crypto::import_secret_key_bytes(&secret_key_bytes)
        .map_err(|_| BridgeError::Crypto("external key could not be parsed".to_string()))?;
    if key.fingerprint().to_ascii_lowercase() != fingerprint {
        return Err(BridgeError::Crypto("external key fingerprint does not match".to_string()));
    }
    if !every_secret_is_unprotected(&key) {
        return Err(BridgeError::Crypto("external key is passphrase protected".to_string()));
    }
    Ok(ExternalPgpKey {
        fingerprint,
        key: std::sync::Arc::new(key),
    })
}

pub async fn load_external_pgp_key(
    client: &ApiClient,
    access_token: &str,
    user_id: &Uuid,
    data_kek_b64: Option<&str>,
) -> Result<Option<ExternalPgpKey>> {
    let Some(data_kek_b64) = data_kek_b64.map(str::trim).filter(|k| !k.is_empty()) else {
        return Ok(None);
    };
    let Some(record) = client.get_external_pgp_key(access_token).await? else {
        return Ok(None);
    };
    let Some(wrapped) = record
        .wrapped_private_key
        .as_deref()
        .map(str::trim)
        .filter(|w| !w.is_empty())
    else {
        return Ok(None);
    };
    match unwrap_external_key(data_kek_b64, user_id, &record.fingerprint, wrapped) {
        Ok(key) => Ok(Some(key)),
        Err(e) => {
            tracing::debug!("external PGP key skipped: {}", e);
            Ok(None)
        }
    }
}

#[cfg(test)]
pub(crate) fn wrap_external_key_for_tests(
    data_kek_b64: &str,
    user_id: &Uuid,
    fingerprint: &str,
    secret_key_bytes: &[u8],
    nonce: [u8; NONCE_LEN],
) -> String {
    let user_id = wrap_user_id(user_id);
    let fingerprint = fingerprint.to_ascii_lowercase();
    let wrap_key = derive_wrap_key(data_kek_b64, &user_id).unwrap();
    let cipher = Aes256Gcm::new_from_slice(wrap_key.as_slice()).unwrap();
    let aad = wrap_aad(&user_id, &fingerprint);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret_key_bytes,
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    let mut blob = vec![WRAP_FORMAT_VERSION];
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    STANDARD.encode(blob)
}

#[cfg(test)]
pub(crate) fn external_key_for_tests(secret_key_bytes: &[u8]) -> ExternalPgpKey {
    let key = aster_crypto::import_secret_key_bytes(secret_key_bytes).unwrap();
    ExternalPgpKey {
        fingerprint: key.fingerprint().to_ascii_lowercase(),
        key: std::sync::Arc::new(key),
    }
}

#[cfg(test)]
pub(crate) mod test_keys {
    use pgp::composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::ser::Serialize;

    fn generate(primary: KeyType, encryption: KeyType) -> Vec<u8> {
        generate_protected(primary, encryption, None, None)
    }

    fn generate_protected(
        primary: KeyType,
        encryption: KeyType,
        primary_passphrase: Option<&str>,
        subkey_passphrase: Option<&str>,
    ) -> Vec<u8> {
        let rng = rand::rngs::OsRng;
        let params = SecretKeyParamsBuilder::default()
            .key_type(primary)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Outside <outside@example.com>".into())
            .passphrase(primary_passphrase.map(str::to_string))
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(encryption)
                    .can_encrypt(true)
                    .passphrase(subkey_passphrase.map(str::to_string))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let unlock = primary_passphrase.unwrap_or_default().to_string();
        let signed = params
            .generate(rng)
            .unwrap()
            .sign(rng, move || unlock)
            .unwrap();
        signed.to_bytes().unwrap()
    }

    pub(crate) fn protected_primary_secret_key() -> Vec<u8> {
        generate_protected(
            KeyType::EdDSALegacy,
            KeyType::ECDH(ECCCurve::Curve25519),
            Some("outside"),
            None,
        )
    }

    pub(crate) fn protected_subkey_secret_key() -> Vec<u8> {
        generate_protected(
            KeyType::EdDSALegacy,
            KeyType::ECDH(ECCCurve::Curve25519),
            None,
            Some("outside"),
        )
    }

    pub(crate) fn curve25519_legacy_secret_key() -> Vec<u8> {
        generate(KeyType::EdDSALegacy, KeyType::ECDH(ECCCurve::Curve25519))
    }

    pub(crate) fn rsa_3072_secret_key() -> Vec<u8> {
        generate(KeyType::Rsa(3072), KeyType::Rsa(3072))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_ID: &str = "6F1C2D3E-4A5B-4C6D-8E9F-0A1B2C3D4E5F";

    fn data_kek() -> String {
        STANDARD.encode([42u8; 32])
    }

    fn user_id() -> Uuid {
        Uuid::parse_str(USER_ID).unwrap()
    }

    fn fixture() -> (Vec<u8>, String) {
        let bytes = test_keys::curve25519_legacy_secret_key();
        let fingerprint = aster_crypto::import_secret_key_bytes(&bytes).unwrap().fingerprint();
        (bytes, fingerprint)
    }

    fn wrap(bytes: &[u8], fingerprint: &str) -> String {
        wrap_external_key_for_tests(&data_kek(), &user_id(), fingerprint, bytes, [3u8; 12])
    }

    #[test]
    fn a_wrapped_key_opens_with_the_same_kek_and_user() {
        let (bytes, fingerprint) = fixture();
        let wrapped = wrap(&bytes, &fingerprint);

        let key = unwrap_external_key(&data_kek(), &user_id(), &fingerprint.to_ascii_uppercase(), &wrapped)
            .unwrap();

        assert_eq!(key.fingerprint(), fingerprint.to_ascii_lowercase());
        assert_eq!(key.key.to_bytes().unwrap(), bytes);
        assert!(!format!("{:?}", key).contains("key:"));
    }

    #[test]
    fn the_external_key_is_limited_to_inbound_mail() {
        for folder in ["inbox", "INBOX", "archive", "spam", "trash", "custom-token"] {
            assert!(external_key_allowed(folder, Some("received")), "{folder}");
            assert!(external_key_allowed(folder, None), "{folder}");
        }
        for folder in ["sent", "Sent", "drafts", "scheduled"] {
            assert!(!external_key_allowed(folder, Some("received")), "{folder}");
            assert!(!external_key_allowed(folder, None), "{folder}");
        }
        for item_type in ["sent", "draft", "drafts", "scheduled", "SENT"] {
            assert!(!external_key_allowed("inbox", Some(item_type)), "{item_type}");
            assert!(!external_key_allowed("custom-token", Some(item_type)), "{item_type}");
        }

        let key = external_key_for_tests(&test_keys::curve25519_legacy_secret_key());
        assert!(external_key_for(Some(&key), "inbox", Some("received")).is_some());
        assert!(external_key_for(Some(&key), "archive", Some("sent")).is_none());
        assert!(external_key_for(Some(&key), "sent", None).is_none());
        assert!(external_key_for(None, "inbox", Some("received")).is_none());
    }

    #[test]
    fn a_passphrase_protected_key_is_rejected() {
        for bytes in [test_keys::protected_primary_secret_key(), test_keys::protected_subkey_secret_key()] {
            let fingerprint = aster_crypto::import_secret_key_bytes(&bytes).unwrap().fingerprint();
            let wrapped = wrap(&bytes, &fingerprint);

            let error = unwrap_external_key(&data_kek(), &user_id(), &fingerprint, &wrapped).unwrap_err();

            assert!(error.to_string().contains("passphrase protected"));
        }
    }

    #[test]
    fn the_parsed_key_decrypts_repeatedly_and_clones_share_it() {
        let (bytes, fingerprint) = fixture();
        let pair = aster_crypto::import_secret_key_bytes(&bytes).unwrap();
        let wrapped = wrap(&bytes, &fingerprint);
        let key = unwrap_external_key(&data_kek(), &user_id(), &fingerprint, &wrapped).unwrap();
        let copy = key.clone();
        let armored = aster_crypto::encrypt_message(b"twice", &[&pair.public_key()]).unwrap();
        let armored = std::str::from_utf8(&armored).unwrap();

        assert_eq!(key.decrypt_armored(armored).unwrap().as_slice(), b"twice");
        assert_eq!(copy.decrypt_armored(armored).unwrap().as_slice(), b"twice");
        assert!(std::sync::Arc::ptr_eq(&key.key, &copy.key));
    }

    #[test]
    fn the_aad_binds_the_user_and_the_fingerprint() {
        let (bytes, fingerprint) = fixture();
        let wrapped = wrap(&bytes, &fingerprint);
        let other_user = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let other_fingerprint = "0".repeat(FINGERPRINT_HEX_LEN);

        assert!(unwrap_external_key(&data_kek(), &other_user, &fingerprint, &wrapped).is_err());
        assert!(unwrap_external_key(&data_kek(), &user_id(), &other_fingerprint, &wrapped).is_err());
        assert!(unwrap_external_key(&STANDARD.encode([7u8; 32]), &user_id(), &fingerprint, &wrapped).is_err());
    }

    #[test]
    fn a_tampered_blob_is_rejected() {
        let (bytes, fingerprint) = fixture();
        let wrapped = wrap(&bytes, &fingerprint);

        let mut flipped = STANDARD.decode(&wrapped).unwrap();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert!(unwrap_external_key(&data_kek(), &user_id(), &fingerprint, &STANDARD.encode(&flipped)).is_err());

        let mut wrong_version = STANDARD.decode(&wrapped).unwrap();
        wrong_version[0] = 0x02;
        assert!(
            unwrap_external_key(&data_kek(), &user_id(), &fingerprint, &STANDARD.encode(&wrong_version)).is_err()
        );
        assert!(unwrap_external_key(&data_kek(), &user_id(), &fingerprint, "AQID").is_err());
    }

    #[test]
    fn a_key_whose_fingerprint_differs_from_the_row_is_rejected() {
        let (bytes, _) = fixture();
        let (_, other_fingerprint) = fixture();
        let wrapped = wrap(&bytes, &other_fingerprint);

        let error = unwrap_external_key(&data_kek(), &user_id(), &other_fingerprint, &wrapped).unwrap_err();

        assert!(error.to_string().contains("fingerprint does not match"));
    }

    #[test]
    fn a_short_data_kek_is_rejected() {
        let (bytes, fingerprint) = fixture();
        let wrapped = wrap(&bytes, &fingerprint);

        assert!(unwrap_external_key(&STANDARD.encode([1u8; 16]), &user_id(), &fingerprint, &wrapped).is_err());
    }

    #[test]
    fn messages_to_an_external_key_decrypt_for_both_key_types() {
        for bytes in [test_keys::curve25519_legacy_secret_key(), test_keys::rsa_3072_secret_key()] {
            let pair = aster_crypto::import_secret_key_bytes(&bytes).unwrap();
            let fingerprint = pair.fingerprint();
            let wrapped = wrap(&bytes, &fingerprint);
            let key = unwrap_external_key(&data_kek(), &user_id(), &fingerprint, &wrapped).unwrap();
            let armored = aster_crypto::encrypt_message(b"hello from outside", &[&pair.public_key()]).unwrap();

            let plain = key.decrypt_armored(std::str::from_utf8(&armored).unwrap()).unwrap();

            assert_eq!(plain.as_slice(), b"hello from outside");
        }
    }

    const SHARED_VECTORS: &str = include_str!("testdata/external_pgp_key_vectors.json");

    fn vector_field<'a>(vector: &'a serde_json::Value, name: &str) -> &'a str {
        vector[name].as_str().unwrap()
    }

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn the_shared_cross_client_vector_unwraps_and_decrypts() {
        let vector: serde_json::Value = serde_json::from_str(SHARED_VECTORS).unwrap();
        assert_eq!(vector["version"].as_u64(), Some(u64::from(WRAP_FORMAT_VERSION)));
        let data_kek = STANDARD.encode(from_hex(vector_field(&vector, "data_kek_hex")));
        let user_id = Uuid::parse_str(vector_field(&vector, "user_id")).unwrap();
        let fingerprint = vector_field(&vector, "fingerprint");
        let wrapped = vector_field(&vector, "wrapped_private_key");
        let secret_key = STANDARD.decode(vector_field(&vector, "secret_key_b64")).unwrap();

        let wrap_key = derive_wrap_key(&data_kek, &wrap_user_id(&user_id)).unwrap();
        assert_eq!(to_hex(wrap_key.as_slice()), vector_field(&vector, "wrap_key_hex"));
        assert_eq!(wrap_aad(&wrap_user_id(&user_id), fingerprint), vector_field(&vector, "aad"));

        let nonce: [u8; NONCE_LEN] = from_hex(vector_field(&vector, "nonce_hex")).try_into().unwrap();
        assert_eq!(wrap_external_key_for_tests(&data_kek, &user_id, fingerprint, &secret_key, nonce), wrapped);

        let key = unwrap_external_key(&data_kek, &user_id, fingerprint, wrapped).unwrap();
        assert_eq!(key.key.to_bytes().unwrap(), secret_key);
        assert_eq!(key.fingerprint(), fingerprint);
        assert_eq!(key.key.fingerprint().to_ascii_lowercase(), fingerprint);

        let plain = key.decrypt_armored(vector_field(&vector, "message_armored")).unwrap();
        assert_eq!(plain.as_slice(), vector_field(&vector, "message_plaintext").as_bytes());
    }
}
