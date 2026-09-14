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
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::ratchet::{ecdh_p256, jwk_d_bytes, ml_kem768_decapsulate};
use crate::crypto::vault::VaultContents;
use crate::error::{BridgeError, Result};

pub const INBOUND_ECDH_MARKER: u8 = 0x03;
pub const INBOUND_PQ_HYBRID_MARKER: u8 = 0x04;

const EPHEMERAL_POINT_LEN: usize = 65;
const ML_KEM_768_CT_LEN: usize = 1088;
const ML_KEM_768_DK_LEN: usize = 2400;
const GCM_TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MAX_INFLATED_BYTES: usize = 64 * 1024 * 1024;

const INFO_ECDH: &[u8] = b"aster-inbound-v1";
const INFO_PQ: &[u8] = b"aster-inbound-pq-v1";

#[derive(Zeroize, Clone)]
pub struct InboundKeyCandidate {
    pub ecdh_secret_d: Vec<u8>,
    pub pq_decap_key: Option<Vec<u8>>,
}

fn decode_pq_decap_key(expanded_b64: Option<&str>, seed_b64: Option<&str>) -> Option<Vec<u8>> {
    if let Some(expanded) = expanded_b64 {
        if let Ok(bytes) = STANDARD.decode(expanded.trim()) {
            if bytes.len() == ML_KEM_768_DK_LEN {
                return Some(bytes);
            }
        }
    }
    let seed = STANDARD.decode(seed_b64?.trim()).ok()?;
    if seed.len() != 64 {
        return None;
    }
    let d = ml_kem::array::Array::try_from(&seed[..32]).ok()?;
    let z = ml_kem::array::Array::try_from(&seed[32..]).ok()?;
    let (dk, _ek) = MlKem768::generate_deterministic(&d, &z);
    Some(dk.as_bytes().to_vec())
}

fn push_candidate(
    candidates: &mut Vec<InboundKeyCandidate>,
    identity_jwk: Option<&str>,
    pq_expanded_b64: Option<&str>,
    pq_seed_b64: Option<&str>,
) {
    let Some(jwk) = identity_jwk else {
        return;
    };
    let Ok(ecdh_secret_d) = jwk_d_bytes(jwk) else {
        return;
    };
    candidates.push(InboundKeyCandidate {
        ecdh_secret_d,
        pq_decap_key: decode_pq_decap_key(pq_expanded_b64, pq_seed_b64),
    });
}

pub fn build_inbound_key_candidates(vault: &VaultContents) -> Vec<InboundKeyCandidate> {
    let mut candidates = Vec::new();
    push_candidate(
        &mut candidates,
        vault.ratchet_identity_key.as_deref(),
        vault.ratchet_pq_identity_key.as_deref(),
        vault.ratchet_pq_identity_seed.as_deref(),
    );
    if let Some(previous) = &vault.ratchet_previous_keys {
        for p in previous {
            push_candidate(
                &mut candidates,
                p.ratchet_identity_key.as_deref(),
                p.ratchet_pq_identity_key.as_deref(),
                p.ratchet_pq_identity_seed.as_deref(),
            );
        }
    }
    candidates
}

pub fn is_inbound_payload(encrypted_data_b64: &str, nonce_b64: &str) -> bool {
    let Ok(nonce_bytes) = STANDARD.decode(nonce_b64) else {
        return false;
    };
    if nonce_bytes.len() != NONCE_LEN {
        return false;
    }
    let Ok(data) = STANDARD.decode(encrypted_data_b64) else {
        return false;
    };
    matches!(
        data.first(),
        Some(&INBOUND_ECDH_MARKER) | Some(&INBOUND_PQ_HYBRID_MARKER)
    )
}

fn hkdf_aes_key(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|e| BridgeError::Crypto(format!("hkdf expand: {}", e)))?;
    Ok(key)
}

fn decrypt_and_inflate(mut aes_key: [u8; 32], nonce_bytes: &[u8], ciphertext: &[u8]) -> Option<String> {
    let cipher = match Aes256Gcm::new_from_slice(&aes_key) {
        Ok(c) => c,
        Err(_) => {
            aes_key.zeroize();
            return None;
        }
    };
    aes_key.zeroize();
    let nonce = Nonce::from_slice(nonce_bytes);
    let compressed = Zeroizing::new(cipher.decrypt(nonce, ciphertext).ok()?);
    let inflated = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
        &compressed,
        MAX_INFLATED_BYTES,
    )
    .ok()?;
    match String::from_utf8(inflated) {
        Ok(s) => Some(s),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            None
        }
    }
}

fn try_ecdh_candidate(
    candidate: &InboundKeyCandidate,
    ephemeral_point: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Option<String> {
    let mut shared_x = ecdh_p256(&candidate.ecdh_secret_d, ephemeral_point).ok()?;
    let key = hkdf_aes_key(&shared_x, INFO_ECDH).ok();
    shared_x.zeroize();
    decrypt_and_inflate(key?, nonce_bytes, ciphertext)
}

fn try_pq_candidate(
    candidate: &InboundKeyCandidate,
    ephemeral_point: &[u8],
    kem_ciphertext: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Option<String> {
    let pq_key = candidate.pq_decap_key.as_deref()?;
    let mut shared_x = ecdh_p256(&candidate.ecdh_secret_d, ephemeral_point).ok()?;
    let mut kem_ss = match ml_kem768_decapsulate(kem_ciphertext, pq_key) {
        Ok(ss) => ss,
        Err(_) => {
            shared_x.zeroize();
            return None;
        }
    };
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&shared_x);
    ikm[32..].copy_from_slice(&kem_ss[..32]);
    shared_x.zeroize();
    kem_ss.zeroize();
    let key = hkdf_aes_key(&ikm, INFO_PQ).ok();
    ikm.zeroize();
    decrypt_and_inflate(key?, nonce_bytes, ciphertext)
}

pub fn decrypt_inbound_envelope(
    payload: &[u8],
    nonce_bytes: &[u8],
    candidates: &[InboundKeyCandidate],
) -> Result<String> {
    if nonce_bytes.len() != NONCE_LEN {
        return Err(BridgeError::Crypto("inbound nonce must be 12 bytes".to_string()));
    }
    if candidates.is_empty() {
        return Err(BridgeError::Crypto("no inbound key candidates".to_string()));
    }
    match payload.first() {
        Some(&INBOUND_ECDH_MARKER) => {
            if payload.len() < 1 + EPHEMERAL_POINT_LEN + GCM_TAG_LEN {
                return Err(BridgeError::Crypto("inbound envelope too short".to_string()));
            }
            let ephemeral_point = &payload[1..1 + EPHEMERAL_POINT_LEN];
            let ciphertext = &payload[1 + EPHEMERAL_POINT_LEN..];
            for candidate in candidates {
                if let Some(s) =
                    try_ecdh_candidate(candidate, ephemeral_point, nonce_bytes, ciphertext)
                {
                    return Ok(s);
                }
            }
            Err(BridgeError::Crypto(
                "inbound envelope decrypt failed for all candidates".to_string(),
            ))
        }
        Some(&INBOUND_PQ_HYBRID_MARKER) => {
            if payload.len() < 1 + EPHEMERAL_POINT_LEN + ML_KEM_768_CT_LEN + GCM_TAG_LEN {
                return Err(BridgeError::Crypto("inbound pq envelope too short".to_string()));
            }
            let ephemeral_point = &payload[1..1 + EPHEMERAL_POINT_LEN];
            let kem_ciphertext =
                &payload[1 + EPHEMERAL_POINT_LEN..1 + EPHEMERAL_POINT_LEN + ML_KEM_768_CT_LEN];
            let ciphertext = &payload[1 + EPHEMERAL_POINT_LEN + ML_KEM_768_CT_LEN..];
            for candidate in candidates {
                if let Some(s) = try_pq_candidate(
                    candidate,
                    ephemeral_point,
                    kem_ciphertext,
                    nonce_bytes,
                    ciphertext,
                ) {
                    return Ok(s);
                }
            }
            Err(BridgeError::Crypto(
                "inbound pq envelope decrypt failed for all candidates".to_string(),
            ))
        }
        _ => Err(BridgeError::Crypto("not an inbound envelope".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use ml_kem::kem::Encapsulate;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand_core::OsRng;

    fn candidate_from(sk: &SecretKey, pq_decap_key: Option<Vec<u8>>) -> InboundKeyCandidate {
        InboundKeyCandidate {
            ecdh_secret_d: sk.to_bytes().to_vec(),
            pq_decap_key,
        }
    }

    fn encrypt_ecdh(plaintext: &[u8], recipient: &SecretKey, nonce_bytes: &[u8; 12]) -> Vec<u8> {
        let recipient_pub = recipient.public_key().to_encoded_point(false);
        let ephemeral = SecretKey::random(&mut OsRng);
        let eph_pub = ephemeral.public_key().to_encoded_point(false);
        let shared_x =
            ecdh_p256(ephemeral.to_bytes().as_slice(), recipient_pub.as_bytes()).unwrap();
        let key = hkdf_aes_key(&shared_x, INFO_ECDH).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(plaintext, 6);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce_bytes), compressed.as_slice())
            .unwrap();
        let mut out = vec![INBOUND_ECDH_MARKER];
        out.extend_from_slice(eph_pub.as_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    fn encrypt_pq(
        plaintext: &[u8],
        recipient: &SecretKey,
        recipient_ek: &<MlKem768 as KemCore>::EncapsulationKey,
        nonce_bytes: &[u8; 12],
    ) -> Vec<u8> {
        let recipient_pub = recipient.public_key().to_encoded_point(false);
        let ephemeral = SecretKey::random(&mut OsRng);
        let eph_pub = ephemeral.public_key().to_encoded_point(false);
        let shared_x =
            ecdh_p256(ephemeral.to_bytes().as_slice(), recipient_pub.as_bytes()).unwrap();
        let (kem_ct, kem_ss) = recipient_ek.encapsulate(&mut OsRng).unwrap();
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&shared_x);
        ikm[32..].copy_from_slice(&kem_ss.as_slice()[..32]);
        let key = hkdf_aes_key(&ikm, INFO_PQ).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(plaintext, 6);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce_bytes), compressed.as_slice())
            .unwrap();
        let mut out = vec![INBOUND_PQ_HYBRID_MARKER];
        out.extend_from_slice(eph_pub.as_bytes());
        out.extend_from_slice(kem_ct.as_slice());
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn ecdh_envelope_round_trips() {
        let recipient = SecretKey::random(&mut OsRng);
        let nonce = [7u8; 12];
        let json = r#"{"subject":"hello","body_text":"inbound"}"#;
        let payload = encrypt_ecdh(json.as_bytes(), &recipient, &nonce);
        let candidates = [candidate_from(&recipient, None)];
        let out = decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn pq_envelope_round_trips() {
        let recipient = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let nonce = [9u8; 12];
        let json = r#"{"subject":"pq","body_text":"hybrid"}"#;
        let payload = encrypt_pq(json.as_bytes(), &recipient, &ek, &nonce);
        let candidates = [candidate_from(&recipient, Some(dk.as_bytes().to_vec()))];
        let out = decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn wrong_key_fails_without_panic() {
        let recipient = SecretKey::random(&mut OsRng);
        let wrong = SecretKey::random(&mut OsRng);
        let nonce = [1u8; 12];
        let payload = encrypt_ecdh(b"{\"subject\":\"x\"}", &recipient, &nonce);
        let candidates = [candidate_from(&wrong, None)];
        assert!(decrypt_inbound_envelope(&payload, &nonce, &candidates).is_err());
    }

    #[test]
    fn truncated_payloads_are_rejected_not_panicking() {
        let recipient = SecretKey::random(&mut OsRng);
        let candidates = [candidate_from(&recipient, None)];
        let nonce = [2u8; 12];
        for len in [0usize, 1, 40, 65, 81] {
            let payload = vec![INBOUND_ECDH_MARKER; len.max(1)][..len].to_vec();
            assert!(decrypt_inbound_envelope(&payload, &nonce, &candidates).is_err());
        }
        for len in [1usize, 66, 1153, 1169] {
            let payload = vec![INBOUND_PQ_HYBRID_MARKER; len];
            assert!(decrypt_inbound_envelope(&payload, &nonce, &candidates).is_err());
        }
        let payload = encrypt_ecdh(b"{}", &recipient, &nonce);
        assert!(decrypt_inbound_envelope(&payload, &[0u8; 8], &candidates).is_err());
    }

    #[test]
    fn pq_candidate_without_secret_is_skipped_not_fatal() {
        let old = SecretKey::random(&mut OsRng);
        let current = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let nonce = [3u8; 12];
        let json = r#"{"subject":"skip"}"#;
        let payload = encrypt_pq(json.as_bytes(), &current, &ek, &nonce);
        let candidates = [
            candidate_from(&old, None),
            candidate_from(&current, Some(dk.as_bytes().to_vec())),
        ];
        let out = decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn previous_key_fallback_succeeds_after_rotation() {
        let rotated_away = SecretKey::random(&mut OsRng);
        let current = SecretKey::random(&mut OsRng);
        let nonce = [4u8; 12];
        let json = r#"{"subject":"old mail"}"#;
        let payload = encrypt_ecdh(json.as_bytes(), &rotated_away, &nonce);
        let candidates = [
            candidate_from(&current, None),
            candidate_from(&rotated_away, None),
        ];
        let out = decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn pq_decap_key_derives_from_seed_when_expanded_absent() {
        let seed = [42u8; 64];
        let d = ml_kem::array::Array::try_from(&seed[..32]).unwrap();
        let z = ml_kem::array::Array::try_from(&seed[32..]).unwrap();
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        let seed_b64 = STANDARD.encode(seed);
        let derived = decode_pq_decap_key(None, Some(&seed_b64)).unwrap();
        assert_eq!(derived, dk.as_bytes().to_vec());

        let recipient = SecretKey::random(&mut OsRng);
        let nonce = [5u8; 12];
        let json = r#"{"subject":"seed"}"#;
        let payload = encrypt_pq(json.as_bytes(), &recipient, &ek, &nonce);
        let candidates = [candidate_from(&recipient, Some(derived))];
        let out = decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn build_candidates_orders_current_before_previous() {
        let current = SecretKey::random(&mut OsRng);
        let previous = SecretKey::random(&mut OsRng);
        let jwk = |sk: &SecretKey| {
            serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "d": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sk.to_bytes().as_slice()),
            })
            .to_string()
        };
        let vault_json = serde_json::json!({
            "identity_key": "ik",
            "ratchet_identity_key": jwk(&current),
            "ratchet_previous_keys": [
                { "ratchet_identity_key": jwk(&previous) }
            ]
        })
        .to_string();
        let vault: VaultContents = serde_json::from_str(&vault_json).unwrap();
        let candidates = build_inbound_key_candidates(&vault);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].ecdh_secret_d, current.to_bytes().to_vec());
        assert_eq!(candidates[1].ecdh_secret_d, previous.to_bytes().to_vec());
        assert!(candidates[0].pq_decap_key.is_none());
    }

    #[test]
    fn is_inbound_payload_detects_markers_only_with_twelve_byte_nonce() {
        let nonce12 = STANDARD.encode([0u8; 12]);
        let nonce1 = STANDARD.encode([0x01u8]);
        let ecdh = STANDARD.encode([INBOUND_ECDH_MARKER, 0, 0]);
        let pq = STANDARD.encode([INBOUND_PQ_HYBRID_MARKER, 0, 0]);
        let other = STANDARD.encode([0x07u8, 0, 0]);
        assert!(is_inbound_payload(&ecdh, &nonce12));
        assert!(is_inbound_payload(&pq, &nonce12));
        assert!(!is_inbound_payload(&other, &nonce12));
        assert!(!is_inbound_payload(&ecdh, &nonce1));
        assert!(!is_inbound_payload("!!!", &nonce12));
    }
}
