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
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::ratchet::{ecdh_p256, jwk_d_bytes, ml_kem768_decapsulate};
use crate::crypto::vault::VaultContents;
use crate::error::{BridgeError, Result};

pub const INBOUND_ECDH_MARKER: u8 = 0x03;
pub const INBOUND_PQ_HYBRID_MARKER: u8 = 0x04;
pub const INBOUND_ECDH_BOUND_MARKER: u8 = 0x05;
pub const INBOUND_PQ_HYBRID_BOUND_MARKER: u8 = 0x06;
pub const BOUND_ENVELOPE_VERSION: i16 = 1;

const EPHEMERAL_POINT_LEN: usize = 65;
const ML_KEM_768_CT_LEN: usize = 1088;
const ML_KEM_768_DK_LEN: usize = 2400;
const GCM_TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MAX_INFLATED_BYTES: usize = 64 * 1024 * 1024;

const INFO_ECDH: &[u8] = b"aster-inbound-v1";
const INFO_PQ: &[u8] = b"aster-inbound-pq-v1";
const INFO_ECDH_BOUND: &[u8] = b"aster-inbound-v2";
const INFO_PQ_BOUND: &[u8] = b"aster-inbound-pq-v2";
const BOUND_AAD_LABEL: &[u8] = b"aster-inbound-v2";

#[derive(Zeroize, Clone)]
pub struct InboundKeyCandidate {
    pub ecdh_secret_d: Vec<u8>,
    pub pq_decap_key: Option<Vec<u8>>,
    #[zeroize(skip)]
    pub owner: Option<[u8; 16]>,
}

pub fn bind_inbound_owner(candidates: &mut [InboundKeyCandidate], user_id: &uuid::Uuid) {
    for candidate in candidates.iter_mut() {
        candidate.owner = Some(*user_id.as_bytes());
    }
}

pub fn is_inbound_marker(marker: u8) -> bool {
    matches!(
        marker,
        INBOUND_ECDH_MARKER
            | INBOUND_PQ_HYBRID_MARKER
            | INBOUND_ECDH_BOUND_MARKER
            | INBOUND_PQ_HYBRID_BOUND_MARKER
    )
}

fn is_bound_marker(marker: u8) -> bool {
    matches!(marker, INBOUND_ECDH_BOUND_MARKER | INBOUND_PQ_HYBRID_BOUND_MARKER)
}

fn is_pq_marker(marker: u8) -> bool {
    matches!(marker, INBOUND_PQ_HYBRID_MARKER | INBOUND_PQ_HYBRID_BOUND_MARKER)
}

fn bound_aad(marker: u8, owner: &[u8; 16], header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BOUND_AAD_LABEL.len() + 1 + owner.len() + header.len());
    aad.extend_from_slice(BOUND_AAD_LABEL);
    aad.push(marker);
    aad.extend_from_slice(owner);
    aad.extend_from_slice(header);
    aad
}

pub(crate) fn decode_pq_decap_key(expanded_b64: Option<&str>, seed_b64: Option<&str>) -> Option<Vec<u8>> {
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
        owner: None,
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
    data.first().copied().is_some_and(is_inbound_marker)
}

fn hkdf_aes_key(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|e| BridgeError::Crypto(format!("hkdf expand: {}", e)))?;
    Ok(key)
}

fn decrypt_and_inflate(
    mut aes_key: [u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<String> {
    let cipher = match Aes256Gcm::new_from_slice(&aes_key) {
        Ok(c) => c,
        Err(_) => {
            aes_key.zeroize();
            return None;
        }
    };
    aes_key.zeroize();
    let nonce = Nonce::from_slice(nonce_bytes);
    let compressed = Zeroizing::new(cipher.decrypt(nonce, Payload { msg: ciphertext, aad }).ok()?);
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
    info: &[u8],
    aad: &[u8],
) -> Option<String> {
    let mut shared_x = ecdh_p256(&candidate.ecdh_secret_d, ephemeral_point).ok()?;
    let key = hkdf_aes_key(&shared_x, info).ok();
    shared_x.zeroize();
    decrypt_and_inflate(key?, nonce_bytes, ciphertext, aad)
}

#[allow(clippy::too_many_arguments)]
fn try_pq_candidate(
    candidate: &InboundKeyCandidate,
    ephemeral_point: &[u8],
    kem_ciphertext: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
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
    let key = hkdf_aes_key(&ikm, info).ok();
    ikm.zeroize();
    decrypt_and_inflate(key?, nonce_bytes, ciphertext, aad)
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
    let marker = match payload.first() {
        Some(&marker) if is_inbound_marker(marker) => marker,
        _ => return Err(BridgeError::Crypto("not an inbound envelope".to_string())),
    };
    let pq = is_pq_marker(marker);
    let bound = is_bound_marker(marker);
    let header_len = if pq {
        1 + EPHEMERAL_POINT_LEN + ML_KEM_768_CT_LEN
    } else {
        1 + EPHEMERAL_POINT_LEN
    };
    if payload.len() < header_len + GCM_TAG_LEN {
        let reason = if pq {
            "inbound pq envelope too short"
        } else {
            "inbound envelope too short"
        };
        return Err(BridgeError::Crypto(reason.to_string()));
    }
    let ephemeral_point = &payload[1..1 + EPHEMERAL_POINT_LEN];
    let kem_ciphertext = &payload[1 + EPHEMERAL_POINT_LEN..header_len];
    let ciphertext = &payload[header_len..];
    let info = match (pq, bound) {
        (false, false) => INFO_ECDH,
        (true, false) => INFO_PQ,
        (false, true) => INFO_ECDH_BOUND,
        (true, true) => INFO_PQ_BOUND,
    };
    for candidate in candidates {
        let aad = match (bound, candidate.owner.as_ref()) {
            (false, _) => Vec::new(),
            (true, Some(owner)) => bound_aad(marker, owner, &payload[1..header_len]),
            (true, None) => continue,
        };
        let plaintext = if pq {
            try_pq_candidate(
                candidate,
                ephemeral_point,
                kem_ciphertext,
                nonce_bytes,
                ciphertext,
                info,
                &aad,
            )
        } else {
            try_ecdh_candidate(candidate, ephemeral_point, nonce_bytes, ciphertext, info, &aad)
        };
        if let Some(s) = plaintext {
            return Ok(s);
        }
    }
    let reason = if pq {
        "inbound pq envelope decrypt failed for all candidates"
    } else {
        "inbound envelope decrypt failed for all candidates"
    };
    Err(BridgeError::Crypto(reason.to_string()))
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
            owner: None,
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

    const OWNER: [u8; 16] = [0x3f, 0x2b, 0x8c, 0x1e, 0x7a, 0x4d, 0x4e, 0x9b, 0x9c, 0x60, 0x5d, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    const OTHER_OWNER: [u8; 16] = [0x11; 16];

    fn owned(mut candidate: InboundKeyCandidate, owner: [u8; 16]) -> InboundKeyCandidate {
        candidate.owner = Some(owner);
        candidate
    }

    fn seal_bound(key: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(plaintext, 6);
        cipher
            .encrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: compressed.as_slice(),
                    aad,
                },
            )
            .unwrap()
    }

    fn encrypt_ecdh_bound(
        plaintext: &[u8],
        recipient: &SecretKey,
        nonce_bytes: &[u8; 12],
        owner: &[u8; 16],
    ) -> Vec<u8> {
        let recipient_pub = recipient.public_key().to_encoded_point(false);
        let ephemeral = SecretKey::random(&mut OsRng);
        let eph_pub = ephemeral.public_key().to_encoded_point(false);
        let shared_x =
            ecdh_p256(ephemeral.to_bytes().as_slice(), recipient_pub.as_bytes()).unwrap();
        let key = hkdf_aes_key(&shared_x, INFO_ECDH_BOUND).unwrap();
        let aad = bound_aad(INBOUND_ECDH_BOUND_MARKER, owner, eph_pub.as_bytes());
        let ciphertext = seal_bound(&key, nonce_bytes, plaintext, &aad);
        let mut out = vec![INBOUND_ECDH_BOUND_MARKER];
        out.extend_from_slice(eph_pub.as_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    fn encrypt_pq_bound(
        plaintext: &[u8],
        recipient: &SecretKey,
        recipient_ek: &<MlKem768 as KemCore>::EncapsulationKey,
        nonce_bytes: &[u8; 12],
        owner: &[u8; 16],
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
        let key = hkdf_aes_key(&ikm, INFO_PQ_BOUND).unwrap();
        let mut header = eph_pub.as_bytes().to_vec();
        header.extend_from_slice(kem_ct.as_slice());
        let aad = bound_aad(INBOUND_PQ_HYBRID_BOUND_MARKER, owner, &header);
        let ciphertext = seal_bound(&key, nonce_bytes, plaintext, &aad);
        let mut out = vec![INBOUND_PQ_HYBRID_BOUND_MARKER];
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn bound_ecdh_envelope_round_trips() {
        let recipient = SecretKey::random(&mut OsRng);
        let nonce = [3u8; 12];
        let json = r#"{"subject":"bound","body_text":"owner"}"#;
        let payload = encrypt_ecdh_bound(json.as_bytes(), &recipient, &nonce, &OWNER);
        let candidates = [owned(candidate_from(&recipient, None), OWNER)];
        let out = decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn bound_pq_envelope_round_trips() {
        let recipient = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let nonce = [4u8; 12];
        let json = r#"{"subject":"bound pq","body_text":"owner"}"#;
        let payload = encrypt_pq_bound(json.as_bytes(), &recipient, &ek, &nonce, &OWNER);
        let candidates = [owned(
            candidate_from(&recipient, Some(dk.as_bytes().to_vec())),
            OWNER,
        )];
        let out = decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn bound_envelope_fails_for_another_owner() {
        let recipient = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let nonce = [5u8; 12];
        let ecdh = encrypt_ecdh_bound(b"{}", &recipient, &nonce, &OWNER);
        let pq = encrypt_pq_bound(b"{}", &recipient, &ek, &nonce, &OWNER);
        let candidates = [owned(
            candidate_from(&recipient, Some(dk.as_bytes().to_vec())),
            OTHER_OWNER,
        )];
        assert!(decrypt_inbound_envelope(&ecdh, &nonce, &candidates).is_err());
        assert!(decrypt_inbound_envelope(&pq, &nonce, &candidates).is_err());
    }

    #[test]
    fn bound_envelope_fails_without_an_owner() {
        let recipient = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let nonce = [6u8; 12];
        let ecdh = encrypt_ecdh_bound(b"{}", &recipient, &nonce, &OWNER);
        let pq = encrypt_pq_bound(b"{}", &recipient, &ek, &nonce, &OWNER);
        let candidates = [candidate_from(&recipient, Some(dk.as_bytes().to_vec()))];
        assert!(decrypt_inbound_envelope(&ecdh, &nonce, &candidates).is_err());
        assert!(decrypt_inbound_envelope(&pq, &nonce, &candidates).is_err());
    }

    #[test]
    fn bound_and_unbound_envelopes_cannot_be_relabeled() {
        let recipient = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let nonce = [8u8; 12];
        let candidates = [owned(
            candidate_from(&recipient, Some(dk.as_bytes().to_vec())),
            OWNER,
        )];
        let swaps = [
            (
                encrypt_ecdh_bound(b"{}", &recipient, &nonce, &OWNER),
                INBOUND_ECDH_MARKER,
            ),
            (
                encrypt_ecdh(b"{}", &recipient, &nonce),
                INBOUND_ECDH_BOUND_MARKER,
            ),
            (
                encrypt_pq_bound(b"{}", &recipient, &ek, &nonce, &OWNER),
                INBOUND_PQ_HYBRID_MARKER,
            ),
            (
                encrypt_pq(b"{}", &recipient, &ek, &nonce),
                INBOUND_PQ_HYBRID_BOUND_MARKER,
            ),
        ];
        for (mut payload, marker) in swaps {
            assert!(decrypt_inbound_envelope(&payload, &nonce, &candidates).is_ok());
            payload[0] = marker;
            assert!(decrypt_inbound_envelope(&payload, &nonce, &candidates).is_err());
        }
    }

    #[test]
    fn bound_envelope_fails_when_its_header_is_altered() {
        let recipient = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let nonce = [10u8; 12];
        let candidates = [owned(
            candidate_from(&recipient, Some(dk.as_bytes().to_vec())),
            OWNER,
        )];
        let mut payload = encrypt_pq_bound(b"{}", &recipient, &ek, &nonce, &OWNER);
        payload[1 + EPHEMERAL_POINT_LEN + 7] ^= 0x01;
        assert!(decrypt_inbound_envelope(&payload, &nonce, &candidates).is_err());
    }

    #[test]
    fn unbound_envelopes_still_open_for_an_owned_candidate() {
        let recipient = SecretKey::random(&mut OsRng);
        let nonce = [11u8; 12];
        let payload = encrypt_ecdh(b"{}", &recipient, &nonce);
        let candidates = [owned(candidate_from(&recipient, None), OWNER)];
        assert_eq!(
            decrypt_inbound_envelope(&payload, &nonce, &candidates).unwrap(),
            "{}"
        );
    }

    #[test]
    fn binding_stamps_every_candidate_with_the_account_id() {
        let recipient = SecretKey::random(&mut OsRng);
        let mut candidates = vec![
            candidate_from(&recipient, None),
            candidate_from(&recipient, None),
        ];
        let user_id = uuid::Uuid::from_bytes(OWNER);
        bind_inbound_owner(&mut candidates, &user_id);
        assert!(candidates.iter().all(|c| c.owner == Some(OWNER)));
    }

    #[test]
    fn bound_markers_are_recognized_as_inbound_payloads() {
        for marker in [0x03u8, 0x04, 0x05, 0x06] {
            assert!(is_inbound_marker(marker));
        }
        for marker in [0x00u8, 0x01, 0x02, 0x07] {
            assert!(!is_inbound_marker(marker));
        }
    }

    fn backend_bound_vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/inbound_bound_envelope_vectors.json"
        ))
        .unwrap()
    }

    fn vector_bytes(vectors: &serde_json::Value, path: &[&str]) -> Vec<u8> {
        let mut node = vectors;
        for key in path {
            node = &node[*key];
        }
        STANDARD.decode(node.as_str().unwrap()).unwrap()
    }

    fn vector_candidate(vectors: &serde_json::Value, owner: Option<[u8; 16]>) -> InboundKeyCandidate {
        InboundKeyCandidate {
            ecdh_secret_d: vector_bytes(vectors, &["recipient_p256_private_scalar_b64"]),
            pq_decap_key: Some(vector_bytes(
                vectors,
                &["recipient_ml_kem768_decapsulation_key_b64"],
            )),
            owner,
        }
    }

    #[test]
    fn opens_bound_envelopes_produced_by_the_server() {
        let vectors = backend_bound_vectors();
        let owner = uuid::Uuid::parse_str(vectors["bound_owner_user_id"].as_str().unwrap())
            .unwrap()
            .into_bytes();
        assert_eq!(owner, OWNER);
        let expected = vectors["plaintext_utf8"].as_str().unwrap();
        for (group, marker) in [
            ("ecdh_bound", INBOUND_ECDH_BOUND_MARKER),
            ("pq_hybrid_bound", INBOUND_PQ_HYBRID_BOUND_MARKER),
        ] {
            let payload = vector_bytes(&vectors, &[group, "envelope_b64"]);
            let nonce = vector_bytes(&vectors, &[group, "nonce_b64"]);
            assert_eq!(payload[0], marker);
            let opened = decrypt_inbound_envelope(
                &payload,
                &nonce,
                &[vector_candidate(&vectors, Some(owner))],
            )
            .unwrap();
            assert_eq!(opened, expected);
            for wrong in [None, Some(OTHER_OWNER)] {
                assert!(decrypt_inbound_envelope(
                    &payload,
                    &nonce,
                    &[vector_candidate(&vectors, wrong)]
                )
                .is_err());
            }
        }
    }
}
