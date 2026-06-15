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
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::vault::VaultContents;

type MlKemDecapKey = <MlKem768 as KemCore>::DecapsulationKey;

const X3DH_INFO_CLASSICAL: &[u8] = b"Aster Mail_X3DH_v1";
const X3DH_INFO_PQ: &[u8] = b"Aster Mail_PQXDH_v1";
const KDF_INFO_ROOT: &[u8] = b"Aster Mail_Root_KDF";
const KDF_INFO_CHAIN: &[u8] = b"Aster Mail_Chain_KDF";
const RATCHET_HEADER_AD_PREFIX: &[u8] = b"astermail-ratchet-header-v2";
const ZERO_SALT_32: [u8; 32] = [0u8; 32];

#[derive(Zeroize, Clone)]
pub struct RatchetReceiverKeys {
    pub identity_secret_d: Vec<u8>,
    pub signed_prekey_secret_d: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
}

pub struct RatchetMessage {
    pub sender_identity_public: Vec<u8>,
    pub ephemeral_public: Vec<u8>,
    pub header_dh_public: Vec<u8>,
    pub previous_chain_length: u32,
    pub message_number: u32,
    pub header_version: Option<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub pq_ciphertext: Option<Vec<u8>>,
    pub pq_key_id: Option<u32>,
    pub pq_secret: Option<Vec<u8>>,
}

fn ecdh_p256(secret_d: &[u8], public_sec1: &[u8]) -> Result<[u8; 32], String> {
    let sk = SecretKey::from_slice(secret_d).map_err(|e| format!("p256 secret: {}", e))?;
    let pk = PublicKey::from_sec1_bytes(public_sec1).map_err(|e| format!("p256 public: {}", e))?;
    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Ok(out)
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).map_err(|e| format!("hkdf expand: {}", e))?;
    Ok(okm)
}

fn ml_kem768_decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<[u8; 32], String> {
    let encoded = ml_kem::Encoded::<MlKemDecapKey>::try_from(sk_bytes)
        .map_err(|e| format!("mlkem secret size: {:?}", e))?;
    let dk = MlKemDecapKey::from_bytes(&encoded);
    let ct: Ciphertext<MlKem768> =
        Array::try_from(ct_bytes).map_err(|e| format!("mlkem ciphertext size: {:?}", e))?;
    let ss = dk
        .decapsulate(&ct)
        .map_err(|e| format!("mlkem decapsulate: {:?}", e))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    Ok(out)
}

fn serialize_header_ad(version: u8, dh_public: &[u8], previous_chain_length: u32, message_number: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(RATCHET_HEADER_AD_PREFIX.len() + 1 + dh_public.len() + 8);
    out.extend_from_slice(RATCHET_HEADER_AD_PREFIX);
    out.push(version);
    out.extend_from_slice(dh_public);
    out.extend_from_slice(&previous_chain_length.to_be_bytes());
    out.extend_from_slice(&message_number.to_be_bytes());
    out
}

pub fn decrypt_bootstrap(keys: &RatchetReceiverKeys, msg: &RatchetMessage) -> Result<String, String> {
    if msg.nonce.len() != 12 {
        return Err("ratchet nonce must be 12 bytes".to_string());
    }

    let dh1 = ecdh_p256(&keys.signed_prekey_secret_d, &msg.sender_identity_public)?;
    let dh2 = ecdh_p256(&keys.identity_secret_d, &msg.ephemeral_public)?;
    let dh3 = ecdh_p256(&keys.signed_prekey_secret_d, &msg.ephemeral_public)?;

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let info: &[u8] = match (&msg.pq_ciphertext, &msg.pq_secret) {
        (Some(ct), Some(sk)) => {
            let mut pq_ss = ml_kem768_decapsulate(ct, sk)?;
            ikm.extend_from_slice(&pq_ss);
            pq_ss.zeroize();
            X3DH_INFO_PQ
        }
        _ => X3DH_INFO_CLASSICAL,
    };

    let mut shared_secret = hkdf_sha256(&ikm, &ZERO_SALT_32, info, 32)?;
    ikm.zeroize();

    let dh_root = ecdh_p256(&keys.signed_prekey_secret_d, &msg.header_dh_public)?;
    let mut root_out = hkdf_sha256(&dh_root, &shared_secret, KDF_INFO_ROOT, 64)?;
    shared_secret.zeroize();

    let mut chain_out = hkdf_sha256(&root_out[32..64], &ZERO_SALT_32, KDF_INFO_CHAIN, 64)?;
    root_out.zeroize();

    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&chain_out[32..64]);
    chain_out.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&message_key).map_err(|e| format!("aes init: {}", e))?;
    message_key.zeroize();
    let nonce = Nonce::from_slice(&msg.nonce);

    let ad = serialize_header_ad(
        msg.header_version.unwrap_or(1),
        &msg.header_dh_public,
        msg.previous_chain_length,
        msg.message_number,
    );

    let prefer_ad = msg.header_version.map(|v| v >= 2).unwrap_or(false);
    let order: [bool; 2] = if prefer_ad { [true, false] } else { [false, true] };

    for with_ad in order {
        let result = if with_ad {
            cipher.decrypt(nonce, Payload { msg: &msg.ciphertext, aad: &ad })
        } else {
            cipher.decrypt(nonce, msg.ciphertext.as_ref())
        };
        if let Ok(plaintext) = result {
            return String::from_utf8(plaintext).map_err(|e| format!("plaintext utf8: {}", e));
        }
    }

    Err("ratchet message decryption failed".to_string())
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s.trim()).map_err(|e| format!("base64 decode: {}", e))
}

fn jwk_d_bytes(jwk_string: &str) -> Result<Vec<u8>, String> {
    let jwk: Value = serde_json::from_str(jwk_string).map_err(|e| format!("jwk parse: {}", e))?;
    let d = jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "jwk missing d".to_string())?;
    URL_SAFE_NO_PAD
        .decode(d.trim().trim_end_matches('='))
        .map_err(|e| format!("jwk d decode: {}", e))
}

pub fn derive_sync_key(vault_passphrase: &[u8]) -> Result<[u8; 32], String> {
    let mut salt_input = b"aster-hkdf-salt-v1:".to_vec();
    salt_input.extend_from_slice(vault_passphrase);
    let salt = Sha256::digest(&salt_input);
    let master = hkdf_sha256(vault_passphrase, &salt, b"aster-storage-encryption-key-v1", 32)?;
    let sync = hkdf_sha256(&master, b"Aster Mail_Ratchet_State_Encryption", b"ratchet_state_key", 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&sync);
    Ok(out)
}

pub fn decrypt_pq_secret(
    sync_key: &[u8],
    encrypted_secret_b64: &str,
    secret_nonce_b64: &str,
) -> Result<Vec<u8>, String> {
    let ciphertext = b64_decode(encrypted_secret_b64)?;
    let nonce_bytes = b64_decode(secret_nonce_b64)?;
    if nonce_bytes.len() != 12 {
        return Err("pq secret nonce must be 12 bytes".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(sync_key).map_err(|e| format!("aes init: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "pq secret decrypt failed".to_string())
}

fn push_key_set(
    sets: &mut Vec<RatchetReceiverKeys>,
    identity_jwk: Option<&str>,
    signed_prekey_jwk: Option<&str>,
    signed_prekey_public_b64: Option<&str>,
) {
    let (Some(id_jwk), Some(spk_jwk), Some(spk_pub)) =
        (identity_jwk, signed_prekey_jwk, signed_prekey_public_b64)
    else {
        return;
    };
    if let (Ok(identity_secret_d), Ok(signed_prekey_secret_d), Ok(signed_prekey_public)) =
        (jwk_d_bytes(id_jwk), jwk_d_bytes(spk_jwk), b64_decode(spk_pub))
    {
        sets.push(RatchetReceiverKeys {
            identity_secret_d,
            signed_prekey_secret_d,
            signed_prekey_public,
        });
    }
}

pub fn build_receiver_key_sets(vault: &VaultContents) -> Vec<RatchetReceiverKeys> {
    let mut sets = Vec::new();
    push_key_set(
        &mut sets,
        vault.ratchet_identity_key.as_deref(),
        vault.ratchet_signed_prekey.as_deref(),
        vault.ratchet_signed_prekey_public.as_deref(),
    );
    if let Some(previous) = &vault.ratchet_previous_keys {
        for p in previous {
            push_key_set(
                &mut sets,
                p.ratchet_identity_key.as_deref(),
                p.ratchet_signed_prekey.as_deref(),
                p.ratchet_signed_prekey_public.as_deref(),
            );
        }
    }
    sets
}

fn is_ratchet_type(value: &Value) -> bool {
    value
        .get("type")
        .and_then(|v| v.as_str())
        .map(|t| t.starts_with("double_ratchet"))
        .unwrap_or(false)
}

pub fn find_ratchet_object(envelope: &Value) -> Option<Value> {
    if is_ratchet_type(envelope) {
        return Some(envelope.clone());
    }
    const BODY_FIELDS: [&str; 7] = [
        "body_html",
        "html_body",
        "html",
        "body_text",
        "text_body",
        "body",
        "text",
    ];
    for field in BODY_FIELDS {
        if let Some(s) = envelope.get(field).and_then(|v| v.as_str()) {
            let trimmed = s.trim_start();
            if trimmed.starts_with('{') {
                if let Ok(inner) = serde_json::from_str::<Value>(trimmed) {
                    if is_ratchet_type(&inner) {
                        return Some(inner);
                    }
                }
            }
        }
    }
    None
}

pub fn parse_recipient_message(ratchet: &Value, our_email: &str) -> Option<RatchetMessage> {
    let sender_identity_public = b64_decode(ratchet.get("sender_identity_key")?.as_str()?).ok()?;
    let recipients = ratchet.get("recipients")?.as_object()?;

    let our_lower = our_email.to_lowercase();
    let rec = recipients
        .iter()
        .find(|(k, _)| k.to_lowercase() == our_lower)
        .map(|(_, v)| v)?;

    let header = rec.get("header")?;
    let header_dh_public = b64_decode(header.get("dh_public")?.as_str()?).ok()?;
    let previous_chain_length = header
        .get("previous_chain_length")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let message_number = header
        .get("message_number")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let header_version = header.get("v").and_then(|v| v.as_u64()).map(|v| v as u8);

    let ephemeral_public = b64_decode(rec.get("ephemeral_key")?.as_str()?).ok()?;
    let ciphertext = b64_decode(rec.get("ciphertext")?.as_str()?).ok()?;
    let nonce = b64_decode(rec.get("nonce")?.as_str()?).ok()?;

    let pq_ciphertext = rec
        .get("pq_ciphertext")
        .and_then(|v| v.as_str())
        .and_then(|s| b64_decode(s).ok());
    let pq_key_id = rec.get("pq_key_id").and_then(|v| v.as_u64()).map(|v| v as u32);

    Some(RatchetMessage {
        sender_identity_public,
        ephemeral_public,
        header_dh_public,
        previous_chain_length,
        message_number,
        header_version,
        ciphertext,
        nonce,
        pq_ciphertext,
        pq_key_id,
        pq_secret: None,
    })
}

pub fn decrypt_with_key_sets(key_sets: &[RatchetReceiverKeys], msg: &RatchetMessage) -> Option<String> {
    for keys in key_sets {
        if let Ok(plaintext) = decrypt_bootstrap(keys, msg) {
            return Some(plaintext);
        }
    }
    None
}

pub fn encrypt_bootstrap(
    sender_identity_secret_d: &[u8],
    recipient_identity_public: &[u8],
    recipient_signed_prekey_public: &[u8],
    recipient_pq_public: Option<&[u8]>,
    pq_key_id: Option<u32>,
    plaintext: &str,
) -> Result<RatchetMessage, String> {
    use ml_kem::kem::Encapsulate;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::{OsRng, RngCore};
    type EncapKey = <MlKem768 as KemCore>::EncapsulationKey;

    let sender_identity = SecretKey::from_slice(sender_identity_secret_d)
        .map_err(|e| format!("sender identity: {}", e))?;
    let sender_identity_public = sender_identity
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let ephemeral = SecretKey::random(&mut OsRng);
    let ephemeral_d = ephemeral.to_bytes();
    let ephemeral_public = ephemeral
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let dh1 = ecdh_p256(sender_identity_secret_d, recipient_signed_prekey_public)?;
    let dh2 = ecdh_p256(ephemeral_d.as_slice(), recipient_identity_public)?;
    let dh3 = ecdh_p256(ephemeral_d.as_slice(), recipient_signed_prekey_public)?;

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let (pq_ciphertext, out_key_id, info): (Option<Vec<u8>>, Option<u32>, &[u8]) =
        match (recipient_pq_public, pq_key_id) {
            (Some(pq_pub), Some(kid)) => {
                let encoded = ml_kem::Encoded::<EncapKey>::try_from(pq_pub)
                    .map_err(|e| format!("mlkem public size: {:?}", e))?;
                let ek = EncapKey::from_bytes(&encoded);
                let (ct, ss) = ek
                    .encapsulate(&mut OsRng)
                    .map_err(|e| format!("encapsulate: {:?}", e))?;
                ikm.extend_from_slice(ss.as_slice());
                (Some(ct.as_slice().to_vec()), Some(kid), X3DH_INFO_PQ)
            }
            _ => (None, None, X3DH_INFO_CLASSICAL),
        };

    let shared_secret = hkdf_sha256(&ikm, &ZERO_SALT_32, info, 32)?;
    ikm.zeroize();

    let sender_ratchet = SecretKey::random(&mut OsRng);
    let sender_ratchet_d = sender_ratchet.to_bytes();
    let sender_ratchet_public = sender_ratchet
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let dh_root = ecdh_p256(sender_ratchet_d.as_slice(), recipient_signed_prekey_public)?;
    let root_out = hkdf_sha256(&dh_root, &shared_secret, KDF_INFO_ROOT, 64)?;
    let chain_out = hkdf_sha256(&root_out[32..64], &ZERO_SALT_32, KDF_INFO_CHAIN, 64)?;

    let cipher = Aes256Gcm::new_from_slice(&chain_out[32..64]).map_err(|e| format!("aes init: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ad = serialize_header_ad(2, &sender_ratchet_public, 0, 0);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad: &ad })
        .map_err(|_| "ratchet encrypt failed".to_string())?;

    Ok(RatchetMessage {
        sender_identity_public,
        ephemeral_public,
        header_dh_public: sender_ratchet_public,
        previous_chain_length: 0,
        message_number: 0,
        header_version: Some(2),
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        pq_ciphertext,
        pq_key_id: out_key_id,
        pq_secret: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::Encapsulate;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;
    use serde_json::json;

    type MlKemEncapKey = <MlKem768 as KemCore>::EncapsulationKey;

    fn pub_sec1(sk: &SecretKey) -> Vec<u8> {
        sk.public_key().to_encoded_point(false).as_bytes().to_vec()
    }

    fn p256_jwk(sk: &SecretKey) -> String {
        let point = sk.public_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "d": URL_SAFE_NO_PAD.encode(sk.to_bytes().as_slice()),
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap().as_slice()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap().as_slice()),
        })
        .to_string()
    }

    struct Built {
        keys: RatchetReceiverKeys,
        msg: RatchetMessage,
    }

    fn build_message(plaintext: &str, use_pq: bool, header_version: Option<u8>) -> Built {
        let recv_identity = SecretKey::random(&mut OsRng);
        let recv_spk = SecretKey::random(&mut OsRng);
        let recv_spk_pub = pub_sec1(&recv_spk);
        let (dk, ek) = MlKem768::generate(&mut OsRng);

        let sender_identity = SecretKey::random(&mut OsRng);
        let ephemeral = SecretKey::random(&mut OsRng);

        let dh1 = ecdh_p256(sender_identity.to_bytes().as_slice(), &recv_spk_pub).unwrap();
        let dh2 = ecdh_p256(ephemeral.to_bytes().as_slice(), &pub_sec1(&recv_identity)).unwrap();
        let dh3 = ecdh_p256(ephemeral.to_bytes().as_slice(), &recv_spk_pub).unwrap();

        let mut ikm = Vec::new();
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);

        let (pq_ct, pq_secret, info): (Option<Vec<u8>>, Option<Vec<u8>>, &[u8]) = if use_pq {
            let (ct, ss) = ek.encapsulate(&mut OsRng).unwrap();
            ikm.extend_from_slice(ss.as_slice());
            (Some(ct.as_slice().to_vec()), Some(dk.as_bytes().to_vec()), X3DH_INFO_PQ)
        } else {
            (None, None, X3DH_INFO_CLASSICAL)
        };

        let shared_secret = hkdf_sha256(&ikm, &ZERO_SALT_32, info, 32).unwrap();

        let sender_ratchet = SecretKey::random(&mut OsRng);
        let sender_ratchet_pub = pub_sec1(&sender_ratchet);
        let dh_root = ecdh_p256(sender_ratchet.to_bytes().as_slice(), &recv_spk_pub).unwrap();
        let root_out = hkdf_sha256(&dh_root, &shared_secret, KDF_INFO_ROOT, 64).unwrap();
        let chain_out = hkdf_sha256(&root_out[32..64], &ZERO_SALT_32, KDF_INFO_CHAIN, 64).unwrap();
        let message_key = &chain_out[32..64];

        let nonce_bytes = [0x24u8; 12];
        let cipher = Aes256Gcm::new_from_slice(message_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ad = serialize_header_ad(header_version.unwrap_or(1), &sender_ratchet_pub, 0, 0);
        let ciphertext = if header_version.map(|v| v >= 2).unwrap_or(false) {
            cipher.encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad: &ad }).unwrap()
        } else {
            cipher.encrypt(nonce, plaintext.as_bytes()).unwrap()
        };

        Built {
            keys: RatchetReceiverKeys {
                identity_secret_d: recv_identity.to_bytes().to_vec(),
                signed_prekey_secret_d: recv_spk.to_bytes().to_vec(),
                signed_prekey_public: recv_spk_pub,
            },
            msg: RatchetMessage {
                sender_identity_public: pub_sec1(&sender_identity),
                ephemeral_public: pub_sec1(&ephemeral),
                header_dh_public: sender_ratchet_pub,
                previous_chain_length: 0,
                message_number: 0,
                header_version,
                ciphertext,
                nonce: nonce_bytes.to_vec(),
                pq_ciphertext: pq_ct,
                pq_key_id: if pq_secret.is_some() { Some(436178) } else { None },
                pq_secret,
            },
        }
    }

    #[test]
    fn round_trip_pqxdh_with_v2_aad() {
        let pt = "Here is your sign-in code: 481920.";
        let b = build_message(pt, true, Some(2));
        assert_eq!(decrypt_bootstrap(&b.keys, &b.msg).unwrap(), pt);
    }

    #[test]
    fn round_trip_pqxdh_no_header_version_no_aad() {
        let pt = "internal message with no header version field";
        let b = build_message(pt, true, None);
        assert_eq!(decrypt_bootstrap(&b.keys, &b.msg).unwrap(), pt);
    }

    #[test]
    fn round_trip_classical_no_pq() {
        let pt = "classical x3dh bootstrap body";
        let b = build_message(pt, false, Some(2));
        assert_eq!(decrypt_bootstrap(&b.keys, &b.msg).unwrap(), pt);
    }

    #[test]
    fn wrong_receiver_identity_key_fails() {
        let b = build_message("secret", true, Some(2));
        let wrong = RatchetReceiverKeys {
            identity_secret_d: SecretKey::random(&mut OsRng).to_bytes().to_vec(),
            signed_prekey_secret_d: b.keys.signed_prekey_secret_d.clone(),
            signed_prekey_public: b.keys.signed_prekey_public.clone(),
        };
        assert!(decrypt_bootstrap(&wrong, &b.msg).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let mut b = build_message("authentic", true, Some(2));
        let last = b.msg.ciphertext.len() - 1;
        b.msg.ciphertext[last] ^= 0xff;
        assert!(decrypt_bootstrap(&b.keys, &b.msg).is_err());
    }

    #[test]
    fn missing_pq_secret_for_pq_message_fails() {
        let mut b = build_message("needs pq", true, Some(2));
        b.msg.pq_secret = None;
        assert!(decrypt_bootstrap(&b.keys, &b.msg).is_err());
    }

    #[test]
    fn full_wiring_decrypts_nested_envelope_via_vault() {
        let pt = "Internal message body, sign-in code 992210.";

        let recv_identity = SecretKey::random(&mut OsRng);
        let recv_spk = SecretKey::random(&mut OsRng);
        let recv_spk_pub = pub_sec1(&recv_spk);
        let (dk, ek) = MlKem768::generate(&mut OsRng);

        let sender_identity = SecretKey::random(&mut OsRng);
        let ephemeral = SecretKey::random(&mut OsRng);
        let dh1 = ecdh_p256(sender_identity.to_bytes().as_slice(), &recv_spk_pub).unwrap();
        let dh2 = ecdh_p256(ephemeral.to_bytes().as_slice(), &pub_sec1(&recv_identity)).unwrap();
        let dh3 = ecdh_p256(ephemeral.to_bytes().as_slice(), &recv_spk_pub).unwrap();
        let (pq_ct, pq_ss) = ek.encapsulate(&mut OsRng).unwrap();

        let mut ikm = Vec::new();
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);
        ikm.extend_from_slice(pq_ss.as_slice());
        let shared_secret = hkdf_sha256(&ikm, &ZERO_SALT_32, X3DH_INFO_PQ, 32).unwrap();

        let sender_ratchet = SecretKey::random(&mut OsRng);
        let sender_ratchet_pub = pub_sec1(&sender_ratchet);
        let dh_root = ecdh_p256(sender_ratchet.to_bytes().as_slice(), &recv_spk_pub).unwrap();
        let root_out = hkdf_sha256(&dh_root, &shared_secret, KDF_INFO_ROOT, 64).unwrap();
        let chain_out = hkdf_sha256(&root_out[32..64], &ZERO_SALT_32, KDF_INFO_CHAIN, 64).unwrap();
        let message_key = &chain_out[32..64];

        let nonce_bytes = [0x33u8; 12];
        let cipher = Aes256Gcm::new_from_slice(message_key).unwrap();
        let msg_ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), pt.as_bytes())
            .unwrap();

        let ratchet_json = json!({
            "type": "double_ratchet_v2",
            "sender_identity_key": STANDARD.encode(pub_sec1(&sender_identity)),
            "recipients": {
                "USER@astermail.org": {
                    "ephemeral_key": STANDARD.encode(pub_sec1(&ephemeral)),
                    "header": {
                        "dh_public": STANDARD.encode(&sender_ratchet_pub),
                        "previous_chain_length": 0,
                        "message_number": 0
                    },
                    "ciphertext": STANDARD.encode(&msg_ct),
                    "nonce": STANDARD.encode(nonce_bytes),
                    "pq_ciphertext": STANDARD.encode(pq_ct.as_slice()),
                    "pq_key_id": 436178
                }
            }
        });

        let envelope = json!({
            "subject": "Hi",
            "from": "sender@astermail.org",
            "to": ["user@astermail.org"],
            "body_html": ratchet_json.to_string()
        });

        let vault_json = json!({
            "identity_key": "pgp-not-used-here",
            "ratchet_identity_key": p256_jwk(&recv_identity),
            "ratchet_identity_public": STANDARD.encode(pub_sec1(&recv_identity)),
            "ratchet_signed_prekey": p256_jwk(&recv_spk),
            "ratchet_signed_prekey_public": STANDARD.encode(&recv_spk_pub)
        })
        .to_string();
        let vault: VaultContents = serde_json::from_str(&vault_json).unwrap();

        let key_sets = build_receiver_key_sets(&vault);
        assert_eq!(key_sets.len(), 1);

        let ratchet_obj = find_ratchet_object(&envelope).expect("nested ratchet detected");
        let mut msg = parse_recipient_message(&ratchet_obj, "user@astermail.org").expect("parsed");
        assert_eq!(msg.pq_key_id, Some(436178));

        msg.pq_secret = Some(dk.as_bytes().to_vec());

        let plaintext = decrypt_with_key_sets(&key_sets, &msg).expect("decrypted");
        assert_eq!(plaintext, pt);
    }

    #[test]
    fn sync_key_and_pq_secret_round_trip() {
        let passphrase = b"correct horse battery staple";
        let sync_key = derive_sync_key(passphrase).unwrap();
        let secret = vec![9u8; 2400];
        let nonce_bytes = [0x55u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&sync_key).unwrap();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), secret.as_slice())
            .unwrap();
        let recovered = decrypt_pq_secret(
            &sync_key,
            &STANDARD.encode(&ct),
            &STANDARD.encode(nonce_bytes),
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn find_ratchet_object_ignores_plain_mail() {
        let envelope = json!({"subject": "s", "body_text": "just a normal message"});
        assert!(find_ratchet_object(&envelope).is_none());
    }
}
