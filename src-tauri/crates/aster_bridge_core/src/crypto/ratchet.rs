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
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::vault::VaultContents;

type MlKemDecapKey = <MlKem768 as KemCore>::DecapsulationKey;

const X3DH_INFO_CLASSICAL: &[u8] = b"Aster Mail_X3DH_v1";
const X3DH_INFO_PQ: &[u8] = b"Aster Mail_PQXDH_v1";
const X3DH_INFO_PQ_IDENTITY: &[u8] = b"Aster Mail_PQXDH_identity_v1";
const X3DH_INFO_CLASSICAL_V2: &[u8] = b"Aster Mail_X3DH_v2";
const X3DH_INFO_PQ_V2: &[u8] = b"Aster Mail_PQXDH_v2";
const X3DH_INFO_PQ_IDENTITY_V2: &[u8] = b"Aster Mail_PQXDH_identity_v2";
const X3DH_INFO_CLASSICAL_V3: &[u8] = b"Aster Mail_X3DH_v3";
const X3DH_INFO_PQ_V3: &[u8] = b"Aster Mail_PQXDH_v3";
const X3DH_INFO_PQ_IDENTITY_V3: &[u8] = b"Aster Mail_PQXDH_identity_v3";
pub const X3DH_VERSION_LEGACY: u8 = 1;
pub const X3DH_VERSION_TRANSCRIPT_BOUND: u8 = 2;
pub const X3DH_VERSION_KEY_BOUND: u8 = 3;
const X3DH_INFO_CLASSICAL_V4: &[u8] = b"Aster Mail_X3DH_v4";
const X3DH_INFO_PQ_V4: &[u8] = b"Aster Mail_PQXDH_v4";
const X3DH_INFO_PQ_IDENTITY_V4: &[u8] = b"Aster Mail_PQXDH_identity_v4";
pub const X3DH_VERSION_ONE_TIME_BOUND: u8 = 4;
pub const ONE_TIME_PREKEY_ID_MAX: u32 = 0x7fff_ffff;
const P256_PUBLIC_LEN: usize = 65;
const KDF_INFO_ROOT: &[u8] = b"Aster Mail_Root_KDF";
const KDF_INFO_CHAIN: &[u8] = b"Aster Mail_Chain_KDF";
const RATCHET_HEADER_AD_PREFIX: &[u8] = b"astermail-ratchet-header-v2";
const ZERO_SALT_32: [u8; 32] = [0u8; 32];

pub const PQ_IDENTITY_KEY_ID: i32 = -1;

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
    pub pq_key_id: Option<i32>,
    pub pq_secret: Option<Vec<u8>>,
    pub x3dh_version: Option<u8>,
    pub opk_id: Option<u32>,
    pub spk_id: Option<String>,
    pub opk_secret: Option<Vec<u8>>,
}

pub fn is_valid_one_time_prekey_id(key_id: u32) -> bool {
    (1..=ONE_TIME_PREKEY_ID_MAX).contains(&key_id)
}

pub fn is_p256_public(public: &[u8]) -> bool {
    public.len() == P256_PUBLIC_LEN && public[0] == 0x04 && PublicKey::from_sec1_bytes(public).is_ok()
}

pub fn signed_prekey_id(signed_prekey_public: &[u8]) -> String {
    use sha2::Digest;
    Sha256::digest(signed_prekey_public)
        .iter()
        .take(8)
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

pub(crate) fn ecdh_p256(secret_d: &[u8], public_sec1: &[u8]) -> Result<[u8; 32], String> {
    let sk = SecretKey::from_slice(secret_d).map_err(|e| format!("p256 secret: {}", e))?;
    let pk = PublicKey::from_sec1_bytes(public_sec1).map_err(|e| format!("p256 public: {}", e))?;
    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Ok(out)
}

pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).map_err(|e| format!("hkdf expand: {}", e))?;
    Ok(okm)
}

pub(crate) fn ml_kem768_decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<[u8; 32], String> {
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

pub(crate) fn serialize_header_ad(version: u8, dh_public: &[u8], previous_chain_length: u32, message_number: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(RATCHET_HEADER_AD_PREFIX.len() + 1 + dh_public.len() + 8);
    out.extend_from_slice(RATCHET_HEADER_AD_PREFIX);
    out.push(version);
    out.extend_from_slice(dh_public);
    out.extend_from_slice(&previous_chain_length.to_be_bytes());
    out.extend_from_slice(&message_number.to_be_bytes());
    out
}

fn identity_public_sec1(secret_d: &[u8]) -> Result<Vec<u8>, String> {
    let sk = SecretKey::from_slice(secret_d).map_err(|e| format!("p256 secret: {}", e))?;
    Ok(sk.public_key().to_encoded_point(false).as_bytes().to_vec())
}

struct PqContribution<'a> {
    shared_secret: &'a [u8],
    ciphertext: &'a [u8],
    from_identity: bool,
}

struct Transcript<'a> {
    version: u8,
    initiator_identity: &'a [u8],
    responder_identity: &'a [u8],
    responder_signed_prekey: &'a [u8],
    initiator_ephemeral: &'a [u8],
    one_time: Option<OneTimeBinding<'a>>,
}

struct OneTimeBinding<'a> {
    key_id: u32,
    public: &'a [u8],
}

fn x3dh_info(version: u8, pq_from_identity: Option<bool>) -> &'static [u8] {
    match (pq_from_identity, version) {
        (Some(true), X3DH_VERSION_ONE_TIME_BOUND) => X3DH_INFO_PQ_IDENTITY_V4,
        (Some(true), X3DH_VERSION_KEY_BOUND) => X3DH_INFO_PQ_IDENTITY_V3,
        (Some(true), X3DH_VERSION_TRANSCRIPT_BOUND) => X3DH_INFO_PQ_IDENTITY_V2,
        (Some(true), _) => X3DH_INFO_PQ_IDENTITY,
        (Some(false), X3DH_VERSION_ONE_TIME_BOUND) => X3DH_INFO_PQ_V4,
        (Some(false), X3DH_VERSION_KEY_BOUND) => X3DH_INFO_PQ_V3,
        (Some(false), X3DH_VERSION_TRANSCRIPT_BOUND) => X3DH_INFO_PQ_V2,
        (Some(false), _) => X3DH_INFO_PQ,
        (None, X3DH_VERSION_ONE_TIME_BOUND) => X3DH_INFO_CLASSICAL_V4,
        (None, X3DH_VERSION_KEY_BOUND) => X3DH_INFO_CLASSICAL_V3,
        (None, X3DH_VERSION_TRANSCRIPT_BOUND) => X3DH_INFO_CLASSICAL_V2,
        (None, _) => X3DH_INFO_CLASSICAL,
    }
}

fn check_one_time_inputs(dh: &[&[u8]], version: u8, transcript: Option<&Transcript<'_>>) -> Result<(), String> {
    let one_time = transcript.and_then(|transcript| transcript.one_time.as_ref());
    if version > X3DH_VERSION_ONE_TIME_BOUND {
        return Err(format!("unsupported x3dh version {}", version));
    }
    if version < X3DH_VERSION_ONE_TIME_BOUND {
        if dh.len() != 3 || one_time.is_some() {
            return Err("one-time prekey is only bound by the one-time handshake".to_string());
        }
        return Ok(());
    }
    let transcript = transcript.ok_or_else(|| "one-time handshake needs its transcript".to_string())?;
    let one_time = one_time.ok_or_else(|| "one-time handshake needs a one-time prekey".to_string())?;
    if dh.len() != 4 || dh.iter().any(|part| part.len() != 32) {
        return Err("one-time handshake needs four key agreements".to_string());
    }
    if !is_valid_one_time_prekey_id(one_time.key_id) {
        return Err("one-time prekey id is out of range".to_string());
    }
    let publics = [
        transcript.initiator_identity,
        transcript.responder_identity,
        transcript.responder_signed_prekey,
        transcript.initiator_ephemeral,
        one_time.public,
    ];
    if publics.iter().any(|public| public.len() != P256_PUBLIC_LEN) {
        return Err("one-time handshake needs every public key".to_string());
    }
    Ok(())
}

fn x3dh_shared_secret(
    dh: &[&[u8]],
    pq: Option<PqContribution<'_>>,
    transcript: Option<Transcript<'_>>,
) -> Result<Vec<u8>, String> {
    let version = transcript
        .as_ref()
        .map_or(X3DH_VERSION_LEGACY, |transcript| transcript.version);
    check_one_time_inputs(dh, version, transcript.as_ref())?;
    let mut ikm = Vec::with_capacity(512);
    for part in dh {
        ikm.extend_from_slice(part);
    }
    if let Some(pq) = &pq {
        ikm.extend_from_slice(pq.shared_secret);
    }
    let info = x3dh_info(version, pq.as_ref().map(|pq| pq.from_identity));
    if let Some(transcript) = transcript {
        ikm.extend_from_slice(transcript.initiator_identity);
        ikm.extend_from_slice(transcript.responder_identity);
        if transcript.version >= X3DH_VERSION_KEY_BOUND {
            ikm.extend_from_slice(transcript.responder_signed_prekey);
            ikm.extend_from_slice(transcript.initiator_ephemeral);
        }
        if let Some(one_time) = &transcript.one_time {
            ikm.extend_from_slice(one_time.public);
            ikm.extend_from_slice(&one_time.key_id.to_be_bytes());
        }
        if let Some(pq) = &pq {
            ikm.extend_from_slice(pq.ciphertext);
        }
    }
    let shared_secret = hkdf_sha256(&ikm, &ZERO_SALT_32, info, 32);
    ikm.zeroize();
    shared_secret
}

pub(crate) fn derive_x3dh_shared_secret(
    keys: &RatchetReceiverKeys,
    msg: &RatchetMessage,
) -> Result<Vec<u8>, String> {
    let version = match msg.x3dh_version {
        None | Some(X3DH_VERSION_LEGACY) => X3DH_VERSION_LEGACY,
        Some(
            version @ (X3DH_VERSION_TRANSCRIPT_BOUND | X3DH_VERSION_KEY_BOUND | X3DH_VERSION_ONE_TIME_BOUND),
        ) => version,
        Some(other) => return Err(format!("unsupported x3dh version {}", other)),
    };

    let mut one_time: Option<(u32, Vec<u8>, [u8; 32])> = if version == X3DH_VERSION_ONE_TIME_BOUND {
        let key_id = msg
            .opk_id
            .filter(|key_id| is_valid_one_time_prekey_id(*key_id))
            .ok_or_else(|| "one-time prekey id missing".to_string())?;
        let secret = msg
            .opk_secret
            .as_deref()
            .ok_or_else(|| "one-time prekey secret missing".to_string())?;
        Some((
            key_id,
            identity_public_sec1(secret)?,
            ecdh_p256(secret, &msg.ephemeral_public)?,
        ))
    } else {
        None
    };

    let dh1 = ecdh_p256(&keys.signed_prekey_secret_d, &msg.sender_identity_public)?;
    let dh2 = ecdh_p256(&keys.identity_secret_d, &msg.ephemeral_public)?;
    let dh3 = ecdh_p256(&keys.signed_prekey_secret_d, &msg.ephemeral_public)?;

    let mut pq_ss = match (&msg.pq_ciphertext, &msg.pq_secret) {
        (Some(ct), Some(sk)) => Some(ml_kem768_decapsulate(ct, sk)?),
        _ => None,
    };
    let pq = match (&pq_ss, &msg.pq_ciphertext) {
        (Some(shared_secret), Some(ciphertext)) => Some(PqContribution {
            shared_secret,
            ciphertext,
            from_identity: msg.pq_key_id == Some(PQ_IDENTITY_KEY_ID),
        }),
        _ => None,
    };
    let responder_identity = identity_public_sec1(&keys.identity_secret_d)?;
    let responder_signed_prekey = identity_public_sec1(&keys.signed_prekey_secret_d)?;
    let transcript = (version >= X3DH_VERSION_TRANSCRIPT_BOUND).then_some(Transcript {
        version,
        initiator_identity: &msg.sender_identity_public,
        responder_identity: &responder_identity,
        responder_signed_prekey: &responder_signed_prekey,
        initiator_ephemeral: &msg.ephemeral_public,
        one_time: one_time.as_ref().map(|(key_id, public, _)| OneTimeBinding {
            key_id: *key_id,
            public: public.as_slice(),
        }),
    });

    let mut dh: Vec<&[u8]> = vec![dh1.as_slice(), dh2.as_slice(), dh3.as_slice()];
    if let Some((_, _, dh4)) = one_time.as_ref() {
        dh.push(dh4.as_slice());
    }
    let shared_secret = x3dh_shared_secret(&dh, pq, transcript);
    drop(dh);
    if let Some(secret) = pq_ss.as_mut() {
        secret.zeroize();
    }
    if let Some((_, _, dh4)) = one_time.as_mut() {
        dh4.zeroize();
    }
    shared_secret
}

pub fn decrypt_bootstrap(keys: &RatchetReceiverKeys, msg: &RatchetMessage) -> Result<String, String> {
    if msg.nonce.len() != 12 {
        return Err("ratchet nonce must be 12 bytes".to_string());
    }

    let mut shared_secret = derive_x3dh_shared_secret(keys, msg)?;

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

    let header_bound = msg.header_version.map(|v| v >= 2).unwrap_or(false);
    let order: &[bool] = if header_bound { &[true, false] } else { &[false] };

    for &with_ad in order {
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

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s.trim()).map_err(|e| format!("base64 decode: {}", e))
}

pub(crate) fn jwk_d_bytes(jwk_string: &str) -> Result<Vec<u8>, String> {
    let jwk: Value = serde_json::from_str(jwk_string).map_err(|e| format!("jwk parse: {}", e))?;
    let d = jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "jwk missing d".to_string())?;
    URL_SAFE_NO_PAD
        .decode(d.trim().trim_end_matches('='))
        .map_err(|e| format!("jwk d decode: {}", e))
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
    let pq_key_id = rec.get("pq_key_id").and_then(|v| v.as_i64()).map(|v| v as i32);
    let x3dh_version = rec
        .get("x3dh_v")
        .and_then(|v| v.as_u64())
        .map(|v| u8::try_from(v).unwrap_or(u8::MAX));
    let one_time_bound = x3dh_version == Some(X3DH_VERSION_ONE_TIME_BOUND);
    let opk_id = rec
        .get("opk_id")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .filter(|key_id| one_time_bound && is_valid_one_time_prekey_id(*key_id));
    let spk_id = rec
        .get("spk_id")
        .and_then(|v| v.as_str())
        .filter(|_| one_time_bound)
        .map(str::to_string);

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
        x3dh_version,
        opk_id,
        spk_id,
        opk_secret: None,
    })
}

fn matches_signed_prekey_hint(keys: &RatchetReceiverKeys, hint: Option<&str>) -> bool {
    let Some(hint) = hint else {
        return false;
    };
    identity_public_sec1(&keys.signed_prekey_secret_d)
        .map(|public| signed_prekey_id(&public).eq_ignore_ascii_case(hint))
        .unwrap_or(false)
}

pub(crate) fn key_sets_in_hint_order<'a>(
    key_sets: &'a [RatchetReceiverKeys],
    hint: Option<&str>,
) -> Vec<&'a RatchetReceiverKeys> {
    let (mut hinted, rest): (Vec<_>, Vec<_>) = key_sets
        .iter()
        .partition(|keys| matches_signed_prekey_hint(keys, hint));
    hinted.extend(rest);
    hinted
}

pub fn decrypt_with_key_sets(key_sets: &[RatchetReceiverKeys], msg: &RatchetMessage) -> Option<String> {
    for keys in key_sets_in_hint_order(key_sets, msg.spk_id.as_deref()) {
        if let Ok(plaintext) = decrypt_bootstrap(keys, msg) {
            return Some(plaintext);
        }
    }
    None
}

#[allow(dead_code)]
pub fn encrypt_bootstrap(
    sender_identity_secret_d: &[u8],
    recipient_identity_public: &[u8],
    recipient_signed_prekey_public: &[u8],
    recipient_pq_public: Option<&[u8]>,
    pq_key_id: Option<i32>,
    plaintext: &str,
) -> Result<RatchetMessage, String> {
    encrypt_bootstrap_versioned(
        sender_identity_secret_d,
        recipient_identity_public,
        recipient_signed_prekey_public,
        recipient_pq_public,
        pq_key_id,
        X3DH_VERSION_LEGACY,
        plaintext,
    )
}

pub fn encrypt_bootstrap_versioned(
    sender_identity_secret_d: &[u8],
    recipient_identity_public: &[u8],
    recipient_signed_prekey_public: &[u8],
    recipient_pq_public: Option<&[u8]>,
    pq_key_id: Option<i32>,
    x3dh_version: u8,
    plaintext: &str,
) -> Result<RatchetMessage, String> {
    let version = match x3dh_version {
        X3DH_VERSION_TRANSCRIPT_BOUND | X3DH_VERSION_KEY_BOUND => x3dh_version,
        _ => X3DH_VERSION_LEGACY,
    };
    seal_bootstrap(
        sender_identity_secret_d,
        recipient_identity_public,
        recipient_signed_prekey_public,
        recipient_pq_public,
        pq_key_id,
        version,
        None,
        plaintext,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_bootstrap_one_time_bound(
    sender_identity_secret_d: &[u8],
    recipient_identity_public: &[u8],
    recipient_signed_prekey_public: &[u8],
    recipient_pq_public: Option<&[u8]>,
    pq_key_id: Option<i32>,
    one_time_key_id: u32,
    one_time_public: &[u8],
    plaintext: &str,
) -> Result<RatchetMessage, String> {
    if !is_valid_one_time_prekey_id(one_time_key_id) {
        return Err("one-time prekey id is out of range".to_string());
    }
    if !is_p256_public(one_time_public) {
        return Err("one-time prekey is not a P-256 public key".to_string());
    }
    if !is_p256_public(recipient_identity_public) || !is_p256_public(recipient_signed_prekey_public) {
        return Err("one-time handshake needs every public key".to_string());
    }
    seal_bootstrap(
        sender_identity_secret_d,
        recipient_identity_public,
        recipient_signed_prekey_public,
        recipient_pq_public,
        pq_key_id,
        X3DH_VERSION_ONE_TIME_BOUND,
        Some((one_time_key_id, one_time_public)),
        plaintext,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_bootstrap(
    sender_identity_secret_d: &[u8],
    recipient_identity_public: &[u8],
    recipient_signed_prekey_public: &[u8],
    recipient_pq_public: Option<&[u8]>,
    pq_key_id: Option<i32>,
    version: u8,
    one_time: Option<(u32, &[u8])>,
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
    let mut dh4 = match one_time {
        Some((_, one_time_public)) => Some(ecdh_p256(ephemeral_d.as_slice(), one_time_public)?),
        None => None,
    };

    let (pq_ciphertext, out_key_id, mut pq_ss): (Option<Vec<u8>>, Option<i32>, Option<Vec<u8>>) =
        match (recipient_pq_public, pq_key_id) {
            (Some(pq_pub), Some(kid)) => {
                let encoded = ml_kem::Encoded::<EncapKey>::try_from(pq_pub)
                    .map_err(|e| format!("mlkem public size: {:?}", e))?;
                let ek = EncapKey::from_bytes(&encoded);
                let (ct, ss) = ek
                    .encapsulate(&mut OsRng)
                    .map_err(|e| format!("encapsulate: {:?}", e))?;
                (Some(ct.as_slice().to_vec()), Some(kid), Some(ss.as_slice().to_vec()))
            }
            _ => (None, None, None),
        };
    let pq = match (&pq_ss, &pq_ciphertext) {
        (Some(shared_secret), Some(ciphertext)) => Some(PqContribution {
            shared_secret,
            ciphertext,
            from_identity: out_key_id == Some(PQ_IDENTITY_KEY_ID),
        }),
        _ => None,
    };
    let transcript = (version >= X3DH_VERSION_TRANSCRIPT_BOUND).then_some(Transcript {
        version,
        initiator_identity: &sender_identity_public,
        responder_identity: recipient_identity_public,
        responder_signed_prekey: recipient_signed_prekey_public,
        initiator_ephemeral: &ephemeral_public,
        one_time: one_time.map(|(key_id, public)| OneTimeBinding { key_id, public }),
    });

    let mut dh: Vec<&[u8]> = vec![dh1.as_slice(), dh2.as_slice(), dh3.as_slice()];
    if let Some(dh4) = dh4.as_ref() {
        dh.push(dh4.as_slice());
    }
    let shared_secret = x3dh_shared_secret(&dh, pq, transcript);
    drop(dh);
    if let Some(secret) = pq_ss.as_mut() {
        secret.zeroize();
    }
    if let Some(secret) = dh4.as_mut() {
        secret.zeroize();
    }
    let shared_secret = shared_secret?;

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
        x3dh_version: (version >= X3DH_VERSION_TRANSCRIPT_BOUND).then_some(version),
        opk_id: one_time.map(|(key_id, _)| key_id),
        spk_id: one_time.map(|_| signed_prekey_id(recipient_signed_prekey_public)),
        opk_secret: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_harness::derive_sync_key;
    use ml_kem::kem::Encapsulate;
    use sha2::Digest;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;
    use serde_json::json;


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
        let header_bound = header_version.map(|v| v >= 2).unwrap_or(false);
        build_sealed_message(plaintext, use_pq, header_version, header_bound)
    }

    fn build_sealed_message(
        plaintext: &str,
        use_pq: bool,
        header_version: Option<u8>,
        header_bound: bool,
    ) -> Built {
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
        let ciphertext = if header_bound {
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
                x3dh_version: None,
                opk_id: None,
                spk_id: None,
                opk_secret: None,
            },
        }
    }

    const VECTOR_RECEIVER_IDENTITY_D: &str = "S-TtOFuUV4kV3U_6iwvv7w_2FsCMvB2JJAP2qEHWENc";
    const VECTOR_RECEIVER_SIGNED_PREKEY_D: &str = "_964242B7JrwBFGRDZSqeWB-34nP1X8JeFrM_kcb2h8";
    const VECTOR_SENDER_IDENTITY: &str =
        "BN8n2kbWCqaAzmq3WZqLmpl2H7G6DM2o8LP4z0ZA6DWEkVAiEcrDMyM/SF0M6g4KvkIGKE52GkieLoXBCXfcGbs=";
    const VECTOR_SENDER_EPHEMERAL: &str =
        "BDfQMwe0A3dW5WScHDZPToNk67qpP/VdQspfEd1zHZwW/IoCDYVRxpWBUF92xIgp85tfr76G3fgbq6w1F8NtXjw=";

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn vector_secret(version: Option<u8>, pq: bool, identity_lane: bool) -> Result<String, String> {
        vector_secret_with_one_time(version, pq, identity_lane, None, None)
    }

    fn vector_secret_with_one_time(
        version: Option<u8>,
        pq: bool,
        identity_lane: bool,
        opk_id: Option<u32>,
        opk_secret: Option<Vec<u8>>,
    ) -> Result<String, String> {
        use ml_kem::EncapsulateDeterministic;

        let seed: Vec<u8> = (0..64u32).map(|i| ((i * 13 + 5) & 0xff) as u8).collect();
        let randomness: Vec<u8> = (0..32u32).map(|i| ((i * 17 + 9) & 0xff) as u8).collect();
        let d = Array::try_from(&seed[..32]).unwrap();
        let z = Array::try_from(&seed[32..]).unwrap();
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        let m = Array::try_from(&randomness[..]).unwrap();
        let (ct, ss) = ek.encapsulate_deterministic(&m).unwrap();

        assert_eq!(
            to_hex(ss.as_slice()),
            "5c21a072f4c2a105009f3b845108363b3768e0a0acaa9f3b8c8e2998eb77cc41"
        );
        assert_eq!(
            to_hex(Sha256::digest(ct.as_slice()).as_slice()),
            "a43360145b62962fd1e7a66fe28a609b95eb15292119638cbff121b9e1dfa341"
        );

        let keys = RatchetReceiverKeys {
            identity_secret_d: URL_SAFE_NO_PAD.decode(VECTOR_RECEIVER_IDENTITY_D).unwrap(),
            signed_prekey_secret_d: URL_SAFE_NO_PAD.decode(VECTOR_RECEIVER_SIGNED_PREKEY_D).unwrap(),
            signed_prekey_public: Vec::new(),
        };
        let msg = RatchetMessage {
            sender_identity_public: STANDARD.decode(VECTOR_SENDER_IDENTITY).unwrap(),
            ephemeral_public: STANDARD.decode(VECTOR_SENDER_EPHEMERAL).unwrap(),
            header_dh_public: Vec::new(),
            previous_chain_length: 0,
            message_number: 0,
            header_version: None,
            ciphertext: Vec::new(),
            nonce: Vec::new(),
            pq_ciphertext: pq.then(|| ct.as_slice().to_vec()),
            pq_key_id: pq.then(|| if identity_lane { PQ_IDENTITY_KEY_ID } else { 7 }),
            pq_secret: pq.then(|| dk.as_bytes().to_vec()),
            x3dh_version: version,
            opk_id,
            spk_id: None,
            opk_secret,
        };

        derive_x3dh_shared_secret(&keys, &msg).map(|secret| to_hex(&secret))
    }

    const VECTOR_RECEIVER_ONE_TIME_PREKEY_D: &str = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw";
    const VECTOR_RECEIVER_ONE_TIME_PREKEY: &str =
        "BCR1say+jFjG6SpReRvhFC2KRyeTOj5xHZXoOuldEQr6ZQuEikGWXN5/AKJYN+xh/HjLnqrQG4QpVkzPocFYbJg=";
    const VECTOR_RECEIVER_SIGNED_PREKEY: &str =
        "BD2011HtZ43TRKxUnMnCmWP/0TK0zPJZz5CCvFz5jI0YIgTYHpcXHehrOpf9cUy8sk9Pl6Xi4+JuPtkA+ZiK1Cc=";
    const VECTOR_ONE_TIME_PREKEY_ID: u32 = 16_909_060;
    const VECTOR_SIGNED_PREKEY_ID: &str = "c5ea95322278e438";

    fn vector_one_time_secret() -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(VECTOR_RECEIVER_ONE_TIME_PREKEY_D).unwrap()
    }

    fn one_time_vector_secret(pq: bool, identity_lane: bool) -> Result<String, String> {
        vector_secret_with_one_time(
            Some(X3DH_VERSION_ONE_TIME_BOUND),
            pq,
            identity_lane,
            Some(VECTOR_ONE_TIME_PREKEY_ID),
            Some(vector_one_time_secret()),
        )
    }

    #[test]
    fn one_time_bound_secrets_match_the_cross_client_vectors() {
        assert_eq!(
            one_time_vector_secret(false, false).unwrap(),
            "cd86fc61ca372fd0fe6cef01c44b004d66956e98779c2c115605d5098a42b148"
        );
        assert_eq!(
            one_time_vector_secret(true, false).unwrap(),
            "80a66a85ce5a08d96469b61f1a35e8512b431519342d5bd597ff86a5bf7ec50a"
        );
        assert_eq!(
            one_time_vector_secret(true, true).unwrap(),
            "49e59d658796cf02446ae941a33c01f0f8bb954ce1f968a45738598c36132818"
        );
    }

    #[test]
    fn the_vector_one_time_prekey_matches_its_public_key_and_agreement() {
        let secret = vector_one_time_secret();
        assert_eq!(
            identity_public_sec1(&secret).unwrap(),
            STANDARD.decode(VECTOR_RECEIVER_ONE_TIME_PREKEY).unwrap()
        );
        let dh4 = ecdh_p256(&secret, &STANDARD.decode(VECTOR_SENDER_EPHEMERAL).unwrap()).unwrap();
        assert_eq!(
            to_hex(&dh4),
            "fac4776f042455e16e259fc01c18495dadf16b63652473797bbd9fbd3232eaa0"
        );
        assert_eq!(VECTOR_ONE_TIME_PREKEY_ID.to_be_bytes(), [1, 2, 3, 4]);
    }

    #[test]
    fn earlier_handshakes_ignore_one_time_prekey_material() {
        let cases = [
            (Some(1), false, false, "8d18029bb35dde7d83b8f9228152e49d34e096819b1fb7c810ef70ac5bc600b6"),
            (Some(2), false, false, "6bb032c615db5f87012e62cf8da751b52343c2b4c2d5ed8f140a2c1bb6014f48"),
            (Some(3), false, false, "09459744acadbaf0e93995b1e78476b89ae2abc12225f3b8471680411f39f075"),
            (Some(1), true, false, "efa41c478ff0477bfea970527a6a9cee3d8a348e3e4704e255593aa18e3b25f6"),
            (Some(2), true, false, "023e364282464ccbe2c013d61f7453907d94e2a464f0ee5025cb485eb9cc324c"),
            (Some(3), true, false, "295cb2db9bb952b6beff8dff48ab2bfda87b16c09eb05397a36326361bcc60f4"),
            (Some(2), true, true, "1ffb50c01be8f1aa988305dc1152a159a7ab59ad9f845e2f3f7544bf272af88a"),
            (Some(3), true, true, "c96ffc27882c8cdd893f3f3a5cea5c5961c94702b6fd34498f254a71e5266fdd"),
        ];
        for (version, pq, identity_lane, expected) in cases {
            let secret = vector_secret_with_one_time(
                version,
                pq,
                identity_lane,
                Some(VECTOR_ONE_TIME_PREKEY_ID),
                Some(vector_one_time_secret()),
            )
            .unwrap();
            assert_eq!(secret, expected, "version {:?}", version);
        }
    }

    #[test]
    fn a_one_time_bound_handshake_refuses_missing_inputs() {
        let secret = vector_one_time_secret;
        let derive = |opk_id: Option<u32>, opk_secret: Option<Vec<u8>>| {
            vector_secret_with_one_time(Some(X3DH_VERSION_ONE_TIME_BOUND), false, false, opk_id, opk_secret)
        };

        assert!(derive(None, None).is_err());
        assert!(derive(Some(VECTOR_ONE_TIME_PREKEY_ID), None).is_err());
        assert!(derive(None, Some(secret())).is_err());
        assert!(derive(Some(0), Some(secret())).is_err());
        assert!(derive(Some(ONE_TIME_PREKEY_ID_MAX + 1), Some(secret())).is_err());
        assert!(derive(Some(u32::MAX), Some(secret())).is_err());
        assert!(derive(Some(VECTOR_ONE_TIME_PREKEY_ID), Some(vec![0u8; 32])).is_err());
        assert!(derive(Some(VECTOR_ONE_TIME_PREKEY_ID), Some(vec![7u8; 16])).is_err());
        assert!(derive(Some(1), Some(secret())).is_ok());
        assert!(derive(Some(ONE_TIME_PREKEY_ID_MAX), Some(secret())).is_ok());
        assert!(vector_secret_with_one_time(Some(5), false, false, Some(1), Some(secret())).is_err());
    }

    fn bound_secret(
        version: u8,
        parts: usize,
        publics: [&[u8]; 4],
        one_time: Option<(u32, &[u8])>,
    ) -> Result<Vec<u8>, String> {
        let agreements = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let dh: Vec<&[u8]> = agreements.iter().take(parts).map(|part| part.as_slice()).collect();
        x3dh_shared_secret(
            &dh,
            None,
            Some(Transcript {
                version,
                initiator_identity: publics[0],
                responder_identity: publics[1],
                responder_signed_prekey: publics[2],
                initiator_ephemeral: publics[3],
                one_time: one_time.map(|(key_id, public)| OneTimeBinding { key_id, public }),
            }),
        )
    }

    #[test]
    fn a_one_time_bound_transcript_is_never_shortened() {
        let full_bytes = [4u8; 65];
        let full: &[u8] = &full_bytes;
        let short: &[u8] = &full_bytes[..64];
        let empty: &[u8] = &[];
        let bound = X3DH_VERSION_ONE_TIME_BOUND;
        let all = [full, full, full, full];

        assert!(bound_secret(bound, 4, all, Some((9u32, full))).is_ok());
        assert!(bound_secret(bound, 3, all, Some((9u32, full))).is_err());
        assert!(bound_secret(bound, 4, all, None).is_err());
        for missing in 0..4 {
            let mut publics = all;
            publics[missing] = empty;
            assert!(bound_secret(bound, 4, publics, Some((9u32, full))).is_err());
            publics[missing] = short;
            assert!(bound_secret(bound, 4, publics, Some((9u32, full))).is_err());
        }
        assert!(bound_secret(bound, 4, all, Some((9u32, short))).is_err());
        assert!(bound_secret(bound, 4, all, Some((9u32, empty))).is_err());
        assert!(bound_secret(bound, 4, all, Some((0u32, full))).is_err());
        assert!(bound_secret(bound, 4, all, Some((ONE_TIME_PREKEY_ID_MAX + 1, full))).is_err());

        assert!(bound_secret(X3DH_VERSION_KEY_BOUND, 3, all, None).is_ok());
        assert!(bound_secret(X3DH_VERSION_KEY_BOUND, 4, all, None).is_err());
        assert!(bound_secret(X3DH_VERSION_KEY_BOUND, 3, all, Some((9u32, full))).is_err());
        assert!(bound_secret(5, 4, all, Some((9u32, full))).is_err());
    }

    #[test]
    fn the_signed_prekey_id_matches_the_vector() {
        let public = STANDARD.decode(VECTOR_RECEIVER_SIGNED_PREKEY).unwrap();
        assert_eq!(signed_prekey_id(&public), VECTOR_SIGNED_PREKEY_ID);
        assert_eq!(
            identity_public_sec1(&URL_SAFE_NO_PAD.decode(VECTOR_RECEIVER_SIGNED_PREKEY_D).unwrap()).unwrap(),
            public
        );
    }

    #[test]
    fn the_signed_prekey_hint_orders_candidates_without_excluding_any() {
        let first = peer().keys;
        let second = peer().keys;
        let key_sets = vec![first.clone(), second.clone()];
        let hint = signed_prekey_id(&second.signed_prekey_public);
        let order = |hint: Option<&str>| -> Vec<Vec<u8>> {
            key_sets_in_hint_order(&key_sets, hint)
                .into_iter()
                .map(|keys| keys.signed_prekey_public.clone())
                .collect()
        };

        assert_eq!(order(None), vec![first.signed_prekey_public.clone(), second.signed_prekey_public.clone()]);
        assert_eq!(
            order(Some(hint.as_str())),
            vec![second.signed_prekey_public.clone(), first.signed_prekey_public.clone()]
        );
        assert_eq!(
            order(Some(hint.to_uppercase().as_str())),
            vec![second.signed_prekey_public.clone(), first.signed_prekey_public.clone()]
        );
        assert_eq!(
            order(Some("0000000000000000")),
            vec![first.signed_prekey_public.clone(), second.signed_prekey_public.clone()]
        );
    }

    #[test]
    fn a_one_time_bound_bootstrap_round_trips_on_every_lane() {
        let sender = SecretKey::random(&mut OsRng);
        for pq_key_id in [None, Some(7), Some(PQ_IDENTITY_KEY_ID)] {
            let recipient = peer();
            let one_time = SecretKey::random(&mut OsRng);
            let mut message = encrypt_bootstrap_one_time_bound(
                sender.to_bytes().as_slice(),
                &recipient.identity_public,
                &recipient.keys.signed_prekey_public,
                pq_key_id.map(|_| recipient.pq_public.as_slice()),
                pq_key_id,
                41,
                &pub_sec1(&one_time),
                "one-time",
            )
            .unwrap();
            assert_eq!(message.x3dh_version, Some(X3DH_VERSION_ONE_TIME_BOUND));
            assert_eq!(message.opk_id, Some(41));
            assert_eq!(
                message.spk_id.as_deref(),
                Some(signed_prekey_id(&recipient.keys.signed_prekey_public).as_str())
            );
            assert!(message.opk_secret.is_none());
            if pq_key_id.is_some() {
                message.pq_secret = Some(recipient.pq_secret.clone());
            }

            assert!(decrypt_bootstrap(&recipient.keys, &message).is_err());

            message.opk_secret = Some(SecretKey::random(&mut OsRng).to_bytes().to_vec());
            assert!(decrypt_bootstrap(&recipient.keys, &message).is_err());

            message.opk_secret = Some(one_time.to_bytes().to_vec());
            assert_eq!(decrypt_bootstrap(&recipient.keys, &message).unwrap(), "one-time");

            message.spk_id = Some("ffffffffffffffff".to_string());
            let other = peer().keys;
            assert_eq!(
                decrypt_with_key_sets(&[other, recipient.keys.clone()], &message).as_deref(),
                Some("one-time")
            );

            message.opk_id = Some(42);
            assert!(decrypt_bootstrap(&recipient.keys, &message).is_err());
            message.opk_id = Some(41);

            message.x3dh_version = Some(X3DH_VERSION_KEY_BOUND);
            assert!(decrypt_bootstrap(&recipient.keys, &message).is_err());
        }
    }

    #[test]
    fn the_one_time_bound_sender_refuses_an_unusable_one_time_prekey() {
        let sender = SecretKey::random(&mut OsRng);
        let recipient = peer();
        let one_time = pub_sec1(&SecretKey::random(&mut OsRng));
        let seal = |key_id: u32, public: &[u8]| {
            encrypt_bootstrap_one_time_bound(
                sender.to_bytes().as_slice(),
                &recipient.identity_public,
                &recipient.keys.signed_prekey_public,
                None,
                None,
                key_id,
                public,
                "refused",
            )
        };
        let mut compressed_tag = one_time.clone();
        compressed_tag[0] = 0x02;
        let mut off_curve = one_time.clone();
        off_curve[64] ^= 0x01;

        assert!(seal(1, &one_time).is_ok());
        assert!(seal(0, &one_time).is_err());
        assert!(seal(ONE_TIME_PREKEY_ID_MAX + 1, &one_time).is_err());
        assert!(seal(1, &one_time[..64]).is_err());
        assert!(seal(1, &[]).is_err());
        assert!(seal(1, &compressed_tag).is_err());
        assert!(seal(1, &off_curve).is_err());
    }

    #[test]
    fn the_versioned_sender_never_writes_the_one_time_bound_version() {
        let sender = SecretKey::random(&mut OsRng);
        let recipient = peer();
        for version in [1, 2, 3, X3DH_VERSION_ONE_TIME_BOUND, 5] {
            let message = encrypt_bootstrap_versioned(
                sender.to_bytes().as_slice(),
                &recipient.identity_public,
                &recipient.keys.signed_prekey_public,
                None,
                None,
                version,
                "earlier",
            )
            .unwrap();
            assert_ne!(message.x3dh_version, Some(X3DH_VERSION_ONE_TIME_BOUND));
            assert!(message.opk_id.is_none());
            assert!(message.spk_id.is_none());
            assert_eq!(decrypt_bootstrap(&recipient.keys, &message).unwrap(), "earlier");
        }
    }

    #[test]
    fn one_time_fields_are_parsed_only_for_the_one_time_bound_version() {
        let (case, _, _) = pq_identity_vector_parts();
        let mut ratchet = find_ratchet_object(&case["envelope"]).unwrap();
        let our_email = case["our_email"].as_str().unwrap();
        let mut set = |version: Value, opk_id: Value, spk_id: Value| {
            for entry in ratchet["recipients"].as_object_mut().unwrap().values_mut() {
                entry["x3dh_v"] = version.clone();
                entry["opk_id"] = opk_id.clone();
                entry["spk_id"] = spk_id.clone();
            }
            parse_recipient_message(&ratchet, our_email).unwrap()
        };

        let bound = set(json!(4), json!(16909060), json!("c5ea95322278e438"));
        assert_eq!(bound.x3dh_version, Some(4));
        assert_eq!(bound.opk_id, Some(16_909_060));
        assert_eq!(bound.spk_id.as_deref(), Some("c5ea95322278e438"));
        assert!(bound.opk_secret.is_none());

        for version in [1, 2, 3] {
            let earlier = set(json!(version), json!(16909060), json!("c5ea95322278e438"));
            assert_eq!(earlier.opk_id, None);
            assert_eq!(earlier.spk_id, None);
        }

        for bad_id in [json!(0), json!(2147483648u64), json!(-1), json!("7"), json!(1.5), Value::Null] {
            assert_eq!(set(json!(4), bad_id, Value::Null).opk_id, None);
        }
        assert_eq!(set(json!(4), json!(2147483647), json!(7)).opk_id, Some(ONE_TIME_PREKEY_ID_MAX));
        assert_eq!(set(json!(4), json!(1), json!(7)).spk_id, None);
    }

    #[test]
    fn x3dh_secrets_match_the_cross_client_vectors() {
        assert_eq!(
            vector_secret(Some(1), false, false).unwrap(),
            "8d18029bb35dde7d83b8f9228152e49d34e096819b1fb7c810ef70ac5bc600b6"
        );
        assert_eq!(vector_secret(None, false, false), vector_secret(Some(1), false, false));
        assert_eq!(
            vector_secret(Some(2), false, false).unwrap(),
            "6bb032c615db5f87012e62cf8da751b52343c2b4c2d5ed8f140a2c1bb6014f48"
        );
        assert_eq!(
            vector_secret(Some(1), true, false).unwrap(),
            "efa41c478ff0477bfea970527a6a9cee3d8a348e3e4704e255593aa18e3b25f6"
        );
        assert_eq!(
            vector_secret(Some(2), true, false).unwrap(),
            "023e364282464ccbe2c013d61f7453907d94e2a464f0ee5025cb485eb9cc324c"
        );
        assert_eq!(
            vector_secret(Some(2), true, true).unwrap(),
            "1ffb50c01be8f1aa988305dc1152a159a7ab59ad9f845e2f3f7544bf272af88a"
        );
        assert_eq!(
            vector_secret(Some(3), false, false).unwrap(),
            "09459744acadbaf0e93995b1e78476b89ae2abc12225f3b8471680411f39f075"
        );
        assert_eq!(
            vector_secret(Some(3), true, false).unwrap(),
            "295cb2db9bb952b6beff8dff48ab2bfda87b16c09eb05397a36326361bcc60f4"
        );
        assert_eq!(
            vector_secret(Some(3), true, true).unwrap(),
            "c96ffc27882c8cdd893f3f3a5cea5c5961c94702b6fd34498f254a71e5266fdd"
        );
    }

    struct Peer {
        keys: RatchetReceiverKeys,
        identity_public: Vec<u8>,
        pq_public: Vec<u8>,
        pq_secret: Vec<u8>,
    }

    fn peer() -> Peer {
        let identity = SecretKey::random(&mut OsRng);
        let prekey = SecretKey::random(&mut OsRng);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let prekey_public = prekey.public_key().to_encoded_point(false).as_bytes().to_vec();
        Peer {
            identity_public: identity.public_key().to_encoded_point(false).as_bytes().to_vec(),
            keys: RatchetReceiverKeys {
                identity_secret_d: identity.to_bytes().to_vec(),
                signed_prekey_secret_d: prekey.to_bytes().to_vec(),
                signed_prekey_public: prekey_public,
            },
            pq_public: ek.as_bytes().to_vec(),
            pq_secret: dk.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_bound_bootstrap_round_trips_on_every_lane() {
        let sender = SecretKey::random(&mut OsRng);
        let lanes = [None, Some(7), Some(PQ_IDENTITY_KEY_ID)];
        let versions = [
            (X3DH_VERSION_TRANSCRIPT_BOUND, X3DH_VERSION_KEY_BOUND),
            (X3DH_VERSION_KEY_BOUND, X3DH_VERSION_TRANSCRIPT_BOUND),
        ];
        for (pq_key_id, (version, other_version)) in
            lanes.into_iter().flat_map(|lane| versions.map(|pair| (lane, pair)))
        {
            let recipient = peer();
            let mut message = encrypt_bootstrap_versioned(
                sender.to_bytes().as_slice(),
                &recipient.identity_public,
                &recipient.keys.signed_prekey_public,
                pq_key_id.map(|_| recipient.pq_public.as_slice()),
                pq_key_id,
                version,
                "bound",
            )
            .unwrap();
            assert_eq!(message.x3dh_version, Some(version));
            if pq_key_id.is_some() {
                message.pq_secret = Some(recipient.pq_secret.clone());
            }

            assert_eq!(decrypt_bootstrap(&recipient.keys, &message).unwrap(), "bound");

            message.x3dh_version = Some(other_version);
            assert!(decrypt_bootstrap(&recipient.keys, &message).is_err());

            message.x3dh_version = None;
            assert!(decrypt_bootstrap(&recipient.keys, &message).is_err());
        }
    }

    #[test]
    fn a_key_bound_bootstrap_does_not_open_under_another_signed_prekey() {
        let sender = SecretKey::random(&mut OsRng);
        let recipient = peer();
        let message = encrypt_bootstrap_versioned(
            sender.to_bytes().as_slice(),
            &recipient.identity_public,
            &recipient.keys.signed_prekey_public,
            None,
            None,
            X3DH_VERSION_KEY_BOUND,
            "bound",
        )
        .unwrap();
        let other_prekey = SecretKey::random(&mut OsRng);
        let other_keys = RatchetReceiverKeys {
            identity_secret_d: recipient.keys.identity_secret_d.clone(),
            signed_prekey_secret_d: other_prekey.to_bytes().to_vec(),
            signed_prekey_public: other_prekey.public_key().to_encoded_point(false).as_bytes().to_vec(),
        };

        assert!(decrypt_bootstrap(&other_keys, &message).is_err());
        assert_eq!(decrypt_bootstrap(&recipient.keys, &message).unwrap(), "bound");
    }

    #[test]
    fn an_unknown_sender_version_falls_back_to_the_first_handshake() {
        let sender = SecretKey::random(&mut OsRng);
        let recipient = peer();
        let message = encrypt_bootstrap_versioned(
            sender.to_bytes().as_slice(),
            &recipient.identity_public,
            &recipient.keys.signed_prekey_public,
            None,
            None,
            9,
            "legacy",
        )
        .unwrap();

        assert_eq!(message.x3dh_version, None);
        assert_eq!(decrypt_bootstrap(&recipient.keys, &message).unwrap(), "legacy");
    }

    #[test]
    fn an_unbound_bootstrap_stays_on_the_first_handshake_version() {
        let sender = SecretKey::random(&mut OsRng);
        let recipient = peer();
        let mut message = encrypt_bootstrap(
            sender.to_bytes().as_slice(),
            &recipient.identity_public,
            &recipient.keys.signed_prekey_public,
            Some(recipient.pq_public.as_slice()),
            Some(7),
            "unbound",
        )
        .unwrap();
        assert_eq!(message.x3dh_version, None);
        message.pq_secret = Some(recipient.pq_secret.clone());

        assert_eq!(decrypt_bootstrap(&recipient.keys, &message).unwrap(), "unbound");

        message.x3dh_version = Some(X3DH_VERSION_TRANSCRIPT_BOUND);
        assert!(decrypt_bootstrap(&recipient.keys, &message).is_err());
    }

    #[test]
    fn unknown_x3dh_version_is_rejected() {
        assert!(vector_secret(Some(4), false, false).is_err());
        assert!(vector_secret(Some(0), false, false).is_err());
        assert!(vector_secret(Some(u8::MAX), false, false).is_err());
    }

    #[test]
    fn parses_the_x3dh_version_from_the_recipient_entry() {
        let (case, _, _) = pq_identity_vector_parts();
        let mut ratchet = find_ratchet_object(&case["envelope"]).unwrap();
        let our_email = case["our_email"].as_str().unwrap();

        assert_eq!(parse_recipient_message(&ratchet, our_email).unwrap().x3dh_version, None);

        let recipients = ratchet["recipients"].as_object_mut().unwrap();
        for entry in recipients.values_mut() {
            entry["x3dh_v"] = json!(2);
        }

        assert_eq!(parse_recipient_message(&ratchet, our_email).unwrap().x3dh_version, Some(2));
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
    fn unversioned_header_never_opens_as_header_bound() {
        for header_version in [None, Some(1)] {
            let b = build_sealed_message("sealed with a header binding", true, header_version, true);
            assert!(decrypt_bootstrap(&b.keys, &b.msg).is_err());
        }
    }

    #[test]
    fn versioned_header_still_opens_mail_sealed_without_its_binding() {
        let pt = "sent by an older desktop build";
        let b = build_sealed_message(pt, true, Some(2), false);
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

    const PQ_IDENTITY_INTEROP_VECTORS: &str = include_str!("pq_identity_interop_vectors.json");

    fn pq_identity_vector() -> Value {
        let root: Value = serde_json::from_str(PQ_IDENTITY_INTEROP_VECTORS).unwrap();
        root["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "pq_identity_bootstrap")
            .unwrap()
            .clone()
    }

    fn pq_identity_vector_parts() -> (Value, Vec<RatchetReceiverKeys>, RatchetMessage) {
        let case = pq_identity_vector();

        let vault_json = json!({
            "identity_key": "pgp-not-used-here",
            "ratchet_identity_key": case["recipient_identity_jwk"].as_str().unwrap(),
            "ratchet_identity_public": case["recipient_identity_public"].as_str().unwrap(),
            "ratchet_signed_prekey": case["recipient_signed_prekey_jwk"].as_str().unwrap(),
            "ratchet_signed_prekey_public": case["recipient_signed_prekey_public"].as_str().unwrap()
        })
        .to_string();
        let vault: VaultContents = serde_json::from_str(&vault_json).unwrap();
        let key_sets = build_receiver_key_sets(&vault);

        let ratchet_obj = find_ratchet_object(&case["envelope"]).expect("web envelope detected");
        let our_email = case["our_email"].as_str().unwrap();
        let mut msg = parse_recipient_message(&ratchet_obj, our_email).expect("parsed");
        msg.pq_secret =
            Some(b64_decode(case["recipient_pq_identity_secret"].as_str().unwrap()).unwrap());

        (case, key_sets, msg)
    }

    #[test]
    fn decrypts_web_sealed_pq_identity_bootstrap() {
        let (case, key_sets, msg) = pq_identity_vector_parts();

        assert_eq!(msg.pq_key_id, Some(PQ_IDENTITY_KEY_ID));
        assert_eq!(key_sets.len(), 1);

        let plaintext = decrypt_with_key_sets(&key_sets, &msg).expect("decrypted");
        assert_eq!(plaintext, case["plaintext"].as_str().unwrap());
    }

    #[test]
    fn pq_identity_vector_fails_with_the_one_time_prekey_info() {
        let (_, key_sets, mut msg) = pq_identity_vector_parts();

        msg.pq_key_id = Some(436178);

        assert!(decrypt_with_key_sets(&key_sets, &msg).is_none());
    }

    #[test]
    fn pq_identity_seed_derives_the_vector_decapsulation_key() {
        let case = pq_identity_vector();
        let seed = b64_decode(case["recipient_pq_identity_seed"].as_str().unwrap()).unwrap();
        let expected = b64_decode(case["recipient_pq_identity_secret"].as_str().unwrap()).unwrap();

        let d = Array::try_from(&seed[..32]).unwrap();
        let z = Array::try_from(&seed[32..]).unwrap();
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);

        assert_eq!(dk.as_bytes().to_vec(), expected);
        assert_eq!(
            ek.as_bytes().to_vec(),
            b64_decode(case["recipient_pq_identity_public"].as_str().unwrap()).unwrap()
        );
    }

    #[test]
    fn find_ratchet_object_ignores_plain_mail() {
        let envelope = json!({"subject": "s", "body_text": "just a normal message"});
        assert!(find_ratchet_object(&envelope).is_none());
    }
}
