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
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::inbound::decode_pq_decap_key;
use crate::crypto::ratchet::{
    b64_decode, ecdh_p256, hkdf_sha256, jwk_d_bytes, ml_kem768_decapsulate, serialize_header_ad,
};
use crate::crypto::vault::VaultContents;

pub const RECOVERY_LANE_VERSION: u64 = 1;
const LANE_LABEL: &str = "aster.ratchet.recovery.lane.v1";
const STORAGE_KEY_INFO_V1: &[u8] = b"aster-storage-encryption-key-v1";
const STORAGE_SALT_PREFIX_V1: &[u8] = b"aster-hkdf-salt-v1:";
const STORAGE_KEY_INFO_V2: &[u8] = b"aster-storage-encryption-key-v2";
const STORAGE_STRETCH_SALT_V2: &[u8] = b"aster-storage-stretch-salt-v2";
const STORAGE_EXPANSION_SALT_V2: &[u8] = b"aster-storage-expansion-salt-v2";
pub const STORAGE_STRETCH_ITERATIONS: u32 = 600_000;
const MASTER_KEY_VAULT_FORMAT: u32 = 2;
const STORAGE_KDF_VERSION_STRETCHED: u32 = 2;
const MAX_LEGACY_KEKS: usize = 64;
const MAX_STORAGE_KEYS: usize = 512;
const PREVIOUS_KEY_CONTEXTS: [&str; 10] = [
    "astermail-tags-v1",
    "astermail-labels-v1",
    "astermail-preferences-v1",
    "astermail-devmode-v1",
    "astermail-draft-v1",
    "astermail-draft-v2",
    "astermail-scheduled-v1",
    "astermail-onboarding-v1",
    "astermail-subscriptions-v1",
    "astermail-recovery-email-v1",
];
const SYNC_KEY_SALT: &[u8] = b"Aster Mail_Ratchet_State_Encryption";
const SYNC_KEY_INFO: &[u8] = b"ratchet_state_key";
const ESCROW_KEY_SALT: &[u8] = b"Aster_Mail_Plaintext_Escrow";
const ESCROW_KEY_INFO: &[u8] = b"plaintext_escrow_key";
const ESCROW_AAD_V2_PREFIX: &[u8] = b"aster.escrow.v2\0";
pub const MAX_ESCROW_PLAINTEXT_BYTES: usize = 100 * 1024;
const GCM_TAG_LEN: usize = 16;
const MAX_ALIAS_RECIPIENT_ATTEMPTS: usize = 8;
pub const SUBJECT_BUNDLE_MARKER: &str = "ASTER_BUNDLE_V2";
const SUBJECT_BUNDLE_DELIMITER: char = '\u{1}';
const MAX_SUBJECT_BUNDLE_DEPTH: usize = 8;

#[derive(Zeroize, Clone)]
pub struct LaneCandidate {
    pub identity_secret_d: Vec<u8>,
    pub identity_public: String,
    pub pq_decap_key: Option<Vec<u8>>,
    pub pq_identity_public: String,
}

#[derive(Clone, Default)]
pub struct RecoveryMaterial {
    pub storage_keys: Vec<Zeroizing<[u8; 32]>>,
    pub lane_candidates: Vec<LaneCandidate>,
}

impl Drop for RecoveryMaterial {
    fn drop(&mut self) {
        for candidate in self.lane_candidates.iter_mut() {
            candidate.zeroize();
        }
    }
}

impl RecoveryMaterial {
    pub fn from_vault(vault: &VaultContents, passphrase: &[u8]) -> Self {
        Self::from_vault_with_iterations(vault, passphrase, STORAGE_STRETCH_ITERATIONS)
    }

    pub fn from_vault_with_iterations(vault: &VaultContents, passphrase: &[u8], iterations: u32) -> Self {
        Self {
            storage_keys: derive_storage_base_keys(vault, passphrase, iterations),
            lane_candidates: build_lane_candidates(vault),
        }
    }

    pub fn sync_keys(&self) -> Vec<Zeroizing<[u8; 32]>> {
        derive_sub_keys(&self.storage_keys, SYNC_KEY_SALT, SYNC_KEY_INFO)
    }

    pub fn escrow_keys(&self) -> Vec<Zeroizing<[u8; 32]>> {
        derive_sub_keys(&self.storage_keys, ESCROW_KEY_SALT, ESCROW_KEY_INFO)
    }
}

fn derive_sub_keys(bases: &[Zeroizing<[u8; 32]>], salt: &[u8], info: &[u8]) -> Vec<Zeroizing<[u8; 32]>> {
    bases
        .iter()
        .filter_map(|base| hkdf_sha256(base.as_slice(), salt, info, 32).ok())
        .filter_map(to_key)
        .collect()
}

fn to_key(mut bytes: Vec<u8>) -> Option<Zeroizing<[u8; 32]>> {
    if bytes.len() != 32 {
        bytes.zeroize();
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Some(out)
}

pub fn derive_storage_key_v1(passphrase: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut salt_input = Zeroizing::new(STORAGE_SALT_PREFIX_V1.to_vec());
    salt_input.extend_from_slice(passphrase);
    let salt = Sha256::digest(salt_input.as_slice());
    to_key(hkdf_sha256(passphrase, &salt, STORAGE_KEY_INFO_V1, 32).ok()?)
}

pub fn derive_storage_key_v2(passphrase: &[u8], iterations: u32) -> Option<Zeroizing<[u8; 32]>> {
    let mut stretched = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, STORAGE_STRETCH_SALT_V2, iterations, stretched.as_mut_slice());
    to_key(hkdf_sha256(stretched.as_slice(), STORAGE_EXPANSION_SALT_V2, STORAGE_KEY_INFO_V2, 32).ok()?)
}

fn push_unique(keys: &mut Vec<Zeroizing<[u8; 32]>>, key: Option<Zeroizing<[u8; 32]>>) {
    let Some(key) = key else {
        return;
    };
    if keys.len() >= MAX_STORAGE_KEYS {
        return;
    }
    if keys.iter().any(|existing| existing.as_slice() == key.as_slice()) {
        return;
    }
    keys.push(key);
}

pub fn derive_storage_base_keys(
    vault: &VaultContents,
    passphrase: &[u8],
    iterations: u32,
) -> Vec<Zeroizing<[u8; 32]>> {
    let mut keys: Vec<Zeroizing<[u8; 32]>> = Vec::new();
    let stretched = vault.kdf_version == Some(STORAGE_KDF_VERSION_STRETCHED);
    let password_derived = |stretch: bool| {
        if passphrase.is_empty() {
            None
        } else if stretch {
            derive_storage_key_v2(passphrase, iterations)
        } else {
            derive_storage_key_v1(passphrase)
        }
    };

    let master = if vault.vault_format.unwrap_or(1) >= MASTER_KEY_VAULT_FORMAT {
        vault
            .data_kek
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(|s| b64_decode(s).ok())
            .and_then(to_key)
    } else {
        None
    };

    push_unique(&mut keys, master);
    push_unique(&mut keys, password_derived(stretched));
    if stretched {
        push_unique(&mut keys, password_derived(false));
    }

    for entry in vault.legacy_keks.iter().flatten().take(MAX_LEGACY_KEKS) {
        push_unique(&mut keys, b64_decode(&entry.k).ok().and_then(to_key));
    }

    let previous = vault
        .previous_keys
        .iter()
        .flatten()
        .chain(vault.legacy_identity_keys.iter().flatten());
    for prev in previous {
        for context in PREVIOUS_KEY_CONTEXTS {
            let mut material = Zeroizing::new(Vec::with_capacity(prev.len() + context.len()));
            material.extend_from_slice(prev.as_bytes());
            material.extend_from_slice(context.as_bytes());
            push_unique(&mut keys, to_key(Sha256::digest(material.as_slice()).to_vec()));
        }
    }

    keys
}

fn push_lane_candidate(
    candidates: &mut Vec<LaneCandidate>,
    identity_jwk: Option<&str>,
    identity_public: Option<&str>,
    pq_expanded: Option<&str>,
    pq_seed: Option<&str>,
    pq_public: Option<&str>,
) {
    let (Some(jwk), Some(public)) = (identity_jwk, identity_public) else {
        return;
    };
    if jwk.is_empty() || public.is_empty() {
        return;
    }
    let Ok(identity_secret_d) = jwk_d_bytes(jwk) else {
        return;
    };
    candidates.push(LaneCandidate {
        identity_secret_d,
        identity_public: public.to_string(),
        pq_decap_key: decode_pq_decap_key(pq_expanded, pq_seed),
        pq_identity_public: pq_public.unwrap_or("").to_string(),
    });
}

pub fn build_lane_candidates(vault: &VaultContents) -> Vec<LaneCandidate> {
    let mut candidates = Vec::new();
    push_lane_candidate(
        &mut candidates,
        vault.ratchet_identity_key.as_deref(),
        vault.ratchet_identity_public.as_deref(),
        vault.ratchet_pq_identity_key.as_deref(),
        vault.ratchet_pq_identity_seed.as_deref(),
        vault.ratchet_pq_identity_public.as_deref(),
    );
    for previous in vault.ratchet_previous_keys.iter().flatten() {
        push_lane_candidate(
            &mut candidates,
            previous.ratchet_identity_key.as_deref(),
            previous.ratchet_identity_public.as_deref(),
            previous.ratchet_pq_identity_key.as_deref(),
            previous.ratchet_pq_identity_seed.as_deref(),
            previous.ratchet_pq_identity_public.as_deref(),
        );
    }
    candidates
}

pub fn conversation_id(email_a: &str, email_b: &str) -> String {
    let mut sorted = [email_a.to_lowercase(), email_b.to_lowercase()];
    sorted.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    STANDARD.encode(Sha256::digest(format!("{}:{}", sorted[0], sorted[1]).as_bytes()))
}

pub(crate) fn lane_binding(
    conversation_id: &str,
    sender_identity_public: &str,
    recipient_identity_public: &str,
    recipient_pq_identity_public: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [
        LANE_LABEL,
        conversation_id,
        sender_identity_public,
        recipient_identity_public,
        recipient_pq_identity_public,
    ] {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into()
}

pub(crate) fn lane_key(secrets: &[&[u8]], binding: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new(Vec::new());
    for secret in secrets {
        ikm.extend_from_slice(secret);
    }
    let salt = Sha256::digest(LANE_LABEL.as_bytes());
    to_key(hkdf_sha256(ikm.as_slice(), &salt, binding, 32).ok()?)
}

fn aes_gcm_open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if nonce.len() != 12 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .ok()
        .map(Zeroizing::new)
}

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(|v| v.as_str())
}

pub fn open_recovery_lane_with(
    lane: &Value,
    conversation_id: &str,
    sender_identity_public: &str,
    candidate: &LaneCandidate,
) -> Option<Zeroizing<String>> {
    if lane.get("v").and_then(|v| v.as_u64()) != Some(RECOVERY_LANE_VERSION) {
        return None;
    }
    let kem_ct = json_str(lane, "kem_ct").filter(|s| !s.is_empty());
    let binding = lane_binding(
        conversation_id,
        sender_identity_public,
        &candidate.identity_public,
        if kem_ct.is_some() { &candidate.pq_identity_public } else { "" },
    );
    let epk = b64_decode(json_str(lane, "epk")?).ok()?;
    let dh = Zeroizing::new(ecdh_p256(&candidate.identity_secret_d, &epk).ok()?);
    let pq = match kem_ct {
        Some(ct) => {
            let decap = candidate.pq_decap_key.as_ref()?;
            let ct = b64_decode(ct).ok()?;
            Some(Zeroizing::new(ml_kem768_decapsulate(&ct, decap).ok()?))
        }
        None => None,
    };
    let key = match &pq {
        Some(pq) => lane_key(&[dh.as_slice(), pq.as_slice()], &binding)?,
        None => lane_key(&[dh.as_slice()], &binding)?,
    };
    let nonce = b64_decode(json_str(lane, "nonce")?).ok()?;
    let ciphertext = b64_decode(json_str(lane, "ciphertext")?).ok()?;
    let plaintext = aes_gcm_open(key.as_slice(), &nonce, &ciphertext, &binding)?;
    String::from_utf8(plaintext.to_vec()).ok().map(Zeroizing::new)
}

pub fn open_recovery_lane(
    lane: &Value,
    conversation_id: &str,
    sender_identity_public: &str,
    candidates: &[LaneCandidate],
) -> Option<Zeroizing<String>> {
    let rid = json_str(lane, "rid").unwrap_or("");
    let ordered = candidates
        .iter()
        .filter(|c| c.identity_public == rid)
        .chain(candidates.iter().filter(|c| c.identity_public != rid));
    for candidate in ordered {
        if let Some(opened) = open_recovery_lane_with(lane, conversation_id, sender_identity_public, candidate) {
            return Some(opened);
        }
    }
    None
}

fn header_u32(header: &Value, key: &str) -> Option<u32> {
    match header.get(key) {
        None | Some(Value::Null) => Some(0),
        Some(v) => v.as_u64().and_then(|n| u32::try_from(n).ok()),
    }
}

pub fn decrypt_with_message_key(recipient: &Value, message_key: &[u8]) -> Option<String> {
    let header = recipient.get("header")?;
    let version = match header.get("v") {
        None | Some(Value::Null) => 1,
        Some(v) => v.as_u64()?,
    };
    let ciphertext = b64_decode(json_str(recipient, "ciphertext")?).ok()?;
    let nonce = b64_decode(json_str(recipient, "nonce")?).ok()?;
    let aad = if version >= 2 {
        let dh_public = b64_decode(json_str(header, "dh_public")?).ok()?;
        let previous_chain_length = header_u32(header, "previous_chain_length")?;
        let message_number = header_u32(header, "message_number")?;
        serialize_header_ad(u8::try_from(version).ok()?, &dh_public, previous_chain_length, message_number)
    } else {
        Vec::new()
    };
    let plaintext = aes_gcm_open(message_key, &nonce, &ciphertext, &aad)?;
    String::from_utf8(plaintext.to_vec()).ok()
}

pub fn decrypt_via_recovery_lane(
    recipient: &Value,
    conversation_id: &str,
    sender_identity_public: &str,
    candidates: &[LaneCandidate],
) -> Option<String> {
    let lane = recipient.get("recovery")?;
    let message_key_b64 = open_recovery_lane(lane, conversation_id, sender_identity_public, candidates)?;
    let message_key = Zeroizing::new(b64_decode(message_key_b64.as_str()).ok()?);
    decrypt_with_message_key(recipient, &message_key)
}

pub fn escrow_dedupe_key(message_id: &str, recipient: &Value) -> Option<String> {
    let header = recipient.get("header")?;
    let dh_public = json_str(header, "dh_public")?;
    let message_number = match header.get("message_number") {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => return None,
    };
    Some(format!("{}:{}:{}", message_id, dh_public, message_number))
}

pub fn escrow_aad_v2(dedupe_key: &str) -> Vec<u8> {
    let mut aad = ESCROW_AAD_V2_PREFIX.to_vec();
    aad.extend_from_slice(dedupe_key.as_bytes());
    aad
}

pub fn decrypt_escrow_entry(
    escrow_keys: &[Zeroizing<[u8; 32]>],
    dedupe_key: &str,
    encrypted_plaintext_b64: &str,
    nonce_b64: &str,
) -> Option<String> {
    let ciphertext = b64_decode(encrypted_plaintext_b64).ok()?;
    let nonce = b64_decode(nonce_b64).ok()?;
    if ciphertext.len() > MAX_ESCROW_PLAINTEXT_BYTES + GCM_TAG_LEN {
        return None;
    }
    let bound_aad = escrow_aad_v2(dedupe_key);
    for key in escrow_keys {
        for aad in [bound_aad.as_slice(), &[][..]] {
            if let Some(plaintext) = aes_gcm_open(key.as_slice(), &nonce, &ciphertext, aad) {
                return String::from_utf8(plaintext.to_vec()).ok();
            }
        }
    }
    None
}

pub fn normalize_address_ignoring_dots(address: &str) -> String {
    let lowered = address.trim().to_lowercase();
    match lowered.rfind('@') {
        None => lowered.replace('.', ""),
        Some(at) => format!("{}{}", lowered[..at].replace('.', ""), &lowered[at..]),
    }
}

fn same_address_ignoring_dots(left: &str, right: &str) -> bool {
    !left.is_empty()
        && !right.is_empty()
        && normalize_address_ignoring_dots(left) == normalize_address_ignoring_dots(right)
}

fn resolve_recipient<'a>(
    address: &str,
    recipients: &'a serde_json::Map<String, Value>,
) -> Option<(String, &'a Value)> {
    let lower = address.to_lowercase();
    if let Some(v) = recipients.get(&lower) {
        return Some((lower, v));
    }
    if let Some((k, v)) = recipients.iter().find(|(k, _)| k.to_lowercase() == lower) {
        return Some((k.clone(), v));
    }
    recipients
        .iter()
        .find(|(k, _)| same_address_ignoring_dots(k, address))
        .map(|(k, v)| (k.clone(), v))
}

pub struct RecipientAttempt<'a> {
    pub address: String,
    pub data: &'a Value,
}

pub fn recipient_attempts<'a>(ratchet: &'a Value, our_email: &str, sender_email: &str) -> Vec<RecipientAttempt<'a>> {
    let Some(recipients) = ratchet.get("recipients").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    if let Some((address, data)) = resolve_recipient(our_email, recipients) {
        return vec![RecipientAttempt { address, data }];
    }
    let mut attempts: Vec<RecipientAttempt<'a>> = Vec::new();
    let our_lower = our_email.to_lowercase();
    let sender_lower = sender_email.to_lowercase();
    if !sender_lower.is_empty() && sender_lower != our_lower {
        if let Some((address, data)) = resolve_recipient(sender_email, recipients) {
            attempts.push(RecipientAttempt { address, data });
        }
    }
    let aliases = recipients
        .iter()
        .filter(|(k, _)| {
            let lower = k.to_lowercase();
            lower != our_lower && lower != sender_lower
        })
        .take(MAX_ALIAS_RECIPIENT_ATTEMPTS);
    for (key, data) in aliases {
        if attempts.iter().any(|a| a.address == *key) {
            continue;
        }
        attempts.push(RecipientAttempt {
            address: key.clone(),
            data,
        });
    }
    attempts
}

fn is_bundle_framing(c: char) -> bool {
    c.is_whitespace()
        || ('\u{0}'..='\u{1f}').contains(&c)
        || c == '\u{7f}'
        || c == '\u{feff}'
        || ('\u{200b}'..='\u{200f}').contains(&c)
}

fn push_utf16(units: &mut Vec<u16>, c: char) {
    let mut buf = [0u16; 2];
    units.extend_from_slice(c.encode_utf16(&mut buf));
}

fn read_lenient_json_string(chars: &[char], open: usize) -> Option<(String, usize)> {
    if chars.get(open) != Some(&'"') {
        return None;
    }
    let mut units: Vec<u16> = Vec::new();
    let mut i = open + 1;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            return Some((String::from_utf16_lossy(&units), i + 1));
        }
        if c != '\\' {
            push_utf16(&mut units, c);
            i += 1;
            continue;
        }
        let Some(&escape) = chars.get(i + 1) else {
            break;
        };
        if escape == 'u' {
            let code: String = chars.iter().skip(i + 2).take(4).collect();
            if code.chars().count() == 4 && code.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(unit) = u16::from_str_radix(&code, 16) {
                    units.push(unit);
                    i += 6;
                    continue;
                }
            }
            push_utf16(&mut units, escape);
            i += 2;
            continue;
        }
        let mapped = match escape {
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            other => other,
        };
        push_utf16(&mut units, mapped);
        i += 2;
    }
    Some((String::from_utf16_lossy(&units), chars.len()))
}

fn find_char(chars: &[char], from: usize, target: char) -> Option<usize> {
    chars
        .iter()
        .skip(from)
        .position(|&c| c == target)
        .map(|p| p + from)
}

fn scan_bundle_payload(payload: &str) -> Option<(Option<String>, String)> {
    let chars: Vec<char> = payload.chars().collect();
    let open_brace = find_char(&chars, 0, '{')?;
    let mut subject: Option<String> = None;
    let mut body: Option<String> = None;
    let mut index = open_brace + 1;
    while index < chars.len() {
        let Some(key_quote) = find_char(&chars, index, '"') else {
            break;
        };
        let Some((key, after_key)) = read_lenient_json_string(&chars, key_quote) else {
            break;
        };
        let Some(colon) = find_char(&chars, after_key, ':') else {
            break;
        };
        let mut value_start = colon + 1;
        while value_start < chars.len() && chars[value_start].is_whitespace() {
            value_start += 1;
        }
        if value_start >= chars.len() {
            break;
        }
        if chars[value_start] != '"' {
            let Some(comma) = find_char(&chars, value_start, ',') else {
                break;
            };
            index = comma + 1;
            continue;
        }
        let Some((value, after_value)) = read_lenient_json_string(&chars, value_start) else {
            break;
        };
        if key == "s" {
            subject = Some(value.clone());
        }
        if key == "b" {
            body = Some(value);
        }
        if subject.is_some() && body.is_some() {
            break;
        }
        index = after_value;
    }
    Some((subject, body?))
}

fn bundle_attachment_manifest(payload: &str) -> Option<Vec<Value>> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(payload) else {
        return None;
    };
    match map.get(crate::crypto::attachment::ATTACHMENT_MANIFEST_FIELD) {
        Some(Value::Array(entries)) if !entries.is_empty() => Some(entries.clone()),
        _ => None,
    }
}

fn bundle_payload(text: &str) -> Option<&str> {
    let marker_index = text.find(SUBJECT_BUNDLE_MARKER)?;
    let prefix = &text[..marker_index];
    let framing = prefix.strip_suffix(SUBJECT_BUNDLE_DELIMITER).unwrap_or(prefix);
    if !framing.chars().all(is_bundle_framing) {
        return None;
    }
    let payload = &text[marker_index + SUBJECT_BUNDLE_MARKER.len()..];
    Some(payload.strip_prefix(SUBJECT_BUNDLE_DELIMITER).unwrap_or(payload))
}

pub fn wrap_subject_bundle(subject: &str, body: &str, attachment_manifest: &[Value]) -> String {
    format!(
        "{delimiter}{marker}{delimiter}{{\"s\":{subject},\"b\":{body},\"{field}\":{manifest}}}",
        delimiter = SUBJECT_BUNDLE_DELIMITER,
        marker = SUBJECT_BUNDLE_MARKER,
        subject = Value::String(subject.to_string()),
        body = Value::String(body.to_string()),
        field = crate::crypto::attachment::ATTACHMENT_MANIFEST_FIELD,
        manifest = Value::Array(attachment_manifest.to_vec()),
    )
}

fn unwrap_subject_bundle_layer(text: &str) -> Option<(Option<String>, String)> {
    let marker_index = text.find(SUBJECT_BUNDLE_MARKER)?;
    let prefix = &text[..marker_index];
    let framing = prefix.strip_suffix(SUBJECT_BUNDLE_DELIMITER).unwrap_or(prefix);
    if !framing.chars().all(is_bundle_framing) {
        return None;
    }
    let mut payload = &text[marker_index + SUBJECT_BUNDLE_MARKER.len()..];
    if let Some(rest) = payload.strip_prefix(SUBJECT_BUNDLE_DELIMITER) {
        payload = rest;
    }
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(payload) {
        if let (Some(Value::String(s)), Some(Value::String(b))) = (map.get("s"), map.get("b")) {
            return Some((Some(s.clone()), b.clone()));
        }
    }
    scan_bundle_payload(payload)
}

pub struct SubjectBundle {
    pub subject: Option<String>,
    pub body: String,
    pub sender_unverified: bool,
    pub attachment_manifest: Option<Vec<Value>>,
}

pub fn extract_subject_bundle(decrypted: &str) -> SubjectBundle {
    let attachment_manifest = bundle_payload(decrypted).and_then(bundle_attachment_manifest);
    let mut subject: Option<String> = None;
    let mut body = decrypted.to_string();
    let mut unwrapped = false;
    for _ in 0..MAX_SUBJECT_BUNDLE_DEPTH {
        let Some((layer_subject, layer_body)) = unwrap_subject_bundle_layer(&body) else {
            break;
        };
        if subject.as_deref().is_none_or(str::is_empty) {
            subject = layer_subject;
        }
        body = layer_body;
        unwrapped = true;
    }
    if !unwrapped {
        return SubjectBundle {
            subject: None,
            body,
            sender_unverified: false,
            attachment_manifest: None,
        };
    }
    SubjectBundle {
        subject: Some(subject.unwrap_or_default()),
        body,
        sender_unverified: false,
        attachment_manifest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;
    use serde_json::json;

    const LANE_VECTORS: &str = include_str!("testdata/recovery_lane_vectors.json");
    const STORAGE_VECTORS: &str = include_str!("testdata/storage_key_vectors.json");

    fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    fn vault_from(value: Value) -> VaultContents {
        let mut base = json!({ "identity_key": "unused" });
        if let (Value::Object(target), Value::Object(extra)) = (&mut base, value) {
            target.extend(extra);
        }
        serde_json::from_value(base).expect("vault parses")
    }

    fn vector_candidate(entry: &Value) -> LaneCandidate {
        let pq_secret = entry["recipient_pq_identity_secret"].as_str().filter(|s| !s.is_empty());
        let pq_seed = entry["recipient_pq_identity_seed"].as_str().filter(|s| !s.is_empty());
        LaneCandidate {
            identity_secret_d: jwk_d_bytes(entry["recipient_identity_jwk"].as_str().unwrap()).unwrap(),
            identity_public: entry["recipient_identity_public"].as_str().unwrap().to_string(),
            pq_decap_key: decode_pq_decap_key(pq_secret, pq_seed),
            pq_identity_public: entry["recipient_pq_identity_public"].as_str().unwrap_or("").to_string(),
        }
    }

    fn seal_gcm(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
            .unwrap()
    }

    struct TestIdentity {
        secret: p256::SecretKey,
        public_b64: String,
    }

    fn identity() -> TestIdentity {
        let secret = p256::SecretKey::random(&mut OsRng);
        let public_b64 = b64(secret.public_key().to_encoded_point(false).as_bytes());
        TestIdentity { secret, public_b64 }
    }

    fn classical_candidate(id: &TestIdentity) -> LaneCandidate {
        LaneCandidate {
            identity_secret_d: id.secret.to_bytes().to_vec(),
            identity_public: id.public_b64.clone(),
            pq_decap_key: None,
            pq_identity_public: String::new(),
        }
    }

    fn seal_classical_lane(recipient: &TestIdentity, conversation: &str, sender: &str, plaintext: &str) -> Value {
        let ephemeral = p256::SecretKey::random(&mut OsRng);
        let epk = ephemeral.public_key().to_encoded_point(false).as_bytes().to_vec();
        let recipient_public = STANDARD.decode(&recipient.public_b64).unwrap();
        let dh = ecdh_p256(&ephemeral.to_bytes(), &recipient_public).unwrap();
        let binding = lane_binding(conversation, sender, &recipient.public_b64, "");
        let key = lane_key(&[dh.as_slice()], &binding).unwrap();
        let nonce = [7u8; 12];
        json!({
            "v": 1,
            "epk": b64(&epk),
            "ciphertext": b64(&seal_gcm(key.as_slice(), &nonce, plaintext.as_bytes(), &binding)),
            "nonce": b64(&nonce),
            "rid": recipient.public_b64,
        })
    }

    fn sealed_recipient(message_key: &[u8; 32], version: Option<u64>, plaintext: &str) -> Value {
        let dh_public = vec![4u8; 65];
        let nonce = [3u8; 12];
        let aad = match version {
            Some(v) if v >= 2 => serialize_header_ad(v as u8, &dh_public, 2, 5),
            _ => Vec::new(),
        };
        let mut header = json!({ "dh_public": b64(&dh_public), "previous_chain_length": 2, "message_number": 5 });
        if let Some(v) = version {
            header["v"] = json!(v);
        }
        json!({
            "header": header,
            "ciphertext": b64(&seal_gcm(message_key, &nonce, plaintext.as_bytes(), &aad)),
            "nonce": b64(&nonce),
        })
    }

    fn lane_cases() -> Vec<Value> {
        let vectors: Value = serde_json::from_str(LANE_VECTORS).unwrap();
        vectors["cases"].as_array().cloned().unwrap_or_default()
    }

    #[test]
    fn opens_shared_web_lane_vectors() {
        let cases = lane_cases();
        assert!(cases.len() >= 2);
        for entry in &cases {
            let candidate = vector_candidate(entry);
            let opened = open_recovery_lane_with(
                &entry["lane"],
                entry["conversation_id"].as_str().unwrap(),
                entry["sender_identity_public"].as_str().unwrap(),
                &candidate,
            );
            assert_eq!(
                opened.as_ref().map(|s| s.as_str()),
                entry["plaintext"].as_str(),
                "{}",
                entry["name"]
            );
        }
    }

    #[test]
    fn shared_vectors_reject_tampering() {
        for entry in &lane_cases() {
            let candidate = vector_candidate(entry);
            let conversation = entry["conversation_id"].as_str().unwrap();
            let sender = entry["sender_identity_public"].as_str().unwrap();
            let lane = &entry["lane"];
            assert!(open_recovery_lane_with(lane, "conversation-vector-tampered", sender, &candidate).is_none());
            assert!(open_recovery_lane_with(lane, conversation, "someone-else", &candidate).is_none());
            let mut wrong_version = lane.clone();
            wrong_version["v"] = json!(2);
            assert!(open_recovery_lane_with(&wrong_version, conversation, sender, &candidate).is_none());
            let mut wrong_public = candidate.clone();
            wrong_public.identity_public = "spoofed".to_string();
            assert!(open_recovery_lane_with(lane, conversation, sender, &wrong_public).is_none());
            let mut flipped = lane.clone();
            let mut ct = STANDARD.decode(lane["ciphertext"].as_str().unwrap()).unwrap();
            ct[0] ^= 1;
            flipped["ciphertext"] = json!(b64(&ct));
            assert!(open_recovery_lane_with(&flipped, conversation, sender, &candidate).is_none());
        }
    }

    #[test]
    fn hybrid_vector_cannot_be_downgraded_to_classical() {
        let cases = lane_cases();
        let entry = cases
            .iter()
            .find(|c| c["lane"].get("kem_ct").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty()))
            .expect("hybrid vector present");
        let conversation = entry["conversation_id"].as_str().unwrap();
        let sender = entry["sender_identity_public"].as_str().unwrap();
        let candidate = vector_candidate(entry);
        assert!(candidate.pq_decap_key.is_some());
        let mut stripped = entry["lane"].clone();
        stripped.as_object_mut().unwrap().remove("kem_ct");
        assert!(open_recovery_lane_with(&stripped, conversation, sender, &candidate).is_none());
        let mut no_pq = candidate.clone();
        no_pq.pq_decap_key = None;
        assert!(open_recovery_lane_with(&entry["lane"], conversation, sender, &no_pq).is_none());
        let mut other_pq_public = candidate.clone();
        other_pq_public.pq_identity_public = "different".to_string();
        assert!(open_recovery_lane_with(&entry["lane"], conversation, sender, &other_pq_public).is_none());
    }

    #[test]
    fn lane_tries_every_candidate_and_prefers_rid() {
        let current = identity();
        let previous = identity();
        let lane = seal_classical_lane(&previous, "conv", "sender-pub", "bWVzc2FnZS1rZXk=");
        let candidates = vec![classical_candidate(&current), classical_candidate(&previous)];
        let opened = open_recovery_lane(&lane, "conv", "sender-pub", &candidates).unwrap();
        assert_eq!(opened.as_str(), "bWVzc2FnZS1rZXk=");
        let mut no_rid = lane.clone();
        no_rid.as_object_mut().unwrap().remove("rid");
        assert!(open_recovery_lane(&no_rid, "conv", "sender-pub", &candidates).is_some());
        assert!(open_recovery_lane(&lane, "conv", "sender-pub", &candidates[..1]).is_none());
        assert!(open_recovery_lane(&lane, "conv", "sender-pub", &[]).is_none());
        let mut bad_epk = lane.clone();
        bad_epk["epk"] = json!("not base64 at all");
        assert!(open_recovery_lane(&bad_epk, "conv", "sender-pub", &candidates).is_none());
        let mut short_nonce = lane.clone();
        short_nonce["nonce"] = json!(b64(&[1u8; 8]));
        assert!(open_recovery_lane(&short_nonce, "conv", "sender-pub", &candidates).is_none());
    }

    #[test]
    fn message_key_decrypt_binds_header_for_v2() {
        let key = [9u8; 32];
        let v2 = sealed_recipient(&key, Some(2), "hello v2");
        assert_eq!(decrypt_with_message_key(&v2, &key).as_deref(), Some("hello v2"));
        let v1 = sealed_recipient(&key, None, "hello v1");
        assert_eq!(decrypt_with_message_key(&v1, &key).as_deref(), Some("hello v1"));

        let mut stripped = v2.clone();
        stripped["header"].as_object_mut().unwrap().remove("v");
        assert!(decrypt_with_message_key(&stripped, &key).is_none());
        let mut renumbered = v2.clone();
        renumbered["header"]["message_number"] = json!(6);
        assert!(decrypt_with_message_key(&renumbered, &key).is_none());
        let mut oversized = v2.clone();
        oversized["header"]["v"] = json!(258);
        assert!(decrypt_with_message_key(&oversized, &key).is_none());
        let mut negative = v2.clone();
        negative["header"]["message_number"] = json!(-1);
        assert!(decrypt_with_message_key(&negative, &key).is_none());
        let mut upgraded = v1.clone();
        upgraded["header"]["v"] = json!(2);
        assert!(decrypt_with_message_key(&upgraded, &key).is_none());
        assert!(decrypt_with_message_key(&v2, &[8u8; 32]).is_none());
    }

    #[test]
    fn recovery_lane_end_to_end_opens_message() {
        let recipient = identity();
        let message_key = [5u8; 32];
        let conversation = conversation_id("hello@astermail.org", "alice@astermail.org");
        let mut data = sealed_recipient(&message_key, Some(2), "lane body");
        data["recovery"] = seal_classical_lane(&recipient, &conversation, "alice-identity", &b64(&message_key));
        let candidates = vec![classical_candidate(&recipient)];
        assert_eq!(
            decrypt_via_recovery_lane(&data, &conversation, "alice-identity", &candidates).as_deref(),
            Some("lane body")
        );
        let other = conversation_id("hello@astermail.org", "mallory@astermail.org");
        assert!(decrypt_via_recovery_lane(&data, &other, "alice-identity", &candidates).is_none());
        assert!(decrypt_via_recovery_lane(&data, &conversation, "mallory-identity", &candidates).is_none());
        data.as_object_mut().unwrap().remove("recovery");
        assert!(decrypt_via_recovery_lane(&data, &conversation, "alice-identity", &candidates).is_none());
    }

    #[test]
    fn storage_keys_match_webcrypto_vectors() {
        let v: Value = serde_json::from_str(STORAGE_VECTORS).unwrap();
        let pass = v["passphrase"].as_str().unwrap().as_bytes();
        let iterations = v["v2_iterations"].as_u64().unwrap() as u32;
        let v1 = derive_storage_key_v1(pass).unwrap();
        let v2 = derive_storage_key_v2(pass, iterations).unwrap();
        assert_eq!(b64(v1.as_slice()), v["storage_v1"].as_str().unwrap());
        assert_eq!(b64(v2.as_slice()), v["storage_v2"].as_str().unwrap());
        let sync = derive_sub_keys(std::slice::from_ref(&v1), SYNC_KEY_SALT, SYNC_KEY_INFO);
        assert_eq!(b64(sync[0].as_slice()), v["sync_from_v1"].as_str().unwrap());
        let escrow = derive_sub_keys(std::slice::from_ref(&v2), ESCROW_KEY_SALT, ESCROW_KEY_INFO);
        assert_eq!(b64(escrow[0].as_slice()), v["escrow_from_v2"].as_str().unwrap());
        let expected_conversation = v["conversation_id_hello_alice"].as_str().unwrap();
        assert_eq!(conversation_id("Hello@AsterMail.org", "alice@astermail.org"), expected_conversation);
        assert_eq!(conversation_id("alice@astermail.org", "hello@astermail.org"), expected_conversation);
    }

    #[test]
    fn escrow_opens_web_entries_with_and_without_aad() {
        let v: Value = serde_json::from_str(STORAGE_VECTORS).unwrap();
        let pass = v["passphrase"].as_str().unwrap().as_bytes();
        let iterations = v["v2_iterations"].as_u64().unwrap() as u32;
        let vault = vault_from(json!({ "kdf_version": 2 }));
        let material = RecoveryMaterial::from_vault_with_iterations(&vault, pass, iterations);
        let keys = material.escrow_keys();
        let dedupe = v["escrow_dedupe_key"].as_str().unwrap();
        let nonce = v["escrow_nonce"].as_str().unwrap();
        let unbound = v["escrow_no_aad"].as_str().unwrap();
        let bound = v["escrow_v2_aad"].as_str().unwrap();
        assert_eq!(
            decrypt_escrow_entry(&keys, dedupe, unbound, nonce).as_deref(),
            Some("escrowed body without aad")
        );
        assert_eq!(
            decrypt_escrow_entry(&keys, dedupe, bound, nonce).as_deref(),
            Some("escrowed body with aad")
        );
        assert!(decrypt_escrow_entry(&keys, "mail-999:BAbc==:4", bound, nonce).is_none());
        let wrong_pass = RecoveryMaterial::from_vault_with_iterations(&vault, b"wrong", iterations).escrow_keys();
        assert!(decrypt_escrow_entry(&wrong_pass, dedupe, unbound, nonce).is_none());
        let oversized = b64(&vec![0u8; MAX_ESCROW_PLAINTEXT_BYTES + GCM_TAG_LEN + 1]);
        assert!(decrypt_escrow_entry(&keys, dedupe, &oversized, nonce).is_none());
        assert!(decrypt_escrow_entry(&keys, dedupe, "%%%", nonce).is_none());
        assert!(decrypt_escrow_entry(&[], dedupe, unbound, nonce).is_none());
    }

    #[test]
    fn storage_base_keys_cover_every_vault_source() {
        let pass = b"pass";
        let master = [1u8; 32];
        let legacy = [2u8; 32];
        let vault = vault_from(json!({
            "vault_format": 2,
            "kdf_version": 2,
            "data_kek": b64(&master),
            "legacy_keks": [{ "k": b64(&legacy) }, { "k": "not base64" }, { "k": b64(&[3u8; 16]) }, "junk"],
            "previous_keys": ["old-identity"],
            "legacy_identity_keys": ["older-identity", 7],
        }));
        let keys = derive_storage_base_keys(&vault, pass, 1000);
        let has = |k: &[u8]| keys.iter().any(|x| x.as_slice() == k);
        assert_eq!(keys[0].as_slice(), &master);
        assert!(has(derive_storage_key_v2(pass, 1000).unwrap().as_slice()));
        assert!(has(derive_storage_key_v1(pass).unwrap().as_slice()));
        assert!(has(&legacy));
        assert!(has(Sha256::digest(b"old-identityastermail-tags-v1").as_slice()));
        assert!(has(Sha256::digest(b"older-identityastermail-recovery-email-v1").as_slice()));
        assert_eq!(keys.len(), 1 + 2 + 1 + 2 * PREVIOUS_KEY_CONTEXTS.len());

        let v1_vault = vault_from(json!({ "data_kek": b64(&master) }));
        let v1_keys = derive_storage_base_keys(&v1_vault, pass, 1000);
        assert_eq!(v1_keys.len(), 1);
        assert_eq!(v1_keys[0].as_slice(), derive_storage_key_v1(pass).unwrap().as_slice());

        assert!(derive_storage_base_keys(&vault_from(json!({})), b"", 1000).is_empty());
    }

    #[test]
    fn storage_base_keys_are_capped_and_deduplicated() {
        let many: Vec<Value> = (0..200).map(|i| json!({ "k": b64(&[i as u8; 32]) })).collect();
        let dupes: Vec<String> = (0..100).map(|_| "same".to_string()).collect();
        let vault = vault_from(json!({ "legacy_keks": many, "previous_keys": dupes }));
        let keys = derive_storage_base_keys(&vault, b"pass", 1000);
        assert_eq!(keys.len(), 1 + MAX_LEGACY_KEKS + PREVIOUS_KEY_CONTEXTS.len());
        assert!(keys.len() <= MAX_STORAGE_KEYS);
    }

    #[test]
    fn lenient_vault_fields_never_fail_the_vault() {
        let vault = vault_from(json!({
            "vault_format": "abc",
            "kdf_version": -4,
            "legacy_keks": "nope",
            "legacy_identity_keys": { "a": 1 },
            "ratchet_pq_identity_public": 12,
        }));
        assert_eq!(vault.vault_format, None);
        assert_eq!(vault.kdf_version, None);
        assert!(vault.legacy_keks.is_none());
        assert!(vault.legacy_identity_keys.is_none());
        assert!(vault.ratchet_pq_identity_public.is_none());
    }

    #[test]
    fn lane_candidates_come_from_current_and_previous_keys() {
        let current = identity();
        let previous = identity();
        let jwk = |id: &TestIdentity| {
            let point = id.secret.public_key().to_encoded_point(false);
            let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": url.encode(point.x().unwrap()),
                "y": url.encode(point.y().unwrap()),
                "d": url.encode(id.secret.to_bytes()),
            })
            .to_string()
        };
        let vault = vault_from(json!({
            "ratchet_identity_key": jwk(&current),
            "ratchet_identity_public": current.public_b64,
            "ratchet_previous_keys": [
                { "ratchet_identity_key": jwk(&previous), "ratchet_identity_public": previous.public_b64 },
                { "ratchet_identity_public": "missing-secret" }
            ],
        }));
        let candidates = build_lane_candidates(&vault);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].identity_public, current.public_b64);
        assert_eq!(candidates[0].identity_secret_d, current.secret.to_bytes().to_vec());
        assert_eq!(candidates[1].identity_secret_d, previous.secret.to_bytes().to_vec());
        assert!(candidates.iter().all(|c| c.pq_decap_key.is_none() && c.pq_identity_public.is_empty()));
    }

    #[test]
    fn recipient_attempts_follow_web_order() {
        let ratchet = json!({ "recipients": {
            "Jo.Hn@astermail.org": { "id": "dotted" },
            "alias@astermail.org": { "id": "alias" },
            "sender@astermail.org": { "id": "self" },
        }});
        let direct = recipient_attempts(&ratchet, "john@astermail.org", "sender@astermail.org");
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].address, "Jo.Hn@astermail.org");

        let exact = recipient_attempts(&ratchet, "ALIAS@astermail.org", "sender@astermail.org");
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].data["id"], "alias");

        let fallback = recipient_attempts(&ratchet, "other@astermail.org", "Sender@astermail.org");
        let ids: Vec<&str> = fallback.iter().map(|a| a.data["id"].as_str().unwrap()).collect();
        assert_eq!(ids[0], "self");
        assert_eq!(ids.len(), 3);

        let mut many = serde_json::Map::new();
        for i in 0..20 {
            many.insert(format!("a{}@x.org", i), json!({}));
        }
        let many_ratchet = json!({ "recipients": many });
        let capped = recipient_attempts(&many_ratchet, "me@x.org", "you@x.org");
        assert_eq!(capped.len(), MAX_ALIAS_RECIPIENT_ATTEMPTS);
        assert!(recipient_attempts(&json!({}), "me@x.org", "you@x.org").is_empty());
        assert_eq!(normalize_address_ignoring_dots(" J.O.E@Ex.Ample.org "), "joe@ex.ample.org");
    }

    #[test]
    fn escrow_dedupe_key_matches_web_format() {
        let data = json!({ "header": { "dh_public": "BAbc==", "message_number": 4 } });
        assert_eq!(escrow_dedupe_key("mail-123", &data).as_deref(), Some("mail-123:BAbc==:4"));
        assert!(escrow_dedupe_key("mail-123", &json!({ "header": {} })).is_none());
        assert!(escrow_dedupe_key("mail-123", &json!({})).is_none());
        assert_eq!(escrow_aad_v2("k"), b"aster.escrow.v2\0k".to_vec());
    }

    #[test]
    fn a_wrapped_bundle_carries_the_attachment_manifest_after_subject_and_body() {
        let manifest = vec![serde_json::json!({"seq": 0, "key": "a2V5", "sha256": "ab", "size": 3})];
        let wrapped = wrap_subject_bundle("Q3 \"plan\"", "<p>s and b</p>", &manifest);
        assert!(wrapped.starts_with("\u{1}ASTER_BUNDLE_V2\u{1}{\"s\":"));
        let subject_at = wrapped.find("\"s\":").unwrap();
        let body_at = wrapped.find("\"b\":").unwrap();
        let manifest_at = wrapped.find("\"attachment_manifest\":").unwrap();
        assert!(subject_at < body_at && body_at < manifest_at);

        let opened = extract_subject_bundle(&wrapped);
        assert_eq!(opened.subject.as_deref(), Some("Q3 \"plan\""));
        assert_eq!(opened.body, "<p>s and b</p>");
        assert_eq!(opened.attachment_manifest, Some(manifest));

        let plain = extract_subject_bundle("\u{1}ASTER_BUNDLE_V2\u{1}{\"s\":\"x\",\"b\":\"y\"}");
        assert_eq!(plain.attachment_manifest, None);
        let inner = wrap_subject_bundle("in", "body", &[serde_json::json!({"seq": 9})]);
        let nested = format!(
            "\u{1}ASTER_BUNDLE_V2\u{1}{{\"s\":\"out\",\"b\":{}}}",
            Value::String(inner)
        );
        assert_eq!(extract_subject_bundle(&nested).attachment_manifest, None);
    }

    #[test]
    fn subject_bundle_extracts_subject_and_body() {
        let plain = extract_subject_bundle("just a body");
        assert_eq!(plain.subject, None);
        assert_eq!(plain.body, "just a body");

        let bundled = extract_subject_bundle("\u{1}ASTER_BUNDLE_V2\u{1}{\"s\":\"Refund\",\"b\":\"<p>Hi</p>\"}");
        assert_eq!(bundled.subject.as_deref(), Some("Refund"));
        assert_eq!(bundled.body, "<p>Hi</p>");

        let nested_inner = "ASTER_BUNDLE_V2{\"s\":\"\",\"b\":\"inner\"}";
        let nested = format!("ASTER_BUNDLE_V2{}", json!({ "s": "Outer", "b": nested_inner }));
        let opened = extract_subject_bundle(&nested);
        assert_eq!(opened.subject.as_deref(), Some("Outer"));
        assert_eq!(opened.body, "inner");

        let lenient = extract_subject_bundle(
            "ASTER_BUNDLE_V2{\"s\":\"Caf\\u00e9 \\\"q\\\"\",\"x\":1,\"b\":\"line\\nnext\" trailing",
        );
        assert_eq!(lenient.subject.as_deref(), Some("Café \"q\""));
        assert_eq!(lenient.body, "line\nnext");

        let quoted = "Please look: ASTER_BUNDLE_V2{\"s\":\"spoof\",\"b\":\"x\"}";
        let untouched = extract_subject_bundle(quoted);
        assert_eq!(untouched.subject, None);
        assert_eq!(untouched.body, quoted);

        let no_body = extract_subject_bundle("ASTER_BUNDLE_V2{\"s\":\"only\"}");
        assert_eq!(no_body.subject, None);

        let mut deep = "core".to_string();
        for i in 0..12 {
            deep = format!("ASTER_BUNDLE_V2{}", json!({ "s": format!("s{}", i), "b": deep }));
        }
        let capped = extract_subject_bundle(&deep);
        assert!(capped.body.starts_with("ASTER_BUNDLE_V2"));
        assert_eq!(capped.subject.as_deref(), Some("s11"));
    }
}
