//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the AGPLv3 as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// AGPLv3 for more details.
//
// You should have received a copy of the AGPLv3
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::bigint::{Encoding, NonZero, U384};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::inbound::decode_pq_decap_key;
use crate::crypto::ratchet::{hkdf_sha256, jwk_d_bytes, RatchetReceiverKeys};
use crate::crypto::ratchet_recovery::LaneCandidate;
use crate::crypto::vault::VaultContents;

pub const ADDRESS_IDENTITY_SALT: &[u8] = b"aster/ratchet/address-sender-identity/v1";
pub const ADDRESS_SIGNED_PREKEY_SALT: &[u8] = b"aster/ratchet/address-signed-prekey/v1";
const ADDRESS_PQ_IDENTITY_SALT: &[u8] = b"aster/ratchet/address-pq-identity/v1";
const ENTRY_LABEL: &str = "aster/ratchet/address-entry/v1";
const ENDORSEMENT_LABEL: &str = "aster/ratchet/address-endorsement/v1";
const P256_SCALAR_LEN: usize = 32;
const SCALAR_SEED_LEN: usize = 48;
const PQ_SEED_LEN: usize = 64;
const POINT_LEN: usize = 65;
const SIGNATURE_LEN: usize = 64;
const ENDORSEMENT_LEN: usize = POINT_LEN + SIGNATURE_LEN;
const P256_ORDER_MINUS_ONE_HEX: &str = "00000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";

pub const MAX_ENTRY_ENDORSEMENTS: usize = 32;

pub fn normalize_identity_address(address: &str) -> String {
    address.trim().to_lowercase()
}

pub fn canonical_address_form(address: &str) -> String {
    let normalized = normalize_identity_address(address);
    let Some(at) = normalized.rfind('@') else {
        return String::new();
    };
    if at == 0 || at == normalized.len() - 1 {
        return String::new();
    }
    let local: String = normalized[..at]
        .split('+')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| *c != '.')
        .collect();
    if local.is_empty() {
        return String::new();
    }
    format!("{}@{}", local, &normalized[at + 1..])
}

pub fn is_primary_address(primary: &str, address: &str) -> bool {
    let primary = canonical_address_form(primary);
    primary.is_empty() || primary == canonical_address_form(address)
}

pub fn address_entry_forms(address: &str) -> Vec<String> {
    let normalized = normalize_identity_address(address);
    let canonical = canonical_address_form(&normalized);
    if canonical.is_empty() {
        return Vec::new();
    }
    if normalized == canonical {
        vec![normalized]
    } else {
        vec![normalized, canonical]
    }
}

pub struct DerivedKey {
    pub jwk: Zeroizing<String>,
    pub public: Vec<u8>,
    pub public_b64: String,
    pub scalar: Zeroizing<Vec<u8>>,
}

fn map_hash_to_scalar(seed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if seed.len() != SCALAR_SEED_LEN {
        return None;
    }
    let modulus = Option::<NonZero<U384>>::from(NonZero::new(U384::from_be_hex(P256_ORDER_MINUS_ONE_HEX)))?;
    let value = U384::from_be_slice(seed);
    let reduced = value.rem(&modulus).wrapping_add(&U384::ONE);
    let bytes = Zeroizing::new(reduced.to_be_bytes());
    Some(Zeroizing::new(bytes[bytes.len() - P256_SCALAR_LEN..].to_vec()))
}

pub fn derive_address_key(account_jwk: &str, address: &str, salt: &[u8]) -> Option<DerivedKey> {
    let normalized = normalize_identity_address(address);
    if account_jwk.is_empty() || normalized.is_empty() {
        return None;
    }
    let account_scalar = Zeroizing::new(jwk_d_bytes(account_jwk).ok()?);
    if account_scalar.len() != P256_SCALAR_LEN {
        return None;
    }
    let seed = Zeroizing::new(hkdf_sha256(&account_scalar, salt, normalized.as_bytes(), SCALAR_SEED_LEN).ok()?);
    let scalar = map_hash_to_scalar(&seed)?;
    let secret = SecretKey::from_slice(&scalar).ok()?;
    let point = secret.public_key().to_encoded_point(false);
    let public = point.as_bytes().to_vec();
    if public.len() != POINT_LEN {
        return None;
    }
    let jwk = Zeroizing::new(format!(
        "{{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"{}\",\"x\":\"{}\",\"y\":\"{}\",\"ext\":true,\"key_ops\":[\"deriveBits\"]}}",
        URL_SAFE_NO_PAD.encode(scalar.as_slice()),
        URL_SAFE_NO_PAD.encode(&public[1..33]),
        URL_SAFE_NO_PAD.encode(&public[33..65]),
    ));
    let public_b64 = STANDARD.encode(&public);
    Some(DerivedKey {
        jwk,
        public,
        public_b64,
        scalar,
    })
}

pub fn derive_address_sender_identity(account_jwk: &str, address: &str) -> Option<DerivedKey> {
    derive_address_key(account_jwk, address, ADDRESS_IDENTITY_SALT)
}

pub struct DerivedPq {
    pub secret: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
    pub public_b64: String,
}

fn account_pq_secret(pq_key: Option<&str>, pq_seed: Option<&str>) -> Option<Zeroizing<Vec<u8>>> {
    if let Some(key) = pq_key.filter(|k| !k.is_empty()) {
        return STANDARD.decode(key.trim()).ok().map(Zeroizing::new);
    }
    let seed = pq_seed.filter(|s| !s.is_empty())?;
    decode_pq_decap_key(None, Some(seed)).map(Zeroizing::new)
}

fn derive_pq_identity(source: &AddressKeySource, form: &str) -> Option<DerivedPq> {
    let account_secret = account_pq_secret(source.pq_identity_key.as_deref(), source.pq_identity_seed.as_deref())?;
    let seed = Zeroizing::new(hkdf_sha256(&account_secret, ADDRESS_PQ_IDENTITY_SALT, form.as_bytes(), PQ_SEED_LEN).ok()?);
    let d = ml_kem::array::Array::try_from(&seed[..32]).ok()?;
    let z = ml_kem::array::Array::try_from(&seed[32..]).ok()?;
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    let secret = Zeroizing::new(dk.as_bytes().to_vec());
    let public = ek.as_bytes().to_vec();
    let public_b64 = STANDARD.encode(&public);
    Some(DerivedPq {
        secret,
        public,
        public_b64,
    })
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AddressKeySource {
    pub identity_jwk: String,
    pub identity_public: String,
    pub signed_prekey_jwk: String,
    pub signed_prekey_public: String,
    pub pq_identity_key: Option<String>,
    pub pq_identity_seed: Option<String>,
}

fn complete_source(
    identity_jwk: Option<&str>,
    identity_public: Option<&str>,
    signed_prekey_jwk: Option<&str>,
    signed_prekey_public: Option<&str>,
    pq_identity_key: Option<&str>,
    pq_identity_seed: Option<&str>,
) -> Option<AddressKeySource> {
    let present = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(str::to_string);
    Some(AddressKeySource {
        identity_jwk: present(identity_jwk)?,
        identity_public: present(identity_public)?,
        signed_prekey_jwk: present(signed_prekey_jwk)?,
        signed_prekey_public: present(signed_prekey_public)?,
        pq_identity_key: present(pq_identity_key),
        pq_identity_seed: present(pq_identity_seed),
    })
}

pub struct AddressKeySet {
    pub identity: DerivedKey,
    pub signed_prekey: DerivedKey,
    pub pq: Option<DerivedPq>,
}

impl AddressKeySet {
    pub fn receiver_keys(&self) -> RatchetReceiverKeys {
        RatchetReceiverKeys {
            identity_secret_d: self.identity.scalar.to_vec(),
            signed_prekey_secret_d: self.signed_prekey.scalar.to_vec(),
            signed_prekey_public: self.signed_prekey.public.clone(),
        }
    }

    pub fn lane_candidate(&self) -> LaneCandidate {
        LaneCandidate {
            identity_secret_d: self.identity.scalar.to_vec(),
            identity_public: self.identity.public_b64.clone(),
            pq_decap_key: self.pq.as_ref().map(|pq| pq.secret.to_vec()),
            pq_identity_public: self.pq.as_ref().map(|pq| pq.public_b64.clone()).unwrap_or_default(),
        }
    }
}

pub fn derive_address_key_set(source: &AddressKeySource, address_form: &str) -> Option<AddressKeySet> {
    let form = normalize_identity_address(address_form);
    if form.is_empty() {
        return None;
    }
    let identity = derive_address_key(&source.identity_jwk, &form, ADDRESS_IDENTITY_SALT)?;
    let signed_prekey = derive_address_key(&source.signed_prekey_jwk, &form, ADDRESS_SIGNED_PREKEY_SALT)?;
    let pq = derive_pq_identity(source, &form);
    Some(AddressKeySet {
        identity,
        signed_prekey,
        pq,
    })
}

#[derive(Clone, Default)]
pub struct AddressKeyring {
    current: Option<AddressKeySource>,
    previous: Vec<AddressKeySource>,
    account_identity_jwks: Vec<Zeroizing<String>>,
    previous_identity_jwks: Vec<Zeroizing<String>>,
}

impl AddressKeyring {
    pub fn from_vault(vault: &VaultContents) -> Self {
        let current = complete_source(
            vault.ratchet_identity_key.as_deref(),
            vault.ratchet_identity_public.as_deref(),
            vault.ratchet_signed_prekey.as_deref(),
            vault.ratchet_signed_prekey_public.as_deref(),
            vault.ratchet_pq_identity_key.as_deref(),
            vault.ratchet_pq_identity_seed.as_deref(),
        );
        let mut previous = Vec::new();
        let mut previous_identity_jwks = Vec::new();
        for set in vault.ratchet_previous_keys.iter().flatten() {
            if let Some(jwk) = set.ratchet_identity_key.as_deref().filter(|s| !s.is_empty()) {
                previous_identity_jwks.push(Zeroizing::new(jwk.to_string()));
            }
            if let Some(source) = complete_source(
                set.ratchet_identity_key.as_deref(),
                set.ratchet_identity_public.as_deref(),
                set.ratchet_signed_prekey.as_deref(),
                set.ratchet_signed_prekey_public.as_deref(),
                set.ratchet_pq_identity_key.as_deref(),
                set.ratchet_pq_identity_seed.as_deref(),
            ) {
                previous.push(source);
            }
        }
        let mut account_identity_jwks = Vec::new();
        if let Some(jwk) = vault.ratchet_identity_key.as_deref().filter(|s| !s.is_empty()) {
            account_identity_jwks.push(Zeroizing::new(jwk.to_string()));
        }
        account_identity_jwks.extend(previous_identity_jwks.iter().cloned());
        Self {
            current,
            previous,
            account_identity_jwks,
            previous_identity_jwks,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.current.is_none() && self.previous.is_empty()
    }

    pub fn current_identity_public(&self) -> Option<&str> {
        self.current.as_ref().map(|c| c.identity_public.as_str())
    }

    pub fn fingerprint(&self) -> String {
        let Some(current) = self.current.as_ref() else {
            return String::new();
        };
        let mut hasher = Sha256::new();
        for part in [
            current.identity_public.as_str(),
            current.signed_prekey_public.as_str(),
            current.pq_identity_seed.as_deref().unwrap_or(""),
            current.pq_identity_key.as_deref().unwrap_or(""),
        ] {
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hasher.update((self.previous_identity_jwks.len() as u32).to_be_bytes());
        hasher
            .finalize()
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    fn sources(&self) -> impl Iterator<Item = &AddressKeySource> {
        self.current.iter().chain(self.previous.iter())
    }

    pub fn key_sets(&self, address: &str) -> Vec<AddressKeySet> {
        let forms = address_entry_forms(address);
        let mut sets = Vec::new();
        for source in self.sources() {
            for form in &forms {
                if let Some(set) = derive_address_key_set(source, form) {
                    sets.push(set);
                }
            }
        }
        sets
    }

    pub fn receiver_key_sets(&self, address: &str) -> Vec<RatchetReceiverKeys> {
        self.key_sets(address).iter().map(AddressKeySet::receiver_keys).collect()
    }

    pub fn lane_candidates(&self, address: &str) -> Vec<LaneCandidate> {
        self.key_sets(address).iter().map(AddressKeySet::lane_candidate).collect()
    }

    pub fn pq_secrets(&self, address: &str) -> Vec<Zeroizing<Vec<u8>>> {
        self.key_sets(address)
            .into_iter()
            .filter_map(|set| set.pq.map(|pq| pq.secret))
            .collect()
    }

    pub fn sender_identity(&self, address: &str) -> Option<DerivedKey> {
        let current = self.current.as_ref()?;
        derive_address_sender_identity(&current.identity_jwk, address)
    }

    pub fn is_own_address_identity_key(&self, addresses: &[&str], identity_key: &str) -> bool {
        if identity_key.is_empty() {
            return false;
        }
        let mut candidates: Vec<String> = Vec::new();
        for address in addresses {
            let normalized = normalize_identity_address(address);
            if !normalized.is_empty() && !candidates.contains(&normalized) {
                candidates.push(normalized);
            }
        }
        for account_jwk in &self.account_identity_jwks {
            for address in &candidates {
                if derive_address_sender_identity(account_jwk, address)
                    .is_some_and(|derived| derived.public_b64 == identity_key)
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn sign_entry(&self, address_form: &str) -> Option<SignedAddressEntry> {
        let form = normalize_identity_address(address_form);
        let current = self.current.as_ref()?;
        if form.is_empty() {
            return None;
        }
        let derived = derive_address_key_set(current, &form)?;
        let keys = EntryKeys {
            kem_identity_key: derived.identity.public_b64.clone(),
            signed_prekey: derived.signed_prekey.public_b64.clone(),
            pq_kem_public_key: derived.pq.as_ref().map(|pq| pq.public_b64.clone()),
        };
        let mut signature = sign_digest(&entry_digest(ENTRY_LABEL, &form, &keys).ok()?, &derived.identity.scalar)?;
        let endorsement_digest = entry_digest(ENDORSEMENT_LABEL, &form, &keys).ok()?;
        let mut seen = vec![derived.identity.public_b64.clone()];
        let mut parts = 1usize;
        for previous in &self.previous_identity_jwks {
            if parts > MAX_ENTRY_ENDORSEMENTS {
                break;
            }
            let Some(earlier) = derive_address_sender_identity(previous, &form) else {
                continue;
            };
            if seen.contains(&earlier.public_b64) {
                continue;
            }
            seen.push(earlier.public_b64.clone());
            signature.extend_from_slice(&earlier.public);
            signature.extend_from_slice(&sign_digest(&endorsement_digest, &earlier.scalar)?);
            parts += 1;
        }
        Some(SignedAddressEntry {
            address: form,
            kem_identity_key: keys.kem_identity_key,
            signed_prekey: keys.signed_prekey,
            pq_kem_public_key: keys.pq_kem_public_key,
            signed_prekey_signature: STANDARD.encode(&signature),
        })
    }
}

impl Drop for AddressKeyring {
    fn drop(&mut self) {
        self.current.zeroize();
        for source in self.previous.iter_mut() {
            source.zeroize();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAddressEntry {
    pub address: String,
    pub kem_identity_key: String,
    pub signed_prekey: String,
    pub pq_kem_public_key: Option<String>,
    pub signed_prekey_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AddressEntryVerification {
    pub valid: bool,
    pub endorsers: Vec<String>,
}

pub struct EntryKeys {
    pub kem_identity_key: String,
    pub signed_prekey: String,
    pub pq_kem_public_key: Option<String>,
}

fn decode_b64(value: &str) -> Result<Vec<u8>, ()> {
    STANDARD.decode(value.trim()).map_err(|_| ())
}

fn entry_digest(label: &str, form: &str, keys: &EntryKeys) -> Result<[u8; 32], ()> {
    let pq = match keys.pq_kem_public_key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => decode_b64(k)?,
        None => Vec::new(),
    };
    let parts: [Vec<u8>; 5] = [
        label.as_bytes().to_vec(),
        form.as_bytes().to_vec(),
        decode_b64(&keys.kem_identity_key)?,
        decode_b64(&keys.signed_prekey)?,
        pq,
    ];
    let mut hasher = Sha256::new();
    for part in &parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    Ok(hasher.finalize().into())
}

fn sign_digest(digest: &[u8; 32], scalar: &[u8]) -> Option<Vec<u8>> {
    let key = SigningKey::from_slice(scalar).ok()?;
    let signature: Signature = key.sign_prehash(digest).ok()?;
    let signature = signature.normalize_s().unwrap_or(signature);
    Some(signature.to_bytes().to_vec())
}

fn verify_digest(digest: &[u8; 32], signature: &[u8], public_key: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_prehash(digest, &signature).is_ok()
}

fn verify_entry_for_form(form: &str, entry: &EntryKeys, signature_b64: &str) -> Result<Option<AddressEntryVerification>, ()> {
    let signature = decode_b64(signature_b64)?;
    let identity = decode_b64(&entry.kem_identity_key)?;
    if identity.len() != POINT_LEN
        || signature.len() < SIGNATURE_LEN
        || !(signature.len() - SIGNATURE_LEN).is_multiple_of(ENDORSEMENT_LEN)
    {
        return Ok(None);
    }
    if !verify_digest(&entry_digest(ENTRY_LABEL, form, entry)?, &signature[..SIGNATURE_LEN], &identity) {
        return Ok(None);
    }
    let endorsement_digest = entry_digest(ENDORSEMENT_LABEL, form, entry)?;
    let mut endorsers = Vec::new();
    let mut offset = SIGNATURE_LEN;
    while offset < signature.len() && endorsers.len() < MAX_ENTRY_ENDORSEMENTS {
        let endorser = &signature[offset..offset + POINT_LEN];
        let endorsement = &signature[offset + POINT_LEN..offset + ENDORSEMENT_LEN];
        if verify_digest(&endorsement_digest, endorsement, endorser) {
            endorsers.push(STANDARD.encode(endorser));
        }
        offset += ENDORSEMENT_LEN;
    }
    Ok(Some(AddressEntryVerification { valid: true, endorsers }))
}

pub fn verify_address_entry(
    address: &str,
    kem_identity_key: &str,
    signed_prekey: &str,
    pq_kem_public_key: Option<&str>,
    signed_prekey_signature: &str,
) -> AddressEntryVerification {
    let keys = EntryKeys {
        kem_identity_key: kem_identity_key.to_string(),
        signed_prekey: signed_prekey.to_string(),
        pq_kem_public_key: pq_kem_public_key.map(str::to_string),
    };
    for form in address_entry_forms(address) {
        match verify_entry_for_form(&form, &keys, signed_prekey_signature) {
            Ok(Some(verified)) => return verified,
            Ok(None) => {}
            Err(()) => return AddressEntryVerification::default(),
        }
    }
    AddressEntryVerification::default()
}

pub fn verify_signed_entry(address: &str, entry: &SignedAddressEntry) -> AddressEntryVerification {
    verify_address_entry(
        address,
        &entry.kem_identity_key,
        &entry.signed_prekey,
        entry.pq_kem_public_key.as_deref(),
        &entry.signed_prekey_signature,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{json, Value};

    const VECTORS: &str = include_str!("address_identity_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn fixed_bytes(fill: u32, len: usize) -> Vec<u8> {
        (0..len).map(|i| ((fill + (i as u32) * 7) & 0xff) as u8).collect()
    }

    fn fixed_key(fill: u32) -> (String, String) {
        let scalar = fixed_bytes(fill, 32);
        let secret = SecretKey::from_slice(&scalar).unwrap();
        let point = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
        let jwk = serde_json::to_string(&json!({
            "kty": "EC",
            "crv": "P-256",
            "d": URL_SAFE_NO_PAD.encode(&scalar),
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
            "ext": true,
            "key_ops": ["deriveBits"],
        }))
        .unwrap();
        (jwk, STANDARD.encode(&point))
    }

    fn fixed_vault_json() -> Value {
        let identity = fixed_key(11);
        let signed_prekey = fixed_key(23);
        let previous_identity = fixed_key(37);
        let previous_signed_prekey = fixed_key(41);
        json!({
            "ratchet_identity_key": identity.0,
            "ratchet_identity_public": identity.1,
            "ratchet_signed_prekey": signed_prekey.0,
            "ratchet_signed_prekey_public": signed_prekey.1,
            "ratchet_pq_identity_seed": STANDARD.encode(fixed_bytes(53, 64)),
            "ratchet_previous_keys": [{
                "ratchet_identity_key": previous_identity.0,
                "ratchet_identity_public": previous_identity.1,
                "ratchet_signed_prekey": previous_signed_prekey.0,
                "ratchet_signed_prekey_public": previous_signed_prekey.1,
            }],
        })
    }

    fn fixed_vault() -> VaultContents {
        let mut value = fixed_vault_json();
        value["identity_key"] = json!("");
        serde_json::from_value(value).unwrap()
    }

    pub(crate) fn fixed_keyring() -> AddressKeyring {
        AddressKeyring::from_vault(&fixed_vault())
    }

    #[test]
    fn vectors_match_the_fixed_vault() {
        fn expand_jwks(value: &Value) -> Value {
            match value {
                Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), expand_jwks(v))).collect()),
                Value::Array(items) => Value::Array(items.iter().map(expand_jwks).collect()),
                Value::String(text) if text.starts_with('{') => {
                    serde_json::from_str::<Value>(text).unwrap_or_else(|_| value.clone())
                }
                _ => value.clone(),
            }
        }
        assert_eq!(expand_jwks(&fixed_vault_json()), expand_jwks(&vectors()["vault"]));
    }

    #[test]
    fn vectors_address_forms() {
        let v = vectors();
        let forms: Vec<String> = serde_json::from_value(v["forms"].clone()).unwrap();
        assert_eq!(address_entry_forms(v["address"].as_str().unwrap()), forms);
        assert_eq!(canonical_address_form("J.o+x@Example.org"), "jo@example.org");
        assert!(is_primary_address("jo@example.org", "J.o+news@Example.org"));
        assert!(is_primary_address("j.o@example.org", "jo@example.org"));
        assert!(is_primary_address("", "alias@example.org"));
        assert!(is_primary_address("  ", "alias@example.org"));
        assert!(!is_primary_address("jo@example.org", "alias@example.org"));
        assert!(!is_primary_address("jo@example.org", "jo@example.net"));
        assert!(address_entry_forms("@example.org").is_empty());
        assert!(address_entry_forms("jo@").is_empty());
        assert!(address_entry_forms("+tag@example.org").is_empty());
        assert_eq!(address_entry_forms(" Plain@Example.org "), vec!["plain@example.org".to_string()]);
    }

    #[test]
    fn vectors_derived_key_sets() {
        let keyring = fixed_keyring();
        let current = keyring.current.as_ref().unwrap();
        let v = vectors();
        for vector in v["derived"].as_array().unwrap() {
            let set = derive_address_key_set(current, vector["form"].as_str().unwrap()).unwrap();
            assert_eq!(set.identity.jwk.as_str(), vector["identity_jwk"].as_str().unwrap());
            assert_eq!(set.identity.public_b64, vector["identity_public"].as_str().unwrap());
            assert_eq!(set.signed_prekey.jwk.as_str(), vector["signed_prekey_jwk"].as_str().unwrap());
            assert_eq!(set.signed_prekey.public_b64, vector["signed_prekey_public"].as_str().unwrap());
            let pq = set.pq.as_ref().unwrap();
            assert_eq!(&pq.public_b64[..64], vector["pq_public_sha_prefix"].as_str().unwrap());
            assert_eq!(pq.public_b64.len() as u64, vector["pq_public_length"].as_u64().unwrap());
        }
    }

    #[test]
    fn vectors_signed_entry_and_verification() {
        let v = vectors();
        let form = v["forms"][0].as_str().unwrap();
        let entry = fixed_keyring().sign_entry(form).unwrap();
        let expected: SignedAddressEntry = serde_json::from_value(v["entry"].clone()).unwrap();
        assert_eq!(entry, expected);
        assert_eq!(serde_json::to_value(&entry).unwrap(), v["entry"]);
        let verification = verify_signed_entry(v["address"].as_str().unwrap(), &expected);
        let expected_verification: AddressEntryVerification =
            serde_json::from_value(v["verification"].clone()).unwrap();
        assert_eq!(verification, expected_verification);
    }

    #[test]
    fn vectors_reject_an_entry_for_another_address() {
        let v = vectors();
        let expected: SignedAddressEntry = serde_json::from_value(v["entry"].clone()).unwrap();
        assert!(!verify_signed_entry("someone.else@example.org", &expected).valid);
        let mut tampered = expected.clone();
        tampered.signed_prekey = tampered.kem_identity_key.clone();
        assert!(!verify_signed_entry(v["address"].as_str().unwrap(), &tampered).valid);
    }

    #[test]
    fn derived_identity_is_recognized_as_own() {
        let keyring = fixed_keyring();
        let alias = "Jo.Doe+news@Example.org";
        let derived = keyring.sender_identity(alias).unwrap();
        assert!(keyring.is_own_address_identity_key(&[alias], &derived.public_b64));
        assert!(!keyring.is_own_address_identity_key(&["other@example.org"], &derived.public_b64));
        assert!(!keyring.is_own_address_identity_key(&[alias], keyring.current_identity_public().unwrap()));
    }

    #[test]
    fn receiver_sets_cover_current_and_previous_keys_for_each_form() {
        let keyring = fixed_keyring();
        assert_eq!(keyring.receiver_key_sets("Jo.Doe+news@Example.org").len(), 4);
        assert_eq!(keyring.lane_candidates("jodoe@example.org").len(), 2);
        assert_eq!(keyring.pq_secrets("jodoe@example.org").len(), 1);
        assert!(keyring.receiver_key_sets("not-an-address").is_empty());
    }

    #[test]
    fn derived_receiver_keys_open_a_bootstrap_sealed_to_the_derived_identity() {
        let keyring = fixed_keyring();
        let alias = "jo.doe+news@example.org";
        let set = derive_address_key_set(keyring.current.as_ref().unwrap(), alias).unwrap();
        let sender = SecretKey::from_slice(&fixed_bytes(97, 32)).unwrap();
        let message = crate::crypto::ratchet::encrypt_bootstrap(
            &sender.to_bytes(),
            &set.identity.public,
            &set.signed_prekey.public,
            None,
            None,
            "hello alias",
        )
        .unwrap();
        assert!(crate::crypto::ratchet::decrypt_with_key_sets(&AddressKeyring::default().receiver_key_sets(alias), &message).is_none());
        assert_eq!(
            crate::crypto::ratchet::decrypt_with_key_sets(&keyring.receiver_key_sets(alias), &message).as_deref(),
            Some("hello alias")
        );
    }
}
