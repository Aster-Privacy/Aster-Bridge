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
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::api_client::{ApiClient, PrekeyBundle};
use crate::crypto::address_identity::verify_address_entry;
use crate::crypto::internal_send::{is_internal_address, key_lookup_username};
use crate::crypto::ratchet::{
    is_p256_public, is_valid_one_time_prekey_id, PQ_IDENTITY_KEY_ID, X3DH_VERSION_KEY_BOUND,
    X3DH_VERSION_LEGACY, X3DH_VERSION_ONE_TIME_BOUND, X3DH_VERSION_TRANSCRIPT_BOUND,
};
use crate::db::Database;
use crate::error::BridgeError;

const CLEARTEXT_SIGNATURE_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const CANONICAL_PREFIX_V1: &str = "aster-ratchet-prekey-v1:";
const CANONICAL_PREFIX_V2: &str = "aster-ratchet-prekey-v2:";
const CANONICAL_PREFIX_V3: &str = "aster-ratchet-prekey-v3:";
const CANONICAL_NUMBER_MAX_DIGITS: usize = 18;
pub const RECIPIENT_TRUST_PROTOCOL: u32 = 2;
const PIN_ID_DOMAIN: &[u8] = b"aster-bridge-recipient-pin-v1";
const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBinding {
    pub x3dh_version: i16,
    pub epoch: i64,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleVerdict {
    Verified {
        covers_pq_identity: bool,
        signed: Option<SignedBinding>,
    },
    Tampered,
    Legacy,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecipientPin {
    pub identity_fingerprint: String,
    pub owner_fingerprint: String,
    pub pq_seen: bool,
    pub pq_fingerprint: String,
    pub transcript_bound: bool,
    pub binding_epoch: i64,
    pub binding_fingerprint: String,
    pub hosted: bool,
    pub flagged: bool,
    pub address_rooted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTarget {
    pub public_key: Vec<u8>,
    pub key_id: i32,
    pub signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimePrekeyTarget {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetTarget {
    pub identity_public: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub pq_target: Option<PqTarget>,
    pub transcript_bound: bool,
    pub key_bound: bool,
    pub one_time_prekey: Option<OneTimePrekeyTarget>,
}

impl RatchetTarget {
    pub fn x3dh_version(&self) -> u8 {
        if self.key_bound && self.one_time_prekey.is_some() {
            X3DH_VERSION_ONE_TIME_BOUND
        } else if self.key_bound {
            X3DH_VERSION_KEY_BOUND
        } else if self.transcript_bound {
            X3DH_VERSION_TRANSCRIPT_BOUND
        } else {
            X3DH_VERSION_LEGACY
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendRoute {
    Ratchet(RatchetTarget),
    AccountKey,
}

#[derive(Debug)]
pub struct Evaluation {
    pub pin: Option<RecipientPin>,
    pub outcome: Result<SendRoute, BridgeError>,
}

fn canonical_v1(bundle: &PrekeyBundle) -> String {
    format!(
        "{}{}.{}",
        CANONICAL_PREFIX_V1, bundle.kem_identity_key, bundle.signed_prekey
    )
}

fn canonical_v2(bundle: &PrekeyBundle) -> Option<String> {
    let pq = advertised_pq_identity_key(bundle)?;
    Some(format!(
        "{}{}.{}.{}",
        CANONICAL_PREFIX_V2, bundle.kem_identity_key, bundle.signed_prekey, pq
    ))
}

fn canonical_number(value: &str) -> Option<i64> {
    if value.is_empty()
        || value.len() > CANONICAL_NUMBER_MAX_DIGITS
        || value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    value.parse::<i64>().ok().filter(|number| *number >= 1)
}

fn signed_v3(bundle: &PrekeyBundle, signed_text: &str) -> Option<SignedBinding> {
    let rest = signed_text.strip_prefix(CANONICAL_PREFIX_V3)?;
    let parts: Vec<&str> = rest.split('.').collect();
    let [kem, spk, pq, version, epoch] = parts.as_slice() else {
        return None;
    };
    if *kem != bundle.kem_identity_key
        || *spk != bundle.signed_prekey
        || *pq != advertised_pq_identity_key(bundle).unwrap_or_default()
    {
        return None;
    }
    let x3dh_version = i16::try_from(canonical_number(version)?).ok()?;
    let epoch = canonical_number(epoch)?;
    Some(SignedBinding {
        x3dh_version,
        epoch,
        fingerprint: hex(&Sha256::digest(signed_text.as_bytes())),
    })
}

fn advertised_pq_identity_key(bundle: &PrekeyBundle) -> Option<&str> {
    bundle
        .pq_kem_public_key
        .as_deref()
        .filter(|key| !key.is_empty())
}

fn cleartext_signature(bundle: &PrekeyBundle) -> Option<String> {
    let encoded = bundle.signed_prekey_signature.as_deref()?.trim();
    let decoded = STANDARD.decode(encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    if text.trim_start().starts_with(CLEARTEXT_SIGNATURE_HEADER) {
        Some(text)
    } else {
        None
    }
}

pub fn verify_bundle(bundle: &PrekeyBundle, owner_public_key: Option<&str>) -> BundleVerdict {
    let Some(armored) = cleartext_signature(bundle) else {
        return BundleVerdict::Legacy;
    };
    let Some(owner_public_key) = owner_public_key else {
        return BundleVerdict::Unknown;
    };
    let signed_text = match aster_crypto::verify_cleartext_signature(owner_public_key, &armored) {
        Ok(Some(text)) => text,
        _ => return BundleVerdict::Tampered,
    };
    let signed_text = signed_text.trim();
    if let Some(signed) = signed_v3(bundle, signed_text) {
        return BundleVerdict::Verified {
            covers_pq_identity: advertised_pq_identity_key(bundle).is_some(),
            signed: Some(signed),
        };
    }
    if canonical_v2(bundle).as_deref() == Some(signed_text) {
        return BundleVerdict::Verified {
            covers_pq_identity: true,
            signed: None,
        };
    }
    if signed_text == canonical_v1(bundle) {
        return BundleVerdict::Verified {
            covers_pq_identity: false,
            signed: None,
        };
    }
    BundleVerdict::Tampered
}

fn spelling_pin_id(account_id: &str, spelling: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PIN_ID_DOMAIN);
    hasher.update([0u8]);
    hasher.update(account_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(spelling.as_bytes());
    hex(&hasher.finalize())
}

fn split_pin_address(lowered: &str) -> Option<(&str, &str)> {
    let at = lowered.rfind('@')?;
    Some((&lowered[..at], &lowered[at + 1..]))
}

fn base_local_part(local: &str) -> &str {
    local.split('+').next().unwrap_or(local)
}

pub fn canonical_pin_address(address: &str) -> String {
    let lowered = address.trim().to_lowercase();
    let Some((local, domain)) = split_pin_address(&lowered) else {
        return lowered;
    };
    let base = base_local_part(local);
    let folded = if is_internal_address(&lowered) {
        base.replace('.', "")
    } else {
        base.to_string()
    };
    if folded.is_empty() || domain.is_empty() {
        return lowered;
    }
    format!("{}@{}", folded, domain)
}

pub fn pin_id(account_id: &str, address: &str) -> String {
    spelling_pin_id(account_id, &canonical_pin_address(address))
}

fn dotted_spellings(canonical: &str, limit: usize) -> Vec<String> {
    let Some((local, domain)) = split_pin_address(canonical) else {
        return Vec::new();
    };
    let letters: Vec<char> = local.chars().collect();
    if letters.len() < 2 || limit == 0 {
        return Vec::new();
    }
    let gaps = letters.len() - 1;
    let mut spellings = Vec::new();
    struct DotLayout<'a> {
        letters: &'a [char],
        domain: &'a str,
        gaps: usize,
        limit: usize,
    }
    fn place(layout: &DotLayout, remaining: usize, start: usize, dots: &mut Vec<usize>, spellings: &mut Vec<String>) {
        let DotLayout { letters, domain, gaps, limit } = *layout;
        if spellings.len() >= limit {
            return;
        }
        if remaining == 0 {
            let mut spelled = String::new();
            for (index, letter) in letters.iter().enumerate() {
                spelled.push(*letter);
                if dots.contains(&index) {
                    spelled.push('.');
                }
            }
            spellings.push(format!("{}@{}", spelled, domain));
            return;
        }
        let mut gap = start;
        while gap + remaining <= gaps {
            dots.push(gap);
            place(layout, remaining - 1, gap + 1, dots, spellings);
            dots.pop();
            if spellings.len() >= limit {
                return;
            }
            gap += 1;
        }
    }
    let layout = DotLayout { letters: &letters, domain, gaps, limit };
    let mut count = 1;
    while count <= gaps && spellings.len() < limit {
        place(&layout, count, 0, &mut Vec::new(), &mut spellings);
        count += 1;
    }
    spellings
}

const DOTTED_SPELLING_LIMIT: usize = 2048;

pub fn legacy_pin_ids(account_id: &str, address: &str) -> Vec<String> {
    let lowered = address.trim().to_lowercase();
    let canonical = canonical_pin_address(&lowered);
    let mut spellings = vec![lowered.clone()];
    if let Some((local, domain)) = split_pin_address(&lowered) {
        let base = base_local_part(local);
        if !base.is_empty() && !domain.is_empty() {
            spellings.push(format!("{}@{}", base, domain));
            let tag = &local[base.len()..];
            let dotless = base.replace('.', "");
            if !tag.is_empty() && !dotless.is_empty() && is_internal_address(&lowered) {
                spellings.push(format!("{}{}@{}", dotless, tag, domain));
            }
        }
    }
    if is_internal_address(&lowered) {
        spellings.extend(dotted_spellings(&canonical, DOTTED_SPELLING_LIMIT));
    }
    let mut ids: Vec<String> = Vec::new();
    for spelling in spellings {
        if spelling == canonical {
            continue;
        }
        let id = spelling_pin_id(account_id, &spelling);
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRead {
    pub id: String,
    pub pin: Option<RecipientPin>,
    pub from_legacy: bool,
}

pub fn read_recipient_pin(db: &Database, account_id: &str, address: &str) -> Result<PinRead, String> {
    let id = pin_id(account_id, address);
    if let Some(pin) = db.recipient_pin_get(&id)? {
        return Ok(PinRead {
            id,
            pin: Some(pin),
            from_legacy: false,
        });
    }
    let legacy = db.recipient_pin_first(&legacy_pin_ids(account_id, address))?;
    Ok(PinRead {
        from_legacy: legacy.is_some(),
        id,
        pin: legacy,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAcceptance {
    Accepted { fingerprint: String },
    Mismatch { fingerprint: Option<String> },
}

pub fn key_fingerprint(owner_public_key: Option<&str>) -> Option<String> {
    owner_public_key.and_then(|key| aster_crypto::public_key_fingerprint_hex(key.as_bytes()))
}

pub fn format_fingerprint(fingerprint: &str) -> String {
    normalize_fingerprint(fingerprint)
        .to_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_lowercase()
}

pub async fn fetch_recipient_account_key(
    client: &ApiClient,
    access_token: &str,
    own_username: &str,
    address: &str,
) -> Result<Option<String>, BridgeError> {
    let username = key_lookup_username(address, own_username).ok_or_else(|| {
        BridgeError::RecipientKey(format!("{} has no username to look up", address))
    })?;
    client
        .get_recipient_public_key(access_token, &username, address)
        .await
}

pub fn accept_recipient_key(
    db: &Database,
    account_id: &str,
    address: &str,
    owner_public_key: Option<&str>,
    confirmed_fingerprint: &str,
) -> Result<KeyAcceptance, String> {
    let current = key_fingerprint(owner_public_key);
    let confirmed = normalize_fingerprint(confirmed_fingerprint);
    let Some(fingerprint) = current
        .clone()
        .filter(|current| !confirmed.is_empty() && normalize_fingerprint(current) == confirmed)
    else {
        return Ok(KeyAcceptance::Mismatch { fingerprint: current });
    };
    let read = read_recipient_pin(db, account_id, address)?;
    let id = read.id;
    let existing = read.pin.unwrap_or_default();
    db.recipient_pin_put(&id, &accepted_pin(existing, &fingerprint))?;
    Ok(KeyAcceptance::Accepted { fingerprint })
}

fn accepted_pin(existing: RecipientPin, fingerprint: &str) -> RecipientPin {
    let owner_changed = !existing.owner_fingerprint.is_empty()
        && !existing.owner_fingerprint.eq_ignore_ascii_case(fingerprint);
    let (binding_epoch, binding_fingerprint) = if owner_changed {
        (0, String::new())
    } else {
        (existing.binding_epoch, existing.binding_fingerprint.clone())
    };
    if existing.address_rooted {
        return RecipientPin {
            owner_fingerprint: fingerprint.to_string(),
            identity_fingerprint: String::new(),
            pq_fingerprint: String::new(),
            binding_epoch,
            binding_fingerprint,
            flagged: false,
            address_rooted: false,
            ..existing
        };
    }
    RecipientPin {
        owner_fingerprint: fingerprint.to_string(),
        binding_epoch,
        binding_fingerprint,
        flagged: false,
        ..existing
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn refuse(address: &str, reason: &str) -> BridgeError {
    BridgeError::RecipientKey(format!("{} for {}", reason, address))
}

fn accept_hint(address: &str, fingerprint: Option<&str>) -> String {
    match fingerprint {
        Some(fingerprint) => format!(
            "The key that {} publishes now has the fingerprint {}. If you expect this change, confirm this fingerprint with the recipient, then accept the key. In Aster Bridge, go to Settings > Advanced, click Accept key, enter the address, and click Show key, or run: aster-bridge recipient-key accept {} --fingerprint {}",
            address,
            format_fingerprint(fingerprint),
            address,
            normalize_fingerprint(fingerprint).to_uppercase()
        ),
        None => format!(
            "To see the fingerprint of the key that {} publishes now, run: aster-bridge recipient-key show {}",
            address, address
        ),
    }
}

fn untrusted(address: &str, fingerprint: Option<&str>) -> BridgeError {
    BridgeError::RecipientKey(format!(
        "The encryption keys for {} changed or failed verification, so the message was not sent. {}",
        address,
        accept_hint(address, fingerprint)
    ))
}

fn tampered(address: &str) -> BridgeError {
    BridgeError::RecipientKey(format!(
        "The encryption keys that {} publishes are not signed by the recipient's account key, so the message was not sent. Accepting the key does not fix this. Ask the recipient to sign in to Aster again so their keys are published again.",
        address
    ))
}

fn downgraded(address: &str) -> BridgeError {
    BridgeError::RecipientKey(format!(
        "The post-quantum key that {} published before is no longer available, so the message was not sent with weaker encryption. Accepting the key does not fix this. Ask the recipient to sign in to an up-to-date Aster app so their post-quantum keys are published again.",
        address
    ))
}

fn stale_binding(address: &str) -> BridgeError {
    BridgeError::RecipientKey(format!(
        "The encryption keys that {} publishes now are older than the keys Aster Bridge already trusts for this recipient, so the message was not sent. This can mean that old keys are being replayed. Accepting the key does not fix this. Ask the recipient to sign in to an up-to-date Aster app so their current keys are published again.",
        address
    ))
}

fn binding_is_stale(base: &RecipientPin, signed: Option<&SignedBinding>) -> bool {
    match signed {
        None => base.binding_epoch > 0,
        Some(signed) => {
            signed.epoch < base.binding_epoch
                || (signed.epoch == base.binding_epoch
                    && !base.binding_fingerprint.is_empty()
                    && signed.fingerprint != base.binding_fingerprint)
        }
    }
}

fn no_published_key(address: &str) -> BridgeError {
    BridgeError::RecipientKey(format!(
        "{} has no published encryption keys, so the message was not sent.",
        address
    ))
}

fn decode_key(address: &str, value: &str, what: &str) -> Result<Vec<u8>, BridgeError> {
    STANDARD
        .decode(value.trim())
        .map_err(|_| refuse(address, &format!("the {} is not valid base64", what)))
}

fn select_pq_target(
    bundle: &PrekeyBundle,
    covers_pq_identity: bool,
    address: &str,
) -> Result<Option<PqTarget>, BridgeError> {
    let identity = match advertised_pq_identity_key(bundle) {
        Some(key) => Some(decode_key(address, key, "post-quantum identity key")?),
        None => None,
    };
    let one_time = match &bundle.pq_prekey {
        Some(prekey) => Some((
            decode_key(address, &prekey.public_key, "post-quantum prekey")?,
            prekey.key_id as i32,
        )),
        None => None,
    };
    let advertises_pq = identity.is_some() || one_time.is_some();
    let identity = identity.filter(|key| key.len() == ML_KEM_768_PUBLIC_KEY_BYTES);
    let one_time = one_time.filter(|(key, _)| key.len() == ML_KEM_768_PUBLIC_KEY_BYTES);

    let malformed = || {
        refuse(
            address,
            "the published post-quantum key is malformed, and the message is not sent with weaker encryption",
        )
    };

    if covers_pq_identity {
        return match identity {
            Some(public_key) => Ok(Some(PqTarget {
                public_key,
                key_id: PQ_IDENTITY_KEY_ID,
                signed: true,
            })),
            None => Err(malformed()),
        };
    }
    if let Some((public_key, key_id)) = one_time {
        return Ok(Some(PqTarget {
            public_key,
            key_id,
            signed: false,
        }));
    }
    if let Some(public_key) = identity {
        return Ok(Some(PqTarget {
            public_key,
            key_id: PQ_IDENTITY_KEY_ID,
            signed: false,
        }));
    }
    if advertises_pq {
        return Err(malformed());
    }
    Ok(None)
}

fn select_one_time_prekey(bundle: &PrekeyBundle) -> Option<OneTimePrekeyTarget> {
    if bundle.x3dh_max_version.unwrap_or(1) < i16::from(X3DH_VERSION_ONE_TIME_BOUND) {
        return None;
    }
    let advertised = bundle.ec_one_time_prekey.as_ref()?;
    let key_id = advertised
        .get("key_id")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .filter(|key_id| is_valid_one_time_prekey_id(*key_id))?;
    let public_key = advertised
        .get("public_key")
        .and_then(|value| value.as_str())
        .and_then(|value| STANDARD.decode(value.trim()).ok())
        .filter(|public_key| is_p256_public(public_key))?;
    Some(OneTimePrekeyTarget { key_id, public_key })
}

fn ratchet_target(
    address: &str,
    bundle: &PrekeyBundle,
    covers_pq_identity: bool,
) -> Result<RatchetTarget, BridgeError> {
    Ok(RatchetTarget {
        identity_public: decode_key(address, &bundle.kem_identity_key, "identity key")?,
        signed_prekey: decode_key(address, &bundle.signed_prekey, "signed prekey")?,
        pq_target: select_pq_target(bundle, covers_pq_identity, address)?,
        transcript_bound: bundle.x3dh_max_version.unwrap_or(1)
            >= i16::from(X3DH_VERSION_TRANSCRIPT_BOUND),
        key_bound: bundle.x3dh_max_version.unwrap_or(1) >= i16::from(X3DH_VERSION_KEY_BOUND),
        one_time_prekey: select_one_time_prekey(bundle),
    })
}

fn changed_pin(existing: Option<&RecipientPin>, pin: RecipientPin) -> Option<RecipientPin> {
    if existing == Some(&pin) {
        None
    } else {
        Some(pin)
    }
}

pub fn evaluate_recipient(
    address: &str,
    bundle: Option<&PrekeyBundle>,
    owner_public_key: Option<&str>,
    existing: Option<&RecipientPin>,
) -> Evaluation {
    let base = existing.cloned().unwrap_or_default();
    let owner_fingerprint = owner_public_key
        .and_then(|key| aster_crypto::public_key_fingerprint_hex(key.as_bytes()));
    let owner_changed = owner_public_key.is_some()
        && !base.owner_fingerprint.is_empty()
        && !owner_fingerprint
            .as_deref()
            .is_some_and(|current| base.owner_fingerprint.eq_ignore_ascii_case(current));
    let verdict = bundle.map(|bundle| verify_bundle(bundle, owner_public_key));
    let leaves_address_keys = base.address_rooted && bundle.is_some();

    if verdict == Some(BundleVerdict::Tampered) || owner_changed || base.flagged || leaves_address_keys {
        return Evaluation {
            pin: changed_pin(
                existing,
                RecipientPin {
                    flagged: true,
                    ..base
                },
            ),
            outcome: Err(if verdict == Some(BundleVerdict::Tampered) {
                tampered(address)
            } else {
                untrusted(address, owner_fingerprint.as_deref())
            }),
        };
    }

    let (Some(_), Some(owner_fingerprint)) = (owner_public_key, owner_fingerprint) else {
        return Evaluation {
            pin: None,
            outcome: Err(no_published_key(address)),
        };
    };

    if let (
        Some(bundle),
        Some(BundleVerdict::Verified {
            covers_pq_identity,
            signed,
        }),
    ) = (bundle, verdict)
    {
        if binding_is_stale(&base, signed.as_ref()) {
            return Evaluation {
                pin: None,
                outcome: Err(stale_binding(address)),
            };
        }
        let advertises_pq = advertised_pq_identity_key(bundle).is_some();
        let pq_pinned = !base.pq_fingerprint.is_empty();
        if (pq_pinned && !covers_pq_identity) || (base.pq_seen && !advertises_pq) {
            return Evaluation {
                pin: None,
                outcome: Err(downgraded(address)),
            };
        }
        let mut target = match ratchet_target(address, bundle, covers_pq_identity) {
            Ok(target) => target,
            Err(error) => {
                return Evaluation {
                    pin: None,
                    outcome: Err(error),
                }
            }
        };
        if let Some(signed) = &signed {
            target.key_bound = signed.x3dh_version >= i16::from(X3DH_VERSION_KEY_BOUND);
        }
        target.transcript_bound = match &signed {
            Some(signed) => signed.x3dh_version >= i16::from(X3DH_VERSION_TRANSCRIPT_BOUND),
            None => target.transcript_bound || base.transcript_bound,
        };
        let (binding_epoch, binding_fingerprint) = match signed {
            Some(signed) => (signed.epoch, signed.fingerprint),
            None => (base.binding_epoch, base.binding_fingerprint.clone()),
        };
        let identity_fingerprint = hex(&Sha256::digest(&target.identity_public));
        let pq_fingerprint = target
            .pq_target
            .as_ref()
            .filter(|pq| pq.signed)
            .map(|pq| hex(&Sha256::digest(&pq.public_key)))
            .unwrap_or_default();
        let pin = RecipientPin {
            identity_fingerprint,
            owner_fingerprint,
            pq_seen: base.pq_seen || advertises_pq,
            pq_fingerprint,
            transcript_bound: target.transcript_bound,
            binding_epoch,
            binding_fingerprint,
            hosted: base.hosted,
            flagged: false,
            address_rooted: base.address_rooted,
        };
        return Evaluation {
            pin: changed_pin(existing, pin),
            outcome: Ok(SendRoute::Ratchet(target)),
        };
    }

    if base.binding_epoch > 0 {
        return Evaluation {
            pin: None,
            outcome: Err(stale_binding(address)),
        };
    }

    if base.pq_seen {
        return Evaluation {
            pin: None,
            outcome: Err(downgraded(address)),
        };
    }

    Evaluation {
        pin: changed_pin(
            existing,
            RecipientPin {
                owner_fingerprint,
                ..base
            },
        ),
        outcome: Ok(SendRoute::AccountKey),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryTrust {
    Account,
    Entry,
    Endorsed,
    Replaced,
    Invalid,
    Downgraded,
}

impl DirectoryTrust {
    pub fn is_rejected(self) -> bool {
        matches!(self, Self::Replaced | Self::Invalid | Self::Downgraded)
    }
}

fn key_fingerprint_hex(public_key_b64: &str) -> Option<String> {
    STANDARD
        .decode(public_key_b64.trim())
        .ok()
        .map(|bytes| hex(&Sha256::digest(bytes)))
}

pub fn is_address_scoped(bundle: &PrekeyBundle) -> bool {
    bundle.address_scoped == Some(true)
}

pub fn unscoped_trust(existing: Option<&RecipientPin>) -> DirectoryTrust {
    if existing.is_some_and(|pin| pin.address_rooted) {
        DirectoryTrust::Downgraded
    } else {
        DirectoryTrust::Account
    }
}

pub fn classify_scoped_entry(
    address: &str,
    bundle: &PrekeyBundle,
    existing: Option<&RecipientPin>,
) -> DirectoryTrust {
    let rooted = existing.is_some_and(|pin| pin.address_rooted);
    let verification = verify_address_entry(
        address,
        &bundle.kem_identity_key,
        &bundle.signed_prekey,
        advertised_pq_identity_key(bundle),
        bundle.signed_prekey_signature.as_deref().unwrap_or(""),
    );
    if !verification.valid {
        return if rooted {
            DirectoryTrust::Invalid
        } else {
            DirectoryTrust::Account
        };
    }
    let Some(pin) = existing.filter(|pin| !pin.identity_fingerprint.is_empty()) else {
        return if existing.is_some_and(|pin| !pin.owner_fingerprint.is_empty()) {
            DirectoryTrust::Account
        } else {
            DirectoryTrust::Entry
        };
    };
    let pinned = |key: &str| {
        key_fingerprint_hex(key).is_some_and(|fingerprint| pin.identity_fingerprint.eq_ignore_ascii_case(&fingerprint))
    };
    if pinned(&bundle.kem_identity_key) {
        return DirectoryTrust::Entry;
    }
    if verification.endorsers.iter().any(|endorser| pinned(endorser)) {
        return DirectoryTrust::Endorsed;
    }
    if rooted {
        DirectoryTrust::Replaced
    } else {
        DirectoryTrust::Account
    }
}

pub fn evaluate_address_entry(
    address: &str,
    bundle: &PrekeyBundle,
    trust: DirectoryTrust,
    existing: Option<&RecipientPin>,
    owner_public_key: Option<&str>,
) -> Evaluation {
    let base = existing.cloned().unwrap_or_default();
    let refused = !matches!(trust, DirectoryTrust::Entry | DirectoryTrust::Endorsed);
    if refused || base.flagged {
        return Evaluation {
            pin: changed_pin(
                existing,
                RecipientPin {
                    flagged: true,
                    ..base
                },
            ),
            outcome: Err(untrusted(address, key_fingerprint(owner_public_key).as_deref())),
        };
    }
    let pq_key = advertised_pq_identity_key(bundle);
    if base.pq_seen && pq_key.is_none() {
        return Evaluation {
            pin: None,
            outcome: Err(downgraded(address)),
        };
    }
    let decoded = (|| -> Result<RatchetTarget, BridgeError> {
        let pq_target = match pq_key {
            Some(key) => {
                let public_key = decode_key(address, key, "post-quantum identity key")?;
                if public_key.len() != ML_KEM_768_PUBLIC_KEY_BYTES {
                    return Err(refuse(
                        address,
                        "the published post-quantum key is malformed, and the message is not sent with weaker encryption",
                    ));
                }
                Some(PqTarget {
                    public_key,
                    key_id: PQ_IDENTITY_KEY_ID,
                    signed: true,
                })
            }
            None => None,
        };
        Ok(RatchetTarget {
            identity_public: decode_key(address, &bundle.kem_identity_key, "identity key")?,
            signed_prekey: decode_key(address, &bundle.signed_prekey, "signed prekey")?,
            pq_target,
            transcript_bound: bundle.x3dh_max_version.unwrap_or(1)
                >= i16::from(X3DH_VERSION_TRANSCRIPT_BOUND)
                || base.transcript_bound,
            key_bound: bundle.x3dh_max_version.unwrap_or(1) >= i16::from(X3DH_VERSION_KEY_BOUND),
            one_time_prekey: select_one_time_prekey(bundle),
        })
    })();
    let target = match decoded {
        Ok(target) => target,
        Err(error) => {
            return Evaluation {
                pin: None,
                outcome: Err(error),
            }
        }
    };
    let pin = RecipientPin {
        identity_fingerprint: hex(&Sha256::digest(&target.identity_public)),
        owner_fingerprint: base.owner_fingerprint.clone(),
        pq_seen: base.pq_seen || target.pq_target.is_some(),
        pq_fingerprint: target
            .pq_target
            .as_ref()
            .map(|pq| hex(&Sha256::digest(&pq.public_key)))
            .unwrap_or_default(),
        transcript_bound: target.transcript_bound,
        binding_epoch: base.binding_epoch,
        binding_fingerprint: base.binding_fingerprint.clone(),
        hosted: base.hosted,
        flagged: false,
        address_rooted: true,
    };
    Evaluation {
        pin: changed_pin(existing, pin),
        outcome: Ok(SendRoute::Ratchet(target)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn accepting_a_changed_key_lets_the_next_send_pin_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let first = owner("bob");
        let replaced = owner("bob");
        let id = pin_id("account", BOB);

        let pinned = evaluate_recipient(BOB, None, Some(&first.public_key), None);
        db.recipient_pin_put(&id, &pinned.pin.unwrap()).unwrap();

        let existing = db.recipient_pin_get(&id).unwrap();
        let refused = evaluate_recipient(BOB, None, Some(&replaced.public_key), existing.as_ref());
        assert!(refused.outcome.is_err());
        db.recipient_pin_put(&id, &refused.pin.unwrap()).unwrap();

        let existing = db.recipient_pin_get(&id).unwrap();
        assert!(
            evaluate_recipient(BOB, None, Some(&first.public_key), existing.as_ref())
                .outcome
                .is_err(),
            "a flagged recipient stays refused even when the old key comes back"
        );

        let shown = key_fingerprint(Some(&replaced.public_key)).unwrap();
        assert_eq!(
            accept_recipient_key(
                &db,
                "account",
                " Bob@AsterMail.org ",
                Some(&replaced.public_key),
                &format_fingerprint(&shown).to_lowercase(),
            )
            .unwrap(),
            KeyAcceptance::Accepted {
                fingerprint: shown.clone()
            }
        );

        let existing = db.recipient_pin_get(&id).unwrap();
        assert_eq!(existing.as_ref().unwrap().owner_fingerprint, shown);
        assert!(!existing.as_ref().unwrap().flagged);
        let accepted = evaluate_recipient(BOB, None, Some(&replaced.public_key), existing.as_ref());
        assert!(accepted.outcome.is_ok());
        assert!(accepted.pin.is_none());
    }

    #[test]
    fn accepting_pins_the_confirmed_key_so_a_later_swap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let confirmed = owner("bob");
        let swapped = owner("mallory");
        let id = pin_id("account", BOB);
        let shown = key_fingerprint(Some(&confirmed.public_key)).unwrap();

        accept_recipient_key(&db, "account", BOB, Some(&confirmed.public_key), &shown).unwrap();

        let existing = db.recipient_pin_get(&id).unwrap();
        let refused = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&swapped)),
            Some(&swapped.public_key),
            existing.as_ref(),
        );
        assert!(matches!(refused.outcome, Err(BridgeError::RecipientKey(_))));
        assert!(refused.pin.unwrap().flagged);
    }

    #[test]
    fn accepting_refuses_when_the_server_key_no_longer_matches_the_fingerprint_shown() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let first = owner("bob");
        let seen = owner("bob");
        let served = owner("mallory");
        let id = pin_id("account", BOB);
        let flagged = RecipientPin {
            owner_fingerprint: key_fingerprint(Some(&first.public_key)).unwrap(),
            flagged: true,
            ..RecipientPin::default()
        };
        db.recipient_pin_put(&id, &flagged).unwrap();
        let shown = key_fingerprint(Some(&seen.public_key)).unwrap();

        assert_eq!(
            accept_recipient_key(&db, "account", BOB, Some(&served.public_key), &shown).unwrap(),
            KeyAcceptance::Mismatch {
                fingerprint: key_fingerprint(Some(&served.public_key))
            }
        );
        assert_eq!(
            accept_recipient_key(&db, "account", BOB, None, &shown).unwrap(),
            KeyAcceptance::Mismatch { fingerprint: None }
        );
        assert_eq!(
            accept_recipient_key(&db, "account", BOB, Some(&seen.public_key), " ").unwrap(),
            KeyAcceptance::Mismatch {
                fingerprint: Some(shown)
            }
        );
        assert_eq!(db.recipient_pin_get(&id).unwrap(), Some(flagged));
    }

    #[test]
    fn the_refusal_names_the_fingerprint_of_the_key_published_now() {
        let alice = owner("alice");
        let mallory = owner("mallory");
        let first = evaluate_recipient(BOB, None, Some(&alice.public_key), None)
            .pin
            .unwrap();
        let fingerprint = key_fingerprint(Some(&mallory.public_key)).unwrap();

        let message = match evaluate_recipient(BOB, None, Some(&mallory.public_key), Some(&first))
            .outcome
        {
            Err(BridgeError::RecipientKey(message)) => message,
            other => panic!("expected a refusal, got {:?}", other),
        };
        assert!(message.contains(&format_fingerprint(&fingerprint)));
        assert!(message.contains(&format!(
            "aster-bridge recipient-key accept {} --fingerprint {}",
            BOB, fingerprint
        )));
    }

    #[test]
    fn fingerprints_are_grouped_for_display_and_compared_without_separators() {
        assert_eq!(format_fingerprint("c5dfc7e1d649"), "C5DF C7E1 D649");
        assert_eq!(normalize_fingerprint("C5:DF c7e1	D649"), "c5dfc7e1d649");
    }
    use crate::api_client::BundlePqPrekey;

    const INTEROP_PUBLIC_KEY: &str = r####"-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEanzDJBYJKwYBBAHaRw8BAQdArxoxl4uqH6QOcVAyuptjvbQIJ2XzcIPi
HSVFyC0ayL/NHVZlY3RvciA8dmVjdG9yQGFzdGVybWFpbC5vcmc+wsATBBMW
CgCFBYJqfMMkAwsJBwkQANAd09mPjFZFFAAAAAAAHAAgc2FsdEBub3RhdGlv
bnMub3BlbnBncGpzLm9yZ7OuU//7oJxy45KJyVjkLSN2IDOAOgPS5ZNf9hcr
fvo3BRUKCA4MBBYAAgECGQECmwMCHgEWIQTF38fh1knLrChOnDwA0B3T2Y+M
VgAAg6wBANNoZ8zqVo9u0SWkiC32zcY0Rn/3ROxybjCmob6AIak2AP9i5gWr
YV5wL95HX3qYUk1u/F472NQRGiJu3wbAZkQWA844BGp8wyQSCisGAQQBl1UB
BQEBB0D6YtgOSWgGymqKRYjmHcmmex+IjWKr4W+AqQCUrZuxEwMBCAfCvgQY
FgoAcAWCanzDJAkQANAd09mPjFZFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMu
b3BlbnBncGpzLm9yZ1wLOHqgm6Tt6hvAc0CX3M3WeNTXZp4lB2SNS9e0lKgq
ApsMFiEExd/H4dZJy6woTpw8ANAd09mPjFYAAOrCAQCIvEazLoEw8siIzIQP
mRAzxACeO34358Q7+LE45z5JVgD/XHvynRacIiyRcIYYCPyN0nGuXJBOMJmU
cpt8U1ja3gU=
=/x1e
-----END PGP PUBLIC KEY BLOCK-----
"####;

    const INTEROP_CLEARTEXT_SIGNATURE: &str = r####"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

aster-ratchet-prekey-v1:BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=.ERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERE=
-----BEGIN PGP SIGNATURE-----

wrsEARYKAG0Fgmp8wyQJEADQHdPZj4xWRRQAAAAAABwAIHNhbHRAbm90YXRp
b25zLm9wZW5wZ3Bqcy5vcmeA+5Zo3PblgnZrYeTfQEnQdSe/yVOplV11/emI
fqpsrhYhBMXfx+HWScusKE6cPADQHdPZj4xWAAC7vAD+Nx9BIXX+yhcmu8d7
/bKeFWp6+9lh7BFXt4b7AzMOyP8A/30z7mXQ6Xq7mFrDY+2K4qs7Gsa9cmSq
X1OEWHpsCOAO
=IpgX
-----END PGP SIGNATURE-----
"####;

    pub(crate) struct Owner {
        pub keypair: aster_crypto::KeyPair,
        pub public_key: String,
    }

    pub(crate) fn owner(name: &str) -> Owner {
        let keypair =
            aster_crypto::generate_keypair(name, &format!("{}@astermail.org", name)).unwrap();
        let public_key = keypair.public_key_armored().unwrap();
        Owner {
            keypair,
            public_key,
        }
    }

    pub(crate) fn unsigned_bundle(pq_identity: Option<Vec<u8>>) -> PrekeyBundle {
        PrekeyBundle {
            kem_identity_key: STANDARD.encode([0x04u8; 65]),
            signed_prekey: STANDARD.encode([0x11u8; 65]),
            signed_prekey_signature: None,
            pq_prekey: None,
            pq_kem_public_key: pq_identity.map(|key| STANDARD.encode(key)),
            x3dh_max_version: None,
            ec_one_time_prekey: None,
            address_scoped: None,
        }
    }

    pub(crate) fn sign(bundle: &mut PrekeyBundle, owner: &Owner, text: &str) {
        let armored = aster_crypto::sign_cleartext_message(text, &owner.keypair).unwrap();
        bundle.signed_prekey_signature = Some(STANDARD.encode(armored));
    }

    pub(crate) fn signed_v2_bundle(owner: &Owner) -> PrekeyBundle {
        let mut bundle = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        let text = canonical_v2(&bundle).unwrap();
        sign(&mut bundle, owner, &text);
        bundle
    }

    pub(crate) fn canonical_v3(bundle: &PrekeyBundle, version: &str, epoch: &str) -> String {
        format!(
            "{}{}.{}.{}.{}.{}",
            CANONICAL_PREFIX_V3,
            bundle.kem_identity_key,
            bundle.signed_prekey,
            advertised_pq_identity_key(bundle).unwrap_or_default(),
            version,
            epoch
        )
    }

    pub(crate) fn signed_v3_bundle(owner: &Owner, version: i16, epoch: i64) -> PrekeyBundle {
        let mut bundle = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        let text = canonical_v3(&bundle, &version.to_string(), &epoch.to_string());
        sign(&mut bundle, owner, &text);
        bundle
    }

    pub(crate) fn signed_v1_bundle(owner: &Owner, pq_identity: Option<Vec<u8>>) -> PrekeyBundle {
        let mut bundle = unsigned_bundle(pq_identity);
        let text = canonical_v1(&bundle);
        sign(&mut bundle, owner, &text);
        bundle
    }

    const BOB: &str = "bob@astermail.org";

    fn ratchet(evaluation: Evaluation) -> RatchetTarget {
        match evaluation.outcome {
            Ok(SendRoute::Ratchet(target)) => target,
            other => panic!("expected the ratchet route, got {:?}", other),
        }
    }

    fn one_time_prekey(fill: u8, len: usize) -> Option<BundlePqPrekey> {
        Some(BundlePqPrekey {
            key_id: 77,
            public_key: STANDARD.encode(vec![fill; len]),
        })
    }

    #[test]
    fn a_signature_made_by_the_web_client_verifies() {
        let mut bundle = unsigned_bundle(None);
        bundle.signed_prekey_signature = Some(STANDARD.encode(INTEROP_CLEARTEXT_SIGNATURE));

        assert_eq!(
            verify_bundle(&bundle, Some(INTEROP_PUBLIC_KEY)),
            BundleVerdict::Verified {
                covers_pq_identity: false,
                signed: None,
            }
        );
    }

    #[test]
    fn a_swapped_prekey_under_a_valid_signature_is_tampered() {
        let mut bundle = unsigned_bundle(None);
        bundle.signed_prekey_signature = Some(STANDARD.encode(INTEROP_CLEARTEXT_SIGNATURE));
        bundle.signed_prekey = STANDARD.encode([0x12u8; 65]);

        assert_eq!(
            verify_bundle(&bundle, Some(INTEROP_PUBLIC_KEY)),
            BundleVerdict::Tampered
        );
        let evaluation =
            evaluate_recipient(BOB, Some(&bundle), Some(INTEROP_PUBLIC_KEY), None);
        let Err(BridgeError::RecipientKey(message)) = &evaluation.outcome else {
            panic!("a tampered bundle must be refused");
        };
        assert!(message.contains("Accepting the key does not fix this"), "{message}");
        assert!(!message.contains("--fingerprint"), "{message}");
        assert!(evaluation.pin.unwrap().flagged);
    }

    #[test]
    fn a_signature_from_another_key_is_tampered() {
        let alice = owner("alice");
        let mallory = owner("mallory");
        let bundle = signed_v2_bundle(&mallory);

        assert_eq!(
            verify_bundle(&bundle, Some(&alice.public_key)),
            BundleVerdict::Tampered
        );
    }

    #[test]
    fn a_v2_signed_bundle_is_verified_and_seals_to_the_signed_post_quantum_key() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        bundle.pq_prekey = one_time_prekey(0x33, ML_KEM_768_PUBLIC_KEY_BYTES);

        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        let pin = evaluation.pin.clone().unwrap();
        let target = ratchet(evaluation).pq_target.unwrap();

        assert_eq!(target.key_id, PQ_IDENTITY_KEY_ID);
        assert_eq!(target.public_key, vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]);
        assert!(target.signed);
        assert!(pin.pq_seen);
        assert_eq!(
            pin.pq_fingerprint,
            hex(&Sha256::digest(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]))
        );
        assert!(!pin.flagged);
        assert!(!pin.identity_fingerprint.is_empty());
    }

    #[test]
    fn a_v1_signed_bundle_without_a_post_quantum_key_is_verified() {
        let alice = owner("alice");
        let bundle = signed_v1_bundle(&alice, None);

        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        let pin = evaluation.pin.clone().unwrap();

        assert!(ratchet(evaluation).pq_target.is_none());
        assert!(!pin.pq_seen);
        assert!(!pin.identity_fingerprint.is_empty());
    }

    #[test]
    fn a_v1_signed_bundle_with_a_post_quantum_key_is_sealed_not_refused() {
        let alice = owner("alice");
        let mut bundle = signed_v1_bundle(&alice, Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        bundle.pq_prekey = one_time_prekey(0x33, ML_KEM_768_PUBLIC_KEY_BYTES);

        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        let pin = evaluation.pin.clone().unwrap();
        let target = ratchet(evaluation).pq_target.unwrap();
        assert_eq!(target.key_id, 77);
        assert_eq!(target.public_key, vec![0x33; ML_KEM_768_PUBLIC_KEY_BYTES]);
        assert!(!target.signed);
        assert!(pin.pq_seen);
        assert!(pin.pq_fingerprint.is_empty());

        bundle.pq_prekey = None;
        let target = ratchet(evaluate_recipient(
            BOB,
            Some(&bundle),
            Some(&alice.public_key),
            None,
        ))
        .pq_target
        .unwrap();
        assert_eq!(target.key_id, PQ_IDENTITY_KEY_ID);
        assert!(!target.signed);
    }

    #[test]
    fn a_signed_post_quantum_key_with_the_wrong_size_never_falls_back_to_an_unsigned_one() {
        let alice = owner("alice");
        let mut bundle = unsigned_bundle(Some(vec![0x22; 100]));
        let text = canonical_v2(&bundle).unwrap();
        sign(&mut bundle, &alice, &text);
        bundle.pq_prekey = one_time_prekey(0x33, ML_KEM_768_PUBLIC_KEY_BYTES);

        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        assert!(matches!(evaluation.outcome, Err(BridgeError::RecipientKey(_))));
        assert!(evaluation.pin.is_none());
    }

    #[test]
    fn a_pinned_signed_post_quantum_key_is_not_replaced_by_an_unsigned_one() {
        let alice = owner("alice");
        let first = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&alice)),
            Some(&alice.public_key),
            None,
        )
        .pin
        .unwrap();
        assert!(!first.pq_fingerprint.is_empty());

        let mut unsigned_pq =
            signed_v1_bundle(&alice, Some(vec![0x44; ML_KEM_768_PUBLIC_KEY_BYTES]));
        unsigned_pq.pq_prekey = one_time_prekey(0x55, ML_KEM_768_PUBLIC_KEY_BYTES);
        let refused =
            evaluate_recipient(BOB, Some(&unsigned_pq), Some(&alice.public_key), Some(&first));
        assert!(matches!(refused.outcome, Err(BridgeError::RecipientKey(_))));
        assert!(refused.pin.is_none());

        let mut rotated = unsigned_bundle(Some(vec![0x66; ML_KEM_768_PUBLIC_KEY_BYTES]));
        let text = canonical_v2(&rotated).unwrap();
        sign(&mut rotated, &alice, &text);
        let evaluation =
            evaluate_recipient(BOB, Some(&rotated), Some(&alice.public_key), Some(&first));
        let pin = evaluation.pin.clone().unwrap();
        let target = ratchet(evaluation).pq_target.unwrap();
        assert!(target.signed);
        assert_eq!(target.public_key, vec![0x66; ML_KEM_768_PUBLIC_KEY_BYTES]);
        assert_eq!(
            pin.pq_fingerprint,
            hex(&Sha256::digest(vec![0x66; ML_KEM_768_PUBLIC_KEY_BYTES]))
        );
    }

    #[test]
    fn an_unsigned_handshake_version_never_lowers_the_pinned_one() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        bundle.x3dh_max_version = Some(2);
        let first = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        let pin = first.pin.clone().unwrap();
        assert!(pin.transcript_bound);
        assert!(ratchet(first).transcript_bound);

        for version in [None, Some(1)] {
            bundle.x3dh_max_version = version;
            let evaluation =
                evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), Some(&pin));
            assert!(evaluation.pin.is_none());
            assert!(ratchet(evaluation).transcript_bound);
        }
    }

    #[test]
    fn the_first_send_after_a_key_rotation_keeps_the_pinned_handshake_version() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        bundle.x3dh_max_version = Some(2);
        let pin = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None)
            .pin
            .unwrap();

        let mut rotated = unsigned_bundle(Some(vec![0x66; ML_KEM_768_PUBLIC_KEY_BYTES]));
        rotated.kem_identity_key = STANDARD.encode([0x05u8; 65]);
        rotated.x3dh_max_version = Some(1);
        let text = canonical_v2(&rotated).unwrap();
        sign(&mut rotated, &alice, &text);

        let evaluation =
            evaluate_recipient(BOB, Some(&rotated), Some(&alice.public_key), Some(&pin));
        let rotated_pin = evaluation.pin.clone().unwrap();
        assert_ne!(rotated_pin.identity_fingerprint, pin.identity_fingerprint);
        assert!(rotated_pin.transcript_bound);
        assert!(ratchet(evaluation).transcript_bound);
    }

    #[test]
    fn a_signed_handshake_version_wins_over_the_unsigned_one() {
        let alice = owner("alice");
        let mut bundle = signed_v3_bundle(&alice, 2, 4);
        bundle.x3dh_max_version = Some(1);
        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        let pin = evaluation.pin.clone().unwrap();
        assert!(ratchet(evaluation).transcript_bound);
        assert!(pin.transcript_bound);
        assert_eq!(pin.binding_epoch, 4);

        let mut older_device = signed_v3_bundle(&alice, 1, 5);
        older_device.x3dh_max_version = Some(2);
        let evaluation =
            evaluate_recipient(BOB, Some(&older_device), Some(&alice.public_key), Some(&pin));
        let lowered = evaluation.pin.clone().unwrap();
        assert!(!ratchet(evaluation).transcript_bound);
        assert!(!lowered.transcript_bound);
        assert_eq!(lowered.binding_epoch, 5);
    }

    #[test]
    fn a_v3_binding_reports_the_signed_version_and_epoch() {
        let alice = owner("alice");
        let bundle = signed_v3_bundle(&alice, 2, 12);
        let BundleVerdict::Verified {
            covers_pq_identity,
            signed: Some(signed),
        } = verify_bundle(&bundle, Some(&alice.public_key))
        else {
            panic!("a v3 binding must verify");
        };
        assert!(covers_pq_identity);
        assert_eq!(signed.x3dh_version, 2);
        assert_eq!(signed.epoch, 12);
        assert_eq!(signed.fingerprint.len(), 64);

        let mut classical = unsigned_bundle(None);
        let text = canonical_v3(&classical, "1", "3");
        sign(&mut classical, &alice, &text);
        assert!(matches!(
            verify_bundle(&classical, Some(&alice.public_key)),
            BundleVerdict::Verified {
                covers_pq_identity: false,
                signed: Some(_),
            }
        ));
    }

    #[test]
    fn a_v3_binding_over_other_keys_or_with_a_loose_number_is_tampered() {
        let alice = owner("alice");
        for (version, epoch) in [("02", "3"), ("2", "03"), ("2", "0"), ("0", "3"), ("2", "+3"), ("2", ""), ("2", "1234567890123456789")] {
            let mut bundle = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
            let text = canonical_v3(&bundle, version, epoch);
            sign(&mut bundle, &alice, &text);
            assert_eq!(
                verify_bundle(&bundle, Some(&alice.public_key)),
                BundleVerdict::Tampered,
                "{version}.{epoch}"
            );
        }

        let mut swapped = signed_v3_bundle(&alice, 2, 3);
        swapped.pq_kem_public_key = Some(STANDARD.encode(vec![0x23; ML_KEM_768_PUBLIC_KEY_BYTES]));
        assert_eq!(
            verify_bundle(&swapped, Some(&alice.public_key)),
            BundleVerdict::Tampered
        );

        let mut stripped = signed_v3_bundle(&alice, 2, 3);
        stripped.pq_kem_public_key = None;
        assert_eq!(
            verify_bundle(&stripped, Some(&alice.public_key)),
            BundleVerdict::Tampered
        );

        let mut extra = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        let text = format!("{}.9", canonical_v3(&extra, "2", "3"));
        sign(&mut extra, &alice, &text);
        assert_eq!(
            verify_bundle(&extra, Some(&alice.public_key)),
            BundleVerdict::Tampered
        );
    }

    #[test]
    fn a_replayed_or_stale_binding_is_refused_once_a_signed_epoch_is_pinned() {
        let alice = owner("alice");
        let current = signed_v3_bundle(&alice, 2, 5);
        let pin = evaluate_recipient(BOB, Some(&current), Some(&alice.public_key), None)
            .pin
            .unwrap();
        assert_eq!(pin.binding_epoch, 5);
        assert!(!pin.binding_fingerprint.is_empty());

        let same = evaluate_recipient(BOB, Some(&current), Some(&alice.public_key), Some(&pin));
        assert!(same.outcome.is_ok());
        assert!(same.pin.is_none());

        let mut other_binding_same_epoch = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        other_binding_same_epoch.signed_prekey = STANDARD.encode([0x12u8; 65]);
        let text = canonical_v3(&other_binding_same_epoch, "2", "5");
        sign(&mut other_binding_same_epoch, &alice, &text);

        let stale = [
            Some(signed_v3_bundle(&alice, 2, 4)),
            Some(other_binding_same_epoch),
            Some(signed_v2_bundle(&alice)),
            Some(signed_v1_bundle(&alice, Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]))),
            Some(unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]))),
            None,
        ];
        for bundle in &stale {
            let evaluation =
                evaluate_recipient(BOB, bundle.as_ref(), Some(&alice.public_key), Some(&pin));
            let Err(BridgeError::RecipientKey(message)) = &evaluation.outcome else {
                panic!("a stale binding must be refused");
            };
            assert!(message.contains("older than the keys"), "{message}");
            assert!(message.contains("Accepting the key does not fix this"), "{message}");
            assert!(evaluation.pin.is_none());
        }

        let newer = signed_v3_bundle(&alice, 2, 6);
        let evaluation = evaluate_recipient(BOB, Some(&newer), Some(&alice.public_key), Some(&pin));
        assert!(evaluation.outcome.is_ok());
        assert_eq!(evaluation.pin.unwrap().binding_epoch, 6);
    }

    #[test]
    fn bindings_without_an_epoch_keep_working_until_one_is_pinned() {
        let alice = owner("alice");
        let pin = evaluate_recipient(BOB, Some(&signed_v2_bundle(&alice)), Some(&alice.public_key), None)
            .pin
            .unwrap();
        assert_eq!(pin.binding_epoch, 0);
        let again = evaluate_recipient(BOB, Some(&signed_v2_bundle(&alice)), Some(&alice.public_key), Some(&pin));
        assert!(again.outcome.is_ok());

        let upgraded = evaluate_recipient(BOB, Some(&signed_v3_bundle(&alice, 2, 1)), Some(&alice.public_key), Some(&pin));
        assert!(upgraded.outcome.is_ok());
        assert_eq!(upgraded.pin.unwrap().binding_epoch, 1);
    }

    #[test]
    fn a_legacy_pin_without_a_post_quantum_fingerprint_is_upgraded_by_the_next_verified_bundle() {
        let alice = owner("alice");
        let legacy = RecipientPin {
            identity_fingerprint: "aa".to_string(),
            owner_fingerprint: key_fingerprint(Some(&alice.public_key)).unwrap(),
            pq_seen: true,
            ..RecipientPin::default()
        };

        let mut unsigned_pq = signed_v1_bundle(&alice, Some(vec![0x44; ML_KEM_768_PUBLIC_KEY_BYTES]));
        unsigned_pq.pq_prekey = one_time_prekey(0x55, ML_KEM_768_PUBLIC_KEY_BYTES);
        let unverified = evaluate_recipient(BOB, Some(&unsigned_pq), Some(&alice.public_key), Some(&legacy));
        let still_legacy = unverified.pin.clone().unwrap();
        assert!(!ratchet(unverified).pq_target.unwrap().signed);
        assert!(still_legacy.pq_fingerprint.is_empty());

        for bundle in [signed_v2_bundle(&alice), signed_v3_bundle(&alice, 2, 7)] {
            let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), Some(&legacy));
            let upgraded = evaluation.pin.clone().unwrap();
            assert!(ratchet(evaluation).pq_target.unwrap().signed);
            assert_eq!(
                upgraded.pq_fingerprint,
                hex(&Sha256::digest(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]))
            );
            let refused = evaluate_recipient(BOB, Some(&unsigned_pq), Some(&alice.public_key), Some(&upgraded));
            assert!(refused.outcome.is_err());
        }

        let replay_floor = RecipientPin {
            binding_epoch: 9,
            binding_fingerprint: "ff".to_string(),
            ..legacy
        };
        let replayed = evaluate_recipient(BOB, Some(&signed_v3_bundle(&alice, 2, 7)), Some(&alice.public_key), Some(&replay_floor));
        assert!(replayed.outcome.is_err());
        assert!(replayed.pin.is_none());
    }

    #[test]
    fn accepting_a_key_never_lowers_pinned_protection() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let alice = owner("alice");
        let id = pin_id("account", BOB);
        let mut bundle = signed_v3_bundle(&alice, 2, 8);
        bundle.x3dh_max_version = Some(2);
        let mut pin = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None)
            .pin
            .unwrap();
        pin.flagged = true;
        db.recipient_pin_put(&id, &pin).unwrap();

        let shown = key_fingerprint(Some(&alice.public_key)).unwrap();
        accept_recipient_key(&db, "account", BOB, Some(&alice.public_key), &shown).unwrap();
        let accepted = db.recipient_pin_get(&id).unwrap().unwrap();
        assert_eq!(
            accepted,
            RecipientPin {
                flagged: false,
                ..pin.clone()
            }
        );

        for weaker in [signed_v1_bundle(&alice, None), signed_v3_bundle(&alice, 2, 7)] {
            assert!(evaluate_recipient(BOB, Some(&weaker), Some(&alice.public_key), Some(&accepted))
                .outcome
                .is_err());
        }
        let mut unsigned_version = signed_v3_bundle(&alice, 2, 9);
        unsigned_version.x3dh_max_version = Some(1);
        assert!(ratchet(evaluate_recipient(BOB, Some(&unsigned_version), Some(&alice.public_key), Some(&accepted))).transcript_bound);
    }

    #[test]
    fn accepting_a_new_account_key_keeps_the_post_quantum_floor_and_resets_the_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let alice = owner("alice");
        let reset = owner("alice");
        let id = pin_id("account", BOB);
        let pin = evaluate_recipient(BOB, Some(&signed_v3_bundle(&alice, 2, 40)), Some(&alice.public_key), None)
            .pin
            .unwrap();
        db.recipient_pin_put(&id, &pin).unwrap();

        let refused = evaluate_recipient(BOB, Some(&signed_v3_bundle(&reset, 2, 1)), Some(&reset.public_key), Some(&pin));
        assert!(refused.outcome.is_err());
        db.recipient_pin_put(&id, &refused.pin.unwrap()).unwrap();

        let shown = key_fingerprint(Some(&reset.public_key)).unwrap();
        accept_recipient_key(&db, "account", BOB, Some(&reset.public_key), &shown).unwrap();
        let accepted = db.recipient_pin_get(&id).unwrap().unwrap();
        assert_eq!(accepted.owner_fingerprint, shown);
        assert!(!accepted.flagged);
        assert!(accepted.pq_seen);
        assert_eq!(accepted.pq_fingerprint, pin.pq_fingerprint);
        assert!(accepted.transcript_bound);
        assert_eq!(accepted.binding_epoch, 0);

        assert!(evaluate_recipient(BOB, Some(&signed_v3_bundle(&reset, 2, 1)), Some(&reset.public_key), Some(&accepted))
            .outcome
            .is_ok());
        let downgraded = evaluate_recipient(BOB, Some(&signed_v1_bundle(&reset, None)), Some(&reset.public_key), Some(&accepted));
        let Err(BridgeError::RecipientKey(message)) = downgraded.outcome else {
            panic!("a dropped post-quantum key must stay refused after Accept");
        };
        assert!(message.contains("Accepting the key does not fix this"), "{message}");
        assert!(!message.contains("--fingerprint"), "{message}");
    }

    #[test]
    fn an_unsigned_bundle_routes_to_the_account_key_without_pinning_its_identity() {
        let alice = owner("alice");
        let mut bundle = unsigned_bundle(None);
        assert_eq!(
            verify_bundle(&bundle, Some(&alice.public_key)),
            BundleVerdict::Legacy
        );

        bundle.signed_prekey_signature = Some(STANDARD.encode("c2hhMjU2LWhhc2g="));
        assert_eq!(
            verify_bundle(&bundle, Some(&alice.public_key)),
            BundleVerdict::Legacy
        );

        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        let pin = evaluation.pin.unwrap();
        assert_eq!(evaluation.outcome.unwrap(), SendRoute::AccountKey);
        assert!(pin.identity_fingerprint.is_empty());
        assert!(!pin.owner_fingerprint.is_empty());
        assert!(!pin.pq_seen);
    }

    #[test]
    fn an_unsigned_bundle_with_a_post_quantum_key_routes_to_the_account_key() {
        let alice = owner("alice");
        let bundle = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));

        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);

        assert!(!evaluation.pin.unwrap().pq_seen);
        assert_eq!(evaluation.outcome.unwrap(), SendRoute::AccountKey);
    }

    #[test]
    fn a_recipient_without_a_bundle_routes_to_the_account_key() {
        let alice = owner("alice");

        let evaluation = evaluate_recipient(BOB, None, Some(&alice.public_key), None);

        assert_eq!(evaluation.outcome.unwrap(), SendRoute::AccountKey);
    }

    #[test]
    fn a_recipient_without_a_published_account_key_is_refused() {
        let alice = owner("alice");
        let signed = signed_v2_bundle(&alice);
        assert_eq!(verify_bundle(&signed, None), BundleVerdict::Unknown);

        for bundle in [Some(&signed), Some(&unsigned_bundle(None)), None] {
            let evaluation = evaluate_recipient(BOB, bundle, None, None);
            assert!(matches!(evaluation.outcome, Err(BridgeError::RecipientKey(_))));
            assert!(evaluation.pin.is_none());
        }
    }

    #[test]
    fn a_malformed_post_quantum_key_never_falls_back_to_classical() {
        let alice = owner("alice");
        let mut bundle = signed_v1_bundle(&alice, None);
        bundle.pq_prekey = one_time_prekey(0x33, 100);

        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        assert!(matches!(evaluation.outcome, Err(BridgeError::RecipientKey(_))));

        bundle.pq_prekey = None;
        assert!(ratchet(evaluate_recipient(
            BOB,
            Some(&bundle),
            Some(&alice.public_key),
            None
        ))
        .pq_target
        .is_none());
    }

    #[test]
    fn a_changed_account_key_is_refused_until_the_pin_is_cleared() {
        let alice = owner("alice");
        let mallory = owner("mallory");
        let first = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&alice)),
            Some(&alice.public_key),
            None,
        )
        .pin
        .unwrap();

        let swapped = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&mallory)),
            Some(&mallory.public_key),
            Some(&first),
        );
        let message = match &swapped.outcome {
            Err(BridgeError::RecipientKey(message)) => message.clone(),
            other => panic!("expected a refusal, got {:?}", other),
        };
        assert!(message.contains("aster-bridge recipient-key accept bob@astermail.org"));
        let flagged = swapped.pin.unwrap();
        assert!(flagged.flagged);
        assert_eq!(flagged.owner_fingerprint, first.owner_fingerprint);

        let restored = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&alice)),
            Some(&alice.public_key),
            Some(&flagged),
        );
        assert!(matches!(restored.outcome, Err(BridgeError::RecipientKey(_))));
        assert!(restored.pin.is_none());

        let accepted = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&mallory)),
            Some(&mallory.public_key),
            None,
        );
        assert!(accepted.outcome.is_ok());

        let unchanged = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&alice)),
            Some(&alice.public_key),
            Some(&first),
        );
        assert!(unchanged.outcome.is_ok());
        assert!(unchanged.pin.is_none());
    }

    #[test]
    fn a_changed_account_key_is_refused_on_the_account_key_route() {
        let alice = owner("alice");
        let mallory = owner("mallory");
        let first = evaluate_recipient(BOB, None, Some(&alice.public_key), None)
            .pin
            .unwrap();

        let swapped = evaluate_recipient(BOB, None, Some(&mallory.public_key), Some(&first));

        assert!(matches!(swapped.outcome, Err(BridgeError::RecipientKey(_))));
        assert!(swapped.pin.unwrap().flagged);
    }

    #[test]
    fn an_identity_key_rotated_under_the_pinned_account_key_is_accepted() {
        let alice = owner("alice");
        let first = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&alice)),
            Some(&alice.public_key),
            None,
        )
        .pin
        .unwrap();

        let mut rotated = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        rotated.kem_identity_key = STANDARD.encode([0x05u8; 65]);
        let text = canonical_v2(&rotated).unwrap();
        sign(&mut rotated, &alice, &text);

        let evaluation =
            evaluate_recipient(BOB, Some(&rotated), Some(&alice.public_key), Some(&first));
        let pin = evaluation.pin.clone().unwrap();
        assert!(evaluation.outcome.is_ok());
        assert_ne!(pin.identity_fingerprint, first.identity_fingerprint);
        assert_eq!(pin.owner_fingerprint, first.owner_fingerprint);
    }

    #[test]
    fn a_dropped_post_quantum_key_is_refused() {
        let alice = owner("alice");
        let first = evaluate_recipient(
            BOB,
            Some(&signed_v2_bundle(&alice)),
            Some(&alice.public_key),
            None,
        )
        .pin
        .unwrap();
        assert!(first.pq_seen);

        let weaker = [
            Some(signed_v1_bundle(&alice, None)),
            Some(signed_v1_bundle(
                &alice,
                Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]),
            )),
            Some(unsigned_bundle(None)),
            Some(unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]))),
            None,
        ];
        for bundle in &weaker {
            let evaluation =
                evaluate_recipient(BOB, bundle.as_ref(), Some(&alice.public_key), Some(&first));
            assert!(matches!(evaluation.outcome, Err(BridgeError::RecipientKey(_))));
            assert!(evaluation.pin.is_none());
        }
    }

    #[test]
    fn a_bundle_advertising_the_bound_handshake_selects_it() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        assert!(
            !ratchet(evaluate_recipient(
                BOB,
                Some(&bundle),
                Some(&alice.public_key),
                None
            ))
            .transcript_bound
        );

        bundle.x3dh_max_version = Some(1);
        assert!(
            !ratchet(evaluate_recipient(
                BOB,
                Some(&bundle),
                Some(&alice.public_key),
                None
            ))
            .transcript_bound
        );

        bundle.x3dh_max_version = Some(2);
        assert!(
            ratchet(evaluate_recipient(
                BOB,
                Some(&bundle),
                Some(&alice.public_key),
                None
            ))
            .transcript_bound
        );
    }

    #[test]
    fn a_bundle_advertising_the_key_bound_handshake_selects_it() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        let version = |bundle: &PrekeyBundle, pin: Option<&RecipientPin>| {
            ratchet(evaluate_recipient(BOB, Some(bundle), Some(&alice.public_key), pin)).x3dh_version()
        };

        assert_eq!(version(&bundle, None), 1);

        bundle.x3dh_max_version = Some(3);
        assert_eq!(version(&bundle, None), 3);
        let evaluation = evaluate_recipient(BOB, Some(&bundle), Some(&alice.public_key), None);
        let pin = evaluation.pin.clone().unwrap();
        assert!(pin.transcript_bound);

        bundle.x3dh_max_version = Some(2);
        assert_eq!(version(&bundle, Some(&pin)), 2);

        bundle.x3dh_max_version = Some(1);
        assert_eq!(version(&bundle, Some(&pin)), 2);

        bundle.x3dh_max_version = None;
        assert_eq!(version(&bundle, Some(&pin)), 2);

        bundle.x3dh_max_version = Some(99);
        assert_eq!(version(&bundle, Some(&pin)), 3);
    }

    fn p256_public() -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        p256::SecretKey::random(&mut rand_core::OsRng)
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn advertised_one_time_prekey(key_id: u64, public_key: &[u8]) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "key_id": key_id,
            "public_key": STANDARD.encode(public_key),
        }))
    }

    fn chosen_target(bundle: &PrekeyBundle, owner: &Owner) -> RatchetTarget {
        ratchet(evaluate_recipient(BOB, Some(bundle), Some(&owner.public_key), None))
    }

    #[test]
    fn the_one_time_bound_handshake_needs_a_usable_one_time_prekey() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        let public = p256_public();

        bundle.x3dh_max_version = Some(4);
        assert_eq!(chosen_target(&bundle, &alice).x3dh_version(), 3);
        assert_eq!(chosen_target(&bundle, &alice).one_time_prekey, None);

        bundle.ec_one_time_prekey = advertised_one_time_prekey(41, &public);
        let chosen = chosen_target(&bundle, &alice);
        assert_eq!(chosen.x3dh_version(), 4);
        assert_eq!(
            chosen.one_time_prekey,
            Some(OneTimePrekeyTarget {
                key_id: 41,
                public_key: public.clone()
            })
        );

        bundle.x3dh_max_version = Some(99);
        assert_eq!(chosen_target(&bundle, &alice).x3dh_version(), 4);

        for advertised in [Some(3i16), Some(2), Some(1), None] {
            bundle.x3dh_max_version = advertised;
            let chosen = chosen_target(&bundle, &alice);
            assert_eq!(chosen.one_time_prekey, None);
            assert_eq!(i16::from(chosen.x3dh_version()), advertised.unwrap_or(1));
        }
    }

    #[test]
    fn a_malformed_one_time_prekey_keeps_the_key_bound_handshake() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        bundle.x3dh_max_version = Some(4);
        let public = p256_public();
        let mut compressed_tag = public.clone();
        compressed_tag[0] = 0x02;
        let mut off_curve = public.clone();
        off_curve[64] ^= 0x01;
        let malformed = vec![
            advertised_one_time_prekey(0, &public),
            advertised_one_time_prekey(2_147_483_648, &public),
            advertised_one_time_prekey(u64::MAX, &public),
            advertised_one_time_prekey(41, &public[..64]),
            advertised_one_time_prekey(41, &[]),
            advertised_one_time_prekey(41, &compressed_tag),
            advertised_one_time_prekey(41, &off_curve),
            advertised_one_time_prekey(41, &[0x04u8; 65]),
            Some(serde_json::json!({ "key_id": "41", "public_key": STANDARD.encode(&public) })),
            Some(serde_json::json!({ "key_id": 41, "public_key": 7 })),
            Some(serde_json::json!({ "key_id": 41, "public_key": "not base64" })),
            Some(serde_json::json!({ "public_key": STANDARD.encode(&public) })),
            Some(serde_json::json!({ "key_id": 41 })),
            Some(serde_json::json!("41")),
            Some(serde_json::Value::Null),
        ];

        for advertised in malformed {
            bundle.ec_one_time_prekey = advertised.clone();
            let chosen = chosen_target(&bundle, &alice);
            assert_eq!(chosen.one_time_prekey, None, "{:?}", advertised);
            assert_eq!(chosen.x3dh_version(), 3, "{:?}", advertised);
        }

        bundle.ec_one_time_prekey = advertised_one_time_prekey(2_147_483_647, &public);
        assert_eq!(chosen_target(&bundle, &alice).x3dh_version(), 4);
    }

    #[test]
    fn a_signed_statement_below_the_key_bound_handshake_blocks_the_one_time_bound_one() {
        let alice = owner("alice");
        let public = p256_public();
        for (signed_version, expected) in [(1i16, 1u8), (2, 2), (3, 4), (4, 4)] {
            let mut bundle = signed_v3_bundle(&alice, signed_version, 5);
            bundle.x3dh_max_version = Some(4);
            bundle.ec_one_time_prekey = advertised_one_time_prekey(41, &public);
            assert_eq!(
                chosen_target(&bundle, &alice).x3dh_version(),
                expected,
                "signed {}",
                signed_version
            );
        }
    }

    #[test]
    fn a_bundle_without_the_one_time_prekey_field_still_parses() {
        let bundle: PrekeyBundle = serde_json::from_value(serde_json::json!({
            "kem_identity_key": "a",
            "signed_prekey": "b",
            "x3dh_max_version": 3
        }))
        .unwrap();
        assert!(bundle.ec_one_time_prekey.is_none());

        let bundle: PrekeyBundle = serde_json::from_value(serde_json::json!({
            "kem_identity_key": "a",
            "signed_prekey": "b",
            "x3dh_max_version": 4,
            "ec_one_time_prekey": [1, 2, 3]
        }))
        .unwrap();
        assert!(select_one_time_prekey(&bundle).is_none());
    }

    #[test]
    fn pin_ids_are_scoped_to_the_account_and_ignore_case() {
        assert_eq!(pin_id("a", "Bob@Astermail.org"), pin_id("a", "bob@astermail.org"));
        assert_ne!(pin_id("a", "bob@astermail.org"), pin_id("b", "bob@astermail.org"));
        assert_eq!(pin_id("a", "bob@astermail.org").len(), 64);
    }

    #[test]
    fn dotted_and_tagged_spellings_share_one_pin() {
        let canonical = pin_id("a", "bob@astermail.org");
        for spelling in ["b.o.b@astermail.org", "Bob+news@astermail.org", "b.ob+x@Astermail.org", " bob@astermail.org "] {
            assert_eq!(pin_id("a", spelling), canonical, "{spelling}");
        }
        assert_eq!(canonical_pin_address("b.ob+x@aster.cx"), "bob@aster.cx");
        assert_eq!(canonical_pin_address("j.doe+x@example.com"), "j.doe@example.com");
        assert_ne!(pin_id("a", "j.doe@example.com"), pin_id("a", "jdoe@example.com"));
    }

    fn pin_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[3u8; 32]).unwrap();
        (dir, db)
    }

    #[test]
    fn a_pin_saved_under_a_dotted_spelling_is_found_for_every_variant() {
        let (_dir, db) = pin_db();
        let pin = RecipientPin {
            identity_fingerprint: "ab".repeat(32),
            ..Default::default()
        };
        let legacy = spelling_pin_id("a", "b.ob@astermail.org");
        db.recipient_pin_put(&legacy, &pin).unwrap();
        for spelling in ["bob@astermail.org", "b.o.b+news@astermail.org", "bo.b@astermail.org"] {
            let read = read_recipient_pin(&db, "a", spelling).unwrap();
            assert_eq!(read.pin.as_ref(), Some(&pin), "{spelling}");
            assert!(read.from_legacy);
            assert_eq!(read.id, pin_id("a", "bob@astermail.org"));
        }
        db.recipient_pin_put(&pin_id("a", "bob@astermail.org"), &pin).unwrap();
        let read = read_recipient_pin(&db, "a", "b.ob+x@astermail.org").unwrap();
        assert!(!read.from_legacy);
        assert_eq!(read.pin, Some(pin));
    }

    #[test]
    fn unreadable_pin_storage_is_an_error_not_a_first_contact() {
        let (_dir, db) = pin_db();
        db.with_conn(|conn| conn.execute_batch("DROP TABLE recipient_key_pin")).unwrap();
        assert!(read_recipient_pin(&db, "a", "bob@astermail.org").is_err());
    }

    fn scoped_entry(address: &str) -> PrekeyBundle {
        let entry = crate::crypto::address_identity::tests::fixed_keyring()
            .sign_entry(address)
            .unwrap();
        PrekeyBundle {
            kem_identity_key: entry.kem_identity_key,
            signed_prekey: entry.signed_prekey,
            signed_prekey_signature: Some(entry.signed_prekey_signature),
            pq_prekey: None,
            pq_kem_public_key: entry.pq_kem_public_key,
            x3dh_max_version: Some(2),
            ec_one_time_prekey: None,
            address_scoped: Some(true),
        }
    }

    fn pinned_to(key_b64: &str, rooted: bool) -> RecipientPin {
        RecipientPin {
            identity_fingerprint: key_fingerprint_hex(key_b64).unwrap(),
            address_rooted: rooted,
            ..Default::default()
        }
    }

    const ALIAS: &str = "alias@example.org";

    #[test]
    fn a_valid_entry_on_first_contact_is_trusted_and_roots_the_pin() {
        let bundle = scoped_entry(ALIAS);
        assert!(is_address_scoped(&bundle));
        assert_eq!(classify_scoped_entry(ALIAS, &bundle, None), DirectoryTrust::Entry);
        let evaluation = evaluate_address_entry(ALIAS, &bundle, DirectoryTrust::Entry, None, None);
        let pin = evaluation.pin.unwrap();
        assert!(pin.address_rooted);
        assert_eq!(pin.identity_fingerprint, key_fingerprint_hex(&bundle.kem_identity_key).unwrap());
        assert!(matches!(evaluation.outcome, Ok(SendRoute::Ratchet(_))));
        let pinned = pinned_to(&bundle.kem_identity_key, true);
        assert_eq!(classify_scoped_entry(ALIAS, &bundle, Some(&pinned)), DirectoryTrust::Entry);
    }

    #[test]
    fn an_entry_endorsed_by_the_pinned_key_is_accepted() {
        let bundle = scoped_entry(ALIAS);
        let verification = crate::crypto::address_identity::verify_address_entry(
            ALIAS,
            &bundle.kem_identity_key,
            &bundle.signed_prekey,
            bundle.pq_kem_public_key.as_deref(),
            bundle.signed_prekey_signature.as_deref().unwrap(),
        );
        assert!(verification.valid);
        let endorser = verification.endorsers.first().expect("the fixed vault endorses its entries");
        let pinned = pinned_to(endorser, true);
        assert_eq!(classify_scoped_entry(ALIAS, &bundle, Some(&pinned)), DirectoryTrust::Endorsed);
        assert!(evaluate_address_entry(ALIAS, &bundle, DirectoryTrust::Endorsed, Some(&pinned), None).outcome.is_ok());
    }

    #[test]
    fn a_replaced_or_invalid_entry_for_a_rooted_pin_is_refused() {
        let bundle = scoped_entry(ALIAS);
        let other = STANDARD.encode([0x04u8; 65]);
        let rooted = pinned_to(&other, true);
        assert_eq!(classify_scoped_entry(ALIAS, &bundle, Some(&rooted)), DirectoryTrust::Replaced);
        assert!(evaluate_address_entry(ALIAS, &bundle, DirectoryTrust::Replaced, Some(&rooted), None).outcome.is_err());

        let loose = pinned_to(&other, false);
        assert_eq!(classify_scoped_entry(ALIAS, &bundle, Some(&loose)), DirectoryTrust::Account);

        let mut forged = scoped_entry(ALIAS);
        forged.signed_prekey = STANDARD.encode([0x11u8; 65]);
        let pinned = pinned_to(&bundle.kem_identity_key, true);
        assert_eq!(classify_scoped_entry(ALIAS, &forged, Some(&pinned)), DirectoryTrust::Invalid);
        assert!(evaluate_address_entry(ALIAS, &forged, DirectoryTrust::Invalid, Some(&pinned), None).outcome.is_err());
        assert_eq!(classify_scoped_entry(ALIAS, &forged, None), DirectoryTrust::Account);
        assert_eq!(classify_scoped_entry("other@example.org", &bundle, None), DirectoryTrust::Account);
    }

    fn offers_to_accept(outcome: &Result<SendRoute, BridgeError>) -> bool {
        matches!(outcome, Err(BridgeError::RecipientKey(message)) if message.contains("recipient-key accept"))
    }

    #[test]
    fn a_refused_address_entry_can_be_accepted_like_any_changed_key() {
        let (_dir, db) = pin_db();
        let account = owner("alias");
        let shown = key_fingerprint(Some(&account.public_key)).unwrap();
        let bundle = scoped_entry(ALIAS);
        let mut forged = scoped_entry(ALIAS);
        forged.signed_prekey = STANDARD.encode([0x11u8; 65]);
        let other = STANDARD.encode([0x04u8; 65]);
        let cases = [
            (DirectoryTrust::Replaced, &bundle, pinned_to(&other, true)),
            (DirectoryTrust::Downgraded, &bundle, pinned_to(&other, true)),
            (DirectoryTrust::Invalid, &forged, pinned_to(&bundle.kem_identity_key, true)),
        ];
        for (trust, served, rooted) in cases {
            let rooted = RecipientPin {
                owner_fingerprint: shown.clone(),
                pq_seen: true,
                pq_fingerprint: "pq".to_string(),
                ..rooted
            };
            let id = read_recipient_pin(&db, "a", ALIAS).unwrap().id;
            db.recipient_pin_put(&id, &rooted).unwrap();

            let refused = evaluate_address_entry(ALIAS, served, trust, Some(&rooted), Some(&account.public_key));
            assert!(offers_to_accept(&refused.outcome), "{trust:?}");
            let flagged = refused.pin.expect("the refusal is recorded");
            assert!(flagged.flagged && flagged.address_rooted);
            db.recipient_pin_put(&id, &flagged).unwrap();

            assert_eq!(
                accept_recipient_key(&db, "a", ALIAS, Some(&account.public_key), &shown).unwrap(),
                KeyAcceptance::Accepted { fingerprint: shown.clone() }
            );
            let accepted = read_recipient_pin(&db, "a", ALIAS).unwrap().pin.unwrap();
            assert!(!accepted.flagged && !accepted.address_rooted);
            assert!(accepted.identity_fingerprint.is_empty());
            assert!(accepted.pq_seen);
            assert_eq!(classify_scoped_entry(ALIAS, served, Some(&accepted)), DirectoryTrust::Account);
            let next = evaluate_recipient(
                ALIAS,
                Some(&signed_v2_bundle(&account)),
                Some(&account.public_key),
                Some(&accepted),
            );
            assert!(matches!(next.outcome, Ok(SendRoute::Ratchet(_))), "{trust:?}");
        }
    }

    #[test]
    fn a_flagged_entry_pin_offers_the_accept_path() {
        let account = owner("alias");
        let bundle = scoped_entry(ALIAS);
        let flagged = RecipientPin {
            flagged: true,
            ..pinned_to(&bundle.kem_identity_key, true)
        };
        let evaluation = evaluate_address_entry(ALIAS, &bundle, DirectoryTrust::Entry, Some(&flagged), Some(&account.public_key));
        assert!(offers_to_accept(&evaluation.outcome));
        assert!(evaluation.pin.is_none());
    }

    #[test]
    fn a_rooted_pin_answered_by_the_account_bundle_offers_the_accept_path() {
        let account = owner("alias");
        let shown = key_fingerprint(Some(&account.public_key)).unwrap();
        let rooted = RecipientPin {
            owner_fingerprint: shown.clone(),
            ..pinned_to(&STANDARD.encode([0x04u8; 65]), true)
        };
        let account_bundle = signed_v2_bundle(&account);
        let refused = evaluate_recipient(ALIAS, Some(&account_bundle), Some(&account.public_key), Some(&rooted));
        assert!(offers_to_accept(&refused.outcome));
        let flagged = refused.pin.unwrap();
        assert!(flagged.flagged);

        let accepted = accepted_pin(flagged, &shown);
        assert!(!accepted.address_rooted && !accepted.flagged);
        let next = evaluate_recipient(ALIAS, Some(&account_bundle), Some(&account.public_key), Some(&accepted));
        assert!(matches!(next.outcome, Ok(SendRoute::Ratchet(_))));

        let no_bundle = evaluate_recipient(ALIAS, None, Some(&account.public_key), Some(&rooted));
        assert!(matches!(no_bundle.outcome, Ok(SendRoute::AccountKey)));
    }

    #[test]
    fn accepting_a_key_for_a_pin_without_an_address_entry_is_unchanged() {
        let loose = RecipientPin {
            identity_fingerprint: "id".to_string(),
            owner_fingerprint: "old".to_string(),
            pq_seen: true,
            pq_fingerprint: "pq".to_string(),
            binding_epoch: 3,
            binding_fingerprint: "binding".to_string(),
            transcript_bound: true,
            hosted: true,
            flagged: true,
            address_rooted: false,
        };
        assert_eq!(
            accepted_pin(loose.clone(), "old"),
            RecipientPin {
                flagged: false,
                ..loose.clone()
            }
        );
        assert_eq!(
            accepted_pin(loose.clone(), "new"),
            RecipientPin {
                owner_fingerprint: "new".to_string(),
                binding_epoch: 0,
                binding_fingerprint: String::new(),
                flagged: false,
                ..loose
            }
        );
    }

    #[test]
    fn an_unscoped_answer_for_a_rooted_pin_is_a_downgrade() {
        let rooted = pinned_to(&STANDARD.encode([0x04u8; 65]), true);
        assert_eq!(unscoped_trust(Some(&rooted)), DirectoryTrust::Downgraded);
        assert_eq!(unscoped_trust(None), DirectoryTrust::Account);
        let loose = pinned_to(&STANDARD.encode([0x04u8; 65]), false);
        assert_eq!(unscoped_trust(Some(&loose)), DirectoryTrust::Account);
    }
}
