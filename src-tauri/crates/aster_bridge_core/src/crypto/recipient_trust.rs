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
use crate::crypto::internal_send::key_lookup_username;
use crate::crypto::ratchet::{PQ_IDENTITY_KEY_ID, X3DH_VERSION_TRANSCRIPT_BOUND};
use crate::db::Database;
use crate::error::BridgeError;

const CLEARTEXT_SIGNATURE_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const CANONICAL_PREFIX_V1: &str = "aster-ratchet-prekey-v1:";
const CANONICAL_PREFIX_V2: &str = "aster-ratchet-prekey-v2:";
const PIN_ID_DOMAIN: &[u8] = b"aster-bridge-recipient-pin-v1";
const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleVerdict {
    Verified { covers_pq_identity: bool },
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
    pub flagged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTarget {
    pub public_key: Vec<u8>,
    pub key_id: i32,
    pub signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetTarget {
    pub identity_public: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub pq_target: Option<PqTarget>,
    pub transcript_bound: bool,
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
    if canonical_v2(bundle).as_deref() == Some(signed_text) {
        return BundleVerdict::Verified {
            covers_pq_identity: true,
        };
    }
    if signed_text == canonical_v1(bundle) {
        return BundleVerdict::Verified {
            covers_pq_identity: false,
        };
    }
    BundleVerdict::Tampered
}

pub fn pin_id(account_id: &str, address: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PIN_ID_DOMAIN);
    hasher.update([0u8]);
    hasher.update(account_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(address.trim().to_lowercase().as_bytes());
    hex(&hasher.finalize())
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
    db.recipient_pin_put(
        &pin_id(account_id, address),
        &RecipientPin {
            owner_fingerprint: fingerprint.clone(),
            ..RecipientPin::default()
        },
    )?;
    Ok(KeyAcceptance::Accepted { fingerprint })
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

fn downgraded(address: &str, fingerprint: Option<&str>) -> BridgeError {
    BridgeError::RecipientKey(format!(
        "The post-quantum key that {} published before is no longer available, so the message was not sent. {}",
        address,
        accept_hint(address, fingerprint)
    ))
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

    if verdict == Some(BundleVerdict::Tampered) || owner_changed || base.flagged {
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

    if let (Some(bundle), Some(BundleVerdict::Verified { covers_pq_identity })) = (bundle, verdict)
    {
        let advertises_pq = advertised_pq_identity_key(bundle).is_some();
        let pq_pinned = !base.pq_fingerprint.is_empty();
        if (pq_pinned && !covers_pq_identity) || (base.pq_seen && !advertises_pq) {
            return Evaluation {
                pin: None,
                outcome: Err(downgraded(address, Some(&owner_fingerprint))),
            };
        }
        let target = match ratchet_target(address, bundle, covers_pq_identity) {
            Ok(target) => target,
            Err(error) => {
                return Evaluation {
                    pin: None,
                    outcome: Err(error),
                }
            }
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
            flagged: false,
        };
        return Evaluation {
            pin: changed_pin(existing, pin),
            outcome: Ok(SendRoute::Ratchet(target)),
        };
    }

    if base.pq_seen {
        return Evaluation {
            pin: None,
            outcome: Err(downgraded(address, Some(&owner_fingerprint))),
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
                covers_pq_identity: false
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
    fn the_handshake_version_follows_what_every_recipient_device_supports() {
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
            assert!(!evaluation.pin.clone().unwrap().transcript_bound);
            assert!(!ratchet(evaluation).transcript_bound);
        }
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
    fn pin_ids_are_scoped_to_the_account_and_ignore_case() {
        assert_eq!(pin_id("a", "Bob@Astermail.org"), pin_id("a", "bob@astermail.org"));
        assert_ne!(pin_id("a", "bob@astermail.org"), pin_id("b", "bob@astermail.org"));
        assert_eq!(pin_id("a", "bob@astermail.org").len(), 64);
    }
}
