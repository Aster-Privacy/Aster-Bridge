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

use crate::api_client::PrekeyBundle;
use crate::crypto::ratchet::PQ_IDENTITY_KEY_ID;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPin {
    pub identity_fingerprint: String,
    pub owner_fingerprint: String,
    pub pq_seen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTarget {
    pub public_key: Vec<u8>,
    pub key_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedBundle {
    pub identity_public: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub pq_target: Option<PqTarget>,
    pub pin: RecipientPin,
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn refuse(address: &str, reason: &str) -> BridgeError {
    BridgeError::RecipientKey(format!("{} for {}", reason, address))
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

    if covers_pq_identity {
        if let Some(public_key) = identity {
            return Ok(Some(PqTarget {
                public_key,
                key_id: PQ_IDENTITY_KEY_ID,
            }));
        }
    }
    if let Some((public_key, key_id)) = one_time {
        return Ok(Some(PqTarget { public_key, key_id }));
    }
    if let Some(public_key) = identity {
        return Ok(Some(PqTarget {
            public_key,
            key_id: PQ_IDENTITY_KEY_ID,
        }));
    }
    if advertises_pq {
        return Err(refuse(
            address,
            "the published post-quantum key is malformed, and the message is not sent with weaker encryption",
        ));
    }
    Ok(None)
}

pub fn evaluate_bundle(
    address: &str,
    bundle: &PrekeyBundle,
    owner_public_key: Option<&str>,
    existing: Option<&RecipientPin>,
) -> Result<TrustedBundle, BridgeError> {
    let verdict = verify_bundle(bundle, owner_public_key);
    let owner_fingerprint = owner_public_key
        .and_then(|key| aster_crypto::public_key_fingerprint_hex(key.as_bytes()));

    if verdict == BundleVerdict::Tampered {
        return Err(refuse(
            address,
            "the published encryption keys failed signature verification",
        ));
    }
    if let (Some(pin), Some(current)) = (existing, owner_fingerprint.as_deref()) {
        if !pin.owner_fingerprint.eq_ignore_ascii_case(current) {
            return Err(refuse(
                address,
                "the account key changed since you last wrote to this address; the message was not sent",
            ));
        }
    }
    let advertises_pq = advertised_pq_identity_key(bundle).is_some();
    if !advertises_pq && existing.is_some_and(|pin| pin.pq_seen) {
        return Err(refuse(
            address,
            "the published keys no longer include the post-quantum key seen before; the message was not sent",
        ));
    }
    let covers_pq_identity = match verdict {
        BundleVerdict::Verified { covers_pq_identity } => covers_pq_identity,
        _ => {
            return Err(refuse(
                address,
                "no signed encryption keys are published, so Aster Bridge cannot verify them; send from the Aster Mail app instead",
            ));
        }
    };
    let owner_fingerprint = owner_fingerprint.ok_or_else(|| {
        refuse(address, "the account key could not be read")
    })?;

    let identity_public = decode_key(address, &bundle.kem_identity_key, "identity key")?;
    let signed_prekey = decode_key(address, &bundle.signed_prekey, "signed prekey")?;
    let pq_target = select_pq_target(bundle, covers_pq_identity, address)?;

    Ok(TrustedBundle {
        pin: RecipientPin {
            identity_fingerprint: hex(&Sha256::digest(&identity_public)),
            owner_fingerprint,
            pq_seen: advertises_pq || existing.is_some_and(|pin| pin.pq_seen),
        },
        identity_public,
        signed_prekey,
        pq_target,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
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

    fn signed_v1_bundle(owner: &Owner, pq_identity: Option<Vec<u8>>) -> PrekeyBundle {
        let mut bundle = unsigned_bundle(pq_identity);
        let text = canonical_v1(&bundle);
        sign(&mut bundle, owner, &text);
        bundle
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
        assert!(matches!(
            evaluate_bundle("bob@astermail.org", &bundle, Some(INTEROP_PUBLIC_KEY), None),
            Err(BridgeError::RecipientKey(_))
        ));
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
    fn an_unsigned_bundle_is_refused() {
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
        assert!(matches!(
            evaluate_bundle("bob@astermail.org", &bundle, Some(&alice.public_key), None),
            Err(BridgeError::RecipientKey(_))
        ));
    }

    #[test]
    fn a_signed_bundle_without_a_published_account_key_is_refused() {
        let alice = owner("alice");
        let bundle = signed_v2_bundle(&alice);

        assert_eq!(verify_bundle(&bundle, None), BundleVerdict::Unknown);
        assert!(matches!(
            evaluate_bundle("bob@astermail.org", &bundle, None, None),
            Err(BridgeError::RecipientKey(_))
        ));
    }

    #[test]
    fn a_signature_over_the_post_quantum_key_selects_that_key() {
        let alice = owner("alice");
        let mut bundle = signed_v2_bundle(&alice);
        bundle.pq_prekey = one_time_prekey(0x33, ML_KEM_768_PUBLIC_KEY_BYTES);

        let trusted =
            evaluate_bundle("bob@astermail.org", &bundle, Some(&alice.public_key), None).unwrap();

        let target = trusted.pq_target.unwrap();
        assert_eq!(target.key_id, PQ_IDENTITY_KEY_ID);
        assert_eq!(target.public_key, vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]);
        assert!(trusted.pin.pq_seen);
    }

    #[test]
    fn a_signature_that_omits_the_post_quantum_key_prefers_the_one_time_prekey() {
        let alice = owner("alice");
        let mut bundle = signed_v1_bundle(&alice, Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        bundle.pq_prekey = one_time_prekey(0x33, ML_KEM_768_PUBLIC_KEY_BYTES);

        let trusted =
            evaluate_bundle("bob@astermail.org", &bundle, Some(&alice.public_key), None).unwrap();
        let target = trusted.pq_target.unwrap();
        assert_eq!(target.key_id, 77);
        assert_eq!(target.public_key, vec![0x33; ML_KEM_768_PUBLIC_KEY_BYTES]);

        bundle.pq_prekey = None;
        let trusted =
            evaluate_bundle("bob@astermail.org", &bundle, Some(&alice.public_key), None).unwrap();
        assert_eq!(trusted.pq_target.unwrap().key_id, PQ_IDENTITY_KEY_ID);
    }

    #[test]
    fn a_malformed_post_quantum_key_never_falls_back_to_classical() {
        let alice = owner("alice");
        let mut bundle = signed_v1_bundle(&alice, None);
        bundle.pq_prekey = one_time_prekey(0x33, 100);

        assert!(matches!(
            evaluate_bundle("bob@astermail.org", &bundle, Some(&alice.public_key), None),
            Err(BridgeError::RecipientKey(_))
        ));

        bundle.pq_prekey = None;
        let trusted =
            evaluate_bundle("bob@astermail.org", &bundle, Some(&alice.public_key), None).unwrap();
        assert!(trusted.pq_target.is_none());
    }

    #[test]
    fn a_changed_account_key_is_refused() {
        let alice = owner("alice");
        let mallory = owner("mallory");
        let first = evaluate_bundle(
            "bob@astermail.org",
            &signed_v2_bundle(&alice),
            Some(&alice.public_key),
            None,
        )
        .unwrap();

        let swapped = evaluate_bundle(
            "bob@astermail.org",
            &signed_v2_bundle(&mallory),
            Some(&mallory.public_key),
            Some(&first.pin),
        );
        assert!(matches!(swapped, Err(BridgeError::RecipientKey(_))));

        let unchanged = evaluate_bundle(
            "bob@astermail.org",
            &signed_v2_bundle(&alice),
            Some(&alice.public_key),
            Some(&first.pin),
        )
        .unwrap();
        assert_eq!(unchanged.pin, first.pin);
    }

    #[test]
    fn an_identity_key_rotated_under_the_pinned_account_key_is_accepted() {
        let alice = owner("alice");
        let first = evaluate_bundle(
            "bob@astermail.org",
            &signed_v2_bundle(&alice),
            Some(&alice.public_key),
            None,
        )
        .unwrap();

        let mut rotated = unsigned_bundle(Some(vec![0x22; ML_KEM_768_PUBLIC_KEY_BYTES]));
        rotated.kem_identity_key = STANDARD.encode([0x05u8; 65]);
        let text = canonical_v2(&rotated).unwrap();
        sign(&mut rotated, &alice, &text);

        let trusted = evaluate_bundle(
            "bob@astermail.org",
            &rotated,
            Some(&alice.public_key),
            Some(&first.pin),
        )
        .unwrap();
        assert_ne!(trusted.pin.identity_fingerprint, first.pin.identity_fingerprint);
        assert_eq!(trusted.pin.owner_fingerprint, first.pin.owner_fingerprint);
    }

    #[test]
    fn a_dropped_post_quantum_key_is_refused() {
        let alice = owner("alice");
        let first = evaluate_bundle(
            "bob@astermail.org",
            &signed_v2_bundle(&alice),
            Some(&alice.public_key),
            None,
        )
        .unwrap();
        assert!(first.pin.pq_seen);

        let downgraded = evaluate_bundle(
            "bob@astermail.org",
            &signed_v1_bundle(&alice, None),
            Some(&alice.public_key),
            Some(&first.pin),
        );
        assert!(matches!(downgraded, Err(BridgeError::RecipientKey(_))));
    }

    #[test]
    fn pin_ids_are_scoped_to_the_account_and_ignore_case() {
        assert_eq!(pin_id("a", "Bob@Astermail.org"), pin_id("a", "bob@astermail.org"));
        assert_ne!(pin_id("a", "bob@astermail.org"), pin_id("b", "bob@astermail.org"));
        assert_eq!(pin_id("a", "bob@astermail.org").len(), 64);
    }
}
