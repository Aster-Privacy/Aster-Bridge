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
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tokio::sync::RwLock;

use crate::api_client::ApiClient;
use crate::auth::session::Session;
use zeroize::Zeroizing;

use crate::crypto::ratchet::{encrypt_bootstrap_versioned, RatchetMessage};
use crate::crypto::recipient_trust::{evaluate_recipient, pin_id, RatchetTarget, SendRoute};
use crate::db::Database;
use crate::error::{BridgeError, Result};

const INTERNAL_DOMAINS: [&str; 6] = [
    "astermail.org",
    "aster.cx",
    "astermail.me",
    "astermail.net",
    "gs-cloud.space",
    "realiased.me",
];

const GHOST_DOMAIN: &str = "realiased.me";

pub fn is_internal_address(address: &str) -> bool {
    let lower = address.trim().to_lowercase();
    INTERNAL_DOMAINS
        .iter()
        .any(|domain| lower.ends_with(&format!("@{}", domain)))
}

pub fn payload_recipients(payload: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for field in ["to", "cc", "bcc"] {
        let Some(list) = payload.get(field).and_then(|v| v.as_array()) else {
            continue;
        };
        for value in list {
            let Some(address) = value.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            if !out.iter().any(|seen| seen.eq_ignore_ascii_case(address)) {
                out.push(address.to_string());
            }
        }
    }
    out
}

pub struct RecipientSplit {
    pub internal: Vec<String>,
    pub has_external: bool,
}

pub fn split_recipients(payload: &Value) -> RecipientSplit {
    let all = payload_recipients(payload);
    let has_external = all.iter().any(|address| !is_internal_address(address));
    let internal = all
        .into_iter()
        .filter(|address| is_internal_address(address))
        .collect();
    RecipientSplit {
        internal,
        has_external,
    }
}

pub fn key_lookup_username(address: &str, own_username: &str) -> Option<String> {
    let (local, domain) = address.trim().split_once('@')?;
    if domain.eq_ignore_ascii_case(GHOST_DOMAIN) && !own_username.is_empty() {
        return Some(own_username.to_string());
    }
    if local.is_empty() {
        return None;
    }
    Some(local.to_string())
}

pub fn recipient_entry(message: &RatchetMessage) -> Value {
    let mut header = json!({
        "dh_public": STANDARD.encode(&message.header_dh_public),
        "previous_chain_length": message.previous_chain_length,
        "message_number": message.message_number,
    });
    if let Some(version) = message.header_version {
        header["v"] = json!(version);
    }
    let mut entry = json!({
        "ephemeral_key": STANDARD.encode(&message.ephemeral_public),
        "header": header,
        "ciphertext": STANDARD.encode(&message.ciphertext),
        "nonce": STANDARD.encode(&message.nonce),
    });
    if let (Some(ciphertext), Some(key_id)) = (&message.pq_ciphertext, message.pq_key_id) {
        entry["pq_ciphertext"] = json!(STANDARD.encode(ciphertext));
        entry["pq_key_id"] = json!(key_id);
    }
    if let Some(version) = message.x3dh_version.filter(|version| *version > 1) {
        entry["x3dh_v"] = json!(version);
    }
    entry
}

pub fn build_envelope(sender_identity_key: &str, recipients: Vec<(String, Value)>) -> String {
    let mut map = serde_json::Map::new();
    for (address, entry) in recipients {
        map.insert(address, entry);
    }
    json!({
        "type": "double_ratchet_v2",
        "sender_identity_key": sender_identity_key,
        "recipients": Value::Object(map),
    })
    .to_string()
}

pub fn apply_envelope(payload: &mut Value, envelope: String, has_external: bool) {
    if has_external {
        payload["internal_encrypted_body"] = json!(envelope);
        payload["is_e2e_encrypted"] = json!(false);
        return;
    }
    payload["body"] = json!(envelope);
    payload["is_e2e_encrypted"] = json!(true);
    payload["is_html"] = json!(false);
    if let Some(object) = payload.as_object_mut() {
        object.remove("body_html");
    }
}

struct SenderKeys {
    identity_secret_d: Vec<u8>,
    username: String,
    account_id: String,
    account_key: Option<Zeroizing<String>>,
    passphrase: Zeroizing<Vec<u8>>,
}

struct RoutedRecipient {
    address: String,
    route: SendRoute,
    account_key: Option<String>,
}

fn seal_for_recipient(
    sender_identity_secret_d: &[u8],
    target: &RatchetTarget,
    plaintext: &str,
) -> Result<RatchetMessage> {
    encrypt_bootstrap_versioned(
        sender_identity_secret_d,
        &target.identity_public,
        &target.signed_prekey,
        target.pq_target.as_ref().map(|pq| pq.public_key.as_slice()),
        target.pq_target.as_ref().map(|pq| pq.key_id),
        target.transcript_bound,
        plaintext,
    )
    .map_err(BridgeError::Crypto)
}

fn seal_ratchet_envelope(
    sender_identity_secret_d: &[u8],
    recipients: &[RoutedRecipient],
    plaintext: &str,
) -> Result<Option<String>> {
    let mut sealed: Vec<(String, Value)> = Vec::with_capacity(recipients.len());
    let mut sender_identity_key: Option<String> = None;
    for recipient in recipients {
        let SendRoute::Ratchet(target) = &recipient.route else {
            return Ok(None);
        };
        let message = seal_for_recipient(sender_identity_secret_d, target, plaintext)?;
        if sender_identity_key.is_none() {
            sender_identity_key = Some(STANDARD.encode(&message.sender_identity_public));
        }
        sealed.push((recipient.address.to_lowercase(), recipient_entry(&message)));
    }
    Ok(sender_identity_key.map(|key| build_envelope(&key, sealed)))
}

fn seal_with_account_keys(
    plaintext: &str,
    recipient_keys: &[&str],
    sender_account_key: &str,
    passphrase: &[u8],
) -> Result<String> {
    let unusable = || BridgeError::Crypto("your account key could not be used to encrypt".to_string());
    let passphrase = Zeroizing::new(
        std::str::from_utf8(passphrase)
            .map_err(|_| unusable())?
            .to_string(),
    );
    let signer = aster_crypto::import_secret_key(sender_account_key).map_err(|_| unusable())?;
    let mut keys = Vec::with_capacity(recipient_keys.len() + 1);
    for armored in recipient_keys {
        keys.push(aster_crypto::import_public_key(armored).map_err(|_| {
            BridgeError::RecipientKey(
                "A recipient's published encryption key could not be read, so the message was not sent."
                    .to_string(),
            )
        })?);
    }
    keys.push(signer.public_key());
    let references: Vec<&aster_crypto::PublicKey> = keys.iter().collect();
    let armored = aster_crypto::encrypt_and_sign_with_passphrase(
        plaintext.as_bytes(),
        &references,
        &signer,
        &passphrase,
    )
    .map_err(|_| BridgeError::Crypto("the message could not be encrypted".to_string()))?;
    String::from_utf8(armored)
        .map_err(|_| BridgeError::Crypto("the message could not be encrypted".to_string()))
}

fn seal_routed(sender: &SenderKeys, recipients: &[RoutedRecipient], plaintext: &str) -> Result<String> {
    if let Some(envelope) = seal_ratchet_envelope(&sender.identity_secret_d, recipients, plaintext)? {
        return Ok(envelope);
    }
    let account_key = sender.account_key.as_ref().ok_or_else(|| {
        BridgeError::Crypto(
            "no account key in the vault; cannot encrypt for Aster recipients".to_string(),
        )
    })?;
    let mut recipient_keys = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        recipient_keys.push(recipient.account_key.as_deref().ok_or_else(|| {
            BridgeError::RecipientKey(format!(
                "{} has no published encryption keys, so the message was not sent.",
                recipient.address
            ))
        })?);
    }
    seal_with_account_keys(plaintext, &recipient_keys, account_key, &sender.passphrase)
}

async fn sender_keys(session: &Arc<RwLock<Session>>) -> Result<SenderKeys> {
    let guard = session.read().await;
    let keys = guard.ratchet_keys.first().ok_or_else(|| {
        BridgeError::Crypto(
            "no ratchet identity in the vault; cannot encrypt for Aster recipients".to_string(),
        )
    })?;
    Ok(SenderKeys {
        identity_secret_d: keys.identity_secret_d.clone(),
        username: guard.username.clone(),
        account_id: guard.user_id.to_string(),
        account_key: guard.identity_key.clone().map(Zeroizing::new),
        passphrase: Zeroizing::new(guard.vault_passphrase.clone()),
    })
}

fn sealed_plaintext(payload: &Value) -> String {
    let body = payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let manifest = crate::crypto::attachment::send_attachment_manifest(payload);
    if manifest.is_empty() {
        return body.to_string();
    }
    let subject = payload
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    crate::crypto::ratchet_recovery::wrap_subject_bundle(subject, body, &manifest)
}

fn has_post_quantum_protection(route: &SendRoute) -> bool {
    matches!(route, SendRoute::Ratchet(target) if target.pq_target.is_some())
}

fn enforce_post_quantum(routed: &[RoutedRecipient], required: bool) -> Result<()> {
    if !required {
        return Ok(());
    }
    match routed
        .iter()
        .find(|recipient| !has_post_quantum_protection(&recipient.route))
    {
        Some(recipient) => Err(BridgeError::RecipientKey(format!(
            "{} cannot receive post-quantum protected mail yet, and Aster Bridge is set to require it, so the message was not sent. To send it anyway, turn off Require post-quantum protection for Aster recipients in the Aster Bridge settings.",
            recipient.address
        ))),
        None => Ok(()),
    }
}

pub async fn seal_internal_body(
    payload: &mut Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    db: &Database,
    access_token: &str,
) -> Result<()> {
    let split = split_recipients(payload);
    if split.internal.is_empty() {
        return Ok(());
    }

    let plaintext = sealed_plaintext(payload);

    let sender = sender_keys(session).await?;
    let mut routed: Vec<RoutedRecipient> = Vec::with_capacity(split.internal.len());
    let mut pending_pins = Vec::new();

    for address in &split.internal {
        let username = key_lookup_username(address, &sender.username).ok_or_else(|| {
            BridgeError::Crypto("recipient address has no username to look up".to_string())
        })?;
        let bundle = client
            .find_prekey_bundle(access_token, &username, address)
            .await?;
        let owner_public_key = client
            .get_recipient_public_key(access_token, &username, address)
            .await?;
        let pin_key = pin_id(&sender.account_id, address);
        let existing = db.recipient_pin_get(&pin_key).map_err(|_| {
            BridgeError::RecipientKey(format!(
                "The saved key record for {} could not be read, so the message was not sent.",
                address
            ))
        })?;
        let evaluation = evaluate_recipient(
            address,
            bundle.as_ref(),
            owner_public_key.as_deref(),
            existing.as_ref(),
        );
        let route = match evaluation.outcome {
            Ok(route) => route,
            Err(error) => {
                if let Some(pin) = &evaluation.pin {
                    let _ = db.recipient_pin_put(&pin_key, pin);
                }
                return Err(error);
            }
        };
        if let Some(pin) = evaluation.pin {
            pending_pins.push((pin_key, pin));
        }
        routed.push(RoutedRecipient {
            address: address.clone(),
            route,
            account_key: owner_public_key,
        });
    }

    enforce_post_quantum(&routed, crate::config::require_post_quantum())?;
    let envelope = seal_routed(&sender, &routed, &plaintext)?;
    for (pin_key, pin) in &pending_pins {
        db.recipient_pin_put(pin_key, pin).map_err(|_| {
            BridgeError::RecipientKey(
                "The recipient key record could not be saved, so the message was not sent."
                    .to_string(),
            )
        })?;
    }
    apply_envelope(payload, envelope, split.has_external);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ratchet::{
        decrypt_bootstrap, encrypt_bootstrap, parse_recipient_message, RatchetReceiverKeys,
    };
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand_core::OsRng;

    fn payload_with(to: Vec<&str>) -> Value {
        json!({
            "to": to,
            "subject": "Hi",
            "body": "<p>hello</p>",
            "body_html": "<p>hello</p>",
            "is_html": true,
            "is_e2e_encrypted": false,
            "client_source": "bridge",
        })
    }

    #[test]
    fn the_sealed_plaintext_lists_attachments_only_when_there_are_some() {
        let mut payload = payload_with(vec!["user@astermail.org"]);
        assert_eq!(sealed_plaintext(&payload), "<p>hello</p>");

        let sealed = crate::crypto::attachment::seal_send_attachments(
            &[crate::crypto::attachment::OutgoingAttachment {
                name: "notes.txt".to_string(),
                mime_type: "text/plain".to_string(),
                content_id: None,
                is_inline: false,
                data: b"notes".to_vec(),
            }],
            b"pass",
        )
        .unwrap();
        payload["attachments"] = Value::Array(sealed);
        let opened = crate::crypto::ratchet_recovery::extract_subject_bundle(&sealed_plaintext(&payload));
        assert_eq!(opened.subject.as_deref(), Some("Hi"));
        assert_eq!(opened.body, "<p>hello</p>");
        let manifest = opened.attachment_manifest.expect("manifest");
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0]["filename"], "notes.txt");
        assert_eq!(manifest[0]["sha256"], crate::crypto::attachment::sha256_hex(b"notes"));
    }

    #[test]
    fn internal_domains_are_recognized() {
        assert!(is_internal_address("a@astermail.org"));
        assert!(is_internal_address("A@ASTER.CX"));
        assert!(is_internal_address("a@astermail.me"));
        assert!(is_internal_address("a@astermail.net"));
        assert!(is_internal_address("a@gs-cloud.space"));
        assert!(is_internal_address("a@realiased.me"));
        assert!(!is_internal_address("a@example.com"));
        assert!(!is_internal_address("a@notastermail.org.example.com"));
    }

    #[test]
    fn ghost_addresses_look_up_the_own_username() {
        assert_eq!(
            key_lookup_username("abc123@realiased.me", "alice").as_deref(),
            Some("alice")
        );
        assert_eq!(
            key_lookup_username("bob@astermail.org", "alice").as_deref(),
            Some("bob")
        );
        assert_eq!(key_lookup_username("nodomain", "alice"), None);
    }

    #[test]
    fn recipients_are_collected_across_to_cc_and_bcc_without_duplicates() {
        let payload = json!({
            "to": ["a@astermail.org", " b@example.com "],
            "cc": ["A@astermail.org"],
            "bcc": ["c@aster.cx"],
        });
        assert_eq!(
            payload_recipients(&payload),
            vec![
                "a@astermail.org".to_string(),
                "b@example.com".to_string(),
                "c@aster.cx".to_string(),
            ]
        );
    }

    #[test]
    fn all_internal_puts_the_ciphertext_in_body_and_flags_encryption() {
        let mut payload = payload_with(vec!["a@astermail.org", "b@aster.cx"]);
        let split = split_recipients(&payload);
        assert_eq!(split.internal.len(), 2);
        assert!(!split.has_external);

        apply_envelope(&mut payload, "SEALED".to_string(), split.has_external);

        assert_eq!(payload["body"], json!("SEALED"));
        assert_eq!(payload["is_e2e_encrypted"], json!(true));
        assert_eq!(payload["is_html"], json!(false));
        assert!(payload.get("body_html").is_none());
        assert!(payload.get("internal_encrypted_body").is_none());
        assert_eq!(payload["subject"], json!("Hi"));
    }

    #[test]
    fn mixed_recipients_keep_plaintext_and_add_the_sealed_copy() {
        let mut payload = payload_with(vec!["a@astermail.org", "b@example.com"]);
        let split = split_recipients(&payload);
        assert_eq!(split.internal, vec!["a@astermail.org".to_string()]);
        assert!(split.has_external);

        apply_envelope(&mut payload, "SEALED".to_string(), split.has_external);

        assert_eq!(payload["body"], json!("<p>hello</p>"));
        assert_eq!(payload["body_html"], json!("<p>hello</p>"));
        assert_eq!(payload["is_e2e_encrypted"], json!(false));
        assert_eq!(payload["internal_encrypted_body"], json!("SEALED"));
        assert_eq!(payload["is_html"], json!(true));
    }

    #[test]
    fn all_external_leaves_the_payload_untouched() {
        let payload = payload_with(vec!["a@example.com", "b@example.net"]);
        let split = split_recipients(&payload);
        assert!(split.internal.is_empty());
        assert!(split.has_external);

        let mut after = payload.clone();
        if !split.internal.is_empty() {
            apply_envelope(&mut after, "SEALED".to_string(), split.has_external);
        }
        assert_eq!(after, payload);
    }

    #[test]
    fn a_sealed_envelope_round_trips_through_the_recipient_parser() {
        let plaintext = "internal body the server must never see";
        let recipient_identity = SecretKey::random(&mut OsRng);
        let recipient_prekey = SecretKey::random(&mut OsRng);
        let sender_identity = SecretKey::random(&mut OsRng);
        let (decap, encap) = MlKem768::generate(&mut OsRng);

        let identity_public = recipient_identity
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let prekey_public = recipient_prekey
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let message = encrypt_bootstrap(
            sender_identity.to_bytes().as_slice(),
            &identity_public,
            &prekey_public,
            Some(encap.as_bytes().as_slice()),
            Some(4242),
            plaintext,
        )
        .expect("sealed");

        let envelope = build_envelope(
            &STANDARD.encode(&message.sender_identity_public),
            vec![("user@astermail.org".to_string(), recipient_entry(&message))],
        );

        let parsed: Value = serde_json::from_str(&envelope).expect("envelope json");
        assert_eq!(parsed["type"], json!("double_ratchet_v2"));
        assert_eq!(
            parsed["recipients"]["user@astermail.org"]["pq_key_id"],
            json!(4242)
        );
        assert_eq!(
            parsed["recipients"]["user@astermail.org"]["header"]["v"],
            json!(2)
        );

        let mut recipient_message =
            parse_recipient_message(&parsed, "USER@astermail.org").expect("parsed");
        recipient_message.pq_secret = Some(decap.as_bytes().to_vec());

        let keys = RatchetReceiverKeys {
            identity_secret_d: recipient_identity.to_bytes().to_vec(),
            signed_prekey_secret_d: recipient_prekey.to_bytes().to_vec(),
            signed_prekey_public: prekey_public,
        };
        assert_eq!(
            decrypt_bootstrap(&keys, &recipient_message).expect("decrypted"),
            plaintext
        );
    }
    struct Recipient {
        identity: SecretKey,
        prekey: SecretKey,
        prekey_public: Vec<u8>,
        pq_secret: Vec<u8>,
        bundle: crate::api_client::PrekeyBundle,
    }

    fn recipient() -> Recipient {
        let identity = SecretKey::random(&mut OsRng);
        let prekey = SecretKey::random(&mut OsRng);
        let (decap, encap) = MlKem768::generate(&mut OsRng);
        let prekey_public = prekey.public_key().to_encoded_point(false).as_bytes().to_vec();
        let bundle = crate::api_client::PrekeyBundle {
            kem_identity_key: STANDARD
                .encode(identity.public_key().to_encoded_point(false).as_bytes()),
            signed_prekey: STANDARD.encode(&prekey_public),
            signed_prekey_signature: None,
            pq_prekey: None,
            pq_kem_public_key: Some(STANDARD.encode(encap.as_bytes())),
            x3dh_max_version: None,
        };
        Recipient {
            identity,
            prekey,
            prekey_public,
            pq_secret: decap.as_bytes().to_vec(),
            bundle,
        }
    }

    fn sign_v2(bundle: &mut crate::api_client::PrekeyBundle, account: &crate::crypto::recipient_trust::tests::Owner) {
        let text = format!(
            "aster-ratchet-prekey-v2:{}.{}.{}",
            bundle.kem_identity_key,
            bundle.signed_prekey,
            bundle.pq_kem_public_key.as_deref().unwrap()
        );
        crate::crypto::recipient_trust::tests::sign(bundle, account, &text);
    }

    fn sender(account: &crate::crypto::recipient_trust::tests::Owner) -> SenderKeys {
        SenderKeys {
            identity_secret_d: SecretKey::random(&mut OsRng).to_bytes().to_vec(),
            username: "sender".to_string(),
            account_id: "account".to_string(),
            account_key: Some(Zeroizing::new(account.keypair.to_armored().unwrap())),
            passphrase: Zeroizing::new(Vec::new()),
        }
    }

    fn routed(
        address: &str,
        bundle: Option<&crate::api_client::PrekeyBundle>,
        account: &crate::crypto::recipient_trust::tests::Owner,
    ) -> RoutedRecipient {
        let route = evaluate_recipient(address, bundle, Some(&account.public_key), None)
            .outcome
            .expect("routed");
        RoutedRecipient {
            address: address.to_string(),
            route,
            account_key: Some(account.public_key.clone()),
        }
    }

    fn open_with_account_key(
        armored: &str,
        reader: &crate::crypto::recipient_trust::tests::Owner,
        signer: &crate::crypto::recipient_trust::tests::Owner,
    ) -> String {
        let opened = aster_crypto::decrypt_and_verify_with_passphrase(
            armored.as_bytes(),
            &[&reader.keypair],
            &[&signer.keypair.public_key()],
            "",
        )
        .expect("opened");
        String::from_utf8(opened).unwrap()
    }

    #[test]
    fn requiring_post_quantum_refuses_recipients_without_it() {
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let mut protected = recipient();
        let (_, encap) = MlKem768::generate(&mut OsRng);
        protected.bundle.pq_prekey = Some(crate::api_client::BundlePqPrekey {
            key_id: 9,
            public_key: STANDARD.encode(encap.as_bytes()),
        });
        protected.bundle.x3dh_max_version = Some(2);
        sign_v2(&mut protected.bundle, &account);
        let with_pq = routed("pq@astermail.org", Some(&protected.bundle), &account);
        assert!(has_post_quantum_protection(&with_pq.route));

        let classical = RoutedRecipient {
            address: "classical@astermail.org".to_string(),
            route: match with_pq.route.clone() {
                SendRoute::Ratchet(mut target) => {
                    target.pq_target = None;
                    SendRoute::Ratchet(target)
                }
                other => other,
            },
            account_key: None,
        };
        let account_key_only = routed("pgp@astermail.org", None, &account);
        assert_eq!(account_key_only.route, SendRoute::AccountKey);

        let all_protected = [routed("pq@astermail.org", Some(&protected.bundle), &account)];
        assert!(enforce_post_quantum(&all_protected, true).is_ok());

        for weak in [classical, account_key_only] {
            let address = weak.address.clone();
            let mixed = [routed("pq@astermail.org", Some(&protected.bundle), &account), weak];
            assert!(enforce_post_quantum(&mixed, false).is_ok());
            match enforce_post_quantum(&mixed, true) {
                Err(BridgeError::RecipientKey(message)) => {
                    assert!(message.starts_with(&address));
                    assert!(message.contains("post-quantum"));
                }
                other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
            }
        }
    }

    #[test]
    fn a_verified_bundle_seals_to_the_signed_post_quantum_key() {
        use crate::crypto::ratchet::PQ_IDENTITY_KEY_ID;
        use crate::crypto::recipient_trust::tests::owner;

        let plaintext = "sealed only after the bundle signature verified";
        let account = owner("user");
        let me = owner("sender");
        let mut bob = recipient();
        let (_, unsigned_encap) = MlKem768::generate(&mut OsRng);
        bob.bundle.pq_prekey = Some(crate::api_client::BundlePqPrekey {
            key_id: 9,
            public_key: STANDARD.encode(unsigned_encap.as_bytes()),
        });
        bob.bundle.x3dh_max_version = Some(2);
        sign_v2(&mut bob.bundle, &account);

        let envelope = seal_routed(
            &sender(&me),
            &[routed("User@astermail.org", Some(&bob.bundle), &account)],
            plaintext,
        )
        .expect("sealed");

        let parsed: Value = serde_json::from_str(&envelope).expect("envelope json");
        assert_eq!(parsed["type"], json!("double_ratchet_v2"));
        assert_eq!(parsed["recipients"]["user@astermail.org"]["x3dh_v"], json!(2));
        let mut message = parse_recipient_message(&parsed, "user@astermail.org").expect("parsed");
        assert_eq!(message.pq_key_id, Some(PQ_IDENTITY_KEY_ID));
        assert_eq!(message.x3dh_version, Some(2));
        message.pq_secret = Some(bob.pq_secret.clone());

        let keys = RatchetReceiverKeys {
            identity_secret_d: bob.identity.to_bytes().to_vec(),
            signed_prekey_secret_d: bob.prekey.to_bytes().to_vec(),
            signed_prekey_public: bob.prekey_public.clone(),
        };
        assert_eq!(decrypt_bootstrap(&keys, &message).expect("decrypted"), plaintext);
    }

    #[test]
    fn a_peer_that_does_not_advertise_the_bound_handshake_gets_the_first_version() {
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let me = owner("sender");
        let mut bob = recipient();
        sign_v2(&mut bob.bundle, &account);

        let envelope = seal_routed(
            &sender(&me),
            &[routed("user@astermail.org", Some(&bob.bundle), &account)],
            "first version",
        )
        .expect("sealed");

        let parsed: Value = serde_json::from_str(&envelope).expect("envelope json");
        assert!(parsed["recipients"]["user@astermail.org"].get("x3dh_v").is_none());
        let mut message = parse_recipient_message(&parsed, "user@astermail.org").expect("parsed");
        message.pq_secret = Some(bob.pq_secret.clone());
        let keys = RatchetReceiverKeys {
            identity_secret_d: bob.identity.to_bytes().to_vec(),
            signed_prekey_secret_d: bob.prekey.to_bytes().to_vec(),
            signed_prekey_public: bob.prekey_public.clone(),
        };
        assert_eq!(decrypt_bootstrap(&keys, &message).expect("decrypted"), "first version");
    }

    #[test]
    fn an_unsigned_bundle_is_sent_under_the_account_key_instead_of_refused() {
        use crate::crypto::recipient_trust::tests::owner;

        let plaintext = "delivered without trusting the unsigned bundle";
        let account = owner("user");
        let me = owner("sender");
        let bob = recipient();

        let sealed = seal_routed(
            &sender(&me),
            &[routed("user@astermail.org", Some(&bob.bundle), &account)],
            plaintext,
        )
        .expect("sealed");

        assert!(sealed.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert!(!sealed.contains(plaintext));
        assert_eq!(open_with_account_key(&sealed, &account, &me), plaintext);
        assert_eq!(open_with_account_key(&sealed, &me, &me), plaintext);
    }

    #[test]
    fn a_recipient_without_a_bundle_is_sent_under_the_account_key() {
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let me = owner("sender");

        let sealed = seal_routed(
            &sender(&me),
            &[routed("user@astermail.org", None, &account)],
            "no bundle",
        )
        .expect("sealed");

        assert_eq!(open_with_account_key(&sealed, &account, &me), "no bundle");
    }

    #[test]
    fn one_recipient_without_a_verified_bundle_moves_the_whole_message_to_account_keys() {
        use crate::crypto::recipient_trust::tests::owner;

        let verified_account = owner("verified");
        let legacy_account = owner("legacy");
        let me = owner("sender");
        let mut verified = recipient();
        sign_v2(&mut verified.bundle, &verified_account);
        let legacy = recipient();

        let sealed = seal_routed(
            &sender(&me),
            &[
                routed("verified@astermail.org", Some(&verified.bundle), &verified_account),
                routed("legacy@astermail.org", Some(&legacy.bundle), &legacy_account),
            ],
            "everyone",
        )
        .expect("sealed");

        assert!(sealed.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert_eq!(open_with_account_key(&sealed, &verified_account, &me), "everyone");
        assert_eq!(open_with_account_key(&sealed, &legacy_account, &me), "everyone");
    }

    #[test]
    fn the_account_key_route_needs_the_sender_account_key() {
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let me = owner("sender");
        let mut keys = sender(&me);
        keys.account_key = None;

        assert!(matches!(
            seal_routed(&keys, &[routed("user@astermail.org", None, &account)], "x"),
            Err(BridgeError::Crypto(_))
        ));
    }
}
