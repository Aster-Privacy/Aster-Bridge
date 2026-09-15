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
use crate::crypto::ratchet::{encrypt_bootstrap, RatchetMessage};
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
    })
}

pub async fn seal_internal_body(
    payload: &mut Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    access_token: &str,
) -> Result<()> {
    let split = split_recipients(payload);
    if split.internal.is_empty() {
        return Ok(());
    }

    let plaintext = payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let sender = sender_keys(session).await?;
    let mut sealed: Vec<(String, Value)> = Vec::with_capacity(split.internal.len());
    let mut sender_identity_key: Option<String> = None;

    for address in &split.internal {
        let username = key_lookup_username(address, &sender.username).ok_or_else(|| {
            BridgeError::Crypto("recipient address has no username to look up".to_string())
        })?;
        let bundle = client
            .get_prekey_bundle(access_token, &username, address)
            .await?;
        let identity_public = STANDARD
            .decode(bundle.kem_identity_key.trim())
            .map_err(|_| {
                BridgeError::Crypto("recipient identity key is not valid base64".to_string())
            })?;
        let signed_prekey = STANDARD.decode(bundle.signed_prekey.trim()).map_err(|_| {
            BridgeError::Crypto("recipient signed prekey is not valid base64".to_string())
        })?;
        let pq = match &bundle.pq_prekey {
            Some(prekey) => {
                let decoded = STANDARD.decode(prekey.public_key.trim()).map_err(|_| {
                    BridgeError::Crypto(
                        "recipient post-quantum prekey is not valid base64".to_string(),
                    )
                })?;
                Some((decoded, prekey.key_id as i32))
            }
            None => None,
        };

        let message = encrypt_bootstrap(
            &sender.identity_secret_d,
            &identity_public,
            &signed_prekey,
            pq.as_ref().map(|(key, _)| key.as_slice()),
            pq.as_ref().map(|(_, key_id)| *key_id),
            &plaintext,
        )
        .map_err(BridgeError::Crypto)?;

        if sender_identity_key.is_none() {
            sender_identity_key = Some(STANDARD.encode(&message.sender_identity_public));
        }
        sealed.push((address.to_lowercase(), recipient_entry(&message)));
    }

    let sender_identity_key = sender_identity_key
        .ok_or_else(|| BridgeError::Crypto("no Aster recipient could be sealed".to_string()))?;
    let envelope = build_envelope(&sender_identity_key, sealed);
    apply_envelope(payload, envelope, split.has_external);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ratchet::{decrypt_bootstrap, parse_recipient_message, RatchetReceiverKeys};
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
}
