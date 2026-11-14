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

use crate::api_client::{ApiClient, PrekeyBundle, RecipientKeyLookup};
use crate::auth::session::Session;
use zeroize::Zeroizing;

use crate::crypto::ratchet::{
    encrypt_bootstrap_one_time_bound, encrypt_bootstrap_versioned, RatchetMessage,
    X3DH_VERSION_KEY_BOUND, X3DH_VERSION_ONE_TIME_BOUND,
};
use crate::crypto::sealed_details::{
    build_sealed_details, format_sent_at, sealed_sender_name, SealedMessageDetails,
};
use crate::crypto::recipient_trust::{
    classify_scoped_entry, evaluate_address_entry, evaluate_recipient, is_address_scoped,
    read_recipient_pin, verify_bundle, BundleVerdict, DirectoryTrust, Evaluation, PinRead,
    RatchetTarget, RecipientPin, SendRoute,
};
use crate::crypto::address_directory::{AddressEntryDirectory, AddressEntryState, ADDRESS_ENTRIES};
use crate::crypto::address_identity::{address_entry_forms, is_primary_address, AddressKeyring, SignedAddressEntry};
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
const LOOKUP_USERNAME_MAX: usize = 64;

const ASTER_SYSTEM_ADDRESSES: [&str; 8] = [
    "noreply@astermail.org",
    "no-reply@astermail.org",
    "noreply@aster.cx",
    "no-reply@aster.cx",
    "system@astermail.org",
    "system@aster.cx",
    "updates@astermail.org",
    "updates@aster.cx",
];

pub fn is_aster_system_address(address: &str) -> bool {
    let lower = address.trim().to_lowercase();
    ASTER_SYSTEM_ADDRESSES.contains(&lower.as_str())
}

pub fn is_internal_address(address: &str) -> bool {
    let lower = address.trim().to_lowercase();
    INTERNAL_DOMAINS
        .iter()
        .any(|domain| lower.ends_with(&format!("@{}", domain)))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsterSenderScope {
    pub account_id: String,
    pub custom_domains: Vec<String>,
}

impl AsterSenderScope {
    pub fn from_session(session: &Session) -> Self {
        let mut custom_domains: Vec<String> = session
            .send_identities
            .iter()
            .filter(|identity| identity.kind == crate::auth::session::SendIdentityKind::CustomDomain)
            .filter_map(|identity| address_domain(&identity.address))
            .filter(|domain| !INTERNAL_DOMAINS.contains(&domain.as_str()))
            .collect();
        custom_domains.sort();
        custom_domains.dedup();
        Self {
            account_id: session.user_id.to_string(),
            custom_domains,
        }
    }
}

fn address_domain(address: &str) -> Option<String> {
    let (local, domain) = address.trim().rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    (!local.is_empty() && !domain.is_empty()).then_some(domain)
}

pub fn note_aster_sender_scope(db: &Database, session: &Session) {
    db.set_aster_sender_scope(AsterSenderScope::from_session(session));
}

pub fn claims_aster_identity(db: &Database, address: &str) -> bool {
    let address = address.trim();
    if address.is_empty() {
        return false;
    }
    if is_internal_address(address) {
        return true;
    }
    let Some(scope) = db.aster_sender_scope() else {
        return false;
    };
    if address_domain(address).is_some_and(|domain| scope.custom_domains.contains(&domain)) {
        return true;
    }
    matches!(
        read_recipient_pin(db, &scope.account_id, address),
        Ok(PinRead { pin: Some(pin), .. }) if pin.hosted
    )
}

pub const SELF_TO_PLACEHOLDER: &str = "bridge_self_to_placeholder";

pub fn take_self_to_placeholder(payload: &mut Value) -> Option<String> {
    payload
        .as_object_mut()?
        .remove(SELF_TO_PLACEHOLDER)?
        .as_str()
        .map(str::to_string)
}

fn drop_sealed_self_placeholder(payload: &mut Value, own_address: &str, hosted: &HostedRecipients) {
    let to_is_placeholder = matches!(
        payload.get("to").and_then(Value::as_array).map(Vec::as_slice),
        Some([only]) if only.as_str().is_some_and(|a| a.trim().eq_ignore_ascii_case(own_address.trim()))
    );
    if !to_is_placeholder {
        return;
    }
    let others: Vec<String> = ["cc", "bcc"]
        .iter()
        .filter_map(|field| payload.get(*field).and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(str::to_string)
        .collect();
    let all_sealed = !others.is_empty()
        && others.iter().all(|address| {
            !address.eq_ignore_ascii_case(own_address.trim())
                && (is_internal_address(address) || hosted.contains(address))
                && !hosted.routed_like_external(address)
        });
    if all_sealed {
        payload["to"] = json!([]);
    }
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
    pub hidden: Vec<String>,
    pub has_external: bool,
}

fn listed_in(payload: &Value, fields: &[&str], address: &str) -> bool {
    fields.iter().any(|field| {
        payload
            .get(*field)
            .and_then(|v| v.as_array())
            .is_some_and(|list| {
                list.iter()
                    .filter_map(|value| value.as_str())
                    .any(|listed| listed.trim().eq_ignore_ascii_case(address.trim()))
            })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedClass {
    Hosted,
    AsterRouted,
    External,
}

pub fn classify_hosted(
    lookup: Option<&RecipientKeyLookup>,
    bundle_verified: bool,
    pin: Option<&RecipientPin>,
) -> HostedClass {
    if lookup.is_some_and(|lookup| lookup.internal) || pin.is_some_and(|pin| pin.hosted) {
        return HostedClass::Hosted;
    }
    if pin.is_some() || bundle_verified {
        return HostedClass::AsterRouted;
    }
    HostedClass::External
}

#[derive(Debug, Default)]
pub struct HostedRecipients {
    pub hosted: Vec<String>,
    pub routed_like_external: Vec<String>,
}

impl HostedRecipients {
    fn contains(&self, address: &str) -> bool {
        self.hosted
            .iter()
            .chain(self.routed_like_external.iter())
            .any(|listed| listed.eq_ignore_ascii_case(address.trim()))
    }

    fn routed_like_external(&self, address: &str) -> bool {
        self.routed_like_external
            .iter()
            .any(|listed| listed.eq_ignore_ascii_case(address.trim()))
    }

    fn all(&self) -> Vec<String> {
        self.hosted
            .iter()
            .chain(self.routed_like_external.iter())
            .cloned()
            .collect()
    }
}

pub fn split_recipients(payload: &Value) -> RecipientSplit {
    split_recipients_with(payload, &HostedRecipients::default())
}

pub fn split_recipients_with(payload: &Value, hosted: &HostedRecipients) -> RecipientSplit {
    let all = payload_recipients(payload);
    let is_aster = |address: &str| is_internal_address(address) || hosted.contains(address);
    let has_external = all
        .iter()
        .any(|address| !is_aster(address) || hosted.routed_like_external(address));
    let internal: Vec<String> = all.into_iter().filter(|address| is_aster(address)).collect();
    let hidden = internal
        .iter()
        .filter(|address| {
            listed_in(payload, &["bcc"], address) && !listed_in(payload, &["to", "cc"], address)
        })
        .cloned()
        .collect();
    RecipientSplit {
        internal,
        hidden,
        has_external,
    }
}

pub fn apply_hidden_bodies(payload: &mut Value, hidden_bodies: Vec<(String, String)>) {
    if hidden_bodies.is_empty() {
        return;
    }
    let mut map = serde_json::Map::new();
    for (address, body) in hidden_bodies {
        map.insert(address.trim().to_lowercase(), json!(body));
    }
    payload["recipient_bodies"] = Value::Object(map);
}

pub fn key_lookup_username(address: &str, own_username: &str) -> Option<String> {
    let (local, domain) = address.trim().rsplit_once('@')?;
    if domain.eq_ignore_ascii_case(GHOST_DOMAIN) && !own_username.is_empty() {
        return Some(own_username.to_string());
    }
    let local = local.split('+').next().unwrap_or_default();
    if local.is_empty() {
        return None;
    }
    Some(local.to_string())
}

fn hosted_lookup_username(address: &str) -> Option<String> {
    let (local, domain) = address.trim().rsplit_once('@')?;
    if domain.is_empty() || !domain.contains('.') {
        return None;
    }
    let local = local.split('+').next().unwrap_or_default();
    let shaped = !local.is_empty()
        && local.len() <= LOOKUP_USERNAME_MAX
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    shaped.then(|| local.to_string())
}

pub fn apply_hosted_recipients(payload: &mut Value, hosted: &HostedRecipients) {
    let listed = hosted.all();
    if listed.is_empty() {
        return;
    }
    payload["hosted_recipients"] = json!(listed);
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
    if message.x3dh_version == Some(X3DH_VERSION_ONE_TIME_BOUND) {
        if let Some(key_id) = message.opk_id {
            entry["opk_id"] = json!(key_id);
        }
        if let Some(signed_prekey_id) = &message.spk_id {
            entry["spk_id"] = json!(signed_prekey_id);
        }
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
    signs_with_account_key: bool,
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
    let mut version = target.x3dh_version();
    if version == X3DH_VERSION_ONE_TIME_BOUND {
        if let Some(one_time) = &target.one_time_prekey {
            if let Ok(message) = encrypt_bootstrap_one_time_bound(
                sender_identity_secret_d,
                &target.identity_public,
                &target.signed_prekey,
                target.pq_target.as_ref().map(|pq| pq.public_key.as_slice()),
                target.pq_target.as_ref().map(|pq| pq.key_id),
                one_time.key_id,
                &one_time.public_key,
                plaintext,
            ) {
                return Ok(message);
            }
        }
        version = X3DH_VERSION_KEY_BOUND;
    }
    encrypt_bootstrap_versioned(
        sender_identity_secret_d,
        &target.identity_public,
        &target.signed_prekey,
        target.pq_target.as_ref().map(|pq| pq.public_key.as_slice()),
        target.pq_target.as_ref().map(|pq| pq.key_id),
        version,
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

const NO_ACCOUNT_KEY_FOR_MESSAGES: &str =
    "no account key in the vault; cannot encrypt for Aster recipients";
const NO_ACCOUNT_KEY_FOR_ATTACHMENTS: &str =
    "no account key in the vault; cannot encrypt attachments for Aster recipients";

fn no_account_key(message: &str) -> BridgeError {
    BridgeError::Crypto(message.to_string())
}

fn import_recipient_keys(recipient_keys: &[&str]) -> Result<Vec<aster_crypto::PublicKey>> {
    recipient_keys
        .iter()
        .map(|armored| {
            aster_crypto::import_public_key(armored).map_err(|_| {
                BridgeError::RecipientKey(
                    "A recipient's published encryption key could not be read, so the message was not sent."
                        .to_string(),
                )
            })
        })
        .collect()
}

fn seal_without_account_signature(plaintext: &str, recipient_keys: &[&str]) -> Result<String> {
    let keys = import_recipient_keys(recipient_keys)?;
    let references: Vec<&aster_crypto::PublicKey> = keys.iter().collect();
    let armored = aster_crypto::encrypt_message(plaintext.as_bytes(), &references)
        .map_err(|_| BridgeError::Crypto("the message could not be encrypted".to_string()))?;
    String::from_utf8(armored)
        .map_err(|_| BridgeError::Crypto("the message could not be encrypted".to_string()))
}

fn seal_for_account_keys(
    sender: &SenderKeys,
    plaintext: &str,
    recipient_keys: &[&str],
    missing_key: &str,
) -> Result<String> {
    if !sender.signs_with_account_key {
        return seal_without_account_signature(plaintext, recipient_keys);
    }
    let account_key = sender.account_key.as_ref().ok_or_else(|| no_account_key(missing_key))?;
    seal_with_account_keys(plaintext, recipient_keys, account_key, &sender.passphrase)
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
    let mut keys = import_recipient_keys(recipient_keys)?;
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
    if sender.signs_with_account_key && sender.account_key.is_none() {
        return Err(no_account_key(NO_ACCOUNT_KEY_FOR_MESSAGES));
    }
    let mut recipient_keys = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        recipient_keys.push(recipient.account_key.as_deref().ok_or_else(|| {
            BridgeError::RecipientKey(format!(
                "{} has no published encryption keys, so the message was not sent.",
                recipient.address
            ))
        })?);
    }
    seal_for_account_keys(sender, plaintext, &recipient_keys, NO_ACCOUNT_KEY_FOR_MESSAGES)
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
        signs_with_account_key: true,
    })
}

fn sender_identity_failed() -> BridgeError {
    BridgeError::Crypto(
        "the encryption keys for the sending address could not be prepared, so the message was not sent"
            .to_string(),
    )
}

async fn address_sender_secret(
    payload: &Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    access_token: &str,
    directory: &AddressEntryDirectory,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(sender_email) = payload
        .get("sender_email")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|address| !address.is_empty())
    else {
        return Ok(None);
    };
    let (primary, username, keyring) = {
        let guard = session.read().await;
        (
            guard.email.clone(),
            guard.username.clone(),
            guard.ratchet_recovery.address_keys.clone(),
        )
    };
    if is_primary_address(&primary, sender_email) {
        return Ok(None);
    }
    if keyring.current_identity_public().is_none() {
        return Ok(None);
    }
    match directory
        .entry_state(client, access_token, &keyring, sender_email)
        .await
    {
        AddressEntryState::Inactive => Ok(None),
        AddressEntryState::Active => keyring
            .sender_identity(sender_email)
            .map(|derived| Some(derived.scalar))
            .ok_or_else(sender_identity_failed),
        AddressEntryState::Unconfirmed => {
            let Some(published) = published_sender_entry(client, access_token, &username, sender_email).await? else {
                return Ok(None);
            };
            let local = address_entry_forms(sender_email)
                .first()
                .and_then(|form| keyring.sign_entry(form));
            match (local, keyring.sender_identity(sender_email)) {
                (Some(local), Some(derived)) if is_same_entry(&published, &local) => Ok(Some(derived.scalar)),
                _ => Err(sender_identity_failed()),
            }
        }
    }
}

async fn published_sender_entry(
    client: &ApiClient,
    access_token: &str,
    username: &str,
    sender_email: &str,
) -> Result<Option<PrekeyBundle>> {
    let lookup_username = key_lookup_username(sender_email, username).ok_or_else(sender_identity_failed)?;
    Ok(client
        .find_prekey_bundle_in_scope(access_token, &lookup_username, sender_email, true)
        .await?
        .filter(is_address_scoped))
}

fn present(key: Option<&str>) -> Option<&str> {
    key.filter(|key| !key.is_empty())
}

fn is_same_entry(published: &PrekeyBundle, local: &SignedAddressEntry) -> bool {
    published.kem_identity_key == local.kem_identity_key
        && published.signed_prekey == local.signed_prekey
        && present(published.pq_kem_public_key.as_deref()) == present(local.pq_kem_public_key.as_deref())
}

fn local_address_bundle(keyring: &AddressKeyring, address: &str) -> Option<PrekeyBundle> {
    let form = address_entry_forms(address).into_iter().next()?;
    let entry = keyring.sign_entry(&form)?;
    Some(PrekeyBundle {
        kem_identity_key: entry.kem_identity_key,
        signed_prekey: entry.signed_prekey,
        signed_prekey_signature: Some(entry.signed_prekey_signature),
        pq_prekey: None,
        pq_kem_public_key: entry.pq_kem_public_key,
        x3dh_max_version: Some(2),
        ec_one_time_prekey: None,
        address_scoped: Some(true),
    })
}

fn payload_addresses(payload: &Value, field: &str) -> Vec<String> {
    payload
        .get(field)
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn payload_details(payload: &Value, account_name: Option<&str>, sent_at: &str) -> SealedMessageDetails {
    let chosen = payload.get("sender_display_name").and_then(Value::as_str);
    let sends_from_alias = payload
        .get("sender_alias_hash")
        .and_then(Value::as_str)
        .is_some_and(|hash| !hash.is_empty());
    build_sealed_details(
        &sealed_sender_name(chosen, sends_from_alias, account_name),
        &payload_addresses(payload, "to"),
        &payload_addresses(payload, "cc"),
        sent_at,
    )
}

fn sealed_plaintext(payload: &Value, account_name: Option<&str>, sent_at: &str) -> String {
    let body = payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let manifest = crate::crypto::attachment::send_attachment_manifest(payload);
    let subject = payload
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let details = payload_details(payload, account_name, sent_at);
    crate::crypto::ratchet_recovery::wrap_subject_bundle_with_details(subject, body, &manifest, Some(&details))
}

fn sealed_send_plaintext(
    payload: &mut Value,
    self_placeholder: Option<&str>,
    account_name: Option<&str>,
    sent_at: &str,
) -> String {
    let only_self = self_placeholder.is_some_and(|own| {
        matches!(
            payload.get("to").and_then(Value::as_array).map(Vec::as_slice),
            Some([only]) if only.as_str().is_some_and(|a| a.trim().eq_ignore_ascii_case(own.trim()))
        )
    });
    if !only_self {
        return sealed_plaintext(payload, account_name, sent_at);
    }
    let addressed = std::mem::replace(&mut payload["to"], json!([]));
    let plaintext = sealed_plaintext(payload, account_name, sent_at);
    payload["to"] = addressed;
    plaintext
}

async fn account_display_name(session: &Arc<RwLock<Session>>) -> Option<String> {
    session
        .read()
        .await
        .send_identities
        .iter()
        .find(|identity| identity.kind == crate::auth::session::SendIdentityKind::Primary)
        .and_then(|identity| identity.display_name.clone())
        .filter(|name| !name.trim().is_empty())
}

fn has_post_quantum_protection(route: &SendRoute) -> bool {
    matches!(
        route,
        SendRoute::Ratchet(target) if target.pq_target.as_ref().is_some_and(|pq| pq.signed)
    )
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

fn enforce_routed_like_external(hosted: &HostedRecipients, required: bool) -> Result<()> {
    match hosted.routed_like_external.first() {
        Some(address) if required => Err(BridgeError::RecipientKey(format!(
            "{} uses Aster, but Aster delivers mail to this address the same way as mail to an address outside Aster, so its contents cannot have post-quantum protection, and Aster Bridge is set to require it, so the message was not sent. To send it anyway, turn off Require post-quantum protection for Aster recipients in the Aster Bridge settings.",
            address
        ))),
        _ => Ok(()),
    }
}

struct KnownKeys {
    address: String,
    username: String,
    bundle: Option<PrekeyBundle>,
    owner_public_key: Option<String>,
}

struct HostedLookup {
    hosted: HostedRecipients,
    known: Vec<KnownKeys>,
}

impl HostedLookup {
    fn take(&mut self, address: &str) -> Option<KnownKeys> {
        let index = self
            .known
            .iter()
            .position(|known| known.address.eq_ignore_ascii_case(address))?;
        Some(self.known.swap_remove(index))
    }
}

fn unreadable_pin_error(address: &str) -> BridgeError {
    BridgeError::RecipientKey(format!(
        "The saved key record for {} could not be read, so the message was not sent.",
        address
    ))
}

fn is_own_address(session: &Session, address: &str) -> bool {
    let address = address.trim();
    session.email.trim().eq_ignore_ascii_case(address)
        || session
            .send_identities
            .iter()
            .any(|identity| identity.address.trim().eq_ignore_ascii_case(address))
}

fn same_entry_address(left: &str, right: &str) -> bool {
    let left = address_entry_forms(left);
    !left.is_empty() && left.first() == address_entry_forms(right).first()
}

fn local_self_recipient(
    session: &Session,
    directory: &AddressEntryDirectory,
    address: &str,
    derived_sender: Option<&str>,
) -> Option<RoutedRecipient> {
    if !is_own_address(session, address) || is_primary_address(&session.email, address) {
        return None;
    }
    let keyring = &session.ratchet_recovery.address_keys;
    let active = derived_sender.is_some_and(|sender| same_entry_address(sender, address))
        || directory.known_state(keyring, address) == Some(AddressEntryState::Active);
    if !active {
        return None;
    }
    let bundle = local_address_bundle(keyring, address)?;
    let route = evaluate_address_entry(address, &bundle, DirectoryTrust::Entry, None, None)
        .outcome
        .ok()?;
    let account_key = aster_crypto::import_secret_key(session.identity_key.as_deref()?)
        .ok()?
        .public_key_armored()
        .ok()?;
    Some(RoutedRecipient {
        address: address.to_string(),
        route,
        account_key: Some(account_key),
    })
}

async fn lookup_hosted_recipients(
    payload: &Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    db: &Database,
    access_token: &str,
) -> Result<HostedLookup> {
    let candidates: Vec<String> = {
        let guard = session.read().await;
        payload_recipients(payload)
            .into_iter()
            .filter(|address| !is_internal_address(address) && !is_own_address(&guard, address))
            .collect()
    };
    let account_id = session.read().await.user_id.to_string();
    let mut lookup = HostedLookup {
        hosted: HostedRecipients::default(),
        known: Vec::new(),
    };
    for address in candidates {
        let Some(username) = hosted_lookup_username(&address) else {
            continue;
        };
        let pin = read_recipient_pin(db, &account_id, &address)
            .map_err(|_| unreadable_pin_error(&address))?
            .pin;
        let fetched = fetch_hosted_keys(client, access_token, &username, &address).await;
        let (key_lookup, bundle) = match fetched {
            Ok(fetched) => fetched,
            Err(error) => return Err(error),
        };
        let owner_public_key = key_lookup.as_ref().and_then(|lookup| lookup.public_key.clone());
        let bundle_verified = match bundle.as_ref() {
            Some(bundle) if is_address_scoped(bundle) => {
                classify_scoped_entry(&address, bundle, None) == DirectoryTrust::Entry
            }
            Some(bundle) => owner_public_key.as_deref().is_some_and(|owner| {
                matches!(verify_bundle(bundle, Some(owner)), BundleVerdict::Verified { .. })
            }),
            None => false,
        };
        match classify_hosted(key_lookup.as_ref(), bundle_verified, pin.as_ref()) {
            HostedClass::Hosted => lookup.hosted.hosted.push(address.clone()),
            HostedClass::AsterRouted => lookup.hosted.routed_like_external.push(address.clone()),
            HostedClass::External => continue,
        }
        lookup.known.push(KnownKeys {
            address,
            username,
            bundle,
            owner_public_key,
        });
    }
    Ok(lookup)
}

async fn fetch_hosted_keys(
    client: &ApiClient,
    access_token: &str,
    username: &str,
    address: &str,
) -> Result<(Option<RecipientKeyLookup>, Option<PrekeyBundle>)> {
    let key_lookup = client
        .lookup_recipient_key(access_token, username, address)
        .await?;
    let bundle = client
        .find_prekey_bundle_in_scope(access_token, username, address, true)
        .await?;
    let has_owner_key = key_lookup
        .as_ref()
        .is_some_and(|lookup| lookup.public_key.is_some());
    if !has_owner_key && !bundle.as_ref().is_some_and(is_address_scoped) {
        return Ok((key_lookup, None));
    }
    Ok((key_lookup, bundle))
}

async fn resolve_recipient_route(
    client: &ApiClient,
    access_token: &str,
    username: &str,
    address: &str,
    first: Option<PrekeyBundle>,
    owner_public_key: Option<&str>,
    existing: Option<&RecipientPin>,
) -> Result<Evaluation> {
    match first {
        Some(bundle) if is_address_scoped(&bundle) => {
            let trust = classify_scoped_entry(address, &bundle, existing);
            if trust != DirectoryTrust::Account {
                return Ok(evaluate_address_entry(address, &bundle, trust, existing, owner_public_key));
            }
            let account_bundle = client
                .find_prekey_bundle_in_scope(access_token, username, address, false)
                .await?
                .filter(|bundle| !is_address_scoped(bundle));
            Ok(evaluate_recipient(
                address,
                account_bundle.as_ref(),
                owner_public_key,
                existing,
            ))
        }
        other => Ok(evaluate_recipient(address, other.as_ref(), owner_public_key, existing)),
    }
}

fn enforce_private_body(has_external: bool, required: bool) -> Result<()> {
    if required && has_external {
        return Err(BridgeError::RecipientKey(
            "This message has recipients outside Aster, so its contents cannot have post-quantum protection, and Aster Bridge is set to require it, so the message was not sent. To send it anyway, turn off Require post-quantum protection for Aster recipients in the Aster Bridge settings.".to_string(),
        ));
    }
    Ok(())
}

pub async fn seal_internal_body(
    payload: &mut Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    db: &Database,
    access_token: &str,
) -> Result<()> {
    let require_post_quantum = crate::config::require_post_quantum();
    seal_internal_body_with(
        payload,
        session,
        client,
        db,
        access_token,
        require_post_quantum,
        &ADDRESS_ENTRIES,
    )
    .await
}

async fn seal_internal_body_with(
    payload: &mut Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    db: &Database,
    access_token: &str,
    require_post_quantum: bool,
    directory: &AddressEntryDirectory,
) -> Result<()> {
    let self_placeholder = take_self_to_placeholder(payload);
    let mut lookup = lookup_hosted_recipients(payload, session, client, db, access_token).await?;
    if let Some(own_address) = self_placeholder.as_deref() {
        drop_sealed_self_placeholder(payload, own_address, &lookup.hosted);
    }
    let split = split_recipients_with(payload, &lookup.hosted);
    if split.internal.is_empty() {
        return Ok(());
    }
    let only_routed_like_external = split
        .internal
        .iter()
        .all(|address| lookup.hosted.routed_like_external(address));
    if only_routed_like_external && session.read().await.ratchet_keys.is_empty() {
        return Ok(());
    }
    enforce_routed_like_external(&lookup.hosted, require_post_quantum)?;
    enforce_private_body(split.has_external, require_post_quantum)?;

    let account_name = account_display_name(session).await;
    let sent_at = format_sent_at(chrono::Utc::now());
    let plaintext = sealed_send_plaintext(payload, self_placeholder.as_deref(), account_name.as_deref(), &sent_at);

    let mut sender = sender_keys(session).await?;
    if let Some(secret) = address_sender_secret(payload, session, client, access_token, directory).await? {
        sender.identity_secret_d = secret.to_vec();
        sender.signs_with_account_key = false;
    }
    let derived_sender = (!sender.signs_with_account_key)
        .then(|| payload.get("sender_email").and_then(Value::as_str))
        .flatten();
    let mut routed: Vec<RoutedRecipient> = Vec::with_capacity(split.internal.len());
    let mut pending_pins = Vec::new();

    for address in &split.internal {
        let own_copy = {
            let guard = session.read().await;
            local_self_recipient(&guard, directory, address, derived_sender)
        };
        if let Some(own_copy) = own_copy {
            routed.push(own_copy);
            continue;
        }
        let is_hosted = lookup.hosted.contains(address);
        let (username, bundle, owner_public_key) = match lookup.take(address) {
            Some(known) => (known.username, known.bundle, known.owner_public_key),
            None => {
                let username = key_lookup_username(address, &sender.username).ok_or_else(|| {
                    BridgeError::Crypto("recipient address has no username to look up".to_string())
                })?;
                let bundle = client
                    .find_prekey_bundle_in_scope(access_token, &username, address, true)
                    .await?;
                let owner_public_key = client
                    .get_recipient_public_key(access_token, &username, address)
                    .await?;
                (username, bundle, owner_public_key)
            }
        };
        let pin_read = read_recipient_pin(db, &sender.account_id, address)
            .map_err(|_| unreadable_pin_error(address))?;
        let pin_key = pin_read.id;
        let from_legacy = pin_read.from_legacy;
        let existing = pin_read.pin;
        let evaluation = resolve_recipient_route(
            client,
            access_token,
            &username,
            address,
            bundle,
            owner_public_key.as_deref(),
            existing.as_ref(),
        )
        .await?;
        let route = match evaluation.outcome {
            Ok(route) => route,
            Err(error) => {
                if let Some(pin) = &evaluation.pin {
                    let _ = db.recipient_pin_put(&pin_key, pin);
                }
                return Err(error);
            }
        };
        let hosted_now = is_hosted && !lookup.hosted.routed_like_external(address);
        match pin_to_save(evaluation.pin, existing.as_ref(), hosted_now) {
            Some(pin) => pending_pins.push((pin_key, pin)),
            None if from_legacy => {
                if let Some(pin) = existing.clone() {
                    pending_pins.push((pin_key, pin));
                }
            }
            None => {}
        }
        routed.push(RoutedRecipient {
            address: address.clone(),
            route,
            account_key: owner_public_key,
        });
    }

    enforce_post_quantum(&routed, require_post_quantum)?;
    if split.has_external {
        let everyone: Vec<&RoutedRecipient> = routed.iter().collect();
        seal_attachment_metas(payload, &sender, &everyone, None)?;
    } else {
        let (private, shared): (Vec<&RoutedRecipient>, Vec<&RoutedRecipient>) =
            routed.iter().partition(|recipient| {
                split
                    .hidden
                    .iter()
                    .any(|address| address.eq_ignore_ascii_case(&recipient.address))
            });
        seal_attachment_metas(payload, &sender, &private, Some(&shared))?;
    }
    let (envelope, hidden_bodies) = seal_shared_and_hidden(&sender, routed, &split.hidden, &plaintext)?;
    for (pin_key, pin) in &pending_pins {
        db.recipient_pin_put(pin_key, pin).map_err(|_| {
            BridgeError::RecipientKey(
                "The recipient key record could not be saved, so the message was not sent."
                    .to_string(),
            )
        })?;
    }
    apply_envelope(payload, envelope, split.has_external);
    apply_hidden_bodies(payload, hidden_bodies);
    apply_hosted_recipients(payload, &lookup.hosted);
    Ok(())
}

fn pin_to_save(
    evaluated: Option<RecipientPin>,
    existing: Option<&RecipientPin>,
    hosted: bool,
) -> Option<RecipientPin> {
    match evaluated {
        Some(pin) => Some(RecipientPin {
            hosted: pin.hosted || hosted,
            ..pin
        }),
        None => existing
            .filter(|pin| hosted && !pin.hosted)
            .map(|pin| RecipientPin {
                hosted: true,
                ..pin.clone()
            }),
    }
}

fn seal_attachment_metas(
    payload: &mut Value,
    sender: &SenderKeys,
    private: &[&RoutedRecipient],
    shared: Option<&[&RoutedRecipient]>,
) -> Result<()> {
    let Some(attachments) = payload
        .get_mut("attachments")
        .and_then(|value| value.as_array_mut())
        .filter(|list| !list.is_empty())
    else {
        return Ok(());
    };
    if private.is_empty() && shared.is_none() {
        return Ok(());
    }
    if sender.signs_with_account_key && sender.account_key.is_none() {
        return Err(no_account_key(NO_ACCOUNT_KEY_FOR_ATTACHMENTS));
    }
    let unreadable = || {
        BridgeError::Crypto("an attachment could not be prepared for Aster recipients".to_string())
    };
    for attachment in attachments.iter_mut() {
        let decoded = Zeroizing::new(
            attachment
                .get("recipient_encrypted_meta")
                .and_then(|value| value.as_str())
                .and_then(|encoded| STANDARD.decode(encoded).ok())
                .ok_or_else(unreadable)?,
        );
        let meta = std::str::from_utf8(&decoded).map_err(|_| unreadable())?;
        if !private.is_empty() {
            let mut metas = serde_json::Map::new();
            for recipient in private {
                let sealed = seal_for_account_keys(
                    sender,
                    meta,
                    &[recipient_account_key(recipient)?],
                    NO_ACCOUNT_KEY_FOR_ATTACHMENTS,
                )?;
                metas.insert(
                    recipient.address.trim().to_lowercase(),
                    json!(STANDARD.encode(sealed.as_bytes())),
                );
            }
            attachment["recipient_metas"] = Value::Object(metas);
        }
        if let Some(shared) = shared {
            let keys = shared
                .iter()
                .map(|recipient| recipient_account_key(recipient))
                .collect::<Result<Vec<&str>>>()?;
            let sealed = seal_for_account_keys(sender, meta, &keys, NO_ACCOUNT_KEY_FOR_ATTACHMENTS)?;
            attachment["recipient_encrypted_meta"] = json!(STANDARD.encode(sealed.as_bytes()));
        }
    }
    Ok(())
}

fn recipient_account_key<'a>(recipient: &'a RoutedRecipient) -> Result<&'a str> {
    recipient.account_key.as_deref().ok_or_else(|| {
        BridgeError::RecipientKey(format!(
            "{} has no published encryption keys, so the message was not sent.",
            recipient.address
        ))
    })
}

fn seal_shared_and_hidden(
    sender: &SenderKeys,
    routed: Vec<RoutedRecipient>,
    hidden: &[String],
    plaintext: &str,
) -> Result<(String, Vec<(String, String)>)> {
    if hidden.is_empty() {
        return Ok((seal_routed(sender, &routed, plaintext)?, Vec::new()));
    }
    let (hidden_routed, shared_routed): (Vec<RoutedRecipient>, Vec<RoutedRecipient>) =
        routed.into_iter().partition(|recipient| {
            hidden
                .iter()
                .any(|address| address.eq_ignore_ascii_case(&recipient.address))
        });
    let shared = seal_routed(sender, &shared_routed, plaintext)?;
    let mut hidden_bodies = Vec::with_capacity(hidden_routed.len());
    for recipient in hidden_routed {
        let address = recipient.address.clone();
        let body = seal_routed(sender, std::slice::from_ref(&recipient), plaintext)?;
        hidden_bodies.push((address, body));
    }
    Ok((shared, hidden_bodies))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::recipient_trust::pin_id;
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

    const TEST_SENT_AT: &str = "2026-11-12T10:15:00.000Z";

    #[test]
    fn the_sealed_plaintext_carries_the_message_details_without_hidden_recipients() {
        let mut payload = payload_with(vec!["bo@astermail.org", "cy@astermail.org"]);
        payload["cc"] = json!(["di@astermail.org"]);
        payload["bcc"] = json!(["hidden@astermail.org"]);
        payload["sender_display_name"] = json!("Ana Real");
        assert_eq!(
            sealed_plaintext(&payload, Some("Account Name"), TEST_SENT_AT),
            "\u{1}ASTER_BUNDLE_V2\u{1}{\"s\":\"Hi\",\"b\":\"<p>hello</p>\",\"details\":{\"v\":1,\"from_name\":\"Ana Real\",\"to\":[{\"name\":\"\",\"email\":\"bo@astermail.org\"},{\"name\":\"\",\"email\":\"cy@astermail.org\"}],\"cc\":[{\"name\":\"\",\"email\":\"di@astermail.org\"}],\"sent_at\":\"2026-11-12T10:15:00.000Z\"}}"
        );
        assert!(!sealed_plaintext(&payload, None, TEST_SENT_AT).contains("hidden@astermail.org"));

        let opened = crate::crypto::ratchet_recovery::extract_subject_bundle(&sealed_plaintext(&payload, None, TEST_SENT_AT));
        let details = opened.details.expect("details");
        assert_eq!(details.from_name, "Ana Real");
        assert_eq!(details.to.len(), 2);
        assert_eq!(details.cc.len(), 1);
        assert_eq!(details.sent_at, TEST_SENT_AT);
    }

    #[test]
    fn the_self_placeholder_never_appears_as_a_sealed_recipient() {
        let mut payload = payload_with(vec!["me@mydomain.example"]);
        payload["bcc"] = json!(["bob@custom.example", "stranger@example.com"]);
        let sealed = sealed_send_plaintext(&mut payload, Some("me@mydomain.example"), None, TEST_SENT_AT);
        let details = crate::crypto::ratchet_recovery::extract_subject_bundle(&sealed).details.expect("details");
        assert!(details.to.is_empty());
        assert!(!sealed.contains("stranger@example.com"));
        assert_eq!(payload["to"], json!(["me@mydomain.example"]));

        let mut addressed = payload_with(vec!["me@mydomain.example"]);
        let kept = sealed_send_plaintext(&mut addressed, None, None, TEST_SENT_AT);
        let details = crate::crypto::ratchet_recovery::extract_subject_bundle(&kept).details.expect("details");
        assert_eq!(details.to[0].email, "me@mydomain.example");
    }

    #[test]
    fn the_sealed_sender_name_follows_the_sending_identity() {
        let name_of = |payload: &Value, account: Option<&str>| payload_details(payload, account, TEST_SENT_AT).from_name;
        let mut payload = payload_with(vec!["bo@astermail.org"]);
        payload["cc"] = Value::Null;
        assert_eq!(name_of(&payload, Some("Account Name")), "Account Name");
        assert_eq!(name_of(&payload, None), "");
        assert!(payload_details(&payload, None, TEST_SENT_AT).cc.is_empty());
        payload["sender_alias_hash"] = json!("aGFzaA==");
        assert_eq!(name_of(&payload, Some("Account Name")), "");
        payload["sender_display_name"] = json!("Sales");
        assert_eq!(name_of(&payload, Some("Account Name")), "Sales");
    }

    #[test]
    fn the_sealed_plaintext_lists_attachments_only_when_there_are_some() {
        let mut payload = payload_with(vec!["user@astermail.org"]);
        let without = sealed_plaintext(&payload, None, TEST_SENT_AT);
        assert!(!without.contains("attachment_manifest"));
        let plain = crate::crypto::ratchet_recovery::extract_subject_bundle(&without);
        assert_eq!(plain.subject.as_deref(), Some("Hi"));
        assert_eq!(plain.body, "<p>hello</p>");
        assert_eq!(plain.attachment_manifest, None);

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
        let opened = crate::crypto::ratchet_recovery::extract_subject_bundle(&sealed_plaintext(&payload, None, TEST_SENT_AT));
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
    fn required_post_quantum_fails_closed_when_the_body_would_be_readable() {
        assert!(matches!(
            enforce_private_body(true, true),
            Err(BridgeError::RecipientKey(_))
        ));
        assert!(enforce_private_body(true, false).is_ok());
        assert!(enforce_private_body(false, true).is_ok());
        assert!(enforce_private_body(false, false).is_ok());
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
            ec_one_time_prekey: None,
            address_scoped: None,
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
            signs_with_account_key: true,
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
    fn unsigned_post_quantum_keys_do_not_meet_the_post_quantum_requirement() {
        use crate::crypto::recipient_trust::tests::{owner, sign};

        let account = owner("user");
        let mut bob = recipient();
        let (_, encap) = MlKem768::generate(&mut OsRng);
        bob.bundle.pq_prekey = Some(crate::api_client::BundlePqPrekey {
            key_id: 9,
            public_key: STANDARD.encode(encap.as_bytes()),
        });
        let text = format!(
            "aster-ratchet-prekey-v1:{}.{}",
            bob.bundle.kem_identity_key, bob.bundle.signed_prekey
        );
        sign(&mut bob.bundle, &account, &text);

        let weak = routed("bob@astermail.org", Some(&bob.bundle), &account);
        assert!(matches!(&weak.route, SendRoute::Ratchet(target) if target.pq_target.is_some()));
        assert!(!has_post_quantum_protection(&weak.route));
        assert!(enforce_post_quantum(std::slice::from_ref(&weak), false).is_ok());
        assert!(matches!(
            enforce_post_quantum(&[weak], true),
            Err(BridgeError::RecipientKey(_))
        ));
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

    fn offered_one_time_prekey(key_id: u32, one_time: &SecretKey) -> Option<Value> {
        Some(json!({
            "key_id": key_id,
            "public_key": STANDARD
                .encode(one_time.public_key().to_encoded_point(false).as_bytes()),
        }))
    }

    #[test]
    fn the_one_time_fields_are_written_only_for_the_one_time_bound_handshake() {
        use crate::crypto::ratchet::signed_prekey_id;
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let me = owner("sender");
        let one_time = SecretKey::random(&mut OsRng);

        for advertised in [None, Some(1i16), Some(2), Some(3)] {
            let mut bob = recipient();
            bob.bundle.x3dh_max_version = advertised;
            bob.bundle.ec_one_time_prekey = offered_one_time_prekey(41, &one_time);
            sign_v2(&mut bob.bundle, &account);
            let envelope = seal_routed(
                &sender(&me),
                &[routed("user@astermail.org", Some(&bob.bundle), &account)],
                "below the one-time bound handshake",
            )
            .expect("sealed");
            let parsed: Value = serde_json::from_str(&envelope).expect("envelope json");
            let entry = &parsed["recipients"]["user@astermail.org"];
            assert!(entry.get("opk_id").is_none(), "{:?}", advertised);
            assert!(entry.get("spk_id").is_none(), "{:?}", advertised);
            match advertised.filter(|version| *version > 1) {
                Some(version) => assert_eq!(entry["x3dh_v"], json!(version)),
                None => assert!(entry.get("x3dh_v").is_none()),
            }
            let message = parse_recipient_message(&parsed, "user@astermail.org").expect("parsed");
            assert_eq!(message.opk_id, None);
            assert_eq!(message.spk_id, None);
        }

        let mut bob = recipient();
        bob.bundle.x3dh_max_version = Some(4);
        sign_v2(&mut bob.bundle, &account);
        let envelope = seal_routed(
            &sender(&me),
            &[routed("user@astermail.org", Some(&bob.bundle), &account)],
            "no one-time prekey offered",
        )
        .expect("sealed");
        let parsed: Value = serde_json::from_str(&envelope).expect("envelope json");
        let entry = &parsed["recipients"]["user@astermail.org"];
        assert_eq!(entry["x3dh_v"], json!(3));
        assert!(entry.get("opk_id").is_none());
        assert!(entry.get("spk_id").is_none());

        let plaintext = "bound to a one-time prekey";
        let mut bob = recipient();
        bob.bundle.x3dh_max_version = Some(4);
        bob.bundle.ec_one_time_prekey = offered_one_time_prekey(41, &one_time);
        sign_v2(&mut bob.bundle, &account);
        let envelope = seal_routed(
            &sender(&me),
            &[routed("user@astermail.org", Some(&bob.bundle), &account)],
            plaintext,
        )
        .expect("sealed");
        let parsed: Value = serde_json::from_str(&envelope).expect("envelope json");
        let entry = &parsed["recipients"]["user@astermail.org"];
        assert_eq!(entry["x3dh_v"], json!(4));
        assert_eq!(entry["opk_id"], json!(41));
        assert_eq!(entry["spk_id"], json!(signed_prekey_id(&bob.prekey_public)));

        let mut message = parse_recipient_message(&parsed, "user@astermail.org").expect("parsed");
        assert_eq!(message.x3dh_version, Some(4));
        assert_eq!(message.opk_id, Some(41));
        message.pq_secret = Some(bob.pq_secret.clone());
        let keys = RatchetReceiverKeys {
            identity_secret_d: bob.identity.to_bytes().to_vec(),
            signed_prekey_secret_d: bob.prekey.to_bytes().to_vec(),
            signed_prekey_public: bob.prekey_public.clone(),
        };
        assert!(decrypt_bootstrap(&keys, &message).is_err());
        message.opk_secret = Some(SecretKey::random(&mut OsRng).to_bytes().to_vec());
        assert!(decrypt_bootstrap(&keys, &message).is_err());
        message.opk_secret = Some(one_time.to_bytes().to_vec());
        assert_eq!(decrypt_bootstrap(&keys, &message).expect("decrypted"), plaintext);
    }

    #[test]
    fn an_unusable_one_time_prekey_falls_back_to_the_key_bound_handshake() {
        use crate::crypto::recipient_trust::tests::owner;
        use crate::crypto::recipient_trust::OneTimePrekeyTarget;

        let account = owner("user");
        let one_time = SecretKey::random(&mut OsRng);
        let mut bob = recipient();
        bob.bundle.x3dh_max_version = Some(4);
        bob.bundle.ec_one_time_prekey = offered_one_time_prekey(41, &one_time);
        sign_v2(&mut bob.bundle, &account);
        let SendRoute::Ratchet(mut target) =
            routed("user@astermail.org", Some(&bob.bundle), &account).route
        else {
            panic!("expected the ratchet route");
        };
        assert_eq!(target.x3dh_version(), 4);
        let sender_secret = SecretKey::random(&mut OsRng).to_bytes().to_vec();

        let bound = seal_for_recipient(&sender_secret, &target, "bound").expect("sealed");
        assert_eq!(bound.x3dh_version, Some(4));
        assert_eq!(bound.opk_id, Some(41));

        for unusable in [
            OneTimePrekeyTarget {
                key_id: 41,
                public_key: vec![0x04; 65],
            },
            OneTimePrekeyTarget {
                key_id: 0,
                public_key: one_time.public_key().to_encoded_point(false).as_bytes().to_vec(),
            },
        ] {
            target.one_time_prekey = Some(unusable);
            let message = seal_for_recipient(&sender_secret, &target, "fallback").expect("sealed");
            assert_eq!(message.x3dh_version, Some(3));
            assert_eq!(message.opk_id, None);
            assert_eq!(message.spk_id, None);
            let entry = recipient_entry(&message);
            assert_eq!(entry["x3dh_v"], json!(3));
            assert!(entry.get("opk_id").is_none());
            assert!(entry.get("spk_id").is_none());
        }
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
    fn hidden_recipients_are_internal_bcc_addresses_not_also_visible() {
        let payload = json!({
            "to": ["a@astermail.org", "out@example.com"],
            "cc": ["B@aster.cx"],
            "bcc": ["hidden@astermail.org", "b@aster.cx", "secret@example.com", " Other@Aster.cx "],
        });
        let split = split_recipients(&payload);
        assert!(split.has_external);
        assert_eq!(
            split.internal,
            vec![
                "a@astermail.org".to_string(),
                "B@aster.cx".to_string(),
                "hidden@astermail.org".to_string(),
                "Other@Aster.cx".to_string(),
            ]
        );
        assert_eq!(
            split.hidden,
            vec!["hidden@astermail.org".to_string(), "Other@Aster.cx".to_string()]
        );
    }

    #[test]
    fn hidden_bodies_are_keyed_by_lowercase_address_and_skipped_when_empty() {
        let mut payload = payload_with(vec!["a@astermail.org"]);
        apply_hidden_bodies(&mut payload, Vec::new());
        assert!(payload.get("recipient_bodies").is_none());

        apply_hidden_bodies(&mut payload, vec![("Hidden@Aster.cx".to_string(), "SEALED".to_string())]);
        assert_eq!(payload["recipient_bodies"], json!({"hidden@aster.cx": "SEALED"}));
    }

    #[test]
    fn a_hidden_bcc_gets_its_own_copy_that_the_visible_recipients_cannot_open() {
        use crate::crypto::recipient_trust::tests::owner;

        let visible_account = owner("visible");
        let hidden_account = owner("hidden");
        let me = owner("sender");

        let (shared, hidden_bodies) = seal_shared_and_hidden(
            &sender(&me),
            vec![
                routed("visible@astermail.org", None, &visible_account),
                routed("hidden@astermail.org", None, &hidden_account),
            ],
            &["hidden@astermail.org".to_string()],
            "for everyone",
        )
        .expect("sealed");

        assert_eq!(open_with_account_key(&shared, &visible_account, &me), "for everyone");
        assert!(aster_crypto::decrypt_and_verify_with_passphrase(
            shared.as_bytes(),
            &[&hidden_account.keypair],
            &[&me.keypair.public_key()],
            "",
        )
        .is_err());

        assert_eq!(hidden_bodies.len(), 1);
        let (address, hidden) = &hidden_bodies[0];
        assert_eq!(address, "hidden@astermail.org");
        assert_eq!(open_with_account_key(hidden, &hidden_account, &me), "for everyone");
        assert!(aster_crypto::decrypt_and_verify_with_passphrase(
            hidden.as_bytes(),
            &[&visible_account.keypair],
            &[&me.keypair.public_key()],
            "",
        )
        .is_err());
    }

    #[test]
    fn a_ratchet_envelope_never_names_a_hidden_bcc() {
        use crate::crypto::recipient_trust::tests::owner;

        let visible_account = owner("visible");
        let hidden_account = owner("hidden");
        let me = owner("sender");
        let mut visible = recipient();
        sign_v2(&mut visible.bundle, &visible_account);
        let mut hidden = recipient();
        sign_v2(&mut hidden.bundle, &hidden_account);

        let (shared, hidden_bodies) = seal_shared_and_hidden(
            &sender(&me),
            vec![
                routed("visible@astermail.org", Some(&visible.bundle), &visible_account),
                routed("hidden@astermail.org", Some(&hidden.bundle), &hidden_account),
            ],
            &["hidden@astermail.org".to_string()],
            "ratchet",
        )
        .expect("sealed");

        let parsed: Value = serde_json::from_str(&shared).expect("shared envelope");
        let names: Vec<&String> = parsed["recipients"].as_object().unwrap().keys().collect();
        assert_eq!(names, vec!["visible@astermail.org"]);
        assert!(!shared.contains("hidden@astermail.org"));

        let (_, hidden_copy) = &hidden_bodies[0];
        let hidden_parsed: Value = serde_json::from_str(hidden_copy).expect("hidden envelope");
        let hidden_names: Vec<&String> =
            hidden_parsed["recipients"].as_object().unwrap().keys().collect();
        assert_eq!(hidden_names, vec!["hidden@astermail.org"]);
        let mut message = parse_recipient_message(&hidden_parsed, "hidden@astermail.org").expect("parsed");
        message.pq_secret = Some(hidden.pq_secret.clone());
        let keys = RatchetReceiverKeys {
            identity_secret_d: hidden.identity.to_bytes().to_vec(),
            signed_prekey_secret_d: hidden.prekey.to_bytes().to_vec(),
            signed_prekey_public: hidden.prekey_public.clone(),
        };
        assert_eq!(decrypt_bootstrap(&keys, &message).expect("decrypted"), "ratchet");
    }

    #[test]
    fn only_hidden_aster_recipients_seal_the_shared_copy_to_the_sender_alone() {
        use crate::crypto::recipient_trust::tests::owner;

        let hidden_account = owner("hidden");
        let me = owner("sender");

        let (shared, hidden_bodies) = seal_shared_and_hidden(
            &sender(&me),
            vec![routed("hidden@astermail.org", None, &hidden_account)],
            &["hidden@astermail.org".to_string()],
            "bcc only",
        )
        .expect("sealed");

        assert_eq!(open_with_account_key(&shared, &me, &me), "bcc only");
        assert!(aster_crypto::decrypt_and_verify_with_passphrase(
            shared.as_bytes(),
            &[&hidden_account.keypair],
            &[&me.keypair.public_key()],
            "",
        )
        .is_err());
        assert_eq!(open_with_account_key(&hidden_bodies[0].1, &hidden_account, &me), "bcc only");
    }

    fn payload_with_attachment(to: Vec<&str>) -> Value {
        let mut payload = payload_with(to);
        let sealed = crate::crypto::attachment::seal_send_attachments(
            &[crate::crypto::attachment::OutgoingAttachment {
                name: "plan.pdf".to_string(),
                mime_type: "application/pdf".to_string(),
                content_id: None,
                is_inline: false,
                data: b"plan".to_vec(),
            }],
            b"pass",
        )
        .unwrap();
        payload["attachments"] = Value::Array(sealed);
        payload
    }

    fn opened_meta(
        encoded: &Value,
        reader: &crate::crypto::recipient_trust::tests::Owner,
        signer: &crate::crypto::recipient_trust::tests::Owner,
    ) -> Option<Value> {
        let armored = String::from_utf8(STANDARD.decode(encoded.as_str()?).ok()?).ok()?;
        let opened = aster_crypto::decrypt_and_verify_with_passphrase(
            armored.as_bytes(),
            &[&reader.keypair],
            &[&signer.keypair.public_key()],
            "",
        )
        .ok()?;
        serde_json::from_slice(&opened).ok()
    }

    #[test]
    fn mixed_attachments_get_a_sealed_key_copy_for_each_aster_recipient_alone() {
        use crate::crypto::recipient_trust::tests::owner;

        let visible_account = owner("visible");
        let hidden_account = owner("hidden");
        let me = owner("sender");
        let mut payload = payload_with_attachment(vec!["Visible@AsterMail.org", "out@example.com"]);
        payload["bcc"] = json!(["hidden@aster.cx"]);
        let outside_before = payload["attachments"][0]["recipient_encrypted_meta"].clone();
        let manifest_before = sealed_plaintext(&payload, None, TEST_SENT_AT);

        let visible = routed("Visible@AsterMail.org", None, &visible_account);
        let hidden = routed("hidden@aster.cx", None, &hidden_account);
        seal_attachment_metas(&mut payload, &sender(&me), &[&visible, &hidden], None)
            .expect("sealed metas");

        let attachment = &payload["attachments"][0];
        assert_eq!(attachment["recipient_encrypted_meta"], outside_before);
        let outside: Value = serde_json::from_slice(
            &STANDARD.decode(outside_before.as_str().unwrap()).unwrap(),
        )
        .unwrap();

        let metas = attachment["recipient_metas"].as_object().expect("metas");
        let mut names: Vec<&String> = metas.keys().collect();
        names.sort();
        assert_eq!(names, vec!["hidden@aster.cx", "visible@astermail.org"]);
        assert!(!metas.contains_key("out@example.com"));

        for (address, owner_key, other) in [
            ("visible@astermail.org", &visible_account, &hidden_account),
            ("hidden@aster.cx", &hidden_account, &visible_account),
        ] {
            let encoded = &metas[address];
            let raw = STANDARD.decode(encoded.as_str().unwrap()).unwrap();
            assert!(raw.starts_with(b"-----BEGIN PGP MESSAGE"));
            assert!(!String::from_utf8_lossy(&raw).contains("session_key"));
            let opened = opened_meta(encoded, owner_key, &me).expect("own copy opens");
            assert_eq!(opened["session_key"], outside["session_key"]);
            assert_eq!(opened["filename"], json!("plan.pdf"));
            assert!(opened_meta(encoded, other, &me).is_none());
        }

        assert_eq!(sealed_plaintext(&payload, None, TEST_SENT_AT), manifest_before);
    }

    #[test]
    fn sealing_attachment_metas_skips_sends_without_attachments() {
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let me = owner("sender");
        let user = routed("user@astermail.org", None, &account);
        let mut payload = payload_with(vec!["user@astermail.org", "out@example.com"]);
        let before = payload.clone();
        seal_attachment_metas(&mut payload, &sender(&me), &[&user], None).expect("no-op");
        seal_attachment_metas(&mut payload, &sender(&me), &[], Some(&[&user])).expect("no-op");
        assert_eq!(payload, before);

        payload["attachments"] = json!([]);
        let before = payload.clone();
        seal_attachment_metas(&mut payload, &sender(&me), &[&user], Some(&[&user])).expect("no-op");
        assert_eq!(payload, before);
    }

    #[test]
    fn aster_only_attachments_never_hand_the_server_a_readable_key() {
        use crate::crypto::recipient_trust::tests::owner;

        let visible_account = owner("visible");
        let hidden_account = owner("hidden");
        let me = owner("sender");
        let mut payload = payload_with_attachment(vec!["visible@astermail.org"]);
        payload["bcc"] = json!(["Hidden@Aster.cx"]);
        let plain_meta: Value = serde_json::from_slice(
            &STANDARD
                .decode(payload["attachments"][0]["recipient_encrypted_meta"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let manifest_before = sealed_plaintext(&payload, None, TEST_SENT_AT);

        let visible = routed("visible@astermail.org", None, &visible_account);
        let hidden = routed("Hidden@Aster.cx", None, &hidden_account);
        seal_attachment_metas(&mut payload, &sender(&me), &[&hidden], Some(&[&visible]))
            .expect("sealed");

        let attachment = &payload["attachments"][0];
        let shared = &attachment["recipient_encrypted_meta"];
        let raw = STANDARD.decode(shared.as_str().unwrap()).unwrap();
        assert!(raw.starts_with(b"-----BEGIN PGP MESSAGE"));
        assert!(!String::from_utf8_lossy(&raw).contains("session_key"));
        assert_eq!(
            opened_meta(shared, &visible_account, &me).expect("visible opens")["session_key"],
            plain_meta["session_key"]
        );
        assert!(opened_meta(shared, &me, &me).is_some());
        assert!(opened_meta(shared, &hidden_account, &me).is_none());

        let metas = attachment["recipient_metas"].as_object().expect("hidden copy");
        assert_eq!(metas.keys().collect::<Vec<_>>(), vec!["hidden@aster.cx"]);
        assert_eq!(
            opened_meta(&metas["hidden@aster.cx"], &hidden_account, &me).expect("hidden opens")
                ["session_key"],
            plain_meta["session_key"]
        );
        assert!(opened_meta(&metas["hidden@aster.cx"], &visible_account, &me).is_none());

        let mut no_hidden = payload_with_attachment(vec!["visible@astermail.org"]);
        seal_attachment_metas(&mut no_hidden, &sender(&me), &[], Some(&[&visible])).expect("sealed");
        assert!(no_hidden["attachments"][0].get("recipient_metas").is_none());
        assert!(opened_meta(
            &no_hidden["attachments"][0]["recipient_encrypted_meta"],
            &visible_account,
            &me
        )
        .is_some());

        let mut only_hidden = payload_with_attachment(vec![]);
        only_hidden["bcc"] = json!(["Hidden@Aster.cx"]);
        seal_attachment_metas(&mut only_hidden, &sender(&me), &[&hidden], Some(&[])).expect("sealed");
        let shared = &only_hidden["attachments"][0]["recipient_encrypted_meta"];
        assert!(opened_meta(shared, &me, &me).is_some());
        assert!(opened_meta(shared, &hidden_account, &me).is_none());
        assert!(manifest_before.contains("plan.pdf"));
    }

    #[test]
    fn sealing_attachment_metas_refuses_instead_of_sending_a_readable_key_copy() {
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let me = owner("sender");

        let user = routed("user@astermail.org", None, &account);
        let mut keyless = routed("user@astermail.org", None, &account);
        keyless.account_key = None;
        let mut payload = payload_with_attachment(vec!["user@astermail.org", "out@example.com"]);
        assert!(matches!(
            seal_attachment_metas(&mut payload, &sender(&me), &[&keyless], None),
            Err(BridgeError::RecipientKey(message)) if message.starts_with("user@astermail.org")
        ));
        assert!(payload["attachments"][0].get("recipient_metas").is_none());

        let mut payload = payload_with_attachment(vec!["user@astermail.org"]);
        let before = payload.clone();
        assert!(matches!(
            seal_attachment_metas(&mut payload, &sender(&me), &[], Some(&[&keyless])),
            Err(BridgeError::RecipientKey(_))
        ));
        assert_eq!(payload, before);

        let mut no_sender_key = sender(&me);
        no_sender_key.account_key = None;
        for shared in [None, Some(&[&user][..])] {
            let mut payload = payload_with_attachment(vec!["user@astermail.org", "out@example.com"]);
            assert!(matches!(
                seal_attachment_metas(&mut payload, &no_sender_key, &[&user], shared),
                Err(BridgeError::Crypto(_))
            ));
        }

        let mut payload = payload_with_attachment(vec!["user@astermail.org", "out@example.com"]);
        payload["attachments"][0]["recipient_encrypted_meta"] = json!("not base64 !!");
        assert!(matches!(
            seal_attachment_metas(&mut payload, &sender(&me), &[&user], None),
            Err(BridgeError::Crypto(_))
        ));
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

    fn opened_by(armored: &str, reader: &crate::crypto::recipient_trust::tests::Owner) -> bool {
        aster_crypto::decrypt_message(armored.as_bytes(), &[&reader.keypair]).is_ok()
    }

    fn signed_by(
        armored: &str,
        reader: &crate::crypto::recipient_trust::tests::Owner,
        signer: &crate::crypto::recipient_trust::tests::Owner,
    ) -> bool {
        aster_crypto::decrypt_and_verify_with_passphrase(
            armored.as_bytes(),
            &[&reader.keypair],
            &[&signer.keypair.public_key()],
            "",
        )
        .is_ok()
    }

    fn alias_sender(account: &crate::crypto::recipient_trust::tests::Owner) -> SenderKeys {
        SenderKeys {
            signs_with_account_key: false,
            ..sender(account)
        }
    }

    #[test]
    fn the_account_key_fallback_signs_for_the_primary_address_and_not_for_an_alias() {
        use crate::crypto::recipient_trust::tests::owner;

        let account = owner("user");
        let me = owner("sender");
        let recipients = [routed("user@astermail.org", None, &account)];

        let primary = seal_routed(&sender(&me), &recipients, "hello").unwrap();
        assert!(signed_by(&primary, &account, &me));
        assert!(opened_by(&primary, &me));

        let alias = seal_routed(&alias_sender(&me), &recipients, "hello").unwrap();
        assert_eq!(
            aster_crypto::decrypt_message(alias.as_bytes(), &[&account.keypair]).unwrap(),
            b"hello"
        );
        assert!(!signed_by(&alias, &account, &me));
        assert!(!opened_by(&alias, &me));

        let mut keyless_alias = alias_sender(&me);
        keyless_alias.account_key = None;
        assert!(seal_routed(&keyless_alias, &recipients, "hello").is_ok());
    }

    #[test]
    fn attachment_metas_are_signed_for_the_primary_address_and_not_for_an_alias() {
        use crate::crypto::recipient_trust::tests::owner;

        let visible_account = owner("visible");
        let hidden_account = owner("hidden");
        let me = owner("sender");
        let visible = routed("visible@astermail.org", None, &visible_account);
        let hidden = routed("hidden@aster.cx", None, &hidden_account);

        for (keys, signs) in [(sender(&me), true), (alias_sender(&me), false)] {
            let mut payload = payload_with_attachment(vec!["visible@astermail.org"]);
            payload["bcc"] = json!(["hidden@aster.cx"]);
            seal_attachment_metas(&mut payload, &keys, &[&hidden], Some(&[&visible])).expect("sealed");
            let attachment = &payload["attachments"][0];
            let private = String::from_utf8(
                STANDARD
                    .decode(attachment["recipient_metas"]["hidden@aster.cx"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            let shared = String::from_utf8(
                STANDARD
                    .decode(attachment["recipient_encrypted_meta"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert!(opened_by(&private, &hidden_account));
            assert!(opened_by(&shared, &visible_account));
            assert!(!opened_by(&shared, &hidden_account));
            assert_eq!(signed_by(&private, &hidden_account, &me), signs);
            assert_eq!(signed_by(&shared, &visible_account, &me), signs);
            assert_eq!(opened_by(&private, &me), signs);
            assert_eq!(opened_by(&shared, &me), signs);
        }

        let mut keyless_alias = alias_sender(&me);
        keyless_alias.account_key = None;
        let mut payload = payload_with_attachment(vec!["visible@astermail.org"]);
        assert!(seal_attachment_metas(&mut payload, &keyless_alias, &[&visible], None).is_ok());
    }

    fn lookup(public_key: Option<&str>, internal: bool) -> RecipientKeyLookup {
        RecipientKeyLookup {
            public_key: public_key.map(str::to_string),
            internal,
        }
    }

    #[test]
    fn hosted_recipients_are_classified_from_the_flag_the_pin_and_a_verified_bundle() {
        let hosted_pin = RecipientPin {
            hosted: true,
            ..RecipientPin::default()
        };
        let plain_pin = RecipientPin::default();
        let flagged = lookup(Some("key"), true);
        let unflagged = lookup(Some("key"), false);

        assert_eq!(classify_hosted(Some(&flagged), false, None), HostedClass::Hosted);
        assert_eq!(classify_hosted(Some(&unflagged), false, Some(&hosted_pin)), HostedClass::Hosted);
        assert_eq!(classify_hosted(None, false, Some(&hosted_pin)), HostedClass::Hosted);
        assert_eq!(classify_hosted(Some(&unflagged), true, None), HostedClass::AsterRouted);
        assert_eq!(classify_hosted(None, false, Some(&plain_pin)), HostedClass::AsterRouted);
        assert_eq!(classify_hosted(Some(&unflagged), false, None), HostedClass::External);
        assert_eq!(classify_hosted(None, false, None), HostedClass::External);
    }

    #[test]
    fn hosted_lookups_use_the_web_username_shape() {
        assert_eq!(hosted_lookup_username("bob@custom.example").as_deref(), Some("bob"));
        assert_eq!(hosted_lookup_username("bob+news@custom.example").as_deref(), Some("bob"));
        assert_eq!(hosted_lookup_username("b.o_b-1@custom.example").as_deref(), Some("b.o_b-1"));
        assert_eq!(hosted_lookup_username("bob@localhost"), None);
        assert_eq!(hosted_lookup_username("bo b@custom.example"), None);
        assert_eq!(hosted_lookup_username("+tag@custom.example"), None);
        assert_eq!(hosted_lookup_username(&format!("{}@custom.example", "a".repeat(65))), None);
        assert_eq!(
            key_lookup_username("bob+news@astermail.org", "alice").as_deref(),
            Some("bob")
        );
    }

    #[test]
    fn hosted_recipients_join_the_sealed_copy_and_routed_ones_keep_a_readable_body() {
        let payload = payload_with(vec!["bob@custom.example", "carol@alias.example"]);
        let hosted = HostedRecipients {
            hosted: vec!["bob@custom.example".to_string()],
            routed_like_external: Vec::new(),
        };
        let split = split_recipients_with(&payload, &hosted);
        assert_eq!(split.internal, vec!["bob@custom.example".to_string()]);
        assert!(split.has_external);

        let only_hosted = payload_with(vec!["bob@custom.example", "a@astermail.org"]);
        let split = split_recipients_with(&only_hosted, &hosted);
        assert_eq!(split.internal.len(), 2);
        assert!(!split.has_external);

        let routed = HostedRecipients {
            hosted: Vec::new(),
            routed_like_external: vec!["carol@alias.example".to_string()],
        };
        let only_routed = payload_with(vec!["carol@alias.example"]);
        let split = split_recipients_with(&only_routed, &routed);
        assert_eq!(split.internal, vec!["carol@alias.example".to_string()]);
        assert!(split.has_external);

        let mut listed = payload_with(vec!["bob@custom.example"]);
        apply_hosted_recipients(&mut listed, &HostedRecipients::default());
        assert!(listed.get("hosted_recipients").is_none());
        apply_hosted_recipients(&mut listed, &hosted);
        assert_eq!(listed["hosted_recipients"], json!(["bob@custom.example"]));
    }

    #[test]
    fn requiring_post_quantum_refuses_an_aster_address_routed_like_an_outside_one() {
        let routed = HostedRecipients {
            hosted: Vec::new(),
            routed_like_external: vec!["carol@alias.example".to_string()],
        };
        assert!(enforce_routed_like_external(&routed, false).is_ok());
        assert!(enforce_routed_like_external(&HostedRecipients::default(), true).is_ok());
        match enforce_routed_like_external(&routed, true) {
            Err(BridgeError::RecipientKey(message)) => {
                assert!(message.starts_with("carol@alias.example uses Aster"));
            }
            other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn a_hosted_pin_is_saved_once_and_never_cleared() {
        let existing = RecipientPin {
            owner_fingerprint: "aa".to_string(),
            ..RecipientPin::default()
        };
        let saved = pin_to_save(None, Some(&existing), true).expect("marked hosted");
        assert!(saved.hosted);
        assert_eq!(saved.owner_fingerprint, "aa");
        assert!(pin_to_save(None, Some(&saved), true).is_none());
        assert!(pin_to_save(None, Some(&existing), false).is_none());
        let evaluated = RecipientPin {
            hosted: true,
            ..RecipientPin::default()
        };
        assert!(pin_to_save(Some(evaluated), None, false).unwrap().hosted);
        assert!(!pin_to_save(Some(RecipientPin::default()), None, false).unwrap().hosted);
    }

    const UNAVAILABLE: &str = "unavailable";

    struct FakeDirectory {
        keys: std::sync::Mutex<std::collections::HashMap<String, Value>>,
        bundles: std::sync::Mutex<std::collections::HashMap<String, Value>>,
        scoped: std::sync::Mutex<std::collections::HashMap<String, Value>>,
        entry_status: std::sync::atomic::AtomicU16,
        entries: std::sync::Mutex<Vec<Value>>,
    }

    impl FakeDirectory {
        fn set_key(&self, address: &str, value: Option<Value>) {
            let mut keys = self.keys.lock().unwrap();
            match value {
                Some(value) => keys.insert(address.to_string(), value),
                None => keys.remove(address),
            };
        }

        fn set_scoped(&self, address: &str, value: Option<Value>) {
            let mut scoped = self.scoped.lock().unwrap();
            match value {
                Some(value) => scoped.insert(address.to_string(), value),
                None => scoped.remove(address),
            };
        }

        fn set_bundle(&self, address: &str, value: Option<Value>) {
            let mut bundles = self.bundles.lock().unwrap();
            match value {
                Some(value) => bundles.insert(address.to_string(), value),
                None => bundles.remove(address),
            };
        }
    }

    async fn start_directory() -> (String, Arc<FakeDirectory>) {
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use std::collections::HashMap;

        let directory = Arc::new(FakeDirectory {
            keys: std::sync::Mutex::new(HashMap::new()),
            bundles: std::sync::Mutex::new(HashMap::new()),
            scoped: std::sync::Mutex::new(HashMap::new()),
            entry_status: std::sync::atomic::AtomicU16::new(404),
            entries: std::sync::Mutex::new(Vec::new()),
        });
        let (keys, bundles, entries) = (directory.clone(), directory.clone(), directory.clone());
        let found = |value: Option<Value>| match value {
            Some(Value::String(status)) if status == UNAVAILABLE => {
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
            Some(value) => axum::Json(value).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
        let app = axum::Router::new()
            .route(
                "/crypto/v1/keys/public/:username",
                axum::routing::get(move |Query(query): Query<HashMap<String, String>>| {
                    let keys = keys.clone();
                    async move {
                        let email = query.get("email").cloned().unwrap_or_default();
                        let value = keys.keys.lock().unwrap().get(&email).cloned();
                        found(value)
                    }
                }),
            )
            .route(
                "/crypto/v1/ratchet/prekey-bundle/:username",
                axum::routing::get(move |Query(query): Query<HashMap<String, String>>| {
                    let bundles = bundles.clone();
                    async move {
                        let email = query.get("email").cloned().unwrap_or_default();
                        let scoped = query.get("scope").map(String::as_str) == Some("address");
                        let value = scoped
                            .then(|| bundles.scoped.lock().unwrap().get(&email).cloned())
                            .flatten()
                            .or_else(|| bundles.bundles.lock().unwrap().get(&email).cloned());
                        found(value)
                    }
                }),
            )
            .route(
                "/crypto/v1/ratchet/address-bundle",
                axum::routing::put(move |axum::Json(body): axum::Json<Value>| {
                    let entries = entries.clone();
                    async move {
                        entries.entries.lock().unwrap().push(body);
                        match entries.entry_status.load(std::sync::atomic::Ordering::SeqCst) {
                            200 => axum::Json(json!({"success": true, "active": true})).into_response(),
                            201 => axum::Json(json!({"success": true, "active": false})).into_response(),
                            status => StatusCode::from_u16(status).unwrap().into_response(),
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{}", port), directory)
    }

    fn bundle_json(bundle: &crate::api_client::PrekeyBundle) -> Value {
        json!({
            "kem_identity_key": bundle.kem_identity_key,
            "signed_prekey": bundle.signed_prekey,
            "signed_prekey_signature": bundle.signed_prekey_signature,
            "pq_kem_public_key": bundle.pq_kem_public_key,
            "x3dh_max_version": bundle.x3dh_max_version,
        })
    }

    fn sending_session(account: &crate::crypto::recipient_trust::tests::Owner) -> Arc<RwLock<Session>> {
        let prekey = SecretKey::random(&mut OsRng);
        Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "sender".to_string(),
            email: "sender@astermail.org".to_string(),
            access_token: Zeroizing::new("token".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: Some(account.keypair.to_armored().unwrap()),
            ratchet_identity_public: None,
            ratchet_keys: vec![crate::crypto::ratchet::RatchetReceiverKeys {
                identity_secret_d: SecretKey::random(&mut OsRng).to_bytes().to_vec(),
                signed_prekey_secret_d: prekey.to_bytes().to_vec(),
                signed_prekey_public: prekey.public_key().to_encoded_point(false).as_bytes().to_vec(),
            }],
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
            external_pgp_key: None,
        }))
    }

    #[tokio::test]
    async fn a_bcc_only_send_from_a_custom_domain_to_aster_users_is_sealed() {
        use crate::auth::session::{SendIdentity, SendIdentityKind};
        use crate::crypto::recipient_trust::tests::owner;

        let (base, directory) = start_directory().await;
        let client = ApiClient::new_with_base_url(&base);
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let session = sending_session(&owner("sender"));
        let identity = SendIdentity {
            address: "me@mydomain.example".to_string(),
            auth_hash_b64: Some("AAAA".to_string()),
            display_name: None,
            kind: SendIdentityKind::CustomDomain,
            enabled: true,
            sender_id: "domain-1".to_string(),
        };
        session.write().await.send_identities = vec![identity.clone()];

        for (address, name) in [("bob@custom.example", "bob"), ("amy@astermail.org", "amy")] {
            let account = owner(name);
            let mut keys = recipient();
            sign_v2(&mut keys.bundle, &account);
            directory.set_key(address, Some(json!({"public_key": account.public_key, "internal": true})));
            directory.set_bundle(address, Some(bundle_json(&keys.bundle)));
        }

        let raw = b"From: me@mydomain.example\r\nSubject: hi\r\n\r\nbody\r\n";
        let build = |bcc: &[&str]| {
            let recipients: Vec<String> = bcc.iter().map(|a| a.to_string()).collect();
            crate::smtp::server::build_send_payload(
                raw,
                Some("me@mydomain.example"),
                &recipients,
                "sender@astermail.org",
                Some(&identity),
                b"pass",
            )
            .unwrap()
        };
        let seal = |mut payload: Value, required: bool| {
            let (session, client, db) = (&session, &client, &db);
            async move {
                seal_internal_body_with(&mut payload, session, client, db, "token", required, &AddressEntryDirectory::new())
                    .await
                    .map(|_| payload)
            }
        };

        let builtin = seal(build(&["amy@astermail.org"]), true).await.unwrap();
        assert_eq!(builtin["to"], json!([]));
        assert_eq!(builtin["is_e2e_encrypted"], json!(true));
        assert!(builtin.get(SELF_TO_PLACEHOLDER).is_none());

        let hosted_payload = build(&["bob@custom.example"]);
        assert_eq!(hosted_payload["to"], json!(["me@mydomain.example"]));
        assert_eq!(hosted_payload[SELF_TO_PLACEHOLDER], json!("me@mydomain.example"));
        let hosted = seal(hosted_payload, true).await.unwrap();
        assert_eq!(hosted["to"], json!([]));
        assert_eq!(hosted["bcc"], json!(["bob@custom.example"]));
        assert_eq!(hosted["is_e2e_encrypted"], json!(true));
        assert!(hosted.get("internal_encrypted_body").is_none());
        assert!(hosted["recipient_bodies"]["bob@custom.example"]
            .as_str()
            .unwrap()
            .contains("double_ratchet_v2"));
        assert!(hosted.get(SELF_TO_PLACEHOLDER).is_none());

        let both = seal(build(&["bob@custom.example", "amy@astermail.org"]), true).await.unwrap();
        assert_eq!(both["to"], json!([]));
        assert_eq!(both["is_e2e_encrypted"], json!(true));

        let with_outside = build(&["bob@custom.example", "stranger@example.com"]);
        assert!(seal(with_outside.clone(), true).await.is_err());
        let readable = seal(with_outside, false).await.unwrap();
        assert_eq!(readable["to"], json!(["me@mydomain.example"]));
        assert_eq!(readable["is_e2e_encrypted"], json!(false));
        assert!(readable.get(SELF_TO_PLACEHOLDER).is_none());

        let unknown = seal(build(&["erin@nowhere.example"]), false).await.unwrap();
        assert_eq!(unknown["to"], json!(["me@mydomain.example"]));
        assert!(unknown.get(SELF_TO_PLACEHOLDER).is_none());

        let addressed_self = build(&["me@mydomain.example", "bob@custom.example"]);
        assert!(addressed_self.get(SELF_TO_PLACEHOLDER).is_none());
        let kept = seal(addressed_self, false).await.unwrap();
        assert_eq!(kept["to"], json!(["me@mydomain.example"]));
        assert_eq!(kept["is_e2e_encrypted"], json!(false));

        let primary = crate::smtp::server::build_send_payload(
            b"From: sender@astermail.org\r\nSubject: hi\r\n\r\nbody\r\n",
            Some("sender@astermail.org"),
            &["bob@custom.example".to_string()],
            "sender@astermail.org",
            None,
            b"pass",
        )
        .unwrap();
        assert_eq!(primary["to"], json!(["sender@astermail.org"]));
        assert_eq!(primary["bcc"], json!(["bob@custom.example"]));
        assert!(primary.get(SELF_TO_PLACEHOLDER).is_none());
    }

    #[tokio::test]
    async fn a_hosted_lookup_that_fails_holds_the_send_instead_of_sending_readable_mail() {
        use crate::crypto::recipient_trust::tests::owner;

        let (base, directory) = start_directory().await;
        let client = ApiClient::new_with_base_url(&base);
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let session = sending_session(&owner("sender"));
        let account = owner("bob");
        let mut keys = recipient();
        sign_v2(&mut keys.bundle, &account);
        let payload_to = |to: &str| {
            let message = format!("From: sender@astermail.org\r\nTo: {to}\r\nSubject: hi\r\n\r\nsecret body\r\n");
            crate::smtp::server::build_send_payload(
                message.as_bytes(),
                Some("sender@astermail.org"),
                &[to.to_string()],
                "sender@astermail.org",
                None,
                b"pass",
            )
            .unwrap()
        };
        let payload = || payload_to("bob@custom.example");
        let seal = |mut payload: Value| {
            let (session, client, db) = (&session, &client, &db);
            async move {
                seal_internal_body_with(&mut payload, session, client, db, "token", false, &AddressEntryDirectory::new())
                    .await
                    .map(|_| payload)
            }
        };

        directory.set_key("bob@custom.example", Some(json!(UNAVAILABLE)));
        let error = seal(payload()).await.unwrap_err();
        assert!(crate::smtp::server::is_transient_send_error(&error), "{error}");

        directory.set_key(
            "bob@custom.example",
            Some(json!({"public_key": account.public_key, "internal": true})),
        );
        directory.set_bundle("bob@custom.example", Some(json!(UNAVAILABLE)));
        let error = seal(payload()).await.unwrap_err();
        assert!(crate::smtp::server::is_transient_send_error(&error), "{error}");

        directory.set_bundle("bob@custom.example", Some(bundle_json(&keys.bundle)));
        let sealed = seal(payload()).await.unwrap();
        assert_eq!(sealed["is_e2e_encrypted"], json!(true));
        assert!(!sealed.to_string().contains("secret body"));

        directory.set_key("bob@custom.example", None);
        directory.set_bundle("bob@custom.example", None);
        let error = seal(payload()).await.unwrap_err();
        assert!(!crate::smtp::server::is_transient_send_error(&error), "{error}");

        let outside = seal(payload_to("carol@custom.example")).await.unwrap();
        assert!(outside.to_string().contains("carol@custom.example"));
        assert_ne!(outside["is_e2e_encrypted"], json!(true));
    }

    #[test]
    fn the_self_placeholder_is_dropped_only_when_every_other_recipient_is_sealed() {
        let hosted = HostedRecipients {
            hosted: vec!["bob@custom.example".to_string()],
            routed_like_external: vec!["carol@alias.example".to_string()],
        };
        let mut payload = json!({
            "to": ["me@mydomain.example"],
            "bcc": ["bob@custom.example", "a@astermail.org"],
            SELF_TO_PLACEHOLDER: "me@mydomain.example",
        });
        let own = take_self_to_placeholder(&mut payload).unwrap();
        assert!(payload.get(SELF_TO_PLACEHOLDER).is_none());
        drop_sealed_self_placeholder(&mut payload, &own, &hosted);
        assert_eq!(payload["to"], json!([]));

        for bcc in [
            json!(["bob@custom.example", "x@example.com"]),
            json!(["carol@alias.example"]),
            json!([]),
            json!(["Me@MyDomain.example", "bob@custom.example"]),
        ] {
            let mut payload = json!({"to": ["me@mydomain.example"], "bcc": bcc.clone()});
            drop_sealed_self_placeholder(&mut payload, "me@mydomain.example", &hosted);
            assert_eq!(payload["to"], json!(["me@mydomain.example"]), "{bcc}");
        }

        let mut explicit_to = json!({"to": ["someone@astermail.org"], "bcc": ["bob@custom.example"]});
        drop_sealed_self_placeholder(&mut explicit_to, "me@mydomain.example", &hosted);
        assert_eq!(explicit_to["to"], json!(["someone@astermail.org"]));
        assert!(take_self_to_placeholder(&mut json!({"to": []})).is_none());
    }

    #[test]
    fn a_claimed_aster_identity_covers_built_in_own_and_pinned_domains() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        assert!(claims_aster_identity(&db, "bob@astermail.org"));
        assert!(claims_aster_identity(&db, "Bob@Aster.CX"));
        assert!(!claims_aster_identity(&db, "dana@hosted.example"));
        assert!(!claims_aster_identity(&db, "not an address"));

        db.set_aster_sender_scope(AsterSenderScope {
            account_id: "account-1".to_string(),
            custom_domains: vec!["mydomain.example".to_string()],
        });
        db.recipient_pin_put(
            &pin_id("account-1", "dana@hosted.example"),
            &RecipientPin { hosted: true, ..RecipientPin::default() },
        )
        .unwrap();
        db.recipient_pin_put(&pin_id("account-2", "eve@hosted.example"), &RecipientPin::default())
            .unwrap();
        assert!(claims_aster_identity(&db, "dana@hosted.example"));
        assert!(claims_aster_identity(&db, "DANA@Hosted.Example"));
        assert!(claims_aster_identity(&db, "anyone@MyDomain.example."));
        assert!(!claims_aster_identity(&db, "eve@hosted.example"));
        assert!(!claims_aster_identity(&db, "frank@hosted.example"));
        assert!(!claims_aster_identity(&db, "x@example.com"));
    }

    #[tokio::test]
    async fn custom_domain_aster_recipients_are_sealed_and_cannot_be_quietly_moved_outside() {
        use crate::crypto::recipient_trust::tests::owner;

        let (base, directory) = start_directory().await;
        let client = ApiClient::new_with_base_url(&base);
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let sender_account = owner("sender");
        let session = sending_session(&sender_account);

        let bob = owner("bob");
        let mut bob_keys = recipient();
        sign_v2(&mut bob_keys.bundle, &bob);
        directory.set_key("bob@custom.example", Some(json!({"public_key": bob.public_key, "internal": true})));
        directory.set_bundle("bob@custom.example", Some(bundle_json(&bob_keys.bundle)));

        let carol = owner("carol");
        let mut carol_keys = recipient();
        sign_v2(&mut carol_keys.bundle, &carol);
        directory.set_key("carol@alias.example", Some(json!({"public_key": carol.public_key, "internal": false})));
        directory.set_bundle("carol@alias.example", Some(bundle_json(&carol_keys.bundle)));

        directory.set_key("dave@mismatch.example", Some(json!({"public_key": carol.public_key, "internal": false})));
        directory.set_bundle("dave@mismatch.example", Some(bundle_json(&bob_keys.bundle)));

        let seal = |to: Vec<&str>| {
            let mut payload = payload_with(to);
            let (session, client, db) = (&session, &client, &db);
            async move {
                seal_internal_body_with(&mut payload, session, client, db, "token", false, &AddressEntryDirectory::new())
                    .await
                    .map(|_| payload)
            }
        };

        let untouched = payload_with(vec!["stranger@example.com", "dave@mismatch.example"]);
        assert_eq!(seal(vec!["stranger@example.com", "dave@mismatch.example"]).await.unwrap(), untouched);

        let sealed = seal(vec!["bob@custom.example"]).await.unwrap();
        assert_eq!(sealed["is_e2e_encrypted"], json!(true));
        assert!(sealed["body"].as_str().unwrap().contains("double_ratchet_v2"));
        assert!(sealed["body"].as_str().unwrap().contains("bob@custom.example"));
        assert!(sealed.get("body_html").is_none());
        assert_eq!(sealed["hosted_recipients"], json!(["bob@custom.example"]));

        let mixed = seal(vec!["bob@custom.example", "stranger@example.com"]).await.unwrap();
        assert_eq!(mixed["is_e2e_encrypted"], json!(false));
        assert_eq!(mixed["body"], json!("<p>hello</p>"));
        assert!(mixed["internal_encrypted_body"].as_str().unwrap().contains("bob@custom.example"));
        assert_eq!(mixed["hosted_recipients"], json!(["bob@custom.example"]));

        let routed = seal(vec!["carol@alias.example"]).await.unwrap();
        assert_eq!(routed["is_e2e_encrypted"], json!(false));
        assert!(routed["internal_encrypted_body"].as_str().unwrap().contains("carol@alias.example"));
        assert_eq!(routed["hosted_recipients"], json!(["carol@alias.example"]));
        let mut strict = payload_with(vec!["carol@alias.example"]);
        assert!(matches!(
            seal_internal_body_with(&mut strict, &session, &client, &db, "token", true, &AddressEntryDirectory::new()).await,
            Err(BridgeError::RecipientKey(_))
        ));

        directory.set_key("bob@custom.example", Some(json!({"public_key": bob.public_key, "internal": false})));
        let flipped = seal(vec!["bob@custom.example"]).await.unwrap();
        assert_eq!(flipped["is_e2e_encrypted"], json!(true), "a pinned hosted recipient stays sealed");
        assert_eq!(flipped["hosted_recipients"], json!(["bob@custom.example"]));

        directory.set_key("bob@custom.example", None);
        directory.set_bundle("bob@custom.example", None);
        assert!(
            matches!(seal(vec!["bob@custom.example"]).await, Err(BridgeError::RecipientKey(_))),
            "a pinned recipient whose keys vanish is refused instead of sent readable"
        );

        directory.set_key("carol@alias.example", Some(json!({"public_key": carol.public_key, "internal": false})));
        directory.set_bundle("carol@alias.example", None);
        assert!(
            seal(vec!["carol@alias.example"]).await.is_err(),
            "a pinned recipient that drops its post-quantum bundle is refused"
        );
    }

    fn sender_identity_keys(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    if key == "sender_identity_key" {
                        if let Some(text) = inner.as_str() {
                            found.push(text.to_string());
                        }
                    }
                    sender_identity_keys(inner, found);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| sender_identity_keys(item, found)),
            Value::String(text) => {
                if let Ok(inner) = serde_json::from_str::<Value>(text.trim()) {
                    if inner.is_object() || inner.is_array() {
                        sender_identity_keys(&inner, found);
                    }
                }
            }
            _ => {}
        }
    }

    #[tokio::test]
    async fn an_alias_with_an_active_entry_sends_with_its_own_identity() {
        use crate::crypto::address_identity::tests::fixed_keyring;
        use crate::crypto::recipient_trust::tests::owner;
        use std::sync::atomic::Ordering;

        let (base, directory) = start_directory().await;
        let client = ApiClient::new_with_base_url(&base);
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let session = sending_session(&owner("sender"));
        let keyring = fixed_keyring();
        session.write().await.ratchet_recovery.address_keys = keyring.clone();
        let account_identity = {
            let guard = session.read().await;
            let secret = SecretKey::from_slice(&guard.ratchet_keys[0].identity_secret_d).unwrap();
            STANDARD.encode(secret.public_key().to_encoded_point(false).as_bytes())
        };

        let amy = owner("amy");
        let mut amy_keys = recipient();
        sign_v2(&mut amy_keys.bundle, &amy);
        directory.set_key("amy@astermail.org", Some(json!({"public_key": amy.public_key, "internal": true})));
        directory.set_bundle("amy@astermail.org", Some(bundle_json(&amy_keys.bundle)));

        let send_from = |from: Option<&'static str>, entries: AddressEntryDirectory| {
            let (session, client, db) = (&session, &client, &db);
            async move {
                let mut payload = payload_with(vec!["amy@astermail.org"]);
                if let Some(from) = from {
                    payload["sender_email"] = json!(from);
                }
                seal_internal_body_with(&mut payload, session, client, db, "token", true, &entries)
                    .await
                    .map(|_| {
                        let mut found = Vec::new();
                        sender_identity_keys(&payload, &mut found);
                        found.sort();
                        found.dedup();
                        found
                    })
            }
        };

        let alias = "alias@example.org";
        let alias_identity = keyring.sender_identity(alias).unwrap().public_b64;
        assert_ne!(alias_identity, account_identity);

        directory.entry_status.store(200, Ordering::SeqCst);
        assert_eq!(send_from(Some(alias), AddressEntryDirectory::new()).await.unwrap(), vec![alias_identity.clone()]);
        assert!(!directory.entries.lock().unwrap().is_empty());

        assert_eq!(send_from(None, AddressEntryDirectory::new()).await.unwrap(), vec![account_identity.clone()]);
        assert_eq!(
            send_from(Some("sender@astermail.org"), AddressEntryDirectory::new()).await.unwrap(),
            vec![account_identity.clone()]
        );
        assert_eq!(
            send_from(Some("s.ender@astermail.org"), AddressEntryDirectory::new()).await.unwrap(),
            vec![account_identity.clone()]
        );

        for status in [201, 404, 405, 400] {
            directory.entry_status.store(status, Ordering::SeqCst);
            assert_eq!(
                send_from(Some(alias), AddressEntryDirectory::new()).await.unwrap(),
                vec![account_identity.clone()],
                "status {status}"
            );
        }

        assert_eq!(
            send_from(Some("s.ender+news@astermail.org"), AddressEntryDirectory::new()).await.unwrap(),
            vec![account_identity.clone()]
        );

        directory.entry_status.store(500, Ordering::SeqCst);
        let uploads = directory.entries.lock().unwrap().len();
        assert_eq!(
            send_from(Some(alias), AddressEntryDirectory::new()).await.unwrap(),
            vec![account_identity.clone()],
            "an upload error with no active entry keeps the account identity"
        );
        assert_eq!(directory.entries.lock().unwrap().len(), uploads + 1);

        let entry_json = |entry: &crate::crypto::address_identity::SignedAddressEntry| {
            json!({
                "kem_identity_key": entry.kem_identity_key,
                "signed_prekey": entry.signed_prekey,
                "signed_prekey_signature": entry.signed_prekey_signature,
                "pq_kem_public_key": entry.pq_kem_public_key,
                "x3dh_max_version": 2,
                "address_scoped": true,
            })
        };
        let entry = keyring.sign_entry(alias).unwrap();
        directory.set_scoped(alias, Some(entry_json(&entry)));
        assert_eq!(
            send_from(Some(alias), AddressEntryDirectory::new()).await.unwrap(),
            vec![alias_identity.clone()],
            "an upload error with our own active entry keeps the address identity"
        );

        let mut other = entry.clone();
        other.signed_prekey = STANDARD.encode([0x11u8; 65]);
        directory.set_scoped(alias, Some(entry_json(&other)));
        assert!(matches!(
            send_from(Some(alias), AddressEntryDirectory::new()).await,
            Err(BridgeError::Crypto(_))
        ));
        directory.set_scoped(alias, None);

        let offline = ApiClient::new_with_base_url("http://127.0.0.1:9");
        let mut payload = payload_with(vec!["amy@astermail.org"]);
        payload["sender_email"] = json!(alias);
        assert!(matches!(
            seal_internal_body_with(&mut payload, &session, &offline, &db, "token", true, &AddressEntryDirectory::new()).await,
            Err(BridgeError::Network(_))
        ));

        session.write().await.ratchet_recovery.address_keys = Default::default();
        assert_eq!(send_from(Some(alias), AddressEntryDirectory::new()).await.unwrap(), vec![account_identity]);
    }

    #[tokio::test]
    async fn a_scoped_entry_is_used_for_an_alias_recipient_and_a_downgrade_is_refused() {
        use crate::crypto::address_identity::tests::fixed_keyring;
        use crate::crypto::recipient_trust::tests::owner;

        let (base, directory) = start_directory().await;
        let client = ApiClient::new_with_base_url(&base);
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let session = sending_session(&owner("sender"));

        let address = "amy.alias@astermail.org";
        let amy = owner("amy");
        let mut amy_keys = recipient();
        sign_v2(&mut amy_keys.bundle, &amy);
        directory.set_key(address, Some(json!({"public_key": amy.public_key, "internal": true})));
        directory.set_bundle(address, Some(bundle_json(&amy_keys.bundle)));
        let entry = fixed_keyring().sign_entry(address).unwrap();
        directory.set_scoped(
            address,
            Some(json!({
                "kem_identity_key": entry.kem_identity_key,
                "signed_prekey": entry.signed_prekey,
                "signed_prekey_signature": entry.signed_prekey_signature,
                "pq_kem_public_key": entry.pq_kem_public_key,
                "x3dh_max_version": 2,
                "address_scoped": true,
            })),
        );

        let seal = || {
            let (session, client, db) = (&session, &client, &db);
            async move {
                let mut payload = payload_with(vec![address]);
                seal_internal_body_with(&mut payload, session, client, db, "token", true, &AddressEntryDirectory::new())
                    .await
                    .map(|_| payload)
            }
        };

        let sealed = seal().await.unwrap();
        assert_eq!(sealed["is_e2e_encrypted"], json!(true));
        let account_id = session.read().await.user_id.to_string();
        let stored = crate::crypto::recipient_trust::read_recipient_pin(&db, &account_id, address)
            .unwrap()
            .pin
            .expect("the entry is pinned");
        assert!(stored.address_rooted);

        directory.set_scoped(address, None);
        let refused = seal().await.unwrap_err();
        assert!(
            matches!(&refused, BridgeError::RecipientKey(message) if message.contains("recipient-key accept")),
            "an unscoped answer for a rooted address asks to accept the changed key: {refused:?}"
        );
        let shown = crate::crypto::recipient_trust::key_fingerprint(Some(&amy.public_key)).unwrap();
        crate::crypto::recipient_trust::accept_recipient_key(&db, &account_id, address, Some(&amy.public_key), &shown).unwrap();
        let accepted = seal().await.unwrap();
        assert_eq!(accepted["is_e2e_encrypted"], json!(true));
        let stored = crate::crypto::recipient_trust::read_recipient_pin(&db, &account_id, address)
            .unwrap()
            .pin
            .unwrap();
        assert!(!stored.address_rooted && !stored.flagged);
    }

    #[tokio::test]
    async fn a_copy_to_our_own_alias_is_sealed_without_fetching_its_entry() {
        use crate::auth::session::{SendIdentity, SendIdentityKind};
        use crate::crypto::address_identity::tests::fixed_keyring;
        use crate::crypto::recipient_trust::tests::owner;
        use std::sync::atomic::Ordering;

        let (base, directory) = start_directory().await;
        let client = ApiClient::new_with_base_url(&base);
        let offline = ApiClient::new_with_base_url("http://127.0.0.1:9");
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let session = sending_session(&owner("sender"));
        let alias = "sender.alias@astermail.org";
        {
            let mut guard = session.write().await;
            guard.ratchet_recovery.address_keys = fixed_keyring();
            guard.send_identities = vec![SendIdentity {
                address: alias.to_string(),
                auth_hash_b64: None,
                display_name: None,
                kind: SendIdentityKind::Alias,
                enabled: true,
                sender_id: "alias-1".to_string(),
            }];
        }
        let entries = AddressEntryDirectory::new();
        directory.entry_status.store(200, Ordering::SeqCst);

        let mut payload = payload_with(vec![alias]);
        payload["sender_email"] = json!(alias);
        seal_internal_body_with(&mut payload, &session, &client, &db, "token", true, &entries)
            .await
            .unwrap();
        assert_eq!(payload["is_e2e_encrypted"], json!(true));

        let mut payload = payload_with(vec![alias]);
        payload["sender_email"] = json!("sender@astermail.org");
        seal_internal_body_with(&mut payload, &session, &offline, &db, "token", true, &entries)
            .await
            .unwrap();
        assert_eq!(payload["is_e2e_encrypted"], json!(true));
    }
}
