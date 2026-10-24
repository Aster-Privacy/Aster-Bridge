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

use crate::crypto::ratchet::{encrypt_bootstrap_versioned, RatchetMessage};
use crate::crypto::recipient_trust::{
    evaluate_recipient, pin_id, verify_bundle, BundleVerdict, RatchetTarget, RecipientPin,
    SendRoute,
};
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
        db.recipient_pin_get(&pin_id(&scope.account_id, address)),
        Ok(Some(pin)) if pin.hosted
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

fn is_own_address(session: &Session, address: &str) -> bool {
    let address = address.trim();
    session.email.trim().eq_ignore_ascii_case(address)
        || session
            .send_identities
            .iter()
            .any(|identity| identity.address.trim().eq_ignore_ascii_case(address))
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
        let pin = db.recipient_pin_get(&pin_id(&account_id, &address)).map_err(|_| {
            BridgeError::RecipientKey(format!(
                "The saved key record for {} could not be read, so the message was not sent.",
                address
            ))
        })?;
        let fetched = fetch_hosted_keys(client, access_token, &username, &address).await;
        let (key_lookup, bundle) = match fetched {
            Ok(fetched) => fetched,
            Err(error) if pin.is_some() => return Err(error),
            Err(_) => continue,
        };
        let owner_public_key = key_lookup.as_ref().and_then(|lookup| lookup.public_key.clone());
        let bundle_verified = matches!(
            (bundle.as_ref(), owner_public_key.as_deref()),
            (Some(bundle), Some(owner)) if matches!(
                verify_bundle(bundle, Some(owner)),
                BundleVerdict::Verified { .. }
            )
        );
        match classify_hosted(key_lookup.as_ref(), bundle_verified, pin.as_ref()) {
            HostedClass::Hosted => lookup.hosted.hosted.push(address.clone()),
            HostedClass::AsterRouted => lookup.hosted.routed_like_external.push(address.clone()),
            HostedClass::External => continue,
        }
        lookup.known.push(KnownKeys {
            address,
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
    if key_lookup.as_ref().and_then(|lookup| lookup.public_key.as_ref()).is_none() {
        return Ok((key_lookup, None));
    }
    let bundle = client
        .find_prekey_bundle(access_token, username, address)
        .await?;
    Ok((key_lookup, bundle))
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
    seal_internal_body_with(payload, session, client, db, access_token, require_post_quantum).await
}

async fn seal_internal_body_with(
    payload: &mut Value,
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    db: &Database,
    access_token: &str,
    require_post_quantum: bool,
) -> Result<()> {
    let self_placeholder = take_self_to_placeholder(payload);
    let mut lookup = lookup_hosted_recipients(payload, session, client, db, access_token).await?;
    if let Some(own_address) = self_placeholder {
        drop_sealed_self_placeholder(payload, &own_address, &lookup.hosted);
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

    let plaintext = sealed_plaintext(payload);

    let sender = sender_keys(session).await?;
    let mut routed: Vec<RoutedRecipient> = Vec::with_capacity(split.internal.len());
    let mut pending_pins = Vec::new();

    for address in &split.internal {
        let is_hosted = lookup.hosted.contains(address);
        let (bundle, owner_public_key) = match lookup.take(address) {
            Some(known) => (known.bundle, known.owner_public_key),
            None => {
                let username = key_lookup_username(address, &sender.username).ok_or_else(|| {
                    BridgeError::Crypto("recipient address has no username to look up".to_string())
                })?;
                let bundle = client
                    .find_prekey_bundle(access_token, &username, address)
                    .await?;
                let owner_public_key = client
                    .get_recipient_public_key(access_token, &username, address)
                    .await?;
                (bundle, owner_public_key)
            }
        };
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
        let hosted_now = is_hosted && !lookup.hosted.routed_like_external(address);
        if let Some(pin) = pin_to_save(evaluation.pin, existing.as_ref(), hosted_now) {
            pending_pins.push((pin_key, pin));
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
    let account_key = sender.account_key.as_ref().ok_or_else(|| {
        BridgeError::Crypto(
            "no account key in the vault; cannot encrypt attachments for Aster recipients"
                .to_string(),
        )
    })?;
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
                let sealed = seal_with_account_keys(
                    meta,
                    &[recipient_account_key(recipient)?],
                    account_key,
                    &sender.passphrase,
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
            let sealed = seal_with_account_keys(meta, &keys, account_key, &sender.passphrase)?;
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
        let manifest_before = sealed_plaintext(&payload);

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

        assert_eq!(sealed_plaintext(&payload), manifest_before);
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
        let manifest_before = sealed_plaintext(&payload);

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

    struct FakeDirectory {
        keys: std::sync::Mutex<std::collections::HashMap<String, Value>>,
        bundles: std::sync::Mutex<std::collections::HashMap<String, Value>>,
    }

    impl FakeDirectory {
        fn set_key(&self, address: &str, value: Option<Value>) {
            let mut keys = self.keys.lock().unwrap();
            match value {
                Some(value) => keys.insert(address.to_string(), value),
                None => keys.remove(address),
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
        });
        let (keys, bundles) = (directory.clone(), directory.clone());
        let found = |value: Option<Value>| match value {
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
                        let value = bundles.bundles.lock().unwrap().get(&email).cloned();
                        found(value)
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
                seal_internal_body_with(&mut payload, session, client, db, "token", required)
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
                seal_internal_body_with(&mut payload, session, client, db, "token", false)
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
            seal_internal_body_with(&mut strict, &session, &client, &db, "token", true).await,
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
}
