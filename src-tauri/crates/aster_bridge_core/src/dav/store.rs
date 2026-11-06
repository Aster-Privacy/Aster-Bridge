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
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::api_client::{ApiClient, ContactRecord, CreateContactRequest, UpdateContactRequest};
use crate::auth::session::Session;
use crate::crypto::contacts::{ContactsKeys, CONTACT_DATA_VERSION};
use crate::error::{BridgeError, Result};

const PAGE_SIZE: u32 = 200;
const MAX_PAGES: usize = 200;
const CACHE_TTL: Duration = Duration::from_secs(5);
const DAV_UID_FIELD: &str = "dav_uid";
const MAX_VCARD_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct ContactEntry {
    pub uid: String,
    pub contact_id: String,
    pub etag: String,
    pub vcard: String,
}

struct CachedListing {
    entries: Vec<ContactEntry>,
    fetched_at: Instant,
}

pub struct ContactsStore {
    client: Arc<ApiClient>,
    session: Arc<RwLock<Session>>,
    cache: RwLock<Option<CachedListing>>,
    write_lock: Mutex<()>,
}

#[derive(Default)]
pub struct Preconditions {
    pub if_match: Option<Vec<String>>,
    pub if_none_match: Option<Vec<String>>,
}

impl Preconditions {
    fn is_empty(&self) -> bool {
        self.if_match.is_none() && self.if_none_match.is_none()
    }

    fn hold_for(&self, current: Option<&ContactEntry>) -> bool {
        let matches = |tags: &[String]| {
            current.is_some_and(|e| tags.iter().any(|t| t == "*" || t == &e.etag))
        };
        if self.if_match.as_deref().is_some_and(|tags| !matches(tags)) {
            return false;
        }
        !self.if_none_match.as_deref().is_some_and(matches)
    }
}

pub enum PutOutcome {
    Stored(ContactEntry, bool),
    PreconditionFailed,
}

pub enum DeleteOutcome {
    Deleted,
    NotFound,
    PreconditionFailed,
}

enum DecodeError {
    Integrity,
    Decrypt(BridgeError),
}

struct ContactsKeyring {
    current: ContactsKeys,
    previous: Vec<ContactsKeys>,
}

impl ContactsKeyring {
    fn new(current: ContactsKeys, previous: &[zeroize::Zeroizing<[u8; 32]>]) -> Self {
        let mut ring: Vec<ContactsKeys> = Vec::new();
        for key in previous {
            if current.same_key(key) || ring.iter().any(|k| k.same_key(key)) {
                continue;
            }
            ring.push(ContactsKeys::from_raw(key));
        }
        Self {
            current,
            previous: ring,
        }
    }
}

fn decode_with_keyring(
    keyring: &ContactsKeyring,
    record: &ContactRecord,
) -> std::result::Result<ContactEntry, DecodeError> {
    let first = match decode_record(&keyring.current, record) {
        Ok(entry) => return Ok(entry),
        Err(e) => e,
    };
    for keys in &keyring.previous {
        if let Ok(entry) = decode_record(keys, record) {
            return Ok(entry);
        }
    }
    Err(first)
}

fn decode_record(
    keys: &ContactsKeys,
    record: &ContactRecord,
) -> std::result::Result<ContactEntry, DecodeError> {
    if let (Some(hash), Some(version)) = (record.integrity_hash.as_deref(), record.data_version) {
        if !keys.verify_integrity_hash(&record.encrypted_data, &record.data_nonce, version, hash) {
            return Err(DecodeError::Integrity);
        }
    }

    let payload = keys
        .decrypt_data(&record.encrypted_data, &record.data_nonce)
        .map_err(DecodeError::Decrypt)?;

    let uid = payload
        .get(DAV_UID_FIELD)
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty() && is_safe_uid(v))
        .unwrap_or(record.id.as_str())
        .to_string();

    let vcard = super::vcard::contact_to_vcard(&uid, &payload, &record.updated_at);
    Ok(ContactEntry {
        uid,
        contact_id: record.id.clone(),
        etag: entry_etag(&vcard),
        vcard,
    })
}

pub fn entry_etag(vcard: &str) -> String {
    let digest = Sha256::digest(vcard.as_bytes());
    format!("\"{}\"", hex_prefix(&digest, 16))
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes
        .iter()
        .take(len)
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub fn collection_ctag(entries: &[ContactEntry]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted: Vec<&ContactEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.uid.cmp(&b.uid));
    for entry in sorted {
        hasher.update(entry.uid.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.etag.as_bytes());
        hasher.update(b"\0");
    }
    format!("\"{}\"", hex_prefix(&hasher.finalize(), 16))
}

impl ContactsStore {
    pub fn new(client: Arc<ApiClient>, session: Arc<RwLock<Session>>) -> Self {
        Self {
            client,
            session,
            cache: RwLock::new(None),
            write_lock: Mutex::new(()),
        }
    }

    async fn keys(&self) -> Result<ContactsKeys> {
        let session = self.session.read().await;
        let Some(data_kek) = session.data_kek.as_ref() else {
            return Err(BridgeError::Crypto(
                "contacts key unavailable - sign in again".to_string(),
            ));
        };
        ContactsKeys::from_data_kek_b64(data_kek)
    }

    async fn keyring(&self) -> Result<ContactsKeyring> {
        let current = self.keys().await?;
        let session = self.session.read().await;
        Ok(ContactsKeyring::new(
            current,
            &session.ratchet_recovery.storage_keys,
        ))
    }

    async fn access_token(&self) -> String {
        self.session.read().await.access_token.to_string()
    }

    async fn fetch_entries(&self) -> Result<Vec<ContactEntry>> {
        let keys = self.keyring().await?;
        let token = self.access_token().await;

        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        let mut skipped_integrity = 0usize;
        let mut skipped_decrypt = 0usize;

        for _ in 0..MAX_PAGES {
            let page = self
                .client
                .list_contacts(&token, PAGE_SIZE, cursor.as_deref())
                .await?;

            for record in &page.items {
                match decode_with_keyring(&keys, record) {
                    Ok(entry) => entries.push(entry),
                    Err(DecodeError::Integrity) => {
                        skipped_integrity += 1;
                        tracing::debug!(
                            "contact {} failed its integrity check and was skipped",
                            record.id
                        );
                    }
                    Err(DecodeError::Decrypt(e)) => {
                        skipped_decrypt += 1;
                        tracing::debug!("contact {} could not be decrypted: {}", record.id, e);
                    }
                }
            }

            match page.next_cursor {
                Some(next) if page.has_more => cursor = Some(next),
                _ => break,
            }
        }

        if skipped_integrity > 0 || skipped_decrypt > 0 {
            tracing::warn!(
                "skipped {} contacts this sync, {} failed an integrity check and {} could not be decrypted",
                skipped_integrity + skipped_decrypt,
                skipped_integrity,
                skipped_decrypt
            );
        }

        let mut seen = HashMap::new();
        entries.retain(|entry| seen.insert(entry.uid.clone(), ()).is_none());

        Ok(entries)
    }

    pub async fn invalidate(&self) {
        *self.cache.write().await = None;
    }

    pub async fn list(&self) -> Result<Vec<ContactEntry>> {
        if let Some(cached) = self.cache.read().await.as_ref() {
            if cached.fetched_at.elapsed() < CACHE_TTL {
                return Ok(cached.entries.clone());
            }
        }

        let entries = self.fetch_entries().await?;
        *self.cache.write().await = Some(CachedListing {
            entries: entries.clone(),
            fetched_at: Instant::now(),
        });

        Ok(entries)
    }

    pub async fn get(&self, uid: &str) -> Result<Option<ContactEntry>> {
        Ok(self.list().await?.into_iter().find(|e| e.uid == uid))
    }

    async fn fetch_entry(&self, contact_id: &str) -> Result<Option<ContactEntry>> {
        let keys = self.keyring().await?;
        let token = self.access_token().await;
        let Some(record) = self.client.get_contact(&token, contact_id).await? else {
            return Ok(None);
        };
        match decode_with_keyring(&keys, &record) {
            Ok(entry) => Ok(Some(entry)),
            Err(DecodeError::Integrity) => Err(BridgeError::Crypto(format!(
                "contact {} failed its integrity check",
                contact_id
            ))),
            Err(DecodeError::Decrypt(e)) => Err(e),
        }
    }

    async fn remember(&self, entry: ContactEntry) {
        if let Some(cached) = self.cache.write().await.as_mut() {
            cached
                .entries
                .retain(|e| e.uid != entry.uid && e.contact_id != entry.contact_id);
            cached.entries.push(entry);
        }
    }

    async fn forget(&self, uid: &str) {
        if let Some(cached) = self.cache.write().await.as_mut() {
            cached.entries.retain(|e| e.uid != uid);
        }
    }

    async fn current(
        &self,
        uid: &str,
        preconditions: &Preconditions,
    ) -> Result<Option<ContactEntry>> {
        let cached = self.get(uid).await?;
        if preconditions.is_empty() {
            return Ok(cached);
        }
        let Some(cached) = cached else {
            return Ok(None);
        };
        let fresh = self.fetch_entry(&cached.contact_id).await?;
        match &fresh {
            Some(entry) => self.remember(entry.clone()).await,
            None => self.forget(uid).await,
        }
        Ok(fresh.filter(|e| e.uid == uid))
    }

    pub async fn put(
        &self,
        uid: &str,
        vcard: &str,
        preconditions: &Preconditions,
    ) -> Result<PutOutcome> {
        if vcard.len() > MAX_VCARD_BYTES {
            return Err(BridgeError::Api("vcard too large".to_string()));
        }
        if !is_safe_uid(uid) {
            return Err(BridgeError::Api("unsupported contact name".to_string()));
        }

        let _guard = self.write_lock.lock().await;

        let existing = self.current(uid, preconditions).await?;
        if !preconditions.hold_for(existing.as_ref()) {
            return Ok(PutOutcome::PreconditionFailed);
        }

        if let Some(body_uid) = super::vcard::extract_uid(vcard) {
            if body_uid != uid {
                tracing::debug!("carddav put uid mismatch: href {} body {}", uid, body_uid);
            }
        }

        let mut payload = super::vcard::vcard_to_contact(vcard);
        payload.insert(DAV_UID_FIELD.to_string(), Value::from(uid));

        let keys = self.keys().await?;
        let token = self.access_token().await;

        let sealed = keys.encrypt_data(&Value::Object(payload.clone()))?;
        let tokens = search_tokens(&keys, &payload);

        let (contact_id, created) = match &existing {
            Some(entry) => {
                self.client
                    .update_contact(
                        &token,
                        &entry.contact_id,
                        &UpdateContactRequest {
                            encrypted_data: sealed.encrypted_data,
                            data_nonce: sealed.data_nonce,
                            integrity_hash: sealed.integrity_hash,
                            name_search_token: tokens.name,
                            email_search_token: tokens.email,
                            company_search_token: tokens.company,
                        },
                    )
                    .await?;
                (entry.contact_id.clone(), false)
            }
            None => {
                let response = self
                    .client
                    .create_contact(
                        &token,
                        &CreateContactRequest {
                            contact_token: tokens.contact,
                            name_search_token: tokens.name,
                            email_search_token: tokens.email,
                            company_search_token: tokens.company,
                            encrypted_data: sealed.encrypted_data,
                            data_nonce: sealed.data_nonce,
                            integrity_hash: sealed.integrity_hash,
                            data_version: CONTACT_DATA_VERSION,
                        },
                    )
                    .await?;
                (response.id, true)
            }
        };

        let Some(entry) = self.fetch_entry(&contact_id).await? else {
            self.invalidate().await;
            return Err(BridgeError::Api("contact was not stored".to_string()));
        };
        self.remember(entry.clone()).await;

        Ok(PutOutcome::Stored(entry, created))
    }

    pub async fn delete(&self, uid: &str, preconditions: &Preconditions) -> Result<DeleteOutcome> {
        let _guard = self.write_lock.lock().await;

        let Some(entry) = self.current(uid, preconditions).await? else {
            return Ok(DeleteOutcome::NotFound);
        };
        if !preconditions.hold_for(Some(&entry)) {
            return Ok(DeleteOutcome::PreconditionFailed);
        }

        let token = self.access_token().await;
        self.client.delete_contact(&token, &entry.contact_id).await?;
        self.forget(uid).await;

        Ok(DeleteOutcome::Deleted)
    }
}

struct SearchTokens {
    contact: String,
    name: Option<String>,
    email: Option<String>,
    company: Option<String>,
}

fn search_tokens(keys: &ContactsKeys, payload: &Map<String, Value>) -> SearchTokens {
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    let first_name = text("first_name");
    let last_name = text("last_name");
    let company = text("company");
    let emails: Vec<String> = payload
        .get("emails")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .map(|v| v.to_string())
                .collect()
        })
        .unwrap_or_default();

    let full_name = format!("{} {}", first_name, last_name).trim().to_string();

    SearchTokens {
        contact: keys.contact_token(&first_name, &last_name, &emails),
        name: (!full_name.is_empty()).then(|| keys.search_token(&full_name)),
        email: emails
            .first()
            .filter(|v| !v.is_empty())
            .map(|v| keys.search_token(v)),
        company: (!company.is_empty()).then(|| keys.search_token(&company)),
    }
}

pub fn is_safe_uid(uid: &str) -> bool {
    !uid.is_empty()
        && uid.len() <= 255
        && uid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+' | '~'))
        && !uid.starts_with('.')
        && uid != ".."
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn entry(uid: &str, vcard: &str) -> ContactEntry {
        ContactEntry {
            uid: uid.to_string(),
            contact_id: uid.to_string(),
            etag: entry_etag(vcard),
            vcard: vcard.to_string(),
        }
    }

    #[test]
    fn etags_are_quoted_and_content_bound() {
        let a = entry_etag("BEGIN:VCARD\r\nEND:VCARD\r\n");
        let b = entry_etag("BEGIN:VCARD\r\nFN:A\r\nEND:VCARD\r\n");

        assert!(a.starts_with('"') && a.ends_with('"'));
        assert_eq!(a.len(), 34);
        assert_ne!(a, b);
    }

    #[test]
    fn ctag_is_order_independent_but_content_sensitive() {
        let first = entry("a", "one");
        let second = entry("b", "two");

        assert_eq!(
            collection_ctag(&[first.clone(), second.clone()]),
            collection_ctag(&[second.clone(), first.clone()])
        );
        assert_ne!(
            collection_ctag(std::slice::from_ref(&first)),
            collection_ctag(&[first, second])
        );
    }

    #[test]
    fn rejects_path_traversal_and_control_characters_in_uids() {
        assert!(is_safe_uid("3f8a-1234"));
        assert!(is_safe_uid("ada@example.com"));
        assert!(!is_safe_uid(".."));
        assert!(!is_safe_uid("../../etc/passwd"));
        assert!(!is_safe_uid("a/b"));
        assert!(!is_safe_uid("a\\b"));
        assert!(!is_safe_uid(""));
        assert!(!is_safe_uid(".hidden"));
        assert!(!is_safe_uid(&"x".repeat(256)));
    }

    #[test]
    fn search_tokens_cover_name_email_and_company() {
        let keys = ContactsKeys::from_data_kek_b64(
            &base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
        )
        .unwrap();
        let payload = serde_json::json!({
            "first_name": "Ada",
            "last_name": "Lovelace",
            "company": "Engines",
            "emails": ["ada@example.com"],
        });
        let tokens = search_tokens(&keys, payload.as_object().unwrap());

        assert_eq!(tokens.name.unwrap(), keys.search_token("Ada Lovelace"));
        assert_eq!(tokens.email.unwrap(), keys.search_token("ada@example.com"));
        assert_eq!(tokens.company.unwrap(), keys.search_token("Engines"));
        assert_eq!(
            tokens.contact,
            keys.contact_token("Ada", "Lovelace", &["ada@example.com".to_string()])
        );
    }

    fn record_sealed_with(keys: &ContactsKeys, payload: &Value) -> ContactRecord {
        let sealed = keys.encrypt_data(payload).unwrap();
        ContactRecord {
            id: "contact-1".to_string(),
            contact_token: "token".to_string(),
            encrypted_data: sealed.encrypted_data,
            data_nonce: sealed.data_nonce,
            integrity_hash: Some(sealed.integrity_hash),
            data_version: Some(CONTACT_DATA_VERSION),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn contacts_written_under_a_previous_key_still_open() {
        let previous = zeroize::Zeroizing::new([9u8; 32]);
        let record = record_sealed_with(
            &ContactsKeys::from_raw(&previous),
            &serde_json::json!({ "first_name": "Ada", "emails": ["ada@example.com"] }),
        );
        let current = ContactsKeys::from_raw(&[3u8; 32]);
        assert!(matches!(decode_record(&current, &record), Err(DecodeError::Integrity)));

        let keyring = ContactsKeyring::new(current, std::slice::from_ref(&previous));
        let entry = decode_with_keyring(&keyring, &record).ok().expect("opens under the previous key");
        assert!(entry.vcard.contains("ada@example.com"));
    }

    #[test]
    fn contacts_keyring_prefers_the_current_key_and_skips_duplicates() {
        let current_raw = zeroize::Zeroizing::new([3u8; 32]);
        let other = zeroize::Zeroizing::new([4u8; 32]);
        let keyring = ContactsKeyring::new(
            ContactsKeys::from_raw(&current_raw),
            &[current_raw.clone(), other.clone(), other.clone()],
        );
        assert_eq!(keyring.previous.len(), 1);

        let record = record_sealed_with(
            &ContactsKeys::from_raw(&current_raw),
            &serde_json::json!({ "first_name": "Grace" }),
        );
        assert!(decode_with_keyring(&keyring, &record).is_ok());
    }

    #[test]
    fn contacts_unreadable_under_every_key_report_the_current_key_error() {
        let record = record_sealed_with(
            &ContactsKeys::from_raw(&[7u8; 32]),
            &serde_json::json!({ "first_name": "Nobody" }),
        );
        let keyring = ContactsKeyring::new(
            ContactsKeys::from_raw(&[3u8; 32]),
            &[zeroize::Zeroizing::new([4u8; 32])],
        );
        assert!(matches!(
            decode_with_keyring(&keyring, &record),
            Err(DecodeError::Integrity)
        ));
    }

    fn store_with(data_kek: Option<[u8; 32]>, storage_keys: Vec<[u8; 32]>) -> ContactsStore {
        let session = Session {
            data_kek: data_kek.map(|k| {
                zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(k))
            }),
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: b"vault-pass".to_vec(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: crate::crypto::ratchet_recovery::RecoveryMaterial {
                storage_keys: storage_keys.into_iter().map(zeroize::Zeroizing::new).collect(),
                lane_candidates: Vec::new(),
            },
        };
        ContactsStore::new(
            Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:9")),
            Arc::new(RwLock::new(session)),
        )
    }

    #[tokio::test]
    async fn contact_writes_use_the_data_kek_and_never_an_older_key() {
        let store = store_with(Some([3u8; 32]), vec![[9u8; 32], [3u8; 32]]);
        let keys = store.keys().await.unwrap();
        assert!(keys.same_key(&[3u8; 32]));

        let keyring = store.keyring().await.unwrap();
        assert!(keyring.current.same_key(&[3u8; 32]));
        assert_eq!(keyring.previous.len(), 1);
        assert!(keyring.previous[0].same_key(&[9u8; 32]));
    }

    #[tokio::test]
    async fn contact_writes_refuse_to_fall_back_to_a_password_key() {
        let store = store_with(None, vec![[9u8; 32]]);
        assert!(store.keys().await.is_err());
        assert!(store.keyring().await.is_err());
    }

    #[test]
    fn search_tokens_are_absent_for_empty_fields() {
        let keys = ContactsKeys::from_data_kek_b64(
            &base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
        )
        .unwrap();
        let payload = serde_json::json!({
            "first_name": "",
            "last_name": "",
            "emails": [],
        });
        let tokens = search_tokens(&keys, payload.as_object().unwrap());

        assert!(tokens.name.is_none());
        assert!(tokens.email.is_none());
        assert!(tokens.company.is_none());
    }
}
