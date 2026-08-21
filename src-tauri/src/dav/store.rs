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

use crate::api_client::{ApiClient, CreateContactRequest, UpdateContactRequest};
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

    async fn access_token(&self) -> String {
        self.session.read().await.access_token.to_string()
    }

    async fn fetch_entries(&self) -> Result<Vec<ContactEntry>> {
        let keys = self.keys().await?;
        let token = self.access_token().await;

        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let page = self
                .client
                .list_contacts(&token, PAGE_SIZE, cursor.as_deref())
                .await?;

            for record in &page.items {
                if let (Some(hash), Some(version)) =
                    (record.integrity_hash.as_deref(), record.data_version)
                {
                    if !keys.verify_integrity_hash(
                        &record.encrypted_data,
                        &record.data_nonce,
                        version,
                        hash,
                    ) {
                        tracing::warn!(
                            "contact {} failed its integrity check and was skipped",
                            record.id
                        );
                        continue;
                    }
                }

                let payload = match keys.decrypt_data(&record.encrypted_data, &record.data_nonce) {
                    Ok(payload) => payload,
                    Err(e) => {
                        tracing::warn!("contact {} could not be decrypted: {}", record.id, e);
                        continue;
                    }
                };

                let uid = payload
                    .get(DAV_UID_FIELD)
                    .and_then(|v| v.as_str())
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty() && is_safe_uid(v))
                    .unwrap_or(record.id.as_str())
                    .to_string();

                let vcard =
                    super::vcard::contact_to_vcard(&uid, &payload, &record.updated_at);
                entries.push(ContactEntry {
                    uid,
                    contact_id: record.id.clone(),
                    etag: entry_etag(&vcard),
                    vcard,
                });
            }

            match page.next_cursor {
                Some(next) if page.has_more => cursor = Some(next),
                _ => break,
            }
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

    pub async fn put(&self, uid: &str, vcard: &str) -> Result<(ContactEntry, bool)> {
        if vcard.len() > MAX_VCARD_BYTES {
            return Err(BridgeError::Api("vcard too large".to_string()));
        }
        if !is_safe_uid(uid) {
            return Err(BridgeError::Api("unsupported contact name".to_string()));
        }

        let _guard = self.write_lock.lock().await;

        if let Some(body_uid) = super::vcard::extract_uid(vcard) {
            if body_uid != uid {
                tracing::debug!("carddav put uid mismatch: href {} body {}", uid, body_uid);
            }
        }

        let mut payload = super::vcard::vcard_to_contact(vcard);
        payload.insert(DAV_UID_FIELD.to_string(), Value::from(uid));

        let keys = self.keys().await?;
        let token = self.access_token().await;
        let existing = self.list().await?.into_iter().find(|e| e.uid == uid);

        let sealed = keys.encrypt_data(&Value::Object(payload.clone()))?;
        let tokens = search_tokens(&keys, &payload);

        let created = match &existing {
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
                false
            }
            None => {
                self.client
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
                true
            }
        };

        self.invalidate().await;

        let entry = self
            .list()
            .await?
            .into_iter()
            .find(|e| e.uid == uid)
            .ok_or_else(|| BridgeError::Api("contact was not stored".to_string()))?;

        Ok((entry, created))
    }

    pub async fn delete(&self, uid: &str) -> Result<bool> {
        let _guard = self.write_lock.lock().await;

        let Some(entry) = self.list().await?.into_iter().find(|e| e.uid == uid) else {
            return Ok(false);
        };

        let token = self.access_token().await;
        self.client.delete_contact(&token, &entry.contact_id).await?;
        self.invalidate().await;

        Ok(true)
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
            collection_ctag(&[first.clone()]),
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
