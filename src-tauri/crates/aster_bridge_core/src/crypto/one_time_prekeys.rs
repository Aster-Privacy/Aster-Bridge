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
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use p256::SecretKey;
use zeroize::Zeroizing;

use crate::api_client::ApiClient;
use crate::crypto::ratchet::{b64_decode, is_valid_one_time_prekey_id};

const MISSING_MEMO: Duration = Duration::from_secs(600);
const WRAPPED_SECRET_LEN: usize = 48;
const WRAP_NONCE_LEN: usize = 12;
const SECRET_LEN: usize = 32;
const MAX_CACHED_SECRETS: usize = 256;
const MAX_MISSING_MEMOS: usize = 1024;

type StoreKey = (String, u32);

#[derive(Default)]
struct OneTimeStore {
    secrets: HashMap<StoreKey, Zeroizing<Vec<u8>>>,
    missing: HashMap<StoreKey, Instant>,
}

fn store_key(account: &str, key_id: u32) -> StoreKey {
    (account.trim().to_lowercase(), key_id)
}

impl OneTimeStore {
    fn secret(&self, account: &str, key_id: u32) -> Option<Zeroizing<Vec<u8>>> {
        self.secrets.get(&store_key(account, key_id)).cloned()
    }

    fn remember_secret(&mut self, account: &str, key_id: u32, secret: Zeroizing<Vec<u8>>) {
        if self.secrets.len() >= MAX_CACHED_SECRETS {
            self.secrets.clear();
        }
        let key = store_key(account, key_id);
        self.missing.remove(&key);
        self.secrets.insert(key, secret);
    }

    fn forget_secret(&mut self, account: &str, key_id: u32) -> bool {
        self.secrets.remove(&store_key(account, key_id)).is_some()
    }

    fn remember_missing(&mut self, account: &str, key_id: u32, now: Instant) {
        if self.missing.len() >= MAX_MISSING_MEMOS {
            self.missing.clear();
        }
        self.missing.insert(store_key(account, key_id), now);
    }

    fn is_known_missing(&mut self, account: &str, key_id: u32, now: Instant) -> bool {
        let key = store_key(account, key_id);
        let Some(noted_at) = self.missing.get(&key).copied() else {
            return false;
        };
        if now.saturating_duration_since(noted_at) < MISSING_MEMO {
            return true;
        }
        self.missing.remove(&key);
        false
    }
}

fn shared_store() -> &'static Mutex<OneTimeStore> {
    static STORE: OnceLock<Mutex<OneTimeStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(OneTimeStore::default()))
}

fn with_store<T>(action: impl FnOnce(&mut OneTimeStore) -> T) -> T {
    let mut guard = match shared_store().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    action(&mut guard)
}

pub fn unwrap_one_time_secret(
    sync_key: &[u8],
    encrypted_secret_b64: &str,
    secret_nonce_b64: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let wrapped = b64_decode(encrypted_secret_b64)?;
    if wrapped.len() != WRAPPED_SECRET_LEN {
        return Err("one-time prekey secret has the wrong length".to_string());
    }
    let nonce = b64_decode(secret_nonce_b64)?;
    if nonce.len() != WRAP_NONCE_LEN {
        return Err("one-time prekey nonce has the wrong length".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(sync_key)
        .map_err(|_| "one-time prekey wrapping key has the wrong length".to_string())?;
    let secret = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), wrapped.as_slice())
            .map_err(|_| "one-time prekey secret did not authenticate".to_string())?,
    );
    if secret.len() != SECRET_LEN {
        return Err("one-time prekey scalar has the wrong length".to_string());
    }
    SecretKey::from_slice(&secret)
        .map_err(|_| "one-time prekey scalar is not a valid key".to_string())?;
    Ok(secret)
}

pub async fn load_one_time_secret(
    client: &ApiClient,
    access_token: &str,
    account: &str,
    sync_keys: &[Zeroizing<[u8; 32]>],
    key_id: u32,
) -> Option<Zeroizing<Vec<u8>>> {
    if !is_valid_one_time_prekey_id(key_id) {
        return None;
    }
    if let Some(secret) = with_store(|store| store.secret(account, key_id)) {
        return Some(secret);
    }
    if sync_keys.is_empty() {
        return None;
    }
    if with_store(|store| store.is_known_missing(account, key_id, Instant::now())) {
        return None;
    }
    let wrapped = match client.get_ec_prekey_secret(access_token, key_id).await {
        Ok(Some(wrapped)) => wrapped,
        Ok(None) => {
            with_store(|store| store.remember_missing(account, key_id, Instant::now()));
            return None;
        }
        Err(_) => {
            tracing::debug!("one-time prekey secret could not be fetched");
            return None;
        }
    };
    let secret = sync_keys.iter().find_map(|sync_key| {
        unwrap_one_time_secret(
            sync_key.as_slice(),
            &wrapped.encrypted_secret,
            &wrapped.secret_nonce,
        )
        .ok()
    });
    match secret {
        Some(secret) => {
            with_store(|store| store.remember_secret(account, key_id, secret.clone()));
            Some(secret)
        }
        None => {
            with_store(|store| store.remember_missing(account, key_id, Instant::now()));
            None
        }
    }
}

pub async fn consume_one_time_secret(
    client: &ApiClient,
    access_token: &str,
    account: &str,
    key_id: u32,
) {
    with_store(|store| store.forget_secret(account, key_id));
    if client.delete_ec_prekey(access_token, key_id).await.is_err() {
        tracing::debug!("one-time prekey could not be removed from the server");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    const SYNC_KEY: [u8; 32] = [7u8; 32];

    fn wrap_nonce() -> [u8; WRAP_NONCE_LEN] {
        rand::random()
    }

    fn scalar() -> Vec<u8> {
        let mut scalar = vec![0u8; 32];
        scalar[31] = 5;
        scalar
    }

    fn wrap(sync_key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> (String, String) {
        let cipher = Aes256Gcm::new_from_slice(sync_key).unwrap();
        let wrapped = cipher.encrypt(Nonce::from_slice(nonce), plaintext).unwrap();
        (STANDARD.encode(wrapped), STANDARD.encode(nonce))
    }

    #[test]
    fn a_wrapped_one_time_secret_opens_with_the_sync_key() {
        let (wrapped, nonce) = wrap(&SYNC_KEY, &wrap_nonce(), &scalar());
        assert_eq!(STANDARD.decode(&wrapped).unwrap().len(), 48);
        assert_eq!(STANDARD.decode(&nonce).unwrap().len(), 12);

        let opened = unwrap_one_time_secret(&SYNC_KEY, &wrapped, &nonce).expect("opened");
        assert_eq!(opened.as_slice(), scalar().as_slice());
    }

    #[test]
    fn a_wrapped_one_time_secret_is_refused_unless_it_matches_the_format() {
        let (wrapped, nonce) = wrap(&SYNC_KEY, &wrap_nonce(), &scalar());

        assert!(unwrap_one_time_secret(&[8u8; 32], &wrapped, &nonce).is_err());
        assert!(unwrap_one_time_secret(&SYNC_KEY[..16], &wrapped, &nonce).is_err());
        assert!(unwrap_one_time_secret(&[], &wrapped, &nonce).is_err());

        let other_nonce = STANDARD.encode([1u8; 12]);
        assert!(unwrap_one_time_secret(&SYNC_KEY, &wrapped, &other_nonce).is_err());
        let short_nonce = STANDARD.encode([9u8; 11]);
        assert!(unwrap_one_time_secret(&SYNC_KEY, &wrapped, &short_nonce).is_err());
        let long_nonce = STANDARD.encode([9u8; 16]);
        assert!(unwrap_one_time_secret(&SYNC_KEY, &wrapped, &long_nonce).is_err());

        let mut tampered = STANDARD.decode(&wrapped).unwrap();
        tampered[0] ^= 0x01;
        assert!(unwrap_one_time_secret(&SYNC_KEY, &STANDARD.encode(&tampered), &nonce).is_err());

        let (short, short_wrap_nonce) = wrap(&SYNC_KEY, &wrap_nonce(), &scalar()[..31]);
        assert!(unwrap_one_time_secret(&SYNC_KEY, &short, &short_wrap_nonce).is_err());
        let (long, long_wrap_nonce) = wrap(&SYNC_KEY, &wrap_nonce(), &[5u8; 33]);
        assert!(unwrap_one_time_secret(&SYNC_KEY, &long, &long_wrap_nonce).is_err());

        let (zero, zero_nonce) = wrap(&SYNC_KEY, &wrap_nonce(), &[0u8; 32]);
        assert!(unwrap_one_time_secret(&SYNC_KEY, &zero, &zero_nonce).is_err());
        let (above_order, above_order_nonce) = wrap(&SYNC_KEY, &wrap_nonce(), &[0xffu8; 32]);
        assert!(unwrap_one_time_secret(&SYNC_KEY, &above_order, &above_order_nonce).is_err());

        assert!(unwrap_one_time_secret(&SYNC_KEY, "not base64", &nonce).is_err());
        assert!(unwrap_one_time_secret(&SYNC_KEY, &wrapped, "not base64").is_err());
        assert!(unwrap_one_time_secret(&SYNC_KEY, "", "").is_err());
    }

    #[test]
    fn a_missing_one_time_secret_is_remembered_for_ten_minutes() {
        let mut store = OneTimeStore::default();
        let start = Instant::now();
        assert!(!store.is_known_missing("user@astermail.org", 41, start));

        store.remember_missing("user@astermail.org", 41, start);
        assert!(store.is_known_missing("user@astermail.org", 41, start));
        assert!(store.is_known_missing(
            "user@astermail.org",
            41,
            start + Duration::from_secs(599)
        ));
        assert!(!store.is_known_missing("user@astermail.org", 42, start));
        assert!(!store.is_known_missing("other@astermail.org", 41, start));

        assert!(!store.is_known_missing(
            "user@astermail.org",
            41,
            start + Duration::from_secs(600)
        ));
        assert!(!store.is_known_missing("user@astermail.org", 41, start));
    }

    #[test]
    fn a_cached_one_time_secret_is_scoped_to_its_account_and_removed_once() {
        let mut store = OneTimeStore::default();
        let start = Instant::now();
        store.remember_missing("user@astermail.org", 41, start);
        store.remember_secret("User@AsterMail.org ", 41, Zeroizing::new(scalar()));

        assert!(!store.is_known_missing("user@astermail.org", 41, start));
        assert_eq!(
            store.secret("user@astermail.org", 41).expect("cached").as_slice(),
            scalar().as_slice()
        );
        assert!(store.secret("user@astermail.org", 42).is_none());
        assert!(store.secret("other@astermail.org", 41).is_none());

        assert!(!store.forget_secret("other@astermail.org", 41));
        assert!(store.forget_secret("USER@astermail.org", 41));
        assert!(!store.forget_secret("user@astermail.org", 41));
        assert!(store.secret("user@astermail.org", 41).is_none());
    }

    #[test]
    fn the_one_time_secret_cache_stays_bounded() {
        let mut store = OneTimeStore::default();
        for key_id in 1..=(MAX_CACHED_SECRETS as u32 + 1) {
            store.remember_secret("user@astermail.org", key_id, Zeroizing::new(scalar()));
        }
        assert!(store.secrets.len() <= MAX_CACHED_SECRETS);
        assert!(store
            .secret("user@astermail.org", MAX_CACHED_SECRETS as u32 + 1)
            .is_some());
    }
}
