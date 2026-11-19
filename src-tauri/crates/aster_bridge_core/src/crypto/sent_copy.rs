//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the AGPLv3 as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// AGPLv3 for more details.
//
// You should have received a copy of the AGPLv3
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::api_client::ApiClient;

pub const FORMAT_WRITES_CACHE_WINDOW: Duration = Duration::from_secs(5 * 60);

pub fn seal_sent_envelope(envelope: &str, identity_key: &str, passphrase: &[u8]) -> Option<String> {
    let passphrase = Zeroizing::new(std::str::from_utf8(passphrase).ok()?.to_string());
    let key = aster_crypto::import_secret_key(identity_key).ok()?;
    let public_key = key.public_key();
    let armored = aster_crypto::encrypt_and_sign_with_passphrase(
        envelope.as_bytes(),
        &[&public_key],
        &key,
        &passphrase,
    )
    .ok()?;
    let reopened = Zeroizing::new(
        aster_crypto::decrypt_and_verify_with_passphrase(
            &armored,
            &[&key],
            &[&public_key],
            &passphrase,
        )
        .ok()?,
    );
    if reopened.as_slice() != envelope.as_bytes() {
        return None;
    }
    Some(STANDARD.encode(armored))
}

pub fn parse_format_writes(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.as_object()?.get("format_writes")?.as_bool())
        .unwrap_or(false)
}

#[derive(Default)]
pub struct FormatWritesCache {
    cached: Option<(bool, Instant)>,
}

impl FormatWritesCache {
    pub fn get(&self, now: Instant) -> Option<bool> {
        self.cached
            .filter(|(_, at)| now.saturating_duration_since(*at) < FORMAT_WRITES_CACHE_WINDOW)
            .map(|(value, _)| value)
    }

    pub fn store(&mut self, value: bool, now: Instant) {
        self.cached = Some((value, now));
    }
}

fn format_writes_cache() -> &'static Mutex<FormatWritesCache> {
    static CACHE: OnceLock<Mutex<FormatWritesCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(FormatWritesCache::default()))
}

pub async fn format_writes_enabled(client: &ApiClient, access_token: &str) -> bool {
    if let Some(value) = format_writes_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.get(Instant::now()))
    {
        return value;
    }
    let value = client.get_account_key_format_writes(access_token).await;
    if let Ok(mut cache) = format_writes_cache().lock() {
        cache.store(value, Instant::now());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::account_key::tests::protected_keypair;
    use crate::crypto::envelope::decrypt_envelope;

    const PASSPHRASE: &str = "correct horse battery staple";
    const ENVELOPE: &str = r#"{"version":1,"subject":"Quarterly plan","body_text":"Body text","to":[{"name":"","email":"friend@example.com"}]}"#;

    fn armored_key() -> String {
        protected_keypair(PASSPHRASE).to_armored().unwrap()
    }

    #[test]
    fn sealed_copy_is_an_armored_message_the_poller_opens() {
        let key = armored_key();
        let sealed = seal_sent_envelope(ENVELOPE, &key, PASSPHRASE.as_bytes()).unwrap();
        let armored = String::from_utf8(STANDARD.decode(&sealed).unwrap()).unwrap();

        assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert!(!armored.contains("Quarterly plan"));
        let opened =
            decrypt_envelope(&sealed, Some(""), PASSPHRASE.as_bytes(), Some(&key), &[]).unwrap();
        assert_eq!(opened, ENVELOPE);
    }

    #[test]
    fn sealed_copy_is_signed_by_the_owner_only() {
        let key = armored_key();
        let owner = aster_crypto::import_secret_key(&key).unwrap();
        let other = protected_keypair(PASSPHRASE);
        let sealed = seal_sent_envelope(ENVELOPE, &key, PASSPHRASE.as_bytes()).unwrap();
        let armored = STANDARD.decode(&sealed).unwrap();

        assert!(aster_crypto::decrypt_and_verify_with_passphrase(
            &armored,
            &[&owner],
            &[&owner.public_key()],
            PASSPHRASE
        )
        .is_ok());
        assert!(aster_crypto::decrypt_and_verify_with_passphrase(
            &armored,
            &[&owner],
            &[&other.public_key()],
            PASSPHRASE
        )
        .is_err());
    }

    #[test]
    fn sealed_copy_is_not_readable_by_another_key() {
        let key = armored_key();
        let other = protected_keypair(PASSPHRASE).to_armored().unwrap();
        let sealed = seal_sent_envelope(ENVELOPE, &key, PASSPHRASE.as_bytes()).unwrap();

        assert!(
            decrypt_envelope(&sealed, Some(""), PASSPHRASE.as_bytes(), Some(&other), &[]).is_err()
        );
    }

    #[test]
    fn each_seal_uses_a_fresh_session_key() {
        let key = armored_key();
        let first = seal_sent_envelope(ENVELOPE, &key, PASSPHRASE.as_bytes()).unwrap();
        let second = seal_sent_envelope(ENVELOPE, &key, PASSPHRASE.as_bytes()).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn seal_fails_for_a_wrong_passphrase() {
        assert!(seal_sent_envelope(ENVELOPE, &armored_key(), b"wrong").is_none());
    }

    #[test]
    fn seal_fails_for_a_passphrase_that_is_not_utf8() {
        assert!(seal_sent_envelope(ENVELOPE, &armored_key(), &[0xFF, 0xFE]).is_none());
    }

    #[test]
    fn seal_fails_for_a_public_key_or_text_that_is_not_a_key() {
        let public_key = protected_keypair(PASSPHRASE).public_key_armored().unwrap();

        assert!(seal_sent_envelope(ENVELOPE, &public_key, PASSPHRASE.as_bytes()).is_none());
        assert!(seal_sent_envelope(ENVELOPE, r#"{"kty":"EC"}"#, PASSPHRASE.as_bytes()).is_none());
    }

    #[test]
    fn format_writes_parses_only_a_boolean() {
        assert!(parse_format_writes(br#"{"format_writes":true}"#));
        assert!(!parse_format_writes(br#"{"format_writes":false}"#));
        assert!(!parse_format_writes(br#"{"format_writes":"true"}"#));
        assert!(!parse_format_writes(br#"{"format_writes":1}"#));
        assert!(!parse_format_writes(br#"{"format_writes":null}"#));
        assert!(!parse_format_writes(b"{}"));
        assert!(!parse_format_writes(b"[true]"));
        assert!(!parse_format_writes(b"not json"));
        assert!(!parse_format_writes(b""));
    }

    #[test]
    fn format_writes_cache_expires_after_the_window() {
        let start = Instant::now();
        let mut cache = FormatWritesCache::default();

        assert_eq!(cache.get(start), None);
        cache.store(true, start);
        assert_eq!(cache.get(start + Duration::from_secs(60)), Some(true));
        assert_eq!(cache.get(start + FORMAT_WRITES_CACHE_WINDOW), None);
        cache.store(false, start + FORMAT_WRITES_CACHE_WINDOW);
        assert_eq!(cache.get(start + FORMAT_WRITES_CACHE_WINDOW), Some(false));
    }
}
