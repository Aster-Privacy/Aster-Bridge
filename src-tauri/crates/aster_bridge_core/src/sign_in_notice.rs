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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub const TLS_REQUIRED_TEXT: &str =
    "Turn on SSL/TLS for this account in your mail app, then try again";

pub const BAD_CREDENTIALS_TEXT: &str =
    "Sign-in failed. Use the username and app password shown in Aster Bridge";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct InsecureSignIn {
    pub protocol: &'static str,
    pub at: i64,
    pub seq: u64,
}

static LAST_INSECURE: Mutex<Option<InsecureSignIn>> = Mutex::new(None);
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
static CLEAR_ON_SIGN_IN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn record_insecure(protocol: &'static str) {
    tracing::warn!("a {} client tried to sign in without SSL/TLS", protocol);
    let at = chrono::Utc::now().timestamp();
    let seq = NEXT_SEQ.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut last) = LAST_INSECURE.lock() {
        *last = Some(InsecureSignIn { protocol, at, seq });
    }
}

pub fn record_signed_in(protocol: &str) {
    #[cfg(test)]
    if !CLEAR_ON_SIGN_IN.load(Ordering::SeqCst) {
        return;
    }
    if let Ok(mut last) = LAST_INSECURE.lock() {
        if last.is_some_and(|l| l.protocol == protocol) {
            *last = None;
        }
    }
}

pub fn last_insecure() -> Option<InsecureSignIn> {
    LAST_INSECURE.lock().ok().and_then(|last| *last)
}

pub fn dismiss_insecure(seq: u64) {
    if let Ok(mut last) = LAST_INSECURE.lock() {
        if last.is_some_and(|l| l.seq <= seq) {
            *last = None;
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::RwLock;

    use crate::api_client::ApiClient;
    use crate::auth::app_passwords::AppPasswords;
    use crate::auth::session::Session;
    use crate::db::Database;

    pub(crate) const APP_PASSWORD: &str = "abcd-efgh-ijkl-mnop";

    pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        SERIALIZE.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) struct Fixture {
        pub session: Arc<RwLock<Session>>,
        pub db: Arc<Database>,
        pub client: Arc<ApiClient>,
        pub passwords: Arc<AppPasswords>,
        pub tls: Arc<rustls::ServerConfig>,
        pub dir: tempfile::TempDir,
    }

    pub(crate) fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[7u8; 32]).unwrap());
        let _ = db.seed_jmap_mailboxes();
        let passwords = Arc::new(AppPasswords::new(db.clone()));
        passwords.store("test", APP_PASSWORD).unwrap();
        crate::tls::install_default_crypto_provider();
        let (certs, key) = crate::tls::ensure_cert(dir.path()).unwrap();
        let tls = crate::tls::server_config(certs, key).unwrap();
        let session = Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }));
        let client = Arc::new(ApiClient::new_with_base_url("http://127.0.0.1:1"));
        Fixture { session, db, client, passwords, tls, dir }
    }

    pub(crate) async fn transcript<F, Fut, T>(script: &str, serve: F) -> String
    where
        F: FnOnce(tokio::io::DuplexStream) -> Fut,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (client_side, server_side) = tokio::io::duplex(16 * 1024);
        let handle = tokio::spawn(serve(server_side));
        let (mut reader, mut writer) = tokio::io::split(client_side);
        writer.write_all(script.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();
        let mut out = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            reader.read_to_string(&mut out),
        )
        .await
        .expect("the server never closed the session")
        .unwrap();
        handle.abort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::test_lock;
    use super::*;

    #[test]
    fn record_keeps_the_latest_attempt() {
        let _guard = test_lock();
        dismiss_insecure(u64::MAX);
        record_insecure("imap");
        record_insecure("smtp");
        let last = last_insecure().expect("an attempt was recorded");
        assert_eq!(last.protocol, "smtp");
        assert!(last.at > 0);
    }

    #[test]
    fn dismiss_clears_only_attempts_the_user_has_seen() {
        let _guard = test_lock();
        record_insecure("pop3");
        let seen = last_insecure().unwrap().seq;
        dismiss_insecure(seen - 1);
        assert!(last_insecure().is_some());
        dismiss_insecure(seen);
        assert_eq!(last_insecure(), None);
    }

    #[test]
    fn a_new_attempt_in_the_same_second_survives_a_dismiss() {
        let _guard = test_lock();
        record_insecure("imap");
        let seen = last_insecure().unwrap();
        record_insecure("imap");
        let newer = last_insecure().unwrap();
        assert_eq!(newer.at, seen.at);
        dismiss_insecure(seen.seq);
        assert_eq!(last_insecure(), Some(newer));
        dismiss_insecure(newer.seq);
    }

    #[test]
    fn a_later_sign_in_on_the_same_protocol_clears_the_notice() {
        let _guard = test_lock();
        CLEAR_ON_SIGN_IN.store(true, Ordering::SeqCst);
        record_insecure("notice-test-a");
        record_signed_in("notice-test-b");
        assert_eq!(last_insecure().map(|l| l.protocol), Some("notice-test-a"));
        record_signed_in("notice-test-a");
        CLEAR_ON_SIGN_IN.store(false, Ordering::SeqCst);
        assert_eq!(last_insecure(), None);
    }

    #[test]
    fn user_texts_are_single_line_and_plain() {
        for text in [TLS_REQUIRED_TEXT, BAD_CREDENTIALS_TEXT] {
            assert!(!text.chars().any(char::is_control));
            assert!(!text.contains('\u{2014}'));
        }
    }
}
