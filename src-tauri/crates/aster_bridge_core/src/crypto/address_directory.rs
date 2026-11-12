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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::api_client::{AddressBundleUpload, ApiClient};
use crate::crypto::address_identity::{address_entry_forms, AddressKeyring};

const ACTIVE_REFRESH: Duration = Duration::from_secs(6 * 60 * 60);
const INACTIVE_RETRY: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressEntryState {
    Active,
    Inactive,
    Unconfirmed,
}

struct PublishedState {
    address: String,
    fingerprint: String,
    state: AddressEntryState,
    retry_at: Instant,
}

struct DirectoryState {
    published: Vec<PublishedState>,
    unsupported_until: Option<Instant>,
}

pub struct AddressEntryDirectory {
    inner: Mutex<DirectoryState>,
}

pub static ADDRESS_ENTRIES: AddressEntryDirectory = AddressEntryDirectory::new();

impl Default for AddressEntryDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressEntryDirectory {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(DirectoryState {
                published: Vec::new(),
                unsupported_until: None,
            }),
        }
    }

    fn with_state<R>(&self, f: impl FnOnce(&mut DirectoryState) -> R) -> R {
        let mut guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    fn cached(&self, address: &str, fingerprint: &str, now: Instant) -> Option<AddressEntryState> {
        self.with_state(|state| {
            state
                .published
                .iter()
                .find(|known| known.address == address && known.fingerprint == fingerprint && now < known.retry_at)
                .map(|known| known.state)
        })
    }

    pub fn known_state(&self, keyring: &AddressKeyring, address: &str) -> Option<AddressEntryState> {
        let exact = address_entry_forms(address).into_iter().next()?;
        keyring.current_identity_public()?;
        self.cached(&exact, &keyring.fingerprint(), Instant::now())
    }

    fn is_unsupported(&self, now: Instant) -> bool {
        self.with_state(|state| state.unsupported_until.is_some_and(|until| now < until))
    }

    fn mark_unsupported(&self) {
        self.with_state(|state| state.unsupported_until = Some(Instant::now() + INACTIVE_RETRY));
    }

    fn record(&self, address: &str, fingerprint: &str, outcome: AddressEntryState, retry: Duration) {
        self.with_state(|state| {
            state.published.retain(|known| known.address != address);
            state.published.push(PublishedState {
                address: address.to_string(),
                fingerprint: fingerprint.to_string(),
                state: outcome,
                retry_at: Instant::now() + retry,
            });
        });
    }

    pub async fn entry_state(
        &self,
        client: &ApiClient,
        access_token: &str,
        keyring: &AddressKeyring,
        address: &str,
    ) -> AddressEntryState {
        let forms = address_entry_forms(address);
        let Some(exact) = forms.first().cloned() else {
            return AddressEntryState::Unconfirmed;
        };
        if keyring.current_identity_public().is_none() {
            return AddressEntryState::Unconfirmed;
        }
        let fingerprint = keyring.fingerprint();
        let now = Instant::now();
        if let Some(known) = self.cached(&exact, &fingerprint, now) {
            return known;
        }
        if self.is_unsupported(now) {
            return AddressEntryState::Inactive;
        }
        let Some((outcome, retry)) = self.upload(client, access_token, keyring, &exact).await else {
            return AddressEntryState::Unconfirmed;
        };
        for form in forms.iter().skip(1) {
            if self.is_unsupported(Instant::now()) {
                break;
            }
            let _ = self.upload(client, access_token, keyring, form).await;
        }
        self.record(&exact, &fingerprint, outcome, retry);
        outcome
    }

    async fn upload(
        &self,
        client: &ApiClient,
        access_token: &str,
        keyring: &AddressKeyring,
        form: &str,
    ) -> Option<(AddressEntryState, Duration)> {
        let entry = keyring.sign_entry(form)?;
        match client.put_address_bundle(access_token, &entry).await {
            Ok(AddressBundleUpload::Active) => Some((AddressEntryState::Active, ACTIVE_REFRESH)),
            Ok(AddressBundleUpload::Inactive) | Ok(AddressBundleUpload::Rejected) => {
                Some((AddressEntryState::Inactive, INACTIVE_RETRY))
            }
            Ok(AddressBundleUpload::Unsupported) => {
                self.mark_unsupported();
                Some((AddressEntryState::Inactive, INACTIVE_RETRY))
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::address_identity::tests::fixed_keyring;
    use crate::crypto::address_identity::verify_signed_entry;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;

    struct FakeServer {
        status: AtomicU16,
        active: std::sync::atomic::AtomicBool,
        uploads: Mutex<Vec<serde_json::Value>>,
    }

    async fn start_server(status: u16, active: bool) -> (ApiClient, Arc<FakeServer>) {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let server = Arc::new(FakeServer {
            status: AtomicU16::new(status),
            active: std::sync::atomic::AtomicBool::new(active),
            uploads: Mutex::new(Vec::new()),
        });
        let shared = server.clone();
        let app = axum::Router::new().route(
            "/crypto/v1/ratchet/address-bundle",
            axum::routing::put(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let shared = shared.clone();
                async move {
                    shared.uploads.lock().unwrap().push(body);
                    let status = shared.status.load(Ordering::SeqCst);
                    if status == 200 {
                        let active = shared.active.load(Ordering::SeqCst);
                        axum::Json(serde_json::json!({"success": true, "active": active})).into_response()
                    } else {
                        StatusCode::from_u16(status).unwrap().into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (ApiClient::new_with_base_url(&format!("http://127.0.0.1:{}", port)), server)
    }

    fn uploaded(server: &FakeServer) -> Vec<String> {
        server
            .uploads
            .lock()
            .unwrap()
            .iter()
            .map(|entry| entry["address"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[tokio::test]
    async fn an_active_entry_is_signed_for_every_form_and_cached() {
        let (client, server) = start_server(200, true).await;
        let directory = AddressEntryDirectory::new();
        let keyring = fixed_keyring();
        let state = directory.entry_state(&client, "token", &keyring, "J.o+News@Example.org").await;
        assert_eq!(state, AddressEntryState::Active);
        assert_eq!(uploaded(&server), vec!["j.o+news@example.org".to_string(), "jo@example.org".to_string()]);
        for entry in server.uploads.lock().unwrap().iter() {
            let entry: crate::crypto::address_identity::SignedAddressEntry =
                serde_json::from_value(entry.clone()).unwrap();
            assert!(verify_signed_entry(&entry.address, &entry).valid);
        }
        let again = directory.entry_state(&client, "token", &keyring, "j.o+news@example.org").await;
        assert_eq!(again, AddressEntryState::Active);
        assert_eq!(server.uploads.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_entry_the_server_keeps_inactive_uses_the_account_key() {
        let (client, _server) = start_server(200, false).await;
        let directory = AddressEntryDirectory::new();
        let state = directory.entry_state(&client, "token", &fixed_keyring(), "alias@example.org").await;
        assert_eq!(state, AddressEntryState::Inactive);
    }

    #[tokio::test]
    async fn a_server_without_address_entries_is_left_alone_for_a_while() {
        for status in [404u16, 405] {
            let (client, server) = start_server(status, true).await;
            let directory = AddressEntryDirectory::new();
            let keyring = fixed_keyring();
            assert_eq!(
                directory.entry_state(&client, "token", &keyring, "a.b@example.org").await,
                AddressEntryState::Inactive
            );
            assert_eq!(uploaded(&server).len(), 1);
            assert_eq!(
                directory.entry_state(&client, "token", &keyring, "other@example.org").await,
                AddressEntryState::Inactive
            );
            assert_eq!(uploaded(&server).len(), 1);
        }
    }

    #[tokio::test]
    async fn a_rejected_entry_is_inactive_and_a_server_error_is_retried_on_the_next_send() {
        let (client, _server) = start_server(400, true).await;
        let directory = AddressEntryDirectory::new();
        assert_eq!(
            directory.entry_state(&client, "token", &fixed_keyring(), "alias@example.org").await,
            AddressEntryState::Inactive
        );

        let (client, server) = start_server(500, true).await;
        let directory = AddressEntryDirectory::new();
        let keyring = fixed_keyring();
        assert_eq!(
            directory.entry_state(&client, "token", &keyring, "alias@example.org").await,
            AddressEntryState::Unconfirmed
        );
        assert_eq!(directory.known_state(&keyring, "alias@example.org"), None);
        assert_eq!(
            directory.entry_state(&client, "token", &keyring, "alias@example.org").await,
            AddressEntryState::Unconfirmed
        );
        assert_eq!(uploaded(&server).len(), 2);
        server.status.store(200, Ordering::SeqCst);
        assert_eq!(
            directory.entry_state(&client, "token", &keyring, "alias@example.org").await,
            AddressEntryState::Active
        );
        assert_eq!(directory.known_state(&keyring, "alias@example.org"), Some(AddressEntryState::Active));

        let offline = ApiClient::new_with_base_url("http://127.0.0.1:9");
        let directory = AddressEntryDirectory::new();
        assert_eq!(
            directory.entry_state(&offline, "token", &keyring, "alias@example.org").await,
            AddressEntryState::Unconfirmed
        );
    }

    #[tokio::test]
    async fn a_keyring_without_keys_or_a_bad_address_is_unconfirmed() {
        let (client, server) = start_server(200, true).await;
        let directory = AddressEntryDirectory::new();
        assert_eq!(
            directory.entry_state(&client, "token", &AddressKeyring::default(), "alias@example.org").await,
            AddressEntryState::Unconfirmed
        );
        assert_eq!(
            directory.entry_state(&client, "token", &fixed_keyring(), "+tag@example.org").await,
            AddressEntryState::Unconfirmed
        );
        assert!(uploaded(&server).is_empty());
    }
}
