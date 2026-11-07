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
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::api_client::ApiClient;

const ADMISSION_RETRY_AFTER: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level2Admission {
    Unknown,
    Admitted,
    Refused,
}

pub struct EnvelopeV2State {
    admission: Level2Admission,
    write_key: Option<Zeroizing<[u8; 32]>>,
    last_attempt: Option<Instant>,
    generation: u64,
}

impl EnvelopeV2State {
    pub const fn new() -> Self {
        Self {
            admission: Level2Admission::Unknown,
            write_key: None,
            last_attempt: None,
            generation: 0,
        }
    }

    pub fn admission(&self) -> Level2Admission {
        self.admission
    }

    pub fn begin_unlock(&mut self, data_kek_b64: Option<&str>) {
        self.write_key = data_kek_b64.and_then(decode_write_key);
        self.admission = Level2Admission::Unknown;
        self.last_attempt = None;
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn update_write_key(&mut self, data_kek_b64: Option<&str>) {
        let next = data_kek_b64.and_then(decode_write_key);
        let same = match (&next, &self.write_key) {
            (Some(a), Some(b)) => **a == **b,
            (None, None) => true,
            _ => false,
        };
        if !same {
            self.begin_unlock(data_kek_b64);
        }
    }

    pub fn forget(&mut self) {
        self.write_key = None;
        self.admission = Level2Admission::Unknown;
        self.last_attempt = None;
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn write_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        match self.admission {
            Level2Admission::Admitted => self.write_key.clone(),
            _ => None,
        }
    }

    pub fn needs_admission(&self, now: Instant) -> bool {
        self.write_key.is_some()
            && self.admission == Level2Admission::Unknown
            && self
                .last_attempt
                .map_or(true, |at| now.saturating_duration_since(at) >= ADMISSION_RETRY_AFTER)
    }

    pub fn start_attempt(&mut self, now: Instant) -> u64 {
        self.last_attempt = Some(now);
        self.generation
    }

    pub fn record(&mut self, generation: u64, outcome: Level2Admission) {
        if generation == self.generation && self.admission == Level2Admission::Unknown {
            self.admission = outcome;
        }
    }
}

impl Default for EnvelopeV2State {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_write_key(key_b64: &str) -> Option<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(STANDARD.decode(key_b64.trim()).ok()?);
    if raw.len() != 32 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw);
    Some(key)
}

static STATE: RwLock<EnvelopeV2State> = RwLock::new(EnvelopeV2State::new());

fn with_state<T>(f: impl FnOnce(&mut EnvelopeV2State) -> T) -> T {
    let mut state = STATE.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut state)
}

pub fn begin_envelope_v2_unlock(data_kek_b64: Option<&str>) {
    with_state(|s| s.begin_unlock(data_kek_b64));
}

pub fn update_envelope_v2_write_key(data_kek_b64: Option<&str>) {
    with_state(|s| s.update_write_key(data_kek_b64));
}

pub fn forget_envelope_v2_state() {
    with_state(|s| s.forget());
}

pub fn envelope_v2_write_key() -> Option<Zeroizing<[u8; 32]>> {
    STATE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .write_key()
}

pub async fn ensure_admission_in(
    state: &RwLock<EnvelopeV2State>,
    client: &ApiClient,
    access_token: &str,
) -> Level2Admission {
    let generation = {
        let mut s = state.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        if !s.needs_admission(now) {
            return s.admission();
        }
        s.start_attempt(now)
    };
    let outcome = client.request_envelope_v2_admission(access_token).await;
    let mut s = state.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    s.record(generation, outcome);
    if outcome == Level2Admission::Unknown {
        tracing::debug!("envelope v2 admission unavailable; keeping the current envelope format");
    }
    s.admission()
}

pub async fn ensure_envelope_v2_admission(client: &ApiClient, access_token: &str) -> Level2Admission {
    if access_token.is_empty() {
        return Level2Admission::Unknown;
    }
    ensure_admission_in(&STATE, client, access_token).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::{routing::post, Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const DATA_KEK: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const OTHER_KEK: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    const ROUTE: &str = "/core/v1/auth/me/storage-rekey/envelope-v2";

    async fn spawn_admission(status: StatusCode, body: serde_json::Value) -> (String, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let app = Router::new().route(
            ROUTE,
            post(move || {
                let seen = seen.clone();
                let body = body.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    (status, Json(body)).into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{}", port), calls)
    }

    fn unlocked(data_kek: Option<&str>) -> RwLock<EnvelopeV2State> {
        let mut state = EnvelopeV2State::new();
        state.begin_unlock(data_kek);
        RwLock::new(state)
    }

    #[test]
    fn no_write_key_until_admitted() {
        let mut state = EnvelopeV2State::new();
        state.begin_unlock(Some(DATA_KEK));
        assert!(state.write_key().is_none());
        let generation = state.start_attempt(Instant::now());
        state.record(generation, Level2Admission::Refused);
        assert!(state.write_key().is_none());
        assert!(!state.needs_admission(Instant::now()));

        state.begin_unlock(Some(DATA_KEK));
        assert_eq!(state.admission(), Level2Admission::Unknown);
        let generation = state.start_attempt(Instant::now());
        state.record(generation, Level2Admission::Admitted);
        assert_eq!(state.write_key().unwrap().as_slice(), STANDARD.decode(DATA_KEK).unwrap());
    }

    #[test]
    fn missing_or_malformed_data_kek_never_asks_or_writes() {
        for kek in [None, Some(""), Some("not base64"), Some("AAAA")] {
            let mut state = EnvelopeV2State::new();
            state.begin_unlock(kek);
            assert!(!state.needs_admission(Instant::now()));
            state.admission = Level2Admission::Admitted;
            assert!(state.write_key().is_none());
        }
    }

    #[test]
    fn a_stale_answer_is_dropped_after_the_key_changes() {
        let mut state = EnvelopeV2State::new();
        state.begin_unlock(Some(DATA_KEK));
        let generation = state.start_attempt(Instant::now());
        state.update_write_key(Some(OTHER_KEK));
        state.record(generation, Level2Admission::Admitted);
        assert_eq!(state.admission(), Level2Admission::Unknown);
        assert!(state.write_key().is_none());
    }

    #[test]
    fn same_key_refresh_keeps_the_answer_and_forget_clears_it() {
        let mut state = EnvelopeV2State::new();
        state.begin_unlock(Some(DATA_KEK));
        let generation = state.start_attempt(Instant::now());
        state.record(generation, Level2Admission::Admitted);
        state.update_write_key(Some(DATA_KEK));
        assert!(state.write_key().is_some());
        state.forget();
        assert!(state.write_key().is_none());
        assert_eq!(state.admission(), Level2Admission::Unknown);
    }

    #[test]
    fn transient_failure_backs_off_before_retrying() {
        let mut state = EnvelopeV2State::new();
        state.begin_unlock(Some(DATA_KEK));
        let start = Instant::now();
        let generation = state.start_attempt(start);
        state.record(generation, Level2Admission::Unknown);
        assert!(!state.needs_admission(start + Duration::from_secs(60)));
        assert!(state.needs_admission(start + ADMISSION_RETRY_AFTER));
    }

    #[tokio::test]
    async fn admitted_response_is_cached_for_the_session() {
        let (base, calls) = spawn_admission(
            StatusCode::OK,
            serde_json::json!({"level2_admitted": true, "storage_rekey_level": 2}),
        )
        .await;
        let client = ApiClient::new_with_base_url(&base);
        let state = unlocked(Some(DATA_KEK));
        assert_eq!(ensure_admission_in(&state, &client, "tok").await, Level2Admission::Admitted);
        assert_eq!(ensure_admission_in(&state, &client, "tok").await, Level2Admission::Admitted);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(state.read().unwrap().write_key().is_some());
    }

    #[tokio::test]
    async fn not_admitted_conflict_keeps_the_current_format() {
        let (base, calls) = spawn_admission(
            StatusCode::CONFLICT,
            serde_json::json!({"code": "VAULT_LEVEL2_NOT_ADMITTED", "error": "not admitted"}),
        )
        .await;
        let client = ApiClient::new_with_base_url(&base);
        let state = unlocked(Some(DATA_KEK));
        assert_eq!(ensure_admission_in(&state, &client, "tok").await, Level2Admission::Refused);
        assert_eq!(ensure_admission_in(&state, &client, "tok").await, Level2Admission::Refused);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(state.read().unwrap().write_key().is_none());
    }

    #[tokio::test]
    async fn other_answers_stay_unknown_and_back_off() {
        for (status, body) in [
            (StatusCode::OK, serde_json::json!({"level2_admitted": false})),
            (StatusCode::OK, serde_json::json!({})),
            (StatusCode::CONFLICT, serde_json::json!({"code": "ENVELOPE_CHANGED"})),
            (StatusCode::TOO_MANY_REQUESTS, serde_json::json!({})),
            (StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({})),
            (StatusCode::NOT_FOUND, serde_json::json!({})),
        ] {
            let (base, calls) = spawn_admission(status, body).await;
            let client = ApiClient::new_with_base_url(&base);
            let state = unlocked(Some(DATA_KEK));
            assert_eq!(ensure_admission_in(&state, &client, "tok").await, Level2Admission::Unknown);
            assert_eq!(ensure_admission_in(&state, &client, "tok").await, Level2Admission::Unknown);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(state.read().unwrap().write_key().is_none());
        }
    }

    #[tokio::test]
    async fn no_data_kek_never_calls_the_server() {
        let (base, calls) = spawn_admission(
            StatusCode::OK,
            serde_json::json!({"level2_admitted": true, "storage_rekey_level": 2}),
        )
        .await;
        let client = ApiClient::new_with_base_url(&base);
        let state = unlocked(None);
        assert_eq!(ensure_admission_in(&state, &client, "tok").await, Level2Admission::Unknown);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
