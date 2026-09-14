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
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api_client::{ApiClient, ReportEnvelopeCapability};
use crate::crypto::inbound::INBOUND_PQ_HYBRID_MARKER;

pub const MAX_ENVELOPE_MARKER: i16 = INBOUND_PQ_HYBRID_MARKER as i16;
pub const PLATFORM: &str = "bridge";
pub const REPORT_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;

const STATE_FILE: &str = "envelope_capability.json";
const IDENTITY_POINT_LEN: usize = 65;
const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CapabilityState {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub last_reported_at: HashMap<String, u64>,
    #[serde(default)]
    pub last_reported_fingerprint: HashMap<String, String>,
}

pub fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_FILE)
}

pub fn load_state(path: &Path) -> CapabilityState {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return CapabilityState::default();
    };
    serde_json::from_str(&contents).unwrap_or_default()
}

pub fn save_state(path: &Path, state: &CapabilityState) -> Result<(), String> {
    let contents = serde_json::to_string(state).map_err(|e| e.to_string())?;
    std::fs::write(path, contents).map_err(|e| e.to_string())
}

pub fn is_report_due(last_reported_at: u64, now: u64) -> bool {
    if last_reported_at == 0 {
        return true;
    }
    if now < last_reported_at {
        return true;
    }
    now - last_reported_at >= REPORT_INTERVAL_SECS
}

pub fn identity_fingerprint(identity_public_b64: Option<&str>) -> Option<String> {
    let encoded = identity_public_b64?.trim();
    if encoded.is_empty() {
        return None;
    }
    let point = STANDARD.decode(encoded).ok()?;
    if point.len() != IDENTITY_POINT_LEN || point[0] != UNCOMPRESSED_POINT_TAG {
        return None;
    }
    Some(STANDARD.encode(Sha256::digest(&point)))
}

pub fn is_report_due_for(
    state: &CapabilityState,
    user_id: &str,
    fingerprint: Option<&str>,
    now: u64,
) -> bool {
    if is_report_due(
        state.last_reported_at.get(user_id).copied().unwrap_or(0),
        now,
    ) {
        return true;
    }
    match fingerprint {
        Some(current) => {
            state.last_reported_fingerprint.get(user_id).map(String::as_str) != Some(current)
        }
        None => false,
    }
}

pub fn ensure_client_id(state: &mut CapabilityState) -> String {
    if state.client_id.trim().is_empty() {
        state.client_id = uuid::Uuid::new_v4().to_string();
    }
    state.client_id.clone()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn report_if_due(
    client: &ApiClient,
    access_token: &str,
    user_id: &str,
    identity_public_b64: Option<&str>,
    data_dir: &Path,
) {
    if user_id.trim().is_empty() {
        return;
    }

    let path = state_path(data_dir);
    let mut state = load_state(&path);
    let now = unix_now();
    let fingerprint = identity_fingerprint(identity_public_b64);

    if !is_report_due_for(&state, user_id, fingerprint.as_deref(), now) {
        return;
    }

    let client_id = ensure_client_id(&mut state);
    let body = ReportEnvelopeCapability {
        client_id: &client_id,
        max_envelope_marker: MAX_ENVELOPE_MARKER,
        platform: PLATFORM,
        identity_fingerprint: fingerprint.as_deref(),
    };

    match client.report_envelope_capability(access_token, &body).await {
        Ok(response) if response.success => {
            state.last_reported_at.insert(user_id.to_string(), now);
            match fingerprint.as_deref() {
                Some(current) => {
                    state
                        .last_reported_fingerprint
                        .insert(user_id.to_string(), current.to_string());
                }
                None => {
                    state.last_reported_fingerprint.remove(user_id);
                }
            }
            if let Err(e) = save_state(&path, &state) {
                tracing::warn!("envelope capability: cannot persist report state: {}", e);
            }
            if !response.identity_verified {
                tracing::warn!(
                    "envelope capability: the server has not confirmed this identity key, so inbound mail stays unsealed"
                );
            }
            tracing::debug!(
                "envelope capability reported: min={:?} pq={} verified={}",
                response.min_supported_marker,
                response.pq_hybrid_enabled,
                response.identity_verified
            );
        }
        Ok(_) => {
            tracing::warn!("envelope capability: server rejected the report");
        }
        Err(e) => {
            tracing::debug!("envelope capability: report failed, retrying later: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_reports_the_pq_hybrid_marker() {
        assert_eq!(MAX_ENVELOPE_MARKER, 4);
        assert_eq!(MAX_ENVELOPE_MARKER, INBOUND_PQ_HYBRID_MARKER as i16);
    }

    #[test]
    fn a_never_reported_user_is_due() {
        assert!(is_report_due(0, 1_000_000));
    }

    #[test]
    fn a_recent_report_is_not_due() {
        assert!(!is_report_due(1_000_000, 1_000_000 + 60));
    }

    #[test]
    fn a_report_older_than_the_interval_is_due() {
        assert!(is_report_due(1_000_000, 1_000_000 + REPORT_INTERVAL_SECS));
    }

    #[test]
    fn a_backwards_clock_reports_instead_of_going_silent() {
        assert!(is_report_due(1_000_000, 5));
    }

    #[test]
    fn the_report_interval_stays_inside_the_server_ttl() {
        assert!(REPORT_INTERVAL_SECS < 90 * 24 * 60 * 60);
    }

    #[test]
    fn a_missing_state_file_loads_as_default() {
        let dir = tempfile::tempdir().unwrap();
        let state = load_state(&state_path(dir.path()));
        assert!(state.client_id.is_empty());
        assert!(state.last_reported_at.is_empty());
    }

    #[test]
    fn a_corrupt_state_file_loads_as_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());
        std::fs::write(&path, "{ not json").unwrap();
        assert!(load_state(&path).client_id.is_empty());
    }

    #[test]
    fn the_client_id_is_generated_once_and_reused() {
        let mut state = CapabilityState::default();
        let first = ensure_client_id(&mut state);
        let second = ensure_client_id(&mut state);
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[test]
    fn a_blank_client_id_is_regenerated() {
        let mut state = CapabilityState {
            client_id: "   ".to_string(),
            ..Default::default()
        };
        let id = ensure_client_id(&mut state);
        assert!(!id.trim().is_empty());
        assert_eq!(id, state.client_id);
    }

    #[test]
    fn state_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());
        let mut state = CapabilityState::default();
        let client_id = ensure_client_id(&mut state);
        state.last_reported_at.insert("user-a".to_string(), 42);
        save_state(&path, &state).unwrap();

        let loaded = load_state(&path);
        assert_eq!(loaded.client_id, client_id);
        assert_eq!(loaded.last_reported_at.get("user-a"), Some(&42));
        assert!(!is_report_due(42, 43));
    }

    fn sample_identity_public() -> String {
        STANDARD.encode(vec![UNCOMPRESSED_POINT_TAG; IDENTITY_POINT_LEN])
    }

    #[test]
    fn the_fingerprint_is_base64_sha256_of_the_uncompressed_point() {
        assert_eq!(
            identity_fingerprint(Some(&sample_identity_public())).as_deref(),
            Some("m9qVvaHvjxth9tRyI/ShGQuZUH122OQ0l7t7F25Zy2U=")
        );
    }

    #[test]
    fn the_fingerprint_matches_the_shared_cross_client_vector() {
        let mut point = vec![UNCOMPRESSED_POINT_TAG];
        point.extend(std::iter::repeat(0x11).take(64));
        assert_eq!(
            identity_fingerprint(Some(&STANDARD.encode(point))).as_deref(),
            Some("8LkxWgRZ2rerX6aQPnM8kXdhFUIWzZDl2XnabIUsYCo=")
        );
    }

    #[test]
    fn a_missing_or_blank_identity_key_has_no_fingerprint() {
        assert!(identity_fingerprint(None).is_none());
        assert!(identity_fingerprint(Some("   ")).is_none());
    }

    #[test]
    fn a_malformed_identity_key_has_no_fingerprint() {
        assert!(identity_fingerprint(Some("not base64 $$")).is_none());
        assert!(identity_fingerprint(Some(&STANDARD.encode(vec![UNCOMPRESSED_POINT_TAG; 33]))).is_none());
        assert!(identity_fingerprint(Some(&STANDARD.encode(vec![0x02; IDENTITY_POINT_LEN]))).is_none());
    }

    #[test]
    fn a_changed_fingerprint_forces_an_immediate_report() {
        let mut state = CapabilityState::default();
        state.last_reported_at.insert("user-a".to_string(), 1_000_000);
        state
            .last_reported_fingerprint
            .insert("user-a".to_string(), "old-fingerprint".to_string());
        assert!(is_report_due_for(&state, "user-a", Some("new-fingerprint"), 1_000_060));
    }

    #[test]
    fn an_unchanged_fingerprint_waits_for_the_interval() {
        let mut state = CapabilityState::default();
        state.last_reported_at.insert("user-a".to_string(), 1_000_000);
        state
            .last_reported_fingerprint
            .insert("user-a".to_string(), "same-fingerprint".to_string());
        assert!(!is_report_due_for(&state, "user-a", Some("same-fingerprint"), 1_000_060));
        assert!(is_report_due_for(
            &state,
            "user-a",
            Some("same-fingerprint"),
            1_000_000 + REPORT_INTERVAL_SECS
        ));
    }

    #[test]
    fn a_first_fingerprint_after_a_null_report_is_due() {
        let mut state = CapabilityState::default();
        state.last_reported_at.insert("user-a".to_string(), 1_000_000);
        assert!(is_report_due_for(&state, "user-a", Some("fingerprint"), 1_000_060));
    }

    #[test]
    fn a_locked_vault_does_not_force_a_report() {
        let mut state = CapabilityState::default();
        state.last_reported_at.insert("user-a".to_string(), 1_000_000);
        state
            .last_reported_fingerprint
            .insert("user-a".to_string(), "fingerprint".to_string());
        assert!(!is_report_due_for(&state, "user-a", None, 1_000_060));
    }

    #[test]
    fn state_written_by_an_older_build_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(dir.path());
        std::fs::write(
            &path,
            r#"{"client_id":"abc","last_reported_at":{"user-a":42}}"#,
        )
        .unwrap();
        let state = load_state(&path);
        assert_eq!(state.client_id, "abc");
        assert_eq!(state.last_reported_at.get("user-a"), Some(&42));
        assert!(state.last_reported_fingerprint.is_empty());
        assert!(is_report_due_for(&state, "user-a", Some("fingerprint"), 43));
    }

    #[test]
    fn each_user_tracks_its_own_report_time() {
        let mut state = CapabilityState::default();
        state.last_reported_at.insert("user-a".to_string(), 1_000_000);
        let now = 1_000_060;
        assert!(!is_report_due(
            state.last_reported_at.get("user-a").copied().unwrap_or(0),
            now
        ));
        assert!(is_report_due(
            state.last_reported_at.get("user-b").copied().unwrap_or(0),
            now
        ));
    }
}
