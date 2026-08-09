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

use serde::{Deserialize, Serialize};

use crate::api_client::{ApiClient, ReportEnvelopeCapability};
use crate::crypto::inbound::INBOUND_PQ_HYBRID_MARKER;

pub const MAX_ENVELOPE_MARKER: i16 = INBOUND_PQ_HYBRID_MARKER as i16;
pub const PLATFORM: &str = "bridge";
pub const REPORT_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;

const STATE_FILE: &str = "envelope_capability.json";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CapabilityState {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub last_reported_at: HashMap<String, u64>,
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
    data_dir: &Path,
) {
    if user_id.trim().is_empty() {
        return;
    }

    let path = state_path(data_dir);
    let mut state = load_state(&path);
    let now = unix_now();

    let last = state.last_reported_at.get(user_id).copied().unwrap_or(0);
    if !is_report_due(last, now) {
        return;
    }

    let client_id = ensure_client_id(&mut state);
    let body = ReportEnvelopeCapability {
        client_id: &client_id,
        max_envelope_marker: MAX_ENVELOPE_MARKER,
        platform: PLATFORM,
    };

    match client.report_envelope_capability(access_token, &body).await {
        Ok(response) if response.success => {
            state.last_reported_at.insert(user_id.to_string(), now);
            if let Err(e) = save_state(&path, &state) {
                tracing::warn!("envelope capability: cannot persist report state: {}", e);
            }
            tracing::debug!(
                "envelope capability reported: min={:?} pq={}",
                response.min_supported_marker,
                response.pq_hybrid_enabled
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
            last_reported_at: HashMap::new(),
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
