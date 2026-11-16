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
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PENDING_FILE: &str = "guard_pending.json";
const CODE_SECRET: &str = "guard-pending-code";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingActivation {
    pub device_id: Uuid,
    pub activates_at: DateTime<Utc>,
    #[serde(default)]
    pub change_id: Option<Uuid>,
    #[serde(default, skip_serializing)]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_device_id: Option<Uuid>,
}

impl PendingActivation {
    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        now >= self.activates_at
    }
}

fn pending_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PENDING_FILE)
}

fn read_record(data_dir: &Path) -> Option<PendingActivation> {
    let bytes = std::fs::read(pending_path(data_dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_record(data_dir: &Path, pending: &PendingActivation) -> Result<(), String> {
    let bytes = serde_json::to_vec(pending).map_err(|e| e.to_string())?;
    crate::atomic_file::write(&pending_path(data_dir), &bytes)
}

fn move_plain_code(data_dir: &Path, record: &PendingActivation, code: &str) {
    if let Err(e) = crate::secrets::set(CODE_SECRET, code) {
        tracing::warn!("couldn't move the held link code to the secret store: {}", e);
        return;
    }
    if let Err(e) = write_record(data_dir, record) {
        tracing::warn!("couldn't rewrite the pending activation record: {}", e);
    }
}

pub fn load(data_dir: &Path) -> Option<PendingActivation> {
    let mut record = read_record(data_dir)?;
    match record.code.as_deref() {
        Some(code) => move_plain_code(data_dir, &record, code),
        None => {
            record.code = crate::secrets::get(CODE_SECRET).unwrap_or_else(|e| {
                tracing::warn!("couldn't read the held link code: {}", e);
                None
            });
        }
    }
    Some(record)
}

pub fn save(data_dir: &Path, pending: &PendingActivation) -> Result<(), String> {
    match pending.code.as_deref() {
        Some(code) => {
            crate::secrets::set(CODE_SECRET, code)?;
            if let Err(e) = write_record(data_dir, pending) {
                let _ = crate::secrets::delete(CODE_SECRET);
                return Err(e);
            }
            Ok(())
        }
        None => {
            write_record(data_dir, pending)?;
            forget_code();
            Ok(())
        }
    }
}

fn forget_code() {
    if let Err(e) = crate::secrets::delete(CODE_SECRET) {
        tracing::warn!("couldn't remove the held link code: {}", e);
    }
}

pub fn clear(data_dir: &Path) {
    let path = pending_path(data_dir);
    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!("couldn't remove the pending activation record: {}", e);
        }
    }
    forget_code();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PendingActivation {
        PendingActivation {
            device_id: Uuid::parse_str("8d4f2b1e-3c6a-4e5f-9a7b-1c2d3e4f5a6b").unwrap(),
            activates_at: DateTime::parse_from_rfc3339("2026-11-15T11:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            change_id: None,
            code: None,
            replaced_device_id: None,
        }
    }

    #[tokio::test]
    async fn missing_file_means_no_pending_state() {
        let _secrets = crate::secrets::test_backend_lock().await;
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()), None);
        clear(dir.path());
    }

    #[tokio::test]
    async fn record_round_trips_and_clears() {
        let _secrets = crate::secrets::test_backend_lock().await;
        let dir = tempfile::tempdir().unwrap();
        let record = sample();
        save(dir.path(), &record).unwrap();
        assert_eq!(load(dir.path()), Some(record));
        clear(dir.path());
        assert_eq!(load(dir.path()), None);
    }

    #[tokio::test]
    async fn a_corrupt_file_reads_as_no_pending_state() {
        let _secrets = crate::secrets::test_backend_lock().await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PENDING_FILE), b"{not json").unwrap();
        assert_eq!(load(dir.path()), None);
    }

    #[tokio::test]
    async fn a_record_without_a_code_still_loads() {
        let _secrets = crate::secrets::test_backend_lock().await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(PENDING_FILE),
            br#"{"device_id":"8d4f2b1e-3c6a-4e5f-9a7b-1c2d3e4f5a6b","activates_at":"2026-11-15T11:00:00Z","change_id":null}"#,
        )
        .unwrap();
        assert_eq!(load(dir.path()), Some(sample()));
    }

    #[tokio::test]
    async fn a_held_code_round_trips() {
        let _secrets = crate::secrets::test_backend_lock().await;
        let dir = tempfile::tempdir().unwrap();
        let record = PendingActivation {
            code: Some("ABCD1234".to_string()),
            ..sample()
        };
        save(dir.path(), &record).unwrap();
        assert_eq!(load(dir.path()).unwrap().code.as_deref(), Some("ABCD1234"));
        let on_disk = std::fs::read_to_string(dir.path().join(PENDING_FILE)).unwrap();
        assert!(!on_disk.contains("ABCD1234"));
        assert!(!on_disk.contains("code"));
        assert_eq!(crate::secrets::get(CODE_SECRET).unwrap().as_deref(), Some("ABCD1234"));
        clear(dir.path());
        assert_eq!(crate::secrets::get(CODE_SECRET).unwrap(), None);
    }

    #[tokio::test]
    async fn a_plain_code_from_an_older_record_moves_to_the_secret_store() {
        let _secrets = crate::secrets::test_backend_lock().await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(PENDING_FILE),
            br#"{"device_id":"8d4f2b1e-3c6a-4e5f-9a7b-1c2d3e4f5a6b","activates_at":"2026-11-15T11:00:00Z","change_id":null,"code":"ABCD1234"}"#,
        )
        .unwrap();
        assert_eq!(load(dir.path()).unwrap().code.as_deref(), Some("ABCD1234"));
        let on_disk = std::fs::read_to_string(dir.path().join(PENDING_FILE)).unwrap();
        assert!(!on_disk.contains("ABCD1234"));
        assert_eq!(crate::secrets::get(CODE_SECRET).unwrap().as_deref(), Some("ABCD1234"));
        assert_eq!(load(dir.path()).unwrap().code.as_deref(), Some("ABCD1234"));
    }

    #[tokio::test]
    async fn saving_without_a_code_drops_the_held_code() {
        let _secrets = crate::secrets::test_backend_lock().await;
        let dir = tempfile::tempdir().unwrap();
        save(
            dir.path(),
            &PendingActivation {
                code: Some("ABCD1234".to_string()),
                ..sample()
            },
        )
        .unwrap();
        save(dir.path(), &sample()).unwrap();
        assert_eq!(load(dir.path()), Some(sample()));
        assert_eq!(crate::secrets::get(CODE_SECRET).unwrap(), None);
    }

    #[test]
    fn due_only_once_the_hold_has_ended() {
        let record = sample();
        assert!(!record.is_due(record.activates_at - chrono::Duration::seconds(1)));
        assert!(record.is_due(record.activates_at));
    }
}
