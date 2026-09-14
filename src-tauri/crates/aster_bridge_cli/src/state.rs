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

use aster_bridge_core::account_state::AccountState;
use aster_bridge_core::runtime::BoundPorts;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const STATE_FILE: &str = "state.json";

static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const PENDING_FILE: &str = "pending_login.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub user_id: String,
    pub email: String,
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortsInfo {
    pub imap: u16,
    pub imaps: u16,
    pub smtp: u16,
    pub smtps: u16,
    pub pop3: u16,
    pub pop3s: u16,
    pub jmap: u16,
    pub carddav: u16,
}

impl From<BoundPorts> for PortsInfo {
    fn from(p: BoundPorts) -> Self {
        Self {
            imap: p.imap,
            imaps: p.imaps,
            smtp: p.smtp,
            smtps: p.smtps,
            pop3: p.pop3,
            pop3s: p.pop3s,
            jmap: p.jmap,
            carddav: p.carddav,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanInfo {
    pub code: Option<String>,
    pub has_bridge_access: bool,
    pub checked_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StopInfo {
    pub reason: String,
    pub at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncInfo {
    pub at: i64,
    pub failed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliState {
    #[serde(default)]
    pub account: Option<AccountInfo>,
    #[serde(default)]
    pub plan: Option<PlanInfo>,
    #[serde(default)]
    pub account_state: AccountState,
    #[serde(default)]
    pub ports: Option<PortsInfo>,
    #[serde(default)]
    pub last_stop: Option<StopInfo>,
    #[serde(default)]
    pub last_sync: Option<SyncInfo>,
    #[serde(default)]
    pub cache_user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingLogin {
    pub code: String,
    pub normalized: String,
    pub expires_at: i64,
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_FILE)
}

fn pending_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PENDING_FILE)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn load(data_dir: &Path) -> CliState {
    read_json(&state_path(data_dir)).unwrap_or_default()
}

pub fn save(data_dir: &Path, state: &CliState) -> Result<(), String> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
    write_private(&state_path(data_dir), &bytes)
}

pub fn update(data_dir: &Path, f: impl FnOnce(&mut CliState)) -> Result<CliState, String> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut state = load(data_dir);
    f(&mut state);
    let bytes = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    write_private(&state_path(data_dir), &bytes)?;
    Ok(state)
}

pub fn remove(data_dir: &Path) {
    let _ = std::fs::remove_file(state_path(data_dir));
}

pub fn load_pending(data_dir: &Path) -> Option<PendingLogin> {
    read_json(&pending_path(data_dir))
}

pub fn save_pending(data_dir: &Path, pending: &PendingLogin) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(pending).map_err(|e| e.to_string())?;
    write_private(&pending_path(data_dir), &bytes)
}

pub fn clear_pending(data_dir: &Path) {
    let _ = std::fs::remove_file(pending_path(data_dir));
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{}.{}.tmp", file_name, std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("couldn't write {}: {}", path.display(), e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_corrupt_state_loads_as_default() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).account.is_none());
        std::fs::write(dir.path().join(STATE_FILE), b"{not json").unwrap();
        assert!(load(dir.path()).account.is_none());
    }

    #[test]
    fn update_persists_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        update(dir.path(), |s| {
            s.account = Some(AccountInfo {
                user_id: "u1".into(),
                email: "a@example.test".into(),
                username: "a".into(),
                display_name: None,
            });
            s.account_state = AccountState::Suspended;
        })
        .unwrap();
        update(dir.path(), |s| s.account_state = AccountState::Active).unwrap();
        let loaded = load(dir.path());
        assert_eq!(loaded.account.unwrap().email, "a@example.test");
        assert_eq!(loaded.account_state, AccountState::Active);
    }

    #[test]
    fn pending_login_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let pending = PendingLogin {
            code: "AB12-CD34".into(),
            normalized: "AB12CD34".into(),
            expires_at: 42,
        };
        save_pending(dir.path(), &pending).unwrap();
        assert_eq!(load_pending(dir.path()), Some(pending));
        clear_pending(dir.path());
        assert_eq!(load_pending(dir.path()), None);
    }
}
