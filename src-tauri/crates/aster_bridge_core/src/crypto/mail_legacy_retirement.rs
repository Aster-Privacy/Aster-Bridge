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
use std::sync::RwLock;

use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAIL_LEGACY_RETIREMENT_VERSION: i64 = 1;

const PIN_PREFIX: &str = "mail_legacy_retired_";
const PUBLIC_KEY_MATERIAL: &str = "undefined";
const PUBLIC_MAIL_KEY_CONTEXTS: &[&str] = &["astermail-envelope-v1", "astermail-import-v1"];

static PIN_DIR: RwLock<Option<PathBuf>> = RwLock::new(None);
static PINNED_USERS: RwLock<Vec<Uuid>> = RwLock::new(Vec::new());

#[cfg(not(test))]
static RETIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    static THREAD_RETIRED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn store_retired(value: bool) {
    #[cfg(test)]
    THREAD_RETIRED.with(|cell| cell.set(value));
    #[cfg(not(test))]
    RETIRED.store(value, std::sync::atomic::Ordering::SeqCst);
}

pub fn is_mail_legacy_retired() -> bool {
    #[cfg(test)]
    return THREAD_RETIRED.with(|cell| cell.get());
    #[cfg(not(test))]
    RETIRED.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn is_valid_retired_marker(marker: &serde_json::Value) -> bool {
    let Some(record) = marker.as_object() else {
        return false;
    };
    let version_ok = record
        .get("v")
        .and_then(serde_json::Value::as_i64)
        .is_some_and(|v| v >= MAIL_LEGACY_RETIREMENT_VERSION);
    version_ok && record.get("at").is_some_and(serde_json::Value::is_string)
}

pub fn set_mail_legacy_pin_dir(data_dir: &Path) {
    *PIN_DIR
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(data_dir.to_path_buf());
}

pub fn mail_legacy_pin_dir() -> Option<PathBuf> {
    PIN_DIR
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn pin_path(dir: &Path, user_id: &Uuid) -> PathBuf {
    dir.join(format!("{}{}", PIN_PREFIX, user_id))
}

fn read_pin(dir: Option<&Path>, user_id: &Uuid) -> Result<bool, String> {
    let in_memory = PINNED_USERS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(user_id);
    let Some(d) = dir.filter(|_| !in_memory) else {
        return Ok(in_memory);
    };
    let path = pin_path(d, user_id);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text.trim() == "1"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && d.is_dir() => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "the folder {} for the stored mail key state is missing or is not a folder",
            d.display()
        )),
        Err(e) => Err(format!(
            "the stored mail key state in {} could not be read: {}",
            path.display(),
            e
        )),
    }
}

fn write_pin(dir: Option<&Path>, user_id: &Uuid) -> Result<(), String> {
    {
        let mut pinned = PINNED_USERS
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !pinned.contains(user_id) {
            pinned.push(*user_id);
        }
    }
    let d =
        dir.ok_or_else(|| "there is no folder to record the stored mail key state".to_string())?;
    let path = pin_path(d, user_id);
    if std::fs::read_to_string(&path).is_ok_and(|text| text.trim() == "1") {
        return Ok(());
    }
    crate::auth::device_identity::write_private_file(&path, b"1").map_err(|e| {
        format!(
            "the stored mail key state in {} could not be recorded: {}",
            path.display(),
            e
        )
    })
}

pub fn note_vault_mail_legacy_marker(marked: bool) {
    if marked {
        store_retired(true);
    }
}

pub(crate) fn sync_mail_legacy_retirement_in(
    dir: Option<&Path>,
    marked: bool,
    user_id: &Uuid,
) -> Result<bool, String> {
    let pinned = if marked {
        write_pin(dir, user_id).map(|()| true)
    } else {
        read_pin(dir, user_id)
    };
    store_retired(marked || pinned.as_ref().map_or(true, |retired| *retired));
    pinned.map(|retired| marked || retired)
}

pub fn sync_mail_legacy_retirement(marked: bool, user_id: &Uuid) -> Result<bool, String> {
    let dir = mail_legacy_pin_dir();
    sync_mail_legacy_retirement_in(dir.as_deref(), marked, user_id)
}

pub fn reset_mail_legacy_retirement() {
    store_retired(false);
}

pub fn is_public_mail_key(key: &[u8; 32]) -> bool {
    PUBLIC_MAIL_KEY_CONTEXTS.iter().any(|context| {
        let mut hasher = Sha256::new();
        hasher.update(PUBLIC_KEY_MATERIAL.as_bytes());
        hasher.update(context.as_bytes());
        let derived: [u8; 32] = hasher.finalize().into();
        derived == *key
    })
}

pub fn is_public_identity_material(identity_key: &str) -> bool {
    let trimmed = identity_key.trim();
    trimmed.is_empty() || trimmed == PUBLIC_KEY_MATERIAL || trimmed == "null"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_marker_needs_an_integer_version_and_a_time() {
        assert!(is_valid_retired_marker(
            &json!({ "v": 1, "at": "2026-11-17T00:00:00Z" })
        ));
        assert!(is_valid_retired_marker(&json!({ "v": 3, "at": "x" })));
        assert!(!is_valid_retired_marker(&json!({ "v": 0, "at": "x" })));
        assert!(!is_valid_retired_marker(&json!({ "v": 1.5, "at": "x" })));
        assert!(!is_valid_retired_marker(&json!({ "v": "1", "at": "x" })));
        assert!(!is_valid_retired_marker(&json!({ "v": 1 })));
        assert!(!is_valid_retired_marker(&json!({ "v": 1, "at": 5 })));
        assert!(!is_valid_retired_marker(&json!(true)));
        assert!(!is_valid_retired_marker(&json!(null)));
    }

    #[test]
    fn a_seen_marker_stays_pinned_when_a_later_vault_omits_it() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(!sync_mail_legacy_retirement_in(Some(dir.path()), false, &user).unwrap());
        assert!(!is_mail_legacy_retired());
        assert!(sync_mail_legacy_retirement_in(Some(dir.path()), true, &user).unwrap());
        assert!(is_mail_legacy_retired());
        assert!(sync_mail_legacy_retirement_in(Some(dir.path()), false, &user).unwrap());
        assert!(is_mail_legacy_retired());
        assert!(!sync_mail_legacy_retirement_in(Some(dir.path()), false, &other).unwrap());
        assert!(!is_mail_legacy_retired());
    }

    #[test]
    fn the_pin_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        write_pin(Some(dir.path()), &user).unwrap();
        PINNED_USERS
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|u| *u != user);
        assert!(sync_mail_legacy_retirement_in(Some(dir.path()), false, &user).unwrap());
    }

    fn blocked_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("blocked");
        std::fs::write(&blocked, "not a folder").unwrap();
        (dir, blocked)
    }

    #[test]
    fn a_retired_state_that_cannot_be_recorded_is_refused() {
        let (_dir, blocked) = blocked_dir();
        let user = Uuid::new_v4();
        let outcome = format!(
            "{:?}",
            sync_mail_legacy_retirement_in(Some(&blocked), true, &user)
        );
        assert!(
            outcome.starts_with("Err"),
            "a retired state that was not recorded was accepted: {}",
            outcome
        );
        assert!(is_mail_legacy_retired());
    }

    #[test]
    fn an_unreadable_retired_state_counts_as_retired() {
        let (_dir, blocked) = blocked_dir();
        let user = Uuid::new_v4();
        let outcome = format!(
            "{:?}",
            sync_mail_legacy_retirement_in(Some(&blocked), false, &user)
        );
        assert!(
            outcome.starts_with("Err"),
            "an unreadable retired state was accepted: {}",
            outcome
        );
        assert!(
            is_mail_legacy_retired(),
            "an unreadable retired state read as not retired"
        );
    }

    #[test]
    fn a_missing_state_folder_counts_as_retired_on_every_platform() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone");
        let user = Uuid::new_v4();
        let outcome = format!(
            "{:?}",
            sync_mail_legacy_retirement_in(Some(&gone), false, &user)
        );
        assert!(
            outcome.starts_with("Err"),
            "a missing state folder read as not retired: {}",
            outcome
        );
        assert!(is_mail_legacy_retired());
        assert!(!gone.exists());
    }

    #[test]
    fn a_pin_path_that_is_a_folder_counts_as_retired() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        std::fs::create_dir(pin_path(dir.path(), &user)).unwrap();
        let outcome = format!(
            "{:?}",
            sync_mail_legacy_retirement_in(Some(dir.path()), false, &user)
        );
        assert!(
            outcome.starts_with("Err"),
            "a pin path that is a folder read as not retired: {}",
            outcome
        );
        assert!(is_mail_legacy_retired());
    }

    #[test]
    fn a_damaged_pin_file_counts_as_retired_and_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let path = pin_path(dir.path(), &user);
        std::fs::write(&path, [0xff, 0xfe, 0x80]).unwrap();
        let outcome = sync_mail_legacy_retirement_in(Some(dir.path()), false, &user);
        let message = outcome.expect_err("a damaged pin file was accepted");
        assert!(
            message.contains(&path.display().to_string()),
            "the message does not name the file: {}",
            message
        );
        assert!(is_mail_legacy_retired());
        assert_eq!(std::fs::read(&path).unwrap(), vec![0xff, 0xfe, 0x80]);
    }

    #[test]
    fn public_mail_keys_are_recognized() {
        let mut hasher = Sha256::new();
        hasher.update(b"undefinedastermail-envelope-v1");
        let public: [u8; 32] = hasher.finalize().into();
        assert!(is_public_mail_key(&public));
        assert!(!is_public_mail_key(&[7u8; 32]));
        assert!(is_public_identity_material(""));
        assert!(is_public_identity_material("undefined"));
        assert!(!is_public_identity_material("real-identity-key"));
    }
}
