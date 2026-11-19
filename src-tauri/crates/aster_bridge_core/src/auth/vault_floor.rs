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
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::session::VaultKeyMaterial;

const FLOOR_DIR: &str = "vault_floor";
const FLOOR_DOMAIN: &[u8] = b"aster-bridge-vault-floor-v1";

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFloor {
    #[serde(default)]
    current_identity: Option<String>,
    #[serde(default)]
    current_storage_key: Option<String>,
    #[serde(default)]
    retired: BTreeSet<String>,
}

fn floors() -> &'static Mutex<HashMap<Uuid, VaultFloor>> {
    static FLOORS: OnceLock<Mutex<HashMap<Uuid, VaultFloor>>> = OnceLock::new();
    FLOORS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn floor_root() -> &'static Mutex<Option<PathBuf>> {
    static ROOT: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    ROOT.get_or_init(|| Mutex::new(None))
}

pub fn use_data_dir(data_dir: &Path) {
    if let Ok(mut root) = floor_root().lock() {
        *root = Some(data_dir.join(FLOOR_DIR));
    }
}

fn tagged(kind: &[u8], material: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FLOOR_DOMAIN);
    hasher.update([kind.len() as u8]);
    hasher.update(kind);
    hasher.update(material);
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

fn identity_id(armored: &str) -> Option<String> {
    let normalized: String = armored.chars().filter(|c| !c.is_whitespace()).collect();
    (!normalized.is_empty()).then(|| tagged(b"identity", normalized.as_bytes()))
}

fn storage_key_id(b64: &str) -> Option<String> {
    let bytes = Zeroizing::new(STANDARD.decode(b64.trim()).ok()?);
    (bytes.len() == 32).then(|| tagged(b"storage", &bytes))
}

impl VaultFloor {
    pub fn admits(&self, material: &VaultKeyMaterial) -> bool {
        let identity_retired = identity_id(&material.identity_key).is_some_and(|id| self.retired.contains(&id));
        let storage_retired = material
            .data_kek
            .as_deref()
            .and_then(|key| storage_key_id(key))
            .is_some_and(|id| self.retired.contains(&id));
        !identity_retired && !storage_retired
    }

    pub fn advance(&mut self, material: &VaultKeyMaterial) {
        let identity = identity_id(&material.identity_key);
        for previous in material.previous_keys.iter() {
            if let Some(id) = identity_id(previous) {
                if Some(&id) != identity.as_ref() {
                    self.retired.insert(id);
                }
            }
        }
        if let Some(identity) = identity {
            if let Some(former) = self.current_identity.replace(identity.clone()) {
                if former != identity {
                    self.retired.insert(former);
                }
            }
        }
        if let Some(storage) = material.data_kek.as_deref().and_then(|key| storage_key_id(key)) {
            if let Some(former) = self.current_storage_key.replace(storage.clone()) {
                if former != storage {
                    self.retired.insert(former);
                }
            }
        }
    }
}

fn floor_file(root: &Path, user_id: &Uuid) -> PathBuf {
    root.join(format!("{}.json", user_id.simple()))
}

fn current_root() -> Result<PathBuf, String> {
    floor_root()
        .lock()
        .ok()
        .and_then(|root| root.clone())
        .ok_or_else(|| "the key record folder is not set".to_string())
}

fn load_floor(user_id: &Uuid) -> Result<VaultFloor, String> {
    let root = current_root()?;
    match std::fs::read(floor_file(&root, user_id)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("the key record could not be read: {}", e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VaultFloor::default()),
        Err(e) => Err(format!("the key record could not be read: {}", e)),
    }
}

fn store_floor(user_id: &Uuid, floor: &VaultFloor) -> Result<(), String> {
    let root = current_root()?;
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(floor).map_err(|e| e.to_string())?;
    crate::auth::device_identity::write_private_file(&floor_file(&root, user_id), &bytes)
}

fn with_floor<R>(user_id: &Uuid, f: impl FnOnce(&mut VaultFloor) -> R) -> Result<R, String> {
    let mut guard = floors().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if !guard.contains_key(user_id) {
        let loaded = load_floor(user_id)?;
        guard.insert(*user_id, loaded);
    }
    let floor = guard.get_mut(user_id).ok_or_else(|| "the key record is missing".to_string())?;
    Ok(f(floor))
}

pub fn check_vault(user_id: &Uuid, material: &VaultKeyMaterial) -> Result<bool, String> {
    with_floor(user_id, |floor| floor.admits(material))
}

pub fn admit_vault(user_id: &Uuid, material: &VaultKeyMaterial) -> bool {
    match check_vault(user_id, material) {
        Ok(admitted) => admitted,
        Err(e) => {
            tracing::warn!("the saved record of this account's keys could not be checked: {}", e);
            false
        }
    }
}

pub fn record_vault(user_id: &Uuid, material: &VaultKeyMaterial) -> Result<(), String> {
    with_floor(user_id, |floor| {
        let mut next = floor.clone();
        next.advance(material);
        if next == *floor {
            return Ok(());
        }
        store_floor(user_id, &next)?;
        *floor = next;
        Ok(())
    })?
}

pub fn forget_all(data_dir: &Path) -> Result<(), String> {
    floors().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    match std::fs::remove_dir_all(data_dir.join(FLOOR_DIR)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn isolated_root() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        static SERIAL: Mutex<()> = Mutex::new(());
        let guard = SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        use_data_dir(dir.path());
        (guard, dir)
    }

    fn unset_root() {
        *floor_root().lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    pub(crate) fn material(identity: &str, previous: &[&str], data_kek: Option<[u8; 32]>) -> VaultKeyMaterial {
        VaultKeyMaterial {
            identity_key: identity.to_string(),
            data_kek: data_kek.map(|key| Zeroizing::new(STANDARD.encode(key))),
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            previous_keys: Zeroizing::new(previous.iter().map(|k| k.to_string()).collect()),
            ratchet_recovery: Default::default(),
            mail_legacy_retired: false,
        }
    }

    #[test]
    fn a_vault_that_lists_the_old_identity_as_previous_retires_it() {
        let mut floor = VaultFloor::default();
        let old = material("old-key", &[], Some([1u8; 32]));
        assert!(floor.admits(&old));
        floor.advance(&old);
        let rotated = material("new-key", &["old-key"], Some([2u8; 32]));
        assert!(floor.admits(&rotated));
        floor.advance(&rotated);
        assert!(!floor.admits(&old));
        assert!(!floor.admits(&material("new-key", &["old-key"], Some([1u8; 32]))));
        assert!(floor.admits(&rotated));
    }

    #[test]
    fn a_storage_key_is_retired_only_after_it_was_current() {
        let mut floor = VaultFloor::default();
        floor.advance(&material("id", &[], None));
        assert!(floor.admits(&material("id", &[], Some([9u8; 32]))));
        floor.advance(&material("id", &[], Some([9u8; 32])));
        floor.advance(&material("id", &[], Some([8u8; 32])));
        assert!(!floor.admits(&material("id", &[], Some([9u8; 32]))));
        assert!(floor.admits(&material("id", &[], Some([8u8; 32]))));
    }

    #[test]
    fn a_recorded_rotation_is_read_back_from_the_data_dir() {
        let (_serial, dir) = isolated_root();
        let user = Uuid::new_v4();
        let _ = record_vault(&user, &material("first", &[], Some([5u8; 32])));
        let _ = record_vault(&user, &material("second", &["first"], Some([6u8; 32])));
        assert!(floor_file(&dir.path().join(FLOOR_DIR), &user).exists());
        floors().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&user);
        assert!(!admit_vault(&user, &material("first", &[], Some([5u8; 32]))));
        assert!(!admit_vault(&user, &material("second", &["first"], Some([5u8; 32]))));
        assert!(admit_vault(&user, &material("second", &["first"], Some([6u8; 32]))));
    }

    #[test]
    fn a_damaged_key_record_refuses_the_vault() {
        let (_serial, dir) = isolated_root();
        let user = Uuid::new_v4();
        let floor_path = dir.path().join(FLOOR_DIR);
        std::fs::create_dir_all(&floor_path).unwrap();
        std::fs::write(floor_file(&floor_path, &user), b"{\"retired\": [").unwrap();
        floors().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&user);
        assert!(!admit_vault(&user, &material("any", &[], Some([7u8; 32]))));
        let saved = format!("{:?}", record_vault(&user, &material("any", &[], Some([7u8; 32]))));
        assert!(saved.starts_with("Err"), "{saved}");
        assert_eq!(std::fs::read(floor_file(&floor_path, &user)).unwrap(), b"{\"retired\": [");
    }

    #[test]
    fn without_a_data_dir_nothing_is_admitted_or_reported_as_saved() {
        let (_serial, _dir) = isolated_root();
        unset_root();
        let user = Uuid::new_v4();
        assert!(!admit_vault(&user, &material("any", &[], Some([4u8; 32]))));
        let saved = format!("{:?}", record_vault(&user, &material("any", &[], Some([4u8; 32]))));
        assert!(saved.starts_with("Err"), "{saved}");
    }

    #[test]
    fn forgetting_the_records_admits_an_earlier_vault_again() {
        let (_serial, dir) = isolated_root();
        let user = Uuid::new_v4();
        let _ = record_vault(&user, &material("first", &[], Some([1u8; 32])));
        let _ = record_vault(&user, &material("second", &["first"], Some([2u8; 32])));
        assert!(!admit_vault(&user, &material("first", &[], Some([1u8; 32]))));
        forget_all(dir.path()).unwrap();
        assert!(!dir.path().join(FLOOR_DIR).exists());
        assert!(admit_vault(&user, &material("first", &[], Some([1u8; 32]))));
    }

    #[test]
    fn the_floor_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let floor_path = dir.path().join(FLOOR_DIR);
        let mut floor = VaultFloor::default();
        floor.advance(&material("a", &[], Some([3u8; 32])));
        floor.advance(&material("b", &["a"], Some([4u8; 32])));
        std::fs::create_dir_all(&floor_path).unwrap();
        crate::auth::device_identity::write_private_file(
            &floor_file(&floor_path, &user),
            &serde_json::to_vec(&floor).unwrap(),
        )
        .unwrap();
        let read: VaultFloor =
            serde_json::from_slice(&std::fs::read(floor_file(&floor_path, &user)).unwrap()).unwrap();
        assert_eq!(read, floor);
        assert!(!read.admits(&material("a", &[], Some([3u8; 32]))));
    }
}
