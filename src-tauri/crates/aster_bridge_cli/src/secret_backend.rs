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

use aster_bridge_core::secrets::{self, SecretBackend, CLI_KEYRING_SERVICE};
use serde::{Deserialize, Serialize};

use crate::cli::SecretBackendChoice;
use crate::exit::{CliError, CliResult, CODE_INTERNAL};

const RECORD_FILE: &str = "secret_backend";
const SECRETS_DIR: &str = "secrets";
const KEY_FILE_ENV: &str = "ASTER_BRIDGE_SECRET_KEY_FILE";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", rename_all = "snake_case")]
enum Record {
    Keyring { service: String },
    File,
}

impl Record {
    fn name(&self) -> &'static str {
        match self {
            Record::Keyring { .. } => "keyring",
            Record::File => "file",
        }
    }
}

fn record_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RECORD_FILE)
}

fn read_record(data_dir: &Path) -> Option<Record> {
    let bytes = std::fs::read(record_path(data_dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn has_record(data_dir: &Path) -> bool {
    read_record(data_dir).is_some()
}

pub fn recorded_name(data_dir: &Path) -> Option<&'static str> {
    read_record(data_dir).map(|record| record.name())
}

pub fn secrets_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(SECRETS_DIR)
}

pub fn remove_record(data_dir: &Path) {
    let _ = std::fs::remove_file(record_path(data_dir));
    let dir = data_dir.join(SECRETS_DIR);
    if std::fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_none()) {
        let _ = std::fs::remove_dir(&dir);
    }
}

pub fn key_file_path() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(KEY_FILE_ENV).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(value));
    }
    let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").filter(|v| !v.is_empty())?;
    let path = PathBuf::from(credentials).join("secret-key");
    path.exists().then_some(path)
}

fn keyring_service(data_dir: &Path) -> String {
    match crate::context::folder_tag(data_dir) {
        None => CLI_KEYRING_SERVICE.to_string(),
        Some(tag) => format!("{}.{}", CLI_KEYRING_SERVICE, tag),
    }
}

fn key_file_hint() -> String {
    format!(
        "To store keys in a file instead, create a key with: openssl rand -hex 32 > secret-key && chmod 600 secret-key\nThen set {}=/path/to/secret-key and run the command again with --secret-backend file.",
        KEY_FILE_ENV
    )
}

fn build_file(data_dir: &Path) -> CliResult<SecretBackend> {
    let Some(path) = key_file_path() else {
        return Err(CliError::secret_store(format!(
            "No secret key file is set. Set {} to a file that holds a 32-byte key.",
            KEY_FILE_ENV
        ))
        .with_hint(key_file_hint()));
    };
    let key = secrets::load_key_file(&path).map_err(|e| {
        CliError::secret_store(format!("Couldn't use the secret key file: {}", e)).with_hint(key_file_hint())
    })?;
    let dir = data_dir.join(SECRETS_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| {
        CliError::secret_store(format!("Couldn't create {}: {}", dir.display(), e))
    })?;
    secrets::restrict_permissions(&dir, true);
    Ok(SecretBackend::File { dir, key })
}

fn build_keyring(service: &str) -> CliResult<SecretBackend> {
    secrets::probe_keyring(service).map_err(|e| {
        CliError::secret_store(format!("The system keyring isn't available: {}", e)).with_hint(key_file_hint())
    })?;
    Ok(SecretBackend::Keyring {
        service: service.to_string(),
    })
}

fn build(data_dir: &Path, record: &Record) -> CliResult<SecretBackend> {
    match record {
        Record::Keyring { service } => build_keyring(service),
        Record::File => build_file(data_dir),
    }
}

fn choose(data_dir: &Path, choice: SecretBackendChoice) -> CliResult<(Record, SecretBackend)> {
    let keyring = Record::Keyring {
        service: keyring_service(data_dir),
    };
    match choice {
        SecretBackendChoice::Keyring => Ok((keyring.clone(), build(data_dir, &keyring)?)),
        SecretBackendChoice::File => Ok((Record::File, build_file(data_dir)?)),
        SecretBackendChoice::Auto => {
            let keyring_error = match build(data_dir, &keyring) {
                Ok(backend) => return Ok((keyring, backend)),
                Err(e) => e,
            };
            if key_file_path().is_some() {
                return Ok((Record::File, build_file(data_dir)?));
            }
            tracing::debug!("keyring probe failed: {}", keyring_error.message);
            Err(CliError::secret_store(
                "Aster Bridge can't find a place to store encryption keys. The system keyring isn't available and no secret key file is set.",
            )
            .with_hint(key_file_hint()))
        }
    }
}

fn check_choice(record: &Record, choice: SecretBackendChoice) -> CliResult<()> {
    let requested = match choice {
        SecretBackendChoice::Auto => return Ok(()),
        SecretBackendChoice::Keyring => "keyring",
        SecretBackendChoice::File => "file",
    };
    if record.name() == requested {
        return Ok(());
    }
    Err(CliError::secret_store(format!(
        "This data folder stores its keys in the {} backend, not the {} backend.",
        record.name(),
        requested
    ))
    .with_hint("To switch backends, sign out with aster-bridge logout and sign in again with the backend you want."))
}

pub fn activate_existing(data_dir: &Path, choice: SecretBackendChoice) -> CliResult<Option<&'static str>> {
    let Some(record) = read_record(data_dir) else {
        return Ok(None);
    };
    check_choice(&record, choice)?;
    let backend = build(data_dir, &record)?;
    let name = backend.name();
    secrets::install_backend(backend);
    Ok(Some(name))
}

pub fn activate_or_create(data_dir: &Path, choice: SecretBackendChoice) -> CliResult<&'static str> {
    if let Some(name) = activate_existing(data_dir, choice)? {
        return Ok(name);
    }
    let (record, backend) = choose(data_dir, choice)?;
    let bytes = serde_json::to_vec(&record).map_err(|e| CliError::coded(CODE_INTERNAL, e.to_string()))?;
    crate::state::write_private(&record_path(data_dir), &bytes).map_err(CliError::secret_store)?;
    let name = backend.name();
    secrets::install_backend(backend);
    Ok(name)
}

pub fn is_secret_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("keyring")
        || lower.contains("secret")
        || lower.contains("key file")
        || lower.contains("db key")
        || lower.contains("wrap key")
        || lower.contains("identity locked")
        || lower.contains("neither plaintext nor decryptable")
}

pub fn map_store_error(context: &str, message: String) -> CliError {
    if is_secret_error(&message) {
        CliError::secret_store(format!("{}: {}", context, message)).with_hint(
            "Check that the keyring or secret key file this folder was set up with is available.",
        )
    } else {
        CliError::coded(CODE_INTERNAL, format!("{}: {}", context, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let record = Record::Keyring {
            service: "svc".into(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(record_path(dir.path()), bytes).unwrap();
        assert_eq!(read_record(dir.path()), Some(record));
        remove_record(dir.path());
        assert!(!has_record(dir.path()));
    }

    #[test]
    fn explicit_choice_must_match_record() {
        assert!(check_choice(&Record::File, SecretBackendChoice::File).is_ok());
        assert!(check_choice(&Record::File, SecretBackendChoice::Auto).is_ok());
        let err = check_choice(&Record::File, SecretBackendChoice::Keyring).unwrap_err();
        assert_eq!(err.exit_code, crate::exit::EXIT_SECRET_STORE);
    }

    #[test]
    fn keyring_service_is_scoped_to_non_default_folders() {
        let dir = tempfile::tempdir().unwrap();
        let a = keyring_service(dir.path());
        let b = keyring_service(&dir.path().join("other"));
        assert!(a.starts_with(CLI_KEYRING_SERVICE));
        assert_ne!(a, b);
        assert_eq!(a, keyring_service(dir.path()));
    }

    #[test]
    fn secret_errors_are_classified() {
        assert!(is_secret_error("db key: keyring get: platform failure"));
        assert!(is_secret_error("secret key file /x: cannot be opened with this key"));
        assert!(!is_secret_error("disk full"));
    }
}
