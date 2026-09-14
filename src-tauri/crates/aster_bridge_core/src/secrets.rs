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
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use zeroize::{Zeroize, Zeroizing};

pub const DESKTOP_KEYRING_SERVICE: &str = "com.astermail.bridge";
pub const CLI_KEYRING_SERVICE: &str = "com.astermail.bridge.cli";
const FILE_MAGIC: &[u8; 8] = b"ASTERSF\x01";

#[derive(Clone)]
pub enum SecretBackend {
    Keyring { service: String },
    File { dir: PathBuf, key: Zeroizing<[u8; 32]> },
}

impl SecretBackend {
    pub fn name(&self) -> &'static str {
        match self {
            SecretBackend::Keyring { .. } => "keyring",
            SecretBackend::File { .. } => "file",
        }
    }
}

static BACKEND: OnceLock<RwLock<SecretBackend>> = OnceLock::new();
static DATA_DIR_OVERRIDE: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();

fn backend_cell() -> &'static RwLock<SecretBackend> {
    BACKEND.get_or_init(|| {
        RwLock::new(SecretBackend::Keyring {
            service: DESKTOP_KEYRING_SERVICE.to_string(),
        })
    })
}

pub fn install_backend(backend: SecretBackend) {
    if let Ok(mut guard) = backend_cell().write() {
        *guard = backend;
    }
}

pub fn current_backend() -> SecretBackend {
    backend_cell()
        .read()
        .map(|g| g.clone())
        .unwrap_or(SecretBackend::Keyring {
            service: DESKTOP_KEYRING_SERVICE.to_string(),
        })
}

pub fn set_data_dir_override(dir: Option<PathBuf>) {
    let cell = DATA_DIR_OVERRIDE.get_or_init(|| RwLock::new(None));
    if let Ok(mut guard) = cell.write() {
        *guard = dir;
    }
}

pub fn data_dir_override() -> Option<PathBuf> {
    DATA_DIR_OVERRIDE
        .get()
        .and_then(|cell| cell.read().ok().and_then(|g| g.clone()))
}

pub fn get(user: &str) -> Result<Option<String>, String> {
    match current_backend() {
        SecretBackend::Keyring { service } => {
            let entry = keyring::Entry::new(&service, user)
                .map_err(|e| format!("keyring init: {}", e))?;
            match entry.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(format!("keyring get: {}", e)),
            }
        }
        SecretBackend::File { dir, key } => file_get(&dir, &key, user),
    }
}

pub fn set(user: &str, value: &str) -> Result<(), String> {
    match current_backend() {
        SecretBackend::Keyring { service } => {
            let entry = keyring::Entry::new(&service, user)
                .map_err(|e| format!("keyring init: {}", e))?;
            entry
                .set_password(value)
                .map_err(|e| format!("keyring set: {}", e))
        }
        SecretBackend::File { dir, key } => file_set(&dir, &key, user, value),
    }
}

pub fn delete(user: &str) -> Result<(), String> {
    match current_backend() {
        SecretBackend::Keyring { service } => {
            let entry = keyring::Entry::new(&service, user)
                .map_err(|e| format!("keyring init: {}", e))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(format!("keyring delete: {}", e)),
            }
        }
        SecretBackend::File { dir, .. } => {
            let path = file_path(&dir, user)?;
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("secret delete: {}", e)),
            }
        }
    }
}

pub fn probe_keyring(service: &str) -> Result<(), String> {
    let user = format!("probe-{}", uuid::Uuid::new_v4());
    let entry =
        keyring::Entry::new(service, &user).map_err(|e| format!("keyring init: {}", e))?;
    let token = uuid::Uuid::new_v4().to_string();
    entry
        .set_password(&token)
        .map_err(|e| format!("keyring set: {}", e))?;
    let read = entry.get_password();
    let _ = entry.delete_credential();
    match read {
        Ok(v) if v == token => Ok(()),
        Ok(_) => Err("keyring returned a different value".to_string()),
        Err(e) => Err(format!("keyring get: {}", e)),
    }
}

pub fn load_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot read secret key file {}: {}", path.display(), e))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "secret key file {} is readable by other users; run chmod 600 on it",
                path.display()
            ));
        }
    }
    let mut raw = std::fs::read(path)
        .map_err(|e| format!("cannot read secret key file {}: {}", path.display(), e))?;
    let result = parse_key_bytes(&raw);
    raw.zeroize();
    result.map_err(|e| format!("secret key file {}: {}", path.display(), e))
}

fn parse_key_bytes(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    let trimmed: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let trimmed = Zeroizing::new(trimmed);
    if trimmed.len() == 64 && trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        for (i, chunk) in trimmed.as_chunks::<2>().0.iter().enumerate() {
            let hi = (chunk[0] as char).to_digit(16).unwrap_or(0);
            let lo = (chunk[1] as char).to_digit(16).unwrap_or(0);
            key[i] = ((hi << 4) | lo) as u8;
        }
        return Ok(key);
    }
    if raw.len() == 32 {
        key.copy_from_slice(raw);
        return Ok(key);
    }
    use base64::Engine as _;
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed.as_slice()) {
        let decoded = Zeroizing::new(decoded);
        if decoded.len() == 32 {
            key.copy_from_slice(&decoded);
            return Ok(key);
        }
    }
    Err("expected 32 bytes as raw, 64 hex characters, or base64".to_string())
}

fn file_path(dir: &Path, user: &str) -> Result<PathBuf, String> {
    if user.is_empty()
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        || user.starts_with('.')
    {
        return Err("invalid secret name".to_string());
    }
    Ok(dir.join(format!("{}.sealed", user)))
}

fn file_get(dir: &Path, key: &[u8; 32], user: &str) -> Result<Option<String>, String> {
    let path = file_path(dir, user)?;
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("secret read: {}", e)),
    };
    if data.len() < 8 + 24 + 16 || &data[..8] != FILE_MAGIC {
        return Err(format!("secret {} is corrupt", user));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&data[8..32]);
    let mut plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &data[32..],
                aad: user.as_bytes(),
            },
        )
        .map_err(|_| format!("secret {} cannot be opened with this key", user))?;
    let value = String::from_utf8(plain.clone()).map_err(|_| "secret is not utf-8".to_string());
    plain.zeroize();
    value.map(Some)
}

fn file_set(dir: &Path, key: &[u8; 32], user: &str, value: &str) -> Result<(), String> {
    let path = file_path(dir, user)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("secret dir: {}", e))?;
    restrict_permissions(dir, true);
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: value.as_bytes(),
                aad: user.as_bytes(),
            },
        )
        .map_err(|_| "secret seal failed".to_string())?;
    let mut out = Vec::with_capacity(8 + 24 + ct.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    let tmp = path.with_extension("sealed.tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("secret write: {}", e))?;
        restrict_permissions(&tmp, false);
        f.write_all(&out).map_err(|e| format!("secret write: {}", e))?;
        f.sync_all().map_err(|e| format!("secret write: {}", e))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("secret write: {}", e))?;
    Ok(())
}

pub fn restrict_permissions(path: &Path, is_dir: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let user = whoami::fallible::username()
            .unwrap_or_else(|_| std::env::var("USERNAME").unwrap_or_default());
        if !user.is_empty() {
            let grant = if is_dir {
                format!("{}:(OI)(CI)F", user)
            } else {
                format!("{}:(F)", user)
            };
            let _ = std::process::Command::new("icacls")
                .args([
                    path.to_string_lossy().as_ref(),
                    "/inheritance:r",
                    "/grant:r",
                    &grant,
                ])
                .creation_flags(0x0800_0000)
                .output();
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, is_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trips_and_binds_name() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        file_set(dir.path(), &key, "vault-passphrase", "hunter2").unwrap();
        assert_eq!(
            file_get(dir.path(), &key, "vault-passphrase").unwrap().as_deref(),
            Some("hunter2")
        );
        std::fs::copy(
            dir.path().join("vault-passphrase.sealed"),
            dir.path().join("db-encryption-key-v1.sealed"),
        )
        .unwrap();
        assert!(file_get(dir.path(), &key, "db-encryption-key-v1").is_err());
        assert!(file_get(dir.path(), &[8u8; 32], "vault-passphrase").is_err());
        assert_eq!(file_get(dir.path(), &key, "missing").unwrap(), None);
    }

    #[test]
    fn file_store_rejects_path_traversal_names() {
        let dir = tempfile::tempdir().unwrap();
        assert!(file_set(dir.path(), &[1u8; 32], "../escape", "x").is_err());
        assert!(file_set(dir.path(), &[1u8; 32], "", "x").is_err());
        assert!(file_set(dir.path(), &[1u8; 32], ".hidden", "x").is_err());
    }

    #[test]
    fn key_file_accepts_hex_raw_and_base64() {
        let hex = "00".repeat(31) + "ff\n";
        assert_eq!(parse_key_bytes(hex.as_bytes()).unwrap()[31], 0xff);
        assert_eq!(parse_key_bytes(&[9u8; 32]).unwrap()[0], 9);
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        assert_eq!(parse_key_bytes(b64.as_bytes()).unwrap()[5], 3);
        assert!(parse_key_bytes(b"short").is_err());
    }
}
