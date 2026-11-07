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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const PASSWORD_KEY_CALLS: &[&str] = &[
    "derive_storage_key(",
    "derive_storage_key_v1(",
    "derive_storage_key_v2(",
    "derive_storage_base_keys(",
    "storage_key_candidates(",
    "encrypt_pbkdf2_envelope(",
    "pbkdf2_hmac",
    "derive_sync_key(",
];

const TEST_ONLY_FILES: &[&str] = &["protocol_harness.rs"];

const ALLOWED: &[(&str, &str, usize)] = &[
    ("auth/session.rs", "storage_key_candidates(", 1),
    ("crypto/alias.rs", "derive_storage_key(", 2),
    ("crypto/alias.rs", "storage_key_candidates(", 1),
    ("crypto/attachment.rs", "encrypt_pbkdf2_envelope(", 1),
    ("crypto/envelope.rs", "encrypt_pbkdf2_envelope(", 1),
    ("crypto/envelope.rs", "pbkdf2_hmac", 2),
    ("crypto/ratchet_recovery.rs", "derive_storage_key_v1(", 2),
    ("crypto/ratchet_recovery.rs", "derive_storage_key_v2(", 2),
    ("crypto/ratchet_recovery.rs", "derive_storage_base_keys(", 2),
    ("crypto/ratchet_recovery.rs", "pbkdf2_hmac", 1),
    ("crypto/vault.rs", "pbkdf2_hmac", 1),
    ("smtp/reply_thread.rs", "encrypt_pbkdf2_envelope(", 1),
];

const SELF_PATH: &str = "crypto/storage_key_call_sites.rs";

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).expect("source directory is readable");
    for entry in entries {
        let path = entry.expect("source entry is readable").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn production_part(source: &str) -> &str {
    let normalized_marker = source
        .find("#[cfg(test)]\nmod tests")
        .or_else(|| source.find("#[cfg(test)]\r\nmod tests"));
    match normalized_marker {
        Some(index) => &source[..index],
        None => source,
    }
}

fn password_key_call_sites() -> BTreeMap<(String, String), usize> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &mut files);

    let mut found = BTreeMap::new();
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .expect("file sits under src")
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if relative == SELF_PATH || TEST_ONLY_FILES.contains(&relative.as_str()) {
            continue;
        }
        let source = std::fs::read_to_string(&file).expect("source file is readable");
        let production = production_part(&source);
        for call in PASSWORD_KEY_CALLS {
            let count = production.matches(call).count();
            if count > 0 {
                found.insert((relative.clone(), call.to_string()), count);
            }
        }
    }
    found
}

#[test]
fn password_derived_storage_keys_stay_in_their_allowlist() {
    let allowed: BTreeMap<(String, String), usize> = ALLOWED
        .iter()
        .map(|(file, call, count)| ((file.to_string(), call.to_string()), *count))
        .collect();

    let unexpected: Vec<String> = password_key_call_sites()
        .into_iter()
        .filter(|(site, count)| allowed.get(site).is_none_or(|max| count > max))
        .map(|((file, call), count)| format!("{} uses {} {} time(s)", file, call, count))
        .collect();

    assert!(
        unexpected.is_empty(),
        "new password-derived storage key use outside the allowlist; write with the data_kek instead: {:?}",
        unexpected
    );
}

#[test]
fn the_call_site_scan_finds_the_known_sites() {
    let found = password_key_call_sites();
    assert!(found.contains_key(&(
        "crypto/ratchet_recovery.rs".to_string(),
        "derive_storage_key_v2(".to_string()
    )));
    assert!(found.contains_key(&(
        "smtp/reply_thread.rs".to_string(),
        "encrypt_pbkdf2_envelope(".to_string()
    )));
}

#[test]
fn production_part_stops_at_the_test_module() {
    let source = "fn a() { derive_storage_key(x) }\n#[cfg(test)]\nmod tests {\n derive_storage_key(y)\n}\n";
    assert_eq!(production_part(source).matches("derive_storage_key(").count(), 1);
}

#[test]
fn test_only_files_are_compiled_only_for_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(root.join("lib.rs"))
        .expect("lib.rs is readable")
        .replace("\r\n", "\n");
    for file in TEST_ONLY_FILES {
        let module = file.trim_end_matches(".rs");
        assert!(
            lib.contains(&format!("#[cfg(test)]\nmod {};", module)),
            "{} must stay behind #[cfg(test)]",
            file
        );
    }
}

#[test]
fn the_password_sync_key_has_no_production_caller() {
    assert!(!password_key_call_sites()
        .keys()
        .any(|(_, call)| call == "derive_sync_key("));
}
