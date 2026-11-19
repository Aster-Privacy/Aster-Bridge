//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the AGPLv3 as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// AGPLv3 for more details.
//
// You should have received a copy of the AGPLv3
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;

pub const ENVELOPE_SALT_BYTES: usize = 16;
const MAX_SAVED_LOGIN_SALTS: usize = 1024;
const MAX_KNOWN_LOGIN_SALTS: usize = MAX_SAVED_LOGIN_SALTS * 16;
const FILE_PREFIX: &str = "known_login_salts_";

type LoginSalt = [u8; ENVELOPE_SALT_BYTES];

static KNOWN_LOGIN_SALTS: RwLock<BTreeSet<LoginSalt>> = RwLock::new(BTreeSet::new());

fn salts_path(dir: &Path, user_id: &Uuid) -> PathBuf {
    dir.join(format!("{}{}", FILE_PREFIX, user_id))
}

fn as_envelope_salt(salt: &[u8]) -> Option<LoginSalt> {
    salt.try_into().ok()
}

fn read_saved(dir: &Path, user_id: &Uuid) -> Result<Vec<LoginSalt>, String> {
    let text = match std::fs::read_to_string(salts_path(dir, user_id)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    Ok(text
        .lines()
        .filter_map(|line| STANDARD.decode(line.trim()).ok())
        .filter_map(|bytes| as_envelope_salt(&bytes))
        .collect())
}

fn write_saved(dir: &Path, user_id: &Uuid, saved: &[LoginSalt]) -> Result<(), String> {
    let text: Vec<String> = saved.iter().map(|salt| STANDARD.encode(salt)).collect();
    let path = salts_path(dir, user_id);
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    crate::system_tools::write_limited_file(
        &tmp,
        text.join("\n").as_bytes(),
        crate::system_tools::restrict_to_current_user,
    )?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

fn add_known(saved: &[LoginSalt], added: &[LoginSalt]) {
    let mut known = KNOWN_LOGIN_SALTS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    known.extend(saved.iter().copied());
    for salt in added {
        if known.len() >= MAX_KNOWN_LOGIN_SALTS {
            tracing::warn!("too many sign-in salts reported, ignoring the rest");
            return;
        }
        known.insert(*salt);
    }
}

fn newly_reported(saved: &[LoginSalt], reported: &[Vec<u8>]) -> Vec<LoginSalt> {
    let mut added: Vec<LoginSalt> = Vec::new();
    for salt in reported.iter().filter_map(|salt| as_envelope_salt(salt)) {
        if saved.contains(&salt) || added.contains(&salt) {
            continue;
        }
        if saved.len() + added.len() >= MAX_SAVED_LOGIN_SALTS {
            tracing::warn!("too many sign-in salts reported, keeping the saved ones");
            break;
        }
        added.push(salt);
    }
    added
}

pub fn remember_login_salts(dir: Option<&Path>, user_id: &Uuid, reported: &[Vec<u8>]) {
    let Some(d) = dir else {
        add_known(&[], &newly_reported(&[], reported));
        return;
    };
    let mut saved = match read_saved(d, user_id) {
        Ok(saved) => saved,
        Err(e) => {
            add_known(&[], &newly_reported(&[], reported));
            tracing::warn!(
                "could not read the saved sign-in salts, leaving the file as it is: {}",
                e
            );
            return;
        }
    };
    let added = newly_reported(&saved, reported);
    add_known(&saved, &added);
    if added.is_empty() {
        return;
    }
    saved.extend(added);
    if let Err(e) = write_saved(d, user_id, &saved) {
        tracing::warn!("could not record the sign-in salts: {}", e);
    }
}

pub fn decode_reported_salts(encoded: &[String]) -> Vec<Vec<u8>> {
    encoded
        .iter()
        .filter_map(|value| STANDARD.decode(value).ok())
        .collect()
}

pub fn is_known_login_salt(salt: &[u8]) -> bool {
    as_envelope_salt(salt).is_some_and(|salt| {
        KNOWN_LOGIN_SALTS
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&salt)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_salt() -> Vec<u8> {
        rand::random::<[u8; ENVELOPE_SALT_BYTES]>().to_vec()
    }

    #[test]
    fn remembers_only_envelope_sized_salts() {
        let user = Uuid::new_v4();
        let short = random_salt();
        let long: Vec<u8> = rand::random::<[u8; 32]>().to_vec();
        remember_login_salts(None, &user, &[short.clone(), long.clone()]);
        assert!(is_known_login_salt(&short));
        assert!(!is_known_login_salt(&long));
        assert!(!is_known_login_salt(&random_salt()));
    }

    #[test]
    fn saved_salts_survive_a_server_that_stops_reporting_them() {
        let dir = std::env::temp_dir().join(format!("aster_login_salts_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let user = Uuid::new_v4();
        let salt = random_salt();
        remember_login_salts(Some(&dir), &user, std::slice::from_ref(&salt));
        assert_eq!(
            read_saved(&dir, &user).unwrap(),
            vec![as_envelope_salt(&salt).unwrap()]
        );
        remember_login_salts(Some(&dir), &user, &[]);
        assert_eq!(read_saved(&dir, &user).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decodes_reported_values() {
        let salt = random_salt();
        let decoded = decode_reported_salts(&[STANDARD.encode(&salt), "%%%".to_string()]);
        assert_eq!(decoded, vec![salt]);
    }

    #[test]
    fn a_flood_of_reported_salts_keeps_the_saved_ones() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let genuine = random_salt();
        remember_login_salts(Some(dir.path()), &user, std::slice::from_ref(&genuine));
        let flood: Vec<Vec<u8>> = (0..2048).map(|_| random_salt()).collect();
        remember_login_salts(Some(dir.path()), &user, &flood[..33]);
        remember_login_salts(Some(dir.path()), &user, &flood);
        let reloaded = read_saved(dir.path(), &user).unwrap();
        assert!(
            reloaded.contains(&as_envelope_salt(&genuine).unwrap()),
            "the saved sign-in salt was dropped after a flood of reported salts"
        );
        assert!(
            is_known_login_salt(&genuine),
            "the sign-in salt was forgotten in memory"
        );
        assert!(
            reloaded.len() <= 1024,
            "the saved list grew to {}",
            reloaded.len()
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_saved_salts_are_readable_only_by_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        remember_login_salts(Some(dir.path()), &user, &[random_salt()]);
        remember_login_salts(Some(dir.path()), &user, &[random_salt()]);
        let mode = std::fs::metadata(salts_path(dir.path(), &user))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the saved salts file has mode {:o}",
            mode & 0o777
        );
        assert_eq!(read_saved(dir.path(), &user).unwrap().len(), 2);
    }

    #[test]
    fn an_unreadable_salts_file_is_left_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let path = salts_path(dir.path(), &user);
        let corrupt: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x80, 0x0a, 0xc3];
        std::fs::write(&path, &corrupt).unwrap();
        let reported = random_salt();
        remember_login_salts(Some(dir.path()), &user, std::slice::from_ref(&reported));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            corrupt,
            "the unreadable salts file was rewritten"
        );
        assert!(read_saved(dir.path(), &user).is_err());
        assert!(
            is_known_login_salt(&reported),
            "the reported salt was not guarded in memory"
        );
    }

    #[test]
    fn damaged_lines_in_the_salts_file_keep_the_valid_salts() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let genuine = random_salt();
        let text = [
            "%%%".to_string(),
            STANDARD.encode(&genuine),
            "short".to_string(),
            STANDARD.encode([1u8; 4]),
        ]
        .join("\n");
        std::fs::write(salts_path(dir.path(), &user), text).unwrap();
        let reported = random_salt();
        remember_login_salts(Some(dir.path()), &user, std::slice::from_ref(&reported));
        let reloaded = read_saved(dir.path(), &user).unwrap();
        assert_eq!(
            reloaded,
            vec![
                as_envelope_salt(&genuine).unwrap(),
                as_envelope_salt(&reported).unwrap()
            ]
        );
        assert!(is_known_login_salt(&genuine));
    }
}
