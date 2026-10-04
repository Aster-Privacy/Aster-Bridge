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
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use uuid::Uuid;

fn argon2_pinned() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        argon2_pinned()
            .hash_password(b"dummy-not-a-real-password", &salt)
            .expect("dummy argon2 hash")
            .to_string()
    })
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand_core::RngCore;
use rusqlite::OptionalExtension;
use sha2::Sha256;

use crate::db::Database;

const VERIFY_CACHE_TTL: Duration = Duration::from_secs(300);
const VERIFY_CACHE_MAX: usize = 64;
const RECORD_USE_INTERVAL: Duration = Duration::from_secs(60);
const RECORD_USE_MAX: usize = 256;

struct CachedVerify {
    id: String,
    hash: String,
    at: Instant,
}

#[derive(Default)]
pub struct VerifyCache {
    matches: Mutex<HashMap<[u8; 32], CachedVerify>>,
    last_recorded: Mutex<HashMap<String, Instant>>,
}

impl VerifyCache {
    pub fn clear(&self) {
        if let Ok(mut matches) = self.matches.lock() {
            matches.clear();
        }
    }
}

fn verify_cache_secret() -> &'static [u8; 32] {
    static SECRET: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    SECRET.get_or_init(|| {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        secret
    })
}

fn verify_cache_key(username: &str, password: &str) -> [u8; 32] {
    let user = username.to_ascii_lowercase();
    let normalized = password.replace('-', "");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(verify_cache_secret())
        .expect("HMAC accepts any key length");
    mac.update(&(user.len() as u64).to_le_bytes());
    mac.update(user.as_bytes());
    mac.update(&(normalized.len() as u64).to_le_bytes());
    mac.update(normalized.as_bytes());
    mac.finalize().into_bytes().into()
}

const PASSWORD_CHARSET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const PASSWORD_SEGMENT_LEN: usize = 4;
const PASSWORD_SEGMENTS: usize = 4;

pub struct AppPasswords {
    db: Arc<Database>,
}

#[allow(dead_code)]
pub struct AppPasswordEntry {
    pub id: String,
    pub label: String,
    pub created_at: String,
    pub last_used_at: Option<i64>,
    pub last_client: Option<String>,
    pub use_count: i64,
}

fn rejection_sample(rng: &mut impl rand_core::RngCore, range: u32) -> u32 {
    let mask = range.next_power_of_two() - 1;
    loop {
        let val = rng.next_u32() & mask;
        if val < range {
            return val;
        }
    }
}

pub fn generate_app_password() -> String {
    let mut rng = OsRng;
    let charset_len = PASSWORD_CHARSET.len() as u32;
    let mut segments = Vec::with_capacity(PASSWORD_SEGMENTS);

    for _ in 0..PASSWORD_SEGMENTS {
        let mut segment = String::with_capacity(PASSWORD_SEGMENT_LEN);
        for _ in 0..PASSWORD_SEGMENT_LEN {
            let idx = rejection_sample(&mut rng, charset_len) as usize;
            segment.push(PASSWORD_CHARSET[idx] as char);
        }
        segments.push(segment);
    }

    segments.join("-")
}

#[allow(dead_code)]
impl AppPasswords {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub fn store(&self, label: &str, password: &str) -> Result<String, String> {
        let id = Uuid::new_v4().to_string();
        let normalized = password.replace('-', "");
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = argon2_pinned();
        let hash = argon2
            .hash_password(normalized.as_bytes(), &salt)
            .map_err(|e| e.to_string())?
            .to_string();

        self.db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO app_passwords (id, label, hash) VALUES (?1, ?2, ?3)",
                rusqlite::params![id, label, hash],
            )?;
            Ok(id.clone())
        })
    }

    pub fn verify(&self, password: &str) -> bool {
        self.verify_and_id(password).is_some()
    }

    pub fn verify_and_id(&self, password: &str) -> Option<String> {
        self.verify_match(password).map(|(id, _)| id)
    }

    fn verify_match(&self, password: &str) -> Option<(String, String)> {
        let normalized = password.replace('-', "");
        let rows: Vec<(String, String)> = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare("SELECT id, hash FROM app_passwords")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .unwrap_or_default();

        let argon2 = argon2_pinned();
        let mut matched: Option<(String, String)> = None;
        for (id, hash_str) in &rows {
            match PasswordHash::new(hash_str) {
                Ok(parsed) => {
                    if argon2.verify_password(normalized.as_bytes(), &parsed).is_ok() && matched.is_none() {
                        matched = Some((id.clone(), hash_str.clone()));
                    }
                }
                Err(_) => {
                    if let Ok(dummy) = PasswordHash::new(dummy_hash()) {
                        let _ = argon2.verify_password(normalized.as_bytes(), &dummy);
                    }
                }
            }
        }
        if rows.is_empty() {
            if let Ok(dummy) = PasswordHash::new(dummy_hash()) {
                let _ = argon2.verify_password(normalized.as_bytes(), &dummy);
            }
        }
        matched
    }

    pub async fn verify_and_id_async(&self, password: &str) -> Option<String> {
        let db = self.db.clone();
        let pw = password.to_string();
        tokio::task::spawn_blocking(move || AppPasswords { db }.verify_and_id(&pw))
            .await
            .ok()
            .flatten()
    }

    pub async fn verify_and_id_cached(&self, username: &str, password: &str) -> Option<String> {
        let key = verify_cache_key(username, password);
        if let Some(id) = self.cached_match(&key) {
            return Some(id);
        }
        let db = self.db.clone();
        let pw = password.to_string();
        let (id, hash) = tokio::task::spawn_blocking(move || AppPasswords { db }.verify_match(&pw))
            .await
            .ok()
            .flatten()?;
        if let Ok(mut cache) = self.db.app_password_cache.matches.lock() {
            let now = Instant::now();
            if cache.len() >= VERIFY_CACHE_MAX {
                cache.retain(|_, e| now.duration_since(e.at) < VERIFY_CACHE_TTL);
            }
            if cache.len() >= VERIFY_CACHE_MAX {
                if let Some(oldest) = cache.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| *k) {
                    cache.remove(&oldest);
                }
            }
            cache.insert(key, CachedVerify { id: id.clone(), hash, at: now });
        }
        Some(id)
    }

    fn cached_match(&self, key: &[u8; 32]) -> Option<String> {
        let (id, hash) = {
            let mut cache = self.db.app_password_cache.matches.lock().ok()?;
            let entry = cache.get(key)?;
            if entry.at.elapsed() >= VERIFY_CACHE_TTL {
                cache.remove(key);
                return None;
            }
            (entry.id.clone(), entry.hash.clone())
        };
        let current: Option<String> = self
            .db
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT hash FROM app_passwords WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })
            .ok()
            .flatten();
        if current.as_deref() == Some(hash.as_str()) {
            return Some(id);
        }
        if let Ok(mut cache) = self.db.app_password_cache.matches.lock() {
            cache.remove(key);
        }
        None
    }

    pub fn record_use_throttled(&self, password_id: &str, client_label: Option<&str>) {
        {
            let Ok(mut marks) = self.db.app_password_cache.last_recorded.lock() else {
                return;
            };
            let now = Instant::now();
            if let Some(last) = marks.get(password_id) {
                if now.duration_since(*last) < RECORD_USE_INTERVAL {
                    return;
                }
            }
            if marks.len() >= RECORD_USE_MAX {
                marks.retain(|_, t| now.duration_since(*t) < RECORD_USE_INTERVAL);
            }
            marks.insert(password_id.to_string(), now);
        }
        self.record_use(password_id, client_label);
    }

    pub fn record_use(&self, password_id: &str, client_label: Option<&str>) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let truncated = client_label.map(|s| {
            let trimmed = s.trim();
            if trimmed.len() > 200 {
                trimmed.chars().take(200).collect::<String>()
            } else {
                trimmed.to_string()
            }
        });
        let _ = self.db.with_conn(|conn| {
            conn.execute(
                "UPDATE app_passwords
                 SET last_used_at = ?1,
                     last_client = ?2,
                     use_count = COALESCE(use_count, 0) + 1
                 WHERE id = ?3",
                rusqlite::params![now, truncated, password_id],
            )?;
            Ok(())
        });
    }

    pub fn list(&self) -> Vec<AppPasswordEntry> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, label, created_at, last_used_at, last_client, COALESCE(use_count, 0)
                     FROM app_passwords ORDER BY created_at",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(AppPasswordEntry {
                            id: row.get(0)?,
                            label: row.get(1)?,
                            created_at: row.get(2)?,
                            last_used_at: row.get(3)?,
                            last_client: row.get(4)?,
                            use_count: row.get(5)?,
                        })
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .unwrap_or_default()
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        let result = self.db.with_conn(|conn| {
            conn.execute("DELETE FROM app_passwords WHERE id = ?1", rusqlite::params![id])?;
            Ok(())
        });
        self.db.app_password_cache.clear();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> (tempfile::TempDir, Arc<Database>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[42u8; 32]).unwrap());
        (dir, db)
    }

    #[test]
    fn generate_app_password_has_expected_shape() {
        let pw = generate_app_password();
        let segments: Vec<&str> = pw.split('-').collect();
        assert_eq!(segments.len(), PASSWORD_SEGMENTS);
        for seg in &segments {
            assert_eq!(seg.len(), PASSWORD_SEGMENT_LEN);
            for ch in seg.bytes() {
                assert!(PASSWORD_CHARSET.contains(&ch));
            }
        }
    }

    #[test]
    fn generate_app_password_is_not_constant() {
        assert_ne!(generate_app_password(), generate_app_password());
    }

    #[test]
    fn correct_password_verifies_and_wrong_one_does_not() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        ap.store("thunderbird", &pw).unwrap();
        assert!(ap.verify(&pw));
        assert!(!ap.verify("xxxx-xxxx-xxxx-xxxx"));
    }

    #[test]
    fn verify_ignores_dashes_in_input() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        ap.store("client", &pw).unwrap();
        let no_dashes = pw.replace('-', "");
        assert!(ap.verify(&no_dashes));
    }

    #[test]
    fn verify_and_id_returns_matching_record_id() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = ap.store("label-a", &pw).unwrap();
        assert_eq!(ap.verify_and_id(&pw), Some(id));
    }

    #[test]
    fn verify_on_empty_table_returns_none_without_panic() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        assert!(!ap.verify("anything-here-now-yep"));
        assert_eq!(ap.verify_and_id("anything-here-now-yep"), None);
    }

    #[tokio::test]
    async fn verify_and_id_async_matches_sync_result() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = ap.store("async-label", &pw).unwrap();
        assert_eq!(ap.verify_and_id_async(&pw).await, Some(id));
        assert_eq!(ap.verify_and_id_async("wrong-wrong-wrong-x").await, None);
    }

    #[test]
    fn store_list_and_delete_round_trip() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = ap.store("to-delete", &pw).unwrap();
        let listed = ap.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label, "to-delete");
        ap.delete(&id).unwrap();
        assert!(ap.list().is_empty());
        assert!(!ap.verify(&pw));
    }

    #[test]
    fn record_use_increments_use_count() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = ap.store("counted", &pw).unwrap();
        ap.record_use(&id, Some("Thunderbird/128"));
        ap.record_use(&id, None);
        let entry = ap.list().into_iter().find(|e| e.id == id).unwrap();
        assert_eq!(entry.use_count, 2);
        assert!(entry.last_used_at.is_some());
    }

    #[tokio::test]
    async fn cached_verify_remembers_a_match_by_digest() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = ap.store("cached", &pw).unwrap();
        assert_eq!(ap.verify_and_id_cached("u@aster.test", &pw).await, Some(id.clone()));
        let key = verify_cache_key("u@aster.test", &pw);
        assert!(ap.db.app_password_cache.matches.lock().unwrap().contains_key(&key));
        assert_eq!(ap.verify_and_id_cached("U@Aster.Test", &pw).await, Some(id));
        assert_eq!(ap.verify_and_id_cached("u@aster.test", "wrong-wrong-wrong-x").await, None);
        assert!(!ap
            .db
            .app_password_cache
            .matches
            .lock()
            .unwrap()
            .contains_key(&verify_cache_key("u@aster.test", "wrong-wrong-wrong-x")));
    }

    #[tokio::test]
    async fn revoked_password_stops_working_immediately() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = ap.store("revoked", &pw).unwrap();
        assert_eq!(ap.verify_and_id_cached("u@aster.test", &pw).await, Some(id.clone()));
        ap.delete(&id).unwrap();
        assert_eq!(ap.verify_and_id_cached("u@aster.test", &pw).await, None);
    }

    #[tokio::test]
    async fn revoke_through_another_instance_stops_cached_password() {
        let (_dir, db) = test_db();
        let serving = AppPasswords::new(db.clone());
        let managing = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = managing.store("other-instance", &pw).unwrap();
        assert_eq!(serving.verify_and_id_cached("u@aster.test", &pw).await, Some(id.clone()));
        managing.delete(&id).unwrap();
        assert_eq!(serving.verify_and_id_cached("u@aster.test", &pw).await, None);
    }

    #[tokio::test]
    async fn row_removed_without_clearing_cache_is_not_honoured() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db.clone());
        let pw = generate_app_password();
        let id = ap.store("raw-delete", &pw).unwrap();
        assert_eq!(ap.verify_and_id_cached("u@aster.test", &pw).await, Some(id.clone()));
        db.with_conn(|conn| {
            conn.execute("DELETE FROM app_passwords WHERE id = ?1", rusqlite::params![id])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(ap.verify_and_id_cached("u@aster.test", &pw).await, None);
    }

    #[tokio::test]
    async fn clearing_user_data_stops_cached_password() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db.clone());
        let pw = generate_app_password();
        let id = ap.store("signed-out", &pw).unwrap();
        assert_eq!(ap.verify_and_id_cached("u@aster.test", &pw).await, Some(id));
        db.clear_all_user_data().unwrap();
        assert!(!ap
            .db
            .app_password_cache
            .matches
            .lock()
            .unwrap()
            .contains_key(&verify_cache_key("u@aster.test", &pw)));
        assert_eq!(ap.verify_and_id_cached("u@aster.test", &pw).await, None);
    }

    #[test]
    fn record_use_throttled_writes_once_per_interval() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw = generate_app_password();
        let id = ap.store("throttled", &pw).unwrap();
        for _ in 0..5 {
            ap.record_use_throttled(&id, Some("DAVx5"));
        }
        let entry = ap.list().into_iter().find(|e| e.id == id).unwrap();
        assert_eq!(entry.use_count, 1);
        assert_eq!(entry.last_client.as_deref(), Some("DAVx5"));
    }

    #[test]
    fn multiple_passwords_each_verify_to_their_own_id() {
        let (_dir, db) = test_db();
        let ap = AppPasswords::new(db);
        let pw_a = generate_app_password();
        let pw_b = generate_app_password();
        let id_a = ap.store("a", &pw_a).unwrap();
        let id_b = ap.store("b", &pw_b).unwrap();
        assert_eq!(ap.verify_and_id(&pw_a), Some(id_a));
        assert_eq!(ap.verify_and_id(&pw_b), Some(id_b));
    }
}
