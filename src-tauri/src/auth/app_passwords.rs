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

use std::sync::Arc;

use crate::db::Database;

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
        let mut matched: Option<String> = None;
        for (id, hash_str) in &rows {
            match PasswordHash::new(hash_str) {
                Ok(parsed) => {
                    if argon2.verify_password(normalized.as_bytes(), &parsed).is_ok() && matched.is_none() {
                        matched = Some(id.clone());
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
        self.db.with_conn(|conn| {
            conn.execute("DELETE FROM app_passwords WHERE id = ?1", rusqlite::params![id])?;
            Ok(())
        })
    }
}
