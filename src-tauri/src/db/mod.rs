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
use rand_core::{OsRng, RngCore};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroize;

const KEYRING_SERVICE: &str = "com.astermail.bridge";
const KEYRING_DB_USER: &str = "db-encryption-key-v1";

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn from_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err("db key must be 64 hex chars".to_string());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex".to_string())?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex".to_string())?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn get_or_create_db_key() -> Result<[u8; 32], String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_DB_USER)
        .map_err(|e| format!("keyring init: {}", e))?;

    match entry.get_password() {
        Ok(mut hex) => {
            let result = from_hex(hex.trim());
            hex.zeroize();
            result
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            let mut hex = to_hex(&key);
            entry
                .set_password(&hex)
                .map_err(|e| format!("keyring set db key: {}", e))?;
            hex.zeroize();
            Ok(key)
        }
        Err(e) => Err(format!("keyring get db key: {}", e)),
    }
}

fn apply_key(conn: &Connection, key: &[u8; 32]) -> Result<(), String> {
    let mut hex = to_hex(key);
    let res = conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex));
    hex.zeroize();
    res.map_err(|e| e.to_string())
}

fn is_readable(conn: &Connection) -> bool {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .is_ok()
}

fn assert_cipher_active(conn: &Connection) -> Result<(), String> {
    let version: Option<String> = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .ok();
    match version {
        Some(v) if !v.trim().is_empty() => Ok(()),
        _ => Err(
            "SQLCipher is not active - refusing to operate on an unencrypted database".to_string(),
        ),
    }
}

fn migrate_plaintext_to_encrypted(db_path: &Path, key: &[u8; 32]) -> Result<(), String> {
    let plaintext = Connection::open(db_path).map_err(|e| e.to_string())?;
    if !is_readable(&plaintext) {
        return Err(
            "bridge.db exists but is neither plaintext nor decryptable with the stored key"
                .to_string(),
        );
    }

    let _ = plaintext.pragma_update(None, "journal_mode", "DELETE");

    let enc_path = db_path.with_extension("db.enc");
    let _ = std::fs::remove_file(&enc_path);

    let mut hex = to_hex(key);
    let export = plaintext.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS encrypted KEY \"x'{}'\";
         SELECT sqlcipher_export('encrypted');
         DETACH DATABASE encrypted;",
        enc_path.to_string_lossy().replace('\'', "''"),
        hex
    ));
    hex.zeroize();
    export.map_err(|e| format!("sqlcipher_export: {}", e))?;
    drop(plaintext);

    {
        let verify = Connection::open(&enc_path).map_err(|e| e.to_string())?;
        apply_key(&verify, key)?;
        if assert_cipher_active(&verify).is_err() || !is_readable(&verify) {
            drop(verify);
            let _ = std::fs::remove_file(&enc_path);
            return Err("encrypted migration copy failed verification".to_string());
        }
    }

    best_effort_overwrite(db_path);
    best_effort_overwrite(&db_path.with_extension("db-wal"));
    best_effort_overwrite(&db_path.with_extension("db-shm"));
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));

    std::fs::rename(&enc_path, db_path).map_err(|e| {
        format!(
            "swap encrypted db into place (data preserved at {}): {}",
            enc_path.display(),
            e
        )
    })?;

    Ok(())
}

fn best_effort_overwrite(path: &Path) {
    use std::io::Write;
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return,
    };
    let mut f = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let zeros = [0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(zeros.len() as u64) as usize;
        if f.write_all(&zeros[..n]).is_err() {
            break;
        }
        remaining -= n as u64;
    }
    let _ = f.flush();
    let _ = f.sync_all();
}

fn plaintext_is_readable(db_path: &Path) -> bool {
    match Connection::open(db_path) {
        Ok(c) => is_readable(&c),
        Err(_) => false,
    }
}

fn quarantine_unreadable_db(db_path: &Path) -> Result<(), String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let dest = db_path.with_extension(format!("db.unreadable.{}", stamp));
    if db_path.exists() {
        tracing::warn!(
            "database could not be decrypted with the stored key; quarantining to {}",
            dest.display()
        );
        std::fs::rename(db_path, &dest)
            .map_err(|e| format!("quarantine unreadable db: {}", e))?;
    }
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    Ok(())
}

fn open_keyed(db_path: &Path, key: &[u8; 32]) -> Result<Connection, String> {
    if db_path.exists() {
        let probe = Connection::open(db_path).map_err(|e| e.to_string())?;
        apply_key(&probe, key)?;
        let readable = is_readable(&probe);
        drop(probe);
        if !readable {
            if plaintext_is_readable(db_path) {
                migrate_plaintext_to_encrypted(db_path, key)?;
            } else {
                quarantine_unreadable_db(db_path)?;
            }
        }
    }

    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    apply_key(&conn, key)?;
    assert_cipher_active(&conn)?;
    if !is_readable(&conn) {
        return Err("failed to open encrypted database".to_string());
    }
    Ok(conn)
}

fn strip_c0_controls(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

fn restrict_db_file_permissions(db_path: &Path) {
    let mut paths = vec![db_path.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut os = db_path.as_os_str().to_os_string();
        os.push(suffix);
        paths.push(PathBuf::from(os));
    }
    for p in paths {
        if !p.exists() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
        #[cfg(windows)]
        {
            let user = whoami::fallible::username()
                .unwrap_or_else(|_| std::env::var("USERNAME").unwrap_or_default());
            if !user.is_empty() {
                let _ = std::process::Command::new("icacls")
                    .args([
                        &p.to_string_lossy().to_string(),
                        "/inheritance:r",
                        "/grant:r",
                        &format!("{}:(F)", user),
                    ])
                    .output();
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = &p;
        }
    }
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let mut key = get_or_create_db_key()?;
        let result = Self::open_with_key(data_dir, &key);
        key.zeroize();
        result
    }

    pub fn open_with_key(data_dir: &Path, key: &[u8; 32]) -> Result<Self, String> {
        let db_path = data_dir.join("bridge.db");
        let conn = open_keyed(&db_path, key)?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| e.to_string())?;
        conn.pragma_update(None, "secure_delete", "ON")
            .map_err(|e| e.to_string())?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS uid_map (
                aster_id TEXT NOT NULL,
                folder TEXT NOT NULL,
                imap_uid INTEGER NOT NULL,
                PRIMARY KEY (aster_id, folder)
            );

            CREATE TABLE IF NOT EXISTS message_cache (
                aster_id TEXT PRIMARY KEY,
                folder TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                recipients TEXT,
                date TEXT,
                flags INTEGER NOT NULL DEFAULT 0,
                size INTEGER NOT NULL DEFAULT 0,
                body_cached INTEGER NOT NULL DEFAULT 0,
                body_text TEXT,
                raw_headers TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS app_passwords (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_message_cache_folder ON message_cache(folder);
            CREATE INDEX IF NOT EXISTS idx_uid_map_folder_uid ON uid_map(folder, imap_uid);

            CREATE TABLE IF NOT EXISTS jmap_mailbox (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                parent_id TEXT,
                role TEXT,
                sort_order INTEGER NOT NULL DEFAULT 0,
                folder_label TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jmap_state (
                type TEXT PRIMARY KEY,
                counter INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS jmap_change_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                state INTEGER NOT NULL,
                object_id TEXT NOT NULL,
                op TEXT NOT NULL CHECK(op IN ('created','updated','destroyed')),
                ts INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_jmap_change_log_type_state ON jmap_change_log(type, state);

            CREATE TABLE IF NOT EXISTS jmap_blob (
                blob_id TEXT PRIMARY KEY,
                data BLOB NOT NULL,
                content_type TEXT,
                size INTEGER NOT NULL,
                created_ts INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| e.to_string())?;

        let _ = conn.execute(
            "ALTER TABLE message_cache ADD COLUMN thread_id TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE message_cache ADD COLUMN message_id TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE app_passwords ADD COLUMN last_used_at INTEGER",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE app_passwords ADD COLUMN last_client TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE app_passwords ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
            [],
        );
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_message_cache_thread_id ON message_cache(thread_id);
             CREATE INDEX IF NOT EXISTS idx_message_cache_message_id ON message_cache(message_id);
             CREATE INDEX IF NOT EXISTS idx_message_cache_folder_date ON message_cache(folder, date DESC);
             CREATE INDEX IF NOT EXISTS idx_jmap_change_log_type_seq ON jmap_change_log(type, seq DESC);
             CREATE INDEX IF NOT EXISTS idx_jmap_blob_created_ts ON jmap_blob(created_ts);
             CREATE UNIQUE INDEX IF NOT EXISTS idx_app_passwords_label ON app_passwords(label);",
        ).map_err(|e| e.to_string())?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS envelope_nonces (
                aster_id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL,
                first_seen INTEGER NOT NULL
             );",
        ).map_err(|e| e.to_string())?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_mime BLOB NOT NULL,
                envelope_from TEXT NOT NULL,
                envelope_to TEXT NOT NULL,
                queued_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt_at INTEGER,
                last_error TEXT,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sending','sent','failed'))
             );
             CREATE INDEX IF NOT EXISTS idx_outbox_status_queued ON outbox(status, queued_at);",
        ).map_err(|e| e.to_string())?;

        conn.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
                aster_id UNINDEXED,
                subject,
                sender,
                recipients,
                body_text,
                tokenize = 'unicode61 remove_diacritics 2'
            );

            CREATE TRIGGER IF NOT EXISTS message_cache_ai AFTER INSERT ON message_cache BEGIN
                INSERT INTO message_fts(aster_id, subject, sender, recipients, body_text)
                VALUES (NEW.aster_id, COALESCE(NEW.subject,''), COALESCE(NEW.sender,''),
                        COALESCE(NEW.recipients,''), COALESCE(NEW.body_text,''));
            END;

            CREATE TRIGGER IF NOT EXISTS message_cache_ad AFTER DELETE ON message_cache BEGIN
                DELETE FROM message_fts WHERE aster_id = OLD.aster_id;
            END;

            CREATE TRIGGER IF NOT EXISTS message_cache_au AFTER UPDATE ON message_cache BEGIN
                DELETE FROM message_fts WHERE aster_id = OLD.aster_id;
                INSERT INTO message_fts(aster_id, subject, sender, recipients, body_text)
                VALUES (NEW.aster_id, COALESCE(NEW.subject,''), COALESCE(NEW.sender,''),
                        COALESCE(NEW.recipients,''), COALESCE(NEW.body_text,''));
            END;",
        ).map_err(|e| e.to_string())?;

        let fts_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_fts", [], |r| r.get(0))
            .unwrap_or(0);
        let cache_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_cache", [], |r| r.get(0))
            .unwrap_or(0);
        if fts_count == 0 && cache_count > 0 {
            conn.execute_batch(
                "INSERT INTO message_fts(aster_id, subject, sender, recipients, body_text)
                 SELECT aster_id, COALESCE(subject,''), COALESCE(sender,''),
                        COALESCE(recipients,''), COALESCE(body_text,'')
                 FROM message_cache;",
            ).map_err(|e| format!("FTS backfill failed: {}", e))?;
        }

        restrict_db_file_permissions(&db_path);

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn fts_search(&self, query: &str, limit: i64) -> Result<Vec<String>, String> {
        let q = sanitize_fts_query(query);
        if q.is_empty() {
            return Ok(Vec::new());
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT message_fts.aster_id FROM message_fts
                 JOIN message_cache ON message_cache.aster_id = message_fts.aster_id
                 WHERE message_fts MATCH ?1
                 ORDER BY message_cache.date DESC
                 LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![q, limit], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn fts_snippet(
        &self,
        aster_id: &str,
        query: &str,
    ) -> Result<Option<(Option<String>, Option<String>)>, String> {
        let q = sanitize_fts_query(query);
        if q.is_empty() {
            return Ok(None);
        }
        self.with_conn(|conn| {
            let row = conn
                .query_row(
                    "SELECT snippet(message_fts, 1, char(2), char(3), '…', 16) AS subj,
                            snippet(message_fts, 4, char(2), char(3), '…', 32) AS body
                     FROM message_fts
                     WHERE message_fts MATCH ?1 AND aster_id = ?2
                     LIMIT 1",
                    rusqlite::params![q, aster_id],
                    |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)),
                )
                .ok();
            Ok(row.map(|(subj, body)| (escape_fts_snippet(subj), escape_fts_snippet(body))))
        })
    }
}

const FTS_MARK_START: char = '\u{0002}';
const FTS_MARK_END: char = '\u{0003}';

fn escape_fts_snippet(raw: Option<String>) -> Option<String> {
    raw.map(|s| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace(FTS_MARK_START, "<mark>")
            .replace(FTS_MARK_END, "</mark>")
    })
}

fn sanitize_fts_query(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tokens: Vec<String> = trimmed
        .split_whitespace()
        .filter_map(|tok| {
            let cleaned: String = tok
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '\'' || *c == '-' || *c == '_' || *c == '@' || *c == '.')
                .collect();
            if cleaned.is_empty() {
                None
            } else {
                Some(format!("\"{}\"", cleaned.replace('"', "\"\"")))
            }
        })
        .collect();
    tokens.join(" ")
}

impl Database {

    pub fn with_conn<F, R>(&self, f: F) -> Result<R, String>
    where
        F: FnOnce(&Connection) -> Result<R, rusqlite::Error>,
    {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        f(&conn).map_err(|e| e.to_string())
    }

    pub fn upsert_cached_message(
        &self,
        aster_id: &str,
        folder: &str,
        subject: Option<&str>,
        sender: Option<&str>,
        recipients: Option<&str>,
        date: Option<&str>,
        size: i64,
        body_text: Option<&str>,
        raw_headers: Option<&str>,
    ) -> Result<bool, String> {
        let subject = subject.map(strip_c0_controls);
        let sender = sender.map(strip_c0_controls);
        let recipients = recipients.map(strip_c0_controls);
        let body_text = body_text.map(strip_c0_controls);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO message_cache (aster_id, folder, subject, sender, recipients, date, size, body_cached, body_text, raw_headers)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    aster_id,
                    folder,
                    subject,
                    sender,
                    recipients,
                    date,
                    size,
                    body_text.is_some() as i32,
                    body_text,
                    raw_headers,
                ],
            )?;
            let was_inserted = conn.changes() > 0;
            if !was_inserted {
                conn.execute(
                    "UPDATE message_cache SET folder=?2, subject=?3, sender=?4, recipients=?5, date=?6, size=?7, raw_headers=?8 WHERE aster_id=?1",
                    rusqlite::params![aster_id, folder, subject, sender, recipients, date, size, raw_headers],
                )?;
                if body_text.is_some() {
                    conn.execute(
                        "UPDATE message_cache SET body_cached=1, body_text=?2 WHERE aster_id=?1",
                        rusqlite::params![aster_id, body_text],
                    )?;
                }
            }
            Ok(was_inserted)
        })
    }

    pub fn body_cached(&self, aster_id: &str) -> bool {
        self.with_conn(|conn| {
            let cached: Option<i64> = conn
                .query_row(
                    "SELECT body_cached FROM message_cache WHERE aster_id = ?1",
                    rusqlite::params![aster_id],
                    |row| row.get(0),
                )
                .ok();
            Ok(cached == Some(1))
        })
        .unwrap_or(false)
    }

    pub fn list_cached_messages(&self, folder: &str) -> Result<Vec<CachedMessage>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT m.aster_id, m.folder, m.subject, m.sender, m.recipients, m.date, m.size, m.flags, m.body_text, m.raw_headers, COALESCE(u.imap_uid, 0), m.thread_id
                 FROM message_cache m
                 LEFT JOIN uid_map u ON u.aster_id = m.aster_id AND u.folder = m.folder
                 WHERE m.folder = ?1
                 ORDER BY u.imap_uid ASC",
            )?;
            let rows = stmt.query_map([folder], |row| {
                Ok(CachedMessage {
                    aster_id: row.get(0)?,
                    folder: row.get(1)?,
                    subject: row.get(2)?,
                    sender: row.get(3)?,
                    recipients: row.get(4)?,
                    date: row.get(5)?,
                    size: row.get(6)?,
                    flags: row.get(7)?,
                    body_text: row.get(8)?,
                    raw_headers: row.get(9)?,
                    imap_uid: row.get::<_, i64>(10)? as u32,
                    thread_id: row.get(11)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn list_cached_message_meta(&self, folder: &str) -> Result<Vec<CachedMessage>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT m.aster_id, m.folder, m.subject, m.sender, m.recipients, m.date, m.size, m.flags, NULL, m.raw_headers, COALESCE(u.imap_uid, 0), m.thread_id
                 FROM message_cache m
                 LEFT JOIN uid_map u ON u.aster_id = m.aster_id AND u.folder = m.folder
                 WHERE m.folder = ?1
                 ORDER BY u.imap_uid ASC",
            )?;
            let rows = stmt.query_map([folder], |row| {
                Ok(CachedMessage {
                    aster_id: row.get(0)?,
                    folder: row.get(1)?,
                    subject: row.get(2)?,
                    sender: row.get(3)?,
                    recipients: row.get(4)?,
                    date: row.get(5)?,
                    size: row.get(6)?,
                    flags: row.get(7)?,
                    body_text: row.get(8)?,
                    raw_headers: row.get(9)?,
                    imap_uid: row.get::<_, i64>(10)? as u32,
                    thread_id: row.get(11)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn count_cached_messages(&self, folder: &str) -> Result<u32, String> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM message_cache WHERE folder = ?1",
                [folder],
                |r| r.get(0),
            )?;
            Ok(n as u32)
        })
    }

    pub fn count_unread_messages(&self, folder: &str) -> Result<u32, String> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM message_cache WHERE folder = ?1 AND (flags & 1) = 0",
                [folder],
                |r| r.get(0),
            )?;
            Ok(n as u32)
        })
    }

    pub fn delete_message_by_uid(&self, uid: i64, folder: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            let aster_id: Option<String> = conn
                .query_row(
                    "SELECT aster_id FROM uid_map WHERE imap_uid = ?1 AND folder = ?2",
                    rusqlite::params![uid, folder],
                    |r| r.get(0),
                )
                .ok();
            if let Some(id) = &aster_id {
                conn.execute("DELETE FROM message_cache WHERE aster_id = ?1", [id])?;
                conn.execute(
                    "DELETE FROM uid_map WHERE aster_id = ?1 AND folder = ?2",
                    rusqlite::params![id, folder],
                )?;
            }
            Ok(())
        })
    }

    pub fn remove_uid_mapping(&self, uid: i64, folder: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM uid_map WHERE imap_uid = ?1 AND folder = ?2",
                rusqlite::params![uid, folder],
            )?;
            Ok(())
        })
    }

    pub fn delete_message_by_aster_id(&self, aster_id: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM message_cache WHERE aster_id = ?1", [aster_id])?;
            conn.execute("DELETE FROM uid_map WHERE aster_id = ?1", [aster_id])?;
            Ok(())
        })
    }

    pub fn get_message_flags_by_id(&self, aster_id: &str) -> Result<i64, String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT flags FROM message_cache WHERE aster_id = ?1",
                rusqlite::params![aster_id],
                |r| r.get::<_, i64>(0),
            )
        })
    }

    pub fn set_message_flags_by_id(&self, aster_id: &str, new_flags: i64) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE message_cache SET flags = ?1 WHERE aster_id = ?2",
                rusqlite::params![new_flags, aster_id],
            )?;
            Ok(())
        })
    }

    pub fn list_all_message_ids(&self) -> Result<Vec<String>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT aster_id FROM message_cache ORDER BY created_at DESC LIMIT 500")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn update_message_flags(&self, imap_uid: i64, folder: &str, new_flags: i64) -> Result<(), String> {
        self.with_conn(|conn| {
            let aster_id: Option<String> = conn
                .query_row(
                    "SELECT aster_id FROM uid_map WHERE imap_uid = ?1 AND folder = ?2",
                    rusqlite::params![imap_uid, folder],
                    |r| r.get(0),
                )
                .ok();
            if let Some(id) = aster_id {
                conn.execute(
                    "UPDATE message_cache SET flags = ?1 WHERE aster_id = ?2",
                    rusqlite::params![new_flags, id],
                )?;
            }
            Ok(())
        })
    }

    pub fn assign_uid_if_missing(&self, folder: &str, aster_id: &str) -> Result<u32, String> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO uid_map (aster_id, folder, imap_uid)
                 SELECT ?1, ?2, COALESCE(MAX(imap_uid), 0) + 1 FROM uid_map WHERE folder = ?2",
                rusqlite::params![aster_id, folder],
            )?;
            let uid: i64 = conn.query_row(
                "SELECT imap_uid FROM uid_map WHERE aster_id = ?1 AND folder = ?2",
                rusqlite::params![aster_id, folder],
                |r| r.get(0),
            )?;
            Ok(uid as u32)
        })
    }

    pub fn max_uid(&self, folder: &str) -> Result<u32, String> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COALESCE(MAX(imap_uid), 0) FROM uid_map WHERE folder = ?1",
                [folder],
                |r| r.get(0),
            )?;
            Ok(n as u32)
        })
    }

    pub fn get_sync_state(&self, key: &str) -> Result<Option<String>, String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT value FROM sync_state WHERE key = ?1",
                [key],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
        })
    }

    pub fn set_sync_state(&self, key: &str, value: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sync_state (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, value],
            )?;
            Ok(())
        })
    }

    pub fn seed_jmap_mailboxes(&self) -> Result<(), String> {
        const SEED: &[(&str, &str, &str, i64)] = &[
            ("mbx_inbox", "Inbox", "inbox", 1),
            ("mbx_archive", "Archive", "archive", 2),
            ("mbx_drafts", "Drafts", "drafts", 3),
            ("mbx_sent", "Sent", "sent", 4),
            ("mbx_trash", "Trash", "trash", 5),
            ("mbx_spam", "Junk", "spam", 6),
        ];
        self.with_conn(|conn| {
            for (id, name, label, order) in SEED {
                conn.execute(
                    "INSERT OR IGNORE INTO jmap_mailbox (id, name, parent_id, role, sort_order, folder_label) VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
                    rusqlite::params![id, name, name.to_lowercase(), order, label],
                )?;
            }
            Ok(())
        })
    }

    pub fn jmap_state_get(&self, ty: &str) -> Result<i64, String> {
        self.with_conn(|conn| {
            let row: Option<i64> = conn
                .query_row(
                    "SELECT counter FROM jmap_state WHERE type = ?1",
                    [ty],
                    |r| r.get::<_, i64>(0),
                )
                .ok();
            Ok(row.unwrap_or(0))
        })
    }

    pub fn jmap_state_bump(&self, ty: &str) -> Result<i64, String> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO jmap_state (type, counter) VALUES (?1, 1)
                 ON CONFLICT(type) DO UPDATE SET counter = counter + 1",
                [ty],
            )?;
            let new: i64 = conn.query_row(
                "SELECT counter FROM jmap_state WHERE type = ?1",
                [ty],
                |r| r.get(0),
            )?;
            Ok(new)
        })
    }

    pub fn jmap_change_log_append(
        &self,
        ty: &str,
        state: i64,
        object_id: &str,
        op: &str,
    ) -> Result<(), String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as i64;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO jmap_change_log (type, state, object_id, op, ts) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![ty, state, object_id, op, now],
            )?;
            let _ = conn.execute(
                "DELETE FROM jmap_change_log WHERE type = ?1 AND seq NOT IN (
                    SELECT seq FROM jmap_change_log WHERE type = ?1 ORDER BY seq DESC LIMIT 10000
                 )",
                [ty],
            );
            Ok(())
        })
    }

    pub fn jmap_changes_since(
        &self,
        ty: &str,
        since: i64,
    ) -> Result<(Vec<(String, String)>, i64, bool, bool), String> {
        self.with_conn(|conn| {
            let oldest: Option<i64> = conn
                .query_row(
                    "SELECT MIN(state) FROM jmap_change_log WHERE type = ?1",
                    [ty],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            let too_old = match oldest {
                Some(o) => since < o - 1,
                None => false,
            };
            if too_old {
                return Ok((Vec::new(), since, true, false));
            }
            let mut stmt = conn.prepare(
                "SELECT object_id, op, state FROM jmap_change_log
                 WHERE type = ?1 AND state > ?2
                 ORDER BY seq ASC LIMIT 501",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![ty, since], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let has_more = rows.len() > 500;
            let rows: Vec<_> = rows.into_iter().take(500).collect();
            let new_state = rows.last().map(|(_, _, s)| *s).unwrap_or(since);
            let entries = rows.into_iter().map(|(id, op, _)| (id, op)).collect();
            Ok((entries, new_state, false, has_more))
        })
    }

    pub fn jmap_blob_put(
        &self,
        blob_id: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> Result<(), String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as i64;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO jmap_blob (blob_id, data, content_type, size, created_ts) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![blob_id, data, content_type, data.len() as i64, now],
            )?;
            Ok(())
        })
    }

    pub fn jmap_blob_gc(&self, older_than_secs: i64) -> Result<usize, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            .saturating_sub(older_than_secs);
        self.with_conn(|conn| {
            let n = conn.execute(
                "DELETE FROM jmap_blob WHERE created_ts < ?1",
                [cutoff],
            )?;
            Ok(n)
        })
    }

    pub fn replay_check_and_record(
        &self,
        aster_id: &str,
        envelope_nonce: &str,
    ) -> Result<bool, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.with_conn(|conn| {
            let existing: Option<String> = conn
                .query_row(
                    "SELECT nonce FROM envelope_nonces WHERE aster_id = ?1",
                    [aster_id],
                    |r| r.get::<_, String>(0),
                )
                .ok();
            if let Some(prev) = existing {
                if prev != envelope_nonce {
                    return Ok(false);
                }
                return Ok(true);
            }
            conn.execute(
                "INSERT INTO envelope_nonces (aster_id, nonce, first_seen) VALUES (?1, ?2, ?3)",
                rusqlite::params![aster_id, envelope_nonce, now],
            )?;
            let _ = conn.execute(
                "DELETE FROM envelope_nonces WHERE rowid NOT IN (
                    SELECT rowid FROM envelope_nonces ORDER BY rowid DESC LIMIT 50000
                 )",
                [],
            );
            Ok(true)
        })
    }

    pub fn jmap_blob_get(&self, blob_id: &str) -> Result<Option<(Vec<u8>, Option<String>)>, String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT data, content_type FROM jmap_blob WHERE blob_id = ?1",
                [blob_id],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .map(Some)
            .or_else(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
        })
    }

    pub fn list_jmap_mailboxes(&self) -> Result<Vec<JmapMailboxRow>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, parent_id, role, sort_order, folder_label FROM jmap_mailbox ORDER BY sort_order",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(JmapMailboxRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        parent_id: r.get(2)?,
                        role: r.get(3)?,
                        sort_order: r.get::<_, i64>(4)? as i32,
                        folder_label: r.get(5)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn update_message_thread_and_msgid(
        &self,
        aster_id: &str,
        thread_id: Option<&str>,
        message_id: Option<&str>,
    ) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE message_cache SET thread_id = COALESCE(?2, thread_id), message_id = COALESCE(?3, message_id) WHERE aster_id = ?1",
                rusqlite::params![aster_id, thread_id, message_id],
            )?;
            Ok(())
        })
    }

    pub fn repair_cache(&self) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute_batch(
                "DELETE FROM message_cache;
                 DELETE FROM message_fts;
                 DELETE FROM jmap_state;
                 DELETE FROM jmap_change_log;
                 DELETE FROM jmap_blob;
                 DELETE FROM uid_map;
                 DELETE FROM envelope_nonces;
                 DELETE FROM sync_state;",
            )?;
            Ok(())
        })
    }

    pub fn clear_user_data(&self) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute_batch(
                "DELETE FROM message_cache;
                 DELETE FROM message_fts;
                 DELETE FROM uid_map;
                 DELETE FROM app_passwords;
                 DELETE FROM sync_state;
                 DELETE FROM jmap_state;
                 DELETE FROM jmap_change_log;
                 DELETE FROM jmap_blob;
                 DELETE FROM envelope_nonces;
                 DELETE FROM outbox;",
            )?;
            Ok(())
        })
    }

    pub fn db_stats(&self) -> Result<(i64, i64, Option<String>), String> {
        self.with_conn(|conn| {
            let messages: i64 = conn
                .query_row("SELECT COUNT(*) FROM message_cache", [], |r| r.get(0))
                .unwrap_or(0);
            let passwords: i64 = conn
                .query_row("SELECT COUNT(*) FROM app_passwords", [], |r| r.get(0))
                .unwrap_or(0);
            let last_sync: Option<String> = conn
                .query_row(
                    "SELECT value FROM sync_state WHERE key = 'last_sync_ts'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .ok();
            Ok((messages, passwords, last_sync))
        })
    }

    pub fn get_cached_message(&self, aster_id: &str) -> Result<Option<CachedMessage>, String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT m.aster_id, m.folder, m.subject, m.sender, m.recipients, m.date, m.size, m.flags, m.body_text, m.raw_headers, COALESCE(u.imap_uid, 0), m.thread_id
                 FROM message_cache m LEFT JOIN uid_map u ON u.aster_id = m.aster_id AND u.folder = m.folder
                 WHERE m.aster_id = ?1",
                [aster_id],
                |row| Ok(CachedMessage {
                    aster_id: row.get(0)?,
                    folder: row.get(1)?,
                    subject: row.get(2)?,
                    sender: row.get(3)?,
                    recipients: row.get(4)?,
                    date: row.get(5)?,
                    size: row.get(6)?,
                    flags: row.get(7)?,
                    body_text: row.get(8)?,
                    raw_headers: row.get(9)?,
                    imap_uid: row.get::<_, i64>(10)? as u32,
                    thread_id: row.get(11)?,
                }),
            )
            .map(Some)
            .or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e) })
        })
    }

}

#[derive(Debug, Clone)]
pub struct OutboxRow {
    pub id: i64,
    pub raw_mime: Vec<u8>,
    pub envelope_from: String,
    pub envelope_to: String,
    pub queued_at: i64,
    pub attempts: i64,
    pub last_attempt_at: Option<i64>,
    pub last_error: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OutboxStats {
    pub pending: i64,
    pub failed: i64,
    pub sent_24h: i64,
}

impl Database {
    pub fn outbox_reset_stale_sending(&self) -> Result<usize, String> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE outbox SET status = 'pending' WHERE status = 'sending'",
                [],
            )
        })
    }

    pub fn outbox_insert(
        &self,
        raw_mime: &[u8],
        envelope_from: &str,
        envelope_to: &str,
    ) -> Result<i64, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO outbox (raw_mime, envelope_from, envelope_to, queued_at, attempts, status)
                 VALUES (?1, ?2, ?3, ?4, 0, 'pending')",
                rusqlite::params![raw_mime, envelope_from, envelope_to, now],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    pub fn outbox_list_pending(&self) -> Result<Vec<OutboxRow>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, raw_mime, envelope_from, envelope_to, queued_at, attempts, last_attempt_at, last_error, status
                 FROM outbox
                 WHERE status IN ('pending','failed','sending')
                 ORDER BY queued_at ASC",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(OutboxRow {
                    id: r.get(0)?,
                    raw_mime: r.get(1)?,
                    envelope_from: r.get(2)?,
                    envelope_to: r.get(3)?,
                    queued_at: r.get(4)?,
                    attempts: r.get(5)?,
                    last_attempt_at: r.get(6)?,
                    last_error: r.get(7)?,
                    status: r.get(8)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn outbox_get(&self, id: i64) -> Result<Option<OutboxRow>, String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT id, raw_mime, envelope_from, envelope_to, queued_at, attempts, last_attempt_at, last_error, status
                 FROM outbox WHERE id = ?1",
                [id],
                |r| Ok(OutboxRow {
                    id: r.get(0)?,
                    raw_mime: r.get(1)?,
                    envelope_from: r.get(2)?,
                    envelope_to: r.get(3)?,
                    queued_at: r.get(4)?,
                    attempts: r.get(5)?,
                    last_attempt_at: r.get(6)?,
                    last_error: r.get(7)?,
                    status: r.get(8)?,
                }),
            )
            .map(Some)
            .or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e) })
        })
    }

    pub fn outbox_mark_sending(&self, id: i64) -> Result<usize, String> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "UPDATE outbox SET status = 'sending' WHERE id = ?1 AND status IN ('pending', 'failed')",
                [id],
            )?;
            Ok(n)
        })
    }

    pub fn outbox_mark_sent(&self, id: i64) -> Result<(), String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE outbox SET status = 'sent', last_attempt_at = ?2, last_error = NULL WHERE id = ?1",
                rusqlite::params![id, now],
            )?;
            Ok(())
        })
    }

    pub fn outbox_mark_failed(&self, id: i64, err: &str) -> Result<(), String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let truncated: String = err.chars().take(512).collect();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE outbox SET status = 'failed', last_attempt_at = ?2, last_error = ?3 WHERE id = ?1",
                rusqlite::params![id, now, truncated],
            )?;
            Ok(())
        })
    }

    pub fn outbox_bump_attempt(&self, id: i64, err: &str) -> Result<(), String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let truncated: String = err.chars().take(512).collect();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE outbox SET attempts = attempts + 1, last_attempt_at = ?2, last_error = ?3, status = 'pending' WHERE id = ?1",
                rusqlite::params![id, now, truncated],
            )?;
            Ok(())
        })
    }

    pub fn outbox_stats(&self) -> Result<OutboxStats, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let cutoff = now - 86400;
        self.with_conn(|conn| {
            let pending: i64 = conn.query_row(
                "SELECT COUNT(*) FROM outbox WHERE status IN ('pending','sending')",
                [],
                |r| r.get(0),
            ).unwrap_or(0);
            let failed: i64 = conn.query_row(
                "SELECT COUNT(*) FROM outbox WHERE status = 'failed'",
                [],
                |r| r.get(0),
            ).unwrap_or(0);
            let sent_24h: i64 = conn.query_row(
                "SELECT COUNT(*) FROM outbox WHERE status = 'sent' AND last_attempt_at >= ?1",
                [cutoff],
                |r| r.get(0),
            ).unwrap_or(0);
            Ok(OutboxStats { pending, failed, sent_24h })
        })
    }

    pub fn jmap_record_sync_batch(&self, ty: &str, ids: &[&str]) -> Result<i64, String> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO jmap_state (type, counter) VALUES (?1, 1)
                 ON CONFLICT(type) DO UPDATE SET counter = counter + 1",
                [ty],
            )?;
            let new_state: i64 = conn.query_row(
                "SELECT counter FROM jmap_state WHERE type = ?1",
                [ty],
                |r| r.get(0),
            )?;
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0) as i64;
            for id in ids {
                let _ = conn.execute(
                    "INSERT INTO jmap_change_log (type, state, object_id, op, ts) VALUES (?1, ?2, ?3, 'created', ?4)",
                    rusqlite::params![ty, new_state, id, now],
                );
            }
            let _ = conn.execute(
                "DELETE FROM jmap_change_log WHERE seq NOT IN (SELECT seq FROM jmap_change_log ORDER BY seq DESC LIMIT 10000)",
                [],
            );
            Ok(new_state)
        })
    }

    pub fn clear_all_user_data(&self) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute_batch(
                "DELETE FROM message_cache;
                 DELETE FROM message_fts;
                 DELETE FROM uid_map;
                 DELETE FROM app_passwords;
                 DELETE FROM sync_state;
                 DELETE FROM jmap_state;
                 DELETE FROM jmap_change_log;
                 DELETE FROM jmap_blob;
                 DELETE FROM envelope_nonces;
                 DELETE FROM outbox;",
            )?;
            Ok(())
        })
    }

}

#[derive(Debug, Clone)]
pub struct JmapMailboxRow {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub role: Option<String>,
    pub sort_order: i32,
    pub folder_label: String,
}

#[derive(Debug, Clone)]
pub struct CachedMessage {
    pub aster_id: String,
    pub folder: String,
    pub subject: Option<String>,
    pub sender: Option<String>,
    pub recipients: Option<String>,
    pub date: Option<String>,
    pub size: i64,
    pub flags: i64,
    pub body_text: Option<String>,
    pub raw_headers: Option<String>,
    pub imap_uid: u32,
    pub thread_id: Option<String>,
}

#[cfg(test)]
mod encryption_tests {
    use super::*;

    #[test]
    fn fresh_db_is_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let key = [3u8; 32];
        let db = Database::open_with_key(dir.path(), &key).unwrap();
        drop(db);

        let bare = Connection::open(dir.path().join("bridge.db")).unwrap();
        assert!(!is_readable(&bare), "plaintext open of encrypted db must fail");
    }

    #[test]
    fn migrates_plaintext_db_preserving_data() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("bridge.db");

        {
            let plain = Connection::open(&db_path).unwrap();
            plain
                .execute_batch(
                    "CREATE TABLE app_passwords (
                        id TEXT PRIMARY KEY,
                        label TEXT NOT NULL,
                        hash TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (datetime('now'))
                     );
                     INSERT INTO app_passwords (id, label, hash)
                     VALUES ('p1', 'thunderbird', 'argon2hash');",
                )
                .unwrap();
        }

        let key = [9u8; 32];
        let db = Database::open_with_key(dir.path(), &key).unwrap();
        let label: String = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT label FROM app_passwords WHERE id = 'p1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(label, "thunderbird");
        drop(db);

        let bare = Connection::open(&db_path).unwrap();
        assert!(!is_readable(&bare), "migrated db must no longer be plaintext");

        let keyed = Connection::open(&db_path).unwrap();
        apply_key(&keyed, &key).unwrap();
        assert!(is_readable(&keyed), "migrated db must open with the key");
    }

    #[test]
    fn reopen_with_same_key_keeps_data_and_does_not_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let key = [5u8; 32];

        let db = Database::open_with_key(dir.path(), &key).unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO sync_state (key, value) VALUES ('marker', 'present')",
                [],
            )
            .unwrap();
        drop(db);

        let db2 = Database::open_with_key(dir.path(), &key).unwrap();
        let value: String = db2
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM sync_state WHERE key = 'marker'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(value, "present");
        assert!(
            !dir.path().join("bridge.db.unreadable").exists(),
            "a correct-key reopen must not quarantine the db"
        );
    }

    #[test]
    fn wrong_key_quarantines_and_recovers_fresh() {
        let dir = tempfile::tempdir().unwrap();

        let db = Database::open_with_key(dir.path(), &[1u8; 32]).unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO sync_state (key, value) VALUES ('marker', 'secret')",
                [],
            )
            .unwrap();
        drop(db);

        let db2 = Database::open_with_key(dir.path(), &[2u8; 32]).unwrap();
        let quarantined = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("bridge.db.unreadable")
            });
        assert!(
            quarantined,
            "undecryptable db must be quarantined, not bricked"
        );
        let count: i64 = db2
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sync_state WHERE key = 'marker'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "fresh db must not expose old-key data");
    }

    #[test]
    fn migrates_wal_mode_plaintext_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("bridge.db");

        {
            let plain = Connection::open(&db_path).unwrap();
            plain.pragma_update(None, "journal_mode", "WAL").unwrap();
            plain
                .execute_batch(
                    "CREATE TABLE sync_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                     INSERT INTO sync_state (key, value) VALUES ('cursor', '42');",
                )
                .unwrap();
        }

        let key = [8u8; 32];
        let db = Database::open_with_key(dir.path(), &key).unwrap();
        let value: String = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM sync_state WHERE key = 'cursor'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(value, "42", "WAL-mode plaintext data must survive migration");
    }

    #[test]
    fn body_cached_reflects_cached_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[4u8; 32]).unwrap();

        assert!(!db.body_cached("unknown-id"), "unknown id is not cached");

        db.upsert_cached_message("m-nobody", "inbox", Some("s"), None, None, None, 0, None, None)
            .unwrap();
        assert!(
            !db.body_cached("m-nobody"),
            "row without a body must not count as cached"
        );

        db.upsert_cached_message(
            "m-withbody",
            "inbox",
            Some("s"),
            None,
            None,
            None,
            4,
            Some("body"),
            None,
        )
        .unwrap();
        assert!(
            db.body_cached("m-withbody"),
            "row with a body must count as cached (skips re-decrypt)"
        );
    }
}
