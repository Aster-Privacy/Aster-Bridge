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
use super::Database;

pub(super) const HISTORY_SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS listing_member (
    listing TEXT NOT NULL,
    aster_id TEXT NOT NULL,
    round INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (listing, aster_id)
);
CREATE INDEX IF NOT EXISTS idx_listing_member_aster ON listing_member(aster_id);
CREATE TABLE IF NOT EXISTS history_prune_queue (
    aster_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS history_retry (
    aster_id TEXT PRIMARY KEY,
    listing TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL
);";

pub(super) const HISTORY_CLEAR_SQL: &str = "DELETE FROM listing_member;
DELETE FROM history_prune_queue;
DELETE FROM history_retry;";

const QUEUE_DEPARTED_SQL: &str = "INSERT OR IGNORE INTO history_prune_queue (aster_id)
    SELECT m.aster_id FROM listing_member m
    JOIN message_cache c ON c.aster_id = m.aster_id
    WHERE m.listing = ?1 AND m.round < ?2 AND c.folder <> 'drafts'
      AND NOT EXISTS (
          SELECT 1 FROM listing_member o WHERE o.aster_id = m.aster_id AND o.listing <> ?1
      )";

impl Database {
    pub fn stamp_listing_members(&self, listing: &str, aster_ids: &[&str], round: i64) -> Result<(), String> {
        if aster_ids.is_empty() {
            return Ok(());
        }
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO listing_member (listing, aster_id, round) VALUES (?1, ?2, ?3)
                     ON CONFLICT(listing, aster_id) DO UPDATE SET round = MAX(round, excluded.round)",
                )?;
                for id in aster_ids {
                    stmt.execute(rusqlite::params![listing, id, round])?;
                }
            }
            tx.commit()
        })
    }

    pub fn forget_listing_member(&self, listing: &str, aster_id: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM listing_member WHERE listing = ?1 AND aster_id = ?2",
                rusqlite::params![listing, aster_id],
            )?;
            Ok(())
        })
    }

    pub fn listing_member_count(&self, listing: &str) -> Result<usize, String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM listing_member WHERE listing = ?1",
                [listing],
                |r| r.get::<_, i64>(0),
            )
        })
        .map(|n| n.max(0) as usize)
    }

    pub fn finish_listing_sweep(&self, listing: &str, round: i64) -> Result<usize, String> {
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let queued = tx.execute(QUEUE_DEPARTED_SQL, rusqlite::params![listing, round])?;
            tx.execute(
                "DELETE FROM listing_member WHERE listing = ?1 AND round < ?2",
                rusqlite::params![listing, round],
            )?;
            tx.commit()?;
            Ok(queued)
        })
    }

    pub fn forget_listings_except(&self, keep: &[String]) -> Result<usize, String> {
        let stale: Vec<String> = self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT DISTINCT listing FROM listing_member")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<Vec<String>, _>>()
        })?;
        let mut queued = 0;
        for listing in stale.iter().filter(|l| !keep.contains(l)) {
            queued += self.finish_listing_sweep(listing, i64::MAX)?;
        }
        Ok(queued)
    }

    pub fn prune_queue_batch(&self, limit: usize) -> Result<Vec<String>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT aster_id FROM history_prune_queue ORDER BY rowid LIMIT ?1")?;
            let rows = stmt.query_map([limit as i64], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<Vec<String>, _>>()
        })
    }

    pub fn prune_queue_drop_listed(&self) -> Result<usize, String> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM history_prune_queue WHERE aster_id IN (SELECT aster_id FROM listing_member)",
                [],
            )
        })
    }

    pub fn prune_queue_remove(&self, aster_id: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM history_prune_queue WHERE aster_id = ?1", [aster_id])?;
            Ok(())
        })
    }

    pub fn history_retry_note(&self, aster_id: &str, listing: &str, delay_for: impl Fn(i64) -> i64, now: i64) -> Result<i64, String> {
        self.with_conn(|conn| {
            let attempts: i64 = conn.query_row(
                "INSERT INTO history_retry (aster_id, listing, attempts, next_at) VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(aster_id) DO UPDATE SET attempts = attempts + 1, listing = excluded.listing
                 RETURNING attempts",
                rusqlite::params![aster_id, listing, now],
                |r| r.get(0),
            )?;
            conn.execute(
                "UPDATE history_retry SET next_at = ?2 WHERE aster_id = ?1",
                rusqlite::params![aster_id, now.saturating_add(delay_for(attempts))],
            )?;
            Ok(attempts)
        })
    }

    pub fn history_retry_due(&self, now: i64, max_attempts: i64, limit: usize) -> Result<Vec<(String, String)>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT aster_id, listing FROM history_retry
                 WHERE next_at <= ?1 AND attempts < ?2 ORDER BY next_at LIMIT ?3",
            )?;
            let rows = stmt.query_map(rusqlite::params![now, max_attempts, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn history_retry_clear(&self, aster_id: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM history_retry WHERE aster_id = ?1", [aster_id])?;
            Ok(())
        })
    }

    pub fn clear_history_index(&self) -> Result<(), String> {
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(HISTORY_CLEAR_SQL)?;
            tx.execute("DELETE FROM sync_state WHERE key LIKE 'history:%'", [])?;
            tx.commit()
        })
    }

    pub fn trim_folders_to_newest(&self, keep: usize) -> Result<Vec<String>, String> {
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let ids: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT aster_id FROM (
                         SELECT aster_id, ROW_NUMBER() OVER (
                             PARTITION BY folder ORDER BY date DESC, created_at DESC
                         ) AS position
                         FROM message_cache WHERE folder <> 'drafts'
                     ) WHERE position > ?1",
                )?;
                let rows = stmt.query_map([keep as i64], |r| r.get::<_, String>(0))?;
                rows.collect::<Result<Vec<String>, _>>()?
            };
            for id in &ids {
                for sql in [
                    "DELETE FROM message_cache WHERE aster_id = ?1",
                    "DELETE FROM message_attachment WHERE aster_id = ?1",
                    "DELETE FROM uid_map WHERE aster_id = ?1",
                ] {
                    tx.execute(sql, [id])?;
                }
            }
            tx.commit()?;
            Ok(ids)
        })
    }
}
