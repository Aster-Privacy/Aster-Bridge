//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::collections::HashMap;

use crate::db::{CachedMessage, Database, JmapMailboxRow};

pub fn label_to_mailbox_id_map(db: &Database) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Ok(rows) = db.list_jmap_mailboxes() {
        for r in rows {
            out.insert(r.folder_label.clone(), r.id.clone());
        }
    }
    out
}

pub fn mailbox_id_to_label_map(db: &Database) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Ok(rows) = db.list_jmap_mailboxes() {
        for r in rows {
            out.insert(r.id.clone(), r.folder_label.clone());
        }
    }
    out
}

pub fn all_mailboxes(db: &Database) -> Vec<JmapMailboxRow> {
    db.list_jmap_mailboxes().unwrap_or_default()
}

pub fn folder_counts(db: &Database, folder: &str) -> (u32, u32) {
    let total = db.count_cached_messages(folder).unwrap_or(0);
    let unread = db
        .with_conn(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM message_cache WHERE folder = ?1 AND (flags & 1) = 0",
                [folder],
                |r| r.get(0),
            )?;
            Ok(n as u32)
        })
        .unwrap_or(0);
    (total, unread)
}

pub fn list_messages_all(db: &Database) -> Vec<CachedMessage> {
    db.with_conn(|conn| {
        let mut stmt = conn.prepare(
            "SELECT m.aster_id, m.folder, m.subject, m.sender, m.recipients, m.date, m.size, m.flags, m.body_text, m.raw_headers, COALESCE(u.imap_uid, 0), m.thread_id
             FROM message_cache m LEFT JOIN uid_map u ON u.aster_id = m.aster_id AND u.folder = m.folder
             ORDER BY m.created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
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
        rows.collect::<std::result::Result<Vec<_>, _>>()
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> (Database, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[1u8; 32]).unwrap();
        db.seed_jmap_mailboxes().unwrap();
        (db, dir)
    }

    fn add(db: &Database, id: &str, folder: &str, seen: bool) {
        db.upsert_cached_message(id, folder, Some("s"), Some("a@b.com"), Some("c@d.com"), Some("2026-01-01T00:00:00Z"), 10, Some("body"), Some("{}"))
            .unwrap();
        if seen {
            db.set_message_flags_by_id(id, 1).unwrap();
        }
    }

    #[test]
    fn all_mailboxes_has_six_seeded() {
        let (db, _d) = test_db();
        let rows = all_mailboxes(&db);
        assert_eq!(rows.len(), 6);
    }

    #[test]
    fn label_and_id_maps_are_inverses() {
        let (db, _d) = test_db();
        let l2i = label_to_mailbox_id_map(&db);
        let i2l = mailbox_id_to_label_map(&db);
        assert_eq!(l2i.get("inbox").map(|s| s.as_str()), Some("mbx_inbox"));
        assert_eq!(i2l.get("mbx_inbox").map(|s| s.as_str()), Some("inbox"));
        for (label, id) in &l2i {
            assert_eq!(i2l.get(id), Some(label));
        }
    }

    #[test]
    fn folder_counts_total_and_unread() {
        let (db, _d) = test_db();
        add(&db, "m1", "inbox", false);
        add(&db, "m2", "inbox", true);
        add(&db, "m3", "inbox", false);
        let (total, unread) = folder_counts(&db, "inbox");
        assert_eq!(total, 3);
        assert_eq!(unread, 2);
    }

    #[test]
    fn folder_counts_empty_folder_is_zero() {
        let (db, _d) = test_db();
        assert_eq!(folder_counts(&db, "archive"), (0, 0));
    }

    #[test]
    fn folder_counts_scoped_per_folder() {
        let (db, _d) = test_db();
        add(&db, "a", "inbox", false);
        add(&db, "b", "sent", false);
        assert_eq!(folder_counts(&db, "inbox").0, 1);
        assert_eq!(folder_counts(&db, "sent").0, 1);
    }

    #[test]
    fn list_messages_all_returns_inserted() {
        let (db, _d) = test_db();
        add(&db, "x1", "inbox", false);
        add(&db, "x2", "sent", false);
        let all = list_messages_all(&db);
        assert_eq!(all.len(), 2);
        let ids: Vec<&str> = all.iter().map(|m| m.aster_id.as_str()).collect();
        assert!(ids.contains(&"x1") && ids.contains(&"x2"));
    }

    #[test]
    fn list_messages_all_empty() {
        let (db, _d) = test_db();
        assert!(list_messages_all(&db).is_empty());
    }
}
