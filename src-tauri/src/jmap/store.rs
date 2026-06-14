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
