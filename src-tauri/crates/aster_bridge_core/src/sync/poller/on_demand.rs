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
use super::*;
use crate::db::ATTACHMENTS_ON_DEMAND;

const FILL_CONCURRENCY: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentFill {
    Ready,
    Replaced,
    Unavailable,
}

fn fill_locks() -> &'static StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn fill_permits() -> &'static tokio::sync::Semaphore {
    static PERMITS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    PERMITS.get_or_init(|| tokio::sync::Semaphore::new(FILL_CONCURRENCY))
}

fn rate_limited_until() -> &'static StdMutex<Option<std::time::Instant>> {
    static UNTIL: OnceLock<StdMutex<Option<std::time::Instant>>> = OnceLock::new();
    UNTIL.get_or_init(|| StdMutex::new(None))
}

fn rate_limited() -> bool {
    let guard = rate_limited_until().lock().unwrap_or_else(|e| e.into_inner());
    guard.is_some_and(|until| std::time::Instant::now() < until)
}

fn note_rate_limit() {
    let mut guard = rate_limited_until().lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(std::time::Instant::now() + RATE_LIMIT_PAUSE);
}

fn lock_for(aster_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = fill_locks().lock().unwrap_or_else(|e| e.into_inner());
    locks.entry(aster_id.to_string()).or_default().clone()
}

fn release_lock(aster_id: &str, lock: Arc<tokio::sync::Mutex<()>>) {
    let mut locks = fill_locks().lock().unwrap_or_else(|e| e.into_inner());
    drop(lock);
    if locks.get(aster_id).is_some_and(|l| Arc::strong_count(l) == 1) {
        locks.remove(aster_id);
    }
}

pub fn is_on_demand(db: &Database, aster_id: &str) -> bool {
    db.attachments_state(aster_id).ok() == Some(ATTACHMENTS_ON_DEMAND)
}

pub async fn ensure_attachments(
    db: &Database,
    client: &ApiClient,
    session: &Arc<RwLock<Session>>,
    aster_id: &str,
    notify: Option<&broadcast::Sender<StateChange>>,
) -> AttachmentFill {
    if !is_on_demand(db, aster_id) {
        return AttachmentFill::Ready;
    }
    let lock = lock_for(aster_id);
    let outcome = {
        let _guard = lock.lock().await;
        if is_on_demand(db, aster_id) {
            fill(db, client, session, aster_id, notify).await
        } else {
            AttachmentFill::Ready
        }
    };
    release_lock(aster_id, lock);
    outcome
}

fn same_shape(advertised: &[CachedAttachment], fetched: &[CachedAttachment]) -> bool {
    advertised.len() == fetched.len()
        && advertised
            .iter()
            .zip(fetched)
            .all(|(a, f)| a.seq == f.seq && a.size == f.data.len() as i64)
}

async fn fill(
    db: &Database,
    client: &ApiClient,
    session: &Arc<RwLock<Session>>,
    aster_id: &str,
    notify: Option<&broadcast::Sender<StateChange>>,
) -> AttachmentFill {
    if rate_limited() {
        return AttachmentFill::Unavailable;
    }
    let Ok(_permit) = fill_permits().acquire().await else {
        return AttachmentFill::Unavailable;
    };
    let Ok(Some(msg)) = db.get_cached_message(aster_id) else {
        return AttachmentFill::Unavailable;
    };
    let advertised = match db.get_message_attachment_meta(aster_id) {
        Ok(parts) => parts,
        Err(_) => return AttachmentFill::Unavailable,
    };
    let keys = history::Keys::of(session).await;
    let download = download_backlog_item(
        client,
        &keys.access_token,
        aster_id.to_string(),
        msg.folder.clone(),
        msg,
        &keys.passphrase,
        keys.identity_key.as_deref(),
        &keys.previous_keys,
        &keys.inbound_keys,
    )
    .await;
    let BacklogDownload {
        aster_id,
        folder,
        msg,
        meta_json,
        result,
    } = download;
    match result {
        Ok(list) if same_shape(&advertised, &list) => {
            let contents: Vec<(i64, Vec<u8>)> = list.into_iter().map(|a| (a.seq, a.data)).collect();
            match db.fill_on_demand_attachments(&aster_id, &contents) {
                Ok(true) => AttachmentFill::Ready,
                _ if db.attachments_state(&aster_id).ok() == Some(ATTACHMENTS_STORED) => AttachmentFill::Ready,
                _ => AttachmentFill::Unavailable,
            }
        }
        Ok(list) => {
            if db.replace_message_attachments(&aster_id, &list).is_err() {
                return AttachmentFill::Unavailable;
            }
            if meta_json != msg.raw_headers {
                let body = msg.body_text.clone().unwrap_or_default();
                let _ = db.update_cached_body(&aster_id, &body, meta_json.as_deref());
            }
            renumber(db, &msg, &folder, notify);
            AttachmentFill::Replaced
        }
        Err(AttachmentFetchError::Transport(e)) => {
            if is_rate_limit_message(&e) {
                note_rate_limit();
            }
            AttachmentFill::Unavailable
        }
        Err(AttachmentFetchError::Permanent(_)) => give_up(db, &msg, &folder, notify),
        Err(AttachmentFetchError::Content(_)) => {
            let attempts = db.bump_attachment_attempts(&aster_id).unwrap_or(0);
            if attempts >= ATTACHMENT_MAX_ATTEMPTS {
                give_up(db, &msg, &folder, notify)
            } else {
                AttachmentFill::Unavailable
            }
        }
    }
}

fn give_up(
    db: &Database,
    msg: &CachedMessage,
    folder: &str,
    notify: Option<&broadcast::Sender<StateChange>>,
) -> AttachmentFill {
    if db.drop_attachment_parts(&msg.aster_id, ATTACHMENTS_FAILED).is_err() {
        return AttachmentFill::Unavailable;
    }
    renumber(db, msg, folder, notify);
    AttachmentFill::Replaced
}

fn renumber(
    db: &Database,
    msg: &CachedMessage,
    folder: &str,
    notify: Option<&broadcast::Sender<StateChange>>,
) {
    if msg.imap_uid > 0 {
        let _ = db.remove_uid_mapping(msg.imap_uid as i64, folder);
    }
    let _ = db.assign_uid_if_missing(folder, &msg.aster_id);
    let _ = db.jmap_record_updated_batch("Email", &[msg.aster_id.as_str()]);
    history::broadcast(db, notify);
}
