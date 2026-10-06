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
use std::time::Duration;

use super::*;

pub(super) const HISTORY_MODE_KEY: &str = "history_mode";
const STATE_PREFIX: &str = "history:";
const PAGE_SIZE: i64 = 100;
#[cfg(not(test))]
const PAGE_INTERVAL: Duration = Duration::from_millis(500);
#[cfg(test)]
const PAGE_INTERVAL: Duration = Duration::from_millis(20);
const IDLE_RECHECK: Duration = Duration::from_secs(60);
#[cfg(not(test))]
const START_JITTER_MAX: Duration = Duration::from_secs(10 * 60);
#[cfg(test)]
const START_JITTER_MAX: Duration = Duration::ZERO;
const BROADCAST_EVERY: Duration = Duration::from_secs(10);
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
const RESWEEP_AFTER_SECS: u64 = 7 * 24 * 60 * 60;
const DRIFT_RESWEEP_AFTER_SECS: u64 = 15 * 60;
const PRUNE_CHECKS_PER_STEP: usize = 25;
const RETRIES_PER_STEP: usize = 10;
const RETRY_BASE_SECS: i64 = 15 * 60;
const RETRY_MAX_SECS: i64 = 24 * 60 * 60;
const RETRY_MAX_ATTEMPTS: i64 = 8;

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
struct ListingState {
    #[serde(default)]
    round: i64,
    #[serde(default)]
    sweeping: bool,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    offset: i64,
    #[serde(default)]
    walked: usize,
    #[serde(default)]
    total: usize,
    #[serde(default)]
    swept_at: u64,
    #[serde(default)]
    total_offset: i64,
    #[serde(default)]
    observed: Option<(usize, usize)>,
}

impl ListingState {
    fn needs_sweep(&self, now: u64) -> bool {
        if self.swept_at == 0 || now.saturating_sub(self.swept_at) >= RESWEEP_AFTER_SECS {
            return true;
        }
        self.observed.is_some_and(|(total, members)| {
            total as i64 - members as i64 != self.total_offset
                && now.saturating_sub(self.swept_at) >= DRIFT_RESWEEP_AFTER_SECS
        })
    }

    fn known_total(&self) -> usize {
        if self.sweeping || self.swept_at > 0 {
            self.total
        } else {
            self.observed.map_or(0, |(total, _)| total)
        }
    }

    fn indexed(&self) -> usize {
        if self.swept_at > 0 {
            self.known_total()
        } else if self.sweeping {
            self.walked.min(self.total)
        } else {
            0
        }
    }
}

#[derive(Debug, Clone)]
struct Listing {
    label: String,
    query: Option<MailListQuery>,
    token: Option<String>,
}

struct Keys {
    access_token: Zeroizing<String>,
    passphrase: Zeroizing<Vec<u8>>,
    identity_key: Option<String>,
    previous_keys: Zeroizing<Vec<String>>,
    inbound_keys: Vec<crate::crypto::inbound::InboundKeyCandidate>,
}

impl Keys {
    async fn of(session: &Arc<RwLock<Session>>) -> Self {
        let s = session.read().await;
        Self {
            access_token: s.access_token.clone(),
            passphrase: Zeroizing::new(s.vault_passphrase.clone()),
            identity_key: s.identity_key.clone(),
            previous_keys: s.previous_keys.clone(),
            inbound_keys: s.inbound_keys.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Step {
    Idle,
    Worked { changed: bool },
    Failed(String),
}

pub(super) fn is_enabled(db: &Database) -> bool {
    matches!(db.get_sync_state(HISTORY_MODE_KEY), Ok(Some(mode)) if mode == "all")
}

pub(super) fn apply_mode(db: &Database, full_history: bool) -> Vec<String> {
    let previous = db.get_sync_state(HISTORY_MODE_KEY).ok().flatten();
    let mut trimmed = Vec::new();
    if !full_history && previous.as_deref() == Some("all") {
        match db.trim_folders_to_newest(SYSTEM_FOLDER_MAX_ITEMS) {
            Ok(ids) => trimmed = ids,
            Err(e) => tracing::warn!("history: freeing older mail failed: {}", e),
        }
        if let Err(e) = db.clear_history_index() {
            tracing::warn!("history: clearing the index failed: {}", e);
        }
        tracing::info!(
            "history: kept the newest {} messages per folder and removed {} older ones",
            SYSTEM_FOLDER_MAX_ITEMS,
            trimmed.len()
        );
    }
    let mode = if full_history { "all" } else { "recent" };
    if let Err(e) = db.set_sync_state(HISTORY_MODE_KEY, mode) {
        tracing::warn!("history: saving the mode failed: {}", e);
    }
    trimmed
}

fn state_key(label: &str) -> String {
    format!("{}{}", STATE_PREFIX, label)
}

fn load(db: &Database, label: &str) -> ListingState {
    db.get_sync_state(&state_key(label))
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save(db: &Database, label: &str, state: &ListingState) {
    let Ok(raw) = serde_json::to_string(state) else {
        return;
    };
    if let Err(e) = db.set_sync_state(&state_key(label), &raw) {
        tracing::warn!("history: saving progress failed: {}", e);
    }
}

pub(super) fn stamp_listed(db: &Database, label: &str, ids: &[String]) {
    let round = load(db, label).round;
    let refs: Vec<&str> = ids.iter().map(String::as_str).filter(|id| is_valid_item_id(id)).collect();
    if let Err(e) = db.stamp_listing_members(label, &refs, round) {
        tracing::warn!("history: recording listed messages failed: {}", e);
    }
}

pub(super) fn note_listing_total(db: &Database, label: &str, total: usize) {
    let mut state = load(db, label);
    if state.sweeping {
        return;
    }
    let members = db.listing_member_count(label).unwrap_or(0);
    state.observed = Some((total, members));
    save(db, label, &state);
}

fn listings(db: &Database) -> Result<Vec<Listing>, String> {
    let custom_folders = db.list_custom_folders()?;
    let system = build_folder_queries().into_iter().map(|q| Listing {
        label: q.label.to_string(),
        query: Some(q.query),
        token: None,
    });
    let custom = custom_folders.into_iter().map(|f| Listing {
        label: crate::folders::folder_label(&f.label_token),
        query: None,
        token: Some(f.label_token),
    });
    Ok(system.chain(custom).collect())
}

fn folder_for(listing: &Listing, item: &MailItem, known_tokens: &HashSet<String>) -> String {
    if listing.token.is_some() {
        listing.label.clone()
    } else {
        target_folder(&listing.label, item, known_tokens)
    }
}

fn retry_delay_secs(attempts: i64) -> i64 {
    let shift = (attempts - 1).clamp(0, 16) as u32;
    RETRY_BASE_SECS.saturating_mul(1i64 << shift).min(RETRY_MAX_SECS)
}

fn is_gone(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Api(msg) if api_status_code(msg).is_some_and(is_permanent_status))
}

fn record_changes(db: &Database, created: &[String], updated: &[String], destroyed: &[String]) -> bool {
    for (ids, op) in [(created, "created"), (updated, "updated"), (destroyed, "destroyed")] {
        if ids.is_empty() {
            continue;
        }
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let _ = match op {
            "created" => db.jmap_record_sync_batch("Email", &refs),
            "updated" => db.jmap_record_updated_batch("Email", &refs),
            _ => db.jmap_record_destroyed_batch("Email", &refs),
        };
    }
    !(created.is_empty() && updated.is_empty() && destroyed.is_empty())
}

pub(super) fn broadcast(db: &Database, jmap_broadcaster: Option<&broadcast::Sender<StateChange>>) {
    let email_state = db.jmap_state_get("Email").unwrap_or(0);
    let mailbox_state = db.jmap_state_bump("Mailbox").unwrap_or(0);
    let thread_state = db.jmap_state_bump("Thread").unwrap_or(0);
    if let Some(tx) = jmap_broadcaster {
        let mut changed = HashMap::new();
        changed.insert("Email".to_string(), email_state.to_string());
        changed.insert("Mailbox".to_string(), mailbox_state.to_string());
        changed.insert("Thread".to_string(), thread_state.to_string());
        let _ = tx.send(StateChange { changed });
    }
}

pub(super) async fn step(
    session: &Arc<RwLock<Session>>,
    client: &ApiClient,
    db: &Database,
    now: u64,
) -> Step {
    if !is_enabled(db) {
        let _ = db.set_sync_state(HISTORY_MODE_KEY, "all");
    }
    let keys = Keys::of(session).await;
    if let Some(step) = retry_undecrypted(db, client, &keys, now).await {
        return step;
    }
    match sweep_page(db, client, &keys, now).await {
        Step::Idle => prune_departed(db, client, &keys).await.unwrap_or(Step::Idle),
        step => step,
    }
}

async fn prune_departed(db: &Database, client: &ApiClient, keys: &Keys) -> Option<Step> {
    let _ = db.prune_queue_drop_listed();
    let queued = db.prune_queue_batch(PRUNE_CHECKS_PER_STEP).ok()?;
    if queued.is_empty() {
        return None;
    }
    let mut destroyed: Vec<String> = Vec::new();
    let mut failure = None;
    for id in queued {
        if !is_valid_item_id(&id) {
            let _ = db.prune_queue_remove(&id);
            continue;
        }
        match client.fetch_mail_item(&keys.access_token, &id).await {
            Ok(_) => {
                let _ = db.prune_queue_remove(&id);
            }
            Err(e) if is_gone(&e) => {
                if db.delete_message_by_aster_id(&id).is_ok() {
                    tracing::info!("history: pruned {} (gone on server)", id);
                    destroyed.push(id);
                }
            }
            Err(e) => {
                failure = Some(format!("history: checking for deleted messages failed: {}", e));
                break;
            }
        }
    }
    let changed = record_changes(db, &[], &[], &destroyed);
    Some(match failure {
        Some(msg) => Step::Failed(msg),
        None => Step::Worked { changed },
    })
}

async fn retry_undecrypted(db: &Database, client: &ApiClient, keys: &Keys, now: u64) -> Option<Step> {
    let due = db
        .history_retry_due(now as i64, RETRY_MAX_ATTEMPTS, RETRIES_PER_STEP)
        .ok()?;
    if due.is_empty() {
        return None;
    }
    let listings = listings(db).ok()?;
    let known_tokens: HashSet<String> = listings.iter().filter_map(|l| l.token.clone()).collect();
    let mut created: Vec<String> = Vec::new();
    let mut failure = None;
    for (id, label) in due {
        let Some(listing) = listings.iter().find(|l| l.label == label) else {
            let _ = db.history_retry_clear(&id);
            continue;
        };
        match client.fetch_mail_item(&keys.access_token, &id).await {
            Ok(item) if item.id == id => {
                let folder = folder_for(listing, &item, &known_tokens);
                let outcome = cache_mail_item(
                    db,
                    &folder,
                    &item,
                    &keys.passphrase,
                    keys.identity_key.as_deref(),
                    &keys.previous_keys,
                    &keys.inbound_keys,
                );
                if outcome.decrypt_failed {
                    let _ = db.history_retry_note(&id, &label, retry_delay_secs, now as i64);
                } else {
                    let _ = db.history_retry_clear(&id);
                    if outcome.was_new {
                        created.push(id);
                    }
                }
            }
            Ok(_) => {
                let _ = db.history_retry_clear(&id);
            }
            Err(e) if is_gone(&e) => {
                let _ = db.history_retry_clear(&id);
            }
            Err(e) => {
                failure = Some(format!("history: retrying a message failed: {}", e));
                break;
            }
        }
    }
    let changed = record_changes(db, &created, &[], &[]);
    Some(match failure {
        Some(msg) => Step::Failed(msg),
        None => Step::Worked { changed },
    })
}

fn emit_progress(states: &[(Listing, ListingState)], finished_first_pass: bool) {
    let active = states.iter().any(|(_, s)| s.swept_at == 0);
    if !active && !finished_first_pass {
        return;
    }
    let (indexed, total) = states
        .iter()
        .fold((0, 0), |(indexed, total), (_, s)| (indexed + s.indexed(), total + s.known_total()));
    let progress = crate::events::HistoryProgress {
        indexed: indexed.min(total),
        total,
        active,
    };
    crate::events::emit(|sink| sink.history_progress(&progress));
}

async fn sweep_page(db: &Database, client: &ApiClient, keys: &Keys, now: u64) -> Step {
    let listings = match listings(db) {
        Ok(listings) => listings,
        Err(e) => return Step::Failed(format!("history: reading folders failed: {}", e)),
    };
    let labels: Vec<String> = listings.iter().map(|l| l.label.clone()).collect();
    if matches!(db.forget_listings_except(&labels), Ok(n) if n > 0) {
        return Step::Worked { changed: false };
    }
    let mut states: Vec<(Listing, ListingState)> = listings
        .into_iter()
        .map(|l| {
            let state = load(db, &l.label);
            (l, state)
        })
        .collect();
    let Some(index) = states
        .iter()
        .position(|(_, s)| s.sweeping)
        .or_else(|| states.iter().position(|(_, s)| s.needs_sweep(now)))
    else {
        return Step::Idle;
    };
    let listing = states[index].0.clone();
    let mut state = states[index].1.clone();
    let first_pass = state.swept_at == 0;
    if !state.sweeping {
        state = ListingState {
            round: state.round + 1,
            sweeping: true,
            swept_at: state.swept_at,
            total: state.known_total(),
            total_offset: state.total_offset,
            ..ListingState::default()
        };
        save(db, &listing.label, &state);
    }

    let page = match (&listing.query, &listing.token) {
        (Some(query), _) => {
            let mut q = query.clone();
            q.limit = Some(PAGE_SIZE);
            q.cursor = state.cursor.clone();
            client.list_mail(&keys.access_token, &q).await
        }
        (None, Some(token)) => {
            client
                .list_folder_mail(&keys.access_token, token, PAGE_SIZE, state.offset)
                .await
        }
        (None, None) => return Step::Idle,
    };
    let resp = match page {
        Ok(resp) => resp,
        Err(e) => {
            let stale_position = matches!(
                &e,
                BridgeError::Api(msg) if api_status_code(msg).is_some_and(|s| matches!(s, 400 | 404 | 410 | 422))
            );
            if stale_position && (state.cursor.is_some() || state.offset > 0) {
                state.cursor = None;
                state.offset = 0;
                state.walked = 0;
                save(db, &listing.label, &state);
            }
            return Step::Failed(format!("history: indexing {} failed: {}", listing.label, e));
        }
    };

    let (created, updated) = index_page(db, &listing, &resp.items, keys, state.round, now);
    let fetched = resp.items.len();
    state.walked += fetched;
    state.total = resp.total.max(0) as usize;
    let reached_end = match listing.token {
        None => !resp.has_more || resp.next_cursor.is_none(),
        Some(_) => !resp.has_more || fetched == 0,
    };
    let runaway = state.walked > state.total + 50 * PAGE_SIZE as usize;
    if reached_end || runaway {
        let queued = db.finish_listing_sweep(&listing.label, state.round).unwrap_or(0);
        let members = db.listing_member_count(&listing.label).unwrap_or(0);
        state.sweeping = false;
        state.swept_at = now.max(1);
        state.cursor = None;
        state.offset = 0;
        state.total_offset = state.total as i64 - members as i64;
        state.observed = None;
        tracing::info!(
            "history: indexed {} ({} listed, {} to re-check)",
            listing.label,
            state.walked,
            queued
        );
    } else {
        state.cursor = resp.next_cursor;
        state.offset += fetched as i64;
    }
    save(db, &listing.label, &state);
    states[index].1 = state.clone();
    emit_progress(&states, first_pass && !state.sweeping);
    Step::Worked {
        changed: record_changes(db, &created, &updated, &[]),
    }
}

fn index_page(
    db: &Database,
    listing: &Listing,
    items: &[MailItem],
    keys: &Keys,
    round: i64,
    now: u64,
) -> (Vec<String>, Vec<String>) {
    let mut created: Vec<String> = Vec::new();
    let mut updated: Vec<String> = Vec::new();
    let mut unique: HashSet<&str> = HashSet::new();
    let page: Vec<&MailItem> = items
        .iter()
        .filter(|i| is_valid_item_id(&i.id) && unique.insert(i.id.as_str()))
        .collect();
    let ids: Vec<&str> = page.iter().map(|i| i.id.as_str()).collect();
    if let Err(e) = db.stamp_listing_members(&listing.label, &ids, round) {
        tracing::warn!("history: recording listed messages failed: {}", e);
    }
    let known_tokens: HashSet<String> = db
        .list_custom_folders()
        .unwrap_or_default()
        .into_iter()
        .map(|f| f.label_token)
        .collect();
    let known_tags: HashSet<String> = db
        .list_custom_tags()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.tag_token)
        .collect();
    let snapshot = db.cached_sync_states(&ids).unwrap_or_default();
    let owned: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
    let tag_snapshot = db.message_tags(&owned).unwrap_or_default();
    let tag_writes_at_start = db.tag_writes.load(std::sync::atomic::Ordering::SeqCst);
    let mut flag_updates: Vec<(&MailItem, i64, i64)> = Vec::new();

    for item in page {
        if listing.token.is_some() && item.is_spam == Some(true) {
            continue;
        }
        let folder = folder_for(listing, item, &known_tokens);
        let state = snapshot.get(&item.id);
        if listing.token.is_some() && state.is_some_and(|s| s.folder != folder) {
            continue;
        }
        if let Some(moved_from) = state.map(|s| &s.folder).filter(|f| **f != folder) {
            let _ = db.forget_listing_member(moved_from, &item.id);
        }
        if db.tag_writes.load(std::sync::atomic::Ordering::SeqCst) == tag_writes_at_start {
            if let Some(wanted) = server_tags_differ(item, &known_tags, &tag_snapshot) {
                if db.set_message_tags(&item.id, &wanted).unwrap_or(false) && state.is_some() {
                    updated.push(item.id.clone());
                }
            }
        }
        match cached_shortcut(state, &folder, item) {
            Some(CachedShortcut::Unchanged) => continue,
            Some(CachedShortcut::FlagsOnly(flags)) => {
                flag_updates.push((item, state.map_or(0, |s| s.flags), flags));
                continue;
            }
            None => {}
        }
        let outcome = match prepare_mail_item(
            db,
            &folder,
            item,
            &keys.passphrase,
            keys.identity_key.as_deref(),
            &keys.previous_keys,
            &keys.inbound_keys,
        ) {
            Prepared::Done(outcome) => outcome,
            Prepared::Ready(prepared) => commit_mail_item(db, &folder, item, prepared, None),
        };
        if outcome.decrypt_failed {
            let _ = db.history_retry_note(&item.id, &listing.label, retry_delay_secs, now as i64);
        } else if outcome.was_new {
            created.push(item.id.clone());
        } else if outcome.flags_changed {
            updated.push(item.id.clone());
        }
    }

    let writes: Vec<(String, i64, i64)> = flag_updates
        .iter()
        .map(|(item, expected, flags)| (item.id.clone(), *expected, *flags))
        .collect();
    let stale: HashSet<String> = match db.set_message_flags_if_unchanged(&writes) {
        Ok(stale) => stale.into_iter().collect(),
        Err(_) => writes.into_iter().map(|(id, _, _)| id).collect(),
    };
    for (item, _, _) in &flag_updates {
        if !stale.contains(&item.id) || reconcile_server_flags(db, item) {
            updated.push(item.id.clone());
        }
    }
    (created, updated)
}

pub(super) struct Pacer {
    next: tokio::time::Instant,
    open: bool,
    failures: u32,
    pending: bool,
    last_broadcast: tokio::time::Instant,
}

impl Pacer {
    pub(super) fn new() -> Self {
        let now = tokio::time::Instant::now();
        Self {
            next: now,
            open: false,
            failures: 0,
            pending: false,
            last_broadcast: now,
        }
    }

    pub(super) fn next_at(&self) -> tokio::time::Instant {
        self.next
    }

    pub(super) fn is_open(&self) -> bool {
        self.open
    }

    pub(super) fn open(&mut self) {
        if !self.open {
            self.open = true;
            self.next = tokio::time::Instant::now() + start_delay(START_JITTER_MAX);
        }
    }

    pub(super) fn defer(&mut self) {
        self.next = tokio::time::Instant::now() + IDLE_RECHECK;
    }

    pub(super) fn finish(
        &mut self,
        outcome: Step,
        db: &Database,
        jmap_broadcaster: Option<&broadcast::Sender<StateChange>>,
    ) -> Option<tokio::time::Instant> {
        let now = tokio::time::Instant::now();
        let mut pause = None;
        let flush = match outcome {
            Step::Idle => {
                self.failures = 0;
                self.next = now + IDLE_RECHECK;
                true
            }
            Step::Worked { changed } => {
                self.failures = 0;
                self.pending |= changed;
                self.next = now + PAGE_INTERVAL;
                now.duration_since(self.last_broadcast) >= BROADCAST_EVERY
            }
            Step::Failed(msg) => {
                self.failures = self.failures.saturating_add(1);
                let limited = is_rate_limit_message(&msg);
                if limited {
                    tracing::warn!("history: the server is limiting requests, so indexing older mail pauses");
                    pause = Some(now + RATE_LIMIT_PAUSE);
                } else {
                    tracing::warn!("{}", msg);
                }
                let base = if limited { RATE_LIMIT_PAUSE } else { BACKOFF_BASE };
                self.next = now + backoff(base, self.failures);
                true
            }
        };
        if flush && self.pending {
            broadcast(db, jmap_broadcaster);
            self.pending = false;
            self.last_broadcast = now;
        }
        pause
    }
}

fn start_delay(max: Duration) -> Duration {
    use rand::Rng;
    let max_ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    if max_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::thread_rng().gen_range(0..max_ms))
}

fn backoff(base: Duration, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(6);
    base.saturating_mul(1u32 << shift).min(BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: u64 = 1_790_000_000;
    const DB_KEY: [u8; 32] = [9u8; 32];

    fn open_db(dir: &std::path::Path) -> Arc<Database> {
        Arc::new(Database::open_with_key(dir, &DB_KEY).unwrap())
    }

    fn session() -> Arc<RwLock<Session>> {
        Arc::new(RwLock::new(Session {
            data_kek: None,
            user_id: uuid::Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: Zeroizing::new("stub".to_string()),
            refresh_token: None,
            vault_passphrase: b"pass".to_vec(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
            default_sender_id: None,
            account_keys: Vec::new(),
            previous_keys: Default::default(),
            ratchet_recovery: Default::default(),
        }))
    }

    fn item_id(n: usize) -> String {
        format!("hist-{:05}", n)
    }

    fn archive_item(n: usize) -> serde_json::Value {
        let date = (chrono::DateTime::parse_from_rfc3339("2026-09-30T12:00:00Z").unwrap()
            - chrono::Duration::hours(n as i64))
        .to_rfc3339();
        let envelope = serde_json::json!({
            "subject": format!("Message {}", n),
            "body_text": format!("Body of message {}", n),
            "date": date,
        });
        serde_json::json!({
            "id": item_id(n),
            "item_type": "received",
            "encrypted_envelope": STANDARD.encode(envelope.to_string()),
            "envelope_nonce": "",
            "folder_token": "tok",
            "is_external": false,
            "created_at": date,
        })
    }

    #[derive(Clone, Default)]
    struct Backend {
        items: Arc<StdMutex<Vec<serde_json::Value>>>,
        inbox: Arc<StdMutex<Vec<serde_json::Value>>>,
        cursors: Arc<StdMutex<Vec<Option<String>>>>,
        list_calls: Arc<AtomicUsize>,
        item_calls: Arc<AtomicUsize>,
        fail_with: Arc<StdMutex<Option<u16>>>,
    }

    impl Backend {
        fn with_archive(count: usize) -> Self {
            let backend = Backend::default();
            *backend.items.lock().unwrap() = (0..count).map(archive_item).collect();
            backend
        }

        fn remove(&self, id: &str) {
            self.items.lock().unwrap().retain(|i| i["id"] != id);
        }

        fn requests(&self) -> usize {
            self.list_calls.load(Ordering::SeqCst) + self.item_calls.load(Ordering::SeqCst)
        }

        async fn serve(&self) -> String {
            use axum::extract::{Path, Query};
            use axum::http::StatusCode;
            use axum::response::IntoResponse;
            use axum::{routing::get, Json, Router};
            let list = self.clone();
            let single = self.clone();
            let app = Router::new()
                .route(
                    "/bridge/v1/messages",
                    get(move |Query(q): Query<HashMap<String, String>>| {
                        let backend = list.clone();
                        async move {
                            backend.list_calls.fetch_add(1, Ordering::SeqCst);
                            if let Some(status) = *backend.fail_with.lock().unwrap() {
                                return (StatusCode::from_u16(status).unwrap(), "refused").into_response();
                            }
                            let archive = q.get("is_archived").map(String::as_str) == Some("true");
                            if archive {
                                backend.cursors.lock().unwrap().push(q.get("cursor").cloned());
                            }
                            let all = if archive {
                                backend.items.lock().unwrap().clone()
                            } else if q.get("item_type").map(String::as_str) == Some("received") {
                                backend.inbox.lock().unwrap().clone()
                            } else {
                                Vec::new()
                            };
                            let start: usize = q.get("cursor").and_then(|c| c.parse().ok()).unwrap_or(0);
                            let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100);
                            let end = (start + limit).min(all.len());
                            let page: Vec<serde_json::Value> = all.get(start..end).unwrap_or(&[]).to_vec();
                            let has_more = end < all.len();
                            Json(serde_json::json!({
                                "items": page,
                                "total": all.len(),
                                "has_more": has_more,
                                "next_cursor": if has_more { serde_json::json!(end.to_string()) } else { serde_json::Value::Null },
                            }))
                            .into_response()
                        }
                    }),
                )
                .route(
                    "/bridge/v1/messages/:id",
                    get(move |Path(id): Path<String>| {
                        let backend = single.clone();
                        async move {
                            backend.item_calls.fetch_add(1, Ordering::SeqCst);
                            if let Some(status) = *backend.fail_with.lock().unwrap() {
                                return (StatusCode::from_u16(status).unwrap(), "refused").into_response();
                            }
                            let found = backend.items.lock().unwrap().iter().find(|i| i["id"] == id).cloned();
                            match found {
                                Some(item) => Json(item).into_response(),
                                None => StatusCode::NOT_FOUND.into_response(),
                            }
                        }
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            format!("http://127.0.0.1:{}", port)
        }
    }

    async fn index_until_idle(session: &Arc<RwLock<Session>>, client: &ApiClient, db: &Database, now: u64) -> usize {
        for steps in 0..400 {
            match step(session, client, db, now).await {
                Step::Idle => return steps,
                Step::Worked { .. } => {}
                Step::Failed(msg) => panic!("history step failed: {}", msg),
            }
        }
        panic!("history never went idle");
    }

    async fn indexed_archive(count: usize) -> (tempfile::TempDir, Arc<Database>, Backend, Arc<ApiClient>, Arc<RwLock<Session>>) {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(count);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        index_until_idle(&session, &client, &db, NOW).await;
        (dir, db, backend, client, session)
    }

    fn archive_state(db: &Database) -> ListingState {
        load(db, "archive")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_pages_past_the_recent_window_and_resumes_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::with_archive(2450);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        {
            let db = open_db(dir.path());
            apply_mode(&db, true);
            run_sync_pass(&session, &client, &db, None, true).await.unwrap();
            assert_eq!(db.count_cached_messages("archive").unwrap(), 2000);
            while archive_state(&db).walked < 2200 {
                assert!(matches!(step(&session, &client, &db, NOW).await, Step::Worked { .. }));
            }
            assert_eq!(db.count_cached_messages("archive").unwrap(), 2200);
            assert!(db.get_cached_message(&item_id(2199)).unwrap().is_some());
        }

        backend.cursors.lock().unwrap().clear();
        let db = open_db(dir.path());
        let state = archive_state(&db);
        assert!(state.sweeping);
        assert_eq!(state.cursor.as_deref(), Some("2200"));
        index_until_idle(&session, &client, &db, NOW).await;

        let resumed = backend.cursors.lock().unwrap().clone();
        assert_eq!(resumed.first().cloned().flatten().as_deref(), Some("2200"));
        assert!(!resumed.contains(&None), "a restart must not walk the folder again from the top");
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2450);
        assert_eq!(db.listing_member_count("archive").unwrap(), 2450);
        let state = archive_state(&db);
        assert!(!state.sweeping);
        assert_eq!(state.swept_at, NOW);
        assert_eq!(state.total_offset, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn imap_select_status_and_fetch_cover_every_indexed_message_without_a_server_request() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let (_dir, db, backend, client, session) = indexed_archive(2300).await;
        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (state_tx, _state_rx) = broadcast::channel(16);
        let served_db = db.clone();
        let served_client = client.clone();
        tokio::spawn(async move {
            let _ = crate::imap::server::serve(listener, session, served_db, served_client, passwords, state_tx, None).await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (r, mut writer) = stream.into_split();
        let mut reader = BufReader::new(r);
        async fn command(
            reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
            writer: &mut tokio::net::tcp::OwnedWriteHalf,
            tag: &str,
            line: &str,
        ) -> String {
            writer.write_all(format!("{} {}\r\n", tag, line).as_bytes()).await.unwrap();
            let mut out = String::new();
            loop {
                let mut next = String::new();
                if reader.read_line(&mut next).await.unwrap() == 0 {
                    break;
                }
                if let Some(open) = next.trim_end().strip_suffix('}').and_then(|l| l.rfind('{').map(|i| l[i + 1..].to_string())) {
                    let mut literal = vec![0u8; open.parse().unwrap()];
                    reader.read_exact(&mut literal).await.unwrap();
                    next.push_str(&String::from_utf8_lossy(&literal));
                }
                out.push_str(&next);
                if next.starts_with(&format!("{} ", tag)) {
                    break;
                }
            }
            out
        }
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        let login = command(&mut reader, &mut writer, "a1", "LOGIN \"tester@aster.test\" \"abcd-efgh-ijkl-mnop\"").await;
        assert!(login.contains("a1 OK"), "{}", login);
        let status = command(&mut reader, &mut writer, "a2", "STATUS Archive (MESSAGES)").await;
        assert!(status.contains("MESSAGES 2300"), "{}", status);
        let select = command(&mut reader, &mut writer, "a3", "SELECT Archive").await;
        assert!(select.contains("* 2300 EXISTS"), "{}", select);

        let before = backend.requests();
        let oldest_uid = db
            .list_cached_message_meta("archive")
            .unwrap()
            .into_iter()
            .find(|m| m.aster_id == item_id(2299))
            .unwrap()
            .imap_uid;
        let fetched = command(&mut reader, &mut writer, "a4", &format!("UID FETCH {} (BODY.PEEK[])", oldest_uid)).await;
        assert!(fetched.contains("Body of message 2299"), "{}", fetched);
        assert!(fetched.contains("a4 OK"), "{}", fetched);
        assert_eq!(backend.requests(), before, "the body arrived with the index, so opening it costs no request");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_side_deletion_of_an_old_message_is_pruned_without_rescanning_every_pass() {
        let (_dir, db, backend, client, session) = indexed_archive(2300).await;
        let listed = backend.list_calls.load(Ordering::SeqCst);
        assert_eq!(step(&session, &client, &db, NOW + 60).await, Step::Idle);
        assert_eq!(backend.list_calls.load(Ordering::SeqCst), listed, "an unchanged folder is not listed again");

        backend.remove(&item_id(2250));
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        assert_eq!(archive_state(&db).observed, Some((2299, 2300)));
        assert_eq!(
            step(&session, &client, &db, NOW + 60).await,
            Step::Idle,
            "a fresh sweep waits out the drift grace period"
        );

        let later = NOW + DRIFT_RESWEEP_AFTER_SECS + 1;
        index_until_idle(&session, &client, &db, later).await;
        assert!(db.get_cached_message(&item_id(2250)).unwrap().is_none());
        assert!(db.get_cached_message(&item_id(2251)).unwrap().is_some());
        assert_eq!(db.listing_member_count("archive").unwrap(), 2299);
        let destroyed: i64 = db
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM jmap_change_log WHERE op = 'destroyed' AND object_id = ?1",
                    [item_id(2250)],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(destroyed, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn moving_recent_mail_between_folders_does_not_trigger_a_full_sweep() {
        let (_dir, db, backend, client, session) = indexed_archive(10).await;
        let mut moving = archive_item(0);
        moving["id"] = serde_json::json!("moving");
        backend.inbox.lock().unwrap().push(moving.clone());
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        assert_eq!(db.listing_member_count("inbox").unwrap(), 1);

        backend.inbox.lock().unwrap().clear();
        backend.items.lock().unwrap().insert(0, moving);
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();

        assert_eq!(db.get_cached_message("moving").unwrap().unwrap().folder, "archive");
        assert_eq!(db.listing_member_count("inbox").unwrap(), 0);
        assert_eq!(load(&db, "inbox").observed, Some((0, 0)));
        assert_eq!(archive_state(&db).observed, Some((11, 11)));
        let listed = backend.list_calls.load(Ordering::SeqCst);
        assert_eq!(step(&session, &client, &db, NOW + DRIFT_RESWEEP_AFTER_SECS + 1).await, Step::Idle);
        assert_eq!(backend.list_calls.load(Ordering::SeqCst), listed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_message_that_moved_away_is_kept_when_the_server_still_has_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        let alive = archive_item(7);
        let queued = item_id(7);
        let backend = Backend::default();
        backend.items.lock().unwrap().push(alive);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let item: MailItem = serde_json::from_value(archive_item(7)).unwrap();
        assert!(cache_mail_item(&db, "archive", &item, b"pass", None, &[], &[]).was_new);
        let gone: MailItem = serde_json::from_value(archive_item(8)).unwrap();
        assert!(cache_mail_item(&db, "archive", &gone, b"pass", None, &[], &[]).was_new);
        db.stamp_listing_members("archive", &[queued.as_str(), gone.id.as_str()], 1).unwrap();
        assert_eq!(db.finish_listing_sweep("archive", 2).unwrap(), 2);

        let keys = Keys::of(&session()).await;
        assert_eq!(prune_departed(&db, &client, &keys).await, Some(Step::Worked { changed: true }));
        assert!(db.get_cached_message(&queued).unwrap().is_some());
        assert!(db.get_cached_message(&gone.id).unwrap().is_none());
        assert!(db.prune_queue_batch(10).unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_sweeps_run_before_queued_messages_are_checked_one_by_one() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(30);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        let gone: MailItem = serde_json::from_value(archive_item(99)).unwrap();
        for item in [serde_json::from_value::<MailItem>(archive_item(7)).unwrap(), gone.clone()] {
            assert!(cache_mail_item(&db, "custom-gone", &item, b"pass", None, &[], &[]).was_new);
        }
        db.stamp_listing_members("custom-gone", &[item_id(7).as_str(), gone.id.as_str()], 1)
            .unwrap();
        assert_eq!(db.forget_listings_except(&[]).unwrap(), 2);

        index_until_idle(&session, &client, &db, NOW).await;

        assert_eq!(
            backend.item_calls.load(Ordering::SeqCst),
            1,
            "a message listed by the sweep needs no single-message check"
        );
        assert!(db.get_cached_message(&item_id(7)).unwrap().is_some());
        assert!(db.get_cached_message(&gone.id).unwrap().is_none());
        assert!(db.prune_queue_batch(10).unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cache_repair_while_running_keeps_the_regular_pass_recording_listings() {
        let (_dir, db, _backend, client, session) = indexed_archive(10).await;
        db.repair_cache().unwrap();
        assert!(!is_enabled(&db));
        step(&session, &client, &db, NOW).await;
        assert!(is_enabled(&db));
    }

    #[test]
    fn the_first_history_step_starts_at_a_random_point_within_the_window() {
        assert_eq!(start_delay(Duration::ZERO), Duration::ZERO);
        let window = Duration::from_secs(600);
        let delays: Vec<Duration> = (0..64).map(|_| start_delay(window)).collect();
        assert!(delays.iter().all(|d| *d < window));
        assert!(delays.iter().any(|d| *d != delays[0]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_undecryptable_message_is_skipped_and_retried_with_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(2200);
        let broken = item_id(2100);
        backend.items.lock().unwrap()[2100]["encrypted_envelope"] = serde_json::json!("!!!not-base64!!!");
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        index_until_idle(&session, &client, &db, NOW).await;

        assert!(db.get_cached_message(&broken).unwrap().is_none());
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2199);
        assert!(db.get_cached_message(&item_id(2199)).unwrap().is_some(), "the cursor moved past it");
        assert!(!archive_state(&db).sweeping);

        let calls = backend.item_calls.load(Ordering::SeqCst);
        assert_eq!(step(&session, &client, &db, NOW + 60).await, Step::Idle);
        assert_eq!(backend.item_calls.load(Ordering::SeqCst), calls, "not retried before its backoff");

        assert_eq!(
            step(&session, &client, &db, NOW + RETRY_BASE_SECS as u64).await,
            Step::Worked { changed: false }
        );
        assert_eq!(backend.item_calls.load(Ordering::SeqCst), calls + 1);
        let due = db.history_retry_due(NOW as i64 + RETRY_BASE_SECS + 60, RETRY_MAX_ATTEMPTS, 10).unwrap();
        assert!(due.is_empty(), "a second failure waits twice as long");

        backend.items.lock().unwrap()[2100] = archive_item(2100);
        let fixed_at = NOW + (RETRY_BASE_SECS * 3) as u64;
        assert_eq!(step(&session, &client, &db, fixed_at).await, Step::Worked { changed: true });
        assert!(db.get_cached_message(&broken).unwrap().is_some());
        assert!(db.history_retry_due(i64::MAX, RETRY_MAX_ATTEMPTS, 10).unwrap().is_empty());
    }

    #[test]
    fn retry_delays_double_up_to_a_day() {
        assert_eq!(retry_delay_secs(1), RETRY_BASE_SECS);
        assert_eq!(retry_delay_secs(2), RETRY_BASE_SECS * 2);
        assert_eq!(retry_delay_secs(3), RETRY_BASE_SECS * 4);
        assert_eq!(retry_delay_secs(40), RETRY_MAX_SECS);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rate_limited_page_keeps_its_place_and_pauses_sync() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(2300);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        while archive_state(&db).walked < 2100 {
            step(&session, &client, &db, NOW).await;
        }

        *backend.fail_with.lock().unwrap() = Some(429);
        let outcome = step(&session, &client, &db, NOW).await;
        let Step::Failed(ref msg) = outcome else {
            panic!("expected a failure, got {:?}", outcome);
        };
        assert!(is_rate_limit_message(msg), "{}", msg);
        assert_eq!(archive_state(&db).cursor.as_deref(), Some("2100"));

        let mut pacer = Pacer::new();
        pacer.open();
        let before = tokio::time::Instant::now();
        let pause = pacer.finish(outcome.clone(), &db, None).expect("a refusal pauses the whole sync");
        assert!(pause >= before + RATE_LIMIT_PAUSE);
        assert!(pacer.next_at() >= before + RATE_LIMIT_PAUSE);
        pacer.finish(outcome, &db, None);
        assert!(pacer.next_at() >= before + RATE_LIMIT_PAUSE * 2, "a second refusal backs off further");

        *backend.fail_with.lock().unwrap() = Some(502);
        assert!(matches!(step(&session, &client, &db, NOW).await, Step::Failed(_)));
        assert_eq!(archive_state(&db).cursor.as_deref(), Some("2100"), "a server error keeps the cursor");

        *backend.fail_with.lock().unwrap() = None;
        let worked = step(&session, &client, &db, NOW).await;
        assert!(pacer.finish(worked, &db, None).is_none());
        let now = tokio::time::Instant::now();
        assert!(pacer.next_at() <= now + PAGE_INTERVAL, "success resets the backoff");
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2200);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejected_cursor_restarts_the_sweep_from_the_top() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(300);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        while archive_state(&db).walked < 100 {
            step(&session, &client, &db, NOW).await;
        }
        *backend.fail_with.lock().unwrap() = Some(400);
        assert!(matches!(step(&session, &client, &db, NOW).await, Step::Failed(_)));
        let state = archive_state(&db);
        assert!(state.sweeping);
        assert_eq!((state.cursor, state.walked), (None, 0));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(BACKOFF_BASE, 1), BACKOFF_BASE);
        assert_eq!(backoff(BACKOFF_BASE, 2), BACKOFF_BASE * 2);
        assert_eq!(backoff(BACKOFF_BASE, 3), BACKOFF_BASE * 4);
        assert_eq!(backoff(BACKOFF_BASE, 50), BACKOFF_MAX);
    }

    #[test]
    fn a_listing_is_swept_again_only_when_counts_drift_or_a_week_passes() {
        let swept = ListingState {
            swept_at: NOW,
            total_offset: 2,
            ..ListingState::default()
        };
        assert!(ListingState::default().needs_sweep(NOW));
        assert!(!swept.needs_sweep(NOW + 60));
        assert!(swept.needs_sweep(NOW + RESWEEP_AFTER_SECS));
        let steady = ListingState {
            observed: Some((502, 500)),
            ..swept.clone()
        };
        assert!(!steady.needs_sweep(NOW + DRIFT_RESWEEP_AFTER_SECS + 1));
        let drifted = ListingState {
            observed: Some((501, 500)),
            ..swept
        };
        assert!(!drifted.needs_sweep(NOW + 60));
        assert!(drifted.needs_sweep(NOW + DRIFT_RESWEEP_AFTER_SECS));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recent_only_mode_keeps_todays_behaviour() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        let backend = Backend::with_archive(2450);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let (_tx, rx) = sync_trigger_channel();
        let tuning = PollTuning::from_interval_secs(Some(3600));
        assert!(!tuning.full_history);
        let handle = tokio::spawn(run_poll_loop_tuned(session(), client, db.clone(), None, rx, tuning));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while db.get_sync_state("last_sync_ts").unwrap().is_none() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        handle.abort();

        assert_eq!(db.count_cached_messages("archive").unwrap(), 2000);
        let deepest = backend
            .cursors
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .filter_map(|c| c.parse::<usize>().ok())
            .max()
            .unwrap_or(0);
        assert!(deepest < 2000, "listed past the newest 2,000 at offset {}", deepest);
        assert_eq!(db.listing_member_count("archive").unwrap(), 0);
        assert_eq!(db.get_sync_state(HISTORY_MODE_KEY).unwrap().as_deref(), Some("recent"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_poll_loop_indexes_older_mail_after_the_regular_pass() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        let backend = Backend::with_archive(2250);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let (_tx, rx) = sync_trigger_channel();
        let tuning = PollTuning {
            full_history: true,
            ..PollTuning::from_interval_secs(Some(3600))
        };
        let (state_tx, mut state_rx) = broadcast::channel(64);
        let handle = tokio::spawn(run_poll_loop_tuned(session(), client, db.clone(), Some(state_tx), rx, tuning));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while db.count_cached_messages("archive").unwrap() < 2250 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let complete_by = tokio::time::Instant::now() + Duration::from_secs(5);
        while archive_state(&db).swept_at == 0 && tokio::time::Instant::now() < complete_by {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        handle.abort();
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2250);
        assert!(archive_state(&db).swept_at > 0);
        let mut heard = false;
        while let Ok(change) = state_rx.try_recv() {
            heard |= change.changed.contains_key("Email");
        }
        assert!(heard, "clients hear about indexed mail");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn switching_to_recent_only_frees_the_older_mail() {
        let (_dir, db, _backend, _client, _session) = indexed_archive(2300).await;
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2300);

        let trimmed = apply_mode(&db, false);

        assert_eq!(trimmed.len(), 300);
        assert!(trimmed.contains(&item_id(2299)));
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2000);
        assert!(db.get_cached_message(&item_id(0)).unwrap().is_some());
        assert_eq!(db.listing_member_count("archive").unwrap(), 0);
        assert_eq!(archive_state(&db), ListingState::default());
        assert!(apply_mode(&db, false).is_empty(), "staying on recent-only trims nothing");
    }

    #[test]
    fn the_attachment_backlog_takes_recent_mail_before_history() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        for (id, date) in [("recent", "2026-09-30T10:00:00+00:00"), ("history", "2019-01-01T10:00:00+00:00")] {
            db.upsert_cached_message(id, "archive", Some(id), None, None, Some(date), 1, Some("b"), None)
                .unwrap();
            db.set_attachments_state(id, ATTACHMENTS_PENDING).unwrap();
        }
        db.with_conn(|conn| {
            conn.execute("UPDATE message_cache SET created_at = '2026-10-01 00:00:00' WHERE aster_id = 'history'", [])?;
            conn.execute("UPDATE message_cache SET created_at = '2026-09-01 00:00:00' WHERE aster_id = 'recent'", [])
        })
        .unwrap();
        let backlog: Vec<String> = db.list_attachment_backlog(10).unwrap().into_iter().map(|(id, _)| id).collect();
        assert_eq!(backlog, vec!["recent".to_string(), "history".to_string()]);
    }
}
