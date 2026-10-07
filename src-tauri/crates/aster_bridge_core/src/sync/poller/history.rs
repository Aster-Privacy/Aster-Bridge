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
use crate::api_client::MailListResponse;

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
const RESWEEP_AFTER_SECS: u64 = 30 * 24 * 60 * 60;
const DRIFT_RESWEEP_AFTER_SECS: u64 = 15 * 60;
const DRIFT_RESWEEP_MAX_SECS: u64 = 24 * 60 * 60;
const PRUNE_CHECKS_PER_STEP: usize = 25;
const RETRIES_PER_STEP: usize = 10;
const RETRY_BASE_SECS: i64 = 15 * 60;
const RETRY_MAX_SECS: i64 = 24 * 60 * 60;
const RETRY_MAX_ATTEMPTS: i64 = 8;
#[cfg(not(test))]
const RECLAIM_MIN_BYTES: i64 = 4 * 1024 * 1024;
#[cfg(test)]
const RECLAIM_MIN_BYTES: i64 = 1;
const RECLAIM_PAGES_PER_STEP: i64 = 1024;

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
    #[serde(default)]
    drift_streak: u32,
    #[serde(default)]
    incomplete: bool,
    #[serde(default)]
    eager: bool,
}

impl ListingState {
    fn drift_wait(&self) -> u64 {
        let shift = self.drift_streak.min(16);
        DRIFT_RESWEEP_AFTER_SECS
            .saturating_mul(1u64 << shift)
            .min(DRIFT_RESWEEP_MAX_SECS)
    }

    fn drifted(&self) -> bool {
        self.incomplete
            || self
                .observed
                .is_some_and(|(total, members)| total as i64 - members as i64 != self.total_offset)
    }

    fn needs_sweep(&self, now: u64) -> bool {
        let age = now.saturating_sub(self.swept_at);
        if self.swept_at == 0 || age >= RESWEEP_AFTER_SECS {
            return true;
        }
        self.drifted() && age >= self.drift_wait()
    }

    fn known_total(&self) -> usize {
        if self.sweeping || self.swept_at > 0 {
            self.total
        } else {
            self.observed.map_or(0, |(total, _)| total)
        }
    }

    fn indexed(&self) -> usize {
        if self.swept_at > 0 && !self.incomplete {
            self.known_total()
        } else if self.sweeping || self.incomplete {
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

pub(super) struct Keys {
    pub(super) access_token: Zeroizing<String>,
    pub(super) passphrase: Zeroizing<Vec<u8>>,
    pub(super) identity_key: Option<String>,
    pub(super) previous_keys: Zeroizing<Vec<String>>,
    pub(super) inbound_keys: Vec<crate::crypto::inbound::InboundKeyCandidate>,
}

impl Keys {
    pub(super) async fn of(session: &Arc<RwLock<Session>>) -> Self {
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
        match db.reclaim_free_space(RECLAIM_MIN_BYTES, RECLAIM_PAGES_PER_STEP) {
            Ok(0) => {}
            Ok(bytes) => tracing::info!("history: returned {} KB of freed space to the disk", bytes / 1024),
            Err(e) => tracing::warn!("history: returning freed space to the disk failed: {}", e),
        }
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
    if !state.drifted() {
        state.drift_streak = 0;
    }
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
                let outcome = cache_history_item(
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
        let drift_round = state.swept_at > 0 && now.saturating_sub(state.swept_at) < RESWEEP_AFTER_SECS;
        state = ListingState {
            round: state.round + 1,
            sweeping: true,
            swept_at: state.swept_at,
            total: state.known_total(),
            total_offset: state.total_offset,
            drift_streak: state.drift_streak.saturating_add(u32::from(drift_round)),
            incomplete: state.incomplete,
            ..ListingState::default()
        };
        save(db, &listing.label, &state);
    }

    let light = !state.eager;
    let mut resp = match list_page(client, keys, &listing, &state, !light).await {
        Some(Ok(resp)) => resp,
        Some(Err(e)) => return page_failed(db, &listing, &mut state, e),
        None => return Step::Idle,
    };
    let mut outcome = index_page(db, &listing, &resp.items, keys, state.round, now, light);
    if light && outcome.missing > 0 {
        resp = match list_page(client, keys, &listing, &state, true).await {
            Some(Ok(resp)) => resp,
            Some(Err(e)) => {
                record_changes(db, &outcome.created, &outcome.updated, &[]);
                return page_failed(db, &listing, &mut state, e);
            }
            None => return Step::Idle,
        };
        let full = index_page(db, &listing, &resp.items, keys, state.round, now, false);
        outcome.created.extend(full.created);
        outcome.updated.extend(full.updated);
        state.eager = true;
    } else if !light && outcome.prepared == 0 {
        state.eager = false;
    }

    let fetched = resp.items.len();
    state.walked += fetched;
    state.total = resp.total.max(0) as usize;
    let stalled = resp.has_more
        && match listing.token {
            None => fetched == 0 || (resp.next_cursor.is_some() && resp.next_cursor == state.cursor),
            Some(_) => fetched == 0,
        };
    let reached_end = match listing.token {
        None => !resp.has_more || resp.next_cursor.is_none(),
        Some(_) => !resp.has_more,
    };
    let runaway = state.walked > state.total + 50 * PAGE_SIZE as usize;
    if stalled {
        state.sweeping = false;
        state.swept_at = now.max(1);
        state.cursor = None;
        state.offset = 0;
        state.observed = None;
        state.incomplete = true;
        tracing::warn!(
            "history: the server stopped advancing while indexing {} after {} messages, so indexing tries again later",
            listing.label,
            state.walked
        );
    } else if reached_end || runaway {
        let queued = db.finish_listing_sweep(&listing.label, state.round).unwrap_or(0);
        let members = db.listing_member_count(&listing.label).unwrap_or(0);
        state.sweeping = false;
        state.swept_at = now.max(1);
        state.cursor = None;
        state.offset = 0;
        state.total_offset = state.total as i64 - members as i64;
        state.observed = None;
        state.incomplete = false;
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
        changed: record_changes(db, &outcome.created, &outcome.updated, &[]),
    }
}

async fn list_page(
    client: &ApiClient,
    keys: &Keys,
    listing: &Listing,
    state: &ListingState,
    include_envelope: bool,
) -> Option<Result<MailListResponse, BridgeError>> {
    match (&listing.query, &listing.token) {
        (Some(query), _) => {
            let mut q = query.clone();
            q.limit = Some(PAGE_SIZE);
            q.cursor = state.cursor.clone();
            Some(client.list_mail_with(&keys.access_token, &q, include_envelope).await)
        }
        (None, Some(token)) => Some(
            client
                .list_folder_mail_with(&keys.access_token, token, PAGE_SIZE, state.offset, include_envelope)
                .await,
        ),
        (None, None) => None,
    }
}

fn page_failed(db: &Database, listing: &Listing, state: &mut ListingState, e: BridgeError) -> Step {
    let stale_position = matches!(
        &e,
        BridgeError::Api(msg) if api_status_code(msg).is_some_and(|s| matches!(s, 400 | 404 | 410 | 422))
    );
    if stale_position && (state.cursor.is_some() || state.offset > 0) {
        state.cursor = None;
        state.offset = 0;
        state.walked = 0;
    }
    save(db, &listing.label, state);
    Step::Failed(format!("history: indexing {} failed: {}", listing.label, e))
}

#[derive(Default)]
struct PageOutcome {
    created: Vec<String>,
    updated: Vec<String>,
    prepared: usize,
    missing: usize,
}

fn index_page(
    db: &Database,
    listing: &Listing,
    items: &[MailItem],
    keys: &Keys,
    round: i64,
    now: u64,
    light: bool,
) -> PageOutcome {
    let mut created: Vec<String> = Vec::new();
    let mut updated: Vec<String> = Vec::new();
    let mut prepared = 0usize;
    let mut missing = 0usize;
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
        if light && item.encrypted_envelope.is_empty() {
            missing += 1;
            continue;
        }
        prepared += 1;
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
            Prepared::Ready(prepared) => commit_history_item(db, &folder, item, prepared),
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
    PageOutcome {
        created,
        updated,
        prepared,
        missing,
    }
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
    const IK: Option<&str> = Some(crate::crypto::envelope::FIXTURE_IDENTITY_KEY);
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
            identity_key: IK.map(str::to_string),
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
        archive_item_with(n, None)
    }

    const ATTACHMENT_KEY: [u8; 32] = [42u8; 32];

    struct Attached<'a> {
        data: &'a [u8],
        sized: bool,
    }

    fn archive_item_with(n: usize, attached: Option<Attached<'_>>) -> serde_json::Value {
        let date = (chrono::DateTime::parse_from_rfc3339("2026-09-30T12:00:00Z").unwrap()
            - chrono::Duration::hours(n as i64))
        .to_rfc3339();
        let mut envelope = serde_json::json!({
            "subject": format!("Message {}", n),
            "body_text": format!("Body of message {}", n),
            "date": date,
        });
        let mut item = serde_json::json!({
            "id": item_id(n),
            "item_type": "received",
            "folder_token": "tok",
            "is_external": false,
            "created_at": date,
        });
        if let Some(attached) = attached {
            let mut key = serde_json::json!({
                "seq": 0,
                "key": STANDARD.encode(ATTACHMENT_KEY),
                "filename": format!("report-{}.pdf", n),
                "content_type": "application/pdf",
            });
            if attached.sized {
                key["size"] = serde_json::json!(attached.data.len());
            }
            envelope["attachment_keys"] = serde_json::json!([key]);
            item["has_attachments"] = serde_json::json!(true);
            item["attachment_count"] = serde_json::json!(1);
        }
        let (encrypted_envelope, envelope_nonce) = crate::crypto::envelope::sealed_fixture(&envelope.to_string());
        item["encrypted_envelope"] = serde_json::json!(encrypted_envelope);
        item["envelope_nonce"] = serde_json::json!(envelope_nonce);
        item
    }

    fn sealed_row(data: &[u8]) -> serde_json::Value {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&ATTACHMENT_KEY).unwrap();
        let data_nonce = [7u8; 12];
        let aad = crate::crypto::attachment::attachment_data_aad(0);
        let ct = cipher
            .encrypt(Nonce::from_slice(&data_nonce), Payload { msg: data, aad: &aad })
            .unwrap();
        let meta_nonce = [9u8; 12];
        let meta = serde_json::json!({"filename": "server-name.pdf", "content_type": "application/pdf"}).to_string();
        let sealed_meta = cipher.encrypt(Nonce::from_slice(&meta_nonce), meta.as_bytes()).unwrap();
        serde_json::json!({
            "id": "att-0",
            "mail_item_id": "mail",
            "encrypted_data": STANDARD.encode(ct),
            "data_nonce": STANDARD.encode(data_nonce),
            "encrypted_meta": STANDARD.encode(sealed_meta),
            "meta_nonce": STANDARD.encode(meta_nonce),
            "size_bytes": data.len(),
            "seq_num": 0,
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
        attachments: Arc<StdMutex<HashMap<String, Arc<serde_json::Value>>>>,
        attachment_calls: Arc<AtomicUsize>,
        fail_attachments_with: Arc<StdMutex<Option<u16>>>,
        envelopes_listed: Arc<AtomicUsize>,
        stall_at: Arc<StdMutex<Option<usize>>>,
    }

    impl Backend {
        fn with_archive(count: usize) -> Self {
            let backend = Backend::default();
            *backend.items.lock().unwrap() = (0..count).map(archive_item).collect();
            backend
        }

        fn attach(&self, n: usize, data: &[u8], sized: bool) {
            let item = archive_item_with(n, Some(Attached { data, sized }));
            let row = sealed_row(data);
            self.attach_item(item, row);
        }

        fn attach_item(&self, item: serde_json::Value, row: serde_json::Value) {
            let id = item["id"].as_str().unwrap().to_string();
            let mut items = self.items.lock().unwrap();
            let slot = items.iter_mut().find(|i| i["id"] == id.as_str()).unwrap();
            *slot = item;
            self.attachments.lock().unwrap().insert(id, Arc::new(row));
        }

        fn attachment_requests(&self) -> usize {
            self.attachment_calls.load(Ordering::SeqCst)
        }

        fn remove(&self, id: &str) {
            self.items.lock().unwrap().retain(|i| i["id"] != id);
        }

        fn requests(&self) -> usize {
            self.list_calls.load(Ordering::SeqCst)
                + self.item_calls.load(Ordering::SeqCst)
                + self.attachment_calls.load(Ordering::SeqCst)
        }

        async fn serve(&self) -> String {
            use axum::extract::{Path, Query};
            use axum::http::StatusCode;
            use axum::response::IntoResponse;
            use axum::{routing::get, Json, Router};
            let list = self.clone();
            let single = self.clone();
            let files = self.clone();
            let app = Router::new()
                .route(
                    "/mail/v1/drafts",
                    get(|| async { Json(serde_json::json!({"items": [], "has_more": false, "next_cursor": serde_json::Value::Null})) }),
                )
                .route(
                    "/mail/v1/labels",
                    get(|| async { Json(serde_json::json!({"labels": [], "has_more": false})) }),
                )
                .route(
                    "/mail/v1/attachments/by-mail/:id",
                    get(move |Path(id): Path<String>| {
                        let backend = files.clone();
                        async move {
                            backend.attachment_calls.fetch_add(1, Ordering::SeqCst);
                            if let Some(status) = *backend.fail_attachments_with.lock().unwrap() {
                                return (StatusCode::from_u16(status).unwrap(), "refused").into_response();
                            }
                            let row = backend.attachments.lock().unwrap().get(&id).cloned();
                            let rows: Vec<serde_json::Value> = row.into_iter().map(|r| (*r).clone()).collect();
                            let total = rows.len();
                            Json(serde_json::json!({"attachments": rows, "total": total})).into_response()
                        }
                    }),
                )
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
                            if archive && *backend.stall_at.lock().unwrap() == Some(start) {
                                return Json(serde_json::json!({
                                    "items": [],
                                    "total": all.len(),
                                    "has_more": true,
                                    "next_cursor": start.to_string(),
                                }))
                                .into_response();
                            }
                            let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100);
                            let end = (start + limit).min(all.len());
                            let mut page: Vec<serde_json::Value> = all.get(start..end).unwrap_or(&[]).to_vec();
                            if q.get("include_envelope").map(String::as_str) == Some("false") {
                                for item in &mut page {
                                    item["encrypted_envelope"] = serde_json::json!("");
                                    item["envelope_nonce"] = serde_json::json!("");
                                }
                            } else {
                                backend.envelopes_listed.fetch_add(page.len(), Ordering::SeqCst);
                            }
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
        assert!(cache_mail_item(&db, "archive", &item, b"pass", IK, &[], &[]).was_new);
        let gone: MailItem = serde_json::from_value(archive_item(8)).unwrap();
        assert!(cache_mail_item(&db, "archive", &gone, b"pass", IK, &[], &[]).was_new);
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
            assert!(cache_mail_item(&db, "custom-gone", &item, b"pass", IK, &[], &[]).was_new);
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
    fn a_listing_is_swept_again_only_when_counts_drift_or_a_month_passes() {
        let swept = ListingState {
            swept_at: NOW,
            total_offset: 2,
            ..ListingState::default()
        };
        assert!(ListingState::default().needs_sweep(NOW));
        assert!(!swept.needs_sweep(NOW + 60));
        assert!(swept.needs_sweep(NOW + RESWEEP_AFTER_SECS));
        assert!(!swept.needs_sweep(NOW + 7 * 24 * 60 * 60), "a week is no longer enough");
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

    #[test]
    fn repeated_drift_waits_twice_as_long_each_time_up_to_a_day() {
        let drifted = |streak: u32| ListingState {
            swept_at: NOW,
            observed: Some((501, 500)),
            drift_streak: streak,
            ..ListingState::default()
        };
        assert_eq!(drifted(0).drift_wait(), DRIFT_RESWEEP_AFTER_SECS);
        assert_eq!(drifted(1).drift_wait(), DRIFT_RESWEEP_AFTER_SECS * 2);
        assert_eq!(drifted(3).drift_wait(), DRIFT_RESWEEP_AFTER_SECS * 8);
        assert_eq!(drifted(40).drift_wait(), DRIFT_RESWEEP_MAX_SECS);
        assert!(!drifted(2).needs_sweep(NOW + DRIFT_RESWEEP_AFTER_SECS * 4 - 1));
        assert!(drifted(2).needs_sweep(NOW + DRIFT_RESWEEP_AFTER_SECS * 4));
        assert!(!drifted(40).needs_sweep(NOW + DRIFT_RESWEEP_MAX_SECS - 1));
        let incomplete = ListingState {
            swept_at: NOW,
            incomplete: true,
            ..ListingState::default()
        };
        assert!(incomplete.needs_sweep(NOW + DRIFT_RESWEEP_AFTER_SECS));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_count_that_never_settles_backs_off_and_survives_a_restart() {
        let (dir, db, backend, client, session) = indexed_archive(150).await;
        let mut now = NOW;
        let mut waits = Vec::new();
        for _ in 0..4 {
            let state = archive_state(&db);
            let members = db.listing_member_count("archive").unwrap();
            let mut drifted = state.clone();
            drifted.observed = Some(((members as i64 + state.total_offset + 1) as usize, members));
            save(&db, "archive", &drifted);
            let wait = drifted.drift_wait();
            waits.push(wait);
            let listed = backend.list_calls.load(Ordering::SeqCst);
            assert_eq!(step(&session, &client, &db, now + wait - 1).await, Step::Idle);
            assert_eq!(backend.list_calls.load(Ordering::SeqCst), listed, "not walked before the wait");
            now += wait;
            index_until_idle(&session, &client, &db, now).await;
        }
        assert_eq!(
            waits,
            vec![
                DRIFT_RESWEEP_AFTER_SECS,
                DRIFT_RESWEEP_AFTER_SECS * 2,
                DRIFT_RESWEEP_AFTER_SECS * 4,
                DRIFT_RESWEEP_AFTER_SECS * 8
            ]
        );
        drop(db);
        let db = open_db(dir.path());
        assert_eq!(archive_state(&db).drift_streak, 4, "the backoff is kept across a restart");

        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        let state = archive_state(&db);
        assert!(!state.drifted());
        assert_eq!(state.drift_streak, 0, "matching counts reset the backoff");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_walk_over_stored_mail_lists_without_envelopes() {
        let (_dir, db, backend, client, session) = indexed_archive(2500).await;
        let full_first_pass = backend.envelopes_listed.load(Ordering::SeqCst);
        assert!(full_first_pass >= 500, "new mail still arrives with its envelope");

        backend.envelopes_listed.store(0, Ordering::SeqCst);
        backend.cursors.lock().unwrap().clear();
        let later = NOW + RESWEEP_AFTER_SECS;
        index_until_idle(&session, &client, &db, later).await;
        assert_eq!(archive_state(&db).swept_at, later);
        assert_eq!(
            backend.envelopes_listed.load(Ordering::SeqCst),
            0,
            "a periodic walk over stored mail downloads no message bodies"
        );
        assert_eq!(backend.cursors.lock().unwrap().len(), 25, "one request per page");

        let mut fresh = archive_item(0);
        fresh["id"] = serde_json::json!("fresh-old-mail");
        backend.items.lock().unwrap().insert(2400, fresh);
        index_until_idle(&session, &client, &db, later + RESWEEP_AFTER_SECS).await;
        assert!(db.get_cached_message("fresh-old-mail").unwrap().is_some());
        assert!(
            backend.envelopes_listed.load(Ordering::SeqCst) <= 2 * PAGE_SIZE as usize,
            "only the page with the new message is listed again with envelopes"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_empty_page_that_claims_more_ends_the_walk_and_retries_later() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(2400);
        *backend.stall_at.lock().unwrap() = Some(2200);
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        let steps = index_until_idle(&session, &client, &db, NOW).await;
        assert!(steps < 100, "the walk ended instead of looping ({} steps)", steps);

        let state = archive_state(&db);
        assert!(!state.sweeping);
        assert!(state.incomplete);
        assert_eq!(state.indexed(), 2200);
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2200);
        assert!(db.prune_queue_batch(10).unwrap().is_empty(), "an unfinished walk queues nothing for pruning");

        let listed = backend.list_calls.load(Ordering::SeqCst);
        assert_eq!(step(&session, &client, &db, NOW + 60).await, Step::Idle);
        assert_eq!(backend.list_calls.load(Ordering::SeqCst), listed);

        *backend.stall_at.lock().unwrap() = None;
        index_until_idle(&session, &client, &db, NOW + DRIFT_RESWEEP_AFTER_SECS * 2).await;
        let state = archive_state(&db);
        assert!(!state.incomplete);
        assert_eq!(db.count_cached_messages("archive").unwrap(), 2400);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn turning_full_sync_off_returns_the_space_to_the_disk() {
        let (dir, db, _backend, _client, _session) = indexed_archive(3500).await;
        let (before, _) = database_bytes(&db, dir.path());

        let trimmed = apply_mode(&db, false);
        assert_eq!(trimmed.len(), 1500);

        let (after, live) = database_bytes(&db, dir.path());
        let free: i64 = db
            .with_conn(|conn| conn.query_row("PRAGMA freelist_count", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(free, 0, "no freed pages are left inside the file");
        assert!(after < before, "the file shrank from {} to {}", before, after);
        assert!(after <= live + 64 * 1024, "{} on disk for {} live", after, live);
        let mode: i64 = db
            .with_conn(|conn| conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(mode, 2, "later trims reclaim in small steps");

        apply_mode(&db, true);
        for n in 0..500 {
            db.delete_message_by_aster_id(&item_id(n)).unwrap();
        }
        apply_mode(&db, false);
        let free: i64 = db
            .with_conn(|conn| conn.query_row("PRAGMA freelist_count", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(free, 0);
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

    struct Imap {
        reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: tokio::net::tcp::OwnedWriteHalf,
        next_tag: usize,
    }

    impl Imap {
        async fn start(db: &Arc<Database>, client: &Arc<ApiClient>, session: &Arc<RwLock<Session>>) -> Self {
            use tokio::io::AsyncBufReadExt;
            let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
            passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (state_tx, _state_rx) = broadcast::channel(16);
            let (db, client, session) = (db.clone(), client.clone(), session.clone());
            tokio::spawn(async move {
                let _ = crate::imap::server::serve(listener, session, db, client, passwords, state_tx, None).await;
            });
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (r, writer) = stream.into_split();
            let mut imap = Imap {
                reader: tokio::io::BufReader::new(r),
                writer,
                next_tag: 0,
            };
            let mut greeting = String::new();
            imap.reader.read_line(&mut greeting).await.unwrap();
            let login = imap.command("LOGIN \"tester@aster.test\" \"abcd-efgh-ijkl-mnop\"").await;
            assert!(login.contains(" OK"), "{}", login);
            imap
        }

        async fn command(&mut self, line: &str) -> String {
            use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
            self.next_tag += 1;
            let tag = format!("t{}", self.next_tag);
            self.writer.write_all(format!("{} {}\r\n", tag, line).as_bytes()).await.unwrap();
            let mut out = String::new();
            loop {
                let mut next = String::new();
                if self.reader.read_line(&mut next).await.unwrap() == 0 {
                    break;
                }
                if let Some(open) = next.trim_end().strip_suffix('}').and_then(|l| l.rfind('{').map(|i| l[i + 1..].to_string())) {
                    let mut literal = vec![0u8; open.parse().unwrap()];
                    self.reader.read_exact(&mut literal).await.unwrap();
                    next.push_str(&String::from_utf8_lossy(&literal));
                }
                out.push_str(&next);
                if next.starts_with(&format!("{} ", tag)) {
                    break;
                }
            }
            out
        }
    }

    fn uid_of(db: &Database, n: usize) -> u32 {
        db.get_cached_message(&item_id(n)).unwrap().unwrap().imap_uid
    }

    fn literal_len(response: &str, key: &str) -> usize {
        let at = response.find(&format!("{} {{", key)).unwrap_or_else(|| panic!("no {} in {}", key, response));
        let rest = &response[at + key.len() + 2..];
        rest[..rest.find('}').unwrap()].parse().unwrap()
    }

    fn fetch_line(response: &str) -> String {
        response
            .lines()
            .find(|l| l.starts_with("* ") && !l.starts_with("* OK "))
            .unwrap_or_default()
            .to_string()
    }

    fn rfc822_size(response: &str) -> usize {
        let at = response.find("RFC822.SIZE ").unwrap();
        response[at + 12..].split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
    }

    fn attachment_rows(db: &Database, ids: &[String]) -> i64 {
        db.with_conn(|conn| {
            let mut total = 0i64;
            for id in ids {
                total += conn.query_row(
                    "SELECT COUNT(*) FROM message_attachment WHERE aster_id = ?1",
                    [id],
                    |r| r.get::<_, i64>(0),
                )?;
            }
            Ok(total)
        })
        .unwrap()
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    async fn indexed_with_attachments(
        count: usize,
        attached: &[(usize, usize, bool)],
    ) -> (tempfile::TempDir, Arc<Database>, Backend, Arc<ApiClient>, Arc<RwLock<Session>>) {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(count);
        for (n, len, sized) in attached {
            backend.attach(*n, &payload(*len, *n as u8), *sized);
        }
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        index_until_idle(&session, &client, &db, NOW).await;
        (dir, db, backend, client, session)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_attachments_wait_for_a_request_while_recent_mail_uses_the_backlog() {
        let (_dir, db, backend, _client, _session) =
            indexed_with_attachments(2100, &[(10, 3000, true), (2050, 4000, true), (2060, 5000, true)]).await;

        let recent = db.get_cached_message(&item_id(10)).unwrap().unwrap();
        assert_eq!(recent.attachments_state, ATTACHMENTS_STORED, "recent mail keeps today's download path");
        assert_eq!(db.get_message_attachments(&item_id(10)).unwrap()[0].data, payload(3000, 10));
        assert_eq!(backend.attachment_requests(), 1, "only the recent message was downloaded");

        for (n, len) in [(2050usize, 4000i64), (2060, 5000)] {
            let old = db.get_cached_message(&item_id(n)).unwrap().unwrap();
            assert_eq!(old.attachments_state, crate::db::ATTACHMENTS_ON_DEMAND);
            let parts = db.get_message_attachments(&item_id(n)).unwrap();
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].name, format!("report-{}.pdf", n));
            assert_eq!(parts[0].content_type, "application/pdf");
            assert_eq!(parts[0].size, len);
            assert!(parts[0].data.is_empty());
        }
        assert!(db.list_attachment_backlog(100).unwrap().is_empty(), "history mail is not queued");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_full_fetch_downloads_once_and_keeps_uid_size_and_structure() {
        let (_dir, db, backend, client, session) =
            indexed_with_attachments(2100, &[(2050, 300_001, true), (2060, 7000, true)]).await;
        let mut imap = Imap::start(&db, &client, &session).await;
        assert!(imap.command("SELECT Archive").await.contains("* 2100 EXISTS"));
        let uid = uid_of(&db, 2050);
        let before = backend.attachment_requests();

        let summary = imap.command(&format!("UID FETCH {} (RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER])", uid)).await;
        assert!(summary.contains(" OK"), "{}", summary);
        assert!(summary.contains("multipart/mixed"), "{}", summary);
        assert!(summary.contains("\"FILENAME\" \"report-2050.pdf\""), "{}", summary);
        let advertised = rfc822_size(&summary);
        let structure = fetch_line(&imap.command(&format!("UID FETCH {} (RFC822.SIZE BODYSTRUCTURE)", uid)).await);
        assert_eq!(backend.attachment_requests(), before, "headers and structure come from the metadata");

        let text_only = imap.command(&format!("UID FETCH {} (BODY.PEEK[1])", uid)).await;
        assert!(text_only.contains("Body of message 2050"), "{}", text_only);
        assert_eq!(backend.attachment_requests(), before, "the text part needs no download");

        let full = imap.command(&format!("UID FETCH {} (BODY.PEEK[])", uid)).await;
        assert!(full.contains(" OK"), "{}", full);
        assert_eq!(backend.attachment_requests(), before + 1);
        assert_eq!(literal_len(&full, "BODY[]"), advertised, "the advertised size was exact");
        let encoded = STANDARD.encode(payload(300_001, 2050usize as u8));
        assert!(full.replace("\r\n", "").contains(&encoded), "the attachment is complete");

        let again = imap.command(&format!("UID FETCH {} (BODY.PEEK[])", uid)).await;
        assert!(again.contains(" OK"), "{}", again);
        assert_eq!(backend.attachment_requests(), before + 1, "the second fetch reads the cache");
        assert_eq!(literal_len(&again, "BODY[]"), advertised);
        assert_eq!(uid_of(&db, 2050), uid, "the UID does not change");
        assert_eq!(fetch_line(&imap.command(&format!("UID FETCH {} (RFC822.SIZE BODYSTRUCTURE)", uid)).await), structure);
        assert_eq!(db.get_cached_message(&item_id(2050)).unwrap().unwrap().attachments_state, ATTACHMENTS_STORED);

        let other = uid_of(&db, 2060);
        let part = imap.command(&format!("UID FETCH {} (BODY.PEEK[2])", other)).await;
        assert!(part.contains(" OK"), "{}", part);
        assert_eq!(backend.attachment_requests(), before + 2, "asking for the attachment part downloads it");
        assert_eq!(uid_of(&db, 2060), other);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_download_answers_no_caches_nothing_and_succeeds_on_retry() {
        let (_dir, db, backend, client, session) = indexed_with_attachments(2100, &[(2050, 9000, true)]).await;
        let mut imap = Imap::start(&db, &client, &session).await;
        imap.command("SELECT Archive").await;
        let uid = uid_of(&db, 2050);
        let size = rfc822_size(&imap.command(&format!("UID FETCH {} (RFC822.SIZE)", uid)).await);

        *backend.fail_attachments_with.lock().unwrap() = Some(503);
        let refused = imap.command(&format!("UID FETCH {} (BODY.PEEK[])", uid)).await;
        assert!(refused.contains(" NO [UNAVAILABLE]"), "{}", refused);
        assert!(!refused.contains("BODY[]"), "nothing partial is served: {}", refused);
        let cached = db.get_cached_message(&item_id(2050)).unwrap().unwrap();
        assert_eq!(cached.attachments_state, crate::db::ATTACHMENTS_ON_DEMAND);
        assert!(db.get_message_attachments(&item_id(2050)).unwrap()[0].data.is_empty());
        assert_eq!(cached.imap_uid, uid);

        *backend.fail_attachments_with.lock().unwrap() = None;
        let served = imap.command(&format!("UID FETCH {} (BODY.PEEK[])", uid)).await;
        assert!(served.contains(" OK"), "{}", served);
        assert_eq!(literal_len(&served, "BODY[]"), size);
        assert_eq!(backend.attachment_requests(), 2);
        assert_eq!(uid_of(&db, 2050), uid);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_unavailable_message_does_not_hold_back_the_rest_of_a_fetch() {
        let (_dir, db, backend, client, session) = indexed_with_attachments(
            2100,
            &[(2050, 6000, false), (2060, 7000, true), (2070, 8000, true), (2080, 4000, true), (2090, 4000, true)],
        )
        .await;
        let mut imap = Imap::start(&db, &client, &session).await;
        imap.command("SELECT Archive").await;
        let uids = [uid_of(&db, 2050), uid_of(&db, 2060), uid_of(&db, 2070)];
        let set = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");

        let response = imap.command(&format!("UID FETCH {} (BODY.PEEK[])", set)).await;
        assert!(response.contains("Body of message 2060"), "{}", response);
        assert!(response.contains("Body of message 2070"), "{}", response);
        assert!(!response.contains("Body of message 2050"), "{}", response);
        assert_eq!(response.matches("BODY[] {").count(), 2, "{}", response);
        let last = response.lines().last().unwrap_or_default();
        assert!(last.contains(" NO [UNAVAILABLE]"), "{}", last);
        assert!(!last.contains("other"), "{}", last);
        assert_eq!(backend.attachment_requests(), 3);
        let cached = db.get_cached_message(&item_id(2060)).unwrap().unwrap();
        assert_eq!(cached.attachments_state, ATTACHMENTS_STORED);

        *backend.fail_attachments_with.lock().unwrap() = Some(503);
        let set = format!("{},{},{}", uid_of(&db, 2060), uid_of(&db, 2080), uid_of(&db, 2090));
        let response = imap.command(&format!("UID FETCH {} (BODY[])", set)).await;
        assert!(response.contains("Body of message 2060"), "{}", response);
        let last = response.lines().last().unwrap_or_default();
        assert!(last.contains(" NO [UNAVAILABLE]"), "{}", last);
        assert!(last.contains("(1 other message also skipped)"), "{}", last);
        let flags = imap.command(&format!("UID FETCH {} (FLAGS)", uid_of(&db, 2080))).await;
        assert!(!flags.contains("\\Seen"), "a skipped message is not marked read: {}", flags);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_envelope_without_sizes_is_rebuilt_once_under_a_new_uid() {
        let (_dir, db, backend, client, session) = indexed_with_attachments(2100, &[(2050, 6000, false)]).await;
        let mut imap = Imap::start(&db, &client, &session).await;
        imap.command("SELECT Archive").await;
        let uid = uid_of(&db, 2050);

        let refused = imap.command(&format!("UID FETCH {} (BODY.PEEK[])", uid)).await;
        assert!(refused.contains(" NO [UNAVAILABLE]"), "{}", refused);
        let new_uid = uid_of(&db, 2050);
        assert!(new_uid > uid, "a message whose size was not known is replaced, never changed in place");
        let noop = imap.command("NOOP").await;
        assert!(noop.contains("EXPUNGE") && noop.contains("EXISTS"), "{}", noop);

        let served = imap.command(&format!("UID FETCH {} (RFC822.SIZE BODY.PEEK[])", new_uid)).await;
        assert!(served.contains(" OK"), "{}", served);
        assert_eq!(literal_len(&served, "BODY[]"), rfc822_size(&served));
        assert!(served.contains("server-name.pdf") || served.contains("report-2050.pdf"));
        assert_eq!(backend.attachment_requests(), 1, "the rebuilt message reads the cache");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_jmap_blob_download_fetches_on_demand_once() {
        let (_dir, db, backend, client, session) = indexed_with_attachments(2100, &[(2050, 5000, true)]).await;
        let _ = db.seed_jmap_mailboxes();
        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, _rx) = broadcast::channel(8);
        let (s, d, c) = (session.clone(), db.clone(), client.clone());
        tokio::spawn(async move {
            let _ = crate::jmap::server::serve(listener, s, d, c, passwords, tx).await;
        });
        let auth = format!("Basic {}", STANDARD.encode(b"tester@aster.test:abcd-efgh-ijkl-mnop"));
        let http = reqwest::Client::new();
        let mut account = None;
        for _ in 0..200 {
            if let Ok(r) = http.get(format!("{}/jmap/session", base)).header("authorization", &auth).send().await {
                let v: serde_json::Value = r.json().await.unwrap();
                account = v["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().map(str::to_string);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let account = account.unwrap();
        let blob = crate::jmap::blob::attachment_blob_id(&item_id(2050), 0);
        let url = format!("{}/jmap/download/{}/{}/report.pdf", base, account, blob);

        *backend.fail_attachments_with.lock().unwrap() = Some(502);
        let refused = http.get(&url).header("authorization", &auth).send().await.unwrap();
        assert_eq!(refused.status(), 503);
        assert!(refused.headers().contains_key("retry-after"));
        *backend.fail_attachments_with.lock().unwrap() = None;

        let first = http.get(&url).header("authorization", &auth).send().await.unwrap();
        assert_eq!(first.status(), 200);
        assert_eq!(first.bytes().await.unwrap().to_vec(), payload(5000, 2050usize as u8));
        let second = http.get(&url).header("authorization", &auth).send().await.unwrap();
        assert_eq!(second.status(), 200);
        assert_eq!(backend.attachment_requests(), 2, "one refused try, then one download for both requests");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn on_demand_attachments_leave_with_their_messages() {
        let attached: Vec<(usize, usize, bool)> = (2010..2020).map(|n| (n, 2000, true)).collect();
        let (_dir, db, _backend, _client, _session) = indexed_with_attachments(2100, &attached).await;
        let ids: Vec<String> = (2010..2020).map(item_id).collect();
        assert_eq!(attachment_rows(&db, &ids), 10);

        db.delete_message_by_aster_id(&ids[0]).unwrap();
        assert_eq!(attachment_rows(&db, &ids[..1]), 0, "pruning removes the stored parts");

        apply_mode(&db, false);
        assert_eq!(attachment_rows(&db, &ids), 0, "turning the setting off removes them");

        let (_dir, db, _backend, _client, _session) = indexed_with_attachments(2100, &attached).await;
        assert_eq!(attachment_rows(&db, &ids), 10);
        db.clear_user_data().unwrap();
        assert_eq!(attachment_rows(&db, &ids), 0, "signing out wipes them");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_mail_that_enters_the_recent_window_stays_on_demand() {
        let (_dir, db, backend, client, session) = indexed_with_attachments(2100, &[(2050, 4000, true)]).await;
        for n in 0..120 {
            backend.remove(&item_id(n));
        }
        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        let cached = db.get_cached_message(&item_id(2050)).unwrap().unwrap();
        assert_eq!(cached.attachments_state, crate::db::ATTACHMENTS_ON_DEMAND);
        assert_eq!(backend.attachment_requests(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pop3_downloads_on_demand_attachments_before_it_answers() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        let backend = Backend::default();
        let data = payload(5000, 1);
        backend.attachments.lock().unwrap().insert("pop-old".to_string(), Arc::new(sealed_row(&data)));
        let meta = serde_json::json!({
            "is_html": false,
            "attachment_count": 1,
            "attachments": [{"seq": 0, "name": "a.pdf", "type": "application/pdf", "size": 5000, "key": STANDARD.encode(ATTACHMENT_KEY)}],
        })
        .to_string();
        db.upsert_cached_message("pop-old", "inbox", Some("old"), Some("a@b.c"), Some("d@e.f"), Some("2019-01-01T00:00:00Z"), 8, Some("old body"), Some(&meta))
            .unwrap();
        db.store_on_demand_attachments(
            "pop-old",
            &[CachedAttachment {
                seq: 0,
                name: "a.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                content_id: None,
                is_inline: false,
                size: 5000,
                data: Vec::new(),
            }],
        )
        .unwrap();
        db.assign_uid_if_missing("inbox", "pop-old").unwrap();
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let passwords = Arc::new(crate::auth::app_passwords::AppPasswords::new(db.clone()));
        passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = db.clone();
        tokio::spawn(async move {
            let _ = crate::pop3::server::serve_with_tls(listener, session(), served, client, passwords, None).await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(r);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        for cmd in ["USER tester@aster.test", "PASS abcd-efgh-ijkl-mnop"] {
            w.write_all(format!("{}\r\n", cmd).as_bytes()).await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("+OK"), "{}", line);
        }
        w.write_all(b"LIST 1\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let listed: usize = line.trim_end().rsplit(' ').next().unwrap().parse().unwrap();

        *backend.fail_attachments_with.lock().unwrap() = Some(503);
        w.write_all(b"RETR 1\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("-ERR [SYS/TEMP]"), "{}", line);
        *backend.fail_attachments_with.lock().unwrap() = None;

        w.write_all(b"RETR 1\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, format!("+OK {} octets\r\n", listed));
        let mut message = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            if line == ".\r\n" {
                break;
            }
            message.push_str(&line);
        }
        assert_eq!(message.len(), listed);
        assert!(message.replace("\r\n", "").contains(&STANDARD.encode(&data)));
        assert_eq!(backend.attachment_requests(), 2);
    }

    fn database_bytes(db: &Database, dir: &std::path::Path) -> (u64, u64) {
        let live = db
            .with_conn(|conn| {
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
                let free: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
                let size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
                Ok(((pages - free) * size) as u64)
            })
            .unwrap();
        let on_disk = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("bridge.db"))
            .map(|e| e.metadata().unwrap().len())
            .sum();
        (on_disk, live)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn measure_on_demand_against_the_backlog() {
        const MESSAGES: usize = 20_000;
        const CLASSES: [usize; 5] = [100_000, 200_000, 300_000, 400_000, 500_000];
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        apply_mode(&db, true);
        let backend = Backend::with_archive(MESSAGES);
        let rows: Vec<Arc<serde_json::Value>> = CLASSES
            .iter()
            .map(|len| Arc::new(sealed_row(&payload(*len, *len as u8))))
            .collect();
        let mut attached = 0usize;
        for n in (0..MESSAGES).filter(|n| n % 10 < 3) {
            let class = (n / 10) % CLASSES.len();
            let data = payload(CLASSES[class], CLASSES[class] as u8);
            let item = archive_item_with(n, Some(Attached { data: &data, sized: true }));
            let id = item["id"].as_str().unwrap().to_string();
            let mut items = backend.items.lock().unwrap();
            *items.iter_mut().find(|i| i["id"] == id.as_str()).unwrap() = item;
            backend.attachments.lock().unwrap().insert(id, rows[class].clone());
            attached += 1;
        }
        let client = Arc::new(ApiClient::new_with_base_url(&backend.serve().await));
        let session = session();
        let keys = Keys::of(&session).await;

        run_sync_pass(&session, &client, &db, None, true).await.unwrap();
        while !db.list_attachment_backlog(1).unwrap().is_empty() {
            backfill_pending_attachments(&db, &client, &keys.access_token, &keys.passphrase, IK, &[], &[], &HashSet::new()).await;
        }
        let (recent_disk, recent_live) = database_bytes(&db, dir.path());
        let lists_before = backend.list_calls.load(Ordering::SeqCst);
        let files_before = backend.attachment_requests();
        let started = std::time::Instant::now();
        index_until_idle(&session, &client, &db, NOW).await;
        let indexed_in = started.elapsed();
        let history_lists = backend.list_calls.load(Ordering::SeqCst) - lists_before;
        let history_files = backend.attachment_requests() - files_before;
        let (lazy_disk, lazy_live) = database_bytes(&db, dir.path());
        let on_demand: i64 = db
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM message_cache WHERE attachments_state = ?1",
                    [crate::db::ATTACHMENTS_ON_DEMAND],
                    |r| r.get(0),
                )
            })
            .unwrap();

        db.with_conn(|conn| {
            conn.execute(
                "UPDATE message_cache SET attachments_state = ?1 WHERE attachments_state = ?2",
                rusqlite::params![ATTACHMENTS_PENDING, crate::db::ATTACHMENTS_ON_DEMAND],
            )
        })
        .unwrap();
        let backlog_started = std::time::Instant::now();
        while !db.list_attachment_backlog(1).unwrap().is_empty() {
            backfill_pending_attachments(&db, &client, &keys.access_token, &keys.passphrase, IK, &[], &[], &HashSet::new()).await;
        }
        let backlog_in = backlog_started.elapsed();
        let backlog_files = backend.attachment_requests() - files_before - history_files;
        let (backlog_disk, backlog_live) = database_bytes(&db, dir.path());

        println!("messages={} with_attachments={} history_on_demand={}", MESSAGES, attached, on_demand);
        println!("after recent window: disk={} live={}", recent_disk, recent_live);
        println!(
            "lazy: index took {:?}, list requests={}, attachment requests={}, disk={} live={}",
            indexed_in, history_lists, history_files, lazy_disk, lazy_live
        );
        println!(
            "backlog: extra attachment requests={}, took {:?}, disk={} live={}",
            backlog_files, backlog_in, backlog_disk, backlog_live
        );
    }
}
