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
use crate::api_client::{ApiClient, CreateTagBody};
use crate::db::{CustomTag, Database};
use crate::error::BridgeError;

pub const MAX_CREATED_PER_COMMAND: usize = 10;
pub const MAX_MIGRATION_ATTEMPTS: u32 = 5;

const MIGRATION_STATE_KEY: &str = "local_keyword_migration";
const MIGRATION_DONE: &str = "done";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagOpError {
    Locked,
    Invalid(String),
    AlreadyExists,
    NotFound,
    LimitReached,
    TooManyNew,
    Busy,
    Server(String),
}

impl TagOpError {
    pub fn is_limit(&self) -> bool {
        matches!(self, TagOpError::LimitReached | TagOpError::TooManyNew)
    }

    pub fn imap_response(&self) -> &'static str {
        match self {
            TagOpError::LimitReached => "[LIMIT] Label limit reached",
            TagOpError::TooManyNew => "[LIMIT] Too many new labels in one command",
            _ => "[UNAVAILABLE] Labels could not be saved, try again later",
        }
    }
}

#[derive(Debug, Default)]
pub struct KeywordOutcome {
    pub changed: Vec<String>,
    pub failed: Vec<String>,
    pub unmapped: Vec<String>,
    pub error: Option<TagOpError>,
}

impl KeywordOutcome {
    fn fail(&mut self, keyword: &str, error: TagOpError) {
        if !self.failed.iter().any(|known| known == keyword) {
            self.failed.push(keyword.to_string());
        }
        let replace = match &self.error {
            None => true,
            Some(current) => !current.is_limit() && error.is_limit(),
        };
        if replace {
            self.error = Some(error);
        }
    }
}

fn server_error(action: &str, e: &BridgeError) -> TagOpError {
    tracing::warn!("could not {}: {}", action, e);
    if matches!(e, BridgeError::PlanLimit(_)) {
        TagOpError::LimitReached
    } else if crate::imap::append::is_rate_limited(e) {
        TagOpError::Busy
    } else {
        TagOpError::Server(action.to_string())
    }
}

fn clean_name(name: &str) -> Result<String, TagOpError> {
    let trimmed = name.trim();
    crate::tags::validate_name(trimmed).map_err(|msg| TagOpError::Invalid(msg.to_string()))?;
    Ok(trimmed.to_string())
}

fn find_by_name<'a>(tags: &'a [CustomTag], name: &str) -> Option<&'a CustomTag> {
    let wanted = name.to_lowercase();
    tags.iter()
        .find(|tag| {
            tag.keyword
                .as_deref()
                .and_then(crate::tags::keyword_text)
                .is_some_and(|text| text.to_lowercase() == wanted)
        })
        .or_else(|| {
            tags.iter()
                .find(|tag| tag.keyword.is_none() && tag.name.to_lowercase() == wanted)
        })
}

fn store(db: &Database, mut tag: CustomTag) -> Result<CustomTag, TagOpError> {
    tag.keyword = crate::tags::keyword_for_name(&tag.name);
    db.upsert_custom_tag(&tag).map_err(TagOpError::Server)?;
    Ok(tag)
}

async fn create(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: &str,
    name: &str,
) -> Result<CustomTag, TagOpError> {
    let name = clean_name(name)?;
    let (encrypted_name, name_nonce) = crate::crypto::tag::encrypt_tag_name(&name, identity_key)
        .map_err(|e| server_error("encrypt the label name", &e))?;
    let tag_token = crate::crypto::tag::generate_tag_token();
    let body = CreateTagBody {
        tag_token: &tag_token,
        encrypted_name: &encrypted_name,
        name_nonce: &name_nonce,
    };
    let server_id = client
        .create_tag(access_token, &body)
        .await
        .map_err(|e| server_error("create the label", &e))?;
    store(
        db,
        CustomTag {
            tag_token: tag_token.clone(),
            server_id,
            name,
            keyword: None,
        },
    )
}

async fn resolve(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
    tags: &mut Vec<CustomTag>,
    keyword: &str,
    budget: &mut usize,
) -> Result<Option<String>, TagOpError> {
    if let Some(tag) = crate::tags::find_by_keyword(tags.as_slice(), keyword) {
        return Ok(Some(tag.tag_token.clone()));
    }
    let Some(name) = crate::tags::name_for_keyword(keyword) else {
        return Ok(None);
    };
    if let Some(tag) = find_by_name(tags.as_slice(), &name) {
        return Ok(Some(tag.tag_token.clone()));
    }
    let identity_key = identity_key.ok_or(TagOpError::Locked)?;
    if *budget == 0 {
        return Err(TagOpError::TooManyNew);
    }
    *budget -= 1;
    let tag = create(db, client, access_token, identity_key, &name).await?;
    let token = tag.tag_token.clone();
    tags.push(tag);
    Ok(Some(token))
}

fn push_unique(list: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !list.contains(value) {
            list.push(value.clone());
        }
    }
}

fn holders(
    current: &std::collections::HashMap<String, Vec<String>>,
    item_ids: &[String],
    token: &String,
    present: bool,
) -> Vec<String> {
    item_ids
        .iter()
        .filter(|id| current.get(*id).is_some_and(|tokens| tokens.contains(token)) == present)
        .cloned()
        .collect()
}

fn fail_all<'a>(
    outcome: &mut KeywordOutcome,
    keywords: impl Iterator<Item = &'a String>,
    message: String,
) {
    for keyword in keywords {
        outcome.fail(keyword, TagOpError::Server(message.clone()));
    }
    if outcome.error.is_none() {
        outcome.error = Some(TagOpError::Server(message));
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_keywords(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
    item_ids: &[String],
    op: i8,
    keywords: &[String],
    budget: &mut usize,
) -> KeywordOutcome {
    let mut outcome = KeywordOutcome::default();
    if item_ids.is_empty() || (op != 0 && keywords.is_empty()) {
        return outcome;
    }
    let _guard = db.tag_lock.lock().await;
    let mut tags = match db.list_custom_tags() {
        Ok(tags) => tags,
        Err(e) => {
            let label_keywords = keywords
                .iter()
                .filter(|keyword| !crate::tags::is_local_keyword(keyword));
            fail_all(&mut outcome, label_keywords, e);
            return outcome;
        }
    };
    let mut wanted: Vec<(String, String)> = Vec::new();
    for keyword in keywords {
        if crate::tags::is_local_keyword(keyword) {
            continue;
        }
        let token = if op == -1 {
            crate::tags::find_by_keyword(&tags, keyword).map(|tag| tag.tag_token.clone())
        } else {
            match resolve(db, client, access_token, identity_key, &mut tags, keyword, budget).await {
                Ok(Some(token)) => Some(token),
                Ok(None) => {
                    push_unique(&mut outcome.unmapped, std::slice::from_ref(keyword));
                    None
                }
                Err(e) => {
                    outcome.fail(keyword, e);
                    None
                }
            }
        };
        if let Some(token) = token {
            if !wanted.iter().any(|(known, _)| *known == token) {
                wanted.push((token, keyword.clone()));
            }
        }
    }
    let current = match db.message_tags(item_ids) {
        Ok(current) => current,
        Err(e) => {
            fail_all(&mut outcome, wanted.iter().map(|(_, keyword)| keyword), e);
            return outcome;
        }
    };
    if op != -1 {
        for (token, keyword) in &wanted {
            let ids = holders(&current, item_ids, token, false);
            if ids.is_empty() {
                continue;
            }
            if let Err(e) = client.add_tag(access_token, &ids, token).await {
                outcome.fail(keyword, server_error("add the label", &e));
                continue;
            }
            if let Err(e) = db.add_message_tag(&ids, token) {
                outcome.fail(keyword, TagOpError::Server(e));
                continue;
            }
            push_unique(&mut outcome.changed, &ids);
        }
    }
    let mut removals: Vec<(String, String)> = Vec::new();
    if op == -1 {
        removals = wanted.clone();
    } else if op == 0 {
        for tag in &tags {
            let Some(keyword) = tag.keyword.as_ref() else {
                continue;
            };
            let held = current.values().any(|tokens| tokens.contains(&tag.tag_token));
            if held && !wanted.iter().any(|(token, _)| *token == tag.tag_token) {
                removals.push((tag.tag_token.clone(), keyword.clone()));
            }
        }
    }
    for (token, keyword) in &removals {
        let ids = holders(&current, item_ids, token, true);
        if ids.is_empty() {
            continue;
        }
        if let Err(e) = client.remove_tag(access_token, &ids, token).await {
            outcome.fail(keyword, server_error("remove the label", &e));
            continue;
        }
        if let Err(e) = db.remove_message_tag(&ids, token) {
            outcome.fail(keyword, TagOpError::Server(e));
            continue;
        }
        push_unique(&mut outcome.changed, &ids);
    }
    outcome
}

pub async fn migrate_local_keywords(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
) -> Vec<String> {
    let state = db.get_sync_state(MIGRATION_STATE_KEY).ok().flatten();
    if state.as_deref() == Some(MIGRATION_DONE) {
        return Vec::new();
    }
    let attempts: u32 = state.and_then(|value| value.parse().ok()).unwrap_or(0);
    let Ok(stored) = db.local_keyword_messages() else {
        return Vec::new();
    };
    let groups: Vec<(String, Vec<String>)> = stored
        .into_iter()
        .filter(|(keyword, _)| crate::tags::name_for_keyword(keyword).is_some())
        .collect();
    if groups.is_empty() {
        let _ = db.set_sync_state(MIGRATION_STATE_KEY, MIGRATION_DONE);
        return Vec::new();
    }
    if identity_key.is_none() {
        return Vec::new();
    }
    let mut budget = MAX_CREATED_PER_COMMAND;
    let mut changed: Vec<String> = Vec::new();
    let mut failed = false;
    let mut paused = false;
    let mut blocked = false;
    for (keyword, ids) in &groups {
        let outcome = apply_keywords(
            db,
            client,
            access_token,
            identity_key,
            ids,
            1,
            std::slice::from_ref(keyword),
            &mut budget,
        )
        .await;
        push_unique(&mut changed, &outcome.changed);
        match outcome.error {
            None => {}
            Some(TagOpError::TooManyNew) => {
                paused = true;
                break;
            }
            Some(TagOpError::LimitReached) => {
                blocked = true;
                break;
            }
            Some(_) => failed = true,
        }
    }
    let next = if blocked {
        MIGRATION_DONE.to_string()
    } else if paused {
        attempts.to_string()
    } else if failed && attempts + 1 < MAX_MIGRATION_ATTEMPTS {
        (attempts + 1).to_string()
    } else {
        MIGRATION_DONE.to_string()
    };
    let _ = db.set_sync_state(MIGRATION_STATE_KEY, &next);
    changed
}

pub async fn copy_tags(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    pairs: &[(String, String)],
) -> Result<(), TagOpError> {
    if pairs.is_empty() {
        return Ok(());
    }
    let _guard = db.tag_lock.lock().await;
    let sources: Vec<String> = pairs.iter().map(|(source, _)| source.clone()).collect();
    let current = db.message_tags(&sources).map_err(TagOpError::Server)?;
    let mut by_token: Vec<(String, Vec<String>)> = Vec::new();
    for (source, copy) in pairs {
        let Some(tokens) = current.get(source) else {
            continue;
        };
        for token in tokens {
            match by_token.iter_mut().find(|(known, _)| known == token) {
                Some((_, ids)) => push_unique(ids, std::slice::from_ref(copy)),
                None => by_token.push((token.clone(), vec![copy.clone()])),
            }
        }
    }
    let mut result: Result<(), TagOpError> = Ok(());
    for (token, ids) in &by_token {
        let applied = match client.add_tag(access_token, ids, token).await {
            Ok(()) => db.add_message_tag(ids, token).map_err(TagOpError::Server),
            Err(e) => Err(server_error("add the label", &e)),
        };
        if result.is_ok() {
            result = applied;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::Arc;

    type Calls = Arc<tokio::sync::Mutex<Vec<(String, serde_json::Value)>>>;

    #[derive(Clone, Copy, PartialEq)]
    enum CreateMode {
        Accept,
        Fail,
        Limit,
    }

    async fn spawn_backend(mode: CreateMode) -> (String, Calls) {
        let calls: Calls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let c_create = calls.clone();
        let c_add = calls.clone();
        let c_remove = calls.clone();
        let app = Router::new()
            .route(
                "/mail/v1/tags",
                post(move |Json(body): Json<serde_json::Value>| {
                    let calls = c_create.clone();
                    async move {
                        let created = {
                            let mut guard = calls.lock().await;
                            guard.push(("create".to_string(), body));
                            guard.iter().filter(|(kind, _)| kind == "create").count()
                        };
                        match mode {
                            CreateMode::Accept => {
                                Json(serde_json::json!({"id": format!("srv-tag-{}", created)})).into_response()
                            }
                            CreateMode::Fail => {
                                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                            }
                            CreateMode::Limit => (
                                axum::http::StatusCode::FORBIDDEN,
                                Json(serde_json::json!({
                                    "error": "limit reached",
                                    "code": "PLAN_LIMIT_EXCEEDED"
                                })),
                            )
                                .into_response(),
                        }
                    }
                }),
            )
            .route(
                "/bridge/v1/messages/bulk/tags",
                post(move |Json(body): Json<serde_json::Value>| {
                    let calls = c_add.clone();
                    async move {
                        calls.lock().await.push(("add".to_string(), body));
                        Json(serde_json::json!({"success": true})).into_response()
                    }
                }),
            )
            .route(
                "/bridge/v1/messages/bulk/tags/remove",
                post(move |Json(body): Json<serde_json::Value>| {
                    let calls = c_remove.clone();
                    async move {
                        calls.lock().await.push(("remove".to_string(), body));
                        Json(serde_json::json!({"success": true})).into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{}", port), calls)
    }

    async fn setup(mode: CreateMode) -> (tempfile::TempDir, Database, ApiClient, Calls) {
        let (base, calls) = spawn_backend(mode).await;
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[7u8; 32]).unwrap();
        let client = ApiClient::new_with_base_url(&base);
        (dir, db, client, calls)
    }

    fn stored_tag(token: &str, name: &str) -> CustomTag {
        CustomTag {
            tag_token: token.to_string(),
            server_id: format!("id-{}", token),
            name: name.to_string(),
            keyword: crate::tags::keyword_for_name(name),
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    async fn count(calls: &Calls, kind: &str) -> usize {
        calls.lock().await.iter().filter(|(k, _)| k == kind).count()
    }

    #[tokio::test]
    async fn a_failed_creation_does_not_block_an_existing_label() {
        let (_dir, db, client, calls) = setup(CreateMode::Fail).await;
        db.replace_custom_tags(&[stored_tag("tok-work", "Work")]).unwrap();
        let ids = strings(&["m-1"]);
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome = apply_keywords(
            &db,
            &client,
            "stub",
            Some("test-ik"),
            &ids,
            1,
            &strings(&["Fresh", "Work"]),
            &mut budget,
        )
        .await;

        assert_eq!(outcome.failed, strings(&["Fresh"]));
        assert!(matches!(outcome.error, Some(TagOpError::Server(_))), "{:?}", outcome.error);
        assert!(outcome.unmapped.is_empty());
        assert_eq!(outcome.changed, ids);
        assert_eq!(db.message_tags(&ids).unwrap().get("m-1").unwrap(), &strings(&["tok-work"]));
        assert_eq!(db.list_custom_tags().unwrap().len(), 1);
        assert_eq!(db.message_keywords("m-1").unwrap(), strings(&["Work"]));
        let log = calls.lock().await.clone();
        assert!(
            log.iter().any(|(kind, body)| kind == "add" && body["tag_token"] == "tok-work"),
            "{:?}",
            log
        );
        assert!(outcome.error.unwrap().imap_response().starts_with("[UNAVAILABLE]"));
    }

    #[tokio::test]
    async fn the_server_label_limit_is_reported_as_a_limit() {
        let (_dir, db, client, _calls) = setup(CreateMode::Limit).await;
        let ids = strings(&["m-1"]);
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome = apply_keywords(
            &db,
            &client,
            "stub",
            Some("test-ik"),
            &ids,
            1,
            &strings(&["Fresh"]),
            &mut budget,
        )
        .await;

        assert_eq!(outcome.failed, strings(&["Fresh"]));
        assert_eq!(outcome.error, Some(TagOpError::LimitReached));
        assert!(TagOpError::LimitReached.imap_response().starts_with("[LIMIT]"));
        assert!(db.list_custom_tags().unwrap().is_empty());
        assert!(db.message_tags(&ids).unwrap().is_empty());
    }

    #[tokio::test]
    async fn one_command_creates_at_most_ten_labels() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        let ids = strings(&["m-1"]);
        let keywords: Vec<String> = (0..12).map(|n| format!("New{}", n)).collect();
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome =
            apply_keywords(&db, &client, "stub", Some("test-ik"), &ids, 1, &keywords, &mut budget).await;

        assert_eq!(budget, 0);
        assert_eq!(outcome.failed, strings(&["New10", "New11"]));
        assert_eq!(outcome.error, Some(TagOpError::TooManyNew));
        assert!(TagOpError::TooManyNew.imap_response().starts_with("[LIMIT]"));
        assert_eq!(db.list_custom_tags().unwrap().len(), 10);
        assert_eq!(db.message_tags(&ids).unwrap().get("m-1").unwrap().len(), 10);
        assert_eq!(count(&calls, "create").await, 10);
        assert_eq!(count(&calls, "add").await, 10);
        let stored = db.message_keywords("m-1").unwrap();
        assert!(stored.contains(&"New9".to_string()), "{:?}", stored);
        assert!(!stored.contains(&"New10".to_string()), "{:?}", stored);
    }

    #[tokio::test]
    async fn client_internal_keywords_never_reach_the_server() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        let ids = strings(&["m-1"]);
        for op in [1, 0, -1] {
            let mut budget = MAX_CREATED_PER_COMMAND;
            let outcome = apply_keywords(
                &db,
                &client,
                "stub",
                Some("test-ik"),
                &ids,
                op,
                &strings(&["$label1", "NonJunk", "Forwarded", "seen", "MDNSent", "receipt-handled"]),
                &mut budget,
            )
            .await;
            assert!(outcome.failed.is_empty(), "{:?}", outcome);
            assert!(outcome.unmapped.is_empty(), "{:?}", outcome);
            assert!(outcome.changed.is_empty(), "{:?}", outcome);
            assert_eq!(outcome.error, None);
            assert_eq!(budget, MAX_CREATED_PER_COMMAND);
        }
        assert!(calls.lock().await.is_empty());
        assert!(db.list_custom_tags().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_label_under_another_letter_case_is_reused() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        db.replace_custom_tags(&[stored_tag("tok-cheese", "K\u{e4}se")]).unwrap();
        let ids = strings(&["m-1"]);
        let keyword = crate::tags::keyword_for_name("K\u{c4}SE").unwrap();
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome =
            apply_keywords(&db, &client, "stub", Some("test-ik"), &ids, 1, &[keyword], &mut budget).await;

        assert!(outcome.failed.is_empty(), "{:?}", outcome);
        assert!(outcome.unmapped.is_empty(), "{:?}", outcome);
        assert_eq!(outcome.error, None);
        assert_eq!(budget, MAX_CREATED_PER_COMMAND);
        assert_eq!(count(&calls, "create").await, 0);
        assert_eq!(db.message_tags(&ids).unwrap().get("m-1").unwrap(), &strings(&["tok-cheese"]));
        assert_eq!(db.list_custom_tags().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn keywords_that_cannot_name_a_label_are_reported_unmapped() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        let ids = strings(&["m-1"]);
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome = apply_keywords(
            &db,
            &client,
            "stub",
            Some("test-ik"),
            &ids,
            1,
            &strings(&["broken&shift"]),
            &mut budget,
        )
        .await;

        assert_eq!(outcome.unmapped, strings(&["broken&shift"]));
        assert!(outcome.failed.is_empty());
        assert_eq!(outcome.error, None);
        assert!(calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_new_label_needs_an_unlocked_session() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        let ids = strings(&["m-1"]);
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome =
            apply_keywords(&db, &client, "stub", None, &ids, 1, &strings(&["Fresh"]), &mut budget).await;

        assert_eq!(outcome.failed, strings(&["Fresh"]));
        assert_eq!(outcome.error, Some(TagOpError::Locked));
        assert!(calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn replacing_keywords_removes_the_labels_left_out() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        db.replace_custom_tags(&[stored_tag("tok-home", "Home"), stored_tag("tok-work", "Work")])
            .unwrap();
        let ids = strings(&["m-1"]);
        db.add_message_tag(&ids, "tok-home").unwrap();
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome = apply_keywords(
            &db,
            &client,
            "stub",
            Some("test-ik"),
            &ids,
            0,
            &strings(&["work", "$label1"]),
            &mut budget,
        )
        .await;

        assert_eq!(outcome.error, None);
        assert_eq!(outcome.changed, ids);
        assert_eq!(db.message_tags(&ids).unwrap().get("m-1").unwrap(), &strings(&["tok-work"]));
        let log = calls.lock().await.clone();
        assert!(log.iter().any(|(kind, body)| kind == "remove" && body["tag_token"] == "tok-home"));
        assert!(log.iter().any(|(kind, body)| kind == "add" && body["tag_token"] == "tok-work"));
        assert_eq!(count(&calls, "create").await, 0);
    }

    #[tokio::test]
    async fn created_labels_are_stored_once() {
        let (_dir, db, client, _calls) = setup(CreateMode::Accept).await;
        db.replace_custom_tags(&[stored_tag("tok-home", "Home")]).unwrap();
        let ids = strings(&["m-1", "m-2"]);
        db.add_message_tag(&ids[..1], "tok-home").unwrap();
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome = apply_keywords(
            &db,
            &client,
            "stub",
            Some("test-ik"),
            &ids,
            1,
            &strings(&["Fresh", "fresh"]),
            &mut budget,
        )
        .await;

        assert_eq!(outcome.error, None);
        assert_eq!(budget, MAX_CREATED_PER_COMMAND - 1);
        let tags = db.list_custom_tags().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags.iter().filter(|tag| tag.keyword.as_deref() == Some("Fresh")).count(), 1);
        assert_eq!(db.messages_with_tag("tok-home").unwrap(), strings(&["m-1"]));
        assert_eq!(db.message_keywords("m-2").unwrap(), strings(&["Fresh"]));
    }

    fn cache(db: &Database, ids: &[&str]) {
        for id in ids {
            db.upsert_cached_message(id, "inbox", Some("s"), None, None, None, 1, None, None)
                .unwrap();
        }
    }

    #[tokio::test]
    async fn a_leaf_name_does_not_resolve_to_a_nested_label() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        let mut nested = stored_tag("tok-nested", "Acme");
        nested.keyword = Some("Clients/Acme".to_string());
        db.replace_custom_tags(&[stored_tag("tok-clients", "Clients"), nested]).unwrap();
        let ids = strings(&["m-1"]);
        let mut budget = MAX_CREATED_PER_COMMAND;
        let outcome = apply_keywords(
            &db,
            &client,
            "stub",
            Some("test-ik"),
            &ids,
            1,
            &strings(&["clients/acme", "Acme"]),
            &mut budget,
        )
        .await;

        assert_eq!(outcome.error, None);
        assert_eq!(count(&calls, "create").await, 1);
        let held = db.message_tags(&ids).unwrap().get("m-1").unwrap().clone();
        assert_eq!(held.len(), 2);
        assert!(held.contains(&"tok-nested".to_string()));
        assert!(!held.contains(&"tok-clients".to_string()));
        let tags = db.list_custom_tags().unwrap();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags.iter().filter(|tag| tag.keyword.as_deref() == Some("Acme")).count(), 1);
    }

    #[tokio::test]
    async fn stored_keywords_become_labels_once() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        cache(&db, &["m-1", "m-2"]);
        db.set_message_keywords("m-1", &strings(&["work", "$label1", "Fresh"])).unwrap();
        db.set_message_keywords("m-2", &strings(&["Work", "NonJunk"])).unwrap();
        db.set_message_keywords("gone", &strings(&["Lost"])).unwrap();
        db.replace_custom_tags(&[stored_tag("tok-work", "Work")]).unwrap();

        let mut changed = migrate_local_keywords(&db, &client, "stub", Some("test-ik")).await;
        changed.sort();

        assert_eq!(changed, strings(&["m-1", "m-2"]));
        assert_eq!(count(&calls, "create").await, 1);
        assert_eq!(db.messages_with_tag("tok-work").unwrap(), strings(&["m-1", "m-2"]));
        assert_eq!(db.message_keywords("m-1").unwrap(), strings(&["$label1", "Fresh", "Work"]));
        assert_eq!(db.message_keywords("m-2").unwrap(), strings(&["NonJunk", "Work"]));
        assert_eq!(db.list_custom_tags().unwrap().len(), 2);
        assert_eq!(db.get_sync_state(MIGRATION_STATE_KEY).unwrap().as_deref(), Some(MIGRATION_DONE));

        let before = calls.lock().await.len();
        assert!(migrate_local_keywords(&db, &client, "stub", Some("test-ik")).await.is_empty());
        assert_eq!(calls.lock().await.len(), before);
    }

    #[tokio::test]
    async fn the_keyword_migration_waits_for_an_unlocked_session() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        cache(&db, &["m-1"]);
        db.set_message_keywords("m-1", &strings(&["Fresh"])).unwrap();

        assert!(migrate_local_keywords(&db, &client, "stub", None).await.is_empty());
        assert!(calls.lock().await.is_empty());
        assert_eq!(db.get_sync_state(MIGRATION_STATE_KEY).unwrap(), None);
        assert_eq!(db.message_keywords("m-1").unwrap(), strings(&["Fresh"]));
    }

    #[tokio::test]
    async fn the_keyword_migration_stops_at_the_label_limit() {
        let (_dir, db, client, calls) = setup(CreateMode::Limit).await;
        cache(&db, &["m-1"]);
        db.set_message_keywords("m-1", &strings(&["Fresh", "Other"])).unwrap();

        assert!(migrate_local_keywords(&db, &client, "stub", Some("test-ik")).await.is_empty());
        assert_eq!(count(&calls, "create").await, 1);
        assert_eq!(db.get_sync_state(MIGRATION_STATE_KEY).unwrap().as_deref(), Some(MIGRATION_DONE));
        assert_eq!(db.message_keywords("m-1").unwrap(), strings(&["Fresh", "Other"]));
    }

    #[tokio::test]
    async fn the_keyword_migration_gives_up_after_repeated_failures() {
        let (_dir, db, client, calls) = setup(CreateMode::Fail).await;
        cache(&db, &["m-1"]);
        db.set_message_keywords("m-1", &strings(&["Fresh"])).unwrap();

        for _ in 0..MAX_MIGRATION_ATTEMPTS + 2 {
            assert!(migrate_local_keywords(&db, &client, "stub", Some("test-ik")).await.is_empty());
        }
        assert_eq!(count(&calls, "create").await, MAX_MIGRATION_ATTEMPTS as usize);
        assert_eq!(db.get_sync_state(MIGRATION_STATE_KEY).unwrap().as_deref(), Some(MIGRATION_DONE));
        assert_eq!(db.message_keywords("m-1").unwrap(), strings(&["Fresh"]));
    }

    #[tokio::test]
    async fn the_keyword_migration_resumes_after_the_creation_cap() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        cache(&db, &["m-1"]);
        let keywords: Vec<String> = (0..12).map(|n| format!("New{:02}", n)).collect();
        db.set_message_keywords("m-1", &keywords).unwrap();

        migrate_local_keywords(&db, &client, "stub", Some("test-ik")).await;
        assert_eq!(count(&calls, "create").await, 10);
        assert_eq!(db.get_sync_state(MIGRATION_STATE_KEY).unwrap().as_deref(), Some("0"));

        migrate_local_keywords(&db, &client, "stub", Some("test-ik")).await;
        assert_eq!(count(&calls, "create").await, 12);
        assert_eq!(db.message_tags(&strings(&["m-1"])).unwrap().get("m-1").unwrap().len(), 12);

        migrate_local_keywords(&db, &client, "stub", Some("test-ik")).await;
        assert_eq!(db.get_sync_state(MIGRATION_STATE_KEY).unwrap().as_deref(), Some(MIGRATION_DONE));
        assert_eq!(count(&calls, "create").await, 12);
    }

    #[tokio::test]
    async fn a_copy_takes_the_labels_of_its_source() {
        let (_dir, db, client, calls) = setup(CreateMode::Accept).await;
        db.replace_custom_tags(&[stored_tag("tok-work", "Work")]).unwrap();
        db.add_message_tag(&strings(&["src-1"]), "tok-work").unwrap();
        let pairs = vec![
            ("src-1".to_string(), "copy-1".to_string()),
            ("src-2".to_string(), "copy-2".to_string()),
        ];
        copy_tags(&db, &client, "stub", &pairs).await.unwrap();

        assert_eq!(db.message_keywords("copy-1").unwrap(), strings(&["Work"]));
        assert!(db.message_keywords("copy-2").unwrap().is_empty());
        let log = calls.lock().await.clone();
        assert_eq!(log.len(), 1, "{:?}", log);
        assert_eq!(log[0].0, "add");
        assert_eq!(log[0].1["ids"], serde_json::json!(["copy-1"]));
        assert_eq!(log[0].1["tag_token"], "tok-work");
    }
}
