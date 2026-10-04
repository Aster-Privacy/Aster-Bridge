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
use crate::api_client::{ApiClient, CreateTagBody, UpdateTagBody};
use crate::db::{CustomTag, Database};
use crate::error::BridgeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagOpError {
    Locked,
    Invalid(String),
    AlreadyExists,
    NotFound,
    LimitReached,
    Busy,
    Server(String),
}

fn server_error(action: &str, e: &BridgeError) -> TagOpError {
    tracing::warn!("could not {}: {}", action, e);
    if crate::imap::append::is_rate_limited(e) {
        TagOpError::Busy
    } else if matches!(e, BridgeError::PlanLimit(_)) || e.to_string().contains("PLAN_LIMIT_EXCEEDED") {
        TagOpError::LimitReached
    } else {
        TagOpError::Server(action.to_string())
    }
}

fn clean_name(name: &str) -> Result<String, TagOpError> {
    let trimmed = name.trim();
    crate::tags::validate_name(trimmed).map_err(|msg| TagOpError::Invalid(msg.to_string()))?;
    Ok(trimmed.to_string())
}

fn name_taken(tags: &[CustomTag], name: &str, except: Option<&str>) -> bool {
    let wanted = name.to_lowercase();
    tags.iter()
        .any(|tag| Some(tag.tag_token.as_str()) != except && tag.name.to_lowercase() == wanted)
}

fn store(db: &Database, tag: CustomTag) -> Result<(), TagOpError> {
    let mut tags = db.list_custom_tags().map_err(TagOpError::Server)?;
    tags.retain(|existing| existing.tag_token != tag.tag_token);
    tags.push(tag);
    crate::tags::assign_keywords(&mut tags);
    db.replace_custom_tags(&tags)
        .map(|_| ())
        .map_err(TagOpError::Server)
}

pub async fn create(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: &str,
    name: &str,
) -> Result<String, TagOpError> {
    let name = clean_name(name)?;
    let tags = db.list_custom_tags().map_err(TagOpError::Server)?;
    if name_taken(&tags, &name, None) {
        return Err(TagOpError::AlreadyExists);
    }
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
    )?;
    Ok(tag_token)
}

pub async fn rename(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: &str,
    tag_token: &str,
    new_name: &str,
) -> Result<(), TagOpError> {
    let name = clean_name(new_name)?;
    let tags = db.list_custom_tags().map_err(TagOpError::Server)?;
    let Some(stored) = tags.iter().find(|tag| tag.tag_token == tag_token).cloned() else {
        return Err(TagOpError::NotFound);
    };
    if stored.name == name {
        return Ok(());
    }
    if name_taken(&tags, &name, Some(tag_token)) {
        return Err(TagOpError::AlreadyExists);
    }
    let (encrypted_name, name_nonce) = crate::crypto::tag::encrypt_tag_name(&name, identity_key)
        .map_err(|e| server_error("encrypt the label name", &e))?;
    let body = UpdateTagBody {
        encrypted_name: &encrypted_name,
        name_nonce: &name_nonce,
    };
    client
        .update_tag(access_token, &stored.server_id, &body)
        .await
        .map_err(|e| server_error("rename the label", &e))?;
    store(
        db,
        CustomTag {
            name,
            keyword: None,
            ..stored
        },
    )
}

pub async fn delete(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    tag_token: &str,
) -> Result<Vec<String>, TagOpError> {
    let tags = db.list_custom_tags().map_err(TagOpError::Server)?;
    let Some(stored) = tags.iter().find(|tag| tag.tag_token == tag_token) else {
        return Err(TagOpError::NotFound);
    };
    client
        .delete_tag(access_token, &stored.server_id)
        .await
        .map_err(|e| server_error("delete the label", &e))?;
    db.delete_custom_tag(tag_token).map_err(TagOpError::Server)
}

async fn ensure_tag(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
    keyword: &str,
) -> Result<Option<String>, TagOpError> {
    let tags = db.list_custom_tags().map_err(TagOpError::Server)?;
    if let Some(tag) = crate::tags::find_by_keyword(&tags, keyword) {
        return Ok(Some(tag.tag_token.clone()));
    }
    let Some(name) = crate::tags::name_for_keyword(keyword) else {
        return Ok(None);
    };
    let identity_key = identity_key.ok_or(TagOpError::Locked)?;
    match create(db, client, access_token, identity_key, &name).await {
        Ok(token) => Ok(Some(token)),
        Err(TagOpError::AlreadyExists) => Ok(None),
        Err(e) => Err(e),
    }
}

fn push_unique(list: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !list.contains(value) {
            list.push(value.clone());
        }
    }
}

pub async fn apply_keywords(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
    item_ids: &[String],
    op: i8,
    keywords: &[String],
) -> Result<Vec<String>, TagOpError> {
    if item_ids.is_empty() || (op != 0 && keywords.is_empty()) {
        return Ok(Vec::new());
    }
    let mut wanted: Vec<String> = Vec::new();
    for keyword in keywords {
        let token = if op == -1 {
            let tags = db.list_custom_tags().map_err(TagOpError::Server)?;
            crate::tags::find_by_keyword(&tags, keyword).map(|tag| tag.tag_token.clone())
        } else {
            ensure_tag(db, client, access_token, identity_key, keyword).await?
        };
        if let Some(token) = token {
            push_unique(&mut wanted, &[token]);
        }
    }
    let current = db.message_tags(item_ids).map_err(TagOpError::Server)?;
    let holders = |token: &String, present: bool| -> Vec<String> {
        item_ids
            .iter()
            .filter(|id| current.get(*id).is_some_and(|tokens| tokens.contains(token)) == present)
            .cloned()
            .collect()
    };
    let mut changed: Vec<String> = Vec::new();
    if op != -1 {
        for token in &wanted {
            let ids = holders(token, false);
            if ids.is_empty() {
                continue;
            }
            client
                .add_tag(access_token, &ids, token)
                .await
                .map_err(|e| server_error("add the label", &e))?;
            db.add_message_tag(&ids, token).map_err(TagOpError::Server)?;
            push_unique(&mut changed, &ids);
        }
    }
    let mut removals: Vec<String> = Vec::new();
    if op == -1 {
        removals = wanted.clone();
    } else if op == 0 {
        let exposed: Vec<String> = db
            .list_custom_tags()
            .map_err(TagOpError::Server)?
            .into_iter()
            .filter(|tag| tag.keyword.is_some())
            .map(|tag| tag.tag_token)
            .collect();
        for tokens in current.values() {
            let extra: Vec<String> = tokens
                .iter()
                .filter(|token| !wanted.contains(token) && exposed.contains(token))
                .cloned()
                .collect();
            push_unique(&mut removals, &extra);
        }
    }
    for token in &removals {
        let ids = holders(token, true);
        if ids.is_empty() {
            continue;
        }
        client
            .remove_tag(access_token, &ids, token)
            .await
            .map_err(|e| server_error("remove the label", &e))?;
        db.remove_message_tag(&ids, token).map_err(TagOpError::Server)?;
        push_unique(&mut changed, &ids);
    }
    Ok(changed)
}
