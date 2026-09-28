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
use std::collections::HashSet;

use serde_json::{json, Value};

use crate::api_client::{ApiClient, CreateFolderBody, UpdateFolderBody};
use crate::db::{CustomFolder, Database};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderOpError {
    Locked,
    Invalid(String),
    AlreadyExists,
    NotFound,
    ParentNotFound,
    SystemMailbox,
    HasChildren,
    Cycle,
    Busy,
    Server(String),
}

impl FolderOpError {
    pub fn imap_response(&self) -> String {
        match self {
            Self::Locked => {
                "[UNAVAILABLE] folder keys are not unlocked yet; try again after sign-in finishes"
                    .to_string()
            }
            Self::Invalid(msg) => format!("[CANNOT] {}", msg),
            Self::AlreadyExists => "[ALREADYEXISTS] mailbox already exists".to_string(),
            Self::NotFound | Self::ParentNotFound => "[NONEXISTENT] No such mailbox".to_string(),
            Self::SystemMailbox => "[CANNOT] system mailboxes cannot be changed".to_string(),
            Self::HasChildren => "[CANNOT] delete the subfolders first".to_string(),
            Self::Cycle => "[CANNOT] a folder cannot be moved inside itself".to_string(),
            Self::Busy => "[UNAVAILABLE] Aster is busy; try again in a moment".to_string(),
            Self::Server(action) => format!("[SERVERBUG] could not {} on the server", action),
        }
    }

    pub fn jmap_set_error(&self) -> Value {
        match self {
            Self::Locked => json!({
                "type": "forbidden",
                "description": "folder keys are not unlocked yet; try again after sign-in finishes"
            }),
            Self::Invalid(msg) => json!({
                "type": "invalidProperties",
                "properties": ["name"],
                "description": msg
            }),
            Self::AlreadyExists => json!({
                "type": "invalidProperties",
                "properties": ["name"],
                "description": "a mailbox with this name already exists here"
            }),
            Self::NotFound => json!({"type": "notFound"}),
            Self::ParentNotFound => json!({
                "type": "invalidProperties",
                "properties": ["parentId"],
                "description": "unknown parent mailbox"
            }),
            Self::SystemMailbox => json!({
                "type": "forbidden",
                "description": "system mailboxes cannot be changed"
            }),
            Self::HasChildren => json!({
                "type": "mailboxHasChild",
                "description": "delete the subfolders first"
            }),
            Self::Cycle => json!({
                "type": "invalidProperties",
                "properties": ["parentId"],
                "description": "a mailbox cannot be moved inside itself"
            }),
            Self::Busy => json!({
                "type": "rateLimit",
                "description": "Aster is busy; try again in a moment"
            }),
            Self::Server(action) => json!({
                "type": "serverFail",
                "description": format!("could not {} on the server", action)
            }),
        }
    }
}

fn server_error(action: &str, e: &crate::error::BridgeError) -> FolderOpError {
    tracing::warn!("could not {}: {}", action, e);
    if crate::imap::append::is_rate_limited(e) {
        FolderOpError::Busy
    } else {
        FolderOpError::Server(action.to_string())
    }
}

fn effective_parent<'a>(folders: &'a [CustomFolder], folder: &'a CustomFolder) -> Option<&'a str> {
    folder
        .parent_token
        .as_deref()
        .filter(|p| *p != folder.label_token && folders.iter().any(|f| f.label_token == *p))
}

fn clean_name(name: &str) -> Result<String, FolderOpError> {
    let trimmed = name.trim();
    crate::folders::validate_name(trimmed)
        .map_err(|msg| FolderOpError::Invalid(msg.to_string()))?;
    Ok(trimmed.to_string())
}

fn sibling_conflict(
    folders: &[CustomFolder],
    parent: Option<&str>,
    name: &str,
    except: Option<&str>,
) -> bool {
    if parent.is_none() && crate::folders::system_mailbox(name).is_some() {
        return true;
    }
    let wanted = name.to_lowercase();
    folders.iter().any(|f| {
        Some(f.label_token.as_str()) != except
            && effective_parent(folders, f) == parent
            && f.name.trim().to_lowercase() == wanted
    })
}

fn creates_cycle(folders: &[CustomFolder], token: &str, new_parent: Option<&str>) -> bool {
    let mut cursor = new_parent;
    let mut seen: HashSet<&str> = HashSet::new();
    while let Some(current) = cursor {
        if current == token {
            return true;
        }
        if !seen.insert(current) {
            return false;
        }
        cursor = folders
            .iter()
            .find(|f| f.label_token == current)
            .and_then(|f| effective_parent(folders, f));
    }
    false
}

pub fn has_children(folders: &[CustomFolder], token: &str) -> bool {
    folders
        .iter()
        .any(|f| f.label_token != token && effective_parent(folders, f) == Some(token))
}

pub async fn create(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: &str,
    name: &str,
    parent: Option<&str>,
) -> Result<String, FolderOpError> {
    let name = clean_name(name)?;
    let folders = db.list_custom_folders().map_err(FolderOpError::Server)?;
    if let Some(p) = parent {
        if !folders.iter().any(|f| f.label_token == p) {
            return Err(FolderOpError::ParentNotFound);
        }
    }
    if sibling_conflict(&folders, parent, &name, None) {
        return Err(FolderOpError::AlreadyExists);
    }
    let (encrypted_name, name_nonce) =
        crate::crypto::folder::encrypt_folder_name(&name, identity_key)
            .map_err(|e| server_error("encrypt the folder name", &e))?;
    let label_token = crate::crypto::folder::generate_folder_token();
    let body = CreateFolderBody {
        label_token: &label_token,
        encrypted_name: &encrypted_name,
        name_nonce: &name_nonce,
        folder_type: "custom",
        parent_token: parent,
    };
    let server_id = client
        .create_folder(access_token, &body)
        .await
        .map_err(|e| server_error("create the folder", &e))?;
    db.upsert_custom_folder(&CustomFolder {
        label_token: label_token.clone(),
        server_id,
        name,
        parent_token: parent.map(str::to_string),
        sort_order: 0,
        created_at: None,
    })
    .map_err(FolderOpError::Server)?;
    Ok(label_token)
}

pub async fn update(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: &str,
    token: &str,
    new_name: Option<&str>,
    new_parent: Option<Option<&str>>,
) -> Result<(), FolderOpError> {
    let folders = db.list_custom_folders().map_err(FolderOpError::Server)?;
    let Some(stored) = folders.iter().find(|f| f.label_token == token).cloned() else {
        return Err(FolderOpError::NotFound);
    };
    let name = match new_name {
        Some(n) => clean_name(n)?,
        None => stored.name.clone(),
    };
    let current_parent = effective_parent(&folders, &stored).map(str::to_string);
    let parent: Option<String> = match new_parent {
        Some(p) => p.map(str::to_string),
        None => current_parent.clone(),
    };
    if let Some(p) = parent.as_deref() {
        if !folders.iter().any(|f| f.label_token == p) {
            return Err(FolderOpError::ParentNotFound);
        }
        if creates_cycle(&folders, token, Some(p)) {
            return Err(FolderOpError::Cycle);
        }
    }
    if name == stored.name && parent == current_parent {
        return Ok(());
    }
    if sibling_conflict(&folders, parent.as_deref(), &name, Some(token)) {
        return Err(FolderOpError::AlreadyExists);
    }
    let (encrypted_name, name_nonce) =
        crate::crypto::folder::encrypt_folder_name(&name, identity_key)
            .map_err(|e| server_error("encrypt the folder name", &e))?;
    let body = UpdateFolderBody {
        encrypted_name: Some(&encrypted_name),
        name_nonce: Some(&name_nonce),
        parent_token: Some(parent.as_deref().unwrap_or("")),
    };
    client
        .update_folder(access_token, &stored.server_id, &body)
        .await
        .map_err(|e| server_error("update the folder", &e))?;
    db.upsert_custom_folder(&CustomFolder {
        name,
        parent_token: parent,
        ..stored
    })
    .map_err(FolderOpError::Server)?;
    Ok(())
}

pub async fn delete(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    token: &str,
) -> Result<Vec<String>, FolderOpError> {
    let folders = db.list_custom_folders().map_err(FolderOpError::Server)?;
    let Some(stored) = folders.iter().find(|f| f.label_token == token) else {
        return Err(FolderOpError::NotFound);
    };
    if has_children(&folders, token) {
        return Err(FolderOpError::HasChildren);
    }
    client
        .delete_folder(access_token, &stored.server_id)
        .await
        .map_err(|e| server_error("delete the folder", &e))?;
    db.delete_custom_folder(token).map_err(FolderOpError::Server)?;
    let moved = db
        .relocate_folder_messages(&crate::folders::folder_label(token), "inbox")
        .map_err(FolderOpError::Server)?;
    if !moved.is_empty() {
        let ids: Vec<&str> = moved.iter().map(|s| s.as_str()).collect();
        let _ = db.jmap_record_updated_batch("Email", &ids);
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(token: &str, name: &str, parent: Option<&str>) -> CustomFolder {
        CustomFolder {
            label_token: token.to_string(),
            server_id: format!("srv-{}", token),
            name: name.to_string(),
            parent_token: parent.map(str::to_string),
            sort_order: 0,
            created_at: None,
        }
    }

    #[test]
    fn sibling_conflict_is_case_insensitive_and_scoped_to_the_parent() {
        let folders = vec![
            folder("a", "Work", None),
            folder("b", "Reports", Some("a")),
            folder("c", "Orphan", Some("gone")),
        ];
        assert!(sibling_conflict(&folders, None, "work", None));
        assert!(!sibling_conflict(&folders, None, "work", Some("a")));
        assert!(sibling_conflict(&folders, Some("a"), "REPORTS", None));
        assert!(!sibling_conflict(&folders, None, "Reports", None));
        assert!(sibling_conflict(&folders, None, "orphan", None));
        assert!(sibling_conflict(&folders, None, "inbox", None));
        assert!(!sibling_conflict(&folders, Some("a"), "Inbox", None));
    }

    #[test]
    fn creates_cycle_detects_self_and_descendants() {
        let folders = vec![
            folder("a", "A", None),
            folder("b", "B", Some("a")),
            folder("c", "C", Some("b")),
        ];
        assert!(creates_cycle(&folders, "a", Some("a")));
        assert!(creates_cycle(&folders, "a", Some("c")));
        assert!(!creates_cycle(&folders, "c", Some("a")));
        assert!(!creates_cycle(&folders, "b", None));
    }

    #[test]
    fn has_children_ignores_dangling_parents() {
        let folders = vec![folder("a", "A", None), folder("b", "B", Some("a"))];
        assert!(has_children(&folders, "a"));
        assert!(!has_children(&folders, "b"));
    }

    #[test]
    fn errors_map_to_imap_codes_and_jmap_types() {
        assert!(FolderOpError::AlreadyExists.imap_response().starts_with("[ALREADYEXISTS]"));
        assert!(FolderOpError::Busy.imap_response().starts_with("[UNAVAILABLE]"));
        assert_eq!(FolderOpError::HasChildren.jmap_set_error()["type"], json!("mailboxHasChild"));
        assert_eq!(FolderOpError::Cycle.jmap_set_error()["properties"], json!(["parentId"]));
        assert_eq!(FolderOpError::Busy.jmap_set_error()["type"], json!("rateLimit"));
    }
}
