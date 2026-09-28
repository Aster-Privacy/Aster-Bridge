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
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::db::{CustomFolder, JmapMailboxRow};

pub const LABEL_PREFIX: &str = "folder:";
pub const JMAP_ID_PREFIX: &str = "mbx_f_";
pub const SEPARATOR: char = '/';
pub const MAX_NAME_CHARS: usize = 100;
const SLASH_SUBSTITUTE: char = '\u{2215}';
const UNNAMED_FOLDER: &str = "Untitled";
const JMAP_SORT_BASE: i32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemMailbox {
    pub name: &'static str,
    pub label: &'static str,
    pub special_use: &'static str,
}

pub const SYSTEM_MAILBOXES: [SystemMailbox; 6] = [
    SystemMailbox { name: "INBOX", label: "inbox", special_use: "" },
    SystemMailbox { name: "Sent", label: "sent", special_use: "\\Sent" },
    SystemMailbox { name: "Drafts", label: "drafts", special_use: "\\Drafts" },
    SystemMailbox { name: "Trash", label: "trash", special_use: "\\Trash" },
    SystemMailbox { name: "Junk", label: "spam", special_use: "\\Junk" },
    SystemMailbox { name: "Archive", label: "archive", special_use: "\\Archive" },
];

pub fn folder_label(token: &str) -> String {
    format!("{}{}", LABEL_PREFIX, token)
}

pub fn token_of_label(label: &str) -> Option<&str> {
    label.strip_prefix(LABEL_PREFIX).filter(|t| !t.is_empty())
}

pub fn is_custom_label(label: &str) -> bool {
    token_of_label(label).is_some()
}

pub fn jmap_mailbox_id(token: &str) -> String {
    format!("{}{}", JMAP_ID_PREFIX, URL_SAFE_NO_PAD.encode(token.as_bytes()))
}

pub fn system_mailbox(name: &str) -> Option<&'static SystemMailbox> {
    SYSTEM_MAILBOXES
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(name))
}

pub fn system_mailbox_by_label(label: &str) -> Option<&'static SystemMailbox> {
    SYSTEM_MAILBOXES.iter().find(|m| m.label == label)
}

pub fn display_segment(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == SEPARATOR { SLASH_SUBSTITUTE } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        UNNAMED_FOLDER.to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn segment_to_name(segment: &str) -> String {
    segment.replace(SLASH_SUBSTITUTE, "/")
}

pub fn validate_name(name: &str) -> Result<(), &'static str> {
    let count = name.chars().count();
    if name.trim().is_empty() {
        return Err("folder name cannot be empty");
    }
    if count > MAX_NAME_CHARS {
        return Err("folder name is longer than 100 characters");
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("folder name contains control characters");
    }
    Ok(())
}

pub fn split_path(path: &str) -> Option<Vec<String>> {
    let trimmed = path.trim().trim_end_matches(SEPARATOR);
    if trimmed.is_empty() {
        return None;
    }
    let segments: Vec<String> = trimmed.split(SEPARATOR).map(|s| s.to_string()).collect();
    if segments.iter().any(|s| s.trim().is_empty()) {
        return None;
    }
    Some(segments)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderNode {
    pub token: String,
    pub server_id: String,
    pub name: String,
    pub parent_token: Option<String>,
    pub path: String,
    pub has_children: bool,
    pub position: usize,
}

fn sibling_order(a: &CustomFolder, b: &CustomFolder) -> Ordering {
    a.sort_order
        .cmp(&b.sort_order)
        .then_with(|| match (&a.created_at, &b.created_at) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| a.label_token.cmp(&b.label_token))
}

fn effective_parents<'a>(folders: &'a [CustomFolder]) -> HashMap<&'a str, Option<&'a str>> {
    let by_token: HashMap<&str, &CustomFolder> = folders
        .iter()
        .map(|f| (f.label_token.as_str(), f))
        .collect();
    let known = &by_token;
    let declared = |f: &'a CustomFolder| -> Option<&'a str> {
        f.parent_token
            .as_deref()
            .filter(|p| !p.is_empty() && *p != f.label_token && known.contains_key(p))
    };
    let mut out = HashMap::new();
    for f in folders {
        let parent = declared(f);
        let mut cursor = parent;
        let mut steps = 0usize;
        let mut cyclic = false;
        while let Some(p) = cursor {
            if p == f.label_token {
                cyclic = true;
                break;
            }
            steps += 1;
            if steps > folders.len() {
                break;
            }
            cursor = by_token.get(p).and_then(|pf| declared(pf));
        }
        out.insert(f.label_token.as_str(), if cyclic { None } else { parent });
    }
    out
}

fn unique_segment(base: &str, used: &mut HashSet<String>) -> String {
    let mut candidate = base.to_string();
    let mut n = 2u32;
    while used.contains(&candidate.to_lowercase()) {
        candidate = format!("{} ({})", base, n);
        n += 1;
    }
    used.insert(candidate.to_lowercase());
    candidate
}

pub fn build_tree(folders: &[CustomFolder]) -> Vec<FolderNode> {
    let mut unique: Vec<CustomFolder> = Vec::with_capacity(folders.len());
    let mut seen_tokens: HashSet<&str> = HashSet::new();
    for f in folders {
        if !f.label_token.is_empty() && seen_tokens.insert(f.label_token.as_str()) {
            unique.push(f.clone());
        }
    }
    let parents = effective_parents(&unique);
    let mut children: HashMap<Option<&str>, Vec<&CustomFolder>> = HashMap::new();
    for f in &unique {
        let parent = parents.get(f.label_token.as_str()).copied().flatten();
        children.entry(parent).or_default().push(f);
    }
    for list in children.values_mut() {
        list.sort_by(|a, b| sibling_order(a, b));
    }

    let mut out: Vec<FolderNode> = Vec::with_capacity(unique.len());
    let mut stack: Vec<(&CustomFolder, String)> = Vec::new();
    push_children(&children, None, None, &mut stack);
    while let Some((f, path)) = stack.pop() {
        let token = f.label_token.as_str();
        let has_children = children.get(&Some(token)).is_some_and(|c| !c.is_empty());
        out.push(FolderNode {
            token: f.label_token.clone(),
            server_id: f.server_id.clone(),
            name: f.name.clone(),
            parent_token: parents.get(token).copied().flatten().map(|p| p.to_string()),
            path: path.clone(),
            has_children,
            position: out.len(),
        });
        push_children(&children, Some(token), Some(&path), &mut stack);
    }
    out
}

fn push_children<'a>(
    children: &HashMap<Option<&'a str>, Vec<&'a CustomFolder>>,
    parent: Option<&'a str>,
    parent_path: Option<&str>,
    stack: &mut Vec<(&'a CustomFolder, String)>,
) {
    let Some(list) = children.get(&parent) else {
        return;
    };
    let mut used: HashSet<String> = HashSet::new();
    if parent.is_none() {
        for m in SYSTEM_MAILBOXES.iter() {
            used.insert(m.name.to_lowercase());
        }
    }
    let mut named: Vec<(&'a CustomFolder, String)> = Vec::with_capacity(list.len());
    for f in list {
        let segment = unique_segment(&display_segment(&f.name), &mut used);
        let path = match parent_path {
            Some(pp) => format!("{}{}{}", pp, SEPARATOR, segment),
            None => segment,
        };
        named.push((*f, path));
    }
    for entry in named.into_iter().rev() {
        stack.push(entry);
    }
}

pub fn jmap_rows(nodes: &[FolderNode]) -> Vec<JmapMailboxRow> {
    nodes
        .iter()
        .map(|n| JmapMailboxRow {
            id: jmap_mailbox_id(&n.token),
            name: {
                let trimmed = n.name.trim();
                if trimmed.is_empty() {
                    UNNAMED_FOLDER.to_string()
                } else {
                    trimmed.to_string()
                }
            },
            parent_id: n.parent_token.as_deref().map(jmap_mailbox_id),
            role: None,
            sort_order: JMAP_SORT_BASE.saturating_add(n.position.min(i32::MAX as usize / 2) as i32),
            folder_label: folder_label(&n.token),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    pub path: String,
    pub label: String,
    pub special_use: &'static str,
    pub has_children: bool,
    pub folder: Option<FolderNode>,
}

#[derive(Debug, Clone, Default)]
pub struct Directory {
    pub entries: Vec<MailboxEntry>,
}

impl Directory {
    pub fn build(folders: &[CustomFolder]) -> Self {
        let mut entries: Vec<MailboxEntry> = SYSTEM_MAILBOXES
            .iter()
            .map(|m| MailboxEntry {
                path: m.name.to_string(),
                label: m.label.to_string(),
                special_use: m.special_use,
                has_children: false,
                folder: None,
            })
            .collect();
        for node in build_tree(folders) {
            entries.push(MailboxEntry {
                path: node.path.clone(),
                label: folder_label(&node.token),
                special_use: "",
                has_children: node.has_children,
                folder: Some(node),
            });
        }
        Directory { entries }
    }

    pub fn resolve(&self, name: &str) -> Option<&MailboxEntry> {
        let trimmed = name.trim();
        let system_candidate = trimmed.trim_end_matches(SEPARATOR);
        if let Some(m) = system_mailbox(system_candidate) {
            return self.entries.iter().find(|e| e.label == m.label);
        }
        let wanted = trimmed.trim_end_matches(SEPARATOR);
        if wanted.is_empty() {
            return None;
        }
        let custom = || self.entries.iter().filter(|e| e.folder.is_some());
        if let Some(e) = custom().find(|e| e.path == wanted) {
            return Some(e);
        }
        let lowered = wanted.to_lowercase();
        let mut matches = custom().filter(|e| e.path.to_lowercase() == lowered);
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    pub fn by_label(&self, label: &str) -> Option<&MailboxEntry> {
        self.entries.iter().find(|e| e.label == label)
    }

    pub fn children_of(&self, token: &str) -> Vec<&FolderNode> {
        self.entries
            .iter()
            .filter_map(|e| e.folder.as_ref())
            .filter(|n| n.parent_token.as_deref() == Some(token))
            .collect()
    }

    pub fn is_descendant(&self, candidate: &str, ancestor: &str) -> bool {
        let nodes: HashMap<&str, &FolderNode> = self
            .entries
            .iter()
            .filter_map(|e| e.folder.as_ref())
            .map(|n| (n.token.as_str(), n))
            .collect();
        let mut cursor = Some(candidate);
        let mut steps = 0usize;
        while let Some(t) = cursor {
            if t == ancestor {
                return true;
            }
            steps += 1;
            if steps > nodes.len() {
                return false;
            }
            cursor = nodes.get(t).and_then(|n| n.parent_token.as_deref());
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(token: &str, name: &str, parent: Option<&str>, order: i64) -> CustomFolder {
        CustomFolder {
            label_token: token.to_string(),
            server_id: format!("id-{}", token),
            name: name.to_string(),
            parent_token: parent.map(|p| p.to_string()),
            sort_order: order,
            created_at: Some(format!("2026-01-01T00:00:0{}Z", order.clamp(0, 9))),
        }
    }

    fn paths(nodes: &[FolderNode]) -> Vec<&str> {
        nodes.iter().map(|n| n.path.as_str()).collect()
    }

    #[test]
    fn nested_folders_get_slash_paths_in_preorder() {
        let tree = build_tree(&[
            folder("c", "Receipts", Some("a"), 1),
            folder("a", "Work", None, 0),
            folder("b", "Travel", None, 1),
            folder("d", "2026", Some("c"), 0),
        ]);
        assert_eq!(paths(&tree), vec!["Work", "Work/Receipts", "Work/Receipts/2026", "Travel"]);
        assert!(tree[0].has_children);
        assert!(tree[1].has_children);
        assert!(!tree[2].has_children);
        assert_eq!(tree[1].parent_token.as_deref(), Some("a"));
        assert_eq!(tree.iter().map(|n| n.position).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn unknown_or_empty_parent_is_a_root() {
        let tree = build_tree(&[
            folder("a", "Orphan", Some("missing"), 0),
            folder("b", "Blank", Some(""), 1),
        ]);
        assert_eq!(paths(&tree), vec!["Orphan", "Blank"]);
        assert!(tree.iter().all(|n| n.parent_token.is_none()));
    }

    #[test]
    fn parent_cycles_are_broken_without_losing_folders() {
        let tree = build_tree(&[
            folder("a", "A", Some("b"), 0),
            folder("b", "B", Some("a"), 1),
            folder("c", "C", Some("a"), 2),
            folder("s", "Self", Some("s"), 3),
        ]);
        assert_eq!(tree.len(), 4);
        assert_eq!(paths(&tree), vec!["A", "A/C", "B", "Self"]);
    }

    #[test]
    fn slashes_in_names_do_not_create_hierarchy() {
        let tree = build_tree(&[folder("a", "2025/2026", None, 0)]);
        assert_eq!(tree[0].path, "2025\u{2215}2026");
        assert_eq!(segment_to_name(&tree[0].path), "2025/2026");
    }

    #[test]
    fn sibling_and_system_name_collisions_get_suffixes() {
        let tree = build_tree(&[
            folder("a", "Projects", None, 0),
            folder("b", "projects", None, 1),
            folder("c", "Inbox", None, 2),
            folder("d", "Archive", None, 3),
            folder("e", "Projects", Some("a"), 0),
        ]);
        assert_eq!(
            paths(&tree),
            vec!["Projects", "Projects/Projects", "projects (2)", "Inbox (2)", "Archive (2)"]
        );
    }

    #[test]
    fn blank_and_control_names_are_cleaned() {
        let tree = build_tree(&[folder("a", "  ", None, 0), folder("b", "Line\r\nBreak", None, 1)]);
        assert_eq!(paths(&tree), vec!["Untitled", "LineBreak"]);
    }

    #[test]
    fn duplicate_tokens_are_ignored() {
        let tree = build_tree(&[folder("a", "One", None, 0), folder("a", "Two", None, 1)]);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn jmap_rows_carry_parent_ids_and_labels() {
        let tree = build_tree(&[folder("a", "Work", None, 0), folder("b", "Clients", Some("a"), 0)]);
        let rows = jmap_rows(&tree);
        assert_eq!(rows[0].parent_id, None);
        assert_eq!(rows[1].parent_id.as_deref(), Some(rows[0].id.as_str()));
        assert_eq!(rows[1].name, "Clients");
        assert_eq!(rows[1].folder_label, "folder:b");
        assert!(rows[0].role.is_none());
        assert!(rows[0].sort_order < rows[1].sort_order);
        assert!(rows[0].sort_order > 6);
    }

    #[test]
    fn jmap_ids_are_url_safe_and_distinct() {
        let a = jmap_mailbox_id("ab+/cd==");
        let b = jmap_mailbox_id("ab+/cd=");
        assert_ne!(a, b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    }

    #[test]
    fn labels_round_trip() {
        assert_eq!(folder_label("tok"), "folder:tok");
        assert_eq!(token_of_label("folder:tok"), Some("tok"));
        assert_eq!(token_of_label("inbox"), None);
        assert_eq!(token_of_label("folder:"), None);
        assert!(is_custom_label("folder:x"));
        assert!(!is_custom_label("archive"));
    }

    #[test]
    fn directory_resolves_system_and_custom_names() {
        let dir = Directory::build(&[
            folder("a", "Work", None, 0),
            folder("b", "Clients", Some("a"), 0),
        ]);
        assert_eq!(dir.resolve("inbox").map(|e| e.label.as_str()), Some("inbox"));
        assert_eq!(dir.resolve("Archive/").map(|e| e.label.as_str()), Some("archive"));
        assert_eq!(dir.resolve("junk").map(|e| e.label.as_str()), Some("spam"));
        assert_eq!(dir.resolve("Work/Clients").map(|e| e.label.as_str()), Some("folder:b"));
        assert_eq!(dir.resolve("work/clients/").map(|e| e.label.as_str()), Some("folder:b"));
        assert!(dir.resolve("Work/Nope").is_none());
        assert!(dir.resolve("").is_none());
        assert!(dir.entries[0].folder.is_none());
        assert!(dir.by_label("folder:a").unwrap().has_children);
    }

    #[test]
    fn directory_prefers_exact_case_then_case_insensitive() {
        let dir = Directory::build(&[
            folder("a", "Team", None, 0),
            folder("b", "team", Some("a"), 0),
            folder("c", "TEAM", Some("a"), 1),
        ]);
        assert_eq!(dir.resolve("Team/team").map(|e| e.label.as_str()), Some("folder:b"));
        assert_eq!(dir.resolve("Team/TEAM (2)").map(|e| e.label.as_str()), Some("folder:c"));
        assert_eq!(dir.resolve("team/Team").map(|e| e.label.as_str()), Some("folder:b"));
        assert_eq!(dir.resolve("TEAM/team (2)").map(|e| e.label.as_str()), Some("folder:c"));
    }

    #[test]
    fn directory_descendant_checks() {
        let dir = Directory::build(&[
            folder("a", "A", None, 0),
            folder("b", "B", Some("a"), 0),
            folder("c", "C", Some("b"), 0),
        ]);
        assert!(dir.is_descendant("c", "a"));
        assert!(dir.is_descendant("a", "a"));
        assert!(!dir.is_descendant("a", "c"));
        assert_eq!(dir.children_of("a").len(), 1);
    }

    #[test]
    fn split_path_rejects_empty_segments() {
        assert_eq!(split_path("A/B/"), Some(vec!["A".to_string(), "B".to_string()]));
        assert_eq!(split_path("A//B"), None);
        assert_eq!(split_path("/"), None);
        assert_eq!(split_path(" "), None);
    }

    #[test]
    fn name_validation() {
        assert!(validate_name("Work").is_ok());
        assert!(validate_name(" ").is_err());
        assert!(validate_name(&"x".repeat(101)).is_err());
        assert!(validate_name(&"\u{e9}".repeat(100)).is_ok());
        assert!(validate_name("a\tb").is_err());
    }
}
