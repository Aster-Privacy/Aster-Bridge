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

use serde_json::{Map, Value};

pub const MAX_RELATION_VALUE_LENGTH: usize = 200;
pub const MAX_RELATION_LABEL_LENGTH: usize = 50;
pub const MAX_RELATIONS: usize = 50;
pub const MAX_SOCIAL_VALUE_LENGTH: usize = 500;
pub const MAX_SOCIAL_LABEL_LENGTH: usize = 50;
pub const MAX_SOCIAL_NETWORKS: usize = 50;

const DIRECT_KINDS: &[&str] = &[
    "friend",
    "manager",
    "partner",
    "assistant",
    "spouse",
    "child",
    "mother",
    "father",
    "brother",
    "sister",
    "relative",
    "parent",
    "sibling",
];

const SOCIAL_TYPES: &[&str] = &[
    "twitter",
    "linkedin",
    "github",
    "instagram",
    "facebook",
    "mastodon",
    "bluesky",
];

const IGNORED_RELATION_TOKENS: &[&str] = &[
    "pref", "text", "uri", "voice", "internet", "other", "custom",
];

const IGNORED_SOCIAL_TOKENS: &[&str] = &[
    "pref", "other", "custom", "internet", "home", "work", "text", "uri", "url", "x-user",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    pub kind: String,
    pub label: String,
    pub value: String,
}

fn is_custom_type(value: &str) -> bool {
    matches!(value, "" | "other" | "custom")
}

pub fn clean_text(raw: &str, max_chars: usize) -> String {
    let replaced: String = raw
        .chars()
        .map(|c| {
            if (c as u32) <= 0x1f || c == '\u{7f}' || c == '\u{2028}' || c == '\u{2029}' {
                ' '
            } else {
                c
            }
        })
        .collect();
    let truncated: String = replaced.trim().chars().take(max_chars).collect();
    truncated.trim().to_string()
}

fn lower_field(entry: &Map<String, Value>, key: &str) -> String {
    entry
        .get(key)
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_lowercase())
        .unwrap_or_default()
}

pub fn decode_relation(entry: &Value) -> Option<Relation> {
    let record = entry.as_object()?;
    let value = record.get("value")?.as_str()?.to_string();
    let kind_type = lower_field(record, "type");
    let relation = lower_field(record, "relation");
    let label = record
        .get("label")
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let build = |kind: &str, label: String| Relation {
        kind: kind.to_string(),
        label,
        value: value.clone(),
    };

    if (relation == "mother" || relation == "father") && kind_type == "parent" {
        return Some(build(&relation, String::new()));
    }
    if (relation == "brother" || relation == "sister") && kind_type == "sibling" {
        return Some(build(&relation, String::new()));
    }
    if relation == "relative" && is_custom_type(&kind_type) {
        return Some(build("relative", String::new()));
    }
    if DIRECT_KINDS.contains(&kind_type.as_str()) {
        return Some(build(&kind_type, String::new()));
    }
    if is_custom_type(&kind_type) {
        return Some(build("custom", label));
    }
    let raw_type = record
        .get("type")
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let label = if label.is_empty() { raw_type } else { label };
    Some(build("custom", label))
}

pub fn encode_relation(kind: &str, label: &str, value: &str) -> Value {
    match kind {
        "mother" | "father" => {
            serde_json::json!({ "value": value, "type": "parent", "relation": kind })
        }
        "brother" | "sister" => {
            serde_json::json!({ "value": value, "type": "sibling", "relation": kind })
        }
        "relative" => {
            serde_json::json!({ "value": value, "type": "other", "relation": "relative" })
        }
        "custom" => {
            if label.trim().is_empty() {
                serde_json::json!({ "value": value, "type": "other" })
            } else {
                serde_json::json!({ "value": value, "type": "other", "label": label })
            }
        }
        other => serde_json::json!({ "value": value, "type": other }),
    }
}

fn english_name(kind: &str) -> &'static str {
    match kind {
        "friend" => "Friend",
        "manager" => "Manager",
        "partner" => "Partner",
        "assistant" => "Assistant",
        "spouse" => "Spouse",
        "relative" => "Relative",
        "child" => "Child",
        "mother" => "Mother",
        "father" => "Father",
        "brother" => "Brother",
        "sister" => "Sister",
        "parent" => "Parent",
        "sibling" => "Sibling",
        _ => "Custom",
    }
}

fn label_alias(raw: &str) -> Option<&'static str> {
    Some(match raw {
        "friend" => "friend",
        "manager" | "supervisor" => "manager",
        "partner" | "domestic partner" | "domestic_partner" => "partner",
        "assistant" => "assistant",
        "spouse" => "spouse",
        "child" => "child",
        "mother" => "mother",
        "father" => "father",
        "brother" => "brother",
        "sister" => "sister",
        "parent" => "parent",
        "sibling" => "sibling",
        "relative" => "relative",
        _ => return None,
    })
}

fn vcard_type_alias(raw: &str) -> Option<&'static str> {
    Some(match raw {
        "kin" | "relative" => "relative",
        "domestic-partner" => "partner",
        other => return label_alias(other),
    })
}

pub fn unwrap_apple_label(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix("_$!<")
        .and_then(|rest| rest.strip_suffix(">!$_"))
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

pub fn relation_from_label(raw: &str) -> (String, String) {
    let inner = unwrap_apple_label(raw);
    match label_alias(&inner.to_lowercase()) {
        Some(kind) => (kind.to_string(), String::new()),
        None => ("custom".to_string(), inner),
    }
}

pub fn relation_from_types(types: &[String]) -> (String, String) {
    let mut fallback = String::new();
    for raw in types {
        let token = raw.trim().to_lowercase();
        if token.is_empty()
            || IGNORED_RELATION_TOKENS.contains(&token.as_str())
            || token.starts_with("x-")
        {
            continue;
        }
        if let Some(kind) = vcard_type_alias(&token) {
            return (kind.to_string(), String::new());
        }
        if fallback.is_empty() {
            fallback = raw.trim().to_string();
        }
    }
    ("custom".to_string(), fallback)
}

pub fn relation_from_android_type(type_int: i64, label: &str) -> (String, String) {
    let mapped = match type_int {
        1 => "assistant",
        2 => "brother",
        3 => "child",
        4 | 10 => "partner",
        5 => "father",
        6 => "friend",
        7 => "manager",
        8 => "mother",
        9 => "parent",
        12 => "relative",
        13 => "sister",
        14 => "spouse",
        11 => return ("custom".to_string(), "Referred by".to_string()),
        _ => "",
    };
    if !mapped.is_empty() {
        return (mapped.to_string(), String::new());
    }
    if label.trim().is_empty() {
        return ("custom".to_string(), String::new());
    }
    relation_from_label(label)
}

pub fn relation_vcard_type(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "friend" => "friend",
        "spouse" => "spouse",
        "child" => "child",
        "mother" | "father" | "parent" => "parent",
        "brother" | "sister" | "sibling" => "sibling",
        "relative" => "kin",
        _ => return None,
    })
}

pub fn relation_ab_label(relation: &Relation) -> String {
    match relation.kind.as_str() {
        "custom" => relation.label.clone(),
        "relative" => english_name("relative").to_string(),
        kind => format!("_$!<{}>!$_", english_name(kind)),
    }
}

fn dedupe_key(kind: &str, label: &str, value: &str) -> String {
    format!("{}\u{0}{}\u{0}{}", kind, label.to_lowercase(), value.to_lowercase())
}

pub fn normalize_related_people(entries: Vec<Value>) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for entry in entries {
        if result.len() >= MAX_RELATIONS {
            break;
        }
        let Some(mut record) = entry.as_object().cloned() else {
            continue;
        };
        let Some(raw_value) = record.get("value").and_then(|v| v.as_str()) else {
            continue;
        };
        let value = clean_text(raw_value, MAX_RELATION_VALUE_LENGTH);
        if value.is_empty() {
            continue;
        }
        record.insert("value".to_string(), Value::from(value));
        if let Some(raw_label) = record.get("label").and_then(|v| v.as_str()) {
            let label = clean_text(raw_label, MAX_RELATION_LABEL_LENGTH);
            if label.is_empty() {
                record.remove("label");
            } else {
                record.insert("label".to_string(), Value::from(label));
            }
        }
        let next = Value::Object(record);
        let Some(decoded) = decode_relation(&next) else {
            continue;
        };
        let label = if decoded.kind == "custom" {
            decoded.label.as_str()
        } else {
            ""
        };
        if seen.insert(dedupe_key(&decoded.kind, label, &decoded.value)) {
            result.push(next);
        }
    }
    result
}

pub fn is_known_social(kind: &str) -> bool {
    SOCIAL_TYPES.contains(&kind)
}

pub fn social_type_from_token(raw: &str) -> Option<&'static str> {
    Some(match raw.trim().to_lowercase().as_str() {
        "twitter" | "x" => "twitter",
        "linkedin" => "linkedin",
        "github" => "github",
        "instagram" => "instagram",
        "facebook" => "facebook",
        "mastodon" => "mastodon",
        "bluesky" | "bsky" => "bluesky",
        _ => return None,
    })
}

pub fn social_type_param(label: &str) -> String {
    let mut out = String::new();
    for c in label.chars() {
        if c.is_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let collapsed = out.trim_matches('-').to_string();
    collapsed.chars().take(MAX_SOCIAL_LABEL_LENGTH).collect()
}

pub fn social_from_tokens(tokens: &[String], group_label: Option<&str>) -> (String, Option<String>) {
    for token in tokens {
        if let Some(kind) = social_type_from_token(token) {
            return (kind.to_string(), None);
        }
    }
    let grouped = clean_text(&unwrap_apple_label(group_label.unwrap_or("")), MAX_SOCIAL_LABEL_LENGTH);
    if !grouped.is_empty() {
        if let Some(kind) = social_type_from_token(&grouped) {
            return (kind.to_string(), None);
        }
        return ("other".to_string(), Some(grouped));
    }
    for token in tokens {
        let trimmed = token.trim();
        let lowered = trimmed.to_lowercase();
        if trimmed.is_empty()
            || IGNORED_SOCIAL_TOKENS.contains(&lowered.as_str())
            || lowered.starts_with("x-")
        {
            continue;
        }
        return (
            "other".to_string(),
            Some(clean_text(trimmed, MAX_SOCIAL_LABEL_LENGTH)),
        );
    }
    ("other".to_string(), None)
}

pub fn normalize_social_networks(entries: Vec<Value>) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for entry in entries {
        if result.len() >= MAX_SOCIAL_NETWORKS {
            break;
        }
        let Some(mut record) = entry.as_object().cloned() else {
            continue;
        };
        let Some(raw_value) = record.get("value").and_then(|v| v.as_str()) else {
            continue;
        };
        let value = clean_text(raw_value, MAX_SOCIAL_VALUE_LENGTH);
        if value.is_empty() {
            continue;
        }
        record.insert("value".to_string(), Value::from(value.clone()));
        let kind = record
            .get("type")
            .and_then(|v| v.as_str())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "other".to_string());
        record.insert("type".to_string(), Value::from(kind.clone()));
        let mut label = String::new();
        if let Some(raw_label) = record.get("label").and_then(|v| v.as_str()) {
            label = clean_text(raw_label, MAX_SOCIAL_LABEL_LENGTH);
            if label.is_empty() {
                record.remove("label");
            } else {
                record.insert("label".to_string(), Value::from(label.clone()));
            }
        }
        let key_label = if kind == "other" { label.as_str() } else { "" };
        if seen.insert(dedupe_key(&kind, key_label, &value)) {
            result.push(Value::Object(record));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_picker_kind_round_trips_through_the_encoding() {
        for kind in [
            "friend", "manager", "partner", "assistant", "spouse", "relative", "child", "mother",
            "father", "brother", "sister", "custom",
        ] {
            let label = if kind == "custom" { "Coach" } else { "" };
            let decoded = decode_relation(&encode_relation(kind, label, "Pat")).unwrap();
            assert_eq!(decoded.kind, kind);
            assert_eq!(decoded.label, label);
            assert_eq!(decoded.value, "Pat");
        }
    }

    #[test]
    fn an_unknown_type_reads_as_a_custom_label() {
        let decoded = decode_relation(&serde_json::json!({ "value": "Noor", "type": "godmother" }))
            .unwrap();
        assert_eq!(decoded.kind, "custom");
        assert_eq!(decoded.label, "godmother");
    }

    #[test]
    fn normalizing_drops_blank_rows_caps_lengths_and_dedupes() {
        let long: String = "\u{1F600}".repeat(MAX_RELATION_VALUE_LENGTH + 5);
        let result = normalize_related_people(vec![
            serde_json::json!({ "value": "   ", "type": "friend" }),
            serde_json::json!({ "value": "Sam", "type": "friend" }),
            serde_json::json!({ "value": "sam", "type": "friend" }),
            serde_json::json!({ "value": "Rui", "type": "other", "label": "  " }),
            serde_json::json!({ "value": long, "type": "friend" }),
            serde_json::json!({ "value": "Noor", "type": "godmother", "since": "2020" }),
            serde_json::json!("junk"),
        ]);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], serde_json::json!({ "value": "Sam", "type": "friend" }));
        assert_eq!(result[1], serde_json::json!({ "value": "Rui", "type": "other" }));
        assert_eq!(
            result[2]["value"].as_str().unwrap().chars().count(),
            MAX_RELATION_VALUE_LENGTH
        );
        assert_eq!(result[3]["since"], "2020");
    }

    #[test]
    fn import_mappings_cover_apple_android_and_vcard_types() {
        assert_eq!(relation_from_label("_$!<Mother>!$_"), ("mother".into(), String::new()));
        assert_eq!(relation_from_label("Godparent"), ("custom".into(), "Godparent".into()));
        assert_eq!(
            relation_from_types(&["PREF".into(), "kin".into()]),
            ("relative".into(), String::new())
        );
        assert_eq!(
            relation_from_types(&["co-worker".into()]),
            ("custom".into(), "co-worker".into())
        );
        assert_eq!(relation_from_android_type(8, ""), ("mother".into(), String::new()));
        assert_eq!(relation_from_android_type(0, "Godparent"), ("custom".into(), "Godparent".into()));
    }

    #[test]
    fn social_tokens_resolve_known_types_then_labels() {
        assert_eq!(social_from_tokens(&["x".into()], None), ("twitter".into(), None));
        assert_eq!(
            social_from_tokens(&["Band".into()], Some("_$!<Band page>!$_")),
            ("other".into(), Some("Band page".into()))
        );
        assert_eq!(
            social_from_tokens(&["Strava".into()], None),
            ("other".into(), Some("Strava".into()))
        );
        assert_eq!(social_from_tokens(&["pref".into()], None), ("other".into(), None));
        assert_eq!(social_type_param("Band page; x=1:2"), "Band-page-x-1-2");
    }

    #[test]
    fn social_normalizing_trims_and_dedupes() {
        let result = normalize_social_networks(vec![
            serde_json::json!({ "value": " ", "type": "other", "label": "Empty" }),
            serde_json::json!({ "value": " pat ", "type": "other", "label": " Coach " }),
            serde_json::json!({ "value": "Pat", "type": "other", "label": "coach" }),
            serde_json::json!({ "value": "w" }),
        ]);
        assert_eq!(
            result,
            vec![
                serde_json::json!({ "value": "pat", "type": "other", "label": "Coach" }),
                serde_json::json!({ "value": "w", "type": "other" }),
            ]
        );
    }
}
