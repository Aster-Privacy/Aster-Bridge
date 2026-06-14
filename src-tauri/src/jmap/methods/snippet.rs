//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::sync::Arc;

use serde_json::{json, Value};

use crate::jmap::dispatcher::MethodError;
use crate::jmap::state::JmapContext;

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let email_ids: Vec<String> = args
        .get("emailIds")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if email_ids.len() > 500 {
        return Err(MethodError::new("requestTooLarge", "too many emailIds"));
    }
    let filter = args.get("filter").cloned().unwrap_or(Value::Null);
    let term = extract_text_filter(&filter).unwrap_or_default();

    let mut list = Vec::new();
    let mut not_found = Vec::new();

    for id in &email_ids {
        let cached = ctx.db.get_cached_message(id).ok().flatten();
        let Some(m) = cached else {
            not_found.push(id.clone());
            continue;
        };

        let (subject_snip, body_snip) = if term.is_empty() {
            (
                Value::String(html_escape(&truncate_chars(m.subject.as_deref().unwrap_or(""), 200))),
                Value::String(html_escape(&truncate_chars(m.body_text.as_deref().unwrap_or(""), 200))),
            )
        } else {
            match ctx.db.fts_snippet(id, &term) {
                Ok(Some((subj, body))) => (
                    subj.map(Value::String).unwrap_or(Value::Null),
                    body.map(Value::String).unwrap_or(Value::Null),
                ),
                _ => (
                    Value::String(html_escape(&truncate_chars(m.subject.as_deref().unwrap_or(""), 200))),
                    Value::String(make_substring_snippet(
                        m.body_text.as_deref().unwrap_or(""),
                        &term,
                    )),
                ),
            }
        };

        list.push(json!({
            "emailId": id,
            "subject": subject_snip,
            "preview": body_snip,
        }));
    }

    Ok(json!({
        "accountId": account_id,
        "list": list,
        "notFound": not_found,
    }))
}

fn extract_text_filter(f: &Value) -> Option<String> {
    if let Some(t) = f.get("text").and_then(|v| v.as_str()) {
        return Some(t.to_string());
    }
    if let Some(t) = f.get("subject").and_then(|v| v.as_str()) {
        return Some(t.to_string());
    }
    if let Some(t) = f.get("body").and_then(|v| v.as_str()) {
        return Some(t.to_string());
    }
    if let Some(conds) = f.get("conditions").and_then(|v| v.as_array()) {
        for c in conds {
            if let Some(t) = extract_text_filter(c) {
                return Some(t);
            }
        }
    }
    None
}

fn truncate_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn make_substring_snippet(text: &str, term: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let max_chars = 200usize;
    let needle = term.to_lowercase();
    let lower_full = text.to_lowercase();
    let Some(match_byte) = lower_full.find(&needle) else {
        return truncate_chars(text, max_chars);
    };
    let pre_chars = lower_full[..match_byte].chars().count();
    let needle_chars = needle.chars().count();
    let window_start = pre_chars.saturating_sub(40);
    let collected: Vec<char> = text.chars().skip(window_start).take(max_chars).collect();
    let local_match = pre_chars - window_start;
    if local_match + needle_chars > collected.len() {
        return collected.iter().collect();
    }
    let prefix: String = collected[..local_match].iter().collect();
    let middle: String = collected[local_match..local_match + needle_chars].iter().collect();
    let suffix: String = collected[local_match + needle_chars..].iter().collect();
    format!("{}<mark>{}</mark>{}", html_escape(&prefix), html_escape(&middle), html_escape(&suffix))
}
