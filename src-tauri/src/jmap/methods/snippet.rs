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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;
    use crate::db::Database;
    use tokio::sync::{broadcast, RwLock};
    use uuid::Uuid;

    fn ok(r: Result<Value, MethodError>) -> Value {
        match r {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got error: {} {}", e.kind, e.message),
        }
    }

    fn err_kind(r: Result<Value, MethodError>) -> String {
        match r {
            Ok(_) => panic!("expected error, got ok"),
            Err(e) => e.kind,
        }
    }

    fn test_ctx() -> (Arc<JmapContext>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_with_key(dir.path(), &[8u8; 32]).unwrap());
        db.seed_jmap_mailboxes().unwrap();
        let session = Arc::new(RwLock::new(Session {
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_keys: Vec::new(),
            send_identities: Vec::new(),
        }));
        let client = Arc::new(crate::api_client::ApiClient::new());
        let (tx, _rx) = broadcast::channel(8);
        (JmapContext::new(session, db, client, tx), dir)
    }

    fn add_msg(ctx: &Arc<JmapContext>, id: &str, subject: &str, body: &str) {
        ctx.db
            .upsert_cached_message(id, "inbox", Some(subject), Some("a@b.com"), Some("c@d.com"), Some("2026-01-01T00:00:00Z"), 10, Some(body), Some("{}"))
            .unwrap();
    }

    #[test]
    fn html_escape_all_specials() {
        assert_eq!(html_escape("<a> & \"b\""), "&lt;a&gt; &amp; &quot;b&quot;");
    }

    #[test]
    fn truncate_chars_respects_unicode_boundaries() {
        assert_eq!(truncate_chars("héllo", 3), "hél");
        assert_eq!(truncate_chars("ab", 10), "ab");
    }

    #[test]
    fn extract_text_filter_priority_and_nested() {
        assert_eq!(extract_text_filter(&json!({"text": "x"})), Some("x".to_string()));
        assert_eq!(extract_text_filter(&json!({"subject": "y"})), Some("y".to_string()));
        let nested = json!({"conditions": [{"body": "z"}]});
        assert_eq!(extract_text_filter(&nested), Some("z".to_string()));
        assert_eq!(extract_text_filter(&json!({"from": "q"})), None);
        assert_eq!(extract_text_filter(&Value::Null), None);
    }

    #[test]
    fn make_substring_snippet_marks_match() {
        let s = make_substring_snippet("the quick brown fox", "brown");
        assert!(s.contains("<mark>brown</mark>"));
    }

    #[test]
    fn make_substring_snippet_no_match_truncates() {
        let s = make_substring_snippet("hello world", "zzz");
        assert_eq!(s, "hello world");
        assert!(!s.contains("<mark>"));
    }

    #[test]
    fn make_substring_snippet_empty_text() {
        assert_eq!(make_substring_snippet("", "x"), "");
    }

    #[test]
    fn make_substring_snippet_escapes_html() {
        let s = make_substring_snippet("a <b> match here", "match");
        assert!(s.contains("&lt;b&gt;"));
        assert!(s.contains("<mark>match</mark>"));
    }

    #[tokio::test]
    async fn get_without_term_returns_truncated_escaped() {
        let (ctx, _d) = test_ctx();
        add_msg(&ctx, "e1", "Hello <World>", "body text");
        let res = ok(get(&ctx, json!({"emailIds": ["e1"]})).await);
        assert_eq!(res["list"][0]["emailId"], json!("e1"));
        assert_eq!(res["list"][0]["subject"], json!("Hello &lt;World&gt;"));
    }

    #[tokio::test]
    async fn get_reports_not_found() {
        let (ctx, _d) = test_ctx();
        let res = ok(get(&ctx, json!({"emailIds": ["ghost"]})).await);
        assert!(res["list"].as_array().unwrap().is_empty());
        assert_eq!(res["notFound"], json!(["ghost"]));
    }

    #[tokio::test]
    async fn get_with_term_highlights() {
        let (ctx, _d) = test_ctx();
        add_msg(&ctx, "e2", "Report", "the quarterly report is attached");
        let res = ok(get(&ctx, json!({"emailIds": ["e2"], "filter": {"text": "quarterly"}})).await);
        let preview = res["list"][0]["preview"].as_str().unwrap_or("");
        assert!(preview.contains("<mark>"));
    }

    #[tokio::test]
    async fn get_rejects_too_many_ids() {
        let (ctx, _d) = test_ctx();
        let ids: Vec<String> = (0..501).map(|i| i.to_string()).collect();
        assert_eq!(
            err_kind(get(&ctx, json!({"emailIds": ids})).await),
            "requestTooLarge"
        );
    }

    #[tokio::test]
    async fn get_empty_email_ids() {
        let (ctx, _d) = test_ctx();
        let res = ok(get(&ctx, json!({})).await);
        assert!(res["list"].as_array().unwrap().is_empty());
        assert!(res["notFound"].as_array().unwrap().is_empty());
    }
}
