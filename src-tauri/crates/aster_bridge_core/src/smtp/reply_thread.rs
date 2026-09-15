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
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api_client::ApiClient;
use crate::db::Database;

const MAX_IN_REPLY_TO_LEN: usize = 512;
const MAX_MESSAGE_ID_LEN: usize = 250;
const BRIDGE_MESSAGE_ID_DOMAIN: &str = "aster-bridge";
const THREAD_TOKEN_PREFIX: &str = "astermail-thread:";
const SENT_FOLDER_SUFFIX: &str = "folder:sent";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReplyHeaders {
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResolvedReply {
    pub parent_aster_id: Option<String>,
    pub in_reply_to: Option<String>,
}

impl ReplyHeaders {
    pub fn from_mime(raw_message: &[u8]) -> Self {
        let Some(parsed) = mail_parser::MessageParser::default().parse(raw_message) else {
            return Self::default();
        };
        Self {
            in_reply_to: parsed.header_raw("In-Reply-To").map(message_ids).unwrap_or_default(),
            references: parsed.header_raw("References").map(message_ids).unwrap_or_default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.in_reply_to.is_empty() && self.references.is_empty()
    }

    pub fn parent(&self) -> Option<&str> {
        self.in_reply_to
            .last()
            .or_else(|| self.references.last())
            .map(|s| s.as_str())
    }

    pub fn chain(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let parent = self.parent().map(|s| s.to_string());
        for id in self.references.iter().chain(self.in_reply_to.iter()) {
            if Some(id) == parent.as_ref() || out.contains(id) {
                continue;
            }
            out.push(id.clone());
        }
        if let Some(p) = parent {
            out.push(p);
        }
        out
    }
}

pub fn message_ids(value: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |candidate: &str| {
        let id = candidate.trim().trim_matches(&['<', '>'][..]).trim();
        let valid = !id.is_empty()
            && id.len() <= MAX_MESSAGE_ID_LEN
            && id.contains('@')
            && !id.chars().any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>' || c == '"');
        if valid && !out.iter().any(|x| x == id) {
            out.push(id.to_string());
        }
    };
    if value.contains('<') {
        let mut rest = value;
        while let Some(start) = rest.find('<') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('>') else { break };
            push(&after[..end]);
            rest = &after[end + 1..];
        }
    } else {
        value.split_whitespace().for_each(push);
    }
    out
}

pub fn bridge_local_aster_id(message_id: &str) -> Option<&str> {
    let (local, domain) = message_id.rsplit_once('@')?;
    if !domain.eq_ignore_ascii_case(BRIDGE_MESSAGE_ID_DOMAIN) {
        return None;
    }
    let valid = !local.is_empty()
        && local.len() <= 128
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    valid.then_some(local)
}

fn cached_metadata(db: &Database, aster_id: &str) -> Option<Value> {
    let msg = db.get_cached_message(aster_id).ok().flatten()?;
    serde_json::from_str(msg.raw_headers.as_deref()?).ok()
}

fn cached_chain(db: &Database, aster_id: &str) -> Vec<String> {
    let Some(meta) = cached_metadata(db, aster_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(refs) = meta.get("references").and_then(|v| v.as_str()) {
        out.extend(message_ids(refs));
    }
    if let Some(mid) = meta.get("message_id").and_then(|v| v.as_str()) {
        out.extend(message_ids(mid).into_iter().take(1));
    }
    out
}

fn aster_id_for(db: &Database, message_id: &str) -> Option<String> {
    if let Some(local) = bridge_local_aster_id(message_id) {
        return Some(local.to_string());
    }
    db.find_aster_id_by_message_id(message_id)
}

pub fn resolve_reply(db: &Database, headers: &ReplyHeaders) -> ResolvedReply {
    let parent_aster_id = headers.parent().and_then(|p| aster_id_for(db, p));
    let chain: Vec<String> = headers
        .chain()
        .into_iter()
        .flat_map(|id| match bridge_local_aster_id(&id) {
            Some(local) => cached_chain(db, local),
            None => vec![id],
        })
        .collect();
    let in_reply_to = in_reply_to_value(&chain);
    if in_reply_to.is_none() && parent_aster_id.is_some() {
        tracing::debug!("reply parent has no rfc message id, sending without in-reply-to");
    }
    ResolvedReply {
        parent_aster_id,
        in_reply_to,
    }
}

pub fn resolve_draft_reply(db: &Database, reply_to_id: &str) -> ResolvedReply {
    let in_reply_to = in_reply_to_value(&cached_chain(db, reply_to_id));
    ResolvedReply {
        parent_aster_id: Some(reply_to_id.to_string()),
        in_reply_to,
    }
}

pub fn in_reply_to_value(chain: &[String]) -> Option<String> {
    let mut seen: Vec<&String> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    for id in chain.iter().rev() {
        if bridge_local_aster_id(id).is_some() || seen.contains(&id) {
            continue;
        }
        seen.push(id);
        let formatted = format!("<{}>", id);
        let used: usize = ids.iter().map(|s| s.len() + 1).sum();
        if used + formatted.len() > MAX_IN_REPLY_TO_LEN {
            break;
        }
        ids.push(formatted);
    }
    if ids.is_empty() {
        return None;
    }
    ids.reverse();
    Some(ids.join(" "))
}

pub fn derived_thread_token(parent_aster_id: &str) -> String {
    let digest = Sha256::digest(format!("{}{}", THREAD_TOKEN_PREFIX, parent_aster_id).as_bytes());
    STANDARD.encode(digest)
}

pub fn random_thread_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

pub async fn resolve_thread_token(
    client: &ApiClient,
    access_token: &str,
    parent_aster_id: Option<&str>,
) -> String {
    let Some(parent) = parent_aster_id else {
        return random_thread_token();
    };
    let item = match client.fetch_mail_item(access_token, parent).await {
        Ok(item) => item,
        Err(e) => {
            tracing::debug!("reply parent lookup failed: {}", e);
            return random_thread_token();
        }
    };
    if let Some(token) = item.thread_token.filter(|t| !t.is_empty()) {
        return token;
    }
    let token = derived_thread_token(parent);
    if let Err(e) = client.link_thread(access_token, parent, &token).await {
        tracing::warn!("linking reply parent to its thread failed: {}", e);
    }
    token
}

pub async fn apply_reply_thread(
    payload: &mut Value,
    client: &ApiClient,
    access_token: &str,
    reply: &ResolvedReply,
) {
    let token = resolve_thread_token(client, access_token, reply.parent_aster_id.as_deref()).await;
    payload["thread_token"] = json!(token);
    if let Some(ref chain) = reply.in_reply_to {
        payload["in_reply_to"] = json!(chain);
    }
}

pub fn sent_folder_token(identity_key: &str) -> String {
    let digest = Sha256::digest(format!("{}{}", identity_key, SENT_FOLDER_SUFFIX).as_bytes());
    STANDARD.encode(digest)
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn plain_text_to_html(text: &str) -> String {
    escape_html(text).replace("\r\n", "\n").replace('\n', "<br>")
}

fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag = String::new();
    let mut skip_until: Option<&str> = None;
    for c in html.chars() {
        if in_tag {
            if c == '>' {
                in_tag = false;
                let name: String = tag
                    .trim_start_matches('/')
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect::<String>()
                    .to_ascii_lowercase();
                let closing = tag.starts_with('/');
                match skip_until {
                    Some(end) if closing && name == end => skip_until = None,
                    Some(_) => {}
                    None => match name.as_str() {
                        "script" | "style" | "head" if !closing => {
                            skip_until = Some(match name.as_str() {
                                "script" => "script",
                                "style" => "style",
                                _ => "head",
                            })
                        }
                        "br" => out.push('\n'),
                        "p" | "div" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" if closing => out.push('\n'),
                        _ => {}
                    },
                }
                tag.clear();
            } else {
                tag.push(c);
            }
        } else if c == '<' {
            in_tag = true;
        } else if skip_until.is_none() {
            out.push(c);
        }
    }
    let decoded = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    let mut collapsed = String::with_capacity(decoded.len());
    let mut newlines = 0;
    for c in decoded.chars() {
        if c == '\n' {
            newlines += 1;
            if newlines > 2 {
                continue;
            }
        } else if !c.is_whitespace() {
            newlines = 0;
        }
        collapsed.push(c);
    }
    collapsed.trim().to_string()
}

fn address_objects(payload: &Value, key: &str) -> Vec<Value> {
    payload
        .get(key)
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .map(|email| json!({"name": "", "email": email}))
                .collect()
        })
        .unwrap_or_default()
}

pub fn sent_envelope(payload: &Value, from_email: &str, plain_text: Option<&str>) -> Value {
    let is_html = payload.get("is_html").and_then(|v| v.as_bool()).unwrap_or(false);
    let body = payload.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let html = payload
        .get("body_html")
        .and_then(|v| v.as_str())
        .filter(|_| is_html)
        .unwrap_or(body);
    let (body_text, body_html) = if is_html {
        let text = plain_text
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.to_string())
            .unwrap_or_else(|| html_to_text(html));
        (text, html.to_string())
    } else {
        (body.to_string(), plain_text_to_html(body))
    };
    let from_name = payload
        .get("sender_display_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!({
        "version": 1,
        "subject": payload.get("subject").and_then(|v| v.as_str()).unwrap_or(""),
        "body_text": body_text,
        "body_html": body_html,
        "from": {"name": from_name, "email": from_email},
        "to": address_objects(payload, "to"),
        "cc": address_objects(payload, "cc"),
        "bcc": address_objects(payload, "bcc"),
        "sent_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

pub fn attach_sent_copy(
    payload: &mut Value,
    from_email: &str,
    plain_text: Option<&str>,
    identity_key: Option<&str>,
    passphrase: &[u8],
) {
    let Some(identity_key) = identity_key.filter(|k| !k.is_empty()) else {
        tracing::warn!("session has no identity key; sent copy skipped");
        return;
    };
    if passphrase.is_empty() {
        tracing::warn!("session has no vault passphrase; sent copy skipped");
        return;
    }
    let sender = payload
        .get("sender_email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(from_email)
        .to_string();
    let envelope = sent_envelope(payload, &sender, plain_text).to_string();
    match crate::crypto::envelope::encrypt_pbkdf2_envelope(&envelope, passphrase) {
        Ok(encrypted) => {
            payload["encrypted_envelope"] = json!(encrypted);
            payload["envelope_nonce"] = json!(crate::crypto::envelope::pbkdf2_envelope_nonce_marker());
            payload["folder_token"] = json!(sent_folder_token(identity_key));
        }
        Err(e) => tracing::warn!("sent copy encryption failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn test_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_with_key(dir.path(), &[9u8; 32]).unwrap();
        (dir, db)
    }

    fn cache(db: &Database, id: &str, message_id: Option<&str>) {
        let meta = json!({"is_html": false, "message_id": message_id}).to_string();
        db.upsert_cached_message(id, "inbox", Some("s"), Some("a@b.test"), Some("me@aster.test"), Some("2026-09-01T00:00:00Z"), 1, Some("b"), Some(&meta))
            .unwrap();
    }

    #[test]
    fn message_ids_parses_angle_bracket_lists() {
        assert_eq!(
            message_ids(" <a@x.test>\r\n <b@y.test> <a@x.test>"),
            vec!["a@x.test".to_string(), "b@y.test".to_string()]
        );
    }

    #[test]
    fn message_ids_accepts_bare_values_and_rejects_junk() {
        assert_eq!(message_ids("bare@x.test"), vec!["bare@x.test".to_string()]);
        assert!(message_ids("no-at-sign").is_empty());
        assert!(message_ids("<has space@x.test>").is_empty());
        assert!(message_ids("").is_empty());
    }

    #[test]
    fn reply_headers_read_in_reply_to_and_references() {
        let raw = b"From: me@aster.test\r\nTo: you@x.test\r\nSubject: Re: hi\r\nIn-Reply-To: <p@x.test>\r\nReferences: <root@x.test>\r\n <p@x.test>\r\n\r\nbody\r\n";
        let h = ReplyHeaders::from_mime(raw);
        assert_eq!(h.parent(), Some("p@x.test"));
        assert_eq!(h.chain(), vec!["root@x.test".to_string(), "p@x.test".to_string()]);
    }

    #[test]
    fn reply_headers_empty_for_new_message() {
        let raw = b"From: me@aster.test\r\nTo: you@x.test\r\nSubject: hi\r\n\r\nbody\r\n";
        let h = ReplyHeaders::from_mime(raw);
        assert!(h.is_empty());
        assert_eq!(h.parent(), None);
    }

    #[test]
    fn parent_falls_back_to_last_reference() {
        let h = ReplyHeaders { in_reply_to: vec![], references: vec!["r1@x".into(), "r2@x".into()] };
        assert_eq!(h.parent(), Some("r2@x"));
    }

    #[test]
    fn bridge_local_ids_map_to_aster_ids() {
        assert_eq!(bridge_local_aster_id("abc-123@aster-bridge"), Some("abc-123"));
        assert_eq!(bridge_local_aster_id("abc@example.com"), None);
        assert_eq!(bridge_local_aster_id("a/b@aster-bridge"), None);
    }

    #[test]
    fn in_reply_to_value_puts_parent_last_and_caps_length() {
        let chain: Vec<String> = (0..40).map(|i| format!("message-number-{}@example.test", i)).collect();
        let value = in_reply_to_value(&chain).unwrap();
        assert!(value.len() <= MAX_IN_REPLY_TO_LEN);
        assert!(value.ends_with("<message-number-39@example.test>"));
        assert!(!value.contains("<message-number-0@example.test>"));
    }

    #[test]
    fn in_reply_to_value_drops_bridge_local_ids() {
        assert_eq!(in_reply_to_value(&["x@aster-bridge".to_string()]), None);
        assert_eq!(
            in_reply_to_value(&["x@aster-bridge".to_string(), "real@x.test".to_string()]),
            Some("<real@x.test>".to_string())
        );
    }

    #[test]
    fn resolve_reply_finds_parent_by_real_message_id() {
        let (_d, db) = test_db();
        cache(&db, "parent-1", Some("<p@x.test>"));
        let h = ReplyHeaders { in_reply_to: vec!["p@x.test".into()], references: vec![] };
        let r = resolve_reply(&db, &h);
        assert_eq!(r.parent_aster_id.as_deref(), Some("parent-1"));
        assert_eq!(r.in_reply_to.as_deref(), Some("<p@x.test>"));
    }

    #[test]
    fn resolve_reply_maps_bridge_local_id_to_real_message_id() {
        let (_d, db) = test_db();
        cache(&db, "parent-2", Some("real-root@x.test"));
        let h = ReplyHeaders { in_reply_to: vec!["parent-2@aster-bridge".into()], references: vec![] };
        let r = resolve_reply(&db, &h);
        assert_eq!(r.parent_aster_id.as_deref(), Some("parent-2"));
        assert_eq!(r.in_reply_to.as_deref(), Some("<real-root@x.test>"));
    }

    #[test]
    fn resolve_reply_carries_the_parents_own_references() {
        let (_d, db) = test_db();
        let meta = json!({
            "is_html": false,
            "message_id": "<parent@x.test>",
            "references": "<root@x.test> <middle@x.test>"
        })
        .to_string();
        db.upsert_cached_message(
            "parent-3",
            "inbox",
            Some("s"),
            Some("a@b.test"),
            Some("me@aster.test"),
            Some("2026-09-01T00:00:00Z"),
            1,
            Some("b"),
            Some(&meta),
        )
        .unwrap();
        let h = ReplyHeaders { in_reply_to: vec!["parent-3@aster-bridge".into()], references: vec![] };
        let r = resolve_reply(&db, &h);
        let chain = r.in_reply_to.unwrap();
        assert!(chain.starts_with("<root@x.test> <middle@x.test>"));
        assert!(chain.ends_with("<parent@x.test>"));
    }

    #[test]
    fn resolve_reply_keeps_chain_for_unknown_parent() {
        let (_d, db) = test_db();
        let h = ReplyHeaders { in_reply_to: vec!["gone@x.test".into()], references: vec![] };
        let r = resolve_reply(&db, &h);
        assert_eq!(r.parent_aster_id, None);
        assert_eq!(r.in_reply_to.as_deref(), Some("<gone@x.test>"));
    }

    #[test]
    fn resolve_draft_reply_uses_cached_parent_message_id() {
        let (_d, db) = test_db();
        cache(&db, "parent-3", Some("<m3@x.test>"));
        let r = resolve_draft_reply(&db, "parent-3");
        assert_eq!(r.parent_aster_id.as_deref(), Some("parent-3"));
        assert_eq!(r.in_reply_to.as_deref(), Some("<m3@x.test>"));
    }

    #[test]
    fn derived_thread_token_is_stable_sha256_base64() {
        let a = derived_thread_token("id-1");
        assert_eq!(a, derived_thread_token("id-1"));
        assert_ne!(a, derived_thread_token("id-2"));
        assert_eq!(STANDARD.decode(&a).unwrap().len(), 32);
        let expected = STANDARD.encode(Sha256::digest(b"astermail-thread:id-1"));
        assert_eq!(a, expected);
    }

    #[test]
    fn random_thread_tokens_differ() {
        let a = random_thread_token();
        assert_eq!(STANDARD.decode(&a).unwrap().len(), 32);
        assert_ne!(a, random_thread_token());
    }

    #[test]
    fn sent_folder_token_matches_web_derivation() {
        let expected = STANDARD.encode(Sha256::digest(b"ik-materialfolder:sent"));
        assert_eq!(sent_folder_token("ik-material"), expected);
    }

    #[test]
    fn sent_envelope_plain_message_shape() {
        let payload = json!({"to": ["a@x.test"], "cc": ["c@x.test"], "bcc": null, "subject": "Hi", "body": "line1\nline2 <b>", "is_html": false});
        let env = sent_envelope(&payload, "me@aster.test", None);
        assert_eq!(env["version"], 1);
        assert_eq!(env["subject"], "Hi");
        assert_eq!(env["body_text"], "line1\nline2 <b>");
        assert_eq!(env["body_html"], "line1<br>line2 &lt;b&gt;");
        assert_eq!(env["from"]["email"], "me@aster.test");
        assert_eq!(env["to"][0]["email"], "a@x.test");
        assert_eq!(env["cc"][0]["email"], "c@x.test");
        assert_eq!(env["bcc"], json!([]));
        assert!(env["sent_at"].is_string());
    }

    #[test]
    fn sent_envelope_html_prefers_mime_plain_text() {
        let payload = json!({"to": ["a@x.test"], "subject": "S", "body": "<p>Hi</p>", "body_html": "<p>Hi</p>", "is_html": true, "sender_display_name": "Me"});
        let env = sent_envelope(&payload, "me@aster.test", Some("Hi plain"));
        assert_eq!(env["body_text"], "Hi plain");
        assert_eq!(env["body_html"], "<p>Hi</p>");
        assert_eq!(env["from"]["name"], "Me");
        let env = sent_envelope(&payload, "me@aster.test", None);
        assert_eq!(env["body_text"], "Hi");
    }

    #[test]
    fn html_to_text_drops_tags_scripts_and_entities() {
        let text = html_to_text("<html><head><style>p{}</style></head><body><p>One &amp; two</p><script>x()</script><div>Three<br>Four</div></body></html>");
        assert_eq!(text, "One & two\nThree\nFour");
    }

    #[test]
    fn attach_sent_copy_encrypts_an_envelope_the_poller_can_open() {
        let mut payload = json!({"to": ["a@x.test"], "subject": "S", "body": "hello", "is_html": false, "sender_email": "alias@aster.test"});
        attach_sent_copy(&mut payload, "me@aster.test", None, Some("ik"), b"vault-pass");
        assert_eq!(payload["folder_token"], json!(sent_folder_token("ik")));
        let opened = crate::crypto::envelope::decrypt_envelope(
            payload["encrypted_envelope"].as_str().unwrap(),
            payload["envelope_nonce"].as_str(),
            b"vault-pass",
            Some("ik"),
            &[],
        )
        .unwrap();
        let env: Value = serde_json::from_str(&opened).unwrap();
        assert_eq!(env["body_text"], "hello");
        assert_eq!(env["from"]["email"], "alias@aster.test");
    }

    #[test]
    fn attach_sent_copy_skips_without_identity_key() {
        let mut payload = json!({"to": ["a@x.test"], "subject": "S", "body": "hello", "is_html": false});
        attach_sent_copy(&mut payload, "me@aster.test", None, None, b"vault-pass");
        assert!(payload.get("encrypted_envelope").is_none());
        assert!(payload.get("folder_token").is_none());
    }

    struct MockThreadApi {
        base: String,
        linked: Arc<Mutex<Vec<(String, Value)>>>,
    }

    async fn mock_thread_api() -> MockThreadApi {
        use axum::extract::Path;
        use axum::http::StatusCode;
        use axum::routing::{get, put};
        use axum::{Json, Router};
        let linked: Arc<Mutex<Vec<(String, Value)>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = linked.clone();
        let app = Router::new()
            .route(
                "/bridge/v1/messages/:id",
                get(|Path(id): Path<String>| async move {
                    let token = match id.as_str() {
                        "threaded" => json!("existing-token"),
                        "unthreaded" => Value::Null,
                        _ => return Err(StatusCode::NOT_FOUND),
                    };
                    Ok(Json(json!({
                        "id": id,
                        "item_type": "received",
                        "encrypted_envelope": "",
                        "envelope_nonce": "",
                        "folder_token": "",
                        "is_external": false,
                        "thread_token": token,
                        "created_at": "2026-09-01T00:00:00Z"
                    })))
                }),
            )
            .route(
                "/bridge/v1/messages/:id/thread",
                put(move |Path(id): Path<String>, Json(body): Json<Value>| {
                    let cap = cap.clone();
                    async move {
                        cap.lock().await.push((id, body));
                        Json(json!({"success": true}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        MockThreadApi { base: format!("http://127.0.0.1:{}", port), linked }
    }

    #[tokio::test]
    async fn thread_token_reuses_the_parent_token() {
        let api = mock_thread_api().await;
        let client = ApiClient::new_with_base_url(&api.base);
        let token = resolve_thread_token(&client, "t", Some("threaded")).await;
        assert_eq!(token, "existing-token");
        assert!(api.linked.lock().await.is_empty());
    }

    #[tokio::test]
    async fn thread_token_links_an_unthreaded_parent() {
        let api = mock_thread_api().await;
        let client = ApiClient::new_with_base_url(&api.base);
        let token = resolve_thread_token(&client, "t", Some("unthreaded")).await;
        assert_eq!(token, derived_thread_token("unthreaded"));
        let linked = api.linked.lock().await;
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].0, "unthreaded");
        assert_eq!(linked[0].1["thread_token"], json!(token));
    }

    #[tokio::test]
    async fn thread_token_is_random_when_parent_is_unknown() {
        let api = mock_thread_api().await;
        let client = ApiClient::new_with_base_url(&api.base);
        let token = resolve_thread_token(&client, "t", Some("missing")).await;
        assert_eq!(STANDARD.decode(&token).unwrap().len(), 32);
        assert_ne!(token, derived_thread_token("missing"));
        let fresh = resolve_thread_token(&client, "t", None).await;
        assert_ne!(fresh, token);
    }

    #[tokio::test]
    async fn apply_reply_thread_sets_token_and_chain() {
        let api = mock_thread_api().await;
        let client = ApiClient::new_with_base_url(&api.base);
        let mut payload = json!({"to": ["a@x.test"]});
        let reply = ResolvedReply {
            parent_aster_id: Some("threaded".into()),
            in_reply_to: Some("<root@x.test> <p@x.test>".into()),
        };
        apply_reply_thread(&mut payload, &client, "t", &reply).await;
        assert_eq!(payload["thread_token"], "existing-token");
        assert_eq!(payload["in_reply_to"], "<root@x.test> <p@x.test>");
    }
}
