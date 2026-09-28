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
use serde_json::Value;

const NAME_SPECIALS: &[char] = &['(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '.', '"'];

fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn format_mailbox(name: &str, email: &str) -> String {
    let name = clean(name);
    let email = clean(email);
    if email.is_empty() {
        return String::new();
    }
    if name.is_empty() || name.eq_ignore_ascii_case(&email) {
        return email;
    }
    if name.contains(NAME_SPECIALS) {
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{}\" <{}>", escaped, email)
    } else {
        format!("{} <{}>", name, email)
    }
}

pub fn split_address_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut angle_depth = 0usize;
    for c in s.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => {
                current.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            '<' if !in_quotes => {
                angle_depth += 1;
                current.push(c);
            }
            '>' if !in_quotes => {
                angle_depth = angle_depth.saturating_sub(1);
                current.push(c);
            }
            ',' | ';' if !in_quotes && angle_depth == 0 => {
                let part = current.trim();
                if !part.is_empty() {
                    out.push(part.to_string());
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let part = current.trim();
    if !part.is_empty() {
        out.push(part.to_string());
    }
    out
}

fn unquote_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let inner = if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    let mut out = String::new();
    let mut escaped = false;
    for c in inner.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out.trim().trim_matches('"').trim().to_string()
}

pub fn parse_mailbox(addr: &str) -> (String, String) {
    let trimmed = addr.trim();
    match (trimmed.rfind('<'), trimmed.rfind('>')) {
        (Some(open), Some(close)) if close > open => (
            unquote_name(&trimmed[..open]),
            trimmed[open + 1..close].trim().to_string(),
        ),
        _ => (String::new(), trimmed.trim_matches(&['<', '>', '"'][..]).trim().to_string()),
    }
}

fn value_entries(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => split_address_list(s)
            .into_iter()
            .map(|a| {
                let (name, email) = parse_mailbox(&a);
                format_mailbox(&name, &email)
            })
            .filter(|s| !s.is_empty())
            .collect(),
        Value::Array(items) => items.iter().flat_map(value_entries).collect(),
        Value::Object(map) => {
            let email = map
                .get("email")
                .or_else(|| map.get("address"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let name = map.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let formatted = format_mailbox(name, email);
            if formatted.is_empty() {
                Vec::new()
            } else {
                vec![formatted]
            }
        }
        _ => Vec::new(),
    }
}

pub fn address_text(v: Option<&Value>) -> Option<String> {
    let entries = value_entries(v?);
    if entries.is_empty() {
        None
    } else {
        Some(entries.join(", "))
    }
}

pub fn meta_address_text(meta: &Value, key: &str) -> Option<String> {
    address_text(meta.get(key))
}

fn raw_header_value<'a>(envelope: &'a Value, name: &str) -> Option<&'a Value> {
    envelope
        .get("raw_headers")?
        .as_array()?
        .iter()
        .find(|h| {
            h.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
        })
        .and_then(|h| h.get("value"))
}

pub fn envelope_cc(envelope: &Value) -> Option<String> {
    address_text(envelope.get("cc")).or_else(|| address_text(raw_header_value(envelope, "cc")))
}

pub fn envelope_bcc(envelope: &Value) -> Option<String> {
    address_text(envelope.get("bcc"))
}

pub fn envelope_reply_to(envelope: &Value) -> Option<String> {
    address_text(envelope.get("reply_to"))
        .or_else(|| address_text(envelope.get("replyTo")))
        .or_else(|| address_text(raw_header_value(envelope, "reply-to")))
}

pub fn jmap_addresses(text: Option<&str>) -> Value {
    let Some(text) = text else { return Value::Null };
    let list: Vec<Value> = split_address_list(text)
        .into_iter()
        .filter_map(|a| {
            let (name, email) = parse_mailbox(&a);
            if email.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "name": if name.is_empty() { Value::Null } else { Value::String(name) },
                "email": email,
            }))
        })
        .collect();
    if list.is_empty() {
        Value::Null
    } else {
        Value::Array(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_names_and_quotes_specials() {
        assert_eq!(format_mailbox("", "a@x.test"), "a@x.test");
        assert_eq!(format_mailbox("Ann", "a@x.test"), "Ann <a@x.test>");
        assert_eq!(format_mailbox("a@x.test", "a@x.test"), "a@x.test");
        assert_eq!(format_mailbox("Doe, John", "j@x.test"), "\"Doe, John\" <j@x.test>");
        assert_eq!(format_mailbox("Say \"hi\"", "h@x.test"), "\"Say \\\"hi\\\"\" <h@x.test>");
        assert_eq!(format_mailbox("Ann\r\nBcc: evil@x.test", "a@x.test"), "\"AnnBcc: evil@x.test\" <a@x.test>");
        assert_eq!(format_mailbox("Ann", ""), "");
    }

    #[test]
    fn splits_respecting_quotes_and_angles() {
        assert_eq!(
            split_address_list("\"Doe, John\" <j@x.test>, b@x.test; <c@x.test>"),
            vec!["\"Doe, John\" <j@x.test>", "b@x.test", "<c@x.test>"]
        );
        assert!(split_address_list(" , ").is_empty());
    }

    #[test]
    fn parses_mailbox_forms() {
        assert_eq!(parse_mailbox("\"Doe, John\" <j@x.test>"), ("Doe, John".into(), "j@x.test".into()));
        assert_eq!(parse_mailbox("Ann <a@x.test>"), ("Ann".into(), "a@x.test".into()));
        assert_eq!(parse_mailbox("<a@x.test>"), ("".into(), "a@x.test".into()));
        assert_eq!(parse_mailbox("a@x.test"), ("".into(), "a@x.test".into()));
    }

    #[test]
    fn address_text_accepts_every_stored_shape() {
        assert_eq!(address_text(Some(&json!("a@x.test, Bob <b@x.test>"))).as_deref(), Some("a@x.test, Bob <b@x.test>"));
        assert_eq!(address_text(Some(&json!(["a@x.test", "b@x.test"]))).as_deref(), Some("a@x.test, b@x.test"));
        assert_eq!(
            address_text(Some(&json!([{"name": "Carol", "email": "c@x.test"}, {"name": "", "email": "d@x.test"}]))).as_deref(),
            Some("Carol <c@x.test>, d@x.test")
        );
        assert_eq!(address_text(Some(&json!({"name": "Ann", "email": "a@x.test"}))).as_deref(), Some("Ann <a@x.test>"));
        assert_eq!(address_text(Some(&json!([]))), None);
        assert_eq!(address_text(Some(&json!(""))), None);
        assert_eq!(address_text(Some(&Value::Null)), None);
        assert_eq!(address_text(None), None);
    }

    #[test]
    fn envelope_reply_to_prefers_field_then_raw_header() {
        let with_field = json!({"reply_to": "r@x.test", "raw_headers": [{"name": "Reply-To", "value": "other@x.test"}]});
        assert_eq!(envelope_reply_to(&with_field).as_deref(), Some("r@x.test"));
        let header_only = json!({"raw_headers": [{"name": "reply-to", "value": "Desk <desk@x.test>"}]});
        assert_eq!(envelope_reply_to(&header_only).as_deref(), Some("Desk <desk@x.test>"));
        assert_eq!(envelope_reply_to(&json!({})), None);
    }

    #[test]
    fn envelope_cc_reads_web_objects() {
        let env = json!({"cc": [{"name": "Carol", "email": "carol@x.test"}], "bcc": []});
        assert_eq!(envelope_cc(&env).as_deref(), Some("Carol <carol@x.test>"));
        assert_eq!(envelope_bcc(&env), None);
    }

    #[test]
    fn jmap_addresses_round_trip() {
        assert_eq!(
            jmap_addresses(Some("\"Doe, John\" <j@x.test>, b@x.test")),
            json!([{"name": "Doe, John", "email": "j@x.test"}, {"name": null, "email": "b@x.test"}])
        );
        assert_eq!(jmap_addresses(None), Value::Null);
        assert_eq!(jmap_addresses(Some("")), Value::Null);
    }
}
