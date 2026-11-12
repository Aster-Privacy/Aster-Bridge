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

pub const SEALED_DETAILS_FIELD: &str = "details";
pub const SEALED_DETAILS_VERSION: u64 = 1;
pub const SEALED_DETAILS_META_KEY: &str = "sealed_details";

const MAX_NAME_UNITS: usize = 256;
const MAX_EMAIL_UNITS: usize = 320;
const MAX_ADDRESSES: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAddress {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessageDetails {
    pub from_name: String,
    pub to: Vec<SealedAddress>,
    pub cc: Vec<SealedAddress>,
    pub sent_at: String,
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn truncate_utf16(text: &str, max_units: usize) -> String {
    let mut out = String::new();
    let mut units = 0usize;
    for c in text.chars() {
        units += c.len_utf16();
        if units > max_units {
            break;
        }
        out.push(c);
    }
    out
}

pub fn clean_name(value: &str) -> String {
    let spaced: String = value
        .chars()
        .map(|c| if matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}') { ' ' } else { c })
        .collect();
    let trimmed = spaced.trim();
    let unquoted = if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1].trim()
    } else {
        trimmed
    };
    truncate_utf16(unquoted, MAX_NAME_UNITS)
}

fn split_entry(entry: &str) -> (Option<&str>, &str) {
    let whole = entry.trim();
    if entry.contains(['\n', '\r']) {
        return (None, whole);
    }
    let Some(before_close) = whole.strip_suffix('>') else {
        return (None, whole);
    };
    let Some(open) = before_close.rfind('<') else {
        return (None, whole);
    };
    let inner = &before_close[open + 1..];
    if inner.is_empty() || inner.contains('>') {
        return (None, whole);
    }
    (Some(before_close[..open].trim()), inner)
}

fn build_address(entry: &str) -> Option<SealedAddress> {
    let (name, email) = split_entry(entry);
    let email = email.trim();
    if email.is_empty() || utf16_len(email) > MAX_EMAIL_UNITS {
        return None;
    }
    Some(SealedAddress {
        name: name.map(clean_name).unwrap_or_default(),
        email: email.to_string(),
    })
}

fn build_addresses(entries: &[String]) -> Vec<SealedAddress> {
    entries
        .iter()
        .filter_map(|entry| build_address(entry))
        .take(MAX_ADDRESSES)
        .collect()
}

pub fn format_sent_at(moment: chrono::DateTime<chrono::Utc>) -> String {
    moment.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn sealed_sender_name(chosen: Option<&str>, sends_from_alias: bool, account_name: Option<&str>) -> String {
    if let Some(chosen) = chosen.filter(|name| !name.is_empty()) {
        return chosen.to_string();
    }
    if sends_from_alias {
        return String::new();
    }
    account_name.unwrap_or_default().to_string()
}

pub fn build_sealed_details(from_name: &str, to: &[String], cc: &[String], sent_at: &str) -> SealedMessageDetails {
    SealedMessageDetails {
        from_name: clean_name(from_name),
        to: build_addresses(to),
        cc: build_addresses(cc),
        sent_at: sent_at.to_string(),
    }
}

fn json_string(text: &str) -> String {
    Value::String(text.to_string()).to_string()
}

fn serialize_addresses(list: &[SealedAddress]) -> String {
    let entries: Vec<String> = list
        .iter()
        .map(|address| {
            format!(
                "{{\"name\":{},\"email\":{}}}",
                json_string(&address.name),
                json_string(&address.email)
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

pub fn serialize_sealed_details(details: &SealedMessageDetails) -> String {
    format!(
        "{{\"v\":{},\"from_name\":{},\"to\":{},\"cc\":{},\"sent_at\":{}}}",
        SEALED_DETAILS_VERSION,
        json_string(&details.from_name),
        serialize_addresses(&details.to),
        serialize_addresses(&details.cc),
        json_string(&details.sent_at),
    )
}

fn parse_addresses(value: Option<&Value>) -> Option<Vec<SealedAddress>> {
    let entries = value?.as_array()?;
    if entries.len() > MAX_ADDRESSES {
        return None;
    }
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let map = entry.as_object()?;
        let email = map.get("email")?.as_str()?;
        if email.trim().is_empty() || utf16_len(email) > MAX_EMAIL_UNITS {
            return None;
        }
        let name = match map.get("name") {
            None => "",
            Some(Value::String(name)) => name.as_str(),
            Some(_) => return None,
        };
        out.push(SealedAddress {
            name: name.to_string(),
            email: email.to_string(),
        });
    }
    Some(out)
}

fn parse_sent_at(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let parsed = chrono::DateTime::parse_from_rfc3339(trimmed)
        .or_else(|_| chrono::DateTime::parse_from_rfc2822(trimmed))
        .ok()?;
    Some(format_sent_at(parsed.with_timezone(&chrono::Utc)))
}

pub fn parse_sealed_details(value: Option<&Value>) -> Option<SealedMessageDetails> {
    let map = value?.as_object()?;
    let version = map.get("v")?;
    if version.as_u64() != Some(SEALED_DETAILS_VERSION) && version.as_f64() != Some(SEALED_DETAILS_VERSION as f64) {
        return None;
    }
    let from_name = map.get("from_name")?.as_str()?;
    let sent_at = parse_sent_at(map.get("sent_at")?.as_str()?)?;
    let to = parse_addresses(map.get("to"))?;
    let cc = parse_addresses(map.get("cc"))?;
    Some(SealedMessageDetails {
        from_name: from_name.to_string(),
        to,
        cc,
        sent_at,
    })
}

fn header_safe_email(email: &str) -> Option<String> {
    let email = email.trim();
    if email.is_empty() || email.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>' | ',' | '"' | ';')) {
        return None;
    }
    Some(email.to_string())
}

fn mailbox_list(list: &[SealedAddress]) -> Option<String> {
    let entries: Vec<String> = list
        .iter()
        .filter_map(|address| {
            let email = header_safe_email(&address.email)?;
            Some(crate::address::format_mailbox(&clean_name(&address.name), &email))
        })
        .filter(|mailbox| !mailbox.is_empty())
        .collect();
    if entries.is_empty() {
        None
    } else {
        Some(entries.join(", "))
    }
}

impl SealedMessageDetails {
    pub fn to_text(&self) -> Option<String> {
        mailbox_list(&self.to)
    }

    pub fn cc_text(&self) -> Option<String> {
        mailbox_list(&self.cc)
    }

    pub fn sender_text(&self, served_sender: Option<&str>) -> Option<String> {
        let (_, email) = crate::address::parse_mailbox(served_sender?);
        let email = header_safe_email(&email)?;
        Some(crate::address::format_mailbox(&clean_name(&self.from_name), &email))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SENT_AT: &str = "2026-11-12T10:15:00.000Z";
    const WEB_FIXTURE: &str = "{\"v\":1,\"from_name\":\"Ana Real\",\"to\":[{\"name\":\"\",\"email\":\"bo@astermail.org\"},{\"name\":\"Cy Real\",\"email\":\"cy@astermail.org\"}],\"cc\":[{\"name\":\"Di Real\",\"email\":\"di@astermail.org\"}],\"sent_at\":\"2026-11-12T10:15:00.000Z\"}";

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn web_details() -> SealedMessageDetails {
        build_sealed_details(
            "Ana Real",
            &strings(&["bo@astermail.org", "Cy Real <cy@astermail.org>"]),
            &strings(&["\"Di Real\" <di@astermail.org>"]),
            SENT_AT,
        )
    }

    #[test]
    fn built_details_serialize_to_the_shared_wire_shape() {
        let details = web_details();
        assert_eq!(details.from_name, "Ana Real");
        assert_eq!(details.to[0], SealedAddress { name: String::new(), email: "bo@astermail.org".to_string() });
        assert_eq!(details.to[1], SealedAddress { name: "Cy Real".to_string(), email: "cy@astermail.org".to_string() });
        assert_eq!(details.cc[0], SealedAddress { name: "Di Real".to_string(), email: "di@astermail.org".to_string() });
        assert_eq!(serialize_sealed_details(&details), WEB_FIXTURE);
        assert!(!serialize_sealed_details(&details).contains("bcc"));
    }

    #[test]
    fn the_shared_wire_shape_parses_back() {
        let value: Value = serde_json::from_str(WEB_FIXTURE).unwrap();
        assert_eq!(parse_sealed_details(Some(&value)), Some(web_details()));
        assert_eq!(parse_sealed_details(None), None);
    }

    #[test]
    fn names_are_cleaned_and_blank_recipients_dropped() {
        let details = build_sealed_details(
            "Ana\nReal",
            &strings(&["", "   ", "bo@astermail.org", " <> "]),
            &[],
            SENT_AT,
        );
        assert_eq!(details.from_name, "Ana Real");
        assert_eq!(details.to.len(), 2);
        assert_eq!(details.to[0].email, "bo@astermail.org");
        assert!(details.cc.is_empty());
        assert_eq!(clean_name("  \"Quoted Name\"  "), "Quoted Name");
        assert_eq!(utf16_len(&clean_name(&"x".repeat(400))), 256);
        let long = format!("{}@astermail.org", "a".repeat(320));
        assert!(build_sealed_details("", &[long], &[], SENT_AT).to.is_empty());
    }

    #[test]
    fn the_sender_name_follows_the_chosen_identity() {
        assert_eq!(sealed_sender_name(Some("Sales"), true, Some("Ana Real")), "Sales");
        assert_eq!(sealed_sender_name(None, true, Some("Ana Real")), "");
        assert_eq!(sealed_sender_name(Some(""), false, Some("Ana Real")), "Ana Real");
        assert_eq!(sealed_sender_name(None, false, None), "");
    }

    #[test]
    fn malformed_details_are_ignored() {
        let base = json!({
            "v": 1,
            "from_name": "Ana Real",
            "to": [{"name": "Bo", "email": "bo@astermail.org"}],
            "cc": [],
            "sent_at": SENT_AT,
        });
        assert!(parse_sealed_details(Some(&base)).is_some());
        let broken = |key: &str, value: Option<Value>| {
            let mut copy = base.clone();
            let map = copy.as_object_mut().unwrap();
            match value {
                Some(value) => {
                    map.insert(key.to_string(), value);
                }
                None => {
                    map.remove(key);
                }
            }
            parse_sealed_details(Some(&copy))
        };
        assert_eq!(broken("v", Some(json!(2))), None);
        assert_eq!(broken("v", Some(json!("1"))), None);
        assert_eq!(broken("v", None), None);
        assert_eq!(broken("from_name", Some(json!(7))), None);
        assert_eq!(broken("to", Some(json!("bo"))), None);
        assert_eq!(broken("cc", None), None);
        assert_eq!(broken("to", Some(json!([{"name": "Bo"}]))), None);
        assert_eq!(broken("to", Some(json!([{"name": 1, "email": "b@a.org"}]))), None);
        assert_eq!(broken("to", Some(json!([{"name": "Bo", "email": "  "}]))), None);
        assert_eq!(broken("to", Some(json!(["bo@astermail.org"]))), None);
        assert_eq!(broken("sent_at", Some(json!("not a date"))), None);
        assert_eq!(broken("sent_at", Some(json!(5))), None);
        assert_eq!(parse_sealed_details(Some(&json!({"v": 1}))), None);
        assert_eq!(parse_sealed_details(Some(&json!([1, 2]))), None);
        assert_eq!(parse_sealed_details(Some(&json!("details"))), None);
        assert_eq!(parse_sealed_details(Some(&Value::Null)), None);
    }

    #[test]
    fn the_date_is_normalized_to_utc_milliseconds() {
        let value = json!({"v": 1, "from_name": "", "to": [], "cc": [], "sent_at": "2026-11-12T11:15:00+01:00"});
        assert_eq!(parse_sealed_details(Some(&value)).unwrap().sent_at, SENT_AT);
    }

    #[test]
    fn header_text_keeps_the_served_address_and_drops_unsafe_entries() {
        let details = web_details();
        assert_eq!(
            details.sender_text(Some("Served Name <ana@astermail.org>")).as_deref(),
            Some("Ana Real <ana@astermail.org>")
        );
        assert_eq!(details.sender_text(Some("ana@astermail.org")).as_deref(), Some("Ana Real <ana@astermail.org>"));
        assert_eq!(details.sender_text(None), None);
        assert_eq!(details.to_text().as_deref(), Some("bo@astermail.org, Cy Real <cy@astermail.org>"));
        assert_eq!(details.cc_text().as_deref(), Some("Di Real <di@astermail.org>"));

        let value = json!({
            "v": 1,
            "from_name": "Ana\r\nBcc: x@y.org",
            "to": [
                {"name": "Bo\r\nCc: z@y.org", "email": "bo@astermail.org"},
                {"name": "", "email": "bad@astermail.org\r\nBcc: x@y.org"},
                {"name": "", "email": "two@astermail.org, three@astermail.org"}
            ],
            "cc": [],
            "sent_at": SENT_AT,
        });
        let hostile = parse_sealed_details(Some(&value)).unwrap();
        let sender = hostile.sender_text(Some("ana@astermail.org")).unwrap();
        assert!(!sender.contains(['\r', '\n']));
        assert!(sender.ends_with("<ana@astermail.org>"));
        let to = hostile.to_text().unwrap();
        assert!(!to.contains(['\r', '\n']));
        assert!(to.ends_with("<bo@astermail.org>"));
        assert_eq!(hostile.cc_text(), None);
    }
}
