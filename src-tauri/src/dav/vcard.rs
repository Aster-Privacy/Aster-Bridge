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
use serde_json::{Map, Value};

const FOLD_WIDTH: usize = 73;

pub struct VCardProperty {
    pub name: String,
    pub params: Vec<(String, String)>,
    pub value: String,
}

impl VCardProperty {
    pub fn types(&self) -> Vec<String> {
        self.params
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("TYPE"))
            .flat_map(|(_, v)| v.split(','))
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .filter(|v| !v.is_empty())
            .collect()
    }
}

fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

fn unescape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') | Some('N') => out.push('\n'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

fn split_unescaped(value: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == separator {
            parts.push(current.clone());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

fn fold_line(line: &str, out: &mut String) {
    let mut width = 0usize;
    let mut first = true;
    for ch in line.chars() {
        let len = ch.len_utf8();
        if width + len > FOLD_WIDTH && !first {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(ch);
        width += len;
        first = false;
    }
    out.push_str("\r\n");
}

fn unfold(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = lines.last_mut() {
                last.push_str(&line[1..]);
                continue;
            }
        }
        lines.push(line.to_string());
    }
    lines
}

fn parse_params(raw: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut segments = Vec::new();
    for ch in raw.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ';' if !in_quotes => {
                segments.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    segments.push(current);

    for segment in segments {
        if segment.is_empty() {
            continue;
        }
        match segment.split_once('=') {
            Some((key, value)) => params.push((
                key.trim().to_uppercase(),
                value.trim().trim_matches('"').to_string(),
            )),
            None => params.push(("TYPE".to_string(), segment.trim().to_string())),
        }
    }
    params
}

pub fn parse_properties(text: &str) -> Vec<VCardProperty> {
    let mut properties = Vec::new();
    for line in unfold(text) {
        if line.trim().is_empty() {
            continue;
        }
        let Some(colon) = find_value_colon(&line) else {
            continue;
        };
        let (head, value) = line.split_at(colon);
        let value = &value[1..];
        let mut head_parts = head.splitn(2, ';');
        let raw_name = head_parts.next().unwrap_or("");
        let params = head_parts.next().map(parse_params).unwrap_or_default();
        let name = raw_name
            .rsplit('.')
            .next()
            .unwrap_or(raw_name)
            .trim()
            .to_uppercase();

        properties.push(VCardProperty {
            name,
            params,
            value: value.to_string(),
        });
    }
    properties
}

fn find_value_colon(line: &str) -> Option<usize> {
    let mut in_quotes = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => return Some(index),
            _ => {}
        }
    }
    None
}

pub fn extract_uid(text: &str) -> Option<String> {
    parse_properties(text)
        .into_iter()
        .find(|p| p.name == "UID")
        .map(|p| unescape_value(&p.value).trim().to_string())
        .filter(|v| !v.is_empty())
}

fn string_field<'a>(contact: &'a Value, key: &str) -> &'a str {
    contact.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn entries<'a>(contact: &'a Value, key: &str) -> &'a [Value] {
    contact
        .get(key)
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

fn push_property(out: &mut String, name: &str, params: &[(&str, &str)], value: &str) {
    if value.is_empty() {
        return;
    }
    let mut line = String::from(name);
    for (key, param_value) in params {
        line.push(';');
        line.push_str(key);
        line.push('=');
        line.push_str(param_value);
    }
    line.push(':');
    line.push_str(value);
    fold_line(&line, out);
}

fn address_value(address: &Value) -> String {
    let field = |key: &str| escape_value(address.get(key).and_then(|v| v.as_str()).unwrap_or(""));
    let parts = [
        String::new(),
        String::new(),
        field("street"),
        field("city"),
        field("state"),
        field("postal_code"),
        field("country"),
    ];
    if parts.iter().all(|p| p.is_empty()) {
        return String::new();
    }
    parts.join(";")
}

fn display_name(contact: &Value) -> String {
    let first = string_field(contact, "first_name").trim().to_string();
    let last = string_field(contact, "last_name").trim().to_string();
    let full = format!("{} {}", first, last).trim().to_string();
    if !full.is_empty() {
        return full;
    }
    for key in ["nickname", "company"] {
        let candidate = string_field(contact, key).trim();
        if !candidate.is_empty() {
            return candidate.to_string();
        }
    }
    let emails = entries(contact, "emails");
    if let Some(first_email) = emails.first().and_then(|v| v.as_str()) {
        return first_email.to_string();
    }
    "Unnamed".to_string()
}

pub fn contact_to_vcard(uid: &str, contact: &Value, revision: &str) -> String {
    let mut out = String::new();
    out.push_str("BEGIN:VCARD\r\nVERSION:3.0\r\n");
    push_property(&mut out, "PRODID", &[], "-//Aster//Aster Bridge//EN");
    push_property(&mut out, "UID", &[], &escape_value(uid));
    push_property(&mut out, "FN", &[], &escape_value(&display_name(contact)));

    let name_value = [
        escape_value(string_field(contact, "last_name")),
        escape_value(string_field(contact, "first_name")),
        escape_value(string_field(contact, "middle_name")),
        escape_value(string_field(contact, "title")),
        escape_value(string_field(contact, "name_suffix")),
    ]
    .join(";");
    push_property(&mut out, "N", &[], &name_value);

    push_property(
        &mut out,
        "NICKNAME",
        &[],
        &escape_value(string_field(contact, "nickname")),
    );

    let email_entries = entries(contact, "email_entries");
    if email_entries.is_empty() {
        for email in entries(contact, "emails") {
            if let Some(email) = email.as_str() {
                push_property(
                    &mut out,
                    "EMAIL",
                    &[("TYPE", "INTERNET")],
                    &escape_value(email),
                );
            }
        }
    } else {
        for entry in email_entries {
            let value = string_field(entry, "value");
            let entry_type = string_field(entry, "type").to_uppercase();
            let type_param = if entry_type.is_empty() {
                "INTERNET".to_string()
            } else {
                format!("INTERNET,{}", entry_type)
            };
            push_property(
                &mut out,
                "EMAIL",
                &[("TYPE", type_param.as_str())],
                &escape_value(value),
            );
        }
    }

    let phone_entries = entries(contact, "phone_entries");
    if phone_entries.is_empty() {
        push_property(
            &mut out,
            "TEL",
            &[("TYPE", "CELL")],
            &escape_value(string_field(contact, "phone")),
        );
    } else {
        for entry in phone_entries {
            let entry_type = match string_field(entry, "type") {
                "mobile" => "CELL",
                "home" => "HOME",
                "work" => "WORK",
                "fax" => "FAX",
                "pager" => "PAGER",
                _ => "OTHER",
            };
            push_property(
                &mut out,
                "TEL",
                &[("TYPE", entry_type)],
                &escape_value(string_field(entry, "value")),
            );
        }
    }

    let company = string_field(contact, "company");
    let department = string_field(contact, "department");
    if !company.is_empty() || !department.is_empty() {
        let org = format!("{};{}", escape_value(company), escape_value(department));
        push_property(&mut out, "ORG", &[], &org);
    }
    push_property(
        &mut out,
        "TITLE",
        &[],
        &escape_value(string_field(contact, "job_title")),
    );
    push_property(
        &mut out,
        "ROLE",
        &[],
        &escape_value(string_field(contact, "role")),
    );

    let address_entries = entries(contact, "address_entries");
    if address_entries.is_empty() {
        if let Some(address) = contact.get("address") {
            push_property(&mut out, "ADR", &[("TYPE", "HOME")], &address_value(address));
        }
    } else {
        for entry in address_entries {
            let entry_type = string_field(entry, "type").to_uppercase();
            let entry_type = if entry_type.is_empty() {
                "OTHER".to_string()
            } else {
                entry_type
            };
            push_property(
                &mut out,
                "ADR",
                &[("TYPE", entry_type.as_str())],
                &address_value(entry),
            );
        }
    }

    push_property(
        &mut out,
        "BDAY",
        &[],
        &escape_value(string_field(contact, "birthday")),
    );

    for entry in entries(contact, "date_entries") {
        let value = escape_value(string_field(entry, "value"));
        if value.is_empty() {
            continue;
        }
        let label = string_field(entry, "type").to_uppercase();
        if label == "ANNIVERSARY" {
            push_property(&mut out, "ANNIVERSARY", &[], &value);
        } else {
            push_property(&mut out, "X-ASTER-DATE", &[("TYPE", label.as_str())], &value);
        }
    }

    let websites = entries(contact, "websites");
    if websites.is_empty() {
        if let Some(link) = contact
            .get("social_links")
            .and_then(|v| v.get("website"))
            .and_then(|v| v.as_str())
        {
            push_property(&mut out, "URL", &[], &escape_value(link));
        }
    } else {
        for entry in websites {
            let entry_type = string_field(entry, "type").to_uppercase();
            let entry_type = if entry_type.is_empty() {
                "OTHER".to_string()
            } else {
                entry_type
            };
            push_property(
                &mut out,
                "URL",
                &[("TYPE", entry_type.as_str())],
                &escape_value(string_field(entry, "value")),
            );
        }
    }

    for entry in entries(contact, "social_networks") {
        let entry_type = string_field(entry, "type").to_uppercase();
        let entry_type = if entry_type.is_empty() {
            "OTHER".to_string()
        } else {
            entry_type
        };
        push_property(
            &mut out,
            "X-SOCIALPROFILE",
            &[("TYPE", entry_type.as_str())],
            &escape_value(string_field(entry, "value")),
        );
    }

    for entry in entries(contact, "instant_messengers") {
        let entry_type = string_field(entry, "type").to_uppercase();
        let entry_type = if entry_type.is_empty() {
            "OTHER".to_string()
        } else {
            entry_type
        };
        push_property(
            &mut out,
            "IMPP",
            &[("TYPE", entry_type.as_str())],
            &escape_value(string_field(entry, "value")),
        );
    }

    for entry in entries(contact, "related_people") {
        let entry_type = string_field(entry, "type").to_uppercase();
        let entry_type = if entry_type.is_empty() {
            "OTHER".to_string()
        } else {
            entry_type
        };
        push_property(
            &mut out,
            "X-ASTER-RELATED",
            &[("TYPE", entry_type.as_str())],
            &escape_value(string_field(entry, "value")),
        );
    }

    let groups: Vec<String> = entries(contact, "groups")
        .iter()
        .filter_map(|v| v.as_str())
        .map(escape_value)
        .collect();
    if !groups.is_empty() {
        push_property(&mut out, "CATEGORIES", &[], &groups.join(","));
    }

    push_property(
        &mut out,
        "NOTE",
        &[],
        &escape_value(string_field(contact, "notes")),
    );
    push_property(
        &mut out,
        "X-PHONETIC-FIRST-NAME",
        &[],
        &escape_value(string_field(contact, "phonetic_first_name")),
    );
    push_property(
        &mut out,
        "X-PHONETIC-LAST-NAME",
        &[],
        &escape_value(string_field(contact, "phonetic_last_name")),
    );
    push_property(
        &mut out,
        "X-ASTER-PRONOUNS",
        &[],
        &escape_value(string_field(contact, "pronouns")),
    );
    if contact
        .get("is_favorite")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        push_property(&mut out, "X-ASTER-FAVORITE", &[], "1");
    }
    push_property(&mut out, "REV", &[], &escape_value(revision));

    out.push_str("END:VCARD\r\n");
    out
}

fn normalized_type(property: &VCardProperty, allowed: &[&str], fallback: &str) -> String {
    for raw in property.types() {
        let mapped = match raw.as_str() {
            "cell" | "mobile" | "iphone" => "mobile",
            "internet" | "pref" | "voice" => "",
            other => other,
        };
        if allowed.contains(&mapped) {
            return mapped.to_string();
        }
    }
    fallback.to_string()
}

fn set_string(map: &mut Map<String, Value>, key: &str, value: String) {
    if !value.is_empty() {
        map.insert(key.to_string(), Value::from(value));
    }
}

pub fn vcard_to_contact(text: &str) -> Map<String, Value> {
    let mut contact = Map::new();
    let mut emails: Vec<Value> = Vec::new();
    let mut email_entries: Vec<Value> = Vec::new();
    let mut phone_entries: Vec<Value> = Vec::new();
    let mut address_entries: Vec<Value> = Vec::new();
    let mut websites: Vec<Value> = Vec::new();
    let mut social_networks: Vec<Value> = Vec::new();
    let mut instant_messengers: Vec<Value> = Vec::new();
    let mut related_people: Vec<Value> = Vec::new();
    let mut date_entries: Vec<Value> = Vec::new();
    let mut groups: Vec<Value> = Vec::new();
    let mut formatted_name = String::new();

    for property in parse_properties(text) {
        let value = unescape_value(&property.value);
        match property.name.as_str() {
            "FN" => formatted_name = value.trim().to_string(),
            "N" => {
                let parts = split_unescaped(&property.value, ';');
                let get = |index: usize| {
                    parts
                        .get(index)
                        .map(|p| unescape_value(p).trim().to_string())
                        .unwrap_or_default()
                };
                set_string(&mut contact, "last_name", get(0));
                set_string(&mut contact, "first_name", get(1));
                set_string(&mut contact, "middle_name", get(2));
                set_string(&mut contact, "title", get(3));
                set_string(&mut contact, "name_suffix", get(4));
            }
            "NICKNAME" => set_string(&mut contact, "nickname", value.trim().to_string()),
            "EMAIL" => {
                let address = value.trim().to_string();
                if address.is_empty() {
                    continue;
                }
                let entry_type =
                    normalized_type(&property, &["home", "work", "other"], "other");
                emails.push(Value::from(address.clone()));
                email_entries.push(serde_json::json!({
                    "value": address,
                    "type": entry_type,
                }));
            }
            "TEL" => {
                let number = value.trim().to_string();
                if number.is_empty() {
                    continue;
                }
                let entry_type = normalized_type(
                    &property,
                    &["mobile", "home", "work", "fax", "pager", "other"],
                    "other",
                );
                phone_entries.push(serde_json::json!({
                    "value": number,
                    "type": entry_type,
                }));
            }
            "ORG" => {
                let parts = split_unescaped(&property.value, ';');
                let get = |index: usize| {
                    parts
                        .get(index)
                        .map(|p| unescape_value(p).trim().to_string())
                        .unwrap_or_default()
                };
                set_string(&mut contact, "company", get(0));
                set_string(&mut contact, "department", get(1));
            }
            "TITLE" => set_string(&mut contact, "job_title", value.trim().to_string()),
            "ROLE" => set_string(&mut contact, "role", value.trim().to_string()),
            "ADR" => {
                let parts = split_unescaped(&property.value, ';');
                let get = |index: usize| {
                    parts
                        .get(index)
                        .map(|p| unescape_value(p).trim().to_string())
                        .unwrap_or_default()
                };
                let entry_type = normalized_type(&property, &["home", "work", "other"], "other");
                let street = get(2);
                let city = get(3);
                let state = get(4);
                let postal_code = get(5);
                let country = get(6);
                if street.is_empty()
                    && city.is_empty()
                    && state.is_empty()
                    && postal_code.is_empty()
                    && country.is_empty()
                {
                    continue;
                }
                address_entries.push(serde_json::json!({
                    "type": entry_type,
                    "street": street,
                    "city": city,
                    "state": state,
                    "postal_code": postal_code,
                    "country": country,
                }));
            }
            "BDAY" => set_string(&mut contact, "birthday", value.trim().to_string()),
            "ANNIVERSARY" => {
                let date = value.trim().to_string();
                if !date.is_empty() {
                    date_entries.push(serde_json::json!({
                        "value": date,
                        "type": "anniversary",
                    }));
                }
            }
            "X-ASTER-DATE" => {
                let date = value.trim().to_string();
                if !date.is_empty() {
                    let entry_type = normalized_type(
                        &property,
                        &["anniversary", "graduation", "wedding", "other"],
                        "other",
                    );
                    date_entries.push(serde_json::json!({
                        "value": date,
                        "type": entry_type,
                    }));
                }
            }
            "URL" => {
                let link = value.trim().to_string();
                if !link.is_empty() {
                    let entry_type = normalized_type(
                        &property,
                        &["private", "work", "blog", "other"],
                        "other",
                    );
                    websites.push(serde_json::json!({
                        "value": link,
                        "type": entry_type,
                    }));
                }
            }
            "X-SOCIALPROFILE" => {
                let handle = value.trim().to_string();
                if !handle.is_empty() {
                    let entry_type = normalized_type(
                        &property,
                        &[
                            "twitter",
                            "linkedin",
                            "github",
                            "instagram",
                            "facebook",
                            "mastodon",
                            "bluesky",
                            "other",
                        ],
                        "other",
                    );
                    social_networks.push(serde_json::json!({
                        "value": handle,
                        "type": entry_type,
                    }));
                }
            }
            "IMPP" => {
                let handle = value.trim().to_string();
                if !handle.is_empty() {
                    let entry_type = normalized_type(
                        &property,
                        &["signal", "matrix", "telegram", "whatsapp", "xmpp", "other"],
                        "other",
                    );
                    instant_messengers.push(serde_json::json!({
                        "value": handle,
                        "type": entry_type,
                    }));
                }
            }
            "X-ASTER-RELATED" => {
                let person = value.trim().to_string();
                if !person.is_empty() {
                    let entry_type = normalized_type(
                        &property,
                        &[
                            "assistant",
                            "manager",
                            "spouse",
                            "partner",
                            "child",
                            "parent",
                            "sibling",
                            "friend",
                            "other",
                        ],
                        "other",
                    );
                    related_people.push(serde_json::json!({
                        "value": person,
                        "type": entry_type,
                    }));
                }
            }
            "CATEGORIES" => {
                for group in split_unescaped(&property.value, ',') {
                    let name = unescape_value(&group).trim().to_string();
                    if !name.is_empty() {
                        groups.push(Value::from(name));
                    }
                }
            }
            "NOTE" => set_string(&mut contact, "notes", value),
            "X-PHONETIC-FIRST-NAME" => {
                set_string(&mut contact, "phonetic_first_name", value.trim().to_string())
            }
            "X-PHONETIC-LAST-NAME" => {
                set_string(&mut contact, "phonetic_last_name", value.trim().to_string())
            }
            "X-ASTER-PRONOUNS" => set_string(&mut contact, "pronouns", value.trim().to_string()),
            "X-ASTER-FAVORITE" => {
                contact.insert("is_favorite".to_string(), Value::from(value.trim() == "1"));
            }
            _ => {}
        }
    }

    if !contact.contains_key("first_name") && !contact.contains_key("last_name") {
        let mut parts = formatted_name.splitn(2, ' ');
        let first = parts.next().unwrap_or("").trim().to_string();
        let last = parts.next().unwrap_or("").trim().to_string();
        set_string(&mut contact, "first_name", first);
        set_string(&mut contact, "last_name", last);
    }

    contact
        .entry("first_name".to_string())
        .or_insert_with(|| Value::from(""));
    contact
        .entry("last_name".to_string())
        .or_insert_with(|| Value::from(""));
    contact.insert("emails".to_string(), Value::Array(emails));

    if let Some(primary) = phone_entries
        .first()
        .and_then(|entry| entry.get("value"))
        .and_then(|v| v.as_str())
    {
        contact.insert("phone".to_string(), Value::from(primary));
    }
    if let Some(primary) = address_entries.first() {
        contact.insert("address".to_string(), primary.clone());
    }

    let mut insert_list = |key: &str, list: Vec<Value>| {
        if !list.is_empty() {
            contact.insert(key.to_string(), Value::Array(list));
        }
    };
    insert_list("email_entries", email_entries);
    insert_list("phone_entries", phone_entries);
    insert_list("address_entries", address_entries);
    insert_list("websites", websites);
    insert_list("social_networks", social_networks);
    insert_list("instant_messengers", instant_messengers);
    insert_list("related_people", related_people);
    insert_list("date_entries", date_entries);
    insert_list("groups", groups);

    contact
        .entry("is_favorite".to_string())
        .or_insert_with(|| Value::from(false));

    contact
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contact() -> Value {
        serde_json::json!({
            "first_name": "Ada",
            "last_name": "Lovelace",
            "middle_name": "Byron",
            "emails": ["ada@example.com", "ada@home.example"],
            "email_entries": [
                { "value": "ada@example.com", "type": "work" },
                { "value": "ada@home.example", "type": "home" }
            ],
            "phone_entries": [{ "value": "+15550000", "type": "mobile" }],
            "company": "Analytical Engines",
            "department": "Research",
            "job_title": "Mathematician",
            "address_entries": [{
                "type": "home",
                "street": "12 Mill; Lane",
                "city": "London",
                "state": "",
                "postal_code": "NW1",
                "country": "UK"
            }],
            "birthday": "1815-12-10",
            "notes": "First line\nsecond, line",
            "groups": ["Pioneers", "Math"],
            "is_favorite": true
        })
    }

    #[test]
    fn emits_a_well_formed_vcard() {
        let card = contact_to_vcard("uid-1", &sample_contact(), "2026-08-21T00:00:00Z");

        assert!(card.starts_with("BEGIN:VCARD\r\nVERSION:3.0\r\n"));
        assert!(card.ends_with("END:VCARD\r\n"));
        assert!(card.contains("UID:uid-1\r\n"));
        assert!(card.contains("FN:Ada Lovelace\r\n"));
        assert!(card.contains("N:Lovelace;Ada;Byron;;\r\n"));
        assert!(card.contains("ORG:Analytical Engines;Research\r\n"));
        assert!(card.contains("CATEGORIES:Pioneers,Math\r\n"));
        assert!(card.contains("X-ASTER-FAVORITE:1\r\n"));
    }

    #[test]
    fn escapes_separators_and_newlines_in_values() {
        let card = contact_to_vcard("uid-1", &sample_contact(), "rev");

        assert!(card.contains("NOTE:First line\\nsecond\\, line\r\n"));
        assert!(card.contains(";12 Mill\\; Lane;London;;NW1;UK\r\n"));
    }

    #[test]
    fn round_trips_contact_fields() {
        let original = sample_contact();
        let card = contact_to_vcard("uid-1", &original, "rev");
        let parsed = Value::Object(vcard_to_contact(&card));

        assert_eq!(parsed["first_name"], original["first_name"]);
        assert_eq!(parsed["last_name"], original["last_name"]);
        assert_eq!(parsed["middle_name"], original["middle_name"]);
        assert_eq!(parsed["company"], original["company"]);
        assert_eq!(parsed["department"], original["department"]);
        assert_eq!(parsed["job_title"], original["job_title"]);
        assert_eq!(parsed["birthday"], original["birthday"]);
        assert_eq!(parsed["notes"], original["notes"]);
        assert_eq!(parsed["groups"], original["groups"]);
        assert_eq!(parsed["is_favorite"], Value::from(true));
        assert_eq!(parsed["emails"], original["emails"]);
        assert_eq!(parsed["email_entries"], original["email_entries"]);
        assert_eq!(parsed["phone_entries"], original["phone_entries"]);
        assert_eq!(parsed["address_entries"], original["address_entries"]);
    }

    #[test]
    fn unfolds_continuation_lines_before_parsing() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lov\r\n elace\r\nEND:VCARD\r\n";
        let parsed = vcard_to_contact(card);

        assert_eq!(parsed["first_name"], Value::from("Ada"));
        assert_eq!(parsed["last_name"], Value::from("Lovelace"));
    }

    #[test]
    fn folds_long_values_at_the_line_limit() {
        let contact = serde_json::json!({
            "first_name": "A",
            "last_name": "B",
            "emails": [],
            "notes": "x".repeat(400),
        });
        let card = contact_to_vcard("uid", &contact, "rev");

        for line in card.split("\r\n") {
            assert!(line.len() <= FOLD_WIDTH + 1, "line too long: {}", line.len());
        }
        assert_eq!(
            Value::Object(vcard_to_contact(&card))["notes"],
            Value::from("x".repeat(400))
        );
    }

    #[test]
    fn falls_back_to_the_formatted_name_when_n_is_absent() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Grace Hopper\r\nEND:VCARD\r\n";
        let parsed = vcard_to_contact(card);

        assert_eq!(parsed["first_name"], Value::from("Grace"));
        assert_eq!(parsed["last_name"], Value::from("Hopper"));
    }

    #[test]
    fn maps_apple_type_aliases_onto_aster_types() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A B\r\nTEL;TYPE=IPHONE:+1555\r\nEMAIL;TYPE=INTERNET,WORK:a@b.c\r\nEND:VCARD\r\n";
        let parsed = vcard_to_contact(card);

        assert_eq!(parsed["phone_entries"][0]["type"], Value::from("mobile"));
        assert_eq!(parsed["email_entries"][0]["type"], Value::from("work"));
    }

    #[test]
    fn extracts_the_uid_property() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:abc-123\r\nFN:A B\r\nEND:VCARD\r\n";

        assert_eq!(extract_uid(card).as_deref(), Some("abc-123"));
        assert!(extract_uid("BEGIN:VCARD\r\nEND:VCARD\r\n").is_none());
    }

    #[test]
    fn ignores_property_groups_in_names() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nitem1.EMAIL;TYPE=WORK:a@b.c\r\nEND:VCARD\r\n";
        let parsed = vcard_to_contact(card);

        assert_eq!(parsed["emails"][0], Value::from("a@b.c"));
    }

    #[test]
    fn a_card_without_any_name_still_produces_required_fields() {
        let parsed = vcard_to_contact("BEGIN:VCARD\r\nVERSION:3.0\r\nEND:VCARD\r\n");

        assert_eq!(parsed["first_name"], Value::from(""));
        assert_eq!(parsed["last_name"], Value::from(""));
        assert_eq!(parsed["emails"], Value::Array(vec![]));
        assert_eq!(parsed["is_favorite"], Value::from(false));
    }
}
