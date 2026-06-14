//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use crate::db::CachedMessage;

fn looks_like_headers(s: &str) -> bool {
    let t = s.trim_start();
    !t.starts_with('{') && t.lines().take(1).any(|l| l.contains(':'))
}

fn parse_is_html(raw: &Option<String>) -> bool {
    raw.as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("is_html").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

fn parse_message_id(raw: &Option<String>) -> Option<String> {
    raw.as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("message_id").and_then(|m| m.as_str().map(String::from)))
}

fn sanitize_header_value(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .collect()
}

fn sanitize_header_block(raw: &str) -> String {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(normalized.len());
    for line in normalized.split('\n') {
        if line.is_empty() {
            break;
        }
        let clean: String = line.chars().filter(|c| *c != '\0').collect();
        out.push_str(&clean);
        out.push_str("\r\n");
    }
    out
}

pub fn build_rfc5322(m: &CachedMessage) -> Vec<u8> {
    let mut out = String::new();

    if let Some(h) = &m.raw_headers {
        if looks_like_headers(h) {
            out.push_str(&sanitize_header_block(h));
            out.push_str("\r\n");
            if let Some(b) = &m.body_text {
                out.push_str(b);
            }
            return out.into_bytes();
        }
    }

    let is_html = parse_is_html(&m.raw_headers);
    let mid = parse_message_id(&m.raw_headers);

    if let Some(s) = &m.date {
        out.push_str(&format!("Date: {}\r\n", sanitize_header_value(s)));
    }
    if let Some(s) = &m.sender {
        out.push_str(&format!("From: {}\r\n", sanitize_header_value(s)));
    }
    if let Some(s) = &m.recipients {
        out.push_str(&format!("To: {}\r\n", sanitize_header_value(s)));
    }
    if let Some(s) = &m.subject {
        out.push_str(&format!("Subject: {}\r\n", sanitize_header_value(s)));
    }
    if let Some(id) = mid {
        out.push_str(&format!("Message-ID: <{}>\r\n", sanitize_header_value(&id)));
    }
    out.push_str("MIME-Version: 1.0\r\n");
    if is_html {
        out.push_str("Content-Type: text/html; charset=utf-8\r\n");
    } else {
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    }
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    if let Some(b) = &m.body_text {
        out.push_str(b);
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_header_block_normalizes_and_strips_nul() {
        let raw = "From: a@b.com\nSubject: hi\0there\n";
        let out = sanitize_header_block(raw);
        assert_eq!(out, "From: a@b.com\r\nSubject: hithere\r\n");
        assert!(!out.contains('\0'));
    }

    #[test]
    fn sanitize_header_block_stops_at_blank_line_preventing_body_smuggling() {
        let raw = "From: a@b.com\r\n\r\nInjected: evil\r\nbody";
        let out = sanitize_header_block(raw);
        assert_eq!(out, "From: a@b.com\r\n");
        assert!(!out.contains("Injected"));
    }
}
