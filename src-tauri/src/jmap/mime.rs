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

    fn base_msg() -> CachedMessage {
        CachedMessage {
            aster_id: "id-1".to_string(),
            folder: "inbox".to_string(),
            subject: Some("Hello".to_string()),
            sender: Some("Alice <a@b.com>".to_string()),
            recipients: Some("Bob <b@c.com>".to_string()),
            date: Some("Wed, 21 May 2026 10:00:00 +0000".to_string()),
            size: 42,
            flags: 0,
            body_text: Some("body content".to_string()),
            raw_headers: Some("{}".to_string()),
            imap_uid: 1,
            thread_id: None,
        }
    }

    #[test]
    fn looks_like_headers_detects_header_vs_json() {
        assert!(looks_like_headers("From: a@b.com\nSubject: x"));
        assert!(!looks_like_headers("{\"is_html\": true}"));
        assert!(!looks_like_headers("just text no colon"));
    }

    #[test]
    fn parse_is_html_reads_flag() {
        assert!(parse_is_html(&Some("{\"is_html\": true}".to_string())));
        assert!(!parse_is_html(&Some("{\"is_html\": false}".to_string())));
        assert!(!parse_is_html(&Some("{}".to_string())));
        assert!(!parse_is_html(&None));
    }

    #[test]
    fn parse_message_id_extracts() {
        assert_eq!(
            parse_message_id(&Some("{\"message_id\": \"abc@x\"}".to_string())),
            Some("abc@x".to_string())
        );
        assert_eq!(parse_message_id(&Some("{}".to_string())), None);
        assert_eq!(parse_message_id(&None), None);
    }

    #[test]
    fn sanitize_header_value_strips_crlf_and_nul() {
        assert_eq!(sanitize_header_value("a\r\nb\0c"), "abc");
    }

    #[test]
    fn build_rfc5322_synthesizes_headers_from_fields() {
        let out = String::from_utf8(build_rfc5322(&base_msg())).unwrap();
        assert!(out.contains("From: Alice <a@b.com>\r\n"));
        assert!(out.contains("To: Bob <b@c.com>\r\n"));
        assert!(out.contains("Subject: Hello\r\n"));
        assert!(out.contains("MIME-Version: 1.0\r\n"));
        assert!(out.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(out.contains("\r\n\r\nbody content"));
    }

    #[test]
    fn build_rfc5322_html_content_type() {
        let mut m = base_msg();
        m.raw_headers = Some("{\"is_html\": true}".to_string());
        let out = String::from_utf8(build_rfc5322(&m)).unwrap();
        assert!(out.contains("Content-Type: text/html; charset=utf-8\r\n"));
    }

    #[test]
    fn build_rfc5322_includes_message_id() {
        let mut m = base_msg();
        m.raw_headers = Some("{\"message_id\": \"mid-9@host\"}".to_string());
        let out = String::from_utf8(build_rfc5322(&m)).unwrap();
        assert!(out.contains("Message-ID: <mid-9@host>\r\n"));
    }

    #[test]
    fn build_rfc5322_uses_raw_header_block_when_present() {
        let mut m = base_msg();
        m.raw_headers = Some("From: raw@x.com\nSubject: Raw Subject\n".to_string());
        let out = String::from_utf8(build_rfc5322(&m)).unwrap();
        assert!(out.starts_with("From: raw@x.com\r\nSubject: Raw Subject\r\n\r\n"));
        assert!(out.contains("body content"));
        assert!(!out.contains("MIME-Version"));
    }

    #[test]
    fn build_rfc5322_strips_injection_in_synthesized_headers() {
        let mut m = base_msg();
        m.subject = Some("evil\r\nBcc: attacker@x.com".to_string());
        let out = String::from_utf8(build_rfc5322(&m)).unwrap();
        assert!(out.contains("Subject: evilBcc: attacker@x.com\r\n"));
        assert!(!out.contains("\r\nBcc:"));
    }

    #[test]
    fn build_rfc5322_handles_missing_optional_fields() {
        let mut m = base_msg();
        m.subject = None;
        m.recipients = None;
        m.date = None;
        m.body_text = None;
        let out = String::from_utf8(build_rfc5322(&m)).unwrap();
        assert!(out.contains("From: Alice <a@b.com>\r\n"));
        assert!(!out.contains("Subject:"));
        assert!(!out.contains("To:"));
        assert!(out.ends_with("\r\n\r\n"));
    }
}
