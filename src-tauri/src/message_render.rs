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
use sha2::{Digest, Sha256};

use crate::db::{CachedAttachment, CachedMessage, ATTACHMENTS_FAILED, ATTACHMENTS_PENDING};
use crate::imap::server::date_header_rfc2822;

const BASE64_LINE: usize = 76;
const LEGACY_NOTE_PREFIX: &str = "[This message has ";

#[derive(Debug, Clone, PartialEq)]
pub struct RenderedPart {
    pub section: String,
    pub header_start: usize,
    pub header_end: usize,
    pub body_start: usize,
    pub body_end: usize,
}

#[derive(Debug, Clone)]
pub struct Rendered {
    pub text: String,
    pub size: usize,
    pub header_end: usize,
    pub parts: Vec<RenderedPart>,
    pub bodystructure: String,
}

impl Rendered {
    pub fn header(&self) -> &str {
        &self.text[..self.header_end]
    }

    pub fn body(&self) -> &str {
        &self.text[self.header_end..]
    }

    pub fn part(&self, section: &str) -> Option<&RenderedPart> {
        self.parts.iter().find(|p| p.section == section)
    }

    pub fn part_body(&self, section: &str) -> Option<&str> {
        self.part(section)
            .map(|p| &self.text[p.body_start..p.body_end])
    }

    pub fn part_header(&self, section: &str) -> Option<&str> {
        self.part(section)
            .map(|p| &self.text[p.header_start..p.header_end])
    }
}

struct Out {
    buf: String,
    len: usize,
    materialize: bool,
}

impl Out {
    fn push(&mut self, s: &str) {
        self.len += s.len();
        if self.materialize {
            self.buf.push_str(s);
        }
    }

    fn push_base64(&mut self, data: &[u8], size_hint: usize) {
        if self.materialize {
            let encoded = STANDARD.encode(data);
            let bytes = encoded.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                let end = (i + BASE64_LINE).min(bytes.len());
                self.buf.push_str(&encoded[i..end]);
                self.buf.push_str("\r\n");
                self.len += end - i + 2;
                i = end;
            }
        } else {
            self.len += base64_encoded_len(size_hint);
        }
    }
}

pub fn base64_encoded_len(raw_len: usize) -> usize {
    if raw_len == 0 {
        return 0;
    }
    let b64 = raw_len.div_ceil(3) * 4;
    b64 + b64.div_ceil(BASE64_LINE) * 2
}

fn sanitize_header(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .collect()
}

fn quote(s: &str) -> String {
    let cleaned = sanitize_header(s);
    format!("\"{}\"", cleaned.replace('\\', "\\\\").replace('"', "\\\""))
}

fn safe_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '"' => '\'',
            '\\' => '_',
            _ => c,
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed.chars().take(200).collect()
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn header_name_params(name: &str) -> (String, String) {
    let safe = safe_filename(name);
    if safe.is_ascii() {
        (
            format!("name=\"{}\"", safe),
            format!("filename=\"{}\"", safe),
        )
    } else {
        let word = format!("=?UTF-8?B?{}?=", STANDARD.encode(safe.as_bytes()));
        (
            format!("name=\"{}\"", word),
            format!(
                "filename=\"{}\"; filename*=UTF-8''{}",
                word,
                percent_encode(&safe)
            ),
        )
    }
}

fn clean_content_id(cid: &str) -> String {
    sanitize_header(cid)
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

fn split_content_type(ct: &str) -> (String, String) {
    let cleaned = sanitize_header(ct);
    let main = cleaned.split(';').next().unwrap_or("").trim();
    match main.split_once('/') {
        Some((t, s)) if !t.is_empty() && !s.is_empty() => {
            (t.to_ascii_uppercase(), s.to_ascii_uppercase())
        }
        _ => ("APPLICATION".to_string(), "OCTET-STREAM".to_string()),
    }
}

fn clean_content_type(ct: &str) -> String {
    let cleaned = sanitize_header(ct);
    let main = cleaned.split(';').next().unwrap_or("").trim();
    if main.contains('/') {
        main.to_ascii_lowercase()
    } else {
        "application/octet-stream".to_string()
    }
}

fn boundary_for(aster_id: &str, level: u8) -> String {
    let mut h = Sha256::new();
    h.update(aster_id.as_bytes());
    let digest = h.finalize();
    let hex: String = digest
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("=_aster_{}_{}", hex, level)
}

fn escape_html_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn format_bytes(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn described_attachments(meta: &serde_json::Value) -> (usize, Vec<String>) {
    let entries = meta
        .get("attachments")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let count = meta
        .get("attachment_count")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(entries.len())
        .max(entries.len());
    let described = entries
        .iter()
        .map(|e| {
            let name = e
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("Attachment");
            let ty = e
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("application/octet-stream");
            match e.get("size").and_then(|v| v.as_i64()) {
                Some(size) => format!("{} ({}, {})", name, ty, format_bytes(size)),
                None => format!("{} ({})", name, ty),
            }
        })
        .collect();
    (count, described)
}

pub fn attachment_status_note(msg: &CachedMessage) -> Option<String> {
    if msg.attachments_state != ATTACHMENTS_PENDING && msg.attachments_state != ATTACHMENTS_FAILED {
        return None;
    }
    if msg
        .body_text
        .as_deref()
        .map(|b| b.contains(LEGACY_NOTE_PREFIX))
        .unwrap_or(false)
    {
        return None;
    }
    let meta: serde_json::Value = msg
        .raw_headers
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let (count, described) = described_attachments(&meta);
    if count == 0 {
        return None;
    }
    let noun = if count == 1 {
        "attachment"
    } else {
        "attachments"
    };
    let list = if described.len() == count {
        format!(": {}", described.join(", "))
    } else {
        String::new()
    };
    let pronoun = if count == 1 { "It" } else { "They" };
    Some(if msg.attachments_state == ATTACHMENTS_PENDING {
        format!(
            "[Aster Bridge is still downloading {} {}{}. {} appears in this message after the download finishes.]",
            count,
            noun,
            list,
            pronoun
        )
        .replace("They appears", "They appear")
    } else {
        format!(
            "[Aster Bridge could not download {} {}{}. To get {}, open the message in the Aster web or mobile app.]",
            count,
            noun,
            list,
            if count == 1 { "it" } else { "them" }
        )
    })
}

pub fn strip_legacy_note(body: &str) -> Option<String> {
    let pos = body.rfind(LEGACY_NOTE_PREFIX)?;
    let mut cut = pos;
    let head = &body[..pos];
    if let Some(p) = head.trim_end().strip_suffix("<p>").map(|h| h.len()) {
        cut = p;
    }
    let mut trimmed = body[..cut].to_string();
    while trimmed.ends_with('\n') || trimmed.ends_with('\r') {
        trimmed.pop();
    }
    Some(trimmed)
}

fn detect_html(meta: &serde_json::Value, body: &str) -> bool {
    meta.get("is_html")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| {
            body.contains("</")
                || body.contains("<html")
                || body.contains("<body")
                || body.contains("<div")
                || body.contains("<p ")
                || body.contains("<!DOCTYPE")
        })
}

fn note_suffix(note: Option<&str>, is_html: bool) -> String {
    match note {
        Some(n) if is_html => format!("\n<p>{}</p>", escape_html_text(n)),
        Some(n) => format!("\n\n{}", n),
        None => String::new(),
    }
}

fn message_id_header(meta: &serde_json::Value, aster_id: &str) -> String {
    let real = meta
        .get("message_id")
        .and_then(|v| v.as_str())
        .map(sanitize_header)
        .filter(|s| !s.is_empty());
    match real {
        Some(mid) if mid.starts_with('<') => format!("Message-ID: {}\r\n", mid),
        Some(mid) => format!("Message-ID: <{}>\r\n", mid),
        None => format!(
            "Message-ID: <{}@aster-bridge>\r\n",
            sanitize_header(aster_id)
        ),
    }
}

fn top_headers(msg: &CachedMessage, meta: &serde_json::Value) -> String {
    let mut out = String::new();
    let date = sanitize_header(&date_header_rfc2822(msg.date.as_deref().unwrap_or("")));
    let from = sanitize_header(msg.sender.as_deref().unwrap_or("unknown@astermail.org"));
    let to = sanitize_header(msg.recipients.as_deref().unwrap_or(""));
    let subject = sanitize_header(msg.subject.as_deref().unwrap_or(""));
    let cc = meta
        .get("cc")
        .and_then(|v| v.as_str())
        .map(sanitize_header)
        .filter(|s| !s.is_empty());
    let bcc = meta
        .get("bcc")
        .and_then(|v| v.as_str())
        .map(sanitize_header)
        .filter(|s| !s.is_empty());
    out.push_str(&format!("Date: {}\r\n", date));
    out.push_str(&format!("From: {}\r\n", from));
    if !to.is_empty() {
        out.push_str(&format!("To: {}\r\n", to));
    }
    if let Some(cc) = cc {
        out.push_str(&format!("Cc: {}\r\n", cc));
    }
    if let Some(bcc) = bcc {
        out.push_str(&format!("Bcc: {}\r\n", bcc));
    }
    out.push_str(&format!("Subject: {}\r\n", subject));
    out.push_str(&message_id_header(meta, &msg.aster_id));
    out.push_str("MIME-Version: 1.0\r\n");
    out
}

fn text_content_type(is_html: bool) -> &'static str {
    if is_html {
        "Content-Type: text/html; charset=utf-8\r\n"
    } else {
        "Content-Type: text/plain; charset=utf-8\r\n"
    }
}

struct TextPart<'a> {
    body: Option<&'a str>,
    body_len_hint: usize,
    suffix: String,
    is_html: bool,
}

impl<'a> TextPart<'a> {
    fn write(&self, out: &mut Out) {
        match self.body {
            Some(b) => out.push(b),
            None => out.len += self.body_len_hint,
        }
        out.push(&self.suffix);
    }

    fn structure(&self, text: &str) -> String {
        let lines = text.chars().filter(|c| *c == '\n').count();
        format!(
            "(\"TEXT\" \"{}\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" {} {})",
            if self.is_html { "HTML" } else { "PLAIN" },
            text.len(),
            lines
        )
    }
}

fn attachment_headers(a: &CachedAttachment, inline: bool) -> String {
    let (name_param, filename_params) = header_name_params(&a.name);
    let ct = clean_content_type(&a.content_type);
    let size = if a.data.is_empty() {
        a.size
    } else {
        a.data.len() as i64
    };
    let mut h = String::new();
    h.push_str(&format!("Content-Type: {}; {}\r\n", ct, name_param));
    h.push_str("Content-Transfer-Encoding: base64\r\n");
    h.push_str(&format!(
        "Content-Disposition: {}; {}; size={}\r\n",
        if inline { "inline" } else { "attachment" },
        filename_params,
        size.max(0)
    ));
    if let Some(cid) = a.content_id.as_deref() {
        let cleaned = clean_content_id(cid);
        if !cleaned.is_empty() {
            h.push_str(&format!("Content-ID: <{}>\r\n", cleaned));
        }
    }
    h.push_str("\r\n");
    h
}

fn attachment_structure(a: &CachedAttachment, inline: bool, encoded_size: usize) -> String {
    let (ty, sub) = split_content_type(&a.content_type);
    let name = safe_filename(&a.name);
    let cid = a
        .content_id
        .as_deref()
        .map(clean_content_id)
        .filter(|c| !c.is_empty())
        .map(|c| quote(&format!("<{}>", c)))
        .unwrap_or_else(|| "NIL".to_string());
    format!(
        "({} {} (\"NAME\" {}) {} NIL \"BASE64\" {} NIL ({} (\"FILENAME\" {})) NIL)",
        quote(&ty),
        quote(&sub),
        quote(&name),
        cid,
        encoded_size,
        if inline {
            "\"INLINE\""
        } else {
            "\"ATTACHMENT\""
        },
        quote(&name)
    )
}

fn attachment_raw_size(a: &CachedAttachment) -> usize {
    if a.data.is_empty() {
        a.size.max(0) as usize
    } else {
        a.data.len()
    }
}

struct Ctx<'a> {
    out: Out,
    parts: Vec<RenderedPart>,
    text: &'a TextPart<'a>,
}

impl<'a> Ctx<'a> {
    fn write_text_part(&mut self, section: &str, header: &str) -> String {
        let header_start = self.out.len;
        self.out.push(header);
        let header_end = self.out.len;
        self.text.write(&mut self.out);
        let body_end = self.out.len;
        self.parts.push(RenderedPart {
            section: section.to_string(),
            header_start,
            header_end,
            body_start: header_end,
            body_end,
        });
        if self.out.materialize {
            self.text.structure(&self.out.buf[header_end..body_end])
        } else {
            String::new()
        }
    }

    fn write_attachment(&mut self, section: &str, a: &CachedAttachment, inline: bool) -> String {
        let header_start = self.out.len;
        self.out.push(&attachment_headers(a, inline));
        let header_end = self.out.len;
        self.out.push_base64(&a.data, attachment_raw_size(a));
        let body_end = self.out.len;
        self.parts.push(RenderedPart {
            section: section.to_string(),
            header_start,
            header_end,
            body_start: header_end,
            body_end,
        });
        attachment_structure(a, inline, body_end - header_end)
    }

    fn write_multipart(
        &mut self,
        section: &str,
        subtype: &str,
        boundary: &str,
        header: &str,
        children: &[Child<'_>],
    ) -> String {
        let header_start = self.out.len;
        self.out.push(header);
        let header_end = self.out.len;
        let mut structures = Vec::new();
        for (idx, child) in children.iter().enumerate() {
            let child_section = if section.is_empty() {
                format!("{}", idx + 1)
            } else {
                format!("{}.{}", section, idx + 1)
            };
            self.out.push(&format!("--{}\r\n", boundary));
            structures.push(match child {
                Child::Text(h) => self.write_text_part(&child_section, h),
                Child::Attachment(a, inline) => self.write_attachment(&child_section, a, *inline),
                Child::Related(inner_boundary, inner_children) => {
                    let inner_header = format!(
                        "Content-Type: multipart/related; boundary=\"{}\"\r\n\r\n",
                        inner_boundary
                    );
                    self.write_multipart(
                        &child_section,
                        "RELATED",
                        inner_boundary,
                        &inner_header,
                        inner_children,
                    )
                }
            });
            self.out.push("\r\n");
        }
        self.out.push(&format!("--{}--\r\n", boundary));
        let body_end = self.out.len;
        if !section.is_empty() {
            self.parts.push(RenderedPart {
                section: section.to_string(),
                header_start,
                header_end,
                body_start: header_end,
                body_end,
            });
        }
        format!(
            "({} \"{}\" (\"BOUNDARY\" \"{}\") NIL NIL)",
            structures.join(""),
            subtype,
            boundary
        )
    }
}

enum Child<'a> {
    Text(String),
    Attachment(&'a CachedAttachment, bool),
    Related(String, Vec<Child<'a>>),
}

pub fn render(
    msg: &CachedMessage,
    attachments: &[CachedAttachment],
    materialize: bool,
) -> Rendered {
    let meta: serde_json::Value = msg
        .raw_headers
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let body_present = msg.body_text.as_deref();
    let is_html = detect_html(&meta, body_present.unwrap_or(""));
    let note = attachment_status_note(msg);
    let text = TextPart {
        body: if materialize {
            Some(body_present.unwrap_or(""))
        } else {
            body_present
        },
        body_len_hint: msg.size.max(0) as usize,
        suffix: note_suffix(note.as_deref(), is_html),
        is_html,
    };

    let mut ctx = Ctx {
        out: Out {
            buf: String::new(),
            len: 0,
            materialize,
        },
        parts: Vec::new(),
        text: &text,
    };

    let mut top = top_headers(msg, &meta);

    if attachments.is_empty() {
        top.push_str(text_content_type(is_html));
        top.push_str("Content-Transfer-Encoding: 8bit\r\n");
        top.push_str("\r\n");
        let structure = ctx.write_text_part("1", &top);
        let header_end = top.len();
        return Rendered {
            text: ctx.out.buf,
            size: ctx.out.len,
            header_end,
            parts: ctx.parts,
            bodystructure: structure,
        };
    }

    let text_header = format!(
        "{}Content-Transfer-Encoding: 8bit\r\n\r\n",
        text_content_type(is_html)
    );
    let mut inline: Vec<&CachedAttachment> = Vec::new();
    let mut regular: Vec<&CachedAttachment> = Vec::new();
    for a in attachments {
        if is_html
            && a.is_inline
            && a.content_id
                .as_deref()
                .map(|c| !c.trim().is_empty())
                .unwrap_or(false)
        {
            inline.push(a);
        } else {
            regular.push(a);
        }
    }

    let outer_boundary = boundary_for(&msg.aster_id, 0);
    let inner_boundary = boundary_for(&msg.aster_id, 1);
    let (subtype, boundary, children): (&str, String, Vec<Child<'_>>) = if inline.is_empty() {
        let mut c = vec![Child::Text(text_header)];
        c.extend(regular.iter().map(|a| Child::Attachment(a, false)));
        ("MIXED", outer_boundary.clone(), c)
    } else if regular.is_empty() {
        let mut c = vec![Child::Text(text_header)];
        c.extend(inline.iter().map(|a| Child::Attachment(a, true)));
        ("RELATED", outer_boundary.clone(), c)
    } else {
        let mut related = vec![Child::Text(text_header)];
        related.extend(inline.iter().map(|a| Child::Attachment(a, true)));
        let mut c = vec![Child::Related(inner_boundary.clone(), related)];
        c.extend(regular.iter().map(|a| Child::Attachment(a, false)));
        ("MIXED", outer_boundary.clone(), c)
    };

    top.push_str(&format!(
        "Content-Type: multipart/{}; boundary=\"{}\"\r\n\r\n",
        subtype.to_ascii_lowercase(),
        boundary
    ));
    let header_end = top.len();
    let structure = ctx.write_multipart("", subtype, &boundary, &top, &children);
    Rendered {
        text: ctx.out.buf,
        size: ctx.out.len,
        header_end,
        parts: ctx.parts,
        bodystructure: structure,
    }
}

pub fn render_text(msg: &CachedMessage, attachments: &[CachedAttachment]) -> String {
    render(msg, attachments, true).text
}

pub fn rendered_size(msg: &CachedMessage, attachments: &[CachedAttachment]) -> usize {
    render(msg, attachments, false).size
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ATTACHMENTS_STORED;

    fn msg(body: Option<&str>, raw: Option<&str>, state: i64) -> CachedMessage {
        CachedMessage {
            aster_id: "msg-1".to_string(),
            folder: "inbox".to_string(),
            subject: Some("Hello".to_string()),
            sender: Some("Alice <alice@example.com>".to_string()),
            recipients: Some("bob@example.com".to_string()),
            date: Some("2026-09-01T10:00:00Z".to_string()),
            size: body.map(|b| b.len() as i64).unwrap_or(0),
            flags: 0,
            body_text: body.map(str::to_string),
            raw_headers: raw.map(str::to_string),
            imap_uid: 1,
            thread_id: None,
            attachments_state: state,
        }
    }

    fn att(seq: i64, name: &str, ct: &str, data: &[u8]) -> CachedAttachment {
        CachedAttachment {
            seq,
            name: name.to_string(),
            content_type: ct.to_string(),
            content_id: None,
            is_inline: false,
            size: data.len() as i64,
            data: data.to_vec(),
        }
    }

    #[test]
    fn a_message_without_attachments_renders_single_part() {
        let m = msg(Some("plain body"), Some("{\"is_html\":false}"), 0);
        let r = render(&m, &[], true);
        assert!(r.text.starts_with("Date: "));
        assert!(r.text.contains("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nplain body"));
        assert!(r.text.ends_with("plain body"));
        assert_eq!(r.body(), "plain body");
        assert_eq!(r.part_body("1"), Some("plain body"));
        assert_eq!(r.size, r.text.len());
        assert_eq!(
            r.bodystructure,
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" 10 0)"
        );
    }

    #[test]
    fn size_only_mode_matches_the_materialized_length() {
        let body = "hello\nworld";
        let raw = "{\"is_html\":false,\"attachment_count\":2,\"attachments\":[{\"seq\":0,\"name\":\"a.pdf\",\"type\":\"application/pdf\",\"size\":5},{\"seq\":1,\"name\":\"b.png\",\"type\":\"image/png\",\"size\":300}]}";
        let atts = vec![
            att(0, "a.pdf", "application/pdf", b"%PDF!"),
            att(1, "b.png", "image/png", &[7u8; 300]),
        ];
        let full = msg(Some(body), Some(raw), ATTACHMENTS_STORED);
        let materialized = render(&full, &atts, true);
        let mut meta_only = full.clone();
        meta_only.body_text = None;
        let mut meta_atts = atts.clone();
        for a in &mut meta_atts {
            a.data.clear();
        }
        assert_eq!(
            rendered_size(&meta_only, &meta_atts),
            materialized.text.len()
        );
        assert_eq!(materialized.size, materialized.text.len());
    }

    #[test]
    fn size_only_mode_matches_for_pending_notes_too() {
        let raw = "{\"is_html\":true,\"attachment_count\":1,\"attachments\":[{\"seq\":0,\"name\":\"a.pdf\",\"type\":\"application/pdf\",\"size\":5}]}";
        let full = msg(Some("<p>hi</p>"), Some(raw), ATTACHMENTS_PENDING);
        let materialized = render(&full, &[], true);
        let mut meta_only = full.clone();
        meta_only.body_text = None;
        assert_eq!(rendered_size(&meta_only, &[]), materialized.text.len());
        assert!(materialized
            .text
            .contains("still downloading 1 attachment: a.pdf (application/pdf, 5 B)"));
        assert!(materialized.text.contains("<p>[Aster Bridge"));
    }

    #[test]
    fn attachments_render_as_multipart_mixed_with_base64_parts() {
        let atts = vec![att(0, "report.pdf", "application/pdf", b"%PDF-1.7 content")];
        let m = msg(
            Some("see attached"),
            Some("{\"is_html\":false}"),
            ATTACHMENTS_STORED,
        );
        let r = render(&m, &atts, true);
        assert!(r
            .header()
            .contains("Content-Type: multipart/mixed; boundary=\""));
        assert!(!r.header().contains("Content-Transfer-Encoding"));
        assert_eq!(r.part_body("1"), Some("see attached"));
        let part2 = r.part_header("2").unwrap();
        assert!(part2.contains("Content-Type: application/pdf; name=\"report.pdf\""));
        assert!(part2.contains("Content-Disposition: attachment; filename=\"report.pdf\"; size=16"));
        let encoded = r.part_body("2").unwrap();
        let decoded = STANDARD.decode(encoded.replace("\r\n", "")).unwrap();
        assert_eq!(decoded, b"%PDF-1.7 content");
        assert!(r.text.ends_with("--\r\n"));
        assert!(r.bodystructure.starts_with("((\"TEXT\" \"PLAIN\""));
        assert!(r
            .bodystructure
            .contains("(\"APPLICATION\" \"PDF\" (\"NAME\" \"report.pdf\") NIL NIL \"BASE64\""));
        assert!(r
            .bodystructure
            .contains("(\"ATTACHMENT\" (\"FILENAME\" \"report.pdf\"))"));
        assert!(r
            .bodystructure
            .contains("\"MIXED\" (\"BOUNDARY\" \"=_aster_"));
    }

    #[test]
    fn multipart_structure_ends_with_the_boundary_parameter() {
        let atts = vec![att(0, "a.txt", "text/plain", b"x")];
        let m = msg(Some("b"), None, ATTACHMENTS_STORED);
        let r = render(&m, &atts, true);
        assert!(r
            .bodystructure
            .contains("\"MIXED\" (\"BOUNDARY\" \"=_aster_"));
        assert!(r.bodystructure.ends_with("\") NIL NIL)"));
    }

    #[test]
    fn inline_images_in_html_go_under_multipart_related() {
        let mut logo = att(0, "logo.png", "image/png", &[1u8; 10]);
        logo.is_inline = true;
        logo.content_id = Some("<logo@x>".to_string());
        let pdf = att(1, "doc.pdf", "application/pdf", b"pdf");
        let m = msg(
            Some("<p><img src=\"cid:logo@x\"></p>"),
            Some("{\"is_html\":true}"),
            ATTACHMENTS_STORED,
        );
        let r = render(&m, &[logo, pdf], true);
        assert!(r.header().contains("multipart/mixed"));
        assert!(r.part_header("1").unwrap().contains("multipart/related"));
        assert!(r.part_header("1.1").unwrap().contains("text/html"));
        let inline_hdr = r.part_header("1.2").unwrap();
        assert!(inline_hdr.contains("Content-Disposition: inline"));
        assert!(inline_hdr.contains("Content-ID: <logo@x>"));
        assert!(r.part_header("2").unwrap().contains("doc.pdf"));
        assert!(r.bodystructure.contains("\"RELATED\""));
        assert!(r
            .bodystructure
            .contains("(\"INLINE\" (\"FILENAME\" \"logo.png\"))"));
        assert!(r.bodystructure.contains("\"<logo@x>\""));
    }

    #[test]
    fn non_ascii_filenames_are_encoded_and_header_injection_is_stripped() {
        let a = att(0, "Ré\"su\\mé\r\nX-Evil: yes.pdf", "application/pdf", b"x");
        let m = msg(Some("b"), None, ATTACHMENTS_STORED);
        let r = render(&m, &[a], true);
        let h = r.part_header("2").unwrap();
        assert!(!h.contains(
            "
X-Evil"
        ));
        assert!(h.lines().all(|l| !l.starts_with("X-Evil")));
        assert!(!h.contains("X-Evil: yes"));
        assert!(h.contains("=?UTF-8?B?"));
        assert!(h.contains("filename*=UTF-8''R%C3%A9"));
        assert!(h.lines().all(|l| l.is_ascii()));
    }

    #[test]
    fn a_failed_download_explains_itself_without_attachments() {
        let raw = "{\"is_html\":false,\"attachment_count\":2,\"attachments\":[{\"seq\":0,\"name\":\"a.pdf\",\"type\":\"application/pdf\",\"size\":5},{\"seq\":1,\"name\":\"b.png\",\"type\":\"image/png\"}]}";
        let m = msg(Some("body"), Some(raw), ATTACHMENTS_FAILED);
        let r = render(&m, &[], true);
        assert!(r.body().starts_with("body\n\n[Aster Bridge could not download 2 attachments: a.pdf (application/pdf, 5 B), b.png (image/png). To get them, open the message in the Aster web or mobile app.]"));
        assert!(r.header().contains("text/plain"));
    }

    #[test]
    fn a_stored_message_carries_no_note() {
        let raw = "{\"is_html\":false,\"attachment_count\":1,\"attachments\":[{\"seq\":0,\"name\":\"a.pdf\",\"type\":\"application/pdf\"}]}";
        let m = msg(Some("body"), Some(raw), ATTACHMENTS_STORED);
        let r = render(&m, &[att(0, "a.pdf", "application/pdf", b"x")], true);
        assert!(!r.text.contains("Aster Bridge"));
    }

    #[test]
    fn a_legacy_baked_note_is_not_doubled() {
        let raw = "{\"is_html\":false,\"attachment_count\":1,\"attachments\":[{\"seq\":0,\"name\":\"a.pdf\",\"type\":\"application/pdf\"}]}";
        let m = msg(
            Some("body\n\n[This message has 1 attachment that Aster Bridge cannot download yet: a.pdf. To get it, open the message in the Aster web or mobile app.]"),
            Some(raw),
            ATTACHMENTS_PENDING,
        );
        let r = render(&m, &[], true);
        assert_eq!(r.text.matches("Aster Bridge").count(), 1);
    }

    #[test]
    fn strip_legacy_note_removes_plain_and_html_notes() {
        assert_eq!(
            strip_legacy_note("body\n\n[This message has 1 attachment ... app.]").as_deref(),
            Some("body")
        );
        assert_eq!(
            strip_legacy_note("<p>hi</p>\n<p>[This message has 2 attachments ... them.]</p>")
                .as_deref(),
            Some("<p>hi</p>")
        );
        assert_eq!(strip_legacy_note("no note"), None);
    }

    #[test]
    fn base64_length_formula_matches_the_encoder() {
        for n in [0usize, 1, 2, 3, 56, 57, 58, 113, 114, 115, 1000, 4096] {
            let data = vec![9u8; n];
            let mut out = Out {
                buf: String::new(),
                len: 0,
                materialize: true,
            };
            out.push_base64(&data, n);
            assert_eq!(out.buf.len(), base64_encoded_len(n), "n={}", n);
            assert_eq!(out.len, base64_encoded_len(n));
        }
    }
}
