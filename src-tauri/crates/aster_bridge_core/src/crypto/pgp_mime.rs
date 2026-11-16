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
use mail_parser::{MessageParser, MimeHeaders};

use crate::crypto::attachment::{placeholder_filename, DEFAULT_ATTACHMENT_CONTENT_TYPE};
use crate::crypto::external_pgp_key::ExternalPgpKey;
use crate::db::CachedAttachment;

const PGP_MESSAGE_ARMOR: &str = "-----BEGIN PGP MESSAGE-----";
const MAX_PART_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
const MAX_PARTS: usize = 100;
const SKIPPED_TYPES: [&str; 7] = [
    "application/pgp-signature",
    "application/pgp-keys",
    "application/pgp-encrypted",
    "application/pkcs7-signature",
    "application/x-pkcs7-signature",
    "text/rfc822-headers",
    "multipart/encrypted",
];

#[derive(Debug, Default)]
pub struct DecryptedMime {
    pub html: Option<String>,
    pub text: Option<String>,
    pub attachments: Vec<CachedAttachment>,
}

impl DecryptedMime {
    pub fn body(&self) -> Option<(String, bool)> {
        self.html
            .clone()
            .map(|h| (h, true))
            .or_else(|| self.text.clone().map(|t| (t, false)))
    }
}

pub fn is_armored_message(body: &str) -> bool {
    body.trim_start().starts_with(PGP_MESSAGE_ARMOR)
}

pub fn open_armored_body(
    armored: &str,
    identity_key: Option<&str>,
    previous_keys: &[String],
    passphrase: &[u8],
    external_key: Option<&ExternalPgpKey>,
) -> Option<DecryptedMime> {
    if !is_armored_message(armored) {
        return None;
    }
    let plain = crate::crypto::envelope::decrypt_own_or_external_pgp(
        armored.trim(),
        identity_key,
        previous_keys,
        passphrase,
        external_key,
    )
    .ok()?;
    Some(parse_decrypted(&plain))
}

pub fn parse_decrypted(plain: &[u8]) -> DecryptedMime {
    if !looks_like_mime(plain) {
        return DecryptedMime {
            text: Some(String::from_utf8_lossy(plain).into_owned()),
            ..DecryptedMime::default()
        };
    }
    let Some(parsed) = MessageParser::default().parse(plain) else {
        return DecryptedMime {
            text: Some(String::from_utf8_lossy(plain).into_owned()),
            ..DecryptedMime::default()
        };
    };
    let html = first_body(&parsed, &parsed.html_body, true);
    let text = first_body(&parsed, &parsed.text_body, false);
    let mut attachments = Vec::new();
    let mut total = 0usize;
    for id in parsed.attachments.iter().copied() {
        if attachments.len() >= MAX_PARTS {
            break;
        }
        let Some(part) = parsed.part(id) else { continue };
        let content_type = part_type(part);
        if SKIPPED_TYPES.contains(&content_type.as_str()) {
            continue;
        }
        let data = part.contents();
        if data.is_empty() || data.len() > MAX_PART_BYTES || total + data.len() > MAX_TOTAL_BYTES {
            continue;
        }
        total += data.len();
        let seq = attachments.len() as i64;
        let content_id = part
            .content_id()
            .map(|c| c.trim().trim_matches(&['<', '>'][..]).to_string())
            .filter(|c| !c.is_empty());
        let disposition_inline = part
            .content_disposition()
            .map(|d| d.ctype().eq_ignore_ascii_case("inline"))
            .unwrap_or(false);
        let name = part
            .attachment_name()
            .map(|n| n.chars().filter(|c| !c.is_control()).collect::<String>())
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| placeholder_filename(seq, &content_type));
        attachments.push(CachedAttachment {
            seq,
            name,
            is_inline: content_id.is_some() && (disposition_inline || part.attachment_name().is_none()),
            content_type,
            content_id,
            size: data.len() as i64,
            data: data.to_vec(),
        });
    }
    DecryptedMime { html, text, attachments }
}

fn looks_like_mime(plain: &[u8]) -> bool {
    let head_len = plain.len().min(16 * 1024);
    let head = String::from_utf8_lossy(&plain[..head_len]);
    let normalized = head.replace("\r\n", "\n");
    let header_block = normalized.split("\n\n").next().unwrap_or("");
    header_block
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("content-type:"))
}

fn part_type(part: &mail_parser::MessagePart<'_>) -> String {
    part.content_type()
        .map(|ct| match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub),
            None => ct.ctype().to_string(),
        })
        .map(|t| t.to_ascii_lowercase())
        .unwrap_or_else(|| DEFAULT_ATTACHMENT_CONTENT_TYPE.to_string())
}

fn first_body(parsed: &mail_parser::Message<'_>, ids: &[usize], html: bool) -> Option<String> {
    ids.iter()
        .filter_map(|id| parsed.part(*id))
        .filter(|part| part.is_text() && part.is_text_html() == html)
        .filter(|part| !SKIPPED_TYPES.contains(&part_type(part).as_str()))
        .filter_map(|part| part.text_contents().map(str::to_string))
        .find(|body| !body.trim().is_empty())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    pub const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, b'I', b'H', b'D', b'R'];
    pub const PDF: &[u8] = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n";
    pub const NOTES_TEXT: &str = "caf\u{e9} = cr\u{e8}me br\u{fb}l\u{e9}e\r\nline two with = sign";
    pub const REPORT_NAME: &str = "\u{43e}\u{442}\u{447}\u{451}\u{442}.bin";
    pub const NOTES_NAME: &str = "r\u{e9}sum\u{e9} notes.txt";

    pub fn big_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + i / 7) % 251) as u8).collect()
    }

    fn wrapped_base64(data: &[u8]) -> String {
        let encoded = STANDARD.encode(data);
        encoded
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n")
    }

    pub fn forwarded_tree(big: &[u8]) -> Vec<u8> {
        let png = wrapped_base64(PNG);
        let pdf = wrapped_base64(PDF);
        let report = wrapped_base64(big);
        [
            "Content-Type: multipart/mixed; boundary=\"outer\"; protected-headers=\"v1\"",
            "Subject: Forwarded report",
            "",
            "--outer",
            "Content-Type: text/rfc822-headers; protected-headers=\"v1\"",
            "Content-Disposition: inline",
            "",
            "Subject: Forwarded report",
            "",
            "--outer",
            "Content-Type: multipart/alternative; boundary=\"alt\"",
            "",
            "--alt",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "See the attached report.",
            "--alt",
            "Content-Type: multipart/related; boundary=\"rel\"",
            "",
            "--rel",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>See the attached report.</p><img src=\"cid:chart@forward\">",
            "--rel",
            "Content-Type: image/png",
            "Content-Transfer-Encoding: base64",
            "Content-ID: <chart@forward>",
            "Content-Disposition: inline",
            "",
            &png,
            "--rel--",
            "--alt--",
            "--outer",
            "Content-Type: application/pdf; name=\"report.pdf\"",
            "Content-Disposition: attachment; filename=\"report.pdf\"",
            "Content-Transfer-Encoding: base64",
            "",
            &pdf,
            "--outer",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9%20notes.txt",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "caf=C3=A9 =3D cr=C3=A8me br=C3=BBl=C3=A9e",
            "line two with =3D sign",
            "--outer",
            "Content-Type: application/octet-stream; name=\"=?utf-8?B?0L7RgtGH0ZHRgi5iaW4=?=\"",
            "Content-Disposition: attachment; filename=\"=?utf-8?B?0L7RgtGH0ZHRgi5iaW4=?=\"",
            "Content-Transfer-Encoding: base64",
            "",
            &report,
            "--outer",
            "Content-Type: application/pgp-signature; name=\"signature.asc\"",
            "",
            "-----BEGIN PGP SIGNATURE-----",
            "c2lnbmF0dXJl",
            "-----END PGP SIGNATURE-----",
            "--outer--",
            "",
        ]
        .join("\r\n")
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::crypto::attachment::sha256_hex;

    fn by_name<'a>(parts: &'a [CachedAttachment], name: &str) -> &'a CachedAttachment {
        parts
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("missing {name}: {:?}", parts.iter().map(|p| &p.name).collect::<Vec<_>>()))
    }

    #[test]
    fn nested_tree_yields_every_attachment_with_names_types_and_bytes() {
        let big = big_payload(4096);
        let opened = parse_decrypted(&forwarded_tree(&big));
        assert_eq!(
            opened.body(),
            Some(("<p>See the attached report.</p><img src=\"cid:chart@forward\">".to_string(), true))
        );
        assert_eq!(opened.text.as_deref(), Some("See the attached report."));
        assert_eq!(opened.attachments.len(), 4);

        let chart = opened
            .attachments
            .iter()
            .find(|p| p.content_id.as_deref() == Some("chart@forward"))
            .unwrap();
        assert_eq!(chart.content_type, "image/png");
        assert!(chart.is_inline);
        assert_eq!(chart.data, PNG);

        let pdf = by_name(&opened.attachments, "report.pdf");
        assert_eq!(pdf.content_type, "application/pdf");
        assert!(!pdf.is_inline);
        assert_eq!(pdf.data, PDF);

        let notes = by_name(&opened.attachments, NOTES_NAME);
        assert_eq!(notes.content_type, "text/plain");
        assert_eq!(String::from_utf8(notes.data.clone()).unwrap(), NOTES_TEXT);

        let report = by_name(&opened.attachments, REPORT_NAME);
        assert_eq!(sha256_hex(&report.data), sha256_hex(&big));
        assert_eq!(report.size, big.len() as i64);
    }

    #[test]
    fn signature_and_protected_header_parts_are_not_attachments() {
        let opened = parse_decrypted(&forwarded_tree(b"x"));
        assert!(opened.attachments.iter().all(|p| p.content_type != "application/pgp-signature"));
        assert!(opened.attachments.iter().all(|p| p.content_type != "text/rfc822-headers"));
    }

    #[test]
    fn continued_and_q_encoded_names_are_decoded() {
        let raw = [
            "Content-Type: multipart/mixed; boundary=\"b\"",
            "",
            "--b",
            "Content-Type: text/plain",
            "",
            "body",
            "--b",
            "Content-Type: application/zip",
            "Content-Disposition: attachment; filename*0*=utf-8''%E6%97%A5%E6%9C%AC; filename*1*=%E8%AA%9E.zip",
            "Content-Transfer-Encoding: base64",
            "",
            "UEsDBA==",
            "--b",
            "Content-Type: text/csv; name=\"=?utf-8?Q?d=C3=A9j=C3=A0_vu.csv?=\"",
            "Content-Disposition: attachment",
            "",
            "a,b",
            "--b--",
            "",
        ]
        .join("\r\n");
        let opened = parse_decrypted(raw.as_bytes());
        let names: Vec<&str> = opened.attachments.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["\u{65e5}\u{672c}\u{8a9e}.zip", "d\u{e9}j\u{e0} vu.csv"]);
        assert_eq!(opened.attachments[0].data, b"PK\x03\x04");
    }

    #[test]
    fn plain_payload_without_headers_is_body_text_only() {
        let opened = parse_decrypted(b"Hello there,\r\n\r\nNo files here.");
        assert_eq!(opened.body(), Some(("Hello there,\r\n\r\nNo files here.".to_string(), false)));
        assert!(opened.attachments.is_empty());
    }

    #[test]
    fn mime_body_without_attachments_keeps_only_the_body() {
        let opened = parse_decrypted(b"Content-Type: text/plain; charset=utf-8\r\n\r\nJust words.");
        assert_eq!(opened.body(), Some(("Just words.".to_string(), false)));
        assert!(opened.attachments.is_empty());
    }

    #[test]
    fn armored_body_opens_with_own_key_signed_or_not() {
        let key = aster_crypto::generate_keypair("throwaway test key", "test-key@example.invalid").unwrap();
        let secret = key.to_armored().unwrap();
        let big = big_payload(3 * 1024 * 1024);
        let tree = forwarded_tree(&big);
        let unsigned = aster_crypto::encrypt_message(&tree, &[&key.public_key()]).unwrap();
        let signed = aster_crypto::encrypt_and_sign_with_passphrase(&tree, &[&key.public_key()], &key, "").unwrap();
        for armored in [unsigned, signed] {
            let armored = String::from_utf8(armored).unwrap();
            assert!(is_armored_message(&armored));
            let opened = open_armored_body(&armored, Some(&secret), &[], b"", None).unwrap();
            assert_eq!(opened.attachments.len(), 4);
            let report = by_name(&opened.attachments, REPORT_NAME);
            assert_eq!(sha256_hex(&report.data), sha256_hex(&big));
        }
    }

    #[test]
    fn armored_body_for_someone_else_stays_closed() {
        let ours = aster_crypto::generate_keypair("throwaway test key", "test-key@example.invalid").unwrap();
        let theirs = aster_crypto::generate_keypair("other test key", "other-key@example.invalid").unwrap();
        let armored =
            aster_crypto::encrypt_message(b"Content-Type: text/plain\r\n\r\nhi", &[&theirs.public_key()]).unwrap();
        let armored = String::from_utf8(armored).unwrap();
        let ours = ours.to_armored().unwrap();
        assert!(open_armored_body(&armored, Some(&ours), &[], b"", None).is_none());
    }
}
