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
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::api_client::AttachmentResponse;
use crate::crypto::envelope::{decrypt_pbkdf2_envelope, encrypt_pbkdf2_envelope};
use crate::error::{BridgeError, Result};

const SESSION_KEY_LEN: usize = 32;
const DATA_NONCE_LEN: usize = 12;
pub const DEFAULT_ATTACHMENT_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AttachmentKeyEntry {
    pub key: Option<String>,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub content_id: Option<String>,
    pub size: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedAttachment {
    pub seq: i64,
    pub filename: String,
    pub content_type: String,
    pub content_id: Option<String>,
    pub is_inline: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
struct RowMeta {
    filename: Option<String>,
    content_type: Option<String>,
    session_key: Option<String>,
    content_id: Option<String>,
    is_inline: Option<bool>,
}

pub fn attachment_data_aad(seq: i64) -> Vec<u8> {
    format!("aster-attachment-v2|att={}|part=data", seq).into_bytes()
}

pub fn normalize_content_type(raw: Option<&str>) -> String {
    match raw.map(str::trim) {
        Some(s) if s.contains('/') => s.to_ascii_lowercase(),
        _ => DEFAULT_ATTACHMENT_CONTENT_TYPE.to_string(),
    }
}

pub fn placeholder_filename(seq: i64, content_type: &str) -> String {
    let ext = match content_type {
        "application/pdf" => "pdf",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "text/plain" => "txt",
        "text/html" => "html",
        "application/zip" => "zip",
        _ => "bin",
    };
    format!("attachment-{}.{}", seq + 1, ext)
}

fn is_sealed_meta_nonce(nonce: &[u8]) -> bool {
    nonce.len() == DATA_NONCE_LEN && nonce.iter().any(|b| *b != 0)
}

fn is_plaintext_data_nonce(nonce: &[u8]) -> bool {
    nonce.len() == DATA_NONCE_LEN && nonce.iter().all(|b| *b == 0)
}

fn json_string(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn row_meta_from_json(v: &serde_json::Value) -> Option<RowMeta> {
    if !v.is_object() {
        return None;
    }
    let filename = json_string(v, "filename")?;
    Some(RowMeta {
        filename: Some(filename),
        content_type: json_string(v, "content_type"),
        session_key: json_string(v, "session_key"),
        content_id: json_string(v, "content_id"),
        is_inline: v.get("is_inline").and_then(|x| x.as_bool()),
    })
}

fn decode_session_key(b64: &str) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>> {
    let raw = Zeroizing::new(
        STANDARD
            .decode(b64.trim())
            .map_err(|e| BridgeError::Crypto(format!("attachment key decode: {}", e)))?,
    );
    if raw.len() != SESSION_KEY_LEN {
        return Err(BridgeError::Crypto(
            "attachment key has the wrong length".to_string(),
        ));
    }
    let mut key = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    key.copy_from_slice(&raw);
    Ok(key)
}

fn open_sealed_meta(encrypted_meta: &[u8], meta_nonce: &[u8], key_b64: &str) -> Option<RowMeta> {
    let key = decode_session_key(key_b64).ok()?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).ok()?;
    let plain = cipher
        .decrypt(Nonce::from_slice(meta_nonce), encrypted_meta)
        .ok()?;
    let parsed: serde_json::Value = serde_json::from_slice(&plain).ok()?;
    let mut meta = row_meta_from_json(&parsed)?;
    meta.session_key = Some(key_b64.to_string());
    Some(meta)
}

fn open_client_authored_meta(
    encrypted_meta_b64: &str,
    encrypted_meta: &[u8],
    passphrase: &[u8],
    identity_key: Option<&str>,
) -> Option<RowMeta> {
    if let Ok(text) = std::str::from_utf8(encrypted_meta) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(meta) = row_meta_from_json(&parsed) {
                if meta.session_key.is_some() {
                    return Some(meta);
                }
            }
        }
        if text.starts_with("-----BEGIN PGP MESSAGE-----") {
            let ik = identity_key?;
            let key_pair = aster_crypto::import_secret_key(ik).ok()?;
            let decrypted = aster_crypto::decrypt_message(text.as_bytes(), &[&key_pair]).ok()?;
            let parsed: serde_json::Value = serde_json::from_slice(&decrypted).ok()?;
            return row_meta_from_json(&parsed);
        }
    }
    let plain = Zeroizing::new(decrypt_pbkdf2_envelope(encrypted_meta_b64, passphrase).ok()?);
    let parsed: serde_json::Value = serde_json::from_str(&plain).ok()?;
    row_meta_from_json(&parsed)
}

fn decrypt_data(
    seq: i64,
    encrypted_data: &[u8],
    data_nonce: &[u8],
    key_b64: &str,
) -> Result<Vec<u8>> {
    if data_nonce.len() != DATA_NONCE_LEN {
        return Err(BridgeError::Crypto(
            "attachment data nonce has the wrong length".to_string(),
        ));
    }
    let key = decode_session_key(key_b64)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|e| BridgeError::Crypto(format!("attachment cipher init: {}", e)))?;
    let nonce = Nonce::from_slice(data_nonce);
    let aad = attachment_data_aad(seq);
    if let Ok(plain) = cipher.decrypt(
        nonce,
        Payload {
            msg: encrypted_data,
            aad: &aad,
        },
    ) {
        return Ok(plain);
    }
    cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| BridgeError::Crypto("attachment data decrypt failed".to_string()))
}

pub fn decrypt_attachment(
    row: &AttachmentResponse,
    entry: Option<&AttachmentKeyEntry>,
    passphrase: &[u8],
    identity_key: Option<&str>,
) -> Result<DecryptedAttachment> {
    let seq = row.seq_num as i64;
    let encrypted_meta = STANDARD
        .decode(row.encrypted_meta.trim())
        .map_err(|e| BridgeError::Crypto(format!("attachment meta decode: {}", e)))?;
    let meta_nonce = if row.meta_nonce.trim().is_empty() {
        Vec::new()
    } else {
        STANDARD
            .decode(row.meta_nonce.trim())
            .map_err(|e| BridgeError::Crypto(format!("attachment meta nonce decode: {}", e)))?
    };
    let entry_key = entry
        .and_then(|e| e.key.as_deref())
        .map(str::trim)
        .filter(|k| !k.is_empty());

    let mut row_meta: Option<RowMeta> = None;
    if is_sealed_meta_nonce(&meta_nonce) {
        if let Some(key) = entry_key {
            row_meta = open_sealed_meta(&encrypted_meta, &meta_nonce, key);
        }
    }
    if row_meta.is_none() && !encrypted_meta.is_empty() {
        row_meta = open_client_authored_meta(
            row.encrypted_meta.trim(),
            &encrypted_meta,
            passphrase,
            identity_key,
        );
    }
    let row_meta = row_meta.unwrap_or_default();

    let session_key = row_meta
        .session_key
        .clone()
        .or_else(|| entry_key.map(str::to_string));

    let content_type = normalize_content_type(
        entry
            .and_then(|e| e.content_type.as_deref())
            .filter(|s| s.contains('/'))
            .or(row_meta.content_type.as_deref()),
    );
    let filename = entry
        .and_then(|e| e.filename.clone())
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .or_else(|| row_meta.filename.clone())
        .unwrap_or_else(|| placeholder_filename(seq, &content_type));
    let content_id = entry
        .and_then(|e| e.content_id.clone())
        .filter(|c| !c.trim().is_empty())
        .or_else(|| row_meta.content_id.clone());

    let encrypted_data = STANDARD
        .decode(row.encrypted_data.trim())
        .map_err(|e| BridgeError::Crypto(format!("attachment data decode: {}", e)))?;
    let data_nonce = STANDARD
        .decode(row.data_nonce.trim())
        .map_err(|e| BridgeError::Crypto(format!("attachment data nonce decode: {}", e)))?;

    let data = match session_key {
        Some(key) => decrypt_data(seq, &encrypted_data, &data_nonce, &key)?,
        None if is_plaintext_data_nonce(&data_nonce) => encrypted_data,
        None => {
            return Err(BridgeError::Crypto(
                "attachment key unavailable".to_string(),
            ))
        }
    };
    if data.is_empty() {
        return Err(BridgeError::Crypto(
            "attachment payload is empty".to_string(),
        ));
    }

    Ok(DecryptedAttachment {
        seq,
        filename,
        content_type,
        content_id,
        is_inline: row_meta.is_inline.unwrap_or(false),
        data,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutgoingAttachment {
    pub name: String,
    pub mime_type: String,
    pub content_id: Option<String>,
    pub is_inline: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SealedAttachment {
    pub encrypted_data: Vec<u8>,
    pub data_nonce: [u8; DATA_NONCE_LEN],
    pub sender_meta: String,
    pub sender_meta_nonce: [u8; DATA_NONCE_LEN],
    pub plain_meta: Zeroizing<String>,
}

pub fn mime_attachments(parsed: &mail_parser::Message<'_>, max_bytes: usize) -> Vec<OutgoingAttachment> {
    use mail_parser::MimeHeaders;

    let mut out = Vec::new();
    for part in parsed.attachments() {
        let data = part.contents();
        if data.is_empty() || data.len() > max_bytes {
            continue;
        }
        let name = part
            .attachment_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("attachment-{}", out.len() + 1));
        let mime_type = part
            .content_type()
            .map(|ct| match ct.subtype() {
                Some(sub) => format!("{}/{}", ct.ctype(), sub),
                None => ct.ctype().to_string(),
            })
            .unwrap_or_else(|| DEFAULT_ATTACHMENT_CONTENT_TYPE.to_string());
        let content_id = part
            .content_id()
            .map(|s| s.trim_matches(&['<', '>'][..]).to_string())
            .filter(|s| !s.is_empty());
        out.push(OutgoingAttachment {
            is_inline: content_id.is_some(),
            name,
            mime_type,
            content_id,
            data: data.to_vec(),
        });
    }
    out
}

pub fn seal_attachment(attachment: &OutgoingAttachment, passphrase: &[u8]) -> Result<SealedAttachment> {
    use rand_core::{OsRng, RngCore};

    let mut session_key = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    OsRng.fill_bytes(&mut *session_key);
    let cipher = Aes256Gcm::new_from_slice(&*session_key)
        .map_err(|e| BridgeError::Crypto(format!("attachment cipher init: {}", e)))?;
    let mut data_nonce = [0u8; DATA_NONCE_LEN];
    OsRng.fill_bytes(&mut data_nonce);
    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&data_nonce), attachment.data.as_ref())
        .map_err(|_| {
            BridgeError::Crypto(format!("attachment encrypt failed for {}", attachment.name))
        })?;
    let plain_meta = Zeroizing::new(
        serde_json::json!({
            "filename": attachment.name,
            "content_type": attachment.mime_type,
            "session_key": STANDARD.encode(*session_key),
            "content_id": attachment.content_id,
            "is_inline": attachment.is_inline,
        })
        .to_string(),
    );
    let sender_meta = encrypt_pbkdf2_envelope(&plain_meta, passphrase)?;
    let mut sender_meta_nonce = [0u8; DATA_NONCE_LEN];
    OsRng.fill_bytes(&mut sender_meta_nonce);
    Ok(SealedAttachment {
        encrypted_data,
        data_nonce,
        sender_meta,
        sender_meta_nonce,
        plain_meta,
    })
}

pub fn send_attachment_value(sealed: &SealedAttachment) -> serde_json::Value {
    serde_json::json!({
        "encrypted_data": STANDARD.encode(&sealed.encrypted_data),
        "data_nonce": STANDARD.encode(sealed.data_nonce),
        "sender_encrypted_meta": sealed.sender_meta,
        "sender_meta_nonce": STANDARD.encode(sealed.sender_meta_nonce),
        "recipient_encrypted_meta": STANDARD.encode(sealed.plain_meta.as_bytes()),
    })
}

pub fn seal_send_attachments(
    attachments: &[OutgoingAttachment],
    passphrase: &[u8],
) -> Result<Vec<serde_json::Value>> {
    attachments
        .iter()
        .map(|a| seal_attachment(a, passphrase).map(|s| send_attachment_value(&s)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn outgoing(name: &str, mime: &str, content_id: Option<&str>, data: &[u8]) -> OutgoingAttachment {
        OutgoingAttachment {
            name: name.to_string(),
            mime_type: mime.to_string(),
            content_id: content_id.map(|s| s.to_string()),
            is_inline: content_id.is_some(),
            data: data.to_vec(),
        }
    }

    fn server_decrypt(value: &serde_json::Value) -> (Vec<u8>, serde_json::Value) {
        let meta_bytes = STANDARD
            .decode(value["recipient_encrypted_meta"].as_str().unwrap())
            .unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&meta_bytes).unwrap();
        let key = STANDARD.decode(meta["session_key"].as_str().unwrap()).unwrap();
        assert_eq!(key.len(), 32);
        let nonce = STANDARD.decode(value["data_nonce"].as_str().unwrap()).unwrap();
        assert_eq!(nonce.len(), 12);
        let ct = STANDARD.decode(value["encrypted_data"].as_str().unwrap()).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let plain = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).unwrap();
        (plain, meta)
    }

    #[test]
    fn sealed_send_attachment_is_readable_by_the_server_delivery_path() {
        let att = outgoing("report.pdf", "application/pdf", None, b"hello pdf");
        let value = send_attachment_value(&seal_attachment(&att, b"pass").unwrap());
        let (plain, meta) = server_decrypt(&value);
        assert_eq!(plain, b"hello pdf");
        assert_eq!(meta["filename"], "report.pdf");
        assert_eq!(meta["content_type"], "application/pdf");
        assert_eq!(meta["is_inline"], false);
        assert!(meta["content_id"].is_null());
        let meta_nonce = STANDARD
            .decode(value["sender_meta_nonce"].as_str().unwrap())
            .unwrap();
        assert_eq!(meta_nonce.len(), 12);
    }

    #[test]
    fn sealed_send_attachment_sender_copy_opens_with_the_passphrase() {
        let att = outgoing("logo.png", "image/png", Some("logo@aster"), b"\x89PNG");
        let sealed = seal_attachment(&att, b"vault-pass").unwrap();
        let (plain, meta) = server_decrypt(&send_attachment_value(&sealed));
        assert_eq!(plain, b"\x89PNG");
        assert_eq!(meta["content_id"], "logo@aster");
        assert_eq!(meta["is_inline"], true);
        let sender_row = AttachmentResponse {
            encrypted_meta: sealed.sender_meta.clone(),
            ..row(
                0,
                &sealed.encrypted_data,
                &sealed.data_nonce,
                b"",
                &sealed.sender_meta_nonce,
            )
        };
        let opened = decrypt_attachment(&sender_row, None, b"vault-pass", None).unwrap();
        assert_eq!(opened.data, b"\x89PNG");
        assert_eq!(opened.filename, "logo.png");
        assert_eq!(opened.content_id.as_deref(), Some("logo@aster"));
        assert!(opened.is_inline);
    }

    #[test]
    fn sealed_send_attachment_received_copy_opens_from_plain_meta() {
        let att = outgoing("notes.txt", "text/plain", None, b"plain notes");
        let sealed = seal_attachment(&att, b"vault-pass").unwrap();
        let received_row = row(
            3,
            &sealed.encrypted_data,
            &sealed.data_nonce,
            sealed.plain_meta.as_bytes(),
            &[0u8; 12],
        );
        let opened = decrypt_attachment(&received_row, None, b"other-pass", None).unwrap();
        assert_eq!(opened.data, b"plain notes");
        assert_eq!(opened.filename, "notes.txt");
    }

    #[test]
    fn every_seal_uses_a_fresh_key_and_nonce() {
        let att = outgoing("a.bin", "application/octet-stream", None, b"same bytes");
        let one = seal_attachment(&att, b"p").unwrap();
        let two = seal_attachment(&att, b"p").unwrap();
        assert_ne!(one.encrypted_data, two.encrypted_data);
        assert_ne!(one.data_nonce, two.data_nonce);
        assert_ne!(one.sender_meta_nonce, two.sender_meta_nonce);
    }

    #[test]
    fn mime_attachments_extracts_regular_and_inline_parts() {
        let raw = concat!(
            "From: a@b.c\r\n",
            "To: d@e.f\r\n",
            "Subject: mixed\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n",
            "\r\n",
            "--OUTER\r\n",
            "Content-Type: multipart/related; boundary=\"INNER\"\r\n",
            "\r\n",
            "--INNER\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p><img src=\"cid:pic@aster\"></p>\r\n",
            "--INNER\r\n",
            "Content-Type: image/png; name=\"pic.png\"\r\n",
            "Content-ID: <pic@aster>\r\n",
            "Content-Disposition: inline; filename=\"pic.png\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "iVBORw0=\r\n",
            "--INNER--\r\n",
            "--OUTER\r\n",
            "Content-Type: application/pdf; name=\"report.pdf\"\r\n",
            "Content-Disposition: attachment; filename=\"report.pdf\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "aGVsbG8gcGRm\r\n",
            "--OUTER--\r\n"
        )
        .as_bytes();
        let parsed = mail_parser::MessageParser::default().parse(raw).unwrap();
        let list = mime_attachments(&parsed, 1024 * 1024);
        assert_eq!(list.len(), 2);
        let pic = list.iter().find(|a| a.name == "pic.png").unwrap();
        assert_eq!(pic.mime_type, "image/png");
        assert_eq!(pic.content_id.as_deref(), Some("pic@aster"));
        assert!(pic.is_inline);
        assert_eq!(pic.data, b"\x89PNG\r");
        let pdf = list.iter().find(|a| a.name == "report.pdf").unwrap();
        assert_eq!(pdf.mime_type, "application/pdf");
        assert!(!pdf.is_inline);
        assert_eq!(pdf.data, b"hello pdf");
    }

    #[test]
    fn mime_attachments_skips_oversized_parts() {
        let raw = concat!(
            "From: a@b.c\r\n",
            "Subject: big\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"B\"\r\n",
            "\r\n",
            "--B\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "body\r\n",
            "--B\r\n",
            "Content-Type: application/octet-stream; name=\"big.bin\"\r\n",
            "Content-Disposition: attachment; filename=\"big.bin\"\r\n",
            "\r\n",
            "0123456789\r\n",
            "--B--\r\n"
        )
        .as_bytes();
        let parsed = mail_parser::MessageParser::default().parse(raw).unwrap();
        assert!(mime_attachments(&parsed, 4).is_empty());
        assert_eq!(mime_attachments(&parsed, 64).len(), 1);
    }

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    }

    fn random_nonce() -> [u8; 12] {
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        n
    }

    fn seal(key: &[u8; 32], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
            .unwrap()
    }

    fn row(
        seq: i16,
        data: &[u8],
        data_nonce: &[u8],
        meta: &[u8],
        meta_nonce: &[u8],
    ) -> AttachmentResponse {
        AttachmentResponse {
            id: format!("att-{}", seq),
            mail_item_id: "mail-1".to_string(),
            encrypted_data: STANDARD.encode(data),
            data_nonce: STANDARD.encode(data_nonce),
            encrypted_meta: STANDARD.encode(meta),
            meta_nonce: STANDARD.encode(meta_nonce),
            size_bytes: data.len() as i64,
            seq_num: seq,
            created_at: None,
        }
    }

    #[test]
    fn bridge_uploaded_attachment_round_trips_with_the_passphrase() {
        let key = random_key();
        let nonce = random_nonce();
        let plain = b"%PDF-1.7 hello".to_vec();
        let ct = seal(&key, &nonce, &plain, b"");
        let meta = serde_json::json!({
            "filename": "report.pdf",
            "content_type": "application/pdf",
            "session_key": STANDARD.encode(key),
            "content_id": null,
            "is_inline": false,
        })
        .to_string();
        let sealed_meta = encrypt_pbkdf2_envelope(&meta, b"pass").unwrap();
        let r = AttachmentResponse {
            encrypted_meta: sealed_meta,
            ..row(0, &ct, &nonce, b"", &random_nonce())
        };
        let out = decrypt_attachment(&r, None, b"pass", None).unwrap();
        assert_eq!(out.filename, "report.pdf");
        assert_eq!(out.content_type, "application/pdf");
        assert_eq!(out.data, plain);
        assert!(!out.is_inline);
        assert_eq!(out.content_id, None);
    }

    #[test]
    fn server_sealed_meta_opens_with_the_envelope_key() {
        let key = random_key();
        let nonce = random_nonce();
        let plain = b"PNG bytes".to_vec();
        let ct = seal(&key, &nonce, &plain, &attachment_data_aad(3));
        let meta_json = serde_json::json!({
            "filename": "pic.png",
            "content_type": "image/png",
            "content_id": "cid-7"
        })
        .to_string();
        let meta_nonce = random_nonce();
        let sealed_meta = seal(&key, &meta_nonce, meta_json.as_bytes(), b"");
        let r = row(3, &ct, &nonce, &sealed_meta, &meta_nonce);
        let entry = AttachmentKeyEntry {
            key: Some(STANDARD.encode(key)),
            ..Default::default()
        };
        let out = decrypt_attachment(&r, Some(&entry), b"unrelated", None).unwrap();
        assert_eq!(out.filename, "pic.png");
        assert_eq!(out.content_type, "image/png");
        assert_eq!(out.content_id.as_deref(), Some("cid-7"));
        assert_eq!(out.data, plain);
    }

    #[test]
    fn envelope_names_win_over_row_meta_and_key_falls_back_to_the_entry() {
        let key = random_key();
        let nonce = random_nonce();
        let plain = vec![1u8, 2, 3, 4];
        let ct = seal(&key, &nonce, &plain, b"");
        let r = row(0, &ct, &nonce, b"not-json-and-not-an-envelope", &[0u8; 12]);
        let entry = AttachmentKeyEntry {
            key: Some(STANDARD.encode(key)),
            filename: Some("from-envelope.bin".to_string()),
            content_type: Some("Application/Octet-Stream".to_string()),
            content_id: None,
            size: Some(4),
        };
        let out = decrypt_attachment(&r, Some(&entry), b"pass", None).unwrap();
        assert_eq!(out.filename, "from-envelope.bin");
        assert_eq!(out.content_type, "application/octet-stream");
        assert_eq!(out.data, plain);
    }

    #[test]
    fn plaintext_json_meta_carries_its_own_session_key() {
        let key = random_key();
        let nonce = random_nonce();
        let plain = b"csv,data".to_vec();
        let ct = seal(&key, &nonce, &plain, b"");
        let meta = serde_json::json!({
            "filename": "x.csv",
            "content_type": "text/csv",
            "session_key": STANDARD.encode(key)
        })
        .to_string();
        let r = row(0, &ct, &nonce, meta.as_bytes(), &[0u8; 12]);
        let out = decrypt_attachment(&r, None, b"pass", None).unwrap();
        assert_eq!(out.filename, "x.csv");
        assert_eq!(out.content_type, "text/csv");
        assert_eq!(out.data, plain);
    }

    #[test]
    fn stored_plaintext_attachment_is_returned_only_with_the_zero_nonce() {
        let plain = b"raw stored bytes".to_vec();
        let r = row(0, &plain, &[0u8; 12], b"", &[0u8; 12]);
        let out = decrypt_attachment(&r, None, b"pass", None).unwrap();
        assert_eq!(out.data, plain);
        assert_eq!(out.filename, "attachment-1.bin");

        let r = row(0, &plain, &random_nonce(), b"", &[0u8; 12]);
        assert!(decrypt_attachment(&r, None, b"pass", None).is_err());
    }

    #[test]
    fn a_wrong_key_never_yields_bytes() {
        let key = random_key();
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"secret", b"");
        let r = row(0, &ct, &nonce, b"", &[0u8; 12]);
        let entry = AttachmentKeyEntry {
            key: Some(STANDARD.encode(random_key())),
            ..Default::default()
        };
        assert!(decrypt_attachment(&r, Some(&entry), b"pass", None).is_err());
    }

    #[test]
    fn an_empty_payload_is_rejected() {
        let key = random_key();
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"", b"");
        let r = row(0, &ct, &nonce, b"", &[0u8; 12]);
        let entry = AttachmentKeyEntry {
            key: Some(STANDARD.encode(key)),
            ..Default::default()
        };
        assert!(decrypt_attachment(&r, Some(&entry), b"pass", None).is_err());
    }

    #[test]
    fn placeholder_names_follow_the_content_type() {
        assert_eq!(
            placeholder_filename(0, "application/pdf"),
            "attachment-1.pdf"
        );
        assert_eq!(placeholder_filename(2, "image/jpeg"), "attachment-3.jpg");
        assert_eq!(placeholder_filename(1, "weird/thing"), "attachment-2.bin");
    }
}
