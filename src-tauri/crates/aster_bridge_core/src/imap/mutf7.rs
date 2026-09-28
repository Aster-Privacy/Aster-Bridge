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
const MODIFIED_BASE64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

fn is_direct(c: char) -> bool {
    matches!(c, '\u{20}'..='\u{7e}') && c != '&'
}

fn encode_run(units: &[u16], out: &mut String) {
    let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_be_bytes()).collect();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let emit = chunk.len() + 1;
        for i in 0..emit {
            let idx = (n >> (18 - 6 * i)) & 0x3f;
            out.push(MODIFIED_BASE64[idx as usize] as char);
        }
    }
}

pub fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending: Vec<u16> = Vec::new();
    for c in name.chars() {
        if is_direct(c) || c == '&' {
            if !pending.is_empty() {
                out.push('&');
                encode_run(&pending, &mut out);
                out.push('-');
                pending.clear();
            }
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    if !pending.is_empty() {
        out.push('&');
        encode_run(&pending, &mut out);
        out.push('-');
    }
    out
}

fn decode_run(run: &str) -> Option<Vec<u16>> {
    let mut bits: u32 = 0;
    let mut bit_count = 0u32;
    let mut bytes: Vec<u8> = Vec::new();
    for b in run.bytes() {
        let v = MODIFIED_BASE64.iter().position(|x| *x == b)? as u32;
        bits = (bits << 6) | v;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            bytes.push(((bits >> bit_count) & 0xff) as u8);
        }
        bits &= (1 << bit_count) - 1;
    }
    if bit_count >= 6 || bits != 0 {
        return None;
    }
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(
        bytes
            .chunks(2)
            .map(|p| u16::from_be_bytes([p[0], p[1]]))
            .collect(),
    )
}

pub fn decode(encoded: &str) -> Option<String> {
    let mut out = String::with_capacity(encoded.len());
    let mut rest = encoded;
    while let Some(pos) = rest.find('&') {
        let direct = &rest[..pos];
        if !direct.chars().all(is_direct) {
            return None;
        }
        out.push_str(direct);
        let after = &rest[pos + 1..];
        let end = after.find('-')?;
        if end == 0 {
            out.push('&');
        } else {
            let units = decode_run(&after[..end])?;
            out.push_str(&String::from_utf16(&units).ok()?);
        }
        rest = &after[end + 1..];
    }
    if !rest.chars().all(is_direct) {
        return None;
    }
    out.push_str(rest);
    Some(out)
}

pub fn decode_lenient(name: &str) -> String {
    if name.is_ascii() {
        decode(name).unwrap_or_else(|| name.to_string())
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_is_unchanged() {
        assert_eq!(encode("Projects/2026"), "Projects/2026");
        assert_eq!(decode("Projects/2026").as_deref(), Some("Projects/2026"));
    }

    #[test]
    fn ampersand_round_trips() {
        assert_eq!(encode("Tom & Jerry"), "Tom &- Jerry");
        assert_eq!(decode("Tom &- Jerry").as_deref(), Some("Tom & Jerry"));
    }

    #[test]
    fn rfc_3501_examples() {
        assert_eq!(
            encode("~peter/mail/\u{53f0}\u{5317}/\u{65e5}\u{672c}\u{8a9e}"),
            "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
        );
        assert_eq!(
            decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-").as_deref(),
            Some("~peter/mail/\u{53f0}\u{5317}/\u{65e5}\u{672c}\u{8a9e}")
        );
    }

    #[test]
    fn accented_and_emoji_names_round_trip() {
        for name in ["Rechnungen \u{e4}lter", "Caf\u{e9}", "Trips \u{1f334}", "\u{2215}x", "a&b\u{e9}&c"] {
            let encoded = encode(name);
            assert!(encoded.is_ascii());
            assert_eq!(decode(&encoded).as_deref(), Some(name));
        }
    }

    #[test]
    fn known_vector_for_latin_letter() {
        assert_eq!(encode("\u{e9}"), "&AOk-");
        assert_eq!(decode("&AOk-").as_deref(), Some("\u{e9}"));
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert_eq!(decode("&AOk"), None);
        assert_eq!(decode("&A-"), None);
        assert_eq!(decode("&!!-"), None);
    }

    #[test]
    fn lenient_decode_keeps_raw_utf8_and_bad_input() {
        assert_eq!(decode_lenient("Caf\u{e9}"), "Caf\u{e9}");
        assert_eq!(decode_lenient("&AOk"), "&AOk");
        assert_eq!(decode_lenient("Caf&AOk-"), "Caf\u{e9}");
    }
}
