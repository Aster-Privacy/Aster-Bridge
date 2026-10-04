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
use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;

use crate::api_client::TagDefinition;
use crate::db::CustomTag;

pub const MAX_NAME_CHARS: usize = 100;
pub const MAX_KEYWORD_LEN: usize = 128;

const SHIFT: char = '&';
const UNSHIFT: char = '-';
const RESERVED_KEYWORDS: [&str; 2] = ["Junk", "NonJunk"];
const ATOM_SPECIALS: &[u8] = b"(){%*\"\\]";

pub fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err("label name cannot be empty");
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err("label name is longer than 100 characters");
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("label name contains control characters");
    }
    Ok(())
}

pub fn is_local_keyword(keyword: &str) -> bool {
    keyword.starts_with('$')
        || RESERVED_KEYWORDS
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(keyword))
}

fn is_direct(c: char) -> bool {
    let code = c as u32;
    code > 0x20 && code < 0x7f && c != SHIFT && !ATOM_SPECIALS.contains(&(code as u8))
}

fn push_run(run: &mut Vec<u16>, out: &mut String) {
    if run.is_empty() {
        return;
    }
    let bytes: Vec<u8> = run.iter().flat_map(|unit| unit.to_be_bytes()).collect();
    out.push(SHIFT);
    out.push_str(&STANDARD_NO_PAD.encode(bytes).replace('/', ","));
    out.push(UNSHIFT);
    run.clear();
}

fn encode_name(name: &str) -> String {
    let shift_first = is_local_keyword(name);
    let mut out = String::with_capacity(name.len());
    let mut run: Vec<u16> = Vec::new();
    for (index, c) in name.chars().enumerate() {
        let forced = shift_first && index == 0;
        if c == SHIFT && !forced {
            push_run(&mut run, &mut out);
            out.push(SHIFT);
            out.push(UNSHIFT);
        } else if is_direct(c) && !forced {
            push_run(&mut run, &mut out);
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            run.extend_from_slice(c.encode_utf16(&mut units));
            if forced {
                push_run(&mut run, &mut out);
            }
        }
    }
    push_run(&mut run, &mut out);
    out
}

fn decode_keyword(keyword: &str) -> Option<String> {
    let mut out = String::with_capacity(keyword.len());
    let mut rest = keyword;
    while let Some(position) = rest.find(SHIFT) {
        out.push_str(&rest[..position]);
        let after = &rest[position + 1..];
        let end = after.find(UNSHIFT)?;
        if end == 0 {
            out.push(SHIFT);
        } else {
            let bytes = STANDARD_NO_PAD
                .decode(after[..end].replace(',', "/"))
                .ok()?;
            if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
                return None;
            }
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            out.push_str(&String::from_utf16(&units).ok()?);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

pub fn keyword_for_name(name: &str) -> Option<String> {
    validate_name(name).ok()?;
    if name.trim() != name {
        return None;
    }
    let keyword = encode_name(name);
    (keyword.len() <= MAX_KEYWORD_LEN).then_some(keyword)
}

pub fn name_for_keyword(keyword: &str) -> Option<String> {
    if is_local_keyword(keyword) || keyword.starts_with('\\') {
        return None;
    }
    let name = decode_keyword(keyword)?;
    let canonical = keyword_for_name(&name)?;
    canonical.eq_ignore_ascii_case(keyword).then_some(name)
}

pub fn assign_keywords(tags: &mut [CustomTag]) {
    tags.sort_by(|a, b| a.tag_token.cmp(&b.tag_token));
    let mut taken: HashSet<String> = HashSet::new();
    for tag in tags.iter_mut() {
        tag.keyword = keyword_for_name(&tag.name)
            .filter(|keyword| taken.insert(keyword.to_ascii_lowercase()));
    }
}

pub fn tags_from_definitions(
    definitions: &[TagDefinition],
    identity_key: &str,
    previous_keys: &[String],
) -> Vec<CustomTag> {
    let mut tags: Vec<CustomTag> = definitions
        .iter()
        .filter(|definition| !definition.tag_token.is_empty())
        .filter_map(|definition| {
            let name = crate::crypto::tag::decrypt_tag_name(
                &definition.encrypted_name,
                &definition.name_nonce,
                identity_key,
                previous_keys,
            )?;
            Some(CustomTag {
                tag_token: definition.tag_token.clone(),
                server_id: definition.id.clone(),
                name,
                keyword: None,
            })
        })
        .collect();
    assign_keywords(&mut tags);
    tags
}

pub fn find_by_keyword<'a>(tags: &'a [CustomTag], keyword: &str) -> Option<&'a CustomTag> {
    tags.iter().find(|tag| {
        tag.keyword
            .as_deref()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(keyword))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(token: &str, name: &str) -> CustomTag {
        CustomTag {
            tag_token: token.to_string(),
            server_id: format!("id-{}", token),
            name: name.to_string(),
            keyword: None,
        }
    }

    fn is_atom(keyword: &str) -> bool {
        keyword
            .bytes()
            .all(|b| b > 0x20 && b < 0x7f && !ATOM_SPECIALS.contains(&b))
    }

    #[test]
    fn plain_names_are_their_own_keyword() {
        assert_eq!(keyword_for_name("Work").as_deref(), Some("Work"));
        assert_eq!(name_for_keyword("Work").as_deref(), Some("Work"));
        assert_eq!(keyword_for_name("Receipts/2025").as_deref(), Some("Receipts/2025"));
    }

    #[test]
    fn names_outside_the_atom_alphabet_round_trip() {
        for name in ["Work Stuff", "R&D", "Käse", "a(b)c", "100%", "日本語", "x \\ y", "🙂 fun"] {
            let keyword = keyword_for_name(name).unwrap();
            assert!(is_atom(&keyword), "{}", keyword);
            assert_eq!(name_for_keyword(&keyword).as_deref(), Some(name));
        }
        assert_eq!(keyword_for_name("Work Stuff").as_deref(), Some("Work&ACA-Stuff"));
        assert_eq!(keyword_for_name("R&D").as_deref(), Some("R&-D"));
    }

    #[test]
    fn reserved_names_never_collide_with_local_keywords() {
        for name in ["$label1", "Junk", "nonjunk"] {
            let keyword = keyword_for_name(name).unwrap();
            assert!(is_atom(&keyword), "{}", keyword);
            assert!(!is_local_keyword(&keyword), "{}", keyword);
            assert_eq!(name_for_keyword(&keyword).as_deref(), Some(name));
        }
    }

    #[test]
    fn local_and_malformed_keywords_are_not_tags() {
        assert_eq!(name_for_keyword("$Forwarded"), None);
        assert_eq!(name_for_keyword("NonJunk"), None);
        assert_eq!(name_for_keyword("\\Seen"), None);
        assert_eq!(name_for_keyword("broken&shift"), None);
        assert_eq!(name_for_keyword("odd&AA-"), None);
    }

    #[test]
    fn names_that_cannot_be_keywords_are_not_exposed() {
        assert_eq!(keyword_for_name(""), None);
        assert_eq!(keyword_for_name(" padded "), None);
        assert_eq!(keyword_for_name(&"é".repeat(100)), None);
    }

    #[test]
    fn duplicate_keywords_go_to_the_first_token() {
        let mut tags = vec![tag("b", "work"), tag("a", "Work"), tag("c", "Home")];
        assign_keywords(&mut tags);
        assert_eq!(tags[0].keyword.as_deref(), Some("Work"));
        assert_eq!(tags[1].keyword, None);
        assert_eq!(tags[2].keyword.as_deref(), Some("Home"));
        assert_eq!(
            find_by_keyword(&tags, "WORK").map(|found| found.tag_token.as_str()),
            Some("a")
        );
    }
}
