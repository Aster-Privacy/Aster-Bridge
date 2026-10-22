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
use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::api_client::TagDefinition;
use crate::db::CustomTag;

pub const MAX_NAME_CHARS: usize = 100;
pub const MAX_KEYWORD_LEN: usize = 128;
pub const MAX_PATH_DEPTH: usize = 8;
pub const PATH_SEPARATOR: &str = "/";

const SHIFT: char = '&';
const UNSHIFT: char = '-';
const RESERVED_KEYWORDS: [&str; 17] = [
    "Junk",
    "NonJunk",
    "NotJunk",
    "JunkRecorded",
    "Forwarded",
    "Redirected",
    "MDNSent",
    "receipt-handled",
    "Recent",
    "Deleted",
    "Seen",
    "Answered",
    "Flagged",
    "Draft",
    "Old",
    "Phishing",
    "NotPhishing",
];
const ATOM_SPECIALS: &[u8] = b"(){%*\"\\]";
const LEGACY_KEY_REPLACED: &[char] = &[' ', '(', ')', '/', '{', '%', '*', '<', '>', '\\', '"'];
const READABLE_KEY_ESCAPED: &[u8] = b"=()[]{}%*\"\\<>;&";
const READABLE_KEY_ESCAPE: char = '=';
const MAX_READABLE_KEY_LEN: usize = 50;
const HASHED_KEY_PREFIX: &str = "&x-moz-";
const HASHED_KEY_BYTES: usize = 16;

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

fn keyword_for_text(text: &str) -> Option<String> {
    if text.trim().is_empty() || text.trim() != text || text.chars().any(|c| c.is_control()) {
        return None;
    }
    let keyword = encode_name(text);
    (keyword.len() <= MAX_KEYWORD_LEN).then_some(keyword)
}

pub fn keyword_for_name(name: &str) -> Option<String> {
    validate_name(name).ok()?;
    keyword_for_text(name)
}

pub fn keyword_text(keyword: &str) -> Option<String> {
    decode_keyword(keyword)
}

fn is_atom_keyword(keyword: &str) -> bool {
    !keyword.is_empty()
        && keyword.len() <= MAX_KEYWORD_LEN
        && keyword
            .bytes()
            .all(|b| b > 0x20 && b < 0x7f && !ATOM_SPECIALS.contains(&b))
}

fn is_folded_shift_key(keyword: &str) -> bool {
    !keyword.bytes().any(|b| b.is_ascii_uppercase())
        && keyword
            .split(SHIFT)
            .skip(1)
            .filter_map(|run| run.split(UNSHIFT).next())
            .any(|run| run.bytes().any(|b| b.is_ascii_lowercase()))
}

fn legacy_client_key(text: &str) -> String {
    let replaced: String = text
        .chars()
        .map(|c| if LEGACY_KEY_REPLACED.contains(&c) { '_' } else { c })
        .collect();
    crate::imap::mutf7::encode(&replaced).to_ascii_lowercase()
}

fn readable_client_key(text: &str) -> String {
    let mut key = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte > 0x20 && byte < 0x7f && !READABLE_KEY_ESCAPED.contains(&byte) {
            key.push(byte.to_ascii_lowercase() as char);
        } else {
            key.push_str(&format!("{}{:02x}", READABLE_KEY_ESCAPE, byte));
        }
    }
    if key.is_empty() {
        key.push_str("tag");
    }
    if key.len() > MAX_READABLE_KEY_LEN {
        let digest = Sha256::digest(text.as_bytes());
        key = HASHED_KEY_PREFIX.to_string();
        for byte in &digest[..HASHED_KEY_BYTES] {
            key.push_str(&format!("{:02x}", byte));
        }
    }
    key
}

fn readable_key_text(keyword: &str) -> Option<String> {
    if !keyword.contains(READABLE_KEY_ESCAPE) || keyword.contains(SHIFT) {
        return None;
    }
    let bytes = keyword.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == READABLE_KEY_ESCAPE as u8 {
            let pair = bytes.get(index + 1..index + 3)?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    let text = String::from_utf8(out).ok()?;
    (readable_client_key(&text) == keyword.to_ascii_lowercase()).then_some(text)
}

pub fn client_keywords(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for key in [legacy_client_key(text), readable_client_key(text)] {
        if is_atom_keyword(&key)
            && !is_local_keyword(&key)
            && !out.iter().any(|known| known.eq_ignore_ascii_case(&key))
        {
            out.push(key);
        }
    }
    out
}

pub fn keyword_aliases(keyword: &str) -> Vec<String> {
    let Some(text) = decode_keyword(keyword) else {
        return Vec::new();
    };
    client_keywords(&text)
        .into_iter()
        .filter(|alias| !alias.eq_ignore_ascii_case(keyword))
        .collect()
}

pub fn alias_rows(tags: &[CustomTag]) -> Vec<(String, String)> {
    let mut ordered: Vec<&CustomTag> = tags.iter().collect();
    ordered.sort_by(|a, b| a.tag_token.cmp(&b.tag_token));
    let owned: Vec<&str> = tags
        .iter()
        .filter_map(|tag| tag.keyword.as_deref())
        .filter(|keyword| !is_folded_shift_key(keyword))
        .collect();
    let mut rows: Vec<(String, String)> = Vec::new();
    for tag in ordered {
        let Some(keyword) = tag.keyword.as_deref() else {
            continue;
        };
        for alias in keyword_aliases(keyword) {
            let taken = owned.iter().any(|known| known.eq_ignore_ascii_case(&alias))
                || rows.iter().any(|(known, _)| known.eq_ignore_ascii_case(&alias));
            if !taken {
                rows.push((alias, tag.tag_token.clone()));
            }
        }
    }
    rows
}

pub fn label_paths(parents: &HashMap<String, (String, Option<String>)>) -> HashMap<String, String> {
    parents
        .iter()
        .map(|(token, (name, parent))| {
            let mut segments: Vec<&str> = vec![name.as_str()];
            let mut seen: HashSet<&str> = HashSet::from([token.as_str()]);
            let mut cursor = parent.as_deref();
            while let Some(parent_token) = cursor {
                if segments.len() >= MAX_PATH_DEPTH || !seen.insert(parent_token) {
                    break;
                }
                let Some((parent_name, grandparent)) = parents.get(parent_token) else {
                    break;
                };
                segments.push(parent_name.as_str());
                cursor = grandparent.as_deref();
            }
            segments.reverse();
            (token.clone(), segments.join(PATH_SEPARATOR))
        })
        .collect()
}

pub fn name_for_keyword(keyword: &str) -> Option<String> {
    if is_local_keyword(keyword) || keyword.starts_with('\\') {
        return None;
    }
    if let Some(name) = readable_key_text(keyword) {
        return keyword_for_name(&name).is_some().then_some(name);
    }
    if is_folded_shift_key(keyword) {
        return None;
    }
    let name = decode_keyword(keyword)?;
    let canonical = keyword_for_name(&name)?;
    canonical.eq_ignore_ascii_case(keyword).then_some(name)
}

pub fn assign_keywords(tags: &mut [CustomTag], paths: &HashMap<String, String>) {
    tags.sort_by(|a, b| a.tag_token.cmp(&b.tag_token));
    let mut taken: HashSet<String> = HashSet::new();
    for tag in tags.iter_mut() {
        tag.keyword = paths
            .get(&tag.tag_token)
            .and_then(|path| keyword_for_text(path))
            .or_else(|| keyword_for_name(&tag.name))
            .filter(|keyword| taken.insert(keyword.to_ascii_lowercase()));
    }
}

pub fn tags_from_definitions(
    definitions: &[TagDefinition],
    identity_key: &str,
    previous_keys: &[String],
) -> Vec<CustomTag> {
    let mut parents: HashMap<String, (String, Option<String>)> = HashMap::new();
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
            parents.insert(
                definition.tag_token.clone(),
                (name.clone(), definition.parent_token.clone()),
            );
            Some(CustomTag {
                tag_token: definition.tag_token.clone(),
                server_id: definition.id.clone(),
                name,
                keyword: None,
            })
        })
        .collect();
    assign_keywords(&mut tags, &label_paths(&parents));
    tags
}

pub fn find_by_keyword<'a>(tags: &'a [CustomTag], keyword: &str) -> Option<&'a CustomTag> {
    let own = tags.iter().find(|tag| {
        tag.keyword
            .as_deref()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(keyword))
    });
    if own.is_some_and(|tag| !tag.keyword.as_deref().is_some_and(is_folded_shift_key)) {
        return own;
    }
    alias_rows(tags)
        .into_iter()
        .find(|(alias, _)| alias.eq_ignore_ascii_case(keyword))
        .and_then(|(_, token)| tags.iter().find(|tag| tag.tag_token == token))
        .or(own)
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
        for name in ["$label1", "Junk", "nonjunk", "Forwarded", "receipt-handled", "SEEN"] {
            let keyword = keyword_for_name(name).unwrap();
            assert!(is_atom(&keyword), "{}", keyword);
            assert!(!is_local_keyword(&keyword), "{}", keyword);
            assert_eq!(name_for_keyword(&keyword).as_deref(), Some(name));
        }
    }

    #[test]
    fn client_internal_keywords_stay_local_in_any_case() {
        for keyword in [
            "Junk",
            "NonJunk",
            "NotJunk",
            "JunkRecorded",
            "Forwarded",
            "Redirected",
            "MDNSent",
            "receipt-handled",
            "Recent",
            "Deleted",
            "Seen",
            "Answered",
            "Flagged",
            "Draft",
            "Old",
            "Phishing",
            "NotPhishing",
            "$label1",
        ] {
            for variant in [
                keyword.to_string(),
                keyword.to_ascii_lowercase(),
                keyword.to_ascii_uppercase(),
            ] {
                assert!(is_local_keyword(&variant), "{}", variant);
                assert_eq!(name_for_keyword(&variant), None, "{}", variant);
            }
        }
        assert!(!is_local_keyword("Work"));
        assert!(!is_local_keyword("Forwarded2"));
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

    fn parent_map(rows: &[(&str, &str, Option<&str>)]) -> HashMap<String, (String, Option<String>)> {
        rows.iter()
            .map(|(token, name, parent)| {
                (token.to_string(), (name.to_string(), parent.map(str::to_string)))
            })
            .collect()
    }

    #[test]
    fn nested_labels_are_exposed_by_their_full_path() {
        let parents = parent_map(&[
            ("a", "Clients", None),
            ("b", "Acme", Some("a")),
            ("c", "Vendors", None),
            ("d", "Acme", Some("c")),
            ("e", "2026 Q1", Some("b")),
        ]);
        let mut tags = vec![
            tag("a", "Clients"),
            tag("b", "Acme"),
            tag("c", "Vendors"),
            tag("d", "Acme"),
            tag("e", "2026 Q1"),
        ];
        assign_keywords(&mut tags, &label_paths(&parents));
        let keywords: Vec<Option<&str>> = tags.iter().map(|t| t.keyword.as_deref()).collect();
        assert_eq!(
            keywords,
            vec![
                Some("Clients"),
                Some("Clients/Acme"),
                Some("Vendors"),
                Some("Vendors/Acme"),
                Some("Clients/Acme/2026&ACA-Q1"),
            ]
        );
        assert_eq!(
            keyword_text("Clients/Acme/2026&ACA-Q1").as_deref(),
            Some("Clients/Acme/2026 Q1")
        );
    }

    #[test]
    fn a_parent_cycle_or_a_missing_parent_ends_the_path() {
        let parents = parent_map(&[
            ("a", "One", Some("b")),
            ("b", "Two", Some("a")),
            ("c", "Orphan", Some("gone")),
        ]);
        let paths = label_paths(&parents);
        assert_eq!(paths["a"], "Two/One");
        assert_eq!(paths["b"], "One/Two");
        assert_eq!(paths["c"], "Orphan");
    }

    #[test]
    fn a_path_too_long_for_a_keyword_falls_back_to_the_leaf_name() {
        let long = "x".repeat(90);
        let parents = parent_map(&[("a", &long, None), ("b", "Leaf", Some("a"))]);
        let mut tags = vec![tag("a", &long), tag("b", "Leaf")];
        assign_keywords(&mut tags, &label_paths(&parents));
        assert_eq!(tags[0].keyword.as_deref(), Some(long.as_str()));
        assert_eq!(tags[1].keyword.as_deref(), Some(format!("{}/Leaf", long).as_str()));

        let longer = "y".repeat(100);
        let parents = parent_map(&[("a", &longer, None), ("b", &longer, Some("a"))]);
        let mut tags = vec![tag("a", &longer), tag("b", &longer)];
        assign_keywords(&mut tags, &label_paths(&parents));
        assert_eq!(tags[0].keyword.as_deref(), Some(longer.as_str()));
        assert_eq!(tags[1].keyword, None);
    }

    #[test]
    fn duplicate_keywords_go_to_the_first_token() {
        let mut tags = vec![tag("b", "work"), tag("a", "Work"), tag("c", "Home")];
        assign_keywords(&mut tags, &HashMap::new());
        assert_eq!(tags[0].keyword.as_deref(), Some("Work"));
        assert_eq!(tags[1].keyword, None);
        assert_eq!(tags[2].keyword.as_deref(), Some("Home"));
        assert_eq!(
            find_by_keyword(&tags, "WORK").map(|found| found.tag_token.as_str()),
            Some("a")
        );
    }

    fn keyed(token: &str, name: &str) -> CustomTag {
        CustomTag {
            keyword: keyword_for_name(name),
            ..tag(token, name)
        }
    }

    #[test]
    fn client_keywords_match_both_generated_forms() {
        assert_eq!(
            client_keywords("\u{1F37F} Entretenimento"),
            vec!["&2dzffw-_entretenimento", "=f0=9f=8d=bf=20entretenimento"]
        );
        assert_eq!(client_keywords("Mais tarde"), vec!["mais_tarde", "mais=20tarde"]);
        assert_eq!(
            client_keywords("\u{1F6CB}\u{FE0F} Mais tarde"),
            vec!["&2d3ey,4p-_mais_tarde", "=f0=9f=9b=8b=ef=b8=8f=20mais=20tarde"]
        );
        assert_eq!(
            client_keywords("Faturas do condom\u{ED}nio (2026)"),
            vec![
                "faturas_do_condom&ao0-nio__2026_",
                "faturas=20do=20condom=c3=adnio=20=282026=29"
            ]
        );
        assert_eq!(client_keywords("R&D"), vec!["r&-d", "r=26d"]);
        assert_eq!(client_keywords("work"), vec!["work"]);
        assert!(client_keywords("Junk").is_empty());
        assert!(client_keywords("$label1").is_empty());

        let long = "Contas a pagar do apartamento novo em Lisboa e Porto";
        let keys = client_keywords(long);
        assert_eq!(keys[1], "&x-moz-820dd116da2f78e411079a56b845175b");
        assert_eq!(keys[1].len(), 39);
        assert_eq!(keys[0], "contas_a_pagar_do_apartamento_novo_em_lisboa_e_porto");
    }

    #[test]
    fn aliases_skip_the_label_keyword_itself() {
        let own = keyword_for_name("Mais tarde").unwrap();
        assert_eq!(keyword_aliases(&own), vec!["mais_tarde", "mais=20tarde"]);
        assert!(keyword_aliases("Work").is_empty());
    }

    #[test]
    fn client_forms_never_become_new_label_names() {
        assert_eq!(name_for_keyword("&2dzffw-_entretenimento"), None);
        assert_eq!(name_for_keyword("&x-moz-820dd116da2f78e411079a56b845175b"), None);
        assert_eq!(name_for_keyword("mais=20tarde").as_deref(), Some("mais tarde"));
        assert_eq!(
            name_for_keyword("=f0=9f=8d=bf=20entretenimento").as_deref(),
            Some("\u{1F37F} entretenimento")
        );
        assert_eq!(name_for_keyword("mais_tarde").as_deref(), Some("mais_tarde"));
        let own = keyword_for_name("\u{1F37F} Entretenimento").unwrap();
        assert_eq!(name_for_keyword(&own).as_deref(), Some("\u{1F37F} Entretenimento"));
    }

    #[test]
    fn client_forms_resolve_to_their_label() {
        let tags = vec![
            keyed("t1", "\u{1F37F} Entretenimento"),
            keyed("t2", "Mais tarde"),
            keyed("t3", "Contas a pagar do apartamento novo em Lisboa e Porto"),
        ];
        let resolve = |keyword: &str| find_by_keyword(&tags, keyword).map(|t| t.tag_token.clone());
        assert_eq!(resolve("&2dzffw-_entretenimento").as_deref(), Some("t1"));
        assert_eq!(resolve("=F0=9F=8D=BF=20ENTRETENIMENTO").as_deref(), Some("t1"));
        assert_eq!(resolve("mais_tarde").as_deref(), Some("t2"));
        assert_eq!(resolve("mais=20tarde").as_deref(), Some("t2"));
        assert_eq!(resolve("&x-moz-820dd116da2f78e411079a56b845175b").as_deref(), Some("t3"));
        assert_eq!(resolve("mais tarde"), None);
        assert_eq!(resolve("$label5"), None);
    }

    #[test]
    fn a_label_made_from_a_client_form_yields_to_the_real_label() {
        let garbage_name = keyword_text("&2dzffw-_entretenimento").unwrap();
        let garbage = keyed("a-garbage", &garbage_name);
        assert!(garbage.keyword.as_deref().unwrap().eq_ignore_ascii_case("&2dzffw-_entretenimento"));
        let tags = vec![garbage, keyed("z-real", "\u{1F37F} Entretenimento")];
        assert_eq!(
            find_by_keyword(&tags, "&2dzffw-_entretenimento").map(|t| t.tag_token.as_str()),
            Some("z-real")
        );
        let rows = alias_rows(&tags);
        assert!(rows
            .iter()
            .any(|(alias, token)| alias == "&2dzffw-_entretenimento" && token == "z-real"));
        assert_eq!(
            find_by_keyword(&tags, tags[0].keyword.as_deref().unwrap()).map(|t| t.tag_token.as_str()),
            Some("z-real")
        );
    }

    #[test]
    fn a_real_keyword_beats_another_label_alias() {
        let tags = vec![keyed("a", "Mais tarde"), keyed("b", "mais_tarde")];
        assert_eq!(find_by_keyword(&tags, "mais_tarde").map(|t| t.tag_token.as_str()), Some("b"));
        assert_eq!(find_by_keyword(&tags, "mais=20tarde").map(|t| t.tag_token.as_str()), Some("a"));
        let rows = alias_rows(&tags);
        assert!(!rows.iter().any(|(alias, _)| alias == "mais_tarde"));
        let first = vec![keyed("a", "Mais tarde"), keyed("b", "mais tarde")];
        assert_eq!(alias_rows(&first).iter().filter(|(_, token)| token == "b").count(), 0);
    }
}
