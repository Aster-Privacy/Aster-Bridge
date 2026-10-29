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
pub const BUILTIN_TAG_SLOTS: usize = 5;
const POSITIONAL_MIN_ANCHORS: usize = 3;
const BUILTIN_KEYWORD_PREFIX: &str = "$label";
const BUILTIN_TAG_NAMES: [&[&str]; BUILTIN_TAG_SLOTS] = [
    &[
        "A-bouez", "Aktar", "Belangrijk", "Belangrik", "Cudromach", "D\u{F4}le\u{17E}it\u{E9}",
        "D\u{16F}le\u{17E}it\u{E9}", "Fontos", "Garrantzitsua", "I r\u{EB}nd\u{EB}sish\u{EB}m",
        "Iimportante", "Important", "Importante", "Impurtant", "K'atzinel", "Mikilv\u{E6}gt",
        "Muhim", "Penting", "Pomembno", "Pwysig", "Quan tr\u{1ECD}ng", "Svarbus", "Svar\u{12B}gi",
        "T\u{E1}bhachtach", "T\u{E4}htis", "T\u{E4}rke\u{E4}", "Va\u{17E}no", "Vigtig", "Viktig",
        "Viktigt", "Wa\u{17C}ne", "Wa\u{17E}ny", "Wichtich", "Wichtig", "\u{D6}nemli",
        "\u{3A3}\u{3B7}\u{3BC}\u{3B1}\u{3BD}\u{3C4}\u{3B9}\u{3BA}\u{3CC}",
        "\u{412}\u{430}\u{436}\u{43B}\u{438}\u{432}\u{435}", "\u{412}\u{430}\u{436}\u{43D}\u{430}",
        "\u{412}\u{430}\u{436}\u{43D}\u{43E}", "\u{412}\u{430}\u{436}\u{43D}\u{43E}\u{435}",
        "\u{412}\u{430}\u{436}\u{43D}\u{44B}", "\u{41C}\u{430}\u{4A3}\u{44B}\u{437}\u{434}\u{44B}",
        "\u{53F}\u{561}\u{580}\u{565}\u{582}\u{578}\u{580}",
        "\u{53F}\u{561}\u{580}\u{587}\u{578}\u{580}", "\u{5D7}\u{5E9}\u{5D5}\u{5D1}",
        "\u{645}\u{647}\u{645}", "\u{E2A}\u{E33}\u{E04}\u{E31}\u{E0D}",
        "\u{10DB}\u{10DC}\u{10D8}\u{10E8}\u{10D5}\u{10DC}\u{10D4}\u{10DA}\u{10DD}\u{10D5}\u{10D0}\u{10DC}\u{10D8}",
        "\u{179F}\u{17C6}\u{1781}\u{17B6}\u{1793}\u{17CB}", "\u{91CD}\u{8981}", "\u{C911}\u{C694}",
    ],
    &[
        "Amahil", "Arbeid", "Arbejde", "Arbete", "Darbo", "Darbs", "Dienstlich",
        "D\u{17A}\u{11B}\u{142}o", "Feina", "Gwaith", "Ish", "Kerja", "Labor", "Labour", "Lanekoa",
        "Lavoro", "Lavur", "L\u{E0}m vi\u{1EC7}c", "Munka", "Obair", "Pekerjaan", "Posao", "Praca",
        "Pracovn\u{ED}", "Pune", "Samaj", "Serviciu", "Slu\u{17E}ba", "Trabajo", "Trabalho",
        "Traballo", "Trabayu", "Travail", "Ty\u{F6}", "T\u{F6}\u{F6}", "Vinna", "Werk", "Work",
        "Wurk", "Zamestnanie", "\u{130}\u{15F}", "\u{179}\u{11B}\u{142}o",
        "\u{395}\u{3C1}\u{3B3}\u{3B1}\u{3C3}\u{3AF}\u{3B1}", "\u{416}\u{4B1}\u{43C}\u{44B}\u{441}",
        "\u{41F}\u{43E}\u{441}\u{430}\u{43E}", "\u{41F}\u{440}\u{430}\u{446}\u{430}",
        "\u{420}\u{430}\u{431}\u{43E}\u{442}\u{430}",
        "\u{420}\u{430}\u{431}\u{43E}\u{447}\u{435}\u{435}",
        "\u{420}\u{43E}\u{431}\u{43E}\u{447}\u{435}",
        "\u{421}\u{43B}\u{443}\u{436}\u{435}\u{431}\u{43D}\u{43E}",
        "\u{531}\u{577}\u{56D}\u{561}\u{57F}\u{561}\u{576}\u{584}\u{561}\u{575}\u{56B}\u{576}",
        "\u{5E2}\u{5D1}\u{5D5}\u{5D3}\u{5D4}", "\u{627}\u{644}\u{639}\u{645}\u{644}",
        "\u{6A9}\u{627}\u{631}", "\u{E17}\u{E35}\u{E48}\u{E17}\u{E33}\u{E07}\u{E32}\u{E19}",
        "\u{10E1}\u{10D0}\u{10DB}\u{10E3}\u{10E8}\u{10D0}\u{10DD}",
        "\u{1780}\u{17B6}\u{179A}\u{1784}\u{17B6}\u{179A}\u{200B}", "\u{4ED5}\u{4E8B}",
        "\u{5546}\u{52D9}", "\u{5DE5}\u{4F5C}", "\u{C9C1}\u{C7A5}",
    ],
    &[
        "Asmeninis", "C\u{E1} nh\u{E2}n", "Ichinan", "Isiklik", "Ki\u{15F}isel", "Li\u{10D}no",
        "Oma", "Osebno", "Osobiste", "Osobno", "Osobn\u{E9}", "Osobn\u{ED}", "Pearsanta",
        "Peribadi", "Persoal", "Persoanlik", "Personal", "Personale", "Personales", "Personel",
        "Personleg", "Personlig", "Personnel", "Personol", "Person\u{12B}gs", "Persoonlijk",
        "Persoonlik", "Persunal", "Pers\u{F3}nulegt", "Pers\u{F6}nlich", "Pertsonala", "Pessoal",
        "Pribadi", "Privat", "Shaxsiy", "Szem\u{E9}lyes", "Udmawan", "Wosobinski",
        "W\u{F3}sobinski", "\u{3A0}\u{3C1}\u{3BF}\u{3C3}\u{3C9}\u{3C0}\u{3B9}\u{3BA}\u{3CC}",
        "\u{410}\u{441}\u{430}\u{431}\u{456}\u{441}\u{442}\u{44B}", "\u{416}\u{435}\u{43A}\u{435}",
        "\u{41B}\u{438}\u{447}\u{43D}\u{430}", "\u{41B}\u{438}\u{447}\u{43D}\u{43E}",
        "\u{41B}\u{438}\u{447}\u{43D}\u{43E}\u{435}",
        "\u{41E}\u{441}\u{43E}\u{431}\u{438}\u{441}\u{442}\u{435}",
        "\u{531}\u{576}\u{571}\u{576}\u{561}\u{56F}\u{561}\u{576}", "\u{5D0}\u{5D9}\u{5E9}\u{5D9}",
        "\u{634}\u{62E}\u{635}\u{64A}", "\u{634}\u{62E}\u{635}\u{6CC}",
        "\u{E2A}\u{E48}\u{E27}\u{E19}\u{E1A}\u{E38}\u{E04}\u{E04}\u{E25}",
        "\u{10DE}\u{10D8}\u{10E0}\u{10D0}\u{10D3}\u{10D8}",
        "\u{1795}\u{17D2}\u{1791}\u{17B6}\u{179B}\u{17CB}\u{200B}\u{1781}\u{17D2}\u{179B}\u{17BD}\u{1793}",
        "\u{30D7}\u{30E9}\u{30A4}\u{30D9}\u{30FC}\u{30C8}", "\u{79C1}\u{4EBA}", "\u{AC1C}\u{C778}",
    ],
    &[
        "A facer", "Ad ittumeg", "Att g\u{F6}ra", "Bajarish", "Da far", "Da fare", "Dabar",
        "Dar\u{101}mais", "De f\u{103}cut", "Do zrobienia", "Egiteke", "Huskeliste", "I'w Gwneud",
        "K vy\u{159}\u{ED}zen\u{ED}", "K'o chi Nib'an", "Le D\u{E9}anamh", "Moetdoen", "Nadawki",
        "Noch te dwaan", "Nog te doen", "Opravek", "Para hacer", "Pendente", "Per fer",
        "Perlu Buat", "Por facer", "Por hacer", "P\u{EB}r T\u{2019}u B\u{EB}r\u{EB}",
        "Ri dh\u{E8}anamh", "S\u{1EBD} l\u{E0}m", "Teend\u{151}k", "Teht\u{E4}v\u{E4}", "To Do",
        "ToDo", "Tugas", "Verk\u{FE}\u{E1}ttur", "Vybavi\u{165}", "War Ober", "Yap\u{131}lacak",
        "Za obaviti", "Zu erledigen", "\u{C0} faire", "\u{C5} gjere", "\u{C5} gj\u{F8}re",
        "\u{DC}lesanne",
        "\u{395}\u{3BA}\u{3BA}\u{3C1}\u{3B5}\u{3BC}\u{3CC}\u{3C4}\u{3B7}\u{3C4}\u{3B1}",
        "\u{414}\u{43B}\u{44F} \u{432}\u{44B}\u{43A}\u{430}\u{43D}\u{430}\u{43D}\u{43D}\u{44F}",
        "\u{414}\u{43E} \u{432}\u{438}\u{43A}\u{43E}\u{43D}\u{430}\u{43D}\u{43D}\u{44F}",
        "\u{416}\u{430}\u{441}\u{430}\u{443} \u{4AF}\u{448}\u{456}\u{43D}",
        "\u{417}\u{430} \u{438}\u{437}\u{43F}\u{44A}\u{43B}\u{43D}\u{435}\u{43D}\u{438}\u{435}",
        "\u{417}\u{430} \u{443}\u{440}\u{430}\u{434}\u{438}\u{442}\u{438}",
        "\u{417}\u{430}\u{434}\u{430}\u{447}\u{430}",
        "\u{41A} \u{438}\u{441}\u{43F}\u{43E}\u{43B}\u{43D}\u{435}\u{43D}\u{438}\u{44E}",
        "\u{531}\u{576}\u{565}\u{56C}",
        "\u{5D3}\u{5D1}\u{5E8}\u{5D9}\u{5DD} \u{5DC}\u{5E2}\u{5E9}\u{5D5}\u{5EA}",
        "\u{627}\u{646}\u{62C}\u{627}\u{645}\u{200C}\u{62F}\u{627}\u{62F}\u{646}\u{6CC}",
        "\u{644}\u{644}\u{642}\u{64A}\u{627}\u{645} \u{628}\u{647}",
        "\u{E2A}\u{E34}\u{E48}\u{E07}\u{E17}\u{E35}\u{E48}\u{E15}\u{E49}\u{E2D}\u{E07}\u{E17}\u{E33}",
        "\u{10D2}\u{10D0}\u{10E1}\u{10D0}\u{10D9}\u{10D4}\u{10D7}\u{10D4}\u{10D1}\u{10D4}\u{10DA}\u{10D8}",
        "\u{1780}\u{17B7}\u{1785}\u{17D2}\u{1785}\u{1780}\u{17B6}\u{179A}\u{200B}\u{178F}\u{17D2}\u{179A}\u{17BC}\u{179C}\u{200B}\u{1792}\u{17D2}\u{179C}\u{17BE}",
        "\u{5F85}\u{529E}", "\u{5F85}\u{8FA6}\u{4E8B}\u{9805}", "\u{D560}\u{C77C}",
    ],
    &[
        "An ceann tamaill", "Despu\u{E9}s", "Diweddarach", "Diwezhatoc'h", "En attente", "Geroago",
        "Hiljem", "Jub'a' chik na", "Kasneje", "Kasnije", "Kemudian", "Keyinroq",
        "K\u{E9}s\u{151}bb", "Later", "Letter", "Mai t\u{E2}rziu", "Mais tarde", "My\u{F6}hemmin",
        "M\u{E1}is tarde", "M\u{E1}s sero", "M\u{E1}s tarde", "M\u{E9}s tard", "Nanti",
        "Nesk\u{F4}r", "N\u{ED}os D\u{E9}ana\u{ED}", "Pi\u{F9} tardi", "Pli tard", "Plus tarde",
        "Pozd\u{11B}ji", "Pozd\u{17A}i\u{161}o", "P\u{EB}r m\u{EB} von\u{EB}", "P\u{F3}zd\u{17A}ej",
        "P\u{F3}\u{17A}niej", "Seinare", "Seinna", "Senare", "Senere", "Sonra", "Sp\u{E4}ter",
        "Ticki", "V\u{113}l\u{101}k", "V\u{117}liau", "\u{110}\u{1EC3} sau",
        "\u{391}\u{3C1}\u{3B3}\u{3CC}\u{3C4}\u{3B5}\u{3C1}\u{3B1}",
        "\u{412}\u{456}\u{434}\u{43A}\u{43B}\u{430}\u{434}\u{435}\u{43D}\u{43E}",
        "\u{41A}\u{430}\u{441}\u{43D}\u{438}\u{458}\u{435}",
        "\u{41A}\u{435}\u{439}\u{456}\u{43D}\u{456}\u{440}\u{435}\u{43A}",
        "\u{41E}\u{442}\u{43B}\u{43E}\u{436}\u{435}\u{43D}\u{43E}",
        "\u{41F}\u{430}\u{437}\u{43D}\u{435}\u{439}",
        "\u{41F}\u{43E}-\u{43A}\u{44A}\u{441}\u{43D}\u{43E}",
        "\u{41F}\u{43E}\u{434}\u{43E}\u{446}\u{43D}\u{430}",
        "\u{531}\u{57E}\u{565}\u{56C}\u{56B} \u{578}\u{582}\u{577}",
        "\u{531}\u{582}\u{565}\u{56C}\u{56B} \u{578}\u{582}\u{577}",
        "\u{5DE}\u{5D0}\u{5D5}\u{5D7}\u{5E8} \u{5D9}\u{5D5}\u{5EA}\u{5E8}",
        "\u{628}\u{639}\u{62F}\u{627}\u{64B}", "\u{644}\u{627}\u{62D}\u{642}\u{64B}\u{627}",
        "\u{E20}\u{E32}\u{E22}\u{E2B}\u{E25}\u{E31}\u{E07}",
        "\u{10D2}\u{10D0}\u{10D3}\u{10D0}\u{10D3}\u{10D4}\u{10D1}\u{10E3}\u{10DA}\u{10D8}",
        "\u{1796}\u{17C1}\u{179B}\u{1780}\u{17D2}\u{179A}\u{17C4}\u{1799}", "\u{5F8C}\u{3067}",
        "\u{7A0D}\u{540E}", "\u{7A0D}\u{5F8C}\u{8655}\u{7406}", "\u{C5F0}\u{AE30}",
    ],
];

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
        .enumerate()
        .filter_map(|(index, definition)| {
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
                position: i64::try_from(index).unwrap_or(i64::MAX),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotOverride {
    Label(String),
    Off,
}

pub fn builtin_slot(keyword: &str) -> Option<usize> {
    let prefix = keyword.get(..BUILTIN_KEYWORD_PREFIX.len())?;
    if !prefix.eq_ignore_ascii_case(BUILTIN_KEYWORD_PREFIX) {
        return None;
    }
    let digit = &keyword[BUILTIN_KEYWORD_PREFIX.len()..];
    if digit.len() != 1 {
        return None;
    }
    digit
        .parse::<usize>()
        .ok()
        .filter(|slot| (1..=BUILTIN_TAG_SLOTS).contains(slot))
}

pub fn builtin_keyword(slot: usize) -> String {
    format!("{}{}", BUILTIN_KEYWORD_PREFIX, slot)
}

pub fn is_label_keyword(keyword: &str) -> bool {
    !is_local_keyword(keyword) || builtin_slot(keyword).is_some()
}

pub(crate) fn match_key(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn matches_builtin_name(slot: usize, name: &str) -> bool {
    let key = match_key(name);
    !key.is_empty()
        && BUILTIN_TAG_NAMES
            .get(slot.wrapping_sub(1))
            .is_some_and(|names| names.iter().any(|known| match_key(known) == key))
}

fn is_top_level(tag: &CustomTag) -> bool {
    tag.keyword
        .as_deref()
        .and_then(keyword_text)
        .is_some_and(|text| text == tag.name)
}

pub fn slot_assignments(
    tags: &[CustomTag],
    overrides: &HashMap<usize, SlotOverride>,
) -> Vec<Option<String>> {
    let mut assigned: Vec<Option<String>> = vec![None; BUILTIN_TAG_SLOTS];
    let mut fixed = [false; BUILTIN_TAG_SLOTS];
    let mut used: HashSet<String> = HashSet::new();
    for slot in 1..=BUILTIN_TAG_SLOTS {
        match overrides.get(&slot) {
            Some(SlotOverride::Off) => fixed[slot - 1] = true,
            Some(SlotOverride::Label(token))
                if tags.iter().any(|tag| tag.tag_token == *token) && used.insert(token.clone()) =>
            {
                assigned[slot - 1] = Some(token.clone());
                fixed[slot - 1] = true;
            }
            _ => {}
        }
    }
    let mut ordered: Vec<&CustomTag> = tags.iter().collect();
    ordered.sort_by(|a, b| {
        is_top_level(b)
            .cmp(&is_top_level(a))
            .then_with(|| a.tag_token.cmp(&b.tag_token))
    });
    for slot in 1..=BUILTIN_TAG_SLOTS {
        if fixed[slot - 1] {
            continue;
        }
        let found = ordered
            .iter()
            .find(|tag| !used.contains(&tag.tag_token) && matches_builtin_name(slot, &tag.name));
        if let Some(tag) = found {
            used.insert(tag.tag_token.clone());
            assigned[slot - 1] = Some(tag.tag_token.clone());
        }
    }
    fill_slots_by_position(tags, &fixed, &mut assigned, &mut used);
    assigned
}

fn fill_slots_by_position(
    tags: &[CustomTag],
    fixed: &[bool; BUILTIN_TAG_SLOTS],
    assigned: &mut [Option<String>],
    used: &mut HashSet<String>,
) {
    let mut listed: Vec<&CustomTag> = tags.iter().filter(|tag| is_top_level(tag)).collect();
    listed.sort_by_key(|tag| tag.position);
    if listed.windows(2).any(|pair| pair[0].position == pair[1].position) {
        return;
    }
    let index_of = |token: &str| listed.iter().position(|tag| tag.tag_token == token);
    let anchors: Vec<(usize, usize)> = assigned
        .iter()
        .enumerate()
        .filter_map(|(index, token)| Some((index + 1, index_of(token.as_deref()?)?)))
        .collect();
    let Some(&(first_slot, first_index)) = anchors.first() else {
        return;
    };
    let offset = first_index as i64 - first_slot as i64;
    if anchors
        .iter()
        .any(|&(slot, index)| index as i64 - slot as i64 != offset)
    {
        return;
    }
    for slot in 1..=BUILTIN_TAG_SLOTS {
        if fixed[slot - 1] || assigned[slot - 1].is_some() {
            continue;
        }
        let enclosed = anchors.iter().any(|&(anchor, _)| anchor < slot)
            && anchors.iter().any(|&(anchor, _)| anchor > slot);
        if !enclosed && anchors.len() < POSITIONAL_MIN_ANCHORS {
            continue;
        }
        let Some(tag) = usize::try_from(slot as i64 + offset)
            .ok()
            .and_then(|index| listed.get(index))
        else {
            continue;
        };
        let named_elsewhere = (1..=BUILTIN_TAG_SLOTS).any(|other| matches_builtin_name(other, &tag.name));
        if !named_elsewhere && used.insert(tag.tag_token.clone()) {
            assigned[slot - 1] = Some(tag.tag_token.clone());
        }
    }
}

pub fn slot_alias_rows(
    tags: &[CustomTag],
    overrides: &HashMap<usize, SlotOverride>,
) -> Vec<(String, String)> {
    slot_assignments(tags, overrides)
        .into_iter()
        .enumerate()
        .filter_map(|(index, token)| Some((builtin_keyword(index + 1), token?)))
        .collect()
}

pub fn slot_is_mapped(slots: &[Option<String>], keyword: &str) -> bool {
    builtin_slot(keyword).is_some_and(|slot| slots.get(slot - 1).is_some_and(Option::is_some))
}

pub fn slot_tag<'a>(
    tags: &'a [CustomTag],
    slots: &[Option<String>],
    keyword: &str,
) -> Option<&'a CustomTag> {
    let token = slots.get(builtin_slot(keyword)? - 1)?.as_deref()?;
    tags.iter().find(|tag| tag.tag_token == token)
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
            position: 0,
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

    #[test]
    fn builtin_tag_keywords_are_recognized_in_any_case() {
        assert_eq!(builtin_slot("$label1"), Some(1));
        assert_eq!(builtin_slot("$LABEL5"), Some(5));
        assert_eq!(builtin_slot("$Label3"), Some(3));
        for keyword in ["$label0", "$label6", "$label10", "$label", "label1", "$labels", "$Forwarded"] {
            assert_eq!(builtin_slot(keyword), None, "{}", keyword);
        }
        assert!(is_label_keyword("$label4"));
        assert!(!is_label_keyword("$Forwarded"));
        assert!(!is_label_keyword("Junk"));
        assert!(is_label_keyword("Work"));
        assert_eq!(builtin_keyword(2), "$label2");
    }

    #[test]
    fn builtin_names_match_in_every_language_and_ignore_decoration() {
        assert!(matches_builtin_name(5, "Mais tarde"));
        assert!(matches_builtin_name(5, "\u{1F6CB}\u{FE0F} Mais tarde"));
        assert!(matches_builtin_name(5, "LATER"));
        assert!(matches_builtin_name(2, "\u{1F4BC} Trabalho"));
        assert!(matches_builtin_name(3, "Pessoal"));
        assert!(matches_builtin_name(1, "Wichtig"));
        assert!(matches_builtin_name(4, "To-Do"));
        assert!(matches_builtin_name(4, "\u{5F85}\u{529E}"));
        assert!(!matches_builtin_name(5, "Trabalho"));
        assert!(!matches_builtin_name(1, "\u{1F534} Aten\u{E7}\u{E3}o"));
        assert!(!matches_builtin_name(4, "Por fazer"));
        assert!(!matches_builtin_name(1, "\u{1F534}"));
        assert!(!matches_builtin_name(0, "Important"));
        assert!(!matches_builtin_name(6, "Important"));
    }

    #[test]
    fn no_language_name_belongs_to_two_builtin_tags() {
        for (index, names) in BUILTIN_TAG_NAMES.iter().enumerate() {
            for name in names.iter() {
                assert!(!match_key(name).is_empty(), "{}", name);
                for other in 1..=BUILTIN_TAG_SLOTS {
                    if other != index + 1 {
                        assert!(!matches_builtin_name(other, name), "{} in {}", name, other);
                    }
                }
            }
        }
    }

    fn raul_tags() -> Vec<CustomTag> {
        vec![
            keyed("t-atencao", "\u{1F534} Aten\u{E7}\u{E3}o"),
            keyed("t-trabalho", "\u{1F4BC} Trabalho"),
            keyed("t-pessoal", "\u{1F3E0} Pessoal"),
            keyed("t-fazer", "\u{1F4DD} Por fazer"),
            keyed("t-tarde", "\u{1F6CB}\u{FE0F} Mais tarde"),
            keyed("t-despesas", "\u{1F4B8} Despesas"),
            keyed("t-entretenimento", "\u{1F37F} Entretenimento"),
        ]
    }

    fn slot_tokens(tags: &[CustomTag], overrides: &HashMap<usize, SlotOverride>) -> Vec<Option<&'static str>> {
        let known = ["t-atencao", "t-trabalho", "t-pessoal", "t-fazer", "t-tarde", "a", "b", "c", "z"];
        slot_assignments(tags, overrides)
            .into_iter()
            .map(|token| token.map(|token| *known.iter().find(|k| **k == token).unwrap()))
            .collect()
    }

    #[test]
    fn builtin_tags_match_labels_by_name_and_by_choice() {
        let tags = raul_tags();
        assert_eq!(
            slot_tokens(&tags, &HashMap::new()),
            vec![None, Some("t-trabalho"), Some("t-pessoal"), None, Some("t-tarde")]
        );
        let overrides = HashMap::from([
            (1, SlotOverride::Label("t-atencao".to_string())),
            (4, SlotOverride::Label("t-fazer".to_string())),
        ]);
        assert_eq!(
            slot_tokens(&tags, &overrides),
            vec![
                Some("t-atencao"),
                Some("t-trabalho"),
                Some("t-pessoal"),
                Some("t-fazer"),
                Some("t-tarde")
            ]
        );
        let rows = slot_alias_rows(&tags, &overrides);
        assert!(rows.contains(&("$label1".to_string(), "t-atencao".to_string())));
        assert!(rows.contains(&("$label5".to_string(), "t-tarde".to_string())));
        assert_eq!(rows.len(), 5);
        let slots = slot_assignments(&tags, &overrides);
        assert_eq!(slot_tag(&tags, &slots, "$LABEL4").map(|t| t.tag_token.as_str()), Some("t-fazer"));
        assert_eq!(slot_tag(&tags, &slots, "$label6"), None);
        assert_eq!(slot_tag(&tags, &slots, "Work"), None);
    }

    #[test]
    fn a_slot_turned_off_or_given_a_missing_label_behaves_as_chosen() {
        let tags = raul_tags();
        let overrides = HashMap::from([
            (5, SlotOverride::Off),
            (2, SlotOverride::Label("gone".to_string())),
        ]);
        assert_eq!(
            slot_tokens(&tags, &overrides),
            vec![None, Some("t-trabalho"), Some("t-pessoal"), None, None]
        );
    }

    #[test]
    fn a_chosen_label_is_not_also_matched_by_name() {
        let tags = raul_tags();
        let overrides = HashMap::from([(1, SlotOverride::Label("t-tarde".to_string()))]);
        assert_eq!(
            slot_tokens(&tags, &overrides),
            vec![Some("t-tarde"), Some("t-trabalho"), Some("t-pessoal"), None, None]
        );
        let twice = HashMap::from([
            (1, SlotOverride::Label("t-tarde".to_string())),
            (4, SlotOverride::Label("t-tarde".to_string())),
        ]);
        assert_eq!(slot_tokens(&tags, &twice)[3], None);
    }

    #[test]
    fn a_top_level_label_wins_a_name_match_over_a_nested_one() {
        let mut tags = vec![tag("a", "Clients"), tag("b", "Later"), tag("z", "Later")];
        let parents = parent_map(&[("a", "Clients", None), ("b", "Later", Some("a")), ("z", "Later", None)]);
        assign_keywords(&mut tags, &label_paths(&parents));
        assert_eq!(slot_tokens(&tags, &HashMap::new())[4], Some("z"));
        let flat = vec![keyed("c", "later"), keyed("b", "Later")];
        assert_eq!(slot_tokens(&flat, &HashMap::new())[4], Some("b"));
    }

    fn listed(rows: &[(&str, &str)]) -> Vec<CustomTag> {
        rows.iter()
            .enumerate()
            .map(|(index, (token, name))| CustomTag {
                position: index as i64,
                ..keyed(token, name)
            })
            .collect()
    }

    fn raul_listed() -> Vec<CustomTag> {
        listed(&[
            ("t-atencao", "\u{1F6A8} Aten\u{E7}\u{E3}o"),
            ("t-trabalho", "\u{1F4BC} Trabalho"),
            ("t-pessoal", "\u{1F9D1} Pessoal"),
            ("t-fazer", "\u{1F477} Por fazer"),
            ("t-tarde", "\u{1F6CB}\u{FE0F} Mais tarde"),
            ("a", "\u{1F911} Despesas"),
            ("b", "\u{1F37F} Entretenimento"),
        ])
    }

    #[test]
    fn renamed_builtin_tags_follow_the_label_order() {
        let tags = raul_listed();
        assert_eq!(
            slot_tokens(&tags, &HashMap::new()),
            vec![
                Some("t-atencao"),
                Some("t-trabalho"),
                Some("t-pessoal"),
                Some("t-fazer"),
                Some("t-tarde")
            ]
        );
        let slots = slot_assignments(&tags, &HashMap::new());
        assert_eq!(slot_tag(&tags, &slots, "$label4").map(|t| t.tag_token.as_str()), Some("t-fazer"));
    }

    #[test]
    fn a_chosen_or_disabled_slot_keeps_priority_over_the_label_order() {
        let tags = raul_listed();
        let overrides = HashMap::from([(4, SlotOverride::Off), (1, SlotOverride::Label("b".to_string()))]);
        assert_eq!(
            slot_tokens(&tags, &overrides),
            vec![Some("b"), Some("t-trabalho"), Some("t-pessoal"), None, Some("t-tarde")]
        );
    }

    #[test]
    fn a_slot_between_name_matches_follows_the_label_order() {
        let tags = listed(&[("a", "Work"), ("b", "Personal"), ("c", "Errands"), ("z", "Later")]);
        assert_eq!(slot_tokens(&tags, &HashMap::new()), vec![None, Some("a"), Some("b"), Some("c"), Some("z")]);
    }

    #[test]
    fn the_label_order_is_ignored_when_it_is_weak_or_inconsistent() {
        let open_ended = listed(&[("a", "Work"), ("b", "Personal"), ("c", "Receipts")]);
        assert_eq!(slot_tokens(&open_ended, &HashMap::new()), vec![None, Some("a"), Some("b"), None, None]);

        let shuffled = listed(&[("a", "Work"), ("c", "Errands"), ("b", "Personal"), ("z", "Later")]);
        assert_eq!(slot_tokens(&shuffled, &HashMap::new()), vec![None, Some("a"), Some("b"), None, Some("z")]);

        let unordered = raul_tags();
        assert_eq!(
            slot_tokens(&unordered, &HashMap::new()),
            vec![None, Some("t-trabalho"), Some("t-pessoal"), None, Some("t-tarde")]
        );

        let named = listed(&[("c", "Important"), ("a", "Work"), ("b", "Personal"), ("z", "Later")]);
        assert_eq!(slot_tokens(&named, &HashMap::new()), vec![Some("c"), Some("a"), Some("b"), None, Some("z")]);
    }

    #[test]
    fn a_label_named_for_another_slot_is_not_taken_by_position() {
        let tags = listed(&[("a", "Work"), ("b", "Personal"), ("c", "Important"), ("z", "Later")]);
        let overrides = HashMap::from([(1, SlotOverride::Off)]);
        assert_eq!(slot_tokens(&tags, &overrides), vec![None, Some("a"), Some("b"), None, Some("z")]);
    }
}
