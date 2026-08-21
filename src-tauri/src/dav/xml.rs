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
use quick_xml::events::Event;
use quick_xml::Reader;

const MAX_DEPTH: usize = 64;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct PropRequest {
    pub names: Vec<String>,
    pub allprop: bool,
    pub propname: bool,
}

impl PropRequest {
    pub fn wants(&self, name: &str) -> bool {
        self.allprop || self.names.iter().any(|n| n == name)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReportRequest {
    Multiget {
        props: PropRequest,
        hrefs: Vec<String>,
    },
    Query {
        props: PropRequest,
    },
    Unsupported,
}

pub fn escape_xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' => {}
            _ => out.push(ch),
        }
    }
    out
}

fn local_name(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.rsplit(':').next().unwrap_or("").to_lowercase()
}

struct Walker<'a> {
    reader: Reader<&'a [u8]>,
    stack: Vec<String>,
    buffer: Vec<u8>,
}

impl<'a> Walker<'a> {
    fn new(body: &'a str) -> Self {
        let mut reader = Reader::from_reader(body.as_bytes());
        reader.config_mut().trim_text(true);
        Self {
            reader,
            stack: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

enum Node {
    Open(String),
    Empty(String),
    Close(String),
    Text(String),
    End,
}

impl<'a> Walker<'a> {
    fn next(&mut self) -> Result<Node, String> {
        self.buffer.clear();
        match self.reader.read_event_into(&mut self.buffer) {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name().as_ref());
                if self.stack.len() >= MAX_DEPTH {
                    return Err("document nested too deeply".to_string());
                }
                self.stack.push(name.clone());
                Ok(Node::Open(name))
            }
            Ok(Event::Empty(e)) => Ok(Node::Empty(local_name(e.name().as_ref()))),
            Ok(Event::End(e)) => {
                self.stack.pop();
                Ok(Node::Close(local_name(e.name().as_ref())))
            }
            Ok(Event::Text(e)) => match e.unescape() {
                Ok(text) => Ok(Node::Text(text.to_string())),
                Err(_) => Err("unresolvable entity reference".to_string()),
            },
            Ok(Event::CData(_)) => Ok(Node::Text(String::new())),
            Ok(Event::Eof) => Ok(Node::End),
            Ok(Event::DocType(_)) => Err("doctype declarations are not accepted".to_string()),
            Ok(_) => Ok(Node::Text(String::new())),
            Err(e) => Err(format!("malformed xml: {}", e)),
        }
    }

    fn in_element(&self, name: &str) -> bool {
        self.stack.iter().any(|n| n == name)
    }
}

fn collect(body: &str) -> Result<(PropRequest, Vec<String>, Option<String>), String> {
    let mut props = PropRequest::default();
    let mut hrefs = Vec::new();
    let mut root: Option<String> = None;
    let mut current_href = String::new();
    let mut walker = Walker::new(body);

    loop {
        match walker.next()? {
            Node::End => break,
            Node::Open(name) | Node::Empty(name) => {
                if root.is_none() && name != "xml" {
                    root = Some(name.clone());
                }
                match name.as_str() {
                    "allprop" => props.allprop = true,
                    "propname" => props.propname = true,
                    "href" => current_href.clear(),
                    _ => {
                        if walker.in_element("prop") && name != "prop" {
                            if !props.names.contains(&name) {
                                props.names.push(name);
                            }
                        }
                    }
                }
            }
            Node::Close(name) => {
                if name == "href" && !current_href.trim().is_empty() {
                    hrefs.push(current_href.trim().to_string());
                    current_href.clear();
                }
            }
            Node::Text(text) => {
                if walker.in_element("href") {
                    current_href.push_str(&text);
                }
            }
        }
    }

    Ok((props, hrefs, root))
}

pub fn parse_propfind(body: &str) -> Result<PropRequest, String> {
    if body.trim().is_empty() {
        return Ok(PropRequest {
            names: Vec::new(),
            allprop: true,
            propname: false,
        });
    }

    let (mut props, _, _) = collect(body)?;
    if props.names.is_empty() && !props.propname {
        props.allprop = true;
    }

    Ok(props)
}

pub fn parse_report(body: &str) -> Result<ReportRequest, String> {
    if body.trim().is_empty() {
        return Ok(ReportRequest::Unsupported);
    }

    let (props, hrefs, root) = collect(body)?;

    match root.as_deref() {
        Some("addressbook-multiget") => Ok(ReportRequest::Multiget { props, hrefs }),
        Some("addressbook-query") => Ok(ReportRequest::Query { props }),
        _ => Ok(ReportRequest::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_and_drops_control_characters() {
        assert_eq!(escape_xml("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
        assert_eq!(escape_xml("ok\u{7}bad"), "okbad");
        assert_eq!(escape_xml("keep\nnewlines"), "keep\nnewlines");
    }

    #[test]
    fn parses_a_prop_list_from_propfind() {
        let body = r#"<?xml version="1.0"?>
            <D:propfind xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">
              <D:prop><D:getetag/><D:resourcetype/><CS:getctag/></D:prop>
            </D:propfind>"#;
        let props = parse_propfind(body).unwrap();

        assert!(!props.allprop);
        assert!(props.wants("getetag"));
        assert!(props.wants("resourcetype"));
        assert!(props.wants("getctag"));
        assert!(!props.wants("displayname"));
    }

    #[test]
    fn an_empty_body_means_allprop() {
        let props = parse_propfind("").unwrap();

        assert!(props.allprop);
        assert!(props.wants("anything"));
    }

    #[test]
    fn recognizes_allprop_and_propname() {
        assert!(parse_propfind(r#"<propfind xmlns="DAV:"><allprop/></propfind>"#)
            .unwrap()
            .allprop);
        assert!(parse_propfind(r#"<propfind xmlns="DAV:"><propname/></propfind>"#)
            .unwrap()
            .propname);
    }

    #[test]
    fn parses_addressbook_multiget_hrefs() {
        let body = r#"<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
            <D:prop><D:getetag/><C:address-data/></D:prop>
            <D:href>/addressbooks/u/contacts/a.vcf</D:href>
            <D:href>/addressbooks/u/contacts/b.vcf</D:href>
          </C:addressbook-multiget>"#;

        match parse_report(body).unwrap() {
            ReportRequest::Multiget { props, hrefs } => {
                assert!(props.wants("address-data"));
                assert_eq!(
                    hrefs,
                    vec![
                        "/addressbooks/u/contacts/a.vcf".to_string(),
                        "/addressbooks/u/contacts/b.vcf".to_string()
                    ]
                );
            }
            other => panic!("expected multiget, got {:?}", other),
        }
    }

    #[test]
    fn parses_addressbook_query_as_a_full_listing() {
        let body = r#"<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
            <D:prop><D:getetag/></D:prop>
            <C:filter/>
          </C:addressbook-query>"#;

        assert!(matches!(
            parse_report(body).unwrap(),
            ReportRequest::Query { .. }
        ));
    }

    #[test]
    fn unknown_reports_are_reported_as_unsupported() {
        let body = r#"<D:sync-collection xmlns:D="DAV:"><D:prop><D:getetag/></D:prop></D:sync-collection>"#;

        assert_eq!(parse_report(body).unwrap(), ReportRequest::Unsupported);
    }

    #[test]
    fn rejects_a_doctype_declaration() {
        let body = r#"<!DOCTYPE propfind [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>"#;

        assert!(parse_propfind(body).is_err());
    }

    #[test]
    fn rejects_malformed_xml() {
        assert!(parse_propfind("<propfind><prop></propfind>").is_err());
    }

    #[test]
    fn does_not_expand_external_entities() {
        let body = r#"<D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&xxe;</D:displayname></D:prop></D:propfind>"#;

        assert!(parse_propfind(body).is_err());
    }
}
