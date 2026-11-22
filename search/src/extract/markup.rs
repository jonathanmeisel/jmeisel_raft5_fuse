//! Text from markup: HTML without its tags, and the text nodes of XML.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// The text of an HTML page. Drops tags, comments, scripts and styles, and
/// decodes the common entities. Block tags end a line. Not a full HTML
/// parser: it only has to find words.
pub fn html_text(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        push_decoded(&mut out, &rest[..lt]);
        rest = &rest[lt..];
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |end| &after[end + 3..]);
            continue;
        }
        let Some(gt) = rest.find('>') else {
            rest = "";
            break;
        };
        let tag = rest[1..gt].trim_start_matches('/').to_ascii_lowercase();
        let name: String = tag
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        rest = &rest[gt + 1..];
        if name == "script" || name == "style" {
            let close = format!("</{name}");
            let lower = rest.to_ascii_lowercase();
            rest = lower.find(&close).map_or("", |end| {
                let after = &rest[end..];
                after.find('>').map_or("", |gt| &after[gt + 1..])
            });
            continue;
        }
        if matches!(
            name.as_str(),
            "p" | "br" | "div" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "td"
        ) {
            out.push('\n');
        } else {
            out.push(' ');
        }
    }
    push_decoded(&mut out, rest);
    out
}

fn push_decoded(out: &mut String, text: &str) {
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let end = rest[1..].find(';').map(|e| e + 1).filter(|&e| e <= 10);
        let decoded = end.and_then(|e| entity(&rest[1..e]));
        match (end, decoded) {
            (Some(e), Some(c)) => {
                out.push(c);
                rest = &rest[e + 1..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
}

fn entity(name: &str) -> Option<char> {
    if let Some(num) = name.strip_prefix('#') {
        let n = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse().ok()?,
        };
        return char::from_u32(n);
    }
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        _ => return None,
    })
}

/// What `xml_text` takes text from, and where it ends lines.
pub struct XmlText<'a> {
    /// Take text only inside elements with these local names; empty for
    /// all text.
    pub inside: &'a [&'a str],
    /// The end of these elements ends a line.
    pub breaks: &'a [&'a str],
    /// These (empty) elements stand for a space: tabs and line breaks.
    pub spaces: &'a [&'a str],
}

/// The text nodes of an XML document, as `rules` says. `None` for XML that
/// does not parse.
pub fn xml_text(xml: &[u8], rules: &XmlText<'_>) -> Option<String> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut out = String::new();
    let mut depth_inside = 0usize;
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(e) => {
                let name = e.local_name();
                if rules.inside.contains(&local(name.as_ref())) {
                    depth_inside += 1;
                }
            }
            Event::End(e) => {
                let name = e.local_name();
                let name = local(name.as_ref());
                if rules.inside.contains(&name) {
                    depth_inside = depth_inside.saturating_sub(1);
                }
                if rules.breaks.contains(&name) {
                    out.push('\n');
                }
            }
            Event::Empty(e) => {
                let name = e.local_name();
                let name = local(name.as_ref());
                if rules.spaces.contains(&name) {
                    out.push(' ');
                }
                if rules.breaks.contains(&name) {
                    out.push('\n');
                }
            }
            Event::Text(t) if rules.inside.is_empty() || depth_inside > 0 => {
                out.push_str(&t.unescape().ok()?);
            }
            Event::CData(t) if rules.inside.is_empty() || depth_inside > 0 => {
                out.push_str(&String::from_utf8_lossy(&t));
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Some(out)
}

fn local(name: &[u8]) -> &str {
    std::str::from_utf8(name).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_loses_tags_scripts_and_comments() {
        let html = "<html><head><style>p{color:red}</style>\
                    <script>var x = '<p>';</script></head>\
                    <body><!-- note --><h1>Trip</h1><p>Fish &amp; chips&nbsp;&#233;&#x41;</p>\
                    <p>a&bogus;b</p></body></html>";
        let text = html_text(html);
        assert!(!text.contains("color") && !text.contains("var x") && !text.contains("note"));
        assert!(text.contains("Trip"));
        assert!(text.contains("Fish & chips éA"));
        assert!(text.contains("a&bogus;b"));
    }

    #[test]
    fn html_with_a_cut_off_tag_ends_cleanly() {
        assert_eq!(html_text("hi <b").trim(), "hi");
        assert_eq!(html_text("a <!-- open").trim(), "a");
    }

    #[test]
    fn xml_text_follows_its_rules() {
        let xml =
            br#"<d xmlns:w="w"><w:p><w:r><w:t>One</w:t><w:tab/><w:t>two &amp;</w:t></w:r></w:p>
                     <w:p><w:instr>SKIP</w:instr><w:t>three</w:t></w:p></d>"#;
        let rules = XmlText {
            inside: &["t"],
            breaks: &["p"],
            spaces: &["tab"],
        };
        assert_eq!(xml_text(xml, &rules).unwrap(), "One two &\nthree\n");
        assert!(xml_text(b"<a><b></a>", &rules).is_none());
    }
}
