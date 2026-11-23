//! Text from office documents: Office Open XML (docx, pptx, xlsx) and
//! OpenDocument (odt, odp, ods). Each is a zip of XML parts.

use std::io::{Cursor, Read};

use super::markup::{XmlText, xml_text};

/// The most bytes read from one part: a part bigger than this is a zip
/// bomb, not a document.
const MAX_PART: u64 = 64 << 20;

fn part(zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<Vec<u8>> {
    let file = zip.by_name(name).ok()?;
    let mut out = Vec::new();
    file.take(MAX_PART).read_to_end(&mut out).ok()?;
    Some(out)
}

fn open(bytes: &[u8]) -> Option<zip::ZipArchive<Cursor<&[u8]>>> {
    zip::ZipArchive::new(Cursor::new(bytes)).ok()
}

/// The parts whose names start with `prefix` and end in `.xml`, in
/// number order (slide2 before slide10).
fn numbered_parts(zip: &zip::ZipArchive<Cursor<&[u8]>>, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = zip
        .file_names()
        .filter(|n| n.starts_with(prefix) && n.ends_with(".xml"))
        .map(str::to_string)
        .collect();
    let number = |n: &str| -> u64 {
        let digits: String = n.chars().filter(char::is_ascii_digit).collect();
        digits.parse().unwrap_or(0)
    };
    names.sort_by_key(|n| number(n));
    names
}

pub fn docx(bytes: &[u8]) -> Option<String> {
    let mut zip = open(bytes)?;
    let rules = XmlText {
        inside: &["t"],
        breaks: &["p"],
        spaces: &["tab", "br"],
    };
    let mut out = xml_text(&part(&mut zip, "word/document.xml")?, &rules)?;
    for extra in ["word/footnotes.xml", "word/endnotes.xml"] {
        if let Some(xml) = part(&mut zip, extra) {
            out.push('\n');
            out.push_str(&xml_text(&xml, &rules).unwrap_or_default());
        }
    }
    Some(out)
}

pub fn pptx(bytes: &[u8]) -> Option<String> {
    let mut zip = open(bytes)?;
    let rules = XmlText {
        inside: &["t"],
        breaks: &["p"],
        spaces: &["br"],
    };
    let mut out = String::new();
    for name in numbered_parts(&zip, "ppt/slides/slide") {
        out.push_str(&xml_text(&part(&mut zip, &name)?, &rules)?);
        out.push('\n');
    }
    Some(out)
}

/// A workbook's text: its shared strings and its inline strings. Numbers
/// and formulas are left out.
pub fn xlsx(bytes: &[u8]) -> Option<String> {
    let mut zip = open(bytes)?;
    let rules = XmlText {
        inside: &["t"],
        breaks: &["si", "is"],
        spaces: &[],
    };
    let mut out = match part(&mut zip, "xl/sharedStrings.xml") {
        Some(xml) => xml_text(&xml, &rules)?,
        None => String::new(),
    };
    for name in numbered_parts(&zip, "xl/worksheets/sheet") {
        // Only inline strings (`<is><t>`) are text in a sheet.
        let inline = XmlText {
            inside: &["is"],
            breaks: &["is"],
            spaces: &[],
        };
        out.push_str(&xml_text(&part(&mut zip, &name)?, &inline)?);
    }
    Some(out)
}

pub fn open_document(bytes: &[u8]) -> Option<String> {
    let mut zip = open(bytes)?;
    let rules = XmlText {
        inside: &["body"],
        breaks: &["p", "h"],
        spaces: &["s", "tab", "line-break"],
    };
    xml_text(&part(&mut zip, "content.xml")?, &rules)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    /// A zip of `parts`, as an office suite writes it.
    pub(crate) fn zip_of(parts: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default();
            for (name, body) in parts {
                z.start_file(*name, opts).unwrap();
                z.write_all(body.as_bytes()).unwrap();
            }
            z.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn a_docx_gives_its_paragraphs() {
        let doc = r#"<w:document xmlns:w="w"><w:body>
            <w:p><w:r><w:t>Quarterly</w:t></w:r><w:r><w:t xml:space="preserve"> report</w:t></w:r></w:p>
            <w:p><w:r><w:instrText>HYPERLINK x</w:instrText><w:t>Second</w:t></w:r></w:p>
            </w:body></w:document>"#;
        let notes = r#"<w:footnotes xmlns:w="w"><w:footnote><w:p><w:r><w:t>See page 3</w:t></w:r></w:p></w:footnote></w:footnotes>"#;
        let bytes = zip_of(&[("word/document.xml", doc), ("word/footnotes.xml", notes)]);
        let text = docx(&bytes).unwrap();
        assert!(text.contains("Quarterly report\n"));
        assert!(text.contains("Second") && !text.contains("HYPERLINK"));
        assert!(text.contains("See page 3"));
    }

    #[test]
    fn a_pptx_gives_its_slides_in_order() {
        let slide = |t: &str| {
            format!(
                r#"<p:sld xmlns:a="a" xmlns:p="p"><a:p><a:r><a:t>{t}</a:t></a:r></a:p></p:sld>"#
            )
        };
        let (s1, s2, s10) = (slide("first"), slide("second"), slide("tenth"));
        let bytes = zip_of(&[
            ("ppt/slides/slide10.xml", &s10),
            ("ppt/slides/slide1.xml", &s1),
            ("ppt/slides/slide2.xml", &s2),
        ]);
        let text = pptx(&bytes).unwrap();
        let at = |w| text.find(w).unwrap();
        assert!(at("first") < at("second") && at("second") < at("tenth"));
    }

    #[test]
    fn an_xlsx_gives_its_strings_not_its_numbers() {
        let shared = r#"<sst><si><t>Budget</t></si><si><r><t>Rent</t></r></si></sst>"#;
        let sheet = r#"<worksheet><sheetData><row><c><v>1234</v></c><c t="inlineStr"><is><t>Inline</t></is></c></row></sheetData></worksheet>"#;
        let bytes = zip_of(&[
            ("xl/sharedStrings.xml", shared),
            ("xl/worksheets/sheet1.xml", sheet),
        ]);
        let text = xlsx(&bytes).unwrap();
        assert!(text.contains("Budget") && text.contains("Rent") && text.contains("Inline"));
        assert!(!text.contains("1234"));
    }

    #[test]
    fn an_odt_gives_its_body() {
        let content = r#"<office:document-content xmlns:office="o" xmlns:text="t">
            <office:meta>Not this</office:meta>
            <office:body><office:text><text:h>Title</text:h><text:p>Body<text:s/>text</text:p></office:text></office:body>
            </office:document-content>"#;
        let text = open_document(&zip_of(&[("content.xml", content)])).unwrap();
        assert!(text.contains("Title\n") && text.contains("Body text"));
        assert!(!text.contains("Not this"));
    }

    #[test]
    fn a_zip_without_the_part_gives_none() {
        assert!(docx(&zip_of(&[("other.xml", "<a/>")])).is_none());
    }
}
