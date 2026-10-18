//! A small, safe Markdown subset for research write-ups (#35).
//!
//! Write-up bodies are parsed into a tree of blocks and inlines, never into
//! HTML. The public pages render the tree as React elements, so text is
//! escaped by construction and there is no raw HTML path at all: `<script>`
//! in a body is shown as the literal text `<script>`. See
//! `docs/research-writeups.md#markdown`.
//!
//! Supported: headings (`#` to `###`, rendered one level down because the
//! page title is the only `h1`), paragraphs, `-` or `*` lists, `1.` lists,
//! `>` quotes, `---` rules, fenced code blocks, and inline `**strong**`,
//! `*emphasis*`, `` `code` `` and `[text](url)` links. Anything else is
//! text. Links keep only `https://` URLs and site-relative paths; any other
//! scheme (`javascript:`, `data:`, `http:`, protocol-relative `//`) drops the
//! link and keeps its text.
//!
//! Parsing is one pass over the lines and one pass over each line's
//! characters, so the cost is linear in the input.

use serde::{Deserialize, Serialize};

use crate::timeline::needs_escape;

/// Largest body accepted, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Most blocks a body may produce.
pub const MAX_BLOCKS: usize = 2_000;
/// Longest link URL kept, in bytes.
pub const MAX_URL_BYTES: usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    /// `level` is 2, 3 or 4: the page title is the only level 1 heading.
    Heading {
        level: u8,
        inlines: Vec<Inline>,
    },
    Paragraph {
        inlines: Vec<Inline>,
    },
    List {
        ordered: bool,
        items: Vec<Vec<Inline>>,
    },
    Quote {
        inlines: Vec<Inline>,
    },
    /// Preformatted text. Never executed or highlighted.
    Code {
        text: String,
    },
    Rule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Inline {
    Text {
        text: String,
    },
    Strong {
        text: String,
    },
    Emphasis {
        text: String,
    },
    Code {
        text: String,
    },
    /// `href` is an `https://` URL or a site-relative path starting with a
    /// single `/`.
    Link {
        text: String,
        href: String,
    },
}

/// Whether a link target may be kept: `https://` with a plausible host, or
/// a site-relative path. Everything else is dropped.
pub fn safe_href(raw: &str) -> Option<String> {
    let href = raw.trim();
    if href.is_empty() || href.len() > MAX_URL_BYTES {
        return None;
    }
    if href
        .chars()
        .any(|c| c.is_whitespace() || needs_escape(c) || matches!(c, '<' | '>' | '"' | '\\'))
    {
        return None;
    }
    if let Some(rest) = href.strip_prefix("https://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let ok = !host.is_empty()
            && !host.contains('@')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
        return ok.then(|| href.to_string());
    }
    // Site-relative only: not protocol-relative (`//host`).
    if href.starts_with('/') && !href.starts_with("//") {
        return Some(href.to_string());
    }
    None
}

/// Make control, bidi and invisible characters visible, so text cannot
/// reorder or hide what a reader sees. Tabs and newlines stay in code.
fn clean(s: &str, keep_newlines: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if keep_newlines && (c == '\n' || c == '\t') {
            out.push(c);
        } else if needs_escape(c) {
            out.push_str(&c.escape_unicode().to_string());
        } else {
            out.push(c);
        }
    }
    out
}

fn push_text(out: &mut Vec<Inline>, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(Inline::Text { text: prev }) = out.last_mut() {
        prev.push_str(text);
    } else {
        out.push(Inline::Text {
            text: text.to_string(),
        });
    }
}

/// Find `needle` in `chars` from `from`, returning its start index.
fn find(chars: &[char], from: usize, needle: &[char]) -> Option<usize> {
    if needle.is_empty() || from >= chars.len() {
        return None;
    }
    (from..=chars.len().saturating_sub(needle.len())).find(|&i| chars[i..].starts_with(needle))
}

/// The `)` that closes a link URL starting at `from`, allowing balanced
/// parentheses inside the URL.
fn closing_paren(chars: &[char], from: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in chars.iter().enumerate().skip(from) {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return Some(i),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Parse one line (or a joined paragraph) of inline Markdown.
pub fn parse_inlines(text: &str) -> Vec<Inline> {
    let text = clean(text, false);
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut plain = String::new();
    let mut i = 0;
    // Each construct searches forward for its closer once; on a miss the
    // opener is plain text and the scan moves on by one character. A
    // closer search can be long, so cap how far it looks to keep the
    // worst case linear in practice.
    const LOOKAHEAD: usize = 512;
    let window = |from: usize| chars.len().min(from + LOOKAHEAD);
    while i < chars.len() {
        let c = chars[i];
        let flush = |plain: &mut String, out: &mut Vec<Inline>| {
            push_text(out, plain);
            plain.clear();
        };
        if c == '`'
            && let Some(end) = find(&chars[..window(i + 1)], i + 1, &['`'])
            && end > i + 1
        {
            flush(&mut plain, &mut out);
            out.push(Inline::Code {
                text: chars[i + 1..end].iter().collect(),
            });
            i = end + 1;
            continue;
        }
        if c == '*'
            && chars.get(i + 1) == Some(&'*')
            && let Some(end) = find(&chars[..window(i + 2)], i + 2, &['*', '*'])
            && end > i + 2
        {
            flush(&mut plain, &mut out);
            out.push(Inline::Strong {
                text: chars[i + 2..end].iter().collect(),
            });
            i = end + 2;
            continue;
        }
        if (c == '*' || c == '_')
            && chars.get(i + 1).is_some_and(|n| !n.is_whitespace())
            && let Some(end) = find(&chars[..window(i + 1)], i + 1, &[c])
            && end > i + 1
        {
            flush(&mut plain, &mut out);
            out.push(Inline::Emphasis {
                text: chars[i + 1..end].iter().collect(),
            });
            i = end + 1;
            continue;
        }
        if c == '['
            && let Some(close) = find(&chars[..window(i + 1)], i + 1, &[']', '('])
            && let Some(end) = closing_paren(&chars[..window(close + 2)], close + 2)
        {
            flush(&mut plain, &mut out);
            let label: String = chars[i + 1..close].iter().collect();
            let url: String = chars[close + 2..end].iter().collect();
            match safe_href(&url) {
                Some(href) if !label.trim().is_empty() => {
                    out.push(Inline::Link { text: label, href })
                }
                _ => push_text(&mut out, &label),
            }
            i = end + 1;
            continue;
        }
        plain.push(c);
        i += 1;
    }
    push_text(&mut out, &plain);
    out
}

fn heading(line: &str) -> Option<(u8, &str)> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if (1..=3).contains(&hashes) && line[hashes..].starts_with(' ') {
        Some((hashes as u8 + 1, line[hashes..].trim()))
    } else {
        None
    }
}

fn bullet(line: &str) -> Option<&str> {
    line.strip_prefix("- ").or_else(|| line.strip_prefix("* "))
}

fn numbered(line: &str) -> Option<&str> {
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if (1..=4).contains(&digits) {
        line[digits..].strip_prefix(". ")
    } else {
        None
    }
}

fn is_rule(line: &str) -> bool {
    let t = line.trim();
    t.len() >= 3 && (t.chars().all(|c| c == '-') || t.chars().all(|c| c == '*'))
}

/// Parse a body. Bodies over [`MAX_BODY_BYTES`] are cut at the limit (on a
/// character boundary) and parsing stops after [`MAX_BLOCKS`] blocks;
/// [`crate::writeup::lint`] reports both before anything is published.
pub fn parse(body: &str) -> Vec<Block> {
    let mut end = body.len().min(MAX_BODY_BYTES);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    let body = body[..end].replace("\r\n", "\n");
    let lines: Vec<&str> = body.split('\n').collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() && blocks.len() < MAX_BLOCKS {
        let line = lines[i];
        let t = line.trim_end();
        if t.trim().is_empty() {
            i += 1;
            continue;
        }
        if t.trim_start().starts_with("```") {
            let mut text = Vec::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with("```") {
                text.push(lines[i]);
                i += 1;
            }
            i += 1; // closing fence, or past the end
            blocks.push(Block::Code {
                text: clean(&text.join("\n"), true),
            });
            continue;
        }
        let t = t.trim_start();
        if let Some((level, rest)) = heading(t) {
            blocks.push(Block::Heading {
                level,
                inlines: parse_inlines(rest),
            });
            i += 1;
            continue;
        }
        if is_rule(t) {
            blocks.push(Block::Rule);
            i += 1;
            continue;
        }
        if bullet(t).is_some() || numbered(t).is_some() {
            let ordered = numbered(t).is_some();
            let mut items = Vec::new();
            while i < lines.len() {
                let l = lines[i].trim();
                let item = if ordered { numbered(l) } else { bullet(l) };
                match item {
                    Some(rest) => items.push(parse_inlines(rest)),
                    None => break,
                }
                i += 1;
            }
            blocks.push(Block::List { ordered, items });
            continue;
        }
        if t.starts_with('>') {
            let mut text = Vec::new();
            while i < lines.len() {
                match lines[i].trim().strip_prefix('>') {
                    Some(rest) => text.push(rest.trim()),
                    None => break,
                }
                i += 1;
            }
            blocks.push(Block::Quote {
                inlines: parse_inlines(&text.join(" ")),
            });
            continue;
        }
        let mut text = Vec::new();
        while i < lines.len() {
            let l = lines[i].trim();
            if l.is_empty()
                || l.starts_with("```")
                || heading(l).is_some()
                || bullet(l).is_some()
                || numbered(l).is_some()
                || l.starts_with('>')
                || is_rule(l)
            {
                break;
            }
            text.push(l);
            i += 1;
        }
        blocks.push(Block::Paragraph {
            inlines: parse_inlines(&text.join(" ")),
        });
    }
    blocks
}

/// The plain text of some inlines, for lint and summaries.
pub fn inline_text(inlines: &[Inline]) -> String {
    let mut s = String::new();
    for i in inlines {
        match i {
            Inline::Text { text }
            | Inline::Strong { text }
            | Inline::Emphasis { text }
            | Inline::Code { text }
            | Inline::Link { text, .. } => s.push_str(text),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(t: &str) -> Inline {
        Inline::Text { text: t.into() }
    }

    #[test]
    fn parses_the_supported_subset() {
        let md = "# Summary\n\nWe assess as an attempt against `CVE-2099-0001`.\nSecond line **bold** and *em*.\n\n- one\n- two [NVD](https://nvd.example.invalid/x)\n\n1. first\n2. second\n\n> quoted\n> more\n\n---\n\n```text\nGET /x HTTP/1.1\n```\n";
        let b = parse(md);
        assert_eq!(
            b[0],
            Block::Heading {
                level: 2,
                inlines: vec![text("Summary")]
            }
        );
        assert_eq!(
            b[1],
            Block::Paragraph {
                inlines: vec![
                    text("We assess as an attempt against "),
                    Inline::Code {
                        text: "CVE-2099-0001".into()
                    },
                    text(". Second line "),
                    Inline::Strong {
                        text: "bold".into()
                    },
                    text(" and "),
                    Inline::Emphasis { text: "em".into() },
                    text("."),
                ]
            }
        );
        assert!(matches!(&b[2], Block::List { ordered: false, items } if items.len() == 2));
        assert!(matches!(&b[3], Block::List { ordered: true, items } if items.len() == 2));
        assert_eq!(
            b[4],
            Block::Quote {
                inlines: vec![text("quoted more")]
            }
        );
        assert_eq!(b[5], Block::Rule);
        assert_eq!(
            b[6],
            Block::Code {
                text: "GET /x HTTP/1.1".into()
            }
        );
    }

    #[test]
    fn raw_html_is_only_ever_text() {
        let b = parse("<script>alert(1)</script> <img src=x onerror=alert(1)>");
        assert_eq!(
            b,
            vec![Block::Paragraph {
                inlines: vec![text(
                    "<script>alert(1)</script> <img src=x onerror=alert(1)>"
                )]
            }]
        );
    }

    #[test]
    fn unsafe_links_keep_their_text_only() {
        for url in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<b>x</b>",
            "http://example.invalid/",
            "//evil.example.invalid/x",
            "https://user@evil.example.invalid/",
            "https://",
            "https://example.invalid/\u{202E}gpj",
            "vbscript:x",
        ] {
            let b = parse(&format!("[click]({url})"));
            assert_eq!(
                b,
                vec![Block::Paragraph {
                    inlines: vec![text("click")]
                }],
                "{url}"
            );
        }
        assert_eq!(
            parse_inlines("[ok](/exploited/demo)"),
            vec![Inline::Link {
                text: "ok".into(),
                href: "/exploited/demo".into()
            }]
        );
    }

    #[test]
    fn bidi_and_control_characters_are_made_visible() {
        let b = parse_inlines("a\u{202E}b\u{0007}c");
        assert_eq!(b, vec![text("a\\u{202e}b\\u{7}c")]);
        let code = parse("```\nx\u{200B}y\n```");
        assert_eq!(
            code,
            vec![Block::Code {
                text: "x\\u{200b}y".into()
            }]
        );
    }

    #[test]
    fn unclosed_markers_are_text_and_long_input_is_bounded() {
        assert_eq!(parse_inlines("a ** b ` c [d"), vec![text("a ** b ` c [d")]);
        let huge = "*a ".repeat(50_000);
        let b = parse(&huge);
        assert_eq!(b.len(), 1);
        let many = "x\n\n".repeat(MAX_BLOCKS + 10);
        assert_eq!(parse(&many).len(), MAX_BLOCKS);
        // A multi-byte character straddling the byte cap does not panic.
        let edge = format!("{}é", "a".repeat(MAX_BODY_BYTES - 1));
        assert!(!parse(&edge).is_empty());
    }
}
