//! The materialised STIX object log behind TAXII (#13).
//!
//! TAXII serves stored object versions, never a rebuild. A materialiser
//! computes objects with [`super::stix::objects`] and hands them to [`plan`]
//! with what the store already holds for those ids. `plan` keeps STIX's
//! versioning rules (STIX 2.1 section 3.6):
//!
//! - A new version is written only when the content differs from the
//!   current head. Content is compared without `created` and `modified`, so
//!   a rebuild that only moves timestamps writes nothing, and content an
//!   object had before (an analyst undoing a decision) is written again as
//!   the newest version, so "latest" is always the current state.
//! - `created` is the first version's, for ever.
//! - Each new `modified` is later than every stored one, so an id and
//!   `modified` pair always names one content.
//! - Marking definitions never change once stored.
//! - Observables have no `modified`; their version is the run time.
//! - An object that is withdrawn (below the gate, or suppressed by an
//!   analyst) gets a last version with `revoked: true` ([`revocation`]).
//!   A revoked object is never un-revoked: if it comes back, it is issued
//!   under a new id ([`reissue_id`], [`rewrite_ids`]).
//!
//! The store assigns `date_added` when it appends, after every version
//! already stored, so TAXII paging on (`date_added`, id, version) never
//! skips or repeats a row. See `docs/intel-outputs.md#taxii-21`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::stix::{StixObject, valid_timestamp};
use super::{canonical, timestamp};

/// The one collection Foiled serves: the published view of a tenant.
pub const PUBLISHED: &str = "published";

/// One stored object version, as TAXII serves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StixVersion {
    pub id: String,
    pub object_type: String,
    /// The TAXII version: `modified`, else `created` (markings), else the
    /// time the observable version was written.
    pub version: String,
    /// When the store added this version (Unix ms).
    pub date_added: i64,
    /// Compact canonical JSON of the object.
    pub content: String,
}

/// What the store holds for one id, for planning: its head.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    /// The first version's `created`, if the object type has one.
    pub created: Option<String>,
    /// The newest version.
    pub latest: String,
    /// The content hash of the newest version.
    pub latest_hash: String,
    /// True when the newest version has `revoked: true`.
    pub revoked: bool,
}

/// A version to append. The store adds `date_added`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVersion {
    pub id: String,
    pub object_type: String,
    pub version: String,
    /// `created` for the head row, when the type has one.
    pub created: Option<String>,
    pub content: String,
    pub content_sha256: String,
    /// Every id the version refers to. Retention keeps an object while
    /// anything that stays refers to it.
    pub refs: Vec<String>,
}

/// The newest evidence behind an object (Unix ms), for retention: the
/// object's `added` time from [`super::stix::objects`], which is never
/// earlier than that of anything referring to it, so purging by it never
/// removes a target while a referrer stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub id: String,
    pub evidence_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub new: Vec<NewVersion>,
    /// Every object seen in this run, new or not.
    pub evidence: Vec<Evidence>,
    pub unchanged: usize,
}

/// SHA-256 (hex) of the object's canonical JSON without `created` and
/// `modified`.
pub fn content_hash(v: &Value) -> String {
    let mut v = v.clone();
    if let Value::Object(m) = &mut v {
        m.remove("created");
        m.remove("modified");
    }
    hex::encode(Sha256::digest(canonical(&v).as_bytes()))
}

/// Unix ms for a STIX timestamp `YYYY-MM-DDTHH:MM:SS[.fff…]Z`.
pub fn parse_timestamp(s: &str) -> Option<i64> {
    if !valid_timestamp(s) {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, sec) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let frac = s.get(20..s.len() - 1).unwrap_or("");
    let ms = format!("{frac:0<3}").get(0..3)?.parse::<i64>().ok()?;
    // Days from civil (Howard Hinnant).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000) + ms)
}

/// A timestamp in the `.fffZ` form versions are stored in, so
/// `01:02:03Z` names the version `01:02:03.000Z`. Sub-millisecond digits
/// other than zeros can match no stored version and are kept as given.
fn millisecond_form(t: &str) -> String {
    let frac = t.get(20..t.len() - 1).unwrap_or("");
    match parse_timestamp(t) {
        Some(ms) if frac.bytes().skip(3).all(|b| b == b'0') => timestamp(ms),
        _ => t.to_string(),
    }
}

/// A version strictly after `latest`, and no earlier than `wanted`.
fn after(latest: Option<&str>, wanted: i64) -> i64 {
    match latest.and_then(parse_timestamp) {
        Some(l) => wanted.max(l + 1),
        None => wanted,
    }
}

/// Decide what to append. `history` holds what the store knows for the
/// objects' ids; `run_ms` is the materialiser's clock.
pub fn plan(objects: &[StixObject], history: &BTreeMap<String, History>, run_ms: i64) -> Plan {
    let mut out = Plan::default();
    for o in objects {
        out.evidence.push(Evidence {
            id: o.id().to_string(),
            evidence_ms: o.added,
        });
        let mut v = o.value();
        let hash = content_hash(&v);
        let hist = history.get(o.id());
        // Same as the head, or revoked for good (the caller reissues
        // objects that come back under a new id before planning).
        if hist.is_some_and(|h| h.latest_hash == hash || h.revoked) {
            out.unchanged += 1;
            continue;
        }
        let ty = o.object_type().to_string();
        let has_modified = v.get("modified").is_some();
        let (version, created) = if ty == "marking-definition" {
            // Markings are immutable: the first one stored stands.
            if hist.is_some() {
                out.unchanged += 1;
                continue;
            }
            let c = v["created"].as_str().unwrap_or_default().to_string();
            (c.clone(), Some(c))
        } else if has_modified {
            let created = hist
                .and_then(|h| h.created.clone())
                .or_else(|| v["created"].as_str().map(str::to_string))
                .unwrap_or_else(|| timestamp(run_ms));
            let wanted = v["modified"]
                .as_str()
                .and_then(parse_timestamp)
                .unwrap_or(run_ms);
            let created_ms = parse_timestamp(&created).unwrap_or(wanted);
            let m = after(hist.map(|h| h.latest.as_str()), wanted.max(created_ms));
            let modified = timestamp(m);
            v["created"] = Value::String(created.clone());
            v["modified"] = Value::String(modified.clone());
            (modified, Some(created))
        } else {
            // Observables carry no timestamps; the version is when it was
            // written.
            (
                timestamp(after(hist.map(|h| h.latest.as_str()), run_ms)),
                None,
            )
        };
        let mut content = canonical(&v);
        content.shrink_to_fit();
        out.new.push(NewVersion {
            id: o.id().to_string(),
            object_type: ty,
            version,
            created,
            content,
            content_sha256: hash,
            refs: o.refs.clone(),
        });
    }
    out
}

/// Object types that can be revoked: everything with `created` and
/// `modified` (observables have no versions; markings never change).
pub fn revocable(object_type: &str) -> bool {
    !matches!(
        object_type,
        "marking-definition"
            | "ipv4-addr"
            | "ipv6-addr"
            | "domain-name"
            | "url"
            | "file"
            | "autonomous-system"
    )
}

/// The last version of a withdrawn object: its head with `revoked: true`
/// and a newer `modified` (STIX 2.1 section 3.6). `None` when the object
/// cannot be revoked or already is.
pub fn revocation(head: &StixVersion, hist: &History, run_ms: i64) -> Option<NewVersion> {
    if hist.revoked || !revocable(&head.object_type) {
        return None;
    }
    let mut v: Value = serde_json::from_str(&head.content).ok()?;
    let m = after(Some(&hist.latest), run_ms);
    let modified = timestamp(m);
    v["modified"] = Value::String(modified.clone());
    v["revoked"] = Value::Bool(true);
    let hash = content_hash(&v);
    let mut content = canonical(&v);
    content.shrink_to_fit();
    Some(NewVersion {
        id: head.id.clone(),
        object_type: head.object_type.clone(),
        version: modified,
        created: hist.created.clone(),
        content,
        content_sha256: hash,
        refs: vec![],
    })
}

/// The id an object is issued under after its `generation`-th revocation:
/// the same type, a UUIDv5 over the original id and the generation.
pub fn reissue_id(id: &str, generation: u32) -> String {
    let ty = id.split_once("--").map_or("x-foiled", |(t, _)| t);
    format!(
        "{ty}--{}",
        super::uuid5::uuid_v5(
            super::FOILED_NAMESPACE,
            &format!("reissue|{id}|{generation}")
        )
    )
}

/// Replace ids (the objects' own and every reference to them) by `map`.
pub fn rewrite_ids(objects: Vec<StixObject>, map: &BTreeMap<String, String>) -> Vec<StixObject> {
    if map.is_empty() {
        return objects;
    }
    fn walk(v: &mut Value, map: &BTreeMap<String, String>) {
        match v {
            Value::String(s) => {
                if let Some(n) = map.get(s.as_str()) {
                    *s = n.clone();
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| walk(x, map)),
            Value::Object(m) => m.values_mut().for_each(|x| walk(x, map)),
            _ => {}
        }
    }
    objects
        .into_iter()
        .map(|o| {
            if !o.refs.iter().any(|r| map.contains_key(r)) && !map.contains_key(o.id()) {
                return o;
            }
            let mut v = o.value();
            walk(&mut v, map);
            StixObject::new(&v, o.added)
        })
        .collect()
}

/// Which versions of each object a TAXII request asks for
/// (`match[version]`, TAXII 2.1 section 3.4.2): any of the first, the last,
/// every version, or exact versions. A row matches when it matches any of
/// the values given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionFilter {
    pub first: bool,
    pub last: bool,
    pub all: bool,
    /// Exact versions (STIX timestamps).
    pub exact: Vec<String>,
}

impl Default for VersionFilter {
    /// The newest version of each object (the TAXII default).
    fn default() -> Self {
        VersionFilter::last()
    }
}

impl VersionFilter {
    const NONE: VersionFilter = VersionFilter {
        first: false,
        last: false,
        all: false,
        exact: Vec::new(),
    };

    pub fn last() -> Self {
        VersionFilter {
            last: true,
            ..VersionFilter::NONE
        }
    }

    pub fn first() -> Self {
        VersionFilter {
            first: true,
            ..VersionFilter::NONE
        }
    }

    pub fn all() -> Self {
        VersionFilter {
            all: true,
            ..VersionFilter::NONE
        }
    }

    /// Parse `match[version]`: a comma-separated list of `first`, `last`,
    /// `all` and STIX timestamps, meaning any of them. `None` when a value
    /// is none of those or the list is empty.
    pub fn parse(s: &str) -> Option<VersionFilter> {
        let mut f = VersionFilter::NONE;
        let mut any = false;
        for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            any = true;
            match p {
                "first" => f.first = true,
                "last" => f.last = true,
                "all" => f.all = true,
                t if valid_timestamp(t) => {
                    let t = millisecond_form(t);
                    if !f.exact.contains(&t) {
                        f.exact.push(t);
                    }
                }
                _ => return None,
            }
        }
        any.then_some(f)
    }

    /// Whether `version` matches, given the object's first and last
    /// versions.
    pub fn matches(&self, version: &str, first: Option<&str>, last: Option<&str>) -> bool {
        self.all
            || (self.first && first == Some(version))
            || (self.last && last == Some(version))
            || self.exact.iter().any(|e| e == version)
    }
}

/// A position in the log: after this `(date_added, id, version)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogCursor {
    pub date_added: i64,
    pub id: String,
    pub version: String,
}

impl LogCursor {
    pub fn of(v: &StixVersion) -> LogCursor {
        LogCursor {
            date_added: v.date_added,
            id: v.id.clone(),
            version: v.version.clone(),
        }
    }

    /// Opaque `next` value: hex of `date_added|id|version`.
    pub fn encode(&self) -> String {
        hex::encode(format!("{}|{}|{}", self.date_added, self.id, self.version))
    }

    pub fn decode(s: &str) -> Option<LogCursor> {
        if s.len() > 1024 {
            return None;
        }
        let raw = String::from_utf8(hex::decode(s).ok()?).ok()?;
        let mut parts = raw.splitn(3, '|');
        let c = LogCursor {
            date_added: parts.next()?.parse().ok()?,
            id: parts.next()?.to_string(),
            version: parts.next()?.to_string(),
        };
        let id_ok =
            c.id.split_once("--")
                .is_some_and(|(t, u)| !t.is_empty() && super::uuid5::is_uuid(u));
        (id_ok && valid_timestamp(&c.version)).then_some(c)
    }
}

/// A TAXII query over the log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogQuery {
    /// Strictly after this `date_added` (`added_after`).
    pub added_after: Option<i64>,
    /// Strictly after this row (`next`).
    pub after: Option<LogCursor>,
    pub ids: Option<Vec<String>>,
    pub types: Option<Vec<String>>,
    pub versions: VersionFilter,
    /// Rows to return. Stores return at most this many.
    pub limit: usize,
}

/// Apply a query to rows already in memory: the reference semantics the
/// Postgres query matches, used by the in-memory store and the tests.
/// `rows` must hold every version of every object (in any order).
pub fn query_rows(rows: &[StixVersion], q: &LogQuery) -> Vec<StixVersion> {
    let mut first: BTreeMap<&str, &str> = BTreeMap::new();
    let mut last: BTreeMap<&str, &str> = BTreeMap::new();
    for r in rows {
        let f = first.entry(&r.id).or_insert(&r.version);
        if r.version.as_str() < *f {
            *f = &r.version;
        }
        let l = last.entry(&r.id).or_insert(&r.version);
        if r.version.as_str() > *l {
            *l = &r.version;
        }
    }
    let mut out: Vec<StixVersion> = rows
        .iter()
        .filter(|r| q.added_after.is_none_or(|t| r.date_added > t))
        .filter(|r| q.after.as_ref().is_none_or(|c| LogCursor::of(r) > *c))
        .filter(|r| q.ids.as_ref().is_none_or(|i| i.contains(&r.id)))
        .filter(|r| q.types.as_ref().is_none_or(|t| t.contains(&r.object_type)))
        .filter(|r| {
            q.versions.matches(
                &r.version,
                first.get(r.id.as_str()).copied(),
                last.get(r.id.as_str()).copied(),
            )
        })
        .cloned()
        .collect();
    out.sort_by(|a, b| LogCursor::of(a).cmp(&LogCursor::of(b)));
    out.truncate(q.limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value, added: i64) -> StixObject {
        StixObject::new(&v, added)
    }

    fn indicator(desc: &str, created: &str, modified: &str) -> StixObject {
        obj(
            json!({"type": "indicator", "spec_version": "2.1",
                "id": "indicator--2ed6657d-e927-568b-95e1-2665a8aea6a2",
                "created": created, "modified": modified, "description": desc,
                "pattern": "[ipv4-addr:value = '203.0.113.7']", "pattern_type": "stix",
                "valid_from": "2026-10-18T01:02:03.000Z"}),
            1,
        )
    }

    fn history_of(rows: &[NewVersion]) -> BTreeMap<String, History> {
        let mut h: BTreeMap<String, History> = BTreeMap::new();
        for r in rows {
            let e = h.entry(r.id.clone()).or_default();
            if e.created.is_none() {
                e.created = r.created.clone();
            }
            if r.version > e.latest {
                e.latest = r.version.clone();
                e.latest_hash = r.content_sha256.clone();
                e.revoked = r.content.contains("\"revoked\":true");
            }
        }
        h
    }

    const T: i64 = 1_792_285_323_000;

    #[test]
    fn timestamps_round_trip() {
        for ms in [0, T + 4, 1_767_225_600_000] {
            assert_eq!(parse_timestamp(&timestamp(ms)), Some(ms));
        }
        assert_eq!(parse_timestamp("2026-10-18T01:02:03.1Z"), Some(T + 100));
        assert_eq!(parse_timestamp("2026-13-18T01:02:03Z"), None);
    }

    #[test]
    fn rebuilds_that_only_move_timestamps_write_nothing() {
        let a = indicator("x", "2026-10-18T01:02:03.000Z", "2026-10-18T01:02:04.000Z");
        let p1 = plan(&[a], &BTreeMap::new(), T);
        assert_eq!(p1.new.len(), 1);
        let h = history_of(&p1.new);
        // Same content, the window moved: created and modified differ.
        let b = indicator("x", "2026-10-18T05:00:00.000Z", "2026-10-18T06:00:00.000Z");
        let p2 = plan(&[b], &h, T + 1000);
        assert!(p2.new.is_empty());
        assert_eq!(p2.unchanged, 1);
    }

    #[test]
    fn new_content_keeps_created_and_moves_modified_forward() {
        let a = indicator("x", "2026-10-18T01:02:03.000Z", "2026-10-18T01:02:09.000Z");
        let p1 = plan(&[a], &BTreeMap::new(), T);
        let h = history_of(&p1.new);
        // New content whose computed modified is earlier than the stored one.
        let b = indicator("y", "2026-10-18T03:00:00.000Z", "2026-10-18T01:02:05.000Z");
        let p2 = plan(&[b], &h, T + 1000);
        assert_eq!(p2.new.len(), 1);
        let v: Value = serde_json::from_str(&p2.new[0].content).unwrap();
        assert_eq!(
            v["created"], "2026-10-18T01:02:03.000Z",
            "created never changes"
        );
        assert_eq!(v["modified"], "2026-10-18T01:02:09.001Z");
        assert_eq!(p2.new[0].version, "2026-10-18T01:02:09.001Z");
        assert!(p2.new[0].version > p1.new[0].version);
        // Back to the first content: written again as the newest version,
        // so "latest" is the current state; same as the head writes nothing.
        let mut all = p1.new.clone();
        all.extend(p2.new.clone());
        let h2 = history_of(&all);
        let c = indicator("x", "2026-10-18T01:02:03.000Z", "2026-10-18T01:02:04.000Z");
        let p3 = plan(std::slice::from_ref(&c), &h2, T + 2000);
        assert_eq!(p3.new.len(), 1);
        assert!(p3.new[0].version > p2.new[0].version);
        all.extend(p3.new.clone());
        assert!(plan(&[c], &history_of(&all), T + 3000).new.is_empty());
    }

    #[test]
    fn markings_never_change_and_observables_version_by_run() {
        let m = obj(super::super::stix::tlp_marking(crate::share::Tlp::Amber), 1);
        let p1 = plan(std::slice::from_ref(&m), &BTreeMap::new(), T);
        assert_eq!(p1.new[0].version, "2022-10-01T00:00:00.000Z");
        let h = history_of(&p1.new);
        let mut changed = m.value();
        changed["name"] = json!("TLP:AMBER (edited)");
        assert!(plan(&[obj(changed, 1)], &h, T).new.is_empty());

        let ip = |asn: &str| {
            obj(
                json!({"type": "ipv4-addr", "spec_version": "2.1",
                    "id": "ipv4-addr--2ed6657d-e927-568b-95e1-2665a8aea6a2",
                    "value": "203.0.113.7", "belongs_to_refs": [asn]}),
                1,
            )
        };
        let p = plan(
            &[ip(
                "autonomous-system--2ed6657d-e927-568b-95e1-2665a8aea6a2",
            )],
            &BTreeMap::new(),
            T,
        );
        assert_eq!(p.new[0].version, timestamp(T));
        assert_eq!(p.new[0].created, None);
        let h = history_of(&p.new);
        let q = plan(
            &[ip(
                "autonomous-system--3ed6657d-e927-568b-95e1-2665a8aea6a2",
            )],
            &h,
            T,
        );
        assert_eq!(q.new[0].version, timestamp(T + 1), "strictly after");
    }

    #[test]
    fn version_filters_and_cursors() {
        assert_eq!(VersionFilter::parse("last"), Some(VersionFilter::last()));
        assert_eq!(VersionFilter::parse(" all "), Some(VersionFilter::all()));
        // A list means any of its values: first or last, not every version.
        let fl = VersionFilter::parse("first,last").unwrap();
        assert!(fl.first && fl.last && !fl.all && fl.exact.is_empty());
        assert_eq!(
            VersionFilter::parse("2026-10-18T01:02:03.000Z,first"),
            Some(VersionFilter {
                first: true,
                exact: vec!["2026-10-18T01:02:03.000Z".into()],
                ..VersionFilter::NONE
            })
        );
        // Any precision names the stored millisecond form.
        for t in [
            "2026-10-18T01:02:03Z",
            "2026-10-18T01:02:03.0Z",
            "2026-10-18T01:02:03.000000Z",
        ] {
            assert_eq!(
                VersionFilter::parse(t).unwrap().exact,
                vec!["2026-10-18T01:02:03.000Z".to_string()],
                "{t}"
            );
        }
        for bad in ["yesterday", "", ",", "last,soon"] {
            assert_eq!(VersionFilter::parse(bad), None, "{bad}");
        }
        let c = LogCursor {
            date_added: 5,
            id: "indicator--2ed6657d-e927-568b-95e1-2665a8aea6a2".into(),
            version: "2026-10-18T01:02:03.000Z".into(),
        };
        assert_eq!(LogCursor::decode(&c.encode()), Some(c));
        assert_eq!(LogCursor::decode("zz"), None);
        assert_eq!(LogCursor::decode(&hex::encode("5|<script>|x")), None);
    }

    #[test]
    fn query_rows_pages_and_filters_versions() {
        let row = |id: &str, v: &str, d: i64| StixVersion {
            id: format!("indicator--{id}"),
            object_type: "indicator".into(),
            version: v.into(),
            date_added: d,
            content: String::new(),
        };
        let a = "2ed6657d-e927-568b-95e1-2665a8aea6a2";
        let b = "3ed6657d-e927-568b-95e1-2665a8aea6a2";
        let rows = vec![
            row(a, "2026-10-18T01:00:00.000Z", 10),
            row(b, "2026-10-18T01:00:00.000Z", 10),
            row(a, "2026-10-18T02:00:00.000Z", 20),
        ];
        let q = |versions, limit, after: Option<LogCursor>| LogQuery {
            versions,
            limit,
            after,
            ..Default::default()
        };
        let last = query_rows(&rows, &q(VersionFilter::last(), 10, None));
        assert_eq!(last.len(), 2);
        assert_eq!(last[1].date_added, 20);
        assert_eq!(
            query_rows(&rows, &q(VersionFilter::all(), 10, None)).len(),
            3
        );
        assert_eq!(
            query_rows(&rows, &q(VersionFilter::first(), 10, None)).len(),
            2
        );
        // Three versions of one object: first,last is two of them.
        let mut three = rows.clone();
        three.push(row(a, "2026-10-18T03:00:00.000Z", 30));
        let fl = VersionFilter::parse("first,last").unwrap();
        let got: Vec<String> = query_rows(&three, &q(fl, 10, None))
            .into_iter()
            .filter(|r| r.id.ends_with(a))
            .map(|r| r.version)
            .collect();
        assert_eq!(
            got,
            ["2026-10-18T01:00:00.000Z", "2026-10-18T03:00:00.000Z"]
        );
        let mixed = VersionFilter::parse("last,2026-10-18T02:00:00.000Z").unwrap();
        assert_eq!(query_rows(&three, &q(mixed, 10, None)).len(), 3);
        let p1 = query_rows(&rows, &q(VersionFilter::all(), 2, None));
        let p2 = query_rows(
            &rows,
            &q(VersionFilter::all(), 2, Some(LogCursor::of(&p1[1]))),
        );
        assert_eq!(p1.len() + p2.len(), 3);
        let added = LogQuery {
            added_after: Some(10),
            versions: VersionFilter::all(),
            limit: 10,
            ..Default::default()
        };
        assert_eq!(query_rows(&rows, &added).len(), 1);
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn revocation_bumps_modified_and_is_final() {
        let head = StixVersion {
            id: "relationship--2ed6657d-e927-568b-95e1-2665a8aea6a2".into(),
            object_type: "relationship".into(),
            version: "2026-10-18T01:02:04.000Z".into(),
            date_added: 1,
            content: json!({"type": "relationship", "id": "relationship--2ed6657d-e927-568b-95e1-2665a8aea6a2",
                "created": "2026-10-18T01:02:03.000Z", "modified": "2026-10-18T01:02:04.000Z"}).to_string(),
        };
        let hist = History {
            created: Some("2026-10-18T01:02:03.000Z".into()),
            latest: head.version.clone(),
            latest_hash: "h".into(),
            revoked: false,
        };
        let r = revocation(&head, &hist, 0).unwrap();
        let v: Value = serde_json::from_str(&r.content).unwrap();
        assert_eq!(v["revoked"], true);
        assert_eq!(v["modified"], "2026-10-18T01:02:04.001Z");
        assert_eq!(v["created"], "2026-10-18T01:02:03.000Z");
        let done = History {
            revoked: true,
            ..hist
        };
        assert!(revocation(&head, &done, 0).is_none());
        // Observables and markings are never revoked.
        let sco = StixVersion {
            object_type: "ipv4-addr".into(),
            ..head
        };
        assert!(revocation(&sco, &History::default(), 0).is_none());
    }

    #[test]
    fn reissued_ids_are_stable_and_references_follow() {
        let a = "indicator--2ed6657d-e927-568b-95e1-2665a8aea6a2";
        let r1 = reissue_id(a, 1);
        assert!(r1.starts_with("indicator--"));
        assert_eq!(r1, reissue_id(a, 1));
        assert_ne!(r1, reissue_id(a, 2));
        let ind = StixObject::new(&json!({"type": "indicator", "id": a}), 1);
        let sight = StixObject::new(
            &json!({"type": "sighting", "id": "sighting--3ed6657d-e927-568b-95e1-2665a8aea6a2", "sighting_of_ref": a}),
            1,
        );
        let map = BTreeMap::from([(a.to_string(), r1.clone())]);
        let out = rewrite_ids(vec![ind, sight], &map);
        assert_eq!(out[0].id(), r1);
        assert_eq!(out[1].refs, vec![r1]);
    }
}
