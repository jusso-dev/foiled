//! STIX 2.1 bundles from a [`Selection`] (#13).
//!
//! Mapping (`docs/intel-outputs.md#stix-21`):
//!
//! - Each IOC: an `indicator` (pattern, `confidence` from #27, wording in
//!   `description`), a `sighting` of it, and a cyber observable where STIX
//!   has one (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file`). A
//!   file hash also gets a `malware` instance (`is_family: false`) with the
//!   `file` as its sample. Memory-only attempts have no file hash, so no
//!   `file`, no file pattern and no `malware`.
//! - Each attempt: an `observed-data` over its source address and its
//!   exported observables, and a `note` with the attempt notes.
//! - Each CVE link: a `vulnerability` and a `relationship` from the
//!   attempt's `observed-data`, with `confidence` and "we assess as".
//! - Each technique link: MITRE's `attack-pattern` (sidecar STIX id) and a
//!   `relationship`, under a marking that carries MITRE's notice.
//! - Campaign links (#33): a `campaign`; actor links (#29, opt-in): an
//!   `intrusion-set` with "possible association".
//! - One TLP 2.0 marking definition (the OASIS objects) on everything
//!   Foiled creates, and one `identity` for Foiled.
//!
//! Ids: Foiled objects are `type--uuid5(FOILED_NAMESPACE, "type|key")`;
//! observables use the STIX deterministic id rule. The bundle id is derived
//! from the objects, so the same selection always gives the same bundle.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::uuid5::{is_uuid, uuid_v5};
use super::{
    FOILED_NAMESPACE, REFERENCE_EPOCH_MS, STIX_SCO_NAMESPACE, Selection, band_name, canonical,
    confirmed, ioc_sentence, link_sentence, link_wording, timestamp,
};
use crate::confidence::{ConfidenceLink, LinkKind};
use crate::ioc::{Ioc, IocRole, IocType};
use crate::share::Tlp;
use crate::timeline::printable;

/// Media type for a bundle (STIX 2.1 section 1.6, TAXII 2.1).
pub const MEDIA_TYPE: &str = "application/stix+json;version=2.1";

/// The OASIS TLP 2.0 extension definition.
pub const TLP_EXTENSION: &str = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d";

/// Largest `count` and `number_observed` STIX allows.
const MAX_COUNT: u64 = 999_999_999;

/// The OASIS TLP 2.0 marking definition id for a label.
pub fn tlp_marking_id(t: Tlp) -> &'static str {
    match t {
        Tlp::Clear => "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        Tlp::Green => "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        Tlp::Amber => "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        Tlp::AmberStrict => "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        Tlp::Red => "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    }
}

/// The OASIS TLP 2.0 marking definition object, verbatim.
pub fn tlp_marking(t: Tlp) -> Value {
    json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": tlp_marking_id(t),
        "created": "2022-10-01T00:00:00.000Z",
        "name": format!("TLP:{}", t.as_str().to_ascii_uppercase()),
        "extensions": {
            TLP_EXTENSION: {
                "extension_type": "property-extension",
                "tlp_2_0": t.as_str()
            }
        }
    })
}

/// One object, held as its compact canonical JSON (a parsed tree costs
/// about four times as much memory), with what paging needs: its id, type,
/// version, references and the time it counts as added (Unix ms) for TAXII
/// `date_added` and `added_after`.
#[derive(Debug, Clone, PartialEq)]
pub struct StixObject {
    id: String,
    ty: String,
    version: Option<String>,
    /// Compact JSON with sorted keys.
    pub json: String,
    /// Every id this object refers to.
    pub refs: Vec<String>,
    pub added: i64,
}

impl StixObject {
    pub fn new(value: &Value, added: i64) -> Self {
        let text = |k: &str| value[k].as_str().map(str::to_string);
        StixObject {
            id: text("id").unwrap_or_default(),
            ty: text("type").unwrap_or_default(),
            version: text("modified").or_else(|| text("created")),
            json: {
                let mut j = canonical(value);
                j.shrink_to_fit();
                j
            },
            refs: refs_of(value),
            added,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn object_type(&self) -> &str {
        &self.ty
    }

    /// `modified`, then `created`, then the added time, as TAXII versions
    /// objects.
    pub fn version(&self) -> String {
        self.version
            .clone()
            .unwrap_or_else(|| timestamp(self.added))
    }

    /// The object as a JSON value.
    pub fn value(&self) -> Value {
        serde_json::from_str(&self.json).unwrap_or(Value::Null)
    }
}

/// A Foiled-minted id.
pub fn foiled_id(ty: &str, key: &str) -> String {
    format!(
        "{ty}--{}",
        uuid_v5(FOILED_NAMESPACE, &format!("{ty}|{key}"))
    )
}

/// The STIX deterministic id for an observable: UUIDv5 in the STIX
/// namespace over the canonical JSON of its id contributing properties.
pub fn sco_id(ty: &str, contributing: &Value) -> String {
    format!(
        "{ty}--{}",
        uuid_v5(STIX_SCO_NAMESPACE, &canonical(contributing))
    )
}

pub fn identity_id() -> String {
    foiled_id("identity", "foiled")
}

/// A STIX pattern string literal: backslash and quote escaped.
pub fn pattern_literal(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The observable for an IOC, where STIX has one.
pub fn observable(i: &Ioc) -> Option<Value> {
    observable_for(i.ioc_type, &i.value)
}

/// The observable for a typed value, where STIX has one.
pub fn observable_for(ty: IocType, value: &str) -> Option<Value> {
    let (ty, props) = match ty {
        IocType::Ip => ("ipv4-addr", json!({"value": value})),
        IocType::Ipv6 => ("ipv6-addr", json!({"value": value})),
        IocType::Domain => ("domain-name", json!({"value": value})),
        IocType::Url => ("url", json!({"value": value})),
        IocType::FileSha256 => ("file", json!({"hashes": {"SHA-256": value}})),
        _ => return None,
    };
    let mut obj = Map::new();
    obj.insert("type".into(), json!(ty));
    obj.insert("spec_version".into(), json!("2.1"));
    obj.insert("id".into(), json!(sco_id(ty, &props)));
    if let Value::Object(p) = props {
        obj.extend(p);
    }
    Some(Value::Object(obj))
}

/// An `autonomous-system` observable for an address IOC with a shareable
/// `asn.number` ref, named from `asn.org` by the same provider.
pub fn autonomous_system(i: &Ioc) -> Option<Value> {
    if !matches!(i.ioc_type, IocType::Ip | IocType::Ipv6) {
        return None;
    }
    let num = i.enrichment.iter().find(|e| e.key == "asn.number")?;
    let number = num.value.as_u64().or_else(|| {
        num.value
            .as_str()
            .and_then(|s| s.trim_start_matches("AS").parse().ok())
    })?;
    let mut o = json!({
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": sco_id("autonomous-system", &json!({"number": number})),
        "number": number,
    });
    if let Some(name) = i
        .enrichment
        .iter()
        .find(|e| e.key == "asn.org" && e.provider == num.provider)
        .and_then(|e| e.value.as_str())
    {
        o["name"] = json!(printable(name));
    }
    Some(o)
}

/// `(pattern, pattern_type)` for an IOC, or `None` when the type is left
/// to another indicator (`dns_query` is covered by its `domain`).
pub fn pattern(i: &Ioc) -> Option<(String, &'static str)> {
    let v = pattern_literal(&i.value);
    Some(match i.ioc_type {
        IocType::Ip => (format!("[ipv4-addr:value = {v}]"), "stix"),
        IocType::Ipv6 => (format!("[ipv6-addr:value = {v}]"), "stix"),
        IocType::Domain => (format!("[domain-name:value = {v}]"), "stix"),
        IocType::Url => (format!("[url:value = {v}]"), "stix"),
        IocType::HttpPath => (
            format!("[network-traffic:extensions.'http-request-ext'.request_value = {v}]"),
            "stix",
        ),
        IocType::HttpUa => (
            format!(
                "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = {v}]"
            ),
            "stix",
        ),
        IocType::PayloadSha256 => (format!("[artifact:hashes.'SHA-256' = {v}]"), "stix"),
        IocType::FileSha256 => (format!("[file:hashes.'SHA-256' = {v}]"), "stix"),
        IocType::Cmdline => (format!("[process:command_line = {v}]"), "stix"),
        // No STIX pattern expresses "this exact substring was sent".
        IocType::RequestSubstring => (i.value.clone(), "foiled-request-substring"),
        IocType::BehaviourFingerprint => (i.value.clone(), "foiled-bf"),
        IocType::DnsQuery => return None,
    })
}

fn role_name(r: IocRole) -> String {
    serde_json::to_value(r)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn common(ty: &str, id: &str, created: i64, modified: i64, tlp: Tlp) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!(ty));
    m.insert("spec_version".into(), json!("2.1"));
    m.insert("id".into(), json!(id));
    m.insert("created_by_ref".into(), json!(identity_id()));
    m.insert("created".into(), json!(timestamp(created)));
    m.insert("modified".into(), json!(timestamp(modified.max(created))));
    m.insert("object_marking_refs".into(), json!([tlp_marking_id(tlp)]));
    m
}

fn evidence_summary(link: &ConfidenceLink) -> Value {
    Value::Array(
        link.contributions
            .iter()
            .map(|c| {
                json!({
                    "source": serde_json::to_value(c.source).unwrap_or(Value::Null),
                    "points": c.points,
                })
            })
            .collect(),
    )
}

/// The object a link points at, and its id.
fn link_target(
    link: &ConfidenceLink,
    sel: &Selection,
    tlp: Tlp,
    notice_marking: Option<&str>,
) -> (String, Value) {
    let name = printable(&link.target);
    match link.kind {
        LinkKind::AttemptCve => {
            let key = link.target.to_ascii_uppercase();
            let id = foiled_id("vulnerability", &key);
            let source = if key.starts_with("CVE-") {
                "cve"
            } else {
                "foiled"
            };
            let mut m = common(
                "vulnerability",
                &id,
                REFERENCE_EPOCH_MS,
                REFERENCE_EPOCH_MS,
                tlp,
            );
            m.insert("name".into(), json!(printable(&key)));
            m.insert(
                "external_references".into(),
                json!([{"source_name": source, "external_id": printable(&key)}]),
            );
            (id, Value::Object(m))
        }
        LinkKind::AttemptTechnique => {
            // Foiled's own object with an external reference to MITRE, not
            // MITRE's id: only the creator may version an object (STIX 2.1
            // section 3.6), and re-emitting MITRE's id would overwrite their
            // object in a TIP. TIPs merge on `external_id`.
            let info = sel.techniques.get(&link.target);
            let id = foiled_id("attack-pattern", &link.target.to_ascii_uppercase());
            let mut m = common(
                "attack-pattern",
                &id,
                REFERENCE_EPOCH_MS,
                REFERENCE_EPOCH_MS,
                tlp,
            );
            let title = info.map_or(name.clone(), |t| t.name.clone());
            m.insert("name".into(), json!(title));
            let version = sel.attack_version.clone().unwrap_or_default();
            m.insert(
                "description".into(),
                json!(format!(
                    "Foiled's reference to MITRE ATT&CK {name} ({title}), ATT&CK v{version}. MITRE's own object is named in external_references and x_foiled_mitre_stix_id."
                )),
            );
            let mut ext = json!({"source_name": "mitre-attack", "external_id": name});
            if let Some(t) = info {
                ext["url"] = json!(t.url);
                m.insert(
                    "kill_chain_phases".into(),
                    Value::Array(
                        t.tactics
                            .iter()
                            .map(|p| json!({"kill_chain_name": "mitre-attack", "phase_name": p}))
                            .collect(),
                    ),
                );
                m.insert("x_foiled_mitre_stix_id".into(), json!(t.stix_id));
            }
            m.insert("external_references".into(), json!([ext]));
            let mut markings = vec![json!(tlp_marking_id(tlp))];
            if let Some(n) = notice_marking {
                markings.push(json!(n));
            }
            m.insert("object_marking_refs".into(), Value::Array(markings));
            if !version.is_empty() {
                m.insert("x_foiled_attack_version".into(), json!(version));
            }
            (id, Value::Object(m))
        }
        LinkKind::AttemptCampaign => {
            let id = foiled_id("campaign", &link.target);
            let mut m = common("campaign", &id, REFERENCE_EPOCH_MS, REFERENCE_EPOCH_MS, tlp);
            m.insert("name".into(), json!(name));
            m.insert(
                "description".into(),
                json!("A Foiled campaign: attempts clustered on shared indicators and behaviour (#33)."),
            );
            (id, Value::Object(m))
        }
        LinkKind::AttemptActor | LinkKind::AttemptIoc => {
            let id = foiled_id("intrusion-set", &link.target);
            let mut m = common(
                "intrusion-set",
                &id,
                REFERENCE_EPOCH_MS,
                REFERENCE_EPOCH_MS,
                tlp,
            );
            m.insert("name".into(), json!(name));
            m.insert(
                "description".into(),
                json!("A publicly named group. Foiled links to it carry their own wording and confidence; read the relationship, not this object, for the claim."),
            );
            (id, Value::Object(m))
        }
    }
}

/// Every object for a selection, in bundle order.
pub fn objects(sel: &Selection) -> Vec<StixObject> {
    let tlp = sel.tlp;
    let tlp_id = tlp_marking_id(tlp);
    let ident = identity_id();
    let mut out: BTreeMap<String, StixObject> = BTreeMap::new();
    // Each object is serialised as soon as it is built, so the whole set
    // never exists as parsed JSON.
    let mut put = |value: Value, added: i64| {
        let id = value["id"].as_str().unwrap_or_default().to_string();
        out.entry(id)
            .and_modify(|o| o.added = o.added.max(added))
            .or_insert_with(|| StixObject::new(&value, added));
    };

    put(
        json!({
            "type": "identity",
            "spec_version": "2.1",
            "id": ident,
            "created": timestamp(REFERENCE_EPOCH_MS),
            "modified": timestamp(REFERENCE_EPOCH_MS),
            "name": "Foiled",
            "identity_class": "system",
            "description": "Foiled deception platform. Observations come from decoys, which have no legitimate users.",
        }),
        REFERENCE_EPOCH_MS,
    );
    put(tlp_marking(tlp), REFERENCE_EPOCH_MS);
    let notice_id = sel.attack_notice.as_ref().map(|notice| {
        let version = sel.attack_version.clone().unwrap_or_default();
        let id = foiled_id(
            "marking-definition",
            &format!("mitre-attack-notice|{version}"),
        );
        put(
            json!({
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": id,
                "created_by_ref": ident,
                "created": timestamp(REFERENCE_EPOCH_MS),
                "name": format!("MITRE ATT&CK v{version} notice"),
                "definition_type": "statement",
                "definition": {"statement": notice},
            }),
            REFERENCE_EPOCH_MS,
        );
        id
    });

    // Observables and indicators.
    let mut sco_of: BTreeMap<&str, String> = BTreeMap::new();
    let mut indicator_of: BTreeMap<&str, String> = BTreeMap::new();
    for i in &sel.iocs {
        if let Some(mut o) = observable(i) {
            sco_of.insert(
                i.ioc_id.as_str(),
                o["id"].as_str().unwrap_or_default().into(),
            );
            o["object_marking_refs"] = json!([tlp_id]);
            // Shareable ASN context (already through `export_refs`).
            if let Some(mut asn) = autonomous_system(i) {
                o["belongs_to_refs"] = json!([asn["id"]]);
                asn["object_marking_refs"] = json!([tlp_id]);
                put(asn, i.last_seen);
            }
            put(o, i.last_seen);
        }
        let Some((pat, pattern_type)) = pattern(i) else {
            continue;
        };
        let id = foiled_id("indicator", &i.ioc_id);
        let mut m = common("indicator", &id, i.first_seen, i.last_seen, tlp);
        m.insert(
            "name".into(),
            json!(format!("{}: {}", i.ioc_type.as_str(), i.display)),
        );
        m.insert("description".into(), json!(ioc_sentence(i)));
        m.insert("indicator_types".into(), json!(["malicious-activity"]));
        m.insert("pattern".into(), json!(pat));
        m.insert("pattern_type".into(), json!(pattern_type));
        m.insert("valid_from".into(), json!(timestamp(i.first_seen)));
        m.insert("confidence".into(), json!(i.confidence.score));
        m.insert(
            "labels".into(),
            json!([format!("foiled-band:{}", band_name(i.confidence.band))]),
        );
        m.insert("x_foiled_ioc_id".into(), json!(i.ioc_id));
        m.insert("x_foiled_ioc_type".into(), json!(i.ioc_type.as_str()));
        m.insert(
            "x_foiled_roles".into(),
            json!(i.roles.iter().map(|r| role_name(*r)).collect::<Vec<_>>()),
        );
        m.insert("x_foiled_wording".into(), json!(i.confidence.wording));
        m.insert(
            "x_foiled_publishable".into(),
            json!(i.confidence.publishable),
        );
        m.insert("x_foiled_redacted".into(), json!(i.redacted));
        m.insert(
            "x_foiled_file_ioc_limited".into(),
            json!(i.file_ioc_limited),
        );
        if !i.enrichment.is_empty() {
            m.insert(
                "x_foiled_enrichment".into(),
                Value::Array(
                    i.enrichment
                        .iter()
                        .map(|e| json!({"provider": e.provider, "key": e.key, "value": e.value}))
                        .collect(),
                ),
            );
        }
        if !i.campaign_ids.is_empty() {
            m.insert("x_foiled_campaign_ids".into(), json!(i.campaign_ids));
        }
        if let Some(fp) = &i.fingerprint {
            m.insert(
                "x_foiled_fingerprint".into(),
                json!({"version": fp.version, "steps": fp.steps}),
            );
        }
        put(Value::Object(m), i.last_seen);
        indicator_of.insert(i.ioc_id.as_str(), id.clone());

        // A captured file: an unclassified malware instance with the file
        // as its sample. YARA family names (#11) can name it later.
        if i.ioc_type == IocType::FileSha256
            && let Some(file) = sco_of.get(i.ioc_id.as_str())
        {
            let mid = foiled_id("malware", &i.ioc_id);
            let mut mw = common("malware", &mid, i.first_seen, i.last_seen, tlp);
            mw.insert(
                "name".into(),
                json!(format!(
                    "Unclassified file {}",
                    &i.value[..12.min(i.value.len())]
                )),
            );
            mw.insert(
                "description".into(),
                json!("A file Foiled captured after exploitation. It has not been classified."),
            );
            mw.insert("malware_types".into(), json!(["unknown"]));
            mw.insert("is_family".into(), json!(false));
            mw.insert("sample_refs".into(), json!([file]));
            put(Value::Object(mw), i.last_seen);
            let rid = foiled_id("relationship", &format!("{id}|indicates|{mid}"));
            let mut r = common("relationship", &rid, i.first_seen, i.last_seen, tlp);
            r.insert("relationship_type".into(), json!("indicates"));
            r.insert("source_ref".into(), json!(id));
            r.insert("target_ref".into(), json!(mid));
            r.insert("confidence".into(), json!(i.confidence.score));
            r.insert("description".into(), json!(ioc_sentence(i)));
            put(Value::Object(r), i.last_seen);
        }
    }

    // Attempts, their notes and their links.
    let mut observed_of: BTreeMap<&str, String> = BTreeMap::new();
    for rec in &sel.attempts {
        let a = &rec.attempt;
        // Observables of the attempt's exported IOCs. The source address
        // is among them only when its own IOC passed the gate (`select`);
        // otherwise it is not named anywhere in the bundle.
        let mut refs: BTreeSet<String> = BTreeSet::new();
        let mut indicators: BTreeSet<String> = BTreeSet::new();
        let mut src_exported = false;
        let src = canonical_ip(&a.src);
        for i in sel.iocs_for(&a.attempt_id) {
            if let Some(s) = sco_of.get(i.ioc_id.as_str()) {
                refs.insert(s.clone());
            }
            if let Some(ind) = indicator_of.get(i.ioc_id.as_str()) {
                indicators.insert(ind.clone());
            }
            src_exported |= matches!(i.ioc_type, IocType::Ip | IocType::Ipv6)
                && src.as_deref() == Some(i.value.as_str());
        }
        let targets: Vec<(String, Value)> = rec
            .links
            .iter()
            .map(|l| link_target(l, sel, tlp, notice_id.as_deref()))
            .collect();
        // The attempt's anchor: `observed-data` over its observables, or,
        // when none passed the gate, a `grouping` of what did.
        let (oid, mut m) = if refs.is_empty() {
            let gid = foiled_id("grouping", &a.attempt_id);
            let mut members: BTreeSet<String> = indicators;
            members.extend(targets.iter().map(|(id, _)| id.clone()));
            if members.is_empty() {
                continue;
            }
            let mut g = common("grouping", &gid, a.first_seen, a.last_seen, tlp);
            g.insert(
                "name".into(),
                json!(format!("Foiled attempt {}", a.attempt_id)),
            );
            g.insert("context".into(), json!("suspicious-activity"));
            g.insert("object_refs".into(), json!(members));
            (gid, g)
        } else {
            let oid = foiled_id("observed-data", &a.attempt_id);
            let mut m = common("observed-data", &oid, a.first_seen, a.last_seen, tlp);
            m.insert("first_observed".into(), json!(timestamp(a.first_seen)));
            m.insert("last_observed".into(), json!(timestamp(a.last_seen)));
            m.insert(
                "number_observed".into(),
                json!((a.event_ids.len() as u64).clamp(1, MAX_COUNT)),
            );
            m.insert("object_refs".into(), json!(refs));
            (oid, m)
        };
        m.insert("x_foiled_attempt_id".into(), json!(a.attempt_id));
        m.insert("x_foiled_state".into(), json!(a.state.as_str()));
        m.insert("x_foiled_decoy_kind".into(), json!(a.decoy_kind.as_str()));
        m.insert(
            "x_foiled_catalogue_id".into(),
            json!(printable(&a.catalogue_id)),
        );
        m.insert(
            "x_foiled_file_ioc_limited".into(),
            json!(rec.file_ioc_limited),
        );
        m.insert(
            "x_foiled_summary".into(),
            json!(attempt_summary(rec, src_exported)),
        );
        if let Some(c) = &a.campaign_id {
            m.insert("x_foiled_campaign_id".into(), json!(printable(c)));
        }
        let is_observed = m["type"] == "observed-data";
        put(Value::Object(m), a.last_seen);
        if is_observed {
            observed_of.insert(a.attempt_id.as_str(), oid.clone());
        }

        if !rec.notes.is_empty() {
            let nid = foiled_id("note", &a.attempt_id);
            let mut n = common("note", &nid, a.first_seen, a.last_seen, tlp);
            n.insert(
                "abstract".into(),
                json!(format!("Foiled notes for attempt {}", a.attempt_id)),
            );
            n.insert("content".into(), json!(rec.notes.join("\n\n")));
            n.insert("object_refs".into(), json!([oid]));
            put(Value::Object(n), a.last_seen);
        }

        for (link, (tid, target)) in rec.links.iter().zip(targets) {
            put(target, a.last_seen);
            let rid = foiled_id("relationship", &format!("{oid}|related-to|{tid}"));
            let mut r = common("relationship", &rid, a.first_seen, a.last_seen, tlp);
            r.insert("relationship_type".into(), json!("related-to"));
            r.insert("source_ref".into(), json!(oid));
            r.insert("target_ref".into(), json!(tid));
            r.insert("confidence".into(), json!(link.score));
            r.insert(
                "description".into(),
                json!(link_sentence(link, sel.techniques.get(&link.target))),
            );
            r.insert(
                "labels".into(),
                json!([format!("foiled-band:{}", band_name(link.band))]),
            );
            r.insert(
                "x_foiled_link_kind".into(),
                serde_json::to_value(link.kind).unwrap_or(Value::Null),
            );
            r.insert("x_foiled_wording".into(), json!(link_wording(link)));
            r.insert("x_foiled_publishable".into(), json!(link.publishable));
            r.insert("x_foiled_confirmed".into(), json!(confirmed(link)));
            r.insert("x_foiled_evidence".into(), evidence_summary(link));
            if !link.caps_applied.is_empty() {
                r.insert("x_foiled_caps_applied".into(), json!(link.caps_applied));
            }
            if link.kind == LinkKind::AttemptTechnique
                && let Some(v) = &sel.attack_version
            {
                r.insert("x_foiled_attack_version".into(), json!(v));
            }
            put(Value::Object(r), a.last_seen);
        }
    }

    // Sightings: one per indicator, over the attempts it was seen in.
    for i in &sel.iocs {
        let Some(ind) = indicator_of.get(i.ioc_id.as_str()) else {
            continue;
        };
        let sid = foiled_id("sighting", &i.ioc_id);
        let mut s = common("sighting", &sid, i.first_seen, i.last_seen, tlp);
        s.insert("sighting_of_ref".into(), json!(ind));
        s.insert("first_seen".into(), json!(timestamp(i.first_seen)));
        s.insert(
            "last_seen".into(),
            json!(timestamp(i.last_seen.max(i.first_seen))),
        );
        s.insert("count".into(), json!(u64::from(i.sightings).min(MAX_COUNT)));
        s.insert("where_sighted_refs".into(), json!([ident]));
        let observed: BTreeSet<&String> = i
            .attempt_ids
            .iter()
            .filter_map(|a| observed_of.get(a.as_str()))
            .collect();
        if !observed.is_empty() {
            s.insert("observed_data_refs".into(), json!(observed));
        }
        s.insert("confidence".into(), json!(i.confidence.score));
        put(Value::Object(s), i.last_seen);
    }

    propagate_added(&mut out);
    let mut list: Vec<StixObject> = out.into_values().collect();
    list.sort_by(|a, b| (rank(a.object_type()), a.id()).cmp(&(rank(b.object_type()), b.id())));
    list
}

/// One line of tier evidence for an attempt: state path, hooks and noise.
/// `src` in the canonical form address IOCs use, when it is an address.
fn canonical_ip(src: &str) -> Option<String> {
    src.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical().to_string())
}

/// `src_exported` says whether the source address passed the gate; if not,
/// the summary does not name it.
pub fn attempt_summary(rec: &super::AttemptRecord, src_exported: bool) -> String {
    let a = &rec.attempt;
    let path: Vec<String> = a
        .state_history
        .iter()
        .map(|c| {
            let signal = serde_json::to_value(c.signal)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            format!("{} ({signal})", c.state.as_str())
        })
        .collect();
    let from = if src_exported {
        format!("from {}", printable(&a.src))
    } else {
        "from an address below the export gate".to_string()
    };
    let mut s = format!(
        "Attempt {from} against {} ({}) reached {}. State changes: {}.",
        printable(&a.catalogue_id),
        a.decoy_kind.as_str(),
        a.state.as_str(),
        path.join(", ")
    );
    let hooks: BTreeSet<String> = a.hook_hits.iter().map(|h| printable(&h.hook_id)).collect();
    if !hooks.is_empty() {
        s.push_str(&format!(
            " Vulnerable-path hooks fired: {}.",
            hooks.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(n) = &a.noise {
        let band = serde_json::to_value(n.band)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        s.push_str(&format!(" Source noise score {} ({band}).", n.score));
    }
    if rec.file_ioc_limited {
        s.push_str(" File IOCs are limited: no file hash is available.");
    }
    s
}

/// Every id an object refers to (`*_ref` and `*_refs` properties).
pub fn refs_of(v: &Value) -> Vec<String> {
    v.as_object()
        .map(|m| m.iter().flat_map(|(k, v)| ref_values(k, v)).collect())
        .unwrap_or_default()
}

/// Raise each object's `added` to at least that of every object referring
/// to it, so a TAXII client that receives an object with `added_after`
/// also receives everything it points at (the target sorts no earlier).
/// The reference graph is shallow (sighting to indicator to observable,
/// relationship to grouping to indicator), so a few passes settle it.
fn propagate_added(objects: &mut BTreeMap<String, StixObject>) {
    for _ in 0..8 {
        let mut raise: BTreeMap<String, i64> = BTreeMap::new();
        for o in objects.values() {
            for r in &o.refs {
                let e = raise.entry(r.clone()).or_insert(i64::MIN);
                *e = (*e).max(o.added);
            }
        }
        let mut changed = false;
        for (id, added) in raise {
            if let Some(t) = objects.get_mut(&id)
                && t.added < added
            {
                t.added = added;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn rank(ty: &str) -> u8 {
    match ty {
        "identity" => 0,
        "marking-definition" => 1,
        "ipv4-addr" | "ipv6-addr" | "domain-name" | "url" | "file" | "autonomous-system" => 2,
        "indicator" => 3,
        "malware" => 4,
        "attack-pattern" => 5,
        "vulnerability" => 6,
        "campaign" => 7,
        "intrusion-set" => 8,
        "observed-data" | "grouping" => 9,
        "note" => 10,
        "relationship" => 11,
        "sighting" => 12,
        _ => 13,
    }
}

/// A bundle over `objects` as JSON text, with an id derived from their
/// content. Objects are already serialised, so this hashes and joins them
/// without a parsed copy of the bundle.
pub fn bundle_text(objects: &[StixObject]) -> String {
    let mut h = Sha256::new();
    let mut len = 0;
    for o in objects {
        h.update(o.json.as_bytes());
        h.update(b"\n");
        len += o.json.len() + 1;
    }
    let id = foiled_id("bundle", &hex::encode(h.finalize()));
    let mut out = String::with_capacity(len + 64);
    out.push_str("{\"id\":\"");
    out.push_str(&id);
    out.push_str("\",\"objects\":[");
    for (n, o) in objects.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        out.push_str(&o.json);
    }
    out.push_str("],\"type\":\"bundle\"}");
    out
}

/// The bundle for a selection, parsed. Routes serve [`bundle_text`].
pub fn bundle(sel: &Selection) -> Value {
    serde_json::from_str(&bundle_text(&objects(sel))).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// Structural validation
// ---------------------------------------------------------------------------

const SCO_TYPES: &[&str] = &[
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "file",
    "autonomous-system",
];
const SDO_TYPES: &[&str] = &[
    "identity",
    "indicator",
    "malware",
    "attack-pattern",
    "vulnerability",
    "campaign",
    "intrusion-set",
    "observed-data",
    "grouping",
    "note",
];

fn valid_id(s: &str) -> bool {
    s.split_once("--")
        .is_some_and(|(t, u)| !t.is_empty() && is_uuid(u))
}

/// `YYYY-MM-DDTHH:MM:SS[.s+]Z`.
pub fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|x| x.iter().all(u8::is_ascii_digit));
    b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[b.len() - 1] == b'Z'
        && (b.len() == 20 || (b[19] == b'.' && b.len() > 21 && digits(20..b.len() - 1)))
}

fn ref_values(key: &str, v: &Value) -> Vec<String> {
    if key.ends_with("_ref") {
        v.as_str().map(|s| vec![s.to_string()]).unwrap_or_default()
    } else if key.ends_with("_refs") {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    }
}

/// Structural problems in a bundle, following STIX 2.1 sections 3 to 7 for
/// the object types Foiled emits: id forms, required properties,
/// timestamps, confidence ranges, custom property names, reference
/// resolution within the bundle and duplicate ids. Empty means valid.
pub fn problems(bundle: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if bundle["type"] != "bundle" {
        out.push("bundle: type must be bundle".into());
    }
    if !bundle["id"]
        .as_str()
        .is_some_and(|i| i.starts_with("bundle--") && valid_id(i))
    {
        out.push("bundle: id must be bundle--<uuid>".into());
    }
    let Some(objects) = bundle["objects"].as_array() else {
        out.push("bundle: objects must be an array".into());
        return out;
    };
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    for o in objects {
        let id = o["id"].as_str().unwrap_or_default().to_string();
        if types
            .insert(id.clone(), o["type"].as_str().unwrap_or_default().into())
            .is_some()
        {
            out.push(format!("{id}: duplicate id"));
        }
    }
    let req = |o: &Value, keys: &[&str], out: &mut Vec<String>, id: &str| {
        for k in keys {
            if o.get(*k).is_none_or(Value::is_null) {
                out.push(format!("{id}: {k} is required"));
            }
        }
    };
    for o in objects {
        let ty = o["type"].as_str().unwrap_or_default();
        let id = o["id"].as_str().unwrap_or_default();
        if !id.starts_with(&format!("{ty}--")) || !valid_id(id) {
            out.push(format!("{id}: id must be {ty}--<uuid>"));
        }
        if o["spec_version"] != "2.1" {
            out.push(format!("{id}: spec_version must be 2.1"));
        }
        let Some(map) = o.as_object() else {
            out.push(format!("{id}: not an object"));
            continue;
        };
        for k in map.keys() {
            // STIX 2.1 section 3.1: 3 to 250 characters of a-z, 0-9 and
            // `_`; `id` is the one shorter name the specification defines.
            let ok = (k == "id" || k.len() >= 3)
                && k.len() <= 250
                && k.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
            if !ok {
                out.push(format!("{id}: property name {k} is not allowed"));
            }
            for r in ref_values(k, &map[k]) {
                if !valid_id(&r) {
                    out.push(format!("{id}: {k} holds malformed id {r}"));
                } else if !types.contains_key(&r) {
                    out.push(format!(
                        "{id}: {k} points at {r}, which is not in the bundle"
                    ));
                } else if k == "object_marking_refs"
                    && types.get(&r).map(String::as_str) != Some("marking-definition")
                {
                    out.push(format!("{id}: {r} is not a marking definition"));
                }
            }
        }
        if let Some(c) = o.get("confidence")
            && c.as_u64().is_none_or(|c| c > 100)
        {
            out.push(format!("{id}: confidence must be an integer from 0 to 100"));
        }
        let sdo_or_sro = SDO_TYPES.contains(&ty) || ty == "relationship" || ty == "sighting";
        if sdo_or_sro {
            req(o, &["created", "modified"], &mut out, id);
            let (c, m) = (o["created"].as_str(), o["modified"].as_str());
            if !c.is_some_and(valid_timestamp) || !m.is_some_and(valid_timestamp) {
                out.push(format!(
                    "{id}: created and modified must be STIX timestamps"
                ));
            } else if m < c {
                out.push(format!("{id}: modified is before created"));
            }
        }
        match ty {
            "marking-definition" => {
                req(o, &["created"], &mut out, id);
                if o.get("extensions").is_none() {
                    req(o, &["definition_type", "definition"], &mut out, id);
                }
            }
            "identity" | "attack-pattern" | "vulnerability" | "campaign" | "intrusion-set" => {
                req(o, &["name"], &mut out, id);
            }
            "malware" => {
                req(o, &["name"], &mut out, id);
                if !o["is_family"].is_boolean() {
                    out.push(format!("{id}: is_family must be a boolean"));
                }
            }
            "indicator" => {
                req(o, &["pattern", "pattern_type", "valid_from"], &mut out, id);
                if o["pattern_type"] == "stix" {
                    let p = o["pattern"].as_str().unwrap_or_default();
                    if !(p.starts_with('[') && p.ends_with(']')) {
                        out.push(format!("{id}: STIX pattern must be bracketed"));
                    }
                }
                if !o["valid_from"].as_str().is_some_and(valid_timestamp) {
                    out.push(format!("{id}: valid_from must be a STIX timestamp"));
                }
            }
            "observed-data" => {
                req(
                    o,
                    &["first_observed", "last_observed", "number_observed"],
                    &mut out,
                    id,
                );
                if !o["number_observed"]
                    .as_u64()
                    .is_some_and(|n| (1..=MAX_COUNT).contains(&n))
                {
                    out.push(format!("{id}: number_observed out of range"));
                }
                let refs = o["object_refs"].as_array();
                if refs.is_none_or(Vec::is_empty) {
                    out.push(format!("{id}: object_refs must not be empty"));
                }
                for r in refs.into_iter().flatten().filter_map(Value::as_str) {
                    if types
                        .get(r)
                        .is_some_and(|t| !SCO_TYPES.contains(&t.as_str()))
                    {
                        out.push(format!("{id}: object_refs must name observables, not {r}"));
                    }
                }
                if o["last_observed"].as_str() < o["first_observed"].as_str() {
                    out.push(format!("{id}: last_observed is before first_observed"));
                }
            }
            "note" => {
                req(o, &["content", "object_refs"], &mut out, id);
            }
            "grouping" => {
                req(o, &["context", "object_refs"], &mut out, id);
            }
            "relationship" => {
                req(
                    o,
                    &["relationship_type", "source_ref", "target_ref"],
                    &mut out,
                    id,
                );
            }
            "sighting" => {
                req(o, &["sighting_of_ref"], &mut out, id);
                if o.get("count")
                    .is_some_and(|c| c.as_u64().is_none_or(|c| c > MAX_COUNT))
                {
                    out.push(format!("{id}: count out of range"));
                }
                if let (Some(f), Some(l)) = (o["first_seen"].as_str(), o["last_seen"].as_str())
                    && l < f
                {
                    out.push(format!("{id}: last_seen is before first_seen"));
                }
            }
            "ipv4-addr" | "ipv6-addr" | "domain-name" | "url" => {
                req(o, &["value"], &mut out, id);
            }
            "autonomous-system" => {
                if !o["number"].is_u64() {
                    out.push(format!("{id}: number must be an integer"));
                }
            }
            "file" => {
                if o.get("hashes").is_none() && o.get("name").is_none() {
                    out.push(format!("{id}: file needs hashes or name"));
                }
            }
            other => out.push(format!("{id}: unexpected object type {other}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observable_ids_follow_the_stix_rule() {
        // uuid.uuid5(UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"),
        //     '{"value":"https://example.com/research/index.html"}')
        assert_eq!(
            sco_id(
                "url",
                &json!({"value": "https://example.com/research/index.html"})
            ),
            "url--47c3cf9a-5027-5bf0-997a-017c7edc7c55"
        );
    }

    #[test]
    fn pattern_literals_escape_quotes_and_backslashes() {
        assert_eq!(pattern_literal(r"a'b\c"), r"'a\'b\\c'");
    }

    #[test]
    fn timestamps_are_checked() {
        assert!(valid_timestamp("2026-10-18T01:02:03.004Z"));
        assert!(valid_timestamp("2026-10-18T01:02:03Z"));
        assert!(!valid_timestamp("2026-10-18 01:02:03Z"));
        assert!(!valid_timestamp("2026-10-18T01:02:03.Z"));
    }

    #[test]
    fn tlp_markings_are_the_oasis_objects() {
        let m = tlp_marking(Tlp::AmberStrict);
        assert_eq!(m["name"], "TLP:AMBER+STRICT");
        assert_eq!(m["extensions"][TLP_EXTENSION]["tlp_2_0"], "amber+strict");
        assert_eq!(m["id"], tlp_marking_id(Tlp::AmberStrict));
    }

    #[test]
    fn problems_catch_dangling_refs_and_bad_confidence() {
        let b = json!({
            "type": "bundle",
            "id": "bundle--2ed6657d-e927-568b-95e1-2665a8aea6a2",
            "objects": [{
                "type": "relationship", "spec_version": "2.1",
                "id": "relationship--2ed6657d-e927-568b-95e1-2665a8aea6a2",
                "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
                "relationship_type": "related-to",
                "source_ref": "indicator--2ed6657d-e927-568b-95e1-2665a8aea6a2",
                "target_ref": "vulnerability--2ed6657d-e927-568b-95e1-2665a8aea6a2",
                "confidence": 101, "Bad-Key": 1
            }]
        });
        let p = problems(&b);
        assert!(p.iter().any(|m| m.contains("not in the bundle")), "{p:?}");
        assert!(p.iter().any(|m| m.contains("confidence")), "{p:?}");
        assert!(p.iter().any(|m| m.contains("Bad-Key")), "{p:?}");
    }
}
