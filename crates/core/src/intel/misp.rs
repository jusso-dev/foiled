//! MISP event JSON from a [`Selection`] (#13).
//!
//! One event per export, never published (`published: false`) and
//! distribution "your organisation only", so nothing leaves the receiving
//! MISP instance until someone there decides it should. Attribute types and
//! categories are from MISP's `describeTypes.json`:
//!
//! | IOC type | MISP | Category |
//! | --- | --- | --- |
//! | `ip`, `ipv6` | `ip-src` (role `source`), else `ip-dst` | Network activity |
//! | `domain` | `domain` | Network activity |
//! | `url` | `url` | Network activity |
//! | `http_path` | `uri` | Network activity |
//! | `http_ua` | `user-agent` | Network activity |
//! | `request_substring` | `pattern-in-traffic` | Payload delivery |
//! | `payload_sha256` | `text` (a request body hash, not a file) | Payload delivery |
//! | `file_sha256` | `file` object with `sha256` | Payload installation |
//! | `cmdline` | `text` | Payload installation |
//! | `behaviour_fingerprint` | `text` | Other |
//! | `dns_query` | covered by its `domain` | |
//!
//! `to_ids` is set only for indicators that passed the publish gate on
//! their own (`publishable`) and whose type a detection tool can match
//! without obvious false positives; user agents, fingerprints and payload
//! hashes never set it. CVE links are `vulnerability` attributes, technique
//! links are `mitre-attack-pattern` galaxy tags, campaign links (#33)
//! `campaign-id` attributes and actor links (#29, opt-in) `threat-actor`
//! attributes, each with the #27 wording in the comment.

use serde_json::{Value, json};

use super::uuid5::uuid_v5;
use super::{
    FOILED_NAMESPACE, Selection, band_name, ioc_sentence, link_sentence, link_wording, timestamp,
};
use crate::confidence::{ConfidenceLink, LinkKind};
use crate::ioc::{Ioc, IocRole, IocType};
use crate::timeline::printable;

/// `uuid` of MISP's `file` object template (misp-objects `objects/file`).
pub const FILE_TEMPLATE_UUID: &str = "688c46fb-5edb-40a3-8273-1af7923e2215";
pub const FILE_TEMPLATE_VERSION: &str = "25";

/// Tag on every event with a memory-only attempt (`docs/iocs.md`).
pub const FILE_LIMITED_TAG: &str = "foiled:file-ioc-limited";

/// The event uuid for an export scope. See [`event`].
pub fn event_uuid(scope: &str) -> String {
    uuid_v5(FOILED_NAMESPACE, &format!("misp-event|{scope}"))
}

/// A uuid for something inside one event. MISP requires attribute and
/// object uuids to be unique across an instance, so they are derived from
/// the event uuid: overlapping exports never share one.
fn uuid(event: &str, kind: &str, key: &str) -> String {
    uuid_v5(FOILED_NAMESPACE, &format!("misp-{kind}|{event}|{key}"))
}

fn secs(ms: i64) -> String {
    ms.div_euclid(1000).to_string()
}

fn tag(name: impl Into<String>) -> Value {
    json!({"name": name.into()})
}

/// `(type, category, comment)` for an IOC, or `None` when covered by
/// another attribute.
pub fn attribute_type(i: &Ioc) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match i.ioc_type {
        IocType::Ip | IocType::Ipv6 if i.roles.contains(&IocRole::Source) => {
            ("ip-src", "Network activity", "attacking address")
        }
        IocType::Ip | IocType::Ipv6 => ("ip-dst", "Network activity", "callback or second stage"),
        IocType::Domain => ("domain", "Network activity", "domain"),
        IocType::Url => ("url", "Network activity", "URL"),
        IocType::HttpPath => ("uri", "Network activity", "request path"),
        IocType::HttpUa => ("user-agent", "Network activity", "user agent"),
        IocType::RequestSubstring => (
            "pattern-in-traffic",
            "Payload delivery",
            "exact request string",
        ),
        IocType::PayloadSha256 => (
            "text",
            "Payload delivery",
            "SHA-256 of a request body sent to the decoy, not a file hash",
        ),
        IocType::FileSha256 => ("sha256", "Payload installation", "captured file"),
        IocType::Cmdline => ("text", "Payload installation", "command line"),
        IocType::BehaviourFingerprint => ("text", "Other", "foiled behaviour fingerprint"),
        IocType::DnsQuery => return None,
    })
}

/// Whether a detection tool should match the IOC (`to_ids`).
pub fn to_ids(i: &Ioc) -> bool {
    i.confidence.publishable
        && matches!(
            i.ioc_type,
            IocType::Ip
                | IocType::Ipv6
                | IocType::Domain
                | IocType::Url
                | IocType::HttpPath
                | IocType::RequestSubstring
                | IocType::FileSha256
                | IocType::Cmdline
        )
}

/// Shareable ASN and country context, already through `export_refs`.
fn context_text(i: &Ioc) -> String {
    let parts: Vec<String> = i
        .enrichment
        .iter()
        .map(|e| {
            let v = match &e.value {
                Value::String(s) => printable(s),
                v => v.to_string(),
            };
            format!("{} {v} ({})", e.key, printable(&e.provider))
        })
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" Context: {}.", parts.join("; "))
    }
}

fn attribute(
    ev: &str,
    i: &Ioc,
    ty: &str,
    category: &str,
    comment: &str,
    relation: Option<&str>,
) -> Value {
    let mut a = json!({
        "uuid": uuid(ev, "attribute", &i.ioc_id),
        "type": ty,
        "category": category,
        "value": i.value,
        "to_ids": to_ids(i),
        "comment": format!("{comment}. {}{}", ioc_sentence(i), context_text(i)),
        "first_seen": timestamp(i.first_seen),
        "last_seen": timestamp(i.last_seen.max(i.first_seen)),
        "timestamp": secs(i.last_seen),
        "distribution": "5",
        "Tag": [
            tag(format!("foiled:confidence=\"{}\"", i.confidence.score)),
            tag(format!("foiled:band=\"{}\"", band_name(i.confidence.band))),
            tag(format!("foiled:wording=\"{}\"", i.confidence.wording)),
        ],
    });
    if let Some(r) = relation {
        a["object_relation"] = json!(r);
    }
    a
}

fn link_attribute(
    ev: &str,
    link: &ConfidenceLink,
    attempt_id: &str,
    sel: &Selection,
) -> Option<Value> {
    let (ty, category) = match link.kind {
        LinkKind::AttemptCve => ("vulnerability", "External analysis"),
        LinkKind::AttemptCampaign => ("campaign-id", "Attribution"),
        LinkKind::AttemptActor => ("threat-actor", "Attribution"),
        // Techniques become galaxy tags; IOC links are attributes already.
        LinkKind::AttemptTechnique | LinkKind::AttemptIoc => return None,
    };
    let value = if link.kind == LinkKind::AttemptCve {
        printable(&link.target.to_ascii_uppercase())
    } else {
        printable(&link.target)
    };
    Some(json!({
        "uuid": uuid(ev, "link", &format!("{attempt_id}|{:?}|{}", link.kind, link.target)),
        "type": ty,
        "category": category,
        "value": value,
        "to_ids": false,
        "comment": format!("Attempt {attempt_id}: {}", link_sentence(link, sel.techniques.get(&link.target))),
        "distribution": "5",
        "Tag": [
            tag(format!("foiled:confidence=\"{}\"", link.score)),
            tag(format!("foiled:band=\"{}\"", band_name(link.band))),
            tag(format!("foiled:wording=\"{}\"", link_wording(link))),
        ],
    }))
}

/// The MISP event for a selection.
/// The MISP event for a selection. `scope` names the export: the API
/// passes a digest of the tenant, the filters and the window. The event
/// uuid is derived from it, so importing the same export twice updates one
/// event instead of creating a second, and every attribute uuid is derived
/// from the event uuid, so two overlapping exports never clash on import.
pub fn event(sel: &Selection, scope: &str) -> Value {
    let ev = event_uuid(scope);
    let mut attributes = Vec::new();
    let mut objects = Vec::new();
    for i in &sel.iocs {
        let Some((ty, category, comment)) = attribute_type(i) else {
            continue;
        };
        if i.ioc_type == IocType::FileSha256 {
            objects.push(json!({
                "uuid": uuid(&ev, "object", &i.ioc_id),
                "name": "file",
                "meta-category": "file",
                "template_uuid": FILE_TEMPLATE_UUID,
                "template_version": FILE_TEMPLATE_VERSION,
                "description": "File object describing a file with meta-information",
                "comment": "A file Foiled captured after exploitation. It has not been classified.",
                "distribution": "5",
                "timestamp": secs(i.last_seen),
                "Attribute": [attribute(&ev, i, ty, category, comment, Some("sha256"))],
            }));
        } else {
            attributes.push(attribute(&ev, i, ty, category, comment, None));
        }
    }

    let mut tags = vec![
        tag(format!("tlp:{}", sel.tlp.as_str())),
        tag("foiled:export"),
    ];
    if sel.unreviewed {
        tags.push(tag("foiled:unreviewed"));
    }
    if sel.attempts.iter().any(|r| r.file_ioc_limited) {
        tags.push(tag(FILE_LIMITED_TAG));
    }
    let mut galaxies: Vec<String> = Vec::new();
    let mut comments: Vec<String> = Vec::new();
    for rec in &sel.attempts {
        let aid = &rec.attempt.attempt_id;
        for link in &rec.links {
            if let Some(a) = link_attribute(&ev, link, aid, sel) {
                attributes.push(a);
            }
            if link.kind == LinkKind::AttemptTechnique
                && let Some(t) = sel.techniques.get(&link.target)
            {
                galaxies.push(format!(
                    "misp-galaxy:mitre-attack-pattern=\"{} - {}\"",
                    t.name, t.id
                ));
                attributes.push(json!({
                    "uuid": uuid(&ev, "link", &format!("{aid}|{:?}|{}", link.kind, link.target)),
                    "type": "text",
                    "category": "External analysis",
                    "value": format!("{} {}", t.id, t.name),
                    "to_ids": false,
                    "comment": format!("Attempt {aid}: {}", link_sentence(link, Some(t))),
                    "distribution": "5",
                    "Tag": [
                        tag(format!("foiled:confidence=\"{}\"", link.score)),
                        tag(format!("foiled:band=\"{}\"", band_name(link.band))),
                        tag(format!("foiled:wording=\"{}\"", link_wording(link))),
                    ],
                }));
            }
        }
        for n in &rec.notes {
            comments.push(format!("Attempt {aid}: {n}"));
        }
    }
    galaxies.sort();
    galaxies.dedup();
    tags.extend(galaxies.into_iter().map(tag));
    if let Some(notice) = &sel.attack_notice {
        comments.push(format!(
            "ATT&CK v{}: {notice}",
            sel.attack_version.clone().unwrap_or_default()
        ));
    }
    comments.dedup();
    if !comments.is_empty() {
        attributes.push(json!({
            "uuid": uuid(&ev, "comment", "attempt-notes"),
            "type": "comment",
            "category": "Other",
            "value": comments.join("\n\n"),
            "to_ids": false,
            "distribution": "5",
        }));
    }

    let first = sel
        .attempts
        .iter()
        .map(|r| r.attempt.first_seen)
        .chain(sel.iocs.iter().map(|i| i.first_seen))
        .min()
        .unwrap_or(0);
    let last = sel
        .attempts
        .iter()
        .map(|r| r.attempt.last_seen)
        .chain(sel.iocs.iter().map(|i| i.last_seen))
        .max()
        .unwrap_or(0);
    let date = &timestamp(first)[..10];
    let body = json!({
        "Attribute": attributes,
        "Object": objects,
        "Tag": tags,
    });
    let mut event = json!({
        "uuid": ev,
        "info": format!(
            "Foiled decoy activity from {date}: {} attempt{}, {} indicator{}",
            sel.attempts.len(),
            if sel.attempts.len() == 1 { "" } else { "s" },
            sel.iocs.len(),
            if sel.iocs.len() == 1 { "" } else { "s" },
        ),
        "date": date,
        "timestamp": secs(last),
        "published": false,
        "distribution": "0",
        "analysis": "1",
        "threat_level_id": "3",
    });
    if let (Value::Object(e), Value::Object(b)) = (&mut event, body) {
        e.extend(b);
    }
    json!({"Event": event})
}

/// Structural problems in a MISP event: required fields, known attribute
/// types for their category, UUID forms and object relations.
pub fn problems(v: &Value) -> Vec<String> {
    use super::uuid5::is_uuid;
    let allowed: &[(&str, &[&str])] = &[
        (
            "Network activity",
            &[
                "ip-src",
                "ip-dst",
                "domain",
                "url",
                "uri",
                "user-agent",
                "text",
            ],
        ),
        (
            "Payload delivery",
            &["pattern-in-traffic", "text", "sha256", "vulnerability"],
        ),
        ("Payload installation", &["sha256", "text"]),
        ("External analysis", &["vulnerability", "text"]),
        ("Attribution", &["threat-actor", "campaign-id", "text"]),
        ("Other", &["text", "comment"]),
    ];
    let mut out = Vec::new();
    let e = &v["Event"];
    for k in [
        "uuid",
        "info",
        "date",
        "timestamp",
        "distribution",
        "analysis",
        "threat_level_id",
    ] {
        if e.get(k).is_none() {
            out.push(format!("Event.{k} is required"));
        }
    }
    if e["published"] != false {
        out.push("Event.published must be false".into());
    }
    if !e["uuid"].as_str().is_some_and(is_uuid) {
        out.push("Event.uuid must be a UUID".into());
    }
    let check = |a: &Value, ctx: &str, out: &mut Vec<String>| {
        let ty = a["type"].as_str().unwrap_or_default();
        let cat = a["category"].as_str().unwrap_or_default();
        if !allowed.iter().any(|(c, ts)| *c == cat && ts.contains(&ty)) {
            out.push(format!("{ctx}: type {ty} is not allowed in category {cat}"));
        }
        if !a["uuid"].as_str().is_some_and(is_uuid) {
            out.push(format!("{ctx}: uuid must be a UUID"));
        }
        if !a["value"].is_string() || !a["to_ids"].is_boolean() {
            out.push(format!("{ctx}: value and to_ids are required"));
        }
    };
    for (n, a) in e["Attribute"].as_array().into_iter().flatten().enumerate() {
        check(a, &format!("Attribute[{n}]"), &mut out);
    }
    for (n, o) in e["Object"].as_array().into_iter().flatten().enumerate() {
        for (m, a) in o["Attribute"].as_array().into_iter().flatten().enumerate() {
            check(a, &format!("Object[{n}].Attribute[{m}]"), &mut out);
            if a.get("object_relation").is_none() {
                out.push(format!(
                    "Object[{n}].Attribute[{m}]: object_relation is required"
                ));
            }
        }
    }
    out
}
