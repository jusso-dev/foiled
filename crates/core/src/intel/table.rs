//! IOC CSV and JSON from a [`Selection`] (#13), with the #34 field list.
//!
//! JSON items are `schemas/ioc.schema.json` objects, exactly as `/v0/iocs`
//! returns them but gated and redacted for export. CSV has one row per IOC:
//! `indicator` is the defanged `display` for people and `value` the exact
//! string for machines. Cells are RFC 4180 quoted and formula-safe. Every
//! row carries the export's TLP label and whether it is a published or an
//! unreviewed export, so the marking survives a download.

use serde::Serialize;
use serde_json::{Value, json};

use super::{Dropped, Selection, band_name, timestamp};
use crate::ioc::{EnrichmentRef, Ioc};

/// The CSV header. The first six columns are the ones `docs/iocs.md`
/// fixes for memory-only attempts.
pub const CSV_COLUMNS: &[&str] = &[
    "indicator_type",
    "indicator",
    "first_seen",
    "last_seen",
    "file_ioc_limited",
    "note",
    "ioc_id",
    "value",
    "roles",
    "sightings",
    "confidence",
    "band",
    "wording",
    "publishable",
    "redacted",
    "attempt_ids",
    "campaign_ids",
    "decoy_ids",
    "catalogue_ids",
    "asn",
    "as_org",
    "country",
    "tlp",
    "review",
];

/// The `review` cell: `published` when only publishable rows were let
/// through, `unreviewed` when an analyst lifted the gate.
pub fn review_state(sel: &Selection) -> &'static str {
    if sel.unreviewed {
        "unreviewed"
    } else {
        "published"
    }
}

/// The marking for the `tlp` cell and JSON field, for example `TLP:AMBER`.
pub fn tlp_label(sel: &Selection) -> String {
    format!("TLP:{}", sel.tlp.as_str().to_ascii_uppercase())
}

/// The `note` cell for a memory-only IOC.
pub const FILE_LIMITED_NOTE: &str = "memory-resident implant: no file hash available";

/// RFC 4180 quoting, plus a leading `'` for cells a spreadsheet would treat
/// as a formula.
pub fn cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn ref_text(refs: &[EnrichmentRef], key: &str) -> String {
    refs.iter()
        .find(|r| r.key == key)
        .map(|r| match &r.value {
            Value::String(s) => s.clone(),
            v => v.to_string(),
        })
        .unwrap_or_default()
}

fn names<T: Serialize>(items: &[T]) -> String {
    items
        .iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<Vec<_>>()
        .join(";")
}

fn row(i: &Ioc, sel: &Selection) -> Vec<String> {
    vec![
        i.ioc_type.as_str().to_string(),
        i.display.clone(),
        timestamp(i.first_seen),
        timestamp(i.last_seen),
        i.file_ioc_limited.to_string(),
        if i.file_ioc_limited {
            FILE_LIMITED_NOTE.to_string()
        } else {
            String::new()
        },
        i.ioc_id.clone(),
        i.value.clone(),
        names(&i.roles),
        i.sightings.to_string(),
        i.confidence.score.to_string(),
        band_name(i.confidence.band).to_string(),
        i.confidence.wording.clone(),
        i.confidence.publishable.to_string(),
        i.redacted.to_string(),
        i.attempt_ids.join(";"),
        i.campaign_ids.join(";"),
        i.decoy_ids.join(";"),
        i.catalogue_ids.join(";"),
        ref_text(&i.enrichment, "asn.number"),
        ref_text(&i.enrichment, "asn.org"),
        ref_text(&i.enrichment, "geo.country"),
        tlp_label(sel),
        review_state(sel).to_string(),
    ]
}

pub fn csv(sel: &Selection) -> String {
    let mut out = CSV_COLUMNS.join(",");
    out.push('\n');
    for i in &sel.iocs {
        let cells: Vec<String> = row(i, sel).iter().map(|c| cell(c)).collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

/// Attempt context carried by the JSON export.
#[derive(Debug, Clone, Serialize)]
pub struct AttemptNote {
    pub attempt_id: String,
    pub state: String,
    pub file_ioc_limited: bool,
    pub notes: Vec<String>,
}

/// The JSON export: export metadata, attempt notes and the IOC items.
pub fn json(sel: &Selection) -> Value {
    let attempts: Vec<AttemptNote> = sel
        .attempts
        .iter()
        .map(|r| AttemptNote {
            attempt_id: r.attempt.attempt_id.clone(),
            state: r.attempt.state.as_str().to_string(),
            file_ioc_limited: r.file_ioc_limited,
            notes: r.notes.clone(),
        })
        .collect();
    json!({
        "format": "foiled-iocs",
        "version": 1,
        "tlp": sel.tlp.as_str(),
        "unreviewed": sel.unreviewed,
        "marking": tlp_label(sel),
        "review": review_state(sel),
        "dropped": serde_json::to_value::<&Dropped>(&sel.dropped).unwrap_or(Value::Null),
        "attempts": attempts,
        "items": sel.iocs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_are_quoted_and_formula_safe() {
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(cell("-c x\ny"), "\"'-c x\ny\"");
    }
}
