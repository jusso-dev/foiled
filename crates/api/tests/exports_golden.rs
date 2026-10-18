//! Golden test for intel exports (#13). Each fixture is grouped into
//! attempts (#25), scored with the bundled rules and catalogue (#12, #26,
//! #27), extracted (#34), enriched and exported as STIX 2.1, MISP, CSV and
//! JSON. Outputs must match `testdata/exports/{stix,misp,table}/`; the
//! repository lint also validates the STIX and MISP files against
//! `schemas/stix-bundle.schema.json` and `schemas/misp-event.schema.json`.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::path::{Path, PathBuf};

use foiled_api::catalogue::Catalogue;
use foiled_api::links::matcher_signals;
use foiled_api::routes::exports::{OverrideIndex, export_input, index_overrides};
use foiled_api::store::LinkOverride;
use foiled_core::attempt::{DEFAULT_IDLE_GAP_MS, build};
use foiled_core::capture::CaptureEvent;
use foiled_core::confidence::{
    ConfidenceConfig, Evidence, EvidenceSource, Feedback, LinkKind, Override, score,
};
use foiled_core::enrichment::{AsnTable, Fact, Observable, Provider, enrich_all};
use foiled_core::intel::{ExportInput, ExportOptions, Selection, misp, select, stix, table};
use foiled_core::ioc::{
    ExtractOptions, Ioc, address_observables, apply_enrichment, attach_refs, extract,
};
use foiled_core::share::Tlp;
use serde_json::{Value, json};

const NOW: i64 = 1_792_285_700_000;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn events(rel: &str) -> Vec<CaptureEvent> {
    let raw: Value =
        serde_json::from_str(&std::fs::read_to_string(root().join(rel)).unwrap()).unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    for e in &events {
        assert!(e.problems(NOW).is_empty(), "{}", e.event_id);
    }
    events
}

fn fact(provider: &str, key: &str, value: Value) -> Fact {
    Fact {
        provider: provider.into(),
        key: key.into(),
        value,
        confidence: 90,
        observed_at: NOW - 60_000,
        ttl_secs: 604_800,
        raw_ref: None,
    }
}

/// The export input for a fixture, as the API builds it.
fn input(rel: &str, store_payloads: bool, events: Vec<CaptureEvent>) -> ExportInput {
    input_with(rel, store_payloads, events, |_| OverrideIndex::new())
}

/// As [`input`], with analyst overrides chosen once the attempt ids are
/// known.
fn input_with(
    rel: &str,
    store_payloads: bool,
    mut events: Vec<CaptureEvent>,
    overrides: impl Fn(&[foiled_core::attempt::Attempt]) -> OverrideIndex,
) -> ExportInput {
    if events.is_empty() {
        events = self::events(rel);
    }
    let mut attempts = build(&events, DEFAULT_IDLE_GAP_MS, &matcher_signals(&events));
    let mut x = extract(
        &attempts,
        &events,
        &ConfidenceConfig::default(),
        ExtractOptions { store_payloads },
    );
    attach_refs(&mut attempts, &x);
    // The fake ASN table is `local_asn`, which is never redistributed; a
    // shareable provider adds ASN context for the synthetic source.
    let asn =
        AsnTable::from_csv(&std::fs::read_to_string(root().join("enrichment/asn.csv")).unwrap())
            .unwrap();
    let providers: [&dyn Provider; 1] = [&asn];
    let mut run = enrich_all(&providers, &address_observables(&x.iocs), NOW);
    let synthetic = Observable::ip("203.0.113.60").unwrap();
    if let Some(f) = run.facts.get_mut(&synthetic) {
        f.extend([
            fact("team_asn", "asn.number", json!(64498)),
            fact("team_asn", "asn.org", json!("Example Hosting")),
            fact("team_asn", "geo.country", json!("US")),
        ]);
    }
    apply_enrichment(&mut x.iocs, &run.facts);
    let iocs = x.iocs.clone();
    let overrides = overrides(&attempts);
    export_input(
        &Catalogue::bundled(),
        attempts,
        &events,
        &x,
        iocs,
        &overrides,
        &[],
        &Default::default(),
    )
}

/// An analyst confirms the T1190 link on the synthetic attempt: rule-only
/// technique links score below publish_min under the #27 weights, so this
/// is how one is published.
fn confirm_t1190(attempts: &[foiled_core::attempt::Attempt]) -> OverrideIndex {
    let a = attempts
        .iter()
        .find(|a| a.src == "203.0.113.60")
        .expect("synthetic attempt");
    index_overrides(vec![LinkOverride {
        attempt_id: a.attempt_id.clone(),
        kind: LinkKind::AttemptTechnique,
        target: "T1190".into(),
        decision: Override {
            feedback: Feedback::TruePositive,
            analyst_id: "analyst-1".into(),
            at: NOW - 30_000,
            note: "hook trigger on the upload path".into(),
        },
    }])
}

fn check_json(dir: &str, name: &str, got: &Value) {
    let path = root()
        .join("exports")
        .join(dir)
        .join(format!("{name}.json"));
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::write(&path, serde_json::to_string_pretty(got).unwrap() + "\n").unwrap();
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(got, &want, "{}", path.display());
}

fn check_text(name: &str, got: &str) {
    let path = root().join("exports/table").join(name);
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::write(&path, got).unwrap();
    }
    assert_eq!(got, std::fs::read_to_string(&path).unwrap(), "{name}");
}

fn golden(name: &str, sel: &Selection) -> (Value, Value) {
    let bundle = stix::bundle(sel);
    let problems = stix::problems(&bundle);
    assert!(problems.is_empty(), "{name}: {problems:#?}");
    let event = misp::event(sel, &format!("golden|{name}"));
    let problems = misp::problems(&event);
    assert!(problems.is_empty(), "{name}: {problems:#?}");
    check_json("stix", name, &bundle);
    check_json("misp", name, &event);
    check_json("table", name, &table::json(sel));
    check_text(&format!("{name}.csv"), &table::csv(sel));
    (bundle, event)
}

fn of_type<'a>(b: &'a Value, ty: &str) -> Vec<&'a Value> {
    b["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] == ty)
        .collect()
}

fn indicator<'a>(b: &'a Value, ioc_type: &str) -> Vec<&'a Value> {
    of_type(b, "indicator")
        .into_iter()
        .filter(|o| o["x_foiled_ioc_type"] == ioc_type)
        .collect()
}

fn relationship_to<'a>(b: &'a Value, target_type: &str) -> Vec<&'a Value> {
    of_type(b, "relationship")
        .into_iter()
        .filter(|r| {
            r["target_ref"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{target_type}--"))
        })
        .collect()
}

fn text(v: &Value) -> String {
    serde_json::to_string(v).unwrap()
}

#[test]
fn synthetic_attempt_exports_ip_payload_string_dns_callback_and_technique() {
    let opts = ExportOptions {
        include_payloads: true,
        ..Default::default()
    };
    let sel = select(
        input_with("exports/synthetic.input.json", true, vec![], confirm_t1190),
        &opts,
    );
    let (b, event) = golden("synthetic", &sel);
    let all = text(&b);

    // ASN-enriched source address: indicator, observable and its AS.
    let ip = indicator(&b, "ip");
    let src = ip
        .iter()
        .find(|i| i["pattern"] == "[ipv4-addr:value = '203.0.113.60']")
        .expect("source indicator");
    assert!(src["confidence"].as_u64().unwrap() >= 60);
    let sco = of_type(&b, "ipv4-addr")
        .into_iter()
        .find(|o| o["value"] == "203.0.113.60")
        .unwrap();
    let asn = of_type(&b, "autonomous-system");
    assert_eq!(asn.len(), 1);
    assert_eq!(asn[0]["number"], 64498);
    assert_eq!(sco["belongs_to_refs"][0], asn[0]["id"]);
    // local_asn context (the fake table's) is never exported.
    assert!(!all.contains("local_asn"));

    // The payload string, only because include_payloads was set.
    let payload = indicator(&b, "request_substring");
    assert_eq!(payload.len(), 1);
    assert_eq!(payload[0]["pattern_type"], "foiled-request-substring");
    assert_eq!(payload[0]["pattern"], "#!/bin/sh\necho foiled-demo");

    // DNS callback: the name as a domain indicator (dns_query rides on it).
    assert!(
        indicator(&b, "domain")
            .iter()
            .any(|i| i["pattern"] == "[domain-name:value = 'q4x9.cb.example.invalid']")
    );
    assert!(indicator(&b, "dns_query").is_empty());

    // Technique link: MITRE's attack-pattern and a relationship with
    // confidence. An analyst confirmed it, so it says so; the unconfirmed
    // technique links stay below publish_min and are left out.
    let t1190 = of_type(&b, "attack-pattern")
        .into_iter()
        .find(|a| a["external_references"][0]["external_id"] == "T1190")
        .expect("T1190");
    // Foiled's own object, pointing at MITRE's: never MITRE's id.
    let sidecar = foiled_api::links::attack_sidecar();
    let mitre = sidecar.get("T1190").unwrap().stix_id.as_str();
    assert_ne!(t1190["id"], mitre);
    assert!(!all.contains(&format!("\"id\":\"{mitre}\"")));
    assert_eq!(t1190["x_foiled_mitre_stix_id"], mitre);
    assert_eq!(t1190["created_by_ref"], stix::identity_id().as_str());
    let rel = of_type(&b, "relationship")
        .into_iter()
        .find(|r| r["target_ref"] == t1190["id"])
        .unwrap();
    assert_eq!(rel["confidence"], 100);
    assert_eq!(rel["x_foiled_confirmed"], true);
    assert_eq!(of_type(&b, "attack-pattern").len(), 1);
    assert!(
        rel["description"].as_str().unwrap().starts_with(
            "An analyst confirmed this attempt as ATT&CK T1190 (Exploit Public-Facing Application)."
        ),
        "{}",
        rel["description"]
    );
    assert!(of_type(&b, "marking-definition").iter().any(|m| {
        m["definition"]["statement"]
            .as_str()
            .is_some_and(|s| s.contains("The MITRE Corporation"))
    }));

    // CVE: vulnerability with "we assess as" and confidence.
    let cve = relationship_to(&b, "vulnerability");
    assert_eq!(cve.len(), 1);
    assert!(
        cve[0]["description"]
            .as_str()
            .unwrap()
            .starts_with("We assess as an attempt against FOILED-DEMO-0001."),
        "{}",
        cve[0]["description"]
    );
    assert!(cve[0]["confidence"].is_u64());

    // Every relationship carries confidence; only the analyst-confirmed
    // technique claims confirmation.
    assert!(
        of_type(&b, "relationship")
            .iter()
            .all(|r| r["confidence"].is_u64())
    );
    assert_eq!(cve[0]["x_foiled_confirmed"], false);
    assert!(!cve[0]["description"].as_str().unwrap().contains("onfirmed"));
    assert!(
        indicator(&b, "ip")
            .iter()
            .all(|i| !i["description"].as_str().unwrap().contains("onfirmed"))
    );

    // The probe-only source stays below publish_min and is left out.
    assert!(!all.contains("198.51.100.9\""));
    assert!(!all.contains("demo-scanner"));
    assert!(sel.dropped.iocs_below_gate > 0);
    assert_eq!(sel.dropped.attempts_empty, 1);

    // TLP:AMBER on everything Foiled creates.
    let amber = stix::tlp_marking_id(Tlp::Amber);
    for o in b["objects"].as_array().unwrap() {
        let ty = o["type"].as_str().unwrap();
        if !matches!(ty, "identity" | "marking-definition" | "attack-pattern") {
            assert_eq!(o["object_marking_refs"][0], amber, "{}", o["id"]);
        }
    }

    // MISP: the same indicators with to_ids gated, CVE and technique as
    // wording-carrying attributes, and the ATT&CK galaxy.
    let e = &event["Event"];
    let attrs = e["Attribute"].as_array().unwrap();
    let ip_src = attrs
        .iter()
        .find(|a| a["type"] == "ip-src" && a["value"] == "203.0.113.60")
        .unwrap();
    assert_eq!(ip_src["to_ids"], true);
    assert!(
        ip_src["comment"]
            .as_str()
            .unwrap()
            .contains("asn.number 64498 (team_asn)")
    );
    assert!(
        attrs
            .iter()
            .any(|a| a["type"] == "pattern-in-traffic" && a["category"] == "Payload delivery")
    );
    let vuln = attrs.iter().find(|a| a["type"] == "vulnerability").unwrap();
    assert!(
        vuln["comment"]
            .as_str()
            .unwrap()
            .contains("We assess as an attempt against FOILED-DEMO-0001.")
    );
    assert!(e["Tag"].as_array().unwrap().iter().any(|t| t["name"]
        == "misp-galaxy:mitre-attack-pattern=\"Exploit Public-Facing Application - T1190\""));
    assert!(
        e["Tag"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "tlp:amber")
    );
    assert_eq!(e["published"], false);
}

#[test]
fn payload_strings_need_the_opt_in() {
    let sel = select(
        input("exports/synthetic.input.json", true, vec![]),
        &ExportOptions::default(),
    );
    assert_eq!(sel.dropped.payload_iocs, 1);
    assert!(indicator(&stix::bundle(&sel), "request_substring").is_empty());
}

#[test]
fn memory_only_attempt_exports_behaviour_without_a_file_hash() {
    let sel = select(
        input("iocs/memory-only.input.json", false, vec![]),
        &ExportOptions::default(),
    );
    let (b, event) = golden("memory-only", &sel);
    let all = text(&b);
    assert!(of_type(&b, "file").is_empty());
    assert!(of_type(&b, "malware").is_empty());
    assert!(!all.contains("[file:"));
    let bf = indicator(&b, "behaviour_fingerprint");
    assert_eq!(bf.len(), 1);
    assert_eq!(bf[0]["pattern_type"], "foiled-bf");
    assert_eq!(bf[0]["x_foiled_file_ioc_limited"], true);
    assert!(bf[0]["x_foiled_fingerprint"]["steps"].is_array());
    assert_eq!(indicator(&b, "cmdline").len(), 1);
    let notes = of_type(&b, "note");
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0]["content"]
            .as_str()
            .unwrap()
            .contains("no file hash is reported")
    );
    let od = of_type(&b, "observed-data");
    assert_eq!(od[0]["x_foiled_file_ioc_limited"], true);

    // MISP: no sha256 attribute, the limitation tag, the fingerprint as text.
    let e = &event["Event"];
    assert!(!text(e).contains("\"sha256\""));
    assert!(e["Object"].as_array().unwrap().is_empty());
    assert!(
        e["Tag"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == misp::FILE_LIMITED_TAG)
    );
    let fp = e["Attribute"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["value"].as_str().unwrap().starts_with("bf2:"))
        .unwrap();
    assert_eq!(fp["type"], "text");
    assert_eq!(fp["to_ids"], false);

    // CSV: the #34 columns, every row says why there is no file hash.
    let csv = table::csv(&sel);
    let header: Vec<&str> = csv.lines().next().unwrap().split(',').collect();
    assert_eq!(header, table::CSV_COLUMNS);
    assert!(
        csv.lines()
            .skip(1)
            .all(|l| l.contains(table::FILE_LIMITED_NOTE))
    );
    // JSON items are #34 IOC objects.
    let j = table::json(&sel);
    let items: Vec<Ioc> = serde_json::from_value(j["items"].clone()).unwrap();
    assert_eq!(items, sel.iocs);
}

#[test]
fn file_drop_exports_the_file_and_an_unclassified_malware_instance() {
    let sel = select(
        input("iocs/file-drop.input.json", false, vec![]),
        &ExportOptions::default(),
    );
    let (b, event) = golden("file-drop", &sel);
    let files = of_type(&b, "file");
    assert_eq!(files.len(), 1);
    let mw = of_type(&b, "malware");
    assert_eq!(mw.len(), 1);
    assert_eq!(mw[0]["is_family"], false);
    assert_eq!(mw[0]["sample_refs"][0], files[0]["id"]);
    assert_eq!(
        relationship_to(&b, "malware")[0]["relationship_type"],
        "indicates"
    );
    let obj = &event["Event"]["Object"][0];
    assert_eq!(obj["name"], "file");
    assert_eq!(obj["Attribute"][0]["type"], "sha256");
}

#[test]
fn exports_are_deterministic() {
    let a = stix::bundle(&select(
        input("iocs/memory-only.input.json", false, vec![]),
        &ExportOptions::default(),
    ));
    let mut ev = events("iocs/memory-only.input.json");
    ev.reverse();
    let b = stix::bundle(&select(
        input("iocs/memory-only.input.json", false, ev),
        &ExportOptions::default(),
    ));
    assert_eq!(a, b);
}

#[test]
fn min_confidence_drops_low_links() {
    // Unreviewed (analyst) view, so links of every strength are present.
    let wide = ExportOptions {
        include_unreviewed: true,
        ..Default::default()
    };
    let base = select(input("exports/synthetic.input.json", false, vec![]), &wide);
    let scores: Vec<u8> = base
        .attempts
        .iter()
        .flat_map(|r| r.links.iter().map(|l| l.score))
        .collect();
    assert!(
        scores.iter().any(|s| *s < 30) && scores.iter().any(|s| *s >= 60),
        "{scores:?}"
    );
    let sel = select(
        input("exports/synthetic.input.json", false, vec![]),
        &ExportOptions {
            min_confidence: Some(30),
            ..wide.clone()
        },
    );
    assert!(sel.dropped.links_below_gate > base.dropped.links_below_gate);
    let b = stix::bundle(&sel);
    assert!(stix::problems(&b).is_empty());
    for r in of_type(&b, "relationship") {
        assert!(r["confidence"].as_u64().unwrap() >= 30, "{r}");
    }
    for i in of_type(&b, "indicator") {
        assert!(i["confidence"].as_u64().unwrap() >= 30, "{i}");
    }
    // T1190 (38) stays, T1071.001 (11) goes.
    let names: Vec<&str> = of_type(&b, "attack-pattern")
        .iter()
        .map(|a| a["external_references"][0]["external_id"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["T1190"]);

    // By default only publishable links leave: the CVE link, not the
    // rule-only technique links.
    let default = select(
        input("exports/synthetic.input.json", false, vec![]),
        &ExportOptions::default(),
    );
    assert!(
        default
            .attempts
            .iter()
            .flat_map(|r| &r.links)
            .all(|l| l.publishable && l.kind == LinkKind::AttemptCve)
    );
    // A threshold below publish_min never widens the default gate.
    let low = select(
        input("exports/synthetic.input.json", false, vec![]),
        &ExportOptions {
            min_confidence: Some(0),
            ..Default::default()
        },
    );
    assert_eq!(low, default);
}

#[test]
fn unreviewed_exports_are_marked_and_strict() {
    let sel = select(
        input("exports/synthetic.input.json", false, vec![]),
        &ExportOptions {
            include_unreviewed: true,
            tlp: Tlp::Clear,
            ..Default::default()
        },
    );
    assert_eq!(sel.tlp, Tlp::AmberStrict);
    let (b, _) = golden("synthetic-unreviewed", &sel);
    // Unconfirmed technique links keep "we assess as".
    let t1071 = of_type(&b, "relationship")
        .into_iter()
        .find(|r| {
            r["description"]
                .as_str()
                .unwrap()
                .starts_with("We assess as ATT&CK T1071.001 (Web Protocols).")
        })
        .expect("T1071.001 relationship");
    assert_eq!(t1071["x_foiled_publishable"], false);
    assert!(text(&b).contains("198.51.100.9"));
    assert!(
        of_type(&b, "indicator")
            .iter()
            .any(|i| i["x_foiled_publishable"] == false)
    );
    assert!(text(&misp::event(&sel, "golden|unreviewed")).contains("foiled:unreviewed"));
    // The marking survives a CSV or JSON download.
    let csv = table::csv(&sel);
    assert!(
        csv.lines()
            .skip(1)
            .all(|l| l.ends_with(",TLP:AMBER+STRICT,unreviewed"))
    );
    let j = table::json(&sel);
    assert_eq!(j["marking"], "TLP:AMBER+STRICT");
    assert_eq!(j["review"], "unreviewed");
}

fn ev(id: &str, source: EvidenceSource, weight: u8, summary: &str) -> Evidence {
    Evidence {
        signal_id: id.into(),
        source,
        weight,
        summary: summary.into(),
        reference: None,
    }
}

fn extra_link(
    kind: LinkKind,
    target: &str,
    attempt_id: &str,
    evidence: Vec<Evidence>,
) -> foiled_core::confidence::ConfidenceLink {
    score(
        &ConfidenceConfig::default(),
        kind,
        attempt_id,
        target,
        evidence,
        None,
    )
    .unwrap()
}

/// Campaign (#33) and actor (#29) links plug into the same records, with
/// evidence of the kind their producers give: cluster joins and the noise
/// score for a campaign member, an LLM proposal and shared infrastructure
/// for an actor. Neither reaches publish_min on its own; actors also need
/// the opt-in, and both keep cautious wording.
#[test]
fn campaign_and_actor_links_map_with_cautious_wording() {
    let mut inp = input("iocs/memory-only.input.json", false, vec![]);
    let aid = inp.attempts[0].attempt.attempt_id.clone();
    let actor = extra_link(
        LinkKind::AttemptActor,
        "Example Group",
        &aid,
        vec![
            ev(
                "llm:1",
                EvidenceSource::Llm,
                80,
                "LLM proposal: tooling overlaps a public report",
            ),
            ev(
                "asn:1",
                EvidenceSource::Enrichment,
                60,
                "source AS also named in the report",
            ),
        ],
    );
    assert!(!actor.publishable);
    inp.attempts[0].links.push(actor);
    let member = extra_link(
        LinkKind::AttemptCampaign,
        "cmp_000000000000000000000001",
        &aid,
        vec![
            ev(
                "join:1",
                EvidenceSource::CampaignCluster,
                70,
                "shares payload hash with another attempt",
            ),
            ev(
                "join:2",
                EvidenceSource::CampaignCluster,
                40,
                "shares request shape with another attempt",
            ),
            ev(
                "noise:1",
                EvidenceSource::NoiseScore,
                10,
                "source noise score 10",
            ),
        ],
    );
    assert!(!member.publishable);
    inp.attempts[0].links.push(member);

    // Default options: neither leaves.
    let sel = select(inp.clone(), &ExportOptions::default());
    assert_eq!(sel.dropped.actor_links, 1);
    let b = stix::bundle(&sel);
    assert!(of_type(&b, "intrusion-set").is_empty());
    assert!(of_type(&b, "campaign").is_empty());
    assert!(!text(&b).contains("cmp_000000000000000000000001"));

    // An analyst's unreviewed export with the actor opt-in shows both,
    // worded "possible".
    let sel = select(
        inp,
        &ExportOptions {
            include_actors: true,
            include_unreviewed: true,
            ..Default::default()
        },
    );
    let (b, e) = golden("memory-only-linked", &sel);
    assert_eq!(of_type(&b, "campaign").len(), 1);
    assert!(
        relationship_to(&b, "campaign")[0]["description"]
            .as_str()
            .unwrap()
            .starts_with("Possible part of campaign cmp_000000000000000000000001.")
    );
    assert_eq!(of_type(&b, "intrusion-set").len(), 1);
    let rel = &relationship_to(&b, "intrusion-set")[0];
    assert!(
        rel["description"]
            .as_str()
            .unwrap()
            .starts_with("Possible association with Example Group. This is not an attribution."),
        "{}",
        rel["description"]
    );
    assert_eq!(rel["x_foiled_wording"], "possible association");
    let ta = e["Event"]["Attribute"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["type"] == "threat-actor")
        .unwrap();
    assert!(
        ta["comment"]
            .as_str()
            .unwrap()
            .contains("Possible association with Example Group.")
    );
    assert!(!text(&e).contains("misp-galaxy:threat-actor"));
}

/// The attempt's source address only appears when its own IOC passed the
/// gate. Here the CVE link (100) passes `min_confidence` but every IOC (98)
/// does not, so the attempt is anchored on a grouping and the address is
/// never named.
#[test]
fn source_address_goes_through_the_gate() {
    let sel = select(
        input("exports/synthetic.input.json", false, vec![]),
        &ExportOptions {
            min_confidence: Some(99),
            ..Default::default()
        },
    );
    assert!(sel.iocs.is_empty());
    // A golden file too, so the vendored schema and the OASIS validator
    // cover the grouping path.
    let (b, _) = golden("synthetic-grouping", &sel);
    let all = text(&b);
    assert!(!all.contains("203.0.113.60"), "{all}");
    assert!(of_type(&b, "observed-data").is_empty());
    let g = of_type(&b, "grouping");
    assert_eq!(g.len(), 1);
    assert!(
        g[0]["x_foiled_summary"]
            .as_str()
            .unwrap()
            .contains("from an address below the export gate")
    );
    assert_eq!(
        relationship_to(&b, "vulnerability")[0]["source_ref"],
        g[0]["id"]
    );
}

/// Every object a relationship, sighting or grouping points at sorts no
/// earlier than the pointer, so `added_after` never strands a reference.
#[test]
fn referenced_objects_are_added_no_earlier_than_their_referrers() {
    let sel = select(
        input_with("exports/synthetic.input.json", true, vec![], confirm_t1190),
        &ExportOptions::default(),
    );
    let objs = stix::objects(&sel);
    let added: std::collections::BTreeMap<String, i64> =
        objs.iter().map(|o| (o.id().to_string(), o.added)).collect();
    for o in &objs {
        for r in &o.refs {
            assert!(added[r] >= o.added, "{} -> {r}", o.id());
        }
    }
    // For any added_after, what is served is closed under references.
    for o in &objs {
        let t = o.added - 1;
        let served: std::collections::BTreeSet<&str> = objs
            .iter()
            .filter(|x| x.added > t)
            .map(|x| x.id())
            .collect();
        for x in objs.iter().filter(|x| x.added > t) {
            for r in &x.refs {
                assert!(served.contains(r.as_str()), "{} -> {r} at {t}", x.id());
            }
        }
    }
}

/// MISP: one stable event per export scope; attribute uuids derived from
/// the event, so overlapping exports never share one.
#[test]
fn misp_ids_are_stable_per_scope_and_disjoint_across_scopes() {
    let sel = select(
        input("iocs/memory-only.input.json", false, vec![]),
        &ExportOptions::default(),
    );
    let a = misp::event(&sel, "scope-a");
    assert_eq!(a, misp::event(&sel, "scope-a"));
    let b = misp::event(&sel, "scope-b");
    assert_ne!(a["Event"]["uuid"], b["Event"]["uuid"]);
    let uuids = |e: &Value| -> std::collections::BTreeSet<String> {
        e["Event"]["Attribute"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["uuid"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(uuids(&a).is_disjoint(&uuids(&b)));
}
