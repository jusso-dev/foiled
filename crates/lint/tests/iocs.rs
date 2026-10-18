//! Golden test for IOC extraction (#34): each `testdata/iocs/*.input.json`
//! is grouped into attempts (#25), enriched with the fake ASN table (#11)
//! and extracted. The IOCs must match `testdata/iocs/expected/`, one file
//! per IOC, which the repository lint also validates against
//! `schemas/ioc.schema.json`.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::path::Path;

use foiled_core::attempt::{DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
use foiled_core::capture::CaptureEvent;
use foiled_core::confidence::ConfidenceConfig;
use foiled_core::enrichment::{AsnTable, Provider, enrich_all};
use foiled_core::ioc::{
    ExtractOptions, Extraction, Ioc, IocType, address_observables, apply_enrichment, extract,
};

const NOW: i64 = 1_792_285_700_000;

fn load(root: &Path, name: &str) -> (Vec<foiled_core::attempt::Attempt>, Extraction) {
    let raw: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(format!("{name}.input.json"))).unwrap(),
    )
    .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    for e in &events {
        assert!(e.problems(NOW).is_empty(), "{}", e.event_id);
    }
    let attempts = build(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
    let mut x = extract(
        &attempts,
        &events,
        &ConfidenceConfig::default(),
        ExtractOptions::default(),
    );
    let asn =
        AsnTable::from_csv(&std::fs::read_to_string(root.join("../enrichment/asn.csv")).unwrap())
            .unwrap();
    let providers: [&dyn Provider; 1] = [&asn];
    let run = enrich_all(&providers, &address_observables(&x.iocs), NOW);
    apply_enrichment(&mut x.iocs, &run.facts);
    (attempts, x)
}

fn check_golden(root: &Path, name: &str, iocs: &[Ioc]) {
    let dir = root.join("expected");
    let prefix = format!("{name}-");
    if std::env::var("FOILED_BLESS").is_ok() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&prefix)
            {
                std::fs::remove_file(p).unwrap();
            }
        }
        for (i, ioc) in iocs.iter().enumerate() {
            let path = dir.join(format!("{name}-{i:02}.json"));
            std::fs::write(path, serde_json::to_string_pretty(ioc).unwrap() + "\n").unwrap();
        }
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&prefix)
        })
        .collect();
    files.sort();
    let expected: Vec<Ioc> = files
        .iter()
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    assert_eq!(iocs, expected.as_slice(), "{name}");
}

fn of(x: &Extraction, ty: IocType) -> Vec<&Ioc> {
    x.iocs.iter().filter(|i| i.ioc_type == ty).collect()
}

#[test]
fn memory_only_attempt_matches_golden_and_has_no_file_hash() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/iocs");
    let (attempts, x) = load(&root, "memory-only");
    check_golden(&root, "memory-only", &x.iocs);

    // #34 validation: IP with ASN, UA, domain and URL, a behaviour
    // fingerprint, and no file hash.
    assert_eq!(attempts.len(), 1);
    let summary = x.for_attempt(&attempts[0].attempt_id).unwrap();
    assert!(summary.file_ioc_limited);
    assert!(of(&x, IocType::FileSha256).is_empty());

    let ip = of(&x, IocType::Ip);
    let src = ip.iter().find(|i| i.value == "203.0.113.50").unwrap();
    assert!(
        src.enrichment
            .iter()
            .any(|e| e.key == "asn.number" && e.value == 64498)
    );
    assert!(ip.iter().any(|i| i.value == "192.0.2.80"));
    assert!(!x.iocs.iter().any(|i| i.value.starts_with("10.")));

    let ua = of(&x, IocType::HttpUa);
    assert_eq!(ua.len(), 1);
    assert_eq!(ua[0].value, "demo-loader/0.1 (REDACTED@example.invalid)");
    assert!(ua[0].redacted);

    let domains: Vec<&str> = of(&x, IocType::Domain)
        .iter()
        .map(|i| i.value.as_str())
        .collect();
    assert!(domains.contains(&"stage2.example.invalid"));
    assert!(domains.contains(&"k7f3q9.cb.example.invalid"));
    assert_eq!(of(&x, IocType::DnsQuery).len(), 2);
    let url = of(&x, IocType::Url);
    assert_eq!(url.len(), 1);
    assert_eq!(url[0].value, "http://stage2.example.invalid/m.sh");

    let bf = of(&x, IocType::BehaviourFingerprint);
    assert_eq!(bf.len(), 1);
    assert!(bf[0].value.starts_with("bf1:"));
    assert_eq!(of(&x, IocType::Cmdline).len(), 1);
    assert!(x.iocs.iter().all(|i| i.file_ioc_limited));
    let upload = of(&x, IocType::HttpPath)
        .into_iter()
        .find(|p| p.value.starts_with("/api/upload"))
        .unwrap();
    assert!(upload.value.ends_with("&token=REDACTED"));
    assert!(upload.redacted);
}

#[test]
fn file_drop_attempts_match_golden() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/iocs");
    let (attempts, x) = load(&root, "file-drop");
    check_golden(&root, "file-drop", &x.iocs);

    assert_eq!(attempts.len(), 3);
    assert!(x.attempts.iter().all(|a| !a.file_ioc_limited));
    assert_eq!(
        of(&x, IocType::FileSha256)[0].value,
        "c1c5d1b2f75673adc7db8fbf8bf1ab10f405dac8e71ce3cb8d7d0fef7fdeb172"
    );
    assert_eq!(of(&x, IocType::Ipv6)[0].value, "2001:db8:1::25");
    assert_eq!(
        of(&x, IocType::RequestSubstring)[0].value,
        "CONFIG SET dir /var/spool/cron"
    );
    assert_eq!(of(&x, IocType::Cmdline)[0].value, "/bin/chmod +x /tmp/x.sh");
}

#[test]
fn golden_files_cover_every_ioc_type() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/iocs");
    let mut seen = std::collections::BTreeSet::new();
    for name in ["memory-only", "file-drop"] {
        let (_, x) = load(&root, name);
        seen.extend(x.iocs.iter().map(|i| i.ioc_type));
    }
    for t in IocType::ALL {
        assert!(seen.contains(&t), "no golden IOC of type {}", t.as_str());
    }
}
