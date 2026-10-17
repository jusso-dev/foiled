//! Checks `configs/alerting.yaml`, `schemas/alerting-config.schema.json`,
//! `schemas/alert.schema.json` and `testdata/alerts/` against the Rust types
//! in foiled-core (#15).

use std::path::{Path, PathBuf};

use foiled_core::alerting::{
    Alert, AlertType, AlertingConfig, Decision, RouteKind, Router, Severity,
};
use serde_json::{Value, json};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn validator(schema: &str) -> jsonschema::Validator {
    let schema = foiled_lint::load(&root().join(schema)).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn shipped_config() -> Value {
    foiled_lint::load(&root().join("configs/alerting.yaml")).unwrap()
}

#[test]
fn shipped_config_parses_validates_and_holds_no_secrets() {
    let value = shipped_config();
    assert!(validator("schemas/alerting-config.schema.json").is_valid(&value));
    let cfg: AlertingConfig = serde_json::from_value(value).unwrap();
    cfg.validate().unwrap();
    assert!(cfg.review_queue_for_medium);
    // Only the log sink is on out of the box; paging routes need secrets.
    let enabled: Vec<_> = cfg.routes.iter().filter(|r| r.enabled).collect();
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0].kind, RouteKind::Log);
    for kind in [
        RouteKind::Webhook,
        RouteKind::SlackWebhook,
        RouteKind::Email,
    ] {
        assert!(cfg.routes.iter().any(|r| r.kind == kind), "{kind:?}");
    }
    let text = std::fs::read_to_string(root().join("configs/alerting.yaml")).unwrap();
    for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
        assert!(
            !line.contains("hooks."),
            "no webhook URLs in config: {line}"
        );
        assert!(!line.contains("@"), "no addresses or credentials: {line}");
    }
    // Round trip through the core type still matches the schema.
    assert!(
        validator("schemas/alerting-config.schema.json")
            .is_valid(&serde_json::to_value(&cfg).unwrap())
    );
    // A router can be built from it.
    Router::new(cfg, 0).unwrap();
}

#[test]
fn config_schema_rejects_bad_configs() {
    let v = validator("schemas/alerting-config.schema.json");
    let good = shipped_config();
    assert!(v.is_valid(&good));

    let mut url_in_config = good.clone();
    url_in_config["routes"][1]["url_env"] = json!("https://hooks.example.com/services/T0/B0/X");
    let mut no_log = good.clone();
    no_log["routes"] = json!([good["routes"][1].clone()]);
    let mut email_on = good.clone();
    email_on["routes"][3]["enabled"] = json!(true);
    let mut unsigned = good.clone();
    unsigned["routes"][1]
        .as_object_mut()
        .unwrap()
        .remove("signing_secret_env");
    let mut sms = good.clone();
    sms["routes"][1]["kind"] = json!("sms");
    let mut unknown_type = good.clone();
    unknown_type["severity_overrides"]["every_connection"] = json!("high");
    let mut short_window = good.clone();
    short_window["dedupe"]["windows"]["vuln_path_hook_fired"] = json!(5);
    let mut zero_burst = good.clone();
    zero_burst["type_limits"]["vuln_path_hook_fired"]["burst"] = json!(0);
    for bad in [
        url_in_config,
        no_log,
        email_on,
        unsigned,
        sms,
        unknown_type,
        short_window,
        zero_burst,
    ] {
        assert!(!v.is_valid(&bad), "{bad}");
    }
}

#[test]
fn alert_fixtures_parse_validate_and_cover_the_issue_types() {
    let v = validator("schemas/alert.schema.json");
    let dir = root().join("testdata/alerts");
    let mut types = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let value = foiled_lint::load(&path).unwrap();
        assert!(v.is_valid(&value), "{}", path.display());
        let alert: Alert = serde_json::from_value(value.clone()).unwrap();
        alert.validate().unwrap();
        assert_eq!(serde_json::to_value(&alert).unwrap(), value);
        types.push(alert.alert_type);
    }
    for t in [
        AlertType::VulnPathHookFired,
        AlertType::CveAssessed,
        AlertType::PredisclosureSpike,
        AlertType::CampaignUpdated,
        AlertType::EdgeSensorOffline,
        AlertType::ReviewQueueItem,
        AlertType::DecoyCompromised,
        AlertType::CanaryUsed,
        AlertType::YaraMatch,
        AlertType::HoneyscoreHigh,
        AlertType::CaptureDiskPressure,
        AlertType::RotationFailed,
        AlertType::HostOffline,
    ] {
        assert!(types.contains(&t), "missing fixture for {t}");
    }
}

#[test]
fn alert_schema_requires_links_on_critical_alerts() {
    let v = validator("schemas/alert.schema.json");
    let mut value =
        foiled_lint::load(&root().join("testdata/alerts/rotation-failed.json")).unwrap();
    assert!(v.is_valid(&value));
    value["links"] = json!([{ "kind": "decoy", "href": "/decoys/dcy-demo-1" }]);
    assert!(!v.is_valid(&value));
    let mut sms = foiled_lint::load(&root().join("testdata/alerts/host-offline.json")).unwrap();
    sms["type"] = json!("connection_seen");
    assert!(!v.is_valid(&sms));
}

#[test]
fn shipped_config_routes_fixtures_as_documented() {
    let mut cfg: AlertingConfig = serde_json::from_value(shipped_config()).unwrap();
    // Turn the paging routes on, as an operator would once secrets exist.
    for r in &mut cfg.routes {
        if r.kind != RouteKind::Email {
            r.enabled = true;
        }
    }
    let mut router = Router::new(cfg, 0).unwrap();
    let load = |name: &str| -> Alert {
        serde_json::from_value(
            foiled_lint::load(&root().join("testdata/alerts").join(name)).unwrap(),
        )
        .unwrap()
    };
    let mut canary = load("canary-used.json");
    assert_eq!(canary.severity, Severity::Critical);
    assert_eq!(
        router.route(&mut canary, 1_792_285_323_000),
        Decision::Send(vec!["log".into(), "ops-webhook".into(), "slack-ops".into()])
    );
    let mut campaign = load("campaign-updated.json");
    assert_eq!(
        router.route(&mut campaign, 1_792_285_323_000),
        Decision::ToReviewQueue
    );
    let mut disk = load("capture-disk-pressure.json");
    assert_eq!(
        router.route(&mut disk, 1_792_285_323_000),
        Decision::Send(vec!["log".into(), "ops-webhook".into()])
    );
}
