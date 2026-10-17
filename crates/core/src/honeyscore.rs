//! Shodan Honeyscore self-check (#18): pure parsing and assessment.
//!
//! The scheduled check in the control plane fetches
//! `https://api.shodan.io/labs/honeyscore/{ip}` for each public decoy IP. That
//! fetch lives in the Worker; this module only turns the response body into a
//! verdict, so it has no network, clock or environment access and builds for
//! `wasm32-unknown-unknown`.
//!
//! The runbook, cadence and response are in `docs/fingerprint-resistance.md`.
//! The config file is `configs/honeyscore.yaml`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Threshold used when the config does not set one.
pub const DEFAULT_THRESHOLD: f64 = 0.5;

/// Name of the environment variable or Worker secret holding the Shodan key.
pub const DEFAULT_API_KEY_ENV: &str = "SHODAN_API_KEY";

/// How often each public decoy IP is checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    /// Once per public decoy IP per day.
    #[default]
    Daily,
    /// Once per public decoy IP per week, for operators with few query credits.
    Weekly,
}

/// Mirrors `configs/honeyscore.yaml`. The check is off unless an operator
/// turns it on and supplies their own Shodan key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneyscoreConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cadence: Cadence,
    /// Scores at or above this value mark the IP as burnt.
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    /// The name of the variable holding the key, never the key itself.
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
}

fn default_threshold() -> f64 {
    DEFAULT_THRESHOLD
}

fn default_api_key_env() -> String {
    DEFAULT_API_KEY_ENV.to_owned()
}

impl Default for HoneyscoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cadence: Cadence::default(),
            threshold: DEFAULT_THRESHOLD,
            api_key_env: default_api_key_env(),
        }
    }
}

impl HoneyscoreConfig {
    /// Checks that the threshold is a valid score and that `api_key_env`
    /// looks like a variable name (upper case letters, digits and `_`, not
    /// starting with a digit). The name rule also catches a pasted key, which
    /// is mixed case.
    pub fn validate(&self) -> Result<(), HoneyscoreError> {
        check_range(self.threshold).map_err(|_| HoneyscoreError::InvalidThreshold)?;
        let name = self.api_key_env.as_str();
        let valid_name = !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if valid_name {
            Ok(())
        } else {
            Err(HoneyscoreError::InvalidApiKeyEnv)
        }
    }
}

/// Outcome of comparing a score with the configured threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HoneyscoreVerdict {
    /// Below the threshold. Nothing to do.
    Ok,
    /// At or above the threshold: raise `honeyscore_high` and rotate with a
    /// new IP (`docs/rotation.md`).
    Burnt { score: f64 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum HoneyscoreError {
    /// The body was empty or only whitespace.
    Empty,
    /// Shodan returned a JSON error object instead of a score.
    Api(String),
    /// The body was not a number.
    NotANumber,
    /// The body was NaN or infinite.
    NotFinite,
    /// The number was outside `0.0..=1.0`.
    OutOfRange(f64),
    /// The configured threshold was not a finite value in `0.0..=1.0`.
    InvalidThreshold,
    /// `api_key_env` was not a valid environment variable name.
    InvalidApiKeyEnv,
}

impl fmt::Display for HoneyscoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty Honeyscore response"),
            Self::Api(msg) => write!(f, "Shodan API error: {msg}"),
            Self::NotANumber => write!(f, "Honeyscore response is not a number"),
            Self::NotFinite => write!(f, "Honeyscore response is not a finite number"),
            Self::OutOfRange(v) => write!(f, "Honeyscore {v} is outside 0.0..=1.0"),
            Self::InvalidThreshold => write!(f, "threshold must be a number in 0.0..=1.0"),
            Self::InvalidApiKeyEnv => {
                write!(f, "api_key_env must be an environment variable name")
            }
        }
    }
}

impl std::error::Error for HoneyscoreError {}

fn check_range(value: f64) -> Result<f64, HoneyscoreError> {
    if !value.is_finite() {
        Err(HoneyscoreError::NotFinite)
    } else if !(0.0..=1.0).contains(&value) {
        Err(HoneyscoreError::OutOfRange(value))
    } else {
        Ok(value)
    }
}

/// Parses the body of `GET /labs/honeyscore/{ip}`. Success is a bare number
/// such as `0.3`, optionally with surrounding whitespace. Errors come back as
/// a JSON object like `{"error": "..."}`.
pub fn parse_response(body: &str) -> Result<f64, HoneyscoreError> {
    let body = body.trim();
    if body.is_empty() {
        return Err(HoneyscoreError::Empty);
    }
    if body.starts_with('{') {
        let message = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(str::to_owned));
        return Err(message.map_or(HoneyscoreError::NotANumber, HoneyscoreError::Api));
    }
    let value: f64 = body.parse().map_err(|_| HoneyscoreError::NotANumber)?;
    check_range(value)
}

/// Compares a parsed score with the threshold. A score equal to the threshold
/// counts as burnt. Both values are expected to have passed
/// [`parse_response`] and [`HoneyscoreConfig::validate`].
pub fn assess(score: f64, threshold: f64) -> HoneyscoreVerdict {
    if score >= threshold {
        HoneyscoreVerdict::Burnt { score }
    } else {
        HoneyscoreVerdict::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_bare_scores() {
        assert_eq!(parse_response("0.3"), Ok(0.3));
        assert_eq!(parse_response("0.0"), Ok(0.0));
        assert_eq!(parse_response("1.0"), Ok(1.0));
        assert_eq!(parse_response("1"), Ok(1.0));
        assert_eq!(parse_response(" 0.5\n"), Ok(0.5));
    }

    #[test]
    fn rejects_empty_bodies() {
        assert_eq!(parse_response(""), Err(HoneyscoreError::Empty));
        assert_eq!(parse_response(" \r\n\t"), Err(HoneyscoreError::Empty));
    }

    #[test]
    fn rejects_non_numbers() {
        for body in [
            "abc",
            "0.3.1",
            "0,3",
            "\"0.3\"",
            "[0.3]",
            "<html>",
            "{not json",
        ] {
            assert_eq!(
                parse_response(body),
                Err(HoneyscoreError::NotANumber),
                "{body}"
            );
        }
    }

    #[test]
    fn surfaces_api_errors() {
        assert_eq!(
            parse_response(r#"{"error": "Invalid API key"}"#),
            Err(HoneyscoreError::Api("Invalid API key".to_owned()))
        );
        assert_eq!(
            parse_response(r#"{"message": "x"}"#),
            Err(HoneyscoreError::NotANumber)
        );
    }

    #[test]
    fn rejects_non_finite_values() {
        for body in ["NaN", "nan", "inf", "-inf", "infinity"] {
            assert_eq!(
                parse_response(body),
                Err(HoneyscoreError::NotFinite),
                "{body}"
            );
        }
    }

    #[test]
    fn rejects_scores_out_of_range() {
        assert_eq!(
            parse_response("-0.1"),
            Err(HoneyscoreError::OutOfRange(-0.1))
        );
        assert_eq!(
            parse_response("1.0000001"),
            Err(HoneyscoreError::OutOfRange(1.0000001))
        );
        assert_eq!(parse_response("42"), Err(HoneyscoreError::OutOfRange(42.0)));
    }

    #[test]
    fn threshold_edge_is_burnt() {
        assert_eq!(assess(0.5, 0.5), HoneyscoreVerdict::Burnt { score: 0.5 });
        assert_eq!(assess(0.49, 0.5), HoneyscoreVerdict::Ok);
        assert_eq!(assess(0.51, 0.5), HoneyscoreVerdict::Burnt { score: 0.51 });
        assert_eq!(assess(0.0, 0.5), HoneyscoreVerdict::Ok);
        assert_eq!(assess(1.0, 1.0), HoneyscoreVerdict::Burnt { score: 1.0 });
        assert_eq!(assess(0.0, 0.0), HoneyscoreVerdict::Burnt { score: 0.0 });
    }

    #[test]
    fn parse_then_assess() {
        let score = parse_response("0.3").unwrap();
        assert_eq!(assess(score, DEFAULT_THRESHOLD), HoneyscoreVerdict::Ok);
        let score = parse_response("0.5").unwrap();
        assert_eq!(
            assess(score, DEFAULT_THRESHOLD),
            HoneyscoreVerdict::Burnt { score: 0.5 }
        );
    }

    #[test]
    fn config_defaults_to_disabled() {
        let cfg: HoneyscoreConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(cfg, HoneyscoreConfig::default());
        assert!(!cfg.enabled);
        assert_eq!(cfg.cadence, Cadence::Daily);
        assert_eq!(cfg.threshold, 0.5);
        assert_eq!(cfg.api_key_env, "SHODAN_API_KEY");
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn config_reads_all_fields() {
        let cfg: HoneyscoreConfig = serde_json::from_value(json!({
            "enabled": true,
            "cadence": "weekly",
            "threshold": 0.7,
            "api_key_env": "FOILED_SHODAN_KEY"
        }))
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.cadence, Cadence::Weekly);
        assert_eq!(cfg.threshold, 0.7);
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn config_rejects_unknown_fields_and_cadences() {
        assert!(serde_json::from_value::<HoneyscoreConfig>(json!({"api_key": "x"})).is_err());
        assert!(serde_json::from_value::<HoneyscoreConfig>(json!({"cadence": "hourly"})).is_err());
    }

    #[test]
    fn config_validate_rejects_bad_threshold() {
        for threshold in [-0.1, 1.1, f64::NAN, f64::INFINITY] {
            let cfg = HoneyscoreConfig {
                threshold,
                ..HoneyscoreConfig::default()
            };
            assert_eq!(
                cfg.validate(),
                Err(HoneyscoreError::InvalidThreshold),
                "{threshold}"
            );
        }
    }

    #[test]
    fn config_validate_rejects_bad_env_names() {
        for name in [
            "",
            "shodan_api_key",
            "1SHODAN",
            "SHODAN-KEY",
            "Ab3dEf9hIjKlMnOp",
        ] {
            let cfg = HoneyscoreConfig {
                api_key_env: name.to_owned(),
                ..HoneyscoreConfig::default()
            };
            assert_eq!(
                cfg.validate(),
                Err(HoneyscoreError::InvalidApiKeyEnv),
                "{name}"
            );
        }
    }
}
