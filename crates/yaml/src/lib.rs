//! The one YAML reader every Foiled crate uses.
//!
//! Wraps [`serde_saphyr`], a pure-Rust parser with no `unsafe` C port behind it
//! (it replaced `serde_yaml_ng`, whose `unsafe-libyaml` backend is unmaintained,
//! RUSTSEC-2024-0449). The options below are pinned so that every repo YAML file
//! deserialises exactly as it did under `serde_yaml_ng`:
//!
//! - `strict_booleans`: only `true` and `false` are booleans (YAML 1.2 core
//!   schema). Without it `on`, `off`, `yes` and `no` would turn into booleans,
//!   which changes values such as `research_sensors_default: on`.
//! - `merge_keys: AsOrdinary`: `<<` is an ordinary key, not a YAML 1.1 merge.
//! - `non_finite_float_policy: PassThrough`: `.inf` and `.nan` read into an
//!   untyped value become JSON `null`, as before, instead of an error.
//! - `with_snippet: false`: errors stay one line ("... at line L column C") and
//!   never echo the input back, which matters for config files with secrets.
//!
//! Known differences, none of which occur in the repo's YAML (checked file by
//! file against `serde_yaml_ng` when this crate was added):
//!
//! - duplicate mapping keys are an error (the parser's default); `serde_yaml_ng`
//!   let the last one win when reading into a map;
//! - into an untyped value, `012`, `08` and `00` read as floats, `1_000` and
//!   `0X10` as integers, where `serde_yaml_ng` kept them as strings (typed
//!   `String` fields still get the text as written). Quote such values;
//! - unknown tags such as `!foo bar` are ignored rather than rejected.

use serde::de::DeserializeOwned;
use serde_saphyr::{MergeKeyPolicy, NonFiniteFloatPolicy, Options};

pub use serde_saphyr::Error;

/// Parser options shared by every Foiled YAML read. See the crate docs.
pub fn options() -> Options {
    serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: MergeKeyPolicy::AsOrdinary,
        non_finite_float_policy: NonFiniteFloatPolicy::PassThrough,
        with_snippet: false,
    }
}

/// Deserialises one YAML document.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_saphyr::from_str_with_options(text, options())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    fn parse(text: &str) -> Value {
        super::from_str(text).unwrap()
    }

    #[test]
    fn only_true_and_false_are_booleans() {
        assert_eq!(
            parse("a: on\nb: off\nc: yes\nd: No\ne: true\nf: false\n"),
            json!({"a": "on", "b": "off", "c": "yes", "d": "No", "e": true, "f": false})
        );
    }

    #[test]
    fn numbers_and_nulls_follow_the_core_schema() {
        assert_eq!(
            parse(
                "a: 0x10\nb: 0o17\nc: +12\nd: 1e3\ne: ~\nf: null\ng:\nh: 2024-01-01\ni: '1'\nj: .inf\n"
            ),
            json!({"a": 16, "b": 15, "c": 12, "d": 1000.0, "e": null, "f": null, "g": null,
                   "h": "2024-01-01", "i": "1", "j": null})
        );
    }

    #[test]
    fn typed_string_fields_keep_the_text() {
        #[derive(serde::Deserialize)]
        struct S {
            a: String,
            b: String,
            c: String,
        }
        let s: S = super::from_str("a: 012\nb: on\nc: 1_000\n").unwrap();
        assert_eq!(
            (s.a.as_str(), s.b.as_str(), s.c.as_str()),
            ("012", "on", "1_000")
        );
    }

    #[test]
    fn merge_keys_are_ordinary_keys() {
        assert_eq!(
            parse("x: &x {a: 1}\ny:\n  <<: *x\n  b: 2\n"),
            json!({"x": {"a": 1}, "y": {"<<": {"a": 1}, "b": 2}})
        );
    }

    #[test]
    fn errors_are_single_line_and_do_not_echo_input() {
        let err = super::from_str::<Value>("secret: hunter2\nb: [1, 2\n").unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains('\n'), "{msg}");
        assert!(!msg.contains("hunter2"), "{msg}");
    }

    #[test]
    fn duplicate_keys_and_multiple_documents_are_rejected() {
        assert!(super::from_str::<Value>("a: 1\na: 2\n").is_err());
        assert!(super::from_str::<Value>("a: 1\n---\nb: 2\n").is_err());
    }
}
