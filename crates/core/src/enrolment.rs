//! Enrolment of edge sensors and sandbox hosts (#31, ADR 0007).
//!
//! An operator registers a sensor (or host) and gets a one-time enrolment
//! token. The sensor generates its own key pair, never sends the private
//! key anywhere, and redeems the token with a certificate signing request.
//! The control plane has the CSR signed by the Cloudflare-managed client CA
//! and records the certificate's SHA-256 fingerprint against the sensor id,
//! its role and its tenant. From then on the fingerprint is the identity:
//! nothing the sensor sends can change its id, role, tenant or scopes.
//!
//! Everything here is pure so it runs in the Worker and in `foiled-hostd`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{Role, Scope};
use crate::decoy::Reason;

/// Enrolment tokens look like `foe_<id>.<secret>`. The prefix differs from
/// API tokens (`fo_`), so neither can be mistaken for the other.
pub const ENROLMENT_TOKEN_PREFIX: &str = "foe_";
/// Default enrolment token lifetime: one hour.
pub const DEFAULT_ENROLMENT_TTL_MS: i64 = 60 * 60 * 1000;
/// Shortest and longest lifetime an operator may ask for.
pub const MIN_ENROLMENT_TTL_MS: i64 = 5 * 60 * 1000;
pub const MAX_ENROLMENT_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Client certificate lifetime requested from the CA.
pub const DEFAULT_CERT_VALIDITY_DAYS: u32 = 90;
/// After a renewal the previous certificate keeps working this long, so a
/// sensor that lost the renewal response can retry with its old key.
pub const RENEWAL_GRACE_MS: i64 = 24 * 60 * 60 * 1000;
/// Largest CSR accepted. A P-256 or RSA-4096 CSR is well under this.
pub const MAX_CSR_BYTES: usize = 8 * 1024;
/// Default offline buffer cap for an edge sensor. Research hosts use 1 GiB.
pub const SENSOR_BUFFER_BYTES: u64 = 256 * 1024 * 1024;
/// Default offline buffer cap for a sandbox host (#41).
pub const HOST_BUFFER_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// Registered; the enrolment token has not been redeemed yet.
    Pending,
    /// Holds at least one live certificate.
    Active,
    /// Revoked. Final: a revoked identity is never re-activated.
    Revoked,
}

impl AgentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentStatus::Pending => "pending",
            AgentStatus::Active => "active",
            AgentStatus::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            AgentStatus::Pending,
            AgentStatus::Active,
            AgentStatus::Revoked,
        ]
        .into_iter()
        .find(|x| x.as_str() == s)
    }
}

/// A registered edge sensor or sandbox host, as returned by `/v0/sensors`
/// and `/v0/hosts`. Contract: `schemas/agent/agent-record.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRecord {
    pub id: String,
    pub tenant_id: String,
    /// `host` or `sensor`.
    pub role: Role,
    pub label: Option<String>,
    pub status: AgentStatus,
    /// Edge sensors run emulations by default. Full sandboxes are heavy and
    /// need this set by the tenant admin (ADR 0007).
    pub sandbox_allowed: bool,
    /// Contribute-back choice (#37); `None` means the policy default.
    pub share_opt_in: Option<bool>,
    pub created_at: i64,
    pub created_by: String,
    pub enrolled_at: Option<i64>,
    /// Fingerprint of the newest certificate.
    pub cert_sha256: Option<String>,
    pub cert_expires_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub last_ip: Option<String>,
    pub last_asn: Option<u32>,
    /// Set when the sensor's network moved unexpectedly (IP or ASN jump).
    pub network_changed_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<Reason>,
}

/// `POST /v0/enrol`. Sent once, by the sensor, before it has a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolRequest {
    pub token: String,
    /// PEM `CERTIFICATE REQUEST` for a key generated on the sensor.
    pub csr_pem: String,
}

/// `POST /v0/{sensors|hosts}/{id}/certificate:renew`, over mTLS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    pub csr_pem: String,
}

/// The identity the control plane bound to the new certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolResponse {
    pub agent_id: String,
    pub tenant_id: String,
    pub role: Role,
    pub scopes: Vec<Scope>,
    pub certificate_pem: String,
    pub cert_sha256: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Split `foe_<id>.<secret>` into its parts.
pub fn parse_enrolment_token(raw: &str) -> Option<(&str, &str)> {
    let rest = raw.trim().strip_prefix(ENROLMENT_TOKEN_PREFIX)?;
    let (id, secret) = rest.split_once('.')?;
    let ok =
        |s: &str| !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric());
    (ok(id) && ok(secret) && secret.len() >= 32).then_some((id, secret))
}

fn b64_value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Standard base64 with padding. Whitespace is ignored.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for (i, chunk) in clean.chunks(4).enumerate() {
        let last = i == clean.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &b in &chunk[..4 - pad] {
            n = (n << 6) | b64_value(b)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// The DER bodies of every PEM block with this label, in order. Returns
/// `None` if any block with the label is malformed.
pub fn pem_blocks(text: &str, label: &str) -> Option<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let stop = after.find(&end)?;
        out.push(base64_decode(&after[..stop])?);
        rest = &after[stop + end.len()..];
    }
    Some(out)
}

/// Why a CSR is refused before it is sent to the CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsrProblem {
    TooLarge,
    /// The text holds a private key. It must never leave the sensor.
    ContainsPrivateKey,
    NotOneRequest,
    NotDer,
}

impl std::fmt::Display for CsrProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsrProblem::TooLarge => write!(f, "csr_pem is larger than {MAX_CSR_BYTES} bytes"),
            CsrProblem::ContainsPrivateKey => write!(
                f,
                "csr_pem contains a private key; send only the certificate request"
            ),
            CsrProblem::NotOneRequest => {
                write!(f, "csr_pem must hold exactly one CERTIFICATE REQUEST block")
            }
            CsrProblem::NotDer => write!(f, "csr_pem is not a DER certificate request"),
        }
    }
}

/// Shape checks only: the CA parses and verifies the request itself. The
/// CSR's subject is ignored; identity comes from the enrolment token.
pub fn csr_problem(pem: &str) -> Option<CsrProblem> {
    if pem.len() > MAX_CSR_BYTES {
        return Some(CsrProblem::TooLarge);
    }
    if pem.contains("PRIVATE KEY") {
        return Some(CsrProblem::ContainsPrivateKey);
    }
    let blocks = match pem_blocks(pem, "CERTIFICATE REQUEST") {
        Some(b) => b,
        None => return Some(CsrProblem::NotDer),
    };
    if blocks.len() != 1 || pem.matches("-----BEGIN ").count() != 1 {
        return Some(CsrProblem::NotOneRequest);
    }
    // A DER SEQUENCE with a long-form length: every real CSR starts 0x30 0x82.
    let der = &blocks[0];
    if der.len() < 64 || der[0] != 0x30 {
        return Some(CsrProblem::NotDer);
    }
    None
}

/// Lowercase hex SHA-256 over the DER of the first certificate in `pem`.
/// This is the value Cloudflare reports as `certFingerprintSHA256`.
pub fn cert_fingerprint(pem: &str) -> Option<String> {
    let blocks = pem_blocks(pem, "CERTIFICATE")?;
    let der = blocks.first()?;
    Some(hex::encode(Sha256::digest(der)))
}

/// Whether a certificate should be renewed: two thirds of its life used,
/// or already expired.
pub fn renew_due(issued_at: i64, expires_at: i64, now: i64) -> bool {
    let life = (expires_at - issued_at).max(0);
    now >= issued_at + life * 2 / 3
}

/// Where a request came from, as seen by Cloudflare.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeenFrom {
    pub ip: Option<String>,
    pub asn: Option<u32>,
}

/// Whether a sensor's network moved in a way worth flagging. A change of
/// ASN is the signal when both sides are known. Without ASNs, a move out of
/// the same IPv4 /16 or IPv6 /32 counts. A first sighting is never a jump.
pub fn network_changed(prev: &SeenFrom, now: &SeenFrom) -> bool {
    if let (Some(a), Some(b)) = (prev.asn, now.asn) {
        return a != b;
    }
    let (Some(a), Some(b)) = (prev.ip.as_deref(), now.ip.as_deref()) else {
        return false;
    };
    use std::net::IpAddr;
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => a.octets()[..2] != b.octets()[..2],
        (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => a.segments()[..2] != b.segments()[..2],
        (Ok(_), Ok(_)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid CSR body: a DER SEQUENCE of 70 bytes.
    fn csr_pem() -> String {
        let mut der = vec![0x30, 0x82, 0x00, 0x42];
        der.extend(std::iter::repeat_n(0x01, 66));
        format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
            encode(&der)
        )
    }

    fn encode(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn enrolment_tokens_parse_strictly() {
        let secret = "s".repeat(32);
        assert_eq!(
            parse_enrolment_token(&format!("foe_abc.{secret}")),
            Some(("abc", secret.as_str()))
        );
        assert_eq!(parse_enrolment_token(&format!("fo_abc.{secret}")), None);
        assert_eq!(parse_enrolment_token("foe_abc.short"), None);
        assert_eq!(parse_enrolment_token(&format!("foe_a-b.{secret}")), None);
        assert_eq!(parse_enrolment_token(&format!("foe_.{secret}")), None);
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (want, input) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_decode(input).unwrap(), want.as_bytes());
            assert_eq!(encode(want.as_bytes()), input);
        }
        assert_eq!(base64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
        for bad in ["Zg=", "Z===", "Zg==Zm9v", "Zm9*"] {
            assert!(base64_decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn csr_shape_checks() {
        assert_eq!(csr_problem(&csr_pem()), None);
        let with_key = format!(
            "{}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            csr_pem()
        );
        assert_eq!(csr_problem(&with_key), Some(CsrProblem::ContainsPrivateKey));
        assert_eq!(
            csr_problem(&format!("{}{}", csr_pem(), csr_pem())),
            Some(CsrProblem::NotOneRequest)
        );
        assert_eq!(csr_problem("hello"), Some(CsrProblem::NotOneRequest));
        assert_eq!(
            csr_problem(&"x".repeat(MAX_CSR_BYTES + 1)),
            Some(CsrProblem::TooLarge)
        );
        let short = "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----";
        assert_eq!(csr_problem(short), Some(CsrProblem::NotDer));
        let broken = "-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----";
        assert_eq!(csr_problem(broken), Some(CsrProblem::NotDer));
    }

    #[test]
    fn fingerprint_is_sha256_of_the_der() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        assert_eq!(
            cert_fingerprint(pem).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(cert_fingerprint("no pem here"), None);
    }

    #[test]
    fn renewal_is_due_at_two_thirds() {
        assert!(!renew_due(0, 90, 59));
        assert!(renew_due(0, 90, 60));
        assert!(renew_due(0, 90, 1000));
    }

    #[test]
    fn network_jumps() {
        let seen = |ip: &str, asn: Option<u32>| SeenFrom {
            ip: Some(ip.into()),
            asn,
        };
        assert!(!network_changed(
            &SeenFrom::default(),
            &seen("192.0.2.1", Some(1))
        ));
        assert!(!network_changed(
            &seen("192.0.2.1", Some(64500)),
            &seen("198.51.100.9", Some(64500))
        ));
        assert!(network_changed(
            &seen("192.0.2.1", Some(64500)),
            &seen("192.0.2.2", Some(64501))
        ));
        assert!(!network_changed(
            &seen("192.0.2.1", None),
            &seen("192.0.200.7", None)
        ));
        assert!(network_changed(
            &seen("192.0.2.1", None),
            &seen("203.0.113.7", None)
        ));
        assert!(network_changed(
            &seen("192.0.2.1", None),
            &seen("2001:db8::1", None)
        ));
        assert!(!network_changed(
            &seen("2001:db8:1::1", None),
            &seen("2001:db8:2::1", None)
        ));
    }

    #[test]
    fn fixtures_parse_into_the_rust_types() {
        for text in [
            include_str!("../../../testdata/agent/registry/sensor-active.json"),
            include_str!("../../../testdata/agent/registry/sensor-revoked.json"),
            include_str!("../../../testdata/agent/registry/host-pending.json"),
        ] {
            let a: AgentRecord = serde_json::from_str(text).unwrap();
            assert_eq!(a.status == AgentStatus::Revoked, a.revoke_reason.is_some());
        }
        let req: EnrolRequest = serde_json::from_str(include_str!(
            "../../../testdata/agent/enrol/requests/sensor.json"
        ))
        .unwrap();
        assert!(parse_enrolment_token(&req.token).is_some());
        assert_eq!(csr_problem(&req.csr_pem), None, "a real P-256 CSR passes");
        let res: EnrolResponse = serde_json::from_str(include_str!(
            "../../../testdata/agent/enrol/responses/sensor.json"
        ))
        .unwrap();
        assert_eq!(
            cert_fingerprint(&res.certificate_pem).as_deref(),
            Some(res.cert_sha256.as_str()),
            "fingerprint matches openssl's DER SHA-256"
        );
        assert_eq!(res.scopes, crate::auth::agent_scopes(res.role));
    }

    #[test]
    fn statuses_round_trip() {
        for s in [
            AgentStatus::Pending,
            AgentStatus::Active,
            AgentStatus::Revoked,
        ] {
            assert_eq!(AgentStatus::parse(s.as_str()), Some(s));
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::json!(s.as_str())
            );
        }
    }
}
