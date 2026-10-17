//! Control plane to host agent protocol (#41, `docs/agent/protocol.md`).
//!
//! The control plane signs every job with an Ed25519 key held as a Worker
//! secret. The host agent pins the public key and refuses anything it cannot
//! verify. The signature covers the exact bytes of `body` (a JSON string),
//! so there is no canonicalisation step to get wrong.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::catalogue::{DecoyKind, ListenPort};
use crate::decoy::{DecoyState, Reason};

/// Fixed job types. The agent never takes free-form commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobKind {
    #[serde(rename = "decoy.create")]
    DecoyCreate,
    #[serde(rename = "decoy.start")]
    DecoyStart,
    #[serde(rename = "decoy.stop")]
    DecoyStop,
    #[serde(rename = "decoy.rotate")]
    DecoyRotate,
    #[serde(rename = "decoy.reset")]
    DecoyReset,
    #[serde(rename = "decoy.mark_compromised")]
    DecoyMarkCompromised,
    #[serde(rename = "decoy.destroy")]
    DecoyDestroy,
    #[serde(rename = "decoy.snapshot")]
    DecoySnapshot,
    #[serde(rename = "capture.flush")]
    CaptureFlush,
    #[serde(rename = "host.drain")]
    HostDrain,
}

impl JobKind {
    pub const ALL: [JobKind; 10] = [
        JobKind::DecoyCreate,
        JobKind::DecoyStart,
        JobKind::DecoyStop,
        JobKind::DecoyRotate,
        JobKind::DecoyReset,
        JobKind::DecoyMarkCompromised,
        JobKind::DecoyDestroy,
        JobKind::DecoySnapshot,
        JobKind::CaptureFlush,
        JobKind::HostDrain,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::DecoyCreate => "decoy.create",
            JobKind::DecoyStart => "decoy.start",
            JobKind::DecoyStop => "decoy.stop",
            JobKind::DecoyRotate => "decoy.rotate",
            JobKind::DecoyReset => "decoy.reset",
            JobKind::DecoyMarkCompromised => "decoy.mark_compromised",
            JobKind::DecoyDestroy => "decoy.destroy",
            JobKind::DecoySnapshot => "decoy.snapshot",
            JobKind::CaptureFlush => "capture.flush",
            JobKind::HostDrain => "host.drain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// Whether the job needs a `reason` (destructive actions, #21).
    pub fn needs_reason(self) -> bool {
        !matches!(
            self,
            JobKind::DecoyCreate | JobKind::DecoyStart | JobKind::CaptureFlush
        )
    }
}

/// What to run. The digest is what the host allow-list is checked against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyParams {
    pub catalogue_id: String,
    pub decoy_kind: DecoyKind,
    pub generation: u32,
    /// `sha256:<hex>` of the OCI image, or `emulator:<id>/<profile>`, or
    /// `module:<id>/<profile>@sha256:<hex>`. `None` when the catalogue entry
    /// has no pinned artefact yet; the host refuses such a job.
    pub artefact: Option<String>,
    /// Full image reference pinned by digest (`registry/repo@sha256:<hex>`)
    /// for sandbox and module decoys, so the runtime can pull exactly the
    /// allow-listed artefact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    pub listen_ports: Vec<ListenPort>,
    /// Unix ms: the host freezes the decoy at this time even if the control
    /// plane is unreachable (ADR 0002).
    pub hard_deadline: i64,
}

/// The signed part of a job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobBody {
    pub job_id: String,
    pub host_id: String,
    pub tenant_id: String,
    pub decoy_id: String,
    pub kind: JobKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy: Option<DecoyParams>,
    pub idempotency_key: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// What travels on the wire: the body as a JSON string and its signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJob {
    pub body: String,
    /// Hex Ed25519 signature over the UTF-8 bytes of `body`.
    pub sig: String,
    /// Names the signing key, so hosts can trust two keys during rotation.
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    BadSignatureEncoding,
    UnknownKey(String),
    BadSignature,
    BadBody(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadSignatureEncoding => write!(f, "signature is not 64 hex bytes"),
            VerifyError::UnknownKey(k) => write!(f, "job signed with unknown key {k}"),
            VerifyError::BadSignature => write!(f, "signature does not verify"),
            VerifyError::BadBody(e) => write!(f, "job body does not parse: {e}"),
        }
    }
}

/// A named signing key.
pub struct JobSigner {
    pub key_id: String,
    key: SigningKey,
}

impl JobSigner {
    /// From the 32-byte seed held as a Worker secret (hex).
    pub fn from_seed_hex(key_id: &str, seed_hex: &str) -> Option<Self> {
        let bytes: [u8; 32] = hex::decode(seed_hex.trim()).ok()?.try_into().ok()?;
        Some(JobSigner {
            key_id: key_id.to_string(),
            key: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, body: &JobBody) -> SignedJob {
        let body = serde_json::to_string(body).expect("job body serialises");
        let sig = self.key.sign(body.as_bytes());
        SignedJob {
            body,
            sig: hex::encode(sig.to_bytes()),
            key_id: self.key_id.clone(),
        }
    }
}

/// Public keys a host trusts, by key id.
#[derive(Debug, Clone, Default)]
pub struct TrustedKeys {
    keys: Vec<(String, VerifyingKey)>,
}

impl TrustedKeys {
    pub fn add_hex(&mut self, key_id: &str, public_hex: &str) -> Result<(), String> {
        let bytes: [u8; 32] = hex::decode(public_hex.trim())
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
        self.keys.push((key_id.to_string(), key));
        Ok(())
    }

    /// Check the signature, then parse. Nothing in `body` is looked at
    /// before the signature verifies.
    pub fn verify(&self, job: &SignedJob) -> Result<JobBody, VerifyError> {
        let key = self
            .keys
            .iter()
            .find(|(id, _)| id == &job.key_id)
            .map(|(_, k)| k)
            .ok_or_else(|| VerifyError::UnknownKey(job.key_id.clone()))?;
        let raw: [u8; 64] = hex::decode(&job.sig)
            .map_err(|_| VerifyError::BadSignatureEncoding)?
            .try_into()
            .map_err(|_| VerifyError::BadSignatureEncoding)?;
        key.verify(job.body.as_bytes(), &Signature::from_bytes(&raw))
            .map_err(|_| VerifyError::BadSignature)?;
        serde_json::from_str(&job.body).map_err(|e| VerifyError::BadBody(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOutcome {
    Succeeded,
    Failed,
    /// The agent refused the job (bad signature, expired, replay, not on the
    /// allow-list). Reported so the control plane can audit it.
    Rejected,
}

/// What the host reports back for a job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResult {
    pub job_id: String,
    pub outcome: JobOutcome,
    /// The decoy's state after the job, when it changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_state: Option<DecoyState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Periodic host health report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub host_id: String,
    pub agent_version: String,
    pub kvm_present: bool,
    pub publicly_exposed: bool,
    pub free_disk_bytes: u64,
    pub running_decoys: Vec<String>,
    /// Host clock at send time, Unix ms. The control plane computes skew.
    pub host_time: i64,
    pub buffered_events: u64,
    pub dropped_events: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoy::ReasonCode;

    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    fn body() -> JobBody {
        JobBody {
            job_id: "j1".into(),
            host_id: "host-1".into(),
            tenant_id: "t1".into(),
            decoy_id: "d1".into(),
            kind: JobKind::DecoyRotate,
            reason: Some(Reason {
                code: ReasonCode::OperatorManual,
                text: "fresh image".into(),
            }),
            decoy: None,
            idempotency_key: "k1".into(),
            issued_at: 1_000,
            expires_at: 61_000,
        }
    }

    fn keys(signer: &JobSigner) -> TrustedKeys {
        let mut k = TrustedKeys::default();
        k.add_hex(&signer.key_id, &signer.public_key_hex()).unwrap();
        k
    }

    #[test]
    fn rfc8032_test_key_has_the_published_public_key() {
        let s = JobSigner::from_seed_hex("k1", SEED).unwrap();
        assert_eq!(
            s.public_key_hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    #[test]
    fn signed_jobs_verify_and_round_trip() {
        let s = JobSigner::from_seed_hex("k1", SEED).unwrap();
        let signed = s.sign(&body());
        assert_eq!(keys(&s).verify(&signed).unwrap(), body());
    }

    #[test]
    fn tampered_body_or_signature_fails() {
        let s = JobSigner::from_seed_hex("k1", SEED).unwrap();
        let mut signed = s.sign(&body());
        signed.body = signed.body.replace("\"d1\"", "\"d2\"");
        assert_eq!(keys(&s).verify(&signed), Err(VerifyError::BadSignature));
        let mut signed = s.sign(&body());
        signed.sig.replace_range(0..2, "00");
        assert_eq!(keys(&s).verify(&signed), Err(VerifyError::BadSignature));
        let mut signed = s.sign(&body());
        signed.sig = "zz".into();
        assert_eq!(
            keys(&s).verify(&signed),
            Err(VerifyError::BadSignatureEncoding)
        );
    }

    #[test]
    fn jobs_from_another_key_are_refused() {
        let ours = JobSigner::from_seed_hex("k1", SEED).unwrap();
        let theirs = JobSigner::from_seed_hex("k1", &"11".repeat(32)).unwrap();
        assert_eq!(
            keys(&ours).verify(&theirs.sign(&body())),
            Err(VerifyError::BadSignature)
        );
        let other_id = JobSigner::from_seed_hex("k2", SEED).unwrap();
        assert!(matches!(
            keys(&ours).verify(&other_id.sign(&body())),
            Err(VerifyError::UnknownKey(_))
        ));
    }

    #[test]
    fn job_kinds_round_trip_and_reasons() {
        for k in JobKind::ALL {
            assert_eq!(JobKind::parse(k.as_str()), Some(k));
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
        }
        assert!(JobKind::DecoyDestroy.needs_reason());
        assert!(!JobKind::DecoyCreate.needs_reason());
    }
}
