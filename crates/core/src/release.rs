//! Signed sensor and host agent builds (#31, ADR 0007, threat model C29).
//!
//! Each release publishes a manifest listing every artefact by target triple
//! with its SHA-256 and size. The manifest is signed with an Ed25519 release
//! key kept offline (never a Worker secret, never the job signing key). The
//! agent pins the release public keys and, before it stages an update,
//! checks in this order:
//!
//! 1. the signature, by a pinned release key, over the exact manifest bytes;
//! 2. `kind` and `product`, so a manifest for another product is refused;
//! 3. the version is strictly newer than the running one (no downgrade);
//! 4. the artefact for its own target has the listed size and SHA-256.
//!
//! Nothing in the manifest is read before step 1 passes.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent::{TrustedKeys, VerifyError};

/// Value of `kind` in every release manifest. Domain separation: a signed
/// job body can never parse as a manifest.
pub const RELEASE_MANIFEST_KIND: &str = "foiled.release.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtefact {
    /// Rust target triple, for example `x86_64-unknown-linux-gnu`.
    pub target: String,
    /// File name in the release, for example `foiled-hostd-x86_64-unknown-linux-gnu`.
    pub file: String,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    pub size: u64,
}

/// The signed part of a release. Contract: `schemas/release-manifest.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub kind: String,
    /// `foiled-hostd` for hosts and edge sensors.
    pub product: String,
    /// `MAJOR.MINOR.PATCH`.
    pub version: String,
    /// Unix ms.
    pub released_at: i64,
    pub artefacts: Vec<ReleaseArtefact>,
}

/// What is published next to the artefacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    /// The manifest as JSON text. The signature covers these exact bytes.
    pub body: String,
    /// Hex Ed25519 signature over the UTF-8 bytes of `body`.
    pub sig: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    NoReleaseKeys,
    Signature(VerifyError),
    BadBody(String),
    WrongKind(String),
    WrongProduct(String),
    BadVersion(String),
    NotNewer { running: String, offered: String },
    NoArtefactForTarget(String),
    SizeMismatch { want: u64, got: u64 },
    DigestMismatch,
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseError::NoReleaseKeys => write!(f, "no release keys are pinned"),
            ReleaseError::Signature(e) => write!(f, "manifest signature: {e}"),
            ReleaseError::BadBody(e) => write!(f, "manifest does not parse: {e}"),
            ReleaseError::WrongKind(k) => {
                write!(f, "manifest kind '{k}' is not {RELEASE_MANIFEST_KIND}")
            }
            ReleaseError::WrongProduct(p) => write!(f, "manifest is for product '{p}'"),
            ReleaseError::BadVersion(v) => write!(f, "version '{v}' is not MAJOR.MINOR.PATCH"),
            ReleaseError::NotNewer { running, offered } => {
                write!(
                    f,
                    "offered version {offered} is not newer than running {running}"
                )
            }
            ReleaseError::NoArtefactForTarget(t) => write!(f, "no artefact for target {t}"),
            ReleaseError::SizeMismatch { want, got } => {
                write!(f, "artefact is {got} bytes, manifest says {want}")
            }
            ReleaseError::DigestMismatch => {
                write!(f, "artefact SHA-256 does not match the manifest")
            }
        }
    }
}

/// Parse `MAJOR.MINOR.PATCH`. Pre-release and build suffixes are refused,
/// so ordering is never ambiguous.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.');
    let mut next = || -> Option<u64> {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let out = (next()?, next()?, next()?);
    parts.next().is_none().then_some(out)
}

/// Signs manifests. Used by the release workflow with the offline key.
pub struct ReleaseSigner {
    pub key_id: String,
    key: SigningKey,
}

impl ReleaseSigner {
    pub fn from_seed_hex(key_id: &str, seed_hex: &str) -> Option<Self> {
        let bytes: [u8; 32] = hex::decode(seed_hex.trim()).ok()?.try_into().ok()?;
        Some(ReleaseSigner {
            key_id: key_id.to_string(),
            key: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, manifest: &ReleaseManifest) -> SignedManifest {
        let body = serde_json::to_string(manifest).expect("manifest serialises");
        let sig = self.key.sign(body.as_bytes());
        SignedManifest {
            body,
            sig: hex::encode(sig.to_bytes()),
            key_id: self.key_id.clone(),
        }
    }
}

/// Steps 1 to 3: signature, kind and product, strictly newer version.
pub fn verify_manifest(
    keys: &TrustedKeys,
    signed: &SignedManifest,
    product: &str,
    running_version: &str,
) -> Result<ReleaseManifest, ReleaseError> {
    if keys.is_empty() {
        return Err(ReleaseError::NoReleaseKeys);
    }
    keys.verify_bytes(&signed.key_id, signed.body.as_bytes(), &signed.sig)
        .map_err(ReleaseError::Signature)?;
    let m: ReleaseManifest =
        serde_json::from_str(&signed.body).map_err(|e| ReleaseError::BadBody(e.to_string()))?;
    if m.kind != RELEASE_MANIFEST_KIND {
        return Err(ReleaseError::WrongKind(m.kind));
    }
    if m.product != product {
        return Err(ReleaseError::WrongProduct(m.product));
    }
    let offered =
        parse_version(&m.version).ok_or_else(|| ReleaseError::BadVersion(m.version.clone()))?;
    let running = parse_version(running_version)
        .ok_or_else(|| ReleaseError::BadVersion(running_version.to_string()))?;
    if offered <= running {
        return Err(ReleaseError::NotNewer {
            running: running_version.to_string(),
            offered: m.version,
        });
    }
    Ok(m)
}

/// Step 4: the bytes the agent downloaded are the ones the manifest lists.
pub fn check_artefact<'a>(
    manifest: &'a ReleaseManifest,
    target: &str,
    bytes: &[u8],
) -> Result<&'a ReleaseArtefact, ReleaseError> {
    let a = manifest
        .artefacts
        .iter()
        .find(|a| a.target == target)
        .ok_or_else(|| ReleaseError::NoArtefactForTarget(target.to_string()))?;
    if a.size != bytes.len() as u64 {
        return Err(ReleaseError::SizeMismatch {
            want: a.size,
            got: bytes.len() as u64,
        });
    }
    if hex::encode(Sha256::digest(bytes)) != a.sha256 {
        return Err(ReleaseError::DigestMismatch);
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const TARGET: &str = "x86_64-unknown-linux-gnu";

    fn fixture() -> ReleaseManifest {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/releases/foiled-hostd-0.2.0.json"
        ))
        .unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn manifest_for(bytes: &[u8]) -> ReleaseManifest {
        let mut m = fixture();
        m.artefacts[0].sha256 = hex::encode(Sha256::digest(bytes));
        m.artefacts[0].size = bytes.len() as u64;
        m
    }

    fn keys(s: &ReleaseSigner) -> TrustedKeys {
        let mut k = TrustedKeys::default();
        k.add_hex(&s.key_id, &s.public_key_hex()).unwrap();
        k
    }

    #[test]
    fn fixture_is_well_formed() {
        let m = fixture();
        assert_eq!(m.kind, RELEASE_MANIFEST_KIND);
        assert!(parse_version(&m.version).is_some());
        assert!(m.artefacts.iter().any(|a| a.target == TARGET));
    }

    #[test]
    fn a_signed_newer_build_verifies_end_to_end() {
        let s = ReleaseSigner::from_seed_hex("rel-2026", SEED).unwrap();
        let bin = b"\x7fELF pretend binary";
        let signed = s.sign(&manifest_for(bin));
        let m = verify_manifest(&keys(&s), &signed, "foiled-hostd", "0.1.0").unwrap();
        assert_eq!(check_artefact(&m, TARGET, bin).unwrap().target, TARGET);
    }

    #[test]
    fn tampering_and_wrong_keys_are_refused() {
        let s = ReleaseSigner::from_seed_hex("rel-2026", SEED).unwrap();
        let mut signed = s.sign(&fixture());
        signed.body = signed.body.replace("0.2.0", "9.9.9");
        assert!(matches!(
            verify_manifest(&keys(&s), &signed, "foiled-hostd", "0.1.0"),
            Err(ReleaseError::Signature(VerifyError::BadSignature))
        ));
        let other = ReleaseSigner::from_seed_hex("rel-2026", &"22".repeat(32)).unwrap();
        assert!(matches!(
            verify_manifest(&keys(&s), &other.sign(&fixture()), "foiled-hostd", "0.1.0"),
            Err(ReleaseError::Signature(VerifyError::BadSignature))
        ));
        assert_eq!(
            verify_manifest(
                &TrustedKeys::default(),
                &s.sign(&fixture()),
                "foiled-hostd",
                "0.1.0"
            ),
            Err(ReleaseError::NoReleaseKeys)
        );
    }

    #[test]
    fn a_job_signature_is_not_a_release_signature() {
        // Same key material used for a job: the body is a job, not a manifest.
        let s = ReleaseSigner::from_seed_hex("k1", SEED).unwrap();
        let job_signer = crate::agent::JobSigner::from_seed_hex("k1", SEED).unwrap();
        let job = job_signer.sign(&crate::agent::JobBody {
            job_id: "j1".into(),
            host_id: "s1".into(),
            tenant_id: "t1".into(),
            decoy_id: "d1".into(),
            kind: crate::agent::JobKind::CaptureFlush,
            reason: None,
            decoy: None,
            idempotency_key: "k".into(),
            issued_at: 1,
            expires_at: 2,
        });
        let as_manifest = SignedManifest {
            body: job.body,
            sig: job.sig,
            key_id: job.key_id,
        };
        assert!(matches!(
            verify_manifest(&keys(&s), &as_manifest, "foiled-hostd", "0.1.0"),
            Err(ReleaseError::BadBody(_))
        ));
    }

    #[test]
    fn downgrades_other_products_and_bad_bytes_are_refused() {
        let s = ReleaseSigner::from_seed_hex("rel-2026", SEED).unwrap();
        let k = keys(&s);
        let signed = s.sign(&fixture());
        assert!(matches!(
            verify_manifest(&k, &signed, "foiled-hostd", "0.2.0"),
            Err(ReleaseError::NotNewer { .. })
        ));
        assert!(matches!(
            verify_manifest(&k, &signed, "foiled-hostd", "1.0.0"),
            Err(ReleaseError::NotNewer { .. })
        ));
        assert!(matches!(
            verify_manifest(&k, &signed, "foiled-other", "0.1.0"),
            Err(ReleaseError::WrongProduct(_))
        ));
        let mut wrong_kind = fixture();
        wrong_kind.kind = "foiled.release.v0".into();
        assert!(matches!(
            verify_manifest(&k, &s.sign(&wrong_kind), "foiled-hostd", "0.1.0"),
            Err(ReleaseError::WrongKind(_))
        ));
        let m = manifest_for(b"good");
        assert_eq!(
            check_artefact(&m, TARGET, b"evil").unwrap_err(),
            ReleaseError::DigestMismatch
        );
        assert!(matches!(
            check_artefact(&m, TARGET, b"longer"),
            Err(ReleaseError::SizeMismatch { .. })
        ));
        assert!(matches!(
            check_artefact(&m, "riscv64gc-unknown-linux-gnu", b"good"),
            Err(ReleaseError::NoArtefactForTarget(_))
        ));
    }

    #[test]
    fn versions_parse_strictly_and_order_numerically() {
        assert_eq!(parse_version("0.10.2"), Some((0, 10, 2)));
        assert!(parse_version("0.10.2") > parse_version("0.9.9"));
        for bad in ["1.2", "1.2.3.4", "1.2.3-rc1", "v1.2.3", "1..3", ""] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
    }
}
