//! Signed build verification before a self-update (#31, ADR 0007, threat
//! model C29).
//!
//! The agent never runs an unverified build. [`stage_update`] checks a
//! release manifest against the pinned release keys (not the job keys),
//! refuses downgrades, checks the downloaded artefact's size and SHA-256,
//! and only then copies it into `<state_dir>/updates/<version>/`. Swapping
//! the running binary and restarting is left to the service manager, so a
//! bad build can be rolled back by the operator.

use std::path::{Path, PathBuf};

use foiled_core::agent::TrustedKeys;
use foiled_core::release::{ReleaseError, SignedManifest, check_artefact, verify_manifest};

/// The product name every manifest for this binary must carry.
pub const PRODUCT: &str = "foiled-hostd";

#[derive(Debug)]
pub enum UpdateError {
    Io(std::io::Error),
    Manifest(String),
    Release(ReleaseError),
    UnknownTarget,
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Io(e) => write!(f, "update: {e}"),
            UpdateError::Manifest(e) => write!(f, "update: manifest file: {e}"),
            UpdateError::Release(e) => write!(f, "update refused: {e}"),
            UpdateError::UnknownTarget => write!(f, "update: no release target for this platform"),
        }
    }
}

/// The release target triple for the running platform.
pub fn current_target() -> Option<String> {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "linux" => Some(format!("{arch}-unknown-linux-gnu")),
        "macos" => Some(format!("{arch}-apple-darwin")),
        _ => None,
    }
}

/// Verify `artefact` against the signed manifest and stage it. Returns the
/// staged path. Nothing is written unless every check passes.
pub fn stage_update(
    keys: &TrustedKeys,
    signed_manifest_json: &str,
    artefact: &Path,
    target: &str,
    running_version: &str,
    state_dir: &Path,
) -> Result<PathBuf, UpdateError> {
    let signed: SignedManifest = serde_json::from_str(signed_manifest_json)
        .map_err(|e| UpdateError::Manifest(e.to_string()))?;
    let manifest =
        verify_manifest(keys, &signed, PRODUCT, running_version).map_err(UpdateError::Release)?;
    // Check the size before reading, so a huge file is never loaded.
    let want = manifest
        .artefacts
        .iter()
        .find(|a| a.target == target)
        .ok_or_else(|| UpdateError::Release(ReleaseError::NoArtefactForTarget(target.into())))?
        .size;
    let got = std::fs::metadata(artefact).map_err(UpdateError::Io)?.len();
    if got != want {
        return Err(UpdateError::Release(ReleaseError::SizeMismatch {
            want,
            got,
        }));
    }
    let bytes = std::fs::read(artefact).map_err(UpdateError::Io)?;
    let entry = check_artefact(&manifest, target, &bytes).map_err(UpdateError::Release)?;

    let dir = state_dir.join("updates").join(&manifest.version);
    std::fs::create_dir_all(&dir).map_err(UpdateError::Io)?;
    let dest = dir.join(PRODUCT);
    let tmp = dir.join(format!(".{}.tmp", entry.file));
    std::fs::write(&tmp, &bytes).map_err(UpdateError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(UpdateError::Io)?;
    }
    std::fs::rename(&tmp, &dest).map_err(UpdateError::Io)?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use foiled_core::release::{
        RELEASE_MANIFEST_KIND, ReleaseArtefact, ReleaseManifest, ReleaseSigner,
    };
    use sha2::{Digest, Sha256};

    const SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const TARGET: &str = "x86_64-unknown-linux-gnu";

    fn setup(bin: &[u8], version: &str) -> (TrustedKeys, String) {
        let signer = ReleaseSigner::from_seed_hex("rel-1", SEED).unwrap();
        let mut keys = TrustedKeys::default();
        keys.add_hex("rel-1", &signer.public_key_hex()).unwrap();
        let m = ReleaseManifest {
            kind: RELEASE_MANIFEST_KIND.into(),
            product: PRODUCT.into(),
            version: version.into(),
            released_at: 1_800_000_000_000,
            artefacts: vec![ReleaseArtefact {
                target: TARGET.into(),
                file: format!("foiled-hostd-{TARGET}"),
                sha256: hex::encode(Sha256::digest(bin)),
                size: bin.len() as u64,
            }],
        };
        (keys, serde_json::to_string(&signer.sign(&m)).unwrap())
    }

    #[test]
    fn verified_builds_are_staged_and_others_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let bin = b"new build";
        let art = dir.path().join("download");
        std::fs::write(&art, bin).unwrap();
        let (keys, manifest) = setup(bin, "0.2.0");
        let staged = stage_update(&keys, &manifest, &art, TARGET, "0.1.0", dir.path()).unwrap();
        assert_eq!(std::fs::read(&staged).unwrap(), bin);
        assert!(staged.ends_with("updates/0.2.0/foiled-hostd"));

        // Tampered download.
        std::fs::write(&art, b"evil build").unwrap();
        let err = stage_update(&keys, &manifest, &art, TARGET, "0.1.0", dir.path()).unwrap_err();
        assert!(matches!(
            err,
            UpdateError::Release(ReleaseError::SizeMismatch { .. })
        ));
        std::fs::write(&art, b"bad build").unwrap();
        let err = stage_update(&keys, &manifest, &art, TARGET, "0.1.0", dir.path()).unwrap_err();
        assert!(matches!(
            err,
            UpdateError::Release(ReleaseError::DigestMismatch)
        ));
        // Downgrade or replay of the running version.
        std::fs::write(&art, bin).unwrap();
        let err = stage_update(&keys, &manifest, &art, TARGET, "0.2.0", dir.path()).unwrap_err();
        assert!(matches!(
            err,
            UpdateError::Release(ReleaseError::NotNewer { .. })
        ));
        // No pinned release keys: nothing is trusted.
        let err = stage_update(
            &TrustedKeys::default(),
            &manifest,
            &art,
            TARGET,
            "0.1.0",
            dir.path(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            UpdateError::Release(ReleaseError::NoReleaseKeys)
        ));
        assert!(
            !dir.path()
                .join("updates/0.2.0/.foiled-hostd-x86_64-unknown-linux-gnu.tmp")
                .exists()
        );
    }
}
