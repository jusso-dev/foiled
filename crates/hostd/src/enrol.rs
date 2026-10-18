//! Enrolment and certificate renewal on the agent (#31, ADR 0007).
//!
//! The private key is generated here and never leaves the machine: only a
//! CSR is sent. Files are written owner-only and replaced atomically. The
//! one-time enrolment token is deleted from disk once it has been redeemed
//! (or refused), so a later compromise of the box cannot replay it.

use std::path::{Path, PathBuf};

use foiled_core::auth::Role;
use foiled_core::enrolment::{EnrolRequest, EnrolResponse, cert_fingerprint, renew_due};
use serde::{Deserialize, Serialize};

use crate::client::{self, ClientError, ControlPlane};

/// Where the identity lives on disk.
#[derive(Debug, Clone)]
pub struct IdentityFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// `identity.json`: what the control plane bound to the certificate.
    pub meta: PathBuf,
}

impl IdentityFiles {
    pub fn new(cert: PathBuf, key: PathBuf, state_dir: &Path) -> Self {
        IdentityFiles {
            cert,
            key,
            meta: state_dir.join("identity.json"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMeta {
    pub agent_id: String,
    pub tenant_id: String,
    pub role: Role,
    pub cert_sha256: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl From<&EnrolResponse> for IdentityMeta {
    fn from(r: &EnrolResponse) -> Self {
        IdentityMeta {
            agent_id: r.agent_id.clone(),
            tenant_id: r.tenant_id.clone(),
            role: r.role,
            cert_sha256: r.cert_sha256.clone(),
            issued_at: r.issued_at,
            expires_at: r.expires_at,
        }
    }
}

/// A fresh ECDSA P-256 key and a CSR for it. Returns `(key_pem, csr_pem)`.
pub fn new_key_and_csr(common_name: &str) -> Result<(String, String), String> {
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let csr = params.serialize_request(&key).map_err(|e| e.to_string())?;
    Ok((key.serialize_pem(), csr.pem().map_err(|e| e.to_string())?))
}

fn tmp_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".new");
    PathBuf::from(s)
}

/// Write `contents` to `path.new` readable by the owner only.
fn write_staged(path: &Path, contents: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = tmp_path(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    Ok(tmp)
}

/// Install a new key and certificate. Both are staged first, then renamed
/// key before certificate; [`recover`] finishes an interrupted install.
pub fn save(files: &IdentityFiles, key_pem: &str, res: &EnrolResponse) -> std::io::Result<()> {
    let key_tmp = write_staged(&files.key, key_pem.as_bytes())?;
    let cert_tmp = write_staged(&files.cert, res.certificate_pem.as_bytes())?;
    let meta = serde_json::to_vec_pretty(&IdentityMeta::from(res))?;
    let meta_tmp = write_staged(&files.meta, &meta)?;
    std::fs::rename(key_tmp, &files.key)?;
    std::fs::rename(cert_tmp, &files.cert)?;
    std::fs::rename(meta_tmp, &files.meta)
}

/// After a crash mid-install the key may be new while the certificate is
/// still staged. Finish the install so the pair matches again.
pub fn recover(files: &IdentityFiles) -> std::io::Result<()> {
    let key_staged = tmp_path(&files.key).exists();
    for p in [&files.cert, &files.meta] {
        let staged = tmp_path(p);
        if staged.exists() {
            if key_staged {
                // The key was never installed: the old pair is intact.
                std::fs::remove_file(staged)?;
            } else {
                std::fs::rename(staged, p)?;
            }
        }
    }
    if key_staged {
        std::fs::remove_file(tmp_path(&files.key))?;
    }
    Ok(())
}

pub fn load_meta(files: &IdentityFiles) -> Option<IdentityMeta> {
    serde_json::from_slice(&std::fs::read(&files.meta).ok()?).ok()
}

#[derive(Debug)]
pub enum EnrolError {
    Io(std::io::Error),
    Key(String),
    Client(ClientError),
    /// The control plane bound the certificate to a different identity than
    /// this config names. Nothing is installed.
    Mismatch(String),
}

impl std::fmt::Display for EnrolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrolError::Io(e) => write!(f, "enrolment: {e}"),
            EnrolError::Key(e) => write!(f, "enrolment: key generation: {e}"),
            EnrolError::Client(e) => write!(f, "enrolment: {e}"),
            EnrolError::Mismatch(e) => write!(f, "enrolment: {e}"),
        }
    }
}

fn check(res: &EnrolResponse, agent_id: &str, role: Role) -> Result<(), EnrolError> {
    if res.agent_id != agent_id || res.role != role {
        return Err(EnrolError::Mismatch(format!(
            "certificate was issued for {} {}, config says {} {}",
            res.role.as_str(),
            res.agent_id,
            role.as_str(),
            agent_id
        )));
    }
    if cert_fingerprint(&res.certificate_pem).as_deref() != Some(res.cert_sha256.as_str()) {
        return Err(EnrolError::Mismatch(
            "certificate does not match its fingerprint".into(),
        ));
    }
    Ok(())
}

/// Redeem the token in `token_file`, install the identity and delete the
/// token file. The file is deleted only after success or a definitive 401
/// (the token is spent, expired, revoked or wrong). On a network error,
/// 429 or 5xx (the CA may be down; the control plane reopens the token)
/// and on a 400 (fix the request and retry) it is kept for a retry.
pub async fn enrol(
    api_base: &str,
    token_file: &Path,
    files: &IdentityFiles,
    agent_id: &str,
    role: Role,
) -> Result<IdentityMeta, EnrolError> {
    let token = std::fs::read_to_string(token_file).map_err(EnrolError::Io)?;
    let (key_pem, csr_pem) = new_key_and_csr(agent_id).map_err(EnrolError::Key)?;
    let req = EnrolRequest {
        token: token.trim().to_string(),
        csr_pem,
    };
    let res = client::enrol(api_base, &req).await;
    if matches!(res, Ok(_) | Err(ClientError::Refused(401, _))) {
        let _ = std::fs::remove_file(token_file);
    }
    let res = res.map_err(EnrolError::Client)?;
    check(&res, agent_id, role)?;
    save(files, &key_pem, &res).map_err(EnrolError::Io)?;
    Ok(IdentityMeta::from(&res))
}

/// Renew when two thirds of the certificate's life has passed. Returns the
/// new identity when it renewed; the caller rebuilds its HTTPS client.
pub async fn renew_if_due(
    cp: &ControlPlane,
    files: &IdentityFiles,
    now: i64,
) -> Result<Option<IdentityMeta>, EnrolError> {
    let Some(meta) = load_meta(files) else {
        return Ok(None);
    };
    if !renew_due(meta.issued_at, meta.expires_at, now) {
        return Ok(None);
    }
    let (key_pem, csr_pem) = new_key_and_csr(&meta.agent_id).map_err(EnrolError::Key)?;
    let res = cp.renew(&csr_pem).await.map_err(EnrolError::Client)?;
    check(&res, &meta.agent_id, meta.role)?;
    save(files, &key_pem, &res).map_err(EnrolError::Io)?;
    Ok(Some(IdentityMeta::from(&res)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foiled_core::enrolment::csr_problem;

    #[test]
    fn generated_csrs_pass_the_control_plane_checks_and_keep_the_key_local() {
        let (key, csr) = new_key_and_csr("sensor-1").unwrap();
        assert_eq!(csr_problem(&csr), None);
        assert!(!csr.contains("PRIVATE KEY"));
        assert!(key.contains("PRIVATE KEY"));
        let (_, other) = new_key_and_csr("sensor-1").unwrap();
        assert_ne!(csr, other, "a fresh key each time");
    }

    fn response(pem: &str) -> EnrolResponse {
        EnrolResponse {
            agent_id: "s1".into(),
            tenant_id: "t1".into(),
            role: Role::Sensor,
            scopes: vec![],
            certificate_pem: pem.into(),
            cert_sha256: cert_fingerprint(pem).unwrap(),
            issued_at: 0,
            expires_at: 90,
        }
    }

    #[test]
    fn identity_files_are_private_and_installs_recover() {
        let dir = tempfile::tempdir().unwrap();
        let files = IdentityFiles::new(
            dir.path().join("c.pem"),
            dir.path().join("k.pem"),
            dir.path(),
        );
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        save(&files, "KEY1", &response(pem)).unwrap();
        assert_eq!(load_meta(&files).unwrap().agent_id, "s1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&files.key).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "key is owner-only");
        }
        // Crash after the key was installed but before the certificate.
        std::fs::write(&files.key, "KEY2").unwrap();
        std::fs::write(tmp_path(&files.cert), "CERT2").unwrap();
        recover(&files).unwrap();
        assert_eq!(std::fs::read_to_string(&files.cert).unwrap(), "CERT2");
        // Crash before the key was installed: keep the old pair.
        std::fs::write(tmp_path(&files.key), "KEY3").unwrap();
        std::fs::write(tmp_path(&files.cert), "CERT3").unwrap();
        recover(&files).unwrap();
        assert_eq!(std::fs::read_to_string(&files.key).unwrap(), "KEY2");
        assert_eq!(std::fs::read_to_string(&files.cert).unwrap(), "CERT2");
        assert!(!tmp_path(&files.cert).exists());
    }

    #[test]
    fn a_certificate_for_another_identity_is_refused() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let r = response(pem);
        assert!(check(&r, "s1", Role::Sensor).is_ok());
        assert!(matches!(
            check(&r, "s2", Role::Sensor),
            Err(EnrolError::Mismatch(_))
        ));
        assert!(matches!(
            check(&r, "s1", Role::Host),
            Err(EnrolError::Mismatch(_))
        ));
        let mut bad = r.clone();
        bad.cert_sha256 = "00".repeat(32);
        assert!(matches!(
            check(&bad, "s1", Role::Sensor),
            Err(EnrolError::Mismatch(_))
        ));
    }
}
