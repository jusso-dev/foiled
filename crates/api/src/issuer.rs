//! Client certificate issuance for enrolment (#31, ADR 0007).
//!
//! In production the Worker asks the Cloudflare-managed client CA to sign
//! the sensor's CSR (`worker_glue::CloudflareIssuer`) and to revoke
//! certificates. Tests, the local mock and contributors without a
//! Cloudflare account use [`FakeIssuer`], which never produces a real
//! X.509 certificate and is never wired into the Worker.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerError(pub String);

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "certificate issuer: {}", self.0)
    }
}

pub type IssuerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, IssuerError>> + Send + 'a>>;

/// What the CA returned for one CSR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCert {
    pub certificate_pem: String,
    /// The CA's id for the certificate, needed to revoke it there.
    pub issuer_ref: Option<String>,
}

pub trait CertIssuer: Send + Sync {
    /// Have the CA sign `csr_pem`. The CSR was shape-checked already.
    fn issue(&self, csr_pem: &str, validity_days: u32) -> IssuerFuture<'_, IssuedCert>;

    /// Revoke a certificate at the CA, so the WAF rule blocks it at the edge.
    fn revoke(&self, issuer_ref: &str) -> IssuerFuture<'_, ()>;
}

/// Test and lab issuer. The "certificate" is a PEM block around a marker
/// and the CSR digest: unique per CSR, with a stable fingerprint, and
/// useless to any real TLS stack.
#[derive(Default)]
pub struct FakeIssuer {
    issued: Mutex<u64>,
    revoked: Mutex<Vec<String>>,
}

impl FakeIssuer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issuer references revoked so far, in order.
    pub fn revoked(&self) -> Vec<String> {
        self.revoked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

fn b64(bytes: &[u8]) -> String {
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

impl CertIssuer for FakeIssuer {
    fn issue(&self, csr_pem: &str, validity_days: u32) -> IssuerFuture<'_, IssuedCert> {
        let n = {
            let mut g = self.issued.lock().unwrap_or_else(|e| e.into_inner());
            *g += 1;
            *g
        };
        let der = format!(
            "foiled-fake-client-certificate:{n}:{validity_days}:{}",
            hex::encode(Sha256::digest(csr_pem.as_bytes()))
        );
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64(der.as_bytes())
        );
        Box::pin(std::future::ready(Ok(IssuedCert {
            certificate_pem: pem,
            issuer_ref: Some(format!("fake-{n}")),
        })))
    }

    fn revoke(&self, issuer_ref: &str) -> IssuerFuture<'_, ()> {
        self.revoked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(issuer_ref.to_string());
        Box::pin(std::future::ready(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foiled_core::enrolment::cert_fingerprint;

    #[tokio::test]
    async fn fake_certificates_have_distinct_fingerprints() {
        let i = FakeIssuer::new();
        let a = i.issue("csr-a", 90).await.unwrap();
        let b = i.issue("csr-a", 90).await.unwrap();
        let fa = cert_fingerprint(&a.certificate_pem).unwrap();
        let fb = cert_fingerprint(&b.certificate_pem).unwrap();
        assert_eq!(fa.len(), 64);
        assert_ne!(fa, fb);
        i.revoke(a.issuer_ref.as_deref().unwrap()).await.unwrap();
        assert_eq!(i.revoked(), vec!["fake-1"]);
    }
}
