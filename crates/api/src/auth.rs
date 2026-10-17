//! Request authentication.
//!
//! Two ways in, never mixed:
//! - Humans and MCP clients send `Authorization: Bearer fo_<id>.<secret>`.
//!   Only the SHA-256 of the secret is stored; comparison is constant time.
//! - Sandbox hosts and edge sensors present an mTLS client certificate on the
//!   ingest hostname. Cloudflare verifies it at the edge (WAF rule), and the
//!   Worker copies `cf.tlsClientAuth` into a [`ClientCert`] request extension.
//!   We check it again here and map the fingerprint to an identity in D1.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use foiled_core::auth::{Principal, Scope};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::error::ApiError;

pub const TOKEN_PREFIX: &str = "fo_";

/// Client certificate details copied from `request.cf.tlsClientAuth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCert {
    /// `certVerified == "SUCCESS"`.
    pub verified: bool,
    /// Lowercase hex SHA-256 fingerprint.
    pub sha256: String,
}

/// Split `fo_<id>.<secret>` into its parts.
pub fn parse_token(raw: &str) -> Option<(&str, &str)> {
    let rest = raw.strip_prefix(TOKEN_PREFIX)?;
    let (id, secret) = rest.split_once('.')?;
    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric());
    (ok(id) && ok(secret) && secret.len() >= 32).then_some((id, secret))
}

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn bearer(parts: &Parts) -> Option<&str> {
    let v = parts
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

/// The authenticated caller.
#[derive(Debug, Clone)]
pub struct Auth(pub Principal);

impl Auth {
    pub fn require(&self, scope: Scope) -> Result<&Principal, ApiError> {
        if self.0.has(scope) {
            Ok(&self.0)
        } else {
            Err(ApiError::forbidden(scope.as_str()))
        }
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let now = (state.clock)();
        if let Some(raw) = bearer(parts) {
            let (id, secret) = parse_token(raw).ok_or_else(ApiError::unauthorised)?;
            let rec = state
                .store
                .token(id)
                .await?
                .ok_or_else(ApiError::unauthorised)?;
            let presented = sha256_hex(secret);
            let matches: bool = presented
                .as_bytes()
                .ct_eq(rec.secret_sha256.as_bytes())
                .into();
            let expired = rec.expires_at.is_some_and(|e| e <= now);
            if !matches || rec.revoked || expired {
                return Err(ApiError::unauthorised());
            }
            return Ok(Auth(Principal::new(
                rec.id,
                rec.role,
                rec.tenant_id,
                rec.scopes,
            )));
        }
        if let Some(cert) = parts.extensions.get::<ClientCert>() {
            if !cert.verified {
                return Err(ApiError::unauthorised());
            }
            let rec = state
                .store
                .identity_by_cert(&cert.sha256)
                .await?
                .ok_or_else(ApiError::unauthorised)?;
            if rec.revoked {
                return Err(ApiError::unauthorised());
            }
            return Ok(Auth(Principal::new(
                rec.id,
                rec.role,
                rec.tenant_id,
                rec.scopes,
            )));
        }
        Err(ApiError::unauthorised())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_tokens_only() {
        let secret = "a".repeat(32);
        let raw = format!("fo_tok1.{secret}");
        assert_eq!(parse_token(&raw), Some(("tok1", secret.as_str())));
        assert_eq!(parse_token("fo_tok1.short"), None);
        assert_eq!(parse_token(&format!("xx_tok1.{secret}")), None);
        assert_eq!(parse_token(&format!("fo_.{secret}")), None);
        assert_eq!(parse_token(&format!("fo_to-k.{secret}")), None);
        assert_eq!(parse_token("fo_tok1"), None);
    }

    #[test]
    fn sha256_is_lower_hex() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
