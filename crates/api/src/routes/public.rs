//! Public, unauthenticated reads (#35): `GET /v0/public/exploited` and
//! `GET /v0/public/exploited/{slug}`. The radar is trusted-side only.
//!
//! These routes never take credentials and never read tenant-scoped data.
//! They make exactly two reads: [`Store::public_page`] and
//! [`Store::public_pages`] (allow-listed snapshots written at publish time,
//! at most [`MAX_PAGES`] rows), plus a per-client rate limit. IOCs on a page
//! appear only after their release time. Every response carries explicit,
//! short cache headers so a withdrawn page leaves caches quickly (it is also
//! purged on withdrawal); errors never leak internals.
//!
//! [`Store::public_page`]: crate::store::Store::public_page
//! [`Store::public_pages`]: crate::store::Store::public_pages

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use foiled_core::writeup::{PublicPageSummary, valid_slug};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::auth::Meta;
use crate::error::ApiError;

/// Browsers and shared caches may keep a public response this long
/// (seconds). Short, so a withdrawn page that could not be purged is gone
/// within a minute.
pub const PUBLIC_MAX_AGE: u32 = 60;
/// Most pages the list returns.
pub const MAX_PAGES: usize = 100;
/// Public reads per client per minute.
pub const PUBLIC_READS_PER_MINUTE: u32 = 120;
/// The client address the public site Worker forwards over the Service
/// Binding. Honoured only with a matching [`BINDING_SECRET_HEADER`].
pub const CLIENT_IP_HEADER: &str = "x-foiled-client-ip";
/// Proves a request came from the public site Worker: the value of the
/// `PUBLIC_BINDING_SECRET` Worker secret, set on both Workers.
pub const BINDING_SECRET_HEADER: &str = "x-foiled-binding-secret";
/// Shortest binding secret we accept. A shorter one is treated as unset.
pub const MIN_BINDING_SECRET_LEN: usize = 32;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/public/exploited", get(list))
        .route("/v0/public/exploited/{slug}", get(page))
}

/// Add the public headers to any response: a short cache for success and
/// 404, none for anything else.
fn public(res: Result<Response, ApiError>) -> Response {
    let mut res = match res {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };
    let status = res.status();
    let cache = if status.is_success() {
        format!("public, max-age={PUBLIC_MAX_AGE}, s-maxage={PUBLIC_MAX_AGE}")
    } else if status == http::StatusCode::NOT_FOUND {
        format!("public, max-age={PUBLIC_MAX_AGE}")
    } else {
        "no-store".to_string()
    };
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&cache) {
        h.insert(header::CACHE_CONTROL, v);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    res
}

/// A visitor address forwarded by the public site Worker and vouched for by
/// the binding secret. Only [`admit_forwarded_client`] inserts it; the
/// public routes never read [`CLIENT_IP_HEADER`] themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedClient(pub String);

/// Decide, before routing, whether `req` carries a visitor address we can
/// trust, and strip both forwarding headers so nothing downstream sees a
/// value the caller made up (#92).
///
/// The API Worker is reachable from the internet (MCP clients, sensors), so
/// anyone can send [`CLIENT_IP_HEADER`]. Trust needs proof the request came
/// from `foiled-public` over the Service Binding. Cloudflare does not mark
/// binding calls: a missing `CF-Connecting-IP` or `cf` object is how they
/// look today, but that is undocumented behaviour and would also match a
/// local or misrouted request. So the proof is a shared secret,
/// `PUBLIC_BINDING_SECRET`, set as a Worker secret on both Workers and sent
/// only over the binding, compared in constant time. With no secret (or one
/// shorter than [`MIN_BINDING_SECRET_LEN`]) the header is never honoured
/// and public reads are limited by the connecting address.
pub fn admit_forwarded_client<B>(req: &mut http::Request<B>, secret: Option<&str>) {
    let headers = req.headers_mut();
    let presented = take_single(headers, BINDING_SECRET_HEADER);
    let forwarded = take_single(headers, CLIENT_IP_HEADER);
    let (Some(secret), Some(presented), Some(forwarded)) = (secret, presented, forwarded) else {
        return;
    };
    if secret.len() < MIN_BINDING_SECRET_LEN || !secret_matches(presented.as_bytes(), secret) {
        return;
    }
    // Key the limit on the canonical form, so one address has one bucket.
    let ip = forwarded
        .to_str()
        .ok()
        .filter(|v| v.len() <= 64)
        .and_then(|v| v.parse::<std::net::IpAddr>().ok());
    if let Some(ip) = ip {
        req.extensions_mut().insert(ForwardedClient(ip.to_string()));
    }
}

/// Remove every `name` header and return the value if there was exactly
/// one. Two copies are refused rather than guessed between.
fn take_single(headers: &mut HeaderMap, name: &str) -> Option<HeaderValue> {
    let one = {
        let mut all = headers.get_all(name).iter();
        let first = all.next().cloned();
        first.filter(|_| all.next().is_none())
    };
    headers.remove(name);
    one
}

/// Constant-time comparison of SHA-256 digests, so neither the contents
/// nor the length of the secret leak through timing.
fn secret_matches(presented: &[u8], secret: &str) -> bool {
    let a = Sha256::digest(presented);
    let b = Sha256::digest(secret.as_bytes());
    a.as_slice().ct_eq(b.as_slice()).into()
}

#[derive(Debug, Serialize)]
pub struct PageList {
    pub items: Vec<PublicPageSummary>,
}

/// Count one public read for the client: the address the public site
/// Worker forwarded (admitted by [`admit_forwarded_client`]), else the
/// connecting address, else one shared bucket.
async fn limit(
    state: &AppState,
    forwarded: Option<&ForwardedClient>,
    meta: &Meta,
) -> Result<(), ApiError> {
    let ip = forwarded
        .map(|f| f.0.clone())
        .or_else(|| meta.0.ip.clone())
        .unwrap_or_else(|| "unknown".into());
    let minute = 60_000;
    let window = (state.clock)() / minute * minute;
    if state
        .store
        .rate_limit(
            &format!("public.read:{ip}"),
            window,
            PUBLIC_READS_PER_MINUTE,
        )
        .await?
    {
        Ok(())
    } else {
        Err(ApiError::rate_limited())
    }
}

async fn list(
    State(state): State<AppState>,
    forwarded: Option<Extension<ForwardedClient>>,
    meta: Meta,
) -> Response {
    let res = async {
        limit(&state, forwarded.as_deref(), &meta).await?;
        let now = (state.clock)();
        let items = state.store.public_pages(now, MAX_PAGES).await?;
        Ok(Json(PageList { items }).into_response())
    }
    .await;
    public(res)
}

async fn page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    forwarded: Option<Extension<ForwardedClient>>,
    meta: Meta,
) -> Response {
    let res = async {
        limit(&state, forwarded.as_deref(), &meta).await?;
        if !valid_slug(&slug) {
            return Err(ApiError::not_found("page"));
        }
        let now = (state.clock)();
        let page = state
            .store
            .public_page(&slug, now)
            .await?
            .ok_or_else(|| ApiError::not_found("page"))?;
        Ok(Json(page.as_of(now)).into_response())
    }
    .await;
    public(res)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth::ClientMeta;
    use crate::memory::MemoryStore;

    const SECRET: &str = "test-binding-secret-0123456789abcdef-not-real";

    fn request(headers: &[(&str, &str)]) -> http::Request<axum::body::Body> {
        let mut b = http::Request::builder().uri("/v0/public/exploited");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    fn admitted(headers: &[(&str, &str)], secret: Option<&str>) -> Option<String> {
        let mut req = request(headers);
        admit_forwarded_client(&mut req, secret);
        assert!(!req.headers().contains_key(CLIENT_IP_HEADER));
        assert!(!req.headers().contains_key(BINDING_SECRET_HEADER));
        req.extensions()
            .get::<ForwardedClient>()
            .map(|f| f.0.clone())
    }

    #[test]
    fn the_forwarded_address_needs_the_binding_secret() {
        let ip = (CLIENT_IP_HEADER, "192.0.2.10");
        let good = (BINDING_SECRET_HEADER, SECRET);
        assert_eq!(
            admitted(&[ip, good], Some(SECRET)).as_deref(),
            Some("192.0.2.10")
        );
        // No secret configured: never trusted, whatever the caller sends.
        assert_eq!(admitted(&[ip, good], None), None);
        assert_eq!(admitted(&[ip, (BINDING_SECRET_HEADER, "")], Some("")), None);
        // A wrong, missing or truncated secret.
        assert_eq!(admitted(&[ip], Some(SECRET)), None);
        assert_eq!(
            admitted(&[ip, (BINDING_SECRET_HEADER, "guess")], Some(SECRET)),
            None
        );
        assert_eq!(
            admitted(&[ip, (BINDING_SECRET_HEADER, &SECRET[..40])], Some(SECRET)),
            None
        );
        // A configured secret that is too short is treated as unset.
        let short = (BINDING_SECRET_HEADER, "short");
        assert_eq!(admitted(&[ip, short], Some("short")), None);
    }

    #[test]
    fn the_forwarded_address_must_be_one_address() {
        let good = (BINDING_SECRET_HEADER, SECRET);
        let one = |v: &str| admitted(&[(CLIENT_IP_HEADER, v), good], Some(SECRET));
        assert_eq!(one("2001:0db8::0001").as_deref(), Some("2001:db8::1"));
        assert_eq!(one("not an ip"), None);
        assert_eq!(one(""), None);
        let two = [
            (CLIENT_IP_HEADER, "192.0.2.10"),
            (CLIENT_IP_HEADER, "192.0.2.11"),
            good,
        ];
        assert_eq!(admitted(&two, Some(SECRET)), None);
        let two_secrets = [(CLIENT_IP_HEADER, "192.0.2.10"), good, good];
        assert_eq!(admitted(&two_secrets, Some(SECRET)), None);
    }

    /// Read the list the way the Worker does: admit, then route, from a
    /// connecting address of 203.0.113.5.
    async fn read(state: &AppState, headers: &[(&str, &str)], secret: Option<&str>) -> u16 {
        let mut req = request(headers);
        admit_forwarded_client(&mut req, secret);
        req.extensions_mut().insert(ClientMeta {
            ip: Some("203.0.113.5".into()),
            asn: None,
        });
        let res = tower::ServiceExt::oneshot(crate::router(state.clone()), req)
            .await
            .unwrap();
        res.status().as_u16()
    }

    fn state() -> AppState {
        AppState::new(Arc::new(MemoryStore::new()), Arc::new(|| 1_792_306_923_000))
    }

    #[tokio::test]
    async fn a_spoofed_address_is_limited_by_the_connecting_address() {
        for (secret, sent) in [(None, SECRET), (Some(SECRET), "wrong-secret")] {
            let state = state();
            for i in 0..PUBLIC_READS_PER_MINUTE {
                let ip = format!("192.0.2.{i}");
                let h = [
                    (CLIENT_IP_HEADER, ip.as_str()),
                    (BINDING_SECRET_HEADER, sent),
                ];
                assert_eq!(read(&state, &h, secret).await, 200);
            }
            // A fresh forwarded address every time still shares one bucket.
            let h = [
                (CLIENT_IP_HEADER, "198.51.100.99"),
                (BINDING_SECRET_HEADER, sent),
            ];
            assert_eq!(read(&state, &h, secret).await, 429);
        }
    }

    #[tokio::test]
    async fn the_public_site_gets_a_bucket_per_visitor() {
        let state = state();
        let from = |ip: &'static str| [(CLIENT_IP_HEADER, ip), (BINDING_SECRET_HEADER, SECRET)];
        for _ in 0..PUBLIC_READS_PER_MINUTE {
            assert_eq!(read(&state, &from("198.51.100.7"), Some(SECRET)).await, 200);
        }
        assert_eq!(read(&state, &from("198.51.100.7"), Some(SECRET)).await, 429);
        // Another visitor behind the same Worker is unaffected.
        assert_eq!(read(&state, &from("198.51.100.8"), Some(SECRET)).await, 200);
    }
}
