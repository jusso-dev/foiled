//! Foiled control plane API.
//!
//! One Axum [`Router`] served from a Cloudflare Worker through workers-rs
//! (`http` and `axum` features). There is no Tokio runtime on Workers, so the
//! router is driven by [`tower_service::Service::call`] from the fetch event
//! rather than `axum::serve`. See ADR 0009.

use axum::{Json, Router, routing::get};
use serde::Serialize;
use tower_service::Service;

/// Body returned by `GET /healthz`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Health {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        service: "foiled-api",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Build the API router. Kept free of Worker bindings so it can be tested on
/// the host with a normal async test runtime.
pub fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

#[worker::event(fetch)]
async fn fetch(
    req: worker::HttpRequest,
    _env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<axum::http::Response<axum::body::Body>> {
    Ok(router().call(req).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_reports_ok_with_crate_version() {
        let res = router()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "foiled-api");
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let res = router()
            .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
