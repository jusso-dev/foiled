//! `GET /v0/whoami`: the authenticated caller's id, role, tenant and scopes.
//! The console (#14) calls it once at sign-in to check a token and to hide
//! actions the token cannot take. The API still enforces every scope.

use axum::routing::get;
use axum::{Json, Router};
use foiled_core::auth::Principal;

use crate::AppState;
use crate::auth::Auth;

pub fn router() -> Router<AppState> {
    Router::new().route("/v0/whoami", get(whoami))
}

async fn whoami(auth: Auth) -> Json<Principal> {
    Json(auth.0)
}
