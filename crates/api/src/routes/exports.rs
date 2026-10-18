//! `GET /v0/exports/iocs.csv`: source IPs seen at the tenant's decoys (#22).
//!
//! The richer IOC model (#34, `/v0/iocs`) and STIX/MISP exports (#13)
//! build on this.
//! Reads live rows only, so anything the retention purge removed (#16)
//! never comes back in an export.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use foiled_core::auth::Scope;
use foiled_core::sigv4::amz_date;
use serde::Deserialize;

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::store::IpIocRow;

pub fn router() -> Router<AppState> {
    Router::new().route("/v0/exports/iocs.csv", get(iocs_csv))
}

#[derive(Debug, Deserialize)]
pub struct CsvQuery {
    /// Unix ms; default is the last 30 days.
    pub since: Option<i64>,
}

/// RFC 4180 quoting, plus a leading `'` for cells a spreadsheet would treat
/// as a formula.
fn cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// ISO 8601 UTC from Unix ms.
fn iso(ms: i64) -> String {
    let d = amz_date(ms); // YYYYMMDDTHHMMSSZ
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &d[0..4],
        &d[4..6],
        &d[6..8],
        &d[9..11],
        &d[11..13],
        &d[13..15]
    )
}

pub fn render_csv(rows: &[IpIocRow]) -> String {
    let mut out = String::from(
        "indicator_type,indicator,first_seen,last_seen,event_count,decoy_ids,catalogue_ids,hook_cves\n",
    );
    for r in rows {
        let ty = if r.ip.contains(':') { "ipv6" } else { "ipv4" };
        let fields = [
            ty.to_string(),
            r.ip.clone(),
            iso(r.first_seen),
            iso(r.last_seen),
            r.events.to_string(),
            r.decoy_ids.join(";"),
            r.catalogue_ids.join(";"),
            r.hook_cves.join(";"),
        ];
        let line: Vec<String> = fields.iter().map(|f| cell(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

async fn iocs_csv(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<CsvQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let who = auth.require(Scope::ExportsRead)?;
    let since = q
        .since
        .unwrap_or_else(|| (state.clock)() - 30 * 24 * 3600 * 1000);
    let rows = state.store.ip_iocs(&who.tenant_id, since).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"iocs.csv\"",
            ),
        ],
        render_csv(&rows),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_are_quoted_and_formula_safe() {
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("=HYPERLINK(1)"), "'=HYPERLINK(1)");
    }

    #[test]
    fn renders_iso_times_and_lists() {
        let csv = render_csv(&[IpIocRow {
            ip: "203.0.113.7".into(),
            first_seen: 1_792_285_323_000,
            last_seen: 1_792_285_383_000,
            events: 3,
            decoy_ids: vec!["d1".into(), "d2".into()],
            catalogue_ids: vec!["foiled/demo-app/1.0.0".into()],
            hook_cves: vec!["FOILED-DEMO-0001".into()],
        }]);
        let line = csv.lines().nth(1).unwrap();
        assert_eq!(
            line,
            "ipv4,203.0.113.7,2026-10-18T01:02:03Z,2026-10-18T01:03:03Z,3,d1;d2,foiled/demo-app/1.0.0,FOILED-DEMO-0001"
        );
    }
}
