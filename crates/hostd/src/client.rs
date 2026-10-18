//! HTTPS client for the ingest hostname. The agent only dials out.
//!
//! Research hosts use `/v0/hosts/{id}/...` and edge sensors
//! `/v0/sensors/{id}/...`; everything else is shared.

use foiled_core::agent::{Heartbeat, JobResult, SignedJob};
use foiled_core::auth::Role;
use foiled_core::capture::CaptureEvent;
use foiled_core::enrolment::{EnrolRequest, EnrolResponse, RenewRequest};
use serde::Deserialize;

#[derive(Debug)]
pub enum ClientError {
    /// Network or 5xx: worth retrying later.
    Unavailable(String),
    /// 4xx other than 429: retrying the same request will not help.
    Refused(u16, String),
}

/// Error codes on a 403 that refuse one piece of data rather than the
/// caller: the rest of the buffer is still deliverable.
const PER_ITEM_403: &[&str] = &["not_assigned"];

impl ClientError {
    /// The `error.code` of a refusal body, when there is one.
    pub fn code(&self) -> Option<String> {
        let ClientError::Refused(_, body) = self else {
            return None;
        };
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        v["error"]["code"].as_str().map(str::to_string)
    }

    /// The control plane does not accept this identity: a 401 (revoked,
    /// retired, expired or unknown certificate) or a 403 about the caller
    /// (missing scope, wrong id). Retrying the same data will not help,
    /// but the data is not at fault, so it must not be dropped. A 403 about
    /// one item, such as `not_assigned` for a decoy that moved, is not.
    pub fn is_identity_problem(&self) -> bool {
        match self {
            ClientError::Refused(401, _) => true,
            ClientError::Refused(403, _) => self
                .code()
                .is_none_or(|c| !PER_ITEM_403.contains(&c.as_str())),
            _ => false,
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unavailable(e) => write!(f, "control plane unavailable: {e}"),
            ClientError::Refused(code, body) => write!(f, "control plane refused ({code}): {body}"),
        }
    }
}

#[derive(Clone)]
pub struct ControlPlane {
    base: String,
    host_id: String,
    /// `hosts` or `sensors`.
    family: &'static str,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct Leased {
    jobs: Vec<SignedJob>,
}

impl ControlPlane {
    /// `identity` is the host's PEM certificate and key for mTLS. Tests pass
    /// `None` against a local server that injects the identity itself.
    pub fn new(
        base: &str,
        host_id: &str,
        identity: Option<reqwest::Identity>,
    ) -> Result<Self, String> {
        let mut b = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("foiled-hostd/", env!("CARGO_PKG_VERSION")));
        if let Some(id) = identity {
            b = b.identity(id).https_only(true);
        }
        Ok(ControlPlane {
            base: base.trim_end_matches('/').to_string(),
            host_id: host_id.to_string(),
            family: "hosts",
            http: b.build().map_err(|e| e.to_string())?,
        })
    }

    /// Use the edge sensor paths when `role` is [`Role::Sensor`].
    pub fn with_role(mut self, role: Role) -> Self {
        self.family = if role == Role::Sensor {
            "sensors"
        } else {
            "hosts"
        };
        self
    }

    fn agent_path(&self, rest: &str) -> String {
        format!("/v0/{}/{}/{rest}", self.family, self.host_id)
    }

    async fn post<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, ClientError> {
        let res = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
            .await
            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
        let status = res.status();
        if status.is_success() {
            Ok(res)
        } else if status.is_server_error() || status.as_u16() == 429 {
            Err(ClientError::Unavailable(status.to_string()))
        } else {
            let text = res.text().await.unwrap_or_default();
            Err(ClientError::Refused(status.as_u16(), text))
        }
    }

    pub async fn lease(&self) -> Result<Vec<SignedJob>, ClientError> {
        let res = self
            .post(&self.agent_path("jobs:lease"), &serde_json::json!({}))
            .await?;
        let leased: Leased = res
            .json()
            .await
            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
        Ok(leased.jobs)
    }

    pub async fn ack(&self, result: &JobResult) -> Result<(), ClientError> {
        self.post(
            &self.agent_path(&format!("jobs/{}:ack", result.job_id)),
            result,
        )
        .await
        .map(|_| ())
    }

    pub async fn heartbeat(&self, hb: &Heartbeat) -> Result<(), ClientError> {
        self.post(&self.agent_path("heartbeat"), hb)
            .await
            .map(|_| ())
    }

    /// A new certificate for a new key, over the current mTLS identity.
    pub async fn renew(&self, csr_pem: &str) -> Result<EnrolResponse, ClientError> {
        let res = self
            .post(
                &self.agent_path("certificate:renew"),
                &RenewRequest {
                    csr_pem: csr_pem.to_string(),
                },
            )
            .await?;
        res.json()
            .await
            .map_err(|e| ClientError::Unavailable(e.to_string()))
    }

    pub async fn send_events(&self, events: &[CaptureEvent]) -> Result<(), ClientError> {
        self.post(
            "/v0/ingest/events",
            &serde_json::json!({ "events": events }),
        )
        .await
        .map(|_| ())
    }
}

/// Redeem an enrolment token. There is no client certificate yet: this is
/// the one call the ingest hostname's WAF rule lets through without one.
pub async fn enrol(base: &str, req: &EnrolRequest) -> Result<EnrolResponse, ClientError> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("foiled-hostd/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| ClientError::Unavailable(e.to_string()))?;
    let res = http
        .post(format!("{}/v0/enrol", base.trim_end_matches('/')))
        .json(req)
        .send()
        .await
        .map_err(|e| ClientError::Unavailable(e.to_string()))?;
    let status = res.status();
    if status.is_success() {
        res.json()
            .await
            .map_err(|e| ClientError::Unavailable(e.to_string()))
    } else if status.is_server_error() || status.as_u16() == 429 {
        Err(ClientError::Unavailable(status.to_string()))
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(ClientError::Refused(status.as_u16(), text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(status: u16, code: &str) -> ClientError {
        ClientError::Refused(
            status,
            format!(r#"{{"error":{{"code":"{code}","message":"x"}}}}"#),
        )
    }

    #[test]
    fn identity_failures_are_told_apart_from_per_event_refusals() {
        assert!(refused(401, "unauthorised").is_identity_problem());
        assert!(refused(403, "forbidden").is_identity_problem());
        assert!(refused(403, "wrong_sensor").is_identity_problem());
        assert!(ClientError::Refused(403, "<html>".into()).is_identity_problem());
        assert!(!refused(403, "not_assigned").is_identity_problem());
        assert!(!refused(404, "not_found").is_identity_problem());
        assert!(!refused(422, "invalid_events").is_identity_problem());
        assert!(!ClientError::Unavailable("down".into()).is_identity_problem());
        assert_eq!(
            refused(403, "not_assigned").code().as_deref(),
            Some("not_assigned")
        );
    }
}
