//! HTTPS client for the ingest hostname. The agent only dials out.

use foiled_core::agent::{Heartbeat, JobResult, SignedJob};
use foiled_core::capture::CaptureEvent;
use serde::Deserialize;

#[derive(Debug)]
pub enum ClientError {
    /// Network or 5xx: worth retrying later.
    Unavailable(String),
    /// 4xx other than 429: retrying the same request will not help.
    Refused(u16, String),
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
            http: b.build().map_err(|e| e.to_string())?,
        })
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
            .post(
                &format!("/v0/hosts/{}/jobs:lease", self.host_id),
                &serde_json::json!({}),
            )
            .await?;
        let leased: Leased = res
            .json()
            .await
            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
        Ok(leased.jobs)
    }

    pub async fn ack(&self, result: &JobResult) -> Result<(), ClientError> {
        self.post(
            &format!("/v0/hosts/{}/jobs/{}:ack", self.host_id, result.job_id),
            result,
        )
        .await
        .map(|_| ())
    }

    pub async fn heartbeat(&self, hb: &Heartbeat) -> Result<(), ClientError> {
        self.post(&format!("/v0/hosts/{}/heartbeat", self.host_id), hb)
            .await
            .map(|_| ())
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
