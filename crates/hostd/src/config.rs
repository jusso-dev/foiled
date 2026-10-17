//! `hostd.toml`. Paths and identities only; no control-plane database
//! credentials ever live on a host (#41).

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxRuntime {
    Firecracker,
    /// Local labs only. Refused when the host is publicly exposed (ADR 0002).
    Docker,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub id: String,
    /// Hex Ed25519 public key of the control plane's job signing key.
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub host_id: String,
    /// Ingest hostname base URL, for example `https://ingest.example.invalid`.
    pub api_base: String,
    /// PEM client certificate and key for mTLS (#31 enrolment).
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub trusted_keys: Vec<TrustedKey>,
    /// Artefacts this host will run: `sha256:<hex>`, `emulator:<id>/<profile>`
    /// or `module:<id>/<profile>[@sha256:<hex>]`.
    pub allowlist: Vec<String>,
    #[serde(default = "default_true")]
    pub publicly_exposed: bool,
    #[serde(default = "default_runtime")]
    pub sandbox_runtime: SandboxRuntime,
    pub state_dir: PathBuf,
    #[serde(default = "default_buffer")]
    pub buffer_max_bytes: u64,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_runtime() -> SandboxRuntime {
    SandboxRuntime::Firecracker
}
fn default_buffer() -> u64 {
    1024 * 1024 * 1024
}
fn default_heartbeat() -> u64 {
    30
}
fn default_poll() -> u64 {
    5
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Parse(String),
    DockerOnPublicHost,
    NoTrustedKeys,
    InsecureApiBase,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Parse(e) => write!(f, "hostd.toml: {e}"),
            ConfigError::DockerOnPublicHost => write!(
                f,
                "sandbox_runtime = \"docker\" is refused on a publicly exposed host"
            ),
            ConfigError::NoTrustedKeys => write!(f, "trusted_keys must list at least one key"),
            ConfigError::InsecureApiBase => write!(f, "api_base must be https://"),
        }
    }
}

impl HostConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let c: HostConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.sandbox_runtime == SandboxRuntime::Docker && self.publicly_exposed {
            return Err(ConfigError::DockerOnPublicHost);
        }
        if self.trusted_keys.is_empty() {
            return Err(ConfigError::NoTrustedKeys);
        }
        if !self.api_base.starts_with("https://") {
            return Err(ConfigError::InsecureApiBase);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
host_id = "host-1"
api_base = "https://ingest.example.invalid"
client_cert = "/etc/foiled/host.crt"
client_key = "/etc/foiled/host.key"
allowlist = ["emulator:redis/redis-7.0"]
state_dir = "/var/lib/foiled"

[[trusted_keys]]
id = "k1"
public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
"#;

    #[test]
    fn shipped_example_parses() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/hostd.example.toml"
        ))
        .unwrap();
        let c = HostConfig::parse(&text).unwrap();
        assert!(c.publicly_exposed);
        assert_eq!(c.sandbox_runtime, SandboxRuntime::Firecracker);
    }

    #[test]
    fn defaults_are_safe() {
        let c = HostConfig::parse(BASE).unwrap();
        assert!(c.publicly_exposed, "assume public unless told otherwise");
        assert_eq!(c.sandbox_runtime, SandboxRuntime::Firecracker);
        assert_eq!(c.heartbeat_secs, 30);
    }

    #[test]
    fn docker_is_refused_on_public_hosts() {
        let docker = format!("sandbox_runtime = \"docker\"\n{BASE}");
        assert_eq!(
            HostConfig::parse(&docker),
            Err(ConfigError::DockerOnPublicHost)
        );
        let lab = format!("sandbox_runtime = \"docker\"\npublicly_exposed = false\n{BASE}");
        assert!(HostConfig::parse(&lab).is_ok());
    }

    #[test]
    fn plain_http_and_unknown_keys_are_refused() {
        let http = BASE.replace("https://", "http://");
        assert_eq!(HostConfig::parse(&http), Err(ConfigError::InsecureApiBase));
        let extra = format!("database_url = \"postgres://x\"\n{BASE}");
        assert!(matches!(
            HostConfig::parse(&extra),
            Err(ConfigError::Parse(_))
        ));
    }
}
