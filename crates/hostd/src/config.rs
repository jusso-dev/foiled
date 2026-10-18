//! `hostd.toml`. Paths and identities only; no control-plane database
//! credentials ever live on a host (#41) or an edge sensor (#31).
//!
//! The same binary runs as a research sandbox host (`role = "host"`, the
//! default) or an edge sensor (`role = "sensor"`).

use std::path::PathBuf;

use foiled_core::auth::Role;
use foiled_core::enrolment::{HOST_BUFFER_BYTES, SENSOR_BUFFER_BYTES};
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
    /// `host` (research sandbox host, #41) or `sensor` (edge sensor, #31).
    #[serde(default = "default_role")]
    pub role: Role,
    /// The host or sensor id the operator got when registering it.
    pub host_id: String,
    /// Ingest hostname base URL, for example `https://ingest.example.invalid`.
    pub api_base: String,
    /// PEM client certificate and key for mTLS (#31 enrolment). Required
    /// for `https://` control planes; only a lab host talking to a loopback
    /// mock may omit them.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub trusted_keys: Vec<TrustedKey>,
    /// Artefacts this host will run: `sha256:<hex>`, `emulator:<id>/<profile>`
    /// or `module:<id>/<profile>[@sha256:<hex>]`.
    pub allowlist: Vec<String>,
    #[serde(default = "default_true")]
    pub publicly_exposed: bool,
    #[serde(default = "default_runtime")]
    pub sandbox_runtime: SandboxRuntime,
    pub state_dir: PathBuf,
    /// Offline buffer cap. Defaults to 1 GiB for hosts, 256 MiB for sensors.
    pub buffer_max_bytes: Option<u64>,
    /// Ed25519 release keys (offline, not the job key) that signed builds
    /// must verify against before an update is staged (#31).
    #[serde(default)]
    pub release_keys: Vec<TrustedKey>,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    /// Settings for the Docker lab runtime.
    #[serde(default)]
    pub docker: crate::docker::DockerConfig,
}

fn default_true() -> bool {
    true
}
fn default_runtime() -> SandboxRuntime {
    SandboxRuntime::Firecracker
}
fn default_role() -> Role {
    Role::Host
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
    MissingClientCertificate,
    BadRole,
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
            ConfigError::InsecureApiBase => write!(
                f,
                "api_base must be https://, except a loopback mock on a host that is not publicly exposed"
            ),
            ConfigError::MissingClientCertificate => {
                write!(f, "client_cert and client_key are required for https://")
            }
            ConfigError::BadRole => write!(f, "role must be \"host\" or \"sensor\""),
        }
    }
}

impl HostConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let c: HostConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        c.validate()?;
        Ok(c)
    }

    /// The offline buffer cap for this role.
    pub fn buffer_cap(&self) -> u64 {
        self.buffer_max_bytes.unwrap_or(match self.role {
            Role::Sensor => SENSOR_BUFFER_BYTES,
            _ => HOST_BUFFER_BYTES,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !matches!(self.role, Role::Host | Role::Sensor) {
            return Err(ConfigError::BadRole);
        }
        if self.sandbox_runtime == SandboxRuntime::Docker && self.publicly_exposed {
            return Err(ConfigError::DockerOnPublicHost);
        }
        if self.trusted_keys.is_empty() {
            return Err(ConfigError::NoTrustedKeys);
        }
        if self.api_base.starts_with("https://") {
            if self.client_cert.is_none() || self.client_key.is_none() {
                return Err(ConfigError::MissingClientCertificate);
            }
        } else {
            let loopback = ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"]
                .iter()
                .any(|p| self.api_base.starts_with(p));
            if !loopback || self.publicly_exposed {
                return Err(ConfigError::InsecureApiBase);
            }
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
    fn shipped_sensor_example_parses() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/sensor.example.toml"
        ))
        .unwrap();
        let c = HostConfig::parse(&text).unwrap();
        assert_eq!(c.role, Role::Sensor);
        assert_eq!(c.buffer_cap(), 256 * 1024 * 1024);
        assert_eq!(c.release_keys.len(), 1);
    }

    #[test]
    fn defaults_are_safe() {
        let c = HostConfig::parse(BASE).unwrap();
        assert!(c.publicly_exposed, "assume public unless told otherwise");
        assert_eq!(c.sandbox_runtime, SandboxRuntime::Firecracker);
        assert_eq!(c.heartbeat_secs, 30);
    }

    #[test]
    fn sensors_get_a_smaller_buffer_and_only_agent_roles_parse() {
        let host = HostConfig::parse(BASE).unwrap();
        assert_eq!(host.role, Role::Host);
        assert_eq!(host.buffer_cap(), 1024 * 1024 * 1024);
        let sensor = HostConfig::parse(&format!("role = \"sensor\"\n{BASE}")).unwrap();
        assert_eq!(sensor.buffer_cap(), 256 * 1024 * 1024);
        let capped = HostConfig::parse(&format!(
            "role = \"sensor\"\nbuffer_max_bytes = 1024\n{BASE}"
        ))
        .unwrap();
        assert_eq!(capped.buffer_cap(), 1024);
        assert_eq!(
            HostConfig::parse(&format!("role = \"human\"\n{BASE}")),
            Err(ConfigError::BadRole)
        );
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
        let lab = BASE.replace("https://ingest.example.invalid", "http://127.0.0.1:8787");
        assert_eq!(
            HostConfig::parse(&lab),
            Err(ConfigError::InsecureApiBase),
            "public host"
        );
        let lab = format!("publicly_exposed = false\n{lab}");
        assert!(HostConfig::parse(&lab).is_ok(), "loopback lab mock");
        let no_cert = BASE.replace("client_cert = \"/etc/foiled/host.crt\"\n", "");
        assert_eq!(
            HostConfig::parse(&no_cert),
            Err(ConfigError::MissingClientCertificate)
        );
        let extra = format!("database_url = \"postgres://x\"\n{BASE}");
        assert!(matches!(
            HostConfig::parse(&extra),
            Err(ConfigError::Parse(_))
        ));
    }
}
