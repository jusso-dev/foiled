//! Docker lab runtime (ADR 0002). For local labs and the MVP walkthrough
//! only: the config refuses it on a publicly exposed host, and it binds
//! published ports to a lab address (loopback by default).
//!
//! Every decoy runs with a read-only root, all capabilities dropped,
//! `no-new-privileges`, PID, memory and CPU limits, tmpfs for the paths the
//! image needs to write, on a dedicated bridge network whose new outbound
//! connections the operator drops in `DOCKER-USER` (see
//! `docs/mvp-walkthrough.md`). Images are run by digest only.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::egress::{self, Cidr, Coverage, Family, Target};
use crate::runtime::{DecoySpec, ExecMeta, RtResult, Runtime, RuntimeError, SnapshotKind};

/// Which firewall listing proves the decoy network's egress block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallCheck {
    /// `iptables -S` and, for an IPv6 subnet, `ip6tables -S` (filter table).
    #[default]
    Iptables,
    /// `nft -j list ruleset`.
    Nftables,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerConfig {
    /// Bridge network created by the operator (for example `foiled-lab`).
    #[serde(default = "default_network")]
    pub network: String,
    /// Address published ports bind to. Loopback unless the lab says otherwise.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Paths inside decoys that get a small tmpfs, since the root is read-only.
    #[serde(default = "default_writable")]
    pub writable: Vec<String>,
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default = "default_pids")]
    pub pids_limit: u32,
    /// Subnets the network must have, for example `["10.86.0.0/24"]`. Empty
    /// accepts whatever the network has, but every subnet must still be
    /// covered by a deny rule.
    #[serde(default)]
    pub subnets: Vec<String>,
    #[serde(default)]
    pub firewall: FirewallCheck,
    /// Prefix for the read-only firewall listing, for example
    /// `["sudo", "-n"]` with a sudoers entry for exactly `iptables -S` and
    /// `ip6tables -S`. Listing rules needs `CAP_NET_ADMIN`.
    #[serde(default)]
    pub firewall_command: Vec<String>,
}

fn default_network() -> String {
    "foiled-lab".into()
}
fn default_bind() -> String {
    "127.0.0.1".into()
}
fn default_writable() -> Vec<String> {
    vec!["/tmp".into()]
}
fn default_memory() -> String {
    "256m".into()
}
fn default_pids() -> u32 {
    256
}

impl Default for DockerConfig {
    fn default() -> Self {
        DockerConfig {
            network: default_network(),
            bind: default_bind(),
            writable: default_writable(),
            memory: default_memory(),
            pids_limit: default_pids(),
            subnets: Vec::new(),
            firewall: FirewallCheck::default(),
            firewall_command: Vec::new(),
        }
    }
}

/// Runs one command and returns its stdout, or a message on failure.
pub type Exec<'a> = &'a dyn Fn(&[String]) -> Result<String, String>;

/// Daemon sockets that share the host's network namespace, so the firewall
/// hostd lists is the one the decoys' traffic crosses. A TCP or SSH
/// endpoint, a rootless daemon or Docker Desktop runs its containers
/// somewhere else.
const LOCAL_DAEMONS: &[&str] = &["unix:///var/run/docker.sock", "unix:///run/docker.sock"];

/// The daemon `docker` talks to must be the host's own system daemon:
/// `DOCKER_HOST` unset or a local socket, and the active context too.
fn check_local_daemon(docker_host: Option<&str>, exec: Exec) -> RtResult<()> {
    if let Some(h) = docker_host.filter(|h| !h.is_empty())
        && !LOCAL_DAEMONS.contains(&h)
    {
        return Err(RuntimeError::egress(format!(
            "DOCKER_HOST={h} is not the local system daemon, so its firewall cannot be checked here"
        )));
    }
    let endpoint = exec(&[
        "docker".into(),
        "context".into(),
        "inspect".into(),
        "--format".into(),
        "{{.Endpoints.docker.Host}}".into(),
    ])
    .map_err(|e| RuntimeError::egress(format!("docker context inspect: {e}")))?;
    let endpoint = endpoint.trim();
    if !LOCAL_DAEMONS.contains(&endpoint) {
        return Err(RuntimeError::egress(format!(
            "the active Docker context uses {endpoint:?}, not the local system daemon, so its firewall cannot be checked here"
        )));
    }
    Ok(())
}

/// Confirm, read only, that `docker` reaches the local system daemon, that
/// the decoy network exists and is the expected bridge, and that new
/// outbound connections from each of its subnets are denied. Returns the
/// network's ID for `docker run`. Any doubt is an egress error.
pub fn egress_preflight(
    cfg: &DockerConfig,
    docker_host: Option<&str>,
    exec: Exec,
) -> RtResult<String> {
    check_local_daemon(docker_host, exec)?;
    let inspect = exec(&[
        "docker".into(),
        "network".into(),
        "inspect".into(),
        cfg.network.clone(),
    ])
    .map_err(|e| RuntimeError::egress(format!("decoy network {}: {e}", cfg.network)))?;
    let info = egress::parse_network_inspect(&inspect).map_err(RuntimeError::egress)?;
    egress::check_network(&cfg.network, &info, &cfg.subnets).map_err(RuntimeError::egress)?;
    if info.id.is_empty() {
        return Err(RuntimeError::egress(format!(
            "decoy network {} has no ID",
            cfg.network
        )));
    }
    let list = |cmd: &[&str]| {
        let argv: Vec<String> = cfg
            .firewall_command
            .iter()
            .cloned()
            .chain(cmd.iter().map(|s| s.to_string()))
            .collect();
        exec(&argv).map_err(|e| RuntimeError::egress(format!("{}: {e}", cmd.join(" "))))
    };
    let (mut v4, mut v6, mut nft) = (None, None, None);
    for (text, net) in &info.subnets {
        let rules = match (cfg.firewall, net.is_v6()) {
            (FirewallCheck::Iptables, false) => cached(&mut v4, || {
                Ok(egress::parse_iptables(
                    &list(&["iptables", "-S"])?,
                    Family::V4,
                ))
            })?,
            (FirewallCheck::Iptables, true) => cached(&mut v6, || {
                Ok(egress::parse_iptables(
                    &list(&["ip6tables", "-S"])?,
                    Family::V6,
                ))
            })?,
            (FirewallCheck::Nftables, _) => cached(&mut nft, || {
                egress::parse_nft(&list(&["nft", "-j", "list", "ruleset"])?)
                    .map_err(RuntimeError::egress)
            })?,
        };
        check_subnet(rules, text, *net, &info.bridge)?;
    }
    Ok(info.id)
}

fn cached(
    slot: &mut Option<egress::Ruleset>,
    load: impl FnOnce() -> RtResult<egress::Ruleset>,
) -> RtResult<&egress::Ruleset> {
    if slot.is_none() {
        *slot = Some(load()?);
    }
    Ok(slot.as_ref().expect("just set"))
}

fn check_subnet(rules: &egress::Ruleset, text: &str, net: Cidr, bridge: &str) -> RtResult<()> {
    let family = if net.is_v6() { "IPv6" } else { "IPv4" };
    match egress::evaluate(rules, &Target { net, bridge }) {
        Coverage::Covered => Ok(()),
        Coverage::Missing => Err(RuntimeError::egress(format!(
            "no rule denies new outbound {family} connections from {text}"
        ))),
        Coverage::Shadowed(rule) => Err(RuntimeError::egress(format!(
            "new outbound {family} connections from {text} can pass `{rule}` before any deny rule"
        ))),
    }
}

pub fn container_name(decoy_id: &str) -> String {
    format!("foiled-{decoy_id}")
}

/// Arguments for `docker run`, attached to the network with ID `network`
/// (the one the preflight checked). Pure, so the hardening is unit tested.
pub fn run_args(
    cfg: &DockerConfig,
    spec: &DecoySpec,
    network: &str,
) -> Result<Vec<String>, RuntimeError> {
    let image = spec
        .params
        .image
        .clone()
        .ok_or_else(|| RuntimeError::new("sandbox job has no image reference"))?;
    let digest = image
        .split_once('@')
        .map(|(_, d)| d.to_string())
        .ok_or_else(|| RuntimeError::new("image is not pinned by digest"))?;
    if spec.params.artefact.as_deref() != Some(digest.as_str()) {
        return Err(RuntimeError::new(
            "image digest does not match the allow-listed artefact",
        ));
    }
    let id = &spec.decoy_id;
    let mut a: Vec<String> = [
        "run",
        "--detach",
        "--name",
        &container_name(id),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        &cfg.pids_limit.to_string(),
        "--memory",
        &cfg.memory,
        "--cpus",
        "1",
        "--network",
        network,
        "--restart",
        "no",
        "--label",
        &format!("foiled.decoy={id}"),
        "--label",
        &format!("foiled.generation={}", spec.params.generation),
        "--label",
        &format!("foiled.catalogue={}", spec.params.catalogue_id),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for path in &cfg.writable {
        a.push("--tmpfs".into());
        // Sticky world-writable like /tmp: images run as a non-root user.
        a.push(format!("{path}:rw,noexec,nosuid,size=64m,mode=1777"));
    }
    for p in &spec.params.listen_ports {
        let proto = match p.protocol {
            foiled_core::catalogue::Protocol::Tcp => "tcp",
            foiled_core::catalogue::Protocol::Udp => "udp",
        };
        a.push("--publish".into());
        a.push(format!("{}:{}:{}/{proto}", cfg.bind, p.port, p.port));
    }
    a.push(image);
    Ok(a)
}

pub struct DockerRuntime {
    pub cfg: DockerConfig,
    running: Mutex<Vec<String>>,
}

/// How long one preflight command may run before it counts as a failure.
const PREFLIGHT_DEADLINE: Duration = Duration::from_secs(10);

/// Run `argv` and return its stdout, or its stderr as the error.
fn exec(argv: &[String]) -> Result<String, String> {
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("{prog}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Like [`exec`], but kills and reaps the command if it runs past
/// `deadline`, so a hung `docker` or firewall listing cannot hold up a job.
fn exec_deadline(argv: &[String], deadline: Duration) -> Result<String, String> {
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{prog}: {e}"))?;
    // Drain both pipes on their own threads so a chatty command cannot
    // block on a full pipe while we wait for it.
    let drain = |p: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = p {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = drain(child.stdout.take().map(|p| Box::new(p) as _));
    let err = drain(child.stderr.take().map(|p| Box::new(p) as _));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                // The readers end when the pipes close; do not wait on them.
                return Err(format!(
                    "{prog} timed out after {}s",
                    deadline.as_secs_f32()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{prog}: {e}"));
            }
        }
    };
    let text = |h: std::thread::JoinHandle<Vec<u8>>| {
        String::from_utf8_lossy(&h.join().unwrap_or_default())
            .trim()
            .to_string()
    };
    if status.success() {
        Ok(text(out))
    } else {
        Err(text(err))
    }
}

impl DockerRuntime {
    /// Also runs the egress preflight once and logs the result, so a missing
    /// rule shows up at start rather than at the first create. Creates still
    /// check again every time.
    pub fn new(cfg: DockerConfig) -> Self {
        let rt = DockerRuntime {
            cfg,
            running: Mutex::new(Vec::new()),
        };
        match rt.verified_network() {
            Ok(_) => eprintln!(
                "foiled-hostd: egress block confirmed for decoy network {}",
                rt.cfg.network
            ),
            Err(e) => eprintln!("foiled-hostd: decoys will not start until this is fixed: {e}"),
        }
        rt
    }

    /// Run the egress preflight and return the checked network's ID.
    pub fn verified_network(&self) -> RtResult<String> {
        let docker_host = std::env::var("DOCKER_HOST").ok();
        egress_preflight(&self.cfg, docker_host.as_deref(), &|argv| {
            exec_deadline(argv, PREFLIGHT_DEADLINE)
        })
    }

    fn docker(&self, args: &[String]) -> RtResult<String> {
        let argv: Vec<String> = std::iter::once("docker".to_string())
            .chain(args.iter().cloned())
            .collect();
        exec(&argv).map_err(|e| {
            RuntimeError::new(format!(
                "docker {}: {e}",
                args.first().map(String::as_str).unwrap_or("")
            ))
        })
    }
}

impl Runtime for DockerRuntime {
    fn preflight(&self) -> RtResult<()> {
        self.verified_network().map(|_| ())
    }

    fn create(&self, spec: &DecoySpec) -> RtResult<ExecMeta> {
        // Check the image before touching Docker, then attach to exactly the
        // network instance the preflight verified, by ID.
        run_args(&self.cfg, spec, &self.cfg.network)?;
        let network = self.verified_network()?;
        let args = run_args(&self.cfg, spec, &network)?;
        let cid = self.docker(&args)?;
        // `docker run --detach` both creates and starts; start() is a no-op.
        self.running.lock().unwrap().push(spec.decoy_id.clone());
        Ok(ExecMeta {
            listen_addrs: spec
                .params
                .listen_ports
                .iter()
                .map(|p| format!("{}:{}", self.cfg.bind, p.port))
                .collect(),
            pid_or_cid: cid,
            artefact: spec.params.artefact.clone().unwrap_or_default(),
        })
    }

    fn start(&self, decoy_id: &str) -> RtResult<()> {
        // `docker run --detach` already started it. Report healthy only if
        // the container is still running a few seconds later, so a decoy
        // that crashes on start is reported as failed.
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let state = match self.docker(&[
                "inspect".into(),
                "--format".into(),
                "{{.State.Running}}".into(),
                container_name(decoy_id),
            ]) {
                Ok(s) => s,
                Err(e) => {
                    self.running.lock().unwrap().retain(|d| d != decoy_id);
                    return Err(e);
                }
            };
            if state != "true" {
                self.running.lock().unwrap().retain(|d| d != decoy_id);
                return Err(RuntimeError::new("container exited during start"));
            }
        }
        Ok(())
    }

    fn stop(&self, decoy_id: &str) -> RtResult<()> {
        // Disconnect first so the guest loses the network before anything else.
        let _ = self.docker(&[
            "network".into(),
            "disconnect".into(),
            "--force".into(),
            self.cfg.network.clone(),
            container_name(decoy_id),
        ]);
        self.docker(&["kill".into(), container_name(decoy_id)])
            .or_else(|e| {
                if e.message.contains("is not running") || e.message.contains("No such container") {
                    Ok(String::new())
                } else {
                    Err(e)
                }
            })?;
        self.running.lock().unwrap().retain(|d| d != decoy_id);
        Ok(())
    }

    fn destroy(&self, decoy_id: &str) -> RtResult<()> {
        let res = self
            .docker(&["rm".into(), "--force".into(), container_name(decoy_id)])
            .map(|_| ());
        if res.is_ok() {
            self.running.lock().unwrap().retain(|d| d != decoy_id);
        }
        res
    }

    fn snapshot(&self, decoy_id: &str, _kind: SnapshotKind) -> RtResult<String> {
        // `docker diff` lists changed paths; full export is left to the
        // forensics tooling, never booted.
        self.docker(&["diff".into(), container_name(decoy_id)])
    }

    fn capture_flush(&self, _decoy_id: &str) -> RtResult<()> {
        // Log capture streams continuously (see `logcapture`); nothing buffered here.
        Ok(())
    }

    fn running(&self) -> Vec<String> {
        self.running.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foiled_core::agent::DecoyParams;
    use foiled_core::catalogue::{DecoyKind, ListenPort, Protocol};

    fn spec(image: Option<&str>, artefact: Option<&str>) -> DecoySpec {
        DecoySpec {
            decoy_id: "d1".into(),
            params: DecoyParams {
                catalogue_id: "foiled/demo-app/1.0.0".into(),
                decoy_kind: DecoyKind::Sandbox,
                generation: 3,
                artefact: artefact.map(str::to_string),
                image: image.map(str::to_string),
                listen_ports: vec![ListenPort {
                    port: 8080,
                    protocol: Protocol::Tcp,
                    service: "http".into(),
                    tls: None,
                }],
                hard_deadline: 0,
            },
        }
    }

    fn digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    #[test]
    fn runs_hardened_and_by_digest() {
        let image = format!("localhost:5000/foiled-demo-app@{}", digest());
        let cfg = DockerConfig {
            writable: vec!["/tmp".into(), "/srv/demo-app".into()],
            ..DockerConfig::default()
        };
        let a = run_args(&cfg, &spec(Some(&image), Some(&digest())), "foiled-lab").unwrap();
        let joined = a.join(" ");
        for flag in [
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 256",
            "--memory 256m",
            "--network foiled-lab",
            "--restart no",
            "--publish 127.0.0.1:8080:8080/tcp",
            "--tmpfs /srv/demo-app:rw,noexec,nosuid,size=64m,mode=1777",
            "--label foiled.generation=3",
        ] {
            assert!(joined.contains(flag), "missing {flag}: {joined}");
        }
        assert!(!joined.contains("--privileged"));
        assert!(!joined.contains("--network host"));
        assert_eq!(a.last().unwrap(), &image, "image comes last, by digest");
    }

    #[test]
    fn refuses_unpinned_or_mismatched_images() {
        let cfg = DockerConfig::default();
        assert!(run_args(&cfg, &spec(None, Some(&digest())), "n").is_err());
        assert!(
            run_args(
                &cfg,
                &spec(Some("foiled-demo-app:latest"), Some(&digest())),
                "n"
            )
            .is_err()
        );
        let other = format!("r/x@sha256:{}", "b".repeat(64));
        assert!(run_args(&cfg, &spec(Some(&other), Some(&digest())), "n").is_err());
    }

    const INSPECT: &str = r#"[{"Name": "foiled-lab", "Id": "0123456789abcdef", "Driver": "bridge",
        "IPAM": {"Config": [{"Subnet": "10.86.0.0/24", "Gateway": "10.86.0.1"}]}, "Options": {}}]"#;
    const INSPECT_V6: &str = r#"[{"Name": "foiled-lab", "Id": "0123456789abcdef", "Driver": "bridge",
        "IPAM": {"Config": [{"Subnet": "10.86.0.0/24"}, {"Subnet": "fd00:86::/64"}]}, "Options": {}}]"#;
    const IPT: &str = "-P FORWARD DROP\n-N DOCKER-USER\n-N DOCKER-FORWARD\n\
        -A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n\
        -A DOCKER-FORWARD -i br-0123456789ab -j ACCEPT\n";
    const DENY4: &str = "-A DOCKER-USER -s 10.86.0.0/24 -m conntrack --ctstate NEW -j REJECT\n";
    const DENY6: &str = "-A DOCKER-USER -s fd00:86::/64 -m conntrack --ctstate NEW -j REJECT\n";

    type Log = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

    /// A command runner that answers from a table and records what it ran.
    fn fake(
        table: Vec<(&'static str, Result<String, String>)>,
    ) -> (impl Fn(&[String]) -> Result<String, String>, Log) {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = log.clone();
        let f = move |argv: &[String]| {
            let cmd = argv.join(" ");
            seen.borrow_mut().push(cmd.clone());
            table
                .iter()
                .find(|(k, _)| cmd.ends_with(k))
                .map(|(_, v)| v.clone())
                .or_else(|| {
                    // The local system daemon, unless a test says otherwise.
                    cmd.starts_with("docker context inspect")
                        .then(|| Ok("unix:///var/run/docker.sock".to_string()))
                })
                .unwrap_or_else(|| Err(format!("unexpected command {cmd}")))
        };
        (f, log)
    }

    fn lab() -> DockerConfig {
        DockerConfig {
            network: "foiled-lab".into(),
            subnets: vec!["10.86.0.0/24".into()],
            ..DockerConfig::default()
        }
    }

    const CONTEXT: &str = "docker context inspect --format {{.Endpoints.docker.Host}}";

    fn egress_err<T: std::fmt::Debug>(r: RtResult<T>) -> String {
        let e = r.unwrap_err();
        assert_eq!(
            e.code,
            Some(foiled_core::agent::FailureCode::EgressUnverified)
        );
        e.message
    }

    #[test]
    fn preflight_passes_with_the_lab_rule_and_only_reads() {
        let (exec, log) = fake(vec![
            ("network inspect foiled-lab", Ok(INSPECT.into())),
            ("iptables -S", Ok(format!("{IPT}{DENY4}"))),
        ]);
        let id = egress_preflight(&lab(), None, &exec).unwrap();
        assert_eq!(id, "0123456789abcdef", "the checked network, by ID");
        assert_eq!(
            *log.borrow(),
            vec![CONTEXT, "docker network inspect foiled-lab", "iptables -S"],
            "list only; never -I, -A or -D"
        );
    }

    #[test]
    fn preflight_fails_without_the_rule() {
        let (exec, _) = fake(vec![
            ("network inspect foiled-lab", Ok(INSPECT.into())),
            ("iptables -S", Ok(IPT.into())),
        ]);
        let msg = egress_err(egress_preflight(&lab(), None, &exec));
        assert!(msg.contains("10.86.0.0/24"), "{msg}");
        assert!(msg.contains("-j ACCEPT"), "names the shadowing rule: {msg}");
    }

    #[test]
    fn preflight_fails_for_a_missing_network_or_unreadable_firewall() {
        let (exec, _) = fake(vec![(
            "network inspect foiled-lab",
            Err("Error: No such network: foiled-lab".into()),
        )]);
        assert!(egress_err(egress_preflight(&lab(), None, &exec)).contains("No such network"));
        let (exec, _) = fake(vec![
            ("network inspect foiled-lab", Ok(INSPECT.into())),
            (
                "iptables -S",
                Err("Permission denied (you must be root)".into()),
            ),
        ]);
        assert!(egress_err(egress_preflight(&lab(), None, &exec)).contains("Permission denied"));
    }

    #[test]
    fn preflight_fails_when_the_subnet_changed() {
        let (exec, _) = fake(vec![(
            "network inspect foiled-lab",
            Ok(INSPECT.replace("10.86.0.0/24", "10.99.0.0/24")),
        )]);
        assert!(egress_err(egress_preflight(&lab(), None, &exec)).contains("expected"));
    }

    #[test]
    fn preflight_checks_ip6tables_for_a_v6_subnet() {
        let cfg = DockerConfig {
            subnets: vec![],
            firewall_command: vec!["sudo".into(), "-n".into()],
            ..lab()
        };
        let (exec, log) = fake(vec![
            ("network inspect foiled-lab", Ok(INSPECT_V6.into())),
            ("sudo -n iptables -S", Ok(format!("{IPT}{DENY4}"))),
            ("sudo -n ip6tables -S", Ok(IPT.into())),
        ]);
        assert!(egress_err(egress_preflight(&cfg, None, &exec)).contains("IPv6"));
        assert!(log.borrow().contains(&"sudo -n ip6tables -S".to_string()));
        let (exec, _) = fake(vec![
            ("network inspect foiled-lab", Ok(INSPECT_V6.into())),
            ("sudo -n iptables -S", Ok(format!("{IPT}{DENY4}"))),
            ("sudo -n ip6tables -S", Ok(format!("{IPT}{DENY6}"))),
        ]);
        egress_preflight(&cfg, None, &exec).unwrap();
    }

    #[test]
    fn preflight_can_read_nftables_once_for_both_families() {
        let cfg = DockerConfig {
            firewall: FirewallCheck::Nftables,
            subnets: vec![],
            ..lab()
        };
        let ruleset = r#"{"nftables": [
            {"chain": {"family": "inet", "table": "lab", "name": "fwd", "type": "filter", "hook": "forward", "policy": "accept"}},
            {"rule": {"family": "inet", "table": "lab", "chain": "fwd", "handle": 2, "expr": [
              {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.86.0.0", "len": 24}}}},
              {"drop": null}]}},
            {"rule": {"family": "inet", "table": "lab", "chain": "fwd", "handle": 3, "expr": [
              {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": {"prefix": {"addr": "fd00:86::", "len": 64}}}},
              {"drop": null}]}}]}"#;
        let (exec, log) = fake(vec![
            ("network inspect foiled-lab", Ok(INSPECT_V6.into())),
            ("nft -j list ruleset", Ok(ruleset.into())),
        ]);
        egress_preflight(&cfg, None, &exec).unwrap();
        assert_eq!(
            log.borrow().len(),
            3,
            "one context check, one inspect, one listing"
        );
    }

    #[test]
    fn preflight_refuses_a_daemon_other_than_the_local_one() {
        let ok = || {
            fake(vec![
                ("network inspect foiled-lab", Ok(INSPECT.into())),
                ("iptables -S", Ok(format!("{IPT}{DENY4}"))),
            ])
        };
        for host in ["unix:///var/run/docker.sock", "unix:///run/docker.sock", ""] {
            let (exec, _) = ok();
            egress_preflight(&lab(), Some(host), &exec).unwrap();
        }
        for host in [
            "tcp://10.0.0.5:2376",
            "ssh://admin@decoy-host",
            "unix:///run/user/1000/docker.sock",
        ] {
            let (exec, log) = ok();
            let msg = egress_err(egress_preflight(&lab(), Some(host), &exec));
            assert!(msg.contains("DOCKER_HOST"), "{msg}");
            assert!(log.borrow().is_empty(), "refused before running anything");
        }
        for endpoint in [
            "tcp://10.0.0.5:2376",
            "unix:///Users/me/.docker/run/docker.sock",
        ] {
            let (exec, log) = fake(vec![(CONTEXT, Ok(endpoint.into()))]);
            let msg = egress_err(egress_preflight(&lab(), None, &exec));
            assert!(msg.contains("context"), "{msg}");
            assert_eq!(*log.borrow(), vec![CONTEXT], "no network or firewall read");
        }
        let (exec, _) = fake(vec![(CONTEXT, Err("context \"x\" does not exist".into()))]);
        assert!(egress_err(egress_preflight(&lab(), None, &exec)).contains("does not exist"));
    }

    #[test]
    fn preflight_commands_are_killed_at_the_deadline() {
        let argv: Vec<String> = ["sh", "-c", "echo started; sleep 30"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let start = Instant::now();
        let err = exec_deadline(&argv, Duration::from_millis(200)).unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "did not wait for sleep"
        );
        let echo: Vec<String> = ["sh", "-c", "echo ok; echo warn >&2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(exec_deadline(&echo, Duration::from_secs(5)).unwrap(), "ok");
        let fail: Vec<String> = ["sh", "-c", "echo nope >&2; exit 3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            exec_deadline(&fail, Duration::from_secs(5)).unwrap_err(),
            "nope"
        );
        // A timeout surfaces as an egress error, and nothing is cached: the
        // next call runs the command again.
        let calls = std::cell::Cell::new(0);
        let slow = |argv: &[String]| {
            if argv.first().is_some_and(|p| p == "iptables") {
                calls.set(calls.get() + 1);
                Err("iptables timed out after 10s".to_string())
            } else if argv.join(" ") == CONTEXT {
                Ok("unix:///var/run/docker.sock".to_string())
            } else {
                Ok(INSPECT.to_string())
            }
        };
        for _ in 0..2 {
            assert!(egress_err(egress_preflight(&lab(), None, &slow)).contains("timed out"));
        }
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn docker_run_attaches_to_the_verified_network_id() {
        let image = format!("r/x@{}", digest());
        let a = run_args(
            &DockerConfig::default(),
            &spec(Some(&image), Some(&digest())),
            "0123456789abcdef",
        )
        .unwrap();
        let i = a.iter().position(|x| x == "--network").unwrap();
        assert_eq!(a[i + 1], "0123456789abcdef");
        let (exec, _) = fake(vec![(
            "network inspect foiled-lab",
            Ok(INSPECT.replace(r#""Id": "0123456789abcdef", "#, "")),
        )]);
        assert!(egress_err(egress_preflight(&lab(), None, &exec)).contains("no ID"));
    }

    #[test]
    fn firewall_settings_parse_from_toml() {
        let cfg: DockerConfig = toml::from_str(
            "network = \"foiled-lab\"\nsubnets = [\"10.86.0.0/24\"]\nfirewall = \"nftables\"\nfirewall_command = [\"sudo\", \"-n\"]\n",
        )
        .unwrap();
        assert_eq!(cfg.firewall, FirewallCheck::Nftables);
        assert_eq!(cfg.subnets, vec!["10.86.0.0/24".to_string()]);
        let cfg: DockerConfig = toml::from_str("").unwrap();
        assert_eq!(cfg, DockerConfig::default());
        assert_eq!(cfg.firewall, FirewallCheck::Iptables);
    }
}
