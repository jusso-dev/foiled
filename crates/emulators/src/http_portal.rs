//! A minimal HTTP/1.1 portal emulator (#30): a hand-written request parser
//! on a Tokio listener, serving the routes, headers and error pages a
//! profile lists. Every request is logged as an envelope. Nothing a client
//! sends is ever executed, written to disk or used as a path on the host;
//! routes are static text.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use foiled_core::capture::{HookEvent, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::profile::{HookPoint, Profile};
use crate::server::{Server, Session};
use crate::sink::{Event, EventSink, now_ms};
use crate::util::{Rng, clip, http_date, sha256_hex};
use crate::{BoxFuture, Emulator, EmulatorError, Health, Jitter};

pub const PLUGIN: &str = "http_portal";

/// Largest request head (request line plus headers).
pub const MAX_HEAD: usize = 8 * 1024;
/// Longest request line before the reply is 414.
pub const MAX_REQUEST_LINE: usize = 4 * 1024;
/// Most headers in one request.
pub const MAX_HEADERS: usize = 100;
/// Hard cap on `max_body_bytes`.
pub const MAX_BODY: usize = 1024 * 1024;
/// Requests served on one keep-alive connection.
pub const MAX_REQUESTS_PER_CONN: u32 = 100;
/// Error statuses every profile must define a page for (FR-10).
pub const REQUIRED_ERRORS: &[u16] = &[400, 404, 405, 413, 414];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSettings {
    /// `Server` header value; omitted when absent. Must be in the catalogue
    /// entry's `banner_hints` (FR-05, FR-10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_header: Option<String>,
    /// Headers added to every response, after the standard ones.
    #[serde(default)]
    pub headers: Vec<Header>,
    pub routes: Vec<Route>,
    pub errors: Vec<ErrorPage>,
    #[serde(default = "default_keepalive")]
    pub keepalive_timeout_s: u32,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
}

fn default_keepalive() -> u32 {
    75
}

fn default_max_body() -> usize {
    64 * 1024
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub path: String,
    /// Match `path` as a prefix instead of exactly.
    #[serde(default)]
    pub prefix: bool,
    /// Allowed methods. `HEAD` is implied by `GET`.
    pub methods: Vec<String>,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    /// Record the username and a hash of the password from a form post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CredentialCapture>,
    /// Extra delay for this route, on top of the profile jitter. Used where
    /// the real product is slow, such as a password check (FR-17).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<Jitter>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_severity() -> Severity {
    Severity::Info
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCapture {
    pub username_field: String,
    pub password_field: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorPage {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn header_problems(h: &Header, out: &mut Vec<String>) {
    if !is_token(&h.name) {
        out.push(format!("header name '{}' is not a token", h.name));
    }
    if h.value.contains(['\r', '\n']) {
        out.push(format!("header '{}' value has a line break", h.name));
    }
}

impl HttpSettings {
    pub fn problems(&self, hooks: &[HookPoint]) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(s) = &self.server_header
            && s.contains(['\r', '\n'])
        {
            out.push("server_header has a line break".into());
        }
        self.headers
            .iter()
            .for_each(|h| header_problems(h, &mut out));
        if self.routes.is_empty() {
            out.push("http.routes is empty".into());
        }
        for r in &self.routes {
            if !r.path.starts_with('/') {
                out.push(format!("route '{}' must start with /", r.path));
            }
            if r.methods.is_empty() {
                out.push(format!("route '{}' has no methods", r.path));
            }
            for m in &r.methods {
                if m.is_empty() || !m.bytes().all(|b| b.is_ascii_uppercase()) {
                    out.push(format!("route '{}' method '{m}' is not upper case", r.path));
                }
            }
            if !(100..=599).contains(&r.status) {
                out.push(format!(
                    "route '{}' status {} is out of range",
                    r.path, r.status
                ));
            }
            r.headers.iter().for_each(|h| header_problems(h, &mut out));
            if let Some(d) = &r.delay_ms {
                out.extend(d.problems());
            }
            if let Some(ct) = &r.content_type
                && ct.contains(['\r', '\n'])
            {
                out.push(format!("route '{}' content_type has a line break", r.path));
            }
        }
        for s in REQUIRED_ERRORS {
            if !self.errors.iter().any(|e| e.status == *s) {
                out.push(format!("http.errors needs a page for {s}"));
            }
        }
        for h in hooks {
            if let Some(p) = &h.on.path
                && !self.routes.iter().any(|r| route_matches(r, p))
            {
                out.push(format!("hook '{}' path {p} matches no route", h.id));
            }
        }
        if self.max_body_bytes > MAX_BODY {
            out.push(format!("http.max_body_bytes is above {MAX_BODY}"));
        }
        if !(1..=600).contains(&self.keepalive_timeout_s) {
            out.push("http.keepalive_timeout_s must be 1..=600".into());
        }
        out
    }
}

fn route_matches(r: &Route, path: &str) -> bool {
    if r.prefix {
        path.starts_with(&r.path)
    } else {
        path == r.path
    }
}

/// Reason phrases as nginx writes them.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        303 => "See Other",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        408 => "Request Time-out",
        411 => "Length Required",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Temporarily Unavailable",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Request parsing

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    /// The request target as sent, lossy UTF-8.
    pub target: String,
    /// Normalised path used for routing.
    pub path: String,
    pub query: Option<String>,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub content_length: usize,
    /// Bytes of the head including the blank line.
    pub head_len: usize,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn keep_alive(&self) -> bool {
        let conn = self.header("connection").map(str::to_ascii_lowercase);
        match self.version.as_str() {
            "HTTP/1.1" => conn.as_deref() != Some("close"),
            _ => conn.as_deref() == Some("keep-alive"),
        }
    }
}

/// A request the parser refused, with the status to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    pub status: u16,
    pub reason: &'static str,
    /// Up to 256 bytes of the request line, for the event.
    pub line: String,
}

fn percent_decode(s: &[u8], plus_is_space: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' if i + 2 < s.len() => {
                let h = (s[i + 1] as char).to_digit(16);
                let l = (s[i + 2] as char).to_digit(16);
                match (h, l) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Decode, merge slashes and resolve `.` and `..` the way nginx does before
/// it matches locations. `None` when `..` climbs above the root.
pub fn normalise_path(raw: &[u8]) -> Option<String> {
    let decoded = percent_decode(raw, false);
    let text = String::from_utf8_lossy(&decoded);
    let mut parts: Vec<&str> = Vec::new();
    for seg in text.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    let mut out = format!("/{}", parts.join("/"));
    if text.ends_with('/') && out != "/" {
        out.push('/');
    }
    Some(out)
}

/// Parse a request head from the front of `buf`. `Ok(None)` means more
/// bytes are needed.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, Reject> {
    // nginx ignores empty lines before a request line.
    let start = buf
        .iter()
        .position(|&b| b != b'\r' && b != b'\n')
        .unwrap_or(buf.len());
    let body = &buf[start..];
    let reject = |status, reason, line: &[u8]| Reject {
        status,
        reason,
        line: clip(line, 256),
    };

    let Some(line_end) = body.iter().position(|&b| b == b'\n') else {
        if body.len() > MAX_REQUEST_LINE {
            return Err(reject(414, "request line too long", body));
        }
        return Ok(None);
    };
    let mut line = &body[..line_end];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    if line.len() > MAX_REQUEST_LINE {
        return Err(reject(414, "request line too long", line));
    }

    // Find the blank line that ends the head.
    let mut pos = line_end + 1;
    let mut header_lines = Vec::new();
    loop {
        let rest = &body[pos..];
        let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
            if start + body.len() > MAX_HEAD {
                return Err(reject(400, "head too large", line));
            }
            return Ok(None);
        };
        let mut h = &rest[..nl];
        if h.last() == Some(&b'\r') {
            h = &h[..h.len() - 1];
        }
        pos += nl + 1;
        if start + pos > MAX_HEAD {
            return Err(reject(400, "head too large", line));
        }
        if h.is_empty() {
            break;
        }
        header_lines.push(h);
        if header_lines.len() > MAX_HEADERS {
            return Err(reject(400, "too many headers", line));
        }
    }

    let mut words = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        return Err(reject(400, "malformed request line", line));
    };
    if method.is_empty() || method.len() > 32 || !method.iter().all(u8::is_ascii_uppercase) {
        return Err(reject(400, "bad method", line));
    }
    let version = match version {
        b"HTTP/1.1" => "HTTP/1.1",
        b"HTTP/1.0" => "HTTP/1.0",
        _ => return Err(reject(400, "bad version", line)),
    };
    // Absolute form: drop the scheme and authority.
    let origin: &[u8] = if target.starts_with(b"http://") || target.starts_with(b"https://") {
        let after = &target[target.iter().position(|&b| b == b':').unwrap_or(0) + 3..];
        match after.iter().position(|&b| b == b'/') {
            Some(i) => &after[i..],
            None => b"/",
        }
    } else {
        target
    };
    if !origin.starts_with(b"/") || origin.iter().any(|b| b.is_ascii_control() || *b == b' ') {
        return Err(reject(400, "bad target", line));
    }
    let (raw_path, query) = match origin.iter().position(|&b| b == b'?') {
        Some(i) => (&origin[..i], Some(clip(&origin[i + 1..], 1024))),
        None => (origin, None),
    };
    let Some(path) = normalise_path(raw_path) else {
        return Err(reject(400, "path above root", line));
    };

    let mut headers = Vec::with_capacity(header_lines.len());
    for h in header_lines {
        let Some(colon) = h.iter().position(|&b| b == b':') else {
            return Err(reject(400, "header without colon", line));
        };
        let name = &h[..colon];
        if name.is_empty()
            || name
                .iter()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(reject(400, "bad header name", line));
        }
        let value = clip(&h[colon + 1..], 1024).trim().to_string();
        headers.push((clip(name, 64), value));
    }
    let mut head = Head {
        method: String::from_utf8_lossy(method).into_owned(),
        target: clip(target, 2048),
        path,
        query,
        version: version.to_string(),
        headers,
        content_length: 0,
        head_len: start + pos,
    };
    if version == "HTTP/1.1" && head.header("host").is_none() {
        return Err(reject(400, "missing host", line));
    }
    if head.header("transfer-encoding").is_some() {
        return Err(reject(400, "transfer-encoding not supported", line));
    }
    if let Some(cl) = head.header("content-length") {
        if cl.is_empty() || cl.len() > 12 || !cl.bytes().all(|b| b.is_ascii_digit()) {
            return Err(reject(400, "bad content-length", line));
        }
        head.content_length = cl.parse().unwrap_or(usize::MAX);
    }
    Ok(Some(head))
}

fn form_field(body: &[u8], name: &str) -> Option<Vec<u8>> {
    body.split(|&b| b == b'&').find_map(|pair| {
        let mut kv = pair.splitn(2, |&b| b == b'=');
        let k = percent_decode(kv.next()?, true);
        (k == name.as_bytes()).then(|| percent_decode(kv.next().unwrap_or_default(), true))
    })
}

// ---------------------------------------------------------------------------
// Serving

/// What one request produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub bytes: Vec<u8>,
    pub status: u16,
    pub close: bool,
    pub severity: Severity,
    pub data: Map<String, Value>,
    pub hooks: Vec<String>,
    pub delay: Option<Jitter>,
}

pub struct Core {
    settings: HttpSettings,
    hooks: Vec<HookPoint>,
    jitter: Jitter,
    seed: u64,
    sink: EventSink,
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
            .http
            .clone()
            .ok_or_else(|| crate::ProfileError::Invalid(vec!["missing http section".into()]))?;
        Ok(Core {
            settings,
            hooks: profile.hooks.clone(),
            jitter: profile.jitter,
            seed: rng.next_u64(),
            sink,
        })
    }

    fn render(
        &self,
        status: u16,
        content_type: Option<&str>,
        extra: &[Header],
        body: &str,
        head_only: bool,
        keep_alive: bool,
    ) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
        if let Some(s) = &self.settings.server_header {
            out.push_str(&format!("Server: {s}\r\n"));
        }
        out.push_str(&format!("Date: {}\r\n", http_date(now_ms() / 1000)));
        if let Some(ct) = content_type {
            out.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
        out.push_str(if keep_alive {
            "Connection: keep-alive\r\n"
        } else {
            "Connection: close\r\n"
        });
        for h in extra.iter().chain(&self.settings.headers) {
            out.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        if !head_only {
            bytes.extend_from_slice(body.as_bytes());
        }
        bytes
    }

    fn error_page(
        &self,
        status: u16,
        head_only: bool,
        keep_alive: bool,
        extra: &[Header],
    ) -> Vec<u8> {
        match self.settings.errors.iter().find(|e| e.status == status) {
            Some(p) => self.render(
                status,
                Some(&p.content_type),
                extra,
                &p.body,
                head_only,
                keep_alive,
            ),
            None => self.render(status, None, extra, "", head_only, keep_alive),
        }
    }

    /// The reply for a request the parser refused.
    pub fn reject(&self, r: &Reject) -> Reply {
        let mut data = Map::new();
        data.insert("protocol".into(), json!("http"));
        data.insert("status".into(), json!(r.status));
        data.insert("result".into(), json!("rejected"));
        data.insert("error".into(), json!(r.reason));
        data.insert("request_line".into(), json!(r.line));
        Reply {
            bytes: self.error_page(r.status, false, false, &[]),
            status: r.status,
            close: true,
            severity: Severity::Low,
            data,
            hooks: Vec::new(),
            delay: None,
        }
    }

    /// Route one parsed request. Never panics on any input.
    pub fn handle(&self, head: &Head, body: &[u8]) -> Reply {
        let head_only = head.method == "HEAD";
        let keep_alive = head.keep_alive();
        let mut data = Map::new();
        data.insert("protocol".into(), json!("http"));
        data.insert("method".into(), json!(head.method));
        data.insert("path".into(), json!(clip(head.path.as_bytes(), 1024)));
        if head.target.as_bytes() != head.path.as_bytes() && head.query.is_none() {
            data.insert("target".into(), json!(head.target));
        }
        if let Some(q) = &head.query {
            data.insert("query".into(), json!(q));
        }
        data.insert("version".into(), json!(head.version));
        for (field, header) in [
            ("host", "host"),
            ("user_agent", "user-agent"),
            ("content_type", "content-type"),
        ] {
            if let Some(v) = head.header(header) {
                data.insert(field.into(), json!(clip(v.as_bytes(), 256)));
            }
        }
        let names: Vec<String> = head
            .headers
            .iter()
            .take(32)
            .map(|(n, _)| n.to_ascii_lowercase())
            .collect();
        data.insert("header_names".into(), json!(names));
        data.insert("bytes".into(), json!(body.len()));
        if !body.is_empty() {
            // Bodies are hashed, not kept (#16).
            data.insert("body_sha256".into(), json!(sha256_hex(body)));
        }

        let allows = |r: &Route, m: &str| {
            r.methods.iter().any(|x| x == m)
                || (m == "HEAD" && r.methods.iter().any(|x| x == "GET"))
        };
        let on_path: Vec<&Route> = self
            .settings
            .routes
            .iter()
            .filter(|r| route_matches(r, &head.path))
            .collect();
        let found = on_path.iter().find(|r| allows(r, &head.method));

        let (bytes, status, severity, delay, hooks) = match found {
            Some(route) => {
                data.insert("route".into(), json!(route.path));
                if !route.tags.is_empty() {
                    data.insert("tags".into(), json!(route.tags));
                }
                if let Some(c) = &route.capture {
                    if let Some(u) = form_field(body, &c.username_field) {
                        data.insert("username".into(), json!(clip(&u, 128)));
                    }
                    if let Some(p) = form_field(body, &c.password_field) {
                        data.insert("password_sha256".into(), json!(sha256_hex(&p)));
                        data.insert("password_len".into(), json!(p.len()));
                    }
                }
                let hooks = self
                    .hooks
                    .iter()
                    .filter(|h| {
                        h.on.path
                            .as_deref()
                            .is_some_and(|p| p == route.path || p == head.path)
                            && h.on.method.as_deref().is_none_or(|m| {
                                m.split('|').any(|x| x.eq_ignore_ascii_case(&head.method))
                            })
                    })
                    .map(|h| h.id.clone())
                    .collect();
                (
                    self.render(
                        route.status,
                        route.content_type.as_deref(),
                        &route.headers,
                        &route.body,
                        head_only,
                        keep_alive,
                    ),
                    route.status,
                    route.severity,
                    route.delay_ms,
                    hooks,
                )
            }
            None if !on_path.is_empty() => {
                let mut allowed: Vec<&str> = on_path
                    .iter()
                    .flat_map(|r| r.methods.iter().map(String::as_str))
                    .collect();
                allowed.sort_unstable();
                allowed.dedup();
                data.insert("allowed".into(), json!(allowed));
                (
                    self.error_page(405, head_only, keep_alive, &[]),
                    405,
                    Severity::Low,
                    None,
                    Vec::new(),
                )
            }
            None => (
                self.error_page(404, head_only, keep_alive, &[]),
                404,
                Severity::Info,
                None,
                Vec::new(),
            ),
        };
        data.insert("status".into(), json!(status));
        data.insert(
            "result".into(),
            json!(if status < 400 { "ok" } else { "error" }),
        );
        Reply {
            bytes,
            status,
            close: !keep_alive,
            severity,
            data,
            hooks,
            delay,
        }
    }

    fn hook_event(&self, hook: &HookPoint, head: &Head, seq: u32, started: Instant) -> HookEvent {
        HookEvent {
            hook_id: hook.id.clone(),
            catalogue_id: self.sink.context().catalogue_id.clone(),
            cve_id: hook.cve_id.clone(),
            stage: hook.stage,
            request_slice_ref: None,
            sequence_no: seq,
            t_offset_ms: started.elapsed().as_millis() as u64,
            cmd_lines: Vec::new(),
            file_writes: Vec::new(),
            implant_refs: Vec::new(),
            notes: Some(clip(
                format!("{} {}", head.method, head.path).as_bytes(),
                512,
            )),
        }
    }
}

impl Session for Core {
    async fn run(
        self: Arc<Self>,
        mut stream: TcpStream,
        peer: SocketAddr,
        local: SocketAddr,
        session_no: u64,
    ) {
        let started = Instant::now();
        let mut rng = Rng::seeded(self.seed ^ session_no.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let session = format!("{}-s{session_no}", self.sink.context().id_prefix);
        let idle = Duration::from_secs(u64::from(self.settings.keepalive_timeout_s));
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        let mut hook_seq = 0u32;

        for request_no in 1..=MAX_REQUESTS_PER_CONN {
            // Head.
            let head = loop {
                match parse_head(&buf) {
                    Ok(Some(h)) => break Ok(h),
                    Ok(None) => {}
                    Err(r) => break Err(r),
                }
                match tokio::time::timeout(idle, stream.read(&mut chunk)).await {
                    Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                    _ => {
                        let _ = stream.shutdown().await;
                        return;
                    }
                }
            };
            let (reply, head) = match head {
                Err(r) => (self.reject(&r), None),
                Ok(h) if h.content_length > self.settings.max_body_bytes => (
                    self.reject(&Reject {
                        status: 413,
                        reason: "body too large",
                        line: clip(format!("{} {}", h.method, h.target).as_bytes(), 256),
                    }),
                    None,
                ),
                Ok(h) => {
                    // Body.
                    let need = h.head_len + h.content_length;
                    while buf.len() < need {
                        match tokio::time::timeout(idle, stream.read(&mut chunk)).await {
                            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => {
                                let _ = stream.shutdown().await;
                                return;
                            }
                        }
                    }
                    let body: Vec<u8> = buf.drain(..need).skip(h.head_len).collect();
                    (self.handle(&h, &body), Some(h))
                }
            };

            self.jitter.wait(&mut rng).await;
            if let Some(d) = reply.delay {
                d.wait(&mut rng).await;
            }
            let write_ok = stream.write_all(&reply.bytes).await.is_ok();

            let mut data = reply.data.clone();
            data.insert("session".into(), json!(session));
            data.insert("request_no".into(), json!(request_no));
            self.sink
                .emit(Event::application(peer, local, reply.severity, data));
            if let Some(h) = &head {
                for id in &reply.hooks {
                    if let Some(hook) = self.hooks.iter().find(|x| &x.id == id) {
                        hook_seq += 1;
                        let he = self.hook_event(hook, h, hook_seq, started);
                        let mut hd = Map::new();
                        hd.insert("protocol".into(), json!("http"));
                        hd.insert("session".into(), json!(session));
                        hd.insert("method".into(), json!(h.method));
                        hd.insert("path".into(), json!(clip(h.path.as_bytes(), 1024)));
                        if let Some(sha) = reply.data.get("body_sha256") {
                            hd.insert("body_sha256".into(), sha.clone());
                        }
                        self.sink
                            .emit(Event::hook(peer, local, hook.severity, he, hd));
                    }
                }
            }
            if !write_ok || reply.close {
                break;
            }
        }
        let _ = stream.shutdown().await;
    }
}

/// The HTTP portal plug-in.
#[derive(Default)]
pub struct HttpPortalEmulator {
    server: Server,
}

impl HttpPortalEmulator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Emulator for HttpPortalEmulator {
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

    fn core() -> Core {
        let p = Profile::builtin("portal-generic").unwrap();
        let values: BTreeMap<String, String> = p
            .canaries
            .iter()
            .map(|c| (c.name.clone(), format!("cnry_{}", c.name)))
            .collect();
        let mut p = p.render(&values).unwrap();
        p.jitter = Jitter::NONE;
        let (sink, _rx) = EventSink::new(
            SinkContext::new("dcy-portal-1", "emulator/ssl-vpn/portal-generic"),
            64,
        );
        Core::new(&p, sink, &mut Rng::seeded(3)).unwrap()
    }

    fn head(raw: &str) -> Head {
        parse_head(raw.as_bytes()).unwrap().unwrap()
    }

    #[test]
    fn parses_heads_and_normalises_paths() {
        let h = head(
            "\r\nGET /portal/../portal//login?next=%2F HTTP/1.1\r\nHost: a\r\nUser-Agent: x\r\n\r\nrest",
        );
        assert_eq!(h.path, "/portal/login");
        assert_eq!(h.query.as_deref(), Some("next=%2F"));
        assert_eq!(h.header("user-agent"), Some("x"));
        assert_eq!(h.head_len, "\r\nGET /portal/../portal//login?next=%2F HTTP/1.1\r\nHost: a\r\nUser-Agent: x\r\n\r\n".len());
        assert_eq!(parse_head(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap(), None);
        let h = head("GET http://203.0.113.20/portal/login HTTP/1.0\r\n\r\n");
        assert_eq!(h.path, "/portal/login");
        assert_eq!(normalise_path(b"/%2e%2e/etc/passwd"), None);
        assert_eq!(normalise_path(b"/a/./b/"), Some("/a/b/".into()));
    }

    #[test]
    fn rejects_bad_requests_with_the_right_status() {
        let status = |raw: &[u8]| parse_head(raw).unwrap_err().status;
        assert_eq!(status(b"GARBAGE\r\n\r\n"), 400);
        assert_eq!(status(b"get / HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
        assert_eq!(status(b"GET / HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(status(b"GET / HTTP/2.0\r\nHost: a\r\n\r\n"), 400);
        assert_eq!(status(b"GET /../x HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
        assert_eq!(
            status(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"),
            400
        );
        assert_eq!(
            status(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"),
            400
        );
        let long = format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(9000));
        assert_eq!(status(long.as_bytes()), 414);
        let big = format!(
            "GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n",
            "b".repeat(9000)
        );
        assert_eq!(status(big.as_bytes()), 400);
    }

    #[test]
    fn routes_405_404_and_credentials() {
        let c = core();
        let r = c.handle(
            &head("DELETE /portal/login HTTP/1.1\r\nHost: a\r\n\r\n"),
            b"",
        );
        assert_eq!(r.status, 405);
        let r = c.handle(&head("GET /nope HTTP/1.1\r\nHost: a\r\n\r\n"), b"");
        assert_eq!(r.status, 404);
        let body = b"username=alice%40example.org&password=Winter%2B2026";
        let r = c.handle(
            &head("POST /portal/login HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 51\r\n\r\n"),
            body,
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.data["username"], json!("alice@example.org"));
        assert_eq!(r.data["password_sha256"], json!(sha256_hex(b"Winter+2026")));
        assert!(!serde_json::to_string(&r.data).unwrap().contains("Winter"));
        let r = c.handle(&head("HEAD /portal/login HTTP/1.1\r\nHost: a\r\n\r\n"), b"");
        assert_eq!(r.status, 200);
        assert!(r.bytes.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let c = core();
        let mut rng = Rng::seeded(0xABCD);
        let alphabet: &[u8] = b"GETPOST /portal/login?%2e.:\r\nHost: a\r\nContent-Length: 5\r\n";
        for round in 0..3000 {
            let len = rng.range(0, 700) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    if round % 2 == 0 {
                        rng.next_u64() as u8
                    } else {
                        alphabet[rng.range(0, alphabet.len() as u64 - 1) as usize]
                    }
                })
                .collect();
            match parse_head(&bytes) {
                Ok(Some(h)) => {
                    assert!(h.head_len <= bytes.len());
                    let body = &bytes[h.head_len..bytes.len().min(h.head_len + h.content_length)];
                    let r = c.handle(&h, body);
                    assert!(r.bytes.starts_with(b"HTTP/1.1 "));
                }
                Ok(None) => {}
                Err(r) => {
                    assert!(c.reject(&r).bytes.starts_with(b"HTTP/1.1 "));
                }
            }
            let _ = normalise_path(&bytes);
            let _ = form_field(&bytes, "password");
        }
    }
}
