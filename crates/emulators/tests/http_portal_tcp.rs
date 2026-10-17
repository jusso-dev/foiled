//! The HTTP portal emulator over a real loopback socket.

mod common;

use std::time::Duration;

use foiled_core::capture::{Channel, Severity};
use foiled_emulators::http_portal::HttpPortalEmulator;
use foiled_emulators::{Emulator, Health};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn read_response(r: &mut BufReader<TcpStream>, head_only: bool) -> Response {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line))
        .await
        .expect("response in time")
        .unwrap();
    let status: u16 = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        r.read_line(&mut h).await.unwrap();
        let h = h.trim_end_matches("\r\n");
        if h.is_empty() {
            break;
        }
        let (n, v) = h.split_once(": ").unwrap();
        headers.push((n.to_string(), v.to_string()));
    }
    let len: usize = headers
        .iter()
        .find(|(n, _)| n == "Content-Length")
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0u8; if head_only { 0 } else { len }];
    r.read_exact(&mut body).await.unwrap();
    Response {
        status,
        headers,
        body: String::from_utf8(body).unwrap(),
    }
}

async fn send(r: &mut BufReader<TcpStream>, req: &[u8]) {
    r.get_mut().write_all(req).await.unwrap();
}

#[tokio::test]
async fn keep_alive_session_serves_routes_and_logs_each_request() {
    let mut emu = HttpPortalEmulator::new();
    let (addr, mut rx) = common::start(&mut emu, &common::rendered("portal-generic")).await;
    let mut r = BufReader::new(TcpStream::connect(addr).await.unwrap());

    send(
        &mut r,
        b"GET / HTTP/1.1\r\nHost: 203.0.113.20\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    )
    .await;
    let res = read_response(&mut r, false).await;
    assert_eq!(res.status, 302);
    assert_eq!(res.header("Location"), Some("/portal/login"));
    let names: Vec<&str> = res.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "Server",
            "Date",
            "Content-Type",
            "Content-Length",
            "Connection",
            "Location"
        ],
        "nginx header order (FR-10)"
    );
    assert_eq!(res.header("Server"), Some("nginx"));
    assert!(res.header("Date").unwrap().ends_with(" GMT"));

    send(&mut r, b"GET /portal/login HTTP/1.1\r\nHost: a\r\n\r\n").await;
    let login = read_response(&mut r, false).await;
    assert_eq!(login.status, 200);
    assert!(login.body.contains("<title>Gateway Portal</title>"));
    common::assert_no_tells(&login.body, "login page");

    let form = "username=admin&password=Spring2026%21";
    send(
        &mut r,
        format!(
            "POST /portal/login HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
            form.len()
        )
        .as_bytes(),
    )
    .await;
    let failed = read_response(&mut r, false).await;
    assert_eq!(failed.status, 200);
    assert!(failed.body.contains("Invalid username or password."));

    send(
        &mut r,
        b"POST /portal/cgi-bin/diagnostics HTTP/1.1\r\nHost: a\r\nContent-Length: 18\r\n\r\nhost=;id;uname -a;",
    )
    .await;
    let diag = read_response(&mut r, false).await;
    assert_eq!(diag.status, 200);
    assert_eq!(diag.body, r#"{"status":"ok","result":""}"#);

    send(
        &mut r,
        b"GET /portal/static/js/portal-settings.js.bak HTTP/1.1\r\nHost: a\r\n\r\n",
    )
    .await;
    let bak = read_response(&mut r, false).await;
    assert!(bak.body.contains("telemetryKey: \"cnry-portal_api_key\""));

    send(
        &mut r,
        b"GET /portal/cgi-bin/diagnostics HTTP/1.1\r\nHost: a\r\n\r\n",
    )
    .await;
    let not_allowed = read_response(&mut r, false).await;
    assert_eq!(not_allowed.status, 405);
    assert!(not_allowed.body.contains("<title>405 Not Allowed</title>"));

    send(&mut r, b"HEAD /portal/login HTTP/1.1\r\nHost: a\r\n\r\n").await;
    let head = read_response(&mut r, true).await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());

    send(
        &mut r,
        b"GET /.env HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
    )
    .await;
    let missing = read_response(&mut r, false).await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.header("Connection"), Some("close"));
    assert!(missing.body.contains("<center>nginx</center>"));
    let mut rest = Vec::new();
    r.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "connection closed after Connection: close");

    // 8 requests, plus one hook for the diagnostics POST.
    let events = common::collect(&mut rx, 9).await;
    assert_eq!(events.len(), 9);
    common::assert_valid(&events);
    let app: Vec<_> = events
        .iter()
        .filter(|e| e.channel == Channel::Application)
        .collect();
    assert_eq!(app.len(), 8);
    let summary: Vec<(String, u64)> = app
        .iter()
        .map(|e| {
            (
                format!(
                    "{} {}",
                    e.data["method"].as_str().unwrap(),
                    e.data["path"].as_str().unwrap()
                ),
                e.data["status"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("GET /".to_string(), 302),
            ("GET /portal/login".into(), 200),
            ("POST /portal/login".into(), 200),
            ("POST /portal/cgi-bin/diagnostics".into(), 200),
            ("GET /portal/static/js/portal-settings.js.bak".into(), 200),
            ("GET /portal/cgi-bin/diagnostics".into(), 405),
            ("HEAD /portal/login".into(), 200),
            ("GET /.env".into(), 404),
        ]
    );
    assert_eq!(app[0].data["user_agent"], json!("Mozilla/5.0"));
    assert_eq!(app[0].data["request_no"], json!(1));
    assert_eq!(app[2].data["username"], json!("admin"));
    assert!(app[2].data.contains_key("password_sha256"));
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("Spring2026")
    );
    assert_eq!(app[3].severity, Severity::High);
    assert!(app[3].data.contains_key("body_sha256"));
    assert!(
        !serde_json::to_string(&app[3].data)
            .unwrap()
            .contains("uname")
    );
    assert_eq!(app[4].severity, Severity::High);
    assert_eq!(app[4].data["tags"], json!(["canary", "sensitive"]));

    let hook = events
        .iter()
        .find(|e| e.channel == Channel::Hook)
        .and_then(|e| e.hook.as_ref())
        .unwrap();
    assert_eq!(hook.hook_id, "portal.diagnostics-exec");
    assert_eq!(hook.cve_id.as_deref(), Some("CVE-2099-0002"));
    assert_eq!(hook.catalogue_id, "emulator/ssl-vpn/portal-generic");
    assert_eq!(hook.sequence_no, 1);

    emu.stop().await;
}

async fn one_shot(addr: std::net::SocketAddr, req: &[u8]) -> (Response, Vec<u8>) {
    let mut r = BufReader::new(TcpStream::connect(addr).await.unwrap());
    send(&mut r, req).await;
    let res = read_response(&mut r, false).await;
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), r.read_to_end(&mut rest)).await;
    (res, rest)
}

#[tokio::test]
async fn bad_requests_get_nginx_errors_and_a_closed_connection() {
    let mut emu = HttpPortalEmulator::new();
    let (addr, mut rx) = common::start(&mut emu, &common::rendered("portal-generic")).await;

    let long_uri = format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(9000));
    let big_body = "POST /portal/login HTTP/1.1\r\nHost: a\r\nContent-Length: 999999\r\n\r\n";
    let cases: Vec<(Vec<u8>, u16, &str)> = vec![
        (b"GARBAGE\r\n\r\n".to_vec(), 400, "400 Bad Request"),
        (b"GET / HTTP/1.1\r\n\r\n".to_vec(), 400, "400 Bad Request"),
        (
            b"GET /../../etc/passwd HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),
            400,
            "400 Bad Request",
        ),
        (long_uri.into_bytes(), 414, "414 Request-URI Too Large"),
        (
            big_body.as_bytes().to_vec(),
            413,
            "413 Request Entity Too Large",
        ),
    ];
    for (req, status, title) in &cases {
        let (res, rest) = one_shot(addr, req).await;
        assert_eq!(res.status, *status);
        assert_eq!(res.header("Connection"), Some("close"));
        assert!(res.body.contains(&format!("<title>{title}</title>")));
        assert!(rest.is_empty());
    }
    // HTTP/1.0 without keep-alive closes after one response.
    let (res, rest) = one_shot(addr, b"GET /robots.txt HTTP/1.0\r\n\r\n").await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, "User-agent: *\nDisallow: /\n");
    assert!(rest.is_empty());

    let events = common::collect(&mut rx, cases.len() + 1).await;
    assert_eq!(events.len(), cases.len() + 1);
    common::assert_valid(&events);
    assert!(
        events[..cases.len()]
            .iter()
            .all(|e| e.data["result"] == json!("rejected"))
    );
    assert!(matches!(emu.health(), Health::Serving { .. }));
    emu.stop().await;
}
