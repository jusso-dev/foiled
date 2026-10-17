#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) Foiled contributors
"""Foiled demo app 1.0.0: a small synthetic decoy for the MVP walkthrough.

THIS IS A DEMO DECOY for the Foiled honeypot project (#22). It exists so
contributors have a tiny, legal, MIT licensed victim to exercise the capture
layer (#9) and instrumentation hooks (#32) without mirroring real vulnerable
software. It carries one SYNTHETIC weakness, FOILED-DEMO-0001, which is a
made-up identifier and not a real CVE.

Safety properties are intentional and must stay:
  * Uploaded content is written to disk and NEVER executed, imported or parsed.
  * Request bodies are capped at MAX_BODY_BYTES (1 MiB).
  * Every request is logged as one JSON line on stdout for the capture layer.
  * The instrumentation hook fails open: if emitting it fails, the decoy keeps
    serving. Hooks are evidence, not a control, for the decoy.

Run only inside a Foiled sandbox under deny-by-default egress. Standard library
only; works on Python 3.9 and later.
"""

import argparse
import html
import json
import os
import itertools
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"
SERVER_BANNER = "demo-app/" + VERSION
CATALOGUE_ID = "foiled/demo-app/1.0.0"
HOOK_ID = "demo-app.upload-path-traversal"
CVE_ID = "FOILED-DEMO-0001"
# Hook lines carry a process-wide sequence number so the host agent can order
# hits that share a millisecond. itertools.count is safe across threads in
# CPython because next() runs under the GIL.
HOOK_SEQUENCE = itertools.count(1)

MAX_BODY_BYTES = 1024 * 1024
MAX_LOGGED_TARGET = 2048
DEFAULT_UPLOAD_ROOT = "/srv/demo-app/uploads"
DEFAULT_PORT = 8080

# Decoy-only credentials from the catalogue entry. The host replaces them with
# a per-decoy canary at start (#17) through these environment variables.
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "foiled-demo-admin"


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def truncate(value, limit=MAX_LOGGED_TARGET):
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit] + "...[truncated]"


class JsonLog:
    """Writes one JSON object per line to a stream, safe across threads."""

    def __init__(self, stream):
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, record):
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


def render_page(title, body):
    return PAGE.format(title=html.escape(title), body=body, version=VERSION)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title} - File Exchange Admin</title>
<style>
body {{ font-family: sans-serif; margin: 0; background: #f4f5f7; color: #222; }}
header {{ background: #2d3e50; color: #fff; padding: 12px 24px; }}
main {{ max-width: 720px; margin: 24px auto; background: #fff; padding: 24px;
       border: 1px solid #ddd; }}
footer {{ text-align: center; font-size: 12px; color: #777; margin: 24px; }}
label {{ display: block; margin-top: 12px; }}
.error {{ color: #b00020; }}
</style>
</head>
<body>
<!-- Foiled demo app {version}: synthetic decoy for FOILED-DEMO-0001. -->
<header>File Exchange Admin</header>
<main>
{body}
</main>
<footer>demo-app {version}</footer>
</body>
</html>
"""

INDEX_BODY = """<h1>File Exchange</h1>
<p>Internal file exchange for the operations team. Please sign in to manage
uploaded documents.</p>
<p><a href="/login">Administrator sign in</a></p>
"""

LOGIN_BODY = """<h1>Administrator sign in</h1>
{notice}
<form method="post" action="/login">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input name="password" type="password"
       autocomplete="current-password"></label>
<label><button type="submit">Sign in</button></label>
</form>
"""

DASHBOARD_BODY = """<h1>Document manager</h1>
<p>Signed in as <strong>{user}</strong>.</p>
<p>Use <code>POST /api/upload?path=NAME</code> to store a document in the
upload area. Example:</p>
<pre>curl --data-binary @report.pdf \\
  'http://HOST:8080/api/upload?path=report.pdf'</pre>
"""


class Config:
    """Runtime configuration, resolved from environment with safe defaults."""

    def __init__(self, upload_root=None, admin_user=None, admin_password=None):
        self.upload_root = os.path.abspath(
            upload_root
            or os.environ.get("DEMO_APP_UPLOAD_ROOT", DEFAULT_UPLOAD_ROOT)
        )
        self.admin_user = admin_user or os.environ.get(
            "DEMO_APP_ADMIN_USER", DEFAULT_ADMIN_USER
        )
        self.admin_password = admin_password or os.environ.get(
            "DEMO_APP_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD
        )

    def ensure_upload_root(self):
        os.makedirs(self.upload_root, exist_ok=True)


class DemoHandler(BaseHTTPRequestHandler):
    # Set by make_handler(). Shared read-only config and the JSON loggers.
    config = None
    access_log = None
    event_log = None

    server_version = SERVER_BANNER
    sys_version = ""  # suppress the default Python version in the Server header
    protocol_version = "HTTP/1.1"

    def version_string(self):
        # Exact banner with no trailing space (the base class joins server and
        # sys version with a space). Catalogue banner_hints depend on this.
        return SERVER_BANNER

    # --- logging -------------------------------------------------------------

    def log_message(self, fmt, *args):
        # Silence the default stderr access log; we emit structured JSON instead.
        return

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "-"

    def _access(self, status, nbytes):
        self.access_log.write(
            {
                "ts": utc_now(),
                "src": self._client_ip(),
                "method": self.command,
                "path": truncate(self.path),
                "status": int(status),
                "bytes": int(nbytes),
                "user_agent": truncate(self.headers.get("User-Agent", "-"), 512),
            }
        )

    # --- helpers -------------------------------------------------------------

    def _send_html(self, status, body_html):
        data = body_html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self._access(status, len(data))

    def _send_json(self, status, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self._access(status, len(data))

    def _read_body(self):
        """Read the request body, enforcing the 1 MiB cap.

        Returns the body bytes, or None if the cap was exceeded (in which case a
        413 response has already been sent).
        """
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            self._send_json(
                413, {"error": "payload too large", "max": MAX_BODY_BYTES}
            )
            return None
        return self.rfile.read(length) if length > 0 else b""

    # --- routing -------------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/" or route == "/index.html":
            self._send_html(200, render_page("File Exchange", INDEX_BODY))
        elif route == "/login":
            self._send_html(
                200, render_page("Sign in", LOGIN_BODY.format(notice=""))
            )
        elif route == "/healthz":
            self._send_json(200, {"status": "ok", "version": VERSION})
        else:
            self._send_html(404, render_page("Not found", "<h1>404 Not found</h1>"))

    def do_POST(self):
        route = urlsplit(self.path).path
        if route == "/login":
            self._handle_login()
        elif route == "/api/upload":
            self._handle_upload()
        else:
            self._send_html(404, render_page("Not found", "<h1>404 Not found</h1>"))

    def _handle_login(self):
        body = self._read_body()
        if body is None:
            return
        form = parse_qs(body.decode("utf-8", "replace"))
        user = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]
        # Plain comparison on purpose: this is a decoy login. The credentials are
        # the decoy canary; a "successful" login just renders a fake dashboard.
        if user == self.config.admin_user and password == self.config.admin_password:
            self._send_html(
                200, render_page("Dashboard", DASHBOARD_BODY.format(user=html.escape(user)))
            )
        else:
            notice = '<p class="error">Invalid credentials.</p>'
            self._send_html(
                401, render_page("Sign in", LOGIN_BODY.format(notice=notice))
            )

    def _emit_hook(self, stage, resolved_path, request_path, started, notes,
                   file_writes=None):
        """Emit one structured instrumentation-hook line for FOILED-DEMO-0001 (#32).

        This is evidence for the capture layer, not a control. It MUST fail open:
        if logging raises for any reason, the decoy keeps serving so the synthetic
        vulnerability still behaves as a real one would. Hooks never block the
        decoy and never phone home. Field names match the capture envelope's
        `hook` object (docs/instrumentation.md).
        """
        try:
            record = {
                "kind": "hook",
                "ts": utc_now(),
                "hook_id": HOOK_ID,
                "catalogue_id": CATALOGUE_ID,
                "cve_id": CVE_ID,
                "stage": stage,
                "sequence_no": next(HOOK_SEQUENCE),
                "t_offset_ms": int((time.monotonic() - started) * 1000),
                "src": self._client_ip(),
                "request_path": truncate(request_path),
                "resolved_path": truncate(resolved_path),
                "upload_root": self.config.upload_root,
                "notes": notes,
            }
            if file_writes:
                record["file_writes"] = [truncate(p) for p in file_writes]
            self.event_log.write(record)
        except Exception:
            # Fail open. The decoy keeps working even if the hook cannot be logged.
            pass

    def _handle_upload(self):
        """POST /api/upload?path=NAME stores the body under the upload root.

        FOILED-DEMO-0001 (SYNTHETIC, not a real CVE): the `path` parameter is
        joined onto UPLOAD_ROOT with os.path.join and is NOT normalised or
        confined, so a traversal value such as `../../tmp/x` resolves outside the
        upload directory. This weakness is DELIBERATE and documented: it is the
        whole point of this demo decoy. Do not add confinement here.

        The content is only ever written to disk. It is never executed, imported,
        rendered or parsed. The body is capped at 1 MiB by _read_body().

        When an escaping upload's name ends in `.sh`, the hook also reports a
        `post_exploit` stage after the write, recording the resolved path in
        `file_writes`. The script is still never executed.
        """
        started = time.monotonic()
        query = parse_qs(urlsplit(self.path).query)
        rel_path = (query.get("path") or [""])[0]
        if not rel_path:
            self._send_json(400, {"error": "missing path parameter"})
            return

        body = self._read_body()
        if body is None:
            return  # 413 already sent by _read_body

        # --- BEGIN DELIBERATE SYNTHETIC VULNERABILITY (FOILED-DEMO-0001) ---
        # No normalisation and no confinement check: os.path.join lets an
        # absolute or `..` path escape UPLOAD_ROOT. This mirrors a real path
        # traversal file write and exists so the capture layer and the hook have
        # something genuine to observe. Keep it as is.
        target = os.path.join(self.config.upload_root, rel_path)
        # --- END DELIBERATE SYNTHETIC VULNERABILITY ---

        # Detect, for evidence only, whether the resolved path escaped the upload
        # root. This decides whether to fire the hook. It does NOT change the
        # write: the write happens either way so the decoy stays vulnerable.
        resolved = os.path.realpath(target)
        root = os.path.realpath(self.config.upload_root)
        escaped = os.path.commonpath([resolved, root]) != root
        if escaped:
            self._emit_hook(
                "trigger", resolved, self.path, started,
                "resolved path escaped the upload root",
            )

        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(body)

        if escaped and rel_path.endswith(".sh"):
            self._emit_hook(
                "post_exploit", resolved, self.path, started,
                "shell script written outside the upload root; never executed",
                file_writes=[resolved],
            )

        self._send_json(
            201,
            {
                "stored": rel_path,
                "bytes": len(body),
                "escaped_upload_root": escaped,
            },
        )


def make_handler(config, access_log, event_log):
    """Build a handler class bound to this config and loggers."""

    class BoundHandler(DemoHandler):
        pass

    BoundHandler.config = config
    BoundHandler.access_log = access_log
    BoundHandler.event_log = event_log
    return BoundHandler


def build_server(host, port, config, access_log=None, event_log=None):
    """Create the HTTP server. Returns the ThreadingHTTPServer (not started)."""
    access_log = access_log or JsonLog(sys.stdout)
    event_log = event_log or access_log
    config.ensure_upload_root()
    handler = make_handler(config, access_log, event_log)
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Foiled demo decoy app")
    parser.add_argument("--host", default=os.environ.get("DEMO_APP_HOST", "0.0.0.0"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("DEMO_APP_PORT", DEFAULT_PORT)),
    )
    parser.add_argument("--upload-root", default=None)
    args = parser.parse_args(argv)

    config = Config(upload_root=args.upload_root)
    server = build_server(args.host, args.port, config)
    log = JsonLog(sys.stdout)
    log.write(
        {
            "ts": utc_now(),
            "event": "start",
            "version": VERSION,
            "host": args.host,
            "port": args.port,
            "upload_root": config.upload_root,
        }
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
