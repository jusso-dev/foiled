#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the Foiled demo decoy app. Standard library (unittest) only.

These tests exercise the synthetic FOILED-DEMO-0001 behaviour deliberately: the
traversal case proves the decoy writes outside the upload root and fires the
instrumentation hook. Everything runs against an in-process server on an
ephemeral port; nothing is written outside a temporary directory.
"""

import http.client
import io
import json
import os
import tempfile
import threading
import unittest

import server


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.upload_root = os.path.join(self.tmp.name, "srv", "demo-app", "uploads")
        self.access_buf = io.StringIO()
        self.event_buf = io.StringIO()
        config = server.Config(upload_root=self.upload_root)
        self.httpd = server.build_server(
            "127.0.0.1",
            0,
            config,
            access_log=server.JsonLog(self.access_buf),
            event_log=server.JsonLog(self.event_buf),
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    # --- tests ---------------------------------------------------------------

    def test_index_serves_with_banner(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Server"), "demo-app/1.0.0")
        self.assertIn(b"File Exchange", body)

    def test_normal_upload_lands_in_upload_dir(self):
        status, _h, body = self.request(
            "POST", "/api/upload?path=report.txt", body=b"hello"
        )
        self.assertEqual(status, 201)
        result = json.loads(body)
        self.assertFalse(result["escaped_upload_root"])
        target = os.path.join(self.upload_root, "report.txt")
        self.assertTrue(os.path.isfile(target))
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), b"hello")
        # No hook event should have been emitted for a well-behaved upload.
        self.assertEqual(self.event_buf.getvalue().strip(), "")

    def test_traversal_upload_escapes_and_fires_hook(self):
        marker = b"owned-by-demo"
        status, _h, body = self.request(
            "POST", "/api/upload?path=../../tmp/x", body=marker
        )
        self.assertEqual(status, 201)
        result = json.loads(body)
        self.assertTrue(result["escaped_upload_root"])
        # The file landed outside the upload root (synthetic FOILED-DEMO-0001).
        escaped_target = os.path.realpath(
            os.path.join(self.upload_root, "../../tmp/x")
        )
        self.assertFalse(escaped_target.startswith(os.path.realpath(self.upload_root)))
        self.assertTrue(os.path.isfile(escaped_target))
        with open(escaped_target, "rb") as handle:
            self.assertEqual(handle.read(), marker)
        # Exactly one hook line, valid JSON, with the expected identifiers.
        lines = [l for l in self.event_buf.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        event = json.loads(lines[0])
        self.assertEqual(event["kind"], "hook")
        self.assertEqual(event["hook_id"], "demo-app.upload-path-traversal")
        self.assertEqual(event["cve_id"], "FOILED-DEMO-0001")
        self.assertEqual(event["stage"], "trigger")

    def test_oversize_body_is_rejected(self):
        oversize = server.MAX_BODY_BYTES + 1
        headers = {"Content-Length": str(oversize)}
        # Send a header that claims an oversize body; the server should reject it
        # on the declared length before reading a full payload.
        status, _h, body = self.request(
            "POST", "/api/upload?path=big.bin", body=b"x", headers=headers
        )
        self.assertEqual(status, 413)
        self.assertNotIn(
            "big.bin", os.listdir(self.upload_root) if os.path.isdir(self.upload_root) else []
        )

    def test_access_log_lines_are_valid_json(self):
        self.request("GET", "/")
        self.request("GET", "/healthz")
        self.request("POST", "/api/upload?path=a.txt", body=b"abc")
        lines = [l for l in self.access_buf.getvalue().splitlines() if l.strip()]
        self.assertGreaterEqual(len(lines), 3)
        for line in lines:
            record = json.loads(line)
            for field in ("ts", "src", "method", "path", "status", "bytes", "user_agent"):
                self.assertIn(field, record)


if __name__ == "__main__":
    unittest.main()
