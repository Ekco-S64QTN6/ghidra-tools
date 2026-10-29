#!/usr/bin/env python3
"""Regression tests for dashboard path containment, output safety, and bind defaults."""

import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import dashboard  # noqa: E402


class DashboardSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_output_dir = dashboard.OUTPUT_DIR
        self.old_db_path = dashboard.DB_PATH
        self.output_dir = os.path.join(self.temp.name, "output")
        self.sample_dir = os.path.join(self.output_dir, "sample")
        os.makedirs(self.sample_dir)
        dashboard.OUTPUT_DIR = self.output_dir
        dashboard.DB_PATH = os.path.join(self.output_dir, "reports.db")

        self.secret_path = os.path.join(self.temp.name, "secret.txt")
        with open(self.secret_path, "w", encoding="utf-8") as handle:
            handle.write("do not expose")

        with open(os.path.join(self.sample_dir, "report_latest.json"), "w", encoding="utf-8") as handle:
            handle.write('{"ok": true}')
        with open(os.path.join(self.sample_dir, "report_latest.html"), "w", encoding="utf-8") as handle:
            handle.write("<!doctype html><script>alert('sample')</script>")

        self.server = dashboard.create_server(0, host="127.0.0.1")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        dashboard.OUTPUT_DIR = self.old_output_dir
        dashboard.DB_PATH = self.old_db_path
        self.temp.cleanup()

    def request(self, target):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request("GET", target)
            response = connection.getresponse()
            body = response.read()
            return response.status, dict(response.getheaders()), body
        finally:
            connection.close()

    def test_dashboard_defaults_to_loopback(self):
        with patch.dict(os.environ, {}, clear=False):
            previous = os.environ.pop("GHIDRA_DASHBOARD_HOST", None)
            try:
                server = dashboard.create_server(0)
                try:
                    self.assertEqual(server.server_address[0], "127.0.0.1")
                finally:
                    server.server_close()
            finally:
                if previous is not None:
                    os.environ["GHIDRA_DASHBOARD_HOST"] = previous

    def test_report_files_are_served_from_output(self):
        status, headers, body = self.request("/output/sample/report_latest.json")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"ok": true}')
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_traversal_and_symlink_escape_are_rejected(self):
        escaped_link = os.path.join(self.sample_dir, "escaped.txt")
        os.symlink(self.secret_path, escaped_link)
        for target in (
            "/output/../secret.txt",
            "/output/%2e%2e/secret.txt",
            "/output/%252e%252e/secret.txt",
            "/output/sample/../../secret.txt",
            "/output/sample/escaped.txt",
            "/output/%00secret.txt",
        ):
            with self.subTest(target=target):
                status, _headers, body = self.request(target)
                self.assertEqual(status, 404)
                self.assertNotIn(b"do not expose", body)

    def test_dashboard_security_headers_and_escaping(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("Content-Security-Policy", headers)
        page = body.decode("utf-8")
        self.assertIn("function escapeHtml(value)", page)
        self.assertIn("$" + "{escapeHtml(r.file)}", page)
        self.assertIn("encodeURIComponent(r.file)", page)
        self.assertIn("$" + "{escapeHtml(m)}", page)
        self.assertNotIn("$" + "{r.file}", page)

    def test_escape_helper_escapes_markup_when_node_is_available(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js not installed; source assertions still cover use of escapeHtml")
        _status, _headers, body = self.request("/")
        page = body.decode("utf-8")
        match = re.search(r"function escapeHtml\(value\) \{.*?\n    \}", page, re.DOTALL)
        self.assertIsNotNone(match)
        payload = '<img src=x onerror="alert(\'xss\')">'
        script = match.group(0) + "\nprocess.stdout.write(escapeHtml(" + json.dumps(payload) + "));"
        result = subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)
        self.assertEqual(
            result.stdout,
            "&lt;img src=x onerror=&quot;alert(&#39;xss&#39;)&quot;&gt;",
        )

    def test_exported_html_is_sandboxed_by_csp(self):
        for target in (
            "/output/sample/report_latest.html",
            "/output/sample/report_latest%2ehtml",
        ):
            with self.subTest(target=target):
                status, headers, body = self.request(target)
                self.assertEqual(status, 200)
                self.assertIn("sandbox", headers.get("Content-Security-Policy", ""))
                self.assertNotIn("script-src", headers.get("Content-Security-Policy", ""))
                self.assertIn(b"<script>", body)

    def test_search_query_length_is_bounded(self):
        status, _headers, body = self.request("/api/search?q=" + ("a" * 257))
        self.assertEqual(status, 400)
        self.assertIn(b"character limit", body)

    def test_large_report_response_is_rejected(self):
        with patch.object(dashboard, "MAX_SERVED_FILE_BYTES", 4):
            status, _headers, _body = self.request("/output/sample/report_latest.json")
        self.assertEqual(status, 413)


if __name__ == "__main__":
    unittest.main(verbosity=2)
