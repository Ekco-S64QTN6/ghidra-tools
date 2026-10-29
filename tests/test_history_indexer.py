#!/usr/bin/env python3
"""Regression tests for mapping the JSON report contract into SQLite history."""

import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import index_report  # noqa: E402


class HistoryIndexerFieldTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="history-indexer-")
        self.old_db_path = index_report.DB_PATH
        index_report.DB_PATH = os.path.join(self.temp.name, "reports.db")

    def tearDown(self):
        index_report.DB_PATH = self.old_db_path
        self.temp.cleanup()

    def index_value(self, value):
        path = os.path.join(self.temp.name, "fixture-report.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(value, handle)
        index_report.index_report(path)
        connection = sqlite3.connect(index_report.DB_PATH)
        self.addCleanup(connection.close)
        return connection

    def test_current_json_generated_iocs_and_mitre_id_are_indexed(self):
        connection = self.index_value({
            "file": "current-sample.bin",
            "format_label": "ELF",
            "generated": "2026-10-29T15:00:00-05:00",
            "hashes": {"md5": "md5-current", "sha256": "sha-current"},
            "threat_summary": {
                "risk_score": 72,
                "risk_level": "HIGH",
                "indicators": [{
                    "category": "execution",
                    "description": "Synthetic test indicator",
                    "mitre_id": "T1059",
                    "weight": 12,
                }],
            },
            "analysis_stats": {"function_count": 9},
            "suspicious_apis": [{
                "library": "KERNEL32.dll",
                "function": "CreateRemoteThread",
                "mitre": "T1055",
                "category": "Process Injection",
            }],
            "iocs": [{
                "type": "url",
                "value": "https://example.invalid/payload",
                "address": "0x401000",
            }],
        })
        report = connection.execute(
            "SELECT timestamp, risk_score, risk_level, function_count FROM reports WHERE file = ?",
            ("current-sample.bin",),
        ).fetchone()
        self.assertEqual(report, ("2026-10-29T15:00:00-05:00", 72, "HIGH", 9))
        ioc_rows = connection.execute(
            "SELECT type, value, address FROM iocs WHERE report_id = (SELECT id FROM reports WHERE file = ?)",
            ("current-sample.bin",),
        ).fetchall()
        self.assertEqual(ioc_rows, [("url", "https://example.invalid/payload", "0x401000")])
        indicator_rows = connection.execute(
            "SELECT category, description, mitre, weight FROM indicators WHERE report_id = (SELECT id FROM reports WHERE file = ?)",
            ("current-sample.bin",),
        ).fetchall()
        self.assertEqual(indicator_rows, [("execution", "Synthetic test indicator", "T1059", 12)])

    def test_search_scope_matches_documented_indexed_fields(self):
        self.index_value({
            "file": "search-scope-sample.bin",
            "generated": "2026-10-29T15:00:00-05:00",
            "hashes": {"md5": "md5-scope", "sha256": "sha-scope"},
            "threat_summary": {
                "risk_score": 72,
                "risk_level": "HIGH",
                "indicators": [{
                    "category": "execution",
                    "description": "Synthetic indicator searchable by description",
                    "mitre_id": "T1059",
                    "weight": 12,
                }],
            },
            "suspicious_apis": [{
                "library": "KERNEL32.dll",
                "function": "CreateRemoteThread",
                "mitre": "T1055",
                "category": "Process Injection",
            }],
            "iocs": [{
                "type": "url",
                "value": "https://example.invalid/history-search",
                "address": "0x401000",
            }],
            "deobfuscated_strings": [{"value": "not-indexed-recovered-string"}],
            "top_functions": [{"name": "not-indexed-function-symbol"}],
        })

        def query(term):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                index_report.search_db(term)
            return output.getvalue()

        self.assertIn("Suspicious API: KERNEL32.dll!CreateRemoteThread", query("CreateRemoteThread"))
        self.assertIn("IOC [url]: https://example.invalid/history-search", query("history-search"))
        self.assertIn("Threat Flag: Synthetic indicator searchable by description", query("Synthetic indicator"))
        self.assertIn("Metadata match", query("sha-scope"))
        self.assertIn(
            "No matching records found",
            query("not-indexed-recovered-string"),
        )
        self.assertIn(
            "No matching records found",
            query("not-indexed-function-symbol"),
        )

    def test_legacy_timestamp_ioc_findings_and_mitre_keys_remain_supported(self):
        connection = self.index_value({
            "file": "legacy-sample.bin",
            "timestamp": "2025-01-02T03:04:05Z",
            "hashes": {},
            "threat_summary": {
                "indicators": [{"category": "test", "description": "Legacy indicator", "mitre": "T1003", "weight": 4}]
            },
            "ioc_findings": [{"type": "ip", "value": "192.0.2.5", "address": "0x10"}],
        })
        timestamp = connection.execute(
            "SELECT timestamp FROM reports WHERE file = ?", ("legacy-sample.bin",)
        ).fetchone()[0]
        self.assertEqual(timestamp, "2025-01-02T03:04:05Z")
        iocs = connection.execute(
            "SELECT type, value FROM iocs WHERE report_id = (SELECT id FROM reports WHERE file = ?)",
            ("legacy-sample.bin",),
        ).fetchall()
        self.assertEqual(iocs, [("ip", "192.0.2.5")])
        mitre = connection.execute(
            "SELECT mitre FROM indicators WHERE report_id = (SELECT id FROM reports WHERE file = ?)",
            ("legacy-sample.bin",),
        ).fetchone()[0]
        self.assertEqual(mitre, "T1003")


if __name__ == "__main__":
    unittest.main(verbosity=2)
