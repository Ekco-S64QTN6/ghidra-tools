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

    def test_migration_preserves_history_and_allows_same_basename(self):
        output_a = os.path.join(self.temp.name, "output", "sample_a")
        output_b = os.path.join(self.temp.name, "output", "sample_b")
        os.makedirs(output_a)
        os.makedirs(output_b)
        report_a = os.path.join(output_a, "sample_report.json")
        report_b = os.path.join(output_b, "sample_report.json")

        legacy = sqlite3.connect(index_report.DB_PATH)
        legacy.executescript("""
            CREATE TABLE reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file TEXT UNIQUE,
                timestamp TEXT,
                format_label TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                md5 TEXT,
                sha256 TEXT,
                imphash TEXT,
                function_count INTEGER,
                json_path TEXT
            );
            CREATE TABLE suspicious_apis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                library TEXT,
                function TEXT,
                mitre TEXT,
                category TEXT,
                FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
            );
            CREATE TABLE iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                type TEXT,
                value TEXT,
                address TEXT,
                FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
            );
            CREATE TABLE indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                category TEXT,
                description TEXT,
                mitre TEXT,
                weight INTEGER,
                FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
            );
        """)
        legacy.execute(
            "INSERT INTO reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "sample.bin", "2026-10-29T10:00:00Z", "ELF", 40, "MEDIUM",
             "md5-a", "sha-a", "", 3, report_a),
        )
        legacy.execute(
            "INSERT INTO suspicious_apis VALUES (?, ?, ?, ?, ?, ?)",
            (1, 1, "LEGACY.dll", "OldFinding", "T1055", "test"),
        )
        legacy.commit()
        legacy.close()

        with open(report_b, "w", encoding="utf-8") as handle:
            json.dump({
                "file": "sample.bin",
                "format_label": "PE",
                "generated": "2026-10-29T11:00:00Z",
                "hashes": {"md5": "md5-b", "sha256": "sha-b"},
                "threat_summary": {"risk_score": 90, "risk_level": "CRITICAL"},
                "analysis_stats": {"function_count": 7},
                "suspicious_apis": [{
                    "library": "NEW.dll",
                    "function": "NewFinding",
                    "mitre": "T1055",
                    "category": "test",
                }],
            }, handle)

        index_report.index_report(report_b)
        connection = sqlite3.connect(index_report.DB_PATH)
        try:
            rows = connection.execute(
                "SELECT id, file, json_path, risk_score FROM reports ORDER BY id"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual([row[1] for row in rows], ["sample.bin", "sample.bin"])
            self.assertEqual([row[3] for row in rows], [40, 90])
            self.assertEqual([row[2] for row in rows], [report_a, os.path.realpath(report_b)])

            apis = connection.execute(
                "SELECT report_id, library, function FROM suspicious_apis ORDER BY id"
            ).fetchall()
            self.assertEqual(apis, [(1, "LEGACY.dll", "OldFinding"), (2, "NEW.dll", "NewFinding")])
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM reports WHERE file = ?", ("sample.bin",)).fetchone()[0],
                2,
            )
        finally:
            connection.close()

        # Re-indexing the same JSON path updates that report instead of duplicating it.
        index_report.index_report(report_b)
        connection = sqlite3.connect(index_report.DB_PATH)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 2)
        finally:
            connection.close()

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
