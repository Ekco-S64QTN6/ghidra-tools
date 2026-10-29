#!/usr/bin/env python3
"""Regression tests for generic and CAPE-style dynamic trace normalization."""

import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import trace_correlator  # noqa: E402


class TraceCorrelatorTests(unittest.TestCase):
    def load_value(self, value):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json") as handle:
            json.dump(value, handle)
            handle.flush()
            return trace_correlator.load_trace(handle.name)

    def test_top_level_list_input_is_supported(self):
        trace = self.load_value([
            {
                "api": "VirtualAllocEx",
                "pid": 123,
                "tid": 7,
                "timestamp": 1.5,
                "args": {"size": 4096},
            },
            "WriteProcessMemory",
            {"name": "CreateRemoteThread", "pid": 123},
        ])
        self.assertEqual(len(trace["calls"]), 3)
        self.assertEqual(trace["calls"][0]["process_id"], 123)
        self.assertEqual(trace["calls"][0]["thread_id"], 7)
        self.assertEqual(trace["calls"][0]["time"], 1.5)
        self.assertEqual(trace["calls"][0]["arguments"], {"size": 4096})
        self.assertEqual(trace["network"], {})
        self.assertEqual(trace["processes"], [])

    def test_cape_process_calls_keep_process_and_event_metadata(self):
        trace = self.load_value({
            "behavior": {
                "processes": [
                    {
                        "process_id": 11,
                        "name": "alpha.exe",
                        "calls": [
                            {"api": "VirtualAllocEx", "time": 1},
                            {"name": "WriteProcessMemory", "tid": 5, "time": 2, "args": {"length": 10}},
                            {"function": "CreateRemoteThread", "time": 3},
                        ],
                    },
                    {"pid": 22, "name": "beta.exe", "calls": [{"api": "OpenProcess", "time": 4}]},
                ]
            }
        })
        self.assertEqual(len(trace["processes"]), 2)
        self.assertEqual([call["process_id"] for call in trace["calls"]], [11, 11, 11, 22])
        self.assertEqual(trace["calls"][1]["process_name"], "alpha.exe")
        self.assertEqual(trace["calls"][1]["thread_id"], 5)
        self.assertEqual(trace["calls"][1]["arguments"], {"length": 10})

    def test_case_insensitive_api_correlation(self):
        trace = {
            "calls": [
                {"api": "KERNEL32!virtualallocex", "process_id": 7},
                {"api": "writeprocessmemory", "process_id": 7},
                {"api": "CreateRemoteThread", "process_id": 7},
            ]
        }
        matches = trace_correlator.match_sliding_chains(trace["calls"])
        self.assertEqual([match["name"] for match in matches], ["Classic Process Injection"])
        result = trace_correlator.correlate_static_and_dynamic(
            {"suspicious_apis": [{"function": "VirtualAllocEx"}, {"function": "WriteProcessMemory"}, {"function": "DormantAPI"}]},
            trace,
        )
        self.assertEqual(result["confirmed_apis"], ["VirtualAllocEx", "WriteProcessMemory"])
        self.assertEqual(result["dormant_apis"], ["DormantAPI"])
        self.assertEqual(result["hidden_dynamic_apis"], ["CreateRemoteThread"])

    def test_attack_chain_cannot_be_joined_across_processes(self):
        calls = [
            {"api": "VirtualAllocEx", "process_id": 10},
            {"api": "WriteProcessMemory", "process_id": 20},
            {"api": "CreateRemoteThread", "process_id": 10},
        ]
        self.assertEqual(trace_correlator.match_sliding_chains(calls), [])

    def test_missing_fields_and_malformed_call_entries_are_ignored(self):
        trace = self.load_value({
            "calls": [{}, None, 42, {"api": "  "}, {"name": "LoadLibraryA"}],
            "network": [],
            "processes": {},
        })
        self.assertEqual([call["api"] for call in trace["calls"]], ["LoadLibraryA"])
        self.assertEqual(trace["network"], {})
        self.assertEqual(trace["processes"], [])

    def test_non_object_non_list_trace_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "object or an array"):
            self.load_value("not a trace object")


if __name__ == "__main__":
    unittest.main(verbosity=2)
