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

    def test_anonymous_cape_processes_get_distinct_identities(self):
        trace = self.load_value({
            "behavior": {
                "processes": [
                    {"pid": None, "calls": [{"api": "VirtualAllocEx"}, {"api": "CreateRemoteThread"}]},
                    {"process_id": None, "calls": [{"api": "WriteProcessMemory"}]},
                ]
            }
        })
        self.assertEqual([call["process_id"] for call in trace["calls"]], ["process-0", "process-0", "process-1"])
        self.assertEqual(trace_correlator.match_sliding_chains(trace["calls"]), [])

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

    def test_complete_import_table_is_preferred_over_suspicious_subset(self):
        static = {
            "imports": [
                {"function": "Sleep", "library": "KERNEL32.dll"},
                {"function": "VirtualAlloc", "library": "KERNEL32.dll"},
            ],
            "suspicious_apis": [{"function": "TaggedOnly"}],
        }
        dynamic = {"calls": [
            {"api": "KERNEL32.DLL!sleep", "process_id": 8},
            {"api": "GetProcAddress", "process_id": 8},
        ]}
        result = trace_correlator.correlate_static_and_dynamic(static, dynamic)
        self.assertTrue(result["static_imports_complete"])
        self.assertEqual(result["static_import_source"], "imports")
        self.assertEqual(result["unique_static_imports"], 2)
        self.assertEqual(result["confirmed_apis"], ["Sleep"])
        self.assertEqual(result["dormant_apis"], ["VirtualAlloc"])
        self.assertEqual(result["not_in_static_imports"], ["GetProcAddress"])
        self.assertEqual(result["hidden_dynamic_apis"], result["not_in_static_imports"])

    def test_explicit_empty_import_table_does_not_fall_back_to_legacy_subset(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {"imports": [], "suspicious_apis": [{"function": "LegacyTagged"}]},
            {"calls": [{"api": "LegacyTagged"}]},
        )
        self.assertTrue(result["static_imports_complete"])
        self.assertEqual(result["static_import_source"], "imports")
        self.assertEqual(result["confirmed_apis"], [])
        self.assertEqual(result["dormant_apis"], [])
        self.assertEqual(result["not_in_static_imports"], ["LegacyTagged"])

    def test_legacy_report_falls_back_to_suspicious_apis_and_marks_incomplete(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {"suspicious_apis": [{"function": "TaggedAPI"}]},
            {"calls": [{"api": "TaggedAPI", "process_id": 1}]},
        )
        self.assertFalse(result["static_imports_complete"])
        self.assertEqual(result["static_import_source"], "suspicious_apis_legacy")
        self.assertEqual(result["confirmed_apis"], ["TaggedAPI"])

    def test_attack_chain_requires_exact_api_names(self):
        calls = [
            {"api": "NotVirtualAllocEx", "process_id": 10},
            {"api": "WriteProcessMemory", "process_id": 10},
            {"api": "CreateRemoteThread", "process_id": 10},
        ]
        self.assertEqual(trace_correlator.match_sliding_chains(calls), [])

    def test_attack_chain_requires_identified_process_id(self):
        calls = [
            {"api": "VirtualAllocEx", "process_name": "same.exe"},
            {"api": "WriteProcessMemory", "process_name": "same.exe"},
            {"api": "CreateRemoteThread", "process_name": "same.exe"},
        ]
        self.assertEqual(trace_correlator.match_sliding_chains(calls), [])

    def test_attack_chain_evidence_includes_exact_event_slice(self):
        calls = [
            {"api": "KERNEL32!virtualallocex", "process_id": 42, "time": 1, "thread_id": 7},
            {"api": "Sleep", "process_id": 42, "time": 2, "thread_id": 7},
            {"api": "WriteProcessMemory", "process_id": 42, "time": 3, "arguments": {"size": 128}},
            {"api": "CreateRemoteThread", "process_id": 42, "time": 4, "thread_id": 9},
        ]
        matches = trace_correlator.match_sliding_chains(calls)
        match = next(item for item in matches if item["name"] == "Classic Process Injection")
        self.assertEqual(match["process_id"], 42)
        self.assertEqual(match["start_call_index"], 0)
        self.assertEqual(match["end_call_index"], 3)
        self.assertEqual(
            [event["api"] for event in match["evidence_calls"]],
            ["KERNEL32!virtualallocex", "WriteProcessMemory", "CreateRemoteThread"],
        )
        self.assertEqual(match["evidence_calls"][1]["arguments"], {"size": 128})
        self.assertEqual(match["evidence_calls"][2]["thread_id"], 9)

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
