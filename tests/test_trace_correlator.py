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

    def test_static_imports_include_non_suspicious_apis_and_exact_matching(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {
                "static_apis": [
                    {"function": "CreateFileW", "library": "KERNEL32.dll"},
                    {"function": "GetModuleHandleA", "library": "KERNEL32.dll"},
                ],
                "suspicious_apis": [{"function": "GetModuleHandleA"}],
            },
            {"calls": [
                {"api": "KERNEL32!__imp__GetModuleHandleA@4", "process_id": 1},
                {"api": "FakeCreateFileW", "process_id": 1},
            ]},
        )
        self.assertEqual(result["confirmed_apis"], ["GetModuleHandleA"])
        self.assertEqual(result["static_unobserved_apis"], ["CreateFileW"])
        self.assertEqual(result["unmatched_dynamic_apis"], ["FakeCreateFileW"])

    def test_old_report_falls_back_to_suspicious_apis(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {"suspicious_apis": [{"function": "VirtualAllocEx"}]},
            {"calls": [{"api": "VirtualAllocEx", "process_id": 8}]},
        )
        self.assertEqual(result["confirmed_apis"], ["VirtualAllocEx"])
        self.assertEqual(result["static_import_count"], 1)

    def test_absent_static_import_does_not_claim_dynamic_resolution(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {"static_apis": []},
            {"calls": [{"api": "CreateRemoteThread", "process_id": 7}]},
        )
        self.assertEqual(result["unmatched_dynamic_apis"], ["CreateRemoteThread"])
        self.assertEqual(result["dynamically_resolved_apis"], [])
        self.assertEqual(result["dynamic_resolution_evidence"], [])

    def test_dynamic_resolution_requires_named_resolver_and_later_same_process_call(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {"static_apis": []},
            {"calls": [
                {"api": "GetProcAddress", "process_id": 10,
                 "arguments": {"hModule": "0x1000", "lpProcName": "WriteProcessMemory"}},
                {"api": "WriteProcessMemory", "process_id": 10, "time": 2},
            ]},
        )
        self.assertEqual(result["dynamically_resolved_apis"], ["WriteProcessMemory"])
        evidence = result["dynamic_resolution_evidence"][0]
        self.assertEqual(evidence["resolver_call_index"], 0)
        self.assertEqual(evidence["call_index"], 1)
        self.assertEqual(evidence["process_id"], 10)

    def test_dynamic_resolution_does_not_cross_process_boundary(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {"static_apis": []},
            {"calls": [
                {"api": "GetProcAddress", "process_id": 10,
                 "arguments": {"lpProcName": "WriteProcessMemory"}},
                {"api": "WriteProcessMemory", "process_id": 20},
            ]},
        )
        self.assertEqual(result["dynamic_resolution_evidence"], [])

    def test_dynamic_resolution_requires_resolver_argument(self):
        result = trace_correlator.correlate_static_and_dynamic(
            {"static_apis": []},
            {"calls": [
                {"api": "GetProcAddress", "process_id": 10, "arguments": {"hModule": "0x10"}},
                {"api": "WriteProcessMemory", "process_id": 10},
            ]},
        )
        self.assertEqual(result["dynamically_resolved_apis"], [])

    def test_api_identity_is_exact_and_handles_import_decoration(self):
        self.assertEqual(
            trace_correlator._api_key("KERNEL32!__imp__CreateFileW@16"),
            "createfilew",
        )
        calls = [
            {"api": "FakeVirtualAllocEx", "process_id": 1},
            {"api": "WriteProcessMemory", "process_id": 1},
            {"api": "CreateRemoteThread", "process_id": 1},
        ]
        self.assertEqual(trace_correlator.match_sliding_chains(calls), [])

    def test_chain_match_contains_exact_event_evidence(self):
        calls = [
            {"api": "VirtualAllocEx", "process_id": 9, "thread_id": 4, "time": 1},
            {"api": "Sleep", "process_id": 9, "time": 2},
            {"api": "WriteProcessMemory", "process_id": 9, "time": 3},
            {"api": "CreateRemoteThread", "process_id": 9, "time": 4},
        ]
        match = trace_correlator.match_sliding_chains(calls)[0]
        self.assertEqual(
            [item["api"] for item in match["evidence_calls"]],
            ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        )
        self.assertEqual(
            [item["call_index"] for item in match["evidence_calls"]],
            [0, 2, 3],
        )
        self.assertEqual(match["evidence_calls"][0]["thread_id"], 4)

    def test_chain_matching_requires_process_identity(self):
        calls = [
            {"api": "VirtualAllocEx"},
            {"api": "WriteProcessMemory"},
            {"api": "CreateRemoteThread"},
        ]
        self.assertEqual(trace_correlator.match_sliding_chains(calls), [])

    def test_trace_hash_provenance_match_mismatch_and_unknown(self):
        sample_hash = "a" * 64
        matched = trace_correlator.correlate_static_and_dynamic(
            {"hashes": {"sha256": sample_hash}, "static_apis": []},
            {"calls": [], "metadata": {"sha256": sample_hash.upper(), "source": "CAPE", "run_id": "42"}},
        )
        self.assertEqual(matched["provenance"], "match")
        self.assertIsNone(matched["provenance_warning"])
        self.assertEqual(matched["trace_source"], "CAPE")
        self.assertEqual(matched["trace_run_id"], "42")

        mismatch = trace_correlator.correlate_static_and_dynamic(
            {"hashes": {"sha256": sample_hash}, "static_apis": []},
            {"calls": [], "metadata": {"sha256": "b" * 64}},
        )
        self.assertEqual(mismatch["provenance"], "mismatch")
        self.assertIn("does not match", mismatch["provenance_warning"])

        unknown = trace_correlator.correlate_static_and_dynamic(
            {"hashes": {"sha256": sample_hash}, "static_apis": []},
            {"calls": []},
        )
        self.assertEqual(unknown["provenance"], "unknown")
        self.assertIn("unavailable", unknown["provenance_warning"])

    def test_load_trace_extracts_cape_hash_and_run_metadata(self):
        trace = self.load_value({
            "info": {"id": 1234},
            "target": {"file": {"sha256": "c" * 64}},
            "behavior": {"processes": []},
        })
        self.assertEqual(trace["metadata"]["sha256"], "c" * 64)
        self.assertEqual(trace["metadata"]["run_id"], "1234")

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
        self.assertEqual(result["unmatched_dynamic_apis"], ["CreateRemoteThread"])
        self.assertEqual(result["static_unobserved_apis"], ["DormantAPI"])

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
