#!/usr/bin/env python3
"""Contract and behavioral tests for the file-aggregate YAML capability DSL."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import capability_engine  # noqa: E402

RULES_DIR = REPO_ROOT / "rules"
RULE_SCHEMA_PATH = REPO_ROOT / "schemas" / "capability-rule-v1.schema.json"

RULE_HEADER = """schema_version: "1.0.0"
id: "ghidra.test-rule"
name: "Test rule"
namespace: "testing/capability"
scope: "file"
meta:
  att&ck: "T1055"
  mbc: "Process::Inject [B0006]"
  weight: 10
  description: "Synthetic test rule"
  rationale: "This fixture validates the documented file-level rule contract."
  references:
    - "https://attack.mitre.org/techniques/T1055/"
"""


def api(name):
    return {"library": "KERNEL32.dll", "function": name}


def function_record(name, address, api_names):
    return {
        "function": name,
        "address": address,
        "suspicious_apis": [
            {
                "function": api_name,
                "target_address": f"EXTERNAL::{api_name}",
                "call_site": f"{address}+0x10",
            }
            for api_name in api_names
        ],
    }


def report(apis=None, indicators=None, blocks=None, iocs=None, function_api_evidence=None):
    return {
        "suspicious_apis": list(apis or []),
        "threat_summary": {"indicators": list(indicators or [])},
        "memory_blocks": list(blocks or []),
        "iocs": list(iocs or []),
        "function_api_evidence": list(function_api_evidence or []),
    }


class CapabilityEngineTests(unittest.TestCase):
    def setUp(self):
        self.context = {
            "apis": [
                api("VirtualAllocEx"),
                api("WriteProcessMemory"),
            ],
            "indicators": [{"category": "execution", "description": "process injection pattern"}],
            "memory_blocks": [{"name": ".text", "rwx": False}],
            "iocs": [{"type": "url", "value": "https://example.invalid/path"}],
        }

    def test_all_shipped_rules_follow_the_versioned_schema(self):
        schema = json.loads(RULE_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft7Validator.check_schema(schema)
        validator = Draft7Validator(schema)
        rules = capability_engine.load_rules(str(RULES_DIR))
        self.assertEqual(len(rules), 11)
        rule_ids = [rule["id"] for rule in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)), "rule IDs must be unique")

        for rule in rules:
            with self.subTest(rule=rule.get("id")):
                self.assertTrue(rule["name"])
                self.assertIsInstance(rule["features"], dict)
                self.assertIn("_filepath", rule)
                serializable_rule = {key: value for key, value in rule.items() if key != "_filepath"}
                validator.validate(serializable_rule)
                self.assertIn(rule["scope"], {"file", "function"})
                self.assertTrue(rule["meta"]["rationale"])
                self.assertTrue(rule["meta"]["references"])

        # The DSL documents count.min as optional with a default of one.
        count_rule = dict(rules[0])
        count_rule["features"] = {"count": {"items": [{"api": "GetTickCount"}]}}
        validator.validate({
            key: value for key, value in count_rule.items() if key != "_filepath"
        })

        function_rule = next(
            rule for rule in rules if rule["scope"] == "function"
        )
        invalid_function_rule = {
            key: value for key, value in function_rule.items() if key != "_filepath"
        }
        invalid_function_rule["features"] = {"api": "KERNEL32.dll!VirtualAllocEx"}
        with self.assertRaises(ValidationError):
            validator.validate(invalid_function_rule)

    def test_missing_pyyaml_fails_instead_of_silently_loading_zero_rules(self):
        with patch.object(capability_engine, "yaml", None):
            with self.assertRaisesRegex(RuntimeError, "PyYAML is required"):
                capability_engine.load_rules(str(RULES_DIR))

    def test_malformed_yaml_fails_with_the_rule_path(self):
        with tempfile.TemporaryDirectory(prefix="bad-capability-rule-") as temp:
            path = Path(temp) / "broken.yaml"
            path.write_text('name: ["unfinished"\nfeatures: {}\n', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "broken.yaml"):
                capability_engine.load_rules(temp)

    def test_and_or_not_and_count_operators(self):
        and_node = {"and": [{"api": "VirtualAllocEx"}, {"indicator": "injection"}]}
        matched, evidence = capability_engine.evaluate_node(and_node, self.context)
        self.assertTrue(matched)
        self.assertEqual(len(evidence), 2)

        or_node = {"or": [{"api": "DefinitelyMissingApi"}, {"section_name": ".text"}]}
        matched, evidence = capability_engine.evaluate_node(or_node, self.context)
        self.assertTrue(matched)
        self.assertEqual(evidence, ["Section: .text"])

        not_node = {"not": {"api": "CreateRemoteThread"}}
        self.assertEqual(capability_engine.evaluate_node(not_node, self.context), (True, []))
        self.assertEqual(
            capability_engine.evaluate_node({"not": {"api": "VirtualAllocEx"}}, self.context),
            (False, []),
        )

        count_node = {
            "count": {
                "min": 3,
                "items": [
                    {"api": "VirtualAllocEx"},
                    {"indicator": "injection"},
                    {"section_name": ".text"},
                ],
            }
        }
        matched, evidence = capability_engine.evaluate_node(count_node, self.context)
        self.assertTrue(matched)
        self.assertEqual(len(evidence), 3)
        count_negative = {"count": {"min": 4, "items": count_node["count"]["items"]}}
        self.assertEqual(capability_engine.evaluate_node(count_negative, self.context), (False, []))

    def test_api_primitive_requires_an_exact_name(self):
        context = {"apis": [api("OpenProcessToken")]}
        self.assertEqual(
            capability_engine.evaluate_node({"api": "OpenProcess"}, context),
            (False, []),
        )
        self.assertEqual(
            capability_engine.evaluate_node({"api": "OpenProcessToken"}, context)[0],
            True,
        )

    def test_section_rwx_and_ioc_primitives(self):
        rwx_context = {"memory_blocks": [{"name": ".packed", "rwx": True}]}
        self.assertEqual(
            capability_engine.evaluate_node({"section_rwx": True}, rwx_context)[0],
            True,
        )
        self.assertEqual(
            capability_engine.evaluate_node({"section_rwx": False}, rwx_context)[0],
            False,
        )
        ioc_context = {"iocs": [{"type": "registry", "value": r"HKCU\Software\Run"}]}
        matched, evidence = capability_engine.evaluate_node(
            {"ioc": r"software\run"}, ioc_context
        )
        self.assertTrue(matched)
        self.assertIn("HKCU", evidence[0])


    def test_invalid_operators_primitives_metadata_and_schema_versions_are_rejected(self):
        invalid_rules = [
            (
                RULE_HEADER + "features:\n  xor:\n    - api: GetTickCount\n",
                "unsupported feature operator 'xor'",
            ),
            (
                RULE_HEADER + "features:\n  api: 42\n",
                "expected a non-empty string",
            ),
            (
                RULE_HEADER + "features:\n  api: GetTickCount\n  indicator: network\n",
                "exactly one operator",
            ),
            (
                RULE_HEADER.replace("weight: 10", "weight: 101") + "features:\n  api: GetTickCount\n",
                "meta.weight must be an integer from 0 through 100",
            ),
            (
                RULE_HEADER.replace('scope: "file"', 'scope: "instruction"') + "features:\n  api: GetTickCount\n",
                "supported scopes are file and function",
            ),
            (
                RULE_HEADER.replace('scope: "file"', 'scope: "function"')
                + "features:\n  indicator: injection\n",
                "unsupported feature operator 'indicator' for this scope",
            ),
            (
                RULE_HEADER.replace('scope: "file"', 'scope: "function"')
                + "features:\n  api: KERNEL32.dll!VirtualAllocEx\n",
                "function scope accepts unqualified API names only",
            ),
            (
                RULE_HEADER.replace('schema_version: "1.0.0"', 'schema_version: "2.0.0"')
                + "features:\n  api: GetTickCount\n",
                "schema_version must be '1.0.0'",
            ),
            (
                RULE_HEADER.replace('id: "ghidra.test-rule"', 'id: "test-rule"')
                + "features:\n  api: GetTickCount\n",
                "stable ghidra.* identifier",
            ),
            (
                RULE_HEADER + "unknown_field: true\nfeatures:\n  api: GetTickCount\n",
                "unknown rule keys",
            ),
            (
                RULE_HEADER.replace("weight: 10", "weight: 10\n  surprise: true")
                + "features:\n  api: GetTickCount\n",
                "unknown meta keys",
            ),
            (
                RULE_HEADER.replace("T1055", "BAD") + "features:\n  api: GetTickCount\n",
                "syntactically valid ATT&CK technique ID",
            ),
            (
                RULE_HEADER.replace(
                    '  rationale: "This fixture validates the documented file-level rule contract."\n', ""
                ) + "features:\n  api: GetTickCount\n",
                "missing required meta keys",
            ),
        ]

        for rule_text, expected_error in invalid_rules:
            with self.subTest(expected_error=expected_error), tempfile.TemporaryDirectory() as temp:
                rule_path = Path(temp) / "invalid.yaml"
                rule_path.write_text(rule_text, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    capability_engine.load_rules(temp)

    def test_duplicate_stable_rule_ids_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="duplicate-capability-id-") as temp:
            for name in ("one.yaml", "two.yaml"):
                (Path(temp) / name).write_text(
                    RULE_HEADER + "features:\n  api: GetTickCount\n",
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(RuntimeError, "duplicate rule id"):
                capability_engine.load_rules(temp)

    def test_every_shipped_rule_has_positive_and_negative_fixture(self):
        rules = capability_engine.load_rules(str(RULES_DIR))
        fixtures = {
            "ghidra.anti-debugging-dynamic-resolution": (
                report([api("GetModuleHandleA"), api("GetProcAddress")]),
                report([api("GetModuleHandleA")]),
            ),
            "ghidra.credential-process-memory-dump": (
                report([api("MiniDumpWriteDump")]),
                report([api("GetTickCount")]),
            ),
            "ghidra.cryptographic-routine-indicators": (
                report(indicators=[{"category": "crypto", "description": "AES constants detected"}]),
                report(indicators=[{"category": "resource", "description": "ordinary resource section"}]),
            ),
            "ghidra.dynamic-api-resolution": (
                report([api("LoadLibraryW"), api("GetProcAddress")]),
                report([api("LoadLibraryW")]),
            ),
            "ghidra.input-capture-keylogging": (
                report([api("GetAsyncKeyState")]),
                report([api("GetTickCount")]),
            ),
            "ghidra.network-configuration-discovery": (
                report([api("GetAdaptersAddresses")]),
                report([api("GetTickCount")]),
            ),
            "ghidra.packed-executable-suspicious-section": (
                report(indicators=[{"category": "packing", "description": "High-entropy section detected"}]),
                report(indicators=[{"category": "resource", "description": "ordinary data block"}]),
            ),
            "ghidra.persistence-registry-autostart": (
                report(
                    [api("RegSetValueExW")],
                    iocs=[{"type": "registry", "value": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"}],
                ),
                report([api("RegSetValueExW")]),
            ),
            "ghidra.process-shell-execution": (
                report([api("CreateProcessW")]),
                report([api("GetTickCount")]),
            ),
            "ghidra.process-hollowing-memory-unmapping": (
                report([api("NtUnmapViewOfSection"), api("SetThreadContext"), api("ResumeThread")]),
                report([api("NtUnmapViewOfSection"), api("SetThreadContext")]),
            ),
            "ghidra.process-injection-memory-modification": (
                report(function_api_evidence=[
                    function_record("inject_payload", "0x401000", ["VirtualAllocEx", "WriteProcessMemory"])
                ]),
                report(function_api_evidence=[
                    function_record("allocate_only", "0x402000", ["VirtualAllocEx"])
                ]),
            ),
        }
        self.assertEqual(set(fixtures), {rule["id"] for rule in rules})
        for rule in rules:
            positive, negative = fixtures[rule["id"]]
            with self.subTest(rule=rule["id"], fixture="positive"):
                positives = capability_engine.evaluate_report(positive, [rule])
                self.assertEqual([hit["id"] for hit in positives], [rule["id"]])
            with self.subTest(rule=rule["id"], fixture="negative"):
                self.assertEqual(capability_engine.evaluate_report(negative, [rule]), [])

    def test_rule_hit_exposes_id_expression_scope_and_evidence_quality(self):
        rules = capability_engine.load_rules(str(RULES_DIR))
        injection = next(rule for rule in rules if rule["id"] == "ghidra.process-injection-memory-modification")
        hits = capability_engine.evaluate_report(
            {
                "suspicious_apis": self.context["apis"],
                "function_api_evidence": [
                    function_record("inject_payload", "0x401000", ["VirtualAllocEx", "WriteProcessMemory"])
                ],
            },
            [injection],
        )
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["id"], injection["id"])
        self.assertEqual(hit["rule_schema_version"], "1.0.0")
        self.assertEqual(hit["scope"], "function")
        self.assertEqual(hit["evidence_quality"], "function_callsite")
        self.assertEqual(hit["function"], {"name": "inject_payload", "address": "0x401000"})
        self.assertEqual(hit["expression"], injection["features"])
        self.assertTrue(any("@ 0x401000+0x10" in item for item in hit["evidence"]))
        self.assertTrue(hit["rationale"])
        self.assertTrue(hit["references"])

    def test_function_scope_does_not_combine_apis_across_functions_or_use_file_imports(self):
        rules = capability_engine.load_rules(str(RULES_DIR))
        injection = next(rule for rule in rules if rule["id"] == "ghidra.process-injection-memory-modification")
        positive = report(function_api_evidence=[
            function_record("inject_payload", "0x401000", ["VirtualAllocEx", "WriteProcessMemory"])
        ])
        split_calls = report(function_api_evidence=[
            function_record("allocate", "0x401000", ["VirtualAllocEx"]),
            function_record("write", "0x402000", ["WriteProcessMemory"]),
        ])
        aggregate_only = report(apis=[api("VirtualAllocEx"), api("WriteProcessMemory")])
        self.assertEqual(len(capability_engine.evaluate_report(positive, [injection])), 1)
        self.assertEqual(capability_engine.evaluate_report(split_calls, [injection]), [])
        self.assertEqual(capability_engine.evaluate_report(aggregate_only, [injection]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
