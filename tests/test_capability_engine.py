#!/usr/bin/env python3
"""Regression tests for YAML capability rule loading and feature operators."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import capability_engine  # noqa: E402

RULES_DIR = os.path.join(REPO_ROOT, "rules")


class CapabilityEngineTests(unittest.TestCase):
    def setUp(self):
        self.context = {
            "apis": [
                {"library": "KERNEL32.dll", "function": "VirtualAllocEx"},
                {"library": "KERNEL32.dll", "function": "WriteProcessMemory"},
            ],
            "indicators": [{"category": "execution", "description": "process injection pattern"}],
            "memory_blocks": [{"name": ".text", "rwx": False}],
            "iocs": [{"type": "url", "value": "https://example.invalid/path"}],
        }

    def test_all_shipped_rules_load_with_feature_trees(self):
        rules = capability_engine.load_rules(RULES_DIR)
        self.assertEqual(len(rules), 11)
        for rule in rules:
            with self.subTest(rule=rule.get("name")):
                self.assertTrue(rule["name"])
                self.assertIsInstance(rule["features"], dict)
                self.assertIn("_filepath", rule)

    def test_missing_pyyaml_fails_instead_of_silently_loading_zero_rules(self):
        with patch.object(capability_engine, "yaml", None):
            with self.assertRaisesRegex(RuntimeError, "PyYAML is required"):
                capability_engine.load_rules(RULES_DIR)

    def test_malformed_yaml_fails_with_the_rule_path(self):
        with tempfile.TemporaryDirectory(prefix="bad-capability-rule-") as temp:
            path = os.path.join(temp, "broken.yaml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('name: ["unfinished"\nfeatures: {}\n')
            with self.assertRaisesRegex(RuntimeError, "broken.yaml"):
                capability_engine.load_rules(temp)

    def test_and_or_not_and_count_operators(self):
        and_node = {
            "and": [
                {"api": "VirtualAllocEx"},
                {"indicator": "injection"},
            ]
        }
        matched, evidence = capability_engine.evaluate_node(and_node, self.context)
        self.assertTrue(matched)
        self.assertEqual(len(evidence), 2)

        or_node = {
            "or": [
                {"api": "DefinitelyMissingApi"},
                {"section_name": ".text"},
            ]
        }
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

    def test_process_injection_rule_has_positive_and_negative_examples(self):
        rules = capability_engine.load_rules(RULES_DIR)
        report = {"suspicious_apis": self.context["apis"]}
        matched = capability_engine.evaluate_report(report, rules)
        self.assertIn("Process Injection via Memory Modification", [item["name"] for item in matched])

        benign_report = {"suspicious_apis": [{"library": "KERNEL32.dll", "function": "GetTickCount"}]}
        unmatched = capability_engine.evaluate_report(benign_report, rules)
        self.assertNotIn("Process Injection via Memory Modification", [item["name"] for item in unmatched])


if __name__ == "__main__":
    unittest.main(verbosity=2)
