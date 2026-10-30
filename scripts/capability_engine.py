#!/usr/bin/env python3
"""
capability_engine.py — Small, file-aggregate capability rule engine for ghidra-report.
This DSL is intentionally not capa-compatible. Rules evaluate fields available in
the generated JSON report; they do not match individual instructions, blocks, or functions.
"""

import os
import sys
import glob
import json
import re

try:
    import yaml
except ImportError:
    yaml = None

def require_yaml():
    """Fail clearly instead of pretending rules loaded without a YAML parser."""
    if yaml is None:
        raise RuntimeError(
            "PyYAML is required for capability rules. Install it with "
            "'python3 -m pip install -r requirements-rules.txt'."
        )


def load_yaml_rule(filepath):
    """Load one complete rule using PyYAML's safe loader."""
    require_yaml()
    with open(filepath, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


SUPPORTED_FEATURE_OPERATORS = {
    "and", "or", "not", "count", "api", "indicator", "section_name", "section_rwx", "ioc"
}
RULE_SCHEMA_VERSION = "1.0.0"
RULE_ID_PATTERN = re.compile(r"^ghidra\.[a-z0-9]+(?:-[a-z0-9]+)*$")
ATTACK_ID_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
SUPPORTED_SCOPES = {"file"}
RULE_KEYS = {"schema_version", "id", "name", "namespace", "scope", "meta", "features"}
META_KEYS = {"att&ck", "mbc", "weight", "description", "rationale", "references"}


def validate_feature_node(node, node_path="features"):
    """Validate a feature expression before it reaches the evaluator."""
    if not isinstance(node, dict) or len(node) != 1:
        raise ValueError(f"{node_path}: expected a mapping with exactly one operator")

    operator, value = next(iter(node.items()))
    if operator not in SUPPORTED_FEATURE_OPERATORS:
        raise ValueError(f"{node_path}: unsupported feature operator {operator!r}")

    if operator in ("and", "or"):
        if not isinstance(value, list) or not value:
            raise ValueError(f"{node_path}.{operator}: expected a non-empty list")
        for index, child in enumerate(value):
            validate_feature_node(child, f"{node_path}.{operator}[{index}]")
    elif operator == "not":
        validate_feature_node(value, f"{node_path}.not")
    elif operator == "count":
        if not isinstance(value, dict):
            raise ValueError(f"{node_path}.count: expected a mapping with 'min' and 'items'")
        unknown = set(value) - {"min", "items"}
        if unknown:
            raise ValueError(f"{node_path}.count: unknown keys {sorted(unknown)!r}")
        minimum = value.get("min", 1)
        items = value.get("items")
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
            raise ValueError(f"{node_path}.count.min: expected a positive integer")
        if not isinstance(items, list) or not items:
            raise ValueError(f"{node_path}.count.items: expected a non-empty list")
        if minimum > len(items):
            raise ValueError(f"{node_path}.count.min: cannot exceed the number of items")
        for index, child in enumerate(items):
            validate_feature_node(child, f"{node_path}.count.items[{index}]")
    elif operator == "section_rwx":
        if not isinstance(value, bool):
            raise ValueError(f"{node_path}.section_rwx: expected true or false")
    elif not isinstance(value, str) or not value.strip():
        raise ValueError(f"{node_path}.{operator}: expected a non-empty string")


def validate_rule(rule, rule_path):
    """Validate the supported rule metadata and expression shape."""
    if not isinstance(rule, dict):
        raise ValueError("expected a YAML mapping")
    unknown = set(rule) - RULE_KEYS
    if unknown:
        raise ValueError(f"unknown rule keys: {sorted(unknown)!r}")
    if rule.get("schema_version") != RULE_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {RULE_SCHEMA_VERSION!r}")
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not RULE_ID_PATTERN.fullmatch(rule_id):
        raise ValueError("id must be a stable ghidra.* identifier")
    if not isinstance(rule.get("name"), str) or not rule["name"].strip():
        raise ValueError("missing non-empty 'name'")
    if not isinstance(rule.get("namespace"), str) or not rule["namespace"].strip():
        raise ValueError("missing non-empty 'namespace'")
    scope = rule.get("scope")
    if scope not in SUPPORTED_SCOPES:
        raise ValueError(
            f"unsupported scope {scope!r}; this engine evaluates file-aggregate report fields only"
        )
    meta = rule.get("meta")
    if not isinstance(meta, dict):
        raise ValueError("'meta' must be a mapping")
    unknown_meta = set(meta) - META_KEYS
    if unknown_meta:
        raise ValueError(f"unknown meta keys: {sorted(unknown_meta)!r}")
    required_meta = {"att&ck", "mbc", "weight", "description", "rationale", "references"}
    missing_meta = required_meta - set(meta)
    if missing_meta:
        raise ValueError(f"missing required meta keys: {sorted(missing_meta)!r}")
    attack_id = meta.get("att&ck")
    if not isinstance(attack_id, str) or not ATTACK_ID_PATTERN.fullmatch(attack_id):
        raise ValueError("meta.att&ck must be a syntactically valid ATT&CK technique ID")
    for key in ("mbc", "description", "rationale"):
        if not isinstance(meta.get(key), str) or not meta[key].strip():
            raise ValueError(f"meta.{key} must be a non-empty string")
    if len(meta["rationale"]) < 20:
        raise ValueError("meta.rationale must contain at least 20 characters")
    weight = meta.get("weight")
    if isinstance(weight, bool) or not isinstance(weight, int) or not 0 <= weight <= 100:
        raise ValueError("meta.weight must be an integer from 0 through 100")
    references = meta.get("references")
    if not isinstance(references, list) or not references:
        raise ValueError("meta.references must be a non-empty list")
    for index, reference in enumerate(references):
        if not isinstance(reference, str) or not reference.startswith("https://"):
            raise ValueError(f"meta.references[{index}] must be an HTTPS URL")
    if "features" not in rule:
        raise ValueError("missing 'features' expression")
    validate_feature_node(rule["features"])


def load_rules(rules_dir):
    """Load all rules, failing closed if any rule has invalid syntax or structure."""
    require_yaml()
    paths = []
    for ext in ("*.yaml", "*.yml"):
        paths.extend(glob.glob(os.path.join(rules_dir, ext)))

    rules = []
    seen_ids = {}
    for path in sorted(paths):
        try:
            rule = load_yaml_rule(path)
            validate_rule(rule, path)
            rule_id = rule["id"]
            if rule_id in seen_ids:
                raise ValueError(
                    f"duplicate rule id {rule_id!r}; already used by {seen_ids[rule_id]}"
                )
        except Exception as exc:
            raise RuntimeError(f"Failed to load capability rule {path}: {exc}") from exc
        seen_ids[rule["id"]] = path
        rule["_filepath"] = path
        rules.append(rule)

    return rules

def evaluate_node(node, context):
    """Recursively evaluates a feature condition node against report context."""
    if not isinstance(node, dict):
        return False, []

    matched_evidence = []

    # Operator: and
    if "and" in node:
        for child in node["and"]:
            res, ev = evaluate_node(child, context)
            if not res:
                return False, []
            matched_evidence.extend(ev)
        return True, matched_evidence

    # Operator: or
    if "or" in node:
        any_match = False
        for child in node["or"]:
            res, ev = evaluate_node(child, context)
            if res:
                any_match = True
                matched_evidence.extend(ev)
        return any_match, matched_evidence

    # Operator: not
    if "not" in node:
        res, ev = evaluate_node(node["not"], context)
        return (not res), []

    # Operator: count / threshold
    if "count" in node:
        spec = node["count"]
        min_count = spec.get("min", 1)
        items = spec.get("items", [])
        hits = 0
        ev_list = []
        for it in items:
            res, ev = evaluate_node(it, context)
            if res:
                hits += 1
                ev_list.extend(ev)
        if hits >= min_count:
            return True, ev_list
        return False, []

    # Primitive match: api
    if "api" in node:
        target_api = node["api"].lower()
        for api in context.get("apis", []):
            fn = api.get("function", "").lower()
            lib = api.get("library", "").lower()
            if target_api == fn or (lib and target_api == f"{lib}!{fn}".lower()):
                return True, [f"API: {api.get('library')}!{api.get('function')}"]
        return False, []

    # Primitive match: indicator
    if "indicator" in node:
        target_ind = node["indicator"].lower()
        for ind in context.get("indicators", []):
            desc = ind.get("description", "").lower()
            cat = ind.get("category", "").lower()
            if target_ind in desc or target_ind in cat:
                return True, [f"Threat Flag: {ind.get('description')}"]
        return False, []

    # Primitive match: section_name
    if "section_name" in node:
        target_sec = node["section_name"].lower()
        for b in context.get("memory_blocks", []):
            if target_sec == b.get("name", "").lower():
                return True, [f"Section: {b.get('name')}"]
        return False, []

    # Primitive match: section_rwx
    if "section_rwx" in node:
        req = bool(node["section_rwx"])
        for b in context.get("memory_blocks", []):
            if bool(b.get("rwx")) == req:
                return True, [f"RWX Section: {b.get('name')}"]
        return False, []

    # Primitive match: ioc
    if "ioc" in node:
        target_ioc = node["ioc"].lower()
        for ioc in context.get("iocs", []):
            if target_ioc in ioc.get("value", "").lower() or target_ioc in ioc.get("type", "").lower():
                return True, [f"IOC: {ioc.get('type')} = {ioc.get('value')}"]
        return False, []

    return False, []

def evaluate_report(report_data, rules):
    """Evaluates all loaded rules against report data."""
    context = {
        "apis": report_data.get("suspicious_apis", []),
        "indicators": report_data.get("threat_summary", {}).get("indicators", []),
        "memory_blocks": report_data.get("memory_blocks", []),
        "iocs": report_data.get("iocs", []),
        "top_functions": report_data.get("top_functions", [])
    }

    matches = []
    for r in rules:
        feat = r.get("features", {})
        matched, evidence = evaluate_node(feat, context)
        if matched:
            meta = r.get("meta", {})
            matches.append({
                "id": r["id"],
                "rule_schema_version": RULE_SCHEMA_VERSION,
                "name": r.get("name"),
                "namespace": r.get("namespace", "uncategorized"),
                "scope": "file",
                "evidence_quality": "file_aggregate",
                "att&ck": meta.get("att&ck", "-"),
                "mbc": meta.get("mbc", "-"),
                "weight": meta.get("weight", 10),
                "description": meta.get("description", ""),
                "rationale": meta.get("rationale", ""),
                "references": list(meta.get("references", [])),
                "expression": feat,
                "evidence": list(dict.fromkeys(evidence)) # deduplicate
            })

    matches.sort(key=lambda m: m["weight"], reverse=True)
    return matches

def print_matches_table(filepath, matches):
    print("=" * 80)
    print("  CAPABILITY DETECTION REPORT (RULE ENGINE)")
    print("=" * 80)
    print(f"  Target File: {filepath}")
    print(f"  Matched Capabilities: {len(matches)}")
    print()
    if not matches:
        print("  No rules matched.")
        print("=" * 80)
        return

    print(f"  {'Capability Name':<38} {'Namespace':<24} {'ATT&CK':<8} {'Scope'}")
    print("  " + "-" * 76)
    for m in matches:
        print(f"  {m['name']:<38} {m['namespace']:<24} {m['att&ck']:<8} [{m['scope'].upper()}]")
        for ev in m["evidence"][:3]:
            print(f"    ↳ Evidence: {ev}")
    print("=" * 80)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <evaluate|list|json> <report.json> [rules_dir]")
        sys.exit(1)

    action = sys.argv[1].lower()
    report_path = sys.argv[2]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = sys.argv[3] if len(sys.argv) > 3 else os.path.join(script_dir, "..", "rules")

    try:
        rules = load_rules(rules_dir)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    if action == "list":
        print(f"Loaded {len(rules)} rule(s) from: {rules_dir}")
        for r in rules:
            print(f"  - [{r.get('scope').upper():<8}] {r.get('id')}: {r.get('name')} ({r.get('namespace')})")
        sys.exit(0)

    if not os.path.isfile(report_path):
        print(f"Error: file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    matches = evaluate_report(data, rules)

    if action == "evaluate":
        print_matches_table(data.get("file", report_path), matches)
    elif action == "json":
        print(json.dumps(matches, indent=2))
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
