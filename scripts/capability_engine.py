#!/usr/bin/env python3
"""
capability_engine.py — Rule-driven multi-scope capability detection engine for ghidra-report.
Evaluates hierarchical YAML rules (instruction, function, and file scopes)
against structured Ghidra report metadata. Inspired by Mandiant capa.
"""

import os
import sys
import glob
import json

try:
    import yaml
except ImportError:
    yaml = None

def load_yaml_rule(filepath):
    """Loads a YAML capability rule file."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    if yaml:
        return yaml.safe_load(content)
    # Minimal fallback parser if pyyaml is unavailable
    rule = {}
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("name:"): rule["name"] = line.split(":", 1)[1].strip().strip("\"\x27")
        elif line.startswith("namespace:"): rule["namespace"] = line.split(":", 1)[1].strip().strip("\"\x27")
        elif line.startswith("scope:"): rule["scope"] = line.split(":", 1)[1].strip().strip("\"\x27")
    return rule

def load_rules(rules_dir):
    """Loads all YAML rules from directory."""
    rules = []
    for ext in ("*.yaml", "*.yml"):
        for path in glob.glob(os.path.join(rules_dir, ext)):
            try:
                r = load_yaml_rule(path)
                if r and "name" in r and "features" in r:
                    r["_filepath"] = path
                    rules.append(r)
            except Exception as e:
                print(f"[WARN] Failed to load rule {path}: {e}", file=sys.stderr)
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
            if target_api == fn or target_api in fn or (lib and f"{lib}!{fn}" == target_api):
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
                "name": r.get("name"),
                "namespace": r.get("namespace", "uncategorized"),
                "scope": r.get("scope", "file"),
                "att&ck": meta.get("att&ck", "-"),
                "mbc": meta.get("mbc", "-"),
                "weight": meta.get("weight", 10),
                "description": meta.get("description", ""),
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

    rules = load_rules(rules_dir)

    if action == "list":
        print(f"Loaded {len(rules)} rule(s) from: {rules_dir}")
        for r in rules:
            print(f"  - [{r.get('scope', 'file').upper():<8}] {r.get('name')} ({r.get('namespace')})")
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
