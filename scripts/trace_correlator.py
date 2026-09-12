#!/usr/bin/env python3
"""
trace_correlator.py — Dynamic sandbox trace ingestion & sliding call window correlation for ghidra-report.

Ingests runtime API logs from sandboxes (CAPE, Cuckoo, DRAKVUF) and correlates
them with static Ghidra disassembly to detect evasive behaviors, dormant APIs,
dynamically resolved calls, and sliding-window attack chains.
"""

import os
import sys
import json
from collections import deque

ATTACK_CHAINS = [
    {
        "name": "Classic Process Injection",
        "technique": "T1055.001",
        "weight": 40,
        "sequence": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    },
    {
        "name": "Process Hollowing",
        "technique": "T1055.012",
        "weight": 45,
        "sequence": ["CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "SetThreadContext", "ResumeThread"]
    },
    {
        "name": "QueueUserAPC Early Bird Injection",
        "technique": "T1055.004",
        "weight": 40,
        "sequence": ["VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC", "ResumeThread"]
    },
    {
        "name": "Registry Persistence Run Key",
        "technique": "T1547.001",
        "weight": 25,
        "sequence": ["RegOpenKeyEx", "RegSetValueEx"]
    },
    {
        "name": "LSASS Memory Dumping",
        "technique": "T1003.001",
        "weight": 45,
        "sequence": ["OpenProcess", "MiniDumpWriteDump"]
    }
]

def load_trace(trace_path):
    """Loads dynamic trace JSON, supporting CAPE/Cuckoo and generic formats."""
    with open(trace_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    calls = []
    # 1. Generic format: {"calls": [...]}
    if "calls" in data:
        calls = data["calls"]
    # 2. CAPE / Cuckoo behavior format: {"behavior": {"processes": [{"calls": [...]}]}}
    elif "behavior" in data and "processes" in data["behavior"]:
        for proc in data["behavior"]["processes"]:
            for c in proc.get("calls", []):
                calls.append(c)
    elif isinstance(data, list):
        calls = data

    normalized_calls = []
    for c in calls:
        if isinstance(c, str):
            normalized_calls.append({"api": c, "category": "general"})
        elif isinstance(c, dict):
            api_name = c.get("api", c.get("name", c.get("function", "")))
            if api_name:
                normalized_calls.append({
                    "api": api_name,
                    "category": c.get("category", ""),
                    "time": c.get("time", ""),
                    "status": c.get("status", ""),
                    "arguments": c.get("arguments", c.get("args", {}))
                })

    return {
        "calls": normalized_calls,
        "network": data.get("network", {}),
        "processes": data.get("processes", [])
    }

def match_sliding_chains(calls, window_size=10):
    """Matches multi-step attack chains across a sliding window of sequential API calls."""
    matches = []
    if len(calls) < 2:
        return matches

    api_names = [c["api"] for c in calls]

    for chain in ATTACK_CHAINS:
        seq = chain["sequence"]
        seq_len = len(seq)

        for i in range(len(api_names)):
            sub_window = api_names[i : i + window_size]
            # Check if all sequence items appear in order in sub_window
            seq_idx = 0
            ev_indices = []
            for w_idx, call_name in enumerate(sub_window):
                if seq_idx < seq_len and (call_name == seq[seq_idx] or call_name.endswith(seq[seq_idx])):
                    ev_indices.append(i + w_idx)
                    seq_idx += 1

            if seq_idx == seq_len:
                matches.append({
                    "name": chain["name"],
                    "technique": chain["technique"],
                    "weight": chain["weight"],
                    "sequence": seq,
                    "start_call_index": ev_indices[0],
                    "end_call_index": ev_indices[-1]
                })
                break # Matched this chain once

    return matches

def correlate_static_and_dynamic(static_data, dynamic_data):
    """Correlates static Ghidra report with runtime dynamic behavior."""
    static_apis = set()
    for item in static_data.get("suspicious_apis", []):
        fn = item.get("function", "")
        if fn: static_apis.add(fn)

    dynamic_calls = dynamic_data.get("calls", [])
    dynamic_api_counts = {}
    for c in dynamic_calls:
        api = c["api"]
        dynamic_api_counts[api] = dynamic_api_counts.get(api, 0) + 1

    dynamic_apis = set(dynamic_api_counts.keys())

    # 1. Confirmed APIs: Present in static imports AND called dynamically
    confirmed = sorted(list(static_apis & dynamic_apis))

    # 2. Dynamically Resolved APIs: Called at runtime but NOT in static imports
    hidden = sorted([a for a in dynamic_apis if a not in static_apis and not a.startswith("__")])

    # 3. Dormant APIs: Statically imported but never observed executing
    dormant = sorted([a for a in static_apis if a not in dynamic_apis])

    # 4. Attack chains via sliding call window
    chains = match_sliding_chains(dynamic_calls, window_size=12)

    return {
        "total_dynamic_calls": len(dynamic_calls),
        "unique_dynamic_apis": len(dynamic_apis),
        "confirmed_apis": confirmed,
        "hidden_dynamic_apis": hidden,
        "dormant_apis": dormant,
        "matched_chains": chains
    }

def print_correlation_report(static_file, trace_file, results):
    print("=" * 80)
    print("  DYNAMIC & STATIC THREAT CORRELATION REPORT")
    print("=" * 80)
    print(f"  Static Binary Report: {static_file}")
    print(f"  Dynamic Sandbox Trace: {trace_file}")
    print(f"  Total Dynamic Calls: {results['total_dynamic_calls']} ({results['unique_dynamic_apis']} unique APIs)")
    print()

    # Attack chains
    print("  ── Sliding Call Window Attack Sequences ──")
    if results["matched_chains"]:
        for ch in results["matched_chains"]:
            seq_str = " -> ".join(ch["sequence"])
            print(f"  ● [{ch['technique']}] {ch['name']} (Weight: +{ch['weight']})")
            print(f"    ↳ Sequence: {seq_str}")
    else:
        print("  No multi-step attack chains identified in sliding window.")
    print()

    # Confirmed APIs
    print("  ── Confirmed Runtime APIs (Static Import + Executed) ──")
    if results["confirmed_apis"]:
        for api in results["confirmed_apis"]:
            print(f"  ✔ {api}")
    else:
        print("  No matching static imports observed during dynamic run.")
    print()

    # Hidden APIs
    print("  ── Dynamically Resolved / Hidden APIs (Evasion Indicator) ──")
    if results["hidden_dynamic_apis"]:
        for api in results["hidden_dynamic_apis"][:10]:
            print(f"  ⚠ {api} (Not in static import table)")
        if len(results["hidden_dynamic_apis"]) > 10:
            print(f"  ... and {len(results['hidden_dynamic_apis']) - 10} additional unhooked/resolved API(s)")
    else:
        print("  No hidden dynamic API invocations detected.")
    print()

    # Dormant APIs
    print("  ── Dormant Static APIs (Imported but Unexecuted) ──")
    if results["dormant_apis"]:
        for api in results["dormant_apis"]:
            print(f"  💤 {api} (Possible dormant trigger or sandbox evasion)")
    else:
        print("  All static imports were executed.")
    print("=" * 80)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <correlate|scan-trace|json> <static_report.json> <trace.json>")
        sys.exit(1)

    action = sys.argv[1].lower()
    static_file = sys.argv[2]
    trace_file = sys.argv[3] if len(sys.argv) > 3 else None

    if action == "scan-trace":
        trace_data = load_trace(static_file)
        chains = match_sliding_chains(trace_data["calls"])
        print(f"Total dynamic calls: {len(trace_data['calls'])}")
        print(f"Matched attack chains: {len(chains)}")
        for ch in chains:
            print(f"  - [{ch['technique']}] {ch['name']}: {' -> '.join(ch['sequence'])}")
        sys.exit(0)

    if not trace_file:
        print("Error: trace.json path required.", file=sys.stderr)
        sys.exit(1)

    with open(static_file, "r", encoding="utf-8") as f:
        static_data = json.load(f)
    trace_data = load_trace(trace_file)

    results = correlate_static_and_dynamic(static_data, trace_data)

    if action == "correlate":
        print_correlation_report(static_file, trace_file, results)
    elif action == "json":
        print(json.dumps(results, indent=2))
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
