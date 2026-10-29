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

def _api_key(value):
    """Return a case-insensitive API identity without an optional library prefix."""
    return str(value or "").strip().casefold().rsplit("!", 1)[-1]


def load_trace(trace_path):
    """Load generic lists, generic objects, or CAPE/Cuckoo behavior traces."""
    with open(trace_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    network = {}
    processes = []
    raw_calls = []

    if isinstance(data, list):
        raw_calls = data
    elif isinstance(data, dict):
        network = data.get("network", {})
        if not isinstance(network, dict):
            network = {}
        processes = data.get("processes", [])
        if not isinstance(processes, list):
            processes = []

        if isinstance(data.get("calls"), list):
            raw_calls = data["calls"]
        else:
            behavior = data.get("behavior")
            behavior_processes = behavior.get("processes") if isinstance(behavior, dict) else None
            if isinstance(behavior_processes, list):
                processes = behavior_processes
                for process_index, process in enumerate(behavior_processes):
                    if not isinstance(process, dict):
                        continue
                    process_id = process.get(
                        "process_id",
                        process.get("pid", process.get("processid", f"process-{process_index}")),
                    )
                    process_name = process.get("process_name", process.get("name", ""))
                    process_calls = process.get("calls", [])
                    if not isinstance(process_calls, list):
                        continue
                    for call in process_calls:
                        if isinstance(call, dict):
                            enriched = dict(call)
                            enriched.setdefault("process_id", process_id)
                            if process_name:
                                enriched.setdefault("process_name", process_name)
                            raw_calls.append(enriched)
                        elif isinstance(call, str):
                            raw_calls.append({
                                "api": call,
                                "process_id": process_id,
                                "process_name": process_name,
                            })
            # A valid object without recognized call collections represents an
            # empty trace; malformed collection types are not iterated.
    else:
        raise ValueError("Trace JSON must be an object or an array of API calls.")

    normalized_calls = []
    for call in raw_calls:
        if isinstance(call, str):
            api_name = call.strip()
            call_data = {"category": "general"}
        elif isinstance(call, dict):
            api_name = call.get("api", call.get("name", call.get("function", "")))
            api_name = str(api_name).strip() if api_name is not None else ""
            call_data = call
        else:
            continue

        if not api_name:
            continue

        process_value = call_data.get("process_id", call_data.get("pid", call_data.get("processid")))
        process_name = call_data.get("process_name", "")
        process_value_object = call_data.get("process")
        if isinstance(process_value_object, dict):
            if process_value is None:
                process_value = process_value_object.get(
                    "process_id", process_value_object.get("pid", process_value_object.get("id"))
                )
            if not process_name:
                process_name = process_value_object.get("name", "")
        elif process_value is None and process_value_object is not None:
            process_value = process_value_object

        thread_id = call_data.get("thread_id", call_data.get("tid", call_data.get("threadId")))
        time_value = call_data.get("time", call_data.get("timestamp", ""))

        normalized = {
            "api": api_name,
            "category": call_data.get("category", ""),
            "time": time_value,
            "status": call_data.get("status", ""),
            "arguments": call_data.get("arguments", call_data.get("args", {})),
        }
        if process_value is not None:
            normalized["process_id"] = process_value
        if process_name:
            normalized["process_name"] = process_name
        if thread_id is not None:
            normalized["thread_id"] = thread_id
        normalized_calls.append(normalized)

    return {
        "calls": normalized_calls,
        "network": network,
        "processes": processes,
    }

def match_sliding_chains(calls, window_size=10):
    """Match ordered API sequences without combining calls from different processes."""
    matches = []
    if len(calls) < 2:
        return matches

    for chain in ATTACK_CHAINS:
        sequence = chain["sequence"]
        sequence_length = len(sequence)

        for start_index, first_call in enumerate(calls):
            process_key = first_call.get("process_id", first_call.get("process_name"))
            sequence_index = 0
            evidence_indices = []

            for call_index in range(start_index, min(len(calls), start_index + window_size)):
                call = calls[call_index]
                candidate_process = call.get("process_id", call.get("process_name"))
                if candidate_process != process_key:
                    continue

                call_name = _api_key(call.get("api", ""))
                expected_name = _api_key(sequence[sequence_index]) if sequence_index < sequence_length else ""
                if sequence_index < sequence_length and call_name.endswith(expected_name):
                    evidence_indices.append(call_index)
                    sequence_index += 1

            if sequence_index == sequence_length:
                matches.append({
                    "name": chain["name"],
                    "technique": chain["technique"],
                    "weight": chain["weight"],
                    "sequence": sequence,
                    "start_call_index": evidence_indices[0],
                    "end_call_index": evidence_indices[-1],
                })
                break  # Report each chain at most once.

    return matches

def correlate_static_and_dynamic(static_data, dynamic_data):
    """Correlate static API names and runtime calls using case-insensitive identities."""
    static_names = []
    for item in static_data.get("suspicious_apis", []):
        if not isinstance(item, dict):
            continue
        fn = item.get("function", "")
        if fn:
            static_names.append(str(fn).strip())

    static_by_key = {}
    for name in static_names:
        key = _api_key(name)
        if key:
            static_by_key.setdefault(key, name)

    dynamic_by_key = {}
    dynamic_calls = dynamic_data.get("calls", [])
    if not isinstance(dynamic_calls, list):
        dynamic_calls = []
    for call in dynamic_calls:
        if not isinstance(call, dict):
            continue
        api = str(call.get("api", "")).strip()
        key = _api_key(api)
        if key:
            dynamic_by_key.setdefault(key, api)

    static_keys = set(static_by_key)
    dynamic_keys = set(dynamic_by_key)

    # Preserve familiar names in the report while matching identity case-insensitively.
    confirmed = sorted(static_by_key[key] for key in static_keys & dynamic_keys)
    hidden = sorted(
        api for key, api in dynamic_by_key.items()
        if key not in static_keys and not api.startswith("__")
    )
    dormant = sorted(static_by_key[key] for key in static_keys - dynamic_keys)
    chains = match_sliding_chains(dynamic_calls, window_size=12)

    return {
        "total_dynamic_calls": len(dynamic_calls),
        "unique_dynamic_apis": len(dynamic_keys),
        "confirmed_apis": confirmed,
        "hidden_dynamic_apis": hidden,
        "dormant_apis": dormant,
        "matched_chains": chains,
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
