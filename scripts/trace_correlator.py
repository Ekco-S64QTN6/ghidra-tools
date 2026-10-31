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
import re

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
    """Normalize module-qualified and common PE import-decorated API names."""
    api = str(value or "").strip().casefold().rsplit("!", 1)[-1]
    if api.startswith("__imp_"):
        api = api[6:]
    if api.startswith("_"):
        api = api[1:]
    return re.sub(r"@\d+$", "", api)


def _process_key(call):
    """Return a stable per-process identity, or None when provenance is absent."""
    value = call.get("process_id")
    if value is None or value == "":
        value = call.get("process_name")
    if value is None or value == "":
        return None
    return str(value).strip().casefold() or None


def _trace_metadata(data):
    """Extract stable trace provenance from generic/CAPE-like objects."""
    if not isinstance(data, dict):
        return {}

    def at_path(root, path):
        value = root
        for key in path:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
        return value

    sha_paths = [
        ("sha256",), ("SHA256",),
        ("target", "sha256"), ("target", "file", "sha256"),
        ("sample", "sha256"), ("sample", "file", "sha256"),
        ("metadata", "sha256"), ("metadata", "target_sha256"),
        ("info", "sha256"), ("info", "target", "sha256"),
    ]
    md5_paths = [
        ("md5",), ("MD5",),
        ("target", "md5"), ("target", "file", "md5"),
        ("sample", "md5"), ("sample", "file", "md5"),
        ("metadata", "md5"), ("info", "md5"),
    ]
    run_paths = [
        ("task_id",), ("analysis_id",), ("info", "id"),
        ("info", "task_id"), ("metadata", "run_id"),
    ]
    source_paths = [
        ("source",), ("sandbox",), ("generator",),
        ("metadata", "source"), ("info", "package", "name"),
    ]

    result = {}
    for field, candidates, pattern in (
        ("sha256", sha_paths, r"^[0-9a-fA-F]{64}$"),
        ("md5", md5_paths, r"^[0-9a-fA-F]{32}$"),
    ):
        for path in candidates:
            value = at_path(data, path)
            if isinstance(value, str) and re.fullmatch(pattern, value.strip()):
                result[field] = value.strip().lower()
                break

    for field, candidates in (("run_id", run_paths), ("source", source_paths)):
        for path in candidates:
            value = at_path(data, path)
            if isinstance(value, (str, int)) and str(value).strip():
                result[field] = str(value).strip()
                break
    return result



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
                    process_id = process.get("process_id")
                    if process_id is None:
                        process_id = process.get("pid")
                    if process_id is None:
                        process_id = process.get("processid")
                    if process_id is None:
                        process_id = f"process-{process_index}"
                    process_name = process.get("process_name", process.get("name", ""))
                    process_calls = process.get("calls", [])
                    if not isinstance(process_calls, list):
                        continue
                    for call in process_calls:
                        if isinstance(call, dict):
                            enriched = dict(call)
                            if enriched.get("process_id") is None:
                                enriched["process_id"] = process_id
                            if process_name and not enriched.get("process_name"):
                                enriched["process_name"] = process_name
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

        process_value = call_data.get("process_id")
        if process_value is None:
            process_value = call_data.get("pid")
        if process_value is None:
            process_value = call_data.get("processid")
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
        "metadata": _trace_metadata(data),
    }

def match_sliding_chains(calls, window_size=10):
    """Match ordered API sequences and retain exact same-process event evidence."""
    matches = []
    if len(calls) < 2:
        return matches

    for chain in ATTACK_CHAINS:
        sequence = chain["sequence"]
        for start_index, first_call in enumerate(calls):
            process_key = _process_key(first_call)
            if process_key is None or _api_key(first_call.get("api", "")) != _api_key(sequence[0]):
                continue

            sequence_index = 1
            evidence_indices = [start_index]
            for call_index in range(start_index + 1, min(len(calls), start_index + window_size)):
                call = calls[call_index]
                if _process_key(call) != process_key:
                    continue
                if _api_key(call.get("api", "")) == _api_key(sequence[sequence_index]):
                    evidence_indices.append(call_index)
                    sequence_index += 1
                    if sequence_index == len(sequence):
                        break

            if sequence_index == len(sequence):
                evidence_calls = []
                for call_index in evidence_indices:
                    call = calls[call_index]
                    event = {
                        "call_index": call_index,
                        "api": call.get("api", ""),
                        "process_id": call.get("process_id"),
                        "process_name": call.get("process_name"),
                        "thread_id": call.get("thread_id"),
                        "time": call.get("time"),
                    }
                    if "arguments" in call:
                        event["arguments"] = call["arguments"]
                    evidence_calls.append(event)

                matches.append({
                    "name": chain["name"],
                    "technique": chain["technique"],
                    "weight": chain["weight"],
                    "sequence": sequence,
                    "start_call_index": evidence_indices[0],
                    "end_call_index": evidence_indices[-1],
                    "evidence_calls": evidence_calls,
                })
                break

    return matches


_RESOLVER_APIS = {
    "getprocaddress",
    "ldrgetprocedureaddress",
    "dlsym",
    "dlvsym",
}
_RESOLVER_ARGUMENT_NAMES = {
    "lpprocname", "procname", "procedurename", "symbol", "symbolname",
    "function", "functionname", "apiname", "requestedname", "name",
}


def _first_string(value):
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        for nested in value.values():
            found = _first_string(nested)
            if found:
                return found
    elif isinstance(value, list):
        for nested in reversed(value):
            found = _first_string(nested)
            if found:
                return found
    return None


def _resolved_symbol_from_call(call):
    arguments = call.get("arguments", call.get("args", {}))
    if isinstance(arguments, dict):
        for key, value in arguments.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized_key in _RESOLVER_ARGUMENT_NAMES:
                found = _first_string(value)
                if found and _api_key(found):
                    return found
        return None
    if isinstance(arguments, list):
        found = _first_string(arguments)
        if found and _api_key(found):
            return found
    return None


def _dynamic_resolution_evidence(calls):
    """Require a named resolver argument and a later same-process API event."""
    evidence = []
    for resolver_index, resolver_call in enumerate(calls):
        resolver_api = _api_key(resolver_call.get("api", ""))
        if resolver_api not in _RESOLVER_APIS:
            continue
        process_key = _process_key(resolver_call)
        if process_key is None:
            continue
        resolved_name = _resolved_symbol_from_call(resolver_call)
        resolved_key = _api_key(resolved_name)
        if not resolved_key:
            continue

        for call_index in range(resolver_index + 1, len(calls)):
            call = calls[call_index]
            if _process_key(call) != process_key:
                continue
            if _api_key(call.get("api", "")) != resolved_key:
                continue
            evidence.append({
                "api": call.get("api", resolved_name),
                "resolver_api": resolver_call.get("api", ""),
                "resolver_call_index": resolver_index,
                "call_index": call_index,
                "process_id": resolver_call.get("process_id"),
                "process_name": resolver_call.get("process_name"),
                "resolver_arguments": resolver_call.get("arguments", {}),
                "call_time": call.get("time"),
            })
            break
    return evidence


def correlate_static_and_dynamic(static_data, dynamic_data):
    """Correlate all static imports with runtime calls without overstating resolution."""
    if not isinstance(static_data, dict):
        static_data = {}
    if not isinstance(dynamic_data, dict):
        dynamic_data = {}

    static_names = []
    for field in ("static_apis", "suspicious_apis"):
        items = static_data.get(field, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            function = item.get("function", "")
            if function:
                static_names.append(str(function).strip())

    static_by_key = {}
    for name in static_names:
        key = _api_key(name)
        if key:
            static_by_key.setdefault(key, name)

    dynamic_calls = dynamic_data.get("calls", [])
    if not isinstance(dynamic_calls, list):
        dynamic_calls = []
    dynamic_by_key = {}
    for call in dynamic_calls:
        if not isinstance(call, dict):
            continue
        api = str(call.get("api", "")).strip()
        key = _api_key(api)
        if key:
            dynamic_by_key.setdefault(key, api)

    static_keys = set(static_by_key)
    dynamic_keys = set(dynamic_by_key)
    confirmed = sorted(static_by_key[key] for key in static_keys & dynamic_keys)
    unmatched = sorted(dynamic_by_key[key] for key in dynamic_keys - static_keys)
    unobserved = sorted(static_by_key[key] for key in static_keys - dynamic_keys)

    resolution_evidence = _dynamic_resolution_evidence(dynamic_calls)
    resolved_by_key = {}
    for item in resolution_evidence:
        key = _api_key(item["api"])
        if key:
            resolved_by_key.setdefault(key, item["api"])

    hashes = static_data.get("hashes", {})
    if not isinstance(hashes, dict):
        hashes = {}
    sample_sha256 = hashes.get("sha256")
    if not isinstance(sample_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sample_sha256):
        sample_sha256 = None
    else:
        sample_sha256 = sample_sha256.lower()

    trace_metadata = dynamic_data.get("metadata", {})
    if not isinstance(trace_metadata, dict):
        trace_metadata = {}
    trace_sha256 = trace_metadata.get("sha256")
    if not isinstance(trace_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", trace_sha256):
        trace_sha256 = None
    else:
        trace_sha256 = trace_sha256.lower()

    if sample_sha256 and trace_sha256:
        provenance = "match" if sample_sha256 == trace_sha256 else "mismatch"
    else:
        provenance = "unknown"

    return {
        "total_dynamic_calls": len(dynamic_calls),
        "unique_dynamic_apis": len(dynamic_keys),
        "static_import_count": len(static_keys),
        "confirmed_apis": confirmed,
        "unmatched_dynamic_apis": unmatched,
        "hidden_dynamic_apis": unmatched,
        "static_unobserved_apis": unobserved,
        "dormant_apis": unobserved,
        "dynamically_resolved_apis": sorted(resolved_by_key.values()),
        "dynamic_resolution_evidence": resolution_evidence,
        "matched_chains": match_sliding_chains(dynamic_calls, window_size=12),
        "provenance": provenance,
        "sample_sha256": sample_sha256,
        "trace_sha256": trace_sha256,
        "trace_run_id": trace_metadata.get("run_id"),
        "trace_source": trace_metadata.get("source"),
        "provenance_warning": (
            "Trace SHA-256 does not match the analyzed sample; treat this as an unrelated observation."
            if provenance == "mismatch" else
            "Trace SHA-256 is unavailable; same-sample provenance is unverified."
            if provenance == "unknown" else None
        ),
    }



def print_correlation_report(static_file, trace_file, results):
    print("=" * 80)
    print("  DYNAMIC & STATIC THREAT CORRELATION REPORT")
    print("=" * 80)
    print(f"  Static Binary Report: {static_file}")
    print(f"  Dynamic Sandbox Trace: {trace_file}")
    print(f"  Total Dynamic Calls: {results['total_dynamic_calls']} ({results['unique_dynamic_apis']} unique APIs)")
    print(f"  Static Imports: {results.get('static_import_count', 0)}")
    print(f"  Trace Provenance: {results.get('provenance', 'unknown').upper()}")
    if results.get("trace_source") or results.get("trace_run_id"):
        print(f"  Trace Source/Run: {results.get('trace_source') or 'unknown'} / {results.get('trace_run_id') or 'unknown'}")
    if results.get("provenance_warning"):
        print(f"  [!] {results['provenance_warning']}")
    print()

    print("  -- Sliding Call Window Attack Sequences --")
    if results["matched_chains"]:
        for chain in results["matched_chains"]:
            sequence = " -> ".join(chain["sequence"])
            print(f"  * [{chain['technique']}] {chain['name']} (Weight: +{chain['weight']})")
            print(f"    Sequence: {sequence}")
            for event in chain.get("evidence_calls", []):
                print(f"      #{event['call_index']} {event.get('api', '')} pid={event.get('process_id', 'unknown')} time={event.get('time', '')}")
    else:
        print("  No multi-step attack chains identified in the process-scoped window.")
    print()

    print("  -- Confirmed Runtime APIs (Imported + Observed) --")
    for api in results["confirmed_apis"]:
        print(f"  + {api}")
    if not results["confirmed_apis"]:
        print("  No matching static imports were observed during this trace.")
    print()

    print("  -- Observed APIs Absent from Static Imports --")
    for api in results["unmatched_dynamic_apis"][:10]:
        print(f"  ? {api} (not proof of dynamic resolution)")
    if len(results["unmatched_dynamic_apis"]) > 10:
        print(f"  ... and {len(results['unmatched_dynamic_apis']) - 10} more")
    if not results["unmatched_dynamic_apis"]:
        print("  No unmatched runtime API names.")
    print()

    print("  -- Explicitly Corroborated Dynamic Resolution --")
    for item in results["dynamic_resolution_evidence"]:
        print(f"  ! {item['resolver_api']} resolved {item['api']} (resolver call #{item['resolver_call_index']}, use #{item['call_index']})")
    if not results["dynamic_resolution_evidence"]:
        print("  No resolver-and-subsequent-call evidence was found.")
    print()

    print("  -- Static Imports Not Observed in This Trace --")
    for api in results["static_unobserved_apis"][:20]:
        print(f"  - {api}")
    if not results["static_unobserved_apis"]:
        print("  All recorded static imports were observed in this trace.")
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
