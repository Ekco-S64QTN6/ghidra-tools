#!/usr/bin/env python3
"""Validate the report-v1 schema and representative PE/SNES report shapes."""

import copy
import json
from pathlib import Path

from jsonschema import Draft7Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "report-v1.schema.json"


def sample_report():
    return {
        "schema_version": "1.0.0",
        "file": "sample.bin",
        "format": "Binary",
        "format_label": "PE",
        "generated": "2026-10-29T12:00:00-05:00",
        "hashes": {"md5": "0" * 32, "sha256": "0" * 64},
        "architecture": {
            "language": "x86",
            "language_id": "x86:LE:32:default",
            "compiler_spec": "default",
            "endianness": "little",
            "pointer_size_bits": 32,
        },
        "threat_summary": {"risk_score": 10, "risk_level": "LOW", "indicators": []},
        "memory_blocks": [],
        "suspicious_apis": [],
        "iocs": [],
        "deobfuscated_strings": [],
        "top_functions": [],
        "analysis_stats": {
            "function_count": 0,
            "symbol_count": 0,
            "initialized_bytes": 0,
            "disassembled_bytes": 0,
            "code_coverage_pct": 0.0,
        },
    }


def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema)

    pe_report = sample_report()
    validator.validate(pe_report)

    # The additive detection section is optional so older v1 consumers/reports
    # remain valid, but when present its nullability and numeric flags are typed.
    detection_report = sample_report()
    detection_report["detection"] = {
        "detected_format": "elf",
        "evidence": "ELF64, little-endian, x86-64, e_flags=0x00000000",
        "processor_language_id": "x86:LE:64:default",
        "selected_processor_language_id": "x86:LE:64:default",
        "requested_loader": None,
        "import_strategy": "explicit_processor",
        "elf_flags": 0,
    }
    validator.validate(detection_report)

    malformed_detection = copy.deepcopy(detection_report)
    malformed_detection["detection"]["elf_flags"] = "0x0"
    try:
        validator.validate(malformed_detection)
    except ValidationError:
        pass
    else:
        raise AssertionError("schema unexpectedly accepted string-valued detection.elf_flags")

    snes_report = sample_report()
    snes_report["snes"] = {
        "title": "SYNTHETIC SNES",
        "mapping_mode": "LoROM",
        "rom_type": "ROM",
        "rom_size": "64 KB",
        "valid_header": True,
        "checksum": 123,
        "complement": 65412,
        "dma_channels": [{
            "channel": 0,
            "mode": "DMA",
            "targets": ["PPU register"],
            "table_pointers": ["0x7E0000"],
            "hits": 3,
        }],
        "mmio_accesses": [{
            "address": 0x2100,
            "register": "INIDISP",
            "category": "PPU",
            "hits": 2,
            "description": "Display control",
        }],
    }
    validator.validate(snes_report)

    bad_version = copy.deepcopy(pe_report)
    bad_version["schema_version"] = "2.0.0"
    try:
        validator.validate(bad_version)
    except ValidationError:
        pass
    else:
        raise AssertionError("schema unexpectedly accepted a different schema_version")

    bad_stats = copy.deepcopy(pe_report)
    bad_stats["analysis_stats"]["function_count"] = "many"
    try:
        validator.validate(bad_stats)
    except ValidationError:
        pass
    else:
        raise AssertionError("schema unexpectedly accepted a string function_count")

    print("[PASS] report-v1 schema validates PE/SNES shapes and rejects incompatible versions/types")


if __name__ == "__main__":
    main()
