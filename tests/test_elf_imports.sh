#!/usr/bin/env bash
# Import each synthetic ELF through the real Ghidra loader and verify report language_id.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export GHIDRA_REPORT_OUTPUT_DIR="$TMP_DIR/output"
export GHIDRA_REPORT_PROJECTS_DIR="$TMP_DIR/projects"
export GHIDRA_REPORT_INGRESS_DIR="$TMP_DIR/ingress"
mkdir -p "$GHIDRA_REPORT_OUTPUT_DIR" "$GHIDRA_REPORT_PROJECTS_DIR" "$GHIDRA_REPORT_INGRESS_DIR"

FIXTURE_DIR="$TMP_DIR/fixtures"
python3 "$SCRIPT_DIR/tests/make_elf_fixtures.py" "$FIXTURE_DIR"

count=0
while IFS=$'\t' read -r fixture expected_language name; do
    log="$TMP_DIR/$name.log"
    if ! "$SCRIPT_DIR/ghidra-report.sh" --reimport "$fixture" --format json >"$log" 2>&1; then
        echo "[FAIL] Ghidra could not import synthetic ELF fixture: $name" >&2
        tail -n 100 "$log" >&2
        exit 1
    fi

    output_key="$(python3 "$SCRIPT_DIR/scripts/project_identity.py" output "$fixture")"
    report="$GHIDRA_REPORT_OUTPUT_DIR/$output_key/report_latest.json"
    if [[ ! -s "$report" ]]; then
        echo "[FAIL] No non-empty JSON report was generated for $name: $report" >&2
        tail -n 100 "$log" >&2
        exit 1
    fi

    if ! python3 - "$report" "$expected_language" "$name" <<'PYASSERT'
import json
import sys

report_path, expected_language, name = sys.argv[1:]
with open(report_path, encoding="utf-8") as handle:
    report = json.load(handle)
architecture = report.get("architecture", {})
actual = architecture.get("language_id")
if report.get("format") != "Executable and Linking Format (ELF)":
    raise SystemExit(f"{name}: expected ELF loader, got format={report.get('format')!r}")
if actual != expected_language:
    raise SystemExit(
        f"{name}: expected opened language {expected_language!r}, got {actual!r}"
    )
PYASSERT
    then
        echo "[FAIL] Ghidra opened an unexpected language for $name" >&2
        exit 1
    fi

    count=$((count + 1))
    echo "[PASS] $name -> $expected_language"
done < <(python3 - "$FIXTURE_DIR/manifest.json" <<'PYMANIFEST'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    rows = json.load(handle)
for row in rows:
    print(f"{row['path']}\t{row['language_id']}\t{row['name']}")
PYMANIFEST
)

[[ "$count" -eq 15 ]] || {
    echo "[FAIL] Expected 15 actual ELF imports, verified $count" >&2
    exit 1
}
echo "[PASS] Ghidra imported 15 synthetic ELF executables and each JSON report recorded the expected opened language_id"
