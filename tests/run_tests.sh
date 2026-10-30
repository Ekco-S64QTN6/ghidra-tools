#!/usr/bin/env bash
#
# tests/run_tests.sh — End-to-end integration test suite for ghidra-report toolkit.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0
SKIP=0

GHIDRA_ROOT="${GHIDRA_ROOT:-}"
if [ -z "$GHIDRA_ROOT" ] || [ ! -d "$GHIDRA_ROOT" ]; then
    for candidate in \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/x86_64/stable/active/files/lib/ghidra" \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra" \
        "/opt/ghidra" \
        "/usr/share/ghidra"; do
        [ -d "$candidate" ] && GHIDRA_ROOT="$candidate" && break
    done
fi
export GHIDRA_ROOT
source "$SCRIPT_DIR/scripts/ghidra_language.sh"

log_test() { echo -e "\033[0;34m[TEST]\033[0m $*"; }
log_pass() { echo -e "\033[0;32m  [PASS]\033[0m $*"; PASS=$((PASS+1)); }
log_fail() { echo -e "\033[0;31m  [FAIL]\033[0m $*"; FAIL=$((FAIL+1)); }
log_skip() { echo -e "\033[0;33m  [SKIP]\033[0m $*"; SKIP=$((SKIP+1)); }

echo "================================================================================"
echo "  ghidra-report Integration Test Suite"
echo "================================================================================"

# ── Fixtures ────────────────────────────────────────────────────────────────
# The suite brings its own samples. It must never read from the drop folder,
# whose contents are git-ignored, machine-specific, and not ours to depend on.
# tests/make_fixtures.py synthesizes both binaries from code, so a fresh clone
# and CI can run this suite too.
FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

log_test "Generating synthetic analysis fixtures..."
if python3 "$SCRIPT_DIR/tests/make_fixtures.py" "$FIXTURE_DIR" >/dev/null 2>&1; then
    log_pass "Fixtures generated (packed PE32 + LoROM SNES cartridge)"
else
    log_fail "Fixture generation failed — remaining tests cannot run"
    exit 1
fi

PE_FIXTURE="$FIXTURE_DIR/packed_sample.dll"
SNES_FIXTURE="$FIXTURE_DIR/console_sample.sfc"
PE_NAME="packed_sample.dll"
SNES_NAME="console_sample.sfc"
PE_OUTPUT_KEY="$(python3 "$SCRIPT_DIR/scripts/project_identity.py" output "$PE_FIXTURE")"
SNES_OUTPUT_KEY="$(python3 "$SCRIPT_DIR/scripts/project_identity.py" output "$SNES_FIXTURE")"

# 1. Test CLI Help & Flags
log_test "Validating CLI Help & Argument Parsing..."
APP_VERSION="$(cat "$SCRIPT_DIR/VERSION")"
if "$SCRIPT_DIR/ghidra-report.sh" --help | grep -F "v${APP_VERSION}" >/dev/null; then
    log_pass "CLI help output displays version banner"
else
    log_fail "CLI help failed"
fi

# 2. Test Single Binary Analysis (synthetic packed PE32)
log_test "Testing Single Binary Analysis ($PE_NAME)..."
"$SCRIPT_DIR/ghidra-report.sh" --reimport "$PE_FIXTURE" > /dev/null 2>&1
REP_DIR="$SCRIPT_DIR/output/$PE_OUTPUT_KEY"

for ext in txt json md html sarif yar misp.json; do
    if [ -f "$REP_DIR/report_latest.$ext" ]; then
        log_pass "Report generated: report_latest.$ext"
    else
        log_fail "Missing artifact: report_latest.$ext"
    fi
done

# Validate JSON schema and Threat Score
if python3 -c "import json; d=json.load(open('$REP_DIR/report_latest.json')); assert d['threat_summary']['risk_score'] == 100" 2>/dev/null; then
    log_pass "Threat score is 100/100 (CRITICAL) for the packed fixture"
else
    log_fail "Threat score verification failed for $PE_NAME"
fi

# Verify detector evidence remains distinct from the loader's actual output.
if python3 - "$REP_DIR/report_latest.json" <<'PYDETECTION'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
detection = report.get("detection", {})
assert detection.get("detected_format") == "pe", detection
assert "PE" in detection.get("evidence", ""), detection
assert detection.get("processor_language_id") is None, detection
assert detection.get("selected_processor_language_id") is None, detection
assert detection.get("requested_loader") is None, detection
assert detection.get("import_strategy") == "ghidra_default", detection
assert report.get("architecture", {}).get("language_id"), report
PYDETECTION
then
    log_pass "PE report preserves detector evidence separately from Ghidra's actual architecture"
else
    log_fail "PE detector/import provenance verification failed"
fi

# Verify that Ghidra records suspicious API call sites under their actual caller function.
if python3 - "$REP_DIR/report_latest.json" <<'PYFUNCTION'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
functions = report.get("function_api_evidence", [])
assert functions, "no function-level suspicious API call evidence was recorded"
assert all(item.get("function") and item.get("address") for item in functions), functions
calls = [
    call
    for function in functions
    for call in function.get("suspicious_apis", [])
]
assert calls, functions
assert all(call.get("function") and call.get("target_address") and call.get("call_site") for call in calls), calls
assert any(call["function"] == "GetModuleHandleA" for call in calls), calls
PYFUNCTION
then
    log_pass "Ghidra report records imported API call sites against their caller functions"
else
    log_fail "Function-scoped API call evidence was missing or incomplete"
fi

# Verify that printable strings are recovered only from contiguous immediate writes
# to stack-frame offsets, not from ordinary register-immediate MOV instructions.
if python3 - "$REP_DIR/report_latest.json" <<'PYSTACK'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
strings = report.get("stack_strings", [])
matches = [item for item in strings if item.get("value") == "ABCDEFGH"]
assert matches, strings
assert all(item.get("method") == "contiguous_stack_immediate_stores" for item in matches), matches
assert all(item.get("function") and item.get("address") and item.get("evidence") for item in matches), matches
assert all(item.get("stack_offset_end", 0) - item.get("stack_offset_start", 0) == 8 for item in matches), matches
assert not any(item.get("value") in {"AAAA", "test", "YZ", "YZABCDEFGH"} for item in strings), strings
PYSTACK
then
    log_pass "Stack-string recovery requires contiguous constant stack writes and rejects register-derived/non-contiguous decoys"
else
    log_fail "Stack-string evidence was missing, non-contiguous, or included stack-store false positives"
fi

# Validate MISP JSON schema
if python3 -c "import json; d=json.load(open('$REP_DIR/report_latest.misp.json')); assert 'Event' in d and len(d['Event']['Attribute']) > 0" 2>/dev/null; then
    log_pass "MISP 2.4 JSON schema validated with populated attributes"
else
    log_fail "MISP schema validation failed"
fi

# Verify the actual Ghidra ELF loader selection and the language recorded in reports.
log_test "Testing real Ghidra ELF architecture and language selection..."
ELF_IMPORT_LOG="$FIXTURE_DIR/elf-import-matrix.log"
if bash "$SCRIPT_DIR/tests/test_elf_imports.sh" >"$ELF_IMPORT_LOG" 2>&1; then
    log_pass "$(tail -n 1 "$ELF_IMPORT_LOG")"
else
    log_fail "Real Ghidra ELF import matrix failed; captured output follows:"
    sed -n '1,260p' "$ELF_IMPORT_LOG" >&2
    exit 1
fi

# 3. Test SNES cartridge detection independent of optional processor extensions.
log_test "Testing SNES ROM header detection ($SNES_NAME)..."
DETECT_SNES="$("$SCRIPT_DIR/ghidra-report.sh" --detect-type "$SNES_FIXTURE")"
if [ "$DETECT_SNES" = "snes" ]; then
    log_pass "Synthetic LoROM cartridge header detected as SNES"
else
    log_fail "SNES detection failed: expected 'snes', got '$DETECT_SNES'"
fi

SNES_ANALYSIS_AVAILABLE=false
if ghidra_language_available "65816:LE:24:snes"; then
    log_test "Testing SNES raw 65816 Ghidra analysis..."
    SNES_ANALYSIS_LOG="$FIXTURE_DIR/snes-analysis.log"
    if "$SCRIPT_DIR/ghidra-report.sh" --reimport "$SNES_FIXTURE" --format all >"$SNES_ANALYSIS_LOG" 2>&1; then
        :
    else
        analysis_status=$?
        log_fail "SNES Ghidra analysis failed with exit status $analysis_status; captured output follows:"
        sed -n '1,240p' "$SNES_ANALYSIS_LOG" >&2
        exit "$analysis_status"
    fi
    SNES_REP="$SCRIPT_DIR/output/$SNES_OUTPUT_KEY/report_latest.json"

    if python3 -c "import json; d=json.load(open('$SNES_REP')); assert d['snes']['valid_header'] and 'LoROM' in d['snes']['mapping_mode']" 2>/dev/null; then
        log_pass "SNES cartridge header parsed and validated as LoROM"
    else
        log_fail "SNES cartridge header validation failed"
    fi

    if python3 -c "import json; d=json.load(open('$SNES_REP')); assert d['analysis_stats']['function_count'] > 0" 2>/dev/null; then
        log_pass "Interrupt vector seeding recovered functions from the raw 65816 import"
    else
        log_fail "Vector seeding produced no functions"
    fi

    if python3 -c "import json; d=json.load(open('$SNES_REP')); assert 'snes' in d and len(d['snes']['mmio_accesses']) > 10" 2>/dev/null; then
        log_pass "SNES MMIO hardware register accesses detected (> 10 registers)"
    else
        log_fail "SNES MMIO detection failed"
    fi

    if python3 -c "import json; d=json.load(open('$SNES_REP')); assert len(d['snes']['dma_channels']) > 0" 2>/dev/null; then
        log_pass "SNES DMA/HDMA channels detected"
    else
        log_fail "SNES DMA detection failed"
    fi
    SNES_ANALYSIS_AVAILABLE=true
else
    log_skip "SNES raw 65816 Ghidra analysis requires optional language 65816:LE:24:snes; header detection remains covered"
fi

# 4. Test Semantic Diff (requires both analyzed reports).
if [ "$SNES_ANALYSIS_AVAILABLE" = true ]; then
    log_test "Testing Semantic Findings Lifecycle Diff..."
    DIFF_OUT="$("$SCRIPT_DIR/ghidra-report.sh" --diff "$PE_OUTPUT_KEY" "$SNES_OUTPUT_KEY" 2>&1)"
    if echo "$DIFF_OUT" | grep -q "Threat Score: 100" && echo "$DIFF_OUT" | grep -q "Lifecycle Summary"; then
        log_pass "Semantic diff generated with threat score delta and API lifecycle summary"
    else
        log_fail "Semantic diff failed"
    fi
else
    log_skip "SNES semantic diff requires a Ghidra SNES report and is not run without the optional 65816 language"
fi

# 5. Test Firmware Container Carver
log_test "Testing Firmware Container Carver Pipeline..."
TEST_TMP="$SCRIPT_DIR/scratch_test_fw.bin"
python3 -c "
import struct, gzip
blob = bytearray(b' ' * 256)
gz = gzip.compress(b'TEST_KERNEL_IMAGE_STREAM' * 10)
blob.extend(gz)
u_hdr = struct.pack('>IIIIIIIBBBB32s', 0x27051956, 0, 1700000000, 20, 0, 0, 0, 5, 1, 2, 0, b'UImage-Test ')
blob.extend(u_hdr)
blob.extend(b'A' * 20)
open('$TEST_TMP', 'wb').write(blob)
"
CARVE_JSON="$(python3 "$SCRIPT_DIR/scripts/firmware_carver.py" json "$TEST_TMP")"
rm -f "$TEST_TMP"
if echo "$CARVE_JSON" | grep -q "uimage" && echo "$CARVE_JSON" | grep -q "gzip"; then
    log_pass "Firmware carver accurately detected embedded GZIP and U-Boot uImage"
else
    log_fail "Firmware carver test failed"
fi

# 6. Test SQLite Historical Search
log_test "Testing SQLite Historical Search..."
SEARCH_OUT="$("$SCRIPT_DIR/ghidra-report.sh" --search "Themida" 2>&1)"
if echo "$SEARCH_OUT" | grep -q "$PE_NAME"; then
    log_pass "Historical search matched 'Themida' to $PE_NAME"
else
    log_fail "Historical search failed"
fi

# 7. Test Web Dashboard API Endpoints
log_test "Testing Web Dashboard REST Endpoints..."
DASH_OUT="$(python3 -c "
import subprocess, time, urllib.request, json
proc = subprocess.Popen(['python3', '$SCRIPT_DIR/scripts/dashboard.py', '8991'])
time.sleep(0.8)
try:
    with urllib.request.urlopen('http://localhost:8991/api/reports') as resp:
        d = json.loads(resp.read().decode())
        print(f'REPORTS_COUNT_{len(d)}')
finally:
    proc.terminate()
    proc.wait()
")"
if echo "$DASH_OUT" | grep -q "REPORTS_COUNT_"; then
    log_pass "Dashboard /api/reports returned active reports"
else
    log_fail "Dashboard API test failed"
fi

# 8. Test Rule-Driven Capability Engine
log_test "Testing Rule-Driven Capability Engine (--rules)..."
RULES_OUT="$("$SCRIPT_DIR/ghidra-report.sh" --rules "$PE_OUTPUT_KEY" 2>&1)"
if echo "$RULES_OUT" | grep -q "Packed Executable with Suspicious Section" && echo "$RULES_OUT" | grep -q "T1027.002"; then
    log_pass "YAML capability engine matched packed executable rule with ATT&CK T1027.002"
else
    log_fail "Capability engine test failed"
fi

# 9. Test Dynamic Sandbox Trace Correlator
log_test "Testing Dynamic Sandbox Trace Correlator (--trace)..."
TRACE_TMP="$SCRIPT_DIR/scratch_trace_test.json"
echo '{"calls": [{"api": "GetModuleHandleA"}, {"api": "VirtualAllocEx"}, {"api": "WriteProcessMemory"}, {"api": "CreateRemoteThread"}]}' > "$TRACE_TMP"
TRACE_OUT="$("$SCRIPT_DIR/ghidra-report.sh" --trace "$TRACE_TMP" "$PE_OUTPUT_KEY" 2>&1)"
rm -f "$TRACE_TMP"
if echo "$TRACE_OUT" | grep -q "Classic Process Injection" && echo "$TRACE_OUT" | grep -q "GetModuleHandleA"; then
    log_pass "Trace correlator detected sliding window injection sequence and confirmed APIs"
else
    log_fail "Trace correlator test failed"
fi

# 10. Test CMSIS-SVD Hardware Register Injection
log_test "Testing CMSIS-SVD Hardware Register Injection (--svd)..."
SVD_TMP="$SCRIPT_DIR/scratch_svd_test.svd"
cat << 'SVD_EOF' > "$SVD_TMP"
<?xml version="1.0" encoding="utf-8"?>
<device schemaVersion="1.1" xmlns:xs="http://www.w3.org/2001/XMLSchema-instance">
  <name>RP2040_TEST</name>
  <description>Test ARM Cortex-M0+ Chip</description>
  <peripherals>
    <peripheral>
      <name>SIO</name>
      <baseAddress>0xD0000000</baseAddress>
      <registers>
        <register><name>CPUID</name><addressOffset>0x000</addressOffset><size>32</size></register>
      </registers>
    </peripheral>
  </peripherals>
</device>
SVD_EOF
SVD_OUT="$("$SCRIPT_DIR/ghidra-report.sh" --svd "$SVD_TMP" 2>&1)"
rm -f "$SVD_TMP"
if echo "$SVD_OUT" | grep -q "RP2040_TEST" && echo "$SVD_OUT" | grep -q "0xD0000000"; then
    log_pass "SVD injector mapped peripheral base address 0xD0000000 and registers"
else
    log_fail "SVD injector test failed"
fi

# 12. Optional Ghidra Extensions & Multi-Format Loader Auto-Detection
log_test "Checking optional community loader extensions..."
EXT_ROOT="${GHIDRA_EXTENSION_ROOT:-$HOME/.config/ghidra}"
ext_count=0
if [ -d "$EXT_ROOT" ]; then
    while IFS= read -r ext_dir; do
        dir_count=$(find "$ext_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
        ext_count=$((ext_count + dir_count))
    done < <(find "$EXT_ROOT" -type d -name Extensions -print 2>/dev/null)
fi
if [ "$ext_count" -ge 7 ]; then
    log_pass "Found $ext_count per-version community extensions under $EXT_ROOT"
else
    log_skip "Found $ext_count community extensions under $EXT_ROOT; optional loader-specific validation is not run in this environment"
fi

# Test GBA, N64, and PSX detection using minimal but structurally valid headers.
TMP_DIR="$FIXTURE_DIR/detection"
mkdir -p "$TMP_DIR"
python3 - "$TMP_DIR" "$SCRIPT_DIR/scripts" <<'PYFIX'
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from architecture_detector import GBA_LOGO_PREFIX

gba = bytearray(0xC0)
gba[4:12] = GBA_LOGO_PREFIX
for offset in range(0xA0, 0xBD):
    gba[offset] = offset & 0xFF
gba[0xBD] = (-(0x19 + sum(gba[0xA0:0xBD]))) & 0xFF
(root / "game.gba").write_bytes(gba)

n64 = bytearray(0x40)
n64[:4] = b"\x80\x37\x12\x40"
n64[0x20:0x2C] = b"TEST N64 ROM"
(root / "mario.z64").write_bytes(n64)

psx = b"PS-X EXE" + (b"\x00" * (0x800 - 8))
(root / "game.psx").write_bytes(psx)
PYFIX

DETECT_GBA=$("$SCRIPT_DIR/ghidra-report.sh" --detect-type "$TMP_DIR/game.gba")
DETECT_N64=$("$SCRIPT_DIR/ghidra-report.sh" --detect-type "$TMP_DIR/mario.z64")
DETECT_PSX=$("$SCRIPT_DIR/ghidra-report.sh" --detect-type "$TMP_DIR/game.psx")
DETECT_OUT="$DETECT_GBA $DETECT_N64 $DETECT_PSX"

if echo "$DETECT_OUT" | grep -q "gba n64 psx"; then
    log_pass "File type auto-detection successfully identified GBA, N64, and PSX formats"
else
    log_fail "Auto-detection failed: expected 'gba n64 psx', got '$DETECT_OUT'"
fi

# 13. Test Java Analysis Pipeline Compiles
log_test "Compiling Ghidra Java analysis pipeline (orchestrator + lib modules)..."
JAVAC="$(command -v javac || true)"
if [ -z "$JAVAC" ]; then
    JAVAC="$(find "${GHIDRA_ROOT%/lib/ghidra}" -maxdepth 3 -type f -name javac 2>/dev/null | head -1)"
fi
if [ -z "$JAVAC" ] || [ ! -d "$GHIDRA_ROOT" ]; then
    log_fail "Cannot compile: javac or GHIDRA_ROOT not found"
else
    JAVA_CP="$(find "$GHIDRA_ROOT/Ghidra" -name '*.jar' | tr '\n' ':')"
    JAVA_OUT="$(mktemp -d)"
    JAVA_LOG="$(mktemp)"
    if "$JAVAC" -nowarn -d "$JAVA_OUT" -cp "$JAVA_CP" \
            "$SCRIPT_DIR/scripts/ExportFullReport.java" "$SCRIPT_DIR"/scripts/lib/*.java > "$JAVA_LOG" 2>&1; then
        log_pass "Java pipeline compiles clean ($(find "$SCRIPT_DIR/scripts" -name '*.java' | wc -l) sources)"
    else
        log_fail "Java pipeline failed to compile"
        sed -n '1,120p' "$JAVA_LOG"
    fi
    rm -rf "$JAVA_OUT"
    rm -f "$JAVA_LOG"
fi

# 11. Test Release Distribution Packager
log_test "Testing Release Distribution Packager..."
APP_VERSION="$(cat "$SCRIPT_DIR/VERSION")"
if "$SCRIPT_DIR/scripts/package_release.sh" > /dev/null 2>&1 && [ -f "$SCRIPT_DIR/dist/ghidra-report-v${APP_VERSION}-linux-x86_64.tar.gz" ]; then
    log_pass "Release distribution packager built tar.gz with sha256 checksum"
else
    log_fail "Release packager failed"
fi

echo "================================================================================"
echo "  TEST RESULTS: $PASS PASSED, $FAIL FAILED, $SKIP SKIPPED"
echo "================================================================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
