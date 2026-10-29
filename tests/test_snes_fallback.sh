#!/usr/bin/env bash
# Exercise the real import_and_analyze() decision path with a mocked headless runner.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { echo "[FAIL] $*" >&2; exit 1; }
pass() { echo "[PASS] $*"; }
log_step() { :; }
log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
log_success() { printf '[SUCCESS] %s\n' "$*"; }

python3 "$SCRIPT_DIR/tests/make_fixtures.py" "$TMP_DIR/fixtures" >/dev/null
SNES_FIXTURE="$TMP_DIR/fixtures/console_sample.sfc"
[[ -s "$SNES_FIXTURE" ]] || fail "synthetic SNES fixture was not generated"

# Source only the function under test; do not parse CLI options or launch Ghidra.
python3 - "$SCRIPT_DIR/ghidra-report.sh" "$TMP_DIR/import_function.sh" <<'PY'
import sys
source_path, output_path = sys.argv[1:]
source = open(source_path, encoding="utf-8").read()
start = source.find("import_and_analyze() {")
end = source.find("\n# Generate reports from an existing Ghidra project", start)
if start < 0 or end < 0:
    raise SystemExit("could not isolate import_and_analyze()")
with open(output_path, "w", encoding="utf-8") as handle:
    handle.write(source[start:end] + "\n")
PY
source "$TMP_DIR/import_function.sh"

SCRIPTS_DIR="$SCRIPT_DIR/scripts"
PROJECTS_DIR="$TMP_DIR/projects"
HEADLESS="$TMP_DIR/mock-headless"
RUN_FINDCRYPT=false
BOLD='' NC=''
mkdir -p "$PROJECTS_DIR"
: > "$TMP_DIR/calls"
: > "$TMP_DIR/args"
CALL_LOG="$TMP_DIR/calls"
ARG_LOG="$TMP_DIR/args"

detect_file_type() { printf 'snes\n'; }

run_headless_logged() {
    local log_path="$1"
    local mode="$2"
    shift 2
    printf '%s\n' "$mode" >> "$CALL_LOG"
    printf '%s\n' "$@" >> "$ARG_LOG"
    case "$mode" in
        import)
            if [[ "${MOCK_IMPORT_LOG_MODE:-generic}" == diagnostic ]]; then
                printf 'Import failed for optional loader\n' > "$log_path"
            else
                printf 'Loader backend terminated without a standard diagnostic\n' > "$log_path"
            fi
            return "${MOCK_IMPORT_STATUS:-41}"
            ;;
        fallback)
            printf 'Raw import selected with 65816\n' > "$log_path"
            return "${MOCK_FALLBACK_STATUS:-0}"
            ;;
        *)
            return 90
            ;;
    esac
}

# A failed SNES loader that exits nonzero without a known error phrase still
# must trigger the raw 65816 fallback.
if MOCK_IMPORT_STATUS=41 MOCK_IMPORT_LOG_MODE=generic MOCK_FALLBACK_STATUS=0 \
    import_and_analyze "$SNES_FIXTURE" "snes-status-fallback" >"$TMP_DIR/generic.log" 2>&1; then
    status=0
else
    status=$?
fi
[[ "$status" -eq 0 ]] || fail "generic SNES loader failure did not recover (status $status)"
[[ "$(sed -n '1p' "$CALL_LOG")" == import ]] || fail "first headless call was not the extension loader"
[[ "$(sed -n '2p' "$CALL_LOG")" == fallback ]] || fail "failed SNES loader without diagnostic did not trigger raw fallback"
grep -Fq -- "-processor" "$ARG_LOG" || fail "raw fallback did not pass an explicit processor"
grep -Fq "65816:LE:24:snes" "$ARG_LOG" || fail "raw fallback used the wrong processor"
grep -Fq "Falling back to raw import with 65816 processor" "$TMP_DIR/generic.log" || fail "fallback diagnostic was not shown"
pass "nonzero loader failure falls back even without a recognized diagnostic"

# Preserve support for Ghidra builds that report a loader rejection in text but
# return a zero exit code.
: > "$CALL_LOG"
: > "$ARG_LOG"
if MOCK_IMPORT_STATUS=0 MOCK_IMPORT_LOG_MODE=diagnostic MOCK_FALLBACK_STATUS=0 \
    import_and_analyze "$SNES_FIXTURE" "snes-text-fallback" >"$TMP_DIR/diagnostic.log" 2>&1; then
    status=0
else
    status=$?
fi
[[ "$status" -eq 0 ]] || fail "diagnostic-only SNES loader rejection did not recover (status $status)"
[[ "$(sed -n '1p' "$CALL_LOG")" == import && "$(sed -n '2p' "$CALL_LOG")" == fallback ]] || fail "diagnostic-only loader rejection did not trigger fallback"
pass "diagnostic-only loader rejection retains the fallback path"

# Failure of the raw processor import must not be converted into success.
: > "$CALL_LOG"
if MOCK_IMPORT_STATUS=41 MOCK_IMPORT_LOG_MODE=generic MOCK_FALLBACK_STATUS=43 \
    import_and_analyze "$SNES_FIXTURE" "snes-fallback-failure" >"$TMP_DIR/fallback-failure.log" 2>&1; then
    fail "failed raw fallback unexpectedly succeeded"
else
    status=$?
fi
[[ "$status" -eq 43 ]] || fail "raw fallback failure status changed (expected 43, got $status)"
grep -Fq "Import failed even with raw 65816 fallback" "$TMP_DIR/fallback-failure.log" || fail "raw fallback failure diagnostic missing"
pass "raw fallback failure remains a nonzero failure"

echo "Passed SNES fallback regression groups."
