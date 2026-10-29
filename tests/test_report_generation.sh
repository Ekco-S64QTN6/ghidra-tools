#!/usr/bin/env bash
# Exercises the real generate_report() function with a mock headless executable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/headless_log.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}
pass() {
    echo "[PASS] $*"
}

# Extract only the function under test so sourcing the CLI does not parse args
# or start a real Ghidra job.
python3 - "$SCRIPT_DIR/ghidra-report.sh" "$TMP_DIR/generate_report_function.sh" <<'PY'
import sys
source_path, output_path = sys.argv[1:]
with open(source_path, encoding="utf-8") as handle:
    source = handle.read()
start = source.find("generate_report() {")
end = source.find("\n# Process a single binary", start)
if start < 0 or end < 0:
    raise SystemExit("could not isolate generate_report()")
with open(output_path, "w", encoding="utf-8") as handle:
    handle.write(source[start:end] + "\n")
PY
source "$TMP_DIR/generate_report_function.sh"

log_step() { :; }
log_success() { printf '[SUCCESS] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*"; }

RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
OUTPUT_DIR="$TMP_DIR/output"
PROJECTS_DIR="$TMP_DIR/projects"
SCRIPTS_DIR="$TMP_DIR/scripts"
mkdir -p "$PROJECTS_DIR" "$SCRIPTS_DIR"
cp "$SCRIPT_DIR/scripts/atomic_publish.py" "$SCRIPTS_DIR/atomic_publish.py"
FORMAT=all
FULL_DISASM=false
WEBHOOK_URL=''
HEADLESS="$TMP_DIR/mock-headless"

cat > "$HEADLESS" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
report_base=''
format=''
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-postScript" ]]; then
        shift
        [[ "${1:-}" == "ExportFullReport.java" ]] || exit 91
        report_base="${2:?missing report base}"
        format="${3:?missing format}"
        break
    fi
    shift
done
[[ -n "$report_base" ]] || exit 92

case "${MOCK_REPORT_MODE:-success}" in
    fail)
        printf 'Report written: partial report at %s.json\n' "$report_base"
        touch "${report_base}.txt" "${report_base}.json"
        printf 'Script export terminated after partial output\n'
        exit "${MOCK_REPORT_STATUS:-37}"
        ;;
    html)
        printf 'Report written: %s.html\n' "$report_base"
        printf '<html>synthetic</html>\n' > "${report_base}.html"
        ;;
    success)
        printf 'Report written: %s.json\n' "$report_base"
        printf 'rule: synthetic export rule\n'
        printf 'THREAT TRIAGE SUMMARY\nFunctions identified: 7\nLanguage: x86:LE:32:default\nEstimated code coverage: 25%%\n' > "${report_base}.txt"
        printf '{"file":"synthetic.bin"}\n' > "${report_base}.json"
        touch "${report_base}.md" "${report_base}.sarif" "${report_base}.yar" "${report_base}.misp.json"
        ;;
    *)
        exit 93
        ;;
esac
MOCK
chmod +x "$HEADLESS"

# A failed export emits partial files and exits 37. It must return 37, remove
# those partial artifacts, and keep the previous successful latest symlink.
FAIL_DIR="$OUTPUT_DIR/fail-key"
mkdir -p "$FAIL_DIR"
printf '{"file":"previous"}\n' > "$FAIL_DIR/previous.json"
ln -s previous.json "$FAIL_DIR/report_latest.json"

if MOCK_REPORT_MODE=fail MOCK_REPORT_STATUS=37 generate_report "project-fail" "failed.bin" "fail-key" > "$TMP_DIR/failure-visible.log" 2>&1; then
    fail "report generation unexpectedly succeeded after mock exit 37"
else
    status=$?
fi
[[ "$status" -eq 37 ]] || fail "expected exit 37 from report generation, got $status"
grep -Fq "Ghidra report generation failed with exit status 37" "$TMP_DIR/failure-visible.log" || fail "failure diagnostic missing"
[[ "$(readlink "$FAIL_DIR/report_latest.json")" == "previous.json" ]] || fail "failed export changed the previous latest symlink"
if find "$FAIL_DIR" -maxdepth 1 -name '*_report_*' -type f | grep -q .; then
    fail "partial per-run report artifacts were left behind"
fi
if find "$FAIL_DIR" -maxdepth 1 -name '.stage.*' -type d | grep -q .; then
    fail "failed-export staging directory was left behind"
fi
pass "failed report export propagates status, cleans partial files, and preserves latest"

# A successful HTML-only export is valid even though TXT/JSON are not requested.
HTML_DIR="$OUTPUT_DIR/html-key"
mkdir -p "$HTML_DIR"
if MOCK_REPORT_MODE=html FORMAT=html generate_report "project-html" "html-only.bin" "html-key" > "$TMP_DIR/html-visible.log" 2>&1; then
    status=0
else
    status=$?
fi
[[ "$status" -eq 0 ]] || fail "HTML-only export returned $status"
[[ -L "$HTML_DIR/report_latest.html" ]] || fail "HTML-only report did not publish report_latest.html"
[[ -f "$HTML_DIR/$(readlink "$HTML_DIR/report_latest.html")" ]] || fail "HTML latest symlink target missing"
grep -Fq "Report written:" "$TMP_DIR/html-visible.log" || fail "report filter did not display the Report written line"
pass "HTML-only export succeeds and report-specific log lines remain visible"

# Guard the actual integration point so a future refactor cannot silently put
# generate_report() back on an unchecked tee pipeline.
grep -Fq 'run_headless_logged "$report_log" report' "$SCRIPT_DIR/ghidra-report.sh" || fail "generate_report() no longer uses status-preserving report mode"
pass "generate_report() is wired to the status-preserving report filter"
grep -Fq 'atomic_publish.py" symlink' "$SCRIPT_DIR/ghidra-report.sh" || fail "latest-link publication is not using the atomic publisher"
pass "report_latest.* links use the atomic publisher"
