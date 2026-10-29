#!/usr/bin/env bash
# Verifies headless command failures survive tee/filtering.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
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

# A successful command logs every line to the file but only selected lines to
# the interactive stream.
if run_headless_logged "$TMP_DIR/success.log" import bash -c '
    printf "INFO Loaded synthetic program\n"
    printf "debug detail remains in the log\n"
    printf "WARN synthetic warning\n" >&2
' >"$TMP_DIR/visible.log"; then
    status=0
else
    status=$?
fi
[[ "$status" -eq 0 ]] || fail "successful command returned $status"
grep -Fq "INFO Loaded synthetic program" "$TMP_DIR/success.log" || fail "complete log omitted INFO line"
grep -Fq "debug detail remains in the log" "$TMP_DIR/success.log" || fail "complete log omitted filtered line"
grep -Fq "WARN synthetic warning" "$TMP_DIR/success.log" || fail "complete log omitted stderr"
grep -Fq "INFO Loaded synthetic program" "$TMP_DIR/visible.log" || fail "INFO line was not displayed"
grep -Fq "WARN synthetic warning" "$TMP_DIR/visible.log" || fail "WARN line was not displayed"
if grep -Fq "debug detail remains in the log" "$TMP_DIR/visible.log"; then
    fail "unfiltered debug line was displayed"
fi
pass "successful command retains full log while filtering console output"

# A command that exits nonzero without emitting known error keywords must still
# return its original status through tee and the filter loop.
if run_headless_logged "$TMP_DIR/failure.log" import bash -c '
    printf "generic analyzer termination without an ERROR marker\n"
    exit 37
' >"$TMP_DIR/failure-visible.log"; then
    fail "failed command unexpectedly succeeded"
else
    status=$?
fi
[[ "$status" -eq 37 ]] || fail "expected command exit 37, got $status"
grep -Fq "generic analyzer termination without an ERROR marker" "$TMP_DIR/failure.log" || fail "failed command output missing from log"
pass "nonzero analyzer exit propagates even without error text"

# Validate filter mode up front even if the command emits no lines.
if run_headless_logged "$TMP_DIR/bad.log" unknown bash -c 'exit 0' 2>"$TMP_DIR/bad.err"; then
    fail "unknown filter mode unexpectedly succeeded"
else
    status=$?
fi
[[ "$status" -eq 2 ]] || fail "expected invalid filter exit 2, got $status"
grep -Fq "Unknown headless log filter mode" "$TMP_DIR/bad.err" || fail "invalid-filter diagnostic missing"
pass "invalid filter mode fails before command execution"
