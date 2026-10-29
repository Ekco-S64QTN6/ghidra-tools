#!/usr/bin/env bash
# Tests scripts/batch_runner.sh with synthetic workers; no Ghidra install needed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/batch_runner.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
BATCH_RUN_LOG="$TMP_DIR/worker.log"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}
pass() {
    echo "[PASS] $*"
}

synthetic_worker() {
    local item="$1"
    printf '%s\n' "$item" >> "$BATCH_RUN_LOG"
    [[ "$item" != *fail* ]]
}

# A failed item must not prevent later items from being attempted, and counts
# must reflect every worker's exit status.
if run_batch_workers 2 synthetic_worker "ok one.bin" "fail two.bin" "ok three.bin"; then
    fail "mixed-result batch unexpectedly succeeded"
fi
[[ "$BATCH_TOTAL_COUNT" -eq 3 ]] || fail "expected three total items"
[[ "$BATCH_SUCCESS_COUNT" -eq 2 ]] || fail "expected two successful items"
[[ "$BATCH_FAILURE_COUNT" -eq 1 ]] || fail "expected one failed item"
[[ "$(wc -l < "$BATCH_RUN_LOG")" -eq 3 ]] || fail "a later item was not attempted after a failure"
grep -Fqx "ok one.bin" "$BATCH_RUN_LOG" || fail "first item did not run"
grep -Fqx "fail two.bin" "$BATCH_RUN_LOG" || fail "failing item did not run"
grep -Fqx "ok three.bin" "$BATCH_RUN_LOG" || fail "last item did not run"
pass "mixed results are counted and remaining batch items still run"

# A clean batch should report zero failures.
: > "$BATCH_RUN_LOG"
if ! run_batch_workers 2 synthetic_worker "alpha.bin" "beta.bin"; then
    fail "all-success batch unexpectedly failed"
fi
[[ "$BATCH_TOTAL_COUNT" -eq 2 && "$BATCH_SUCCESS_COUNT" -eq 2 && "$BATCH_FAILURE_COUNT" -eq 0 ]] || fail "successful counts were incorrect"
pass "successful batch returns zero and reports counts"

# Invalid worker counts fail before invoking the worker.
before="$(wc -l < "$BATCH_RUN_LOG")"
if run_batch_workers 0 synthetic_worker "should-not-run.bin" 2>"$TMP_DIR/invalid.err"; then
    fail "zero worker count unexpectedly succeeded"
fi
grep -Fq "must be a positive integer" "$TMP_DIR/invalid.err" || fail "invalid worker-count diagnostic missing"
[[ "$(wc -l < "$BATCH_RUN_LOG")" -eq "$before" ]] || fail "worker ran despite invalid worker count"
pass "invalid worker count fails closed"
