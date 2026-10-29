#!/usr/bin/env bash
# Verify output lock exclusivity, release, and fail-closed timeout behavior.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { echo "[FAIL] $*" >&2; exit 1; }
pass() { echo "[PASS] $*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }

source "$ROOT_DIR/scripts/output_lock.sh"
SCRIPTS_DIR="$ROOT_DIR/scripts"
OUTPUT_DIR="$TMP_DIR/output"
mkdir -p "$OUTPUT_DIR"
KEY="same_sample_a1b2c3"

if ! acquire_output_lock "$KEY"; then
    fail "first process could not acquire an uncontended lock"
fi

# A second process using the same identity must wait until the first releases.
(
    source "$ROOT_DIR/scripts/output_lock.sh"
    SCRIPTS_DIR="$ROOT_DIR/scripts"
    OUTPUT_DIR="$TMP_DIR/output"
    : > "$TMP_DIR/second-started"
    if acquire_output_lock "$KEY"; then
        : > "$TMP_DIR/second-acquired"
        release_output_lock
    else
        exit 20
    fi
) >"$TMP_DIR/second.stdout" 2>"$TMP_DIR/second.stderr" &
second_pid=$!

for _ in $(seq 1 100); do
    [[ -f "$TMP_DIR/second-started" ]] && break
    sleep 0.02
done
[[ -f "$TMP_DIR/second-started" ]] || fail "second process did not start"
sleep 0.25
[[ ! -f "$TMP_DIR/second-acquired" ]] || fail "same-identity second process entered concurrently"

release_output_lock
if ! wait "$second_pid"; then
    fail "second process did not acquire the lock after release"
fi
[[ -f "$TMP_DIR/second-acquired" ]] || fail "second process never acquired the released lock"
pass "same-output runs serialize and the lock releases for the next process"

# Hold it again and verify a short timeout fails instead of proceeding unlocked.
if ! acquire_output_lock "$KEY"; then
    fail "could not reacquire the released lock"
fi
(
    source "$ROOT_DIR/scripts/output_lock.sh"
    SCRIPTS_DIR="$ROOT_DIR/scripts"
    OUTPUT_DIR="$TMP_DIR/output"
    GHIDRA_OUTPUT_LOCK_TIMEOUT=1
    export GHIDRA_OUTPUT_LOCK_TIMEOUT
    if acquire_output_lock "$KEY"; then
        release_output_lock
        exit 30
    fi
    exit 0
) >"$TMP_DIR/timeout.stdout" 2>"$TMP_DIR/timeout.stderr" &
timeout_pid=$!
if ! wait "$timeout_pid"; then
    fail "a contender did not fail closed after its lock timeout"
fi
grep -Fq "Timed out waiting for report-output lock" "$TMP_DIR/timeout.stderr" || fail "timeout diagnostic missing"
release_output_lock
pass "lock timeout fails closed with an actionable diagnostic"
