#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/ghidra_language.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
fail() { echo "[FAIL] $*" >&2; exit 1; }
pass() { echo "[PASS] $*"; }

GHIDRA_ROOT="$TMP_DIR/ghidra"
GHIDRA_EXTENSION_ROOT="$TMP_DIR/extensions"
mkdir -p "$GHIDRA_ROOT/Ghidra/Processors/6502/data/languages" \
    "$GHIDRA_EXTENSION_ROOT/ghidra_TEST/Extensions/Example/data/languages"
printf '<language_definitions><language id="6502:LE:16:default"/></language_definitions>\n' \
    > "$GHIDRA_ROOT/Ghidra/Processors/6502/data/languages/6502.ldefs"
printf '<language_definitions><language id="65816:LE:24:snes"/></language_definitions>\n' \
    > "$GHIDRA_EXTENSION_ROOT/ghidra_TEST/Extensions/Example/data/languages/65816.ldefs"
export GHIDRA_ROOT GHIDRA_EXTENSION_ROOT

ghidra_language_available "6502:LE:16:default" || fail "core Ghidra language was not found"
ghidra_language_available "65816:LE:24:snes" || fail "extension language was not found"
if ghidra_language_available "missing:LE:1:none"; then
    fail "unknown language was reported as installed"
fi
if ghidra_language_available ""; then
    fail "empty language ID should be rejected"
else
    status=$?
    [[ "$status" -eq 2 ]] || fail "empty language ID returned $status instead of 2"
fi
pass "language lookup checks core and extension definitions and rejects missing IDs"
