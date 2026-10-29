#!/usr/bin/env bash
# Regression tests for run-headless.sh. Mocks Java/Ghidra so no install is needed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS=0
fail() {
    echo "[FAIL] $*" >&2
    exit 1
}
pass() {
    echo "[PASS] $*"
    PASS=$((PASS + 1))
}

make_mock_java() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path" <<'MOCK'
#!/usr/bin/env bash
printf 'JAVA_HOME=%s\n' "${JAVA_HOME:-}" > "$CALL_LOG"
printf 'ARG=%s\n' "$@" >> "$CALL_LOG"
if [[ "${1:-}" == "-version" ]]; then
    echo 'openjdk version "25.0.1"' >&2
    exit 0
fi
MOCK
    chmod +x "$path"
}

# Standard Ghidra roots must use support/analyzeHeadless and preserve arguments.
STANDARD_ROOT="$TMP_DIR/standard-ghidra"
JAVA_ROOT="$TMP_DIR/jdk"
mkdir -p "$STANDARD_ROOT/support" "$STANDARD_ROOT/Ghidra" "$JAVA_ROOT/bin"
printf 'application.version=12.2\n' > "$STANDARD_ROOT/Ghidra/application.properties"
make_mock_java "$JAVA_ROOT/bin/java"
cat > "$STANDARD_ROOT/support/analyzeHeadless" <<'MOCK'
#!/usr/bin/env bash
printf 'JAVA_HOME=%s\n' "${JAVA_HOME:-}" > "$CALL_LOG"
printf 'ARG=%s\n' "$@" >> "$CALL_LOG"
MOCK
chmod +x "$STANDARD_ROOT/support/analyzeHeadless"

CALL_LOG="$TMP_DIR/standard.log" GHIDRA_ROOT="$STANDARD_ROOT" JAVA_HOME="$JAVA_ROOT" \
    bash "$SCRIPT_DIR/run-headless.sh" --projectName "project with spaces" -import sample.bin > "$TMP_DIR/standard.out"
grep -Fqx "JAVA_HOME=$JAVA_ROOT" "$TMP_DIR/standard.log" || fail "JAVA_HOME was not preserved for standard installs"
grep -Fqx "ARG=--projectName" "$TMP_DIR/standard.log" || fail "standard launcher did not receive the first argument"
grep -Fqx "ARG=project with spaces" "$TMP_DIR/standard.log" || fail "standard launcher did not preserve spaced arguments"
grep -Fqx "ARG=sample.bin" "$TMP_DIR/standard.log" || fail "standard launcher did not receive the final argument"
grep -Fq "[INFO] Ghidra version: 12.2" "$TMP_DIR/standard.out" || fail "Ghidra version diagnostic missing"
grep -Fq 'openjdk version "25.0.1"' "$TMP_DIR/standard.out" || fail "Java runtime diagnostic missing"
grep -Fq "[INFO] Ghidra root: $STANDARD_ROOT" "$TMP_DIR/standard.out" || fail "Ghidra root diagnostic missing"
pass "standard install honors GHIDRA_ROOT/JAVA_HOME, preserves arguments, and reports runtime versions"

# Flatpak roots must retain the direct-JVM workaround, deriving the bundled JDK.
FLATPAK_FILES="$TMP_DIR/flatpak/files"
FLATPAK_ROOT="$FLATPAK_FILES/lib/ghidra"
mkdir -p "$FLATPAK_ROOT/Ghidra/Framework/Utility/lib" "$FLATPAK_FILES/jdk/bin"
: > "$FLATPAK_ROOT/Ghidra/Framework/Utility/lib/Utility.jar"
make_mock_java "$FLATPAK_FILES/jdk/bin/java"

env -u JAVA_HOME CALL_LOG="$TMP_DIR/flatpak.log" GHIDRA_ROOT="$FLATPAK_ROOT" \
    bash "$SCRIPT_DIR/run-headless.sh" --projectName flatpak-project
grep -Fqx "JAVA_HOME=$FLATPAK_FILES/jdk" "$TMP_DIR/flatpak.log" || fail "Flatpak JDK was not derived from GHIDRA_ROOT"
grep -Fqx "ARG=-Djava.system.class.loader=ghidra.GhidraClassLoader" "$TMP_DIR/flatpak.log" || fail "Flatpak JVM workaround was not used"
grep -Fqx "ARG=ghidra.app.util.headless.AnalyzeHeadless" "$TMP_DIR/flatpak.log" || fail "Flatpak headless entry point was not passed"
grep -Fqx "ARG=flatpak-project" "$TMP_DIR/flatpak.log" || fail "Flatpak arguments were not forwarded"
pass "Flatpak root retains its derived direct-JVM path"

# Invalid explicit JAVA_HOME must fail clearly instead of launching with a bad JDK.
if CALL_LOG="$TMP_DIR/invalid.log" GHIDRA_ROOT="$STANDARD_ROOT" JAVA_HOME="$TMP_DIR/missing-jdk" \
    bash "$SCRIPT_DIR/run-headless.sh" >/dev/null 2>"$TMP_DIR/invalid.err"; then
    fail "invalid JAVA_HOME unexpectedly succeeded"
fi
grep -Fq "JAVA_HOME is set but java is not executable" "$TMP_DIR/invalid.err" || fail "invalid JAVA_HOME error was not actionable"
pass "invalid JAVA_HOME fails with a clear diagnostic"

echo "Passed $PASS headless launcher regression groups."
