#!/usr/bin/env bash
# Run Ghidra's headless analyzer for a selected installation.
#
# Standard installs use Ghidra's supported support/analyzeHeadless launcher.
# Flatpak installs keep the direct-JVM workaround because launch.sh may resolve
# launch.properties differently inside and outside the sandbox.

set -euo pipefail

GHIDRA_ROOT="${GHIDRA_ROOT:-}"
if [[ -z "$GHIDRA_ROOT" || ! -d "$GHIDRA_ROOT" ]]; then
    GHIDRA_ROOT=""
    for candidate in \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/x86_64/stable/active/files/lib/ghidra" \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra" \
        "/opt/ghidra" \
        "/usr/share/ghidra"; do
        if [[ -d "$candidate" ]]; then
            GHIDRA_ROOT="$candidate"
            break
        fi
    done
fi

if [[ -z "$GHIDRA_ROOT" || ! -d "$GHIDRA_ROOT" ]]; then
    echo "[ERROR] Ghidra installation not found. Set GHIDRA_ROOT to the Ghidra install directory." >&2
    exit 1
fi
export GHIDRA_ROOT

FLATPAK_MODE=false
FLATPAK_FILES_ROOT=""
if [[ "$GHIDRA_ROOT" == */files/lib/ghidra ]]; then
    FLATPAK_MODE=true
    FLATPAK_FILES_ROOT="${GHIDRA_ROOT%/lib/ghidra}"
    if [[ -z "${JAVA_HOME:-}" && -x "$FLATPAK_FILES_ROOT/jdk/bin/java" ]]; then
        JAVA_HOME="$FLATPAK_FILES_ROOT/jdk"
    fi
fi

if [[ -n "${JAVA_HOME:-}" ]]; then
    if [[ ! -x "$JAVA_HOME/bin/java" ]]; then
        echo "[ERROR] JAVA_HOME is set but java is not executable at: $JAVA_HOME/bin/java" >&2
        exit 1
    fi
    export JAVA_HOME
    export PATH="$JAVA_HOME/bin:$PATH"
elif ! command -v java >/dev/null 2>&1; then
    echo "[ERROR] Java was not found on PATH. Install the supported JDK or set JAVA_HOME." >&2
    exit 1
fi

# Report the runtime selected by this launcher. This is diagnostic rather than
# a loose version gate: compatibility also depends on extensions and processors.
JAVA_BIN="$(command -v java)"
JAVA_VERSION_OUTPUT="$("$JAVA_BIN" -version 2>&1)" || {
    echo "[ERROR] Could not query the selected Java runtime: $JAVA_BIN" >&2
    exit 1
}
JAVA_VERSION_LINE="${JAVA_VERSION_OUTPUT%%
    # The Flatpak launch.sh wrapper can fail outside the sandbox. Derive the
    # bundled JDK from the detected installation instead of hard-coding a host.
    UTILITY_JAR="$GHIDRA_ROOT/Ghidra/Framework/Utility/lib/Utility.jar"
    if [[ ! -f "$UTILITY_JAR" ]]; then
        echo "[ERROR] Flatpak Ghidra Utility.jar was not found: $UTILITY_JAR" >&2
        exit 1
    fi

    JAVA_BIN="$(command -v java)"
    MAXMEM="${GHIDRA_HEADLESS_MAXMEM:-2G}"
    export INSTALL_DIR="$GHIDRA_ROOT"

    exec "$JAVA_BIN" \
        -Xmx"$MAXMEM" \
        -Djava.system.class.loader=ghidra.GhidraClassLoader \
        -Djava.awt.headless=true \
        -XX:ParallelGCThreads=2 \
        -XX:CICompilerCount=2 \
        -Xshare:off \
        --enable-native-access=ALL-UNNAMED \
        -Dpython.console.encoding=UTF-8 \
        -cp "$UTILITY_JAR" \
        ghidra.GhidraLauncher \
        ghidra.app.util.headless.AnalyzeHeadless \
        "$@"
fi

HEADLESS_LAUNCHER="$GHIDRA_ROOT/support/analyzeHeadless"
if [[ ! -x "$HEADLESS_LAUNCHER" ]]; then
    echo "[ERROR] Ghidra headless launcher is not executable: $HEADLESS_LAUNCHER" >&2
    echo "        Set GHIDRA_ROOT to a supported Ghidra installation directory." >&2
    exit 1
fi

exec "$HEADLESS_LAUNCHER" "$@"
\\n'*}"
GHIDRA_VERSION=""
for properties_path in "$GHIDRA_ROOT/Ghidra/application.properties" "$GHIDRA_ROOT/application.properties"; do
    if [[ -r "$properties_path" ]]; then
        GHIDRA_VERSION="$(awk -F= '/^[[:space:]]*application\\.version[[:space:]]*=/ { sub(/^[^=]*=/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' "$properties_path")"
        if [[ -n "$GHIDRA_VERSION" ]]; then
            break
        fi
    fi
done
echo "[INFO] Ghidra root: $GHIDRA_ROOT"
echo "[INFO] Ghidra version: ${GHIDRA_VERSION:-unknown (version metadata missing)}"
echo "[INFO] Java runtime: $JAVA_VERSION_LINE"

if [[ "$FLATPAK_MODE" == true ]]; then
    # The Flatpak launch.sh wrapper can fail outside the sandbox. Derive the
    # bundled JDK from the detected installation instead of hard-coding a host.
    UTILITY_JAR="$GHIDRA_ROOT/Ghidra/Framework/Utility/lib/Utility.jar"
    if [[ ! -f "$UTILITY_JAR" ]]; then
        echo "[ERROR] Flatpak Ghidra Utility.jar was not found: $UTILITY_JAR" >&2
        exit 1
    fi

    JAVA_BIN="$(command -v java)"
    MAXMEM="${GHIDRA_HEADLESS_MAXMEM:-2G}"
    export INSTALL_DIR="$GHIDRA_ROOT"

    exec "$JAVA_BIN" \
        -Xmx"$MAXMEM" \
        -Djava.system.class.loader=ghidra.GhidraClassLoader \
        -Djava.awt.headless=true \
        -XX:ParallelGCThreads=2 \
        -XX:CICompilerCount=2 \
        -Xshare:off \
        --enable-native-access=ALL-UNNAMED \
        -Dpython.console.encoding=UTF-8 \
        -cp "$UTILITY_JAR" \
        ghidra.GhidraLauncher \
        ghidra.app.util.headless.AnalyzeHeadless \
        "$@"
fi

HEADLESS_LAUNCHER="$GHIDRA_ROOT/support/analyzeHeadless"
if [[ ! -x "$HEADLESS_LAUNCHER" ]]; then
    echo "[ERROR] Ghidra headless launcher is not executable: $HEADLESS_LAUNCHER" >&2
    echo "        Set GHIDRA_ROOT to a supported Ghidra installation directory." >&2
    exit 1
fi

exec "$HEADLESS_LAUNCHER" "$@"
