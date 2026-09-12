#!/usr/bin/env bash
# Wrapper to run Ghidra's analyzeHeadless outside the Flatpak sandbox.
#
# The Flatpak install has a broken symlink for launch.properties that only
# resolves inside the sandbox. We bypass launch.sh entirely and invoke the
# JVM directly with the correct classpath and classloader.

set -euo pipefail

GHIDRA_ROOT="/var/lib/flatpak/app/org.ghidra_sre.Ghidra/x86_64/stable/active/files/lib/ghidra"
JAVA_HOME="/var/lib/flatpak/app/org.ghidra_sre.Ghidra/x86_64/stable/active/files/jdk"

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"
export INSTALL_DIR="$GHIDRA_ROOT"

CPATH="$GHIDRA_ROOT/Ghidra/Framework/Utility/lib/Utility.jar"
MAXMEM="${GHIDRA_HEADLESS_MAXMEM:-2G}"

exec java \
    -Xmx"$MAXMEM" \
    -Djava.system.class.loader=ghidra.GhidraClassLoader \
    -Djava.awt.headless=true \
    -XX:ParallelGCThreads=2 \
    -XX:CICompilerCount=2 \
    -Xshare:off \
    --enable-native-access=ALL-UNNAMED \
    -Dpython.console.encoding=UTF-8 \
    -cp "$CPATH" \
    ghidra.GhidraLauncher \
    ghidra.app.util.headless.AnalyzeHeadless \
    "$@"
