#!/usr/bin/env bash
# scripts/package_release.sh — Build standalone release distribution tarballs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="0.2.0"
DIST_DIR="$SCRIPT_DIR/dist"
ARCHIVE_NAME="ghidra-report-v${VERSION}-linux-x86_64"
TARGET_TAR="$DIST_DIR/${ARCHIVE_NAME}.tar.gz"

mkdir -p "$DIST_DIR"
TMP_STAGE="$(mktemp -d)"
STAGE_DIR="$TMP_STAGE/ghidra-report"
mkdir -p "$STAGE_DIR"

cp -r "$SCRIPT_DIR/ghidra-report.sh" \
      "$SCRIPT_DIR/run-headless.sh" \
      "$SCRIPT_DIR/ghidra-report.1" \
      "$SCRIPT_DIR/README.md" \
      "$SCRIPT_DIR/LICENSE" \
      "$SCRIPT_DIR/scripts" \
      "$SCRIPT_DIR/rules" \
      "$SCRIPT_DIR/docs" \
      "$SCRIPT_DIR/tests" \
      "$STAGE_DIR/"

# Never ship build artifacts or interpreter caches
find "$STAGE_DIR" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$STAGE_DIR" -type f \( -name '*.pyc' -o -name '*.class' \) -delete

mkdir -p "$STAGE_DIR/ingress" "$STAGE_DIR/output" "$STAGE_DIR/projects"
touch "$STAGE_DIR/ingress/.gitkeep" "$STAGE_DIR/output/.gitkeep"

tar -czf "$TARGET_TAR" -C "$TMP_STAGE" ghidra-report
rm -rf "$TMP_STAGE"

sha256sum "$TARGET_TAR" > "${TARGET_TAR}.sha256"
echo "[+] Built release tarball: $TARGET_TAR ($(du -h "$TARGET_TAR" | cut -f1))"
echo "[+] SHA256: $(cat "${TARGET_TAR}.sha256")"
