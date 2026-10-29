#!/usr/bin/env python3
"""Guard version references against the canonical root VERSION file.

The formula checksums intentionally remain placeholders until a release asset
exists; this test reports that status rather than pretending the package path is
ready to publish.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    version = read("VERSION").strip()
    require(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None,
            f"VERSION must be a semantic x.y.z version, got {version!r}")

    cli = read("ghidra-report.sh")
    require('tr -d' in cli and '< "$SCRIPT_DIR/VERSION"' in cli,
            "CLI must read its banner version from VERSION")
    require(r'ghidra-report v${APP_VERSION}' in cli,
            "CLI banner must interpolate APP_VERSION, not hardcode a release version")

    launcher = read("run-headless.sh")
    require('< "$SCRIPT_DIR/VERSION"' in launcher,
            "headless launcher must read the canonical VERSION")
    require("export GHIDRA_REPORT_VERSION" in launcher,
            "headless launcher must export the version to Ghidra Java scripts")

    release = read("scripts/package_release.sh")
    require('< "$SCRIPT_DIR/VERSION"' in release,
            "release tarball builder must read the canonical VERSION")
    require('ghidra-report-v${VERSION}-linux-x86_64' in release,
            "release tarball name must interpolate the canonical VERSION")
    require('"$SCRIPT_DIR/VERSION"' in release,
            "release tarball must include VERSION")
    require(r"^[0-9]+\.[0-9]+\.[0-9]+$" in release,
            "release script must validate VERSION")

    sarif = read("scripts/lib/SarifExporter.java")
    require('System.getenv("GHIDRA_REPORT_VERSION")' in sarif,
            "SARIF driver must consume GHIDRA_REPORT_VERSION")
    require("0.2.0" not in sarif,
            "SARIF driver must not hardcode the previous release")
    require("https://github.com/Ekco-S64QTN6/ghidra-tools" in sarif,
            "SARIF driver information URIs must point at the actual project")

    man = read("ghidra-report.1")
    require(f"ghidra-report v{version}" in man,
            "man-page header version has drifted from VERSION")

    readme = read("README.md")
    require("ghidra-report-v${APP_VERSION}-linux-x86_64.tar.gz" in readme,
            "README package example must use the canonical version variable")
    require("release tags/assets have not been published" in readme,
            "README must describe the pending release/checksum limitation")

    formula = read("packaging/ghidra-report.rb")
    require('homepage "https://github.com/Ekco-S64QTN6/ghidra-tools"' in formula,
            "Homebrew homepage must reference the real repository")
    require("archive/refs/tags/v#{version}.tar.gz" in formula,
            "Homebrew source URL must interpolate Formula version")
    require('depends_on "openjdk@25"' in formula,
            "Homebrew Java dependency must match the Ghidra 12.2 target")
    require('assert_match "ghidra-report v#{version}"' in formula,
            "Homebrew test must use its declared Formula version")

    aur = read("packaging/PKGBUILD")
    pkgver_match = re.search(r"(?m)^pkgver=([0-9]+\.[0-9]+\.[0-9]+)$", aur)
    require(pkgver_match is not None and pkgver_match.group(1) == version,
            "PKGBUILD pkgver must match VERSION")
    require('url="https://github.com/Ekco-S64QTN6/ghidra-tools"' in aur,
            "PKGBUILD URL must reference the real repository")
    require("java-runtime>=25" in aur,
            "PKGBUILD Java dependency must match the Ghidra 12.2 target")
    require("archive/refs/tags/v${pkgver}.tar.gz" in aur,
            "PKGBUILD source must use the repository tag URL")

    full_suite = read("tests/run_tests.sh")
    require('cat "$SCRIPT_DIR/VERSION"' in full_suite,
            "full integration suite must compare CLI/package output to VERSION")
    workflow = read(".github/workflows/binary-analysis.yml")
    require('cat VERSION' in workflow and 'ghidra-report-v${version}-linux-x86_64.tar.gz' in workflow,
            "CI package smoke must derive its expected archive name from VERSION")
    require("python3 tests/test_version_consistency.py" in workflow,
            "version consistency test must run in CI")

    # A checksum cannot be invented before a release asset exists. Enforce that
    # the pending status remains explicit until release publication is real.
    if 'sha256 "SKIP"' in formula or "sha256sums=('SKIP')" in aur:
        require("Release tag/checksum not published yet" in formula,
                "Homebrew checksum placeholder must be explicitly documented as pending")
        require("Release tag/checksum not published yet" in aur,
                "AUR checksum placeholder must be explicitly documented as pending")
    print(f"[PASS] application version {version} is consistent across CLI, SARIF, package metadata, docs, and CI")
    if 'sha256 "SKIP"' in formula or "sha256sums=('SKIP')" in aur:
        print("[INFO] Homebrew/AUR checksums are intentionally pending publication of a real release asset")


if __name__ == "__main__":
    main()
