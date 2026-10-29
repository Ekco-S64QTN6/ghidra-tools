#!/usr/bin/env python3
"""Regression tests for read-only package assets and user-owned writable data."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def test_launcher():
    template = read("packaging/ghidra-report-launcher.sh.in")
    require(template.count("@APP_ROOT@") == 1, "launcher must have exactly one app-root placeholder")

    with tempfile.TemporaryDirectory(prefix="ghidra package layout ") as temp:
        root = Path(temp)
        app_root = root / "prefix" / "libexec" / "ghidra report"
        app_root.mkdir(parents=True)
        (app_root / "vendor").mkdir()
        fake_cli = app_root / "ghidra-report.sh"
        fake_cli.write_text(
            '#!/usr/bin/env bash\n'
            'set -euo pipefail\n'
            'printf "%s\\n" "$GHIDRA_REPORT_DATA_DIR" > "$CAPTURE_FILE"\n'
            'printf "PYTHONPATH:%s\\n" "$PYTHONPATH" >> "$CAPTURE_FILE"\\n'
            'printf "ARG:%s\\n" "$@" >> "$CAPTURE_FILE"\n',
            encoding="utf-8",
        )
        fake_cli.chmod(0o755)

        launcher = root / "ghidra-report"
        launcher.write_text(template.replace("@APP_ROOT@", str(app_root)), encoding="utf-8")
        launcher.chmod(0o755)

        home = root / "home with spaces"
        xdg = root / "xdg data with spaces"
        home.mkdir()
        xdg.mkdir()
        capture = root / "capture.txt"
        env = os.environ.copy()
        env.update({"HOME": str(home), "XDG_DATA_HOME": str(xdg), "CAPTURE_FILE": str(capture)})
        env.pop("GHIDRA_REPORT_DATA_DIR", None)
        subprocess.run(
            [str(launcher), "--detect-type", "file name with spaces.bin"],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        lines = capture.read_text(encoding="utf-8").splitlines()
        require(lines[0] == str(xdg / "ghidra-report"), "launcher should default to XDG user data")
        require(str(app_root / "vendor") in lines[1], "launcher should expose the private Python dependency directory")
        require(lines[2:] == ["ARG:--detect-type", "ARG:file name with spaces.bin"],
                "launcher must preserve arguments, including embedded spaces")

        custom_data = root / "custom ghidra data"
        capture.unlink()
        env["GHIDRA_REPORT_DATA_DIR"] = str(custom_data)
        subprocess.run([str(launcher), "--help"], env=env, check=True, capture_output=True, text=True)
        require(capture.read_text(encoding="utf-8").splitlines()[0] == str(custom_data),
                "explicit GHIDRA_REPORT_DATA_DIR must override the default")


def test_source_and_package_layouts():
    cli = read("ghidra-report.sh")
    require('DATA_ROOT="${GHIDRA_REPORT_DATA_DIR:-$SCRIPT_DIR}"' in cli,
            "checkout mode must default data beside the source tree")
    require('OUTPUT_DIR="${GHIDRA_REPORT_OUTPUT_DIR:-$DATA_ROOT/output}"' in cli,
            "output path should allow explicit override")
    require('export GHIDRA_REPORT_OUTPUT_DIR="$OUTPUT_DIR"' in cli,
            "output directory must be inherited by dashboard/indexer subprocesses")
    require('mkdir -p "$INGRESS_DIR" "$OUTPUT_DIR" "$PROJECTS_DIR"' in cli,
            "setup_dirs must create only writable data directories")
    require('mkdir -p "$INGRESS_DIR" "$OUTPUT_DIR" "$PROJECTS_DIR" "$SCRIPTS_DIR"' not in cli,
            "setup_dirs must never try to create a scripts directory under an installed read-only prefix")

    dashboard = read("scripts/dashboard.py")
    require('os.environ.get("GHIDRA_REPORT_OUTPUT_DIR"' in dashboard,
            "dashboard should read the configured output root")
    require('os.environ.get("GHIDRA_REPORT_DB_PATH"' in dashboard,
            "dashboard should read the configured history database path")

    indexer = read("scripts/index_report.py")
    require('os.environ.get("GHIDRA_REPORT_OUTPUT_DIR"' in indexer,
            "history indexer should read the configured output root")
    require('os.environ.get("GHIDRA_REPORT_DB_PATH"' in indexer,
            "history indexer should read the configured history database path")

    formula = read("packaging/ghidra-report.rb")
    require('libexec.install "ghidra-report.sh", "run-headless.sh", "VERSION", "requirements-rules.txt"' in formula,
            "Homebrew must colocate the CLI, launcher, version, and runtime dependency manifest")
    require('libexec.install "scripts", "rules", "schemas"' in formula,
            "Homebrew must keep support scripts/rules/schema beside the installed CLI")
    require('File.read("packaging/ghidra-report-launcher.sh.in")' in formula,
            "Homebrew must use the common package launcher template")
    require('resource "pyyaml" do' in formula and "pyyaml-6.0.3.tar.gz" in formula,
            "Homebrew must pin the YAML parser as a source resource")
    require('sha256 "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"' in formula,
            "Homebrew must verify the pinned PyYAML source digest")
    require('cp_r "lib/yaml", libexec/"vendor"' in formula,
            "Homebrew must vendor the pinned pure-Python YAML package under the app root")
    require('APP_ROOT/vendor' in read("packaging/ghidra-report-launcher.sh.in"),
            "the package launcher must add vendored Python dependencies to PYTHONPATH")
    require('pkgshare.install "scripts", "rules", "run-headless.sh"' not in formula,
            "Homebrew must not split runtime scripts away from the CLI directory")

    aur = read("packaging/PKGBUILD")
    require('app_root="$pkgdir/usr/lib/ghidra-report/app"' in aur,
            "AUR must install source assets beneath one app root")
    require('cp -r scripts rules schemas "$app_root/"' in aur,
            "AUR must colocate runtime support assets")
    require("packaging/ghidra-report-launcher.sh.in" in aur and "@APP_ROOT@" in aur,
            "AUR must generate the same data-directory-aware package launcher")
    require('install -Dm755 ghidra-report.sh "$pkgdir/usr/bin/ghidra-report"' not in aur,
            "AUR must not install the source CLI as a bare bin script with broken sibling paths")


def main():
    test_launcher()
    test_source_and_package_layouts()
    print("[PASS] package launcher preserves arguments, selects writable user data, and keeps runtime assets together")


if __name__ == "__main__":
    main()
