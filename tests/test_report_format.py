#!/usr/bin/env python3
"""Compile the real Java escaper and round-trip adversarial strings with json.loads."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FORMAT_SOURCE = ROOT / "scripts" / "lib" / "ReportFormat.java"
PROBE_SOURCE = ROOT / "tests" / "java" / "ReportFormatEscapeProbe.java"


def main():
    javac = shutil.which("javac")
    java = shutil.which("java")
    if not javac or not java:
        raise SystemExit("javac and java are required for the ReportFormat escaping regression")

    with tempfile.TemporaryDirectory(prefix="report-format-escape-") as temporary:
        output_dir = Path(temporary)
        subprocess.run(
            [javac, "-encoding", "UTF-8", "-d", str(output_dir), str(FORMAT_SOURCE), str(PROBE_SOURCE)],
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run(
            [java, "-cp", str(output_dir), "ReportFormatEscapeProbe"],
            check=True,
            capture_output=True,
            text=True,
        )

    expected = "".join(chr(value) for value in range(0x20))
    expected += ' Quote:" Backslash:\\ Unicode:雪 Ω 😀 Markup:<script>&</script>'
    payload = json.loads(result.stdout)
    if payload.get("value") != expected:
        raise AssertionError("JSON parser round-trip changed control characters or Unicode content")

    encoded_line = result.stdout.rstrip("\n")
    if any(ord(character) < 0x20 for character in encoded_line):
        raise AssertionError("escaped JSON contains a raw control character")
    if "\\u0000" not in encoded_line or "\\u001f" not in encoded_line:
        raise AssertionError("the least and greatest unmapped control characters should use Unicode escapes")

    print("[PASS] production Java JSON escaper round-trips all U+0000–U+001F controls, quote/backslash, Unicode, and markup")


if __name__ == "__main__":
    main()
