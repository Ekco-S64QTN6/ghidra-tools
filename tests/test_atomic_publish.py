#!/usr/bin/env python3
"""Regression tests for per-artifact atomic latest-link replacement."""

import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from atomic_publish import replace_symlink


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    with tempfile.TemporaryDirectory(prefix="atomic-publish-") as temporary:
        root = Path(temporary)
        (root / "first.json").write_text('{"run":1}\n', encoding="utf-8")
        (root / "second.json").write_text('{"run":2}\n', encoding="utf-8")
        latest = root / "report_latest.json"
        latest.symlink_to("first.json")

        replace_symlink(str(latest), "second.json")
        check(latest.is_symlink(), "latest path was not left as a symlink")
        check(os.readlink(latest) == "second.json", "latest link did not point to the new artifact")
        check(latest.read_text(encoding="utf-8") == '{"run":2}\n', "latest link did not resolve to complete new content")
        check(not list(root.glob(".report_latest.json.tmp.*")), "temporary symlink was left behind")
        print("[PASS] latest symlink atomically switches to the completed artifact")

        regular = root / "report_latest.txt"
        regular.write_text("keep me\n", encoding="utf-8")
        try:
            replace_symlink(str(regular), "second.json")
        except FileExistsError:
            pass
        else:
            raise AssertionError("helper overwrote a regular file at a latest-link path")
        check(regular.read_text(encoding="utf-8") == "keep me\n", "regular file was modified")
        print("[PASS] publisher fails closed rather than overwriting a regular file")

        try:
            replace_symlink(str(latest), str(root / "second.json"))
        except ValueError:
            pass
        else:
            raise AssertionError("helper accepted an absolute symlink target")
        print("[PASS] publisher accepts only relative sibling targets")


if __name__ == "__main__":
    main()
