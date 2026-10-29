#!/usr/bin/env python3
"""Compute stable output and Ghidra project identities for an input sample."""

import hashlib
import os
import re
import sys


def _digest_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _source_identity(path):
    """Return output-name parts after hashing the canonical path and full content."""
    real_path = os.path.realpath(os.path.abspath(path))
    if not os.path.isfile(real_path):
        raise FileNotFoundError(f"Input file does not exist or is not a regular file: {path}")

    basename = os.path.basename(path)
    safe_base = re.sub(r"[^a-zA-Z0-9_]+", "_", basename).strip("_") or "sample"
    safe_base = safe_base[:72]
    path_digest = hashlib.sha256(os.fsencode(real_path)).hexdigest()[:10]
    content_digest = _digest_file(real_path)[:12]
    return safe_base, path_digest, content_digest


def output_identity(path):
    """Return the stable output directory name for a path and its current bytes."""
    safe_base, path_digest, content_digest = _source_identity(path)
    return f"{safe_base}_{path_digest}_{content_digest}"


def project_identity(path, findcrypt="false", ghidra_root=""):
    """Return the project name including settings that can affect its contents."""
    output_key = output_identity(path)
    settings = (
        f"findcrypt={findcrypt}\0"
        f"ghidra_root={os.path.realpath(ghidra_root) if ghidra_root else ''}"
    )
    settings_digest = hashlib.sha256(settings.encode("utf-8")).hexdigest()[:8]
    return f"{output_key}_{settings_digest}"


def identities(path, findcrypt="false", ghidra_root=""):
    """Compute project and output names while hashing the sample only once."""
    safe_base, path_digest, content_digest = _source_identity(path)
    output_key = f"{safe_base}_{path_digest}_{content_digest}"
    settings = (
        f"findcrypt={findcrypt}\0"
        f"ghidra_root={os.path.realpath(ghidra_root) if ghidra_root else ''}"
    )
    settings_digest = hashlib.sha256(settings.encode("utf-8")).hexdigest()[:8]
    return f"{output_key}_{settings_digest}", output_key


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"project", "output", "identities"}:
        command = argv.pop(0)
    else:
        # Keep the original one-file CLI as a project-name alias.
        command = "project"

    try:
        if command == "output":
            if len(argv) != 1:
                raise ValueError("output command requires exactly one binary path")
            print(output_identity(argv[0]))
        elif command == "project":
            if len(argv) not in (1, 2, 3):
                raise ValueError("project command requires a binary path and optional settings")
            findcrypt = argv[1] if len(argv) >= 2 else "false"
            ghidra_root = argv[2] if len(argv) >= 3 else ""
            print(project_identity(argv[0], findcrypt, ghidra_root))
        else:
            if len(argv) not in (1, 2, 3):
                raise ValueError("identities command requires a binary path and optional settings")
            findcrypt = argv[1] if len(argv) >= 2 else "false"
            ghidra_root = argv[2] if len(argv) >= 3 else ""
            project_name, output_key = identities(argv[0], findcrypt, ghidra_root)
            print(f"{project_name}\t{output_key}")
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
