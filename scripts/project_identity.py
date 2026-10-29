#!/usr/bin/env python3
"""Compute stable, collision-resistant Ghidra project identities.

Project identity includes the source path, sample content, and project-affecting
settings. Hashing the path as well as the contents avoids two copied files with
the same basename sharing one writable Ghidra project.
"""

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


def project_identity(path, findcrypt="false", ghidra_root=""):
    """Return a filesystem-safe, stable name for a binary analysis project."""
    real_path = os.path.realpath(os.path.abspath(path))
    if not os.path.isfile(real_path):
        raise FileNotFoundError(f"Input file does not exist or is not a regular file: {path}")

    basename = os.path.basename(path)
    safe_base = re.sub(r"[^a-zA-Z0-9_]+", "_", basename).strip("_") or "sample"
    safe_base = safe_base[:72]

    path_digest = hashlib.sha256(os.fsencode(real_path)).hexdigest()[:10]
    content_digest = _digest_file(real_path)[:12]
    settings = f"findcrypt={findcrypt}\0ghidra_root={os.path.realpath(ghidra_root) if ghidra_root else ''}"
    settings_digest = hashlib.sha256(settings.encode("utf-8")).hexdigest()[:8]

    return f"{safe_base}_{path_digest}_{content_digest}_{settings_digest}"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) not in (1, 2, 3):
        print(
            f"Usage: {os.path.basename(sys.argv[0])} <binary> [findcrypt-enabled] [ghidra-root]",
            file=sys.stderr,
        )
        return 2
    findcrypt = argv[1] if len(argv) >= 2 else "false"
    ghidra_root = argv[2] if len(argv) >= 3 else ""
    try:
        print(project_identity(argv[0], findcrypt, ghidra_root))
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
