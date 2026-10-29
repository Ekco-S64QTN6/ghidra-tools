#!/usr/bin/env python3
"""Atomically replace one report-latest symlink without an unlink/create gap."""

import os
import secrets
import sys


def replace_symlink(link_path, target):
    """Atomically make link_path point to a sibling target path."""
    if not target or os.path.isabs(target) or os.path.basename(target) != target or target in {".", ".."}:
        raise ValueError("symlink target must be a non-empty sibling filename")

    link_path = os.path.abspath(link_path)
    parent = os.path.dirname(link_path)
    os.makedirs(parent, exist_ok=True)

    if os.path.lexists(link_path) and not os.path.islink(link_path):
        raise FileExistsError(f"refusing to replace non-symlink latest path: {link_path}")

    temporary_link = os.path.join(
        parent,
        f".{os.path.basename(link_path)}.tmp.{os.getpid()}.{secrets.token_hex(8)}",
    )
    try:
        os.symlink(target, temporary_link)
        # Do not clobber a regular file should one appear before the swap.
        if os.path.lexists(link_path) and not os.path.islink(link_path):
            raise FileExistsError(f"refusing to replace non-symlink latest path: {link_path}")
        os.replace(temporary_link, link_path)
    finally:
        try:
            if os.path.lexists(temporary_link):
                os.unlink(temporary_link)
        except OSError:
            pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 3 or argv[0] != "symlink":
        print("Usage: atomic_publish.py symlink LINK_PATH SIBLING_TARGET", file=sys.stderr)
        return 2
    try:
        replace_symlink(argv[1], argv[2])
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
