#!/usr/bin/env python3
"""Hold a POSIX advisory lock until the requesting shell closes its pipe.

The lock is held by this helper process, rather than by a shell-side PID file,
so the operating system releases it when the helper exits. The lock file itself
is deliberately persistent: unlinking it while another process waits could let
later callers lock a different inode and enter the critical section together.
"""
import fcntl
import math
import os
import sys
import time

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print("ERROR usage: output_lock.py LOCK_FILE TIMEOUT_SECONDS", flush=True)
        return 2
    lock_path, timeout_text = argv
    try:
        timeout = float(timeout_text)
    except ValueError:
        print("ERROR lock timeout must be a positive number of seconds", flush=True)
        return 2
    if not math.isfinite(timeout) or timeout <= 0:
        print("ERROR lock timeout must be a positive number of seconds", flush=True)
        return 2
    try:
        os.makedirs(os.path.dirname(os.path.abspath(lock_path)), exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        print(f"ERROR cannot open output lock: {exc}", flush=True)
        return 2
    deadline = time.monotonic() + timeout
    reported_wait = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not reported_wait:
                    print(
                        f"[INFO] Waiting for report-output lock {os.path.basename(lock_path)}",
                        file=sys.stderr,
                        flush=True,
                    )
                    reported_wait = True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    print("ERROR output lock acquisition timed out", flush=True)
                    return 2
                time.sleep(min(0.1, remaining))
        os.ftruncate(fd, 0)
        os.write(fd, f"pid={os.getpid()}\n".encode("ascii"))
        print("LOCKED", flush=True)
        while sys.stdin.buffer.read(4096):
            pass
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR output lock failed: {exc}", file=sys.stderr, flush=True)
        return 2
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)

if __name__ == "__main__":
    raise SystemExit(main())
