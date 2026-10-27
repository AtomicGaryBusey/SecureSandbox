#!/usr/bin/env python3
"""Run a trusted argv under a real wall-clock deadline."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time


def main() -> int:
    if len(sys.argv) < 3 or not sys.argv[1].isdigit():
        print("usage: run-with-deadline.py SECONDS COMMAND [ARG ...]", file=sys.stderr)
        return 2
    seconds = int(sys.argv[1])
    if not 1 <= seconds <= 3600:
        print("deadline_invalid", file=sys.stderr)
        return 2
    process = subprocess.Popen(sys.argv[2:], start_new_session=True)
    try:
        return process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        time.sleep(2)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        if process.poll() is None:
            process.wait()
        print("deadline_exceeded", file=sys.stderr)
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
