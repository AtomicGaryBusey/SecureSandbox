#!/usr/bin/env python3
"""Forced-command entry point for the unprivileged control identity."""

from __future__ import annotations

import os
import sys


def main() -> int:
    if os.environ.get("SSH_ORIGINAL_COMMAND") != "request":
        print("control_request_required", file=sys.stderr)
        return 64
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/nonexistent",
    }
    os.execve(
        "/usr/bin/sudo",
        ["sudo", "-n", "--", "/usr/local/libexec/secure-sandbox/privileged_control.py", "dispatch"],
        environment,
    )


if __name__ == "__main__":
    raise SystemExit(main())
