#!/usr/bin/env python3
"""Unprivileged coordination wrapper for host-controller deploy and rollback."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("secure-sandbox-claude-launcher.py")
SPEC = importlib.util.spec_from_file_location("secure_sandbox_launcher", MODULE_PATH)
LAUNCHER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(LAUNCHER)
MANAGER_PATH = Path(__file__).with_name("host-controller-release.py")
MANAGER_SPEC = importlib.util.spec_from_file_location("host_controller_release", MANAGER_PATH)
MANAGER = importlib.util.module_from_spec(MANAGER_SPEC)
assert MANAGER_SPEC.loader is not None
MANAGER_SPEC.loader.exec_module(MANAGER)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("deploy", "rollback", "migrate-launcher"))
    parser.add_argument("identity", nargs="?")
    args = parser.parse_args()
    if args.command == "deploy" and args.identity:
        parser.error("deploy does not accept a release ID")
    if args.command == "migrate-launcher" and not args.identity:
        parser.error("migrate-launcher requires the expected installed launcher SHA-256")
    state_root = LAUNCHER.STATE_ROOT
    lock = LAUNCHER.acquire_lock(state_root, timeout=10.0)
    try:
        live = MANAGER.active_markers(state_root)
        if live:
            print("active_controller_invocations:" + ",".join(live), file=sys.stderr)
            return 1
        manager_action = "install" if args.command == "deploy" else args.command
        command = [
            "sudo", "/usr/bin/python3", str(MANAGER_PATH), manager_action,
            "--state-root", str(state_root),
        ]
        if args.command == "rollback" and args.identity:
            command.extend(["--release-id", args.identity])
        if args.command == "migrate-launcher":
            command.extend(["--expected-launcher-sha256", args.identity])
            replacement = MANAGER.read_regular(MODULE_PATH)
            command.extend(["--expected-replacement-sha256", hashlib.sha256(replacement).hexdigest()])
        command.append("--json")
        return subprocess.run(command, check=False).returncode
    finally:
        LAUNCHER.release_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())
