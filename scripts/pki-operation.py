#!/usr/bin/env python3
"""Serialize PKI deployment/rotation against SecureSandbox agent launches."""

from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import subprocess
from pathlib import Path


LAUNCHER_PATH = Path(__file__).with_name("secure-sandbox-claude-launcher.py")
SPEC = importlib.util.spec_from_file_location("secure_sandbox_launcher_pki", LAUNCHER_PATH)
LAUNCHER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(LAUNCHER)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("deploy", "rotate"))
    parser.add_argument("generation_id", nargs="?")
    args = parser.parse_args()
    if args.command == "deploy" and args.generation_id:
        parser.error("deploy does not accept a generation ID")
    lock = LAUNCHER.acquire_lock(LAUNCHER.STATE_ROOT, timeout=10.0)
    try:
        # Fail closed on any marker; the controller's early cleanup trap owns
        # marker removal, so maintenance never guesses whether a run is stale.
        marker_root = LAUNCHER.STATE_ROOT / "active"
        if marker_root.exists():
            info = marker_root.lstat()
            entries = list(marker_root.iterdir())
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or len(entries) > 64:
                print("active_marker_directory_invalid", file=__import__("sys").stderr)
                return 1
            if entries:
                print("active_controller_invocation", file=__import__("sys").stderr)
                return 1
        script = Path(__file__).with_name(
            "deploy-pki-lifecycle.sh" if args.command == "deploy" else "rotate-pki-generation.sh"
        )
        command = [str(script)]
        if args.generation_id:
            command.append(args.generation_id)
        environment = os.environ.copy()
        environment["SECURE_SANDBOX_COORDINATION_LOCK_HELD"] = "1"
        return subprocess.run(command, env=environment, check=False).returncode
    finally:
        LAUNCHER.release_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())
