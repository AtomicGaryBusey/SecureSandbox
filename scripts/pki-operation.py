#!/usr/bin/env python3
"""Serialize PKI deployment/rotation against SecureSandbox launches."""

from __future__ import annotations

import argparse
import importlib.util
import os
import signal
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_PATH = ROOT / "scripts/secure-sandbox-claude-launcher.py"
CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
DEFERRED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def load_launcher():
    spec = importlib.util.spec_from_file_location("secure_sandbox_launcher_pki", LAUNCHER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


LAUNCHER = load_launcher()


class DeferredSignals:
    """Record termination without releasing the launch lock under a live child."""

    def __init__(self) -> None:
        self.received: int | None = None
        self.previous: dict[int, object] = {}

    def handle(self, signum: int, _frame: object) -> None:
        if self.received is None:
            self.received = signum

    def __enter__(self) -> "DeferredSignals":
        for signum in DEFERRED_SIGNALS:
            self.previous[signum] = signal.signal(signum, self.handle)
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)


def protected_regular_file(path: Path, executable: bool = False) -> bool:
    try:
        metadata = path.stat()
        leaf = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(leaf.st_mode):
        return False
    return not executable or os.access(path, os.X_OK)


def run_child(command: list[str], environment: dict[str, str], deferred: DeferredSignals) -> int:
    if deferred.received is not None:
        return 128 + deferred.received
    # Catchable signals remain handled by the parent, but must stay unblocked
    # in the child so shell cleanup traps and ordinary termination semantics work.
    process = subprocess.Popen(command, env=environment, start_new_session=True)
    return process.wait()


def client_command(*arguments: str) -> list[str]:
    return [
        str(CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
        "sandbox-research-control", *arguments,
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("deploy", "rotate"))
    parser.add_argument("generation_id", nargs="?")
    parser.add_argument("--inherited-lock", action="store_true")
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--requesting-agent", default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"))
    parser.add_argument("--requesting-session", default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"))
    args = parser.parse_args()
    if args.command == "deploy" and args.generation_id:
        parser.error("deploy does not accept a generation ID")
    if args.recover and (args.command != "rotate" or not args.generation_id):
        parser.error("--recover requires rotate and an explicit generation ID")
    if args.command == "rotate" and args.generation_id and not args.recover:
        parser.error("an explicit generation ID requires --recover")
    if args.command == "rotate" and (not args.requesting_agent or not args.requesting_session):
        parser.error(
            "rotation requires --requesting-agent and --requesting-session for attributed host authorization"
        )

    lock = None
    with DeferredSignals() as deferred:
        try:
            if args.inherited_lock:
                state_root = os.environ.get("SECURE_SANDBOX_STATE_ROOT", "")
                holder = os.environ.get("SECURE_SANDBOX_COORDINATION_HOLDER_PID", "")
                pid_file = LAUNCHER.STATE_ROOT / "coordination.lock" / "pid"
                if (state_root != str(LAUNCHER.STATE_ROOT) or holder != str(os.getppid())
                        or pid_file.is_symlink() or not pid_file.is_file()
                        or pid_file.read_text(encoding="ascii").strip() != holder):
                    print("inherited_coordination_lock_invalid", file=sys.stderr)
                    return 1
            else:
                lock = LAUNCHER.acquire_lock(LAUNCHER.STATE_ROOT, timeout=10.0)
            marker_root = LAUNCHER.STATE_ROOT / "active"
            if marker_root.exists():
                info = marker_root.lstat()
                entries = list(marker_root.iterdir())
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or len(entries) > 64:
                    print("active_marker_directory_invalid", file=sys.stderr)
                    return 1
                if entries:
                    print("active_controller_invocation", file=sys.stderr)
                    return 1
            if not protected_regular_file(CLIENT, executable=True) or not protected_regular_file(SSH_CONFIG):
                print("protected_control_plane_unavailable", file=sys.stderr)
                return 1

            idle = subprocess.run(client_command("run", "lifecycle-idle"), check=False)
            if idle.returncode != 0:
                print("research_lifecycle_not_idle", file=sys.stderr)
                return 1
            if deferred.received is not None:
                return 128 + deferred.received

            script = ROOT / "scripts" / (
                "deploy-pki-lifecycle.sh" if args.command == "deploy" else "rotate-pki-generation.sh"
            )
            command = [str(script)]
            if args.generation_id:
                command.append(args.generation_id)
            environment = os.environ.copy()
            environment["SECURE_SANDBOX_STATE_ROOT"] = str(LAUNCHER.STATE_ROOT)
            environment["SECURE_SANDBOX_COORDINATION_PARENT_PID"] = str(os.getpid())
            environment["SECURE_SANDBOX_COORDINATION_HOLDER_PID"] = (
                str(os.getppid()) if args.inherited_lock else str(os.getpid())
            )
            if args.recover:
                environment["SECURE_SANDBOX_PKI_RECOVERY"] = "1"
            if args.requesting_agent:
                environment["SECURE_SANDBOX_REQUESTING_AGENT"] = args.requesting_agent
            if args.requesting_session:
                environment["SECURE_SANDBOX_REQUESTING_SESSION"] = args.requesting_session
            result = run_child(command, environment, deferred)
            if deferred.received is not None:
                print(f"pki_operation_interrupted:{deferred.received}", file=sys.stderr)
                return 128 + deferred.received
            return result
        except (OSError, TimeoutError, LAUNCHER.LaunchFailure) as error:
            print(str(error), file=sys.stderr)
            return 1
        finally:
            if lock is not None:
                LAUNCHER.release_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())
