#!/usr/bin/env python3
"""Serialize privileged-control deployment against Claude launch admission."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_PATH = ROOT / "scripts/secure-sandbox-claude-launcher.py"
MANAGER_PATH = ROOT / "scripts/host-controller-release.py"
SUPPORT_PATH = ROOT / "scripts/secure_enclave_ddd_support.py"
CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
PUBLIC_KEY = ROOT / "runs/control_key.pub"
DEFERRED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


LAUNCHER = load_module("secure_sandbox_launcher_privileged_control", LAUNCHER_PATH)
MANAGER = load_module("host_controller_release_privileged_control", MANAGER_PATH)


class DeferredSignals:
    """Record termination requests without abandoning an authenticated child."""

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


def run_command(command: list[str], deferred: DeferredSignals) -> subprocess.CompletedProcess[str]:
    """Start one child atomically with respect to deferred termination signals."""

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, DEFERRED_SIGNALS)
    try:
        if deferred.received is not None:
            raise InterruptedError
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    stdout, stderr = process.communicate()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def require_success(
    command: list[str], deferred: DeferredSignals, label: str
) -> subprocess.CompletedProcess[str]:
    result = run_command(command, deferred)
    if result.returncode != 0:
        if result.stderr:
            sys.stderr.write(result.stderr)
        raise RuntimeError(f"{label}_failed:{result.returncode}")
    return result


def verify_host_controller_release(
    deferred: DeferredSignals,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(MANAGER_PATH), "verify", "--json"]
    result = run_command(command, deferred)
    if result.returncode == 0:
        return result
    try:
        rejection = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        rejection = None
    if (result.stderr or not isinstance(rejection, dict)
            or set(rejection) != {"error", "schema", "status"}
            or rejection.get("schema")
            != "secure-sandbox-host-controller-release-v1"
            or rejection.get("status") != "rejected"
            or rejection.get("error") != "execution_approval_floor_invalid"):
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        raise RuntimeError(f"host_controller_release_verify_failed:{result.returncode}")
    # Protocol v2 deliberately makes the monotonic floor root-only. Fall back
    # only for that exact structured denial to the post-activation verifier,
    # which checks the complete immutable source release and independently
    # queries the protected broker for an active hardware-backed identity.
    return require_success(
        [
            sys.executable, str(SUPPORT_PATH),
            "verify-postactivation-host-release",
            "--repo", str(ROOT),
            "--install-root", "/usr/local/libexec/secure-sandbox-host",
            "--launcher", "/usr/local/bin/secure-sandbox-claude",
        ],
        deferred,
        "postactivation_host_controller_release_verify",
    )


def client_command(host: str, *arguments: str) -> list[str]:
    return [
        str(CLIENT),
        "client",
        "--ssh-config",
        str(SSH_CONFIG),
        host,
        *arguments,
    ]


def deploy_role(host: str, role: str, deferred: DeferredSignals) -> None:
    result = require_success(
        client_command(
            host,
            "deploy",
            "install-privileged-control.sh",
            role,
            "/tmp/control_key.pub",
            "--file",
            str(ROOT / "scripts/install-privileged-control.sh"),
            "--file",
            str(ROOT / "scripts/privileged_control.py"),
            "--file",
            str(ROOT / "scripts/privileged_control_entry.py"),
            "--file",
            str(ROOT / "config/privileged-control.sudoers"),
            "--file",
            str(ROOT / "config/sshd-control.conf"),
            "--file",
            str(PUBLIC_KEY),
        ),
        deferred,
        f"privileged_control_install_{role}",
    )
    expected = f"privileged-control:installed:{role}"
    if result.stdout.strip() != expected:
        raise RuntimeError(f"privileged_control_install_result_invalid:{role}")


def interrupted_status(deferred: DeferredSignals) -> int | None:
    if deferred.received is None:
        return None
    print(f"deployment_interrupted:{deferred.received}", file=sys.stderr)
    return 128 + deferred.received


def deploy(state_root: Path = LAUNCHER.STATE_ROOT) -> int:
    lock = None
    with DeferredSignals() as deferred:
        try:
            lock = LAUNCHER.acquire_lock(state_root, timeout=10.0)
            # Launch admission creates its marker while holding this same lock.
            # Therefore an empty marker set stays empty until this function
            # releases the lock after every authenticated deployment child.
            if MANAGER.active_markers(state_root):
                print("active_controller_invocation", file=sys.stderr)
                return 1
            status = interrupted_status(deferred)
            if status is not None:
                return status

            verify_host_controller_release(deferred)
            if not protected_regular_file(CLIENT, executable=True):
                raise RuntimeError("protected_control_client_unavailable")
            if not protected_regular_file(SSH_CONFIG):
                raise RuntimeError("protected_ssh_config_unavailable")
            if not protected_regular_file(PUBLIC_KEY):
                raise RuntimeError("control_public_key_unavailable")

            # Upgrade Research first so an older installation gains the fixed
            # root-side idle probe before any broader control-plane mutation.
            deploy_role("sandbox-research-control", "research", deferred)
            status = interrupted_status(deferred)
            if status is not None:
                return status

            require_success(
                client_command("sandbox-research-control", "run", "lifecycle-idle"),
                deferred,
                "research_lifecycle_idle",
            )
            status = interrupted_status(deferred)
            if status is not None:
                return status

            deploy_role("sandbox-gateway-control", "gateway", deferred)
            status = interrupted_status(deferred)
            if status is not None:
                return status
            deploy_role("sandbox-target-control", "target", deferred)
            status = interrupted_status(deferred)
            if status is not None:
                return status

            policy = require_success(
                client_command(
                    "sandbox-research-control",
                    "deploy",
                    "install-approved-claude-policy.sh",
                    "--file",
                    str(ROOT / "scripts/apply-approved-claude-policy.sh")
                    + ":install-approved-claude-policy.sh",
                    "--file",
                    str(ROOT / "research/managed-settings.proposed.json"),
                    "--file",
                    str(ROOT / "research/research-claude.proposed"),
                    "--file",
                    str(ROOT / "research/session_registry.py"),
                ),
                deferred,
                "claude_policy_install",
            )
            expected_policy = (
                "claude-policy:installed; run the post-install safety audit before use"
            )
            if policy.stdout.strip() != expected_policy:
                raise RuntimeError("claude_policy_install_result_invalid")
            status = interrupted_status(deferred)
            if status is not None:
                return status

            verification = require_success(
                [sys.executable, str(ROOT / "scripts/verify-privileged-control-live.py")],
                deferred,
                "privileged_control_live_verify",
            )
            status = interrupted_status(deferred)
            if status is not None:
                return status
            sys.stdout.write(verification.stdout)
            return 0
        except InterruptedError:
            return interrupted_status(deferred) or 1
        except (OSError, RuntimeError, TimeoutError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        finally:
            if lock is not None:
                LAUNCHER.release_lock(lock)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("deploy",))
    parser.parse_args()
    return deploy()


if __name__ == "__main__":
    raise SystemExit(main())
