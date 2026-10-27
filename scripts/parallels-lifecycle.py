#!/usr/bin/env python3
"""Readback-driven lifecycle control for the three SecureSandbox VMs."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from collections.abc import Callable
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PRLCTL = Path("/Applications/Parallels Desktop.app/Contents/MacOS/prlctl")
CONTROL_CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
PGREP = Path("/usr/bin/pgrep")
SYNC_SCRIPT = ROOT / "scripts/sync-lab-time.sh"
VERIFY_SCRIPT = ROOT / "scripts/verify-boundaries.sh"
LOCK_PATH = Path(f"/tmp/secure-sandbox-lifecycle-{os.getuid()}.lock")

VMS = (
    ("gateway", "SecureSandbox-Gateway", "sandbox-gateway-control"),
    ("research", "SecureSandbox-Research", "sandbox-research-control"),
    ("target", "SecureSandbox-Target", "sandbox-target-control"),
)
START_ORDER = VMS
STOP_ORDER = tuple(reversed(VMS))
MAX_OUTPUT = 64 * 1024


class LifecycleError(RuntimeError):
    pass


def command(
    argv: list[str], *, timeout: float = 15, capture: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    kwargs: dict[str, Any] = {"check": False, "timeout": timeout}
    if capture:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        result = subprocess.run(argv, **kwargs)
    except OSError as error:
        raise LifecycleError(f"command_unavailable:{Path(argv[0]).name}") from error
    if capture and (len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT):
        raise LifecycleError("command_output_limit_exceeded")
    return result


def require_regular(path: Path, *, executable: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LifecycleError(f"prerequisite_unavailable:{path.name}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LifecycleError(f"prerequisite_untrusted:{path.name}")
    if executable and not os.access(path, os.X_OK):
        raise LifecycleError(f"prerequisite_unexecutable:{path.name}")


def parse_json_output(result: subprocess.CompletedProcess[bytes], label: str) -> Any:
    if result.returncode != 0:
        raise LifecycleError(f"{label}_unavailable")
    try:
        return json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleError(f"{label}_invalid") from error


def vm_state(name: str) -> str:
    value = parse_json_output(
        command([str(PRLCTL), "list", "--all", "--json", name]), "vm_inventory"
    )
    if not isinstance(value, list) or len(value) != 1 or value[0].get("name") != name:
        raise LifecycleError("vm_inventory_invalid")
    state = value[0].get("status")
    if not isinstance(state, str) or not state or len(state) > 32:
        raise LifecycleError("vm_state_invalid")
    return state


def gateway_uplink_state() -> str:
    value = parse_json_output(
        command([str(PRLCTL), "list", "--info", "--json", "SecureSandbox-Gateway"]),
        "gateway_inventory",
    )
    if not isinstance(value, list) or len(value) != 1:
        raise LifecycleError("gateway_inventory_invalid")
    item = value[0]
    if item.get("Name") != "SecureSandbox-Gateway":
        raise LifecycleError("gateway_inventory_invalid")
    try:
        enabled = item["Hardware"]["net0"]["enabled"]
    except (KeyError, TypeError) as error:
        raise LifecycleError("gateway_uplink_invalid") from error
    if not isinstance(enabled, bool):
        raise LifecycleError("gateway_uplink_invalid")
    return "connected" if enabled else "disconnected"


def guest_reachable(host: str) -> bool:
    result = command(
        [str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG), host,
         "run", "control-status"],
        timeout=5,
    )
    return result.returncode == 0


def gui_running() -> bool:
    result = command([str(PGREP), "-x", "prl_client_app"], timeout=5)
    if result.returncode not in (0, 1):
        raise LifecycleError("parallels_gui_state_unavailable")
    return result.returncode == 0


def acquire_lock() -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(LOCK_PATH, flags, 0o600)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise LifecycleError("lifecycle_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise LifecycleError("lifecycle_transition_active") from error
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise LifecycleError("lifecycle_lock_unavailable") from error
    except LifecycleError:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def observe(*, reachability: bool = False) -> tuple[dict[str, str], dict[str, str]]:
    observed: dict[str, str] = {}
    reachable: dict[str, str] = {}
    for key, name, host in VMS:
        try:
            observed[key] = vm_state(name)
        except LifecycleError:
            observed[key] = "unknown"
        if reachability:
            try:
                reachable[key] = "reachable" if guest_reachable(host) else "unreachable"
            except (LifecycleError, subprocess.TimeoutExpired):
                reachable[key] = "unknown"
    try:
        observed["gateway_net0"] = gateway_uplink_state()
    except (LifecycleError, subprocess.TimeoutExpired):
        observed["gateway_net0"] = "unknown"
    return observed, reachable


def emit(
    operation: str, status: str, phase: str, outcomes: list[dict[str, str]],
    failures: list[str], *, reachability: bool = False,
) -> None:
    observed, reachable = observe(reachability=reachability)
    record: dict[str, Any] = {
        "schema": "secure-sandbox-host-lifecycle-v1",
        "operation": operation,
        "status": status,
        "phase": phase,
        "transition_id": str(uuid.uuid4()),
        "observed": observed,
        "action_outcomes": outcomes,
        "action_failures": failures,
    }
    if reachability:
        record["reachability"] = reachable
    print(json.dumps(record, sort_keys=True, separators=(",", ":")),
          file=sys.stdout if status == "verified" else sys.stderr, flush=True)


def wait_vm(name: str, desired: str, attempts: int = 60) -> bool:
    for _ in range(attempts):
        try:
            if vm_state(name) == desired:
                return True
        except (LifecycleError, subprocess.TimeoutExpired):
            pass
        time.sleep(1)
    return False


def wait_guest(host: str, attempts: int = 60) -> bool:
    for _ in range(attempts):
        try:
            if guest_reachable(host):
                return True
        except (LifecycleError, subprocess.TimeoutExpired):
            pass
        time.sleep(1)
    return False


def mutate(
    argv: list[str], action: str, target: str, outcomes: list[dict[str, str]],
    verify: Callable[[], bool],
) -> bool:
    try:
        result = command(argv, timeout=20)
        returncode = result.returncode
    except (LifecycleError, subprocess.TimeoutExpired):
        returncode = 124
    verified = verify()
    if verified:
        outcome = "succeeded" if returncode == 0 else "lost_response"
    else:
        outcome = "failed"
    outcomes.append({"action": action, "target": target, "result": outcome})
    return verified


def ensure_mutation_preconditions(operation: str) -> int:
    for path, executable in ((PRLCTL, True), (CONTROL_CLIENT, True), (SSH_CONFIG, False)):
        require_regular(path, executable=executable)
    try:
        if gui_running():
            emit(operation, "rejected", "preflight", [], ["parallels_gui_running"])
            raise SystemExit(1)
    except subprocess.TimeoutExpired:
        emit(operation, "rejected", "preflight", [], ["parallels_gui_state_unavailable"])
        raise SystemExit(1)
    try:
        return acquire_lock()
    except LifecycleError as error:
        emit(operation, "rejected", "preflight", [], [str(error)])
        raise SystemExit(1) from error


def start() -> int:
    lock = ensure_mutation_preconditions("start")
    outcomes: list[dict[str, str]] = []
    failures: list[str] = []
    try:
        initial, _ = observe()
        if any(initial[key] not in ("running", "stopped") for key, _, _ in VMS):
            emit("start", "rejected", "preflight", outcomes, ["mixed_or_unknown_vm_state"])
            return 1
        for key, name, host in START_ORDER:
            state = vm_state(name)
            if state == "stopped":
                if not mutate(
                    [str(PRLCTL), "start", name], "vm_start", key, outcomes,
                    lambda name=name: wait_vm(name, "running"),
                ):
                    failures.append(f"{key}_start")
                    emit("start", "rejected", "transition", outcomes, failures)
                    return 1
            else:
                outcomes.append({"action": "vm_start", "target": key, "result": "already_satisfied"})
            if key == "gateway":
                uplink = gateway_uplink_state()
                if uplink == "disconnected":
                    if not mutate(
                        [str(PRLCTL), "set", name, "--device-connect", "net0"],
                        "gateway_uplink_connect", key, outcomes,
                        lambda: gateway_uplink_state() == "connected",
                    ):
                        failures.append("gateway_uplink_connect")
                        emit("start", "rejected", "transition", outcomes, failures)
                        return 1
                else:
                    outcomes.append({"action": "gateway_uplink_connect", "target": key,
                                     "result": "already_satisfied"})
            if not wait_guest(host):
                failures.append(f"{key}_control_unreachable")
                emit("start", "rejected", "readiness", outcomes, failures, reachability=True)
                return 1
        sync = command([str(SYNC_SCRIPT), "--apply"], timeout=120, capture=False)
        if sync.returncode != 0:
            emit("start", "rejected", "time_sync", outcomes, ["time_sync_failed"], reachability=True)
            return 1
        verification = command([str(VERIFY_SCRIPT)], timeout=600, capture=False)
        if verification.returncode != 0:
            emit("start", "rejected", "boundary_verification", outcomes,
                 ["boundary_verification_failed"], reachability=True)
            return 1
        emit("start", "verified", "complete", outcomes, [], reachability=True)
        return 0
    except (LifecycleError, subprocess.TimeoutExpired) as error:
        failures.append(str(error) or error.__class__.__name__)
        emit("start", "rejected", "transition", outcomes, failures, reachability=True)
        return 1
    finally:
        os.close(lock)


def stop() -> int:
    lock = ensure_mutation_preconditions("stop")
    outcomes: list[dict[str, str]] = []
    failures: list[str] = []
    try:
        initial, _ = observe()
        if any(initial[key] not in ("running", "stopped") for key, _, _ in VMS):
            emit("stop", "rejected", "preflight", outcomes, ["mixed_or_unknown_vm_state"])
            return 1
        for key, name, host in STOP_ORDER:
            state = vm_state(name)
            if state == "stopped":
                outcomes.append({"action": "guest_shutdown", "target": key,
                                 "result": "already_satisfied"})
                continue
            if not mutate(
                [str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG), host,
                 "run", "poweroff"],
                "guest_shutdown", key, outcomes,
                lambda name=name: wait_vm(name, "stopped"),
            ):
                failures.append(f"{key}_guest_shutdown")
                emit("stop", "rejected", "transition", outcomes, failures)
                return 1
        emit("stop", "verified", "complete", outcomes, [])
        return 0
    except (LifecycleError, subprocess.TimeoutExpired) as error:
        failures.append(str(error) or error.__class__.__name__)
        emit("stop", "rejected", "transition", outcomes, failures)
        return 1
    finally:
        os.close(lock)


def status() -> int:
    try:
        require_regular(PRLCTL, executable=True)
        require_regular(CONTROL_CLIENT, executable=True)
        require_regular(SSH_CONFIG)
        observed, reachable = observe(reachability=True)
        stable = all(observed[key] in ("running", "stopped") for key, _, _ in VMS)
        record = {
            "schema": "secure-sandbox-host-lifecycle-v1",
            "operation": "status",
            "status": "verified" if stable else "rejected",
            "phase": "readback",
            "observed": observed,
            "reachability": reachable,
            "action_outcomes": [],
            "action_failures": [] if stable else ["mixed_or_unknown_vm_state"],
        }
        print(json.dumps(record, sort_keys=True, separators=(",", ":")),
              file=sys.stdout if stable else sys.stderr)
        return 0 if stable else 1
    except (LifecycleError, subprocess.TimeoutExpired) as error:
        emit("status", "rejected", "readback", [], [str(error) or error.__class__.__name__],
             reachability=True)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("start", "stop", "status"))
    args = parser.parse_args()
    return {"start": start, "stop": stop, "status": status}[args.operation]()


if __name__ == "__main__":
    raise SystemExit(main())
