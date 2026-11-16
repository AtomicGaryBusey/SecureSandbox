#!/usr/bin/env python3
"""Bridge an exact stopped VM inventory across Parallels GUI closure.

Parallels Desktop 27.2.1 on macOS 27.2.1 tears down the per-user API
session used by ``prlctl`` when its GUI exits.  This helper is deliberately
limited to the all-stopped boundary: it observes the fixed VM set while one
stable GUI process owns the API session, quits that GUI normally, proves that
the GUI and VM runtime processes are absent, and publishes a short-lived,
zero-authority receipt for explicit consumption by the morning preflight.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
MAX_OUTPUT = 4096


class ClosedInventoryError(RuntimeError):
    """Stable, content-free closed-inventory failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ClosedInventoryError("closed_vm_inventory_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PREFLIGHT = load_script(
    "harness_lifecycle_closed_inventory_preflight",
    ROOT / "scripts/harness-lifecycle-acceptance-morning-preflight.py",
)
SUPERVISOR = PREFLIGHT.SUPERVISOR


def process_ids(
    name: str, *, runner: Callable[..., Any] = subprocess.run,
) -> tuple[int, ...]:
    try:
        result = runner(
            ["/usr/bin/pgrep", "-x", name], cwd=Path("/"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ClosedInventoryError("closed_vm_inventory_process_probe_failed") from error
    if (result.returncode not in {0, 1} or len(result.stdout) > MAX_OUTPUT
            or len(result.stderr) > MAX_OUTPUT or result.stderr):
        raise ClosedInventoryError("closed_vm_inventory_process_probe_failed")
    if result.returncode == 1:
        if result.stdout:
            raise ClosedInventoryError("closed_vm_inventory_process_probe_failed")
        return ()
    try:
        values = tuple(int(line) for line in result.stdout.decode("ascii").splitlines())
    except (UnicodeDecodeError, ValueError) as error:
        raise ClosedInventoryError("closed_vm_inventory_process_probe_failed") from error
    if not values or any(value <= 0 for value in values) or len(set(values)) != len(values):
        raise ClosedInventoryError("closed_vm_inventory_process_probe_failed")
    return values


def quit_parallels(*, runner: Callable[..., Any] = subprocess.run) -> None:
    try:
        result = runner(
            ["/usr/bin/osascript", "-e",
             'tell application "Parallels Desktop" to quit'],
            cwd=Path("/"), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=15,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ClosedInventoryError("closed_vm_inventory_gui_quit_failed") from error
    if (result.returncode != 0 or len(result.stdout) > MAX_OUTPUT
            or len(result.stderr) > MAX_OUTPUT or result.stderr):
        raise ClosedInventoryError("closed_vm_inventory_gui_quit_failed")


def validate_output_target(
    output: Path, *, expected_uid: int,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    """Reject a doomed publication target before closing the vendor GUI."""
    if (not output.is_absolute() or not output.name
            or output.name in {".", ".."} or os.path.lexists(output)):
        raise ClosedInventoryError("closed_vm_inventory_output_invalid")
    try:
        parent = output.parent.lstat()
        acl = runner(
            ["/bin/ls", "-lde", str(output.parent)], cwd=Path("/"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ClosedInventoryError("closed_vm_inventory_output_invalid") from error
    if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != expected_uid
            or stat.S_IMODE(parent.st_mode) != 0o700
            or acl.returncode != 0 or acl.stderr
            or len(acl.stdout) > MAX_OUTPUT
            or len(acl.stdout.splitlines()) != 1):
        raise ClosedInventoryError("closed_vm_inventory_output_invalid")


def capture(
    output: Path, *, now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    operator_uid = os.geteuid()
    if operator_uid == 0:
        raise ClosedInventoryError("closed_vm_inventory_must_not_run_as_root")
    validate_output_target(output, expected_uid=operator_uid, runner=runner)
    commit, remote_tips = PREFLIGHT.source_checkout(runner=runner)
    try:
        machine_identity = SUPERVISOR.current_machine_identity()
    except SUPERVISOR.SupervisorError as error:
        raise ClosedInventoryError("closed_vm_inventory_machine_invalid") from error
    initial_pids = process_ids("prl_client_app", runner=runner)
    if len(initial_pids) != 1:
        raise ClosedInventoryError("closed_vm_inventory_gui_session_invalid")
    gui_pid = initial_pids[0]
    try:
        vm_states = SUPERVISOR.vm_inventory()
    except SUPERVISOR.SupervisorError as error:
        raise ClosedInventoryError("closed_vm_inventory_readback_failed") from error
    if vm_states != {
        "gateway": "stopped", "research": "stopped", "target": "stopped",
    }:
        raise ClosedInventoryError("closed_vm_inventory_not_all_stopped")
    if process_ids("prl_client_app", runner=runner) != (gui_pid,):
        raise ClosedInventoryError("closed_vm_inventory_gui_session_changed")
    inventory_observed_at = int(now())

    quit_parallels(runner=runner)
    deadline = now() + 20
    while True:
        gui_pids = process_ids("prl_client_app", runner=runner)
        runtime_pids = process_ids("prl_vm_app", runner=runner)
        if not gui_pids and not runtime_pids:
            break
        if now() >= deadline:
            raise ClosedInventoryError("closed_vm_inventory_processes_remain")
        sleep(0.25)

    observed_at = int(now())
    if observed_at < inventory_observed_at or observed_at - inventory_observed_at > 30:
        raise ClosedInventoryError("closed_vm_inventory_capture_expired")
    value: dict[str, Any] = {
        "schema": PREFLIGHT.CLOSED_STOPPED_INVENTORY_SCHEMA,
        "status": "verified",
        "inventory_observed_at": inventory_observed_at,
        "observed_at": observed_at,
        "source_commit": commit,
        "branch": PREFLIGHT.PUBLIC_BRANCH,
        "remote_tips": remote_tips,
        "machine_identity_sha256": machine_identity,
        "operator_uid": operator_uid,
        "parallels_gui_pid": gui_pid,
        "parallels_gui_closed": True,
        "vm_runtime_processes_absent": True,
        "vm_states": vm_states,
        "authority": "none",
    }
    value["receipt_sha256"] = PREFLIGHT.digest(value)
    PREFLIGHT.write_preflight_receipt(output, value, expected_uid=operator_uid, runner=runner)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Capture an all-stopped VM inventory and close Parallels",
    )
    value.add_argument("--output", type=Path, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    result = capture(args.output)
    sys.stdout.buffer.write(PREFLIGHT.canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClosedInventoryError, PREFLIGHT.PreflightError,
            PREFLIGHT.AcceptanceError, OSError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(
            error, (ClosedInventoryError, PREFLIGHT.PreflightError,
                    PREFLIGHT.AcceptanceError),
        ) else "closed_vm_inventory_failed"
        print(PREFLIGHT.json.dumps({
            "schema": "secure-sandbox-harness-lifecycle-closed-stopped-vm-inventory-error-v1",
            "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
