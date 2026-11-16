#!/usr/bin/env python3
"""Bootstrap an all-stopped Parallels service without GUI-bound network changes.

Parallels Desktop 27.1.0 on macOS 27.2.1 tears down its per-user service when
the GUI exits and every VM is stopped.  This explicit recovery path starts only
the fixed Gateway while one stable GUI session exists, closes that GUI, proves
the vendor service and exact intermediate VM state remain available, and then
hands the already-held lifecycle lock to the ordinary start controller.  The
ordinary controller still performs every adapter mutation, remaining VM start,
readiness check, time sync, and boundary verification with the GUI closed.
"""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
MAX_OUTPUT = 4096
GATEWAY_NAME = "SecureSandbox-Gateway"


class ServiceBootstrapError(RuntimeError):
    """Stable, content-free stopped-service bootstrap failure."""


def load_lifecycle() -> ModuleType:
    path = ROOT / "scripts/parallels-lifecycle.py"
    specification = importlib.util.spec_from_file_location(
        "secure_sandbox_parallels_lifecycle", path,
    )
    if specification is None or specification.loader is None:
        raise ServiceBootstrapError("parallels_lifecycle_module_unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


LIFECYCLE = load_lifecycle()


def gui_process_ids(
    *, runner: Callable[..., Any] = subprocess.run,
) -> tuple[int, ...]:
    try:
        result = runner(
            ["/usr/bin/pgrep", "-x", "prl_client_app"], cwd=Path("/"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ServiceBootstrapError("parallels_gui_probe_failed") from error
    if (result.returncode not in {0, 1} or result.stderr
            or len(result.stdout) > MAX_OUTPUT):
        raise ServiceBootstrapError("parallels_gui_probe_failed")
    if result.returncode == 1:
        if result.stdout:
            raise ServiceBootstrapError("parallels_gui_probe_failed")
        return ()
    try:
        values = tuple(
            int(line) for line in result.stdout.decode("ascii").splitlines()
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ServiceBootstrapError("parallels_gui_probe_failed") from error
    if (not values or any(value <= 0 for value in values)
            or len(values) != len(set(values))):
        raise ServiceBootstrapError("parallels_gui_probe_failed")
    return values


def terminate_gui(
    pid: int, *,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    runner: Callable[..., Any] = subprocess.run,
    killer: Callable[[int, int], None] = os.kill,
) -> None:
    """Terminate only the bound GUI PID, escalating after exact readback.

    Parallels 27.1 vetoes both its Apple-event quit and SIGTERM while a VM is
    running.  SIGKILL is therefore permitted only after a bounded TERM grace
    period in which every process probe still returns the same sole PID.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ServiceBootstrapError("parallels_gui_session_invalid")

    def send(value: int) -> None:
        try:
            killer(pid, value)
        except ProcessLookupError:
            return
        except OSError as error:
            raise ServiceBootstrapError("parallels_gui_termination_failed") from error

    def wait_until(deadline: float) -> bool:
        while True:
            current = gui_process_ids(runner=runner)
            if not current:
                return True
            if current != (pid,):
                raise ServiceBootstrapError("parallels_gui_session_changed")
            if now() >= deadline:
                return False
            sleep(0.25)

    send(signal.SIGTERM)
    if wait_until(now() + 3):
        return
    send(signal.SIGKILL)
    if not wait_until(now() + 10):
        raise ServiceBootstrapError("parallels_gui_remains")


def exact_intermediate(value: dict[str, str]) -> bool:
    return (
        value.get("gateway") == "running"
        and value.get("research") == "stopped"
        and value.get("target") == "stopped"
        and value.get("gateway_net0") in {"connected", "disconnected"}
    )


def run() -> int:
    if os.geteuid() == 0:
        raise ServiceBootstrapError("parallels_service_bootstrap_must_not_run_as_root")
    try:
        LIFECYCLE.require_mutation_prerequisites()
    except LIFECYCLE.LifecycleError as error:
        raise ServiceBootstrapError(
            str(error) or "parallels_service_bootstrap_prerequisite_invalid"
        ) from error
    initial_pids = gui_process_ids()
    if len(initial_pids) != 1:
        raise ServiceBootstrapError("parallels_gui_session_invalid")
    gui_pid = initial_pids[0]
    try:
        lock = LIFECYCLE.acquire_lock()
    except LIFECYCLE.LifecycleError as error:
        raise ServiceBootstrapError(
            str(error) or "parallels_service_bootstrap_lock_unavailable"
        ) from error
    outcomes: list[dict[str, str]] = []
    try:
        initial, _ = LIFECYCLE.observe()
        all_stopped = all(
            initial.get(key) == "stopped"
            for key in ("gateway", "research", "target")
        )
        if not (all_stopped or exact_intermediate(initial)):
            LIFECYCLE.emit(
                "start", "rejected", "preflight", outcomes,
                ["parallels_service_bootstrap_state_invalid"],
            )
            return 1
        if gui_process_ids() != (gui_pid,):
            LIFECYCLE.emit(
                "start", "rejected", "preflight", outcomes,
                ["parallels_gui_session_changed"],
            )
            return 1
        if all_stopped:
            if not LIFECYCLE.mutate(
                [str(LIFECYCLE.PRLCTL), "start", GATEWAY_NAME],
                "parallels_service_bootstrap", "gateway", outcomes,
                lambda: LIFECYCLE.wait_vm(GATEWAY_NAME, "running"),
            ):
                LIFECYCLE.emit(
                    "start", "rejected", "transition", outcomes,
                    ["gateway_service_bootstrap"],
                )
                return 1
        else:
            outcomes.append({
                "action": "parallels_service_bootstrap", "target": "gateway",
                "result": "already_satisfied",
            })
        intermediate, _ = LIFECYCLE.observe()
        if not exact_intermediate(intermediate):
            LIFECYCLE.emit(
                "start", "rejected", "transition", outcomes,
                ["parallels_service_bootstrap_readback_invalid"],
            )
            return 1
        if gui_process_ids() != (gui_pid,):
            LIFECYCLE.emit(
                "start", "rejected", "transition", outcomes,
                ["parallels_gui_session_changed"],
            )
            return 1
        terminate_gui(gui_pid)
        closed, _ = LIFECYCLE.observe()
        if not exact_intermediate(closed):
            LIFECYCLE.emit(
                "start", "rejected", "transition", outcomes,
                ["parallels_closed_service_readback_invalid"],
            )
            return 1
        return LIFECYCLE.start(inherited_lock=lock, prior_outcomes=outcomes)
    except (ServiceBootstrapError, LIFECYCLE.LifecycleError,
            subprocess.SubprocessError, OSError) as error:
        LIFECYCLE.emit(
            "start", "rejected", "transition", outcomes,
            [str(error) or "parallels_service_bootstrap_failed"],
        )
        return 1
    finally:
        LIFECYCLE.PROGRESS_PATH.unlink(missing_ok=True)
        os.close(lock)


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (ServiceBootstrapError, LIFECYCLE.LifecycleError,
            subprocess.SubprocessError, OSError) as error:
        reason = (str(error) if isinstance(
            error, (ServiceBootstrapError, LIFECYCLE.LifecycleError),
        ) else "parallels_service_bootstrap_failed")
        LIFECYCLE.emit(
            "start", "rejected", "preflight", [],
            [reason or "parallels_service_bootstrap_failed"],
        )
        raise SystemExit(1)
