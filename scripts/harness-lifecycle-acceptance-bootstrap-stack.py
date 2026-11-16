#!/usr/bin/env python3
"""Start only the fixed disposable-campaign bootstrap stack.

This is not a production ``labctl start`` substitute.  It binds the current
campaign and its exact protected drivers before mutation, uses the reviewed
Parallels stopped-service bridge, requires Gateway egress already disconnected,
starts only Gateway and Research, leaves Target stopped, and accepts only the
suite-fixed clean-install Host/Research boundary.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
STATE_ROOT = Path.home() / "Library/Application Support/SecureSandbox/harness-acceptance"
CAMPAIGN_PATH = STATE_ROOT / "campaign.json"
OBSERVATIONS = STATE_ROOT / "observations"
CASE_ID = "bootstrap-clean-install"
SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-stack-v1"
SSH = Path("/usr/bin/ssh")
GATEWAY_CONTROL = "sandbox-gateway-control"
RESEARCH_CONTROL = "sandbox-research-control"
GATEWAY_ADMIN = "sandbox-gateway"
RESEARCH_ADMIN = "sandbox-research-admin"


class AcceptanceStackError(RuntimeError):
    """Stable, content-free campaign stack failure."""


def load_script(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise AcceptanceStackError("acceptance_stack_module_unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


BOOTSTRAP = load_script(
    "acceptance_stack_bootstrap",
    ROOT / "scripts/harness-lifecycle-acceptance-bootstrap.py",
)
SERVICE_BOOTSTRAP = load_script(
    "acceptance_stack_service_bootstrap",
    ROOT / "scripts/parallels-stopped-service-bootstrap.py",
)
LIFECYCLE = SERVICE_BOOTSTRAP.LIFECYCLE


def emit(status: str, phase: str, outcomes: list[dict[str, str]],
         failures: list[str], *, campaign: dict[str, Any] | None = None,
         readbacks: dict[str, dict[str, Any]] | None = None,
         required_observed: dict[str, str] | None = None) -> bool:
    try:
        observed, reachable = LIFECYCLE.observe(reachability=True)
    except (LIFECYCLE.LifecycleError, subprocess.SubprocessError, OSError):
        observed = {
            "gateway": "unknown", "research": "unknown",
            "target": "unknown", "gateway_net0": "unknown",
        }
        reachable = {
            "gateway": "unknown", "research": "unknown", "target": "unknown",
        }
    if status == "verified" and (
            required_observed is None or observed != required_observed
            or reachable.get("gateway") != "reachable"
            or reachable.get("research") != "reachable"
            or reachable.get("target") != "unreachable"):
        status = "rejected"
        phase = "final_readback"
        failures = [*failures, "acceptance_stack_final_readback_invalid"]
    record: dict[str, Any] = {
        "schema": SCHEMA, "status": status, "phase": phase,
        "operation": "bootstrap-start", "observed": observed,
        "reachability": reachable, "action_outcomes": outcomes,
        "action_failures": failures, "case_id": CASE_ID,
        "authority": "none", "production_material_used": False,
    }
    if campaign is not None:
        record.update({
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "source_commit": campaign["source_commit"],
        })
    if readbacks is not None:
        record["readback_sha256"] = {
            name: BOOTSTRAP.digest(value) for name, value in readbacks.items()
        }
    print(json.dumps(record, sort_keys=True, separators=(",", ":")),
          file=sys.stdout if status == "verified" else sys.stderr, flush=True)
    return status == "verified"


def preflight(now: int) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        campaign, case = BOOTSTRAP.preflight(
            CAMPAIGN_PATH, OBSERVATIONS, CASE_ID, now,
        )
        readiness = BOOTSTRAP.ACCEPTANCE_CLI.driver_readiness(
            ROOT, source_commit=campaign["source_commit"],
        )
    except (BOOTSTRAP.BootstrapError, BOOTSTRAP.AcceptanceError,
            OSError) as error:
        raise AcceptanceStackError("acceptance_stack_preflight_failed") from error
    expected = len(BOOTSTRAP.ACCEPTANCE_CLI.DRIVER_ENTRYPOINTS)
    if (readiness.get("status") != "ready"
            or readiness.get("driver_count") != expected
            or readiness.get("available_driver_count") != expected
            or readiness.get("campaign_initialization_allowed") is not True
            or not isinstance(readiness.get("drivers"), list)
            or len(readiness["drivers"]) != expected
            or any(item.get("available") is not True
                   for item in readiness["drivers"])):
        raise AcceptanceStackError("acceptance_stack_drivers_unready")
    return campaign, case


def require_isolated_initial(observed: dict[str, str]) -> None:
    if observed.get("gateway_net0") != "disconnected":
        raise SERVICE_BOOTSTRAP.ServiceBootstrapError(
            "acceptance_stack_uplink_must_be_disconnected_before_start"
        )


def command(argv: list[str], *, timeout: float = 20
            ) -> subprocess.CompletedProcess[bytes]:
    return LIFECYCLE.command(argv, timeout=timeout)


def synchronize_time() -> None:
    active = command([
        str(SSH), "-F", str(LIFECYCLE.SSH_CONFIG),
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
        RESEARCH_ADMIN,
        "for state in /run/secure-sandbox/run-id "
        "/run/secure-sandbox/evidence-run-id "
        "/run/secure-sandbox/run-lease.json "
        "/run/secure-sandbox/run-process.json "
        "/var/lib/secure-sandbox/run-lifecycle/active.json "
        "/var/lib/secure-sandbox/run-lifecycle/failure-latched.json; do "
        "test ! -e \"$state\" && test ! -L \"$state\" || exit 3; done; "
        "! pgrep -x claude >/dev/null",
    ])
    if active.returncode != 0 or active.stderr or active.stdout:
        raise AcceptanceStackError("acceptance_stack_active_run_or_time_unavailable")
    for host in (GATEWAY_CONTROL, RESEARCH_CONTROL):
        epoch = int(time.time())
        result = command([
            str(LIFECYCLE.CONTROL_CLIENT), "client", "--ssh-config",
            str(LIFECYCLE.SSH_CONFIG), "--timeout-seconds", "15",
            host, "run", "set-time", f"@{epoch}",
        ], timeout=20)
        if result.returncode != 0 or result.stderr:
            raise AcceptanceStackError("acceptance_stack_time_sync_failed")
    for host in (GATEWAY_ADMIN, RESEARCH_ADMIN):
        result = command([
            str(SSH), "-F", str(LIFECYCLE.SSH_CONFIG),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
            host, "date -u +%s",
        ])
        try:
            guest = int(result.stdout.strip())
        except (AttributeError, ValueError) as error:
            raise AcceptanceStackError("acceptance_stack_time_readback_invalid") from error
        if (result.returncode != 0 or result.stderr
                or abs(int(time.time()) - guest) > 5):
            raise AcceptanceStackError("acceptance_stack_time_readback_invalid")


def continue_start(*, inherited_lock: int,
                   prior_outcomes: list[dict[str, str]],
                   campaign: dict[str, Any], case: dict[str, Any]) -> int:
    outcomes = list(prior_outcomes)
    try:
        LIFECYCLE.require_mutation_prerequisites()
        if LIFECYCLE.gui_running():
            raise AcceptanceStackError("parallels_gui_running")
        initial, _ = LIFECYCLE.observe()
        if not SERVICE_BOOTSTRAP.exact_intermediate(initial):
            raise AcceptanceStackError("acceptance_stack_intermediate_invalid")

        if initial["gateway_net0"] != "disconnected":
            raise AcceptanceStackError(
                "acceptance_stack_post_power_uplink_not_isolated"
            )
        outcomes.append({
            "action": "gateway_uplink_disconnect", "target": "gateway",
            "result": "already_satisfied",
        })
        if not LIFECYCLE.gateway_gamepad_sharing_disabled():
            if not LIFECYCLE.mutate(
                [str(LIFECYCLE.PRLCTL), "set", SERVICE_BOOTSTRAP.GATEWAY_NAME,
                 "--auto-share-gamepad", "off"],
                "gateway_gamepad_sharing_disable", "gateway", outcomes,
                LIFECYCLE.gateway_gamepad_sharing_disabled,
            ):
                raise AcceptanceStackError("acceptance_stack_gamepad_disable_failed")
        else:
            outcomes.append({
                "action": "gateway_gamepad_sharing_disable", "target": "gateway",
                "result": "already_satisfied",
            })

        if not LIFECYCLE.mutate(
            [str(LIFECYCLE.PRLCTL), "start", "SecureSandbox-Research"],
            "vm_start", "research", outcomes,
            lambda: LIFECYCLE.wait_vm("SecureSandbox-Research", "running"),
        ):
            raise AcceptanceStackError("acceptance_stack_research_start_failed")
        for host in (GATEWAY_CONTROL, RESEARCH_CONTROL):
            if not LIFECYCLE.wait_guest(host):
                raise AcceptanceStackError("acceptance_stack_control_unreachable")
        synchronize_time()
        readbacks = BOOTSTRAP.clean_install_readback(
            campaign, case, int(time.time()),
        )
        required_final = {
            "gateway": "running", "research": "running", "target": "stopped",
            "gateway_net0": "disconnected",
        }
        final, _ = LIFECYCLE.observe()
        if final != required_final:
            raise AcceptanceStackError("acceptance_stack_final_state_invalid")
        return 0 if emit(
            "verified", "complete", outcomes, [], campaign=campaign,
            readbacks=readbacks, required_observed=required_final,
        ) else 1
    except (AcceptanceStackError, BOOTSTRAP.BootstrapError,
            LIFECYCLE.LifecycleError, subprocess.SubprocessError,
            OSError) as error:
        emit("rejected", "transition", outcomes,
             [str(error) or "acceptance_stack_failed"], campaign=campaign)
        return 1


def run() -> int:
    now = int(time.time())
    try:
        campaign, case = preflight(now)
    except AcceptanceStackError as error:
        emit("rejected", "preflight", [], [str(error)])
        return 1
    return SERVICE_BOOTSTRAP.run(
        continuation=lambda **values: continue_start(
            **values, campaign=campaign, case=case,
        ),
        initial_validator=require_isolated_initial,
    )


if __name__ == "__main__":
    raise SystemExit(run())
