#!/usr/bin/env python3
"""Read-only gate before any disposable-Mac root or Touch ID ceremony."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    DRIVER_ENTRYPOINTS,
    canonical,
    digest,
    validate_enrollment,
)


SCHEMA = "secure-sandbox-harness-lifecycle-morning-preflight-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-morning-preflight-error-v1"
PUBLIC_BRANCH = "public-release"
AUTHORIZED_REMOTES = (
    ("origin", "https://github.com/AtomicGaryBusey/SecureSandbox.git"),
)
MAX_OUTPUT = 1024 * 1024
TOUCH_ID_CASE_COUNT = 11


class PreflightError(RuntimeError):
    """Stable, content-free preflight failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PreflightError("preflight_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_morning_acceptance_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)
ENROLLER = load_script(
    "harness_lifecycle_morning_enroller",
    ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py",
)
SUPERVISOR = load_script(
    "harness_lifecycle_morning_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)


def git_command(
    arguments: list[str], *, cwd: Path,
    runner: Callable[..., Any] = subprocess.run,
) -> bytes:
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = runner(
            ["/usr/bin/git", *arguments], cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=30, env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError("preflight_git_probe_failed") from error
    if (result.returncode != 0 or len(result.stdout) > MAX_OUTPUT
            or len(result.stderr) > 64 * 1024):
        raise PreflightError("preflight_git_probe_failed")
    return result.stdout


def source_checkout(*, runner: Callable[..., Any] = subprocess.run) -> tuple[str, dict[str, str]]:
    head = git_command(
        ["rev-parse", "--verify", "HEAD^{commit}"], cwd=ROOT, runner=runner,
    )
    branch = git_command(
        ["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=ROOT,
        runner=runner,
    )
    status = git_command(
        ["status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT,
        runner=runner,
    )
    try:
        commit = head.decode("ascii").strip()
        branch_name = branch.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise PreflightError("preflight_checkout_invalid") from error
    if (len(commit) != 40 or any(value not in "0123456789abcdef" for value in commit)
            or branch_name != PUBLIC_BRANCH or status):
        raise PreflightError("preflight_checkout_invalid")
    tips: dict[str, str] = {}
    for remote, authorized_url in AUTHORIZED_REMOTES:
        raw = git_command(
            ["ls-remote", "--exit-code", authorized_url,
             f"refs/heads/{PUBLIC_BRANCH}"],
            cwd=Path("/"), runner=runner,
        )
        try:
            fields = raw.decode("ascii", "strict").split()
        except UnicodeDecodeError as error:
            raise PreflightError("preflight_remote_tip_invalid") from error
        if fields != [commit, f"refs/heads/{PUBLIC_BRANCH}"]:
            raise PreflightError("preflight_remote_tip_mismatch")
        tips[remote] = commit
    return commit, tips


def production_material_absent(
    *, home: Path, environment: dict[str, str],
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    if any(environment.get(name) for name in ENROLLER.PROVIDER_ENVIRONMENT):
        raise PreflightError("preflight_production_material_present")
    if any(os.path.lexists(home / relative) for relative in ENROLLER.FORBIDDEN_HOME_PATHS):
        raise PreflightError("preflight_production_material_present")
    try:
        ENROLLER.keychain_absent(runner)
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        raise PreflightError("preflight_production_material_present") from error


def run_preflight(
    enrollment_path: Path, *, now: int, home: Path,
    environment: dict[str, str], git_runner: Callable[..., Any] = subprocess.run,
    probe_runner: Callable[..., Any] = subprocess.run,
    protected_root: Path = ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
    expected_install_uid: int = 0,
    effective_uid: int | None = None,
) -> dict[str, Any]:
    operator_uid = os.geteuid() if effective_uid is None else effective_uid
    if operator_uid == 0:
        raise PreflightError("preflight_must_not_run_as_root")
    commit, remote_tips = source_checkout(runner=git_runner)
    try:
        enrollment = validate_enrollment(
            ACCEPTANCE_CLI.trusted_json(enrollment_path), now,
        )
        identity = ENROLLER.machine_identity(probe_runner)
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        raise PreflightError("preflight_enrollment_invalid") from error
    if identity != enrollment["machine_identity_sha256"]:
        raise PreflightError("preflight_machine_identity_mismatch")
    production_material_absent(
        home=home, environment=environment, runner=probe_runner,
    )

    source = ACCEPTANCE_CLI.driver_readiness(ROOT)
    if (source.get("driver_count") != len(DRIVER_ENTRYPOINTS)
            or not all(item.get("source_complete") is True for item in source["drivers"])):
        raise PreflightError("preflight_source_closure_incomplete")
    installed = ACCEPTANCE_CLI.driver_readiness(
        ROOT, source_commit=commit, protected_root=protected_root,
        expected_install_uid=expected_install_uid,
    )
    installed_count = installed["available_driver_count"]
    if installed_count not in {0, len(DRIVER_ENTRYPOINTS)}:
        raise PreflightError("preflight_protected_installation_partial")
    if installed_count == 0 and any(
        item.get("installation_error") != "protected_driver_installation_missing"
        for item in installed["drivers"]
    ):
        raise PreflightError("preflight_protected_installation_invalid")

    try:
        SUPERVISOR.require_gui_closed()
        vm_states = SUPERVISOR.vm_inventory()
    except SUPERVISOR.SupervisorError as error:
        raise PreflightError("preflight_vm_boundary_invalid") from error
    if set(vm_states) != {"gateway", "research", "target"} or any(
        state not in {"running", "stopped"} for state in vm_states.values()
    ):
        raise PreflightError("preflight_vm_boundary_invalid")

    protected_ready = installed_count == len(DRIVER_ENTRYPOINTS)
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "ready",
        "observed_at": now,
        "source_commit": commit,
        "branch": PUBLIC_BRANCH,
        "remote_tips": remote_tips,
        "machine_identity_sha256": identity,
        "operator_uid": operator_uid,
        "enrollment_sha256": enrollment["enrollment_sha256"],
        "production_material_absent": True,
        "parallels_gui_closed": True,
        "vm_states": vm_states,
        "source_driver_count": len(DRIVER_ENTRYPOINTS),
        "source_closure_complete": True,
        "protected_driver_count": installed_count,
        "protected_installation_ready": protected_ready,
        "touch_id_cases_queued": TOUCH_ID_CASE_COUNT,
        "touch_id_authorization_ready": False,
        "next_authorization": "none" if protected_ready else "root-password",
        "next_action": (
            "initialize-exact-commit-campaign" if protected_ready
            else "install-exact-commit-protected-host-release"
        ),
        "authority": "none",
    }
    value["preflight_sha256"] = digest(value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Read-only gate before disposable-Mac operator ceremonies",
    )
    value.add_argument("--enrollment", required=True, type=Path)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    result = run_preflight(
        args.enrollment, now=int(time.time()), home=Path.home(),
        environment=dict(os.environ),
    )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PreflightError, AcceptanceError, OSError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, (PreflightError, AcceptanceError)) else "preflight_failed"
        print(json.dumps({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
