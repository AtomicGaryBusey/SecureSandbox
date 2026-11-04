#!/usr/bin/env python3
"""Read-only, content-bound deployment observation for one native guest plane."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Callable, Sequence


MAX_OUTPUT = 1024 * 1024


class NativeDeploymentProbeError(RuntimeError):
    """Stable fail-closed deployment probe error."""


def _load(path: Path, name: str) -> ModuleType:
    try:
        info = path.lstat()
    except OSError as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_module_unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or not 1 <= info.st_size <= 16 * 1024 * 1024
    ):
        raise NativeDeploymentProbeError(
            "native_deployment_probe_module_untrusted")
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_module_unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_command_failed") from error
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_command_failed")
    return result


def _service(name: str, *, runner: Callable[[Sequence[str]],
                                            subprocess.CompletedProcess[bytes]]) -> dict[str, str]:
    shown = runner([
        "/usr/bin/systemctl", "show", name, "--property=LoadState",
        "--property=ActiveState", "--property=SubState", "--property=MainPID",
        "--property=UnitFileState",
    ])
    values: dict[str, str] = {}
    for line in shown.stdout.decode("ascii", "strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_service_invalid")
        values[key] = value
    if values != {
        "LoadState": "loaded", "ActiveState": "inactive",
        "SubState": "dead", "MainPID": "0", "UnitFileState": "disabled",
    }:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_service_not_closed")
    return values


def observe(
    role: str, release_module: ModuleType, deployment_module: ModuleType,
    *, runner: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]] = _run,
    now: int | None = None,
) -> dict:
    if role not in {"gateway", "research"}:
        raise NativeDeploymentProbeError("native_deployment_probe_role_invalid")
    pending = (
        Path("/var/lib/secure-sandbox/native-egress-control/"
             "gateway-install.pending.json")
        if role == "gateway"
        else Path("/var/lib/secure-sandbox/native-vendor/install/"
                  "native-research-install.pending.json")
    )
    if pending.exists() or pending.is_symlink():
        raise NativeDeploymentProbeError(
            "native_deployment_probe_recovery_required")
    manifest = release_module.MANIFEST
    if not manifest.exists() and not manifest.is_symlink():
        if any(Path(name).exists() or Path(name).is_symlink()
               for name in release_module.EXPECTED_ARTIFACTS):
            raise NativeDeploymentProbeError(
                "native_deployment_probe_partial_installation")
        return deployment_module.make_status(
            role=role, state="absent", package_sha256=None,
            release_id=None, catalog_sha256=None,
            closed_evidence_sha256=None,
            observed_at=int(time.time()) if now is None else now,
        )
    release = release_module.verify_installed()
    closed_raw = runner([
        "/usr/local/libexec/secure-sandbox/native_guest_control.py",
        "installed", "verify-closed",
    ]).stdout
    try:
        closed = json.loads(closed_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_closed_readback_invalid") from error
    if (
        closed_raw != deployment_module.canonical(closed)
        or not isinstance(closed, dict)
        or closed.get("state") != "closed"
    ):
        raise NativeDeploymentProbeError(
            "native_deployment_probe_closed_readback_invalid")
    watchdog = runner([
        "/usr/bin/systemctl", "is-active",
        "secure-sandbox-native-egress-watchdog.service",
    ]).stdout.decode("ascii", "strict").strip()
    if watchdog != "active":
        raise NativeDeploymentProbeError(
            "native_deployment_probe_watchdog_not_active")
    service_name = (
        "native-opaque-tunnel.service" if role == "gateway"
        else "native-harness-supervisor.service"
    )
    service = _service(service_name, runner=runner)
    catalog_sha256 = None
    if role == "research":
        catalog = [
            item["sha256"] for item in release["artifacts"]
            if item["path"] == "/etc/secure-sandbox/native-vendor-stacks.json"
        ]
        if len(catalog) != 1:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_catalog_identity_missing")
        catalog_sha256 = catalog[0]
    closed_evidence = deployment_module.digest({
        "closed": closed, "watchdog": watchdog, "service": service,
    })
    return deployment_module.make_status(
        role=role, state="verified",
        package_sha256=release["package_sha256"],
        release_id=release["release_id"],
        catalog_sha256=catalog_sha256,
        closed_evidence_sha256=closed_evidence,
        observed_at=int(time.time()) if now is None else now,
    )


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != 3:
        return 64
    role, release_path, deployment_path = values
    try:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_root_required")
        release_module = _load(Path(release_path), "_native_deployment_release")
        deployment_module = _load(
            Path(deployment_path), "_native_deployment_contract")
        result = observe(role, release_module, deployment_module)
        sys.stdout.buffer.write(deployment_module.canonical(result))
        return 0
    except Exception as error:
        code = str(error)
        if not code.startswith("native_deployment_"):
            code = "native_deployment_probe_rejected"
        print(code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
