#!/usr/bin/env python3
"""Migrate one existing Gateway onto the isolated Host control plane.

This is deliberately a bounded bridge between two controller generations.  It
runs only from an exact protected acceptance release while the predecessor Host
controller can still reach a running Gateway over its Shared adapter.  It
installs only the exact firewall delta carried by that release.  Activation of
the successor Host controller and disconnection of the Shared adapter remain
separate, independently read-back transitions.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any, Callable


PROTECTED_ROOT = Path(
    "/usr/local/libexec/secure-sandbox-harness-acceptance"
)
CONTROL_CLIENT = Path(
    "/usr/local/libexec/secure-sandbox-host/current/control_client"
)
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
DRIVER = "clean-machine-bootstrap"
SCRIPT = "scripts/harness-lifecycle-acceptance-host-control-migrate.py"
INSTALLER = "scripts/install-gateway-host-control-transport.sh"
PAYLOAD = "scripts/gateway-host-control-transport.py"
COMMIT = re.compile(r"[0-9a-f]{40}")
REQUEST_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}"
)
MAX_OUTPUT = 64 * 1024
SCHEMA = "secure-sandbox-harness-lifecycle-host-control-migration-v1"
EXPECTED_INITIAL = {
    "gateway": "running",
    "research": "stopped",
    "target": "stopped",
    "gateway_net0": "connected",
}


class MigrationError(RuntimeError):
    """Stable, content-free migration failure."""


def canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
        ) + "\n"
    ).encode("ascii")


def load_module(path: Path, name: str) -> ModuleType:
    try:
        specification = importlib.util.spec_from_file_location(name, path)
        if specification is None or specification.loader is None:
            raise MigrationError("migration_module_unavailable")
        module = importlib.util.module_from_spec(specification)
        sys.modules[name] = module
        specification.loader.exec_module(module)
        return module
    except (ImportError, OSError, SyntaxError) as error:
        raise MigrationError("migration_module_unavailable") from error


def require_active_component(path: Path, *, executable: bool) -> None:
    """Require a root-owned immutable regular file below the Host releases."""
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
        releases = Path(
            "/usr/local/libexec/secure-sandbox-host/releases"
        ).resolve(strict=True)
        resolved.relative_to(releases)
    except (OSError, ValueError) as error:
        raise MigrationError("migration_host_component_untrusted") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or executable != bool(info.st_mode & stat.S_IXUSR)):
        raise MigrationError("migration_host_component_untrusted")


def protected_modules(
    source_commit: str, *, protected_root: Path = PROTECTED_ROOT,
    expected_uid: int = 0,
) -> tuple[Path, dict[str, Any], ModuleType, ModuleType]:
    if COMMIT.fullmatch(source_commit) is None:
        raise MigrationError("migration_source_commit_invalid")
    release = protected_root / "releases" / source_commit
    expected_script = release / SCRIPT
    try:
        executing = Path(__file__).resolve(strict=True)
        expected = expected_script.resolve(strict=True)
    except OSError as error:
        raise MigrationError("migration_protected_release_untrusted") from error
    if executing != expected:
        raise MigrationError("migration_must_run_from_protected_release")
    acceptance = load_module(
        release / "scripts/harness-lifecycle-acceptance.py",
        "secure_sandbox_migration_acceptance",
    )
    try:
        manifest = acceptance.verify_protected_driver(
            protected_root, source_commit, DRIVER, expected_uid,
        )
    except (OSError, ValueError, RuntimeError) as error:
        raise MigrationError("migration_protected_release_untrusted") from error
    lifecycle = load_module(
        release / "scripts/parallels-lifecycle.py",
        "secure_sandbox_migration_lifecycle",
    )
    gui = load_module(
        release / "scripts/parallels-stopped-service-bootstrap.py",
        "secure_sandbox_migration_gui",
    )
    return release, manifest, lifecycle, gui


def validate_result(value: Any, transport: ModuleType) -> dict[str, Any]:
    try:
        predecessor = transport.digest(
            transport.rules("192.0.2.1", host_control=False)
        )
        successor = transport.digest(
            transport.rules("192.0.2.1", host_control=True)
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise MigrationError("migration_transport_module_invalid") from error
    # The admin address is intentionally excluded from the reported hashes: it
    # is machine-local, and the transport module already binds its exact value
    # to the predecessor and successor files.  Validate hash shape here and the
    # invariant-independent result fields below.
    if (not isinstance(predecessor, str) or not isinstance(successor, str)
            or len(predecessor) != 64 or len(successor) != 64):
        raise MigrationError("migration_transport_module_invalid")
    if (not isinstance(value, dict)
            or set(value) != {
                "schema", "status", "predecessor_sha256", "successor_sha256",
                "backup_sha256", "host_control_address", "authority",
            }
            or value.get("schema")
                != "secure-sandbox-gateway-host-control-transport-v1"
            or value.get("status") not in {"installed", "verified"}
            or not isinstance(value.get("predecessor_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["predecessor_sha256"])
            or not isinstance(value.get("successor_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["successor_sha256"])
            or value["predecessor_sha256"] == value["successor_sha256"]
            or value.get("host_control_address") != "172.30.10.30"
            or value.get("authority") != "guest-firewall-only"):
        raise MigrationError("migration_result_invalid")
    expected_backup = (
        value["predecessor_sha256"] if value["status"] == "installed" else None
    )
    if value.get("backup_sha256") != expected_backup:
        raise MigrationError("migration_result_invalid")
    return value


def migrate(
    release: Path, source_commit: str, manifest: dict[str, Any],
    lifecycle: ModuleType, gui: ModuleType, transport: ModuleType,
    request_id: str, *, runner: Callable[..., Any] = subprocess.run,
    control_client: Path = CONTROL_CLIENT, ssh_config: Path = SSH_CONFIG,
) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise MigrationError("migration_must_not_run_as_root")
    if not isinstance(request_id, str):
        raise MigrationError("migration_request_id_invalid")
    supplied_request_id = request_id
    try:
        request_id = str(uuid.UUID(request_id))
    except ValueError as error:
        raise MigrationError("migration_request_id_invalid") from error
    if supplied_request_id != request_id or REQUEST_ID.fullmatch(request_id) is None:
        raise MigrationError("migration_request_id_invalid")
    require_active_component(control_client, executable=True)
    require_active_component(ssh_config, executable=False)
    installer = release / INSTALLER
    payload = release / PAYLOAD
    if not isinstance(manifest.get("manifest_sha256"), str):
        raise MigrationError("migration_protected_release_untrusted")
    try:
        lifecycle.require_mutation_prerequisites()
        initial_pids = gui.gui_process_ids()
        lock = lifecycle.acquire_lock()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise MigrationError("migration_preflight_failed") from error
    try:
        initial, _ = lifecycle.observe()
        if initial != EXPECTED_INITIAL or len(initial_pids) != 1:
            raise MigrationError("migration_initial_state_invalid")
        command = [
            str(control_client), "client", "--ssh-config", str(ssh_config),
            "--timeout-seconds", "120", "--request-id", request_id,
            "sandbox-gateway-control", "deploy", installer.name,
            "--file", str(installer), "--file", str(payload),
        ]
        try:
            completed = runner(
                command, cwd=Path("/"), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                timeout=130,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C", "LC_ALL": "C",
                },
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise MigrationError("migration_control_outcome_ambiguous") from error
        if (len(completed.stdout) > MAX_OUTPUT
                or len(completed.stderr) > MAX_OUTPUT):
            raise MigrationError("migration_control_output_invalid")
        if completed.returncode != 0:
            raise MigrationError("migration_control_rejected")
        if completed.stderr:
            raise MigrationError("migration_control_output_invalid")
        try:
            deployed = validate_result(json.loads(completed.stdout), transport)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MigrationError("migration_result_invalid") from error
        final, _ = lifecycle.observe()
        final_pids = gui.gui_process_ids()
        if final != EXPECTED_INITIAL or final_pids != initial_pids:
            raise MigrationError("migration_final_state_invalid")
        return {
            "schema": SCHEMA,
            "status": "verified",
            "source_commit": source_commit,
            "manifest_sha256": manifest["manifest_sha256"],
            "request_id": request_id,
            "initial": initial,
            "final": final,
            "gateway_transport": deployed,
            "authority": "protected-release-and-independent-readback",
        }
    finally:
        os.close(lock)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--source-commit", required=True)
    value.add_argument("--request-id", default=None)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    request_id = args.request_id or str(uuid.uuid4())
    try:
        release, manifest, lifecycle, gui = protected_modules(args.source_commit)
        transport = load_module(
            release / PAYLOAD, "secure_sandbox_migration_transport",
        )
        result = migrate(
            release, args.source_commit, manifest, lifecycle, gui, transport,
            request_id,
        )
    except (MigrationError, OSError, RuntimeError,
            subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, MigrationError) else "migration_failed"
        sys.stderr.buffer.write(canonical({
            "schema": f"{SCHEMA}-error", "status": "rejected",
            "error": reason, "request_id": request_id,
        }))
        return 1
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
