#!/usr/bin/env python3
"""Durably re-arm one exact committed Gateway deployment for compensation."""

from __future__ import annotations

import importlib.util
import fcntl
import json
import os
import re
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


class NativeGatewayCompensationError(RuntimeError):
    """Stable fail-closed compensation error."""


def acquire_locks(
    install_lock: Path, guest_lock: Path, *, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> tuple[int, int]:
    """Acquire the Gateway install then actuator barrier by held descriptor."""
    descriptors: list[int] = []
    try:
        for path in (install_lock, guest_lock):
            before = path.lstat()
            descriptor = os.open(
                path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or opened.st_uid != trusted_uid
                    or opened.st_gid != trusted_gid
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or (before.st_dev, before.st_ino)
                       != (opened.st_dev, opened.st_ino)):
                os.close(descriptor)
                raise NativeGatewayCompensationError(
                    "native_gateway_compensation_lock_untrusted")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            current = path.lstat()
            if (stat.S_ISLNK(current.st_mode)
                    or (current.st_dev, current.st_ino)
                       != (opened.st_dev, opened.st_ino)):
                os.close(descriptor)
                raise NativeGatewayCompensationError(
                    "native_gateway_compensation_lock_changed")
            descriptors.append(descriptor)
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise
    return descriptors[0], descriptors[1]


def lock_exec() -> None:
    install, guest = acquire_locks(
        Path("/var/lib/secure-sandbox/native-egress-control/install.lock"),
        Path("/var/lib/secure-sandbox/native-egress-control/.lock"),
    )
    install_copy = guest_copy = -1
    try:
        install_copy = fcntl.fcntl(install, fcntl.F_DUPFD_CLOEXEC, 10)
        guest_copy = fcntl.fcntl(guest, fcntl.F_DUPFD_CLOEXEC, 10)
        os.close(install)
        os.close(guest)
        install = guest = -1
        os.dup2(guest_copy, 8, inheritable=True)
        os.dup2(install_copy, 9, inheritable=True)
        os.close(install_copy)
        os.close(guest_copy)
        install_copy = guest_copy = -1
        environment = dict(os.environ)
        environment["SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD"] = "9"
        environment["SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD"] = "8"
        os.execve(
            "/bin/bash",
            ["bash", "/tmp/install-native-gateway-compensation.sh"],
            environment,
        )
    finally:
        for descriptor in {install, guest, install_copy, guest_copy, 8, 9}:
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError:
                pass


def _load(path: Path, name: str, *, trusted_uid: int,
          trusted_gid: int) -> ModuleType:
    try:
        info = path.lstat()
    except OSError as error:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_payload_unavailable") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != trusted_uid or info.st_gid != trusted_gid
            or info.st_nlink != 1 or info.st_mode & 0o022
            or not 1 <= info.st_size <= 16 * 1024 * 1024):
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_payload_untrusted")
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_payload_invalid")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def arm(
    *, plan_path: Path, transaction_path: Path, deployment_path: Path,
    state_root: Path, trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    transaction = _load(
        transaction_path, "_native_install_transaction",
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    deployment = _load(
        deployment_path, "_native_deployment",
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    plan_raw, _ = transaction._read_regular(
        plan_path, expected_uid=trusted_uid, expected_gid=trusted_gid,
        expected_mode=0o600, maximum=1024 * 1024)
    try:
        plan = deployment.validate_plan(
            json.loads(plan_raw), require_fresh=False)
    except Exception as error:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_plan_invalid") from error
    if plan_raw != deployment.canonical(plan):
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_plan_not_canonical")
    try:
        root_info = state_root.lstat()
    except OSError as error:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_state_unavailable") from error
    if (not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != trusted_uid
            or root_info.st_gid != trusted_gid
            or stat.S_IMODE(root_info.st_mode) != 0o700):
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_state_untrusted")
    pending = state_root / "gateway-install.pending.json"
    if pending.exists() or pending.is_symlink():
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_recovery_already_pending")
    pattern = re.compile(
        r"gateway-install\.pending\.[0-9a-f]{8}-[0-9a-f]{4}-"
        r"4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\."
        r"committed\.json")
    names = [name for name in os.listdir(state_root) if pattern.fullmatch(name)]
    if len(names) > transaction.MAX_RETAINED_ARCHIVES:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_archive_limit")
    matches: list[dict[str, Any]] = []
    for name in names:
        archive_raw, _ = transaction._read_regular(
            state_root / name, expected_uid=trusted_uid,
            expected_gid=trusted_gid, expected_mode=0o600,
            maximum=transaction.MAX_ARCHIVE_BYTES)
        try:
            archive = json.loads(archive_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_archive_invalid") from error
        if archive_raw != transaction.canonical(
                archive, maximum=transaction.MAX_ARCHIVE_BYTES):
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_archive_invalid")
        if (not isinstance(archive, dict)
                or set(archive) != {
                    "schema", "status", "completed_at", "transaction",
                    "archive_sha256",
                }
                or archive.get("schema") != transaction.ARCHIVE_SCHEMA
                or archive.get("status") != "committed"):
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_archive_invalid")
        try:
            record = transaction.validate_record(archive.get("transaction"))
        except Exception as error:
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_archive_invalid") from error
        body = {
            "status": archive["status"],
            "completed_at": archive["completed_at"],
            "transaction": record,
        }
        if archive.get("archive_sha256") != transaction.digest(
                body, maximum=transaction.MAX_ARCHIVE_BYTES):
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_archive_invalid")
        metadata = record["metadata"]
        predecessor_kind = metadata.get("predecessor_kind")
        predecessor_package = metadata.get("predecessor_package_sha256")
        expected_predecessor = plan["previous_gateway_package_sha256"]
        predecessor_exact = (
            predecessor_kind in {"absent", "legacy", "protected"}
            and predecessor_package == expected_predecessor
            and ((predecessor_kind == "absent")
                 == (predecessor_package is None))
            and (predecessor_package is None
                 or deployment.SHA256.fullmatch(predecessor_package)
                    is not None)
        )
        if (record["decision"] == "commit"
                and metadata.get("deployment_id") == plan["deployment_id"]
                and metadata.get("deployment_plan_sha256")
                    == plan["plan_sha256"]
                and metadata.get("package_sha256")
                    == plan["gateway_package_sha256"]
                and predecessor_exact):
            matches.append(record)
    if len(matches) != 1:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_archive_not_unique")
    record = dict(matches[0])
    record["decision"] = None
    record["decided_at"] = None
    state = {key: value for key, value in record.items()
             if key != "state_sha256"}
    record["state_sha256"] = transaction.digest(state)
    try:
        record = transaction.validate_record(record)
        transaction._atomic_file(
            pending, transaction.canonical(record), uid=trusted_uid,
            gid=trusted_gid, mode=0o600)
        observed = transaction.read_record(
            pending, expected_uid=trusted_uid, expected_gid=trusted_gid)
    except Exception as error:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_pending_write_failed") from error
    if observed != record:
        raise NativeGatewayCompensationError(
            "native_gateway_compensation_pending_readback_failed")
    return record


def main() -> int:
    try:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_root_required")
        if sys.argv[1:] == ["lock-exec"]:
            lock_exec()
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_lock_exec_returned")
        if sys.argv[1:]:
            raise NativeGatewayCompensationError(
                "native_gateway_compensation_arguments_invalid")
        arm(
            plan_path=Path("/tmp/native-deployment-plan.json"),
            transaction_path=Path("/tmp/native_install_transaction.py"),
            deployment_path=Path("/tmp/native_deployment.py"),
            state_root=Path(
                "/var/lib/secure-sandbox/native-egress-control"),
        )
        return 0
    except Exception as error:
        code = str(error)
        if not code.startswith("native_gateway_compensation_"):
            code = "native_gateway_compensation_rejected"
        print(code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
