#!/usr/bin/env python3
"""Durable one-time plans and operation identities for Control Center backups."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path

if __package__:
    from . import control_center_backup as backup
else:
    import control_center_backup as backup

PLAN_SCHEMA = "secure-sandbox-control-center-backup-plan-v1"
MAX_PLAN_BYTES = 16 * 1024
PLAN_LIFETIME_SECONDS = 15 * 60
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class OperationError(RuntimeError):
    pass


def default_root() -> Path:
    return Path.home() / "Library/Application Support/SecureSandbox/backup-operations"


def trusted_root(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise OperationError("backup_operation_directory_untrusted")


def write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        backup.write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    backup.fsync_directory(path.parent)


def read_exact(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                or opened.st_size > maximum
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise OperationError("backup_operation_file_untrusted")
        data = bytearray()
        while chunk := os.read(descriptor, min(4096, maximum + 1 - len(data))):
            data.extend(chunk)
            if len(data) > maximum:
                raise OperationError("backup_operation_file_oversized")
        after = os.fstat(descriptor)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
            raise OperationError("backup_operation_file_changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def create_plan(root: Path, destination: Path, volume_uuid: str,
                vm_identities: dict[str, dict[str, int | str]], key: bytes,
                *, now: int | None = None, plan_id: str | None = None) -> dict:
    trusted_root(root)
    now = int(time.time()) if now is None else now
    plan_id = plan_id or str(uuid.uuid4())
    if (UUID.fullmatch(plan_id) is None or not destination.is_absolute()
            or not isinstance(volume_uuid, str) or UUID.fullmatch(volume_uuid.lower()) is None
            or set(vm_identities) != set(backup.NAMES) or len(key) < 32):
        raise OperationError("backup_plan_identity_invalid")
    body = {"schema": PLAN_SCHEMA, "plan_id": plan_id,
            "destination": str(destination), "volume_uuid": volume_uuid,
            "vm_identities": vm_identities, "created_unix": now,
            "expires_unix": now + PLAN_LIFETIME_SECONDS}
    digest = hmac.new(key, backup.canonical(body), hashlib.sha256).hexdigest()
    value = {**body, "plan_hmac_sha256": digest}
    payload = backup.canonical(value)
    if len(payload) > MAX_PLAN_BYTES:
        raise OperationError("backup_plan_too_large")
    write_exclusive(root / f"{plan_id}.json", payload)
    return value


def load_plan(root: Path, plan_id: str, key: bytes, *, now: int | None = None,
              allow_expired: bool = False) -> dict:
    if UUID.fullmatch(plan_id) is None or len(key) < 32:
        raise OperationError("backup_plan_identity_invalid")
    trusted_root(root)
    value = json.loads(read_exact(root / f"{plan_id}.json", MAX_PLAN_BYTES))
    if (not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA
            or value.get("plan_id") != plan_id
            or not isinstance(value.get("plan_hmac_sha256"), str)):
        raise OperationError("backup_plan_invalid")
    recorded = value.pop("plan_hmac_sha256")
    expected = hmac.new(key, backup.canonical(value), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(recorded, expected):
        raise OperationError("backup_plan_authentication_failed")
    current = int(time.time()) if now is None else now
    if not allow_expired and (not isinstance(value.get("expires_unix"), int)
                              or current > value["expires_unix"]):
        raise OperationError("backup_plan_expired")
    value["plan_hmac_sha256"] = recorded
    return value


def claim_plan(root: Path, plan_id: str, key: bytes, *, now: int | None = None) -> dict:
    value = load_plan(root, plan_id, key, now=now)
    try:
        write_exclusive(root / f"{plan_id}.claimed", b"claimed\n")
    except FileExistsError as error:
        raise OperationError("backup_plan_already_claimed") from error
    return value
